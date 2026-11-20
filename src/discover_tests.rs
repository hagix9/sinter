//! `sinter discover` (DESIGN §46) against the scripted target.

use super::*;
use crate::engine::{Engine, Mode, RunOptions, TargetSpec};
use crate::executor::{FakeTarget, FsEventAction, Output};
use std::os::unix::fs::PermissionsExt;

/// Synthetic canaries only (never real credentials).
const CANARY: &str = "SINTERCANARY7f3a";

fn out(code: i32, stdout: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

const LOGIN_DEFS: &str = "# login.defs\nUID_MIN 1000\nUID_MAX 60000\nGID_MIN 1000\nGID_MAX 60000\n";

/// Ubuntu with: manual packages nginx and curl (installed), two enabled
/// units (one at its vendor preset), local accounts around the range
/// boundaries, and a few files.
fn host() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .as_root()
        .with_fake_fs()
        .with_fs_file("/etc/login.defs", LOGIN_DEFS)
        .with_fs_file("/etc/motd", "Welcome \"team\"\n\tbackslash \\ here\n")
        .with_fs_dir("/etc/app")
        .with_group("app", 1001)
        .with_group("edge", 60000)
        .with_group("below", 999)
        .with_group("above", 60001)
        .with_user("alice", 1000, 1001, "/home/alice", "/bin/bash")
        .with_user("svc", 999, 999, "/var/lib/svc", "/usr/sbin/nologin")
        .with_user("hi", 60000, 60000, "/home/hi", "/bin/sh")
        .with_user("over", 60001, 60001, "/home/over", "/bin/sh");
    for p in ["nginx", "curl"] {
        t.packages.insert(p.to_string());
    }
    t.program_outputs
        .insert("/usr/bin/apt-mark".into(), out(0, "curl\nnginx\n"));
    for (u, preset) in [
        ("nginx.service", "disabled"),
        ("ssh.service", "enabled"),
        ("backup.timer", "disabled"),
    ] {
        t.services.insert(
            u.into(),
            ("loaded".into(), "active".into(), "enabled".into()),
        );
        t.manager.presets.insert(u.into(), preset.into());
    }
    if let Some(fs) = t.fs.as_mut() {
        fs.put_symlink("/etc/app/current", "/opt/app/v1", 0, 0);
        fs.put_file(
            "/etc/app/app.conf",
            b"listen = 8080\nworkers = 4\n",
            0o644,
            0,
            1001,
        );
    }
    t
}

fn cfg(profiles: &[Profile], paths: &[&str]) -> DiscoverConfig {
    DiscoverConfig {
        profiles: profiles.iter().copied().collect(),
        include_paths: paths.iter().map(|s| s.to_string()).collect(),
        host_label: "web01".into(),
        collected_at: "2026-11-20T00:00:00Z".into(),
    }
}

fn opts(t: FakeTarget, mode: Mode) -> RunOptions {
    RunOptions {
        mode,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(t),
    }
}

/// Collect with a plan-mode engine; returns the discovery and the commands.
fn collect(t: FakeTarget, c: &DiscoverConfig) -> (Discovery, Vec<crate::executor::CommandRecord>) {
    let mut e = Engine::new(empty_model(), opts(t, Mode::Plan)).unwrap();
    let d = e.discover(c).unwrap();
    (d, e.fs.log())
}

fn ids(d: &Discovery) -> Vec<String> {
    d.resources.iter().map(|r| r.id.clone()).collect()
}

fn unsupported<'a>(d: &'a Discovery, key: &str) -> &'a Unsupported {
    d.unsupported
        .iter()
        .find(|u| u.key == key)
        .unwrap_or_else(|| panic!("no unsupported {key}: {:?}", d.unsupported))
}

/// Every command is one of the read-only forms.
fn read_only(log: &[crate::executor::CommandRecord]) {
    for c in log {
        let prog = c.program.rsplit('/').next().unwrap_or("");
        let ok = match prog {
            "test" | "cat" | "uname" | "hostname" | "id" | "stat" | "readlink" | "getfattr" => true,
            "getent" => {
                c.args.first().map(|s| s.as_str()) != Some("shadow")
                    && !c.args.iter().any(|a| a == "shadow" || a == "gshadow")
            }
            "dd" => {
                c.args.iter().any(|a| a == "iflag=nofollow,nonblock")
                    && !c.args.iter().any(|a| a.starts_with("of="))
            }
            "apt-mark" => c.args == ["showmanual"],
            "systemctl" => c.args.first().map(|s| s.as_str()) == Some("list-unit-files"),
            _ => false,
        };
        assert!(
            ok,
            "not a read-only discover command: {} {:?}",
            c.program, c.args
        );
        assert!(
            !c.args.iter().any(|a| a.contains("/etc/shadow")),
            "{:?}",
            c.args
        );
    }
}

// ---------------------------------------------------------------------------
// read-only boundary
// ---------------------------------------------------------------------------

#[test]
fn the_collector_cannot_mutate() {
    let mut e = Engine::new(empty_model(), opts(host(), Mode::Plan)).unwrap();
    assert!(
        e.fs.mutation_permit().is_err(),
        "a plan-mode engine has no permit"
    );
    let d = e
        .discover(&cfg(
            &Profile::all().into_iter().collect::<Vec<_>>(),
            &["/etc/motd"],
        ))
        .unwrap();
    assert!(!d.resources.is_empty());
    read_only(&e.fs.log());
    // An apply-mode engine is refused before anything is collected.
    let mut a = Engine::new(empty_model(), opts(host(), Mode::Apply)).unwrap();
    let before = a.fs.log().len();
    assert!(a.discover(&cfg(&[Profile::Packages], &[])).is_err());
    assert_eq!(a.fs.log().len(), before, "nothing ran");
    // `run` refuses an apply-mode request outright.
    let dir = tempfile::tempdir().unwrap();
    let e = run(
        opts(host(), Mode::Apply),
        &cfg(&[], &[]),
        &dir.path().join("x.yaml"),
    )
    .unwrap_err();
    assert!(e.message.contains("plan-mode"));
}

#[test]
fn fixed_argv() {
    let (_, log) = collect(
        host(),
        &cfg(
            &Profile::all().into_iter().collect::<Vec<_>>(),
            &["/etc/motd"],
        ),
    );
    let find = |p: &str| {
        log.iter()
            .find(|c| c.program.ends_with(p))
            .map(|c| c.args.clone())
    };
    assert_eq!(find("apt-mark").unwrap(), ["showmanual"]);
    assert_eq!(
        find("systemctl").unwrap(),
        [
            "list-unit-files",
            "--type=service",
            "--type=timer",
            "--state=enabled",
            "--no-legend",
            "--plain",
            "--no-pager"
        ]
    );
    assert!(log
        .iter()
        .any(|c| c.program.ends_with("getent") && c.args == ["-s", "files", "passwd"]));
    assert!(log
        .iter()
        .any(|c| c.program.ends_with("getent") && c.args == ["-s", "files", "group"]));
    assert_eq!(
        find("dd").unwrap(),
        [
            "if=/etc/motd",
            "iflag=nofollow,nonblock",
            "bs=65537",
            "count=1",
            "status=none"
        ]
    );
}

// ---------------------------------------------------------------------------
// packages
// ---------------------------------------------------------------------------

#[test]
fn packages_debian_manual_only() {
    let mut t = host();
    t.program_outputs.insert(
        "/usr/bin/apt-mark".into(),
        out(0, "nginx\ncurl\nlibc6:i386\n-bad\nnginx\n"),
    );
    let (d, _) = collect(t, &cfg(&[Profile::Packages], &[]));
    assert_eq!(ids(&d), ["pkg-nginx", "pkg-curl"]);
    assert_eq!(
        unsupported(&d, "libc6:i386").reason,
        "architecture-qualified name"
    );
    assert_eq!(
        unsupported(&d, "(line 4)").reason,
        "unreadable package name"
    );
    // A failing apt-mark: the profile is unsupported, nothing else is listed.
    let mut t = host();
    t.program_outputs
        .insert("/usr/bin/apt-mark".into(), out(1, "nginx\n"));
    let (d, _) = collect(t, &cfg(&[Profile::Packages], &[]));
    assert!(d.resources.is_empty());
    assert_eq!(unsupported(&d, "packages").kind, "profile");
}

#[test]
fn packages_red_hat_run_no_dnf_and_never_list_everything() {
    let mut t = FakeTarget::rocky9().as_root().with_fake_fs();
    t.packages.insert("httpd".into());
    let (d, log) = collect(t, &cfg(&[Profile::Packages], &[]));
    assert!(d.resources.is_empty());
    assert!(unsupported(&d, "packages").reason.contains("not measured"));
    // No dnf or rpm command: no metadata refresh, no full package list.
    assert!(
        !log.iter()
            .any(|c| c.program.ends_with("dnf") || c.program.ends_with("rpm")),
        "{log:?}"
    );
}

// ---------------------------------------------------------------------------
// units
// ---------------------------------------------------------------------------

#[test]
fn units_services_timers_and_vendor_presets() {
    let (d, _) = collect(host(), &cfg(&[Profile::Units], &[]));
    // ssh.service is at its vendor preset (enabled) and left out.
    assert_eq!(ids(&d), ["svc-backup.timer", "svc-nginx.service"]);
    assert_eq!(d.resources[0].type_, "service");
    assert_eq!(d.resources[0].with["enabled"], Value::Bool(true));
    assert!(d.warnings.is_empty());
    // No preset column: every enabled unit, with a warning.
    let mut t = host();
    t.observation_overrides.insert(
        "systemctl".into(),
        [out(
            0,
            "a.service enabled\nb.timer enabled\ngetty@.service enabled\nx.socket enabled\n",
        )]
        .into(),
    );
    let (d, _) = collect(t, &cfg(&[Profile::Units], &[]));
    assert_eq!(ids(&d), ["svc-a.service", "svc-b.timer"]);
    assert_eq!(d.warnings.len(), 1);
    assert_eq!(unsupported(&d, "getty@.service").reason, "template unit");
    assert_eq!(
        unsupported(&d, "x.socket").reason,
        "unit name Sinter cannot declare"
    );
    // Mixed columns: unsupported, nothing guessed.
    let mut t = host();
    t.observation_overrides.insert(
        "systemctl".into(),
        [out(0, "a.service enabled\nb.service enabled disabled\n")].into(),
    );
    let (d, _) = collect(t, &cfg(&[Profile::Units], &[]));
    assert!(d.resources.is_empty());
    assert_eq!(
        unsupported(&d, "units").reason,
        "unexpected systemctl output"
    );
    // Another state than enabled (alias, masked): unsupported.
    let mut t = host();
    t.observation_overrides.insert(
        "systemctl".into(),
        [out(
            0,
            "a.service alias disabled\nb.service masked enabled\n",
        )]
        .into(),
    );
    let (d, _) = collect(t, &cfg(&[Profile::Units], &[]));
    assert!(d.resources.is_empty());
    assert_eq!(unsupported(&d, "a.service").reason, "state is not enabled");
}

// ---------------------------------------------------------------------------
// accounts
// ---------------------------------------------------------------------------

#[test]
fn accounts_use_login_defs_ranges_and_no_gecos_or_shadow() {
    let (d, log) = collect(host(), &cfg(&[Profile::Accounts], &[]));
    // Groups first, then users; 999 and 60001 are outside both ranges.
    assert_eq!(
        ids(&d),
        ["group-app", "group-edge", "user-alice", "user-hi"]
    );
    let alice = &d.resources[2].with;
    assert_eq!(alice["uid"], Value::Int(1000));
    assert_eq!(alice["group"], s("app"));
    assert!(!alice.contains_key("comment") && !alice.contains_key("password_hash"));
    assert!(
        !log.iter()
            .any(|c| c.args.iter().any(|a| a.contains("shadow"))),
        "{log:?}"
    );
    // GECOS with personal data is never emitted anywhere.
    let mut t = host();
    t.observation_overrides.insert(
        "getent".into(),
        [
            out(
                0,
                &format!("alice:x:1000:1001:Alice {CANARY},Room 1:/home/alice:/bin/bash\n"),
            ),
            out(0, "app:x:1001:\n"),
        ]
        .into(),
    );
    let (d, _) = collect(t, &cfg(&[Profile::Accounts], &[]));
    let c = cfg(&[Profile::Accounts], &[]);
    let all = format!("{}{}", render_yaml(&d, &c), provenance(&d, &c));
    assert!(!all.contains(CANARY), "{all}");
    assert!(d
        .collectors
        .iter()
        .filter(|c| c.id == "accounts.passwd")
        .all(|c| c.output_sha256.is_none()));
    // Without the four login.defs values nothing is guessed.
    let mut t = host();
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/login.defs", b"UID_MIN 1000\n", 0o644, 0, 0);
    let (d, _) = collect(t, &cfg(&[Profile::Accounts], &[]));
    assert!(d.resources.is_empty());
    assert_eq!(unsupported(&d, "accounts").kind, "profile");
}

#[test]
fn login_defs_parser() {
    assert_eq!(
        parse_login_defs(LOGIN_DEFS),
        Some((1000, 60000, 1000, 60000))
    );
    assert_eq!(
        parse_login_defs("UID_MIN 1000\nUID_MAX 60000\nGID_MIN 1000\n"),
        None
    );
    assert_eq!(
        parse_login_defs(&format!("{LOGIN_DEFS}UID_MIN 500\n")),
        None,
        "twice"
    );
    assert_eq!(
        parse_login_defs(&LOGIN_DEFS.replace("1000\nUID_MAX", "01000\nUID_MAX")),
        None
    );
    assert_eq!(
        parse_login_defs(&LOGIN_DEFS.replace("UID_MAX 60000", "UID_MAX 10")),
        None
    );
}

// ---------------------------------------------------------------------------
// files and secrets
// ---------------------------------------------------------------------------

#[test]
fn files_regular_symlink_directory() {
    let (d, log) = collect(
        host(),
        &cfg(
            &[Profile::Files],
            &["/etc/motd", "/etc/app/current", "/etc/app", "/etc/nothing"],
        ),
    );
    assert_eq!(
        ids(&d),
        ["file-etc-motd", "link-etc-app-current", "dir-etc-app"]
    );
    assert_eq!(d.resources[0].with["mode"], s("0644"));
    assert_eq!(d.resources[0].with["owner"], s("0"));
    assert_eq!(d.resources[1].with["target"], s("/opt/app/v1"));
    assert!(!d.resources[2].with.contains_key("content"));
    assert_eq!(unsupported(&d, "/etc/nothing").reason, "absent");
    // The link and the directory were never read.
    assert!(!log
        .iter()
        .any(|c| c.program.ends_with("dd") && c.args[0] != "if=/etc/motd"));
    // File content has no digest anywhere.
    assert!(d.resources[0].value_sha256.is_none());
}

fn one_file(content: &[u8], mode: u32) -> Discovery {
    let mut t = host();
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/x.conf", content, mode, 0, 0);
    collect(t, &cfg(&[Profile::Files], &["/etc/x.conf"])).0
}

fn excluded(content: &[u8], mode: u32, reason: &str) {
    let d = one_file(content, mode);
    assert!(d.resources.is_empty(), "{reason}: {:?}", d.resources);
    let u = unsupported(&d, "/etc/x.conf");
    assert!(u.reason.contains(reason), "{reason}: {u:?}");
    let c = cfg(&[Profile::Files], &["/etc/x.conf"]);
    let all = format!("{}{}{:?}", render_yaml(&d, &c), provenance(&d, &c), d);
    assert!(!all.contains(CANARY), "{reason}: canary leaked: {all}");
    // No digest of the content anywhere.
    let digest = sha256(content);
    assert!(!all.contains(&digest), "{reason}: digest leaked");
}

#[test]
fn secrets_fail_closed() {
    excluded(
        format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{CANARY}\n").as_bytes(),
        0o644,
        "private key",
    );
    excluded(
        format!("db_password = {CANARY}\n").as_bytes(),
        0o644,
        "credential",
    );
    excluded(
        format!("\"api_key\": \"{CANARY}\"\n").as_bytes(),
        0o644,
        "credential",
    );
    excluded(format!("TOKEN: {CANARY}\n").as_bytes(), 0o644, "credential");
    excluded(
        format!("x {CANARY}Zq8Lp2Vw9Kx4Rt7Ym3Nb6Hc1 y\n").as_bytes(),
        0o644,
        "high-entropy",
    );
    excluded(
        format!("ok {CANARY}\u{1b}[31m\n").as_bytes(),
        0o644,
        "control",
    );
    excluded(format!("a\r\nb {CANARY}\n").as_bytes(), 0o644, "control");
    let mut bad = format!("x {CANARY} ").into_bytes();
    bad.extend_from_slice(&[0xff, 0xfe, b'\n']);
    excluded(&bad, 0o644, "undecodable");
    excluded(
        format!("\u{feff}x {CANARY}\n").as_bytes(),
        0o644,
        "undecodable",
    );
    excluded(
        format!("plain {CANARY}\n").as_bytes(),
        0o640,
        "not readable by others",
    );
    excluded(
        format!("plain {CANARY}\n").as_bytes(),
        0o600,
        "not readable by others",
    );
    // A plain configuration is taken in.
    let d = one_file(b"listen = 8080\n# password is set elsewhere\n", 0o644);
    assert_eq!(d.resources.len(), 1, "{:?}", d.unsupported);
}

#[test]
fn secret_names_are_excluded_without_reading() {
    for p in [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/ssh/ssh_host_ed25519_key",
        "/etc/ssh/ssh_host_ed25519_key.pub",
        "/root/.ssh/id_ed25519",
        "/etc/pki/tls/private/web.key",
        "/etc/ssl/certs/site.pem",
        "/etc/app/store.p12",
    ] {
        let mut t = host();
        let fs = t.fs.as_mut().unwrap();
        for dir in [
            "/root",
            "/root/.ssh",
            "/etc/ssh",
            "/etc/pki",
            "/etc/pki/tls",
            "/etc/pki/tls/private",
            "/etc/ssl",
            "/etc/ssl/certs",
        ] {
            fs.mkdir_node(dir, 0o755, 0, 0);
        }
        fs.put_file(p, format!("x {CANARY}\n").as_bytes(), 0o644, 0, 0);
        let (d, log) = collect(t, &cfg(&[Profile::Files], &[p]));
        assert!(d.resources.is_empty(), "{p}");
        assert!(
            unsupported(&d, p).reason.contains("secret-bearing name"),
            "{p}"
        );
        assert!(
            !log.iter().any(|c| c.program.ends_with("dd")),
            "{p} was read"
        );
    }
}

#[test]
fn size_boundary_64_kib() {
    let at = "a".repeat(MAX_FILE - 1) + "\n";
    assert_eq!(
        one_file(at.as_bytes(), 0o644).resources.len(),
        1,
        "exactly 64 KiB is taken in"
    );
    let over = "a".repeat(MAX_FILE) + "\n";
    let d = one_file(over.as_bytes(), 0o644);
    assert!(d.resources.is_empty());
    assert_eq!(unsupported(&d, "/etc/x.conf").reason, "larger than 64 KiB");
}

#[test]
fn utf8_text_is_kept_exactly() {
    let text = "名前 = \"テスト\" ✓\n\ttab and \\ backslash\n";
    let d = one_file(text.as_bytes(), 0o644);
    assert_eq!(d.resources[0].with["content"], s(text));
}

#[test]
fn a_file_changed_while_read_is_excluded() {
    // TOCTOU: the file is replaced right before it is read (another inode)
    // or its mode changes; the observation after the read differs.
    for action in [
        FsEventAction::PutFile {
            path: "/etc/motd".into(),
            data: format!("db_password = {CANARY}\n").into_bytes(),
            mode: 0o644,
            uid: 0,
            gid: 0,
        },
        FsEventAction::PutSymlink {
            path: "/etc/motd".into(),
            target: "/etc/shadow".into(),
            uid: 0,
            gid: 0,
        },
    ] {
        let t = host().with_fs_event("dd", "if=/etc/motd", 0, vec![action]);
        let (d, _) = collect(t, &cfg(&[Profile::Files], &["/etc/motd"]));
        assert!(d.resources.is_empty(), "{:?}", d.resources);
        let r = &unsupported(&d, "/etc/motd").reason;
        assert!(
            r == "changed while it was read" || r == "could not be read",
            "{r}"
        );
        let c = cfg(&[Profile::Files], &["/etc/motd"]);
        assert!(!format!("{}{}", render_yaml(&d, &c), provenance(&d, &c)).contains(CANARY));
    }
}

#[test]
fn classifier_unit_cases() {
    assert!(credential_assignment("password=x"));
    assert!(credential_assignment("  Secret_Key : 'abc'"));
    assert!(!credential_assignment("password="));
    assert!(!credential_assignment("# no password here"));
    assert!(!credential_assignment("password_file /etc/x"));
    assert!(high_entropy_token("k=Zq8Lp2Vw9Kx4Rt7Ym3Nb6Hc1Jd5"));
    assert!(!high_entropy_token("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    assert!(!high_entropy_token("/usr/share/doc/package/README"));
    assert!(valid_include_path("/etc/motd"));
    for bad in [
        "etc",
        "/",
        "/etc/",
        "/etc//x",
        "/etc/../shadow",
        "/etc/./x",
        "/etc/a b",
        "/etc/\u{1b}",
    ] {
        assert!(!valid_include_path(bad), "{bad:?}");
    }
}

// ---------------------------------------------------------------------------
// YAML, ids, round trip, provenance
// ---------------------------------------------------------------------------

#[test]
fn yaml_escaping_and_header() {
    assert_eq!(quote("a\"b\\c\nd\te"), "\"a\\\"b\\\\c\\nd\\te\"");
    assert_eq!(quote("x\u{7f}\u{85}\u{2028}"), "\"x\\x7f\\u0085\\u2028\"");
    let c = cfg(&[], &[]);
    let y = render_yaml(&Discovery::default(), &c);
    assert!(y.starts_with("# Sinter discover candidate recipe: NOT APPLIED"));
    assert!(y.contains("# host: web01\n# collected: 2026-11-20T00:00:00Z\n"));
    assert!(y.contains("version: 1\nresources: []\n"));
}

#[test]
fn ids_are_unique_and_deterministic() {
    let mut t = host();
    let fs = t.fs.as_mut().unwrap();
    fs.put_file("/etc/a-b", b"1\n", 0o644, 0, 0);
    fs.put_file("/etc/a_b", b"2\n", 0o644, 0, 0);
    fs.put_file("/etc/a b", b"3\n", 0o644, 0, 0);
    let (d, _) = collect(
        t.clone(),
        &cfg(&[Profile::Files], &["/etc/a-b", "/etc/a_b"]),
    );
    assert_eq!(ids(&d), ["file-etc-a-b", "file-etc-a_b"]);
    let mut rs = vec![
        IrResource {
            id: "x".into(),
            type_: "file".into(),
            with: BTreeMap::new(),
            collector: String::new(),
            source_key: String::new(),
            value_sha256: None
        };
        4
    ];
    rs[3].id = "x-2".into();
    unique_ids(&mut rs);
    assert_eq!(
        rs.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["x", "x-2", "x-3", "x-2-2"]
    );
}

fn all_profiles() -> Vec<Profile> {
    Profile::all().into_iter().collect()
}

#[test]
fn round_trip_publish_provenance_and_audit_without_drift() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let outp = dir.path().join("web01.yaml");
    let c = cfg(
        &all_profiles(),
        &[
            "/etc/motd",
            "/etc/app/current",
            "/etc/app",
            "/etc/app/app.conf",
        ],
    );
    let (d, p) = run(opts(host(), Mode::Plan), &c, &outp).unwrap();
    use std::os::unix::fs::MetadataExt;
    for f in [&p.recipe, &p.provenance] {
        assert_eq!(std::fs::metadata(f).unwrap().mode() & 0o777, 0o600, "{f:?}");
    }
    assert_eq!(p.provenance, dir.path().join("web01.yaml.discover.json"));
    // The recipe loads with the existing loader and validates.
    let model = crate::model::load_model(&p.recipe).unwrap();
    assert_eq!(model.resources.len(), d.resources.len());
    // Provenance.
    let pv: J = serde_json::from_str(&std::fs::read_to_string(&p.provenance).unwrap()).unwrap();
    assert_eq!(pv["schema"], PROVENANCE_SCHEMA);
    assert_eq!(pv["host"], "web01");
    assert_eq!(pv["applied"], false);
    let res = pv["resources"].as_array().unwrap();
    assert_eq!(res.len(), d.resources.len());
    let motd = res.iter().find(|r| r["id"] == "file-etc-motd").unwrap();
    assert!(motd["value_sha256"].is_null());
    assert!(res.iter().find(|r| r["id"] == "pkg-nginx").unwrap()["value_sha256"].is_string());
    assert!(pv["collectors"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["argv"].is_array()));
    // Audit against the same host: no drift for anything taken in.
    let a = crate::audit::run_audit(Engine::new(model, opts(host(), Mode::Plan)).unwrap()).unwrap();
    for r in &a.resources {
        assert_eq!(
            r.status,
            crate::audit::AuditResourceStatus::Compliant,
            "{} {:?} {:?}",
            r.id,
            r.reason,
            r.details
        );
    }
    // After the host changes, audit reports drift.
    let mut changed = host();
    changed
        .fs
        .as_mut()
        .unwrap()
        .put_file("/etc/motd", b"changed\n", 0o644, 0, 0);
    changed.services.insert(
        "nginx.service".into(),
        ("loaded".into(), "inactive".into(), "disabled".into()),
    );
    let model = crate::model::load_model(&p.recipe).unwrap();
    let a =
        crate::audit::run_audit(Engine::new(model, opts(changed, Mode::Plan)).unwrap()).unwrap();
    for id in ["file-etc-motd", "svc-nginx.service"] {
        let r = a.resources.iter().find(|r| r.id == id).unwrap();
        assert_ne!(
            r.status,
            crate::audit::AuditResourceStatus::Compliant,
            "{id}"
        );
    }
}

#[test]
fn round_trip_mismatch_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let c = cfg(&[Profile::Packages], &[]);
    let (mut d, _) = collect(host(), &c);
    let yaml = render_yaml(&d, &c);
    // The IR says something else than the text.
    d.resources[0].with.insert("name".into(), s("other"));
    let e = round_trip(&yaml, &d, dir.path()).unwrap_err();
    assert_eq!(e.kind, crate::error::ErrorKind::Plan);
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "the check copy is gone"
    );
}

#[test]
fn outputs_are_never_overwritten_or_followed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let o = dir.path().join("r.yaml");
    std::fs::write(&o, "keep").unwrap();
    assert!(check_outputs(&o)
        .unwrap_err()
        .message
        .contains("already exists"));
    let o2 = dir.path().join("s.yaml");
    std::os::unix::fs::symlink("/nonexistent", &o2).unwrap();
    assert!(
        check_outputs(&o2).is_err(),
        "a dangling symlink counts as existing"
    );
    let o3 = dir.path().join("t.yaml");
    std::fs::write(provenance_path(&o3), "keep").unwrap();
    assert!(check_outputs(&o3).is_err(), "the provenance path exists");
    // A group-writable directory, or a symlinked one, is refused.
    let open = dir.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(check_outputs(&open.join("r.yaml")).is_err());
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&real, dir.path().join("via")).unwrap();
    assert!(check_outputs(&dir.path().join("via").join("r.yaml")).is_err());
    assert!(check_outputs(&dir.path().join(".hidden.yaml")).is_err());
    // A run with an existing output contacts nothing and keeps the file.
    let e = run(
        opts(host(), Mode::Plan),
        &cfg(&[Profile::Packages], &[]),
        &o,
    )
    .unwrap_err();
    assert_eq!(e.kind, crate::error::ErrorKind::Schema);
    assert_eq!(std::fs::read_to_string(&o).unwrap(), "keep");
}

#[test]
fn partial_publish_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let o = dir.path().join("r.yaml");
    let c = cfg(&[], &[]);
    let d = Discovery::default();
    // The provenance path appears between the check and its publication:
    // publish_new refuses it, the recipe stays, and the error says so.
    let pp = provenance_path(&o);
    let yaml = render_yaml(&d, &c);
    crate::securefile::publish_new(&o, yaml.as_bytes(), 0o600).unwrap();
    std::fs::remove_file(&o).unwrap();
    std::fs::write(&pp, "other").unwrap();
    // check_outputs refuses up front.
    assert!(publish(&o, &yaml, &provenance(&d, &c)).is_err());
    assert_eq!(std::fs::read_to_string(&pp).unwrap(), "other");
    assert!(!o.exists());
}

#[test]
fn rfc3339_dates() {
    assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(rfc3339(1_795_651_199), "2026-11-25T23:59:59Z");
}

#[test]
fn profile_list_parser() {
    assert_eq!(Profile::parse_list("files,units").unwrap().len(), 2);
    assert!(Profile::parse_list("files,files").is_err());
    assert!(Profile::parse_list("firewalld").is_err());
    assert!(Profile::parse_list("").is_err());
}

// ---------------------------------------------------------------------------
// independent audit 1 (B-1, N-1..N-4)
// ---------------------------------------------------------------------------

#[test]
fn template_syntax_is_never_generated() {
    // B-1: host text would become a Sinter expression.
    for content in [
        "host = {{ facts.hostname }}\n",
        "lit = \\{{ x }}\n",
        "v = {{ vars.x }}\n",
        "tag = \"{{.Name}}\"\n",
    ] {
        let d = one_file(content.as_bytes(), 0o644);
        assert!(d.resources.is_empty(), "{content}");
        assert_eq!(
            unsupported(&d, "/etc/x.conf").reason,
            "excluded: template syntax",
            "{content}"
        );
    }
    // A path or link target with template syntax; the rest is still written.
    let mut t = host();
    {
        let fs = t.fs.as_mut().unwrap();
        fs.put_file("/etc/{{x}}", b"a\n", 0o644, 0, 0);
        fs.put_symlink("/etc/lnk", "/opt/{{ facts.hostname }}", 0, 0);
    }
    t = t.with_user("tmpl", 1500, 1001, "/home/{{x}}", "/bin/sh");
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let c = cfg(&all_profiles(), &["/etc/{{x}}", "/etc/lnk", "/etc/motd"]);
    let (d, p) = run(opts(t, Mode::Plan), &c, &dir.path().join("r.yaml")).unwrap();
    assert_eq!(unsupported(&d, "/etc/{{x}}").reason, "template syntax");
    assert!(unsupported(&d, "/etc/lnk")
        .reason
        .contains("cannot declare"));
    assert!(unsupported(&d, "tmpl").reason.contains("cannot declare"));
    assert!(!std::fs::read_to_string(&p.recipe).unwrap().contains("{{"));
    // The round trip refuses template syntax as a safety net.
    let mut d2 = Discovery::default();
    let mut with = BTreeMap::new();
    // A file content that loads (facts are known only at run time): only
    // the safety net can refuse it.
    with.insert("path".to_string(), s("/etc/x"));
    with.insert("content".to_string(), s("{{ facts.hostname }}"));
    d2.resources.push(IrResource {
        id: "x".into(),
        type_: "file".into(),
        with,
        collector: String::new(),
        source_key: String::new(),
        value_sha256: None,
    });
    let e = round_trip(&render_yaml(&d2, &c), &d2, dir.path()).unwrap_err();
    assert_eq!(e.kind, crate::error::ErrorKind::Plan);
    assert!(e.message.contains("template syntax"), "{}", e.message);
}

#[test]
fn more_credentials_and_format_characters_are_excluded() {
    // N-1.
    excluded(
        format!("admin:$apr1$Ab3dEf7h$Zq8Lp2Vw9Kx4{CANARY}\n").as_bytes(),
        0o644,
        "credential",
    );
    excluded(
        format!("u:$6$saltsalt$abc{CANARY}\n").as_bytes(),
        0o644,
        "credential",
    );
    excluded(format!("PASS={CANARY}\n").as_bytes(), 0o644, "credential");
    excluded(
        format!("wpa psk={CANARY}\n").as_bytes(),
        0o644,
        "credential",
    );
    excluded(
        format!("url = https://user:{CANARY}@example.com/x\n").as_bytes(),
        0o644,
        "credential",
    );
    excluded(
        format!("Authorization: Bearer {CANARY}\n").as_bytes(),
        0o644,
        "credential",
    );
    excluded(
        format!("rocommunity {CANARY}\n").as_bytes(),
        0o644,
        "credential",
    );
    excluded(
        format!("k {CANARY}Ab9/Zq8Lp2Vw9Kx4Rt7Ym3Nb6Hc1Jd5Fg0Qe\n").as_bytes(),
        0o644,
        "high-entropy",
    );
    // N-2: bidi and zero-width characters.
    excluded(
        format!("a {}{CANARY}", "\u{202e}\n").as_bytes(),
        0o644,
        "control",
    );
    excluded(
        format!("a {}{CANARY}", "\u{200b}\n").as_bytes(),
        0o644,
        "control",
    );
    for ch in ["\u{feff}", "\u{e0041}", "\u{fff9}"] {
        excluded(format!("a {ch}{CANARY}\n").as_bytes(), 0o644, "control");
    }
    // Plain text with an URL, a path and a dollar sign stays in.
    let d = one_file(
        b"url = https://example.com/docs\npath = /usr/share/doc/README\ncost = $5\n",
        0o644,
    );
    assert_eq!(d.resources.len(), 1, "{:?}", d.unsupported);
}

#[test]
fn a_failed_provenance_after_the_recipe_is_reported() {
    // N-3: the provenance path appears between the check and its
    // publication; the recipe stays and the error (exit 5) names both.
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let o = dir.path().join("r.yaml");
    let c = cfg(&[], &[]);
    let d = Discovery::default();
    check_outputs(&o).unwrap();
    std::fs::write(provenance_path(&o), "other").unwrap();
    let e = publish_files(&o, &render_yaml(&d, &c), &provenance(&d, &c)).unwrap_err();
    assert_eq!(e.kind, crate::error::ErrorKind::Apply);
    assert!(
        e.message.contains("was written, but its provenance"),
        "{}",
        e.message
    );
    assert!(o.exists());
    assert_eq!(
        std::fs::read_to_string(provenance_path(&o)).unwrap(),
        "other"
    );
}

#[test]
fn host_labels_are_never_addresses() {
    // N-4.
    assert_eq!(host_label("web01", "192.0.2.10"), "web01");
    assert_eq!(host_label("192.0.2.10", "192.0.2.10"), "inventory-host");
    assert_eq!(host_label("192.0.2.10", "web.example"), "inventory-host");
    assert_eq!(host_label("2001:db8::1", "x"), "inventory-host");
    assert_eq!(host_label("db.example", "db.example"), "inventory-host");
}
