//! CLI surface of Resource Plugins (DESIGN §38.7): `--plugin-root`, the
//! default root, and fail-closed loading. No host is contacted: every case
//! is `validate`, or a plan whose recipe is refused before connecting.

use std::path::Path;
use std::process::{Command, Output};

const PLUGIN_RECIPE: &str = "version: 1\nplugins:\n  - { id: firewalld, version: 0.1.0 }\nresources:\n  - id: a\n    type: firewalld.service\n    with: { zone: public, service: http, state: present }\n";
const PLAIN_RECIPE: &str = "version: 1\nresources:\n  - id: f\n    type: file\n    with: { path: /tmp/sinter-plugin-cli-never-written, content: x }\n";

fn sinter(args: &[&str], home: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(args)
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn a_recipe_without_plugins_ignores_the_plugin_root() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLAIN_RECIPE).unwrap();
    let missing = d.path().join("no-such-root");
    let o = sinter(
        &[
            "validate",
            r.to_str().unwrap(),
            "--plugin-root",
            missing.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(!missing.exists());
}

#[test]
fn an_explicit_plugin_root_that_does_not_exist_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLUGIN_RECIPE).unwrap();
    let missing = d.path().join("no-such-root");
    let o = sinter(
        &[
            "validate",
            r.to_str().unwrap(),
            "--plugin-root",
            missing.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(
        text(&o).contains("cannot resolve the plugin root"),
        "{}",
        text(&o)
    );
}

#[test]
fn the_default_root_is_under_home_and_is_refused_when_absent() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLUGIN_RECIPE).unwrap();
    let o = sinter(&["validate", r.to_str().unwrap()], d.path());
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains(".config/sinter/plugins"), "{}", text(&o));
}

#[test]
fn a_plan_with_an_unusable_plugin_is_refused_before_connecting() {
    // The default target is localhost; nothing may run because the recipe
    // is refused while it is loaded (exit 2, no target contact).
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLUGIN_RECIPE).unwrap();
    let missing = d.path().join("no-such-root");
    let o = sinter(
        &[
            "plan",
            r.to_str().unwrap(),
            "--plugin-root",
            missing.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(!text(&o).contains("== Sinter PLAN =="), "{}", text(&o));
}

#[test]
fn a_root_without_the_attested_catalog_is_refused() {
    // A protected plugin root (user-owned, 0700) whose catalog is not the
    // attested first-party file and that has no trust file: the recipe is
    // refused (exit 2) before anything runs.
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("plugins");
    for sub in ["", "catalogs", "plugins"] {
        let p = root.join(sub);
        std::fs::create_dir_all(&p).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let catalog = "format = 1\nid = \"firewalld\"\nversion = \"0.1.0\"\n\n[[op]]\nid = \"state\"\nclass = \"observe\"\nprogram = \"/usr/bin/firewall-cmd\"\nargv = [\"--state\"]\ntimeout_secs = 30\nexit = { \"0\" = \"running\" }\n";
    std::fs::write(root.join("catalogs/firewalld-0.1.0.catalog.toml"), catalog).unwrap();
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLUGIN_RECIPE).unwrap();
    let o = sinter(
        &[
            "validate",
            r.to_str().unwrap(),
            "--plugin-root",
            root.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("plugin:"), "{}", text(&o));
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{:02x}", x))
        .collect()
}

/// A plugin root holding the repository's first-party files and an Owner
/// trust file that pins them, all user-owned and not writable by others.
fn first_party_root(d: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins/first-party");
    let root = d.join("plugins");
    for sub in ["", "catalogs", "plugins"] {
        let p = root.join(sub);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for f in [
        "catalogs/firewalld-0.1.0.catalog.toml",
        "plugins/firewalld-0.1.0.plugin.toml",
    ] {
        std::fs::write(root.join(f), std::fs::read(repo.join(f)).unwrap()).unwrap();
        std::fs::set_permissions(root.join(f), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let trust = "format = 1\n\n[[catalog]]\nid = \"firewalld\"\nversion = \"0.1.0\"\nsha256 = \"27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff\"\nattested_observe = [\"state\", \"zone_defined\", \"service_defined\", \"query_service_runtime\", \"query_service_permanent\"]\nallowed_mutate = [\"add_service_runtime\", \"add_service_permanent\"]\n\n[[plugin]]\nid = \"firewalld\"\nversion = \"0.1.0\"\nsha256 = \"47f33f171d239103cbb97450d17b57c857ce22436620ddf809fdd2be94948544\"\n";
    std::fs::write(root.join("trust.toml"), trust).unwrap();
    std::fs::set_permissions(
        root.join("trust.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    root
}

/// Whether every ancestor of `p` is owned by root or by us and not writable
/// by group or other, unless sticky (DESIGN §38.5). Where the temporary
/// directory does not meet this, the production loader refuses any root
/// below it, and the positive case cannot be shown there.
fn ancestors_trusted(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let me = unsafe { libc::geteuid() };
    let p = std::fs::canonicalize(p).unwrap();
    p.ancestors().skip(1).all(|a| {
        let m = std::fs::metadata(a).unwrap();
        (m.uid() == 0 || m.uid() == me) && (m.mode() & 0o022 == 0 || m.mode() & 0o1000 != 0)
    })
}

#[test]
fn the_release_binary_accepts_the_attested_first_party_files() {
    // The release registry admits the repository's catalog: `validate` of a
    // plugin recipe succeeds and contacts no host.
    let d = tempfile::tempdir().unwrap();
    let root = first_party_root(d.path());
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLUGIN_RECIPE).unwrap();
    let o = sinter(
        &[
            "validate",
            r.to_str().unwrap(),
            "--plugin-root",
            root.to_str().unwrap(),
        ],
        d.path(),
    );
    assert!(
        !text(&o).contains("not a reviewed first-party catalog"),
        "{}",
        text(&o)
    );
    if ancestors_trusted(&root) {
        assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    } else {
        assert_eq!(o.status.code(), Some(2), "{}", text(&o));
        eprintln!(
            "temporary directory ancestors are not trusted here: {}",
            text(&o)
        );
    }
}

#[test]
fn the_release_binary_refuses_the_attested_files_with_one_byte_changed() {
    let d = tempfile::tempdir().unwrap();
    let root = first_party_root(d.path());
    let c = root.join("catalogs/firewalld-0.1.0.catalog.toml");
    let mut b = std::fs::read(&c).unwrap();
    b.extend_from_slice(b"# edited\n");
    std::fs::write(&c, &b).unwrap();
    // The Owner pins the edited bytes: the release registry still refuses.
    let t = root.join("trust.toml");
    let pinned = std::fs::read_to_string(&t).unwrap().replace(
        "27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff",
        &sha256_hex(&b),
    );
    std::fs::write(&t, pinned).unwrap();
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLUGIN_RECIPE).unwrap();
    let o = sinter(
        &[
            "validate",
            r.to_str().unwrap(),
            "--plugin-root",
            root.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("plugin:"), "{}", text(&o));
    if ancestors_trusted(&root) {
        assert!(
            text(&o).contains("not a reviewed first-party catalog"),
            "{}",
            text(&o)
        );
    }
}

// ---------------------------------------------------------------------------
// `sinter plugin list` and `sinter plugin verify` (DESIGN §38.15): read-only
// reports. No host is contacted and no recipe is read.
// ---------------------------------------------------------------------------

fn json_of(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not one JSON document ({}): {}",
            e,
            String::from_utf8_lossy(&o.stdout)
        )
    })
}

#[test]
fn plugin_list_without_a_root_shows_the_embedded_plugins_as_json() {
    let d = tempfile::tempdir().unwrap();
    let missing = d.path().join("no-such-root");
    let o = sinter(
        &[
            "plugin",
            "list",
            "--json",
            "--plugin-root",
            missing.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(o.stderr.is_empty(), "{}", text(&o));
    let j = json_of(&o);
    assert_eq!(j["root"], "absent");
    let plugins = j["plugins"].as_array().unwrap();
    let names: Vec<String> = plugins
        .iter()
        .map(|p| {
            format!(
                "{}@{}",
                p["id"].as_str().unwrap(),
                p["version"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(names, ["firewalld@0.1.0", "firewalld@0.2.0"]);
    assert!(plugins
        .iter()
        .all(|p| p["available"] == true && p["installed"] == false && p["status"] == "available"));
    assert!(!missing.exists());
}

#[test]
fn plugin_list_uses_the_default_root_and_prints_a_table() {
    let d = tempfile::tempdir().unwrap();
    let o = sinter(&["plugin", "list"], d.path());
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains(".config/sinter/plugins"), "{}", out);
    assert!(out.contains("ID"), "{}", out);
    assert!(out.contains("STATUS"), "{}", out);
    assert!(out.contains("firewalld"), "{}", out);
    assert!(!d.path().join(".config").exists());
}

#[test]
fn plugin_verify_with_nothing_installed_is_not_a_success() {
    let d = tempfile::tempdir().unwrap();
    let missing = d.path().join("no-such-root");
    let o = sinter(
        &[
            "plugin",
            "verify",
            "--json",
            "--plugin-root",
            missing.to_str().unwrap(),
        ],
        d.path(),
    );
    // Nothing verified is exit 2 (DESIGN §38.15); stdout stays one JSON
    // document and the reason goes to standard error.
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let j = json_of(&o);
    assert_eq!(j["ok"], false);
    assert_eq!(j["nothing_verified"], "root-absent");
    assert_eq!(j["plugins"], serde_json::json!([]));
    assert!(String::from_utf8_lossy(&o.stderr).contains("no plugin verified (root-absent)"));
    // A named plugin that is not installed fails, and stdout stays JSON.
    let o = sinter(
        &[
            "plugin",
            "verify",
            "firewalld@0.2.0",
            "--json",
            "--plugin-root",
            missing.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert_eq!(json_of(&o)["plugins"][0]["status"], "not-installed");
}

#[test]
fn plugin_verify_keeps_errors_on_stderr_and_json_on_stdout() {
    let d = tempfile::tempdir().unwrap();
    let root = first_party_root(d.path());
    std::fs::write(
        root.join("trust.toml"),
        "format = 1\n[[plugin]]\nid = \"x\"\n",
    )
    .unwrap();
    let o = sinter(
        &[
            "plugin",
            "verify",
            "--json",
            "--plugin-root",
            root.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let j = json_of(&o);
    assert_eq!(j["ok"], false);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("plugin:"), "{}", err);
    assert!(!String::from_utf8_lossy(&o.stdout).contains("sinter:"));
    if ancestors_trusted(&root) {
        assert_eq!(j["trust"], "invalid");
    } else {
        assert_eq!(j["root"], "refused");
    }
}

#[test]
fn plugin_list_and_verify_accept_the_installed_first_party_files() {
    let d = tempfile::tempdir().unwrap();
    let root = first_party_root(d.path());
    let r = root.to_str().unwrap();
    let l = sinter(&["plugin", "list", "--json", "--plugin-root", r], d.path());
    let v = sinter(
        &["plugin", "verify", "--json", "--plugin-root", r],
        d.path(),
    );
    let vt = sinter(
        &["plugin", "verify", "firewalld@0.1.0", "--plugin-root", r],
        d.path(),
    );
    if !ancestors_trusted(&root) {
        assert_eq!(l.status.code(), Some(2), "{}", text(&l));
        eprintln!(
            "temporary directory ancestors are not trusted here: {}",
            text(&l)
        );
        return;
    }
    assert_eq!(l.status.code(), Some(0), "{}", text(&l));
    let lj = json_of(&l);
    assert_eq!(lj["plugins"][0]["status"], "installed");
    assert_eq!(lj["plugins"][0]["mutate_allowed"], 2);
    assert_eq!(lj["plugins"][1]["status"], "available");
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let vj = json_of(&v);
    assert_eq!(vj["ok"], true);
    assert_eq!(vj["plugins"].as_array().unwrap().len(), 1);
    assert_eq!(vj["plugins"][0]["status"], "ok");
    assert_eq!(vt.status.code(), Some(0), "{}", text(&vt));
    let out = String::from_utf8_lossy(&vt.stdout);
    assert!(out.contains("firewalld@0.1.0: ok"), "{}", out);
    assert!(out.contains("Result: OK"), "{}", out);
}

#[test]
fn plugin_verify_refuses_a_malformed_plugin_name() {
    let d = tempfile::tempdir().unwrap();
    let o = sinter(&["plugin", "verify", "firewalld", "--json"], d.path());
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(o.stdout.is_empty(), "{}", text(&o));
    assert!(String::from_utf8_lossy(&o.stderr).contains("ID@VERSION"));
}

#[test]
fn plugin_management_is_not_an_mcp_tool() {
    assert!(
        sinter::mcp::tool_names()
            .iter()
            .all(|n| !n.contains("plugin")),
        "{:?}",
        sinter::mcp::tool_names()
    );
}

/// [`first_party_root`] with a trust file that attests every observe
/// operation of firewalld 0.1.0 and allows only `mutate`.
fn first_party_root_allowing(d: &Path, mutate: &str) -> std::path::PathBuf {
    let root = first_party_root(d);
    let trust = std::fs::read_to_string(root.join("trust.toml")).unwrap();
    let trust = trust.replace(
        "allowed_mutate = [\"add_service_runtime\", \"add_service_permanent\"]",
        &format!("allowed_mutate = {}", mutate),
    );
    assert!(trust.contains(&format!("allowed_mutate = {}", mutate)));
    std::fs::write(root.join("trust.toml"), trust).unwrap();
    root
}

const C1_GATE: &str = "plan and apply refuse it before contacting any target";

#[test]
fn plan_and_apply_refuse_an_observe_only_plugin_before_contacting_a_target() {
    // C1: the trust file allows no mutate operation. The plugin loads
    // (validate succeeds), plan and apply are refused with exit 2 before any
    // connection (the host name cannot resolve, so reaching it would be a
    // connection error, exit 3), and audit is not refused by the gate.
    let d = tempfile::tempdir().unwrap();
    let root = first_party_root_allowing(d.path(), "[]");
    if !ancestors_trusted(&root) {
        eprintln!("temporary directory ancestors are not trusted here; skipped");
        return;
    }
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLUGIN_RECIPE).unwrap();
    let rs = r.to_str().unwrap();
    let rootp = root.to_str().unwrap();
    let o = sinter(&["validate", rs, "--plugin-root", rootp], d.path());
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    for phase in ["plan", "apply"] {
        let o = sinter(
            &[
                phase,
                rs,
                "--plugin-root",
                rootp,
                "--host",
                "c1-gate-check.invalid",
                "--no-ssh-config",
            ],
            d.path(),
        );
        assert_eq!(o.status.code(), Some(2), "{}: {}", phase, text(&o));
        assert!(text(&o).contains(C1_GATE), "{}: {}", phase, text(&o));
        assert!(
            text(&o).contains("add_service_permanent, add_service_runtime"),
            "{}",
            text(&o)
        );
    }
    let o = sinter(
        &[
            "audit",
            rs,
            "--plugin-root",
            rootp,
            "--host",
            "c1-gate-check.invalid",
            "--no-ssh-config",
        ],
        d.path(),
    );
    assert!(!text(&o).contains(C1_GATE), "{}", text(&o));
    assert_ne!(o.status.code(), Some(2), "{}", text(&o));
}

#[test]
fn a_bundle_is_refused_as_a_whole_before_its_first_recipe_runs() {
    // The first recipe needs no plugin; the second could need a mutate
    // operation that is not allowed. The whole run is refused before the
    // first recipe connects (exit 2, not a connection error).
    let d = tempfile::tempdir().unwrap();
    let root = first_party_root_allowing(d.path(), "[\"add_service_runtime\"]");
    if !ancestors_trusted(&root) {
        eprintln!("temporary directory ancestors are not trusted here; skipped");
        return;
    }
    std::fs::write(d.path().join("plain.yml"), PLAIN_RECIPE).unwrap();
    std::fs::write(d.path().join("fw.yml"), PLUGIN_RECIPE).unwrap();
    let b = d.path().join("b.yml");
    std::fs::write(&b, "version: 1\nrecipes: [plain.yml, fw.yml]\n").unwrap();
    let o = sinter(
        &[
            "apply",
            b.to_str().unwrap(),
            "--plugin-root",
            root.to_str().unwrap(),
            "--host",
            "c1-gate-check.invalid",
            "--no-ssh-config",
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains(C1_GATE), "{}", text(&o));
    assert!(text(&o).contains("add_service_permanent"), "{}", text(&o));
    assert!(!text(&o).contains("add_service_runtime,"), "{}", text(&o));
    assert!(!Path::new("/tmp/sinter-plugin-cli-never-written").exists());
}

/// A loopback listener that only counts connections: a host pointed at it
/// shows whether anything contacted it.
struct CountingListener(std::net::TcpListener);

impl CountingListener {
    fn new() -> Self {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        CountingListener(l)
    }
    fn port(&self) -> u16 {
        self.0.local_addr().unwrap().port()
    }
    fn accepted(&self) -> usize {
        let mut n = 0;
        while self.0.accept().is_ok() {
            n += 1;
        }
        n
    }
}

/// `sinter` with a scripted `ssh` first on PATH that records every call
/// (`ssh -G` resolution) and resolves nothing.
fn sinter_recording_ssh(args: &[&str], d: &Path) -> (Output, usize) {
    use std::os::unix::fs::PermissionsExt;
    let bin = d.join("fakebin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = d.join("ssh.log");
    let ssh = bin.join("ssh");
    std::fs::write(
        &ssh,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf 'hostname 127.0.0.1\\n'\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(args)
        .current_dir(d)
        .env("HOME", d)
        .env_remove("XDG_CONFIG_HOME")
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .unwrap();
    let calls = std::fs::read_to_string(&log)
        .map(|s| s.lines().count())
        .unwrap_or(0);
    (o, calls)
}

fn two_host_inventory(d: &Path, port: u16) -> String {
    let kh = d.join("known_hosts");
    std::fs::write(&kh, "").unwrap();
    let p = d.join("hosts.yaml");
    std::fs::write(
        &p,
        format!(
            "hosts:\n  web01:\n    address: 127.0.0.1\n    port: {port}\n    user: u\n    known_hosts: {kh}\n  web02:\n    address: 127.0.0.1\n    port: {port}\n    user: u\n    known_hosts: {kh}\ngroups:\n  web:\n    hosts: [web01, web02]\n",
            kh = kh.display()
        ),
    )
    .unwrap();
    p.display().to_string()
}

#[test]
fn an_inventory_run_is_refused_before_resolving_or_contacting_any_host() {
    // Two hosts, observe-only trust: plan and apply stop with exit 2 before
    // `ssh -G` runs for any host and before anything connects.
    let d = tempfile::tempdir().unwrap();
    let root = first_party_root_allowing(d.path(), "[]");
    if !ancestors_trusted(&root) {
        eprintln!("temporary directory ancestors are not trusted here; skipped");
        return;
    }
    let listener = CountingListener::new();
    let inv = two_host_inventory(d.path(), listener.port());
    let r = d.path().join("r.yml");
    std::fs::write(
        &r,
        "version: 1\ntargets:\n  groups: [web]\nplugins:\n  - { id: firewalld, version: 0.1.0 }\nresources:\n  - id: a\n    type: firewalld.service\n    with: { zone: public, service: http, state: present }\n",
    )
    .unwrap();
    for phase in ["plan", "apply"] {
        let (o, calls) = sinter_recording_ssh(
            &[
                phase,
                r.to_str().unwrap(),
                "--inventory",
                &inv,
                "--plugin-root",
                root.to_str().unwrap(),
            ],
            d.path(),
        );
        assert_eq!(o.status.code(), Some(2), "{}: {}", phase, text(&o));
        assert!(text(&o).contains(C1_GATE), "{}: {}", phase, text(&o));
        assert_eq!(calls, 0, "{}: ssh -G ran", phase);
        assert_eq!(listener.accepted(), 0, "{}: a host was contacted", phase);
    }
}

#[test]
fn a_variables_file_run_checks_every_host_model_before_contacting_any() {
    // The wanted state comes from a variable, so every value of the field
    // counts: with only the add operations allowed, the run is refused for
    // both hosts before anything is resolved or contacted.
    let d = tempfile::tempdir().unwrap();
    let root = first_party_root_allowing(d.path(), "[\"add_service_runtime\"]");
    if !ancestors_trusted(&root) {
        eprintln!("temporary directory ancestors are not trusted here; skipped");
        return;
    }
    let listener = CountingListener::new();
    let inv = two_host_inventory(d.path(), listener.port());
    let r = d.path().join("r.yml");
    std::fs::write(
        &r,
        "version: 1\ntargets:\n  groups: [web]\nvars:\n  svc: { value: http }\nplugins:\n  - { id: firewalld, version: 0.1.0 }\nresources:\n  - id: a\n    type: firewalld.service\n    with: { zone: public, service: \"{{ vars.svc }}\", state: present }\n",
    )
    .unwrap();
    let v = d.path().join("v.yaml");
    std::fs::write(
        &v,
        "version: 1\nhosts:\n  web01: { svc: http }\n  web02: { svc: https }\n",
    )
    .unwrap();
    for phase in ["plan", "apply"] {
        let (o, calls) = sinter_recording_ssh(
            &[
                phase,
                r.to_str().unwrap(),
                "--inventory",
                &inv,
                "--vars-file",
                v.to_str().unwrap(),
                "--plugin-root",
                root.to_str().unwrap(),
            ],
            d.path(),
        );
        assert_eq!(o.status.code(), Some(2), "{}: {}", phase, text(&o));
        assert!(text(&o).contains(C1_GATE), "{}: {}", phase, text(&o));
        assert!(text(&o).contains("add_service_permanent"), "{}", text(&o));
        assert_eq!(calls, 0, "{}: ssh -G ran", phase);
        assert_eq!(listener.accepted(), 0, "{}: a host was contacted", phase);
    }
}

#[test]
fn a_limited_or_selected_run_is_refused_before_resolving_or_contacting_any_host() {
    // `--limit` and a selector argument take their own static path
    // (`limit_source`); the gate stops plan and apply there too, before
    // `ssh -G` and before anything connects.
    let d = tempfile::tempdir().unwrap();
    let root = first_party_root_allowing(d.path(), "[]");
    if !ancestors_trusted(&root) {
        eprintln!("temporary directory ancestors are not trusted here; skipped");
        return;
    }
    let listener = CountingListener::new();
    let inv = two_host_inventory(d.path(), listener.port());
    let r = d.path().join("r.yml");
    std::fs::write(
        &r,
        "version: 1\ntargets:\n  groups: [web]\nplugins:\n  - { id: firewalld, version: 0.1.0 }\nresources:\n  - id: a\n    type: firewalld.service\n    with: { zone: public, service: http, state: present }\n",
    )
    .unwrap();
    let rs = r.to_str().unwrap();
    let rootp = root.to_str().unwrap();
    for phase in ["plan", "apply"] {
        for args in [
            vec![
                phase,
                rs,
                "--inventory",
                &inv,
                "--limit",
                "web01",
                "--plugin-root",
                rootp,
            ],
            vec![
                phase,
                rs,
                "web01,web02",
                "--inventory",
                &inv,
                "--plugin-root",
                rootp,
            ],
        ] {
            let (o, calls) = sinter_recording_ssh(&args, d.path());
            assert_eq!(o.status.code(), Some(2), "{:?}: {}", args, text(&o));
            assert!(text(&o).contains(C1_GATE), "{:?}: {}", args, text(&o));
            assert_eq!(calls, 0, "{:?}: ssh -G ran", args);
            assert_eq!(listener.accepted(), 0, "{:?}: a host was contacted", args);
        }
    }
}
