//! CLI surface of `--limit` (DESIGN §19.2).
//!
//! No test needs a reachable host. Inventory hosts point at listeners this
//! test owns (to prove that an excluded host is never contacted) or at closed
//! loopback ports (to observe which executions were attempted). `ssh -G` is a
//! scripted `ssh` on PATH that records every call, so the tests can tell
//! which hosts had their SSH configuration evaluated.

mod common;

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};

/// A fictitious value that must never be printed.
const CANARY: &str = "SINTER_LIMIT_CANARY_DO_NOT_PRINT_20261020";

struct Fx {
    dir: tempfile::TempDir,
}

impl Fx {
    fn new() -> Self {
        let f = Fx {
            dir: tempfile::tempdir().unwrap(),
        };
        let bin = f.path("fakebin");
        std::fs::create_dir_all(&bin).unwrap();
        let p = bin.join("ssh");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf 'hostname 127.0.0.1\\n'\n",
                f.path("ssh.log").display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        f
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, body: &str) -> String {
        let p = self.path(name);
        std::fs::write(&p, body).unwrap();
        p.display().to_string()
    }

    /// Inventory: web01, web02 (group web), db01 (group db), ops = web01+db01.
    fn inventory(&self, ports: [u16; 3]) -> String {
        let kh = self.write("known_hosts", "");
        let host = |name: &str, port: u16| {
            format!(
                "  {name}:\n    address: 127.0.0.1\n    port: {port}\n    user: u\n    known_hosts: {kh}\n"
            )
        };
        self.write(
            "hosts.yaml",
            &format!(
                "hosts:\n{}{}{}groups:\n  web:\n    hosts: [web01, web02]\n  db:\n    hosts: [db01]\n  ops:\n    hosts: [web01, db01]\n",
                host("web01", ports[0]),
                host("web02", ports[1]),
                host("db01", ports[2]),
            ),
        )
    }

    /// The lines `ssh -G` was called with.
    fn ssh_log(&self) -> Vec<String> {
        std::fs::read_to_string(self.path("ssh.log"))
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sinter"))
            .args(args)
            .current_dir(self.dir.path())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.path("fakebin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("NO_COLOR", "1")
            .env("SINTER_PROGRESS", "never")
            .output()
            .unwrap()
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o.stdout)))
}

/// A listener counting connection attempts.
struct Listener(TcpListener);

impl Listener {
    fn new() -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        Listener(l)
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

/// Every file under `dir` (relative path, content), sorted, without the
/// `ssh -G` log (which is how the tests observe `ssh`).
fn snapshot(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                let rel = p.strip_prefix(base).unwrap().display().to_string();
                if rel != "ssh.log" {
                    out.push((rel, std::fs::read(&p).unwrap()));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Targets group `web`; `root` defaults to a valid path.
const WEB: &str = "version: 1\ntargets:\n  groups: [web]\nvars:\n  root: { value: /srv/default }\n  tok: { value: s, sensitive: true }\nresources:\n  - id: index\n    type: file\n    with: { path: \"{{ vars.root }}/index.html\", content: x }\n";
const DB: &str = "version: 1\ntargets:\n  groups: [db]\nresources:\n  - id: db\n    type: file\n    with: { path: /srv/db.conf, content: y }\n";

const PHASES: [&str; 3] = ["plan", "audit", "apply"];

fn executed(o: &Output) -> Vec<String> {
    json(o)["executions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["target"]["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn limit_attempts_only_the_selected_hosts_in_every_phase() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let r = f.write("r.yaml", WEB);
    let cases: &[(&str, &[&str])] = &[
        ("web01", &["web01"]),
        ("web02", &["web02"]),
        ("host:web02", &["web02"]),
        ("web01,web02", &["web01", "web02"]),
        ("web02,web01", &["web01", "web02"]),
        ("web", &["web01", "web02"]),
        ("group:web", &["web01", "web02"]),
        ("web0*", &["web01", "web02"]),
        ("*", &["web01", "web02"]),
        ("web01,web01", &["web01"]),
    ];
    for (limit, want) in cases {
        for phase in PHASES {
            let o = f.run(&[
                phase,
                &r,
                "--inventory",
                &inv,
                "--limit",
                limit,
                "--format",
                "json",
            ]);
            // Closed ports: every attempted execution fails to connect.
            assert_eq!(
                o.status.code(),
                Some(3),
                "{limit} {phase}: {}",
                text(&o.stderr)
            );
            assert_eq!(executed(&o), *want, "{limit} {phase}");
            let doc = json(&o);
            let hosts = doc["resolution"][0]["hosts"].as_array().unwrap();
            for h in hosts {
                let name = h["name"].as_str().unwrap();
                let targeted = name.starts_with("web");
                let selected = want.contains(&name);
                assert_eq!(h["selected"], selected, "{limit} {phase} {name}");
                assert_eq!(
                    h.get("excluded_by").is_some(),
                    targeted && !selected,
                    "{limit} {phase} {name}"
                );
                // Reasons are kept for an excluded host.
                assert_eq!(h["reasons"].as_array().unwrap().is_empty(), !targeted);
            }
        }
    }
}

#[test]
fn ssh_configuration_is_evaluated_for_the_selected_hosts_only() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let r = f.write("r.yaml", WEB);
    for phase in PHASES {
        let _ = std::fs::remove_file(f.path("ssh.log"));
        let o = f.run(&[phase, &r, "--inventory", &inv, "--limit", "web01"]);
        assert_eq!(o.status.code(), Some(3), "{phase}: {}", text(&o.stderr));
        let log = f.ssh_log();
        assert_eq!(log.len(), 1, "{phase}: {log:?}");
        let for_port = |p: u16| format!("-p {p} --");
        assert!(log[0].contains(&for_port(ports.port(0))), "{log:?}");
        for other in [1, 2] {
            assert!(
                !log.iter().any(|l| l.contains(&for_port(ports.port(other)))),
                "{phase}: ssh -G ran for a host --limit leaves out: {log:?}"
            );
        }
    }
    // An invalid --limit evaluates nothing at all.
    let _ = std::fs::remove_file(f.path("ssh.log"));
    for bad in ["nosuch", "db01", "web01,nosuch", "", "web01,"] {
        let o = f.run(&["plan", &r, "--inventory", &inv, "--limit", bad]);
        assert_eq!(o.status.code(), Some(2), "{bad:?}: {}", text(&o.stderr));
    }
    assert!(f.ssh_log().is_empty(), "ssh -G ran: {:?}", f.ssh_log());
    // Without --limit both targeted hosts are evaluated, as in v1.6.0.
    let o = f.run(&["plan", &r, "--inventory", &inv]);
    assert_eq!(o.status.code(), Some(3));
    assert_eq!(f.ssh_log().len(), 2);
    // --no-ssh-config: no evaluation, with or without --limit.
    let _ = std::fs::remove_file(f.path("ssh.log"));
    let o = f.run(&[
        "plan",
        &r,
        "--inventory",
        &inv,
        "--limit",
        "web01",
        "--no-ssh-config",
    ]);
    assert_eq!(o.status.code(), Some(3));
    assert!(f.ssh_log().is_empty());
}

#[test]
fn an_excluded_host_is_never_contacted_and_nothing_is_written() {
    let f = Fx::new();
    // The selected host refuses at once; the others listen, so any contact
    // with them is counted (and would hold the run up).
    let closed = common::ClosedPorts::reserve(1);
    let (l2, l3) = (Listener::new(), Listener::new());
    let inv = f.inventory([closed.port(0), l2.port(), l3.port()]);
    let r = f.write("r.yaml", WEB);
    let before = snapshot(f.dir.path());
    for phase in PHASES {
        let o = f.run(&[phase, &r, "--inventory", &inv, "--limit", "web01"]);
        // The selected host's port is closed: it fails to connect.
        assert_eq!(o.status.code(), Some(3), "{phase}: {}", text(&o.stderr));
    }
    assert_eq!(
        l2.accepted(),
        0,
        "web02 (excluded by --limit) was contacted"
    );
    assert_eq!(l3.accepted(), 0, "db01 (not targeted) was contacted");
    assert_eq!(snapshot(f.dir.path()), before, "a file changed");
    // A refused --limit contacts nobody.
    for bad in ["nosuch", "db01", "web01,nosuch"] {
        let o = f.run(&["apply", &r, "--inventory", &inv, "--limit", bad]);
        assert_eq!(o.status.code(), Some(2), "{bad}");
    }
    assert_eq!(l2.accepted() + l3.accepted(), 0);
}

#[test]
fn without_limit_the_output_and_behavior_are_those_of_v1_6_0() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let r = f.write("r.yaml", WEB);
    let o = f.run(&["plan", &r, "--inventory", &inv, "--no-ssh-config"]);
    assert_eq!(o.status.code(), Some(3));
    let out = text(&o.stdout);
    assert!(!out.contains("--limit"), "{out}");
    assert!(!out.contains("limit:"), "{out}");
    assert!(out.contains("db01   SKIP   no matching target"), "{out}");
    assert!(out.contains("selected 2, excluded 1\n"), "{out}");
    let o = f.run(&[
        "plan",
        &r,
        "--inventory",
        &inv,
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    let doc = json(&o);
    assert!(doc.get("limit").is_none());
    for h in doc["resolution"][0]["hosts"].as_array().unwrap() {
        assert!(h.get("excluded_by").is_none(), "{h}");
    }
    assert_eq!(executed(&o), ["web01", "web02"]);
}

#[test]
fn plan_audit_and_apply_agree_on_the_hosts() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let r = f.write("r.yaml", WEB);
    let v = f.write(
        "v.yaml",
        "version: 1\nhosts: { web01: { root: /srv/one }, web02: { root: /srv/two } }\n",
    );
    for limit in ["web01", "web", "web02,web01"] {
        let mut seen: Vec<(Vec<String>, serde_json::Value, serde_json::Value)> = Vec::new();
        for phase in PHASES {
            let o = f.run(&[
                phase,
                &r,
                "--inventory",
                &inv,
                "--vars-file",
                &v,
                "--limit",
                limit,
                "--no-ssh-config",
                "--format",
                "json",
            ]);
            assert_eq!(
                o.status.code(),
                Some(3),
                "{limit} {phase}: {}",
                text(&o.stderr)
            );
            let doc = json(&o);
            seen.push((
                executed(&o),
                doc["resolution"].clone(),
                doc["limit"].clone(),
            ));
        }
        assert!(seen.windows(2).all(|w| w[0] == w[1]), "{limit}: {seen:?}");
    }
}

#[test]
fn text_output_names_the_limit_and_what_it_left_out() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let r = f.write("r.yaml", WEB);
    let o = f.run(&[
        "plan",
        &r,
        "--inventory",
        &inv,
        "--limit",
        "web01",
        "--no-ssh-config",
    ]);
    let out = text(&o.stdout);
    assert!(out.contains("limit: web01\n"), "{out}");
    assert!(out.contains("web01  MATCH  group:web"), "{out}");
    assert!(
        out.contains("web02  SKIP   excluded by --limit (matched: group:web)"),
        "{out}"
    );
    assert!(out.contains("db01   SKIP   no matching target"), "{out}");
    assert!(
        out.contains("selected 1, excluded 2 (1 by --limit)"),
        "{out}"
    );
    assert!(
        out.contains("executions: 1 (1 recipe(s), 3 host(s))"),
        "{out}"
    );
}

#[test]
fn limit_is_refused_without_an_inventory_and_with_host() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let r = f.write("r.yaml", WEB);
    let plain = f.write("plain.yaml", "version: 1\nresources: []\n");
    let cases: Vec<Vec<&str>> = vec![
        vec![&plain, "--limit", "web01"],
        vec![&plain, "--host", "h", "--limit", "web01"],
        vec![&r, "--host", "h", "--inventory", &inv, "--limit", "web01"],
        vec![&r, "--inventory", &inv, "--limit", "a", "--limit", "b"],
    ];
    for phase in PHASES {
        for args in &cases {
            let o = f.run(&[&[phase], &args[..]].concat());
            assert_eq!(
                o.status.code(),
                Some(2),
                "{phase} {args:?}: {}",
                text(&o.stderr)
            );
            assert!(o.stdout.is_empty(), "{phase} {args:?}");
        }
    }
    assert!(f.ssh_log().is_empty());
}

#[test]
fn a_name_that_is_a_host_and_a_group_must_be_spelled_out() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let kh = f.write("known_hosts", "");
    let host = |name: &str, port: u16| {
        format!("  {name}:\n    address: 127.0.0.1\n    port: {port}\n    user: u\n    known_hosts: {kh}\n")
    };
    let inv = f.write(
        "amb.yaml",
        &format!(
            "hosts:\n{}{}{}groups:\n  web:\n    hosts: [web01, web02]\n",
            host("web", ports.port(0)),
            host("web01", ports.port(1)),
            host("web02", ports.port(2)),
        ),
    );
    let r = f.write(
        "r.yaml",
        "version: 1\ntargets:\n  hosts: [web]\n  groups: [web]\nresources:\n  - id: f\n    type: file\n    with: { path: /srv/f, content: x }\n",
    );
    let o = f.run(&[
        "plan",
        &r,
        "--inventory",
        &inv,
        "--limit",
        "web",
        "--no-ssh-config",
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        text(&o.stderr).contains("both a host and a group"),
        "{}",
        text(&o.stderr)
    );
    for (limit, want) in [
        ("host:web", vec!["web", "web01", "web02"][..1].to_vec()),
        ("group:web", vec!["web01", "web02"]),
    ] {
        let o = f.run(&[
            "plan",
            &r,
            "--inventory",
            &inv,
            "--limit",
            limit,
            "--no-ssh-config",
            "--format",
            "json",
        ]);
        assert_eq!(o.status.code(), Some(3), "{limit}: {}", text(&o.stderr));
        assert_eq!(executed(&o), want, "{limit}");
    }
}

#[test]
fn inventory_errors_stop_before_any_limit_is_applied() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let r = f.write("r.yaml", WEB);
    let kh = f.write("known_hosts", "");
    let good = format!(
        "hosts:\n  web01:\n    address: 127.0.0.1\n    port: {}\n    user: u\n    known_hosts: {kh}\n",
        ports.port(0)
    );
    for (what, body) in [
        ("syntax", format!("{good}  web02: [\n")),
        (
            "unknown member",
            format!("{good}groups:\n  web:\n    hosts: [web01, nosuch]\n"),
        ),
        (
            "empty group",
            format!("{good}groups:\n  web:\n    hosts: []\n"),
        ),
        (
            "duplicate member",
            format!("{good}groups:\n  web:\n    hosts: [web01, web01]\n"),
        ),
        ("bad host name", format!("{good}  \"bad/name\": {{}}\n")),
    ] {
        let inv = f.write("bad.yaml", &body);
        for limit in ["web01", "web", "nosuch"] {
            let o = f.run(&["plan", &r, "--inventory", &inv, "--limit", limit]);
            assert_eq!(o.status.code(), Some(2), "{what} {limit}");
            assert!(o.stdout.is_empty(), "{what}");
        }
    }
    assert!(f.ssh_log().is_empty());
}

// ---------------------------------------------------------------------------
// Variables files (DESIGN §3.5): structure is global, host-specific values are
// checked for the selected hosts only, and only with --limit.
// ---------------------------------------------------------------------------

#[test]
fn host_specific_variable_errors_of_unselected_hosts_do_not_stop_a_limited_run() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let r = f.write("r.yaml", WEB);
    // (body, passes with `--limit web01`, passes without `--limit`)
    let cases: &[(&str, bool, bool)] = &[
        ("hosts: { web02: { root: 5 } }", true, false),
        ("hosts: { db01: { root: 5 } }", true, false),
        ("hosts: { db01: { nope: 1 } }", true, false),
        ("groups: { db: { root: 5 } }", true, false),
        ("hosts: { web01: { root: 5 } }", false, false),
        ("groups: { web: { root: 5 } }", false, false),
        ("groups: { ops: { root: 5 } }", false, false),
        ("vars: { root: 5 }", false, false),
        ("hosts: { ghost: { root: /x } }", false, false),
        ("groups: { nosuch: { root: /x } }", false, false),
        ("hosts: { db01: { tok: t } }", false, false),
        ("groups: { db: { tok: t } }", false, false),
        ("vars: { tok: t }", false, false),
        // two groups of web01 disagree...
        (
            "groups: { web: { root: /b }, ops: { root: /c } }",
            false,
            false,
        ),
        // ...unless the host's own value decides
        (
            "hosts: { web01: { root: /a } }\ngroups: { web: { root: /b }, ops: { root: /c } }",
            true,
            true,
        ),
        (
            "hosts: { web01: { root: /a }, web02: { root: /d } }",
            true,
            true,
        ),
    ];
    for (body, limited, plain) in cases {
        let v = f.write("v.yaml", &format!("version: 1\n{body}\n"));
        for phase in PHASES {
            for (limit, ok) in [(Some("web01"), *limited), (None, *plain)] {
                let before = f.ssh_log().len();
                let mut args = vec![
                    phase,
                    &r,
                    "--inventory",
                    &inv,
                    "--vars-file",
                    &v,
                    "--no-ssh-config",
                ];
                if let Some(l) = limit {
                    args.extend(["--limit", l]);
                }
                let o = f.run(&args);
                let want = if ok { 3 } else { 2 };
                assert_eq!(
                    o.status.code(),
                    Some(want),
                    "{body} {phase} {limit:?}: {}",
                    text(&o.stderr)
                );
                assert_eq!(f.ssh_log().len(), before);
            }
        }
    }
}

#[test]
fn a_group_conflict_is_reported_only_for_a_selected_host_and_a_host_value_resolves_it() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let r = f.write("r.yaml", WEB);
    // web01 is in web and ops, which disagree.
    let v = f.write(
        "v.yaml",
        "version: 1\ngroups: { web: { root: /b }, ops: { root: /c } }\n",
    );
    let run = |limit: Option<&str>, vars: &str| {
        let mut args = vec![
            "plan",
            &r,
            "--inventory",
            &inv,
            "--vars-file",
            vars,
            "--no-ssh-config",
        ];
        if let Some(l) = limit {
            args.extend(["--limit", l]);
        }
        f.run(&args).status.code()
    };
    assert_eq!(run(None, &v), Some(2));
    assert_eq!(run(Some("web01"), &v), Some(2));
    assert_eq!(run(Some("web02"), &v), Some(3));
    let fixed = f.write(
        "fixed.yaml",
        "version: 1\ngroups: { web: { root: /b }, ops: { root: /c } }\nhosts: { web01: { root: /a } }\n",
    );
    assert_eq!(run(Some("web01"), &fixed), Some(3));
    assert_eq!(run(None, &fixed), Some(3));
}

#[test]
fn a_variable_error_never_prints_the_value_with_or_without_limit() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let r = f.write("r.yaml", WEB);
    for body in [
        format!("hosts: {{ web01: {{ root: [\"{CANARY}\"] }} }}"),
        format!("hosts: {{ web01: {{ root: \"rel/{CANARY}\" }} }}"),
        format!("hosts: {{ db01: {{ tok: \"{CANARY}\" }} }}"),
        format!("vars: {{ tok: \"{CANARY}\" }}"),
        format!("hosts: {{ web01: {{ root: \"{CANARY}\n"),
    ] {
        let v = f.write("v.yaml", &format!("version: 1\n{body}\n"));
        for limit in [None, Some("web01"), Some("web02")] {
            for phase in ["plan", "validate"] {
                let mut args = vec![phase, &r, "--inventory", &inv, "--vars-file", &v];
                if let Some(l) = limit {
                    args.extend(["--limit", l]);
                }
                for format in ["text", "json"] {
                    let mut a = args.clone();
                    a.extend(["--format", format, "--no-ssh-config"]);
                    let o = f.run(&a);
                    let (out, err) = (text(&o.stdout), text(&o.stderr));
                    assert!(
                        !out.contains(CANARY) && !err.contains(CANARY),
                        "LEAK {body} {phase} {limit:?} {format}"
                    );
                }
            }
        }
    }
}

#[test]
fn a_hostile_limit_is_refused_and_printed_safely() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let r = f.write("r.yaml", WEB);
    let marker = f.path("pwned").display().to_string();
    let hostile = [
        format!("$(touch {marker})"),
        format!("`touch {marker}`"),
        format!("web01;touch {marker}"),
        "web01\u{1b}[31mred".to_string(),
        "web01\nweb02".to_string(),
        "web01 web02".to_string(),
        "../web01".to_string(),
        "web[01]".to_string(),
        "-web".to_string(),
        "host:group:web".to_string(),
        "x".repeat(65),
        vec!["a"; 257].join(","),
    ];
    for h in &hostile {
        let o = f.run(&["plan", &r, "--inventory", &inv, "--limit", h]);
        assert_eq!(o.status.code(), Some(2), "{h:?}: {}", text(&o.stderr));
        assert!(
            !text(&o.stderr).contains('\u{1b}'),
            "an escape reached the terminal: {h:?}"
        );
        assert!(o.stdout.is_empty());
    }
    assert!(!f.path("pwned").exists());
    assert!(f.ssh_log().is_empty());
}

// ---------------------------------------------------------------------------
// validate --vars-file --limit
// ---------------------------------------------------------------------------

#[test]
fn validate_with_a_limit_checks_the_selected_hosts_only() {
    let f = Fx::new();
    let listeners = (Listener::new(), Listener::new(), Listener::new());
    let inv = f.inventory([listeners.0.port(), listeners.1.port(), listeners.2.port()]);
    let r = f.write("r.yaml", WEB);
    let bad = f.write("bad.yaml", "version: 1\nhosts: { web02: { root: 5 } }\n");
    let good = f.write("good.yaml", "version: 1\nhosts: { web01: { root: /a } }\n");
    let before = snapshot(f.dir.path());
    let v = |args: &[&str]| f.run(&[&["validate"], args].concat());
    // web02's value is wrong: validate fails without --limit, passes for web01.
    let o = v(&[&r, "--inventory", &inv, "--vars-file", &bad]);
    assert_eq!(o.status.code(), Some(2));
    let o = v(&[
        &r,
        "--inventory",
        &inv,
        "--vars-file",
        &bad,
        "--limit",
        "web01",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).contains("ok: --limit web01 selects 1 of 2 execution(s)"),
        "{}",
        text(&o.stdout)
    );
    let o = v(&[
        &r,
        "--inventory",
        &inv,
        "--vars-file",
        &bad,
        "--limit",
        "web02",
    ]);
    assert_eq!(o.status.code(), Some(2));
    // JSON.
    let o = v(&[
        &r,
        "--inventory",
        &inv,
        "--vars-file",
        &good,
        "--limit",
        "web01",
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(0));
    let doc = json(&o);
    assert_eq!(doc["limit"], serde_json::json!(["web01"]));
    assert_eq!(doc["variables"]["executions"], 1);
    assert_eq!(doc["variables"]["targeted_executions"], 2);
    let o = v(&[
        &r,
        "--inventory",
        &inv,
        "--vars-file",
        &good,
        "--format",
        "json",
    ]);
    let doc = json(&o);
    assert!(doc.get("limit").is_none());
    assert!(doc["variables"].get("targeted_executions").is_none());
    assert_eq!(doc["variables"]["executions"], 2);
    // Unresolvable limits and a missing inventory are refused.
    for args in [
        vec![
            &r[..],
            "--inventory",
            &inv,
            "--vars-file",
            &good,
            "--limit",
            "nosuch",
        ],
        vec![
            &r[..],
            "--inventory",
            &inv,
            "--vars-file",
            &good,
            "--limit",
            "db01",
        ],
        vec![&r[..], "--vars-file", &good, "--limit", "web01"],
        vec![
            &r[..],
            "--host",
            "h",
            "--inventory",
            &inv,
            "--vars-file",
            &good,
            "--limit",
            "web01",
        ],
    ] {
        let o = v(&args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", text(&o.stderr));
    }
    // validate never connects, never evaluates ssh, never writes.
    assert!(f.ssh_log().is_empty());
    assert_eq!(
        listeners.0.accepted() + listeners.1.accepted() + listeners.2.accepted(),
        0
    );
    assert!(snapshot(f.dir.path()) == before, "a file changed");
}

#[test]
fn validate_without_a_variables_file_does_not_look_at_the_inventory() {
    let f = Fx::new();
    let r = f.write("r.yaml", WEB.replace("CHANGE_ME", "x").as_str());
    let o = f.run(&["validate", &r]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let o = f.run(&["validate", &r, "--format", "json"]);
    assert!(json(&o).get("limit").is_none());
}

// ---------------------------------------------------------------------------
// Bundles
// ---------------------------------------------------------------------------

#[test]
fn a_bundle_runs_each_recipe_where_it_is_targeted_and_limited() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    f.write("web.yaml", WEB);
    f.write("db.yaml", DB);
    let b = f.write("b.yaml", "version: 1\nrecipes: [web.yaml, db.yaml]\n");
    let pairs = |o: &Output| -> Vec<(String, String)> {
        json(o)["executions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["recipe"].as_str().unwrap_or("").to_string(),
                    e["target"]["name"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let run = |limit: Option<&str>| {
        let mut args = vec![
            "plan",
            &b,
            "--inventory",
            &inv,
            "--no-ssh-config",
            "--format",
            "json",
        ];
        if let Some(l) = limit {
            args.extend(["--limit", l]);
        }
        f.run(&args)
    };
    let all = run(None);
    assert_eq!(all.status.code(), Some(3), "{}", text(&all.stderr));
    assert_eq!(pairs(&all).len(), 3);
    // web01 only: the db recipe has nothing selected and does not run.
    let o = run(Some("web01"));
    assert_eq!(o.status.code(), Some(3), "{}", text(&o.stderr));
    let p = pairs(&o);
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].1, "web01");
    // db01 only.
    let o = run(Some("db01"));
    let p = pairs(&o);
    assert_eq!((p.len(), p[0].1.as_str()), (1, "db01"));
    // Each item reaches some recipe.
    let o = run(Some("web01,db01"));
    assert_eq!(pairs(&o).len(), 2);
    // A group reaching the hosts of both recipes (ops = web01 + db01).
    let o = run(Some("group:ops"));
    assert_eq!(pairs(&o).len(), 2);
    // Names no recipe targets are refused.
    let f2 = Fx::new();
    let inv2 = f2.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    f2.write("web.yaml", WEB);
    let b2 = f2.write("b.yaml", "version: 1\nrecipes: [web.yaml]\n");
    let o = f2.run(&[
        "plan",
        &b2,
        "--inventory",
        &inv2,
        "--limit",
        "db01",
        "--no-ssh-config",
    ]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
}

#[test]
fn help_describes_the_option() {
    let f = Fx::new();
    for cmd in PHASES {
        let o = f.run(&[cmd, "--help"]);
        let h = text(&o.stdout);
        assert!(h.contains("--limit <ITEMS>"), "{cmd}: {h}");
    }
}

// ---------------------------------------------------------------------------
// Phase 2.5, D-15: a recipe no host runs is not frozen
// ---------------------------------------------------------------------------

/// A recipe for group `db` whose own default cannot be frozen (a relative
/// path): it only works where a variables file or a host gives `root`.
const PLACEHOLDER_DB: &str = "version: 1\ntargets:\n  groups: [db]\nvars:\n  root: { value: CHANGE_ME }\n  dbtok: { value: s, sensitive: true }\nresources:\n  - id: db\n    type: file\n    with: { path: \"{{ vars.root }}/db.conf\", content: y }\n";

/// web, db (placeholder default), mon (group web): in bundle order.
fn three_recipe_bundle(f: &Fx, db: &str) -> String {
    f.write("web.yaml", WEB);
    f.write("db.yaml", db);
    f.write("mon.yaml", &WEB.replace("id: index", "id: mon"));
    f.write(
        "b.yaml",
        "version: 1\nrecipes: [web.yaml, db.yaml, mon.yaml]\n",
    )
}

fn recipe_names(o: &Output) -> Vec<String> {
    json(o)["resolution"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["recipe"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn a_recipe_no_host_runs_does_not_stop_the_run_with_or_without_a_variables_file() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let b = three_recipe_bundle(&f, PLACEHOLDER_DB);
    let nothing = f.write("nothing.yaml", "version: 1\n");
    let common = f.write("common.yaml", "version: 1\nvars: { root: /common }\n");
    // No file; a file without a value for `root`; a file with a common value.
    for vars in [None, Some(&nothing), Some(&common)] {
        for phase in PHASES {
            let mut args = vec![
                phase,
                &b,
                "--inventory",
                &inv,
                "--limit",
                "web01",
                "--no-ssh-config",
                "--format",
                "json",
            ];
            if let Some(v) = vars {
                args.extend(["--vars-file", v]);
            }
            let o = f.run(&args);
            // Closed ports: web and mon are attempted on web01 and fail to connect.
            assert_eq!(
                o.status.code(),
                Some(3),
                "{vars:?} {phase}: {}",
                text(&o.stderr)
            );
            let doc = json(&o);
            // Bundle order is kept; db is listed, with the reason, and not run.
            assert_eq!(recipe_names(&o), ["web", "db", "mon"]);
            let res = doc["resolution"].as_array().unwrap();
            assert!(res[0].get("excluded_by").is_none());
            assert_eq!(res[1]["excluded_by"], "limit");
            assert!(res[2].get("excluded_by").is_none());
            let ran: Vec<(String, String)> = doc["executions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        e["recipe"].as_str().unwrap().to_string(),
                        e["target"]["name"].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            let want: &[(&str, &str)] = &[("web", "web01"), ("mon", "web01")];
            let want: Vec<(String, String)> = want
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect();
            // apply stops at the first failure and reports the rest not_run.
            assert_eq!(ran, want, "{vars:?} {phase}");
            // The hosts of the db recipe all carry the reason that is theirs.
            for h in res[1]["hosts"].as_array().unwrap() {
                assert_eq!(h["selected"], false);
                if h["name"] == "db01" {
                    assert_eq!(h["excluded_by"], "limit");
                    assert_eq!(h["reasons"], serde_json::json!(["group:db"]));
                }
            }
        }
    }
    // The text output says so.
    let o = f.run(&[
        "plan",
        &b,
        "--inventory",
        &inv,
        "--limit",
        "web01",
        "--no-ssh-config",
    ]);
    let out = text(&o.stdout);
    let (w, d, m) = (
        out.find("recipe web (").unwrap(),
        out.find("recipe db (").unwrap(),
        out.find("recipe mon (").unwrap(),
    );
    assert!(w < d && d < m, "{out}");
    assert!(
        out.contains("SKIP   recipe not run: --limit leaves no host for it"),
        "{out}"
    );
    assert!(
        out.contains("executions: 2 (3 recipe(s), 3 host(s))"),
        "{out}"
    );
}

#[test]
fn without_limit_a_placeholder_default_is_checked_as_before() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let b = three_recipe_bundle(&f, PLACEHOLDER_DB);
    let nothing = f.write("nothing.yaml", "version: 1\n");
    let common = f.write("common.yaml", "version: 1\nvars: { root: /common }\n");
    let o = f.run(&["plan", &b, "--inventory", &inv, "--no-ssh-config"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("path must be absolute: CHANGE_ME/db.conf"));
    let o = f.run(&[
        "plan",
        &b,
        "--inventory",
        &inv,
        "--vars-file",
        &nothing,
        "--no-ssh-config",
    ]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
    // A value in the file makes every execution valid: 4 executions, all attempted.
    let o = f.run(&[
        "plan",
        &b,
        "--inventory",
        &inv,
        "--vars-file",
        &common,
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o.stderr));
    assert_eq!(executed(&o), ["web01", "web02", "db01", "web01", "web02"]);
    // And `--limit` that selects the recipe freezes it: its default must hold.
    let o = f.run(&[
        "plan",
        &b,
        "--inventory",
        &inv,
        "--limit",
        "db01",
        "--no-ssh-config",
    ]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("path must be absolute: CHANGE_ME/db.conf"));
}

#[test]
fn a_recipe_no_host_runs_is_still_parsed_and_its_declarations_still_count() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let common = f.write("common.yaml", "version: 1\n");
    // What loading a recipe checks stays an error although no host runs it.
    let broken: &[(&str, &str)] = &[
        (
            "yaml syntax",
            "version: 1\ntargets: { groups: [db] }\nresources: [\n",
        ),
        (
            "unknown field",
            "version: 1\ntargets: { groups: [db] }\nbogus: 1\nresources: []\n",
        ),
        (
            "bad version",
            "version: 2\ntargets: { groups: [db] }\nresources: []\n",
        ),
        (
            "unknown target group",
            "version: 1\ntargets: { groups: [nosuch] }\nresources: []\n",
        ),
        ("no targets", "version: 1\nresources: []\n"),
        (
            "bad interpolation",
            "version: 1\ntargets: { groups: [db] }\nresources:\n  - { id: d, type: file, with: { path: /x, content: \"{{ secret.nosuch }}\" } }\n",
        ),
        // What does not depend on a variable's value is checked too.
        (
            "unknown resource type",
            "version: 1\ntargets: { groups: [db] }\nresources:\n  - { id: d, type: nosuchtype, with: {} }\n",
        ),
        (
            "unknown resource field",
            "version: 1\ntargets: { groups: [db] }\nresources:\n  - { id: d, type: file, with: { path: /x, nosuch: 1 } }\n",
        ),
        (
            "duplicate resource id",
            "version: 1\ntargets: { groups: [db] }\nresources:\n  - { id: d, type: file, with: { path: /x, content: y } }\n  - { id: d, type: file, with: { path: /y, content: y } }\n",
        ),
        (
            "unknown depends_on",
            "version: 1\ntargets: { groups: [db] }\nresources:\n  - { id: d, type: file, depends_on: [zz], with: { path: /x, content: y } }\n",
        ),
        (
            "unknown notify handler",
            "version: 1\ntargets: { groups: [db] }\nresources:\n  - { id: d, type: file, notify: [zz], with: { path: /x, content: y } }\n",
        ),
        (
            "dependency cycle",
            "version: 1\ntargets: { groups: [db] }\nresources:\n  - { id: a, type: file, depends_on: [b], with: { path: /x, content: y } }\n  - { id: b, type: file, depends_on: [a], with: { path: /y, content: y } }\n",
        ),
        (
            "missing secret file",
            "version: 1\ntargets: { groups: [db] }\nresources:\n  - { id: d, type: file, with: { path: /x, content: { secret: nosuch.age } } }\n",
        ),
        (
            "undefined variable",
            "version: 1\ntargets: { groups: [db] }\nresources:\n  - { id: d, type: file, with: { path: \"{{ vars.nope }}/x\", content: y } }\n",
        ),
        (
            "literal relative path",
            "version: 1\ntargets: { groups: [db] }\nresources:\n  - { id: d, type: file, with: { path: rel/x, content: y } }\n",
        ),
        (
            "structure error next to a variable",
            "version: 1\ntargets: { groups: [db] }\nvars: { root: { value: CHANGE_ME } }\nresources:\n  - { id: d, type: nosuchtype, with: { path: \"{{ vars.root }}/x\" } }\n",
        ),
    ];
    for (what, body) in broken {
        let b = three_recipe_bundle(&f, body);
        for vars in [None, Some(&common)] {
            for cmd in ["plan", "validate"] {
                let mut args = vec![cmd, &b, "--inventory", &inv, "--limit", "web01"];
                if let Some(v) = vars {
                    args.extend(["--vars-file", v]);
                }
                if cmd == "plan" {
                    args.push("--no-ssh-config");
                }
                let o = f.run(&args);
                assert_eq!(
                    o.status.code(),
                    Some(2),
                    "{what} {vars:?} {cmd}: {}",
                    text(&o.stderr)
                );
                assert!(o.stdout.is_empty(), "{what} {vars:?} {cmd}");
            }
        }
    }
    // A missing recipe file of the bundle.
    f.write("web.yaml", WEB);
    let b = f.write(
        "missing.yaml",
        "version: 1\nrecipes: [web.yaml, nosuch.yaml]\n",
    );
    let o = f.run(&[
        "plan",
        &b,
        "--inventory",
        &inv,
        "--limit",
        "web01",
        "--no-ssh-config",
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(f.ssh_log().is_empty());
}

#[test]
fn sensitive_overrides_for_a_recipe_no_host_runs_are_refused() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    // `dbtok` is declared sensitive only by the db recipe, which `--limit
    // web01` leaves without a host.
    let b = three_recipe_bundle(&f, PLACEHOLDER_DB);
    for (what, body) in [
        ("common", format!("vars: {{ dbtok: \"{CANARY}\" }}")),
        (
            "db01",
            format!("hosts: {{ db01: {{ dbtok: \"{CANARY}\" }} }}"),
        ),
        (
            "web01",
            format!("hosts: {{ web01: {{ dbtok: \"{CANARY}\" }} }}"),
        ),
        (
            "group db",
            format!("groups: {{ db: {{ dbtok: \"{CANARY}\" }} }}"),
        ),
    ] {
        let v = f.write("v.yaml", &format!("version: 1\n{body}\n"));
        for phase in ["plan", "validate"] {
            for format in ["text", "json"] {
                let o = f.run(&[
                    phase,
                    &b,
                    "--inventory",
                    &inv,
                    "--vars-file",
                    &v,
                    "--limit",
                    "web01",
                    "--no-ssh-config",
                    "--format",
                    format,
                ]);
                assert_eq!(o.status.code(), Some(2), "{what} {phase} {format}");
                assert!(o.stdout.is_empty(), "{what} {phase} {format}");
                let err = text(&o.stderr);
                assert!(err.contains("sensitive"), "{what}: {err}");
                assert!(!err.contains(CANARY), "LEAK {what} {phase} {format}");
            }
        }
    }
    assert!(f.ssh_log().is_empty());
}

#[test]
fn a_recipe_no_host_runs_is_never_contacted_resolved_or_changed() {
    let f = Fx::new();
    let closed = common::ClosedPorts::reserve(1);
    let (l2, l3) = (Listener::new(), Listener::new());
    // web01 refuses at once; web02 and db01 listen and would be counted.
    let inv = f.inventory([closed.port(0), l2.port(), l3.port()]);
    let b = three_recipe_bundle(&f, PLACEHOLDER_DB);
    let common = f.write("common.yaml", "version: 1\nvars: { root: /common }\n");
    let before = snapshot(f.dir.path());
    let _ = std::fs::remove_file(f.path("ssh.log"));
    for phase in PHASES {
        let o = f.run(&[
            phase,
            &b,
            "--inventory",
            &inv,
            "--vars-file",
            &common,
            "--limit",
            "web01",
        ]);
        assert_eq!(o.status.code(), Some(3), "{phase}: {}", text(&o.stderr));
    }
    assert_eq!(
        l2.accepted() + l3.accepted(),
        0,
        "an excluded host was contacted"
    );
    // `ssh -G` ran for web01 only: 3 phases x 1 host (web and mon share it).
    let log = f.ssh_log();
    assert_eq!(log.len(), 3, "{log:?}");
    assert!(
        log.iter()
            .all(|l| l.contains(&format!("-p {} --", closed.port(0)))),
        "{log:?}"
    );
    assert!(snapshot(f.dir.path()) == before, "a file changed");
}

#[test]
fn json_of_validate_and_plan_agree_on_what_is_skipped() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let common = f.write("common.yaml", "version: 1\nvars: { root: /common }\n");
    // The skipped recipe is not frozen whether its own default would freeze
    // or not.
    let valid_db = PLACEHOLDER_DB.replace("CHANGE_ME", "/srv/db");
    for (db, vars) in [
        (PLACEHOLDER_DB, None),
        (PLACEHOLDER_DB, Some(&common)),
        (valid_db.as_str(), None),
        (valid_db.as_str(), Some(&common)),
    ] {
        let b = three_recipe_bundle(&f, db);
        let mut args = vec![
            "validate",
            &b,
            "--inventory",
            &inv,
            "--limit",
            "web01",
            "--format",
            "json",
        ];
        if let Some(v) = vars {
            args.extend(["--vars-file", v]);
        }
        let o = f.run(&args);
        assert_eq!(o.status.code(), Some(0), "{vars:?}: {}", text(&o.stderr));
        let doc = json(&o);
        let recipes = doc["recipes"].as_array().unwrap();
        assert_eq!(recipes.len(), 3);
        assert_eq!(recipes[1]["recipe"], "db");
        assert_eq!(recipes[1]["excluded_by"], "limit");
        assert!(recipes[1]["resources"].is_null() && recipes[1]["vars"].is_null());
        assert!(recipes[0].get("excluded_by").is_none());
        assert_eq!(recipes[0]["resources"], 1);
        assert_eq!(doc["limit"], serde_json::json!(["web01"]));
        // Totals count the recipes that are checked.
        assert_eq!(doc["resources"], 2);
        match vars {
            Some(_) => {
                assert_eq!(doc["variables"]["executions"], 2);
                assert_eq!(doc["variables"]["targeted_executions"], 5);
            }
            None => {
                assert_eq!(doc["selected_executions"], 2);
                assert_eq!(doc["targeted_executions"], 5);
                assert!(doc.get("variables").is_none());
            }
        }
        let t = f.run(&{
            let mut t = args.clone();
            t[0] = "plan";
            t.push("--no-ssh-config");
            t
        });
        assert_eq!(t.status.code(), Some(3));
        assert_eq!(recipe_names(&t), ["web", "db", "mon"]);
    }
    // Text.
    let b = three_recipe_bundle(&f, PLACEHOLDER_DB);
    let o = f.run(&["validate", &b, "--inventory", &inv, "--limit", "web01"]);
    let out = text(&o.stdout);
    assert!(
        out.contains("skip  db: excluded by --limit, not frozen"),
        "{out}"
    );
    assert!(
        out.contains("ok: --limit web01 selects 2 of 5 execution(s)"),
        "{out}"
    );
}

// ---------------------------------------------------------------------------
// Phase 2.5, D-16: the ban on overriding a sensitive variable is global
// ---------------------------------------------------------------------------

#[test]
fn a_sensitive_override_is_refused_in_every_layer_with_or_without_limit() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let r = f.write("r.yaml", WEB);
    let layers = [
        ("common", format!("vars: {{ tok: \"{CANARY}\" }}")),
        (
            "selected host",
            format!("hosts: {{ web01: {{ tok: \"{CANARY}\" }} }}"),
        ),
        (
            "unselected host",
            format!("hosts: {{ web02: {{ tok: \"{CANARY}\" }} }}"),
        ),
        (
            "host no recipe targets",
            format!("hosts: {{ db01: {{ tok: \"{CANARY}\" }} }}"),
        ),
        (
            "group of the host",
            format!("groups: {{ web: {{ tok: \"{CANARY}\" }} }}"),
        ),
        (
            "group of unselected hosts",
            format!("groups: {{ db: {{ tok: \"{CANARY}\" }} }}"),
        ),
    ];
    for (what, body) in &layers {
        let v = f.write("v.yaml", &format!("version: 1\n{body}\n"));
        for limit in [None, Some("web01"), Some("web02"), Some("web")] {
            for phase in ["plan", "validate"] {
                for format in ["text", "json"] {
                    let mut args = vec![
                        phase,
                        &r,
                        "--inventory",
                        &inv,
                        "--vars-file",
                        &v,
                        "--no-ssh-config",
                        "--format",
                        format,
                    ];
                    if let Some(l) = limit {
                        args.extend(["--limit", l]);
                    }
                    let o = f.run(&args);
                    let ctx = format!("{what} {limit:?} {phase} {format}");
                    assert_eq!(o.status.code(), Some(2), "{ctx}: {}", text(&o.stderr));
                    assert!(o.stdout.is_empty(), "{ctx}");
                    assert!(text(&o.stderr).contains("sensitive"), "{ctx}");
                    assert!(
                        !text(&o.stderr).contains(CANARY) && !text(&o.stdout).contains(CANARY),
                        "LEAK {ctx}"
                    );
                }
            }
        }
    }
    // An ordinary variable of an unselected host stays D-2: it does not stop a
    // limited run (and does without --limit).
    let v = f.write("v.yaml", "version: 1\nhosts: { web02: { root: 5 } }\n");
    let o = f.run(&[
        "plan",
        &r,
        "--inventory",
        &inv,
        "--vars-file",
        &v,
        "--no-ssh-config",
        "--limit",
        "web01",
    ]);
    assert_eq!(o.status.code(), Some(3));
    let o = f.run(&[
        "plan",
        &r,
        "--inventory",
        &inv,
        "--vars-file",
        &v,
        "--no-ssh-config",
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(f.ssh_log().is_empty());
}

// ---------------------------------------------------------------------------
// Phase 2.5, D-6: `validate --limit` checks the selection without a variables file
// ---------------------------------------------------------------------------

#[test]
fn validate_with_a_limit_and_no_variables_file_checks_the_selection() {
    let f = Fx::new();
    let listeners = (Listener::new(), Listener::new(), Listener::new());
    let inv = f.inventory([listeners.0.port(), listeners.1.port(), listeners.2.port()]);
    let r = f.write("r.yaml", WEB);
    let bad = f.write("bad.yaml", "hosts: [\n");
    let plain = f.write("plain.yaml", "version: 1\nresources: []\n");
    let before = snapshot(f.dir.path());
    let v = |args: &[&str]| f.run(&[&["validate", &r][..], args].concat());
    // Good selections.
    for (limit, selected) in [
        ("web01", 1),
        ("host:web02", 1),
        ("web", 2),
        ("group:web", 2),
        ("web0*", 2),
        ("w?b01,web02", 2),
        ("web01,web01", 1),
    ] {
        let o = v(&["--inventory", &inv, "--limit", limit]);
        assert_eq!(o.status.code(), Some(0), "{limit}: {}", text(&o.stderr));
        assert!(
            text(&o.stdout).contains(&format!("selects {selected} of 2 execution(s)")),
            "{limit}: {}",
            text(&o.stdout)
        );
        let o = v(&["--inventory", &inv, "--limit", limit, "--format", "json"]);
        let doc = json(&o);
        assert_eq!(doc["selected_executions"], selected, "{limit}");
        assert_eq!(doc["targeted_executions"], 2);
        assert!(doc.get("variables").is_none());
        assert_eq!(doc["status"], "ok");
    }
    // Refused selections, and the same text `plan` prints.
    for limit in [
        "",
        "!!!",
        "a,,b",
        "web01,",
        "group:web*",
        "host:",
        "-web",
        "web 01",
        "nosuch",
        "host:web",
        "group:web01",
        "zz*",
        "web01,nosuch",
        "db01",
        "group:db",
    ] {
        let o = v(&["--inventory", &inv, "--limit", limit]);
        assert_eq!(o.status.code(), Some(2), "{limit:?}: {}", text(&o.stderr));
        assert!(o.stdout.is_empty(), "{limit:?}");
        let p = f.run(&[
            "plan",
            &r,
            "--inventory",
            &inv,
            "--limit",
            limit,
            "--no-ssh-config",
        ]);
        assert_eq!(p.status.code(), Some(2), "{limit:?}");
        // clap's own usage errors name the command; every other text is shared.
        if !text(&o.stderr).starts_with("error: unexpected argument") {
            assert_eq!(
                text(&o.stderr),
                text(&p.stderr),
                "{limit:?}: validate and plan differ"
            );
        }
    }
    // An inventory is needed, and `--host` cannot be combined with it.
    let o = v(&["--limit", "web01"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        text(&o.stderr).contains("--limit needs --inventory"),
        "{}",
        text(&o.stderr)
    );
    let o = v(&["--host", "h", "--limit", "web01"]);
    assert_eq!(o.status.code(), Some(2));
    let o = v(&["--host", "h", "--inventory", &inv, "--limit", "web01"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        text(&o.stderr).contains("mutually exclusive"),
        "{}",
        text(&o.stderr)
    );
    // The inventory must exist and be well formed; the recipe must declare targets.
    let o = v(&["--inventory", "/nonexistent/hosts.yaml", "--limit", "web01"]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(
        v(&["--inventory", &bad, "--limit", "web01"]).status.code(),
        Some(2)
    );
    let o = f.run(&["validate", &plain, "--inventory", &inv, "--limit", "web01"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        text(&o.stderr).contains("declares no targets"),
        "{}",
        text(&o.stderr)
    );
    // Two options at once are a parse error (exit 2) as for plan.
    let o = v(&["--inventory", &inv, "--limit", "a", "--limit", "b"]);
    assert_eq!(o.status.code(), Some(2));
    // validate never connects, never runs ssh and never writes.
    assert!(f.ssh_log().is_empty(), "{:?}", f.ssh_log());
    assert_eq!(
        listeners.0.accepted() + listeners.1.accepted() + listeners.2.accepted(),
        0
    );
    assert!(snapshot(f.dir.path()) == before, "validate changed a file");
}

#[test]
fn validate_without_a_limit_is_the_validate_it_was() {
    let f = Fx::new();
    let r = f.write("r.yaml", WEB);
    // Target options are accepted and ignored, even contradicting ones, and no
    // inventory is read.
    for args in [
        vec![],
        vec!["--host", "h"],
        vec!["--inventory", "/nonexistent/hosts.yaml"],
        vec!["--host", "h", "--inventory", "/nonexistent/hosts.yaml"],
    ] {
        let o = f.run(&[&["validate", &r][..], &args[..]].concat());
        assert_eq!(o.status.code(), Some(0), "{args:?}: {}", text(&o.stderr));
        assert_eq!(
            text(&o.stdout),
            "ok: 1 resource(s), 0 handler(s), 2 var(s)\n",
            "{args:?}"
        );
    }
    let o = f.run(&["validate", &r, "--format", "json"]);
    let doc = json(&o);
    for key in [
        "limit",
        "selected_executions",
        "targeted_executions",
        "variables",
    ] {
        assert!(doc.get(key).is_none(), "{key}");
    }
    assert!(f.ssh_log().is_empty());
}

#[test]
fn validate_with_a_limit_checks_the_recipes_some_host_runs_as_loading_does() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let b = three_recipe_bundle(&f, PLACEHOLDER_DB);
    // Without --limit validate of the bundle fails on the placeholder, as ever.
    let o = f.run(&["validate", &b]);
    assert_eq!(o.status.code(), Some(2));
    // --limit web01: the db recipe is not frozen, so the bundle validates.
    let o = f.run(&["validate", &b, "--inventory", &inv, "--limit", "web01"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    // --limit db01: the db recipe runs, so its default must freeze.
    let o = f.run(&["validate", &b, "--inventory", &inv, "--limit", "db01"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
    assert!(text(&o.stderr).contains("path must be absolute: CHANGE_ME/db.conf"));
    // A variables file supplies the value: the same selection passes.
    let common = f.write("common.yaml", "version: 1\nvars: { root: /common }\n");
    let o = f.run(&[
        "validate",
        &b,
        "--inventory",
        &inv,
        "--limit",
        "db01",
        "--vars-file",
        &common,
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
}

// ---- D-15: a recipe no host runs, checked past a field a variable decides ----

/// The db recipe of a bundle: placeholder variable `root` (no usable default),
/// the sensitive `tok` (default is the canary) and the given resources.
fn db_with_resources(resources: &str) -> String {
    format!(
        "version: 1\ntargets:\n  groups: [db]\nvars:\n  root: {{ value: CHANGE_ME }}\n  tok: {{ value: {CANARY}, sensitive: true }}\n  n: {{ value: 7 }}\nresources:\n{resources}"
    )
}

/// What does not depend on what a variable holds, written next to a field that
/// does (the placeholder `root` fails that field's check with its default):
/// (case, resources, text the error must carry).
const BESIDE_A_VARIABLE: &[(&str, &str, &str)] = &[
    (
        "undeclared variable in the same field",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/{{ vars.nope }}/x\", content: y } }\n",
        "undefined variable",
    ),
    (
        "fact in the same field",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/{{ facts.os }}\", content: y } }\n",
        "facts",
    ),
    (
        "sensitive value in the same field",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/{{ vars.tok }}\", content: y } }\n",
        "sensitive",
    ),
    (
        "variable of another type in the same field",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", source: \"{{ vars.n }}\" } }\n",
        "must be a string",
    ),
    (
        "empty owner",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", owner: \"\", content: y } }\n",
        "invalid owner",
    ),
    (
        "empty group",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", group: \"\", content: y } }\n",
        "invalid group",
    ),
    (
        "content and source",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", content: y, source: s.txt } }\n",
        "mutually exclusive",
    ),
    (
        "mode",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", mode: \"99\", content: y } }\n",
        "mode",
    ),
    (
        "secret reference",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", content: { secret: ../bad.age } } }\n",
        "secret reference",
    ),
    (
        "second variable field of a command",
        "  - { id: a, type: command, with: { program: /bin/true, creates: \"{{ vars.root }}/c\", removes: /r } }\n",
        "mutually exclusive",
    ),
    (
        "command cwd",
        "  - { id: a, type: command, with: { program: /bin/true, creates: \"{{ vars.root }}/c\", cwd: rel } }\n",
        "cwd",
    ),
    (
        "package state",
        "  - { id: a, type: package, with: { name: \"{{ vars.root }} bad\", state: sideways } }\n",
        "state",
    ),
    (
        "account literal",
        "  - { id: a, type: user, with: { name: \"{{ vars.root }}\", uid: -5 } }\n",
        "uid",
    ),
    (
        "path owned twice (the first one fails a later field)",
        "  - { id: a, type: template, with: { path: /etc/same, source: \"{{ vars.root }}/t.j2\" } }\n  - { id: b, type: file, with: { path: /etc/same, content: y } }\n",
        "conflicting ownership",
    ),
    (
        "template source file",
        "  - { id: a, type: template, with: { path: \"{{ vars.root }}/x\", source: nosuch.j2 } }\n",
        "not found",
    ),
    (
        "template body",
        "  - { id: a, type: template, with: { path: \"{{ vars.root }}/x\", source: bad.j2 } }\n",
        "{%",
    ),
    (
        "failing resource, then another resource",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", content: y } }\n  - { id: b, type: file, with: { path: /y, content: y, owner: \"\" } }\n",
        "invalid owner",
    ),
];

#[test]
fn a_recipe_no_host_runs_is_checked_past_a_field_a_variable_decides() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    f.write("bad.j2", "{% if a %}x{% endif %}\n");
    f.write("t.j2", "x\n");
    let common = f.write("common.yaml", "version: 1\nvars: { root: /common }\n");
    for (what, resources, want) in BESIDE_A_VARIABLE {
        let b = three_recipe_bundle(&f, &db_with_resources(resources));
        for vars in [None, Some(&common)] {
            for cmd in ["plan", "audit", "apply", "validate"] {
                for format in ["text", "json"] {
                    let mut args = vec![
                        cmd,
                        &b,
                        "--inventory",
                        &inv,
                        "--limit",
                        "web01",
                        "--format",
                        format,
                    ];
                    if let Some(v) = vars {
                        args.extend(["--vars-file", v]);
                    }
                    if cmd != "validate" {
                        args.push("--no-ssh-config");
                    }
                    let o = f.run(&args);
                    let err = text(&o.stderr);
                    assert_eq!(o.status.code(), Some(2), "{what} {vars:?} {cmd}: {err}");
                    assert!(o.stdout.is_empty(), "{what} {vars:?} {cmd} {format}");
                    assert!(err.contains(want), "{what}: {err}");
                    assert!(!err.contains("withheld"), "{what}: {err}");
                    assert!(!err.contains(CANARY), "LEAK {what}: {err}");
                }
            }
        }
    }
    // Nothing was resolved or contacted for any of them.
    assert!(f.ssh_log().is_empty(), "{:?}", f.ssh_log());
}

#[test]
fn a_defect_next_to_a_variable_stops_a_run_without_limit_as_before() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let common = f.write("common.yaml", "version: 1\nvars: { root: /common }\n");
    for (what, resources, _) in BESIDE_A_VARIABLE {
        let b = three_recipe_bundle(&f, &db_with_resources(resources));
        // Without `--limit` the recipe runs on its hosts, so any error stops
        // the run before a host is contacted; with a variables file as well.
        for vars in [None, Some(&common)] {
            let mut args = vec!["validate", &b, "--inventory", &inv];
            if let Some(v) = vars {
                args.extend(["--vars-file", v]);
            }
            let o = f.run(&args);
            assert_eq!(o.status.code(), Some(2), "{what} {vars:?}");
        }
    }
}

/// Values only a variable decides stay undecided for a recipe no host runs:
/// it is neither refused nor frozen, and it is checked when a host runs it.
const NOT_FOR_A_SKIPPED_RECIPE_TO_JUDGE: &[(&str, &str)] = &[
    (
        "relative path",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", content: y } }\n",
    ),
    (
        "every kind of resource",
        "  - { id: d, type: directory, with: { path: \"{{ vars.root }}/d\" } }\n  - { id: l, type: link, with: { path: \"{{ vars.root }}/l\", target: /t } }\n  - { id: t, type: template, with: { path: \"{{ vars.root }}/t\", source: \"{{ vars.root }}/t.j2\" } }\n  - { id: c, type: command, with: { program: \"/bin/{{ vars.root }}\", creates: \"{{ vars.root }}/c\", cwd: \"{{ vars.root }}\" } }\n  - { id: p, type: package, with: { name: \"{{ vars.root }} x\", state: present } }\n  - { id: s, type: service, with: { name: \"{{ vars.root }}\", state: running } }\n  - { id: u, type: user, with: { name: \"{{ vars.root }}\" } }\n  - { id: g, type: group, with: { name: \"{{ vars.root }}\" } }\n",
    ),
    (
        "path owned twice, decided by a variable",
        "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", content: y } }\n  - { id: b, type: file, with: { path: \"{{ vars.root }}/x\", content: y } }\n",
    ),
    (
        "account owned twice, decided by a variable",
        "  - { id: a, type: user, with: { name: \"{{ vars.root }}\" } }\n  - { id: b, type: user, with: { name: \"{{ vars.root }}\" } }\n",
    ),
    (
        "template file chosen by a variable",
        "  - { id: a, type: template, with: { path: \"{{ vars.root }}/x\", source: \"{{ vars.root }}/t.j2\" } }\n",
    ),
];

#[test]
fn a_value_only_a_variable_decides_is_not_judged_for_a_recipe_no_host_runs() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    let common = f.write("common.yaml", "version: 1\nvars: { root: /common }\n");
    for (what, resources) in NOT_FOR_A_SKIPPED_RECIPE_TO_JUDGE {
        let b = three_recipe_bundle(&f, &db_with_resources(resources));
        for vars in [None, Some(&common)] {
            for phase in PHASES {
                let mut args = vec![
                    phase,
                    &b,
                    "--inventory",
                    &inv,
                    "--limit",
                    "web01",
                    "--no-ssh-config",
                    "--format",
                    "json",
                ];
                if let Some(v) = vars {
                    args.extend(["--vars-file", v]);
                }
                let o = f.run(&args);
                // web and mon are attempted on web01 (closed port): exit 3.
                assert_eq!(
                    o.status.code(),
                    Some(3),
                    "{what} {vars:?} {phase}: {}",
                    text(&o.stderr)
                );
                assert_eq!(json(&o)["resolution"][1]["excluded_by"], "limit", "{what}");
            }
        }
    }
    let o = f.run(&[
        "validate",
        &three_recipe_bundle(
            &f,
            &db_with_resources(NOT_FOR_A_SKIPPED_RECIPE_TO_JUDGE[1].1),
        ),
        "--inventory",
        &inv,
        "--limit",
        "web01",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    // The same recipe is refused where a host runs it with no value for `root`.
    let o = f.run(&[
        "validate",
        &three_recipe_bundle(
            &f,
            &db_with_resources(NOT_FOR_A_SKIPPED_RECIPE_TO_JUDGE[0].1),
        ),
        "--inventory",
        &inv,
        "--limit",
        "db01",
    ]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn the_check_of_a_recipe_no_host_runs_is_the_same_in_toml() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    f.write("web.yaml", WEB);
    for (what, body, want) in [
        (
            "empty owner next to a variable",
            "[[resources]]\nid = \"a\"\ntype = \"file\"\n[resources.with]\npath = \"{{ vars.root }}/x\"\nowner = \"\"\ncontent = \"y\"\n",
            "invalid owner",
        ),
        (
            "undeclared variable next to a variable",
            "[[resources]]\nid = \"a\"\ntype = \"file\"\n[resources.with]\npath = \"{{ vars.root }}/{{ vars.nope }}\"\ncontent = \"y\"\n",
            "undefined variable",
        ),
    ] {
        f.write(
            "db.toml",
            &format!(
                "version = 1\n[targets]\ngroups = [\"db\"]\n[vars]\nroot = {{ value = \"CHANGE_ME\" }}\n{body}"
            ),
        );
        let b = f.write("b.yaml", "version: 1\nrecipes: [web.yaml, db.toml]\n");
        let o = f.run(&["validate", &b, "--inventory", &inv, "--limit", "web01"]);
        let err = text(&o.stderr);
        assert_eq!(o.status.code(), Some(2), "{what}: {err}");
        assert!(err.contains(want) && !err.contains("withheld"), "{what}: {err}");
        // A placeholder alone is not refused.
        f.write(
            "db.toml",
            "version = 1\n[targets]\ngroups = [\"db\"]\n[vars]\nroot = { value = \"CHANGE_ME\" }\n[[resources]]\nid = \"a\"\ntype = \"file\"\n[resources.with]\npath = \"{{ vars.root }}/x\"\ncontent = \"y\"\n",
        );
        let o = f.run(&["validate", &b, "--inventory", &inv, "--limit", "web01"]);
        assert_eq!(o.status.code(), Some(0), "{what}: {}", text(&o.stderr));
    }
}

#[test]
fn a_single_recipe_is_never_left_without_a_host_and_so_never_skipped() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    // A single recipe is not a bundle: when `--limit` leaves it no host the run
    // is refused before the recipe is looked at (nothing would run), so there
    // is no skipped single recipe whose structure could go unchecked. Where a
    // host runs it, it is held to every check, defect or not.
    let r = f.write(
        "single.yaml",
        &db_with_resources(
            "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", owner: \"\", content: y } }\n",
        ),
    );
    let o = f.run(&["validate", &r, "--inventory", &inv, "--limit", "web01"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("would run nothing"),
        "{}",
        text(&o.stderr)
    );
    let o = f.run(&["validate", &r, "--inventory", &inv, "--limit", "db01"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("path must be absolute"),
        "{}",
        text(&o.stderr)
    );
    assert!(f.ssh_log().is_empty());
}
