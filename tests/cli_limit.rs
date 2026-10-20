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
    assert_eq!(snapshot(f.dir.path()), before);
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
fn a_bundle_recipe_with_nothing_selected_needs_values_that_stand_alone() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let inv = f.inventory([ports.port(0), ports.port(1), ports.port(2)]);
    // The db recipe has no default for `root`.
    f.write("web.yaml", WEB);
    f.write(
        "db.yaml",
        "version: 1\ntargets:\n  groups: [db]\nvars:\n  root: { value: CHANGE_ME }\nresources:\n  - id: db\n    type: file\n    with: { path: \"{{ vars.root }}/db.conf\", content: y }\n",
    );
    let b = f.write("b.yaml", "version: 1\nrecipes: [web.yaml, db.yaml]\n");
    let v = f.write("v.yaml", "version: 1\nhosts: { db01: { root: /srv/db } }\n");
    // Without --limit db01 supplies its own value.
    let o = f.run(&[
        "plan",
        &b,
        "--inventory",
        &inv,
        "--vars-file",
        &v,
        "--no-ssh-config",
    ]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o.stderr));
    // With --limit web01 the db recipe has no execution; db01's value is not
    // used to fill it in, so its own defaults must stand alone (D-15).
    let o = f.run(&[
        "plan",
        &b,
        "--inventory",
        &inv,
        "--vars-file",
        &v,
        "--limit",
        "web01",
        "--no-ssh-config",
    ]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("recipe db: --limit leaves no host to run it on"),
        "{}",
        text(&o.stderr)
    );
    assert!(!text(&o.stderr).contains("/srv/db"));
    assert!(f.ssh_log().is_empty());
    // Defaults that stand alone make the same command line work, and then the
    // bundle with a variables file contacts only the selected host.
    f.write(
        "db.yaml",
        &std::fs::read_to_string(f.path("db.yaml"))
            .unwrap()
            .replace("CHANGE_ME", "/srv/default"),
    );
    let o = f.run(&[
        "plan",
        &b,
        "--inventory",
        &inv,
        "--vars-file",
        &v,
        "--limit",
        "web01",
    ]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o.stderr));
    let log = f.ssh_log();
    assert_eq!(log.len(), 1, "{log:?}");
    assert!(
        log[0].contains(&format!("-p {} --", ports.port(0))),
        "{log:?}"
    );
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
