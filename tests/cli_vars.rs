//! CLI surface of variables files (`--vars-file`, DESIGN §19.5).
//!
//! No test needs a reachable host. Inventory hosts point at a listener this
//! test owns (to prove that nothing connects when a static check fails) or
//! at closed loopback ports (to observe which executions were attempted
//! once every check passes). `ssh -G` is a scripted `ssh` on PATH that
//! records every call.

mod common;

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};

/// A fictitious value that must never be printed.
const CANARY: &str = "SINTER_VARS_CANARY_DO_NOT_PRINT_20261019";

struct Fx {
    dir: tempfile::TempDir,
}

impl Fx {
    fn new() -> Self {
        let f = Fx {
            dir: tempfile::tempdir().unwrap(),
        };
        // A scripted `ssh` that records its arguments and resolves nothing
        // beyond the defaults.
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

    /// Inventory: web01, web02 (group web) on the given ports.
    fn inventory(&self, ports: [u16; 2]) -> String {
        let kh = self.write("known_hosts", "");
        self.write(
            "hosts.yaml",
            &format!(
                "hosts:\n  web01:\n    address: 127.0.0.1\n    port: {}\n    user: u\n    known_hosts: {kh}\n  web02:\n    address: 127.0.0.1\n    port: {}\n    user: u\n    known_hosts: {kh}\ngroups:\n  web:\n    hosts: [web01, web02]\n",
                ports[0], ports[1]
            ),
        )
    }

    fn ssh_calls(&self) -> usize {
        std::fs::read_to_string(self.path("ssh.log"))
            .map(|s| s.lines().count())
            .unwrap_or(0)
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

/// Each case: (recipe, variables file name, variables file body).
fn failing_cases(f: &Fx) -> Vec<(String, String, String)> {
    let tmpl = f.write("ok.tmpl", "x\n");
    let _ = tmpl;
    let one = |name: &str, default: &str, resource: &str| {
        f.write(
            name,
            &format!(
                "version: 1\ntargets:\n  groups: [web]\nvars:\n  v: {{ value: {default} }}\n  w: {{ value: /srv/w }}\nresources:\n{resource}"
            ),
        )
    };
    let c = CANARY;
    let host_value = |v: &str| {
        format!("version: 1\nhosts:\n  web01: {{ v: \"{v}\" }}\n  web02: {{ v: \"{v}\" }}\n")
    };
    vec![
        (
            one("path.yaml", "/ok", "  - id: f\n    type: file\n    with: { path: \"{{ vars.v }}/x\", content: x }\n"),
            "path.yaml".into(),
            host_value(&format!("rel/{c}")),
        ),
        (
            one("own.yaml", "/a", "  - id: f1\n    type: file\n    with: { path: \"{{ vars.v }}\", content: x }\n  - id: f2\n    type: file\n    with: { path: \"{{ vars.w }}\", content: y }\n"),
            "own.yaml".into(),
            format!("version: 1\nvars: {{ v: \"/srv/{c}\", w: \"/srv/{c}\" }}\n"),
        ),
        (
            one("pkg.yaml", "jq", "  - id: p\n    type: package\n    with: { name: \"{{ vars.v }}\", state: present }\n"),
            "pkg.yaml".into(),
            host_value(&format!("bad name {c}")),
        ),
        (
            one("user.yaml", "alice", "  - id: u\n    type: user\n    with: { name: \"{{ vars.v }}\" }\n"),
            "user.yaml".into(),
            host_value(&format!("bad name {c}")),
        ),
        (
            one("role.yaml", "app", "  - id: r\n    type: postgresql_role\n    with: { name: \"{{ vars.v }}\" }\n"),
            "role.yaml".into(),
            host_value(&format!("bad name {c}")),
        ),
        (
            one("tmpl.yaml", "ok.tmpl", "  - id: t\n    type: template\n    with: { path: /etc/t, source: \"{{ vars.v }}\" }\n"),
            "tmpl.yaml".into(),
            host_value(&format!("{c}.tmpl")),
        ),
        (
            one("cwd.yaml", "/ok", "  - id: c\n    type: command\n    with: { program: /bin/true, cwd: \"{{ vars.v }}\" }\n"),
            "cwd.yaml".into(),
            host_value(c),
        ),
        (
            one("creates.yaml", "/ok", "  - id: c\n    type: command\n    with: { program: /bin/true, creates: \"{{ vars.v }}\" }\n"),
            "creates.yaml".into(),
            host_value(c),
        ),
        (
            one("removes.yaml", "/ok", "  - id: c\n    type: command\n    with: { program: /bin/true, removes: \"{{ vars.v }}\" }\n"),
            "removes.yaml".into(),
            host_value(c),
        ),
        (
            one("type.yaml", "/ok", "  - id: f\n    type: file\n    with: { path: \"{{ vars.v }}\", content: x }\n"),
            "type.yaml".into(),
            format!("version: 1\nvars: {{ v: [\"{c}\"] }}\n"),
        ),
        (
            one("eval.yaml", "[a]", "  - id: f\n    type: file\n    with: { path: \"/x/{{ vars.v }}\", content: x }\n"),
            "eval.yaml".into(),
            format!("version: 1\nvars: {{ v: [\"{c}\"] }}\n"),
        ),
        (
            one("syn.yaml", "/ok", "  - id: f\n    type: file\n    with: { path: /etc/f, content: \"{{ vars.v }}\" }\n"),
            "syn.yaml".into(),
            format!("version: 1\nvars: {{ v: \"{c}\n"),
        ),
        (
            one("synt.yaml", "/ok", "  - id: f\n    type: file\n    with: { path: /etc/f, content: \"{{ vars.v }}\" }\n"),
            "syn.toml".into(),
            format!("version = 1\n[vars]\nv = \"{c}\" trailing\n"),
        ),
        (
            one("range.yaml", "1", "  - id: f\n    type: file\n    with: { path: /etc/f, content: \"{{ vars.v }}\" }\n"),
            "range.yaml".into(),
            format!("version: 1\nvars: {{ v: 9{} }}\n", "9".repeat(40)),
        ),
        (
            one("schema.yaml", "/ok", "  - id: f\n    type: file\n    with: { path: /etc/f, content: \"{{ vars.v }}\" }\n"),
            "schema.yaml".into(),
            format!("version: 1\n\"{c}\": 1\nvars: {{ \"{c} x\": 1, nope: 1 }}\ngroups: {{ \"{c}!\": {{}} }}\n"),
        ),
        (
            f.write(
                "sens.yaml",
                "version: 1\ntargets:\n  groups: [web]\nvars:\n  w: { value: s, sensitive: true }\nresources:\n  - id: f\n    type: file\n    with: { path: /etc/f, content: \"{{ vars.w }}\" }\n",
            ),
            "sens.yaml".into(),
            format!("version: 1\nvars: {{ w: \"{c}\" }}\n"),
        ),
    ]
}

#[test]
fn a_static_failure_prints_no_value_and_contacts_no_host() {
    let f = Fx::new();
    let listener = Listener::new();
    let inv = f.inventory([listener.port(), listener.port()]);
    for (recipe, vname, vbody) in failing_cases(&f) {
        let v = f.write(&format!("vars-{vname}"), &vbody);
        for phase in ["plan", "audit", "apply"] {
            for format in ["text", "json"] {
                let o = f.run(&[
                    phase,
                    &recipe,
                    "--inventory",
                    &inv,
                    "--vars-file",
                    &v,
                    "--format",
                    format,
                ]);
                let ctx = format!("{vname} {phase} {format}");
                assert_eq!(o.status.code(), Some(2), "{ctx}: {}", text(&o.stderr));
                let (out, err) = (text(&o.stdout), text(&o.stderr));
                assert!(!out.contains(CANARY), "LEAK stdout {ctx}: {out}");
                assert!(!err.contains(CANARY), "LEAK stderr {ctx}: {err}");
                assert!(
                    out.is_empty(),
                    "{ctx}: nothing runs, nothing is reported: {out}"
                );
                assert!(err.contains("no host was contacted"), "{ctx}: {err}");
            }
        }
    }
    assert_eq!(f.ssh_calls(), 0, "ssh -G ran before the checks passed");
    assert_eq!(listener.accepted(), 0, "a host was contacted");
}

#[test]
fn diagnostics_name_the_resource_field_and_variable() {
    let f = Fx::new();
    let listener = Listener::new();
    let inv = f.inventory([listener.port(), listener.port()]);
    let r = f.write(
        "r.yaml",
        "version: 1\ntargets:\n  groups: [web]\nvars:\n  root: { value: /srv }\nresources:\n  - id: index\n    type: file\n    with: { path: \"{{ vars.root }}/index.html\", content: x }\n",
    );
    let v = f.write(
        "v.yaml",
        &format!("version: 1\nhosts:\n  web01: {{ root: /srv/ok }}\n  web02: {{ root: \"rel/{CANARY}\" }}\n"),
    );
    let o = f.run(&["plan", &r, "--inventory", &inv, "--vars-file", &v]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(
        text(&o.stderr),
        "sinter: recipe r @ web02: index: file static check failed: field path; it depends on variables from the variables file: root (hosts.web02); the value is withheld\n\
         sinter: variables: the static checks failed (problems listed above); no host was contacted\n"
    );
    assert_eq!(listener.accepted(), 0);
}

#[test]
fn once_every_check_passes_each_host_is_resolved_and_attempted() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(2);
    let inv = f.inventory([ports.ports()[0], ports.ports()[1]]);
    let r = f.write(
        "r.yaml",
        "version: 1\ntargets:\n  groups: [web]\nvars:\n  root: { value: CHANGE_ME }\nresources:\n  - id: index\n    type: file\n    with: { path: \"{{ vars.root }}/index.html\", content: x }\n",
    );
    let v = f.write(
        "v.yaml",
        "version: 1\nhosts:\n  web01: { root: /srv/one }\n  web02: { root: /srv/two }\n",
    );
    let o = f.run(&[
        "plan",
        &r,
        "--inventory",
        &inv,
        "--vars-file",
        &v,
        "--format",
        "json",
    ]);
    // Closed ports: every execution is attempted and fails to connect.
    assert_eq!(o.status.code(), Some(3), "{}", text(&o.stderr));
    let doc: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let ex: Vec<(&str, &str)> = doc["executions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["target"]["name"].as_str().unwrap(),
                e["status"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(ex, [("web01", "error"), ("web02", "error")]);
    assert_eq!(f.ssh_calls(), 2, "ssh -G once per selected host");
    // The same recipe without the file fails validation (its placeholder).
    let o = f.run(&["plan", &r, "--inventory", &inv, "--format", "json"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o.stderr).contains("path must be absolute: CHANGE_ME/index.html"));
}

#[test]
fn an_empty_variables_file_changes_no_output() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(2);
    let inv = f.inventory([ports.ports()[0], ports.ports()[1]]);
    let r = f.write(
        "r.yaml",
        "version: 1\ntargets:\n  groups: [web]\nvars:\n  root: { value: /srv }\nresources:\n  - id: index\n    type: file\n    with: { path: \"{{ vars.root }}/index.html\", content: x }\n",
    );
    let v = f.write("v.yaml", "version: 1\n");
    for phase in ["plan", "audit", "apply"] {
        for format in ["text", "json"] {
            let a = f.run(&[phase, &r, "--inventory", &inv, "--format", format]);
            let b = f.run(&[
                phase,
                &r,
                "--inventory",
                &inv,
                "--vars-file",
                &v,
                "--format",
                format,
            ]);
            assert_eq!(a.status.code(), b.status.code(), "{phase} {format}");
            assert_eq!(text(&a.stdout), text(&b.stdout), "{phase} {format}");
            assert_eq!(text(&a.stderr), text(&b.stderr), "{phase} {format}");
        }
    }
}

#[test]
fn validate_ignores_the_variables_file() {
    let f = Fx::new();
    let r = f.write(
        "r.yaml",
        "version: 1\nvars:\n  x: { value: 1 }\nresources: []\n",
    );
    for v in ["/does/not/exist.yaml", "v.json"] {
        let o = f.run(&["validate", &r, "--vars-file", v]);
        assert_eq!(o.status.code(), Some(0), "{v}: {}", text(&o.stderr));
    }
    let bad = f.write("bad.yaml", &format!("version: 1\nvars: {{ x: \"{CANARY}\n"));
    let o = f.run(&["validate", &r, "--vars-file", &bad]);
    assert_eq!(o.status.code(), Some(0));
    assert!(!text(&o.stdout).contains(CANARY) && !text(&o.stderr).contains(CANARY));
    assert_eq!(f.ssh_calls(), 0);
}

#[test]
fn host_and_inventory_stay_exclusive_and_groups_need_an_inventory() {
    let f = Fx::new();
    let listener = Listener::new();
    let inv = f.inventory([listener.port(), listener.port()]);
    let r = f.write(
        "r.yaml",
        "version: 1\nvars:\n  x: { value: 1 }\nresources: []\n",
    );
    let v = f.write("v.yaml", "version: 1\ngroups:\n  web: { x: 2 }\n");
    let o = f.run(&[
        "plan",
        &r,
        "--host",
        "web01",
        "--inventory",
        &inv,
        "--vars-file",
        &v,
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o.stderr).contains("mutually exclusive"));
    for args in [
        vec![
            "plan",
            r.as_str(),
            "--host",
            "127.0.0.1",
            "--vars-file",
            v.as_str(),
        ],
        vec!["apply", r.as_str(), "--vars-file", v.as_str()],
    ] {
        let o = f.run(&args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(
            text(&o.stderr).contains("groups.web: group variables need --inventory"),
            "{}",
            text(&o.stderr)
        );
    }
    assert_eq!(f.ssh_calls(), 0);
    assert_eq!(listener.accepted(), 0);
}

#[test]
fn help_says_the_file_is_not_for_secrets() {
    let o = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["plan", "--help"])
        .output()
        .unwrap();
    let help = text(&o.stdout);
    assert!(help.contains("--vars-file <PATH>"), "{help}");
    assert!(help.contains("never put secrets in it"), "{help}");
}

#[test]
fn bundle_error_order_with_and_without_a_variables_file() {
    let f = Fx::new();
    // Recipe 1 fails while freezing (duplicate id), recipe 2 fails to parse.
    f.write(
        "one.yaml",
        "version: 1\nresources:\n  - id: x\n    type: file\n    with: { path: /etc/a, content: a }\n  - id: x\n    type: file\n    with: { path: /etc/b, content: b }\n",
    );
    f.write("two.yaml", "version: 1\nresources: [\n");
    let b = f.write("b.yaml", "version: 1\nrecipes: [one.yaml, two.yaml]\n");
    let v = f.write("v.yaml", "version: 1\n");
    let without = f.run(&["plan", &b]);
    assert_eq!(without.status.code(), Some(2));
    assert!(text(&without.stderr).contains("duplicate resource id: x"));
    // With a variables file freezing happens per execution, after every
    // recipe has loaded: the parse error of recipe 2 comes first.
    let with = f.run(&["plan", &b, "--vars-file", &v]);
    assert_eq!(with.status.code(), Some(2));
    assert!(
        text(&with.stderr).contains("YAML parse error")
            && !text(&with.stderr).contains("duplicate"),
        "{}",
        text(&with.stderr)
    );
    // Once recipe 2 parses, recipe 1's freeze error is reported per execution.
    f.write("two.yaml", "version: 1\nresources: []\n");
    let with = f.run(&["plan", &b, "--vars-file", &v]);
    assert_eq!(with.status.code(), Some(2));
    assert!(
        text(&with.stderr).contains("recipe one @ localhost: duplicate resource id: x"),
        "{}",
        text(&with.stderr)
    );
}

#[test]
fn one_variables_file_per_invocation() {
    let f = Fx::new();
    let r = f.write("r.yaml", "version: 1\nresources: []\n");
    let v = f.write("v.yaml", "version: 1\n");
    let o = f.run(&["plan", &r, "--vars-file", &v, "--vars-file", &v]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
}
