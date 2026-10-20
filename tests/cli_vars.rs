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

// ---- validate --vars-file ------------------------------------------------------
//
// `validate` with a variables file runs the very static gate `plan`, `apply`
// and `audit` run (DESIGN §19.5): same checks, same diagnostics, no host
// contacted, no `ssh -G`, nothing written.

/// A recipe whose own default fails alone (a relative path): it validates only
/// when the variables file gives `root` an absolute value for every execution.
const NEEDS_ROOT: &str = "version: 1\ntargets:\n  groups: [web]\nvars:\n  root: { value: CHANGE_ME }\nresources:\n  - id: index\n    type: file\n    with: { path: \"{{ vars.root }}/index.html\", content: x }\n";

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o.stdout)))
}

/// Every file under `dir` (relative path, content), sorted.
fn snapshot(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                let rel = p.strip_prefix(base).unwrap().display().to_string();
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
fn validate_rejects_a_bad_variables_file_without_a_value_or_a_host() {
    let f = Fx::new();
    // The recipe is valid on its own: any exit 2 below comes from the file.
    let r = f.write("r.yaml", &NEEDS_ROOT.replace("CHANGE_ME", "/ok"));
    assert_eq!(f.run(&["validate", &r]).status.code(), Some(0));
    let good = f.write("good.yaml", "version: 1\nvars: { root: /srv/ok }\n");
    assert_eq!(
        f.run(&["validate", &r, "--vars-file", &good]).status.code(),
        Some(0)
    );
    // (file name, body, what the diagnostic says)
    let cases: Vec<(&str, String, &str)> = vec![
        ("missing.yaml", String::new(), "cannot read"),
        ("wrong-ext.json", "{}".to_string(), "unsupported extension"),
        (
            "syntax.yaml",
            format!("version: 1\nvars: {{ root: \"{CANARY}\n"),
            "YAML syntax error",
        ),
        (
            "syntax.toml",
            format!("version = 1\n[vars]\nroot = \"{CANARY}\" trailing\n"),
            "TOML syntax error",
        ),
        (
            "version.yaml",
            format!("version: 2\nvars: {{ root: \"/{CANARY}\" }}\n"),
            "version must be 1",
        ),
        (
            "no-version.yaml",
            format!("vars: {{ root: \"/{CANARY}\" }}\n"),
            "missing required field version",
        ),
        (
            "unknown-top.yaml",
            format!("version: 1\n\"{CANARY}\": 1\nnope: 1\n"),
            "unknown top-level field",
        ),
        (
            "type.yaml",
            format!("version: 1\nvars: {{ root: [\"{CANARY}\"] }}\n"),
            "declares a string",
        ),
        (
            "undeclared.yaml",
            format!("version: 1\nvars: {{ nope: \"/{CANARY}\" }}\n"),
            "is not declared by any recipe of this run",
        ),
        (
            "null.yaml",
            "version: 1\nvars: { root: null }\n".to_string(),
            "may not be null",
        ),
    ];
    for (name, body, needle) in cases {
        let v = if name == "missing.yaml" {
            f.path(name).display().to_string()
        } else {
            f.write(name, &body)
        };
        for format in ["text", "json"] {
            let o = f.run(&["validate", &r, "--vars-file", &v, "--format", format]);
            let ctx = format!("{name} {format}");
            assert_eq!(o.status.code(), Some(2), "{ctx}: {}", text(&o.stderr));
            let (out, err) = (text(&o.stdout), text(&o.stderr));
            assert!(
                out.is_empty(),
                "{ctx}: nothing is reported on failure: {out}"
            );
            assert!(
                !out.contains(CANARY) && !err.contains(CANARY),
                "LEAK {ctx}: {err}"
            );
            assert!(err.contains(needle), "{ctx}: expected {needle:?} in {err}");
            if name != "missing.yaml" && name != "wrong-ext.json" {
                assert!(err.contains("no host was contacted"), "{ctx}: {err}");
            }
        }
    }
    assert_eq!(f.ssh_calls(), 0);
}

#[test]
fn validate_applies_the_inventory_and_sensitivity_rules_plan_applies() {
    let f = Fx::new();
    let inv = f.inventory([1, 1]);
    let e = f.write("e.yaml", "version: 1\n");
    f.write("a.yaml", NEEDS_ROOT);
    f.write("b.yaml", &NEEDS_ROOT.replace("id: index", "id: other"));
    let bundle = f.write(
        "pair.yaml",
        "version: 1\nname: pair\nrecipes: [a.yaml, b.yaml]\n",
    );
    f.write("c.yaml", "version: 1\nresources: []\n");
    let mixed = f.write(
        "mixed.yaml",
        "version: 1\nname: mixed\nrecipes: [a.yaml, c.yaml]\n",
    );
    let no_targets = f.write("nt.yaml", "version: 1\nresources: []\n");
    let sens = f.write(
        "s.yaml",
        "version: 1\ntargets:\n  groups: [web]\nvars:\n  tok: { value: s, sensitive: true }\nresources:\n  - id: f\n    type: file\n    with: { path: /etc/f, content: \"{{ vars.tok }}\" }\n",
    );
    let v_root = f.write("root.yaml", "version: 1\nvars: { root: /srv/c }\n");
    let v_tok = f.write(
        "tok.yaml",
        &format!("version: 1\nvars: {{ tok: \"{CANARY}\" }}\n"),
    );
    let missing_inv = f.path("nope.yaml").display().to_string();
    // A bundle on an inventory: every recipe on every host of its group.
    let o = f.run(&[
        "validate",
        &bundle,
        "--inventory",
        &inv,
        "--vars-file",
        &v_root,
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(json(&o)["variables"]["executions"], 4);
    // Everything plan refuses before it contacts a host, validate refuses with
    // the very same words and exit code.
    let refused: [(&str, &str, &str, &str); 4] = [
        // a recipe without `targets` (CHANGELOG 4), also inside a bundle
        (&no_targets, &inv, &e, "declares no targets"),
        (&mixed, &inv, &e, "declares no targets"),
        // a missing inventory (CHANGELOG 5)
        (&bundle, &missing_inv, &e, "cannot read inventory"),
        // a sensitive variable cannot be overridden
        (&sens, &inv, &v_tok, "cannot override a sensitive variable"),
    ];
    for (recipe, inventory, vars, needle) in refused {
        let args = [recipe, "--inventory", inventory, "--vars-file", vars];
        let a = f.run(&[&["validate"], &args[..]].concat());
        let p = f.run(&[&["plan"], &args[..]].concat());
        assert_eq!(a.status.code(), Some(2), "{needle}: {}", text(&a.stderr));
        assert_eq!(p.status.code(), Some(2), "{needle}");
        assert!(
            text(&a.stderr).contains(needle),
            "{needle}: {}",
            text(&a.stderr)
        );
        assert_eq!(text(&a.stderr), text(&p.stderr), "{needle}");
        assert!(!text(&a.stderr).contains(CANARY), "LEAK {needle}");
    }
    assert_eq!(f.ssh_calls(), 0);
}

#[test]
fn validate_checks_the_recipe_with_the_values_of_a_yaml_or_toml_file() {
    let f = Fx::new();
    let r = f.write("r.yaml", NEEDS_ROOT);
    // The recipe's own default fails alone: without the file it is refused.
    let o = f.run(&["validate", &r]);
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o.stderr).contains("path must be absolute: CHANGE_ME/index.html"));
    let yaml = f.write("v.yaml", "version: 1\nvars:\n  root: /srv/app\n");
    let toml = f.write("v.toml", "version = 1\n[vars]\nroot = \"/srv/app\"\n");
    for v in [&yaml, &toml] {
        let o = f.run(&["validate", &r, "--vars-file", v]);
        assert_eq!(o.status.code(), Some(0), "{v}: {}", text(&o.stderr));
        let out = text(&o.stdout);
        assert!(
            out.contains("ok: 1 resource(s), 0 handler(s), 1 var(s)"),
            "{out}"
        );
        assert!(
            out.contains("variables file") && out.contains("1 execution(s)"),
            "{out}"
        );
        let o = f.run(&["validate", &r, "--vars-file", v, "--format", "json"]);
        assert_eq!(o.status.code(), Some(0));
        let doc = json(&o);
        assert_eq!(doc["command"], "validate");
        assert_eq!(doc["status"], "ok");
        assert_eq!(doc["variables"]["file"], v.as_str());
        assert_eq!(doc["variables"]["executions"], 1);
    }
    assert_eq!(f.ssh_calls(), 0);
}

#[test]
fn validate_applies_common_group_and_host_values_per_execution() {
    let f = Fx::new();
    let inv = f.inventory([1, 1]);
    let r = f.write("r.yaml", NEEDS_ROOT);
    // (variables file, expected exit, text expected on stderr)
    let cases: [(&str, i32, &str); 7] = [
        ("version: 1\nvars: { root: /srv/c }\n", 0, ""),
        ("version: 1\ngroups: { web: { root: /srv/g } }\n", 0, ""),
        ("version: 1\nhosts: { web01: { root: /srv/1 }, web02: { root: /srv/2 } }\n", 0, ""),
        // web02 is left on the recipe's own (failing) default.
        ("version: 1\nhosts: { web01: { root: /srv/1 } }\n", 2, "recipe r @ web02"),
        // Precedence: host > group > common; the lower layers alone would fail.
        ("version: 1\nvars: { root: rel }\ngroups: { web: { root: /srv/g } }\n", 0, ""),
        ("version: 1\nvars: { root: rel }\ngroups: { web: { root: rel2 } }\nhosts: { web01: { root: /a }, web02: { root: /b } }\n", 0, ""),
        // A host or group the inventory does not define.
        ("version: 1\nvars: { root: /srv/c }\nhosts: { ghost: { root: /srv/x } }\n", 2, "hosts.ghost"),
    ];
    for (i, (body, code, needle)) in cases.iter().enumerate() {
        let v = f.write(&format!("v{i}.yaml"), body);
        let o = f.run(&[
            "validate",
            &r,
            "--inventory",
            &inv,
            "--vars-file",
            &v,
            "--format",
            "json",
        ]);
        assert_eq!(
            o.status.code(),
            Some(*code),
            "case {i}: {}",
            text(&o.stderr)
        );
        if *code == 0 {
            assert_eq!(json(&o)["variables"]["executions"], 2, "case {i}");
        } else {
            assert!(
                text(&o.stderr).contains(needle),
                "case {i}: {}",
                text(&o.stderr)
            );
        }
    }
    assert_eq!(f.ssh_calls(), 0);
}

#[test]
fn validate_reports_group_conflicts_and_lets_a_host_value_decide() {
    let f = Fx::new();
    let kh = f.write("known_hosts", "");
    let inv = f.write(
        "hosts.yaml",
        &format!("hosts:\n  web01: {{ address: 127.0.0.1, port: 1, user: u, known_hosts: {kh} }}\n  web02: {{ address: 127.0.0.1, port: 1, user: u, known_hosts: {kh} }}\ngroups:\n  a: {{ hosts: [web01, web02] }}\n  b: {{ hosts: [web01] }}\n"),
    );
    let r = f.write(
        "r.yaml",
        &NEEDS_ROOT.replace("groups: [web]", "groups: [a]"),
    );
    let conflict = f.write(
        "c.yaml",
        "version: 1\ngroups: { a: { root: /a }, b: { root: /b } }\n",
    );
    let o = f.run(&[
        "validate",
        &r,
        "--inventory",
        &inv,
        "--vars-file",
        &conflict,
    ]);
    assert_eq!(o.status.code(), Some(2));
    let err = text(&o.stderr);
    assert!(
        err.contains("hosts.web01: variable root is given different values by groups a, b"),
        "{err}"
    );
    assert!(
        !err.contains("hosts.web02"),
        "web02 is only in group a: {err}"
    );
    // The same values for both groups are no conflict.
    let same = f.write(
        "same.yaml",
        "version: 1\ngroups: { a: { root: /a }, b: { root: /a } }\n",
    );
    let o = f.run(&["validate", &r, "--inventory", &inv, "--vars-file", &same]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    // A host value decides.
    let decided = f.write(
        "d.yaml",
        "version: 1\ngroups: { a: { root: /a }, b: { root: /b } }\nhosts: { web01: { root: /h } }\n",
    );
    let o = f.run(&["validate", &r, "--inventory", &inv, "--vars-file", &decided]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(f.ssh_calls(), 0);
}

#[test]
fn validate_without_an_inventory_is_one_target_and_bundles_share_the_file() {
    let f = Fx::new();
    let r = f.write("r.yaml", NEEDS_ROOT);
    let ok = |v: &str| f.write("v.yaml", v);
    // Local target: `hosts.localhost`.
    let v = ok("version: 1\nhosts: { localhost: { root: /srv/l } }\n");
    let o = f.run(&["validate", &r, "--vars-file", &v, "--format", "json"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(json(&o)["variables"]["executions"], 1);
    // `--host H`: `hosts.H` applies, `hosts.localhost` does not.
    let o = f.run(&["validate", &r, "--host", "web01", "--vars-file", &v]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        text(&o.stderr).contains("recipe r @ web01"),
        "{}",
        text(&o.stderr)
    );
    let v = ok("version: 1\nhosts: { web01: { root: /srv/w } }\n");
    let o = f.run(&["validate", &r, "--host", "web01", "--vars-file", &v]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    // Group values need an inventory.
    let v = ok("version: 1\nvars: { root: /srv/c }\ngroups: { web: { root: /srv/g } }\n");
    let o = f.run(&["validate", &r, "--vars-file", &v]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        text(&o.stderr).contains("need --inventory"),
        "{}",
        text(&o.stderr)
    );
    // A bundle: both recipes receive the same common value (one target each).
    f.write("a.yaml", NEEDS_ROOT);
    f.write("b.yaml", &NEEDS_ROOT.replace("id: index", "id: other"));
    let b = f.write(
        "b-bundle.yaml",
        "version: 1\nname: pair\nrecipes: [a.yaml, b.yaml]\n",
    );
    let v = ok("version: 1\nvars: { root: /srv/c }\n");
    let o = f.run(&["validate", &b, "--vars-file", &v, "--format", "json"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let doc = json(&o);
    assert_eq!(doc["bundle"], "pair");
    assert_eq!(doc["recipes"].as_array().unwrap().len(), 2);
    assert_eq!(doc["variables"]["executions"], 2);
    let o = f.run(&["validate", &b]);
    assert_eq!(o.status.code(), Some(2), "the bundle's defaults fail alone");
    assert_eq!(f.ssh_calls(), 0);
}

#[test]
fn validate_keeps_host_and_inventory_exclusive_and_checks_the_host_like_plan() {
    let f = Fx::new();
    let inv = f.inventory([1, 1]);
    let r = f.write("r.yaml", NEEDS_ROOT);
    let v = f.write("v.yaml", "version: 1\nvars: { root: /srv/c }\n");
    let both = [
        "--host",
        "web01",
        "--inventory",
        inv.as_str(),
        "--vars-file",
        v.as_str(),
    ];
    let a = f.run(&[&["validate", r.as_str()], &both[..]].concat());
    let p = f.run(&[&["plan", r.as_str()], &both[..]].concat());
    assert_eq!(a.status.code(), Some(2));
    assert!(text(&a.stderr).contains("mutually exclusive"));
    assert_eq!(text(&a.stderr), text(&p.stderr));
    // A host the `ssh` client would read as an option: the same refusal.
    let one = ["--host=-x", "--vars-file", v.as_str()];
    let a = f.run(&[&["validate", r.as_str()], &one[..]].concat());
    let p = f.run(&[&["plan", r.as_str()], &one[..]].concat());
    assert_eq!(a.status.code(), Some(2));
    assert_eq!(p.status.code(), Some(2));
    assert_eq!(text(&a.stderr), text(&p.stderr));
    assert_eq!(f.ssh_calls(), 0);
}

#[test]
fn validate_without_a_variables_file_is_unchanged() {
    let f = Fx::new();
    let r = f.write(
        "r.yaml",
        "version: 1\nvars:\n  x: { value: 1 }\nresources: []\n",
    );
    let o = f.run(&["validate", &r]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        text(&o.stdout),
        "ok: 0 resource(s), 0 handler(s), 1 var(s)\n"
    );
    assert_eq!(text(&o.stderr), "");
    let o = f.run(&["validate", &r, "--format", "json"]);
    let doc = json(&o);
    let mut keys: Vec<&str> = doc
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort();
    assert_eq!(keys, ["command", "handlers", "resources", "status", "vars"]);
    // Every target option is still accepted and ignored, even contradictory
    // ones and files that do not exist.
    let o = f.run(&[
        "validate",
        &r,
        "--host",
        "a",
        "--hosts",
        "/does/not/exist.yaml",
        "--user",
        "u",
        "--sudo",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(f.ssh_calls(), 0);
}

#[test]
fn validate_with_a_variables_file_contacts_no_host_and_changes_nothing() {
    let f = Fx::new();
    let listener = Listener::new();
    let inv = f.inventory([listener.port(), listener.port()]);
    let r = f.write("r.yaml", NEEDS_ROOT);
    let v = f.write("v.yaml", "version: 1\nvars: { root: /srv/c }\n");
    let before = snapshot(f.dir.path());
    for format in ["text", "json"] {
        let o = f.run(&[
            "validate",
            &r,
            "--inventory",
            &inv,
            "--vars-file",
            &v,
            "--format",
            format,
        ]);
        assert_eq!(o.status.code(), Some(0), "{format}: {}", text(&o.stderr));
    }
    // A failing run neither.
    let bad = f.write("bad.yaml", "version: 1\nvars: { root: 5 }\n");
    let before = {
        let mut b = before;
        b.push(("bad.yaml".to_string(), std::fs::read(&bad).unwrap()));
        b.sort();
        b
    };
    let o = f.run(&["validate", &r, "--inventory", &inv, "--vars-file", &bad]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(f.ssh_calls(), 0, "ssh -G ran");
    assert_eq!(listener.accepted(), 0, "a host was contacted");
    assert_eq!(snapshot(f.dir.path()), before, "validate wrote a file");
}

#[test]
fn validate_fails_on_exactly_what_plan_fails_on_before_it_contacts_a_host() {
    let f = Fx::new();
    let listener = Listener::new();
    let inv = f.inventory([listener.port(), listener.port()]);
    for (recipe, vname, vbody) in failing_cases(&f) {
        let v = f.write(&format!("vars-{vname}"), &vbody);
        for format in ["text", "json"] {
            let args = [
                recipe.as_str(),
                "--inventory",
                inv.as_str(),
                "--vars-file",
                v.as_str(),
                "--format",
                format,
            ];
            let a = f.run(&[&["validate"], &args[..]].concat());
            let p = f.run(&[&["plan"], &args[..]].concat());
            let ctx = format!("{vname} {format}");
            assert_eq!(a.status.code(), Some(2), "{ctx}: {}", text(&a.stderr));
            assert_eq!(a.status.code(), p.status.code(), "{ctx}");
            assert_eq!(text(&a.stdout), text(&p.stdout), "{ctx}");
            assert_eq!(text(&a.stderr), text(&p.stderr), "{ctx}");
            assert!(!text(&a.stderr).contains(CANARY), "LEAK {ctx}");
        }
    }
    assert_eq!(f.ssh_calls(), 0);
    assert_eq!(listener.accepted(), 0);
}

#[test]
fn what_validate_accepts_plan_carries_on_to_the_connection() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(2);
    let inv = f.inventory([ports.ports()[0], ports.ports()[1]]);
    let r = f.write("r.yaml", NEEDS_ROOT);
    let v = f.write(
        "v.yaml",
        "version: 1\nhosts: { web01: { root: /srv/1 }, web02: { root: /srv/2 } }\n",
    );
    let args = [
        r.as_str(),
        "--inventory",
        inv.as_str(),
        "--vars-file",
        v.as_str(),
    ];
    let a = f.run(&[&["validate"], &args[..]].concat());
    assert_eq!(a.status.code(), Some(0), "{}", text(&a.stderr));
    assert_eq!(f.ssh_calls(), 0, "validate ran ssh");
    // Same input, `plan`: every check passes, both hosts are resolved and
    // attempted (closed ports: exit 3).
    let p = f.run(&[&["plan"], &args[..]].concat());
    assert_eq!(p.status.code(), Some(3), "{}", text(&p.stderr));
    assert_eq!(f.ssh_calls(), 2);
}

#[test]
fn validate_lists_each_warning_once_and_counts_what_it_leaves_out() {
    let f = Fx::new();
    f.write("t.conf", "x = {{ template.p0 }}\n");
    let keys: Vec<String> = (0..51)
        .map(|i| format!("p{i}: \"{{{{ facts.hostname }}}}\""))
        .collect();
    let r = f.write(
        "r.yaml",
        &format!("version: 1\ntargets:\n  groups: [web]\nresources:\n  - id: t\n    type: template\n    with:\n      path: /etc/app.conf\n      source: t.conf\n      vars: {{ {} }}\n", keys.join(", ")),
    );
    let inv = f.inventory([1, 1]);
    let v = f.write("v.yaml", "version: 1\n");
    // Without a file every warning is listed (unchanged).
    let o = f.run(&["validate", &r, "--format", "json"]);
    assert_eq!(json(&o)["warnings"].as_array().unwrap().len(), 51);
    // With a file, over two executions: each warning once, at most 50, the
    // rest counted.
    let o = f.run(&[
        "validate",
        &r,
        "--inventory",
        &inv,
        "--vars-file",
        &v,
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let doc = json(&o);
    assert_eq!(doc["variables"]["executions"], 2);
    assert_eq!(doc["warnings"].as_array().unwrap().len(), 50);
    assert_eq!(doc["warnings_omitted"], 1);
    let o = f.run(&["validate", &r, "--inventory", &inv, "--vars-file", &v]);
    let err = text(&o.stderr);
    assert_eq!(
        err.matches("warning: t: template vars value").count(),
        50,
        "{err}"
    );
    assert!(err.contains("warning: ... and 1 more warning(s)"), "{err}");
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
