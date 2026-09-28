//! CLI surface of the multi-host foundation: validate semantics, inventory,
//! host groups, recipe targets, bundles, fail-closed target resolution,
//! OpenSSH configuration inheritance and terminal color.
//!
//! No test needs a reachable host: every inventory address is a closed
//! loopback port (connection refused, exit 3), which is enough to observe
//! *which* executions were attempted, in which order, and how failures
//! aggregate. `ssh -G` is replaced by a scripted `ssh` on PATH that records
//! every host it was asked about.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

#[test]
fn shipped_multihost_example_resolves_as_documented() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/multihost");
    let inv = sinter::inventory::load_inventory(&root.join("hosts.yaml")).unwrap();
    let sinter::bundle::Source::Bundle(b) =
        sinter::bundle::load_source(&root.join("web-stack.yaml")).unwrap()
    else {
        panic!("web-stack.yaml must be a bundle")
    };
    let selected: Vec<Vec<String>> = b
        .recipes
        .iter()
        .map(|u| {
            sinter::inventory::resolve(&inv, u.model.targets.as_ref(), &u.label)
                .unwrap()
                .selected()
                .map(str::to_string)
                .collect()
        })
        .collect();
    assert_eq!(
        selected,
        vec![
            vec!["cache01", "db01", "web01", "web02"],
            vec!["web01", "web02"],
            vec!["db01"],
        ]
    );
    assert_eq!(inv.hosts["cache01"].address, "cache01");
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sinter")
}

struct Fx {
    dir: tempfile::TempDir,
}

impl Fx {
    fn new() -> Self {
        Fx {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, body: &str) -> String {
        let p = self.path(name);
        std::fs::write(&p, body).unwrap();
        p.display().to_string()
    }

    /// A recipe with one command resource and the given `targets` block.
    fn recipe(&self, name: &str, targets: &str) -> String {
        self.write(
            name,
            &format!(
                "version: 1\n{}resources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n",
                targets
            ),
        )
    }

    /// Inventory whose hosts are closed loopback ports.
    /// Hosts: web01, web02 (group web, linux), db01 (group db, linux).
    fn inventory(&self) -> String {
        let kh = self.write("known_hosts", "");
        let mut body = String::from("hosts:\n");
        for (h, port) in ["web01", "web02", "db01"].iter().zip(closed_ports(3)) {
            body.push_str(&format!(
                "  {h}:\n    address: 127.0.0.1\n    port: {port}\n    user: inv-{h}\n    known_hosts: {kh}\n"
            ));
        }
        body.push_str(
            "groups:\n  web:\n    hosts: [web01, web02]\n  db:\n    hosts: [db01]\n  linux:\n    hosts: [web01, web02, db01]\n",
        );
        self.write("hosts.yaml", &body)
    }

    /// A scripted `ssh` recording each invocation and printing `g`.
    fn fake_ssh(&self, g: &str) {
        let bin_dir = self.path("fakebin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let out = self.write("ssh_g.txt", g);
        let log = self.path("ssh.log");
        let p = bin_dir.join("ssh");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncat '{}'\n",
                log.display(),
                out
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn ssh_log(&self) -> Option<String> {
        std::fs::read_to_string(self.path("ssh.log")).ok()
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin());
        c.args(args).current_dir(self.dir.path());
        c.env(
            "PATH",
            format!(
                "{}:{}",
                self.path("fakebin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().unwrap()
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// `n` distinct loopback ports with nothing listening: all listeners are
/// held until every port is chosen, so the ports cannot repeat.
fn closed_ports(n: usize) -> Vec<u16> {
    let ls: Vec<_> = (0..n)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    ls.iter().map(|l| l.local_addr().unwrap().port()).collect()
}

fn closed_port() -> u16 {
    closed_ports(1)[0]
}

fn assert_no_ansi(bytes: &[u8], ctx: &str) {
    assert!(
        !bytes.contains(&0x1b),
        "{ctx}: output must not contain ANSI escapes: {:?}",
        String::from_utf8_lossy(bytes)
    );
}

fn json(o: &Output) -> serde_json::Value {
    assert_no_ansi(&o.stdout, "json");
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("stdout must be one JSON document ({e}): {}", stdout(o)))
}

/// (recipe, target name) of every attempted or skipped execution.
fn executions(v: &serde_json::Value) -> Vec<(String, String, String)> {
    v["executions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["recipe"].as_str().unwrap().to_string(),
                e["target"]["name"].as_str().unwrap().to_string(),
                e["status"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

const WEB: &str = "targets:\n  groups: [web]\n";

// ---------------------------------------------------------------------------
// validate: static configuration only
// ---------------------------------------------------------------------------

#[test]
fn validate_recipe_only() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "");
    let o = f.run(&["validate", &r]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(stdout(&o).starts_with("ok: 1 resource(s)"));
}

#[test]
fn validate_ignores_execution_options_without_reading_anything() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", WEB);
    f.fake_ssh("hostname 127.0.0.1\n");
    for args in [
        vec!["--host", "server01.invalid"],
        vec!["--hosts", "/does/not/exist.yaml"],
        vec!["--inventory", "/does/not/exist.yaml"],
        vec!["--host", "a", "--hosts", "b.yaml"],
        vec![
            "--user",
            "nobody",
            "--port",
            "2222",
            "--identity",
            "/no/key",
            "--known-hosts",
            "/no/kh",
            "--sudo",
            "--no-ssh-config",
            "--verbose",
        ],
    ] {
        let mut full = vec!["validate", r.as_str()];
        full.extend(args.iter().copied());
        let o = f.run(&full);
        assert_eq!(o.status.code(), Some(0), "{args:?}: {o:?}");
    }
    let bad = f.write("bad.yaml", "hosts: [\n");
    assert_eq!(
        f.run(&["validate", &r, "--hosts", &bad]).status.code(),
        Some(0)
    );
    assert!(f.ssh_log().is_none(), "validate must never run ssh");
}

#[test]
fn validate_still_fails_on_bad_recipes() {
    let f = Fx::new();
    for (name, body) in [
        ("v2.yaml", "version: 2\n"),
        ("parse.yaml", "version: [\n"),
        ("schema.yaml", "version: 1\nbogus: 1\n"),
        ("t1.yaml", "version: 1\ntargets: web\n"),
        ("t2.yaml", "version: 1\ntargets: {}\n"),
        ("t3.yaml", "version: 1\ntargets:\n  hosts: []\n"),
        (
            "t4.yaml",
            "version: 1\ntargets:\n  groups: [\"bad name\"]\n",
        ),
        ("t5.yaml", "version: 1\ntargets:\n  hosts: [a, a]\n"),
        ("t6.yaml", "version: 1\ntargets:\n  pattern: \"web*\"\n"),
    ] {
        let p = f.write(name, body);
        let o = f.run(&["validate", &p, "--host", "x", "--hosts", "h.yaml"]);
        assert_eq!(o.status.code(), Some(2), "{name}: {o:?}");
    }
    let o = f.run(&["validate", &f.path("missing.yaml").display().to_string()]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn validate_rejects_a_present_link_without_a_target() {
    // Previously accepted by validate and refused only when executed.
    let f = Fx::new();
    let p = f.write(
        "l.yaml",
        "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: /tmp/l\n",
    );
    let o = f.run(&["validate", &p]);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(stdout(&o).is_empty(), "{o:?}");
    assert!(
        stderr(&o).contains("link target is required when present"),
        "{o:?}"
    );
}

#[test]
fn validate_rejects_invalid_link_state_and_empty_handler_service() {
    let f = Fx::new();
    for (name, body, message) in [
        (
            "state.yaml",
            "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: /tmp/l\n      target: /tmp/t\n      state: presnet\n",
            "link state must be present or absent",
        ),
        (
            "handler.yaml",
            "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n    notify:\n      - h\nhandlers:\n  - id: h\n    service: \"\"\n    action: restart\n",
            "service must not be empty",
        ),
    ] {
        let p = f.write(name, body);
        let o = f.run(&["validate", &p]);
        assert_eq!(o.status.code(), Some(2), "{name}: {o:?}");
        assert!(stdout(&o).is_empty(), "{name}: {o:?}");
        assert!(stderr(&o).contains(message), "{name}: {o:?}");
    }
}

#[test]
fn targets_in_an_included_file_are_rejected() {
    let f = Fx::new();
    f.write("frag.yaml", "version: 1\ntargets:\n  groups: [web]\n");
    let r = f.write("main.yaml", "version: 1\ninclude: [frag.yaml]\n");
    let o = f.run(&["validate", &r]);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(stderr(&o).contains("top-level recipe"), "{}", stderr(&o));
}

#[test]
fn unknown_or_misspelled_options_fail() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "");
    for bad in [
        "--hots",
        "--hostname",
        "--identity-file",
        "--inventroy",
        "--targets",
    ] {
        let o = f.run(&["validate", &r, bad, "x"]);
        assert_ne!(o.status.code(), Some(0), "{bad} must be rejected");
        assert!(
            stderr(&o).contains("unexpected argument"),
            "{bad}: {}",
            stderr(&o)
        );
    }
}

#[test]
fn validate_bundle() {
    let f = Fx::new();
    f.recipe("common.yaml", "targets:\n  groups: [linux]\n");
    f.recipe("nginx.yaml", WEB);
    let b = f.write(
        "stack.yaml",
        "version: 1\nname: web-stack\nrecipes:\n  - common.yaml\n  - nginx.yaml\n",
    );
    let o = f.run(&["validate", &b, "--hosts", "/nope.yaml"]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(
        stdout(&o).contains("bundle web-stack: 2 recipe(s)"),
        "{}",
        stdout(&o)
    );
    let o = f.run(&["validate", &b, "--format", "json"]);
    let v = json(&o);
    assert_eq!(v["bundle"], "web-stack");
    assert_eq!(v["resources"], 2);
    assert_eq!(v["recipes"][1]["recipe"], "nginx");
    assert_eq!(v["recipes"][1]["targets"]["groups"][0], "web");
}

#[test]
fn invalid_bundles_fail_validation() {
    let f = Fx::new();
    f.recipe("a.yaml", "");
    f.write("broken.yaml", "version: 1\nbogus: 1\n");
    for body in [
        "version: 1\nrecipes: [missing.yaml]\n",
        "version: 1\nrecipes: [a.yaml, ./a.yaml]\n",
        "version: 1\nrecipes: [broken.yaml]\n",
        "version: 1\nrecipes: []\n",
        "version: 1\nrecipes: [b.yaml]\n", // lists itself: bundles do not nest
    ] {
        let b = f.write("b.yaml", body);
        let o = f.run(&["validate", &b]);
        assert_eq!(o.status.code(), Some(2), "{body}: {o:?}");
    }
}

// ---------------------------------------------------------------------------
// inventory, groups, targets: fail closed
// ---------------------------------------------------------------------------

#[test]
fn host_and_inventory_conflict() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", WEB);
    let inv = f.inventory();
    f.fake_ssh("hostname 127.0.0.1\n");
    for phase in ["plan", "apply", "audit"] {
        for flag in ["--hosts", "--inventory"] {
            let o = f.run(&[phase, &r, "--host", "x", flag, &inv]);
            assert_eq!(o.status.code(), Some(2), "{phase} {flag}: {o:?}");
            assert!(stderr(&o).contains("mutually exclusive"), "{}", stderr(&o));
        }
    }
    assert!(f.ssh_log().is_none());
}

#[test]
fn inventory_without_recipe_targets_fails_closed() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "");
    let inv = f.inventory();
    f.fake_ssh("hostname 127.0.0.1\n");
    for phase in ["plan", "apply", "audit"] {
        let o = f.run(&[phase, &r, "--hosts", &inv, "--format", "json"]);
        assert_eq!(o.status.code(), Some(2), "{phase}: {o:?}");
        assert!(stdout(&o).is_empty(), "nothing may run: {}", stdout(&o));
        assert!(stderr(&o).contains("declares no targets"), "{}", stderr(&o));
    }
    assert!(f.ssh_log().is_none(), "no host may even be resolved");
}

#[test]
fn group_target_selects_only_its_members() {
    let f = Fx::new();
    let r = f.recipe("nginx.yaml", WEB);
    let inv = f.inventory();
    let o = f.run(&[
        "plan",
        &r,
        "--hosts",
        &inv,
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    let v = json(&o);
    let ex: Vec<_> = executions(&v).into_iter().map(|(r, t, _)| (r, t)).collect();
    assert_eq!(
        ex,
        vec![
            ("nginx".to_string(), "web01".to_string()),
            ("nginx".to_string(), "web02".to_string())
        ]
    );
    let hosts = v["resolution"][0]["hosts"].as_array().unwrap();
    let db = hosts.iter().find(|h| h["name"] == "db01").unwrap();
    assert_eq!(db["selected"], false);
    let web = hosts.iter().find(|h| h["name"] == "web01").unwrap();
    assert_eq!(web["reasons"][0], "group:web");
    assert!(
        !stderr(&o).contains("db01"),
        "a skipped host is never contacted"
    );
    // Target identity (evidence): inventory name plus resolved endpoint.
    assert_eq!(v["executions"][0]["target"]["user"], "inv-web01");
    assert_eq!(v["executions"][0]["target"]["host"], "127.0.0.1");
    assert_eq!(v["inventory"], inv);
}

#[test]
fn host_and_group_targets_union() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "targets:\n  hosts: [db01]\n  groups: [web]\n");
    let inv = f.inventory();
    let o = f.run(&[
        "plan",
        &r,
        "--hosts",
        &inv,
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    let ex: Vec<_> = executions(&json(&o)).into_iter().map(|e| e.1).collect();
    assert_eq!(ex, vec!["db01", "web01", "web02"]);
}

#[test]
fn single_host_target() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "targets:\n  hosts: [db01]\n");
    let inv = f.inventory();
    let o = f.run(&[
        "plan",
        &r,
        "--hosts",
        &inv,
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    let ex: Vec<_> = executions(&json(&o)).into_iter().map(|e| e.1).collect();
    assert_eq!(ex, vec!["db01"]);
}

#[test]
fn unknown_target_names_fail_closed() {
    let f = Fx::new();
    let inv = f.inventory();
    for t in [
        "targets:\n  hosts: [web03]\n",
        "targets:\n  groups: [cache]\n",
        "targets:\n  hosts: [web01]\n  groups: [cache]\n",
    ] {
        let r = f.recipe("r.yaml", t);
        let o = f.run(&["plan", &r, "--hosts", &inv, "--no-ssh-config"]);
        assert_eq!(o.status.code(), Some(2), "{t}: {o:?}");
        assert!(stdout(&o).is_empty());
    }
}

#[test]
fn malformed_and_missing_inventories_exit_2() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", WEB);
    let cases = [
        f.path("missing.yaml").display().to_string(),
        f.write("m.yaml", "hosts: [\n"),
        f.write(
            "u.yaml",
            "hosts:\n  web01:\n    host: 10.0.0.1\ngroups:\n  web:\n    hosts: [web01]\n",
        ),
        f.write(
            "g.yaml",
            "hosts:\n  web01: {}\ngroups:\n  web:\n    hosts: [web01, web09]\n",
        ),
        f.write("e.yaml", "hosts: {}\n"),
        f.write("d.yaml", "hosts:\n  web01: {}\n  web01: {}\n"),
    ];
    for inv in &cases {
        let o = f.run(&["plan", &r, "--hosts", inv, "--no-ssh-config"]);
        assert_eq!(o.status.code(), Some(2), "{inv}: {o:?}");
        assert!(stderr(&o).contains("inventory"), "{}", stderr(&o));
    }
}

#[test]
fn duplicate_resolved_address_is_rejected_before_connecting() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", WEB);
    let inv = f.write(
        "dup.yaml",
        "hosts:\n  web01:\n    address: 127.0.0.1\n    port: 2222\n  web02:\n    address: 127.0.0.1\n    port: 2222\ngroups:\n  web:\n    hosts: [web01, web02]\n",
    );
    let o = f.run(&[
        "plan",
        &r,
        "--hosts",
        &inv,
        "--no-ssh-config",
        "--user",
        "u",
    ]);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(stderr(&o).contains("same address"), "{}", stderr(&o));
    assert!(stdout(&o).is_empty());
}

#[test]
fn skipped_hosts_are_never_resolved() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "targets:\n  hosts: [web01]\n");
    let inv = f.write(
        "h.yaml",
        "hosts:\n  web01:\n    address: web01-alias\n  db01:\n    address: db01-alias\n",
    );
    f.fake_ssh(&format!(
        "hostname 127.0.0.1\nport {}\nuser u\n",
        closed_port()
    ));
    let o = f.run(&["plan", &r, "--hosts", &inv]);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    let log = f.ssh_log().unwrap();
    assert!(log.contains("web01-alias"), "{log}");
    assert!(!log.contains("db01-alias"), "{log}");
}

#[test]
fn read_only_phases_attempt_every_selected_host() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", WEB);
    let inv = f.inventory();
    for phase in ["plan", "audit"] {
        let o = f.run(&[
            phase,
            &r,
            "--hosts",
            &inv,
            "--no-ssh-config",
            "--format",
            "json",
        ]);
        assert_eq!(o.status.code(), Some(3), "{phase}: {o:?}");
        let v = json(&o);
        assert_eq!(v["mode"], phase);
        assert_eq!(v["exit_code"], 3);
        for e in v["executions"].as_array().unwrap() {
            assert_eq!(e["status"], "error");
            assert_eq!(e["exit_code"], 3);
            assert_eq!(e["error"]["kind"], "connect");
        }
        assert!(stderr(&o).contains("[r @ web01]") && stderr(&o).contains("[r @ web02]"));
    }
}

#[test]
fn apply_stops_at_the_first_failed_execution() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", WEB);
    let inv = f.inventory();
    let o = f.run(&[
        "apply",
        &r,
        "--hosts",
        &inv,
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    let v = json(&o);
    let ex = executions(&v);
    assert_eq!(ex[0].2, "error");
    assert_eq!(ex[1].2, "not_run");
    assert!(v["executions"][1]["exit_code"].is_null());
    assert!(v["executions"][1]["reason"]
        .as_str()
        .unwrap()
        .contains("r @ web01"));
    assert!(
        !stderr(&o).contains("web02]"),
        "web02 must not be attempted"
    );
}

#[test]
fn text_output_shows_resolution_and_summary() {
    let f = Fx::new();
    let r = f.recipe("nginx.yaml", WEB);
    let inv = f.inventory();
    let o = f.run(&["plan", &r, "--hosts", &inv, "--no-ssh-config"]);
    let out = stdout(&o);
    assert_no_ansi(&o.stdout, "piped text");
    assert!(out.contains("== target resolution =="), "{out}");
    assert!(out.contains("db01   SKIP   no matching target"), "{out}");
    assert!(out.contains("web01  MATCH  group:web"), "{out}");
    assert!(out.contains("selected 2, excluded 1"), "{out}");
    assert!(
        out.contains("executions: 2 (1 recipe(s), 3 host(s))"),
        "{out}"
    );
    assert!(
        out.contains("== nginx @ web01 (inv-web01@127.0.0.1:"),
        "{out}"
    );
    assert!(
        out.contains("executions: 2 total, 0 exit 0, 2 non-zero, 0 not run"),
        "{out}"
    );
}

// ---------------------------------------------------------------------------
// bundles
// ---------------------------------------------------------------------------

#[test]
fn bundle_resolves_each_recipe_against_its_own_targets() {
    let f = Fx::new();
    f.recipe("common.yaml", "targets:\n  groups: [linux]\n");
    f.recipe("nginx.yaml", WEB);
    f.recipe("postgres.yaml", "targets:\n  groups: [db]\n");
    let b = f.write(
        "stack.yaml",
        "version: 1\nname: stack\nrecipes: [common.yaml, nginx.yaml, postgres.yaml]\n",
    );
    let inv = f.inventory();
    let o = f.run(&[
        "plan",
        &b,
        "--hosts",
        &inv,
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    let v = json(&o);
    let ex: Vec<_> = executions(&v)
        .into_iter()
        .map(|(r, t, _)| format!("{r}@{t}"))
        .collect();
    // 3 + 2 + 1 = 6 executions, not 3 recipes x 3 hosts = 9.
    assert_eq!(
        ex,
        vec![
            "common@db01",
            "common@web01",
            "common@web02",
            "nginx@web01",
            "nginx@web02",
            "postgres@db01"
        ]
    );
    assert_eq!(v["bundle"]["name"], "stack");
    assert_eq!(v["resolution"].as_array().unwrap().len(), 3);
}

#[test]
fn bundle_with_an_untargeted_recipe_fails_closed() {
    let f = Fx::new();
    f.recipe("common.yaml", "targets:\n  groups: [linux]\n");
    f.recipe("loose.yaml", "");
    let b = f.write(
        "stack.yaml",
        "version: 1\nrecipes: [common.yaml, loose.yaml]\n",
    );
    let inv = f.inventory();
    let o = f.run(&["apply", &b, "--hosts", &inv, "--no-ssh-config"]);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(
        stdout(&o).is_empty(),
        "not even common may run: {}",
        stdout(&o)
    );
    assert!(
        stderr(&o).contains("recipe loose declares no targets"),
        "{}",
        stderr(&o)
    );
}

#[test]
fn bundle_apply_stops_across_recipes() {
    let f = Fx::new();
    f.recipe("common.yaml", "targets:\n  hosts: [db01]\n");
    f.recipe("nginx.yaml", WEB);
    let b = f.write(
        "stack.yaml",
        "version: 1\nrecipes: [common.yaml, nginx.yaml]\n",
    );
    let inv = f.inventory();
    let o = f.run(&[
        "apply",
        &b,
        "--hosts",
        &inv,
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    let st: Vec<_> = executions(&json(&o)).into_iter().map(|e| e.2).collect();
    assert_eq!(st, vec!["error", "not_run", "not_run"]);
}

#[test]
fn bundle_on_one_explicit_host_runs_each_recipe_there() {
    let f = Fx::new();
    f.recipe("a.yaml", "");
    f.recipe("b.yaml", WEB);
    let b = f.write("stack.yaml", "version: 1\nrecipes: [a.yaml, b.yaml]\n");
    let port = closed_port().to_string();
    let o = f.run(&[
        "plan",
        &b,
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--user",
        "u",
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    let v = json(&o);
    let ex: Vec<_> = executions(&v)
        .into_iter()
        .map(|(r, t, _)| format!("{r}@{t}"))
        .collect();
    assert_eq!(ex, vec!["a@127.0.0.1", "b@127.0.0.1"]);
    assert!(v["resolution"].is_null() && v["inventory"].is_null());
}

// ---------------------------------------------------------------------------
// single host compatibility
// ---------------------------------------------------------------------------

#[test]
fn single_host_keeps_the_single_document_contract() {
    let f = Fx::new();
    // `targets` only matter with an inventory; an explicit --host is the
    // operator's explicit choice and keeps its established behavior.
    let r = f.recipe("r.yaml", "targets:\n  groups: [db]\n");
    let port = closed_port().to_string();
    let o = f.run(&[
        "plan",
        &r,
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--user",
        "u",
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(
        stdout(&o).is_empty(),
        "failure before a report prints no document"
    );
    assert!(
        stderr(&o).starts_with("sinter: cannot connect to 127.0.0.1:"),
        "{}",
        stderr(&o)
    );
}

// ---------------------------------------------------------------------------
// OpenSSH configuration inheritance and precedence (scripted `ssh -G`)
// ---------------------------------------------------------------------------

#[test]
fn ssh_config_supplies_hostname_port_user() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "");
    let port = closed_port();
    f.fake_ssh(&format!(
        "user configuser\nhostname 127.0.0.1\nport {port}\n"
    ));
    let o = f.run(&["plan", &r, "--host", "web01-alias"]);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(
        stderr(&o).contains(&format!("cannot connect to 127.0.0.1:{port}")),
        "{}",
        stderr(&o)
    );
    assert!(f.ssh_log().unwrap().contains("-G -- web01-alias"));
}

#[test]
fn precedence_cli_over_inventory_over_ssh_config() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "targets:\n  hosts: [a, b]\n");
    let (pa, pb) = match closed_ports(2)[..] {
        [a, b] => (a, b),
        _ => unreachable!(),
    };
    // a states user and port in the inventory, b states nothing.
    let inv = f.write(
        "h.yaml",
        &format!("hosts:\n  a:\n    address: a-alias\n    user: invuser\n    port: {pa}\n  b:\n    address: b-alias\n"),
    );
    // The scripted client ignores -l/-p and always answers the same, so a
    // value that differs from it must have come from Sinter's precedence.
    f.fake_ssh(&format!("user configuser\nhostname 127.0.0.1\nport {pb}\n"));
    let run = |extra: &[&str]| {
        let mut args = vec![
            "plan",
            r.as_str(),
            "--hosts",
            inv.as_str(),
            "--format",
            "json",
        ];
        args.extend_from_slice(extra);
        let v = json(&f.run(&args));
        let t = |i: usize| v["executions"][i]["target"].clone();
        (t(0), t(1))
    };
    let (a, b) = run(&[]);
    assert_eq!(
        (a["user"].as_str(), a["port"].as_u64()),
        (Some("invuser"), Some(pa as u64))
    );
    assert_eq!(
        (b["user"].as_str(), b["port"].as_u64()),
        (Some("configuser"), Some(pb as u64))
    );
    let (a, b) = run(&["--user", "cliuser"]);
    assert_eq!(a["user"], "cliuser");
    assert_eq!(b["user"], "cliuser");
    let log = f.ssh_log().unwrap();
    assert!(
        log.contains("-l invuser") && log.contains("-l cliuser"),
        "{log}"
    );
}

#[test]
fn proxy_jump_fails_closed() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "");
    f.fake_ssh("hostname 10.0.0.5\nport 22\nuser u\nproxyjump bastion\n");
    let o = f.run(&["plan", &r, "--host", "internal"]);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(stderr(&o).contains("ProxyJump"), "{}", stderr(&o));
    assert!(!stderr(&o).contains("cannot connect"));
}

#[test]
fn no_ssh_config_skips_openssh() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "");
    f.fake_ssh("hostname 10.255.255.1\n");
    let port = closed_port();
    let o = f.run(&[
        "plan",
        &r,
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--user",
        "u",
        "--no-ssh-config",
    ]);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(f.ssh_log().is_none());
    assert!(
        stderr(&o).contains(&format!("127.0.0.1:{port}")),
        "{}",
        stderr(&o)
    );
}

#[test]
fn failing_ssh_config_evaluation_is_a_connect_error() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "");
    let bin_dir = f.path("fakebin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let p = bin_dir.join("ssh");
    std::fs::write(
        &p,
        "#!/bin/sh\necho 'bad configuration option' >&2\nexit 255\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    let o = f.run(&["plan", &r, "--host", "web01"]);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert!(stderr(&o).contains("--no-ssh-config"), "{}", stderr(&o));
}

// ---------------------------------------------------------------------------
// color
// ---------------------------------------------------------------------------

/// Run the binary under a pseudo-terminal with `script(1)`.
fn run_in_pty(args: &[&str], no_color: Option<&str>) -> Option<Vec<u8>> {
    let mut c = if cfg!(target_os = "linux") {
        let quote = |a: &str| format!("'{}'", a.replace('\'', "'\\''"));
        let line = std::iter::once(bin())
            .chain(args.iter().copied())
            .map(quote)
            .collect::<Vec<_>>()
            .join(" ");
        let mut c = Command::new("script");
        c.args(["-qec", &line, "/dev/null"]);
        c
    } else {
        let mut c = Command::new("script");
        c.arg("-q").arg("/dev/null").arg(bin()).args(args);
        c
    };
    c.env("TERM", "xterm").env_remove("NO_COLOR");
    if let Some(v) = no_color {
        c.env("NO_COLOR", v);
    }
    c.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().ok()?;
    drop(child.stdin.take().map(|mut i| i.flush()));
    Some(child.wait_with_output().ok()?.stdout)
}

macro_rules! pty_or_skip {
    ($e:expr) => {
        match $e {
            Some(o) => o,
            None => {
                eprintln!("SINTER_TEST_SKIPPED: script(1) unavailable");
                return;
            }
        }
    };
}

#[test]
fn tty_output_is_colored() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "");
    let out = pty_or_skip!(run_in_pty(&["validate", &r], None));
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("\x1b[32mok\x1b[0m:"), "{text:?}");
    let bad = f.write("bad.yaml", "version: 2\n");
    let out = pty_or_skip!(run_in_pty(&["validate", &bad], None));
    assert!(
        String::from_utf8_lossy(&out).contains("\x1b[31msinter:\x1b[0m"),
        "{out:?}"
    );
    let inv = f.inventory();
    let r = f.recipe("n.yaml", WEB);
    let out = pty_or_skip!(run_in_pty(
        &["plan", &r, "--hosts", &inv, "--no-ssh-config"],
        None
    ));
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("\x1b[32mMATCH\x1b[0m"), "{text:?}");
    assert!(text.contains("\x1b[31merror\x1b[0m"), "{text:?}");
}

#[test]
fn no_color_disables_tty_color() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", "");
    let out = pty_or_skip!(run_in_pty(&["validate", &r], Some("1")));
    assert_no_ansi(&out, "NO_COLOR");
    assert!(String::from_utf8_lossy(&out).contains("ok: 1 resource(s)"));
}

#[test]
fn json_is_never_colored_even_on_a_tty() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", WEB);
    let out = pty_or_skip!(run_in_pty(&["validate", &r, "--format", "json"], None));
    assert_no_ansi(&out, "json on tty");
    let inv = f.inventory();
    let out = pty_or_skip!(run_in_pty(
        &[
            "plan",
            &r,
            "--hosts",
            &inv,
            "--no-ssh-config",
            "--format",
            "json"
        ],
        None
    ));
    // stderr diagnostics share the pty; the JSON document itself is plain.
    let text = String::from_utf8_lossy(&out);
    let (start, end) = (text.find('{').unwrap(), text.rfind('}').unwrap());
    assert_no_ansi(text[start..=end].as_bytes(), "multi-host json on tty");
}

#[test]
fn piped_output_is_never_colored() {
    let f = Fx::new();
    let r = f.recipe("r.yaml", WEB);
    let o = f
        .cmd(&["validate", &r])
        .env("TERM", "xterm")
        .env_remove("NO_COLOR")
        .output()
        .unwrap();
    assert_no_ansi(&o.stdout, "piped validate");
    let bad = f.write("bad.yaml", "version: 2\n");
    assert_no_ansi(&f.run(&["validate", &bad]).stderr, "piped stderr");
    let inv = f.inventory();
    let o = f.run(&["audit", &r, "--hosts", &inv, "--no-ssh-config"]);
    assert_no_ansi(&o.stdout, "piped multi-host audit text");
    assert_no_ansi(&o.stderr, "piped multi-host stderr");
}

// ---------------------------------------------------------------------------
// aggregate JSON: execution-level backup record (F-03)
// ---------------------------------------------------------------------------

fn backup_recipe(f: &Fx, name: &str, targets: &str, path: &str) -> String {
    f.write(
        name,
        &format!(
            "version: 1\n{targets}backup:\n  paths: [{path}]\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n"
        ),
    )
}

#[test]
fn aggregate_backup_record_per_phase() {
    let f = Fx::new();
    let r = backup_recipe(&f, "r.yaml", WEB, "/etc/example.conf");
    let inv = f.inventory();
    let run = |phase: &str| {
        let o = f.run(&[
            phase,
            &r,
            "--hosts",
            &inv,
            "--no-ssh-config",
            "--format",
            "json",
        ]);
        json(&o)["executions"].as_array().unwrap().clone()
    };
    for e in run("plan") {
        let b = &e["backup"];
        assert_eq!(b["status"], "planned", "{e}");
        assert!(b["run_id"].is_null() && b["directory"].is_null());
        assert_eq!(b["entries"][0]["path"], "/etc/example.conf");
        assert_eq!(b["entries"][0]["status"], "planned");
    }
    let ex = run("apply");
    // web01 failed to connect before the backup step; web02 was not run.
    assert_eq!(ex[0]["backup"]["status"], "not_started");
    assert_eq!(ex[0]["backup"]["entries"][0]["status"], "not_run");
    assert!(ex[0]["backup"]["directory"].is_null());
    assert_eq!(ex[1]["status"], "not_run");
    assert_eq!(ex[1]["backup"]["status"], "not_run");
    assert_eq!(ex[1]["backup"]["entries"][0]["status"], "not_run");
    for e in run("audit") {
        assert!(e["backup"].is_null(), "audit does not handle backups: {e}");
    }
}

#[test]
fn aggregate_backup_record_follows_recipe_identity() {
    let f = Fx::new();
    backup_recipe(&f, "withbackup.yaml", WEB, "/etc/web.conf");
    f.recipe("nobackup.yaml", "targets:\n  groups: [db]\n");
    let b = f.write(
        "stack.yaml",
        "version: 1\nrecipes: [withbackup.yaml, nobackup.yaml]\n",
    );
    let inv = f.inventory();
    let o = f.run(&[
        "plan",
        &b,
        "--hosts",
        &inv,
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    let v = json(&o);
    let rows: Vec<(String, String, serde_json::Value)> = v["executions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["recipe"].as_str().unwrap().to_string(),
                e["target"]["name"].as_str().unwrap().to_string(),
                e["backup"].clone(),
            )
        })
        .collect();
    assert_eq!(rows.len(), 3);
    for (recipe, host, backup) in &rows {
        match recipe.as_str() {
            "withbackup" => {
                assert!(host.starts_with("web"), "{host}");
                assert_eq!(backup["entries"][0]["path"], "/etc/web.conf");
            }
            "nobackup" => {
                assert_eq!(host, "db01");
                assert!(backup.is_null(), "no backup declared: {backup}");
            }
            other => panic!("unexpected recipe {other}"),
        }
    }
}

#[test]
fn single_host_json_has_no_execution_level_backup_field() {
    // The established single-target document is unchanged: backup data (if
    // any) lives only in its own `backup` key, never an envelope.
    let f = Fx::new();
    let r = backup_recipe(&f, "r.yaml", "", "/etc/x.conf");
    let o = f.run(&["validate", &r, "--format", "json"]);
    let v = json(&o);
    assert!(v.get("executions").is_none() && v.get("backup").is_none());
}

#[test]
fn overlapping_selection_executes_each_host_once() {
    let f = Fx::new();
    let r = f.recipe(
        "r.yaml",
        "targets:\n  hosts: [web01, web02]\n  groups: [web, linux]\n",
    );
    let inv = f.inventory();
    let o = f.run(&[
        "plan",
        &r,
        "--hosts",
        &inv,
        "--no-ssh-config",
        "--format",
        "json",
    ]);
    let v = json(&o);
    let ex: Vec<_> = executions(&v).into_iter().map(|e| e.1).collect();
    assert_eq!(ex, vec!["db01", "web01", "web02"], "each host exactly once");
    let web01 = v["resolution"][0]["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == "web01")
        .unwrap()
        .clone();
    assert_eq!(
        web01["reasons"],
        serde_json::json!(["host:web01", "group:web", "group:linux"])
    );
}
