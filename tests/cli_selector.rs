//! CLI surface of the selector argument, inventory auto-detection and the
//! short options (FR-072..074, DESIGN §39).
//!
//! No test needs a reachable host. Inventory hosts point at listeners this test
//! owns (to count connections) or at closed loopback ports (to observe which
//! executions were attempted). `ssh` is a script on PATH that records every
//! call, so a test can tell whether `ssh -G` ran.

mod common;

use std::net::TcpListener;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

struct Fx {
    dir: tempfile::TempDir,
}

/// Targets group `web`.
const WEB: &str = "version: 1\ntargets:\n  groups: [web]\nresources:\n  - id: a\n    type: file\n    with: { path: /srv/a, content: x }\n";
/// Declares no `targets`.
const FREE: &str =
    "version: 1\nresources:\n  - id: a\n    type: file\n    with: { path: /srv/a, content: x }\n";
const PHASES: [&str; 3] = ["plan", "audit", "apply"];
const ALL: [&str; 4] = ["validate", "plan", "audit", "apply"];

impl Fx {
    fn new() -> Self {
        let f = Fx {
            dir: tempfile::tempdir().unwrap(),
        };
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        f.mkdir("fakebin");
        f.set_ssh("");
        f
    }

    /// A scripted `ssh`: logs its arguments, runs `extra`, answers like `ssh -G`.
    fn set_ssh(&self, extra: &str) {
        let p = self.path("fakebin/ssh");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n{extra}\nprintf 'hostname 127.0.0.1\\n'\n",
                self.path("fakebin/ssh.log").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Creates `name` and any missing parents below the fixture root with mode
    /// 755, whatever the umask. A directory that already exists keeps its mode
    /// (a test may have loosened it on purpose), and a symbolic link on the way
    /// is an error: nothing is followed, nothing outside the root is touched.
    fn mkdir(&self, name: &str) {
        let mut p = self.dir.path().to_path_buf();
        for part in Path::new(name).components() {
            let Component::Normal(part) = part else {
                panic!("{name} is not a relative path below the fixture root");
            };
            p.push(part);
            match std::fs::create_dir(&p) {
                Ok(()) => {
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap()
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let md = std::fs::symlink_metadata(&p).unwrap();
                    assert!(md.is_dir(), "{} is not a directory", p.display());
                }
                Err(e) => panic!("{}: {e}", p.display()),
            }
        }
    }

    fn write(&self, name: &str, body: &str) -> String {
        let p = self.path(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        p.display().to_string()
    }

    /// web01, web02 (group web), db01 (group db), without `known_hosts`.
    fn hosts_body(ports: [u16; 3]) -> String {
        let host = |name: &str, port: u16| {
            format!("  {name}:\n    address: 127.0.0.1\n    port: {port}\n    user: u\n")
        };
        format!(
            "hosts:\n{}{}{}groups:\n  web:\n    hosts: [web01, web02]\n  db:\n    hosts: [db01]\n",
            host("web01", ports[0]),
            host("web02", ports[1]),
            host("db01", ports[2]),
        )
    }

    fn ssh_log(&self) -> Vec<String> {
        std::fs::read_to_string(self.path("fakebin/ssh.log"))
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn run_in(&self, cwd: &str, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sinter"))
            .args(args)
            .current_dir(self.path(cwd))
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

    fn run(&self, args: &[&str]) -> Output {
        self.run_in(".", args)
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!("{e}: {} / {}", text(&o.stdout), text(&o.stderr));
    })
}

fn executed(o: &Output) -> Vec<String> {
    json(o)["executions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["target"]["name"].as_str().unwrap().to_string())
        .collect()
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

/// A project with `hosts.yaml` on closed ports and both kinds of recipe.
fn project() -> (Fx, common::ClosedPorts) {
    project_with_ports(3)
}

/// A thread may hold one `ClosedPorts` at a time, so a test that needs more
/// asks for them here. The first three are the ones in `hosts.yaml`.
fn project_with_ports(n: usize) -> (Fx, common::ClosedPorts) {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(n);
    f.write(
        "hosts.yaml",
        &Fx::hosts_body([ports.port(0), ports.port(1), ports.port(2)]),
    );
    f.write("web.yaml", WEB);
    f.write("free.yaml", FREE);
    (f, ports)
}

// --- FR-072: which hosts run ---------------------------------------------

#[test]
fn a_selector_runs_exactly_the_named_hosts_in_every_phase() {
    let (f, _ports) = project();
    let cases: &[(&str, &str, &[&str])] = &[
        ("web.yaml", "web01", &["web01"]),
        ("web.yaml", "web02,web01", &["web01", "web02"]),
        ("web.yaml", "@web", &["web01", "web02"]),
        ("web.yaml", "web01,@web,web01", &["web01", "web02"]),
        ("web.yaml", "web01,web01", &["web01"]),
        ("free.yaml", "db01", &["db01"]),
        ("free.yaml", "web01,db01", &["db01", "web01"]),
        ("free.yaml", "@web", &["web01", "web02"]),
        ("free.yaml", "@web,@db", &["db01", "web01", "web02"]),
        ("free.yaml", "@web,db01,web01", &["db01", "web01", "web02"]),
    ];
    for (recipe, selector, want) in cases {
        for phase in PHASES {
            let _ = std::fs::remove_file(f.path("fakebin/ssh.log"));
            let o = f.run(&[phase, recipe, selector, "--format", "json"]);
            // Closed ports: every attempted execution fails to connect.
            assert_eq!(
                o.status.code(),
                Some(3),
                "{recipe} {selector} {phase}: {}",
                text(&o.stderr)
            );
            assert_eq!(executed(&o), *want, "{recipe} {selector} {phase}");
            assert_eq!(
                f.ssh_log().len(),
                want.len(),
                "ssh -G runs once per host: {:?}",
                f.ssh_log()
            );
            let doc = json(&o);
            assert_eq!(doc["inventory_source"], "detected");
            assert!(doc["inventory"].as_str().unwrap().ends_with("/hosts.yaml"));
            assert!(doc.get("limit").is_none());
            assert_eq!(
                doc["selector"].as_array().unwrap().len(),
                selector
                    .split(',')
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            );
            let declared = *recipe == "web.yaml";
            assert_eq!(doc["resolution"][0]["targets_declared"], declared);
        }
    }
}

#[test]
fn a_host_and_a_group_of_one_name_are_told_apart() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let host = |n: &str, p: u16| format!("  {n}: {{ address: 127.0.0.1, port: {p}, user: u }}\n");
    f.write(
        "hosts.yaml",
        &format!(
            "hosts:\n{}{}{}groups:\n  web:\n    hosts: [web01, web02]\n",
            host("web", ports.port(0)),
            host("web01", ports.port(1)),
            host("web02", ports.port(2)),
        ),
    );
    f.write("free.yaml", FREE);
    let o = f.run(&["plan", "free.yaml", "web", "--format", "json"]);
    assert_eq!(executed(&o), ["web"]);
    let o = f.run(&["plan", "free.yaml", "@web", "--format", "json"]);
    assert_eq!(executed(&o), ["web01", "web02"]);
}

#[test]
fn a_wrong_selector_is_exit_2_with_nothing_evaluated_or_contacted() {
    let f = Fx::new();
    let (a, b, c) = (Listener::new(), Listener::new(), Listener::new());
    f.write(
        "hosts.yaml",
        &Fx::hosts_body([a.port(), b.port(), c.port()]),
    );
    f.write("web.yaml", WEB);
    f.write("free.yaml", FREE);
    f.write(
        "empty-targets.yaml",
        "version: 1\ntargets:\n  hosts: []\nresources: []\n",
    );
    f.write("one.yaml", WEB);
    f.write("bundle.yaml", "version: 1\nrecipes: [free.yaml]\n");
    let before = text(&std::fs::read(f.path("hosts.yaml")).unwrap());
    let cases: &[(&str, &str)] = &[
        // Unknown names.
        ("web.yaml", "nosuch"),
        ("web.yaml", "@nosuch"),
        ("free.yaml", "nosuch"),
        ("free.yaml", "@nosuch"),
        ("free.yaml", "web01,nosuch"),
        ("free.yaml", "@web,@nosuch"),
        // A name of the other kind.
        ("free.yaml", "web"),
        ("free.yaml", "@web01"),
        // Outside `targets`, so it would widen or run nothing.
        ("web.yaml", "db01"),
        ("web.yaml", "@db"),
        ("web.yaml", "web01,db01"),
        // Empty, malformed, patterns, an implicit all.
        ("free.yaml", ""),
        ("free.yaml", ","),
        ("free.yaml", "web01,"),
        ("free.yaml", "@"),
        ("free.yaml", "*"),
        ("free.yaml", "web*"),
        ("free.yaml", "all"),
        ("free.yaml", "@all"),
        ("free.yaml", "host:web01"),
        ("free.yaml", "group:web"),
        ("free.yaml", "localhost"),
        // targets declared but naming nothing, and a bundle recipe without them.
        ("empty-targets.yaml", "web01"),
        ("bundle.yaml", "web01"),
        ("bundle.yaml", "@web"),
    ];
    for (recipe, selector) in cases {
        for phase in ALL {
            let o = f.run(&[phase, recipe, selector]);
            assert_eq!(
                o.status.code(),
                Some(2),
                "{phase} {recipe} {selector:?}: {} / {}",
                text(&o.stdout),
                text(&o.stderr)
            );
            assert!(
                !text(&o.stdout).contains("executions:"),
                "{phase} {recipe} {selector:?}: {}",
                text(&o.stdout)
            );
        }
    }
    assert!(f.ssh_log().is_empty(), "ssh -G ran: {:?}", f.ssh_log());
    assert_eq!(
        a.accepted() + b.accepted() + c.accepted(),
        0,
        "a host was contacted"
    );
    assert_eq!(text(&std::fs::read(f.path("hosts.yaml")).unwrap()), before);
}

#[test]
fn a_selector_excludes_host_and_limit_and_needs_one_argument() {
    let (f, _ports) = project();
    let cases: &[&[&str]] = &[
        &["web.yaml", "web01", "--host", "web01"],
        &["web.yaml", "web01", "-H", "web01"],
        &["web.yaml", "web01", "--limit", "web01"],
        &[
            "web.yaml",
            "@web",
            "--inventory",
            "hosts.yaml",
            "--limit",
            "web01",
        ],
        &[
            "web.yaml",
            "web01",
            "--inventory",
            "hosts.yaml",
            "--host",
            "x",
        ],
        // One selector only: a list uses commas.
        &["web.yaml", "web01", "web02"],
    ];
    for phase in ALL {
        for args in cases {
            let mut all = vec![phase];
            all.extend_from_slice(args);
            let o = f.run(&all);
            assert_eq!(o.status.code(), Some(2), "{all:?}: {}", text(&o.stderr));
        }
    }
    assert!(f.ssh_log().is_empty(), "{:?}", f.ssh_log());
}

#[test]
fn targets_and_limit_keep_their_rules() {
    let (f, _ports) = project();
    // A recipe without targets stays an error with --inventory or --limit alone.
    for args in [
        vec!["plan", "free.yaml", "--inventory", "hosts.yaml"],
        vec![
            "plan",
            "free.yaml",
            "--inventory",
            "hosts.yaml",
            "--limit",
            "web01",
        ],
        vec![
            "validate",
            "free.yaml",
            "--inventory",
            "hosts.yaml",
            "--limit",
            "web01",
        ],
        // --limit never finds an inventory by itself.
        vec!["plan", "web.yaml", "--limit", "web01"],
    ] {
        let o = f.run(&args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", text(&o.stderr));
    }
    assert!(f.ssh_log().is_empty());
    // A targets recipe narrowed by --limit reports as it always did.
    let o = f.run(&[
        "plan",
        "web.yaml",
        "--inventory",
        "hosts.yaml",
        "--limit",
        "web01",
        "--format",
        "json",
    ]);
    let doc = json(&o);
    assert_eq!(doc["limit"], serde_json::json!(["web01"]));
    assert!(doc.get("selector").is_none());
    assert!(doc.get("inventory_source").is_none());
    assert!(doc["resolution"][0].get("targets_declared").is_none());
    let hosts = doc["resolution"][0]["hosts"].as_array().unwrap();
    assert!(hosts.iter().any(|h| h["excluded_by"] == "limit"));
}

#[test]
fn bundles_are_narrowed_and_a_recipe_left_without_hosts_is_skipped() {
    let (f, _ports) = project();
    f.write(
        "db.yaml",
        "version: 1\ntargets:\n  groups: [db]\nresources:\n  - id: d\n    type: file\n    with: { path: /srv/d, content: y }\n",
    );
    f.write("bundle.yaml", "version: 1\nrecipes: [web.yaml, db.yaml]\n");
    let o = f.run(&["plan", "bundle.yaml", "web01", "--format", "json"]);
    assert_eq!(executed(&o), ["web01"]);
    let doc = json(&o);
    assert_eq!(doc["resolution"][1]["excluded_by"], "selector");
    assert_eq!(doc["resolution"][0]["targets_declared"], true);
    let web02 = doc["resolution"][0]["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == "web02")
        .unwrap()
        .clone();
    assert_eq!(web02["excluded_by"], "selector");
    let o = f.run(&["plan", "bundle.yaml", "@web,@db", "--format", "json"]);
    assert_eq!(executed(&o), ["web01", "web02", "db01"]);
    let o = f.run(&["validate", "bundle.yaml", "web01"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains("excluded by selector, not frozen"), "{out}");
    assert!(
        out.contains("ok: selector web01 selects 1 of 3 execution(s)"),
        "{out}"
    );
}

#[test]
fn validate_contacts_nothing_and_reports_the_selection() {
    let f = Fx::new();
    let (a, b, c) = (Listener::new(), Listener::new(), Listener::new());
    f.write(
        "hosts.yaml",
        &Fx::hosts_body([a.port(), b.port(), c.port()]),
    );
    f.write("web.yaml", WEB);
    f.write("free.yaml", FREE);
    let o = f.run(&["validate", "free.yaml", "@web", "--format", "json"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let doc = json(&o);
    assert_eq!(doc["selector"], serde_json::json!(["@web"]));
    assert_eq!(doc["inventory_source"], "detected");
    assert_eq!(doc["selected_executions"], 2);
    assert_eq!(doc["targeted_executions"], 2);
    assert!(
        text(&o.stderr).contains("(auto-detected)"),
        "{}",
        text(&o.stderr)
    );
    let o = f.run(&["validate", "web.yaml", "web01"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.starts_with("inventory: "), "{out}");
    assert!(out.contains("hosts.yaml (auto-detected)"), "{out}");
    assert!(
        out.contains("ok: selector web01 selects 1 of 2 execution(s)"),
        "{out}"
    );
    assert!(f.ssh_log().is_empty(), "{:?}", f.ssh_log());
    assert_eq!(a.accepted() + b.accepted() + c.accepted(), 0);
}

#[test]
fn text_output_names_the_source_and_a_recipe_without_targets() {
    let (f, _ports) = project();
    let o = f.run(&["plan", "free.yaml", "web01"]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.starts_with("inventory: "), "{out}");
    assert!(out.contains("hosts.yaml (auto-detected)"), "{out}");
    assert!(out.contains("selector: web01"), "{out}");
    assert!(out.contains("targets: none declared"), "{out}");
    assert!(out.contains("not named by the selector"), "{out}");
    assert!(out.contains("selected 1, excluded 2\n"), "{out}");
    assert!(!out.contains("--limit"), "{out}");
    let o = f.run(&["plan", "web.yaml", "web01"]);
    let out = text(&o.stdout);
    assert!(
        out.contains("excluded by the selector (matched: group:web)"),
        "{out}"
    );
    assert!(!out.contains("targets: none declared"), "{out}");
    assert!(!out.contains("--limit"), "{out}");
    let o = f.run(&["plan", "web.yaml", "web01", "--inventory", "hosts.yaml"]);
    assert!(text(&o.stdout).contains("hosts.yaml (--inventory)"));
}

#[test]
fn a_variables_file_is_checked_for_the_selected_hosts() {
    let (f, _ports) = project();
    let vars_recipe = "version: 1\nvars:\n  root: { value: /srv/x }\nresources:\n  - id: a\n    type: file\n    with: { path: \"{{ vars.root }}/a\", content: x }\n";
    f.write("v.yaml", vars_recipe);
    f.write(
        "vars.yaml",
        "version: 1\nhosts:\n  web01:\n    root: /srv/web01\n  web02:\n    root: relative/bad\n",
    );
    // web02's bad value does not stop a run of web01, and stops one of web02.
    let o = f.run(&["validate", "v.yaml", "web01", "--vars-file", "vars.yaml"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let o = f.run(&["validate", "v.yaml", "web02", "--vars-file", "vars.yaml"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stdout));
    let o = f.run(&["plan", "v.yaml", "web02", "--vars-file", "vars.yaml"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stdout));
    assert!(f.ssh_log().is_empty());
    let o = f.run(&[
        "plan",
        "v.yaml",
        "web01",
        "--vars-file",
        "vars.yaml",
        "--format",
        "json",
    ]);
    assert_eq!(executed(&o), ["web01"]);
}

// --- FR-073: detection ---------------------------------------------------

#[test]
fn detection_looks_in_the_current_and_the_recipe_directory_only() {
    let f = Fx::new();
    let ports = common::ClosedPorts::reserve(3);
    let body = Fx::hosts_body([ports.port(0), ports.port(1), ports.port(2)]);
    f.mkdir("project/recipes");
    f.write("project/recipes/r.yaml", FREE);
    // The documented layout: hosts.yaml at the project root.
    f.write("project/hosts.yaml", &body);
    let o = f.run_in(
        "project",
        &["plan", "recipes/r.yaml", "web01", "--format", "json"],
    );
    assert_eq!(executed(&o), ["web01"], "{}", text(&o.stderr));
    // From inside recipes/ the file is in a parent: it is not found.
    let o = f.run_in("project/recipes", &["plan", "r.yaml", "web01"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stdout));
    assert!(
        text(&o.stderr).contains("no inventory"),
        "{}",
        text(&o.stderr)
    );
    // Beside the recipe, from anywhere.
    std::fs::rename(
        f.path("project/hosts.yaml"),
        f.path("project/recipes/hosts.yml"),
    )
    .unwrap();
    for (cwd, recipe) in [
        ("project", "recipes/r.yaml"),
        ("project/recipes", "r.yaml"),
        (".", "project/recipes/r.yaml"),
    ] {
        let o = f.run_in(cwd, &["plan", recipe, "web01", "--format", "json"]);
        assert_eq!(
            executed(&o),
            ["web01"],
            "{cwd} {recipe}: {}",
            text(&o.stderr)
        );
        assert!(json(&o)["inventory"]
            .as_str()
            .unwrap()
            .ends_with("recipes/hosts.yml"));
    }
    // One each for the three runs that ran and the first one; none for the refusal.
    assert_eq!(f.ssh_log().len(), 4);
}

#[test]
fn no_selector_means_no_detection_whatever_lies_around() {
    let f = Fx::new();
    f.write("r.yaml", FREE);
    let baseline: Vec<Output> = ["validate", "plan", "audit"]
        .iter()
        .map(|p| f.run(&[p, "r.yaml", "--format", "json"]))
        .collect();
    // A broken inventory, then a valid one: neither is read, nothing changes.
    for body in [
        "hosts: [\n",
        "hosts:\n  evil: { address: 127.0.0.1, port: 1 }\n",
    ] {
        f.write("hosts.yaml", body);
        for (i, p) in ["validate", "plan", "audit"].iter().enumerate() {
            let o = f.run(&[p, "r.yaml", "--format", "json"]);
            assert_eq!(o.status.code(), baseline[i].status.code(), "{p}");
            assert_eq!(o.stdout, baseline[i].stdout, "{p}");
            assert_eq!(o.stderr, baseline[i].stderr, "{p}");
        }
    }
    assert!(f.ssh_log().is_empty(), "{:?}", f.ssh_log());
}

#[test]
fn several_candidates_stop_the_run_before_anything_runs() {
    let (f, _ports) = project();
    f.mkdir("recipes");
    f.write("recipes/r.yaml", WEB);
    f.write("recipes/hosts.toml", "[hosts.web01]\n");
    for phase in ALL {
        let o = f.run(&[phase, "recipes/r.yaml", "web01"]);
        assert_eq!(o.status.code(), Some(2), "{phase}");
        let err = text(&o.stderr);
        assert!(err.contains("several inventories"), "{err}");
        assert!(
            err.contains("hosts.yaml") && err.contains("hosts.toml"),
            "{err}"
        );
    }
    assert!(f.ssh_log().is_empty());
}

#[test]
fn an_explicit_inventory_comes_first_and_never_falls_back() {
    let (f, ports) = project_with_ports(6);
    f.mkdir("other");
    let other = Fx::hosts_body([ports.port(3), ports.port(4), ports.port(5)]);
    // Detection would see two candidates; a named file sidesteps it.
    f.write("hosts.yml", "hosts: [\n");
    let named = f.write("other/inv.yaml", &other);
    let o = f.run(&[
        "plan",
        "free.yaml",
        "web01",
        "--inventory",
        &named,
        "--format",
        "json",
    ]);
    assert_eq!(executed(&o), ["web01"], "{}", text(&o.stderr));
    let doc = json(&o);
    assert_eq!(doc["inventory"], named);
    assert_eq!(doc["inventory_source"], "explicit");
    assert_eq!(doc["executions"][0]["target"]["port"], ports.port(3));
    // A named file that is broken or missing is an error even with a good
    // hosts.yaml next to the recipe.
    std::fs::remove_file(f.path("hosts.yml")).unwrap();
    let _ = std::fs::remove_file(f.path("fakebin/ssh.log"));
    let bad = f.write("other/bad.yaml", "hosts: [\n");
    for path in [bad.as_str(), "other/missing.yaml"] {
        let o = f.run(&["plan", "free.yaml", "web01", "--inventory", path]);
        assert_eq!(o.status.code(), Some(2), "{path}");
    }
    assert!(f.ssh_log().is_empty());
    // An explicit file keeps its privileges: a symlink, group-writable modes and
    // known_hosts, as in every release so far.
    let kh = f.write("other/known_hosts", "");
    let with_kh = f.write(
        "other/kh.yaml",
        &format!("hosts:\n  web01:\n    address: 127.0.0.1\n    port: {}\n    user: u\n    known_hosts: {kh}\n", ports.port(0)),
    );
    symlink(&with_kh, f.path("other/link.yaml")).unwrap();
    std::fs::set_permissions(&with_kh, std::fs::Permissions::from_mode(0o666)).unwrap();
    let o = f.run(&[
        "plan",
        "free.yaml",
        "web01",
        "--inventory",
        "other/link.yaml",
        "--format",
        "json",
    ]);
    assert_eq!(executed(&o), ["web01"], "{}", text(&o.stderr));
}

#[test]
fn a_detected_file_is_refused_when_it_cannot_be_trusted() {
    let bodies: &[(&str, &str, u32, &str)] = &[
        ("bad yaml", "hosts: [\n", 0o644, "invalid inventory"),
        ("no hosts", "hosts: {}\n", 0o644, "defines no hosts"),
        (
            "group writable",
            "hosts:\n  web01: {}\n",
            0o664,
            "writable by group",
        ),
        (
            "other writable",
            "hosts:\n  web01: {}\n",
            0o646,
            "writable by group",
        ),
        (
            "known_hosts",
            "hosts:\n  web01:\n    known_hosts: ./k\n",
            0o644,
            "known_hosts",
        ),
        (
            "known_hosts abs",
            "hosts:\n  web01:\n    known_hosts: /etc/k\n",
            0o644,
            "known_hosts",
        ),
        (
            "relative key",
            "hosts:\n  web01:\n    identity_files: [k/id]\n",
            0o644,
            "relative identity_files",
        ),
        (
            "option as address",
            "hosts:\n  web01:\n    address: \"-oProxyCommand=touch owned\"\n",
            0o644,
            "web01",
        ),
    ];
    for (what, body, mode, want) in bodies {
        let f = Fx::new();
        f.write("free.yaml", FREE);
        f.write("hosts.yaml", body);
        std::fs::set_permissions(f.path("hosts.yaml"), std::fs::Permissions::from_mode(*mode))
            .unwrap();
        for phase in ALL {
            let o = f.run(&[phase, "free.yaml", "web01"]);
            assert_eq!(
                o.status.code(),
                Some(2),
                "{what} {phase}: {}",
                text(&o.stdout)
            );
            assert!(
                text(&o.stderr).contains(want),
                "{what}: {}",
                text(&o.stderr)
            );
        }
        assert!(f.ssh_log().is_empty(), "{what}: {:?}", f.ssh_log());
        assert!(!f.path("owned").exists(), "{what}");
    }
}

#[test]
fn symlinks_and_loose_directories_are_refused() {
    let f = Fx::new();
    f.write("free.yaml", FREE);
    f.write("real.yaml", "hosts:\n  web01: {}\n");
    symlink(f.path("real.yaml"), f.path("hosts.yaml")).unwrap();
    let o = f.run(&["apply", "free.yaml", "web01"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        text(&o.stderr).contains("symbolic link"),
        "{}",
        text(&o.stderr)
    );
    std::fs::remove_file(f.path("hosts.yaml")).unwrap();

    // A directory others can write to.
    f.mkdir("shared");
    f.write("shared/r.yaml", FREE);
    f.write("shared/hosts.yaml", "hosts:\n  web01: {}\n");
    std::fs::set_permissions(f.path("shared"), std::fs::Permissions::from_mode(0o777)).unwrap();
    let o = f.run(&["apply", "shared/r.yaml", "web01"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        text(&o.stderr).contains("its directory is writable"),
        "{}",
        text(&o.stderr)
    );

    // A recipe directory reached through a link.
    f.mkdir("real");
    f.write("real/r.yaml", FREE);
    f.write("real/hosts.yaml", "hosts:\n  web01: {}\n");
    symlink(f.path("real"), f.path("link")).unwrap();
    let o = f.run(&["apply", "link/r.yaml", "web01"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(
        text(&o.stderr).contains("symbolic link"),
        "{}",
        text(&o.stderr)
    );
    assert!(f.ssh_log().is_empty());
}

#[test]
fn replacing_the_inventory_after_it_was_read_changes_nothing() {
    // `ssh -G` runs after the inventory is read; the scripted ssh swaps the
    // file at exactly that moment, to a host on another port.
    let f = Fx::new();
    let closed = common::ClosedPorts::reserve(1);
    let evil = Listener::new();
    f.write("free.yaml", FREE);
    f.write(
        "hosts.yaml",
        &format!(
            "hosts:\n  web01:\n    address: 127.0.0.1\n    port: {}\n    user: u\n",
            closed.port(0)
        ),
    );
    f.write(
        "evil",
        &format!(
            "hosts:\n  web01:\n    address: 127.0.0.1\n    port: {}\n    user: u\n",
            evil.port()
        ),
    );
    f.set_ssh(&format!(
        "mv '{}' '{}'",
        f.path("evil").display(),
        f.path("hosts.yaml").display()
    ));
    let o = f.run(&["plan", "free.yaml", "web01", "--format", "json"]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o.stderr));
    let doc = json(&o);
    assert_eq!(doc["executions"][0]["target"]["port"], closed.port(0));
    assert_eq!(evil.accepted(), 0, "the replaced file was used");
    assert_eq!(f.ssh_log().len(), 1);
    assert!(!f.path("evil").exists(), "the swap did not happen");
}

// --- FR-074: short options -----------------------------------------------

#[test]
fn short_options_mean_the_long_ones() {
    let (f, ports) = project();
    let port = ports.port(0);
    let target = |args: &[&str]| -> serde_json::Value {
        let mut all = vec!["plan"];
        all.extend_from_slice(args);
        all.extend_from_slice(&["--format", "json", "--no-ssh-config"]);
        let o = f.run(&all);
        assert_eq!(o.status.code(), Some(3), "{all:?}: {}", text(&o.stderr));
        json(&o)["executions"][0]["target"].clone()
    };
    assert_eq!(
        target(&["free.yaml", "web01", "-u", "root"])["user"],
        "root"
    );
    assert_eq!(
        target(&["free.yaml", "web01", "-u", "root"]),
        target(&["free.yaml", "web01", "--user", "root"])
    );
    assert_eq!(target(&["free.yaml", "web01"])["port"], port);
    assert_eq!(target(&["free.yaml", "web01", "-p", "2222"])["port"], 2222);
    assert_eq!(
        target(&["free.yaml", "web01", "-p", "2222"]),
        target(&["free.yaml", "web01", "--port", "2222"])
    );
    // A short option is the same whichever side of the selector it is on.
    assert_eq!(
        target(&["-u", "root", "free.yaml", "web01"])["user"],
        "root"
    );
    // -i takes a key like --identity and needs no other change.
    let o = f.run(&[
        "plan",
        "free.yaml",
        "web01",
        "-i",
        "/nonexistent/id",
        "--no-ssh-config",
    ]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o.stderr));
    // Invalid values are refused as for the long option, before anything runs.
    let _ = std::fs::remove_file(f.path("fakebin/ssh.log"));
    for bad in [
        &["-p", "70000"][..],
        &["-p", "x"],
        &["-H", "-oProxyCommand=x"],
    ] {
        let mut all = vec!["plan", "free.yaml"];
        all.extend_from_slice(bad);
        let o = f.run(&all);
        assert_eq!(o.status.code(), Some(2), "{bad:?}: {}", text(&o.stderr));
    }
    assert!(f.ssh_log().is_empty());
}

#[test]
fn short_host_is_a_single_target_outside_any_inventory() {
    let (f, ports) = project();
    let port = ports.port(0).to_string();
    let a = f.run(&[
        "plan",
        "free.yaml",
        "-H",
        "127.0.0.1",
        "-p",
        &port,
        "-u",
        "u",
    ]);
    let b = f.run(&[
        "plan",
        "free.yaml",
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--user",
        "u",
    ]);
    assert_eq!(a.status.code(), Some(3), "{}", text(&a.stderr));
    assert_eq!(a.status.code(), b.status.code());
    assert_eq!(a.stdout, b.stdout);
    assert_eq!(a.stderr, b.stderr);
    assert!(!text(&a.stdout).contains("auto-detected"));
}

#[test]
fn help_lists_the_short_options_and_the_selector() {
    let f = Fx::new();
    for phase in ALL {
        let o = f.run(&[phase, "--help"]);
        let out = text(&o.stdout);
        assert_eq!(o.status.code(), Some(0));
        for want in [
            "[SELECTOR]",
            "-H, --host",
            "-p, --port",
            "-u, --user",
            "-i, --identity",
            "--inventory",
            "--limit",
            "--sudo",
            "--format",
        ] {
            assert!(out.contains(want), "{phase}: {want}: {out}");
        }
        // These four stay long-only.
        for no in ["-s, --sudo", "-f, --format", "-l, --limit"] {
            assert!(!out.contains(no), "{phase}: {no}");
        }
    }
    // `secrets decrypt -i` keeps its own meaning.
    let o = f.run(&["secrets", "decrypt", "--help"]);
    assert!(text(&o.stdout).contains("-i, --identity"));
}
