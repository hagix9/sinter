//! The usability features together, through the command line (DESIGN §39, §40):
//! a project file, several selectors, layered variables, exclusions and backup
//! stores. Connections go to closed local ports, so what is checked is what would
//! have been contacted, in every phase, and that a refusal contacts nothing.
#![cfg(unix)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

const CANARY: &str = "USABILITY_CANARY_DO_NOT_PRINT";
const PHASES: [&str; 3] = ["plan", "audit", "apply"];

struct Fx {
    dir: tempfile::TempDir,
    _ports: common::ClosedPorts,
}

impl Fx {
    /// `sinter.yaml`, `inventory.yaml`, `recipes/` and `vars/`, as the Owner's
    /// example lays them out.
    fn new(project: &str) -> Self {
        let ports = common::ClosedPorts::reserve(3);
        let f = Fx {
            dir: tempfile::tempdir().unwrap(),
            _ports: ports,
        };
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        for d in ["fakebin", "p", "p/recipes", "p/vars", "p/sub"] {
            std::fs::create_dir(f.path(d)).unwrap();
            std::fs::set_permissions(f.path(d), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let ssh = f.path("fakebin/ssh");
        std::fs::write(
            &ssh,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf 'hostname 127.0.0.1\\n'\nexit 0\n",
                f.path("fakebin/ssh.log").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
        let host =
            |n: &str, p: u16| format!("  {n}: {{ address: 127.0.0.1, port: {p}, user: u }}\n");
        f.write(
            "p/inventory.yaml",
            &format!(
                "hosts:\n{}{}{}groups:\n  web:\n    hosts: [web01, web02]\n  database:\n    hosts: [db01]\n",
                host("web01", f._ports.port(0)),
                host("web02", f._ports.port(1)),
                host("db01", f._ports.port(2)),
            ),
        );
        f.write(
            "p/recipes/web.yaml",
            "version: 1\ntargets:\n  groups: [web]\nvars:\n  web_port: { value: 80 }\nresources:\n  - id: pkg\n    type: package\n    with: { name: jq, state: present }\n  - id: conf\n    type: file\n    depends_on: [pkg]\n    with: { path: /srv/conf, content: x }\n  - id: other\n    type: file\n    with: { path: /srv/other, content: x }\n",
        );
        f.write(
            "p/recipes/free.yaml",
            "version: 1\nvars:\n  web_port: { value: 80 }\nresources:\n  - id: a\n    type: file\n    with: { path: /srv/a, content: x }\n",
        );
        f.write(
            "p/recipes/db.yaml",
            "version: 1\nvars:\n  db_port: { value: 1 }\n  db_host: { value: h }\nresources: []\n",
        );
        f.write(
            "p/vars/common.yaml",
            &format!(
                "version: 1\nvars: {{ web_port: 8080, db_port: 5432, db_host: \"{CANARY}\" }}\n"
            ),
        );
        f.write(
            "p/vars/production.yaml",
            "version: 1\nvars: { web_port: 443 }\n",
        );
        f.write("p/sinter.yaml", project);
        f
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn write(&self, rel: &str, body: &str) -> String {
        let p = self.path(rel);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        p.display().to_string()
    }

    fn run_in(&self, dir: &str, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sinter"))
            .args(args)
            .current_dir(self.path(dir))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.path("fakebin").display(),
                    std::env::var("PATH").unwrap()
                ),
            )
            .env("NO_COLOR", "1")
            .env("SINTER_PROGRESS", "never")
            .output()
            .unwrap()
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_in("p", args)
    }

    fn ssh_log(&self) -> String {
        std::fs::read_to_string(self.path("fakebin/ssh.log")).unwrap_or_default()
    }

    fn clear_log(&self) {
        let _ = std::fs::remove_file(self.path("fakebin/ssh.log"));
    }
}

const PROJECT: &str = "version: 1\ninventory: ./inventory.yaml\nrecipe_paths: [./recipes]\nvars_files: [./vars/common.yaml, ./vars/production.yaml]\n";

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("{e}: {} / {}", text(&o.stdout), text(&o.stderr)))
}

fn executed(o: &Output) -> Vec<String> {
    json(o)["executions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["target"]["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn a_project_and_several_selectors_reach_exactly_the_same_hosts_in_every_phase() {
    let f = Fx::new(PROJECT);
    for (selectors, want) in [
        (&["web01"][..], &["web01"][..]),
        (&["web01", "web02"], &["web01", "web02"]),
        (&["group:web"], &["web01", "web02"]),
        (&["host:web02", "web02"], &["web02"]),
    ] {
        for phase in PHASES {
            f.clear_log();
            let mut args = vec![phase, "web.yaml"];
            args.extend_from_slice(selectors);
            args.extend_from_slice(&["--format", "json"]);
            let o = f.run(&args);
            assert_eq!(executed(&o), want, "{args:?}: {}", text(&o.stderr));
            let log = f.ssh_log();
            // `ssh -G` runs for each host that will be contacted, and only those: the
            // hosts share an address, so the port tells them apart.
            for (i, host) in ["web01", "web02", "db01"].iter().enumerate() {
                let resolved = log.contains(&format!("-p {} --", f._ports.port(i)));
                assert_eq!(resolved, want.contains(host), "{args:?} {host}: {log}");
            }
        }
    }
    // A mix reaches past the recipe's targets: refused, nothing contacted.
    for phase in PHASES {
        f.clear_log();
        let o = f.run(&[phase, "web.yaml", "web01", "group:database"]);
        assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
        assert_eq!(f.ssh_log(), "");
    }
    // A recipe without targets runs on exactly what is named.
    let o = f.run(&[
        "plan",
        "free.yaml",
        "web01",
        "group:database",
        "--format",
        "json",
    ]);
    assert_eq!(executed(&o), ["db01", "web01"]);
}

#[test]
fn the_project_layers_variables_and_the_command_line_comes_last() {
    let f = Fx::new(PROJECT);
    let o = f.run(&["validate", "web.yaml", "web01"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    // db.yaml declares them: another recipe's variables, nothing to say.
    let err = text(&o.stderr);
    assert!(
        !err.contains("db_port") && !err.contains("db_host"),
        "{err}"
    );
    assert!(!err.contains(CANARY) && !text(&o.stdout).contains(CANARY));
    // Strict: this run must use every name; the value stays out.
    let o = f.run(&["validate", "web.yaml", "web01", "--strict-vars"]);
    assert_eq!(o.status.code(), Some(2));
    let err = text(&o.stderr);
    assert!(err.contains("db_port") && !err.contains(CANARY), "{err}");
    // A later file on the command line wins; the wrong type of what is used stops.
    f.write("p/vars/bad.yaml", "version: 1\nvars: { web_port: wrong }\n");
    let o = f.run(&[
        "validate",
        "web.yaml",
        "web01",
        "--vars-file",
        "vars/bad.yaml",
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o.stderr).contains("web_port"));
    // Something missing from the project stops before anything.
    f.write(
        "p/sinter.yaml",
        "version: 1\ninventory: ./inventory.yaml\nvars_files: [./vars/none.yaml]\n",
    );
    f.clear_log();
    assert_eq!(
        f.run(&["plan", "recipes/web.yaml", "web01"]).status.code(),
        Some(2)
    );
    assert_eq!(f.ssh_log(), "");
}

#[test]
fn exclusions_and_selectors_and_the_project_agree() {
    let f = Fx::new(PROJECT);
    for phase in PHASES {
        let o = f.run(&[
            phase,
            "web.yaml",
            "web01",
            "web02",
            "--skip-resource",
            "other",
            "--format",
            "json",
        ]);
        assert_eq!(executed(&o), ["web01", "web02"], "{phase}");
        assert_eq!(json(&o)["skips"]["partial"], true, "{phase}");
    }
    // What another resource needs cannot be left out, whatever else is said.
    for phase in PHASES {
        f.clear_log();
        let o = f.run(&[phase, "web.yaml", "group:web", "--skip-resource", "pkg"]);
        assert_eq!(o.status.code(), Some(2), "{phase}");
        assert!(
            text(&o.stderr).contains("depends on"),
            "{}",
            text(&o.stderr)
        );
        assert_eq!(f.ssh_log(), "", "{phase}");
    }
}

#[test]
fn stores_are_shown_with_the_project_default_and_the_recipe_wins() {
    let f = Fx::new(
        "version: 1\ninventory: ./inventory.yaml\nbackup: { directory: /var/backups/project }\n",
    );
    f.write(
        "p/b.yaml",
        "version: 1\nbackup:\n  paths:\n    - /etc/a\n    - { path: /etc/b, directory: /var/backups/own }\nresources: []\n",
    );
    let o = f.run(&["plan", "b.yaml", "web01", "--format", "json"]);
    let doc = json(&o);
    assert_eq!(doc["resolved"]["backup_directory"], "/var/backups/project");
    let entries = doc["executions"][0]["backup"]["entries"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(entries[1]["store"], "/var/backups/own", "{doc}");
    // An audit has no backup record at all.
    let o = f.run(&["audit", "b.yaml", "web01", "--format", "json"]);
    assert!(json(&o)["executions"][0]["backup"].is_null());
    // A bad store stops every phase before contacting anything.
    f.write(
        "p/bad.yaml",
        "version: 1\nbackup:\n  directory: /etc/app\n  paths: [/etc/app/a]\nresources: []\n",
    );
    for phase in ["validate", "plan", "audit", "apply"] {
        f.clear_log();
        let o = f.run(&[phase, "bad.yaml", "web01"]);
        assert_eq!(o.status.code(), Some(2), "{phase}");
        assert_eq!(f.ssh_log(), "", "{phase}");
    }
}

#[test]
fn without_a_project_file_the_old_commands_are_what_they_were() {
    let f = Fx::new("version: 1\n");
    std::fs::remove_file(f.path("p/sinter.yaml")).unwrap();
    let rec = "recipes/free.yaml";
    // Explicit forms.
    let o = f.run(&[
        "plan",
        rec,
        "--inventory",
        "inventory.yaml",
        "--limit",
        "group:web",
        "--format",
        "json",
    ]);
    assert_eq!(
        o.status.code(),
        Some(2),
        "a recipe without targets: {}",
        text(&o.stderr)
    );
    let o = f.run(&[
        "plan",
        "recipes/web.yaml",
        "--inventory",
        "inventory.yaml",
        "--limit",
        "group:web",
        "--format",
        "json",
    ]);
    assert_eq!(executed(&o), ["web01", "web02"]);
    let o = f.run(&["validate", rec]);
    assert_eq!(o.status.code(), Some(0));
    assert!(!text(&o.stdout).contains("config:"));
    // A recipe of the v1.9.0 form: a plain string list of backup paths.
    f.write(
        "p/old.yaml",
        "version: 1\nbackup:\n  paths: [/etc/x, /etc/y]\nresources:\n  - id: a\n    type: file\n    with: { path: /srv/a, content: x }\n",
    );
    assert_eq!(f.run(&["validate", "old.yaml"]).status.code(), Some(0));
    // No inventory and a selector: an error, not this machine.
    f.clear_log();
    let o = f.run_in("p/sub", &["apply", "../recipes/free.yaml", "web01"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
    assert_eq!(f.ssh_log(), "");
}
