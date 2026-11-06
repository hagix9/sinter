//! The project file, recipe search, layered variables and exclusions through the
//! real binary (DESIGN §40). No test needs a reachable host: hosts point at closed
//! ports and `ssh` is a script that records every call, so a test can tell that
//! nothing was resolved or attempted. Nothing here ever runs on the local target:
//! the phases that could are checked by what they refuse before that.
#![cfg(unix)]

mod common;

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FREE: &str =
    "version: 1\nresources:\n  - id: a\n    type: file\n    with: { path: /srv/a, content: x }\n";
const WEB: &str = "version: 1\ntargets:\n  groups: [web]\nresources:\n  - id: a\n    type: file\n    with: { path: /srv/a, content: x }\n";
const PHASES: [&str; 3] = ["plan", "audit", "apply"];
const CANARY: &str = "PROJECT_CANARY_DO_NOT_PRINT";

struct Fx {
    dir: tempfile::TempDir,
}

fn set_mode(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

impl Fx {
    fn new() -> Self {
        let f = Fx {
            dir: tempfile::tempdir().unwrap(),
        };
        set_mode(f.dir.path(), 0o755);
        f.mkdir("fakebin");
        let ssh = f.path("fakebin/ssh");
        std::fs::write(
            &ssh,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf 'hostname 127.0.0.1\\n'\nexit 0\n",
                f.path("fakebin/ssh.log").display()
            ),
        )
        .unwrap();
        set_mode(&ssh, 0o755);
        f.mkdir("work");
        f
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn mkdir(&self, rel: &str) {
        std::fs::create_dir_all(self.path(rel)).unwrap();
        set_mode(&self.path(rel), 0o755);
    }

    fn write(&self, rel: &str, body: &str) -> String {
        let p = self.path(rel);
        std::fs::write(&p, body).unwrap();
        set_mode(&p, 0o644);
        p.display().to_string()
    }

    fn inventory(&self, rel: &str) -> String {
        let ports = common::ClosedPorts::reserve(2);
        self.write(
            rel,
            &format!(
                "hosts:\n  web01: {{ address: 127.0.0.1, port: {}, user: u }}\n  db01: {{ address: 127.0.0.1, port: {}, user: u }}\ngroups:\n  web:\n    hosts: [web01]\n  db:\n    hosts: [db01]\n",
                ports.port(0),
                ports.port(1)
            ),
        )
    }

    fn run_in(&self, dir: &str, args: &[&str]) -> Output {
        let path = format!(
            "{}:{}",
            self.path("fakebin").display(),
            std::env::var("PATH").unwrap()
        );
        Command::new(env!("CARGO_BIN_EXE_sinter"))
            .args(args)
            .current_dir(self.path(dir))
            .env("PATH", path)
            .env("NO_COLOR", "1")
            .env("SINTER_PROGRESS", "never")
            .output()
            .unwrap()
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_in("work", args)
    }

    fn ssh_calls(&self) -> usize {
        std::fs::read_to_string(self.path("fakebin/ssh.log"))
            .map(|s| s.lines().count())
            .unwrap_or(0)
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("{e}: {} / {}", text(&o.stdout), text(&o.stderr)))
}

fn code(o: &Output, want: i32, ctx: &str) {
    assert_eq!(
        o.status.code(),
        Some(want),
        "{ctx}: {} / {}",
        text(&o.stdout),
        text(&o.stderr)
    );
}

#[test]
fn without_a_project_file_nothing_is_added() {
    let f = Fx::new();
    f.write("work/r.yaml", FREE);
    let o = f.run(&["validate", "r.yaml", "--format", "json"]);
    code(&o, 0, "json");
    let d = json(&o);
    assert!(d.get("resolved").is_none() && d.get("skips").is_none());
    assert!(text(&o.stderr).is_empty(), "{}", text(&o.stderr));
    let o = f.run(&["validate", "r.yaml"]);
    code(&o, 0, "text");
    assert_eq!(
        text(&o.stdout),
        "ok: 1 resource(s), 0 handler(s), 0 var(s)\n"
    );
}

#[test]
fn the_project_file_of_the_current_directory_is_used_and_shown() {
    let f = Fx::new();
    f.write("work/r.yaml", FREE);
    let cfg = f.write("work/sinter.project.yaml", "version: 1\n");
    let o = f.run(&["validate", "r.yaml"]);
    code(&o, 0, "text");
    let out = text(&o.stdout);
    assert!(
        out.contains(&format!("config: {cfg} (auto-detected)")),
        "{out}"
    );
    assert!(out.contains("recipe: r.yaml (as given)"), "{out}");
    let o = f.run(&["validate", "r.yaml", "--format", "json"]);
    let d = json(&o);
    assert_eq!(d["resolved"]["config"]["source"], "detected");
    assert_eq!(d["resolved"]["recipe"]["via"], "given");
    assert!(
        text(&o.stderr).contains("config:"),
        "stdout stays one document"
    );
}

#[test]
fn neither_parents_nor_the_recipes_directory_are_searched() {
    let f = Fx::new();
    f.write(
        "sinter.project.yaml",
        "version: 1\nthis is: not valid for a project\n",
    );
    f.mkdir("elsewhere");
    f.write("elsewhere/sinter.project.yaml", "not: valid\n");
    let r = f.write("elsewhere/r.yaml", FREE);
    let o = f.run(&["validate", &r]);
    code(&o, 0, "a file above or next to the recipe is not looked at");
    assert!(!text(&o.stdout).contains("config:"));
}

#[test]
fn a_named_file_is_used_from_anywhere_and_its_paths_are_relative_to_it() {
    let f = Fx::new();
    f.mkdir("proj/recipes");
    f.write("proj/recipes/r.yaml", WEB);
    f.inventory("proj/hosts.yaml");
    let cfg = f.write(
        "proj/custom.yaml",
        "version: 1\nrecipe_paths: [recipes]\ninventory: hosts.yaml\n",
    );
    let o = f.run(&[
        "validate", "--config", &cfg, "r.yaml", "web01", "--format", "json",
    ]);
    code(&o, 0, "");
    let d = json(&o);
    assert_eq!(d["resolved"]["config"]["source"], "explicit");
    assert_eq!(d["resolved"]["recipe"]["via"], "recipe_paths");
    assert!(d["resolved"]["recipe"]["path"]
        .as_str()
        .unwrap()
        .ends_with("proj/recipes/r.yaml"));
    assert_eq!(d["resolved"]["inventory"]["source"], "project");
    assert_eq!(d["inventory_source"], "project");
    assert_eq!(f.ssh_calls(), 0);
    // A file that does not exist is an error, not "no project".
    let o = f.run(&["validate", "--config", "nope.yaml", "r.yaml"]);
    code(&o, 2, "");
}

#[test]
fn no_config_ignores_a_broken_file_and_excludes_config() {
    let f = Fx::new();
    f.write("work/r.yaml", FREE);
    f.write("work/sinter.project.yaml", "broken: [");
    code(
        &f.run(&["validate", "r.yaml"]),
        2,
        "a bad file never means no project",
    );
    code(&f.run(&["validate", "r.yaml", "--no-config"]), 0, "");
    code(
        &f.run(&["validate", "r.yaml", "--no-config", "--config", "x"]),
        2,
        "",
    );
}

#[test]
fn a_detected_file_is_held_to_the_detection_rules() {
    let f = Fx::new();
    f.write("work/r.yaml", FREE);
    let p = f.write("work/sinter.project.yaml", "version: 1\n");
    set_mode(Path::new(&p), 0o666);
    let o = f.run(&["validate", "r.yaml"]);
    code(&o, 2, "");
    assert!(
        text(&o.stderr).contains("writable by group or others"),
        "{}",
        text(&o.stderr)
    );
    set_mode(Path::new(&p), 0o644);
    set_mode(&f.path("work"), 0o777);
    let o = f.run(&["validate", "r.yaml"]);
    code(&o, 2, "");
    assert!(
        text(&o.stderr).contains("its directory is writable"),
        "{}",
        text(&o.stderr)
    );
    set_mode(&f.path("work"), 0o755);
    f.write("work/sinter.project.toml", "version = 1\n");
    let o = f.run(&["validate", "r.yaml"]);
    code(&o, 2, "");
    assert!(
        text(&o.stderr).contains("several project files"),
        "{}",
        text(&o.stderr)
    );
    std::fs::remove_file(f.path("work/sinter.project.toml")).unwrap();
    std::fs::remove_file(&p).unwrap();
    f.write("real.yaml", "version: 1\n");
    symlink(f.path("real.yaml"), &p).unwrap();
    let o = f.run(&["validate", "r.yaml"]);
    code(&o, 2, "");
    assert!(
        text(&o.stderr).contains("symbolic link"),
        "{}",
        text(&o.stderr)
    );
}

#[test]
fn a_recipe_is_found_once_or_the_run_stops() {
    let f = Fx::new();
    f.mkdir("work/recipes");
    f.mkdir("shared");
    f.write("shared/s.yaml", FREE);
    f.write("work/recipes/r.yaml", FREE);
    f.write(
        "work/sinter.project.yaml",
        &format!(
            "version: 1\nrecipe_paths: [{}, ./recipes]\n",
            f.path("shared").display()
        ),
    );
    // Found in another directory than the current one.
    let o = f.run(&["validate", "s.yaml", "--format", "json"]);
    code(&o, 0, "");
    assert_eq!(json(&o)["resolved"]["recipe"]["via"], "recipe_paths");
    // In the current directory and in a search directory: not picked.
    f.write("work/r.yaml", FREE);
    let o = f.run(&["validate", "r.yaml"]);
    code(&o, 2, "");
    assert!(text(&o.stderr).contains("ambiguous"), "{}", text(&o.stderr));
    // A path settles it, and is never searched for.
    code(&f.run(&["validate", "./r.yaml"]), 0, "");
    code(&f.run(&["validate", "recipes/r.yaml"]), 0, "");
    // Not found: no other recipe, and no extension.
    let o = f.run(&["validate", "nope.yaml"]);
    code(&o, 2, "");
    assert!(
        text(&o.stderr).contains("was not found"),
        "{}",
        text(&o.stderr)
    );
    code(&f.run(&["validate", "s"]), 2, "");
    code(
        &f.run(&["validate", "./s.yaml"]),
        2,
        "a path is not searched for",
    );
}

#[test]
fn a_shared_recipe_directory_brings_no_inventory() {
    let f = Fx::new();
    f.mkdir("shared");
    f.write("shared/r.yaml", WEB);
    f.inventory("shared/hosts.yaml");
    f.write(
        "work/sinter.project.yaml",
        &format!(
            "version: 1\nrecipe_paths: [{}]\n",
            f.path("shared").display()
        ),
    );
    let o = f.run(&["validate", "r.yaml", "web01"]);
    code(&o, 2, "");
    assert!(
        text(&o.stderr).contains("no inventory"),
        "{}",
        text(&o.stderr)
    );
    // The current directory is where it is looked for.
    f.inventory("work/hosts.yaml");
    let o = f.run(&["validate", "r.yaml", "web01", "--format", "json"]);
    code(&o, 0, "");
    assert_eq!(json(&o)["inventory_source"], "detected");
}

#[test]
fn the_command_line_wins_over_the_project_file() {
    let f = Fx::new();
    f.write("work/r.yaml", WEB);
    f.inventory("work/project-hosts.yaml");
    let other = f.inventory("other-hosts.yaml");
    f.write(
        "work/sinter.project.yaml",
        "version: 1\ninventory: project-hosts.yaml\nbackup: { directory: /var/backups/p }\n",
    );
    let o = f.run(&[
        "validate",
        "r.yaml",
        "web01",
        "--inventory",
        &other,
        "--format",
        "json",
    ]);
    code(&o, 0, "");
    let d = json(&o);
    assert_eq!(d["inventory"], other);
    assert_eq!(d["inventory_source"], "explicit");
    assert_eq!(d["resolved"]["backup_directory"], "/var/backups/p");
    let o = f.run(&[
        "validate",
        "r.yaml",
        "--backup-dir",
        "/var/backups/c",
        "--format",
        "json",
    ]);
    assert_eq!(json(&o)["resolved"]["backup_directory"], "/var/backups/c");
    // --host means that host: the project's inventory is not in the way.
    let o = f.run(&["validate", "r.yaml", "--host", "h1", "--format", "json"]);
    code(&o, 0, "");
    assert!(json(&o)["resolved"]["inventory"].is_null());
}

#[test]
fn an_apply_naming_no_host_never_reaches_machines_because_of_a_project_file() {
    let f = Fx::new();
    f.write("work/r.yaml", WEB);
    f.inventory("work/hosts.yaml");
    f.write(
        "work/sinter.project.yaml",
        "version: 1\ninventory: hosts.yaml\n",
    );
    let o = f.run(&["apply", "r.yaml", "--no-ssh-config"]);
    code(&o, 2, "");
    assert!(
        text(&o.stderr).contains("allow_implicit_apply"),
        "{}",
        text(&o.stderr)
    );
    // Naming them is enough, and so is saying so in the file; read-only phases go on.
    code(
        &f.run(&["apply", "r.yaml", "web01", "--no-ssh-config"]),
        3,
        "",
    );
    code(
        &f.run(&["apply", "r.yaml", "--limit", "web01", "--no-ssh-config"]),
        3,
        "",
    );
    code(&f.run(&["plan", "r.yaml", "--no-ssh-config"]), 3, "");
    f.write(
        "work/sinter.project.yaml",
        "version: 1\ninventory: hosts.yaml\nallow_implicit_apply: true\n",
    );
    code(&f.run(&["apply", "r.yaml", "--no-ssh-config"]), 3, "");
}

#[test]
fn a_name_that_does_not_resolve_never_falls_back_to_the_local_target() {
    let f = Fx::new();
    f.write("work/free.yaml", FREE);
    f.write("work/web.yaml", WEB);
    f.inventory("work/hosts.yaml");
    f.write(
        "work/sinter.project.yaml",
        "version: 1\ninventory: hosts.yaml\n",
    );
    for phase in PHASES {
        // A selector naming nothing.
        let o = f.run(&[phase, "web.yaml", "ghost", "--no-ssh-config"]);
        code(&o, 2, phase);
        let o = f.run(&[phase, "web.yaml", "@ghost", "--no-ssh-config"]);
        code(&o, 2, phase);
        // A recipe without targets and no selector, in a project with hosts.
        let o = f.run(&[phase, "free.yaml", "--no-ssh-config"]);
        code(&o, 2, phase);
        assert!(!text(&o.stdout).contains("== free"), "{}", text(&o.stdout));
        // An unreachable host is a failed connection, not a local run.
        let o = f.run(&[
            phase,
            "web.yaml",
            "web01",
            "--no-ssh-config",
            "--format",
            "json",
        ]);
        code(&o, 3, phase);
        assert_eq!(json(&o)["executions"][0]["target"]["name"], "web01");
    }
}

#[test]
fn a_default_target_never_applies_without_being_allowed() {
    let f = Fx::new();
    f.write("work/r.yaml", WEB);
    f.inventory("work/hosts.yaml");
    f.write(
        "work/sinter.project.yaml",
        "version: 1\ninventory: hosts.yaml\ndefault_target: \"@web\"\n",
    );
    let o = f.run(&["apply", "r.yaml"]);
    code(&o, 2, "");
    assert!(
        text(&o.stderr).contains("allow_implicit_apply"),
        "{}",
        text(&o.stderr)
    );
    assert_eq!(f.ssh_calls(), 0);
    // Read-only phases use it, and say so.
    let o = f.run(&["validate", "r.yaml", "--format", "json"]);
    code(&o, 0, "");
    let d = json(&o);
    assert_eq!(d["selector"], serde_json::json!(["@web"]));
    assert_eq!(d["resolved"]["default_target"], true);
    let o = f.run(&["plan", "r.yaml", "--no-ssh-config"]);
    code(&o, 3, "plan reaches the host of the default target");
    assert!(
        text(&o.stdout).contains("default_target of the project file"),
        "{}",
        text(&o.stdout)
    );
    // Naming the hosts is always enough.
    let o = f.run(&["apply", "r.yaml", "web01", "--no-ssh-config"]);
    code(&o, 3, "");
    // Stated in the file, apply may use it too.
    f.write(
        "work/sinter.project.yaml",
        "version: 1\ninventory: hosts.yaml\ndefault_target: \"@web\"\nallow_implicit_apply: true\n",
    );
    code(&f.run(&["apply", "r.yaml", "--no-ssh-config"]), 3, "");
}

#[test]
fn variables_layer_project_files_then_the_command_line() {
    let f = Fx::new();
    f.write(
        "work/r.yaml",
        "version: 1\nvars:\n  root: { value: /srv }\nresources:\n  - id: a\n    type: directory\n    with: { path: \"{{ vars.root }}/a\" }\n",
    );
    f.write("work/common.yaml", "version: 1\nvars: { root: /c }\n");
    f.write("work/more.yaml", "version: 1\nvars: { root: /d }\n");
    f.write(
        "work/sinter.project.yaml",
        "version: 1\nvars_files: [common.yaml]\n",
    );
    let o = f.run(&[
        "validate",
        "r.yaml",
        "--vars-file",
        "more.yaml",
        "--format",
        "json",
    ]);
    code(&o, 0, "");
    let d = json(&o);
    let files = d["resolved"]["vars_files"].as_array().unwrap();
    assert!(files[0].as_str().unwrap().ends_with("common.yaml"));
    assert_eq!(files[1], "more.yaml");
    assert_eq!(d["variables"]["files"].as_array().unwrap().len(), 2);
    assert!(d["variables"].get("file").is_none());
    // --no-config leaves only the command line's, in the established shape.
    let o = f.run(&[
        "validate",
        "r.yaml",
        "--no-config",
        "--vars-file",
        "more.yaml",
        "--format",
        "json",
    ]);
    assert_eq!(json(&o)["variables"]["file"], "more.yaml");
}

#[test]
fn unknown_variables_warn_typos_stop_and_values_stay_out() {
    let f = Fx::new();
    f.write(
        "work/r.yaml",
        "version: 1\nvars:\n  app_root: { value: /srv }\nresources:\n  - id: a\n    type: directory\n    with: { path: \"{{ vars.app_root }}/a\" }\n",
    );
    let other = f.write(
        "work/other.yaml",
        &format!("version: 1\nvars: {{ another_recipes_port: \"{CANARY}\" }}\n"),
    );
    let o = f.run(&["validate", "r.yaml", "--vars-file", &other]);
    code(&o, 0, "");
    let err = text(&o.stderr);
    assert!(
        err.contains("warning:") && err.contains("another_recipes_port"),
        "{err}"
    );
    assert!(!err.contains(CANARY) && !text(&o.stdout).contains(CANARY));
    let o = f.run(&[
        "validate",
        "r.yaml",
        "--vars-file",
        &other,
        "--format",
        "json",
    ]);
    let d = json(&o);
    assert_eq!(d["vars_warnings"].as_array().unwrap().len(), 1);
    assert!(!d.to_string().contains(CANARY));
    code(
        &f.run(&["validate", "r.yaml", "--vars-file", &other, "--strict-vars"]),
        2,
        "",
    );
    f.write(
        "work/sinter.project.yaml",
        "version: 1\nstrict_vars: true\n",
    );
    code(
        &f.run(&["validate", "r.yaml", "--vars-file", &other]),
        2,
        "",
    );
    std::fs::remove_file(f.path("work/sinter.project.yaml")).unwrap();
    let typo = f.write(
        "work/typo.yaml",
        &format!("version: 1\nvars: {{ app_rot: \"{CANARY}\" }}\n"),
    );
    let o = f.run(&["validate", "r.yaml", "--vars-file", &typo]);
    code(&o, 2, "");
    let err = text(&o.stderr);
    assert!(err.contains("did you mean app_root?"), "{err}");
    assert!(!err.contains(CANARY), "{err}");
}

#[test]
fn a_store_path_is_checked_on_every_phase_before_anything_runs() {
    let f = Fx::new();
    f.write("work/r.yaml", FREE);
    for phase in ["validate", "plan", "audit", "apply"] {
        for bad in ["rel/dir", "/a/../b", "/"] {
            let o = f.run(&[phase, "r.yaml", "--backup-dir", bad]);
            code(&o, 2, &format!("{phase} {bad}"));
        }
    }
    f.write(
        "work/sinter.project.yaml",
        "version: 1\nbackup: { directory: rel }\n",
    );
    code(&f.run(&["validate", "r.yaml"]), 2, "");
}

const BUNDLE_WEB: &str = "version: 1\ntargets:\n  groups: [web]\nresources:\n  - id: base\n    type: file\n    with: { path: /srv/b, content: x }\n  - id: conf\n    type: file\n    depends_on: [base]\n    with: { path: /srv/c, content: x }\n  - id: both\n    type: file\n    with: { path: /srv/d, content: x }\n";
const BUNDLE_DB: &str = "version: 1\ntargets:\n  groups: [db]\nresources:\n  - id: both\n    type: file\n    with: { path: /srv/e, content: x }\n";

fn bundle(f: &Fx) -> String {
    f.write("work/web.yaml", BUNDLE_WEB);
    f.write("work/db.yaml", BUNDLE_DB);
    f.inventory("work/hosts.yaml");
    f.write(
        "work/stack.yaml",
        "version: 1\nrecipes: [web.yaml, db.yaml]\n",
    )
}

#[test]
fn exclusions_are_shown_and_reported_with_their_reason() {
    let f = Fx::new();
    let b = bundle(&f);
    let o = f.run(&[
        "validate",
        &b,
        "--skip-recipe",
        "db",
        "--skip-resource",
        "web/conf",
    ]);
    code(&o, 0, "");
    let out = text(&o.stdout);
    assert!(out.contains("Included:\n  web/base\n  web/both\n"), "{out}");
    assert!(out.contains("db/*"), "{out}");
    assert!(out.contains("web/conf"), "{out}");
    assert!(out.contains("SKIPPED_BY_USER"), "{out}");
    assert!(out.contains("Blocked dependencies:\n  none\n"), "{out}");
    assert!(out.contains("PARTIAL_VALIDATE:"), "{out}");
    assert!(!out.contains('\x1b'), "NO_COLOR: {out:?}");
    let o = f.run(&["validate", &b, "--skip-recipe", "db", "--format", "json"]);
    let d = json(&o);
    assert_eq!(d["skips"]["partial"], true);
    assert_eq!(d["skips"]["excluded"][0]["reason"], "SKIPPED_BY_USER");
    assert_eq!(d["skips"]["excluded"][0]["recipe"], "db");
}

#[test]
fn what_cannot_run_stops_before_any_host_in_every_phase() {
    let f = Fx::new();
    let b = bundle(&f);
    let inv = f.path("work/hosts.yaml").display().to_string();
    let cases: &[(&[&str], &str)] = &[
        (&["--skip-recipe", "nope"], "no such recipe"),
        (&["--skip-resource", "nope"], "no recipe of this run"),
        (&["--skip-resource", "both"], "several recipes have this id"),
        (&["--skip-resource", "web/base"], "web/conf depends on base"),
        (
            &["--skip-recipe", "web", "--skip-recipe", "db"],
            "nothing to run",
        ),
    ];
    for phase in ["plan", "audit", "apply", "validate"] {
        for (extra, says) in cases {
            let mut args = vec![phase, &b, "--inventory", &inv];
            args.extend_from_slice(extra);
            let o = f.run(&args);
            code(&o, 2, &format!("{phase} {extra:?}"));
            assert!(
                text(&o.stderr).contains(says),
                "{says}: {}",
                text(&o.stderr)
            );
        }
    }
    assert_eq!(f.ssh_calls(), 0, "nothing was resolved");
    let o = f.run(&[
        "audit",
        &b,
        "--inventory",
        &inv,
        "--audit-policy",
        "strict",
        "--skip-recipe",
        "db",
    ]);
    code(&o, 2, "");
    assert!(text(&o.stderr).contains("strict"), "{}", text(&o.stderr));
}

#[test]
fn a_blocked_edge_is_shown_in_the_preview_too() {
    let f = Fx::new();
    let b = bundle(&f);
    let o = f.run(&["validate", &b, "--skip-resource", "web/base"]);
    code(&o, 2, "");
    let out = text(&o.stdout);
    assert!(out.contains("web/conf depends on base  BLOCKED"), "{out}");
}

#[test]
fn an_excluded_recipe_has_no_execution_and_its_only_host_is_not_resolved() {
    let f = Fx::new();
    let b = bundle(&f);
    let inv = f.path("work/hosts.yaml").display().to_string();
    let o = f.run(&[
        "plan",
        &b,
        "--inventory",
        &inv,
        "--skip-recipe",
        "db",
        "--format",
        "json",
    ]);
    code(&o, 3, "the web host is closed");
    let d = json(&o);
    let ex = d["executions"].as_array().unwrap();
    assert_eq!(ex.len(), 1);
    assert_eq!(ex[0]["recipe"], "web");
    assert_eq!(ex[0]["target"]["name"], "web01");
    assert_eq!(f.ssh_calls(), 1, "only web01 went through ssh -G");
    let o = f.run(&["plan", &b, "--inventory", &inv, "--skip-recipe", "db"]);
    let out = text(&o.stdout);
    assert!(out.contains("SKIPPED_BY_USER   recipe not run"), "{out}");
    assert!(out.contains("PARTIAL_PLAN:"), "{out}");
}

#[test]
fn an_excluded_recipe_is_still_validated() {
    let f = Fx::new();
    f.write("work/good.yaml", FREE);
    f.write("work/bad.yaml", "version: 1\nresources: 3\n");
    let b = f.write(
        "work/stack.yaml",
        "version: 1\nrecipes: [good.yaml, bad.yaml]\n",
    );
    code(&f.run(&["validate", &b, "--skip-recipe", "bad"]), 2, "");
}

#[test]
fn a_required_variable_stops_the_run_without_contact() {
    let f = Fx::new();
    let inv = f.inventory("work/hosts.yaml");
    f.write(
        "work/r.yaml",
        "version: 1\ntargets:\n  groups: [web]\nvars:\n  need: { value: x, required: true }\n",
    );
    let e = f.write("work/e.yaml", "version: 1\n");
    for phase in PHASES {
        let o = f.run(&[phase, "r.yaml", "--inventory", &inv, "--vars-file", &e]);
        code(&o, 2, phase);
        assert!(
            text(&o.stderr).contains("variable need is required"),
            "{}",
            text(&o.stderr)
        );
    }
    assert_eq!(f.ssh_calls(), 0);
}
