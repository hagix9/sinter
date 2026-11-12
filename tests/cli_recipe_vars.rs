//! The project file's `recipe_vars` through the real binary (DESIGN §40.5):
//! each recipe of a run gets its own variables files and nothing else. No test
//! needs a reachable host: hosts point at closed ports and `ssh` is a script
//! that records every call. Nothing here runs on the local target.
//!
//! The values a recipe ends up with are observed through what they decide: a
//! path that must be absolute (a relative one stops the run, naming the recipe)
//! and a required variable (no value stops the run). So a file that reached the
//! wrong recipe, or did not reach its own, changes the exit code.
#![cfg(unix)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const CANARY: &str = "RECIPE_VARS_CANARY_DO_NOT_PRINT";

// 05_ssh: `ssh_root` must be absolute; its default is.
const SSH: &str = "version: 1\ntargets:\n  hosts: [web01]\nvars:\n  ssh_root: { value: /srv/ssh }\nresources:\n  - id: k\n    type: directory\n    with: { path: \"{{ vars.ssh_root }}/k\" }\n";
// 10_firewall: `fw_port` is required.
const FW: &str = "version: 1\ntargets:\n  hosts: [web01]\nvars:\n  fw_port: { value: 1, required: true }\nresources:\n  - id: f\n    type: file\n    with: { path: /etc/fw, content: \"{{ vars.fw_port }}\" }\n";
// 20_web: `web_root` must be absolute and `web_port` is required.
const WEB: &str = "version: 1\ntargets:\n  hosts: [web01]\nvars:\n  web_root: { value: /srv/web }\n  web_port: { value: 1, required: true }\n  site_name: { value: s }\nresources:\n  - id: w\n    type: file\n    with: { path: \"{{ vars.web_root }}/index\", content: \"{{ vars.site_name }}:{{ vars.web_port }}\" }\n";
const BUNDLE: &str =
    "version: 1\nrecipes:\n  - recipes/05_ssh.yaml\n  - recipes/10_firewall.yaml\n  - recipes/20_web.yaml\n";
const PROJECT: &str = "version: 1\nrecipe_vars:\n  05_ssh:\n    - vars/ssh_key.yaml\n  10_firewall:\n    - vars/firewall.yaml\n  20_web:\n    - vars/common.yaml\n    - vars/web.yaml\n";

struct Fx {
    dir: tempfile::TempDir,
}

fn set_mode(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

impl Fx {
    /// The recipes, their bundle, each recipe's files and the project file.
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
        for d in ["work", "work/recipes", "work/vars"] {
            f.mkdir(d);
        }
        f.write("work/recipes/05_ssh.yaml", SSH);
        f.write("work/recipes/10_firewall.yaml", FW);
        f.write("work/recipes/20_web.yaml", WEB);
        f.write("work/site.yaml", BUNDLE);
        f.write(
            "work/vars/ssh_key.yaml",
            "version: 1\nvars: { ssh_root: /srv/keys }\n",
        );
        f.write(
            "work/vars/firewall.yaml",
            "version: 1\nvars: { fw_port: 2222 }\n",
        );
        f.write(
            "work/vars/common.yaml",
            "version: 1\nvars: { site_name: common, web_root: relative-common }\n",
        );
        f.write(
            "work/vars/web.yaml",
            "version: 1\nvars: { web_root: /srv/www, web_port: 8080 }\n",
        );
        f.write("work/sinter.yaml", PROJECT);
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

    fn inventory(&self) -> String {
        let ports = common::ClosedPorts::reserve(1);
        self.write(
            "work/hosts.yaml",
            &format!(
                "hosts:\n  web01: {{ address: 127.0.0.1, port: {}, user: u }}\ngroups:\n  web:\n    hosts: [web01]\n",
                ports.port(0)
            ),
        )
    }

    fn run(&self, args: &[&str]) -> Output {
        let path = format!(
            "{}:{}",
            self.path("fakebin").display(),
            std::env::var("PATH").unwrap()
        );
        Command::new(env!("CARGO_BIN_EXE_sinter"))
            .args(args)
            .current_dir(self.path("work"))
            .env("PATH", path)
            .env("NO_COLOR", "1")
            .env("SINTER_PROGRESS", "never")
            .output()
            .unwrap()
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

fn all(o: &Output) -> String {
    format!("{}\n{}", text(&o.stdout), text(&o.stderr))
}

fn code(o: &Output, want: i32, ctx: &str) {
    assert_eq!(o.status.code(), Some(want), "{ctx}: {}", all(o));
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", all(o)))
}

/// RV-01, RV-02, RV-03, RV-13: each recipe of the bundle gets exactly its own
/// files; the run is clean (no warning), which with the same files given to
/// every recipe it is not.
#[test]
fn each_recipe_gets_its_own_files_and_the_run_has_no_warning() {
    let f = Fx::new();
    let o = f.run(&["validate", "site.yaml"]);
    code(&o, 0, "bundle");
    let out = text(&o.stdout);
    let err = text(&o.stderr);
    for line in [
        "vars: recipe 05_ssh: ",
        "vars: recipe 10_firewall: ",
        "vars: recipe 20_web: ",
    ] {
        assert!(out.contains(line), "{line}: {out}");
    }
    assert!(
        out.contains("vars/common.yaml, ") && out.contains("vars/web.yaml"),
        "{out}"
    );
    assert!(!err.contains("warning"), "{err}");
    // The same files for every recipe (what recipe_vars replaces): one recipe
    // run alone warns about every other recipe's names.
    let mut args = vec!["validate", "recipes/05_ssh.yaml", "--no-config"];
    let files = ["vars/ssh_key.yaml", "vars/firewall.yaml", "vars/web.yaml"];
    for v in &files {
        args.push("--vars-file");
        args.push(v);
    }
    let o = f.run(&args);
    code(&o, 0, "shared files");
    let err = text(&o.stderr);
    assert!(err.contains("warning") && err.contains("fw_port"), "{err}");
    // With recipe_vars, the same recipe alone: no warning.
    let o = f.run(&["validate", "recipes/05_ssh.yaml"]);
    code(&o, 0, "05_ssh alone, recipe_vars");
    assert!(!text(&o.stderr).contains("warning"), "{}", all(&o));
    // A recipe alone gets its files only: the others are not even read. Make
    // them unreadable and broken to prove it.
    f.write("work/vars/firewall.yaml", "a: b: c: [\n");
    std::fs::remove_file(f.path("work/vars/web.yaml")).unwrap();
    let o = f.run(&["validate", "recipes/05_ssh.yaml"]);
    code(&o, 0, "05_ssh alone");
    assert!(
        text(&o.stdout).contains("vars: recipe 05_ssh: "),
        "{}",
        all(&o)
    );
    assert!(!all(&o).contains("firewall.yaml") && !all(&o).contains("web.yaml"));
    // The bundle reads them, and stops on them.
    let o = f.run(&["validate", "site.yaml"]);
    code(&o, 2, "bundle with broken files");
    assert!(
        all(&o).contains("firewall.yaml") && all(&o).contains("web.yaml"),
        "{}",
        all(&o)
    );
}

/// RV-02: a file of one recipe never reaches another recipe that declares the
/// same name; for the recipe it was not meant for the name is not declared.
#[test]
fn a_file_never_reaches_another_recipe() {
    let f = Fx::new();
    // firewall.yaml also names ssh_root, which only 05_ssh declares, with a
    // value 05_ssh would refuse. If it leaked, the run would stop on 05_ssh.
    f.write(
        "work/vars/firewall.yaml",
        &format!("version: 1\nvars: {{ fw_port: 2222, ssh_root: rel-{CANARY} }}\n"),
    );
    let o = f.run(&["validate", "site.yaml"]);
    code(&o, 0, "no leak");
    let err = text(&o.stderr);
    assert!(
        err.contains("variable ssh_root") && err.contains("is not declared by recipe 10_firewall"),
        "{err}"
    );
    assert!(!all(&o).contains(CANARY));
    // The same value in 05_ssh's own file is applied to 05_ssh, and refused.
    f.write(
        "work/vars/ssh_key.yaml",
        &format!("version: 1\nvars: {{ ssh_root: rel-{CANARY} }}\n"),
    );
    let o = f.run(&["validate", "site.yaml"]);
    code(&o, 2, "own file applies");
    assert!(all(&o).contains("recipe 05_ssh"), "{}", all(&o));
    assert!(!all(&o).contains(CANARY), "{}", all(&o));
}

/// RV-03, RV-06: a recipe's files layer in order, a later file winning
/// variable by variable; what it does not name stays.
#[test]
fn a_recipes_files_layer_in_the_order_listed() {
    let f = Fx::new();
    // common.yaml's relative web_root is replaced by web.yaml's absolute one.
    code(&f.run(&["validate", "site.yaml"]), 0, "web.yaml last");
    // The other order: common.yaml's value wins, and is refused.
    f.write(
        "work/sinter.yaml",
        &PROJECT.replace(
            "    - vars/common.yaml\n    - vars/web.yaml\n",
            "    - vars/web.yaml\n    - vars/common.yaml\n",
        ),
    );
    let o = f.run(&["validate", "site.yaml"]);
    code(&o, 2, "common.yaml last");
    assert!(all(&o).contains("recipe 20_web"), "{}", all(&o));
    // web_port, required, comes from web.yaml whichever is last.
    f.write(
        "work/vars/common.yaml",
        "version: 1\nvars: { site_name: c }\n",
    );
    code(
        &f.run(&["validate", "site.yaml"]),
        0,
        "required from web.yaml",
    );
}

/// RV-04: a recipe that recipe_vars does not list, or lists with no file, gets
/// no file: its defaults, and a required variable stops the run. Either way
/// the run says so.
#[test]
fn a_recipe_without_files_gets_none_and_says_so() {
    let f = Fx::new();
    f.write(
        "work/sinter.yaml",
        "version: 1\nrecipe_vars:\n  05_ssh:\n    - vars/ssh_key.yaml\n  20_web:\n    - vars/common.yaml\n    - vars/web.yaml\n",
    );
    let o = f.run(&["validate", "site.yaml"]);
    code(&o, 2, "required fw_port");
    assert!(
        all(&o).contains("vars: none for recipe 10_firewall (not listed in recipe_vars)"),
        "{}",
        all(&o)
    );
    assert!(all(&o).contains("fw_port is required"), "{}", all(&o));
    f.write(
        "work/sinter.yaml",
        "version: 1\nrecipe_vars:\n  10_firewall: []\n",
    );
    let o = f.run(&["validate", "recipes/05_ssh.yaml"]);
    code(&o, 0, "05_ssh with its defaults");
    assert!(
        text(&o.stdout).contains("vars: none for recipe 05_ssh (not listed in recipe_vars)"),
        "{}",
        all(&o)
    );
    assert!(
        text(&o.stdout).contains("no variables file applies"),
        "{}",
        all(&o)
    );
    let o = f.run(&["validate", "recipes/10_firewall.yaml"]);
    code(&o, 2, "listed with no file");
    assert!(all(&o).contains("recipe_vars lists no file"), "{}", all(&o));
}

/// RV-05, RV-14: --vars-file is refused next to recipe_vars and works as before
/// without it; a project without recipe_vars behaves as before.
#[test]
fn the_command_lines_files_and_recipe_vars_do_not_mix() {
    let f = Fx::new();
    let o = f.run(&["validate", "site.yaml", "--vars-file", "vars/web.yaml"]);
    code(&o, 2, "--vars-file with recipe_vars");
    assert!(
        all(&o).contains("--vars-file cannot be used with the recipe_vars"),
        "{}",
        all(&o)
    );
    // --no-config: the command line's files, as ever, given to every recipe.
    let o = f.run(&[
        "validate",
        "recipes/20_web.yaml",
        "--no-config",
        "--vars-file",
        "vars/web.yaml",
    ]);
    code(&o, 0, "--no-config");
    assert!(!text(&o.stdout).contains("vars: recipe "), "{}", all(&o));
    // vars_files and recipe_vars in one project file: refused.
    f.write(
        "work/sinter.yaml",
        &format!("{PROJECT}vars_files: [vars/common.yaml]\n"),
    );
    let o = f.run(&["validate", "site.yaml"]);
    code(&o, 2, "both fields");
    assert!(all(&o).contains("cannot both be set"), "{}", all(&o));
    // A project without recipe_vars: vars_files as before.
    f.write(
        "work/sinter.yaml",
        "version: 1\nvars_files: [vars/web.yaml]\n",
    );
    let o = f.run(&["validate", "recipes/20_web.yaml", "--format", "json"]);
    code(&o, 0, "vars_files");
    let d = json(&o);
    assert!(d["resolved"].get("recipe_vars").is_none(), "{d}");
    assert!(d["variables"]["file"]
        .as_str()
        .unwrap()
        .ends_with("vars/web.yaml"));
}

/// RV-07, RV-08: a missing file, a bad key and a broken field stop the run
/// before anything; a key that names no recipe of the run is not used.
#[test]
fn what_is_wrong_in_recipe_vars_stops_the_run() {
    let f = Fx::new();
    let inv = f.inventory();
    std::fs::remove_file(f.path("work/vars/firewall.yaml")).unwrap();
    for phase in ["validate", "plan", "audit", "apply"] {
        let o = f.run(&[phase, "site.yaml", "--inventory", &inv]);
        code(&o, 2, phase);
        assert!(all(&o).contains("firewall.yaml"), "{phase}: {}", all(&o));
    }
    assert_eq!(f.ssh_calls(), 0);
    for (body, want) in [
        (
            "version: 1\nrecipe_vars:\n  \"05 ssh\": [vars/ssh_key.yaml]\n",
            "a key must be a recipe name",
        ),
        (
            "version: 1\nrecipe_vars:\n  05_ssh: vars/ssh_key.yaml\n",
            "must be a list of paths",
        ),
        ("version: 1\nrecipe_vars: {}\n", "must not be empty"),
    ] {
        f.write("work/sinter.yaml", body);
        let o = f.run(&["validate", "site.yaml"]);
        code(&o, 2, want);
        assert!(all(&o).contains(want), "{want}: {}", all(&o));
    }
    // A key of another bundle's recipe is fine; this run's recipes are listed
    // with what they got.
    f.write(
        "work/sinter.yaml",
        "version: 1\nrecipe_vars:\n  99_other: [vars/nowhere.yaml]\n  05_ssh: [vars/ssh_key.yaml]\n",
    );
    let o = f.run(&["validate", "recipes/05_ssh.yaml"]);
    code(&o, 0, "other key");
    assert!(!all(&o).contains("nowhere.yaml"), "{}", all(&o));
}

/// RV-09: two recipes of one label are refused when recipe_vars names that
/// label, never matched to one of them.
#[test]
fn two_recipes_of_one_name_are_refused() {
    let f = Fx::new();
    f.mkdir("work/other");
    f.write("work/other/05_ssh.yaml", SSH);
    f.write(
        "work/twin.yaml",
        "version: 1\nrecipes:\n  - recipes/05_ssh.yaml\n  - other/05_ssh.yaml\n",
    );
    let o = f.run(&["validate", "twin.yaml"]);
    code(&o, 2, "twins");
    assert!(
        all(&o).contains("recipe_vars: 2 recipes of this run are named 05_ssh"),
        "{}",
        all(&o)
    );
    // Not named in recipe_vars: no file for either, and no ambiguity.
    f.write(
        "work/sinter.yaml",
        "version: 1\nrecipe_vars:\n  20_web: [vars/web.yaml]\n",
    );
    code(&f.run(&["validate", "twin.yaml"]), 0, "twins not named");
}

/// RV-10: group and host layers of a recipe's own files apply to that recipe
/// with the precedence of §19.5, and are checked against the inventory.
#[test]
fn group_and_host_layers_of_a_recipes_files_apply() {
    let f = Fx::new();
    let inv = f.inventory();
    // The common value is refused; the group's value (and over it the host's)
    // is what web01 runs with.
    f.write(
        "work/vars/ssh_key.yaml",
        "version: 1\nvars: { ssh_root: relative }\ngroups: { web: { ssh_root: also-relative } }\nhosts: { web01: { ssh_root: /srv/h } }\n",
    );
    code(
        &f.run(&["validate", "site.yaml", "--inventory", &inv]),
        0,
        "host layer",
    );
    f.write(
        "work/vars/ssh_key.yaml",
        "version: 1\nvars: { ssh_root: relative }\ngroups: { web: { ssh_root: /srv/g } }\n",
    );
    code(
        &f.run(&["validate", "site.yaml", "--inventory", &inv]),
        0,
        "group layer",
    );
    f.write(
        "work/vars/ssh_key.yaml",
        "version: 1\nvars: { ssh_root: /srv/c }\ngroups: { ghost: { ssh_root: /x } }\n",
    );
    let o = f.run(&["validate", "site.yaml", "--inventory", &inv]);
    code(&o, 2, "unknown group");
    assert!(
        all(&o).contains("group ghost is not defined in inventory"),
        "{}",
        all(&o)
    );
    // Without an inventory a group layer is refused, as for any file.
    let o = f.run(&["validate", "site.yaml"]);
    code(&o, 2, "groups without inventory");
    assert!(
        all(&o).contains("group variables need --inventory"),
        "{}",
        all(&o)
    );
}

/// RV-11: validate, plan, audit and apply run the same gate: the same files per
/// recipe, the same refusal before any contact, and past the gate the same
/// clean start.
#[test]
fn every_phase_gives_each_recipe_the_same_files() {
    let f = Fx::new();
    let inv = f.inventory();
    let mut seen: Vec<Vec<String>> = Vec::new();
    for phase in ["validate", "plan", "audit", "apply"] {
        let o = f.run(&[phase, "site.yaml", "--inventory", &inv]);
        let lines: Vec<String> = text(&o.stdout)
            .lines()
            .filter(|l| l.starts_with("vars: "))
            .map(str::to_string)
            .collect();
        assert_eq!(lines.len(), 4, "{phase}: {}", all(&o));
        assert!(!text(&o.stderr).contains("warning"), "{phase}: {}", all(&o));
        seen.push(lines);
    }
    assert!(seen.windows(2).all(|w| w[0] == w[1]), "{seen:?}");
    // The gate passed for plan, audit and apply: they went on to the host.
    assert!(f.ssh_calls() > 0);
    // A value that is refused for one recipe stops every phase before contact.
    let before = f.ssh_calls();
    f.write(
        "work/vars/web.yaml",
        "version: 1\nvars: { web_root: relative, web_port: 8080 }\n",
    );
    for phase in ["validate", "plan", "audit", "apply"] {
        let o = f.run(&[phase, "site.yaml", "--inventory", &inv]);
        code(&o, 2, phase);
        assert!(all(&o).contains("recipe 20_web"), "{phase}: {}", all(&o));
    }
    assert_eq!(f.ssh_calls(), before, "nothing was contacted");
    // JSON says which files each recipe got.
    f.write(
        "work/vars/web.yaml",
        "version: 1\nvars: { web_root: /srv/www, web_port: 8080 }\n",
    );
    let o = f.run(&[
        "validate",
        "site.yaml",
        "--inventory",
        &inv,
        "--format",
        "json",
    ]);
    code(&o, 0, "json");
    let d = json(&o);
    let rv = d["resolved"]["recipe_vars"].as_array().unwrap();
    let names: Vec<&str> = rv.iter().map(|r| r["recipe"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["05_ssh", "10_firewall", "20_web"]);
    assert_eq!(rv[2]["files"].as_array().unwrap().len(), 2);
    assert_eq!(d["resolved"]["vars_files"].as_array().unwrap().len(), 0);
    assert_eq!(d["variables"]["files"].as_array().unwrap().len(), 4);
}

/// RV-12: values stay out of every message, warning and document.
#[test]
fn values_never_appear_in_output() {
    let f = Fx::new();
    let inv = f.inventory();
    f.write(
        "work/vars/firewall.yaml",
        &format!("version: 1\nvars: {{ fw_port: 2222, stray: \"{CANARY}\" }}\n"),
    );
    f.write(
        "work/vars/web.yaml",
        &format!("version: 1\nvars: {{ web_root: /srv/www, web_port: \"{CANARY}\" }}\n"),
    );
    for args in [
        vec!["validate", "site.yaml"],
        vec!["validate", "site.yaml", "--format", "json"],
        vec![
            "plan",
            "site.yaml",
            "--inventory",
            inv.as_str(),
            "--format",
            "json",
        ],
        vec!["validate", "site.yaml", "--strict-vars"],
    ] {
        let o = f.run(&args);
        code(&o, 2, &args.join(" "));
        assert!(!all(&o).contains(CANARY), "{args:?}: {}", all(&o));
    }
    // The stray name alone is a warning naming the variable, not its value.
    f.write(
        "work/vars/web.yaml",
        "version: 1\nvars: { web_root: /srv/www, web_port: 8080 }\n",
    );
    let o = f.run(&["validate", "site.yaml", "--format", "json"]);
    code(&o, 0, "warning only");
    let d = json(&o);
    let w = d["vars_warnings"].as_array().unwrap();
    assert_eq!(w.len(), 1, "{d}");
    assert!(w[0].as_str().unwrap().contains("stray"));
    assert!(!all(&o).contains(CANARY));
}

/// A recipe's files are held to the rules of a file the project names (DESIGN
/// §40.1): a file others can write, or a link, is refused before anything runs.
#[test]
fn a_recipes_files_are_held_to_the_project_file_rules() {
    let f = Fx::new();
    set_mode(&f.path("work/vars/firewall.yaml"), 0o666);
    let o = f.run(&["validate", "site.yaml"]);
    code(&o, 2, "group/other writable");
    assert!(all(&o).contains("firewall.yaml"), "{}", all(&o));
    set_mode(&f.path("work/vars/firewall.yaml"), 0o644);
    std::fs::rename(
        f.path("work/vars/firewall.yaml"),
        f.path("work/vars/fw-real.yaml"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        f.path("work/vars/fw-real.yaml"),
        f.path("work/vars/firewall.yaml"),
    )
    .unwrap();
    let o = f.run(&["validate", "site.yaml"]);
    code(&o, 2, "symbolic link");
    // A recipe this run does not have: its file is never looked at.
    let o = f.run(&["validate", "recipes/05_ssh.yaml"]);
    code(&o, 0, "05_ssh alone");
}

/// A recipe --skip-recipe leaves out is still validated, with its own files.
#[test]
fn a_skipped_recipe_is_still_validated_with_its_own_files() {
    let f = Fx::new();
    f.write(
        "work/vars/firewall.yaml",
        "version: 1\nvars: { fw_port: \"text\" }\n",
    );
    let o = f.run(&["validate", "site.yaml", "--skip-recipe", "10_firewall"]);
    code(&o, 2, "skipped but checked");
    assert!(all(&o).contains("recipe 10_firewall"), "{}", all(&o));
    f.write(
        "work/vars/firewall.yaml",
        "version: 1\nvars: { fw_port: 2222 }\n",
    );
    code(
        &f.run(&["validate", "site.yaml", "--skip-recipe", "10_firewall"]),
        0,
        "skipped, files fine",
    );
}

/// Two hosts of group web, for `--limit`.
fn two_host_inventory(f: &Fx) -> (String, u16, u16) {
    let ports = common::ClosedPorts::reserve(2);
    let (a, b) = (ports.port(0), ports.port(1));
    let inv = f.write(
        "work/hosts2.yaml",
        &format!(
            "hosts:\n  web01: {{ address: 127.0.0.1, port: {a}, user: u }}\n  web02: {{ address: 127.0.0.1, port: {b}, user: u }}\ngroups:\n  web:\n    hosts: [web01, web02]\n"
        ),
    );
    (inv, a, b)
}

/// RV-15: with `--limit` each selected host gets its own layer of its recipe's
/// files, a host left out is neither checked nor contacted, no recipe gets
/// another's files, and a bad selection stops before any contact.
#[test]
fn limit_applies_each_recipes_files_to_the_selected_hosts_only() {
    let f = Fx::new();
    let (inv, port1, port2) = two_host_inventory(&f);
    for (rel, body) in [
        ("work/recipes/05_ssh.yaml", SSH),
        ("work/recipes/10_firewall.yaml", FW),
        ("work/recipes/20_web.yaml", WEB),
    ] {
        f.write(rel, &body.replace("hosts: [web01]", "groups: [web]"));
    }
    // web01's value is valid, web02's would be refused; firewall.yaml names
    // ssh_root for web01 with a refused value, which must not reach 05_ssh.
    f.write(
        "work/vars/ssh_key.yaml",
        "version: 1\nhosts: { web01: { ssh_root: /srv/one }, web02: { ssh_root: relative-two } }\n",
    );
    f.write(
        "work/vars/firewall.yaml",
        "version: 1\nvars: { fw_port: 2222 }\nhosts: { web01: { ssh_root: relative-fw } }\n",
    );
    // Without --limit both hosts run: web02's value stops the run, before contact.
    let o = f.run(&["validate", "site.yaml", "--inventory", &inv]);
    code(&o, 2, "web02 runs");
    assert!(all(&o).contains("recipe 05_ssh @ web02"), "{}", all(&o));
    // --limit web01: web02's layer is out of the run; 05_ssh gets web01's own
    // value (not firewall.yaml's), so the run is clean but for the stray name.
    for phase in ["validate", "plan", "audit", "apply"] {
        let o = f.run(&[phase, "site.yaml", "--inventory", &inv, "--limit", "web01"]);
        assert!(
            !all(&o).contains("recipe 05_ssh @"),
            "{phase}: no refusal of 05_ssh: {}",
            all(&o)
        );
        assert!(
            all(&o).contains("is not declared by recipe 10_firewall"),
            "{phase}: {}",
            all(&o)
        );
        if phase == "validate" {
            code(&o, 0, phase);
        }
    }
    // Only web01 was contacted, never web02.
    let log = std::fs::read_to_string(f.path("fakebin/ssh.log")).unwrap_or_default();
    let contacted = |port: u16| log.lines().any(|l| l.contains(&format!(" -p {port} -- ")));
    assert!(contacted(port1), "{log}");
    assert!(!contacted(port2), "{log}");
    // A bad selection stops every phase before anything is contacted.
    let before = f.ssh_calls();
    for phase in ["validate", "plan", "audit", "apply"] {
        let o = f.run(&[phase, "site.yaml", "--inventory", &inv, "--limit", "web99"]);
        code(&o, 2, phase);
    }
    assert_eq!(f.ssh_calls(), before);
}

/// RV-16: a recipe's own file cannot set a sensitive variable of it: exit 2 in
/// every phase, before contact, the value never shown. The same name in
/// another recipe's file is that recipe's undeclared name and never reaches
/// the recipe that declares it sensitive.
#[test]
fn a_sensitive_variable_cannot_be_set_and_its_value_never_shows() {
    let f = Fx::new();
    let inv = f.inventory();
    f.write(
        "work/recipes/30_secret.yaml",
        "version: 1\ntargets:\n  hosts: [web01]\nvars:\n  api_token: { value: placeholder, sensitive: true }\nresources:\n  - id: s\n    type: directory\n    with: { path: /srv/s }\n",
    );
    f.write(
        "work/site.yaml",
        &format!("{BUNDLE}  - recipes/30_secret.yaml\n"),
    );
    f.write(
        "work/vars/secret.yaml",
        &format!("version: 1\nvars: {{ api_token: \"{CANARY}\" }}\n"),
    );
    f.write(
        "work/sinter.yaml",
        &format!("{PROJECT}  30_secret:\n    - vars/secret.yaml\n"),
    );
    for phase in ["validate", "plan", "audit", "apply"] {
        for json in [false, true] {
            let mut args = vec![phase, "site.yaml", "--inventory", inv.as_str()];
            if json {
                args.extend(["--format", "json"]);
            }
            let o = f.run(&args);
            code(&o, 2, &args.join(" "));
            assert!(
                all(&o).contains("variable api_token is declared sensitive by recipe 30_secret"),
                "{args:?}: {}",
                all(&o)
            );
            assert!(!all(&o).contains(CANARY), "{args:?}: {}", all(&o));
        }
    }
    assert_eq!(f.ssh_calls(), 0, "nothing was contacted");
    // In another recipe's file the name is that recipe's stray name: a warning
    // naming the variable, never applied to 30_secret, the value never shown.
    f.write("work/sinter.yaml", PROJECT);
    f.write(
        "work/vars/firewall.yaml",
        &format!("version: 1\nvars: {{ fw_port: 2222, api_token: \"{CANARY}\" }}\n"),
    );
    let o = f.run(&[
        "validate",
        "site.yaml",
        "--inventory",
        &inv,
        "--format",
        "json",
    ]);
    code(&o, 0, "other recipe's file");
    assert!(
        all(&o).contains("variable api_token")
            && all(&o).contains("is not declared by recipe 10_firewall"),
        "{}",
        all(&o)
    );
    assert!(!all(&o).contains(CANARY), "{}", all(&o));
}
