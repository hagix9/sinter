//! Recipe, bundle and inventory resolution by name through the real binary
//! (DESIGN §39.3, §40.2, §40.3; SR-2). No test reaches a host: hosts point at
//! closed ports, `ssh` is a script that records every call, and the phases are
//! `validate` (which contacts nothing) or runs that stop before any contact.
#![cfg(unix)]

mod common;

use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const FREE: &str =
    "version: 1\nresources:\n  - id: a\n    type: file\n    with: { path: /srv/a, content: x }\n";
const WEB: &str = "version: 1\ntargets:\n  groups: [web]\nresources:\n  - id: a\n    type: file\n    with: { path: /srv/a, content: x }\n";
const BUNDLE: &str = "version: 1\nrecipes:\n  - packages.yaml\n  - services.yaml\n";
const PROJECT: &str = "version: 1\nrecipe_paths: [./recipes]\n";

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

    /// The layout of the Owner's example: a project with `recipe_paths` and
    /// single recipes, a subdirectory and a bundle directory below it.
    fn project() -> Self {
        let f = Fx::new();
        f.write("work/sinter.yaml", PROJECT);
        f.write("work/recipes/nginx.yaml", FREE);
        f.write("work/recipes/security/ssh.yaml", FREE);
        f.write("work/recipes/security/firewall.yaml", FREE);
        f.bundle("work/recipes/common/02_moge");
        f
    }

    fn bundle(&self, dir: &str) {
        self.write(&format!("{dir}/bundle.yaml"), BUNDLE);
        self.write(&format!("{dir}/packages.yaml"), FREE);
        self.write(&format!("{dir}/services.yaml"), FREE);
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn mkdir(&self, rel: &str) {
        let p = self.path(rel);
        std::fs::create_dir_all(&p).unwrap();
        // Every directory on the way gets a private mode, as after umask 022.
        let mut d = p.as_path();
        while d != self.dir.path() {
            set_mode(d, 0o755);
            d = d.parent().unwrap();
        }
    }

    fn write(&self, rel: &str, body: &str) -> String {
        if let Some(parent) = Path::new(rel).parent() {
            if !parent.as_os_str().is_empty() {
                self.mkdir(parent.to_str().unwrap());
            }
        }
        let p = self.path(rel);
        std::fs::write(&p, body).unwrap();
        set_mode(&p, 0o644);
        p.display().to_string()
    }

    fn inventory(&self, rel: &str) -> String {
        let ports = common::ClosedPorts::reserve(2);
        let body = if rel.ends_with(".toml") {
            format!(
                "[hosts.web01]\naddress = \"127.0.0.1\"\nport = {}\nuser = \"u\"\n[hosts.db01]\naddress = \"127.0.0.1\"\nport = {}\nuser = \"u\"\n[groups.web]\nhosts = [\"web01\"]\n[groups.db]\nhosts = [\"db01\"]\n",
                ports.port(0),
                ports.port(1)
            )
        } else {
            format!(
                "hosts:\n  web01: {{ address: 127.0.0.1, port: {}, user: u }}\n  db01: {{ address: 127.0.0.1, port: {}, user: u }}\ngroups:\n  web:\n    hosts: [web01]\n  db:\n    hosts: [db01]\n",
                ports.port(0),
                ports.port(1)
            )
        };
        self.write(rel, &body)
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

/// Exit 2 with every needle in stderr.
fn refused(o: &Output, needles: &[&str], ctx: &str) {
    code(o, 2, ctx);
    let err = text(&o.stderr);
    for n in needles {
        assert!(err.contains(n), "{ctx}: missing {n:?} in {err}");
    }
}

/// The same file, whichever spelling of the temporary directory the binary saw
/// (`/var` is `/private/var` on macOS).
fn assert_same_file(got: &serde_json::Value, want: &str, ctx: &str) {
    let got = got.as_str().unwrap_or_else(|| panic!("{ctx}: {got}"));
    let canon = |p: &str| std::fs::canonicalize(p).unwrap_or_else(|e| panic!("{ctx}: {p}: {e}"));
    assert_eq!(canon(got), canon(want), "{ctx}");
}

fn resolved_path(o: &Output) -> String {
    json(o)["resolved"]["recipe"]["path"]
        .as_str()
        .unwrap_or_else(|| panic!("no resolved.recipe.path: {}", text(&o.stdout)))
        .to_string()
}

// 1, 6, 7: single recipes are found below recipe_paths by their file name, or by
// the last components of their path.
#[test]
fn a_single_recipe_is_found_by_its_file_name_below_recipe_paths() {
    let f = Fx::project();
    for (arg, want) in [
        ("ssh.yaml", "recipes/security/ssh.yaml"),
        ("firewall.yaml", "recipes/security/firewall.yaml"),
        ("security/ssh.yaml", "recipes/security/ssh.yaml"),
    ] {
        let o = f.run(&["validate", arg, "--format", "json"]);
        code(&o, 0, arg);
        assert!(
            resolved_path(&o).ends_with(want),
            "{arg}: {}",
            resolved_path(&o)
        );
        let d = json(&o);
        assert_eq!(d["resolved"]["recipe"]["via"], "recipe_paths", "{arg}");
        assert_eq!(d["resolved"]["recipe"]["match"], "search", "{arg}");
        assert_eq!(d["resolved"]["recipe"]["query"], arg, "{arg}");
        // The text line says where it came from, before anything runs.
        assert!(
            text(&o.stderr).contains("found by searching recipe_paths"),
            "{arg}"
        );
        let t = f.run(&["validate", arg]);
        code(&t, 0, arg);
        assert!(
            text(&t.stdout).contains(&format!("({arg} found by searching recipe_paths)")),
            "{}",
            text(&t.stdout)
        );
    }
    // The exact name of v1.10.0 keeps its output: no match or query keys.
    let o = f.run(&["validate", "nginx.yaml", "--format", "json"]);
    code(&o, 0, "exact");
    let r = &json(&o)["resolved"]["recipe"];
    assert_eq!(r["via"], "recipe_paths");
    assert!(r.get("match").is_none() && r.get("query").is_none(), "{r}");
    let t = f.run(&["validate", "nginx.yaml"]);
    assert!(text(&t.stdout).contains("(found through recipe_paths)"));
    // Another directory of the same name ending does not match.
    refused(
        &f.run(&["validate", "other/ssh.yaml"]),
        &["was not found"],
        "other/ssh.yaml",
    );
    // Names compare byte for byte in the search, on every system.
    refused(
        &f.run(&["validate", "SSH.yaml"]),
        &["was not found"],
        "case",
    );
}

// 2: no extension is added to a single recipe, with or without a project file.
#[test]
fn a_single_recipe_never_gets_an_extension_added() {
    let f = Fx::project();
    for arg in ["nginx", "ssh", "security/ssh"] {
        let o = f.run(&["validate", arg]);
        refused(&o, &["was not found", "never added"], arg);
    }
    // The file it was probably meant as is shown, never used.
    refused(
        &f.run(&["validate", "ssh"]),
        &["not used, since the name differs", "security/ssh.yaml"],
        "hint",
    );
    // Without a project file the argument stays what it was in v1.10.0.
    let g = Fx::new();
    g.write("work/r.yaml", FREE);
    refused(
        &g.run(&["validate", "r"]),
        &["cannot read recipe r"],
        "no project",
    );
    code(&g.run(&["validate", "r.yaml"]), 0, "with its extension");
    // An extensionless file is still refused for its extension.
    g.write("work/plain", FREE);
    refused(
        &g.run(&["validate", "plain"]),
        &["unsupported recipe extension"],
        "extensionless",
    );
}

// 3: a bundle is named by its directory, in recipe_paths and in the current
// directory, with or without a project file.
#[test]
fn a_bundle_is_named_by_its_directory() {
    let f = Fx::project();
    for arg in ["02_moge", "common/02_moge"] {
        let o = f.run(&["validate", arg, "--format", "json"]);
        code(&o, 0, arg);
        assert!(
            resolved_path(&o).ends_with("recipes/common/02_moge/bundle.yaml"),
            "{arg}: {}",
            resolved_path(&o)
        );
        let r = &json(&o)["resolved"]["recipe"];
        assert_eq!(r["match"], "bundle_directory", "{arg}");
        assert_eq!(r["via"], "recipe_paths", "{arg}");
    }
    let t = f.run(&["validate", "02_moge"]);
    assert!(
        text(&t.stdout).contains("(bundle directory 02_moge found by searching recipe_paths)"),
        "{}",
        text(&t.stdout)
    );
    // The bundle file by its path still works, and a member by a name that
    // names the bundle directory.
    code(
        &f.run(&["validate", "recipes/common/02_moge/bundle.yaml"]),
        0,
        "file",
    );
    let o = f.run(&["validate", "02_moge/packages.yaml", "--format", "json"]);
    code(&o, 0, "member");
    assert!(resolved_path(&o).ends_with("02_moge/packages.yaml"));
    // A member is never found by its own name alone.
    refused(
        &f.run(&["validate", "packages.yaml"]),
        &["was not found"],
        "member alone",
    );
    // bundle.yaml alone reaches no bundle: each lies inside its directory.
    refused(
        &f.run(&["validate", "bundle.yaml"]),
        &["was not found"],
        "bundle.yaml",
    );

    // Overlapping recipe_paths reach one bundle directory twice: one candidate.
    f.write(
        "work/sinter.yaml",
        "version: 1\nrecipe_paths: [./recipes, ./recipes/common]\n",
    );
    let o = f.run(&["validate", "02_moge", "--format", "json"]);
    code(&o, 0, "overlapping roots");
    f.write("work/sinter.yaml", PROJECT);

    // No project file: a bundle directory directly in the current directory.
    let g = Fx::new();
    g.bundle("work/02_moge");
    let o = g.run(&["validate", "02_moge", "--format", "json"]);
    code(&o, 0, "here");
    let r = &json(&o)["resolved"]["recipe"];
    assert_eq!(r["via"], "current_directory");
    assert_eq!(r["match"], "bundle_directory");
    assert!(json(&o)["resolved"]["config"].is_null());
    let t = g.run(&["validate", "02_moge"]);
    assert!(
        text(&t.stdout).contains(
            "recipe: 02_moge/bundle.yaml (bundle directory 02_moge in the current directory)"
        ),
        "{}",
        text(&t.stdout)
    );
    // Only directly: a bundle directory further down is not looked for.
    g.bundle("work/deep/03_x");
    refused(
        &g.run(&["validate", "03_x"]),
        &["cannot read recipe 03_x"],
        "not below",
    );
    // A directory with no bundle file is what it was: not a recipe.
    g.mkdir("work/plain_dir");
    refused(
        &g.run(&["validate", "plain_dir"]),
        &["cannot read recipe plain_dir"],
        "dir",
    );
}

// 4: `<name>.yaml` is never another name for the bundle directory `<name>`.
#[test]
fn a_bundle_directory_has_no_yaml_alias() {
    let f = Fx::project();
    refused(
        &f.run(&["validate", "02_moge.yaml"]),
        &[
            "was not found",
            "never as <name>.yaml",
            "recipes/common/02_moge",
        ],
        "alias",
    );
    // A real 02_moge.yaml is a single recipe, and 02_moge still the directory:
    // the two names mean two things, and neither is ambiguous.
    f.write("work/recipes/02_moge.yaml", FREE);
    let o = f.run(&["validate", "02_moge.yaml", "--format", "json"]);
    code(&o, 0, "file");
    assert!(resolved_path(&o).ends_with("recipes/02_moge.yaml"));
    let o = f.run(&["validate", "02_moge", "--format", "json"]);
    code(&o, 0, "dir");
    assert!(resolved_path(&o).ends_with("02_moge/bundle.yaml"));
}

// 5: one bundle file per bundle directory, and it must be a bundle.
#[test]
fn a_bundle_directory_holds_one_bundle() {
    let f = Fx::project();
    f.write(
        "work/recipes/common/02_moge/bundle.toml",
        "version = 1\nrecipes = [\"packages.yaml\"]\n",
    );
    refused(
        &f.run(&["validate", "02_moge"]),
        &[
            "several bundle files",
            "bundle.toml",
            "bundle.yaml",
            "never picks",
        ],
        "two",
    );
    let g = Fx::project();
    g.write("work/recipes/common/02_moge/bundle.yaml", FREE);
    refused(
        &g.run(&["validate", "02_moge"]),
        &["has no top-level recipes"],
        "not a bundle",
    );
    // bundle.yml and bundle.toml are conventional names too.
    let h = Fx::new();
    h.write(
        "work/03/bundle.toml",
        "version = 1\nrecipes = [\"a.yaml\"]\n",
    );
    h.write("work/03/a.yaml", FREE);
    let o = h.run(&["validate", "03", "--format", "json"]);
    code(&o, 0, "toml");
    assert!(resolved_path(&o).ends_with("03/bundle.toml"));
}

// 8: two candidates are never a choice.
#[test]
fn several_candidates_stop_the_run() {
    let f = Fx::project();
    f.write("work/recipes/legacy/ssh.yaml", FREE);
    let o = f.run(&["validate", "ssh.yaml"]);
    refused(
        &o,
        &[
            "ambiguous",
            "recipes/legacy/ssh.yaml",
            "recipes/security/ssh.yaml",
            "never picks",
        ],
        "two files",
    );
    // More of the path settles it.
    let o = f.run(&["validate", "security/ssh.yaml", "--format", "json"]);
    code(&o, 0, "settled");
    assert!(resolved_path(&o).ends_with("recipes/security/ssh.yaml"));
    // Two bundle directories of one name.
    f.bundle("work/recipes/other/02_moge");
    refused(
        &f.run(&["validate", "02_moge"]),
        &["ambiguous", "common/02_moge", "other/02_moge"],
        "two bundles",
    );
    // A bundle directory in the current directory and one in recipe_paths.
    let g = Fx::project();
    g.bundle("work/02_moge");
    refused(
        &g.run(&["validate", "02_moge"]),
        &["ambiguous"],
        "here and there",
    );
    // The exact rule of v1.10.0 still decides first, and still refuses two.
    let h = Fx::project();
    h.write("work/nginx.yaml", FREE);
    refused(
        &h.run(&["validate", "nginx.yaml"]),
        &["ambiguous"],
        "v1.10.0",
    );
    // Something unusable under the name is a candidate, never skipped.
    let k = Fx::project();
    k.write("work/recipes/x/02_moge", FREE);
    refused(
        &k.run(&["validate", "02_moge"]),
        &["ambiguous"],
        "a file named like the bundle",
    );
    nothing_contacted(&k);
}

fn nothing_contacted(f: &Fx) {
    assert_eq!(f.ssh_calls(), 0, "no ssh -G may run");
}

// 9: links are not followed, paths are not names, and what is found is held
// to the owner and mode rules, a found bundle's members too.
#[test]
fn links_paths_and_modes_are_refused() {
    let f = Fx::project();
    f.write("outside/escape.yaml", FREE);
    f.bundle("outside/04_out");
    // A linked directory is not entered.
    symlink(f.path("outside"), f.path("work/recipes/linked")).unwrap();
    refused(
        &f.run(&["validate", "escape.yaml"]),
        &["was not found"],
        "linked dir",
    );
    refused(
        &f.run(&["validate", "04_out"]),
        &["was not found"],
        "linked bundle dir",
    );
    // A linked file is a candidate, and refused.
    symlink(
        f.path("outside/escape.yaml"),
        f.path("work/recipes/security/l.yaml"),
    )
    .unwrap();
    refused(
        &f.run(&["validate", "l.yaml"]),
        &["symbolic link"],
        "linked file",
    );
    // A link next to its own target is a second candidate, in either order.
    for (real, link) in [
        ("a1/twin.yaml", "b1/twin.yaml"),
        ("b2/twin2.yaml", "a2/twin2.yaml"),
    ] {
        f.write(&format!("work/recipes/{real}"), FREE);
        f.mkdir(&format!(
            "work/recipes/{}",
            Path::new(link).parent().unwrap().display()
        ));
        symlink(
            f.path(&format!("work/recipes/{real}")),
            f.path(&format!("work/recipes/{link}")),
        )
        .unwrap();
        let name = Path::new(real)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        refused(
            &f.run(&["validate", &name]),
            &["ambiguous", real, link],
            "link and target",
        );
    }
    // ../ and ./ are paths, never names: used as given.
    refused(
        &f.run(&["validate", "../outside/nope.yaml"]),
        &["cannot read recipe"],
        "../",
    );
    code(
        &f.run(&["validate", "../outside/escape.yaml"]),
        0,
        "a path that exists",
    );
    refused(
        &f.run(&["validate", "./ssh.yaml"]),
        &["cannot read recipe"],
        "./",
    );
    // A found file writable by others is refused, not passed over.
    set_mode(&f.path("work/recipes/security/firewall.yaml"), 0o666);
    refused(
        &f.run(&["validate", "firewall.yaml"]),
        &["writable by group or others"],
        "mode",
    );
    // A member of a bundle found by name is checked too; by its path it is not.
    set_mode(&f.path("work/recipes/common/02_moge/services.yaml"), 0o664);
    refused(
        &f.run(&["validate", "02_moge"]),
        &["services.yaml", "writable by group or others"],
        "member",
    );
    code(
        &f.run(&["validate", "recipes/common/02_moge/bundle.yaml"]),
        0,
        "by path",
    );
    // A bundle directory in the current directory is held to the same rules.
    let g = Fx::new();
    g.bundle("work/02_moge");
    set_mode(&g.path("work/02_moge"), 0o775);
    refused(
        &g.run(&["validate", "02_moge"]),
        &["recipe file found by name", "writable by group or others"],
        "here",
    );
    nothing_contacted(&f);
    nothing_contacted(&g);
}

// 10: beyond the limits nothing is used.
#[test]
fn the_search_stops_at_its_limits() {
    let f = Fx::project();
    f.write("work/recipes/1/2/3/4/5/6/deep.yaml", FREE);
    refused(
        &f.run(&["validate", "ssh.yaml"]),
        &["more than 6 levels"],
        "depth",
    );
    // Six levels are searched.
    let g = Fx::project();
    g.write("work/recipes/1/2/3/4/5/six.yaml", FREE);
    code(&g.run(&["validate", "six.yaml"]), 0, "six levels");
    // The number of entries.
    let h = Fx::project();
    h.mkdir("work/recipes/many");
    for i in 0..20_001 {
        std::fs::write(h.path(&format!("work/recipes/many/f{i}")), "").unwrap();
    }
    refused(
        &h.run(&["validate", "ssh.yaml"]),
        &["more than 20000 entries"],
        "entries",
    );
    // The exact rule needs no search, so it still works.
    code(&h.run(&["validate", "nginx.yaml"]), 0, "exact");
    // A directory that cannot be read stops it (root reads everything).
    if unsafe { libc::geteuid() } != 0 {
        let k = Fx::project();
        k.mkdir("work/recipes/closed");
        set_mode(&k.path("work/recipes/closed"), 0o000);
        let o = k.run(&["validate", "ssh.yaml"]);
        set_mode(&k.path("work/recipes/closed"), 0o755);
        refused(&o, &["cannot read", "closed"], "unreadable");
    }
}

// 11-14: the six names of an inventory are detected for a selector.
#[test]
fn every_inventory_name_is_detected_for_a_selector() {
    for name in [
        "hosts.yaml",
        "hosts.yml",
        "hosts.toml",
        "inventory.yaml",
        "inventory.yml",
        "inventory.toml",
    ] {
        let f = Fx::new();
        f.write("work/r.yaml", WEB);
        let inv = f.inventory(&format!("work/{name}"));
        let o = f.run(&["validate", "r.yaml", "web01", "--format", "json"]);
        code(&o, 0, name);
        let d = json(&o);
        assert_same_file(&d["inventory"], &inv, name);
        assert_eq!(d["inventory_source"], "detected", "{name}");
        assert!(
            text(&o.stderr).contains(&format!("work/{name} (auto-detected)")),
            "{name}"
        );
        nothing_contacted(&f);
    }
}

// 15: two candidates of any names are an error that names both.
#[test]
fn several_inventories_are_never_a_choice() {
    for (a, b) in [
        ("work/hosts.yaml", "work/inventory.yaml"),
        ("work/inventory.yaml", "work/inventory.toml"),
        ("work/inventory.yml", "work/hosts.toml"),
        // The current directory and the recipe's directory.
        ("work/hosts.yaml", "work/sub/inventory.yml"),
    ] {
        let f = Fx::new();
        f.write("work/sub/r.yaml", WEB);
        f.inventory(a);
        f.inventory(b);
        let o = f.run(&["validate", "sub/r.yaml", "web01"]);
        let name = |p: &str| {
            Path::new(p)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };
        refused(
            &o,
            &[
                "several inventories",
                &name(a),
                &name(b),
                "--inventory",
                "sinter.yaml",
            ],
            &format!("{a} {b}"),
        );
        nothing_contacted(&f);
    }
    // A broken candidate is an error, never passed over for the other.
    let f = Fx::new();
    f.write("work/r.yaml", WEB);
    f.write("work/inventory.yaml", "all:\n  hosts: {}\n");
    refused(
        &f.run(&["validate", "r.yaml", "web01"]),
        &["inventory"],
        "broken",
    );
    let g = Fx::new();
    g.write("work/r.yaml", WEB);
    g.inventory("work/hosts.yaml");
    symlink(g.path("work/hosts.yaml"), g.path("work/inventory.yml")).unwrap();
    refused(
        &g.run(&["validate", "r.yaml", "web01"]),
        &["symbolic link"],
        "link",
    );
}

// 16, 17: --inventory, then the project file's inventory, win over detection.
#[test]
fn a_named_inventory_wins_over_detection() {
    let f = Fx::new();
    f.write("work/r.yaml", WEB);
    f.inventory("work/hosts.yaml");
    f.inventory("work/inventory.yaml");
    let named = f.inventory("work/named.yaml");
    let o = f.run(&[
        "validate",
        "r.yaml",
        "web01",
        "--inventory",
        "named.yaml",
        "--format",
        "json",
    ]);
    code(&o, 0, "--inventory");
    assert_eq!(json(&o)["inventory_source"], "explicit");
    f.write("work/sinter.yaml", "version: 1\ninventory: ./named.yaml\n");
    let o = f.run(&["validate", "r.yaml", "web01", "--format", "json"]);
    code(&o, 0, "project");
    assert_same_file(&json(&o)["inventory"], &named, "inventory");
    nothing_contacted(&f);
}

// 18: without a selector nothing is detected, whatever is there.
#[test]
fn without_a_selector_no_inventory_is_read() {
    let f = Fx::new();
    f.write("work/r.yaml", FREE);
    for name in [
        "hosts.yaml",
        "inventory.yaml",
        "inventory.yml",
        "inventory.toml",
    ] {
        f.write(&format!("work/{name}"), "not: [an, inventory\n");
    }
    let o = f.run(&["validate", "r.yaml", "--format", "json"]);
    code(&o, 0, "no selector");
    let d = json(&o);
    assert!(
        d.get("inventory").is_none() && d.get("resolved").is_none(),
        "{d}"
    );
    nothing_contacted(&f);
}

// A recipe found by name brings no place of its own to look for an inventory:
// a bundle directory's inventory is not the project's.
#[test]
fn a_recipe_found_by_name_looks_for_an_inventory_here_only() {
    let f = Fx::new();
    f.bundle("work/02_moge");
    f.write("work/02_moge/packages.yaml", WEB);
    f.write("work/02_moge/services.yaml", WEB);
    f.inventory("work/02_moge/inventory.yaml");
    refused(
        &f.run(&["validate", "02_moge", "web01"]),
        &["no inventory for the selector"],
        "inside",
    );
    let inv = f.inventory("work/hosts.yaml");
    let o = f.run(&["validate", "02_moge", "web01", "--format", "json"]);
    code(&o, 0, "here");
    assert_same_file(&json(&o)["inventory"], &inv, "inventory");
    nothing_contacted(&f);
}

// 19: a name decides which file is read, never which hosts run.
#[test]
fn a_recipe_found_by_name_runs_only_where_its_targets_allow() {
    let f = Fx::project();
    f.write("work/recipes/web/site.yaml", WEB);
    f.inventory("work/hosts.yaml");
    for phase in ["validate", "plan", "audit", "apply"] {
        refused(&f.run(&[phase, "site.yaml", "db01"]), &["db01"], phase);
    }
    let o = f.run(&["validate", "site.yaml", "@web", "--format", "json"]);
    code(&o, 0, "web");
    assert_eq!(json(&o)["selected_executions"], 1);
    // A name that finds nothing never falls back to the local host.
    for phase in ["plan", "audit", "apply"] {
        refused(&f.run(&[phase, "missing.yaml"]), &["was not found"], phase);
        refused(
            &f.run(&[phase, "missing_bundle", "web01"]),
            &["was not found"],
            phase,
        );
    }
    nothing_contacted(&f);
}

// 20: what existed is unchanged in JSON; stdout stays one document.
#[test]
fn json_output_keeps_its_keys() {
    let f = Fx::new();
    f.write("work/r.yaml", FREE);
    let o = f.run(&["validate", "r.yaml", "--format", "json"]);
    code(&o, 0, "plain");
    assert!(
        json(&o).get("resolved").is_none(),
        "nothing new without a project file"
    );
    assert!(text(&o.stderr).is_empty(), "{}", text(&o.stderr));
    let p = Fx::project();
    let o = p.run(&["validate", "02_moge", "--format", "json"]);
    let d = json(&o);
    let keys: Vec<&String> = d["resolved"]["recipe"]
        .as_object()
        .unwrap()
        .keys()
        .collect();
    assert_eq!(keys, ["match", "path", "query", "via"]);
    for k in [
        "config",
        "inventory",
        "default_target",
        "vars_files",
        "backup_directory",
    ] {
        assert!(d["resolved"].get(k).is_some(), "{k}");
    }
}
