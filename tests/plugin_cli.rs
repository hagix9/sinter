//! CLI surface of Resource Plugins (DESIGN §38.7): `--plugin-root`, the
//! default root, and fail-closed loading. No host is contacted: every case
//! is `validate`, or a plan whose recipe is refused before connecting.

use std::path::Path;
use std::process::{Command, Output};

const PLUGIN_RECIPE: &str = "version: 1\nplugins:\n  - { id: firewalld, version: 0.1.0 }\nresources:\n  - id: a\n    type: firewalld.service\n    with: { zone: public, service: http, state: present }\n";
const PLAIN_RECIPE: &str = "version: 1\nresources:\n  - id: f\n    type: file\n    with: { path: /tmp/sinter-plugin-cli-never-written, content: x }\n";

fn sinter(args: &[&str], home: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(args)
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn a_recipe_without_plugins_ignores_the_plugin_root() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLAIN_RECIPE).unwrap();
    let missing = d.path().join("no-such-root");
    let o = sinter(
        &[
            "validate",
            r.to_str().unwrap(),
            "--plugin-root",
            missing.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(!missing.exists());
}

#[test]
fn an_explicit_plugin_root_that_does_not_exist_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLUGIN_RECIPE).unwrap();
    let missing = d.path().join("no-such-root");
    let o = sinter(
        &[
            "validate",
            r.to_str().unwrap(),
            "--plugin-root",
            missing.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(
        text(&o).contains("cannot resolve the plugin root"),
        "{}",
        text(&o)
    );
}

#[test]
fn the_default_root_is_under_home_and_is_refused_when_absent() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLUGIN_RECIPE).unwrap();
    let o = sinter(&["validate", r.to_str().unwrap()], d.path());
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains(".config/sinter/plugins"), "{}", text(&o));
}

#[test]
fn a_plan_with_an_unusable_plugin_is_refused_before_connecting() {
    // The default target is localhost; nothing may run because the recipe
    // is refused while it is loaded (exit 2, no target contact).
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLUGIN_RECIPE).unwrap();
    let missing = d.path().join("no-such-root");
    let o = sinter(
        &[
            "plan",
            r.to_str().unwrap(),
            "--plugin-root",
            missing.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(!text(&o).contains("== Sinter PLAN =="), "{}", text(&o));
}

#[test]
fn a_valid_root_is_still_refused_because_no_catalog_is_released() {
    // A correctly protected, Owner-pinned plugin root (user-owned, 0700)
    // under a fresh directory: v1.9.0 lists no first-party catalog, so the
    // recipe is refused (exit 2) at the registry or, where the temporary
    // directory's ancestors are writable by others, at the ancestor check.
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("plugins");
    for sub in ["", "catalogs", "plugins"] {
        let p = root.join(sub);
        std::fs::create_dir_all(&p).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let catalog = "format = 1\nid = \"firewalld\"\nversion = \"0.1.0\"\n\n[[op]]\nid = \"state\"\nclass = \"observe\"\nprogram = \"/usr/bin/firewall-cmd\"\nargv = [\"--state\"]\ntimeout_secs = 30\nexit = { \"0\" = \"running\" }\n";
    std::fs::write(root.join("catalogs/firewalld-0.1.0.catalog.toml"), catalog).unwrap();
    let r = d.path().join("r.yml");
    std::fs::write(&r, PLUGIN_RECIPE).unwrap();
    let o = sinter(
        &[
            "validate",
            r.to_str().unwrap(),
            "--plugin-root",
            root.to_str().unwrap(),
        ],
        d.path(),
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("plugin:"), "{}", text(&o));
}
