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
fn a_root_without_the_attested_catalog_is_refused() {
    // A protected plugin root (user-owned, 0700) whose catalog is not the
    // attested first-party file and that has no trust file: the recipe is
    // refused (exit 2) before anything runs.
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

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{:02x}", x))
        .collect()
}

/// A plugin root holding the repository's first-party files and an Owner
/// trust file that pins them, all user-owned and not writable by others.
fn first_party_root(d: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins/first-party");
    let root = d.join("plugins");
    for sub in ["", "catalogs", "plugins"] {
        let p = root.join(sub);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for f in [
        "catalogs/firewalld-0.1.0.catalog.toml",
        "plugins/firewalld-0.1.0.plugin.toml",
    ] {
        std::fs::write(root.join(f), std::fs::read(repo.join(f)).unwrap()).unwrap();
        std::fs::set_permissions(root.join(f), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let trust = "format = 1\n\n[[catalog]]\nid = \"firewalld\"\nversion = \"0.1.0\"\nsha256 = \"27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff\"\nattested_observe = [\"state\", \"zone_defined\", \"service_defined\", \"query_service_runtime\", \"query_service_permanent\"]\nallowed_mutate = [\"add_service_runtime\", \"add_service_permanent\"]\n\n[[plugin]]\nid = \"firewalld\"\nversion = \"0.1.0\"\nsha256 = \"47f33f171d239103cbb97450d17b57c857ce22436620ddf809fdd2be94948544\"\n";
    std::fs::write(root.join("trust.toml"), trust).unwrap();
    std::fs::set_permissions(
        root.join("trust.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    root
}

/// Whether every ancestor of `p` is owned by root or by us and not writable
/// by group or other, unless sticky (DESIGN §38.5). Where the temporary
/// directory does not meet this, the production loader refuses any root
/// below it, and the positive case cannot be shown there.
fn ancestors_trusted(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let me = unsafe { libc::geteuid() };
    let p = std::fs::canonicalize(p).unwrap();
    p.ancestors().skip(1).all(|a| {
        let m = std::fs::metadata(a).unwrap();
        (m.uid() == 0 || m.uid() == me) && (m.mode() & 0o022 == 0 || m.mode() & 0o1000 != 0)
    })
}

#[test]
fn the_release_binary_accepts_the_attested_first_party_files() {
    // The release registry admits the repository's catalog: `validate` of a
    // plugin recipe succeeds and contacts no host.
    let d = tempfile::tempdir().unwrap();
    let root = first_party_root(d.path());
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
    assert!(
        !text(&o).contains("not a reviewed first-party catalog"),
        "{}",
        text(&o)
    );
    if ancestors_trusted(&root) {
        assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    } else {
        assert_eq!(o.status.code(), Some(2), "{}", text(&o));
        eprintln!(
            "temporary directory ancestors are not trusted here: {}",
            text(&o)
        );
    }
}

#[test]
fn the_release_binary_refuses_the_attested_files_with_one_byte_changed() {
    let d = tempfile::tempdir().unwrap();
    let root = first_party_root(d.path());
    let c = root.join("catalogs/firewalld-0.1.0.catalog.toml");
    let mut b = std::fs::read(&c).unwrap();
    b.extend_from_slice(b"# edited\n");
    std::fs::write(&c, &b).unwrap();
    // The Owner pins the edited bytes: the release registry still refuses.
    let t = root.join("trust.toml");
    let pinned = std::fs::read_to_string(&t).unwrap().replace(
        "27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff",
        &sha256_hex(&b),
    );
    std::fs::write(&t, pinned).unwrap();
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
    if ancestors_trusted(&root) {
        assert!(
            text(&o).contains("not a reviewed first-party catalog"),
            "{}",
            text(&o)
        );
    }
}
