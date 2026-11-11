//! PM-3 tests: `plugin install` and `plugin remove` (DESIGN §38.16). Every
//! root is built in a fresh temporary directory, which is the boundary of
//! the ancestor checks, with the production bundle and registry.

use super::bundle::{self, EmbeddedPlugin, FIRST_PARTY_BUNDLE};
use super::install::{self, ChangeReport, Fault, FileNow, InstallRequest, RootSpec};
use super::manage::{self, Source};
use super::protect::sha256_hex;
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

fn e(version: &str) -> &'static EmbeddedPlugin {
    bundle::embedded(FIRST_PARTY_BUNDLE, "firewalld", version).expect("embedded")
}

fn fw(version: &str) -> PluginRef {
    PluginRef {
        id: "firewalld".into(),
        version: version.into(),
    }
}

struct Fx {
    _tmp: tempfile::TempDir,
    boundary: PathBuf,
    root: PathBuf,
}

fn mode(p: &Path, m: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
}

fn mode_of(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().mode() & 0o7777
}

/// A boundary with no root yet: the root is `<boundary>/home/.config/sinter/plugins`.
fn fx() -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let boundary = tmp.path().to_path_buf();
    mode(&boundary, 0o700);
    std::fs::create_dir(boundary.join("home")).unwrap();
    mode(&boundary.join("home"), 0o700);
    let root = boundary.join("home/.config/sinter/plugins");
    Fx {
        _tmp: tmp,
        boundary,
        root,
    }
}

/// An existing empty root with its two directories.
fn fx_existing() -> Fx {
    let f = fx();
    for sub in ["", "catalogs", "plugins"] {
        std::fs::create_dir_all(f.root.join(sub)).unwrap();
    }
    for p in [
        f.boundary.join("home/.config"),
        f.boundary.join("home/.config/sinter"),
        f.root.clone(),
        f.root.join("catalogs"),
        f.root.join("plugins"),
    ] {
        mode(&p, 0o700);
    }
    f
}

fn req(version: &str, mutate: &[&str], for_types: &[&str]) -> InstallRequest {
    InstallRequest {
        target: Some(fw(version)),
        allow_mutate: mutate.iter().map(|s| s.to_string()).collect(),
        allow_mutate_for: for_types.iter().map(|s| s.to_string()).collect(),
    }
}

impl Fx {
    fn spec(&self) -> RootSpec {
        RootSpec {
            path: self.root.clone(),
            boundary: Some(self.boundary.clone()),
        }
    }
    fn plan(&self, r: &InstallRequest) -> Result<install::InstallPlan> {
        install::plan_install_with(&self.spec(), r, FIRST_PARTY_BUNDLE, FIRST_PARTY_CATALOGS)
    }
    fn install_at(&self, r: &InstallRequest, at: Option<Fault>) -> ChangeReport {
        let plan = self.plan(r).expect("plan");
        install::execute_install_with(
            &self.spec(),
            r,
            &plan,
            FIRST_PARTY_BUNDLE,
            FIRST_PARTY_CATALOGS,
            at,
        )
    }
    fn install(&self, r: &InstallRequest) -> ChangeReport {
        self.install_at(r, None)
    }
    fn plan_remove(&self, v: &str) -> Result<install::RemovePlan> {
        install::plan_remove_with(
            &self.spec(),
            &fw(v),
            FIRST_PARTY_BUNDLE,
            FIRST_PARTY_CATALOGS,
        )
    }
    fn remove_at(&self, v: &str, at: Option<Fault>) -> ChangeReport {
        let plan = self.plan_remove(v).expect("plan");
        install::execute_remove_with(
            &self.spec(),
            &plan,
            FIRST_PARTY_BUNDLE,
            FIRST_PARTY_CATALOGS,
            at,
        )
    }
    fn remove(&self, v: &str) -> ChangeReport {
        self.remove_at(v, None)
    }
    fn trust(&self) -> Vec<u8> {
        std::fs::read(self.root.join("trust.toml")).unwrap()
    }
    fn write_trust(&self, body: &str) {
        let t = self.root.join("trust.toml");
        std::fs::write(&t, body).unwrap();
        mode(&t, 0o600);
    }
    fn plugin_path(&self, v: &str) -> PathBuf {
        self.root
            .join(format!("plugins/firewalld-{}.plugin.toml", v))
    }
    fn catalog_path(&self, v: &str) -> PathBuf {
        self.root
            .join(format!("catalogs/firewalld-{}.catalog.toml", v))
    }
    fn source_open(&self) -> impl Fn(&Path) -> Result<PluginRoot> {
        let b = self.boundary.clone();
        move |p: &Path| PluginRoot::open_below(p, &b)
    }
    fn verify(&self, v: &str) -> manage::VerifyReport {
        let open = self.source_open();
        manage::verify_with(
            &Source::Root {
                path: self.root.clone(),
                open: &open,
            },
            &[fw(v)],
            FIRST_PARTY_BUNDLE,
            FIRST_PARTY_CATALOGS,
        )
    }
    fn list(&self) -> manage::ListReport {
        let open = self.source_open();
        manage::list_with(
            &Source::Root {
                path: self.root.clone(),
                open: &open,
            },
            FIRST_PARTY_BUNDLE,
            FIRST_PARTY_CATALOGS,
        )
    }
    fn status(&self, v: &str) -> &'static str {
        let l = self.list();
        l.plugins
            .iter()
            .find(|p| p.version == v)
            .map(|p| p.status)
            .unwrap()
    }
    /// Every path below the boundary, for "nothing changed" checks.
    fn tree(&self) -> Vec<(String, u32, Option<Vec<u8>>)> {
        fn walk(p: &Path, base: &Path, out: &mut Vec<(String, u32, Option<Vec<u8>>)>) {
            let md = std::fs::symlink_metadata(p).unwrap();
            let rel = p.strip_prefix(base).unwrap().display().to_string();
            if md.file_type().is_dir() {
                out.push((rel, md.mode() & 0o7777, None));
                let mut names: Vec<_> = std::fs::read_dir(p)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .collect();
                names.sort();
                for n in names {
                    walk(&n, base, out);
                }
            } else if md.file_type().is_file() {
                out.push((rel, md.mode() & 0o7777, Some(std::fs::read(p).unwrap())));
            } else {
                out.push((rel, md.mode() & 0o7777, None));
            }
        }
        let mut out = Vec::new();
        walk(&self.boundary, &self.boundary, &mut out);
        out
    }
}

fn not_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() != 0 }
}

// ---------------------------------------------------------------------------
// 1, 16. install, then list and verify
// ---------------------------------------------------------------------------

#[test]
fn install_creates_the_root_writes_the_files_and_trusts_only_what_was_shown() {
    let f = fx();
    let r = f.install(&req("0.2.0", &[], &[]));
    assert_eq!(
        (r.result, r.exit_code()),
        ("installed", 0),
        "{:?}",
        r.messages
    );
    assert_eq!(r.verify, Some("ok"));
    assert_eq!(r.trust, "created");
    // Directories from the deepest existing ancestor (home), all 0700.
    assert_eq!(
        r.directories_created.len(),
        5,
        "{:?}",
        r.directories_created
    );
    for d in [
        f.boundary.join("home/.config"),
        f.boundary.join("home/.config/sinter"),
        f.root.clone(),
        f.root.join("catalogs"),
        f.root.join("plugins"),
    ] {
        assert_eq!(mode_of(&d), 0o700, "{}", d.display());
    }
    assert_eq!(
        mode_of(&f.boundary.join("home")),
        0o700,
        "existing ancestor untouched"
    );
    // Files: exactly the embedded bytes, 0600.
    assert_eq!(
        std::fs::read(f.plugin_path("0.2.0")).unwrap(),
        e("0.2.0").plugin
    );
    assert_eq!(
        std::fs::read(f.catalog_path("0.2.0")).unwrap(),
        e("0.2.0").catalog
    );
    for p in [
        f.plugin_path("0.2.0"),
        f.catalog_path("0.2.0"),
        f.root.join("trust.toml"),
    ] {
        assert_eq!(mode_of(&p), 0o600, "{}", p.display());
    }
    // Trust: every observe operation attested, no mutate allowed.
    let t = String::from_utf8(f.trust()).unwrap();
    assert!(t.contains("allowed_mutate = []"), "{}", t);
    assert!(t.contains(e("0.2.0").catalog_sha256) && t.contains(e("0.2.0").plugin_sha256));
    assert_eq!(r.attested_observe.len(), 9);
    assert!(r.allowed_mutate.is_empty());
    assert_eq!(r.mutate_not_allowed.len(), 12);
    // list and verify agree.
    assert_eq!(f.status("0.2.0"), "installed");
    assert_eq!(f.status("0.1.0"), "available");
    let v = f.verify("0.2.0");
    assert_eq!((v.plugins[0].status, v.exit_code()), ("ok", 0));
    // No temporary file is left behind.
    let names: Vec<String> = std::fs::read_dir(&f.root)
        .unwrap()
        .chain(std::fs::read_dir(f.root.join("plugins")).unwrap())
        .chain(std::fs::read_dir(f.root.join("catalogs")).unwrap())
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(!names.iter().any(|n| n.contains(".tmp-")), "{:?}", names);
}

// ---------------------------------------------------------------------------
// 3. dry run
// ---------------------------------------------------------------------------

#[test]
fn planning_changes_nothing() {
    let f = fx();
    let before = f.tree();
    let p = f
        .plan(&req("0.2.0", &["add_service_runtime"], &[]))
        .unwrap();
    assert!(!p.nothing_to_do);
    assert_eq!(p.dirs_to_create.len(), 5);
    assert_eq!(p.allowed_mutate, ["add_service_runtime"]);
    assert_eq!(install::plan_report("install", &p, true).exit_code(), 0);
    assert_eq!(f.tree(), before);
    // The same for an existing root and for remove.
    let f = fx_existing();
    f.install(&req("0.2.0", &[], &[]));
    let before = f.tree();
    f.plan(&req("0.1.0", &[], &[])).unwrap();
    f.plan_remove("0.2.0").unwrap();
    assert_eq!(f.tree(), before);
}

// ---------------------------------------------------------------------------
// 4. installing again
// ---------------------------------------------------------------------------

#[test]
fn installing_again_is_nothing_to_do_and_never_changes_an_entry() {
    let f = fx();
    f.install(&req("0.2.0", &[], &["firewalld.service"]));
    let trust = f.trust();
    let again = f.install(&req("0.2.0", &[], &["firewalld.service"]));
    assert_eq!((again.result, again.exit_code()), ("nothing-to-do", 0));
    assert_eq!(f.trust(), trust);
    // Other permissions: refused, nothing changed (never widened or narrowed).
    let before = f.tree();
    for r in [
        req("0.2.0", &[], &[]),
        req("0.2.0", &[], &["firewalld.service", "firewalld.port"]),
    ] {
        let Err(err) = f.plan(&r) else {
            panic!("a different permission set must be refused");
        };
        assert!(
            err.message.contains("never changes an existing entry"),
            "{}",
            err.message
        );
    }
    assert_eq!(f.tree(), before);
}

// ---------------------------------------------------------------------------
// 5. coexistence, and appending keeps the Owner's bytes
// ---------------------------------------------------------------------------

#[test]
fn two_versions_coexist_and_the_existing_trust_bytes_are_kept() {
    let f = fx();
    f.install(&req(
        "0.1.0",
        &["add_service_runtime", "add_service_permanent"],
        &[],
    ));
    // The Owner adds a comment and blank lines by hand.
    let mut t = f.trust();
    t.extend_from_slice(b"\n# reviewed by the owner\n");
    f.write_trust(std::str::from_utf8(&t).unwrap());
    let r = f.install(&req("0.2.0", &[], &[]));
    assert_eq!(
        (r.result, r.trust),
        ("installed", "appended"),
        "{:?}",
        r.messages
    );
    let after = f.trust();
    assert!(after.starts_with(&t), "existing bytes changed");
    assert_eq!(f.status("0.1.0"), "installed");
    assert_eq!(f.status("0.2.0"), "installed");
    assert_eq!(f.verify("0.1.0").exit_code(), 0);
    assert_eq!(f.verify("0.2.0").exit_code(), 0);
}

// ---------------------------------------------------------------------------
// 2, 17. remove, then list and verify
// ---------------------------------------------------------------------------

#[test]
fn remove_takes_out_exactly_one_plugin_and_keeps_the_previous_trust() {
    let f = fx();
    f.install(&req(
        "0.1.0",
        &["add_service_runtime", "add_service_permanent"],
        &[],
    ));
    f.install(&req("0.2.0", &[], &[]));
    let before = f.trust();
    let r = f.remove("0.2.0");
    assert_eq!(
        (r.result, r.exit_code()),
        ("removed", 0),
        "{:?}",
        r.messages
    );
    assert_eq!(r.verify, Some("not-installed"));
    assert_eq!(r.trust, "rewritten");
    assert!(!f.plugin_path("0.2.0").exists() && !f.catalog_path("0.2.0").exists());
    assert!(f.plugin_path("0.1.0").exists() && f.catalog_path("0.1.0").exists());
    assert_eq!(
        std::fs::read(f.root.join("trust.toml.prev")).unwrap(),
        before
    );
    assert_eq!(mode_of(&f.root.join("trust.toml.prev")), 0o600);
    let t = String::from_utf8(f.trust()).unwrap();
    assert!(!t.contains(e("0.2.0").plugin_sha256) && !t.contains(e("0.2.0").catalog_sha256));
    assert!(t.contains(e("0.1.0").plugin_sha256) && t.contains("add_service_permanent"));
    assert_eq!(f.status("0.2.0"), "available");
    assert_eq!(f.status("0.1.0"), "installed");
    assert_eq!(f.verify("0.2.0").plugins[0].status, "not-installed");
    assert_eq!(f.verify("0.1.0").exit_code(), 0);
    // Removing again: nothing to do.
    let again = f.remove("0.2.0");
    assert_eq!((again.result, again.exit_code()), ("nothing-to-do", 0));
    // No root at all: nothing to do.
    let g = fx();
    assert!(g.plan_remove("0.2.0").unwrap().nothing_to_do);
}

#[test]
fn remove_says_when_the_rewrite_drops_comments() {
    let f = fx();
    f.install(&req("0.2.0", &[], &[]));
    assert!(!f.plan_remove("0.2.0").unwrap().formatting_lost);
    let mut t = f.trust();
    t.extend_from_slice(b"# a note\n");
    f.write_trust(std::str::from_utf8(&t).unwrap());
    assert!(f.plan_remove("0.2.0").unwrap().formatting_lost);
}

// ---------------------------------------------------------------------------
// 6. a shared catalog is kept
// ---------------------------------------------------------------------------

/// A second plugin on the firewalld 0.1.0 catalog, installed and pinned by
/// hand (the loader accepts it; it is not a first-party plugin).
const PLUGIN_RT: &str = "format = 1\nid = \"fwruntime\"\nversion = \"0.1.0\"\ncatalog = { id = \"firewalld\", version = \"0.1.0\" }\n\n[[type]]\nname = \"fwruntime.service\"\nfields = { zone = { kind = \"ident\" }, service = { kind = \"ident\" } }\nprecheck = [{ op = \"state\", expect = \"running\" }]\n\n[[type.facet]]\nname = \"runtime\"\nobserve = \"query_service_runtime\"\nwant = \"present\"\nensure = { present = \"add_service_runtime\" }\n";

#[test]
fn remove_keeps_a_catalog_another_plugin_uses_or_may_use() {
    let f = fx();
    f.install(&req(
        "0.1.0",
        &["add_service_runtime", "add_service_permanent"],
        &[],
    ));
    let rt = f.root.join("plugins/fwruntime-0.1.0.plugin.toml");
    std::fs::write(&rt, PLUGIN_RT).unwrap();
    mode(&rt, 0o600);
    let mut t = String::from_utf8(f.trust()).unwrap();
    t.push_str(&format!(
        "\n[[plugin]]\nid = \"fwruntime\"\nversion = \"0.1.0\"\nsha256 = \"{}\"\n",
        sha256_hex(PLUGIN_RT.as_bytes())
    ));
    f.write_trust(&t);
    let p = f.plan_remove("0.1.0").unwrap();
    assert_eq!(p.catalog_kept, Some("used-by-another-plugin"));
    assert!(!p.remove_catalog_entry && !p.delete_catalog_file && p.delete_plugin_file);
    let r = f.remove("0.1.0");
    assert_eq!(r.result, "removed", "{:?}", r.messages);
    assert!(!f.plugin_path("0.1.0").exists());
    assert!(f.catalog_path("0.1.0").exists() && rt.exists());
    let t = String::from_utf8(f.trust()).unwrap();
    assert!(t.contains(e("0.1.0").catalog_sha256), "catalog entry kept");
    assert!(t.contains("fwruntime"), "the other plugin's entry kept");
    assert!(!t.contains(e("0.1.0").plugin_sha256));

    // When the other plugin's file cannot be read, the catalog stays too.
    let g = fx();
    g.install(&req(
        "0.1.0",
        &["add_service_runtime", "add_service_permanent"],
        &[],
    ));
    let mut t = String::from_utf8(g.trust()).unwrap();
    t.push_str("\n[[plugin]]\nid = \"fwruntime\"\nversion = \"0.1.0\"\nsha256 = \"1111111111111111111111111111111111111111111111111111111111111111\"\n");
    g.write_trust(&t);
    let p = g.plan_remove("0.1.0").unwrap();
    assert_eq!(p.catalog_kept, Some("use-unknown"));
    assert!(!p.delete_catalog_file);
}

// ---------------------------------------------------------------------------
// 7. digests
// ---------------------------------------------------------------------------

#[test]
fn files_with_other_bytes_are_never_replaced_or_removed() {
    // install: a plugin file that is not the first-party file.
    let f = fx_existing();
    std::fs::write(f.plugin_path("0.2.0"), b"format = 1\n# not it\n").unwrap();
    mode(&f.plugin_path("0.2.0"), 0o600);
    let before = f.tree();
    let Err(err) = f.plan(&req("0.2.0", &[], &[])) else {
        panic!("expected a refusal");
    };
    assert!(err.message.contains("never replaced"), "{}", err.message);
    assert_eq!(f.tree(), before);

    // remove: the installed file was changed afterwards.
    let g = fx();
    g.install(&req("0.2.0", &[], &[]));
    std::fs::write(g.catalog_path("0.2.0"), b"changed").unwrap();
    let before = g.tree();
    let Err(err) = g.plan_remove("0.2.0") else {
        panic!("expected a refusal");
    };
    assert!(
        err.message.contains("never replaced or removed"),
        "{}",
        err.message
    );
    assert_eq!(g.tree(), before);

    // remove: the trust file pins another digest.
    let h = fx();
    h.install(&req("0.2.0", &[], &[]));
    let t = String::from_utf8(h.trust())
        .unwrap()
        .replace(e("0.2.0").plugin_sha256, &"2".repeat(64));
    h.write_trust(&t);
    let Err(err) = h.plan_remove("0.2.0") else {
        panic!("expected a refusal");
    };
    assert!(err.message.contains("another digest"), "{}", err.message);
}

// ---------------------------------------------------------------------------
// 8. symbolic links and names
// ---------------------------------------------------------------------------

#[test]
fn symbolic_links_are_refused_and_their_targets_untouched() {
    let elsewhere = |f: &Fx| -> PathBuf {
        let d = f.boundary.join("elsewhere");
        std::fs::create_dir_all(&d).unwrap();
        mode(&d, 0o700);
        d
    };
    // plugins/ is a link
    let f = fx_existing();
    let d = elsewhere(&f);
    std::fs::remove_dir(f.root.join("plugins")).unwrap();
    std::os::unix::fs::symlink(&d, f.root.join("plugins")).unwrap();
    assert!(f.plan(&req("0.2.0", &[], &[])).is_err());
    assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);

    // the plugin file is a link
    let f = fx_existing();
    let d = elsewhere(&f);
    let target = d.join("victim");
    std::fs::write(&target, b"keep").unwrap();
    std::os::unix::fs::symlink(&target, f.plugin_path("0.2.0")).unwrap();
    assert!(f.plan(&req("0.2.0", &[], &[])).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");

    // trust.toml is a link
    let f = fx_existing();
    let d = elsewhere(&f);
    let target = d.join("trust");
    std::fs::write(&target, b"format = 1\n").unwrap();
    std::os::unix::fs::symlink(&target, f.root.join("trust.toml")).unwrap();
    assert!(f.plan(&req("0.2.0", &[], &[])).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"format = 1\n");

    // the lock file is a link: refused at execution, nothing left behind
    let f = fx_existing();
    let d = elsewhere(&f);
    let target = d.join("lock");
    std::fs::write(&target, b"").unwrap();
    std::os::unix::fs::symlink(&target, f.root.join(".lock")).unwrap();
    let before = f.tree();
    let r = f.install(&req("0.2.0", &[], &[]));
    assert_eq!(
        (r.result, r.exit_code()),
        ("refused", 2),
        "{:?}",
        r.messages
    );
    assert_eq!(f.tree(), before);

    // the root is a dangling link
    let f = fx();
    std::fs::create_dir_all(f.root.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(f.boundary.join("nowhere"), &f.root).unwrap();
    assert!(f.plan(&req("0.2.0", &[], &[])).is_err());
    assert!(!f.boundary.join("nowhere").exists());
}

#[test]
fn only_embedded_first_party_plugins_and_well_formed_names_are_accepted() {
    let f = fx();
    for bad in [
        "../x@1.0.0",
        "firewalld@0.2",
        "firewalld",
        "Firewalld@0.2.0",
        "a/b@1.0.0",
    ] {
        assert!(manage::parse_target(bad).is_err(), "{}", bad);
    }
    let Err(err) = f.plan(&req("9.9.9", &[], &[])) else {
        panic!("not embedded");
    };
    assert!(
        err.message
            .contains("not a first-party plugin of this Sinter"),
        "{}",
        err.message
    );
    assert!(f.plan_remove("9.9.9").is_err());
    assert!(!f.boundary.join("home/.config").exists());
}

// ---------------------------------------------------------------------------
// 9. permissions
// ---------------------------------------------------------------------------

#[test]
fn an_unwritable_root_is_refused_and_left_as_it_was() {
    if !not_root() {
        return;
    }
    let f = fx_existing();
    mode(&f.root.join("plugins"), 0o500);
    let before = f.tree();
    let r = f.install(&req("0.2.0", &[], &[]));
    mode(&f.root.join("plugins"), 0o700);
    assert_eq!(
        (r.result, r.exit_code()),
        ("refused", 2),
        "{:?}",
        r.messages
    );
    let mut after = f.tree();
    // The lock file is the only trace (the root existed before).
    after.retain(|(p, _, _)| !p.ends_with(".lock"));
    let mut b = before;
    for x in b.iter_mut().chain(after.iter_mut()) {
        if x.0.ends_with("plugins") {
            x.1 = 0;
        }
    }
    assert_eq!(after, b);
}

#[test]
fn an_unsafe_root_or_ancestor_is_refused() {
    // A group-writable root: refused, unchanged.
    let f = fx_existing();
    mode(&f.root, 0o770);
    let before = f.tree();
    assert!(f.plan(&req("0.2.0", &[], &[])).is_err());
    assert_eq!(f.tree(), before);
    mode(&f.root, 0o700);
    // A group-writable existing ancestor of a root still to create: refused
    // before anything is created.
    let g = fx();
    mode(&g.boundary.join("home"), 0o775);
    let before = g.tree();
    let Err(err) = g.plan(&req("0.2.0", &[], &[])) else {
        panic!("expected a refusal");
    };
    assert!(
        err.message.contains("writable by group or others"),
        "{}",
        err.message
    );
    assert_eq!(g.tree(), before);
}

// ---------------------------------------------------------------------------
// 10. the trust file's limit
// ---------------------------------------------------------------------------

#[test]
fn the_sixty_four_entry_limit_is_kept() {
    let f = fx_existing();
    let mut t = "format = 1\n".to_string();
    for i in 0..64 {
        t.push_str(&format!(
            "\n[[catalog]]\nid = \"c{}\"\nversion = \"1.0.0\"\nsha256 = \"{}\"\n",
            i,
            "a".repeat(64)
        ));
    }
    f.write_trust(&t);
    let before = f.tree();
    let Err(err) = f.plan(&req("0.2.0", &[], &[])) else {
        panic!("over the limit");
    };
    assert!(err.message.contains("more than 64"), "{}", err.message);
    assert_eq!(f.tree(), before);
}

// ---------------------------------------------------------------------------
// 11. concurrency
// ---------------------------------------------------------------------------

#[test]
fn a_second_writer_is_refused_without_waiting() {
    let f = fx();
    f.install(&req(
        "0.1.0",
        &["add_service_runtime", "add_service_permanent"],
        &[],
    ));
    let held =
        protect::TrustedDir::open_root(&f.root, &protect::Ancestors::Below(f.boundary.clone()))
            .unwrap();
    let _lock = held.lock(".lock").unwrap();
    let before = f.tree();
    let r = f.install(&req("0.2.0", &[], &[]));
    assert_eq!((r.result, r.exit_code()), ("refused", 2));
    assert!(
        r.messages
            .iter()
            .any(|m| m.0.contains("another plugin install or remove")),
        "{:?}",
        r.messages
    );
    let r = f.remove("0.1.0");
    assert_eq!((r.result, r.exit_code()), ("refused", 2));
    assert_eq!(f.tree(), before);
}

#[test]
fn a_change_between_plan_and_execution_is_refused() {
    let f = fx();
    f.install(&req(
        "0.1.0",
        &["add_service_runtime", "add_service_permanent"],
        &[],
    ));
    let r = req("0.2.0", &[], &[]);
    let plan = f.plan(&r).unwrap();
    // The Owner edits the trust file after the plan was shown.
    let mut t = f.trust();
    t.extend_from_slice(b"# edited\n");
    f.write_trust(std::str::from_utf8(&t).unwrap());
    let before = f.tree();
    let rep = install::execute_install_with(
        &f.spec(),
        &r,
        &plan,
        FIRST_PARTY_BUNDLE,
        FIRST_PARTY_CATALOGS,
        None,
    );
    assert_eq!(
        (rep.result, rep.exit_code()),
        ("refused", 2),
        "{:?}",
        rep.messages
    );
    assert_eq!(f.tree(), before);
}

// ---------------------------------------------------------------------------
// 12. interruption and recovery
// ---------------------------------------------------------------------------

#[test]
fn an_install_interrupted_before_the_trust_file_is_undone_completely() {
    for at in [
        Fault::AfterCatalogFile,
        Fault::AfterPluginFile,
        Fault::BeforeTrust,
    ] {
        // A new root: everything this run created goes again.
        let f = fx();
        let before = f.tree();
        let r = f.install_at(&req("0.2.0", &[], &[]), Some(at));
        assert_eq!(
            (r.result, r.exit_code()),
            ("refused", 2),
            "{:?}: {:?}",
            at,
            r.messages
        );
        assert_eq!(f.tree(), before, "{:?}", at);
        // Running it again completes.
        let r = f.install(&req("0.2.0", &[], &[]));
        assert_eq!(r.result, "installed", "{:?}", at);

        // An existing root with another plugin: only this run's files go.
        let g = fx();
        g.install(&req(
            "0.1.0",
            &["add_service_runtime", "add_service_permanent"],
            &[],
        ));
        let before = g.tree();
        let r = g.install_at(&req("0.2.0", &[], &[]), Some(at));
        assert_eq!(r.exit_code(), 2, "{:?}", at);
        assert_eq!(g.tree(), before, "{:?}", at);
        assert_eq!(g.verify("0.1.0").exit_code(), 0);
    }
}

#[test]
fn an_install_interrupted_after_the_trust_file_is_partial_and_recoverable() {
    let f = fx();
    let r = f.install_at(&req("0.2.0", &[], &[]), Some(Fault::AfterTrust));
    assert_eq!(
        (r.result, r.exit_code()),
        ("partial", 5),
        "{:?}",
        r.messages
    );
    // Everything is in place; installing again finishes with nothing to do.
    let again = f.install(&req("0.2.0", &[], &[]));
    assert_eq!(again.result, "nothing-to-do");
    assert_eq!(f.verify("0.2.0").exit_code(), 0);
}

#[test]
fn a_remove_interrupted_at_each_step_never_damages_another_plugin() {
    // Before the trust file changes: refused, trust unchanged.
    let f = fx();
    f.install(&req(
        "0.1.0",
        &["add_service_runtime", "add_service_permanent"],
        &[],
    ));
    f.install(&req("0.2.0", &[], &[]));
    let trust = f.trust();
    let r = f.remove_at("0.2.0", Some(Fault::AfterPrev));
    assert_eq!(
        (r.result, r.exit_code()),
        ("refused", 2),
        "{:?}",
        r.messages
    );
    assert_eq!(f.trust(), trust);
    assert_eq!(f.status("0.2.0"), "installed");

    // After the trust file changed: partial, the plugin is no longer used.
    for at in [Fault::AfterTrust, Fault::AfterPluginRemoved] {
        let f = fx();
        f.install(&req(
            "0.1.0",
            &["add_service_runtime", "add_service_permanent"],
            &[],
        ));
        f.install(&req("0.2.0", &[], &[]));
        let r = f.remove_at("0.2.0", Some(at));
        assert_eq!((r.result, r.exit_code()), ("partial", 5), "{:?}", at);
        assert_ne!(f.status("0.2.0"), "installed");
        assert_eq!(f.verify("0.1.0").exit_code(), 0, "{:?}", at);
        // Recovery: install again (the files left are the same bytes), then
        // remove.
        assert_eq!(
            f.install(&req("0.2.0", &[], &[])).result,
            "installed",
            "{:?}",
            at
        );
        assert_eq!(f.remove("0.2.0").result, "removed", "{:?}", at);
        assert_eq!(f.status("0.1.0"), "installed");
    }
}

// ---------------------------------------------------------------------------
// 15. --yes and mutate permission are separate (the CLI's --yes only
//     confirms; permissions come only from the request)
// ---------------------------------------------------------------------------

#[test]
fn mutate_permission_comes_only_from_named_operations_or_types() {
    let f = fx();
    let p = f.plan(&req("0.2.0", &[], &[])).unwrap();
    assert!(p.allowed_mutate.is_empty());
    let p = f
        .plan(&req(
            "0.2.0",
            &["add_port_runtime", "add_port_permanent"],
            &[],
        ))
        .unwrap();
    assert_eq!(p.allowed_mutate, ["add_port_runtime", "add_port_permanent"]);
    let p = f.plan(&req("0.2.0", &[], &["firewalld.service"])).unwrap();
    assert_eq!(
        p.allowed_mutate,
        [
            "add_service_runtime",
            "add_service_permanent",
            "remove_service_runtime",
            "remove_service_permanent"
        ]
    );
    assert_eq!(p.expanded.len(), 1);
    for (m, t, why) in [
        (vec!["query_port_runtime"], vec![], "an observe operation"),
        (vec!["rm_everything"], vec![], "not an operation"),
        (vec![], vec!["firewalld.zone"], "not a type"),
    ] {
        let Err(err) = f.plan(&req("0.2.0", &m, &t)) else {
            panic!("{}", why);
        };
        assert!(err.message.contains(why), "{}", err.message);
    }
}

// ---------------------------------------------------------------------------
// 18. C1: an installed observe-only plugin
// ---------------------------------------------------------------------------

#[test]
fn an_observe_only_install_loads_for_audit_and_plan_apply_refuse() {
    let f = fx();
    f.install(&req("0.2.0", &[], &[]));
    let ctx = PluginContext::Test {
        root: f.root.clone(),
        boundary: f.boundary.clone(),
        registry: FIRST_PARTY_CATALOGS.to_vec(),
    };
    let recipe = f.boundary.join("r.yml");
    std::fs::write(
        &recipe,
        "version: 1\nplugins:\n  - { id: firewalld, version: 0.2.0 }\nresources:\n  - id: svc\n    type: firewalld.service\n    with: { zone: public, service: http, state: present }\n",
    )
    .unwrap();
    let m = crate::model::load_model_with_plugins(&recipe, &ctx).expect("loads");
    assert!(
        require_allowed_mutations(&m).is_err(),
        "plan and apply refuse"
    );
    // With the service type allowed, the same recipe passes the gate.
    let g = fx();
    g.install(&req("0.2.0", &[], &["firewalld.service"]));
    let ctx = PluginContext::Test {
        root: g.root.clone(),
        boundary: g.boundary.clone(),
        registry: FIRST_PARTY_CATALOGS.to_vec(),
    };
    let recipe = g.boundary.join("r.yml");
    std::fs::write(
        &recipe,
        "version: 1\nplugins:\n  - { id: firewalld, version: 0.2.0 }\nresources:\n  - id: svc\n    type: firewalld.service\n    with: { zone: public, service: http, state: present }\n",
    )
    .unwrap();
    let m = crate::model::load_model_with_plugins(&recipe, &ctx).unwrap();
    assert!(require_allowed_mutations(&m).is_ok());
}

// ---------------------------------------------------------------------------
// 19. JSON and exit codes
// ---------------------------------------------------------------------------

#[test]
fn reports_serialize_states_and_map_exit_codes() {
    let f = fx();
    let r = f.install(&req("0.2.0", &[], &[]));
    let j = serde_json::to_value(&r).unwrap();
    assert_eq!(j["format"], 1);
    assert_eq!(j["command"], "install");
    assert_eq!(j["result"], "installed");
    assert_eq!(j["trust"], "created");
    assert_eq!(j["verify"], "ok");
    assert!(j.get("messages").is_none());
    for (result, code) in [
        ("planned", 0),
        ("installed", 0),
        ("removed", 0),
        ("nothing-to-do", 0),
        ("refused", 2),
        ("partial", 5),
    ] {
        let mut x =
            install::plan_report("install", &f.plan(&req("0.2.0", &[], &[])).unwrap(), false);
        x.result = result;
        assert_eq!(x.exit_code(), code, "{}", result);
    }
}

#[test]
fn file_states_are_reported_for_existing_identical_files() {
    let f = fx_existing();
    std::fs::write(f.plugin_path("0.2.0"), e("0.2.0").plugin).unwrap();
    mode(&f.plugin_path("0.2.0"), 0o644);
    let p = f.plan(&req("0.2.0", &[], &[])).unwrap();
    assert_eq!(p.plugin_file, FileNow::Same);
    assert_eq!(p.catalog_file, FileNow::Absent);
    let r = f.install(&req("0.2.0", &[], &[]));
    assert_eq!(r.result, "installed");
    assert_eq!(r.files_written, ["catalogs/firewalld-0.2.0.catalog.toml"]);
    assert_eq!(
        mode_of(&f.plugin_path("0.2.0")),
        0o644,
        "an existing file is not changed"
    );
}

// ---------------------------------------------------------------------------
// 13. modes whatever the umask (default ACLs: Linux, see the CLI test)
// ---------------------------------------------------------------------------

#[test]
fn created_directories_and_files_have_exact_private_modes() {
    // The process umask is shared by the test threads, so it is not changed
    // here; the CLI test runs the binary under umask 000. This checks that
    // the modes are set explicitly on the new descriptors.
    let f = fx();
    f.install(&req("0.2.0", &[], &[]));
    for d in [
        f.root.clone(),
        f.root.join("catalogs"),
        f.root.join("plugins"),
    ] {
        assert_eq!(mode_of(&d), 0o700);
    }
    for p in [
        f.plugin_path("0.2.0"),
        f.catalog_path("0.2.0"),
        f.root.join("trust.toml"),
        f.root.join(".lock"),
    ] {
        assert_eq!(mode_of(&p), 0o600, "{}", p.display());
    }
}

// ---------------------------------------------------------------------------
// R1: a change that took place, followed by a failed fsync (or a later
// check). The failures are injected at the exact point inside the protected
// writer (`protect::hooks`, test builds only), after the link, rename,
// removal or directory creation and before the directory's fsync.
// ---------------------------------------------------------------------------

/// Run `f` with the given injection points armed on this thread.
fn failing<T>(points: &[&str], f: impl FnOnce() -> T) -> T {
    protect::hooks::fail_at(points);
    let out = f();
    protect::hooks::clear();
    out
}

const CAT2: &str = "firewalld-0.2.0.catalog.toml";
const PLG2: &str = "firewalld-0.2.0.plugin.toml";

#[test]
fn r1_a_b_a_file_linked_before_a_failed_fsync_is_undone_or_reported() {
    for name in [CAT2, PLG2] {
        let link = format!("sync-after-link:{}", name);
        // Undo succeeds: exit 2 and the tree is as before (new root).
        let f = fx();
        let before = f.tree();
        let r = failing(&[&link], || f.install(&req("0.2.0", &[], &[])));
        assert_eq!(
            (r.result, r.exit_code()),
            ("refused", 2),
            "{}: {:?}",
            name,
            r.messages
        );
        assert_eq!(f.tree(), before, "{}", name);

        // Undo succeeds next to another plugin: its files stay.
        let g = fx();
        g.install(&req(
            "0.1.0",
            &["add_service_runtime", "add_service_permanent"],
            &[],
        ));
        let before = g.tree();
        let r = failing(&[&link], || g.install(&req("0.2.0", &[], &[])));
        assert_eq!(r.exit_code(), 2, "{}: {:?}", name, r.messages);
        assert_eq!(g.tree(), before, "{}", name);
        assert_eq!(g.verify("0.1.0").exit_code(), 0);

        // Undo fails: exit 5, the linked file is reported and left, the
        // trust file is not written.
        let h = fx();
        let remove = format!("remove:{}", name);
        let r = failing(&[&link, &remove], || h.install(&req("0.2.0", &[], &[])));
        assert_eq!(
            (r.result, r.exit_code()),
            ("partial", 5),
            "{}: {:?}",
            name,
            r.messages
        );
        let sub = if name == CAT2 { "catalogs" } else { "plugins" };
        assert!(
            r.files_written.contains(&format!("{}/{}", sub, name)),
            "{:?}",
            r.files_written
        );
        assert!(h.root.join(sub).join(name).exists());
        assert!(!h.root.join("trust.toml").exists());
        assert!(
            r.messages.iter().any(|m| m.0.contains("could not undo")),
            "{:?}",
            r.messages
        );
        // Recovery: installing again keeps the identical file and finishes.
        assert_eq!(h.install(&req("0.2.0", &[], &[])).result, "installed");
    }
}

#[test]
fn r1_c_a_trust_file_created_before_a_failed_fsync_is_partial_and_kept() {
    let f = fx();
    let r = failing(&["sync-after-link:trust.toml"], || {
        f.install(&req("0.2.0", &[], &[]))
    });
    assert_eq!(
        (r.result, r.exit_code()),
        ("partial", 5),
        "{:?}",
        r.messages
    );
    assert_eq!(r.trust, "created");
    // Nothing was undone: the files and the trust file are in place.
    assert!(f.root.join("trust.toml").exists());
    assert!(f.plugin_path("0.2.0").exists() && f.catalog_path("0.2.0").exists());
    assert!(
        r.messages.iter().any(|m| m.0.contains("in effect")),
        "{:?}",
        r.messages
    );
    assert_eq!(f.verify("0.2.0").exit_code(), 0);
    assert_eq!(f.install(&req("0.2.0", &[], &[])).result, "nothing-to-do");
}

#[test]
fn r1_d_a_trust_file_replaced_before_a_failed_fsync_is_partial_and_kept() {
    let f = fx();
    f.install(&req(
        "0.1.0",
        &["add_service_runtime", "add_service_permanent"],
        &[],
    ));
    let before = f.trust();
    let r = failing(&["sync-after-rename:trust.toml"], || {
        f.install(&req("0.2.0", &[], &[]))
    });
    assert_eq!(
        (r.result, r.exit_code()),
        ("partial", 5),
        "{:?}",
        r.messages
    );
    assert_eq!(r.trust, "appended");
    let after = f.trust();
    assert!(after.starts_with(&before) && after.len() > before.len());
    assert!(f.plugin_path("0.2.0").exists() && f.catalog_path("0.2.0").exists());
    assert_eq!(f.verify("0.1.0").exit_code(), 0);
    assert_eq!(f.verify("0.2.0").exit_code(), 0);
    assert_eq!(f.install(&req("0.2.0", &[], &[])).result, "nothing-to-do");
}

#[test]
fn r1_a_directory_created_before_a_failed_step_is_undone() {
    for point in [
        "sync-after-mkdir:sinter",
        "after-mkdir:plugins",
        "after-mkdir:catalogs",
        "sync-after-mkdir:plugins",
    ] {
        let f = fx();
        let before = f.tree();
        let r = failing(&[point], || f.install(&req("0.2.0", &[], &[])));
        assert_eq!(
            (r.result, r.exit_code()),
            ("refused", 2),
            "{}: {:?}",
            point,
            r.messages
        );
        assert_eq!(f.tree(), before, "{}", point);
    }
}

fn two_installed() -> Fx {
    let f = fx();
    f.install(&req(
        "0.1.0",
        &["add_service_runtime", "add_service_permanent"],
        &[],
    ));
    f.install(&req("0.2.0", &[], &[]));
    f
}

#[test]
fn r1_e_remove_reports_exactly_what_a_failed_fsync_leaves() {
    // .prev renamed, then its fsync fails: trust.toml unchanged, exit 2.
    let f = two_installed();
    let trust = f.trust();
    let r = failing(&["sync-after-rename:trust.toml.prev"], || f.remove("0.2.0"));
    assert_eq!(
        (r.result, r.exit_code()),
        ("refused", 2),
        "{:?}",
        r.messages
    );
    assert_eq!(r.trust, "unchanged");
    assert_eq!(f.trust(), trust);
    assert_eq!(
        std::fs::read(f.root.join("trust.toml.prev")).unwrap(),
        trust
    );
    assert_eq!(f.status("0.2.0"), "installed");
    assert!(
        r.messages
            .iter()
            .any(|m| m.0.contains("trust.toml is unchanged")),
        "{:?}",
        r.messages
    );

    // trust.toml renamed, then its fsync fails: in effect, partial, no file
    // removed.
    let f = two_installed();
    let r = failing(&["sync-after-rename:trust.toml"], || f.remove("0.2.0"));
    assert_eq!(
        (r.result, r.exit_code()),
        ("partial", 5),
        "{:?}",
        r.messages
    );
    assert_eq!(r.trust, "rewritten");
    assert!(r.files_removed.is_empty());
    assert!(f.plugin_path("0.2.0").exists() && f.catalog_path("0.2.0").exists());
    assert_ne!(f.status("0.2.0"), "installed");
    assert_eq!(f.verify("0.1.0").exit_code(), 0);

    // the plugin file removed, then the fsync fails: reported as removed,
    // the catalog not reached.
    let f = two_installed();
    let r = failing(&[&format!("sync-after-unlink:{}", PLG2)], || {
        f.remove("0.2.0")
    });
    assert_eq!(
        (r.result, r.exit_code()),
        ("partial", 5),
        "{:?}",
        r.messages
    );
    assert_eq!(r.files_removed, [format!("plugins/{}", PLG2)]);
    assert!(!f.plugin_path("0.2.0").exists() && f.catalog_path("0.2.0").exists());
    assert_eq!(f.verify("0.1.0").exit_code(), 0);

    // the catalog file removed, then the fsync fails: both reported.
    let f = two_installed();
    let r = failing(&[&format!("sync-after-unlink:{}", CAT2)], || {
        f.remove("0.2.0")
    });
    assert_eq!(
        (r.result, r.exit_code()),
        ("partial", 5),
        "{:?}",
        r.messages
    );
    assert_eq!(
        r.files_removed,
        [format!("plugins/{}", PLG2), format!("catalogs/{}", CAT2)]
    );
    assert!(!f.plugin_path("0.2.0").exists() && !f.catalog_path("0.2.0").exists());
    assert_eq!(f.status("0.2.0"), "available");
    assert_eq!(f.verify("0.1.0").exit_code(), 0);
}

#[test]
fn r1_injection_points_are_off_unless_armed_on_this_thread() {
    // Arming on another thread does not affect this one.
    std::thread::spawn(|| protect::hooks::fail_at(&["sync-after-link:trust.toml"]))
        .join()
        .unwrap();
    let f = fx();
    assert_eq!(f.install(&req("0.2.0", &[], &[])).result, "installed");
}

// ---------------------------------------------------------------------------
// The lock file's mode (Linux combined acceptance, 2026-11-11): `openat` was
// called without its mode argument, so `.lock` was created with an undefined
// mode (000 on Linux) and every later install or remove was refused.
// ---------------------------------------------------------------------------

#[test]
fn the_lock_file_is_private_and_a_wrong_mode_is_set_back() {
    let f = fx();
    f.install(&req(
        "0.1.0",
        &["add_service_runtime", "add_service_permanent"],
        &[],
    ));
    let lock = f.root.join(".lock");
    assert_eq!(mode_of(&lock), 0o600, "a new lock file is exactly 0600");
    // A lock file an earlier build left with mode 000 (which this user cannot
    // open), or with any other mode, is set back to 0600 and works.
    for (m, v) in [
        (0o000, "0.2.0"),
        (0o400, "0.2.0"),
        (0o644, "0.2.0"),
        (0o200, "0.2.0"),
    ] {
        if f.plugin_path(v).exists() {
            assert_eq!(f.remove(v).result, "removed");
        }
        mode(&lock, m);
        let r = f.install(&req(v, &[], &[]));
        assert_eq!(
            (r.result, r.exit_code()),
            ("installed", 0),
            "mode {:o}: {:?}",
            m,
            r.messages
        );
        assert_eq!(mode_of(&lock), 0o600, "mode {:o} set back", m);
        mode(&lock, m);
        let r = f.remove(v);
        assert_eq!(r.result, "removed", "mode {:o}: {:?}", m, r.messages);
        assert_eq!(mode_of(&lock), 0o600);
    }
    assert_eq!(f.verify("0.1.0").exit_code(), 0);
}

#[test]
fn a_lock_file_link_is_still_refused_and_never_followed() {
    let f = fx();
    f.install(&req(
        "0.1.0",
        &["add_service_runtime", "add_service_permanent"],
        &[],
    ));
    let lock = f.root.join(".lock");
    std::fs::remove_file(&lock).unwrap();
    let target = f.boundary.join("lock-target");
    std::fs::write(&target, b"").unwrap();
    mode(&target, 0o000);
    std::os::unix::fs::symlink(&target, &lock).unwrap();
    let r = f.install(&req("0.2.0", &[], &[]));
    assert_eq!(
        (r.result, r.exit_code()),
        ("refused", 2),
        "{:?}",
        r.messages
    );
    assert_eq!(mode_of(&target), 0o000, "the link's target is untouched");
    assert!(std::fs::symlink_metadata(&lock)
        .unwrap()
        .file_type()
        .is_symlink());
}
