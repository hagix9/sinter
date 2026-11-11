//! PM-2 tests: the embedded first-party files, `plugin list` and `plugin
//! verify`. Every root is built in a fresh temporary directory (the
//! boundary of the ancestor checks) with the production registry and the
//! production bundle.

use super::bundle::{self, EmbeddedPlugin, FIRST_PARTY_BUNDLE};
use super::format::CatalogFile;
use super::manage::{self, ListReport, Source, VerifyReport};
use super::protect::sha256_hex;
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("plugins/first-party")
        .join(rel)
}

fn e(version: &str) -> &'static EmbeddedPlugin {
    bundle::embedded(FIRST_PARTY_BUNDLE, "firewalld", version).expect("embedded")
}

struct Fx {
    _tmp: tempfile::TempDir,
    boundary: PathBuf,
    root: PathBuf,
}

fn mode(p: &Path, m: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
}

/// An empty protected root with `catalogs/` and `plugins/`.
fn fx() -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let boundary = tmp.path().to_path_buf();
    let root = boundary.join("root");
    for sub in ["", "catalogs", "plugins"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
        mode(&root.join(sub), 0o700);
    }
    Fx {
        _tmp: tmp,
        boundary,
        root,
    }
}

/// A boundary without any root below it.
fn fx_absent() -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let boundary = tmp.path().to_path_buf();
    let root = boundary.join("root");
    Fx {
        _tmp: tmp,
        boundary,
        root,
    }
}

impl Fx {
    fn files(&self, e: &EmbeddedPlugin) {
        let c = self.root.join(format!(
            "catalogs/{}-{}.catalog.toml",
            e.catalog_id, e.catalog_version
        ));
        let p = self
            .root
            .join(format!("plugins/{}-{}.plugin.toml", e.id, e.version));
        std::fs::write(&c, e.catalog).unwrap();
        std::fs::write(&p, e.plugin).unwrap();
        mode(&c, 0o644);
        mode(&p, 0o644);
    }
    fn plugin_path(&self, v: &str) -> PathBuf {
        self.root
            .join(format!("plugins/firewalld-{}.plugin.toml", v))
    }
    fn catalog_path(&self, v: &str) -> PathBuf {
        self.root
            .join(format!("catalogs/firewalld-{}.catalog.toml", v))
    }
    fn trust(&self, body: &str) {
        let t = self.root.join("trust.toml");
        std::fs::write(&t, body).unwrap();
        mode(&t, 0o600);
    }
    fn list(&self) -> ListReport {
        let boundary = self.boundary.clone();
        let open = move |p: &Path| PluginRoot::open_below(p, &boundary);
        manage::list_with(
            &Source::Root {
                path: self.root.clone(),
                open: &open,
            },
            FIRST_PARTY_BUNDLE,
            FIRST_PARTY_CATALOGS,
        )
    }
    fn verify(&self, targets: &[&str]) -> VerifyReport {
        let boundary = self.boundary.clone();
        let open = move |p: &Path| PluginRoot::open_below(p, &boundary);
        let t: Vec<PluginRef> = targets
            .iter()
            .map(|s| manage::parse_target(s).unwrap())
            .collect();
        manage::verify_with(
            &Source::Root {
                path: self.root.clone(),
                open: &open,
            },
            &t,
            FIRST_PARTY_BUNDLE,
            FIRST_PARTY_CATALOGS,
        )
    }
}

/// Trust entries for `e` with every operation of its catalog listed
/// (`skip_mutate` names mutate operations left out).
fn trust_entry(e: &EmbeddedPlugin, skip_mutate: &[&str]) -> String {
    let c: CatalogFile = toml::from_str(std::str::from_utf8(e.catalog).unwrap()).unwrap();
    let list = |class: &str| -> String {
        c.op.iter()
            .filter(|o| o.class == class && !skip_mutate.contains(&o.id.as_str()))
            .map(|o| format!("\"{}\"", o.id))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "[[catalog]]\nid = \"{}\"\nversion = \"{}\"\nsha256 = \"{}\"\nattested_observe = [{}]\nallowed_mutate = [{}]\n\n[[plugin]]\nid = \"{}\"\nversion = \"{}\"\nsha256 = \"{}\"\n\n",
        e.catalog_id,
        e.catalog_version,
        e.catalog_sha256,
        list("observe"),
        list("mutate"),
        e.id,
        e.version,
        e.plugin_sha256
    )
}

fn trust_of(entries: &[String]) -> String {
    format!("format = 1\n\n{}", entries.concat())
}

/// Both firewalld versions installed with complete trust entries.
fn fx_both() -> Fx {
    let f = fx();
    f.files(e("0.1.0"));
    f.files(e("0.2.0"));
    f.trust(&trust_of(&[
        trust_entry(e("0.1.0"), &[]),
        trust_entry(e("0.2.0"), &[]),
    ]));
    f
}

fn entry<'a>(r: &'a ListReport, v: &str) -> &'a manage::ListEntry {
    r.plugins
        .iter()
        .find(|p| p.id == "firewalld" && p.version == v)
        .expect("listed")
}

fn ventry<'a>(r: &'a VerifyReport, v: &str) -> &'a manage::VerifyEntry {
    r.plugins
        .iter()
        .find(|p| p.id == "firewalld" && p.version == v)
        .expect("verified")
}

fn check<'a>(p: &'a manage::VerifyEntry, name: &str) -> &'a str {
    p.checks
        .iter()
        .find(|c| c.name == name)
        .map(|c| c.result)
        .unwrap()
}

/// Every path below `root` with its type, size, mode and mtime.
fn snapshot(root: &Path) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let m = std::fs::symlink_metadata(&p).unwrap();
        out.push(format!(
            "{} {:o} {} {}.{}",
            p.display(),
            m.mode(),
            m.len(),
            m.mtime(),
            m.mtime_nsec()
        ));
        if m.is_dir() {
            for d in std::fs::read_dir(&p).unwrap() {
                stack.push(d.unwrap().path());
            }
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// The embedded files
// ---------------------------------------------------------------------------

#[test]
fn the_embedded_files_are_the_repository_files_with_their_digests() {
    assert_eq!(FIRST_PARTY_BUNDLE.len(), 2);
    for e in FIRST_PARTY_BUNDLE {
        let p = repo(&format!("plugins/{}-{}.plugin.toml", e.id, e.version));
        let c = repo(&format!(
            "catalogs/{}-{}.catalog.toml",
            e.catalog_id, e.catalog_version
        ));
        assert_eq!(
            e.plugin,
            std::fs::read(&p).unwrap().as_slice(),
            "{}",
            e.version
        );
        assert_eq!(
            e.catalog,
            std::fs::read(&c).unwrap().as_slice(),
            "{}",
            e.version
        );
        assert_eq!(sha256_hex(e.plugin), e.plugin_sha256);
        assert_eq!(sha256_hex(e.catalog), e.catalog_sha256);
        // The plugin file names itself and its catalog as the entry does.
        let pf: format::PluginFile =
            toml::from_str(std::str::from_utf8(e.plugin).unwrap()).unwrap();
        assert_eq!((pf.id.as_str(), pf.version.as_str()), (e.id, e.version));
        assert_eq!(
            (pf.catalog.id.as_str(), pf.catalog.version.as_str()),
            (e.catalog_id, e.catalog_version)
        );
    }
    // The four exact digests reviewed for firewalld 0.1.0 and 0.2.0.
    let digests: Vec<(&str, &str)> = FIRST_PARTY_BUNDLE
        .iter()
        .map(|e| (e.plugin_sha256, e.catalog_sha256))
        .collect();
    assert_eq!(
        digests,
        vec![
            (
                "47f33f171d239103cbb97450d17b57c857ce22436620ddf809fdd2be94948544",
                "27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff"
            ),
            (
                "e5819cfe0e2c017648f628a27d0ed6e4a18ed402f3ff6de072e61a724f0aa99a",
                "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641"
            ),
        ]
    );
}

#[test]
fn the_bundle_and_the_registry_list_the_same_catalogs() {
    bundle::consistent(FIRST_PARTY_BUNDLE, FIRST_PARTY_CATALOGS).unwrap();
    let from_bundle: Vec<(&str, &str, &str)> = FIRST_PARTY_BUNDLE
        .iter()
        .map(|e| (e.catalog_id, e.catalog_version, e.catalog_sha256))
        .collect();
    let from_registry: Vec<(&str, &str, &str)> = FIRST_PARTY_CATALOGS
        .iter()
        .map(|f| (f.id, f.version, f.sha256))
        .collect();
    assert_eq!(from_bundle, from_registry);
    // Every plugin file in the repository is embedded, and nothing else.
    let mut files: Vec<String> = std::fs::read_dir(repo("plugins"))
        .unwrap()
        .map(|d| d.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    let mut embedded: Vec<String> = FIRST_PARTY_BUNDLE
        .iter()
        .map(|e| format!("{}-{}.plugin.toml", e.id, e.version))
        .collect();
    embedded.sort();
    assert_eq!(files, embedded);
}

#[test]
fn an_inconsistent_bundle_or_registry_is_detected() {
    let good = *e("0.2.0");
    let bad_plugin: &'static [EmbeddedPlugin] = Box::leak(Box::new([EmbeddedPlugin {
        plugin_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
        ..good
    }]));
    assert!(bundle::consistent(bad_plugin, &FIRST_PARTY_CATALOGS[1..]).is_err());
    let bad_catalog: &'static [EmbeddedPlugin] = Box::leak(Box::new([EmbeddedPlugin {
        catalog: e("0.1.0").catalog,
        ..good
    }]));
    assert!(bundle::consistent(bad_catalog, &FIRST_PARTY_CATALOGS[1..]).is_err());
    // A registry entry without an embedded catalog, and an embedded catalog
    // the registry does not list.
    assert!(bundle::consistent(&FIRST_PARTY_BUNDLE[1..], FIRST_PARTY_CATALOGS).is_err());
    assert!(bundle::consistent(FIRST_PARTY_BUNDLE, &FIRST_PARTY_CATALOGS[1..]).is_err());
    // The commands refuse to report with an inconsistent bundle.
    let f = fx_both();
    let boundary = f.boundary.clone();
    let open = move |p: &Path| PluginRoot::open_below(p, &boundary);
    let src = Source::Root {
        path: f.root.clone(),
        open: &open,
    };
    let r = manage::list_with(&src, bad_plugin, &FIRST_PARTY_CATALOGS[1..]);
    assert_eq!(r.exit_code(), 2);
    let v = manage::verify_with(&src, &[], bad_plugin, &FIRST_PARTY_CATALOGS[1..]);
    assert_eq!(v.exit_code(), 2);
}

#[test]
fn embedding_grants_nothing_to_the_loader() {
    // The loader still reads only the root: a root with a trust file but no
    // files refuses the plugin although its bytes are embedded.
    let f = fx();
    f.trust(&trust_of(&[trust_entry(e("0.2.0"), &[])]));
    let pr = PluginRoot::open_below(&f.root, &f.boundary).unwrap();
    let r = load(
        &pr,
        &[PluginRef {
            id: "firewalld".into(),
            version: "0.2.0".into(),
        }],
    );
    assert!(r.is_err());
    // And the loader module does not refer to the bundle.
    let src = include_str!("mod.rs");
    let start = src.find("pub(crate) fn load_with(").unwrap();
    let end = src[start..].find("\n}\n").unwrap() + start;
    assert!(
        !src[start..end].contains("bundle"),
        "load_with uses the bundle"
    );
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

#[test]
fn list_without_a_root_shows_the_embedded_plugins_and_creates_nothing() {
    let f = fx_absent();
    let r = f.list();
    assert_eq!(r.root, "absent");
    assert_eq!(r.exit_code(), 0);
    assert_eq!(r.plugins.len(), 2);
    for v in ["0.1.0", "0.2.0"] {
        let p = entry(&r, v);
        assert!(p.available);
        assert_eq!(p.installed, Some(false));
        assert_eq!(p.status, "available");
    }
    assert_eq!(entry(&r, "0.1.0").mutate_total, Some(2));
    assert_eq!(entry(&r, "0.2.0").mutate_total, Some(12));
    assert_eq!(entry(&r, "0.2.0").mutate_allowed, Some(0));
    assert!(!f.root.exists());
}

#[test]
fn list_with_an_empty_root_shows_nothing_installed() {
    let f = fx();
    let r = f.list();
    assert_eq!((r.root, r.trust), ("ok", "absent"));
    assert_eq!(r.exit_code(), 0);
    assert!(r.plugins.iter().all(|p| p.status == "available"));
}

#[test]
fn list_shows_both_versions_installed_side_by_side() {
    let f = fx_both();
    let r = f.list();
    assert_eq!(r.exit_code(), 0, "{:?}", r.messages);
    let a = entry(&r, "0.1.0");
    let b = entry(&r, "0.2.0");
    assert_eq!((a.status, a.installed), ("installed", Some(true)));
    assert_eq!((b.status, b.installed), ("installed", Some(true)));
    assert_eq!((a.observe_attested, a.observe_total), (Some(5), Some(5)));
    assert_eq!((a.mutate_allowed, a.mutate_total), (Some(2), Some(2)));
    assert_eq!((b.observe_attested, b.observe_total), (Some(9), Some(9)));
    assert_eq!((b.mutate_allowed, b.mutate_total), (Some(12), Some(12)));
}

#[test]
fn list_distinguishes_missing_damaged_untrusted_and_unsupported() {
    // Missing plugin file.
    let f = fx_both();
    std::fs::remove_file(f.plugin_path("0.2.0")).unwrap();
    let r = f.list();
    assert_eq!(entry(&r, "0.2.0").status, "missing-file");
    assert_eq!(entry(&r, "0.2.0").installed, Some(false));
    assert_eq!(entry(&r, "0.1.0").status, "installed");

    // Missing catalog file.
    let f = fx_both();
    std::fs::remove_file(f.catalog_path("0.1.0")).unwrap();
    assert_eq!(entry(&f.list(), "0.1.0").status, "missing-file");

    // Changed bytes, re-pinned by the trust file: still not the first-party
    // file.
    let f = fx_both();
    let mut b = e("0.2.0").plugin.to_vec();
    b.extend_from_slice(b"# edited\n");
    std::fs::write(f.plugin_path("0.2.0"), &b).unwrap();
    f.trust(
        &trust_of(&[trust_entry(e("0.1.0"), &[]), trust_entry(e("0.2.0"), &[])])
            .replace(e("0.2.0").plugin_sha256, &sha256_hex(&b)),
    );
    assert_eq!(entry(&f.list(), "0.2.0").status, "digest-mismatch");

    // Files without a trust entry.
    let f = fx();
    f.files(e("0.2.0"));
    let r = f.list();
    assert_eq!(entry(&r, "0.2.0").status, "not-trusted");
    assert_eq!(entry(&r, "0.2.0").installed, Some(false));

    // Only a catalog file, no trust entry.
    let f = fx();
    f.files(e("0.1.0"));
    std::fs::remove_file(f.plugin_path("0.1.0")).unwrap();
    assert_eq!(entry(&f.list(), "0.1.0").status, "not-trusted");

    // A trusted plugin this Sinter does not carry.
    let f = fx_both();
    let extra = "[[plugin]]\nid = \"firewalld\"\nversion = \"9.9.9\"\nsha256 = \"1111111111111111111111111111111111111111111111111111111111111111\"\n";
    f.trust(&format!(
        "{}{}",
        trust_of(&[trust_entry(e("0.1.0"), &[]), trust_entry(e("0.2.0"), &[])]),
        extra
    ));
    let r = f.list();
    let u = entry(&r, "9.9.9");
    assert_eq!(
        (u.status, u.available),
        ("unsupported-by-this-sinter", false)
    );
    assert_eq!(u.mutate_total, None);
}

#[test]
fn list_and_verify_show_an_incomplete_trust_entry_without_widening_it() {
    // The loader refuses the whole plugin while a mutate operation it uses
    // is not allowed (DESIGN §38.6). The reports say so; nothing is allowed.
    let f = fx();
    f.files(e("0.2.0"));
    let skipped = ["remove_port_runtime", "remove_port_permanent"];
    f.trust(&trust_of(&[trust_entry(e("0.2.0"), &skipped)]));
    let before = std::fs::read(f.root.join("trust.toml")).unwrap();
    let l = f.list();
    let p = entry(&l, "0.2.0");
    assert_eq!(p.status, "trust-incomplete");
    assert_eq!((p.mutate_allowed, p.mutate_total), (Some(10), Some(12)));
    let v = f.verify(&["firewalld@0.2.0"]);
    let q = ventry(&v, "0.2.0");
    assert_eq!(q.status, "load-refused");
    assert_eq!(check(q, "load"), "fail");
    assert_eq!(
        q.required_not_enabled,
        vec!["remove_port_permanent", "remove_port_runtime"]
    );
    assert_eq!(v.exit_code(), 2);
    assert_eq!(std::fs::read(f.root.join("trust.toml")).unwrap(), before);
}

#[test]
fn list_refuses_an_invalid_trust_file_or_an_unsafe_root() {
    let f = fx_both();
    f.trust("format = 1\n[[plugin]]\nid = \"firewalld\"\n");
    let r = f.list();
    assert_eq!((r.root, r.trust), ("ok", "invalid"));
    assert_eq!(r.exit_code(), 2);
    assert!(r
        .plugins
        .iter()
        .all(|p| p.status == "unknown" && p.installed.is_none()));
    assert!(!r.messages.is_empty());

    let f = fx_both();
    mode(&f.root, 0o770);
    let r = f.list();
    assert_eq!(r.root, "refused");
    assert_eq!(r.exit_code(), 2);
    assert!(r.messages[0].0.contains("writable by group or others"));
}

#[test]
fn symbolic_links_and_unsafe_files_are_refused() {
    // A plugin file replaced by a link to an identical copy.
    let f = fx_both();
    let copy = f.boundary.join("copy.toml");
    std::fs::write(&copy, e("0.2.0").plugin).unwrap();
    std::fs::remove_file(f.plugin_path("0.2.0")).unwrap();
    std::os::unix::fs::symlink(&copy, f.plugin_path("0.2.0")).unwrap();
    assert_eq!(entry(&f.list(), "0.2.0").status, "refused");
    let v = f.verify(&["firewalld@0.2.0"]);
    assert_eq!(ventry(&v, "0.2.0").status, "refused");
    assert!(v.messages.iter().any(|m| m.0.contains("symbolic link")));

    // A dangling link is refused too, not reported as missing.
    let f = fx_both();
    std::fs::remove_file(f.plugin_path("0.1.0")).unwrap();
    std::os::unix::fs::symlink(f.boundary.join("nowhere"), f.plugin_path("0.1.0")).unwrap();
    assert_eq!(entry(&f.list(), "0.1.0").status, "refused");

    // The plugins directory as a link.
    let f = fx_both();
    let real = f.boundary.join("real-plugins");
    std::fs::rename(f.root.join("plugins"), &real).unwrap();
    std::os::unix::fs::symlink(&real, f.root.join("plugins")).unwrap();
    let r = f.list();
    assert!(
        r.plugins.iter().all(|p| p.status == "refused"),
        "{:?}",
        r.plugins
    );

    // A group-writable catalog file.
    let f = fx_both();
    mode(&f.catalog_path("0.1.0"), 0o664);
    assert_eq!(entry(&f.list(), "0.1.0").status, "refused");
    assert_eq!(ventry(&f.verify(&[]), "0.1.0").status, "refused");

    // A trust file that is a link.
    let f = fx_both();
    let t = f.boundary.join("t.toml");
    std::fs::rename(f.root.join("trust.toml"), &t).unwrap();
    std::os::unix::fs::symlink(&t, f.root.join("trust.toml")).unwrap();
    assert_eq!(f.list().trust, "invalid");
    assert_eq!(f.verify(&[]).exit_code(), 2);
}

#[test]
fn list_orders_plugins_deterministically() {
    let f = fx_both();
    let extra = "[[plugin]]\nid = \"firewalld\"\nversion = \"0.10.0\"\nsha256 = \"1111111111111111111111111111111111111111111111111111111111111111\"\n\n[[plugin]]\nid = \"aaa\"\nversion = \"1.0.0\"\nsha256 = \"2222222222222222222222222222222222222222222222222222222222222222\"\n";
    f.trust(&format!(
        "{}{}",
        trust_of(&[trust_entry(e("0.2.0"), &[]), trust_entry(e("0.1.0"), &[])]),
        extra
    ));
    let order: Vec<String> = f
        .list()
        .plugins
        .iter()
        .map(|p| format!("{}@{}", p.id, p.version))
        .collect();
    assert_eq!(
        order,
        [
            "aaa@1.0.0",
            "firewalld@0.1.0",
            "firewalld@0.2.0",
            "firewalld@0.10.0"
        ]
    );
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

#[test]
fn verify_passes_every_check_for_both_installed_versions() {
    let f = fx_both();
    let r = f.verify(&[]);
    assert!(r.ok, "{:?}", r.messages);
    assert_eq!(r.exit_code(), 0);
    assert_eq!(r.plugins.len(), 2);
    for v in ["0.1.0", "0.2.0"] {
        let p = ventry(&r, v);
        assert_eq!(p.status, "ok");
        assert_eq!(
            p.checks.iter().map(|c| c.name).collect::<Vec<_>>(),
            manage::CHECKS.to_vec()
        );
        assert!(
            p.checks.iter().all(|c| c.result == "pass"),
            "{:?}",
            p.checks
        );
        assert!(p.required_not_enabled.is_empty());
    }
    let one = f.verify(&["firewalld@0.1.0"]);
    assert_eq!(one.plugins.len(), 1);
    assert!(one.ok);
}

#[test]
fn verify_tells_not_installed_from_damaged() {
    // Nothing installed and no root: an empty verification passes; a named
    // plugin is not installed.
    let f = fx_absent();
    let r = f.verify(&[]);
    assert!(r.ok && r.plugins.is_empty());
    let r = f.verify(&["firewalld@0.2.0"]);
    assert_eq!(ventry(&r, "0.2.0").status, "not-installed");
    assert_eq!(r.exit_code(), 2);
    assert!(!f.root.exists());

    // Files present, no trust entry: not trusted, and not added.
    let f = fx();
    f.files(e("0.2.0"));
    let r = f.verify(&["firewalld@0.2.0"]);
    assert_eq!(ventry(&r, "0.2.0").status, "not-trusted");
    assert!(!f.root.join("trust.toml").exists());
    // Without a target, untrusted files are not verified (nothing pinned).
    assert!(f.verify(&[]).plugins.is_empty());

    // Missing plugin file.
    let f = fx_both();
    std::fs::remove_file(f.plugin_path("0.1.0")).unwrap();
    let r = f.verify(&[]);
    let p = ventry(&r, "0.1.0");
    assert_eq!(p.status, "missing-file");
    assert_eq!(check(p, "plugin_file"), "fail");
    assert_eq!(check(p, "load"), "skip");
    assert_eq!(ventry(&r, "0.2.0").status, "ok");
    assert_eq!(r.exit_code(), 2);

    // Missing catalog file.
    let f = fx_both();
    std::fs::remove_file(f.catalog_path("0.2.0")).unwrap();
    assert_eq!(ventry(&f.verify(&[]), "0.2.0").status, "missing-file");
}

#[test]
fn verify_reports_each_digest_mismatch() {
    // A changed catalog the Owner re-pinned: the trust pin matches, the
    // registry and the embedded file do not.
    let f = fx_both();
    let mut b = e("0.1.0").catalog.to_vec();
    b.extend_from_slice(b"# edited\n");
    std::fs::write(f.catalog_path("0.1.0"), &b).unwrap();
    f.trust(
        &trust_of(&[trust_entry(e("0.1.0"), &[]), trust_entry(e("0.2.0"), &[])])
            .replace(e("0.1.0").catalog_sha256, &sha256_hex(&b)),
    );
    let r = f.verify(&["firewalld@0.1.0"]);
    let p = ventry(&r, "0.1.0");
    assert_eq!(p.status, "digest-mismatch");
    assert_eq!(check(p, "catalog_digest_trust"), "pass");
    assert_eq!(check(p, "catalog_registry"), "fail");
    assert_eq!(check(p, "catalog_digest_embedded"), "fail");
    assert_eq!(check(p, "load"), "skip");

    // A changed plugin file that the trust file does not re-pin.
    let f = fx_both();
    let mut b = e("0.2.0").plugin.to_vec();
    b.extend_from_slice(b"# edited\n");
    std::fs::write(f.plugin_path("0.2.0"), &b).unwrap();
    let p = f.verify(&["firewalld@0.2.0"]);
    let q = ventry(&p, "0.2.0");
    assert_eq!(q.status, "digest-mismatch");
    assert_eq!(check(q, "plugin_digest_trust"), "fail");
    assert_eq!(check(q, "plugin_digest_embedded"), "fail");
}

#[test]
fn verify_refuses_an_invalid_trust_file_and_unknown_plugins() {
    let f = fx_both();
    f.trust("format = 2\n");
    let r = f.verify(&[]);
    assert_eq!(r.trust, "invalid");
    assert!(!r.ok);
    assert_eq!(r.exit_code(), 2);

    let f = fx_both();
    let r = f.verify(&["firewalld@9.9.9"]);
    assert_eq!(ventry(&r, "9.9.9").status, "unsupported-by-this-sinter");
    assert_eq!(r.exit_code(), 2);

    for bad in [
        "firewalld",
        "firewalld@1.0",
        "Fire@1.0.0",
        "a@01.0.0",
        "@1.0.0",
    ] {
        assert!(manage::parse_target(bad).is_err(), "{}", bad);
    }
}

#[test]
fn list_and_verify_change_nothing_in_the_root() {
    let f = fx_both();
    // An incomplete and an unsafe case as well, so refusals are exercised.
    let before = snapshot(&f.boundary);
    for _ in 0..2 {
        let _ = f.list();
        let _ = f.verify(&[]);
        let _ = f.verify(&["firewalld@0.2.0", "firewalld@9.9.9"]);
    }
    assert_eq!(snapshot(&f.boundary), before);

    let f = fx();
    mode(&f.root.join("plugins"), 0o777);
    let before = snapshot(&f.boundary);
    let _ = f.list();
    let _ = f.verify(&["firewalld@0.1.0"]);
    assert_eq!(snapshot(&f.boundary), before);
}

#[test]
fn reports_serialize_to_json_with_states_only() {
    let f = fx_absent();
    let l = serde_json::to_value(f.list()).unwrap();
    assert_eq!(l["format"], 1);
    assert_eq!(l["command"], "list");
    assert_eq!(l["root"], "absent");
    assert_eq!(l["plugins"].as_array().unwrap().len(), 2);
    assert!(l.get("messages").is_none());
    let v = serde_json::to_value(f.verify(&[])).unwrap();
    assert_eq!(v["plugins"], serde_json::json!([]));
    assert_eq!(v["ok"], true);

    // Messages (which may contain paths) stay out of the JSON.
    let f = fx_both();
    f.trust("format = 1\n[[plugin]]\nid = \"firewalld\"\n");
    let r = f.verify(&[]);
    assert!(!r.messages.is_empty());
    let text = serde_json::to_string(&r).unwrap();
    assert!(!text.contains("trust.toml"), "{}", text);

    // Serializing twice gives the same document.
    let f = fx_both();
    assert_eq!(
        serde_json::to_string(&f.verify(&[])).unwrap(),
        serde_json::to_string(&f.verify(&[])).unwrap()
    );
}

#[test]
fn an_unset_root_reports_nothing_installed() {
    let r = manage::list_with(&Source::Unset, FIRST_PARTY_BUNDLE, FIRST_PARTY_CATALOGS);
    assert_eq!(r.root, "unset");
    assert!(r.plugins.iter().all(|p| p.status == "available"));
    let v = manage::verify_with(
        &Source::Unset,
        &[manage::parse_target("firewalld@0.1.0").unwrap()],
        FIRST_PARTY_BUNDLE,
        FIRST_PARTY_CATALOGS,
    );
    assert_eq!(ventry(&v, "0.1.0").status, "not-installed");
}

#[test]
fn the_management_module_has_no_path_to_a_write_a_process_or_a_target() {
    let src = include_str!("manage.rs");
    for word in [
        "std::process",
        "Command::new",
        "executor",
        "targetfs",
        "TargetFs",
        "MutationPermit",
        "create_dir",
        "File::create",
        "OpenOptions",
        "remove_file",
        "remove_dir",
        "rename(",
        "set_permissions",
        "fs::write",
        "fs::copy",
        "symlink(",
        "ssh",
    ] {
        assert!(!src.contains(word), "manage.rs uses {}", word);
    }
}
