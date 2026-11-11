//! Read-only plugin management (DESIGN §38.15): `sinter plugin list` and
//! `sinter plugin verify`.
//!
//! Both commands only read. They open the plugin root with the loader's
//! protected reader (`protect.rs`), read the trust file with the loader's
//! parser, and `verify` runs the loader itself (`load_with`) for each
//! plugin. They never create, change or remove a file or directory, never
//! read a recipe, and never contact a target. Nothing here trusts, enables or
//! installs a plugin, and nothing here changes what the loader accepts.
//!
//! Whether a path exists is asked once without following a final symbolic
//! link, only to tell "not installed" from "damaged" in the report. Every
//! byte that is compared or parsed comes from the protected reader.

use super::bundle::{self, EmbeddedPlugin};
use super::format::{CatalogFile, PluginFile, TrustedCatalog};
use super::protect::{Loaded, TrustedDir};
use super::verify::{self, TrustIndex};
use super::{FirstPartyCatalog, PluginContext, PluginRef, PluginRoot};
use crate::error::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Format number of the JSON reports.
pub const REPORT_FORMAT: u32 = 1;

/// Where the plugin root comes from for one report.
pub enum Source<'a> {
    /// No plugin root can be determined (for example HOME is not set).
    Unset,
    Root {
        path: PathBuf,
        open: &'a dyn Fn(&Path) -> Result<PluginRoot>,
    },
}

impl Source<'static> {
    /// The CLI's plugin root, resolved exactly as for plan and apply
    /// (`--plugin-root`, then the user's configuration directory).
    pub fn controller(explicit: Option<&Path>) -> Source<'static> {
        match PluginContext::controller(explicit) {
            PluginContext::Root(path) => Source::Root {
                path,
                open: &PluginRoot::open,
            },
            _ => Source::Unset,
        }
    }
}

/// A message for standard error. Reports keep only machine states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message(pub String);

#[derive(Debug, Serialize)]
pub struct ListReport {
    pub format: u32,
    pub command: &'static str,
    pub plugin_root: Option<String>,
    /// `unset`, `absent`, `ok` or `refused`.
    pub root: &'static str,
    /// `not-read`, `absent`, `ok` or `invalid`.
    pub trust: &'static str,
    pub plugins: Vec<ListEntry>,
    #[serde(skip)]
    pub messages: Vec<Message>,
}

#[derive(Debug, Serialize)]
pub struct ListEntry {
    pub id: String,
    pub version: String,
    /// The plugin and its catalog are embedded in this Sinter.
    pub available: bool,
    /// The trust file pins the plugin and its file is in the root; `null`
    /// when the root or the trust file could not be read.
    pub installed: Option<bool>,
    /// `available`, `installed`, `trust-incomplete` (installed, but the
    /// trust file leaves out an operation the plugin's types use, so the
    /// loader refuses the plugin), `missing-file`, `digest-mismatch`,
    /// `not-trusted`, `refused`, `unsupported-by-this-sinter` or `unknown`.
    pub status: &'static str,
    pub observe_attested: Option<usize>,
    pub observe_total: Option<usize>,
    pub mutate_allowed: Option<usize>,
    pub mutate_total: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub format: u32,
    pub command: &'static str,
    pub plugin_root: Option<String>,
    pub root: &'static str,
    pub trust: &'static str,
    pub ok: bool,
    pub plugins: Vec<VerifyEntry>,
    #[serde(skip)]
    pub messages: Vec<Message>,
}

#[derive(Debug, Serialize)]
pub struct VerifyEntry {
    pub id: String,
    pub version: String,
    /// `ok`, `not-installed`, `not-trusted`, `missing-file`,
    /// `digest-mismatch`, `refused`, `unsupported-by-this-sinter`,
    /// `load-refused` or `unknown`.
    pub status: &'static str,
    pub checks: Vec<Check>,
    pub observe_attested: Option<usize>,
    pub observe_total: Option<usize>,
    pub mutate_allowed: Option<usize>,
    pub mutate_total: Option<usize>,
    /// Operations the plugin's types use that the trust file does not
    /// attest or allow. The loader refuses the whole plugin while any is
    /// listed (DESIGN §38.6).
    pub required_not_enabled: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    /// `pass`, `fail` or `skip`.
    pub result: &'static str,
}

impl ListReport {
    /// 0, or 2 when the root or the trust file could not be read.
    pub fn exit_code(&self) -> u8 {
        if self.root == "refused" || self.trust == "invalid" {
            2
        } else {
            0
        }
    }
}

impl VerifyReport {
    /// 0 when every verified plugin is usable and the root and trust file
    /// are sound, otherwise 2.
    pub fn exit_code(&self) -> u8 {
        if self.ok {
            0
        } else {
            2
        }
    }
}

// ---------------------------------------------------------------------------
// Reading the root
// ---------------------------------------------------------------------------

/// Whether `p` exists, without following a final symbolic link. Only used
/// to choose between "missing" and the protected reader's verdict.
fn absent(p: &Path) -> bool {
    matches!(std::fs::symlink_metadata(p), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

enum DirState {
    Missing,
    Refused,
    Open(TrustedDir),
}

enum FileState {
    Missing,
    Refused,
    Read(Loaded),
}

impl FileState {
    fn present(&self) -> bool {
        !matches!(self, FileState::Missing)
    }
}

/// The opened root, its trust index and its two directories.
struct Opened {
    path: PathBuf,
    root: PluginRoot,
    trust: TrustIndex,
    plugins: DirState,
    catalogs: DirState,
}

struct RootView {
    shown: Option<String>,
    root: &'static str,
    trust: &'static str,
    opened: Option<Opened>,
}

fn open_root(source: &Source, messages: &mut Vec<Message>) -> RootView {
    let (path, open) = match source {
        Source::Unset => {
            messages.push(Message(
                "no plugin root: pass --plugin-root (HOME is not set)".into(),
            ));
            return RootView {
                shown: None,
                root: "unset",
                trust: "not-read",
                opened: None,
            };
        }
        Source::Root { path, open } => (path, open),
    };
    let shown = Some(super::protect::shown(path));
    // A missing root (or a missing directory above it) is "nothing
    // installed", not an error. The check follows links as the loader's
    // own resolution does.
    if matches!(std::fs::metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        return RootView {
            shown,
            root: "absent",
            trust: "not-read",
            opened: None,
        };
    }
    let root = match open(path) {
        Ok(r) => r,
        Err(e) => {
            messages.push(Message(e.message));
            return RootView {
                shown,
                root: "refused",
                trust: "not-read",
                opened: None,
            };
        }
    };
    let (trust_state, trust) = if absent(&path.join("trust.toml")) {
        ("absent", empty_trust())
    } else {
        match root
            .dir
            .read_file_with("trust.toml", verify::MAX_FILE_BYTES, &mut || {})
            .and_then(|f| {
                verify::verify_trust(&f.bytes, &format!("{}/trust.toml", root.dir.shown()))
            }) {
            Ok(t) => ("ok", t),
            Err(e) => {
                messages.push(Message(e.message));
                return RootView {
                    shown,
                    root: "ok",
                    trust: "invalid",
                    opened: None,
                };
            }
        }
    };
    let mut sub = |name: &str| -> DirState {
        if absent(&path.join(name)) {
            return DirState::Missing;
        }
        match root.dir.subdir(name) {
            Ok(d) => DirState::Open(d),
            Err(e) => {
                messages.push(Message(e.message));
                DirState::Refused
            }
        }
    };
    let plugins = sub("plugins");
    let catalogs = sub("catalogs");
    RootView {
        shown,
        root: "ok",
        trust: trust_state,
        opened: Some(Opened {
            path: path.clone(),
            root,
            trust,
            plugins,
            catalogs,
        }),
    }
}

fn empty_trust() -> TrustIndex {
    TrustIndex {
        catalogs: BTreeMap::new(),
        plugins: BTreeMap::new(),
    }
}

fn read_in(
    o: &Opened,
    dir: &DirState,
    sub: &str,
    name: &str,
    messages: &mut Vec<Message>,
) -> FileState {
    match dir {
        DirState::Missing => FileState::Missing,
        DirState::Refused => FileState::Refused,
        DirState::Open(d) => {
            if absent(&o.path.join(sub).join(name)) {
                return FileState::Missing;
            }
            match d.read_file_with(name, verify::MAX_FILE_BYTES, &mut || {}) {
                Ok(f) => FileState::Read(f),
                Err(e) => {
                    messages.push(Message(e.message));
                    FileState::Refused
                }
            }
        }
    }
}

fn plugin_file(o: &Opened, id: &str, version: &str, m: &mut Vec<Message>) -> FileState {
    read_in(
        o,
        &o.plugins,
        "plugins",
        &format!("{}-{}.plugin.toml", id, version),
        m,
    )
}

fn catalog_file(o: &Opened, id: &str, version: &str, m: &mut Vec<Message>) -> FileState {
    read_in(
        o,
        &o.catalogs,
        "catalogs",
        &format!("{}-{}.catalog.toml", id, version),
        m,
    )
}

// ---------------------------------------------------------------------------
// Permissions of an embedded plugin under a trust entry
// ---------------------------------------------------------------------------

struct Permissions {
    observe_attested: usize,
    observe_total: usize,
    mutate_allowed: usize,
    mutate_total: usize,
    required_not_enabled: Vec<String>,
}

/// Count the catalog's operations by class, those the trust entry enables,
/// and the operations the plugin's types use that it does not enable.
/// Parses only embedded bytes, whose digests were checked.
fn permissions(e: &EmbeddedPlugin, tc: Option<&TrustedCatalog>) -> Option<Permissions> {
    let catalog: CatalogFile = toml::from_str(std::str::from_utf8(e.catalog).ok()?).ok()?;
    let plugin: PluginFile = toml::from_str(std::str::from_utf8(e.plugin).ok()?).ok()?;
    let class: BTreeMap<&str, &str> = catalog
        .op
        .iter()
        .map(|o| (o.id.as_str(), o.class.as_str()))
        .collect();
    let enabled = |op: &str| -> bool {
        let Some(tc) = tc else { return false };
        match class.get(op) {
            Some(&"observe") => tc.attested_observe.iter().any(|x| x == op),
            Some(&"mutate") => tc.allowed_mutate.iter().any(|x| x == op),
            _ => false,
        }
    };
    let count = |c: &str| class.values().filter(|v| **v == c).count();
    let on = |c: &str| {
        class
            .iter()
            .filter(|(op, v)| **v == c && enabled(op))
            .count()
    };
    let mut used = BTreeSet::new();
    for t in &plugin.types {
        for p in &t.precheck {
            used.insert(p.op.clone());
        }
        for f in &t.facet {
            used.insert(f.observe.clone());
            used.extend(f.ensure.values().cloned());
        }
    }
    Some(Permissions {
        observe_attested: on("observe"),
        observe_total: count("observe"),
        mutate_allowed: on("mutate"),
        mutate_total: count("mutate"),
        required_not_enabled: used.into_iter().filter(|op| !enabled(op)).collect(),
    })
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn version_key(v: &str) -> Vec<u64> {
    v.split('.')
        .map(|p| p.parse().unwrap_or(u64::MAX))
        .collect()
}

fn sorted_keys(
    bundle: &[EmbeddedPlugin],
    trust: Option<&TrustIndex>,
    extra: &[PluginRef],
) -> Vec<(String, String)> {
    let mut keys: BTreeSet<(String, String)> = bundle
        .iter()
        .map(|e| (e.id.to_string(), e.version.to_string()))
        .collect();
    if let Some(t) = trust {
        keys.extend(t.plugins.keys().cloned());
    }
    keys.extend(extra.iter().map(|r| (r.id.clone(), r.version.clone())));
    let mut v: Vec<_> = keys.into_iter().collect();
    v.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| version_key(&a.1).cmp(&version_key(&b.1)))
            .then_with(|| a.1.cmp(&b.1))
    });
    v
}

/// `sinter plugin list`.
pub fn list(source: &Source) -> ListReport {
    list_with(
        source,
        bundle::FIRST_PARTY_BUNDLE,
        super::FIRST_PARTY_CATALOGS,
    )
}

pub(crate) fn list_with(
    source: &Source,
    bundle: &'static [EmbeddedPlugin],
    registry: &[FirstPartyCatalog],
) -> ListReport {
    let mut messages = Vec::new();
    if let Err(m) = bundle::consistent(bundle, registry) {
        messages.push(Message(m));
        return ListReport {
            format: REPORT_FORMAT,
            command: "list",
            plugin_root: None,
            root: "refused",
            trust: "not-read",
            plugins: Vec::new(),
            messages,
        };
    }
    let view = open_root(source, &mut messages);
    let unreadable = view.root == "refused" || view.trust == "invalid";
    let keys = sorted_keys(bundle, view.opened.as_ref().map(|o| &o.trust), &[]);
    let mut plugins = Vec::new();
    for (id, version) in keys {
        let e = bundle::embedded(bundle, &id, &version);
        let mut entry = ListEntry {
            id: id.clone(),
            version: version.clone(),
            available: e.is_some(),
            installed: None,
            status: "unknown",
            observe_attested: None,
            observe_total: None,
            mutate_allowed: None,
            mutate_total: None,
        };
        let tp = view
            .opened
            .as_ref()
            .and_then(|o| o.trust.plugins.get(&(id.clone(), version.clone())));
        let tc = match (view.opened.as_ref(), e) {
            (Some(o), Some(e)) => o
                .trust
                .catalogs
                .get(&(e.catalog_id.to_string(), e.catalog_version.to_string())),
            _ => None,
        };
        let mut incomplete = false;
        if let Some(e) = e {
            if let Some(p) = permissions(e, tc) {
                entry.observe_total = Some(p.observe_total);
                entry.mutate_total = Some(p.mutate_total);
                if !unreadable {
                    entry.observe_attested = Some(p.observe_attested);
                    entry.mutate_allowed = Some(p.mutate_allowed);
                }
                incomplete = !p.required_not_enabled.is_empty();
            }
        }
        if unreadable {
            plugins.push(entry);
            continue;
        }
        let Some(o) = view.opened.as_ref() else {
            // No root: nothing is installed.
            entry.installed = Some(false);
            entry.status = if e.is_some() {
                "available"
            } else {
                "unsupported-by-this-sinter"
            };
            plugins.push(entry);
            continue;
        };
        let pf = plugin_file(o, &id, &version, &mut messages);
        entry.installed = Some(tp.is_some() && pf.present());
        let Some(e) = e else {
            entry.status = "unsupported-by-this-sinter";
            plugins.push(entry);
            continue;
        };
        let cf = catalog_file(o, e.catalog_id, e.catalog_version, &mut messages);
        entry.status = match tp {
            None if pf.present() || cf.present() => "not-trusted",
            None => "available",
            Some(tp) => {
                if matches!(pf, FileState::Refused) || matches!(cf, FileState::Refused) {
                    "refused"
                } else if tc.is_none() {
                    "not-trusted"
                } else if !pf.present() || !cf.present() {
                    "missing-file"
                } else if !digests_match(e, tp.sha256.as_str(), tc, &pf, &cf) {
                    "digest-mismatch"
                } else if incomplete {
                    "trust-incomplete"
                } else {
                    "installed"
                }
            }
        };
        plugins.push(entry);
    }
    ListReport {
        format: REPORT_FORMAT,
        command: "list",
        plugin_root: view.shown,
        root: view.root,
        trust: view.trust,
        plugins,
        messages,
    }
}

/// The plugin and catalog files equal their trust pins and the embedded
/// bytes (whose digests equal the registry's).
fn digests_match(
    e: &EmbeddedPlugin,
    plugin_pin: &str,
    tc: Option<&TrustedCatalog>,
    pf: &FileState,
    cf: &FileState,
) -> bool {
    let (FileState::Read(p), FileState::Read(c), Some(tc)) = (pf, cf, tc) else {
        return false;
    };
    p.sha256 == plugin_pin
        && p.sha256 == e.plugin_sha256
        && c.sha256 == tc.sha256
        && c.sha256 == e.catalog_sha256
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// `sinter plugin verify`: the named plugins, or every plugin the trust file
/// pins.
pub fn verify(source: &Source, targets: &[PluginRef]) -> VerifyReport {
    verify_with(
        source,
        targets,
        bundle::FIRST_PARTY_BUNDLE,
        super::FIRST_PARTY_CATALOGS,
    )
}

pub(crate) fn verify_with(
    source: &Source,
    targets: &[PluginRef],
    bundle: &'static [EmbeddedPlugin],
    registry: &[FirstPartyCatalog],
) -> VerifyReport {
    let mut messages = Vec::new();
    if let Err(m) = bundle::consistent(bundle, registry) {
        messages.push(Message(m));
        return VerifyReport {
            format: REPORT_FORMAT,
            command: "verify",
            plugin_root: None,
            root: "refused",
            trust: "not-read",
            ok: false,
            plugins: Vec::new(),
            messages,
        };
    }
    let view = open_root(source, &mut messages);
    let unreadable = view.root == "refused" || view.trust == "invalid";
    let keys: Vec<(String, String)> = if targets.is_empty() {
        match view.opened.as_ref() {
            Some(o) => sorted_keys(&[], Some(&o.trust), &[]),
            None => Vec::new(),
        }
    } else {
        sorted_keys(&[], None, targets)
    };
    let mut plugins = Vec::new();
    for (id, version) in keys {
        let entry = verify_one(
            &view,
            unreadable,
            &id,
            &version,
            bundle,
            registry,
            &mut messages,
        );
        plugins.push(entry);
    }
    let ok = !unreadable && plugins.iter().all(|p| p.status == "ok");
    VerifyReport {
        format: REPORT_FORMAT,
        command: "verify",
        plugin_root: view.shown,
        root: view.root,
        trust: view.trust,
        ok,
        plugins,
        messages,
    }
}

struct Checks(Vec<Check>);

impl Checks {
    fn push(&mut self, name: &'static str, pass: bool) -> bool {
        self.0.push(Check {
            name,
            result: if pass { "pass" } else { "fail" },
        });
        pass
    }
    fn skip_rest(&mut self, names: &[&'static str]) {
        for n in names {
            if !self.0.iter().any(|c| c.name == *n) {
                self.0.push(Check {
                    name: n,
                    result: "skip",
                });
            }
        }
    }
}

/// Every check `verify` reports, in order.
pub const CHECKS: &[&str] = &[
    "embedded",
    "trust_plugin",
    "trust_catalog",
    "plugin_file",
    "plugin_digest_trust",
    "plugin_digest_embedded",
    "catalog_file",
    "catalog_digest_trust",
    "catalog_registry",
    "catalog_digest_embedded",
    "load",
];

#[allow(clippy::too_many_arguments)]
fn verify_one(
    view: &RootView,
    unreadable: bool,
    id: &str,
    version: &str,
    bundle: &'static [EmbeddedPlugin],
    registry: &[FirstPartyCatalog],
    m: &mut Vec<Message>,
) -> VerifyEntry {
    let e = bundle::embedded(bundle, id, version);
    let mut entry = VerifyEntry {
        id: id.to_string(),
        version: version.to_string(),
        status: "unknown",
        checks: Vec::new(),
        observe_attested: None,
        observe_total: None,
        mutate_allowed: None,
        mutate_total: None,
        required_not_enabled: Vec::new(),
    };
    let mut c = Checks(Vec::new());
    let finish = |mut entry: VerifyEntry, mut c: Checks, status: &'static str| {
        c.skip_rest(CHECKS);
        entry.checks = c.0;
        entry.status = status;
        entry
    };
    if unreadable {
        return finish(entry, c, "unknown");
    }
    let Some(e) = e else {
        c.push("embedded", false);
        m.push(Message(format!(
            "{}@{}: not a first-party plugin of this Sinter",
            id, version
        )));
        return finish(entry, c, "unsupported-by-this-sinter");
    };
    c.push("embedded", true);
    let Some(o) = view.opened.as_ref() else {
        if let Some(p) = permissions(e, None) {
            entry.observe_attested = Some(p.observe_attested);
            entry.observe_total = Some(p.observe_total);
            entry.mutate_allowed = Some(p.mutate_allowed);
            entry.mutate_total = Some(p.mutate_total);
        }
        c.push("trust_plugin", false);
        return finish(entry, c, "not-installed");
    };
    let tc = o
        .trust
        .catalogs
        .get(&(e.catalog_id.to_string(), e.catalog_version.to_string()));
    if let Some(p) = permissions(e, tc) {
        entry.observe_attested = Some(p.observe_attested);
        entry.observe_total = Some(p.observe_total);
        entry.mutate_allowed = Some(p.mutate_allowed);
        entry.mutate_total = Some(p.mutate_total);
        entry.required_not_enabled = p.required_not_enabled;
    }
    let pf = plugin_file(o, id, version, m);
    let cf = catalog_file(o, e.catalog_id, e.catalog_version, m);
    let tp = o.trust.plugins.get(&(id.to_string(), version.to_string()));
    let Some(tp) = tp else {
        c.push("trust_plugin", false);
        let status = if pf.present() || cf.present() {
            m.push(Message(format!(
                "{}@{}: files are present but the trust file does not pin the plugin",
                id, version
            )));
            "not-trusted"
        } else {
            "not-installed"
        };
        return finish(entry, c, status);
    };
    c.push("trust_plugin", true);
    if !c.push("trust_catalog", tc.is_some()) {
        m.push(Message(format!(
            "{}@{}: the trust file does not pin catalog {}@{}",
            id, version, e.catalog_id, e.catalog_version
        )));
        return finish(entry, c, "not-trusted");
    }
    let tc = tc.expect("checked above");
    let p = match &pf {
        FileState::Read(p) => {
            c.push("plugin_file", true);
            p
        }
        FileState::Missing => {
            c.push("plugin_file", false);
            m.push(Message(format!(
                "{}@{}: plugin file is missing",
                id, version
            )));
            return finish(entry, c, "missing-file");
        }
        FileState::Refused => {
            c.push("plugin_file", false);
            return finish(entry, c, "refused");
        }
    };
    let mut mismatch = false;
    mismatch |= !c.push("plugin_digest_trust", p.sha256 == tp.sha256);
    mismatch |= !c.push("plugin_digest_embedded", p.sha256 == e.plugin_sha256);
    let cat = match &cf {
        FileState::Read(x) => {
            c.push("catalog_file", true);
            x
        }
        FileState::Missing => {
            c.push("catalog_file", false);
            m.push(Message(format!(
                "{}@{}: catalog file is missing",
                id, version
            )));
            return finish(
                entry,
                c,
                if mismatch {
                    "digest-mismatch"
                } else {
                    "missing-file"
                },
            );
        }
        FileState::Refused => {
            c.push("catalog_file", false);
            return finish(entry, c, "refused");
        }
    };
    mismatch |= !c.push("catalog_digest_trust", cat.sha256 == tc.sha256);
    mismatch |= !c.push(
        "catalog_registry",
        registry
            .iter()
            .any(|f| f.id == tc.id && f.version == tc.version && f.sha256 == tc.sha256),
    );
    mismatch |= !c.push("catalog_digest_embedded", cat.sha256 == e.catalog_sha256);
    if mismatch {
        m.push(Message(format!(
            "{}@{}: a file or a trust pin differs from this Sinter's first-party files",
            id, version
        )));
        return finish(entry, c, "digest-mismatch");
    }
    let loaded = super::load_with(
        &o.root,
        &[PluginRef {
            id: id.to_string(),
            version: version.to_string(),
        }],
        registry,
        &mut |_| {},
    );
    match loaded {
        Ok(_) => {
            c.push("load", true);
            finish(entry, c, "ok")
        }
        Err(err) => {
            c.push("load", false);
            m.push(Message(err.message));
            finish(entry, c, "load-refused")
        }
    }
}

/// Parse `ID@VERSION` as `sinter plugin verify` takes it.
pub fn parse_target(s: &str) -> std::result::Result<PluginRef, String> {
    let Some((id, version)) = s.split_once('@') else {
        return Err("a plugin is named ID@VERSION (for example firewalld@0.2.0)".into());
    };
    if !verify::id_ok(id) || !verify::version_ok(version) {
        return Err("a plugin is named ID@VERSION (for example firewalld@0.2.0)".into());
    }
    Ok(PluginRef {
        id: id.to_string(),
        version: version.to_string(),
    })
}
