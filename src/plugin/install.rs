//! Plugin installation and removal (PM-3, DESIGN §38.16): `sinter plugin
//! install` and `sinter plugin remove`.
//!
//! Only the first-party files embedded in this Sinter are written, after
//! their digests are checked against the bundle and the release registry;
//! nothing is fetched and no other input becomes a file. The plugin root is
//! resolved as for every other command and opened with the protected
//! reader; every write goes through a checked directory descriptor
//! (`protect.rs`), never follows a symbolic link and never replaces a plugin
//! or catalog file. The trust file is the Owner's: install appends to it and
//! never changes an existing byte; remove rebuilds it and keeps the previous
//! content in `trust.toml.prev`. Every new trust file is parsed with the
//! loader's own parser before it is written, and the plugin is checked with
//! the loader afterwards (`manage::verify_with`).
//!
//! Each command plans first (read-only), the CLI shows the plan and asks for
//! the Owner's confirmation, and execution takes the root's lock, plans
//! again and refuses when anything changed. Exit codes (Owner decision D-5):
//! 0 success, nothing to do or a dry run; 2 refused with no change left; 5 a
//! failure after a change began (what remains is reported).
//!
//! Nothing here enables a plugin (a recipe does, §38.7), contacts a target or
//! is reachable from MCP.

use super::bundle::{self, EmbeddedPlugin};
use super::format::{CatalogFile, PluginFile, TrustFile, TrustedCatalog, TrustedPlugin};
use super::manage::{self, Message, Source};
use super::protect::{self, Ancestors, Entry, TrustedDir};
use super::verify::{self, TrustIndex};
use super::{FirstPartyCatalog, PluginRef, PluginRoot};
use crate::error::{Result, SinterError};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const TRUST: &str = "trust.toml";
const TRUST_PREV: &str = "trust.toml.prev";
const LOCK: &str = ".lock";
const MAX_TRUST_ENTRIES: usize = 64;

fn refuse(msg: impl Into<String>) -> SinterError {
    SinterError::schema(format!("plugin: {}", msg.into()))
}

/// The plugin root a command works on.
pub struct RootSpec {
    pub path: PathBuf,
    #[cfg(test)]
    pub(crate) boundary: Option<PathBuf>,
}

impl RootSpec {
    /// The CLI's plugin root, resolved as for plan, apply, list and verify.
    pub fn controller(explicit: Option<&Path>) -> Option<RootSpec> {
        match super::PluginContext::controller(explicit) {
            super::PluginContext::Root(path) => Some(RootSpec {
                path,
                #[cfg(test)]
                boundary: None,
            }),
            _ => None,
        }
    }

    fn ancestors(&self) -> Ancestors {
        #[cfg(test)]
        if let Some(b) = &self.boundary {
            return Ancestors::Below(b.clone());
        }
        Ancestors::All
    }

    fn shown(&self) -> String {
        protect::shown(&self.path)
    }

    fn open(&self) -> Result<TrustedDir> {
        TrustedDir::open_root(&self.path, &self.ancestors())
    }

    /// The loader-side verification of one plugin of this root.
    fn verify(
        &self,
        target: &PluginRef,
        bundle: &'static [EmbeddedPlugin],
        registry: &[FirstPartyCatalog],
    ) -> manage::VerifyReport {
        #[cfg(test)]
        if let Some(b) = &self.boundary {
            let b = b.clone();
            let open = move |p: &Path| PluginRoot::open_below(p, &b);
            return manage::verify_with(
                &Source::Root {
                    path: self.path.clone(),
                    open: &open,
                },
                std::slice::from_ref(target),
                bundle,
                registry,
            );
        }
        manage::verify_with(
            &Source::Root {
                path: self.path.clone(),
                open: &PluginRoot::open,
            },
            std::slice::from_ref(target),
            bundle,
            registry,
        )
    }
}

/// Where execution fails on purpose in tests (interruption and recovery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    AfterCatalogFile,
    AfterPluginFile,
    BeforeTrust,
    AfterTrust,
    AfterPrev,
    AfterPluginRemoved,
}

/// Test builds only: fail on purpose at `here`. In every other build the
/// injection point does nothing, whatever `at` is (production passes `None`).
#[cfg(test)]
fn fault(at: Option<Fault>, here: Fault) -> Result<()> {
    if at == Some(here) {
        return Err(refuse(format!("injected failure at {:?}", here)));
    }
    Ok(())
}

#[cfg(not(test))]
#[inline(always)]
fn fault(_at: Option<Fault>, _here: Fault) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// The report both commands print
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ChangeReport {
    pub format: u32,
    pub command: &'static str,
    pub plugin: String,
    pub plugin_root: Option<String>,
    pub dry_run: bool,
    /// `planned` (dry run), `installed`, `removed`, `nothing-to-do`,
    /// `refused` (nothing changed) or `partial` (a change began and did not
    /// finish; see the lists).
    pub result: &'static str,
    pub attested_observe: Vec<String>,
    pub allowed_mutate: Vec<String>,
    /// Mutate operations the plugin's types use that stay not allowed (plan
    /// and apply refuse resources that could need them, §38.4).
    pub mutate_not_allowed: Vec<String>,
    pub directories_created: Vec<String>,
    pub files_written: Vec<String>,
    pub files_removed: Vec<String>,
    /// `unchanged`, `created`, `appended` or `rewritten`.
    pub trust: &'static str,
    /// The loader's verdict on the plugin afterwards (`manage::verify`
    /// status), when it was checked.
    pub verify: Option<&'static str>,
    #[serde(skip)]
    pub messages: Vec<Message>,
}

impl ChangeReport {
    fn new(command: &'static str, target: &PluginRef, root: Option<String>, dry: bool) -> Self {
        ChangeReport {
            format: manage::REPORT_FORMAT,
            command,
            plugin: format!("{}@{}", target.id, target.version),
            plugin_root: root,
            dry_run: dry,
            result: "refused",
            attested_observe: Vec::new(),
            allowed_mutate: Vec::new(),
            mutate_not_allowed: Vec::new(),
            directories_created: Vec::new(),
            files_written: Vec::new(),
            files_removed: Vec::new(),
            trust: "unchanged",
            verify: None,
            messages: Vec::new(),
        }
    }

    /// 0 success / nothing to do / dry run, 2 refused with nothing changed,
    /// 5 partial (DESIGN §33, §38.16).
    pub fn exit_code(&self) -> u8 {
        match self.result {
            "planned" | "installed" | "removed" | "nothing-to-do" => 0,
            "partial" => 5,
            _ => 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Reading the root (shared)
// ---------------------------------------------------------------------------

/// A file the command may write or remove, as it is now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileNow {
    Absent,
    /// Present with exactly the embedded bytes.
    Same,
}

struct RootNow {
    /// Directories that do not exist yet (shown paths), outermost first.
    to_create: Vec<String>,
    catalogs: Option<TrustedDir>,
    plugins: Option<TrustedDir>,
    trust_bytes: Option<Vec<u8>>,
    trust: TrustIndex,
    trust_file: Option<TrustFile>,
}

fn sub_now(root: &TrustedDir, name: &str) -> Result<Option<TrustedDir>> {
    match root.entry(name)? {
        Entry::Absent => Ok(None),
        Entry::Dir => Ok(Some(root.subdir(name)?)),
        _ => Err(refuse(format!(
            "{}/{}: not a directory (a symbolic link or file is refused)",
            root.shown(),
            name
        ))),
    }
}

fn read_root(spec: &RootSpec) -> Result<RootNow> {
    let missing = protect::create_missing_dirs_plan(&spec.path, &spec.ancestors())?;
    if !missing.is_empty() {
        let mut to_create: Vec<String> = missing.iter().map(|p| protect::shown(p)).collect();
        to_create.push(format!("{}/catalogs", spec.shown()));
        to_create.push(format!("{}/plugins", spec.shown()));
        return Ok(RootNow {
            to_create,
            catalogs: None,
            plugins: None,
            trust_bytes: None,
            trust: TrustIndex {
                catalogs: BTreeMap::new(),
                plugins: BTreeMap::new(),
            },
            trust_file: None,
        });
    }
    let root = spec.open()?;
    let catalogs = sub_now(&root, "catalogs")?;
    let plugins = sub_now(&root, "plugins")?;
    let mut to_create = Vec::new();
    if catalogs.is_none() {
        to_create.push(format!("{}/catalogs", root.shown()));
    }
    if plugins.is_none() {
        to_create.push(format!("{}/plugins", root.shown()));
    }
    let (trust_bytes, trust, trust_file) = match root.entry(TRUST)? {
        Entry::Absent => (
            None,
            TrustIndex {
                catalogs: BTreeMap::new(),
                plugins: BTreeMap::new(),
            },
            None,
        ),
        Entry::File => {
            let f = root.read_file_with(TRUST, verify::MAX_FILE_BYTES, &mut || {})?;
            let shown = format!("{}/{}", root.shown(), TRUST);
            let idx = verify::verify_trust(&f.bytes, &shown)?;
            let tf: TrustFile = verify::parse(&f.bytes, &shown)?;
            (Some(f.bytes), idx, Some(tf))
        }
        _ => {
            return Err(refuse(format!(
                "{}/{}: not a regular file (a symbolic link is refused)",
                root.shown(),
                TRUST
            )))
        }
    };
    Ok(RootNow {
        to_create,
        catalogs,
        plugins,
        trust_bytes,
        trust,
        trust_file,
    })
}

/// The state of one embedded file in its directory: absent, or present with
/// exactly `want`'s bytes. Anything else (other bytes, a link, unreadable)
/// is a refusal: an existing file is never replaced.
fn file_now(dir: Option<&TrustedDir>, name: &str, want_sha: &str) -> Result<FileNow> {
    let Some(d) = dir else {
        return Ok(FileNow::Absent);
    };
    match d.entry(name)? {
        Entry::Absent => Ok(FileNow::Absent),
        Entry::File => {
            let f = d.read_file_with(name, verify::MAX_FILE_BYTES, &mut || {})?;
            if f.sha256 == want_sha {
                Ok(FileNow::Same)
            } else {
                Err(refuse(format!(
                    "{}/{}: exists with other bytes than this Sinter's first-party file; it is never replaced or removed (check it with `sinter plugin verify`)",
                    d.shown(),
                    name
                )))
            }
        }
        _ => Err(refuse(format!(
            "{}/{}: not a regular file (a symbolic link is refused)",
            d.shown(),
            name
        ))),
    }
}

fn sha(b: &Option<Vec<u8>>) -> Option<String> {
    b.as_ref().map(|b| protect::sha256_hex(b))
}

fn catalog_name(e: &EmbeddedPlugin) -> String {
    format!("{}-{}.catalog.toml", e.catalog_id, e.catalog_version)
}

fn plugin_name(e: &EmbeddedPlugin) -> String {
    format!("{}-{}.plugin.toml", e.id, e.version)
}

fn embedded_for(
    target: &PluginRef,
    bundle: &'static [EmbeddedPlugin],
    registry: &[FirstPartyCatalog],
) -> Result<&'static EmbeddedPlugin> {
    bundle::consistent(bundle, registry).map_err(refuse)?;
    bundle::embedded(bundle, &target.id, &target.version).ok_or_else(|| {
        refuse(format!(
            "{}@{} is not a first-party plugin of this Sinter (see `sinter plugin list`)",
            target.id, target.version
        ))
    })
}

fn list_text(ops: &[String]) -> String {
    format!(
        "[{}]",
        ops.iter()
            .map(|o| format!("\"{}\"", o))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn catalog_entry_text(
    id: &str,
    version: &str,
    sha: &str,
    obs: &[String],
    mutate: &[String],
) -> String {
    format!(
        "[[catalog]]\nid = \"{}\"\nversion = \"{}\"\nsha256 = \"{}\"\nattested_observe = {}\nallowed_mutate = {}\n",
        id,
        version,
        sha,
        list_text(obs),
        list_text(mutate)
    )
}

fn plugin_entry_text(id: &str, version: &str, sha: &str) -> String {
    format!(
        "[[plugin]]\nid = \"{}\"\nversion = \"{}\"\nsha256 = \"{}\"\n",
        id, version, sha
    )
}

fn same_catalog(a: &TrustedCatalog, b: &TrustedCatalog) -> bool {
    let set = |v: &[String]| v.iter().cloned().collect::<BTreeSet<_>>();
    a.id == b.id
        && a.version == b.version
        && a.sha256 == b.sha256
        && set(&a.attested_observe) == set(&b.attested_observe)
        && set(&a.allowed_mutate) == set(&b.allowed_mutate)
}

fn same_plugin(a: &TrustedPlugin, b: &TrustedPlugin) -> bool {
    a.id == b.id && a.version == b.version && a.sha256 == b.sha256
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

/// What the Owner asks install to allow.
#[derive(Debug, Clone, Default)]
pub struct InstallRequest {
    pub target: Option<PluginRef>,
    /// Mutate operations named one by one (`--allow-mutate`).
    pub allow_mutate: Vec<String>,
    /// Resource types whose ensure operations are allowed
    /// (`--allow-mutate-for`), expanded and shown before confirmation.
    pub allow_mutate_for: Vec<String>,
}

/// What install would do, computed without changing anything.
#[derive(Debug, Clone)]
pub struct InstallPlan {
    pub target: PluginRef,
    pub plugin_root: String,
    pub dirs_to_create: Vec<String>,
    pub catalog_file: FileNow,
    pub plugin_file: FileNow,
    pub catalog_file_name: String,
    pub plugin_file_name: String,
    pub trust_before_sha: Option<String>,
    /// The whole new trust file, when it changes.
    pub new_trust: Option<Vec<u8>>,
    pub add_catalog_entry: bool,
    pub add_plugin_entry: bool,
    /// Every observe operation of the catalog: what the confirmation attests.
    pub attested_observe: Vec<String>,
    pub allowed_mutate: Vec<String>,
    pub mutate_not_allowed: Vec<String>,
    /// For each `--allow-mutate-for` type, the operations it expanded to.
    pub expanded: Vec<(String, Vec<String>)>,
    pub nothing_to_do: bool,
}

impl InstallPlan {
    /// What must not change between the confirmation and the writes.
    fn fingerprint(&self) -> (Option<String>, Option<Vec<u8>>, FileNow, FileNow) {
        (
            self.trust_before_sha.clone(),
            self.new_trust.clone(),
            self.catalog_file.clone(),
            self.plugin_file.clone(),
        )
    }
}

pub fn plan_install(spec: &RootSpec, req: &InstallRequest) -> Result<InstallPlan> {
    plan_install_with(
        spec,
        req,
        bundle::FIRST_PARTY_BUNDLE,
        super::FIRST_PARTY_CATALOGS,
    )
}

pub(crate) fn plan_install_with(
    spec: &RootSpec,
    req: &InstallRequest,
    bundle: &'static [EmbeddedPlugin],
    registry: &[FirstPartyCatalog],
) -> Result<InstallPlan> {
    let target = req
        .target
        .clone()
        .ok_or_else(|| refuse("install needs ID@VERSION"))?;
    let e = embedded_for(&target, bundle, registry)?;
    let catalog: CatalogFile = verify::parse(e.catalog, "embedded catalog")?;
    let plugin: PluginFile = verify::parse(e.plugin, "embedded plugin")?;
    let class: BTreeMap<&str, &str> = catalog
        .op
        .iter()
        .map(|o| (o.id.as_str(), o.class.as_str()))
        .collect();

    // What is attested and allowed.
    let observe: Vec<String> = catalog
        .op
        .iter()
        .filter(|o| o.class == "observe")
        .map(|o| o.id.clone())
        .collect();
    let mut wanted: BTreeSet<String> = BTreeSet::new();
    for op in &req.allow_mutate {
        match class.get(op.as_str()) {
            Some(&"mutate") => {
                wanted.insert(op.clone());
            }
            Some(_) => {
                return Err(refuse(format!(
                    "--allow-mutate {}: an observe operation, not a mutate operation",
                    op
                )))
            }
            None => {
                return Err(refuse(format!(
                    "--allow-mutate {}: not an operation of catalog {}@{}",
                    op, e.catalog_id, e.catalog_version
                )))
            }
        }
    }
    let mut expanded = Vec::new();
    for t in &req.allow_mutate_for {
        let Some(ty) = plugin.types.iter().find(|x| &x.name == t) else {
            let names: Vec<&str> = plugin.types.iter().map(|x| x.name.as_str()).collect();
            return Err(refuse(format!(
                "--allow-mutate-for {}: not a type of {}@{} (its types: {})",
                t,
                target.id,
                target.version,
                names.join(", ")
            )));
        };
        let mut ops: BTreeSet<String> = BTreeSet::new();
        for f in &ty.facet {
            ops.extend(f.ensure.values().cloned());
        }
        wanted.extend(ops.iter().cloned());
        expanded.push((t.clone(), in_catalog_order(&catalog, &ops)));
    }
    let allowed = in_catalog_order(&catalog, &wanted);
    let mut used: BTreeSet<String> = BTreeSet::new();
    for t in &plugin.types {
        for f in &t.facet {
            used.extend(f.ensure.values().cloned());
        }
    }
    let not_allowed: Vec<String> =
        in_catalog_order(&catalog, &used.difference(&wanted).cloned().collect());

    // The root as it is now.
    let now = read_root(spec)?;
    let cname = catalog_name(e);
    let pname = plugin_name(e);
    let catalog_file = file_now(now.catalogs.as_ref(), &cname, e.catalog_sha256)?;
    let plugin_file = file_now(now.plugins.as_ref(), &pname, e.plugin_sha256)?;

    let ckey = (e.catalog_id.to_string(), e.catalog_version.to_string());
    let pkey = (e.id.to_string(), e.version.to_string());
    let want_catalog = TrustedCatalog {
        id: e.catalog_id.to_string(),
        version: e.catalog_version.to_string(),
        sha256: e.catalog_sha256.to_string(),
        attested_observe: observe.clone(),
        allowed_mutate: allowed.clone(),
    };
    let want_plugin = TrustedPlugin {
        id: e.id.to_string(),
        version: e.version.to_string(),
        sha256: e.plugin_sha256.to_string(),
    };
    let add_catalog_entry = match now.trust.catalogs.get(&ckey) {
        None => true,
        Some(c) if same_catalog(c, &want_catalog) => false,
        Some(c) => {
            return Err(refuse(format!(
                "the trust file already has an entry for catalog {}@{} that differs from this request (it attests {} and allows {}; requested: attest {} and allow {}). install never changes an existing entry: repeat the same permissions, or edit trust.toml yourself",
                e.catalog_id,
                e.catalog_version,
                list_text(&c.attested_observe),
                list_text(&c.allowed_mutate),
                list_text(&observe),
                list_text(&allowed)
            )))
        }
    };
    let add_plugin_entry = match now.trust.plugins.get(&pkey) {
        None => true,
        Some(p) if same_plugin(p, &want_plugin) => false,
        Some(_) => {
            return Err(refuse(format!(
                "the trust file pins {}@{} with another digest than this Sinter's first-party file; install never changes an existing entry",
                e.id, e.version
            )))
        }
    };
    if (add_catalog_entry && now.trust.catalogs.len() + 1 > MAX_TRUST_ENTRIES)
        || (add_plugin_entry && now.trust.plugins.len() + 1 > MAX_TRUST_ENTRIES)
    {
        return Err(refuse(format!(
            "the trust file would have more than {} catalog or plugin entries",
            MAX_TRUST_ENTRIES
        )));
    }

    let new_trust = if add_catalog_entry || add_plugin_entry {
        let mut text = match &now.trust_bytes {
            Some(b) => String::from_utf8(b.clone())
                .map_err(|_| refuse("the trust file is not valid UTF-8"))?,
            None => "format = 1\n".to_string(),
        };
        if !text.ends_with('\n') {
            text.push('\n');
        }
        if add_catalog_entry {
            text.push('\n');
            text.push_str(&catalog_entry_text(
                e.catalog_id,
                e.catalog_version,
                e.catalog_sha256,
                &observe,
                &allowed,
            ));
        }
        if add_plugin_entry {
            text.push('\n');
            text.push_str(&plugin_entry_text(e.id, e.version, e.plugin_sha256));
        }
        let bytes = text.into_bytes();
        if bytes.len() > verify::MAX_FILE_BYTES {
            return Err(refuse("the trust file would exceed the 64 KiB limit"));
        }
        // The loader's parser must read exactly the old entries plus the new.
        let shown = format!("{}/{}", spec.shown(), TRUST);
        let idx = verify::verify_trust(&bytes, &shown)?;
        let mut expect_c = now.trust.catalogs.keys().cloned().collect::<BTreeSet<_>>();
        let mut expect_p = now.trust.plugins.keys().cloned().collect::<BTreeSet<_>>();
        expect_c.insert(ckey.clone());
        expect_p.insert(pkey.clone());
        let ok = idx.catalogs.keys().cloned().collect::<BTreeSet<_>>() == expect_c
            && idx.plugins.keys().cloned().collect::<BTreeSet<_>>() == expect_p
            && now
                .trust
                .catalogs
                .iter()
                .all(|(k, v)| idx.catalogs.get(k).is_some_and(|n| same_catalog(n, v)))
            && now
                .trust
                .plugins
                .iter()
                .all(|(k, v)| idx.plugins.get(k).is_some_and(|n| same_plugin(n, v)))
            && idx
                .catalogs
                .get(&ckey)
                .is_some_and(|n| same_catalog(n, &want_catalog))
            && idx
                .plugins
                .get(&pkey)
                .is_some_and(|n| same_plugin(n, &want_plugin));
        if !ok {
            return Err(refuse(
                "the appended trust file does not read back as the old entries plus the new ones; nothing was written",
            ));
        }
        Some(bytes)
    } else {
        None
    };

    // The loader's own verification of the embedded files under the
    // resulting trust entries, before anything is written.
    {
        let shown = format!("{}/{}", spec.shown(), TRUST);
        let idx = match &new_trust {
            Some(b) => verify::verify_trust(b, &shown)?,
            None => TrustIndex {
                catalogs: now
                    .trust
                    .catalogs
                    .iter()
                    .map(|(k, v)| (k.clone(), clone_catalog(v)))
                    .collect(),
                plugins: now
                    .trust
                    .plugins
                    .iter()
                    .map(|(k, v)| (k.clone(), clone_plugin(v)))
                    .collect(),
            },
        };
        let tc = idx
            .catalogs
            .get(&ckey)
            .ok_or_else(|| refuse("internal: no catalog entry"))?;
        let tp = idx
            .plugins
            .get(&pkey)
            .ok_or_else(|| refuse("internal: no plugin entry"))?;
        let vc = verify::verify_catalog(
            e.catalog,
            e.catalog_sha256,
            &format!("{}/catalogs/{}", spec.shown(), cname),
            tc,
            registry,
        )?;
        let mut cats = BTreeMap::new();
        cats.insert(ckey.clone(), vc);
        verify::verify_plugin(
            e.plugin,
            e.plugin_sha256,
            &format!("{}/plugins/{}", spec.shown(), pname),
            tp,
            &cats,
        )?;
    }

    let nothing_to_do = now.to_create.is_empty()
        && catalog_file == FileNow::Same
        && plugin_file == FileNow::Same
        && new_trust.is_none();
    Ok(InstallPlan {
        target,
        plugin_root: spec.shown(),
        dirs_to_create: now.to_create,
        catalog_file,
        plugin_file,
        catalog_file_name: cname,
        plugin_file_name: pname,
        trust_before_sha: sha(&now.trust_bytes),
        new_trust,
        add_catalog_entry,
        add_plugin_entry,
        attested_observe: observe,
        allowed_mutate: allowed,
        mutate_not_allowed: not_allowed,
        expanded,
        nothing_to_do,
    })
}

fn clone_catalog(c: &TrustedCatalog) -> TrustedCatalog {
    TrustedCatalog {
        id: c.id.clone(),
        version: c.version.clone(),
        sha256: c.sha256.clone(),
        attested_observe: c.attested_observe.clone(),
        allowed_mutate: c.allowed_mutate.clone(),
    }
}

fn clone_plugin(p: &TrustedPlugin) -> TrustedPlugin {
    TrustedPlugin {
        id: p.id.clone(),
        version: p.version.clone(),
        sha256: p.sha256.clone(),
    }
}

fn in_catalog_order(catalog: &CatalogFile, set: &BTreeSet<String>) -> Vec<String> {
    catalog
        .op
        .iter()
        .filter(|o| set.contains(&o.id))
        .map(|o| o.id.clone())
        .collect()
}

/// Fill a report with what a plan says.
pub fn plan_report(command: &'static str, plan: &InstallPlan, dry: bool) -> ChangeReport {
    let mut r = ChangeReport::new(command, &plan.target, Some(plan.plugin_root.clone()), dry);
    r.attested_observe = plan.attested_observe.clone();
    r.allowed_mutate = plan.allowed_mutate.clone();
    r.mutate_not_allowed = plan.mutate_not_allowed.clone();
    r.result = if plan.nothing_to_do {
        "nothing-to-do"
    } else {
        "planned"
    };
    r
}

/// A refusal before anything was planned or changed.
pub fn refused_report(
    command: &'static str,
    target: &PluginRef,
    root: Option<String>,
    dry: bool,
    e: SinterError,
) -> ChangeReport {
    let mut r = ChangeReport::new(command, target, root, dry);
    r.messages.push(Message(e.message));
    r
}

/// Undo what this run created before the trust file changed. `Ok` when
/// everything was removed.
struct Undo {
    /// Files this run created: (directory, name, expected SHA-256). Only a
    /// file that still has exactly these bytes is removed again.
    placed: Vec<(PathBuf, String, &'static str)>,
    /// Directories created, outermost first (removed innermost first).
    dirs: Vec<PathBuf>,
    /// The root itself was created by this run (its lock file goes too).
    root_created: bool,
    root: PathBuf,
}

impl Undo {
    fn run(&self, spec: &RootSpec, messages: &mut Vec<Message>) -> bool {
        let mut clean = true;
        let open_dir =
            |p: &Path| -> Result<TrustedDir> { TrustedDir::open_root(p, &spec.ancestors()) };
        for (dir, name, want) in self.placed.iter().rev() {
            // Remove only this run's file: read it again and compare first.
            let res = open_dir(dir).and_then(|d| {
                let f = d.read_file_with(name, verify::MAX_FILE_BYTES, &mut || {})?;
                if f.sha256 != *want {
                    return Err(refuse(format!(
                        "{}/{}: no longer the file this run wrote; it is left in place",
                        d.shown(),
                        name
                    )));
                }
                d.remove_file_synced(name).map_err(|w| {
                    if w.published {
                        refuse(format!(
                            "{} (the file was removed, but making that durable failed)",
                            w.error.message
                        ))
                    } else {
                        w.error
                    }
                })
            });
            if let Err(e) = res {
                clean = false;
                messages.push(Message(format!("could not undo: {}", e.message)));
            }
        }
        if self.root_created {
            if let Ok(d) = open_dir(&self.root) {
                let _ = d.remove_file(LOCK);
            }
        }
        for dir in self.dirs.iter().rev() {
            let (Some(parent), Some(name)) =
                (dir.parent(), dir.file_name().and_then(|n| n.to_str()))
            else {
                clean = false;
                continue;
            };
            // The parent of the outermost created directory is an existing
            // ancestor, opened with the ancestor rules only.
            let res = if dir.starts_with(&self.root) && dir != &self.root {
                open_dir(parent)
            } else {
                protect::open_dir_relaxed(parent, &spec.ancestors())
            }
            .and_then(|d| d.remove_dir(name).and_then(|_| d.sync()));
            // (A directory is removed only when it is empty: never another's.)
            if let Err(e) = res {
                clean = false;
                messages.push(Message(format!("could not undo: {}", e.message)));
            }
        }
        clean
    }
}

/// Install as planned (the Owner confirmed the plan). Takes the root's lock,
/// plans again and refuses when anything changed since `plan`.
pub fn execute_install(spec: &RootSpec, req: &InstallRequest, plan: &InstallPlan) -> ChangeReport {
    execute_install_with(
        spec,
        req,
        plan,
        bundle::FIRST_PARTY_BUNDLE,
        super::FIRST_PARTY_CATALOGS,
        None,
    )
}

pub(crate) fn execute_install_with(
    spec: &RootSpec,
    req: &InstallRequest,
    plan: &InstallPlan,
    bundle: &'static [EmbeddedPlugin],
    registry: &[FirstPartyCatalog],
    at: Option<Fault>,
) -> ChangeReport {
    let mut r = plan_report("install", plan, false);
    if plan.nothing_to_do {
        r.verify = Some(
            spec.verify(&plan.target, bundle, registry)
                .plugins
                .first()
                .map(|p| p.status)
                .unwrap_or("unknown"),
        );
        return r;
    }
    r.result = "refused";
    let mut undo = Undo {
        placed: Vec::new(),
        dirs: Vec::new(),
        root_created: false,
        root: spec.path.clone(),
    };
    let e = match embedded_for(&plan.target, bundle, registry) {
        Ok(e) => e,
        Err(err) => {
            r.messages.push(Message(err.message));
            return r;
        }
    };
    let mut trust_written = false;
    let outcome = (|| -> Result<()> {
        // Directories, from the deepest existing ancestor. Each directory is
        // recorded for the undo as soon as it exists, also when a later step
        // (its fsync, its checks) fails.
        let (created, failed) = match protect::create_missing_dirs(&spec.path, &spec.ancestors()) {
            Ok(c) => (c, None),
            Err((e, c)) => (c, Some(e)),
        };
        undo.root_created = created.iter().any(|p| p == &spec.path);
        for p in &created {
            r.directories_created.push(protect::shown(p));
        }
        undo.dirs.extend(created);
        if let Some(e) = failed {
            return Err(e);
        }
        let root = spec.open()?;
        let _lock = root.lock(LOCK)?;
        let mut sub = |name: &str| -> Result<TrustedDir> {
            let (made, d) = match root.make_dir(name) {
                Ok(x) => x,
                Err(w) => {
                    if w.published {
                        undo.dirs.push(spec.path.join(name));
                        r.directories_created
                            .push(format!("{}/{}", root.shown(), name));
                    }
                    return Err(w.error);
                }
            };
            if made {
                undo.dirs.push(spec.path.join(name));
                r.directories_created
                    .push(format!("{}/{}", root.shown(), name));
            }
            Ok(d)
        };
        let cdir = sub("catalogs")?;
        let pdir = sub("plugins")?;
        root.sync()?;
        // Plan again under the lock: nothing may have changed.
        let again = plan_install_with(spec, req, bundle, registry)?;
        if again.fingerprint() != plan.fingerprint() {
            return Err(refuse(
                "the plugin root changed after the plan was shown; nothing was installed (run the command again)",
            ));
        }
        // A file is recorded for the undo as soon as its link exists, also
        // when only the directory's fsync failed (R1-02).
        let mut place = |dir: &TrustedDir,
                         sub: &str,
                         name: &str,
                         bytes: &[u8],
                         sha: &'static str|
         -> Result<()> {
            let res = dir.place_new_file(name, bytes);
            let published = match &res {
                Ok(()) => true,
                Err(w) => w.published,
            };
            if published {
                undo.placed
                    .push((spec.path.join(sub), name.to_string(), sha));
                r.files_written.push(format!("{}/{}", sub, name));
            }
            res.map_err(|w| w.error)
        };
        if plan.catalog_file == FileNow::Absent {
            place(
                &cdir,
                "catalogs",
                &plan.catalog_file_name,
                e.catalog,
                e.catalog_sha256,
            )?;
        }
        fault(at, Fault::AfterCatalogFile)?;
        if plan.plugin_file == FileNow::Absent {
            place(
                &pdir,
                "plugins",
                &plan.plugin_file_name,
                e.plugin,
                e.plugin_sha256,
            )?;
        }
        fault(at, Fault::AfterPluginFile)?;
        if let Some(new) = &plan.new_trust {
            // The trust file must still be exactly what was planned on.
            let current = match root.entry(TRUST)? {
                Entry::Absent => None,
                Entry::File => Some(
                    root.read_file_with(TRUST, verify::MAX_FILE_BYTES, &mut || {})?
                        .sha256,
                ),
                _ => {
                    return Err(refuse(format!(
                        "{}/{}: not a regular file",
                        root.shown(),
                        TRUST
                    )))
                }
            };
            if current != plan.trust_before_sha {
                return Err(refuse(
                    "the trust file changed after the plan was shown; nothing was installed (run the command again)",
                ));
            }
            fault(at, Fault::BeforeTrust)?;
            // Once the link or rename took place the new trust file is
            // visible, even when the directory's fsync then fails (R1-01):
            // from here nothing is undone and a failure is partial (5).
            let (res, what) = match current {
                None => (root.place_new_file(TRUST, new), "created"),
                Some(_) => (root.replace_file(TRUST, new), "appended"),
            };
            let published = match &res {
                Ok(()) => true,
                Err(w) => w.published,
            };
            if published {
                trust_written = true;
                r.trust = what;
            }
            res.map_err(|w| {
                if w.published {
                    refuse(format!(
                        "{} (trust.toml was {} and is in effect, but making that durable failed: after a crash the file may be the new one or the previous one)",
                        w.error.message, what
                    ))
                } else {
                    w.error
                }
            })?;
        }
        fault(at, Fault::AfterTrust)?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let v = spec.verify(&plan.target, bundle, registry);
            let status = v.plugins.first().map(|p| p.status).unwrap_or("unknown");
            r.verify = Some(status);
            if status == "ok" {
                r.result = "installed";
            } else {
                r.result = "partial";
                r.messages.extend(v.messages);
                r.messages.push(Message(format!(
                    "installed, but the loader's verification reports {}; check with `sinter plugin verify {}`",
                    status, r.plugin
                )));
            }
        }
        Err(err) => {
            r.messages.push(Message(err.message));
            if trust_written {
                r.result = "partial";
                r.messages.push(Message(
                    "the trust entries were written (the files listed are in place and nothing was undone), but the installation did not finish; check with `sinter plugin verify`".into(),
                ));
            } else if undo.run(spec, &mut r.messages) {
                r.result = "refused";
                r.directories_created.clear();
                r.files_written.clear();
            } else {
                r.result = "partial";
                r.messages.push(Message(
                    "some of what this run created could not be removed (listed); the trust file is unchanged, so the loader uses none of it".into(),
                ));
            }
        }
    }
    r
}

// ---------------------------------------------------------------------------
// remove
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RemovePlan {
    pub target: PluginRef,
    pub plugin_root: String,
    pub trust_before_sha: Option<String>,
    trust_before: Vec<u8>,
    pub new_trust: Option<Vec<u8>>,
    pub remove_plugin_entry: bool,
    pub remove_catalog_entry: bool,
    pub delete_plugin_file: bool,
    pub delete_catalog_file: bool,
    pub catalog_file_name: String,
    pub plugin_file_name: String,
    /// Why the catalog stays: `used-by-another-plugin` or `use-unknown`.
    pub catalog_kept: Option<&'static str>,
    /// The rewrite drops comments or formatting of the current trust file.
    pub formatting_lost: bool,
    pub nothing_to_do: bool,
}

impl RemovePlan {
    fn fingerprint(&self) -> (Option<String>, Option<Vec<u8>>, bool, bool) {
        (
            self.trust_before_sha.clone(),
            self.new_trust.clone(),
            self.delete_plugin_file,
            self.delete_catalog_file,
        )
    }
}

fn rebuild_trust(
    tf: &TrustFile,
    drop_catalog: Option<&(String, String)>,
    drop_plugin: &(String, String),
) -> Vec<u8> {
    let mut text = "format = 1\n".to_string();
    for c in &tf.catalog {
        if drop_catalog.is_some_and(|k| k.0 == c.id && k.1 == c.version) {
            continue;
        }
        text.push('\n');
        text.push_str(&catalog_entry_text(
            &c.id,
            &c.version,
            &c.sha256,
            &c.attested_observe,
            &c.allowed_mutate,
        ));
    }
    for p in &tf.plugin {
        if p.id == drop_plugin.0 && p.version == drop_plugin.1 {
            continue;
        }
        text.push('\n');
        text.push_str(&plugin_entry_text(&p.id, &p.version, &p.sha256));
    }
    text.into_bytes()
}

pub fn plan_remove(spec: &RootSpec, target: &PluginRef) -> Result<RemovePlan> {
    plan_remove_with(
        spec,
        target,
        bundle::FIRST_PARTY_BUNDLE,
        super::FIRST_PARTY_CATALOGS,
    )
}

pub(crate) fn plan_remove_with(
    spec: &RootSpec,
    target: &PluginRef,
    bundle: &'static [EmbeddedPlugin],
    registry: &[FirstPartyCatalog],
) -> Result<RemovePlan> {
    let e = embedded_for(target, bundle, registry)?;
    let cname = catalog_name(e);
    let pname = plugin_name(e);
    let mut plan = RemovePlan {
        target: target.clone(),
        plugin_root: spec.shown(),
        trust_before_sha: None,
        trust_before: Vec::new(),
        new_trust: None,
        remove_plugin_entry: false,
        remove_catalog_entry: false,
        delete_plugin_file: false,
        delete_catalog_file: false,
        catalog_file_name: cname.clone(),
        plugin_file_name: pname.clone(),
        catalog_kept: None,
        formatting_lost: false,
        nothing_to_do: false,
    };
    if std::fs::symlink_metadata(&spec.path).is_err() {
        // No root: nothing is installed.
        plan.nothing_to_do = true;
        return Ok(plan);
    }
    let now = read_root(spec)?;
    let pkey = (e.id.to_string(), e.version.to_string());
    let ckey = (e.catalog_id.to_string(), e.catalog_version.to_string());
    let plugin_present = match now.plugins.as_ref() {
        Some(d) => d.entry(&pname)? != Entry::Absent,
        None => false,
    };
    let Some(tp) = now.trust.plugins.get(&pkey) else {
        if plugin_present {
            return Err(refuse(format!(
                "{}@{}: its file is present but the trust file does not pin it; remove only acts on an installed plugin (remove the file yourself)",
                e.id, e.version
            )));
        }
        plan.nothing_to_do = true;
        return Ok(plan);
    };
    if tp.sha256 != e.plugin_sha256 {
        return Err(refuse(format!(
            "the trust file pins {}@{} with another digest than this Sinter's first-party file; edit trust.toml yourself",
            e.id, e.version
        )));
    }
    plan.remove_plugin_entry = true;
    // The plugin file must be exactly the pinned first-party file.
    plan.delete_plugin_file =
        file_now(now.plugins.as_ref(), &pname, e.plugin_sha256)? == FileNow::Same;

    // Does another trusted plugin use the catalog?
    let mut kept: Option<&'static str> = None;
    for (k, p) in &now.trust.plugins {
        if k == &pkey {
            continue;
        }
        let uses = match bundle::embedded(bundle, &p.id, &p.version) {
            Some(o) if o.plugin_sha256 == p.sha256 => {
                Some(o.catalog_id == e.catalog_id && o.catalog_version == e.catalog_version)
            }
            _ => other_plugin_catalog(now.plugins.as_ref(), p)
                .map(|c| c.id == e.catalog_id && c.version == e.catalog_version),
        };
        match uses {
            Some(true) => {
                kept = Some("used-by-another-plugin");
                break;
            }
            Some(false) => {}
            None => kept = kept.or(Some("use-unknown")),
        }
    }
    plan.catalog_kept = kept;
    if kept.is_none() {
        if let Some(tc) = now.trust.catalogs.get(&ckey) {
            if tc.sha256 != e.catalog_sha256 {
                return Err(refuse(format!(
                    "the trust file pins catalog {}@{} with another digest than this Sinter's first-party file; edit trust.toml yourself",
                    e.catalog_id, e.catalog_version
                )));
            }
            plan.remove_catalog_entry = true;
        }
        plan.delete_catalog_file =
            file_now(now.catalogs.as_ref(), &cname, e.catalog_sha256)? == FileNow::Same;
    }

    let tf = now
        .trust_file
        .as_ref()
        .ok_or_else(|| refuse("internal: no trust file"))?;
    let before = now.trust_bytes.clone().unwrap_or_default();
    let new = rebuild_trust(tf, plan.remove_catalog_entry.then_some(&ckey), &pkey);
    let shown = format!("{}/{}", spec.shown(), TRUST);
    let idx = verify::verify_trust(&new, &shown)?;
    let mut expect_c: BTreeSet<_> = now.trust.catalogs.keys().cloned().collect();
    let mut expect_p: BTreeSet<_> = now.trust.plugins.keys().cloned().collect();
    if plan.remove_catalog_entry {
        expect_c.remove(&ckey);
    }
    expect_p.remove(&pkey);
    let ok = idx.catalogs.keys().cloned().collect::<BTreeSet<_>>() == expect_c
        && idx.plugins.keys().cloned().collect::<BTreeSet<_>>() == expect_p
        && idx.catalogs.iter().all(|(k, v)| {
            now.trust
                .catalogs
                .get(k)
                .is_some_and(|o| same_catalog(o, v))
        })
        && idx
            .plugins
            .iter()
            .all(|(k, v)| now.trust.plugins.get(k).is_some_and(|o| same_plugin(o, v)));
    if !ok {
        return Err(refuse(
            "the rebuilt trust file does not read back as the old entries without this plugin; nothing was written",
        ));
    }
    plan.formatting_lost = rebuild_trust_all(tf) != before;
    plan.trust_before_sha = Some(protect::sha256_hex(&before));
    plan.trust_before = before;
    plan.new_trust = Some(new);
    Ok(plan)
}

/// The trust file rebuilt without removing anything: equal to the current
/// bytes only when the rewrite keeps everything (no comments, same layout).
fn rebuild_trust_all(tf: &TrustFile) -> Vec<u8> {
    rebuild_trust(tf, None, &(String::new(), String::new()))
}

/// The catalog another pinned plugin names, read from its pinned bytes
/// through the protected reader; `None` when it cannot be told.
fn other_plugin_catalog(dir: Option<&TrustedDir>, p: &TrustedPlugin) -> Option<super::CatalogRef> {
    let d = dir?;
    let name = format!("{}-{}.plugin.toml", p.id, p.version);
    let f = d
        .read_file_with(&name, verify::MAX_FILE_BYTES, &mut || {})
        .ok()?;
    if f.sha256 != p.sha256 {
        return None;
    }
    super::catalog_ref_of(&f.bytes, &name).ok()
}

pub fn remove_report(plan: &RemovePlan, dry: bool) -> ChangeReport {
    let mut r = ChangeReport::new("remove", &plan.target, Some(plan.plugin_root.clone()), dry);
    r.result = if plan.nothing_to_do {
        "nothing-to-do"
    } else {
        "planned"
    };
    r
}

pub fn execute_remove(spec: &RootSpec, plan: &RemovePlan) -> ChangeReport {
    execute_remove_with(
        spec,
        plan,
        bundle::FIRST_PARTY_BUNDLE,
        super::FIRST_PARTY_CATALOGS,
        None,
    )
}

pub(crate) fn execute_remove_with(
    spec: &RootSpec,
    plan: &RemovePlan,
    bundle: &'static [EmbeddedPlugin],
    registry: &[FirstPartyCatalog],
    at: Option<Fault>,
) -> ChangeReport {
    let mut r = remove_report(plan, false);
    if plan.nothing_to_do {
        return r;
    }
    r.result = "refused";
    let e = match embedded_for(&plan.target, bundle, registry) {
        Ok(e) => e,
        Err(err) => {
            r.messages.push(Message(err.message));
            return r;
        }
    };
    let mut changed = false;
    let outcome = (|| -> Result<()> {
        let root = spec.open()?;
        let _lock = root.lock(LOCK)?;
        let again = plan_remove_with(spec, &plan.target, bundle, registry)?;
        if again.fingerprint() != plan.fingerprint() {
            return Err(refuse(
                "the plugin root changed after the plan was shown; nothing was removed (run the command again)",
            ));
        }
        let new = plan
            .new_trust
            .as_ref()
            .ok_or_else(|| refuse("internal: no new trust file"))?;
        // trust.toml.prev: a copy of the current trust file, which the loader
        // never reads. A failure after its rename leaves that copy in place
        // and trust.toml unchanged: still nothing changed for the loader (2).
        root.replace_file(TRUST_PREV, &plan.trust_before)
            .map_err(|w| {
                if w.published {
                    refuse(format!(
                        "{} ({} was updated with a copy of the current trust.toml; trust.toml is unchanged)",
                        w.error.message, TRUST_PREV
                    ))
                } else {
                    w.error
                }
            })?;
        fault(at, Fault::AfterPrev)?;
        // Once the rename took place the new trust file is in effect, even
        // when the directory's fsync then fails (R1-01): partial from here.
        let res = root.replace_file(TRUST, new);
        if res.is_ok() || res.as_ref().is_err_and(|w| w.published) {
            changed = true;
            r.trust = "rewritten";
        }
        res.map_err(|w| {
            if w.published {
                refuse(format!(
                    "{} (trust.toml was rewritten and is in effect, but making that durable failed: after a crash the file may be the new one or the previous one, which {} also holds)",
                    w.error.message, TRUST_PREV
                ))
            } else {
                w.error
            }
        })?;
        fault(at, Fault::AfterTrust)?;
        let delete = |sub: &str, name: &str, want: &str, r: &mut ChangeReport| -> Result<()> {
            let d = root.subdir(sub)?;
            // Read again just before removing: only the exact bytes go.
            let f = d.read_file_with(name, verify::MAX_FILE_BYTES, &mut || {})?;
            if f.sha256 != want {
                return Err(refuse(format!(
                    "{}/{}: changed since the plan; it was not removed",
                    d.shown(),
                    name
                )));
            }
            // A file removed is reported as removed even when only the
            // directory's fsync failed afterwards.
            let res = d.remove_file_synced(name);
            if res.is_ok() || res.as_ref().is_err_and(|w| w.published) {
                r.files_removed.push(format!("{}/{}", sub, name));
            }
            res.map_err(|w| {
                if w.published {
                    refuse(format!(
                        "{} (the file was removed, but making that durable failed)",
                        w.error.message
                    ))
                } else {
                    w.error
                }
            })
        };
        if plan.delete_plugin_file {
            delete("plugins", &plan.plugin_file_name, e.plugin_sha256, &mut r)?;
        }
        fault(at, Fault::AfterPluginRemoved)?;
        if plan.delete_catalog_file {
            delete(
                "catalogs",
                &plan.catalog_file_name,
                e.catalog_sha256,
                &mut r,
            )?;
        }
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let v = spec.verify(&plan.target, bundle, registry);
            let status = v.plugins.first().map(|p| p.status).unwrap_or("unknown");
            r.verify = Some(status);
            // A catalog kept for another plugin leaves a file the report
            // calls `not-trusted` for this plugin; its own file must be gone.
            let kept_catalog_only = status == "not-trusted"
                && plan.catalog_kept.is_some()
                && root_has_no_plugin_file(spec, &plan.plugin_file_name);
            if status == "not-installed" || kept_catalog_only {
                r.result = "removed";
            } else {
                r.result = "partial";
                r.messages.extend(v.messages);
                r.messages.push(Message(format!(
                    "removed from the trust file, but the loader's verification reports {}",
                    status
                )));
            }
        }
        Err(err) => {
            r.messages.push(Message(err.message));
            if changed {
                r.result = "partial";
                r.messages.push(Message(format!(
                    "the trust entries were removed (previous content in {}), but not every file was removed; the loader no longer uses the plugin",
                    TRUST_PREV
                )));
            } else {
                r.result = "refused";
            }
        }
    }
    r
}

fn root_has_no_plugin_file(spec: &RootSpec, name: &str) -> bool {
    match spec.open().and_then(|root| root.subdir("plugins")) {
        Ok(d) => matches!(d.entry(name), Ok(Entry::Absent)),
        Err(_) => false,
    }
}
