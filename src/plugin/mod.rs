//! Resource Plugins (E3-H) (DESIGN §38).
//!
//! Step 1 (`format`, `protect`, `verify`, this file): read the Owner's trust
//! file, the capability catalogs and the plugin definitions from a protected
//! plugin root on the controller, verify them against the Core-fixed rules,
//! and produce a sealed model. Loading never runs a program or touches a
//! target.
//!
//! Step 2 (`exec`, `run`): recipes enable plugins explicitly (`plugins:`),
//! the engine runs plugin resource types through the two channels of
//! `TargetFs` (observe, and mutate with the mutation permit), and audit
//! observes only. A catalog is usable only when this release's first-party
//! registry lists its exact bytes. The registry lists firewalld 0.1.0 and
//! firewalld 0.2.0, whose exit codes were measured on real hosts; their
//! files are kept in the repository under `plugins/first-party/`.
//!
//! `bundle` embeds those first-party files in this Sinter and `manage` reads
//! a plugin root for `sinter plugin list` and `sinter plugin verify`
//! (DESIGN §38.15). Neither grants trust nor changes what the loader accepts.

pub mod bundle;
pub mod exec;
pub mod format;
pub mod manage;
mod protect;
pub(crate) mod run;
pub mod verify;

#[cfg(all(test, unix))]
mod c1_tests;
#[cfg(all(test, unix))]
mod firewalld_020_tests;
#[cfg(all(test, unix))]
mod manage_tests;
#[cfg(all(test, unix))]
mod run_tests;
#[cfg(all(test, unix))]
mod tests;

pub use format::CatalogRef;
pub use run::require_allowed_mutations;
pub use verify::{
    operand_ok, operand_ok_for, port_single_ok, port_spec_ok, ArgToken, Facet, FieldKind, OpClass,
    ResourceType, SlotClass, VerifiedCatalog, VerifiedOp, VerifiedPlugin, Want,
    BUILTIN_RESOURCE_TYPES,
};

use crate::error::{Result, SinterError};
use crate::value::Value;
use protect::{Ancestors, TrustedDir};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Whether this Sinter has the plugin execution channels (step 2: yes). It
/// does not mean a plugin can run: that also needs a catalog listed in the
/// release's first-party registry (see [`production_enabled`]).
pub const EXECUTION_AVAILABLE: bool = true;

/// Whether any plugin can run in this build: only when the release lists at
/// least one reviewed first-party catalog (firewalld 0.1.0 and 0.2.0).
/// It says what the build can do, not that a release is approved.
pub fn production_enabled() -> bool {
    !FIRST_PARTY_CATALOGS.is_empty()
}

/// A capability catalog reviewed by the Sinter project and shipped as part
/// of this release (DESIGN §38.4). A catalog whose exact bytes are not listed
/// here is refused, whatever the trust file says: third-party catalogs are
/// not supported in v1.9.0.
#[derive(Debug, Clone, Copy)]
pub struct FirstPartyCatalog {
    pub id: &'static str,
    pub version: &'static str,
    pub sha256: &'static str,
}

/// The reviewed first-party catalogs of this release (DESIGN §38.4). Each
/// entry is the SHA-256 of the exact bytes of a file under
/// `plugins/first-party/catalogs/`; a test checks that they agree.
///
/// firewalld 0.1.0: the seven operations of the firewalld design, with the
/// exit codes measured directly on Rocky Linux 9.8 (firewalld 1.3.4), Rocky
/// Linux 10.2 (2.4.3) and Ubuntu 24.04 (2.1.1) on 2026-11-01.
///
/// firewalld 0.2.0: those seven operations unchanged plus 14 (service
/// removal, ports and protocols, runtime and permanent), measured directly on
/// Rocky Linux 9.8 (firewalld 1.3.4), Rocky Linux 10.2 (2.4.3) and Ubuntu
/// 24.04.5 (2.1.1) on 2026-11-09, with identical results.
///
/// Other OS and firewalld versions are not verified.
pub const FIRST_PARTY_CATALOGS: &[FirstPartyCatalog] = &[
    FirstPartyCatalog {
        id: "firewalld",
        version: "0.1.0",
        sha256: "27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff",
    },
    FirstPartyCatalog {
        id: "firewalld",
        version: "0.2.0",
        sha256: "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641",
    },
];

/// A plugin a recipe enables (`plugins: [{ id, version }]`, DESIGN §38.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRef {
    pub id: String,
    pub version: String,
}

/// The controller-side plugin root, opened and checked (DESIGN §38.5). Its
/// location comes only from the operator's configuration, never from a
/// recipe, a plugin file or MCP input.
pub struct PluginRoot {
    dir: TrustedDir,
}

impl PluginRoot {
    pub fn open(path: &Path) -> Result<PluginRoot> {
        Ok(PluginRoot {
            dir: TrustedDir::open_root(path, &Ancestors::All)?,
        })
    }

    #[cfg(all(test, unix))]
    pub(crate) fn open_below(path: &Path, boundary: &Path) -> Result<PluginRoot> {
        Ok(PluginRoot {
            dir: TrustedDir::open_root(path, &Ancestors::Below(boundary.to_path_buf()))?,
        })
    }
}

/// Everything the enabled plugins need, verified.
#[derive(Debug, Default)]
pub struct PluginSet {
    catalogs: BTreeMap<(String, String), VerifiedCatalog>,
    plugins: Vec<VerifiedPlugin>,
}

impl PluginSet {
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
    pub fn plugins(&self) -> &[VerifiedPlugin] {
        &self.plugins
    }
    pub fn catalog(&self, r: &CatalogRef) -> Option<&VerifiedCatalog> {
        self.catalogs.get(&(r.id.clone(), r.version.clone()))
    }
    /// The plugin and type that provide `name`, if an enabled plugin does.
    pub fn resource_type(&self, name: &str) -> Option<(&VerifiedPlugin, &ResourceType)> {
        self.plugins
            .iter()
            .find_map(|p| p.resource_type(name).map(|t| (p, t)))
    }
    /// Whether the execution channels exist (see [`EXECUTION_AVAILABLE`]).
    pub fn execution_available(&self) -> bool {
        EXECUTION_AVAILABLE
    }
    /// Provenance of every enabled plugin, for results (DESIGN §38.11).
    pub fn provenance(&self) -> Vec<Provenance> {
        self.plugins
            .iter()
            .map(|p| {
                let c = self.catalog(p.catalog());
                Provenance {
                    plugin_id: p.id().to_string(),
                    plugin_version: p.version().to_string(),
                    plugin_sha256: p.sha256().to_string(),
                    catalog_id: p.catalog().id.clone(),
                    catalog_version: p.catalog().version.clone(),
                    catalog_sha256: c.map(|c| c.sha256().to_string()).unwrap_or_default(),
                    catalog_registry: "first-party",
                    types: p.resource_types().map(|t| t.name().to_string()).collect(),
                }
            })
            .collect()
    }
}

/// Where a plugin came from, as results report it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Provenance {
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_sha256: String,
    pub catalog_id: String,
    pub catalog_version: String,
    pub catalog_sha256: String,
    /// Which registry admitted the catalog. Always `first-party` in v1.9.0.
    pub catalog_registry: &'static str,
    pub types: Vec<String>,
}

/// Where plugins may come from for one load (DESIGN §38.7). Only the CLI
/// builds [`PluginContext::Root`], from `--plugin-root` or the user's
/// configuration directory; every other caller (MCP, `secrets list`, library
/// users) gets [`PluginContext::Disabled`], and a recipe that enables plugins
/// is then refused. Nothing in a recipe, a variables file, a plugin file or
/// MCP input can choose the root.
#[derive(Debug, Clone)]
pub enum PluginContext {
    Disabled(&'static str),
    Root(PathBuf),
    /// Tests: a root checked only below `boundary`, and a test registry of
    /// first-party catalogs in place of the release's.
    #[cfg(all(test, unix))]
    Test {
        root: PathBuf,
        boundary: PathBuf,
        registry: Vec<FirstPartyCatalog>,
    },
}

impl Default for PluginContext {
    fn default() -> Self {
        PluginContext::Disabled("Resource Plugins are not available here")
    }
}

impl PluginContext {
    /// The CLI's plugin root: `explicit` (`--plugin-root`) when given, else
    /// `$XDG_CONFIG_HOME/sinter/plugins` when that variable is an absolute
    /// path, else `$HOME/.config/sinter/plugins`. Nothing is opened here; the
    /// root is opened only when a recipe enables a plugin.
    pub fn controller(explicit: Option<&Path>) -> PluginContext {
        if let Some(p) = explicit {
            return PluginContext::Root(p.to_path_buf());
        }
        let abs = |v: Option<std::ffi::OsString>| {
            v.map(PathBuf::from)
                .filter(|p| p.is_absolute() && p != Path::new("/"))
        };
        if let Some(x) = abs(std::env::var_os("XDG_CONFIG_HOME")) {
            return PluginContext::Root(x.join("sinter/plugins"));
        }
        if let Some(h) = abs(std::env::var_os("HOME")) {
            return PluginContext::Root(h.join(".config/sinter/plugins"));
        }
        PluginContext::Disabled("no plugin root: pass --plugin-root (HOME is not set)")
    }

    /// Load the plugins a recipe enables (never called when it enables none).
    pub(crate) fn load(&self, enabled: &[PluginRef]) -> Result<PluginSet> {
        match self {
            PluginContext::Disabled(why) => Err(refuse(format!(
                "this recipe enables plugins, which are not available: {}",
                why
            ))),
            PluginContext::Root(p) => load(&PluginRoot::open(p)?, enabled),
            #[cfg(all(test, unix))]
            PluginContext::Test {
                root,
                boundary,
                registry,
            } => load_with(
                &PluginRoot::open_below(root, boundary)?,
                enabled,
                registry,
                &mut |_| {},
            ),
        }
    }
}

/// Static check of one plugin resource declaration while a recipe is loaded
/// (DESIGN §38.9): the type must come from an enabled plugin, the fields must
/// be exactly the type's, and every literal value must be a valid operand.
/// A value with `{{ }}` is checked when it is evaluated. Without enabled
/// plugins the error is the one every unknown type gets.
pub(crate) fn check_declaration(
    set: Option<&PluginSet>,
    type_: &str,
    with: &BTreeMap<String, Value>,
    ctx: &str,
) -> Result<()> {
    let Some(set) = set else {
        return Err(SinterError::schema(format!(
            "{}: unknown resource type {}",
            ctx, type_
        )));
    };
    let Some((_, t)) = set.resource_type(type_) else {
        return Err(SinterError::schema(format!(
            "{}: unknown resource type {} (no enabled plugin provides it)",
            ctx, type_
        )));
    };
    t.check_field_names(with.keys().map(String::as_str), ctx)?;
    let mut literals = BTreeMap::new();
    let mut all_literal = true;
    for (k, v) in with {
        match v {
            Value::Str(s) if crate::expressions::has_interpolation(s) => all_literal = false,
            Value::Str(s) => {
                t.check_field(k, s, ctx)?;
                literals.insert(k.clone(), s.clone());
            }
            _ => {
                return Err(SinterError::schema(format!(
                    "{}: with.{} must be a string",
                    ctx, k
                )))
            }
        }
    }
    // A refused combination is caught here when every value is a literal,
    // and otherwise when the values are evaluated, before anything runs.
    if all_literal {
        t.check_deny(&literals, ctx)?;
    }
    Ok(())
}

fn refuse(msg: impl Into<String>) -> SinterError {
    SinterError::schema(format!("plugin: {}", msg.into()))
}

/// Load and verify the enabled plugins. With nothing enabled this reads
/// nothing and returns an empty set.
pub fn load(root: &PluginRoot, enabled: &[PluginRef]) -> Result<PluginSet> {
    load_with(root, enabled, FIRST_PARTY_CATALOGS, &mut |_| {})
}

/// [`load`] with an explicit first-party registry and a test seam that runs
/// after each file is opened and checked, before it is read.
pub(crate) fn load_with(
    root: &PluginRoot,
    enabled: &[PluginRef],
    first_party: &[FirstPartyCatalog],
    after_open: &mut dyn FnMut(&str),
) -> Result<PluginSet> {
    if enabled.is_empty() {
        return Ok(PluginSet::default());
    }
    let mut ids = BTreeSet::new();
    for r in enabled {
        if !verify::id_ok(&r.id) || !verify::version_ok(&r.version) {
            return Err(refuse(
                "an enabled plugin needs a valid id and MAJOR.MINOR.PATCH version",
            ));
        }
        if !ids.insert(r.id.clone()) {
            return Err(refuse(format!("plugin {} is enabled more than once", r.id)));
        }
    }
    let mut seam = |name: &str| after_open(name);
    let trust_file = root
        .dir
        .read_file_with("trust.toml", verify::MAX_FILE_BYTES, &mut || {
            seam("trust.toml")
        })?;
    let trust_shown = format!("{}/trust.toml", root.dir.shown());
    let trust = verify::verify_trust(&trust_file.bytes, &trust_shown)?;

    let plugins_dir = root.dir.subdir("plugins")?;
    let mut catalogs_dir: Option<TrustedDir> = None;
    let mut set = PluginSet::default();
    for r in enabled {
        let trusted = trust
            .plugins
            .get(&(r.id.clone(), r.version.clone()))
            .ok_or_else(|| {
                refuse(format!(
                    "plugin {}@{} is not trusted (no entry in the trust file)",
                    r.id, r.version
                ))
            })?;
        let name = format!("{}-{}.plugin.toml", r.id, r.version);
        let loaded =
            plugins_dir.read_file_with(&name, verify::MAX_FILE_BYTES, &mut || seam(&name))?;
        let shown = format!("{}/{}", plugins_dir.shown(), name);
        // The catalog reference is read from the pinned bytes only after the
        // digest matched (verify_plugin checks the digest before parsing).
        if loaded.sha256 != trusted.sha256 {
            return Err(refuse(format!(
                "{}: does not match the sha256 pinned in the trust file",
                shown
            )));
        }
        let cref = catalog_ref_of(&loaded.bytes, &shown)?;
        let key = (cref.id.clone(), cref.version.clone());
        if let std::collections::btree_map::Entry::Vacant(slot) = set.catalogs.entry(key.clone()) {
            let tc = trust.catalogs.get(&key).ok_or_else(|| {
                refuse(format!(
                    "{}: catalog {}@{} is not trusted",
                    shown, cref.id, cref.version
                ))
            })?;
            if catalogs_dir.is_none() {
                catalogs_dir = Some(root.dir.subdir("catalogs")?);
            }
            let cdir = catalogs_dir.as_ref().expect("opened above");
            let cname = format!("{}-{}.catalog.toml", cref.id, cref.version);
            let c = cdir.read_file_with(&cname, verify::MAX_FILE_BYTES, &mut || seam(&cname))?;
            let cshown = format!("{}/{}", cdir.shown(), cname);
            slot.insert(verify::verify_catalog(
                &c.bytes,
                &c.sha256,
                &cshown,
                tc,
                first_party,
            )?);
        }
        let vp = verify::verify_plugin(
            &loaded.bytes,
            &loaded.sha256,
            &shown,
            trusted,
            &set.catalogs,
        )?;
        set.plugins.push(vp);
    }
    Ok(set)
}

/// The catalog a pinned plugin file names (its full verification follows).
fn catalog_ref_of(bytes: &[u8], shown: &str) -> Result<CatalogRef> {
    #[derive(serde::Deserialize)]
    struct OnlyCatalog {
        catalog: CatalogRef,
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| refuse(format!("{}: not valid UTF-8", shown)))?;
    let c: OnlyCatalog = toml::from_str(text).map_err(|_| {
        refuse(format!(
            "{}: invalid format: missing or invalid catalog reference",
            shown
        ))
    })?;
    if !verify::id_ok(&c.catalog.id) || !verify::version_ok(&c.catalog.version) {
        return Err(refuse(format!("{}: invalid catalog reference", shown)));
    }
    Ok(c.catalog)
}
