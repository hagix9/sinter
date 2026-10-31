//! Resource Plugins (E3-H), foundation step 1 (DESIGN §38).
//!
//! What this step does: read the Owner's trust file, the capability catalogs
//! and the plugin definitions from a protected plugin root on the controller,
//! verify them against the Core-fixed rules, and produce a sealed model.
//!
//! What it does not do: nothing here runs a program, opens a connection or
//! touches a target, and nothing is wired into recipes, the CLI or MCP yet.
//! There is no execution channel ([`EXECUTION_AVAILABLE`] is `false`), so a
//! loaded plugin is never presented as runnable.

pub mod format;
mod protect;
pub mod verify;

#[cfg(all(test, unix))]
mod tests;

pub use format::CatalogRef;
pub use verify::{
    operand_ok, ArgToken, Facet, FieldKind, OpClass, ResourceType, VerifiedCatalog, VerifiedOp,
    VerifiedPlugin, Want, BUILTIN_RESOURCE_TYPES,
};

use crate::error::{Result, SinterError};
use protect::{Ancestors, TrustedDir};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Whether plugin operations can be run by this Sinter. Step 1 has no
/// execution channel: loading and verification only.
pub const EXECUTION_AVAILABLE: bool = false;

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

/// The reviewed first-party catalogs of this release. Empty in step 1: the
/// firewalld catalog is a draft until its exit codes are confirmed on real
/// hosts (SINTER_PLUGIN_FIREWALLD_DESIGN §4.5), so no catalog is usable yet.
pub const FIRST_PARTY_CATALOGS: &[FirstPartyCatalog] = &[];

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
    /// Always `false` in step 1 (see [`EXECUTION_AVAILABLE`]).
    pub fn execution_available(&self) -> bool {
        EXECUTION_AVAILABLE
    }
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
