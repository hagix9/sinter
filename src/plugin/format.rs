//! On-disk formats of the three Resource Plugin data files (DESIGN §38.3).
//!
//! Every struct denies unknown keys: a key Sinter does not know is an error,
//! never ignored. These types carry only what the files say; every rule about
//! what the values may be is checked in `verify.rs`.

use serde::Deserialize;
use std::collections::BTreeMap;

/// The only file format version this Sinter reads.
pub const FORMAT_VERSION: u32 = 1;

/// `trust.toml`: the Owner's trust store, the root of trust (DESIGN §38.4).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustFile {
    pub format: u32,
    #[serde(default)]
    pub catalog: Vec<TrustedCatalog>,
    #[serde(default)]
    pub plugin: Vec<TrustedPlugin>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedCatalog {
    pub id: String,
    pub version: String,
    pub sha256: String,
    /// Observe operations the Owner attests to be read-only.
    #[serde(default)]
    pub attested_observe: Vec<String>,
    /// Mutate operations the Owner allows apply to run.
    #[serde(default)]
    pub allowed_mutate: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPlugin {
    pub id: String,
    pub version: String,
    pub sha256: String,
}

/// `catalogs/<id>-<version>.catalog.toml`: the operations a plugin may use.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogFile {
    pub format: u32,
    pub id: String,
    pub version: String,
    pub op: Vec<OpDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpDef {
    pub id: String,
    /// `observe` or `mutate`.
    pub class: String,
    pub program: String,
    pub argv: Vec<String>,
    pub timeout_secs: u64,
    #[serde(default)]
    pub slots: BTreeMap<String, SlotDef>,
    /// Exit code (decimal string) -> state. Every other completion is an error.
    pub exit: BTreeMap<String, String>,
    /// Observe only: trimmed standard output template -> state.
    #[serde(default)]
    pub stdout_map: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotDef {
    /// Operand class. `ident` is the only class in format 1.
    pub class: String,
    pub max_len: usize,
}

/// `plugins/<id>-<version>.plugin.toml`: resource types built from catalog
/// operations. A plugin has no field for a program, argv, environment,
/// working directory or standard input.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginFile {
    pub format: u32,
    pub id: String,
    pub version: String,
    pub catalog: CatalogRef,
    #[serde(rename = "type")]
    pub types: Vec<TypeDef>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct CatalogRef {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeDef {
    pub name: String,
    pub fields: BTreeMap<String, FieldDef>,
    #[serde(default)]
    pub precheck: Vec<PrecheckDef>,
    pub facet: Vec<FacetDef>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDef {
    /// `ident` or `enum`.
    pub kind: String,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrecheckDef {
    pub op: String,
    pub expect: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacetDef {
    pub name: String,
    pub observe: String,
    /// A state name, or `field:<enum field>`.
    pub want: String,
    /// Desired state -> mutate operation.
    pub ensure: BTreeMap<String, String>,
}
