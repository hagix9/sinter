//! The first-party plugin files embedded in this Sinter (DESIGN §38.4,
//! §38.15).
//!
//! Each entry carries the exact bytes of one first-party plugin definition
//! and of the catalog it names, as kept in the repository under
//! `plugins/first-party/`, with the SHA-256 of both. The catalog digests are
//! the ones in [`super::FIRST_PARTY_CATALOGS`]; a test checks that the
//! registry, these entries, their bytes and the repository files agree.
//!
//! Embedding grants nothing. The loader never reads these bytes: a plugin is
//! still used only from the plugin root, pinned by the Owner's trust file,
//! with its operations attested or allowed there, and enabled by a recipe.
//! `sinter plugin list` and `sinter plugin verify` compare the files of a
//! plugin root with these bytes.

/// One first-party plugin definition and its catalog, as shipped.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedPlugin {
    pub id: &'static str,
    pub version: &'static str,
    pub plugin_sha256: &'static str,
    pub plugin: &'static [u8],
    pub catalog_id: &'static str,
    pub catalog_version: &'static str,
    pub catalog_sha256: &'static str,
    pub catalog: &'static [u8],
}

macro_rules! first_party_file {
    ($path:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/plugins/first-party/",
            $path
        ))
    };
}

/// The first-party plugins of this release, ordered by id and version.
pub const FIRST_PARTY_BUNDLE: &[EmbeddedPlugin] = &[
    EmbeddedPlugin {
        id: "firewalld",
        version: "0.1.0",
        plugin_sha256: "47f33f171d239103cbb97450d17b57c857ce22436620ddf809fdd2be94948544",
        plugin: first_party_file!("plugins/firewalld-0.1.0.plugin.toml"),
        catalog_id: "firewalld",
        catalog_version: "0.1.0",
        catalog_sha256: "27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff",
        catalog: first_party_file!("catalogs/firewalld-0.1.0.catalog.toml"),
    },
    EmbeddedPlugin {
        id: "firewalld",
        version: "0.2.0",
        plugin_sha256: "e5819cfe0e2c017648f628a27d0ed6e4a18ed402f3ff6de072e61a724f0aa99a",
        plugin: first_party_file!("plugins/firewalld-0.2.0.plugin.toml"),
        catalog_id: "firewalld",
        catalog_version: "0.2.0",
        catalog_sha256: "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641",
        catalog: first_party_file!("catalogs/firewalld-0.2.0.catalog.toml"),
    },
];

/// The embedded plugin with this id and version, if this Sinter has one.
pub fn embedded(
    bundle: &'static [EmbeddedPlugin],
    id: &str,
    version: &str,
) -> Option<&'static EmbeddedPlugin> {
    bundle.iter().find(|e| e.id == id && e.version == version)
}

/// Check that every embedded entry hashes to its stated digests and that its
/// catalog is listed in `registry` with the same digest, and that every
/// registry entry is the catalog of at least one embedded plugin. Run before the bundle is
/// used; tests check the same against the repository files.
pub(crate) fn consistent(
    bundle: &[EmbeddedPlugin],
    registry: &[super::FirstPartyCatalog],
) -> std::result::Result<(), String> {
    use super::protect::sha256_hex;
    for e in bundle {
        if sha256_hex(e.plugin) != e.plugin_sha256 {
            return Err(format!(
                "embedded plugin {}@{} does not match its digest",
                e.id, e.version
            ));
        }
        if sha256_hex(e.catalog) != e.catalog_sha256 {
            return Err(format!(
                "embedded catalog {}@{} does not match its digest",
                e.catalog_id, e.catalog_version
            ));
        }
        if !registry.iter().any(|f| {
            f.id == e.catalog_id && f.version == e.catalog_version && f.sha256 == e.catalog_sha256
        }) {
            return Err(format!(
                "embedded catalog {}@{} is not in the first-party registry",
                e.catalog_id, e.catalog_version
            ));
        }
    }
    for f in registry {
        let n = bundle
            .iter()
            .filter(|e| {
                e.catalog_id == f.id
                    && e.catalog_version == f.version
                    && e.catalog_sha256 == f.sha256
            })
            .count();
        if n == 0 {
            return Err(format!(
                "first-party catalog {}@{} is not embedded",
                f.id, f.version
            ));
        }
    }
    Ok(())
}
