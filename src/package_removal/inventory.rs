//! Package-inventory fingerprints and planned/actual removal deltas (Stage R1).
//!
//! R1 does not run `rpm -qa` or `dpkg-query`; callers hand the captured text to
//! this pure module. An empty input is a valid empty inventory, while a
//! malformed or non-UTF-8 record is an error: acquisition failure is never
//! represented as an empty inventory. The hash is over a canonical, sorted
//! `name<TAB>arch<TAB>version<TAB>installed` listing.
//!
//! Fingerprints are evidence of package-set stability, not a filesystem
//! read-only proof and not an atomic transaction. A/B/C equality narrows the
//! TOCTOU window; it does not eliminate it.

use super::{
    PackageIdentity, PlannedRemoval, RemovalBackend, RemovalSafetyError, MAX_ARCHITECTURE,
    MAX_PACKAGE_NAME, MAX_VERSION,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct InventoryEntry {
    name: String,
    architecture: String,
    version: String,
    installed: bool,
}

impl InventoryEntry {
    fn new(
        name: &str,
        architecture: &str,
        version: &str,
        installed: bool,
    ) -> Result<Self, RemovalSafetyError> {
        if !valid_name(name) || !valid_arch(architecture) || !valid_version(version) {
            return Err(RemovalSafetyError::identity());
        }
        Ok(InventoryEntry {
            name: name.to_string(),
            architecture: architecture.to_string(),
            version: version.to_string(),
            installed,
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn architecture(&self) -> &str {
        &self.architecture
    }

    pub(crate) fn version(&self) -> &str {
        &self.version
    }

    pub(crate) fn installed(&self) -> bool {
        self.installed
    }

    fn key(&self) -> (String, String, String) {
        (
            self.name.clone(),
            self.architecture.clone(),
            self.version.clone(),
        )
    }
}

impl fmt::Debug for InventoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InventoryEntry")
            .field("name", &"<redacted>")
            .field("architecture", &"<redacted>")
            .field("version", &"<redacted>")
            .field("installed", &self.installed)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct InventoryFingerprint {
    backend: RemovalBackend,
    entries: Vec<InventoryEntry>,
    hash: [u8; 32],
}

impl InventoryFingerprint {
    /// Parse captured inventory text.
    ///
    /// APT rows: `name<TAB>version<TAB>architecture<TAB>status`.
    /// DNF rows: `name<TAB>version<TAB>architecture`.
    ///
    /// An absent status on a DNF row means installed. An APT status is
    /// accepted only from the clean set Sinter already classifies; a broken
    /// state is not folded into installed/absent.
    pub(crate) fn from_records(
        backend: RemovalBackend,
        bytes: &[u8],
    ) -> Result<Self, RemovalSafetyError> {
        let text = std::str::from_utf8(bytes).map_err(|_| RemovalSafetyError::parse(None))?;
        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();
        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            if line.trim().is_empty() {
                continue;
            }
            let entry = match backend {
                RemovalBackend::Apt => {
                    let f: Vec<&str> = line.splitn(4, '\t').collect();
                    if f.len() != 4 {
                        return Err(RemovalSafetyError::parse(Some(line_number)));
                    }
                    let installed = match f[3] {
                        "install ok installed" => true,
                        "deinstall ok config-files"
                        | "deinstall ok not-installed"
                        | "purge ok not-installed"
                        | "purge ok config-files"
                        | "unknown ok not-installed" => false,
                        _ => return Err(RemovalSafetyError::parse(Some(line_number))),
                    };
                    // dpkg-query's ${binary:Package} qualifies a multi-arch
                    // package as `name:arch`. The architecture column must
                    // agree; storing the base name plus the column keeps the
                    // identity unambiguous.
                    let name = match f[0].rsplit_once(':') {
                        Some((name, arch)) => {
                            if !valid_arch(arch) || arch != f[2] {
                                return Err(RemovalSafetyError::parse(Some(line_number)));
                            }
                            name
                        }
                        None => f[0],
                    };
                    InventoryEntry::new(name, f[2], f[1], installed)
                        .map_err(|_| RemovalSafetyError::parse(Some(line_number)))?
                }
                RemovalBackend::Dnf4 | RemovalBackend::Dnf5 => {
                    let f: Vec<&str> = line.split('\t').collect();
                    if f.len() != 3 {
                        return Err(RemovalSafetyError::parse(Some(line_number)));
                    }
                    InventoryEntry::new(f[0], f[2], f[1], true)
                        .map_err(|_| RemovalSafetyError::parse(Some(line_number)))?
                }
            };
            if !seen.insert(entry.key()) {
                return Err(RemovalSafetyError::identity());
            }
            entries.push(entry);
        }
        entries.sort_by_key(|a| a.key());
        let mut hasher = Sha256::new();
        for entry in &entries {
            hasher.update(entry.name.as_bytes());
            hasher.update(b"\t");
            hasher.update(entry.architecture.as_bytes());
            hasher.update(b"\t");
            hasher.update(entry.version.as_bytes());
            hasher.update(b"\t");
            hasher.update(if entry.installed { b"1" } else { b"0" });
            hasher.update(b"\n");
        }
        let hash: [u8; 32] = hasher.finalize().into();
        Ok(InventoryFingerprint {
            backend,
            entries,
            hash,
        })
    }

    pub(crate) fn backend(&self) -> RemovalBackend {
        self.backend
    }

    pub(crate) fn entries(&self) -> &[InventoryEntry] {
        &self.entries
    }

    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn hash_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.hash {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl fmt::Debug for InventoryFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InventoryFingerprint")
            .field("backend", &self.backend)
            .field("entry_count", &self.entries.len())
            .field("hash", &self.hash_hex())
            .finish()
    }
}

/// Require the A/B/C fingerprints to be identical. A mismatch is a definite
/// refusal: the preview no longer describes the inventory it will be compared
/// against.
pub(crate) fn verify_stability(
    a: &InventoryFingerprint,
    b: &InventoryFingerprint,
    c: &InventoryFingerprint,
) -> Result<(), RemovalSafetyError> {
    if a == b && b == c {
        Ok(())
    } else {
        Err(RemovalSafetyError::inventory_changed())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RemovalExecutionDelta {
    planned_removals: Vec<PlannedRemoval>,
    actual_removals: Vec<InventoryEntry>,
    unexpected_removals: Vec<InventoryEntry>,
    missing_removals: Vec<PlannedRemoval>,
    unexpected_additions: Vec<InventoryEntry>,
}

impl RemovalExecutionDelta {
    pub(crate) fn compute(
        planned: &[PlannedRemoval],
        preview_backend: RemovalBackend,
        before: &InventoryFingerprint,
        after: &InventoryFingerprint,
    ) -> Result<Self, RemovalSafetyError> {
        if preview_backend != before.backend || preview_backend != after.backend {
            return Err(RemovalSafetyError::backend_mismatch());
        }
        let before_map: BTreeMap<(String, String, String), &InventoryEntry> = before
            .entries
            .iter()
            .map(|entry| (entry.key(), entry))
            .collect();
        let after_map: BTreeMap<(String, String, String), &InventoryEntry> = after
            .entries
            .iter()
            .map(|entry| (entry.key(), entry))
            .collect();

        let mut actual_removals = Vec::new();
        for entry in &before.entries {
            if !entry.installed {
                continue;
            }
            let still_installed = after_map
                .get(&entry.key())
                .is_some_and(|after_entry| after_entry.installed);
            if !still_installed {
                actual_removals.push(entry.clone());
            }
        }

        let mut unexpected_additions = Vec::new();
        for entry in &after.entries {
            if !entry.installed {
                continue;
            }
            let was_installed = before_map
                .get(&entry.key())
                .is_some_and(|before_entry| before_entry.installed);
            if !was_installed {
                unexpected_additions.push(entry.clone());
            }
        }

        let mut unexpected_removals = Vec::new();
        for entry in &actual_removals {
            let matches = planned
                .iter()
                .filter(|planned| identity_matches_planned(entry, planned.identity()))
                .count();
            match matches {
                0 => unexpected_removals.push(entry.clone()),
                1 => {}
                _ => return Err(RemovalSafetyError::identity()),
            }
        }

        let mut missing_removals = Vec::new();
        for planned in planned {
            let matches = actual_removals
                .iter()
                .filter(|entry| identity_matches_planned(entry, planned.identity()))
                .count();
            match matches {
                0 => missing_removals.push(planned.clone()),
                1 => {}
                _ => return Err(RemovalSafetyError::identity()),
            }
        }

        Ok(RemovalExecutionDelta {
            planned_removals: planned.to_vec(),
            actual_removals,
            unexpected_removals,
            missing_removals,
            unexpected_additions,
        })
    }

    pub(crate) fn is_clean(&self) -> bool {
        self.unexpected_removals.is_empty()
            && self.missing_removals.is_empty()
            && self.unexpected_additions.is_empty()
    }

    pub(crate) fn require_clean(&self) -> Result<(), RemovalSafetyError> {
        if self.is_clean() {
            Ok(())
        } else {
            let count = self.unexpected_removals.len()
                + self.missing_removals.len()
                + self.unexpected_additions.len();
            Err(RemovalSafetyError::actual_mismatch(count))
        }
    }

    pub(crate) fn planned_removals(&self) -> &[PlannedRemoval] {
        &self.planned_removals
    }

    pub(crate) fn actual_removals(&self) -> &[InventoryEntry] {
        &self.actual_removals
    }

    pub(crate) fn unexpected_removals(&self) -> &[InventoryEntry] {
        &self.unexpected_removals
    }

    pub(crate) fn missing_removals(&self) -> &[PlannedRemoval] {
        &self.missing_removals
    }

    pub(crate) fn unexpected_additions(&self) -> &[InventoryEntry] {
        &self.unexpected_additions
    }
}

impl fmt::Debug for RemovalExecutionDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemovalExecutionDelta")
            .field("planned", &self.planned_removals.len())
            .field("actual", &self.actual_removals.len())
            .field("unexpected_removals", &self.unexpected_removals.len())
            .field("missing_removals", &self.missing_removals.len())
            .field("unexpected_additions", &self.unexpected_additions.len())
            .finish()
    }
}

fn identity_matches_planned(entry: &InventoryEntry, planned: &PackageIdentity) -> bool {
    if entry.name != planned.name() {
        return false;
    }
    if let Some(arch) = planned.architecture() {
        if entry.architecture != arch {
            return false;
        }
    }
    if let Some(version) = planned.version() {
        if entry.version != version {
            return false;
        }
    }
    true
}

fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_PACKAGE_NAME {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~'))
}

fn valid_arch(arch: &str) -> bool {
    if arch == "(none)" {
        return true;
    }
    !arch.is_empty()
        && arch.len() <= MAX_ARCHITECTURE
        && arch.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION
        && version.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'~' | b'^' | b':' | b'-')
        })
}
