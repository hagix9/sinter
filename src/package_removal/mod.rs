//! Package-removal safety contract (WP-PKG-PROGRESS Stage R1).
//!
//! R1 is deliberately **not** connected to the apply path. It provides the
//! preview parsers, the exact-set decision, the inventory fingerprint and the
//! planned/actual delta as an independently testable safety seam. R2/R3 will
//! wire this seam into `run_package`; until then no package manager is run and
//! no existing argv, result or JSON output changes.
//!
//! The contract is fail-closed: a preview that cannot be fully established is
//! an error, never an empty/allowed preview. A preview is only `Allowed` when
//! the requested package is present and every other planned removal is in the
//! explicitly supplied allow-list. The default allow-list is empty.
//!
//! Sensitive data: package names, versions and architectures are never part of
//! `Debug` or `Display` output from this module. The structured values keep the
//! exact identities for comparison; callers that render a decision must use
//! [`RemovalSafetyDecision::render`] with the resource's sensitivity.

#![cfg_attr(not(test), allow(dead_code))]

mod apt;
mod dnf;
mod inventory;
#[cfg(test)]
mod tests;

pub(crate) use inventory::{InventoryFingerprint, RemovalExecutionDelta};

use crate::error::SinterError;
use std::collections::BTreeSet;
use std::fmt;

/// R1's defensive bound on a package name. The model applies no length bound
/// (it validates characters only), and the progress renderer caps names at 64;
/// this module keeps its own bound so an unbounded token cannot enter a
/// fingerprint or preview identity.
pub(super) const MAX_PACKAGE_NAME: usize = 256;
/// Longest accepted architecture token.
pub(super) const MAX_ARCHITECTURE: usize = 32;
/// Longest accepted version / EVR token.
pub(super) const MAX_VERSION: usize = 128;

/// The backends whose remove-preview grammar R1 understands.
///
/// DNF4 and DNF5 are separate variants even though their table sections are
/// identical: their summary and abort grammars differ, and a caller must not
/// silently apply one backend's grammar to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemovalBackend {
    Apt,
    Dnf4,
    Dnf5,
}

impl RemovalBackend {
    pub(crate) fn label(self) -> &'static str {
        match self {
            RemovalBackend::Apt => "apt",
            RemovalBackend::Dnf4 => "dnf4",
            RemovalBackend::Dnf5 => "dnf5",
        }
    }

    pub(crate) fn is_dnf(self) -> bool {
        matches!(self, RemovalBackend::Dnf4 | RemovalBackend::Dnf5)
    }

    fn command_identity(self, no_autoremove: bool) -> PreviewCommandIdentity {
        match self {
            RemovalBackend::Apt => PreviewCommandIdentity::AptSimulatedRemove,
            RemovalBackend::Dnf4 => PreviewCommandIdentity::Dnf4RemoveAssumeno { no_autoremove },
            RemovalBackend::Dnf5 => PreviewCommandIdentity::Dnf5RemoveAssumeno { no_autoremove },
        }
    }
}

/// Why the package manager proposed one removal.
///
/// APT's simulation does not label a removal as dependent or unused. Such an
/// entry is [`RemovalReason::Unknown`]; it is never promoted to `Requested`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemovalReason {
    Requested,
    Dependent,
    UnusedDependency,
    Unknown,
}

/// The exact command shape a preview was taken with. It deliberately does not
/// carry the package name, so it is safe to show and log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreviewCommandIdentity {
    AptSimulatedRemove,
    Dnf4RemoveAssumeno { no_autoremove: bool },
    Dnf5RemoveAssumeno { no_autoremove: bool },
}

impl PreviewCommandIdentity {
    pub(crate) fn no_autoremove(self) -> Option<bool> {
        match self {
            PreviewCommandIdentity::AptSimulatedRemove => None,
            PreviewCommandIdentity::Dnf4RemoveAssumeno { no_autoremove }
            | PreviewCommandIdentity::Dnf5RemoveAssumeno { no_autoremove } => Some(no_autoremove),
        }
    }
}

/// One package identity as printed by a package manager.
///
/// A field is `None` exactly when the backend printed no value for it. APT's
/// `Remv` line prints a version but no architecture; DNF prints architecture,
/// EVR and repository. No value is invented to fill a gap.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PackageIdentity {
    name: String,
    architecture: Option<String>,
    version: Option<String>,
}

impl PackageIdentity {
    /// Build and validate an identity. Validation is deliberately shared by
    /// every parser so a malformed token cannot enter a preview through one
    /// backend and be rejected only by another.
    pub(super) fn new(
        name: &str,
        architecture: Option<&str>,
        version: Option<&str>,
    ) -> Result<Self, RemovalSafetyError> {
        if !valid_package_name(name) {
            return Err(RemovalSafetyError::identity());
        }
        if let Some(arch) = architecture {
            if !valid_architecture(arch) {
                return Err(RemovalSafetyError::identity());
            }
        }
        if let Some(version) = version {
            if !valid_version(version) {
                return Err(RemovalSafetyError::identity());
            }
        }
        Ok(PackageIdentity {
            name: name.to_string(),
            architecture: architecture.map(ToOwned::to_owned),
            version: version.map(ToOwned::to_owned),
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn architecture(&self) -> Option<&str> {
        self.architecture.as_deref()
    }

    pub(crate) fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Whether this identity is the requested package by name. Architecture
    /// and version are deliberately not part of this comparison: `absent` has
    /// no version pinning, and a requested name may match more than one
    /// installed instance (for example an installonly package).
    pub(crate) fn is_requested_name(&self, requested: &str) -> bool {
        self.name == requested
    }
}

impl fmt::Debug for PackageIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackageIdentity")
            .field("name", &"<redacted>")
            .field(
                "architecture",
                &self.architecture.as_ref().map(|_| "<redacted>"),
            )
            .field("version", &self.version.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// One planned removal and the section that established its reason.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PlannedRemoval {
    identity: PackageIdentity,
    reason: RemovalReason,
}

impl PlannedRemoval {
    pub(super) fn new(identity: PackageIdentity, reason: RemovalReason) -> Self {
        PlannedRemoval { identity, reason }
    }

    pub(crate) fn identity(&self) -> &PackageIdentity {
        &self.identity
    }

    pub(crate) fn reason(&self) -> RemovalReason {
        self.reason
    }
}

impl fmt::Debug for PlannedRemoval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlannedRemoval")
            .field("identity", &self.identity)
            .field("reason", &self.reason)
            .finish()
    }
}

/// How the preview process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreviewExit {
    /// Exit 0 with at least one parsed removal.
    Completed,
    /// The documented `--assumeno` abort (exit 1) with a complete table.
    Aborted,
    /// Exit 0 with a recognized "nothing to do" response and no removals.
    NoOp,
}

impl PreviewExit {
    pub(crate) fn is_noop(self) -> bool {
        self == PreviewExit::NoOp
    }
}

/// Raw preview output. Bytes are checked as strict UTF-8; truncation flags are
/// part of the input because a truncated table cannot establish a set.
#[derive(Clone, Copy)]
pub(crate) struct PreviewInput<'a> {
    pub exit_code: i32,
    pub stdout: &'a [u8],
    pub stderr: &'a [u8],
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub backend_version: Option<&'a str>,
}

impl fmt::Debug for PreviewInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreviewInput")
            .field("exit_code", &self.exit_code)
            .field("stdout_len", &self.stdout.len())
            .field("stderr_len", &self.stderr.len())
            .field("stdout_truncated", &self.stdout_truncated)
            .field("stderr_truncated", &self.stderr_truncated)
            .finish()
    }
}

/// A fully parsed removal preview.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RemovalPreview {
    backend: RemovalBackend,
    backend_version: Option<String>,
    requested_package: String,
    planned_removals: Vec<PlannedRemoval>,
    summary_count: usize,
    exit: PreviewExit,
    command_identity: PreviewCommandIdentity,
}

impl RemovalPreview {
    pub(super) fn new(
        backend: RemovalBackend,
        requested_package: String,
        planned_removals: Vec<PlannedRemoval>,
        summary_count: usize,
        exit: PreviewExit,
        command_identity: PreviewCommandIdentity,
        backend_version: Option<&str>,
    ) -> Self {
        RemovalPreview {
            backend,
            backend_version: backend_version.map(ToOwned::to_owned),
            requested_package,
            planned_removals,
            summary_count,
            exit,
            command_identity,
        }
    }

    pub(crate) fn backend(&self) -> RemovalBackend {
        self.backend
    }

    pub(crate) fn backend_version(&self) -> Option<&str> {
        self.backend_version.as_deref()
    }

    pub(crate) fn requested_package(&self) -> &str {
        &self.requested_package
    }

    pub(crate) fn planned_removals(&self) -> &[PlannedRemoval] {
        &self.planned_removals
    }

    pub(crate) fn summary_count(&self) -> usize {
        self.summary_count
    }

    pub(crate) fn exit(&self) -> PreviewExit {
        self.exit
    }

    pub(crate) fn command_identity(&self) -> PreviewCommandIdentity {
        self.command_identity
    }
}

impl fmt::Debug for RemovalPreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemovalPreview")
            .field("backend", &self.backend)
            .field("backend_version", &self.backend_version)
            .field("requested_package", &"<redacted>")
            .field("planned_removals", &self.planned_removals)
            .field("summary_count", &self.summary_count)
            .field("exit", &self.exit)
            .field("command_identity", &self.command_identity)
            .finish()
    }
}

/// Parse one backend's preview output. This is the only entry point; each
/// backend parser is private to this module so a caller cannot accidentally
/// apply the wrong grammar.
pub(crate) fn parse_preview(
    backend: RemovalBackend,
    requested: &str,
    input: PreviewInput<'_>,
    no_autoremove: bool,
) -> Result<RemovalPreview, RemovalSafetyError> {
    if backend == RemovalBackend::Apt && no_autoremove {
        return Err(RemovalSafetyError::configuration());
    }
    match backend {
        RemovalBackend::Apt => apt::parse(requested, input),
        RemovalBackend::Dnf4 | RemovalBackend::Dnf5 => {
            dnf::parse(backend, requested, input, no_autoremove)
        }
    }
}

/// An exact-name allow-list for additional removals. It has no wildcard,
/// regular-expression or prefix mode: every entry is a complete package name.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct RemovalAllowList {
    names: BTreeSet<String>,
}

impl fmt::Debug for RemovalAllowList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemovalAllowList")
            .field("entry_count", &self.names.len())
            .finish()
    }
}

impl RemovalAllowList {
    pub(crate) fn empty() -> Self {
        RemovalAllowList::default()
    }

    /// Build an allow-list from exact package names. Wildcards and malformed
    /// names are rejected; duplicates are rejected rather than silently
    /// collapsed.
    pub(crate) fn from_names<I, S>(names: I) -> Result<Self, RemovalSafetyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = RemovalAllowList::empty();
        for name in names {
            let name = name.as_ref();
            if !valid_package_name(name) {
                return Err(RemovalSafetyError::identity());
            }
            if out.names.contains(name) {
                return Err(RemovalSafetyError::identity());
            }
            out.names.insert(name.to_string());
        }
        Ok(out)
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    pub(crate) fn len(&self) -> usize {
        self.names.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// The safety decision for one preview. `Denied` is the default when the
/// planned set contains anything not requested/allowed. `Indeterminate` means
/// the contract cannot be established at all (missing requested package,
/// ambiguous identities), and is never rounded to `Allowed`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum RemovalSafetyDecision {
    Allowed {
        requested: String,
        additional: Vec<PlannedRemoval>,
    },
    Denied {
        unexpected: Vec<PlannedRemoval>,
    },
    Indeterminate {
        error: RemovalSafetyError,
    },
}

impl RemovalSafetyDecision {
    pub(crate) fn is_allowed(&self) -> bool {
        matches!(self, RemovalSafetyDecision::Allowed { .. })
    }

    pub(crate) fn is_denied(&self) -> bool {
        matches!(self, RemovalSafetyDecision::Denied { .. })
    }

    /// Number of planned removals that were not requested or allow-listed.
    pub(crate) fn unexpected_count(&self) -> Option<usize> {
        match self {
            RemovalSafetyDecision::Denied { unexpected } => Some(unexpected.len()),
            _ => None,
        }
    }

    /// Convert a refusal to Sinter's pre-mutation error contract. `Allowed`
    /// has no error. A denial is a definite `Apply` failure with no mutation;
    /// an indeterminate decision keeps the category-specific message. The
    /// `sensitive` flag controls whether package identities may appear in the
    /// human-readable message.
    pub(crate) fn to_sinter_error(&self, sensitive: bool) -> Option<SinterError> {
        match self {
            RemovalSafetyDecision::Allowed { .. } => None,
            RemovalSafetyDecision::Denied { .. } => {
                Some(SinterError::apply(self.render(sensitive)))
            }
            RemovalSafetyDecision::Indeterminate { error } => Some(error.to_sinter_error()),
        }
    }

    /// Render a human-readable reason. When `sensitive` is true no package
    /// name, version or architecture is included; counts and the category are
    /// retained. This is the only supported rendering path for a resource.
    pub(crate) fn render(&self, sensitive: bool) -> String {
        match self {
            RemovalSafetyDecision::Allowed { additional, .. } => {
                format!(
                    "package removal preview is allowed ({} additional removal(s))",
                    additional.len()
                )
            }
            RemovalSafetyDecision::Denied { unexpected } => {
                if sensitive {
                    format!(
                        "package removal preview would remove {} package(s) that were not requested; nothing was changed",
                        unexpected.len()
                    )
                } else {
                    let names: Vec<&str> = unexpected.iter().map(|p| p.identity.name()).collect();
                    format!(
                        "package removal preview would remove {} package(s) that were not requested: {}; nothing was changed",
                        unexpected.len(),
                        names.join(", ")
                    )
                }
            }
            RemovalSafetyDecision::Indeterminate { error } => error.render(sensitive),
        }
    }
}

impl fmt::Debug for RemovalSafetyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemovalSafetyDecision::Allowed { additional, .. } => f
                .debug_struct("Allowed")
                .field("requested", &"<redacted>")
                .field("additional", additional)
                .finish(),
            RemovalSafetyDecision::Denied { unexpected } => f
                .debug_struct("Denied")
                .field("unexpected", unexpected)
                .finish(),
            RemovalSafetyDecision::Indeterminate { error } => f
                .debug_struct("Indeterminate")
                .field("error", error)
                .finish(),
        }
    }
}

/// Apply the exact-set contract to a parsed preview.
///
/// The default allow-list is empty, so any removal other than the requested
/// package is denied. A name in the allow-list permits that name only; if the
/// planned set contains more than one architecture or version for an allowed
/// extra name, the identity is ambiguous and the decision is indeterminate.
pub(crate) fn evaluate(
    preview: &RemovalPreview,
    allow: &RemovalAllowList,
) -> RemovalSafetyDecision {
    if preview.exit.is_noop() || preview.planned_removals.is_empty() {
        return RemovalSafetyDecision::Indeterminate {
            error: RemovalSafetyError::requested_missing(),
        };
    }

    if preview.summary_count != preview.planned_removals.len() {
        return RemovalSafetyDecision::Indeterminate {
            error: RemovalSafetyError::summary(
                preview.summary_count,
                preview.planned_removals.len(),
            ),
        };
    }
    let mut planned_seen = BTreeSet::new();
    for planned in &preview.planned_removals {
        if !planned_seen.insert((
            planned.identity.name().to_string(),
            planned.identity.architecture().map(ToOwned::to_owned),
            planned.identity.version().map(ToOwned::to_owned),
        )) {
            return RemovalSafetyDecision::Indeterminate {
                error: RemovalSafetyError::identity(),
            };
        }
    }

    let requested = preview.requested_package.as_str();
    let requested_identities: Vec<&PlannedRemoval> = preview
        .planned_removals
        .iter()
        .filter(|p| p.identity.is_requested_name(requested))
        .collect();
    if requested_identities.is_empty() {
        return RemovalSafetyDecision::Indeterminate {
            error: RemovalSafetyError::requested_missing(),
        };
    }
    // A requested name that resolves to more than one architecture is an
    // ambiguous identity, even though the user asked only by name. A name
    // with several versions on one architecture is a normal installonly case
    // and remains allowed.
    let requested_architectures: BTreeSet<Option<&str>> = requested_identities
        .iter()
        .map(|p| p.identity.architecture())
        .collect();
    if requested_architectures.len() > 1 {
        return RemovalSafetyDecision::Indeterminate {
            error: RemovalSafetyError::identity(),
        };
    }

    // An allowed extra whose name matches more than one architecture or more
    // than one version cannot be authorized by a name-only allow-list entry.
    for planned in &preview.planned_removals {
        if planned.identity.is_requested_name(requested) || !allow.contains(planned.identity.name())
        {
            continue;
        }
        let same_name: Vec<&PlannedRemoval> = preview
            .planned_removals
            .iter()
            .filter(|p| p.identity.name() == planned.identity.name())
            .collect();
        let architectures: BTreeSet<Option<&str>> = same_name
            .iter()
            .map(|p| p.identity.architecture())
            .collect();
        let versions: BTreeSet<Option<&str>> =
            same_name.iter().map(|p| p.identity.version()).collect();
        if architectures.len() > 1 || versions.len() > 1 {
            return RemovalSafetyDecision::Indeterminate {
                error: RemovalSafetyError::identity(),
            };
        }
    }

    let unexpected: Vec<PlannedRemoval> = preview
        .planned_removals
        .iter()
        .filter(|p| !p.identity.is_requested_name(requested) && !allow.contains(p.identity.name()))
        .cloned()
        .collect();
    if !unexpected.is_empty() {
        return RemovalSafetyDecision::Denied { unexpected };
    }

    let additional: Vec<PlannedRemoval> = preview
        .planned_removals
        .iter()
        .filter(|p| !p.identity.is_requested_name(requested))
        .cloned()
        .collect();
    RemovalSafetyDecision::Allowed {
        requested: requested.to_string(),
        additional,
    }
}

// ---------------------------------------------------------------------------
// Error contract
// ---------------------------------------------------------------------------

/// Categories of a fail-closed removal-safety refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemovalSafetyCategory {
    PreviewCommandFailed,
    PreviewAbortUnexpected,
    PreviewParseFailed,
    PreviewSummaryMismatch,
    PackageIdentityAmbiguous,
    UnexpectedRemoval,
    InventoryChanged,
    ActualRemovalMismatch,
    RequestedPackageMissing,
    BackendMismatch,
    PreviewConfigurationInvalid,
    PrivilegeRequired,
}

impl RemovalSafetyCategory {
    pub(crate) fn label(self) -> &'static str {
        match self {
            RemovalSafetyCategory::PreviewCommandFailed => "preview_command_failed",
            RemovalSafetyCategory::PreviewAbortUnexpected => "preview_abort_unexpected",
            RemovalSafetyCategory::PreviewParseFailed => "preview_parse_failed",
            RemovalSafetyCategory::PreviewSummaryMismatch => "preview_summary_mismatch",
            RemovalSafetyCategory::PackageIdentityAmbiguous => "package_identity_ambiguous",
            RemovalSafetyCategory::UnexpectedRemoval => "unexpected_removal",
            RemovalSafetyCategory::InventoryChanged => "inventory_changed",
            RemovalSafetyCategory::ActualRemovalMismatch => "actual_removal_mismatch",
            RemovalSafetyCategory::RequestedPackageMissing => "requested_package_missing",
            RemovalSafetyCategory::BackendMismatch => "backend_mismatch",
            RemovalSafetyCategory::PreviewConfigurationInvalid => "preview_configuration_invalid",
            RemovalSafetyCategory::PrivilegeRequired => "privilege_required",
        }
    }
}

/// A safety refusal. It never carries raw stdout/stderr and never carries a
/// package name/version/architecture: only a category, an optional count and
/// an optional line number. That makes `Debug` and `Display` safe for a
/// sensitive resource by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemovalSafetyError {
    category: RemovalSafetyCategory,
    count: Option<usize>,
    line: Option<usize>,
    summary_counts: Option<(usize, usize)>,
}

impl RemovalSafetyError {
    pub(super) fn parse(line: Option<usize>) -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::PreviewParseFailed,
            count: None,
            line,
            summary_counts: None,
        }
    }

    pub(super) fn summary(expected: usize, actual: usize) -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::PreviewSummaryMismatch,
            count: None,
            line: None,
            summary_counts: Some((expected, actual)),
        }
    }

    pub(crate) fn command_failed() -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::PreviewCommandFailed,
            count: None,
            line: None,
            summary_counts: None,
        }
    }

    pub(crate) fn abort_unexpected() -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::PreviewAbortUnexpected,
            count: None,
            line: None,
            summary_counts: None,
        }
    }

    pub(crate) fn identity() -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::PackageIdentityAmbiguous,
            count: None,
            line: None,
            summary_counts: None,
        }
    }

    pub(crate) fn unexpected_removal(count: usize) -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::UnexpectedRemoval,
            count: Some(count),
            line: None,
            summary_counts: None,
        }
    }

    pub(crate) fn inventory_changed() -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::InventoryChanged,
            count: None,
            line: None,
            summary_counts: None,
        }
    }

    pub(crate) fn actual_mismatch(count: usize) -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::ActualRemovalMismatch,
            count: Some(count),
            line: None,
            summary_counts: None,
        }
    }

    pub(crate) fn requested_missing() -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::RequestedPackageMissing,
            count: None,
            line: None,
            summary_counts: None,
        }
    }

    fn configuration() -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::PreviewConfigurationInvalid,
            count: None,
            line: None,
            summary_counts: None,
        }
    }

    pub(crate) fn privilege_required() -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::PrivilegeRequired,
            count: None,
            line: None,
            summary_counts: None,
        }
    }

    pub(crate) fn backend_mismatch() -> Self {
        RemovalSafetyError {
            category: RemovalSafetyCategory::BackendMismatch,
            count: None,
            line: None,
            summary_counts: None,
        }
    }

    pub(crate) fn category(&self) -> RemovalSafetyCategory {
        self.category
    }

    /// Whether the contract could not be established (as opposed to a
    /// definite "unexpected removals" refusal). R1 does not map this to a
    /// `SinterError` kind; it exposes the distinction for the R2/R3 caller.
    pub(crate) fn is_indeterminate(&self) -> bool {
        matches!(
            self.category,
            RemovalSafetyCategory::PreviewCommandFailed
                | RemovalSafetyCategory::PreviewAbortUnexpected
                | RemovalSafetyCategory::PreviewParseFailed
                | RemovalSafetyCategory::PreviewSummaryMismatch
                | RemovalSafetyCategory::PackageIdentityAmbiguous
                | RemovalSafetyCategory::InventoryChanged
                | RemovalSafetyCategory::RequestedPackageMissing
                | RemovalSafetyCategory::BackendMismatch
        )
    }

    /// Human-readable fixed text. No package identity is included; `sensitive`
    /// is accepted so callers can keep one rendering path, but the result is
    /// identical for both values.
    pub(crate) fn render(&self, _sensitive: bool) -> String {
        let mut text = match self.category {
            RemovalSafetyCategory::PreviewCommandFailed => {
                "package removal preview command did not complete"
            }
            RemovalSafetyCategory::PreviewAbortUnexpected => {
                "package removal preview aborted unexpectedly"
            }
            RemovalSafetyCategory::PreviewParseFailed => {
                "package removal preview output could not be parsed"
            }
            RemovalSafetyCategory::PreviewSummaryMismatch => {
                "package removal preview summary does not match the parsed removals"
            }
            RemovalSafetyCategory::PackageIdentityAmbiguous => {
                "package removal identity is ambiguous"
            }
            RemovalSafetyCategory::UnexpectedRemoval => {
                "package removal preview includes packages that were not requested"
            }
            RemovalSafetyCategory::InventoryChanged => {
                "package inventory changed while the removal preview was evaluated"
            }
            RemovalSafetyCategory::ActualRemovalMismatch => {
                "package removal result does not match the previewed removal set"
            }
            RemovalSafetyCategory::RequestedPackageMissing => {
                "package removal preview does not contain the requested package"
            }
            RemovalSafetyCategory::BackendMismatch => {
                "package removal preview backend does not match the inventory backend"
            }
            RemovalSafetyCategory::PreviewConfigurationInvalid => {
                "invalid package removal preview configuration"
            }
            RemovalSafetyCategory::PrivilegeRequired => {
                "package removal requires root or --sudo; nothing was changed"
            }
        }
        .to_string();
        if let Some((expected, actual)) = self.summary_counts {
            text.push_str(&format!(" (summary {expected}, parsed {actual})"));
        } else if let Some(count) = self.count {
            text.push_str(&format!(" ({count} package(s))"));
        }
        if let Some(line) = self.line {
            text.push_str(&format!(" (line {line})"));
        }
        text
    }

    /// Connect a refusal to Sinter's existing pre-mutation error contract.
    /// No mutation was dispatched, so `Change`/`MutationState` must stay
    /// `None`; `SinterError::apply` carries exactly that state.
    pub(crate) fn to_sinter_error(&self) -> SinterError {
        match self.category {
            // A post-mutation mismatch must not claim that nothing changed.
            // The exact change set is decided by the caller's delta; at the
            // error-contract boundary Possible is the truthful conservative
            // state.
            RemovalSafetyCategory::ActualRemovalMismatch => {
                SinterError::apply(self.render(false)).possible()
            }
            // Invalid internal preview configuration is a schema/usage error,
            // not a target command failure.
            RemovalSafetyCategory::PreviewConfigurationInvalid => {
                SinterError::schema(self.render(false))
            }
            _ => SinterError::apply(self.render(false)),
        }
    }
}

impl fmt::Display for RemovalSafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render(false))
    }
}

impl std::error::Error for RemovalSafetyError {}

// ---------------------------------------------------------------------------
// Identity validation
// ---------------------------------------------------------------------------

/// Same character contract Sinter applies to a package resource name.
fn valid_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_PACKAGE_NAME {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~'))
}

fn valid_architecture(arch: &str) -> bool {
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
