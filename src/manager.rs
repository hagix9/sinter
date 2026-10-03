//! systemd manager synchronization (`daemon-reload`).
//!
//! Sinter manages systemd unit files, drop-ins and related symlinks through
//! the ordinary `file` / `template` / `link` resources. systemd keeps its own
//! loaded copy of that configuration and only re-reads it on `daemon-reload`,
//! so a changed unit has no effect on a service decision until the manager is
//! synchronized. This module holds the internal, typed state and the strict
//! parsers for that synchronization. It introduces no resource type, handler
//! action or recipe option.
//!
//! The contract in short:
//!
//! * a producer (`file`/`template`/`link`) that really changes a recognized
//!   system-manager input records a typed [`PendingChange`];
//! * a consumer (service, notified handler, end of run) calls
//!   `Engine::manager_sync`, which reloads when there is pending input or when
//!   a fresh `NeedDaemonReload=yes` is observed, and always re-observes;
//! * `NeedDaemonReload=no` is a limited observation, never proof that the
//!   loaded definition equals the bytes on disk;
//! * plan and audit only observe; they never reload.

use crate::error::{Result, SinterError};
use crate::result::{Change, Execution, Verification};
use std::collections::BTreeSet;

/// Unit-type suffixes whose files/drop-ins are system-manager input.
/// `.scope` and `.device` units cannot be configured through files.
const UNIT_SUFFIXES: [&str; 9] = [
    "service",
    "socket",
    "target",
    "timer",
    "path",
    "mount",
    "automount",
    "swap",
    "slice",
];

/// Exact, finite table of system-manager configuration files: `system.conf`
/// and its standard drop-in directories. `user.conf` (the user manager) and
/// every other `/etc/systemd` file are deliberately absent.
const MANAGER_CONFIG_FILES: [&str; 1] = ["/etc/systemd/system.conf"];
const MANAGER_CONFIG_DROPIN_DIRS: [&str; 4] = [
    "/etc/systemd/system.conf.d",
    "/run/systemd/system.conf.d",
    "/usr/lib/systemd/system.conf.d",
    "/usr/local/lib/systemd/system.conf.d",
];

/// Placeholder stored in place of any diagnostic derived from a sensitive
/// manager synchronization episode. The raw text is never kept.
pub(crate) const REDACTED_REASON: &str = "<redacted>";

/// The diagnostic to store for a manager operation: the raw message for an
/// ordinary episode, never the raw message for a sensitive one.
pub(crate) fn episode_reason(sensitive: bool, message: &str) -> String {
    if sensitive {
        REDACTED_REASON.to_string()
    } else {
        message.to_string()
    }
}

/// What kind of manager input a managed path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagerInputKind {
    UnitFile,
    DropIn,
    /// Alias / mask / `.wants` / `.requires` style link.
    UnitLink,
    ManagerConfig,
}

/// A managed path that the system manager reads. Produced by classification
/// *before* any mutation so that an unusable UnitPath query stops the
/// resource instead of being guessed around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagerInput {
    pub(crate) kind: ManagerInputKind,
    /// The unit that `systemctl show` can query directly for this input
    /// (`None` for template, type-wide, prefix, `.wants` and manager-config
    /// inputs, where no single unit name is safely derivable).
    pub(crate) unit: Option<String>,
}

/// What the lexical (filename only) pre-filter recognized. It decides whether
/// the target UnitPath has to be asked at all; the authoritative decision is
/// the comparison against the manager's own UnitPath roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathShape {
    /// `<dir>/<name>.<suffix>`: unit file, alias or mask link.
    UnitFile {
        dir: String,
        name: String,
        link: bool,
    },
    /// `<root>/<stem>.d/<file>.conf`.
    DropIn { root: String, stem: String },
    /// `<root>/<stem>.wants|requires/<name>.<suffix>` (links only).
    Wants { root: String },
    /// A path from the finite manager-config table.
    ManagerConfig,
}

/// A change recorded by a producer that the manager has not yet loaded.
#[derive(Debug, Clone)]
pub(crate) struct PendingChange {
    pub(crate) resource_id: String,
    /// The reload generation current when the change was recorded; a reload
    /// covers every change recorded under a generation up to its own.
    pub(crate) generation: u64,
    pub(crate) sensitive: bool,
}

/// Why a manager reload ran (or is planned).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerReloadTrigger {
    /// A producer changed recognized manager input.
    PendingInput,
    /// A fresh observation reported `NeedDaemonReload=yes`.
    ObservedStale,
    /// A changed package was expected to provide a unit the manager had not
    /// discovered.
    PackageDiscovery,
}

impl ManagerReloadTrigger {
    pub fn label(self) -> &'static str {
        match self {
            ManagerReloadTrigger::PendingInput => "pending_input",
            ManagerReloadTrigger::ObservedStale => "observed_stale",
            ManagerReloadTrigger::PackageDiscovery => "package_discovery",
        }
    }
}

/// Where in the run the manager synchronization happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerReloadPhase {
    /// Before a service resource's observation/decision.
    Resource,
    /// Before a notified handler.
    Handler,
    /// After all resources and handlers.
    Final,
    /// Plan only: a reload that apply would perform.
    Planned,
}

impl ManagerReloadPhase {
    pub fn label(self) -> &'static str {
        match self {
            ManagerReloadPhase::Resource => "resource",
            ManagerReloadPhase::Handler => "handler",
            ManagerReloadPhase::Final => "final",
            ManagerReloadPhase::Planned => "planned",
        }
    }
}

/// One manager maintenance operation: neither a resource nor a handler. It
/// reuses the closed execution/change/verification value sets.
#[derive(Debug, Clone)]
pub struct ManagerReloadResult {
    pub phase: ManagerReloadPhase,
    pub trigger: ManagerReloadTrigger,
    /// Resource IDs whose input changes this reload covers.
    pub causes: Vec<String>,
    /// The service resource or handler whose decision required it.
    pub consumer: Option<String>,
    pub execution: Execution,
    pub change: Change,
    pub verification: Verification,
    pub reason: Option<String>,
    /// Plan only: the operation's outcome cannot be known before apply.
    pub unknown: bool,
    /// A cause or consumer was sensitive: `reason` is redacted on output.
    pub sensitive: bool,
}

impl ManagerReloadResult {
    pub fn is_failure(&self) -> bool {
        self.execution == Execution::Failed || self.verification == Verification::Failed
    }

    pub fn is_indeterminate(&self) -> bool {
        self.execution == Execution::Indeterminate || self.verification == Verification::Unknown
    }
}

/// Target-local, per-invocation manager synchronization state.
#[derive(Debug, Default)]
pub(crate) struct ManagerState {
    /// UnitPath roots, cached after the first successful query.
    pub(crate) unit_roots: Option<Vec<String>>,
    /// Real (apply) or projected (plan) producer changes not yet reloaded.
    pub(crate) pending: Vec<PendingChange>,
    /// Count of reloads that completed; changes recorded under an older
    /// generation were covered by that reload.
    pub(crate) generation: u64,
    /// Units that a managed unit file/drop-in names directly, with the
    /// recording resource. Queried for `NeedDaemonReload` at the end of a run
    /// even when nothing changed.
    pub(crate) managed_units: Vec<(String, String, bool)>,
    /// IDs of resources that succeeded with a definite change.
    pub(crate) changed_ids: BTreeSet<String>,
    pub(crate) reloads: Vec<ManagerReloadResult>,
    /// Set once a reload failed or became indeterminate: no further reload is
    /// attempted in this invocation (no retry loop).
    pub(crate) blocked: Option<String>,
    /// Why the most recent handler could not start (manager sync/observation).
    pub(crate) last_handler_failure: Option<String>,
}

impl ManagerState {
    pub(crate) fn pending_causes(&self) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for p in &self.pending {
            if seen.insert(p.resource_id.clone()) {
                out.push(p.resource_id.clone());
            }
        }
        out
    }

    pub(crate) fn pending_sensitive(&self) -> bool {
        self.pending.iter().any(|p| p.sensitive)
    }

    pub(crate) fn note_managed_unit(&mut self, unit: &str, resource_id: &str, sensitive: bool) {
        if !self.managed_units.iter().any(|(u, _, _)| u == unit) {
            self.managed_units
                .push((unit.to_string(), resource_id.to_string(), sensitive));
        }
    }
}

// ---------------------------------------------------------------------------
// Path recognition
// ---------------------------------------------------------------------------

/// Whether `name` is a plausible unit name with a configurable unit suffix.
/// Returns the stem (the part before the suffix) when it is.
fn unit_name_parts(name: &str) -> Option<(&str, &str)> {
    let (stem, suffix) = name.rsplit_once('.')?;
    if stem.is_empty() || !UNIT_SUFFIXES.contains(&suffix) {
        return None;
    }
    // systemd unit-name alphabet; `\` appears in escaped names.
    if name.len() > 255
        || !name.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.' | b'\\' | b'@' | b'-')
        })
    {
        return None;
    }
    Some((stem, suffix))
}

/// A template unit file name such as `foo@.service`.
fn is_template_name(name: &str) -> bool {
    match unit_name_parts(name) {
        Some((stem, _)) => stem.ends_with('@'),
        None => false,
    }
}

/// A prefix drop-in directory stem such as `foo-.service` (applies to every
/// unit whose name starts with `foo-`).
fn is_prefix_dropin_stem(stem_with_suffix: &str) -> bool {
    match unit_name_parts(stem_with_suffix) {
        Some((stem, _)) => stem.ends_with('-'),
        None => false,
    }
}

fn parent_of(path: &str) -> Option<(&str, &str)> {
    let i = path.rfind('/')?;
    if i == 0 {
        return None;
    }
    Some((&path[..i], &path[i + 1..]))
}

/// Lexical, filename-only recognition of a managed path. Never touches the
/// target. `link` selects the alias/mask/`.wants` vocabulary.
pub(crate) fn path_shape(path: &str, link: bool) -> Option<PathShape> {
    if !path.starts_with('/') {
        return None;
    }
    // Manager configuration is recognized for regular files and for symlinks
    // alike: a vendor drop-in is masked with a `/dev/null` symlink, and
    // creating, retargeting or removing that link changes what the manager
    // reparses. The match is lexical on the managed path only; the link
    // target is never followed.
    if MANAGER_CONFIG_FILES.contains(&path) {
        return Some(PathShape::ManagerConfig);
    }
    let (dir, name) = parent_of(path)?;
    if !link || !is_wants_dir(dir) {
        if name.ends_with(".conf")
            && name.len() > ".conf".len()
            && MANAGER_CONFIG_DROPIN_DIRS.contains(&dir)
        {
            return Some(PathShape::ManagerConfig);
        }
        // Drop-in: `<root>/<stem>.d/<file>.conf`.
        if name.ends_with(".conf") && name.len() > ".conf".len() {
            if let Some((root, dirname)) = parent_of(dir) {
                if let Some(stem) = dirname.strip_suffix(".d") {
                    let type_wide = UNIT_SUFFIXES.contains(&stem);
                    if type_wide || unit_name_parts(stem).is_some() {
                        return Some(PathShape::DropIn {
                            root: root.to_string(),
                            stem: stem.to_string(),
                        });
                    }
                }
            }
        }
        if unit_name_parts(name).is_some() {
            return Some(PathShape::UnitFile {
                dir: dir.to_string(),
                name: name.to_string(),
                link,
            });
        }
        return None;
    }
    // link inside a `.wants` / `.requires` directory
    if unit_name_parts(name).is_some() {
        let (root, _) = parent_of(dir)?;
        return Some(PathShape::Wants {
            root: root.to_string(),
        });
    }
    None
}

fn is_wants_dir(dir: &str) -> bool {
    let Some((_, base)) = parent_of(dir) else {
        return false;
    };
    for ext in [".wants", ".requires"] {
        if let Some(stem) = base.strip_suffix(ext) {
            return unit_name_parts(stem).is_some();
        }
    }
    false
}

/// Combine the lexical shape with the manager's own UnitPath roots. `None`
/// means the path is not (known to be) system-manager input.
pub(crate) fn resolve_input(shape: &PathShape, roots: &[String]) -> Option<ManagerInput> {
    let in_roots = |dir: &str| roots.iter().any(|r| r == dir);
    match shape {
        PathShape::ManagerConfig => Some(ManagerInput {
            kind: ManagerInputKind::ManagerConfig,
            unit: None,
        }),
        PathShape::UnitFile { dir, name, link } => {
            if !in_roots(dir) {
                return None;
            }
            Some(ManagerInput {
                kind: if *link {
                    ManagerInputKind::UnitLink
                } else {
                    ManagerInputKind::UnitFile
                },
                unit: if is_template_name(name) {
                    None
                } else {
                    Some(name.clone())
                },
            })
        }
        PathShape::DropIn { root, stem } => {
            if !in_roots(root) {
                return None;
            }
            let direct = unit_name_parts(stem).is_some()
                && !is_template_name(stem)
                && !is_prefix_dropin_stem(stem);
            Some(ManagerInput {
                kind: ManagerInputKind::DropIn,
                unit: if direct { Some(stem.clone()) } else { None },
            })
        }
        PathShape::Wants { root } => {
            if !in_roots(root) {
                return None;
            }
            Some(ManagerInput {
                kind: ManagerInputKind::UnitLink,
                unit: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// systemctl output parsers
// ---------------------------------------------------------------------------

/// Parse the output of `systemctl show --property=UnitPath`.
///
/// Grammar accepted (anything else is an error, never a guess): exactly one
/// record `UnitPath=<value>\n`; the value is a non-empty sequence of absolute
/// canonical paths separated by single spaces. A path is either unquoted
/// (no whitespace, quote, backslash or control character) or double-quoted
/// with the escapes `\\ \" \$ \`` that systemctl's shell-style quoting
/// produces. No shell is involved and nothing is split on bare whitespace
/// inside a quoted path.
pub(crate) fn parse_unit_path(text: &str) -> Result<Vec<String>> {
    let fail = |why: &str| SinterError::apply(format!("systemd UnitPath query: {}", why));
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| fail("output is not newline terminated"))?;
    if body.contains('\n') {
        return Err(fail("expected exactly one record"));
    }
    let value = body
        .strip_prefix("UnitPath=")
        .ok_or_else(|| fail("record is not UnitPath"))?;
    if value.is_empty() {
        return Err(fail("UnitPath is empty"));
    }
    let chars: Vec<char> = value.chars().collect();
    let mut roots: Vec<String> = Vec::new();
    let mut i = 0usize;
    loop {
        let mut token = String::new();
        if chars.get(i) == Some(&'"') {
            i += 1;
            loop {
                match chars.get(i) {
                    None => return Err(fail("unterminated quoted path")),
                    Some('"') => {
                        i += 1;
                        break;
                    }
                    Some('\\') => {
                        match chars.get(i + 1) {
                            Some(c @ ('\\' | '"' | '$' | '`')) => token.push(*c),
                            _ => return Err(fail("unsupported escape in quoted path")),
                        }
                        i += 2;
                    }
                    Some(c) => {
                        token.push(*c);
                        i += 1;
                    }
                }
            }
        } else {
            while let Some(c) = chars.get(i) {
                if *c == ' ' {
                    break;
                }
                if matches!(c, '"' | '\\' | '\'') {
                    return Err(fail("unexpected quoting in unquoted path"));
                }
                token.push(*c);
                i += 1;
            }
        }
        if token.is_empty() {
            return Err(fail("empty path entry"));
        }
        if token.chars().any(|c| c.is_control()) {
            return Err(fail("path entry contains a control character"));
        }
        if token == "/" || crate::paths::validate_path(&token).is_err() {
            return Err(fail("path entry is not an absolute canonical path"));
        }
        roots.push(token);
        match chars.get(i) {
            None => break,
            Some(' ') => {
                i += 1;
                if i >= chars.len() {
                    return Err(fail("trailing separator"));
                }
            }
            Some(_) => return Err(fail("path entries must be separated by one space")),
        }
    }
    Ok(roots)
}

/// Parse a strict `yes`/`no` property value.
pub(crate) fn parse_yes_no(value: &str) -> Option<bool> {
    match value {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Engine integration: classification, reload, synchronization gate
// ---------------------------------------------------------------------------

use crate::engine::{Engine, Mode};
use crate::executor::{Completion, ExecRequest};
use crate::model::FrozenResource;
use crate::resources::{baseline_env, ServiceObs};

impl Engine {
    /// Ask the target manager for its UnitPath once per invocation. A failed
    /// or unparsable answer is an error: nothing is guessed, and callers run
    /// this *before* any mutation of the path that needed it.
    fn manager_unit_roots(&mut self) -> Result<Vec<String>> {
        if let Some(r) = &self.manager.unit_roots {
            return Ok(r.clone());
        }
        let out = self.fs.systemctl_show_unit_path()?;
        match out.completion {
            Completion::Exited(0) => {}
            Completion::Exited(c) => {
                return Err(SinterError::apply(format!(
                    "systemd UnitPath query failed: systemctl exited {}",
                    c
                )))
            }
            Completion::Signaled(s) => {
                return Err(SinterError::apply(format!(
                    "systemd UnitPath query terminated by signal {}",
                    s
                )))
            }
            Completion::Indeterminate { reason, .. } => {
                return Err(SinterError::apply(format!(
                    "systemd UnitPath query did not complete: {}",
                    reason
                )))
            }
        }
        if out.stdout_truncated || out.stderr_truncated {
            return Err(SinterError::apply(
                "systemd UnitPath query output was truncated or incomplete",
            ));
        }
        let text = std::str::from_utf8(&out.stdout)
            .map_err(|_| SinterError::apply("systemd UnitPath query captured invalid UTF-8"))?;
        let roots = parse_unit_path(text)?;
        self.manager.unit_roots = Some(roots.clone());
        Ok(roots)
    }

    /// Decide, before any mutation, whether a managed path is system-manager
    /// input. Only paths whose *filename* looks like manager input cause a
    /// UnitPath query; an ordinary application config never does.
    pub(crate) fn classify_manager_input(
        &mut self,
        res: &FrozenResource,
        path: &str,
        link: bool,
    ) -> Result<Option<ManagerInput>> {
        let Some(shape) = path_shape(path, link) else {
            return Ok(None);
        };
        let roots = if matches!(shape, PathShape::ManagerConfig) {
            Vec::new()
        } else {
            self.manager_unit_roots()?
        };
        let input = resolve_input(&shape, &roots);
        if let Some(i) = &input {
            if matches!(
                i.kind,
                ManagerInputKind::UnitFile | ManagerInputKind::DropIn
            ) {
                if let Some(unit) = &i.unit {
                    self.manager.note_managed_unit(
                        unit,
                        &res.id,
                        res.sensitive || res.derived_sensitive,
                    );
                }
            }
        }
        Ok(input)
    }

    /// A producer really changed (apply) or would change (plan) recognized
    /// manager input. Metadata-only changes never reach this.
    pub(crate) fn record_manager_change(
        &mut self,
        res: &FrozenResource,
        input: &Option<ManagerInput>,
    ) {
        if input.is_some() {
            self.manager.pending.push(PendingChange {
                resource_id: res.id.clone(),
                generation: self.manager.generation,
                sensitive: res.sensitive || res.derived_sensitive,
            });
        }
    }

    /// Run `systemctl daemon-reload` (apply only) and record the operation.
    /// Success clears every pending change (all are older than this reload);
    /// failure or uncertainty is recorded, blocks any further reload in this
    /// invocation, and is returned as an error. Never retried.
    pub(crate) fn manager_reload(
        &mut self,
        phase: ManagerReloadPhase,
        trigger: ManagerReloadTrigger,
        consumer: Option<&str>,
        causes: Vec<String>,
        sensitive: bool,
    ) -> Result<usize> {
        if let Some(prev) = &self.manager.blocked {
            return Err(SinterError::apply(format!(
                "daemon-reload not attempted: an earlier manager reload did not succeed ({})",
                prev
            )));
        }
        let permit = self.fs.mutation_permit()?;
        let mut req = ExecRequest::new("/usr/bin/systemctl");
        req.args = vec!["daemon-reload".to_string()];
        req.env = baseline_env(self.fs.home_env());
        let record =
            |execution, change, verification, reason: Option<String>| ManagerReloadResult {
                phase,
                trigger,
                causes: causes.clone(),
                consumer: consumer.map(|c| c.to_string()),
                execution,
                change,
                verification,
                reason,
                unknown: false,
                sensitive,
            };
        let outcome: std::result::Result<(), SinterError> = match self.fs.exec(&permit, &req) {
            Ok(out) => match out.completion {
                Completion::Exited(0) => Ok(()),
                Completion::Exited(c) => {
                    let detail = if sensitive {
                        String::new()
                    } else {
                        let e = String::from_utf8_lossy(&out.stderr);
                        let e = crate::diff::sanitize_line(e.trim());
                        if e.is_empty() {
                            String::new()
                        } else {
                            format!(": {}", e)
                        }
                    };
                    Err(SinterError::apply(format!(
                        "systemctl daemon-reload failed with exit code {}{}",
                        c, detail
                    ))
                    .possible())
                }
                Completion::Signaled(s) => Err(SinterError::indeterminate(format!(
                    "systemctl daemon-reload terminated by signal {}",
                    s
                ))),
                Completion::Indeterminate { reason, .. } => {
                    Err(SinterError::indeterminate(if sensitive {
                        "systemctl daemon-reload did not complete (details redacted)".to_string()
                    } else {
                        format!("systemctl daemon-reload did not complete: {}", reason)
                    }))
                }
            },
            Err(e) => Err(e),
        };
        match outcome {
            Ok(()) => {
                let covered = self.manager.generation;
                self.manager.pending.retain(|p| p.generation > covered);
                self.manager.generation += 1;
                self.manager.reloads.push(record(
                    Execution::Succeeded,
                    Change::Changed,
                    Verification::NotPerformed,
                    None,
                ));
                Ok(self.manager.reloads.len() - 1)
            }
            Err(e) => {
                let indeterminate = e.kind == crate::error::ErrorKind::Indeterminate;
                self.manager.blocked = Some(if sensitive {
                    "details redacted".to_string()
                } else {
                    e.message.clone()
                });
                self.manager.reloads.push(record(
                    if indeterminate {
                        Execution::Indeterminate
                    } else {
                        Execution::Failed
                    },
                    Change::Possible,
                    if indeterminate {
                        Verification::Unknown
                    } else {
                        Verification::NotPerformed
                    },
                    Some(episode_reason(sensitive, &e.message)),
                ));
                Err(e)
            }
        }
    }

    fn observe_units(&mut self, units: &[(String, bool)]) -> Result<Vec<ServiceObs>> {
        let mut out = Vec::with_capacity(units.len());
        for (name, sensitive) in units {
            out.push(self.observe_service_sensitive(name, *sensitive)?);
        }
        Ok(out)
    }

    fn manager_sync_inner(
        &mut self,
        phase: ManagerReloadPhase,
        consumer: Option<&str>,
        units: &[(String, bool)],
        episode: &mut Vec<usize>,
        sensitive: bool,
    ) -> Result<Vec<ServiceObs>> {
        // `sensitive` is the effective sensitivity of the whole episode: any
        // sensitive pending producer or sensitive consumer. Every observation
        // and diagnostic of the episode uses it, so a non-sensitive consumer
        // cannot surface output derived from a sensitive producer.
        let units: Vec<(String, bool)> = units
            .iter()
            .map(|(n, s)| (n.clone(), *s || sensitive))
            .collect();
        if !self.manager.pending.is_empty() {
            let causes = self.manager.pending_causes();
            let before = self.manager.reloads.len();
            match self.manager_reload(
                phase,
                ManagerReloadTrigger::PendingInput,
                consumer,
                causes,
                sensitive,
            ) {
                Ok(i) => episode.push(i),
                Err(e) => {
                    // A failed reload recorded its own entry; a reload that
                    // was refused (an earlier one failed) recorded nothing.
                    if self.manager.reloads.len() > before {
                        episode.push(self.manager.reloads.len() - 1);
                    }
                    return Err(e);
                }
            }
        }
        let mut observed = self.observe_units(&units)?;
        if observed.iter().any(|o| o.need_daemon_reload) {
            let before = self.manager.reloads.len();
            match self.manager_reload(
                phase,
                ManagerReloadTrigger::ObservedStale,
                consumer,
                Vec::new(),
                sensitive,
            ) {
                Ok(i) => episode.push(i),
                Err(e) => {
                    if self.manager.reloads.len() > before {
                        episode.push(self.manager.reloads.len() - 1);
                    }
                    return Err(e);
                }
            }
            observed = self.observe_units(&units)?;
            if observed.iter().any(|o| o.need_daemon_reload) {
                return Err(SinterError::apply(
                    "NeedDaemonReload is still yes after daemon-reload; the manager state \
                     could not be synchronized (not retried)",
                ));
            }
        }
        Ok(observed)
    }

    /// Manager synchronization gate. Reloads when producer changes are
    /// pending or a fresh observation reports `NeedDaemonReload=yes`, then
    /// returns *fresh* observations of `units`, taken after any reload. At
    /// most one reload per cause (pending input, observed staleness); the
    /// result of the last reload in an episode carries the verification.
    pub(crate) fn manager_sync(
        &mut self,
        phase: ManagerReloadPhase,
        consumer: Option<&str>,
        units: &[(String, bool)],
    ) -> Result<Vec<ServiceObs>> {
        let mut episode: Vec<usize> = Vec::new();
        let sensitive = self.manager.pending_sensitive() || units.iter().any(|(_, s)| *s);
        let result = self.manager_sync_inner(phase, consumer, units, &mut episode, sensitive);
        self.finish_episode(&episode, units.is_empty(), result.as_ref().err());
        result
    }

    fn finish_episode(&mut self, episode: &[usize], no_units: bool, err: Option<&SinterError>) {
        let Some((&last, earlier)) = episode.split_last() else {
            return;
        };
        for &i in earlier {
            if self.manager.reloads[i].verification == Verification::NotPerformed {
                self.manager.reloads[i].verification = Verification::NotApplicable;
            }
        }
        let r = &mut self.manager.reloads[last];
        if r.execution != Execution::Succeeded {
            return; // the reload itself failed; that is already the result
        }
        match err {
            None => {
                r.verification = if no_units {
                    Verification::NotApplicable
                } else {
                    Verification::Verified
                };
            }
            Some(e) => {
                r.verification = if e.kind == crate::error::ErrorKind::Indeterminate {
                    Verification::Unknown
                } else {
                    Verification::Failed
                };
                r.reason = Some(episode_reason(r.sensitive, &e.message));
            }
        }
    }

    /// Record `NeedDaemonReload` observation for a plan consumer that cannot
    /// decide until apply has synchronized the manager.
    pub(crate) fn manager_plan_deferred(
        &mut self,
        trigger: ManagerReloadTrigger,
        consumer: &str,
        sensitive: bool,
    ) {
        self.manager.reloads.push(ManagerReloadResult {
            phase: ManagerReloadPhase::Planned,
            trigger,
            causes: Vec::new(),
            consumer: Some(consumer.to_string()),
            execution: Execution::NotRun,
            change: Change::None,
            verification: Verification::NotPerformed,
            reason: Some(
                "NeedDaemonReload=yes: apply reloads the manager before deciding".to_string(),
            ),
            unknown: true,
            sensitive,
        });
    }

    /// End of run. Apply: flush pending manager input and query managed
    /// units for `NeedDaemonReload`. Plan: report the reload apply would
    /// perform. A run that already stopped reports (does not run) an
    /// unflushed manager reload.
    pub(crate) fn manager_finish(&mut self, stopped: bool) {
        let pending_nonempty = !self.manager.pending.is_empty();
        if self.opts.mode == Mode::Plan {
            if pending_nonempty {
                let causes = self.manager.pending_causes();
                let sensitive = self.manager.pending_sensitive();
                self.manager.reloads.push(ManagerReloadResult {
                    phase: ManagerReloadPhase::Planned,
                    trigger: ManagerReloadTrigger::PendingInput,
                    causes,
                    consumer: None,
                    execution: Execution::NotRun,
                    change: Change::None,
                    verification: Verification::NotPerformed,
                    reason: Some(
                        "managed systemd input changes are planned; apply runs daemon-reload \
                         and re-observes before dependent services and handlers"
                            .to_string(),
                    ),
                    unknown: true,
                    sensitive,
                });
            }
            return;
        }
        if stopped {
            if pending_nonempty {
                let causes = self.manager.pending_causes();
                let sensitive = self.manager.pending_sensitive();
                self.manager.reloads.push(ManagerReloadResult {
                    phase: ManagerReloadPhase::Final,
                    trigger: ManagerReloadTrigger::PendingInput,
                    causes,
                    consumer: None,
                    execution: Execution::NotRun,
                    change: Change::None,
                    verification: Verification::NotPerformed,
                    reason: Some(
                        "the run stopped before the manager was synchronized; managed systemd \
                         input changed but daemon-reload was not run (re-apply, or run \
                         `systemctl daemon-reload` manually)"
                            .to_string(),
                    ),
                    unknown: false,
                    sensitive,
                });
            }
            return;
        }
        if self.manager.blocked.is_some() {
            return;
        }
        let units: Vec<(String, bool)> = self
            .manager
            .managed_units
            .iter()
            .map(|(u, _, s)| (u.clone(), *s))
            .collect();
        if !pending_nonempty && units.is_empty() {
            return;
        }
        let before = self.manager.reloads.len();
        let sensitive = units.iter().any(|(_, s)| *s) || self.manager.pending_sensitive();
        if let Err(e) = self.manager_sync(ManagerReloadPhase::Final, None, &units) {
            if self.manager.reloads.len() == before {
                // No reload was dispatched: the synchronization check itself
                // failed (for example an unobservable NeedDaemonReload).
                let indeterminate = e.kind == crate::error::ErrorKind::Indeterminate;
                self.manager.reloads.push(ManagerReloadResult {
                    phase: ManagerReloadPhase::Final,
                    trigger: ManagerReloadTrigger::ObservedStale,
                    causes: Vec::new(),
                    consumer: None,
                    execution: Execution::NotRun,
                    change: Change::None,
                    verification: if indeterminate {
                        Verification::Unknown
                    } else {
                        Verification::Failed
                    },
                    reason: Some(episode_reason(sensitive, &e.message)),
                    unknown: false,
                    sensitive,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unit_path_parses_standard_output() {
        let r = parse_unit_path(
            "UnitPath=/etc/systemd/system.control /run/systemd/system.control /etc/systemd/system /usr/lib/systemd/system\n",
        )
        .unwrap();
        assert_eq!(
            r,
            roots(&[
                "/etc/systemd/system.control",
                "/run/systemd/system.control",
                "/etc/systemd/system",
                "/usr/lib/systemd/system"
            ])
        );
    }

    #[test]
    fn unit_path_parses_quoted_paths_with_spaces_and_escapes() {
        let r = parse_unit_path(
            "UnitPath=\"/opt/my units/system\" /etc/systemd/system \"/a/b\\\"c\\\\d\"\n",
        )
        .unwrap();
        assert_eq!(
            r,
            roots(&["/opt/my units/system", "/etc/systemd/system", "/a/b\"c\\d"])
        );
    }

    #[test]
    fn unit_path_rejects_malformed_output() {
        for bad in [
            "",
            "UnitPath=\n",
            "UnitPath=/etc/systemd/system",
            "UnitPath=/etc/systemd/system\nUnitPath=/x\n",
            "Other=/etc/systemd/system\n",
            "UnitPath=etc/systemd/system\n",
            "UnitPath=/etc/systemd/system  /usr/lib/systemd/system\n",
            "UnitPath= /etc/systemd/system\n",
            "UnitPath=/etc/systemd/system \n",
            "UnitPath=\"/etc/systemd/system\n",
            "UnitPath=\"/etc/x\\q\"\n",
            "UnitPath=\"/etc/x\"/y\n",
            "UnitPath=/etc/a\\b\n",
            "UnitPath=/etc/../etc\n",
            "UnitPath=/etc//systemd\n",
            "UnitPath=/etc/systemd/system/\n",
            "UnitPath=/\n",
            "UnitPath=$(touch /x)\n/y\n",
        ] {
            assert!(parse_unit_path(bad).is_err(), "must reject {:?}", bad);
        }
    }

    #[test]
    fn unit_path_never_evaluates_shell_syntax() {
        // `$` and backticks are plain path characters; they are never expanded.
        let r = parse_unit_path("UnitPath=/etc/$HOME/system\n").unwrap();
        assert_eq!(r, roots(&["/etc/$HOME/system"]));
    }

    #[test]
    fn shapes_recognize_unit_files_dropins_and_links() {
        assert!(matches!(
            path_shape("/etc/systemd/system/foo.service", false),
            Some(PathShape::UnitFile { .. })
        ));
        assert!(matches!(
            path_shape("/etc/systemd/system/foo.service.d/override.conf", false),
            Some(PathShape::DropIn { .. })
        ));
        assert!(matches!(
            path_shape("/etc/systemd/system/service.d/10-all.conf", false),
            Some(PathShape::DropIn { .. })
        ));
        assert!(matches!(
            path_shape(
                "/etc/systemd/system/multi-user.target.wants/foo.service",
                true
            ),
            Some(PathShape::Wants { .. })
        ));
        assert!(matches!(
            path_shape("/etc/systemd/system/foo.service", true),
            Some(PathShape::UnitFile { link: true, .. })
        ));
        assert_eq!(
            path_shape("/etc/systemd/system.conf", false),
            Some(PathShape::ManagerConfig)
        );
        assert_eq!(
            path_shape("/etc/systemd/system.conf.d/10-x.conf", false),
            Some(PathShape::ManagerConfig)
        );
    }

    #[test]
    fn shapes_ignore_unrelated_paths() {
        for p in [
            "/etc/app.conf",
            "/etc/systemd/user.conf",
            "/etc/systemd/user.conf.d/10-x.conf",
            "/etc/systemd/journald.conf",
            "/etc/systemd/network/10-eth.network",
            "/etc/sysctl.d/10-x.conf",
            "/etc/systemd/system/foo.txt",
            "/etc/systemd/system/foo.d/override.conf",
            "/etc/systemd/system/.service",
            "/etc/systemd/system/foo bar.service",
            "/etc/systemd/system/foo.service.d/readme.txt",
        ] {
            assert_eq!(path_shape(p, false), None, "{}", p);
        }
        // `.wants` vocabulary is link-only.
        assert!(!matches!(
            path_shape(
                "/etc/systemd/system/multi-user.target.wants/foo.service",
                false
            ),
            Some(PathShape::Wants { .. })
        ));
    }

    #[test]
    fn resolution_uses_manager_roots_not_a_fixed_directory() {
        let custom = roots(&["/opt/units/system", "/usr/lib/systemd/system"]);
        let in_custom = path_shape("/opt/units/system/foo.service", false).unwrap();
        let in_etc = path_shape("/etc/systemd/system/foo.service", false).unwrap();
        let got = resolve_input(&in_custom, &custom).unwrap();
        assert_eq!(got.kind, ManagerInputKind::UnitFile);
        assert_eq!(got.unit.as_deref(), Some("foo.service"));
        // /etc is not in this manager's UnitPath: not input, no guessing.
        assert_eq!(resolve_input(&in_etc, &custom), None);
    }

    #[test]
    fn resolution_names_a_unit_only_when_safely_derivable() {
        let r = roots(&["/etc/systemd/system"]);
        let unit =
            |p: &str, link: bool| resolve_input(&path_shape(p, link).unwrap(), &r).map(|i| i.unit);
        assert_eq!(
            unit("/etc/systemd/system/foo.service", false),
            Some(Some("foo.service".to_string()))
        );
        assert_eq!(unit("/etc/systemd/system/foo@.service", false), Some(None));
        assert_eq!(
            unit("/etc/systemd/system/foo@bar.service", false),
            Some(Some("foo@bar.service".to_string()))
        );
        assert_eq!(
            unit("/etc/systemd/system/foo.service.d/o.conf", false),
            Some(Some("foo.service".to_string()))
        );
        assert_eq!(
            unit("/etc/systemd/system/foo-.service.d/o.conf", false),
            Some(None)
        );
        assert_eq!(
            unit("/etc/systemd/system/service.d/o.conf", false),
            Some(None)
        );
        assert_eq!(
            unit(
                "/etc/systemd/system/multi-user.target.wants/foo.service",
                true
            ),
            Some(None)
        );
    }

    #[test]
    fn manager_config_is_recognized_without_unit_path() {
        let shape = path_shape("/etc/systemd/system.conf.d/10-x.conf", false).unwrap();
        let got = resolve_input(&shape, &[]).unwrap();
        assert_eq!(got.kind, ManagerInputKind::ManagerConfig);
        assert_eq!(got.unit, None);
    }

    #[test]
    fn manager_config_symlinks_are_recognized_lexically_and_user_config_is_not() {
        // A `/dev/null` mask of a vendor drop-in is a link at a manager
        // config path; only the managed path matters, never the target.
        for p in [
            "/etc/systemd/system.conf",
            "/etc/systemd/system.conf.d/10-vendor.conf",
            "/run/systemd/system.conf.d/10-vendor.conf",
            "/usr/lib/systemd/system.conf.d/10-vendor.conf",
            "/usr/local/lib/systemd/system.conf.d/10-vendor.conf",
        ] {
            assert_eq!(
                path_shape(p, true),
                Some(PathShape::ManagerConfig),
                "link {}",
                p
            );
            assert_eq!(
                path_shape(p, false),
                Some(PathShape::ManagerConfig),
                "file {}",
                p
            );
        }
        for p in [
            "/etc/systemd/user.conf",
            "/etc/systemd/user.conf.d/10-x.conf",
            "/etc/systemd/system.conf.d/readme.txt",
            "/etc/systemd/system.conf.d/.conf",
            "/etc/systemd/system.conf.d.bak/10-x.conf",
            "/etc/systemd/journald.conf.d/10-x.conf",
            "/etc/app/system.conf.d/10-x.conf",
        ] {
            assert_eq!(path_shape(p, true), None, "link {}", p);
        }
        // the `.wants` link vocabulary is unchanged by this
        assert!(matches!(
            path_shape("/etc/systemd/system/a.target.wants/b.service", true),
            Some(PathShape::Wants { .. })
        ));
    }

    #[test]
    fn yes_no_is_strict() {
        assert_eq!(parse_yes_no("yes"), Some(true));
        assert_eq!(parse_yes_no("no"), Some(false));
        for bad in ["", "YES", "true", "1", "no ", " yes", "n/a"] {
            assert_eq!(parse_yes_no(bad), None, "{:?}", bad);
        }
    }
}
