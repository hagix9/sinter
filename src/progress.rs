//! Internal progress events (WP-PROGRESS S1/S2).
//!
//! The engine reports *where it is* to an observer without ever being able to
//! depend on that observer. This module is the whole contract: a closed event
//! vocabulary, an infallible observation-only [`ProgressSink`], and the
//! default [`NoopSink`]. There is no renderer here and none is implied; the
//! CLI, MCP and cancellation surfaces are later work packages.
//!
//! This is library API and is not part of the 1.x CLI/JSON compatibility
//! promise. Every enum is `#[non_exhaustive]` so vocabulary can grow.
//!
//! # Who emits what
//!
//! * The **engine** owns `StageStarted`, `Progress` and `StageEnded`:
//!   [`Engine::new_with_progress`](crate::engine::Engine::new_with_progress)
//!   (`connect`), `Engine::run` (`backup`, `resources`, `handlers`) and
//!   [`run_audit`](crate::audit::run_audit) (`resources`).
//! * The **caller layer** owns `RunStarted` and `RunEnded` (the engine cannot
//!   tell `plan` from `audit`, and `connect` happens before `run` can be
//!   entered). The types live here; the CLI emits them through
//!   [`progress_session`](crate::progress_session) (S3), which also emits
//!   `Resolve` (the `ssh -G` evaluation of inventory/`--host` resolution).
//!
//! # Lifecycle invariants (executable form: [`validate_stream`])
//!
//! For one execution's event stream:
//!
//! 1. `RunStarted` occurs at most once and, if present, first. When it is
//!    present, `RunEnded` occurs exactly once and last, on every path the
//!    caller wraps (including `Err`). No event follows `RunEnded`. A stream
//!    that stops without `RunEnded` means the process was killed or panicked.
//! 2. Stages are serial, at most one active, in the fixed order
//!    `Resolve < Connect < Backup < Resources < Handlers`; each starts at most
//!    once.
//! 3. `StageStarted(s)` precedes every `Progress(s)` and its `StageEnded(s)`;
//!    each started stage ends exactly once (the engine guarantees it on every
//!    `?`/early-return path; only termination of the process can prevent it).
//!    `Progress` never names a stage other than the active one.
//! 4. `Progress` is emitted once per item, when the item *starts*:
//!    `done` is the number of items already terminal, so it equals the index
//!    of that `Progress` within the stage, and is `<= total` when known.
//! 5. `StageEnded.done` counts items that reached a terminal disposition. The
//!    item in flight when a stage ends is the item that ended it and its
//!    disposition (failed) is known, so it counts. Hence `done` is the number
//!    of `Progress` events of the stage (0 when none). A `Completed` stage
//!    with a known total has `done == total`.
//! 6. After a `Failed`/`Indeterminate` stage no later stage starts.
//!
//! # Counter semantics
//!
//! `done` = items that reached a terminal disposition in the stage: succeeded,
//! changed, converged, skipped (`when: false`), blocked by a dependency,
//! unknown, or failed. `total` = items that exist for the stage when that is
//! honestly known (`None` for `connect`). Items skipped by fail-fast after an
//! apply stop are *not visited*, so they are not counted: the stage ends
//! `Failed` with `done` = items attempted. Never a percentage, never an ETA,
//! never a command count.
//!
//! # Safe by construction
//!
//! An event is built from closed enums, integer counters and at most two
//! bounded strings: [`ItemRef::id`], a recipe-literal resource or handler id
//! (`{{` is rejected in ids at parse time and a loop item never enters one),
//! and [`PackageProgress::package`], a package name parsed from target output
//! and capped at [`PACKAGE_NAME_MAX`] printable ASCII characters. There is no
//! message or reason field and no way to reach an error, a `ResourceResult`, a
//! `CommandStat`, a command line, a path, a hash, a secret reference or any
//! SSH detail from an event. Backup items carry no `current` at all: a backup
//! path is target data, not an id.
//!
//! # Sink contract
//!
//! [`ProgressSink::emit`] returns `()` and must be cheap, must not block and
//! must not panic. The engine never reads anything back, so a sink cannot
//! influence control flow, cannot cancel and cannot make a run fail. An
//! observer may disappear at any time (a channel-backed sink must discard
//! `SendError`, e.g. `let _ = tx.send(..)`).
//!
//! **Which thread calls `emit`.** Two kinds of emitters exist:
//!
//! * The **engine** emits `StageStarted`, `Progress`, `StageEnded` and
//!   `RunEnded` synchronously on the engine thread. The engine adds no panic
//!   isolation of its own: a panicking sink unwinds through the engine. The
//!   production CLI path isolates the engine from a misbehaving consumer
//!   ([`progress_session`](crate::progress_session): a panic-free
//!   `ChannelSink`, a worker thread, bounded teardown).
//! * A **package reporter** ([`crate::package_progress`]) emits
//!   [`ProgressEvent::PackageDetail`] from its own parser thread, never from
//!   the engine thread and never from an executor drain thread. The executor
//!   only hands raw chunks to a package reporter through an unbounded channel,
//!   so a slow or panicking sink cannot stall the pipe/drain loop, cannot
//!   delay the child process, and cannot change an exit code, a result or a
//!   timeout. See `WP-PKG-PROGRESS` P1-C1 in the Phase 1 design record.
//!
//! A sink must therefore be prepared to receive events from more than one
//! thread over a run, though never concurrently for the same event: the
//! channel preserves order between an executor's detail events and the
//! engine's later lifecycle events because the parser thread is joined before
//! the resource returns.
//!
//! `Send + Sync` is required on purpose: `Engine` itself is `!Send`, but the
//! sink is the only part a later consumer (a renderer thread, or the MCP
//! adapter reading cancellation on another thread) must share, and widening
//! the bound later would be a breaking change.

//! # Decisions recorded for the consumers (not implemented here)
//!
//! * Owner decision OQ-1: TTY progress is automatic; non-TTY/CI progress is
//!   off by default, so default non-TTY output stays byte-compatible, and any
//!   future plain progress is explicit opt-in only; JSON mode emits no
//!   progress on any stream (its error diagnostics are unchanged). Encoded by
//!   [`progress_session::decide_mode`](crate::progress_session::decide_mode)
//!   (S3); binding on S5.
//! * Review decision OQ-5: the transient TTY line is disabled when any
//!   `FrozenResource.secret` is set, which avoids prompt/redraw races. Binding
//!   on S4; S3 only reports the fact to the consumer
//!   ([`SessionInfo::references_secrets`](crate::progress_session::SessionInfo)).
//!   Nothing coordinates with prompts.

use std::sync::{Arc, Mutex};

/// The longest package name a [`PackageProgress`] may carry. Renderers use the
/// same cap; the validator enforces it so an event is bounded by construction.
pub const PACKAGE_NAME_MAX: usize = 64;

/// Which command a run belongs to. Display names are a renderer concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunKind {
    Plan,
    Apply,
    Audit,
}

/// A stage of one execution. The identity is stable; command-specific display
/// labels (`plan`/`apply`/`audit` for `Resources`) belong to renderers.
///
/// There is deliberately no `validate`, `verify` or post-apply `audit` stage:
/// none exists as a separate step in any command. The order of the variants is
/// the order stages may occur in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Stage {
    /// Target resolution before any connection (CLI layer; inventory/`--host`).
    Resolve,
    /// Executor setup and capability/fact probes (`Engine::new_with_progress`).
    Connect,
    /// Apply only, only when the recipe declares `backup.paths`.
    Backup,
    /// The dependency-ordered traversal of resources (plan, apply and audit).
    Resources,
    /// Apply only, only when at least one handler was queued and the resource
    /// traversal did not stop.
    Handlers,
}

impl Stage {
    pub fn label(self) -> &'static str {
        match self {
            Stage::Resolve => "resolve",
            Stage::Connect => "connect",
            Stage::Backup => "backup",
            Stage::Resources => "resources",
            Stage::Handlers => "handlers",
        }
    }
}

/// How a stage ended. This is about the stage's own traversal; the run-level
/// result (including a final manager sync) is derived by the caller layer.
/// A successful audit that reports drift is `Completed`: drift is a finding.
/// An audit that could not observe something is `Indeterminate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StageOutcome {
    Completed,
    Failed,
    Indeterminate,
}

/// How a run ended (caller layer; see the module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunOutcome {
    Completed,
    Failed,
    Indeterminate,
}

/// The fixed vocabulary of item kinds: the resource types plus `Handler`.
/// Mirrors `engine::scope_label` (pinned equal by a test); an unknown type is
/// `Other`, never the type's own text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ItemKind {
    File,
    Directory,
    Link,
    Template,
    Command,
    Package,
    Service,
    Group,
    User,
    Other,
    Handler,
}

impl ItemKind {
    pub(crate) fn for_resource_type(type_: &str) -> ItemKind {
        match type_ {
            "file" => ItemKind::File,
            "directory" => ItemKind::Directory,
            "link" => ItemKind::Link,
            "template" => ItemKind::Template,
            "command" => ItemKind::Command,
            "package" => ItemKind::Package,
            "service" => ItemKind::Service,
            "group" => ItemKind::Group,
            "user" => ItemKind::User,
            _ => ItemKind::Other,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ItemKind::File => "file",
            ItemKind::Directory => "directory",
            ItemKind::Link => "link",
            ItemKind::Template => "template",
            ItemKind::Command => "command",
            ItemKind::Package => "package",
            ItemKind::Service => "service",
            ItemKind::Group => "group",
            ItemKind::User => "user",
            ItemKind::Other => "other",
            ItemKind::Handler => "handler",
        }
    }
}

/// The item currently in flight. `id` is a recipe-literal resource or handler
/// id and nothing else. Renderers must still sanitize it for a terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRef {
    pub kind: ItemKind,
    pub id: String,
}

impl ItemRef {
    pub(crate) fn resource(type_: &str, id: &str) -> ItemRef {
        ItemRef {
            kind: ItemKind::for_resource_type(type_),
            id: id.to_string(),
        }
    }

    pub(crate) fn handler(id: &str) -> ItemRef {
        ItemRef {
            kind: ItemKind::Handler,
            id: id.to_string(),
        }
    }
}

/// Which package-manager step a [`PackageDetail`](ProgressEvent::PackageDetail)
/// describes. Observation only: a phase never implies success or failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackagePhase {
    Resolving,
    Downloading,
    Installing,
    Configuring,
    Triggering,
    Removing,
    Verifying,
    Waiting,
}

impl PackagePhase {
    /// The word a renderer shows for this phase. Fixed vocabulary; never
    /// package-manager text.
    pub fn label(self) -> &'static str {
        match self {
            PackagePhase::Resolving => "resolving",
            PackagePhase::Downloading => "downloading",
            PackagePhase::Installing => "installing",
            PackagePhase::Configuring => "configuring",
            PackagePhase::Triggering => "triggering",
            PackagePhase::Removing => "removing",
            PackagePhase::Verifying => "verifying",
            PackagePhase::Waiting => "waiting",
        }
    }
}

/// Whether a detail is about one package's own step or the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackageScope {
    Package,
    Transaction,
}

/// What a [`PackageProgress::percent`] counts. The two are never
/// interchangeable: a download percentage is never an install percentage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PercentScope {
    /// Aggregate download progress (APT `dlstatus`; weighted bytes/items).
    DownloadAggregate,
    /// Transaction-wide install/remove/configure progress (APT `pmstatus`;
    /// dpkg state operations over every package of the transaction).
    TransactionOperation,
}

/// Which record produced a detail. A closed vocabulary: no raw text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProgressSource {
    AptStatusFdDl,
    AptStatusFdPm,
    AptOutputMarker,
    DnfDownloadLine,
    DnfTransactionLine,
    DnfOutputMarker,
    StageFallback,
}

/// How the numbers in a detail were obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProgressConfidence {
    /// Parsed directly from a documented record or line.
    Measured,
    /// Computed only from measured values (elapsed, or a rate from two
    /// measured samples). Never guessed.
    Derived,
    /// The phase is known; the quantity is not.
    Unknown,
}

/// Package-phase detail for the item currently in flight.
///
/// Every optional field is `None` when the source did not measure it; absent
/// is never reported as zero. `percent` is only present when `percent_scope`
/// says what it counts, and is never present for
/// [`ProgressConfidence::Unknown`] or [`ProgressSource::StageFallback`].
///
/// A detail never changes the item counters (`done`/`total`), never ends a
/// stage and never implies success: the resource result remains the
/// authority.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PackageProgress {
    /// Always [`Stage::Resources`].
    pub stage: Stage,
    /// The item in flight; `id` equals the active `Progress.current.id`.
    pub resource: ItemRef,
    pub backend: crate::platform::PackageBackend,
    pub phase: PackagePhase,
    pub scope: PackageScope,
    /// The package currently being processed, sanitized and capped at 64
    /// characters. `None` for a transaction-only record, for a sensitive
    /// resource, or when the source did not name one.
    pub package: Option<String>,
    /// `0..=100`, only when measured.
    pub percent: Option<u8>,
    /// Present exactly when `percent` is present.
    pub percent_scope: Option<PercentScope>,
    pub files_done: Option<u32>,
    pub files_total: Option<u32>,
    pub packages_done: Option<u32>,
    pub packages_total: Option<u32>,
    pub bytes_downloaded: Option<u64>,
    pub bytes_total: Option<u64>,
    pub rate_bps: Option<u64>,
    pub source: ProgressSource,
    pub confidence: ProgressConfidence,
    /// 1 for the first attempt. Reserved for a future retry/resume; Phase 1
    /// always emits 1.
    pub attempt: u32,
}

impl PackageProgress {
    /// A detail with no measured quantity, for the given resource and phase.
    /// Callers set the optional fields they actually measured.
    pub fn new(
        resource: ItemRef,
        backend: crate::platform::PackageBackend,
        phase: PackagePhase,
        scope: PackageScope,
        source: ProgressSource,
        confidence: ProgressConfidence,
    ) -> Self {
        PackageProgress {
            stage: Stage::Resources,
            resource,
            backend,
            phase,
            scope,
            package: None,
            percent: None,
            percent_scope: None,
            files_done: None,
            files_total: None,
            packages_done: None,
            packages_total: None,
            bytes_downloaded: None,
            bytes_total: None,
            rate_bps: None,
            source,
            confidence,
            attempt: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProgressEvent {
    /// Caller layer. At most once, first.
    RunStarted { command: RunKind },
    StageStarted {
        stage: Stage,
        /// Items that will be visited, when honestly known.
        total: Option<u32>,
    },
    /// An item of the active stage started. `done` items are already terminal.
    Progress {
        stage: Stage,
        done: u32,
        total: Option<u32>,
        /// `None` where the item has no safe identity (backup paths).
        current: Option<ItemRef>,
    },
    StageEnded {
        stage: Stage,
        outcome: StageOutcome,
        done: u32,
    },
    /// Package-phase detail for the item in flight. Additive: the item
    /// counters, the stage lifecycle and the resource result are unchanged.
    /// Emitted by a [`crate::package_progress::PackageReporter`]'s own thread;
    /// see the module documentation.
    PackageDetail(PackageProgress),
    /// Caller layer. Exactly once, last, whenever `RunStarted` occurred.
    RunEnded { outcome: RunOutcome },
}

/// An infallible, observation-only consumer of [`ProgressEvent`]s. See the
/// module documentation for the full contract.
pub trait ProgressSink: Send + Sync {
    fn emit(&self, event: &ProgressEvent);

    /// Whether events of this sink are worth producing at all. `false` lets
    /// callers skip building a parser, an observer or a thread. Defaults to
    /// `true`; the no-op sink is the one built-in `false`.
    fn is_enabled(&self) -> bool {
        true
    }

    /// Whether [`emit`](Self::emit) is guaranteed to return promptly: no
    /// blocking I/O, no unbounded work and no wait a caller could not bound.
    ///
    /// A package reporter
    /// ([`crate::package_progress::PackageReporter`]) uses this at the end of
    /// an execution. For a sink that declares `true` (the production
    /// `ChannelSink`, `NoopSink` and the test `RecordingSink`) the reporter
    /// **joins** its parser thread, so every detail event is emitted before
    /// the caller's next lifecycle event. For an unknown sink the default is
    /// `false`: the reporter never waits for a sink call that may never
    /// return; it stops the parser at the next safe point and detaches the
    /// thread instead, so progress observation can never hang an execution.
    fn is_non_blocking(&self) -> bool {
        false
    }
}

/// The default sink: observes nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSink;

impl ProgressSink for NoopSink {
    fn emit(&self, _event: &ProgressEvent) {}

    fn is_enabled(&self) -> bool {
        false
    }

    fn is_non_blocking(&self) -> bool {
        true
    }
}

/// A sink that records every event in order. Meant for tests and diagnostics.
#[derive(Debug, Default)]
pub struct RecordingSink {
    events: Mutex<Vec<ProgressEvent>>,
}

impl RecordingSink {
    pub fn new() -> Arc<RecordingSink> {
        Arc::new(RecordingSink::default())
    }

    pub fn events(&self) -> Vec<ProgressEvent> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl ProgressSink for RecordingSink {
    fn emit(&self, event: &ProgressEvent) {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(event.clone());
    }

    fn is_non_blocking(&self) -> bool {
        true
    }
}

/// Saturating conversion of an item count to the event counter type.
fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Engine-side bookkeeping for one stage. It makes the lifecycle invariants
/// structural: `StageStarted` is emitted on construction, `StageEnded` exactly
/// once, either by [`StageTracker::end`] or, on any early return (`?`), by
/// `Drop` as `Failed`. `Drop` stays silent while unwinding from a panic.
pub(crate) struct StageTracker<'a> {
    sink: &'a dyn ProgressSink,
    stage: Stage,
    total: Option<u32>,
    done: u32,
    in_flight: bool,
    ended: bool,
}

impl<'a> StageTracker<'a> {
    pub(crate) fn start(sink: &'a dyn ProgressSink, stage: Stage, total: Option<usize>) -> Self {
        let total = total.map(count);
        sink.emit(&ProgressEvent::StageStarted { stage, total });
        StageTracker {
            sink,
            stage,
            total,
            done: 0,
            in_flight: false,
            ended: false,
        }
    }

    /// The previous item (if any) is now terminal; announce the next one.
    pub(crate) fn item_started(&mut self, current: Option<ItemRef>) {
        if self.in_flight {
            self.done += 1;
        }
        self.in_flight = true;
        self.sink.emit(&ProgressEvent::Progress {
            stage: self.stage,
            done: self.done,
            total: self.total,
            current,
        });
    }

    pub(crate) fn end(mut self, outcome: StageOutcome) {
        self.finish(outcome);
    }

    fn finish(&mut self, outcome: StageOutcome) {
        if self.ended {
            return;
        }
        self.ended = true;
        if self.in_flight {
            self.done += 1;
            self.in_flight = false;
        }
        self.sink.emit(&ProgressEvent::StageEnded {
            stage: self.stage,
            outcome,
            done: self.done,
        });
    }
}

impl Drop for StageTracker<'_> {
    fn drop(&mut self) {
        if !self.ended && !std::thread::panicking() {
            self.finish(StageOutcome::Failed);
        }
    }
}

/// Check a complete event stream against the lifecycle invariants in the
/// module documentation. `Ok(())` for a conforming stream (including one
/// without `RunStarted`/`RunEnded`, as the engine alone produces).
pub fn validate_stream(events: &[ProgressEvent]) -> Result<(), String> {
    struct Active {
        stage: Stage,
        total: Option<u32>,
        progress: u32,
        current: Option<ItemRef>,
    }
    let mut run_started = false;
    let mut run_ended = false;
    let mut active: Option<Active> = None;
    let mut last_stage: Option<Stage> = None;
    let mut last_stage_failed = false;

    for (i, ev) in events.iter().enumerate() {
        if run_ended {
            return Err(format!("event {i}: event after RunEnded"));
        }
        match ev {
            ProgressEvent::RunStarted { .. } => {
                if run_started || i != 0 {
                    return Err(format!("event {i}: RunStarted must occur once, first"));
                }
                run_started = true;
            }
            ProgressEvent::RunEnded { .. } => {
                if !run_started {
                    return Err(format!("event {i}: RunEnded without RunStarted"));
                }
                if active.is_some() {
                    return Err(format!("event {i}: RunEnded while a stage is active"));
                }
                run_ended = true;
            }
            ProgressEvent::StageStarted { stage, total } => {
                if active.is_some() {
                    return Err(format!("event {i}: StageStarted while a stage is active"));
                }
                if last_stage.is_some_and(|s| s >= *stage) {
                    return Err(format!(
                        "event {i}: stage {stage:?} out of order or repeated"
                    ));
                }
                if last_stage_failed {
                    return Err(format!("event {i}: stage started after a failed stage"));
                }
                active = Some(Active {
                    stage: *stage,
                    total: *total,
                    progress: 0,
                    current: None,
                });
            }
            ProgressEvent::Progress {
                stage,
                done,
                total,
                current,
            } => {
                let a = active
                    .as_mut()
                    .ok_or_else(|| format!("event {i}: Progress outside a stage"))?;
                if a.stage != *stage {
                    return Err(format!(
                        "event {i}: Progress names {stage:?}, active {:?}",
                        a.stage
                    ));
                }
                if *total != a.total {
                    return Err(format!(
                        "event {i}: Progress total differs from StageStarted"
                    ));
                }
                if *done != a.progress {
                    return Err(format!(
                        "event {i}: Progress done {done} != items already terminal {}",
                        a.progress
                    ));
                }
                if a.total.is_some_and(|t| *done >= t) {
                    return Err(format!("event {i}: Progress beyond total"));
                }
                a.progress += 1;
                a.current = current.clone();
            }
            ProgressEvent::PackageDetail(detail) => {
                let a = active
                    .as_ref()
                    .ok_or_else(|| format!("event {i}: PackageDetail outside a stage"))?;
                if detail.stage != Stage::Resources {
                    return Err(format!(
                        "event {i}: PackageDetail stage must be Resources, got {:?}",
                        detail.stage
                    ));
                }
                if a.stage != Stage::Resources {
                    return Err(format!(
                        "event {i}: PackageDetail while {:?} is active",
                        a.stage
                    ));
                }
                let Some(current) = a.current.as_ref() else {
                    return Err(format!("event {i}: PackageDetail before any Progress item"));
                };
                if current != &detail.resource {
                    return Err(format!(
                        "event {i}: PackageDetail for {:?}, active item is {:?}",
                        detail.resource, current
                    ));
                }
                if detail.resource.kind != ItemKind::Package {
                    return Err(format!("event {i}: PackageDetail for a non-package item"));
                }
                if detail.attempt < 1 {
                    return Err(format!("event {i}: PackageDetail attempt must be >= 1"));
                }
                if detail.percent.is_some_and(|p| p > 100) {
                    return Err(format!("event {i}: PackageDetail percent > 100"));
                }
                if detail.percent.is_some() != detail.percent_scope.is_some() {
                    return Err(format!(
                        "event {i}: PackageDetail percent and percent_scope must appear together"
                    ));
                }
                if detail.percent.is_some()
                    && (detail.confidence == ProgressConfidence::Unknown
                        || detail.source == ProgressSource::StageFallback)
                {
                    return Err(format!(
                        "event {i}: unmeasured PackageDetail must not carry a percent"
                    ));
                }
                if let (Some(done), Some(total)) = (detail.bytes_downloaded, detail.bytes_total) {
                    if done > total {
                        return Err(format!(
                            "event {i}: PackageDetail bytes_downloaded > bytes_total"
                        ));
                    }
                }
                if let (Some(done), Some(total)) = (detail.files_done, detail.files_total) {
                    if done > total {
                        return Err(format!("event {i}: PackageDetail files_done > files_total"));
                    }
                }
                if let (Some(done), Some(total)) = (detail.packages_done, detail.packages_total) {
                    if done > total {
                        return Err(format!(
                            "event {i}: PackageDetail packages_done > packages_total"
                        ));
                    }
                }
                if let Some(name) = detail.package.as_ref() {
                    if name.is_empty()
                        || name.chars().count() > PACKAGE_NAME_MAX
                        || !name.chars().all(|c| c.is_ascii_graphic())
                    {
                        return Err(format!(
                            "event {i}: PackageDetail package name is not a bounded printable token"
                        ));
                    }
                }
            }
            ProgressEvent::StageEnded {
                stage,
                outcome,
                done,
            } => {
                let a = active
                    .take()
                    .ok_or_else(|| format!("event {i}: StageEnded outside a stage"))?;
                if a.stage != *stage {
                    return Err(format!(
                        "event {i}: StageEnded names {stage:?}, active {:?}",
                        a.stage
                    ));
                }
                if *done != a.progress {
                    return Err(format!(
                        "event {i}: StageEnded done {done} != Progress events {}",
                        a.progress
                    ));
                }
                if a.total.is_some_and(|t| *done > t) {
                    return Err(format!("event {i}: StageEnded beyond total"));
                }
                if *outcome == StageOutcome::Completed && a.total.is_some_and(|t| *done != t) {
                    return Err(format!("event {i}: Completed stage with done != total"));
                }
                last_stage = Some(*stage);
                last_stage_failed = *outcome != StageOutcome::Completed;
            }
        }
    }
    if active.is_some() {
        return Err("stream ends inside an active stage".to_string());
    }
    if run_started && !run_ended {
        return Err("RunStarted without RunEnded".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started(stage: Stage, total: Option<u32>) -> ProgressEvent {
        ProgressEvent::StageStarted { stage, total }
    }

    fn progress(stage: Stage, done: u32, total: Option<u32>) -> ProgressEvent {
        ProgressEvent::Progress {
            stage,
            done,
            total,
            current: None,
        }
    }

    fn ended(stage: Stage, outcome: StageOutcome, done: u32) -> ProgressEvent {
        ProgressEvent::StageEnded {
            stage,
            outcome,
            done,
        }
    }

    /// Exhaustive, wildcard-free: adding a variant or a field forces this
    /// review. Every payload is a closed enum, an integer counter, `ItemRef`,
    /// or the bounded package-name string.
    #[test]
    fn event_payload_is_closed_by_construction() {
        fn check(ev: &ProgressEvent) -> usize {
            match ev {
                ProgressEvent::RunStarted { command } => {
                    let _: &RunKind = command;
                    0
                }
                ProgressEvent::StageStarted { stage, total } => {
                    let _: (&Stage, &Option<u32>) = (stage, total);
                    0
                }
                ProgressEvent::Progress {
                    stage,
                    done,
                    total,
                    current,
                } => {
                    let _: (&Stage, &u32, &Option<u32>) = (stage, done, total);
                    match current {
                        // `id` is a recipe-literal string an event can hold.
                        Some(ItemRef { kind, id }) => {
                            let _: &ItemKind = kind;
                            let _: &String = id;
                            1
                        }
                        None => 0,
                    }
                }
                ProgressEvent::StageEnded {
                    stage,
                    outcome,
                    done,
                } => {
                    let _: (&Stage, &StageOutcome, &u32) = (stage, outcome, done);
                    0
                }
                ProgressEvent::PackageDetail(p) => {
                    let _: (&Stage, &ItemRef, &crate::platform::PackageBackend) =
                        (&p.stage, &p.resource, &p.backend);
                    let _: (&PackagePhase, &PackageScope) = (&p.phase, &p.scope);
                    let _: (&Option<u8>, &Option<PercentScope>) = (&p.percent, &p.percent_scope);
                    let _: (&Option<u32>, &Option<u32>, &Option<u32>, &Option<u32>) = (
                        &p.files_done,
                        &p.files_total,
                        &p.packages_done,
                        &p.packages_total,
                    );
                    let _: (&Option<u64>, &Option<u64>, &Option<u64>) =
                        (&p.bytes_downloaded, &p.bytes_total, &p.rate_bps);
                    let _: (&ProgressSource, &ProgressConfidence, &u32) =
                        (&p.source, &p.confidence, &p.attempt);
                    // The only other free string, bounded and validated.
                    match &p.package {
                        Some(name) => {
                            let _: &String = name;
                            1
                        }
                        None => 0,
                    }
                }
                ProgressEvent::RunEnded { outcome } => {
                    let _: &RunOutcome = outcome;
                    0
                }
            }
        }
        let item = Some(ItemRef::resource("file", "a"));
        let evs = [
            ProgressEvent::RunStarted {
                command: RunKind::Plan,
            },
            started(Stage::Connect, None),
            ProgressEvent::Progress {
                stage: Stage::Resources,
                done: 0,
                total: Some(1),
                current: item,
            },
            ended(Stage::Connect, StageOutcome::Completed, 0),
            ProgressEvent::RunEnded {
                outcome: RunOutcome::Completed,
            },
        ];
        assert_eq!(evs.iter().map(check).sum::<usize>(), 1);
    }

    #[test]
    fn item_kind_vocabulary_matches_the_statistics_scope_labels() {
        for t in [
            "file",
            "directory",
            "link",
            "template",
            "command",
            "package",
            "service",
            "group",
            "user",
            "made-up-type-with-secret-text",
        ] {
            assert_eq!(
                ItemKind::for_resource_type(t).label(),
                crate::engine::scope_label(t),
                "{t}"
            );
        }
        assert_eq!(ItemKind::Handler.label(), "handler");
    }

    #[test]
    fn stage_order_is_the_documented_order() {
        assert!(Stage::Resolve < Stage::Connect);
        assert!(Stage::Connect < Stage::Backup);
        assert!(Stage::Backup < Stage::Resources);
        assert!(Stage::Resources < Stage::Handlers);
    }

    #[test]
    fn validator_accepts_conforming_streams() {
        let run = |inner: Vec<ProgressEvent>| {
            let mut v = vec![ProgressEvent::RunStarted {
                command: RunKind::Apply,
            }];
            v.extend(inner);
            v.push(ProgressEvent::RunEnded {
                outcome: RunOutcome::Completed,
            });
            v
        };
        assert!(validate_stream(&[]).is_ok());
        assert!(validate_stream(&run(vec![])).is_ok());
        assert!(validate_stream(&run(vec![
            started(Stage::Connect, None),
            ended(Stage::Connect, StageOutcome::Completed, 0),
            started(Stage::Resources, Some(0)),
            ended(Stage::Resources, StageOutcome::Completed, 0),
        ]))
        .is_ok());
        assert!(validate_stream(&run(vec![
            started(Stage::Resources, Some(2)),
            progress(Stage::Resources, 0, Some(2)),
            progress(Stage::Resources, 1, Some(2)),
            ended(Stage::Resources, StageOutcome::Failed, 2),
        ]))
        .is_ok());
    }

    #[test]
    fn validator_rejects_each_violation() {
        let bad: Vec<(&str, Vec<ProgressEvent>)> = vec![
            (
                "event after RunEnded",
                vec![
                    ProgressEvent::RunStarted {
                        command: RunKind::Plan,
                    },
                    ProgressEvent::RunEnded {
                        outcome: RunOutcome::Completed,
                    },
                    started(Stage::Connect, None),
                ],
            ),
            (
                "RunStarted without RunEnded",
                vec![ProgressEvent::RunStarted {
                    command: RunKind::Plan,
                }],
            ),
            (
                "RunEnded without RunStarted",
                vec![ProgressEvent::RunEnded {
                    outcome: RunOutcome::Completed,
                }],
            ),
            (
                "RunStarted must occur once",
                vec![
                    ProgressEvent::RunStarted {
                        command: RunKind::Plan,
                    },
                    ProgressEvent::RunStarted {
                        command: RunKind::Plan,
                    },
                ],
            ),
            (
                "Progress outside a stage",
                vec![progress(Stage::Resources, 0, Some(1))],
            ),
            (
                "stream ends inside an active stage",
                vec![started(Stage::Connect, None)],
            ),
            (
                "StageStarted while a stage is active",
                vec![
                    started(Stage::Connect, None),
                    started(Stage::Resources, None),
                ],
            ),
            (
                "Progress names",
                vec![
                    started(Stage::Resources, Some(2)),
                    progress(Stage::Handlers, 0, Some(2)),
                ],
            ),
            (
                "StageEnded names",
                vec![
                    started(Stage::Resources, Some(2)),
                    ended(Stage::Handlers, StageOutcome::Failed, 0),
                ],
            ),
            (
                "out of order or repeated",
                vec![
                    started(Stage::Resources, Some(0)),
                    ended(Stage::Resources, StageOutcome::Completed, 0),
                    started(Stage::Connect, None),
                ],
            ),
            (
                "stage started after a failed stage",
                vec![
                    started(Stage::Connect, None),
                    ended(Stage::Connect, StageOutcome::Failed, 0),
                    started(Stage::Resources, Some(0)),
                ],
            ),
            (
                "Progress done",
                vec![
                    started(Stage::Resources, Some(3)),
                    progress(Stage::Resources, 1, Some(3)),
                ],
            ),
            (
                "Progress beyond total",
                vec![
                    started(Stage::Resources, Some(1)),
                    progress(Stage::Resources, 0, Some(1)),
                    progress(Stage::Resources, 1, Some(1)),
                ],
            ),
            (
                "Progress total differs",
                vec![
                    started(Stage::Resources, Some(3)),
                    progress(Stage::Resources, 0, Some(2)),
                ],
            ),
            (
                "StageEnded done",
                vec![
                    started(Stage::Resources, Some(3)),
                    progress(Stage::Resources, 0, Some(3)),
                    ended(Stage::Resources, StageOutcome::Failed, 0),
                ],
            ),
            (
                "Completed stage with done != total",
                vec![
                    started(Stage::Resources, Some(3)),
                    progress(Stage::Resources, 0, Some(3)),
                    ended(Stage::Resources, StageOutcome::Completed, 1),
                ],
            ),
        ];
        for (needle, events) in bad {
            let err = validate_stream(&events).expect_err(needle);
            assert!(err.contains(needle), "{needle}: got {err}");
        }
    }

    #[test]
    fn validator_accepts_package_details_between_progress_and_stage_end() {
        let run = |inner: Vec<ProgressEvent>| {
            let mut v = vec![ProgressEvent::RunStarted {
                command: RunKind::Apply,
            }];
            v.extend(inner);
            v.push(ProgressEvent::RunEnded {
                outcome: RunOutcome::Completed,
            });
            v
        };
        let item = ItemRef::resource("package", "postgresql");
        let evs = run(vec![
            started(Stage::Resources, Some(1)),
            ProgressEvent::Progress {
                stage: Stage::Resources,
                done: 0,
                total: Some(1),
                current: Some(item.clone()),
            },
            detail_for(&item, Some(9), Some(2), Some(3)),
            detail_for(&item, Some(72), Some(2), Some(3)),
            detail_for(&item, Some(100), None, None),
            ended(Stage::Resources, StageOutcome::Completed, 1),
        ]);
        validate_stream(&evs).unwrap();
    }

    #[test]
    fn validator_rejects_each_package_detail_violation() {
        let item = ItemRef::resource("package", "postgresql");
        let other = ItemRef::resource("package", "nginx");
        let prefix = |ev: Vec<ProgressEvent>| {
            let mut v = vec![
                started(Stage::Resources, Some(1)),
                ProgressEvent::Progress {
                    stage: Stage::Resources,
                    done: 0,
                    total: Some(1),
                    current: Some(item.clone()),
                },
            ];
            v.extend(ev);
            v
        };
        let bad: Vec<(&str, Vec<ProgressEvent>)> = vec![
            (
                "PackageDetail outside a stage",
                vec![detail_for(&item, Some(1), None, None)],
            ),
            (
                "before any Progress item",
                vec![
                    started(Stage::Resources, Some(1)),
                    detail_for(&item, Some(1), None, None),
                ],
            ),
            (
                "active item is",
                prefix(vec![detail_for(&other, Some(1), None, None)]),
            ),
            (
                "percent > 100",
                prefix(vec![
                    ProgressEvent::PackageDetail(measured(&item, 101, Some(0), Some(1))),
                    ended(Stage::Resources, StageOutcome::Completed, 1),
                ]),
            ),
            (
                "must appear together",
                prefix(vec![
                    ProgressEvent::PackageDetail(unscoped(&item, 50)),
                    ended(Stage::Resources, StageOutcome::Completed, 1),
                ]),
            ),
            (
                "unmeasured PackageDetail",
                prefix(vec![
                    ProgressEvent::PackageDetail(unmeasured_with_percent(&item, 50)),
                    ended(Stage::Resources, StageOutcome::Completed, 1),
                ]),
            ),
            (
                "bytes_downloaded > bytes_total",
                prefix(vec![
                    ProgressEvent::PackageDetail(measured(&item, 50, Some(9), Some(1))),
                    ended(Stage::Resources, StageOutcome::Completed, 1),
                ]),
            ),
            (
                "attempt must be",
                prefix(vec![
                    ProgressEvent::PackageDetail(with_attempt(&item, 0)),
                    ended(Stage::Resources, StageOutcome::Completed, 1),
                ]),
            ),
            ("non-package item", {
                let file = ItemRef::resource("file", "postgresql");
                let mut p = base_detail(&file);
                p.resource = file.clone();
                vec![
                    started(Stage::Resources, Some(1)),
                    ProgressEvent::Progress {
                        stage: Stage::Resources,
                        done: 0,
                        total: Some(1),
                        current: Some(file),
                    },
                    ProgressEvent::PackageDetail(p),
                ]
            }),
            (
                "bounded printable token",
                prefix(vec![
                    ProgressEvent::PackageDetail(with_package(&item, "two words")),
                    ended(Stage::Resources, StageOutcome::Completed, 1),
                ]),
            ),
        ];
        for (needle, events) in bad {
            let err = validate_stream(&events).expect_err(needle);
            assert!(err.contains(needle), "{needle}: got {err}");
        }
    }

    fn base_detail(item: &ItemRef) -> PackageProgress {
        PackageProgress::new(
            item.clone(),
            crate::platform::PackageBackend::Apt,
            PackagePhase::Downloading,
            PackageScope::Transaction,
            ProgressSource::AptStatusFdDl,
            ProgressConfidence::Measured,
        )
    }

    fn detail_for(
        item: &ItemRef,
        percent: Option<u8>,
        files_done: Option<u32>,
        files_total: Option<u32>,
    ) -> ProgressEvent {
        let mut p = base_detail(item);
        p.percent = percent;
        p.percent_scope = percent.map(|_| PercentScope::DownloadAggregate);
        p.files_done = files_done;
        p.files_total = files_total;
        ProgressEvent::PackageDetail(p)
    }

    fn measured(
        item: &ItemRef,
        percent: u8,
        done: Option<u64>,
        total: Option<u64>,
    ) -> PackageProgress {
        let mut p = base_detail(item);
        p.percent = Some(percent);
        p.percent_scope = Some(PercentScope::DownloadAggregate);
        p.bytes_downloaded = done;
        p.bytes_total = total;
        p
    }

    fn unscoped(item: &ItemRef, percent: u8) -> PackageProgress {
        let mut p = base_detail(item);
        p.percent = Some(percent);
        p.percent_scope = None;
        p
    }

    fn unmeasured_with_percent(item: &ItemRef, percent: u8) -> PackageProgress {
        let mut p = unscoped(item, percent);
        p.percent_scope = Some(PercentScope::DownloadAggregate);
        p.confidence = ProgressConfidence::Unknown;
        p
    }

    fn with_attempt(item: &ItemRef, attempt: u32) -> PackageProgress {
        let mut p = base_detail(item);
        p.attempt = attempt;
        p
    }

    fn with_package(item: &ItemRef, package: &str) -> PackageProgress {
        let mut p = base_detail(item);
        p.package = Some(package.to_string());
        p
    }

    #[test]
    fn tracker_counts_the_in_flight_item_and_ends_exactly_once() {
        let sink = RecordingSink::new();
        let mut t = StageTracker::start(&*sink, Stage::Resources, Some(3));
        t.item_started(Some(ItemRef::resource("file", "a")));
        t.item_started(Some(ItemRef::resource("file", "b")));
        t.end(StageOutcome::Failed);
        let evs = sink.events();
        assert_eq!(
            evs[3],
            ended(Stage::Resources, StageOutcome::Failed, 2),
            "{evs:?}"
        );
        assert_eq!(evs.len(), 4);
        validate_stream(&evs).unwrap();
    }

    #[test]
    fn dropping_a_tracker_ends_the_stage_as_failed() {
        let sink = RecordingSink::new();
        {
            let mut t = StageTracker::start(&*sink, Stage::Backup, Some(2));
            t.item_started(None);
            // early return / `?`
        }
        let evs = sink.events();
        assert_eq!(
            evs.last(),
            Some(&ended(Stage::Backup, StageOutcome::Failed, 1))
        );
        validate_stream(&evs).unwrap();
    }

    #[test]
    fn dropping_a_tracker_while_unwinding_emits_nothing() {
        let sink = RecordingSink::new();
        let s2 = sink.clone();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _t = StageTracker::start(&*s2, Stage::Connect, None);
            panic!("boom");
        }));
        assert!(r.is_err());
        assert_eq!(sink.events(), vec![started(Stage::Connect, None)]);
    }

    #[test]
    fn counts_saturate() {
        assert_eq!(count(usize::MAX), u32::MAX);
        assert_eq!(count(7), 7);
    }

    #[test]
    fn recording_sink_survives_a_poisoned_lock() {
        let sink = RecordingSink::new();
        let s2 = sink.clone();
        let _ = std::thread::spawn(move || {
            let _g = s2.events.lock().unwrap();
            panic!("poison");
        })
        .join();
        sink.emit(&started(Stage::Connect, None));
        assert_eq!(sink.events().len(), 1);
    }
}
