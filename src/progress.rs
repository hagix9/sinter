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
//! An event is built from closed enums, `u32` counters and exactly one string:
//! [`ItemRef::id`], a recipe-literal resource or handler id (`{{` is rejected
//! in ids at parse time and a loop item never enters one). There is no message
//! or reason field and no way to reach an error, a `ResourceResult`, a
//! `CommandStat`, a command line, a path, a hash, a secret reference or any
//! SSH detail from an event. Backup items carry no `current` at all: a backup
//! path is target data, not an id.
//!
//! # Sink contract
//!
//! [`ProgressSink::emit`] returns `()`, is called synchronously on the engine
//! thread, and must be cheap, must not block and must not panic. The engine
//! never reads anything back, so a sink cannot influence control flow, cannot
//! cancel and cannot make a run fail. An observer may disappear at any time (a
//! channel-backed sink must discard `SendError`, e.g. `let _ = tx.send(..)`).
//! The engine adds **no** panic isolation of its own: a panicking sink unwinds
//! through the engine. The production CLI path isolates the engine from a
//! misbehaving consumer instead ([`progress_session`](crate::progress_session):
//! a panic-free `ChannelSink`, a worker thread, bounded teardown); an
//! arbitrary third-party sink passed to `new_with_progress` stays outside that
//! guarantee.
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
    /// Caller layer. Exactly once, last, whenever `RunStarted` occurred.
    RunEnded { outcome: RunOutcome },
}

/// An infallible, observation-only consumer of [`ProgressEvent`]s. See the
/// module documentation for the full contract.
pub trait ProgressSink: Send + Sync {
    fn emit(&self, event: &ProgressEvent);
}

/// The default sink: observes nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSink;

impl ProgressSink for NoopSink {
    fn emit(&self, _event: &ProgressEvent) {}
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
                });
            }
            ProgressEvent::Progress {
                stage,
                done,
                total,
                current: _,
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
    /// review. Every payload is a closed enum, a counter, or `ItemRef::id`.
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
                        // `id` is the only free string an event can hold.
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
