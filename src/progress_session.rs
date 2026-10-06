//! CLI-layer progress plumbing (WP-PROGRESS S3).
//!
//! S1/S2 gave the engine a [`ProgressSink`]. This module is everything between
//! that sink and a future renderer, with **no renderer**: the only consumer
//! shipped here is [`NullConsumer`], which drops every event. Nothing in this
//! module writes to stdout, stderr or a terminal, so S3 changes no user-visible
//! byte. S4 (TTY) and S5 (explicit plain progress) plug a [`ProgressConsumer`]
//! in through [`ProgressOptions::with_consumer_factory`]; they own formatting,
//! clocks and terminal handling.
//!
//! This is library API and, like [`crate::progress`], is not part of the 1.x
//! CLI/JSON compatibility promise.
//!
//! # Owner policy (structural)
//!
//! * TTY, text format: progress is automatic ([`ProgressMode::Tty`]).
//! * Not a TTY (pipes, redirects, CI): off by default ([`ProgressMode::Disabled`]).
//!   A future explicit plain mode is a new variant, not a changed default.
//! * JSON: off on every stream, whatever the terminal ([`decide_mode`]).
//!   Existing JSON-mode error diagnostics are not progress and are untouched.
//!
//! # The decision happens in two phases
//!
//! 1. [`decide_mode`]: from facts known at the command line (format, whether
//!    stderr is a terminal, `TERM`). Only `plan`, `apply` and `audit` ever ask;
//!    `validate`, `secrets` and `mcp` never construct a session.
//! 2. Per execution, once the recipe model exists: [`SessionInfo`] carries
//!    [`SessionInfo::references_secrets`] (any resource has a `secret`). It is
//!    information for the consumer: S4 must not draw a transient line when it is
//!    set (owner decision OQ-5), because a passphrase prompt or a `sinter:`
//!    secret note may write to the terminal mid-run. S3's null consumer ignores
//!    it; nothing here coordinates with prompts.
//!
//! # One session per execution
//!
//! A [`ProgressSession`] owns one channel, one worker thread and one consumer.
//! Its stream is exactly `RunStarted`, the stages, `RunEnded` and is valid on
//! its own ([`crate::progress::validate_stream`]). There is no global sink: a
//! multi-execution invocation creates one session per executed `(recipe,
//! target)` pair, strictly sequentially as the CLI runs them, so streams cannot
//! mix. Which execution a stream belongs to is carried by the session object,
//! never by the events (no host, address or label is representable in one).
//! Executions that are not run (apply stopped earlier) have no session.
//!
//! The CLI uses two kinds of scope, both through this type:
//!
//! * the **execution** scope around `Engine::new_with_progress` and `run` /
//!   `run_audit`; for a single recipe on a single target it also covers target
//!   resolution, so a resolve failure ends that run;
//! * the **resolution** scope, only for invocations that run several
//!   executions (inventory or bundle) and have resolution work: it is a
//!   `RunStarted`, an optional `Resolve` stage, `RunEnded` stream of its own.
//!
//! # The `Resolve` stage
//!
//! Emitted only around real pre-engine waiting: the local `ssh -G` evaluation
//! of the OpenSSH client configuration (up to ten seconds per host), once per
//! host that is actually queried. `total` is the number of hosts to be queried
//! (exact, known before the first query). With `--no-ssh-config`, or for
//! localhost, there is no such work and no stage. Inventory loading, selection
//! and the duplicate-address check are instantaneous and are not part of it.
//! Items carry no `current`: a host name is target data, not a recipe id.
//!
//! # Teardown
//!
//! The engine thread only ever calls [`ChannelSink::emit`]: an unbounded
//! `mpsc` send whose failure is discarded. It never blocks and cannot panic, so
//! a slow, stalled or dead consumer cannot slow, block or alter an execution.
//! Events per execution are a small multiple of the resource count, so the queue
//! is memory-safe.
//!
//! * **Normal shutdown.** [`ProgressSession::end`] emits `RunEnded`; the worker
//!   stops after delivering it, drops the consumer, and only then signals
//!   completion. The session waits for that signal for at most
//!   [`ProgressOptions::teardown_bound`] and then joins (by then the thread
//!   runs no Sinter code).
//! * **Early exit.** Dropping a session that was not ended (an `Err` returned
//!   with `?`) emits `RunEnded(Failed)` the same way.
//! * **Receiver disappearance.** A send to a gone worker is discarded.
//! * **Worker panic.** The panic unwinds only the worker thread; the signal
//!   still fires; the session reports [`Teardown::WorkerPanicked`] and the run is
//!   unaffected. The default panic hook still prints its message to stderr: that
//!   is a renderer bug being visible, not a change of result.
//! * **Timeout.** `JoinHandle` has no timed join, so the bound is a
//!   `recv_timeout` on a completion channel. When it expires the worker is
//!   abandoned (detached) and [`Teardown::Abandoned`] is reported; the process
//!   may exit while it is blocked. One abandoned worker per stuck execution is
//!   the worst case, and only a consumer that blocks can cause it.
//! * **Panic of the run itself.** `Drop` emits nothing while the thread is
//!   panicking and does not wait, so a panic cannot become a double panic or be
//!   delayed. The worker then sees the channel close and exits by itself. No
//!   stronger panic guarantee is claimed: a stream may end without `RunEnded`.
//!
//! The production path (`ChannelSink`, the worker loop, `Drop`) contains no
//! `unwrap`/`expect` and no operation that panics on a closed channel. An
//! arbitrary third-party [`ProgressSink`] given to `Engine::new_with_progress`
//! remains outside this guarantee, as documented in [`crate::progress`].

use crate::audit::AuditReport;
use crate::engine::{AggregateStatus, RunReport};
use crate::error::{ErrorKind, SinterError};
use crate::model::Model;
use crate::progress::{
    NoopSink, ProgressEvent, ProgressSink, RunKind, RunOutcome, Stage, StageOutcome, StageTracker,
};
use std::ffi::OsStr;
use std::io::IsTerminal;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// How long [`ProgressSession::end`] waits for its worker before abandoning it.
/// Generous for a consumer that only erases a line; small enough that a stalled
/// stderr delays process exit by well under a second.
pub const DEFAULT_TEARDOWN_BOUND: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// Mode decision
// ---------------------------------------------------------------------------

/// Whether progress is produced for an invocation. The only two states S3
/// needs; plain (non-TTY) progress is a later, explicit opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProgressMode {
    /// No events, no thread, no channel.
    Disabled,
    /// Events flow to the consumer. In S3 the consumer is the null consumer.
    Tty,
}

/// The command-line facts the first phase of the decision depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeInputs {
    /// `--format json`.
    pub json: bool,
    /// stderr is a terminal (progress is a stderr concern; stdout is the report).
    pub stderr_is_tty: bool,
    /// `TERM=dumb`.
    pub term_is_dumb: bool,
}

/// Pure phase-1 decision. JSON wins over everything; `NO_COLOR` is irrelevant
/// here (it affects colour, not whether a line may exist).
pub fn decide_mode(inputs: &ModeInputs) -> ProgressMode {
    if inputs.json || !inputs.stderr_is_tty || inputs.term_is_dumb {
        ProgressMode::Disabled
    } else {
        ProgressMode::Tty
    }
}

/// [`decide_mode`] with the process environment.
pub fn mode_from_environment(json: bool) -> ProgressMode {
    decide_mode(&ModeInputs {
        json,
        stderr_is_tty: std::io::stderr().is_terminal(),
        term_is_dumb: std::env::var_os("TERM").is_some_and(|t| t == OsStr::new("dumb")),
    })
}

/// Whether any resource of `model` opens an encrypted secret
/// (`FrozenResource.secret`). Decided from the model alone, before any run.
pub fn references_secrets(model: &Model) -> bool {
    model.resources.iter().any(|r| r.secret.is_some())
}

// ---------------------------------------------------------------------------
// Sink
// ---------------------------------------------------------------------------

/// The production sink: forwards each event over an unbounded `mpsc` channel.
///
/// `emit` clones the event, sends it and discards the result: a vanished
/// receiver is not an error for the engine. It does no formatting, no I/O and
/// no blocking.
#[derive(Debug)]
pub struct ChannelSink {
    tx: Sender<ProgressEvent>,
}

impl ChannelSink {
    pub fn new(tx: Sender<ProgressEvent>) -> Self {
        ChannelSink { tx }
    }

    /// A sink and the receiving end of its channel.
    pub fn channel() -> (ChannelSink, Receiver<ProgressEvent>) {
        let (tx, rx) = mpsc::channel();
        (ChannelSink { tx }, rx)
    }
}

impl ProgressSink for ChannelSink {
    fn emit(&self, event: &ProgressEvent) {
        let _ = self.tx.send(event.clone());
    }
}

// ---------------------------------------------------------------------------
// Consumer (the renderer seam)
// ---------------------------------------------------------------------------

/// What a worker thread does with the events of one session. Owns no business
/// logic and cannot influence the run (it has no handle to it). S4/S5 implement
/// formatters behind this trait.
pub trait ProgressConsumer: Send {
    fn consume(&mut self, event: &ProgressEvent);
}

/// The S3 consumer: receives every event and does nothing. No output.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullConsumer;

impl ProgressConsumer for NullConsumer {
    fn consume(&mut self, _event: &ProgressEvent) {}
}

/// Facts about one session that are known before it starts. None of them is
/// carried by an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionInfo {
    pub kind: RunKind,
    /// See the module documentation (OQ-5): S4 draws no transient line when set.
    pub references_secrets: bool,
}

/// Builds the consumer of one session, on the caller's thread; the consumer is
/// then moved to the worker.
pub type ConsumerFactory = Arc<dyn Fn(&SessionInfo) -> Box<dyn ProgressConsumer> + Send + Sync>;

// ---------------------------------------------------------------------------
// Options and session
// ---------------------------------------------------------------------------

/// Invocation-wide progress configuration; creates one session per scope.
#[derive(Clone)]
pub struct ProgressOptions {
    mode: ProgressMode,
    factory: ConsumerFactory,
    teardown_bound: Duration,
}

impl ProgressOptions {
    /// Production options for `mode`: the null consumer.
    pub fn new(mode: ProgressMode) -> Self {
        ProgressOptions {
            mode,
            factory: Arc::new(|_| Box::new(NullConsumer)),
            teardown_bound: DEFAULT_TEARDOWN_BOUND,
        }
    }

    pub fn disabled() -> Self {
        Self::new(ProgressMode::Disabled)
    }

    /// Replace the consumer (the S4/S5 seam, and the test seam).
    pub fn with_consumer_factory(mut self, factory: ConsumerFactory) -> Self {
        self.factory = factory;
        self
    }

    pub fn with_teardown_bound(mut self, bound: Duration) -> Self {
        self.teardown_bound = bound;
        self
    }

    pub fn mode(&self) -> ProgressMode {
        self.mode
    }

    pub fn teardown_bound(&self) -> Duration {
        self.teardown_bound
    }

    /// Start one session. With [`ProgressMode::Disabled`] (or when no worker
    /// thread can be started) the session emits nothing and costs nothing.
    pub fn begin(&self, info: SessionInfo) -> ProgressSession {
        if self.mode == ProgressMode::Disabled {
            return ProgressSession::inert(self.teardown_bound);
        }
        let consumer = (self.factory)(&info);
        let (sink, rx) = ChannelSink::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("sinter-progress".to_string())
            .spawn(move || worker_main(rx, consumer, done_tx));
        let Ok(handle) = spawned else {
            // Progress is optional: never let it stop an execution.
            return ProgressSession::inert(self.teardown_bound);
        };
        let sink = Arc::new(sink);
        sink.emit(&ProgressEvent::RunStarted { command: info.kind });
        ProgressSession {
            sink,
            worker: Some(Worker {
                done: done_rx,
                handle,
            }),
            ended: false,
            teardown_bound: self.teardown_bound,
        }
    }
}

impl std::fmt::Debug for ProgressOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressOptions")
            .field("mode", &self.mode)
            .field("teardown_bound", &self.teardown_bound)
            .finish_non_exhaustive()
    }
}

/// Signals worker completion when dropped, including while unwinding.
struct DoneSignal(Sender<()>);

impl Drop for DoneSignal {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

/// The worker: deliver events to the consumer until `RunEnded` or until the
/// channel closes, then drop everything it owns and only then signal.
fn worker_main(rx: Receiver<ProgressEvent>, consumer: Box<dyn ProgressConsumer>, done: Sender<()>) {
    let signal = DoneSignal(done);
    {
        let mut consumer = consumer;
        let rx = rx;
        while let Ok(event) = rx.recv() {
            consumer.consume(&event);
            if matches!(event, ProgressEvent::RunEnded { .. }) {
                break;
            }
        }
    }
    drop(signal);
}

struct Worker {
    done: Receiver<()>,
    handle: JoinHandle<()>,
}

/// How a session's worker ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Teardown {
    /// No worker was running (progress disabled).
    Inert,
    /// The worker finished and was joined.
    Clean,
    /// The worker panicked; the run is unaffected.
    WorkerPanicked,
    /// The worker did not finish within the bound and was left behind.
    Abandoned,
}

/// The progress scope of one execution (or of one resolution phase). See the
/// module documentation.
pub struct ProgressSession {
    sink: Arc<dyn ProgressSink>,
    worker: Option<Worker>,
    ended: bool,
    teardown_bound: Duration,
}

impl ProgressSession {
    fn inert(teardown_bound: Duration) -> Self {
        ProgressSession {
            sink: Arc::new(NoopSink),
            worker: None,
            ended: false,
            teardown_bound,
        }
    }

    /// The sink to hand to `Engine::new_with_progress`.
    pub fn sink(&self) -> Arc<dyn ProgressSink> {
        self.sink.clone()
    }

    /// Whether events flow (a worker was started).
    pub fn is_active(&self) -> bool {
        self.worker.is_some()
    }

    /// Begin the `Resolve` stage (CLI layer, around the real `ssh -G` queries).
    /// `total` is the number of hosts that will be queried.
    pub fn resolve_stage(&self, total: usize) -> ResolveStage<'_> {
        ResolveStage {
            tracker: StageTracker::start(&*self.sink, Stage::Resolve, Some(total)),
        }
    }

    /// End the session with `outcome` and tear the worker down within the bound.
    pub fn end(mut self, outcome: RunOutcome) -> Teardown {
        self.finish(outcome)
    }

    fn finish(&mut self, outcome: RunOutcome) -> Teardown {
        if self.ended {
            return Teardown::Inert;
        }
        self.ended = true;
        let Some(worker) = self.worker.take() else {
            return Teardown::Inert;
        };
        self.sink.emit(&ProgressEvent::RunEnded { outcome });
        // Release our sender; the worker already stops at `RunEnded`.
        self.sink = Arc::new(NoopSink);
        match worker.done.recv_timeout(self.teardown_bound) {
            // Signalled (or the signal's sender is gone): the worker holds no
            // Sinter state any more, so the join returns at once.
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => match worker.handle.join() {
                Ok(()) => Teardown::Clean,
                Err(_) => Teardown::WorkerPanicked,
            },
            Err(mpsc::RecvTimeoutError::Timeout) => Teardown::Abandoned,
        }
    }
}

impl Drop for ProgressSession {
    fn drop(&mut self) {
        if self.ended || self.worker.is_none() {
            return;
        }
        if std::thread::panicking() {
            // No event, no wait: unwinding must not be delayed or doubled. The
            // sender drops with `self`; the worker sees the close and exits.
            return;
        }
        let _ = self.finish(RunOutcome::Failed);
    }
}

/// An active `Resolve` stage. Ends `Failed` if dropped without [`end`](Self::end)
/// (every `?` out of the resolution code), silently while unwinding.
pub struct ResolveStage<'a> {
    tracker: StageTracker<'a>,
}

impl ResolveStage<'_> {
    /// The next host is about to be queried.
    pub fn host_started(&mut self) {
        self.tracker.item_started(None);
    }

    pub fn end(self) {
        self.tracker.end(StageOutcome::Completed);
    }
}

// ---------------------------------------------------------------------------
// Outcome mapping (closed vocabulary: no error text, no report content)
// ---------------------------------------------------------------------------

/// A returned `Err` is never a completed run; only an indeterminate error maps
/// to `Indeterminate`.
pub fn outcome_of_error(e: &SinterError) -> RunOutcome {
    match e.kind {
        ErrorKind::Indeterminate => RunOutcome::Indeterminate,
        _ => RunOutcome::Failed,
    }
}

/// Plan/apply report. A plan error or an apply failure is a failed run.
pub fn outcome_of_report(report: &RunReport) -> RunOutcome {
    match report.status {
        AggregateStatus::Success => RunOutcome::Completed,
        AggregateStatus::PlanError | AggregateStatus::ApplyFailed => RunOutcome::Failed,
        AggregateStatus::Indeterminate => RunOutcome::Indeterminate,
    }
}

/// Audit report. Drift (exit 7) is a finding, so the run completed; an
/// observation error (exit 6) leaves the verdict indeterminate. Mirrors
/// `AuditReport::exit_code` and the audit `resources` stage outcome.
pub fn outcome_of_audit(report: &AuditReport) -> RunOutcome {
    if report.summary.errors > 0 {
        RunOutcome::Indeterminate
    } else {
        RunOutcome::Completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(json: bool, tty: bool, dumb: bool) -> ModeInputs {
        ModeInputs {
            json,
            stderr_is_tty: tty,
            term_is_dumb: dumb,
        }
    }

    #[test]
    fn mode_table() {
        use ProgressMode::*;
        for (json, tty, dumb, want) in [
            (false, true, false, Tty),
            (false, true, true, Disabled),
            (false, false, false, Disabled),
            (false, false, true, Disabled),
            (true, true, false, Disabled),
            (true, true, true, Disabled),
            (true, false, false, Disabled),
            (true, false, true, Disabled),
        ] {
            assert_eq!(
                decide_mode(&inputs(json, tty, dumb)),
                want,
                "json={json} tty={tty} dumb={dumb}"
            );
        }
    }

    #[test]
    fn channel_sink_discards_a_closed_receiver() {
        let (sink, rx) = ChannelSink::channel();
        drop(rx);
        sink.emit(&ProgressEvent::RunEnded {
            outcome: RunOutcome::Completed,
        });
    }
}
