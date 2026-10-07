//! CLI-layer progress plumbing (WP-PROGRESS S3).
//!
//! S1/S2 gave the engine a [`ProgressSink`]. This module is everything between
//! that sink and a renderer. This module has **no renderer** of its own: the
//! only consumer shipped here is [`NullConsumer`], which drops every event, and
//! nothing in this module writes to stdout, stderr or a terminal. The TTY
//! renderer (S4, [`crate::progress_tty`]) and the explicit plain renderer (S5,
//! [`crate::progress_plain`]) plug a [`ProgressConsumer`] in through
//! [`ProgressOptions::with_consumer_factory`]; they own formatting, clocks and
//! terminal handling. The worker only offers them a wake-up when they ask for
//! one ([`ProgressConsumer::wake_after`]).
//!
//! This is library API and, like [`crate::progress`], is not part of the 1.x
//! CLI/JSON compatibility promise.
//!
//! # Owner policy (structural)
//!
//! * TTY, text format: progress is automatic ([`ProgressMode::Tty`]).
//! * Not a TTY (pipes, redirects, CI): off by default ([`ProgressMode::Disabled`]).
//!   Plain progress ([`ProgressMode::Plain`]) is an explicit opt-in only:
//!   `SINTER_PROGRESS=plain` ([`PROGRESS_ENV`]). Nothing else turns it on, and
//!   no value of that variable changes the automatic behaviour.
//! * JSON: off on every stream, whatever the terminal and whatever the
//!   environment ([`decide_mode`]). Existing JSON-mode error diagnostics are not
//!   progress and are untouched.
//!
//! # The decision happens in two phases
//!
//! 1. [`decide_mode`]: from facts known at the command line (format, whether
//!    stderr is a terminal, `TERM`). Only `plan`, `apply` and `audit` ever ask;
//!    `validate`, `secrets` and `mcp` never construct a session.
//! 2. Per execution, once the recipe model exists: [`SessionInfo`] carries
//!    [`SessionInfo::references_secrets`] (any resource has a `secret`). It is
//!    information for the consumer: no renderer may write when it is set (owner
//!    decision OQ-5), because a passphrase prompt or a `sinter:` secret note may
//!    write to the terminal mid-run. The null consumer ignores it and the
//!    factories of both renderers (S4 and S5) build the null consumer when it is
//!    set; nothing here coordinates with prompts.
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
//!   the worst case, and only a consumer that blocks can cause it. The consumer
//!   is told through an [`AbandonLatch`] and must hold no lock the run needs
//!   while it blocks (the renderer writes through a private descriptor, never
//!   through `std::io::stderr()`), so an abandoned worker can neither hold the
//!   run up nor write after the run has moved on.
//! * **Panic of the run itself.** While the thread is panicking `Drop` emits
//!   nothing, does not wait and does not join, so a panic cannot become a double
//!   panic or be delayed. It does set the [`AbandonLatch`] (one atomic store):
//!   the worker is detached, and a detached worker that still had events queued
//!   would otherwise draw them after the panic message. Muted, it processes
//!   nothing, schedules nothing and writes nothing (no final erase either) and
//!   exits when the channel closes. The one write that may already be blocked in
//!   the kernel is the same residual as for an abandoned worker. No stronger
//!   panic guarantee is claimed: a stream may end without `RunEnded`.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// The shortest wait the worker will ask `recv_timeout` for, whatever a
/// consumer's [`ProgressConsumer::wake_after`] says (no busy spin).
pub(crate) const MIN_WAKE: Duration = Duration::from_millis(1);

/// How long [`ProgressSession::end`] waits for its worker before abandoning it.
/// Generous for a consumer that only erases a line; small enough that a stalled
/// stderr delays process exit by well under a second.
pub const DEFAULT_TEARDOWN_BOUND: Duration = Duration::from_millis(500);

// ---------------------------------------------------------------------------
// Mode decision
// ---------------------------------------------------------------------------

/// Whether progress is produced for an invocation, and which kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProgressMode {
    /// No events, no thread, no channel.
    Disabled,
    /// Events flow to the consumer: the automatic mode of an eligible terminal
    /// (the transient line of [`crate::progress_tty`]).
    Tty,
    /// Events flow to the consumer: the explicit opt-in (`SINTER_PROGRESS=plain`)
    /// of [`crate::progress_plain`], bounded persistent lines on stderr.
    Plain,
}

/// The environment variable that opts in to [`ProgressMode::Plain`]. The only
/// value it recognises is `plain`; any other value (or none) leaves the
/// automatic behaviour untouched.
pub const PROGRESS_ENV: &str = "SINTER_PROGRESS";

/// The command-line facts the first phase of the decision depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeInputs {
    /// `--format json`.
    pub json: bool,
    /// stderr is a terminal (progress is a stderr concern; stdout is the report).
    pub stderr_is_tty: bool,
    /// `TERM=dumb`.
    pub term_is_dumb: bool,
    /// `SINTER_PROGRESS=plain` ([`plain_requested`]).
    pub plain_requested: bool,
}

/// Whether the value of [`PROGRESS_ENV`] asks for plain progress: exactly
/// `plain`, nothing else.
pub fn plain_requested(value: Option<&OsStr>) -> bool {
    value.is_some_and(|v| v == OsStr::new("plain"))
}

/// Pure phase-1 decision, the only place progress is decided. JSON wins over
/// everything. Otherwise an explicit request for plain progress wins (it has no
/// terminal, `TERM` or colour dependency: it writes persistent ASCII lines),
/// and without one an eligible terminal gets the transient line and everything
/// else gets nothing. `NO_COLOR` is irrelevant (it affects colour, not whether
/// a line may exist).
pub fn decide_mode(inputs: &ModeInputs) -> ProgressMode {
    if inputs.json {
        ProgressMode::Disabled
    } else if inputs.plain_requested {
        ProgressMode::Plain
    } else if !inputs.stderr_is_tty || inputs.term_is_dumb {
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
        plain_requested: plain_requested(std::env::var_os(PROGRESS_ENV).as_deref()),
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
/// logic and cannot influence the run (it has no handle to it). The S4 and S5
/// renderers implement formatters behind this trait.
pub trait ProgressConsumer: Send {
    fn consume(&mut self, event: &ProgressEvent);

    /// How long the worker may wait for the next event before it must call
    /// [`tick`](Self::tick), `None` to wait for events only. Asked again before
    /// every wait, so the consumer owns its clock and its schedule; the worker
    /// never waits less than a millisecond. S4's renderer uses it for the quiet
    /// elapsed refresh; the default (and the null consumer) never ticks.
    fn wake_after(&mut self) -> Option<Duration> {
        None
    }

    /// The wait asked for by [`wake_after`](Self::wake_after) expired with no
    /// event.
    fn tick(&mut self) {}

    /// Called once, on the caller's thread, before the consumer moves to its
    /// worker. A consumer that writes somewhere a stall can block must keep the
    /// latch and stop writing for good as soon as it is set (see
    /// [`AbandonLatch`]). The default ignores it.
    fn attach_abandon_latch(&mut self, _latch: AbandonLatch) {}
}

/// Set by [`ProgressSession::end`] at the moment it gives up waiting for the
/// worker and returns [`Teardown::Abandoned`]. From then on the run goes on
/// without the worker, so the worker's consumer must not write again: a late
/// write would land after (or inside) output that the run has printed since.
/// One write that is already blocked in the kernel cannot be called back; the
/// latch stops everything after it.
#[derive(Debug, Clone, Default)]
pub struct AbandonLatch(Arc<AtomicBool>);

impl AbandonLatch {
    /// Whether the session has abandoned the worker.
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    pub(crate) fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
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
    /// See the module documentation (OQ-5): no renderer writes when set.
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

    /// Replace the consumer (the S4/S5 seam, and the test seam). Which renderer
    /// belongs to the decided [`mode`](Self::mode) is the caller's choice; a
    /// renderer never decides whether it runs.
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
        let mut consumer = (self.factory)(&info);
        let latch = AbandonLatch::default();
        consumer.attach_abandon_latch(latch.clone());
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
                latch,
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
/// channel closes, then drop everything it owns and only then signal. While the
/// consumer asks for a wake-up the wait for the next event is bounded by it and
/// an expired wait is a [`ProgressConsumer::tick`]; there is no other timer and
/// no thread besides this one.
fn worker_main(rx: Receiver<ProgressEvent>, consumer: Box<dyn ProgressConsumer>, done: Sender<()>) {
    let signal = DoneSignal(done);
    {
        let mut consumer = consumer;
        let rx = rx;
        loop {
            let event = match consumer.wake_after() {
                None => match rx.recv() {
                    Ok(event) => event,
                    Err(_) => break,
                },
                Some(wait) => match rx.recv_timeout(wait.max(MIN_WAKE)) {
                    Ok(event) => event,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        consumer.tick();
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                },
            };
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
    latch: AbandonLatch,
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
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Mute the worker before the run prints anything else.
                worker.latch.set();
                Teardown::Abandoned
            }
        }
    }
}

impl Drop for ProgressSession {
    fn drop(&mut self) {
        if self.ended || self.worker.is_none() {
            return;
        }
        if std::thread::panicking() {
            // No event, no wait, no join: unwinding must not be delayed or
            // doubled. The worker is about to be detached, so mute it first
            // (one atomic store): events still queued must not be drawn after
            // the panic message, and a muted worker does not even erase. The
            // sender drops with `self`; the worker sees the close and exits.
            if let Some(worker) = &self.worker {
                worker.latch.set();
            }
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
            plain_requested: false,
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
    fn mode_table_with_an_explicit_plain_request() {
        use ProgressMode::*;
        // JSON wins; otherwise an explicit request wins over every terminal
        // fact; without one the table above applies unchanged.
        for (json, tty, dumb, want) in [
            (false, true, false, Plain),
            (false, true, true, Plain),
            (false, false, false, Plain),
            (false, false, true, Plain),
            (true, true, false, Disabled),
            (true, true, true, Disabled),
            (true, false, false, Disabled),
            (true, false, true, Disabled),
        ] {
            let mut i = inputs(json, tty, dumb);
            i.plain_requested = true;
            assert_eq!(
                decide_mode(&i),
                want,
                "json={json} tty={tty} dumb={dumb} plain"
            );
        }
    }

    #[test]
    fn only_the_exact_value_plain_requests_plain_progress() {
        assert!(plain_requested(Some(OsStr::new("plain"))));
        for other in [
            "", "Plain", "PLAIN", " plain", "plain ", "1", "true", "auto", "off", "tty", "plain,x",
        ] {
            assert!(
                !plain_requested(Some(OsStr::new(other))),
                "{other:?} must not enable plain progress"
            );
        }
        assert!(!plain_requested(None));
    }

    /// Keeps the latch it is given so a test can look at it from outside.
    struct KeepsLatch(Arc<std::sync::Mutex<Option<AbandonLatch>>>);

    impl ProgressConsumer for KeepsLatch {
        fn consume(&mut self, _event: &ProgressEvent) {}

        fn attach_abandon_latch(&mut self, latch: AbandonLatch) {
            if let Ok(mut slot) = self.0.lock() {
                *slot = Some(latch);
            }
        }
    }

    fn latch_probe() -> (ProgressOptions, Arc<std::sync::Mutex<Option<AbandonLatch>>>) {
        let slot = Arc::new(std::sync::Mutex::new(None));
        let handed = slot.clone();
        let opts =
            ProgressOptions::new(ProgressMode::Tty).with_consumer_factory(Arc::new(move |_| {
                Box::new(KeepsLatch(handed.clone())) as Box<dyn ProgressConsumer>
            }));
        (opts, slot)
    }

    fn the_latch(slot: &Arc<std::sync::Mutex<Option<AbandonLatch>>>) -> AbandonLatch {
        slot.lock()
            .unwrap()
            .clone()
            .expect("the session attached a latch")
    }

    fn info() -> SessionInfo {
        SessionInfo {
            kind: RunKind::Apply,
            references_secrets: false,
        }
    }

    /// RA-L1: a session dropped while the thread unwinds from a panic detaches
    /// its worker, so it must mute it first.
    #[test]
    fn a_session_dropped_by_a_panic_mutes_its_detached_worker() {
        let (opts, slot) = latch_probe();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _session = opts.begin(info());
            assert!(!the_latch(&slot).is_set(), "not muted while healthy");
            panic!("the run panicked (expected by this test)");
        }));
        assert!(caught.is_err());
        assert!(
            the_latch(&slot).is_set(),
            "the panic-unwind drop left the detached worker unmuted"
        );
    }

    /// The panic branch only mutes: no `RunEnded`, no wait, no join.
    #[test]
    fn the_panic_branch_neither_waits_nor_emits() {
        let events = Arc::new(std::sync::Mutex::new(Vec::<ProgressEvent>::new()));
        struct Rec(Arc<std::sync::Mutex<Vec<ProgressEvent>>>);
        impl ProgressConsumer for Rec {
            fn consume(&mut self, event: &ProgressEvent) {
                if let Ok(mut v) = self.0.lock() {
                    v.push(event.clone());
                }
            }
        }
        let handed = events.clone();
        let opts = ProgressOptions::new(ProgressMode::Tty)
            .with_consumer_factory(Arc::new(move |_| {
                Box::new(Rec(handed.clone())) as Box<dyn ProgressConsumer>
            }))
            .with_teardown_bound(Duration::from_secs(30));
        let started = std::time::Instant::now();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _session = opts.begin(info());
            panic!("expected by this test");
        }));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the panic path waited for the worker"
        );
        // Give the detached worker the chance to deliver anything it was sent.
        std::thread::sleep(Duration::from_millis(100));
        let seen = events.lock().unwrap().clone();
        assert!(
            !seen
                .iter()
                .any(|e| matches!(e, ProgressEvent::RunEnded { .. })),
            "the panic branch must not emit RunEnded: {seen:?}"
        );
    }

    /// The normal early-exit drop is unchanged: it ends the run `Failed` and
    /// does not mute a worker that finished in time.
    #[test]
    fn a_normal_drop_still_ends_the_run_and_leaves_the_latch_alone() {
        let (opts, slot) = latch_probe();
        {
            let _session = opts.begin(info());
        }
        assert!(
            !the_latch(&slot).is_set(),
            "a clean teardown must not set the latch"
        );
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
