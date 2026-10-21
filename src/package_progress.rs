//! Package-progress observation (WP-PKG-PROGRESS P1).
//!
//! This module is the seam between an execution's byte streams and the
//! [`ProgressEvent::PackageDetail`] vocabulary. The generic machinery lives
//! here; the backend grammars live beside it. APT's status-fd grammar is
//! [`apt::AptProgressParser`] (Phase 2). DNF's stage lines are Phase 3 work and
//! still use [`SkeletonParser`], which recognizes nothing.
//!
//! 1. **A parser never sees raw strings.** [`LineSplitter`] frames bytes into
//!    complete lines, caps a line at [`MAX_LINE`] bytes, drops over-long lines
//!    whole (never a truncated prefix), and drops invalid UTF-8. A
//!    [`PackageParser`] therefore only ever receives a bounded `&str`.
//! 2. **Parsing and emitting happen off the drain thread.**
//!    [`PackageReporter::start`] creates one parser thread and one unbounded
//!    channel. `ExecObserver::stdout/stderr` only copies a chunk into the
//!    channel, so a slow parser, a slow sink or a panicking sink can never
//!    stall the executor's pipe/SSH drain loop, delay the child process or
//!    change an exit code, a result or a timeout.
//! 3. **Bounded in every direction.** At most [`MAX_LINE`] bytes per line, at
//!    most [`MAX_OBSERVED_BYTES`] observed per stream (the same per-stream
//!    bound the capture uses, so 2 MiB per execution), at most one event per
//!    `(source, phase, percent, …)` key
//!    and at most [`MAX_EVENTS_PER_SECOND`] events per second. Absent data is
//!    `None`, never zero.
//! 4. **No invented numbers.** An observation carries `percent_scope` exactly
//!    when it carries a percent, and `ProgressConfidence::Unknown` /
//!    `ProgressSource::StageFallback` never carry a percent; the validator in
//!    [`crate::progress`] enforces both.
//! 5. **Ordering is preserved for a sink that cannot block.** `finish` sends
//!    the end marker and joins the parser thread when the sink declared
//!    [`crate::progress::ProgressSink::is_non_blocking`] (the production
//!    `ChannelSink` does), so every detail of one execution is emitted before
//!    the engine can emit the matching `StageEnded`/`RunEnded`. For an unknown
//!    sink the wait is bounded instead: the parser is stopped and the thread is
//!    detached if a chunk is in flight, which can leave at most one in-flight
//!    `emit` to complete late. A blocking sink therefore cannot hang the run;
//!    it can only truncate its own detail stream.
//!
//!    The bound is structural, not a timeout: `finish` reads a `busy` flag
//!    under the same lock the parser takes before a chunk. When the flag is
//!    clear, no future chunk can start, so joining is bounded by the parser's
//!    own O(bytes) work. When it is set, the reporter detaches rather than
//!    waiting for a call it does not control.
//!
//! The reporter is an observation device only. It has no handle to the
//! executor's result, cannot cancel anything, cannot retry anything and never
//! writes to stdout or to the terminal.

pub mod apt;

use crate::executor::ExecObserver;
use crate::platform::PackageBackend;
use crate::progress::{
    ItemRef, PackagePhase, PackageProgress, PackageScope, PercentScope, ProgressConfidence,
    ProgressEvent, ProgressSink, ProgressSource, PACKAGE_NAME_MAX,
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The longest line a parser sees, in bytes. A line that would exceed it is
/// dropped whole: a truncated prefix could otherwise match a stricter grammar.
pub const MAX_LINE: usize = 4096;

/// The most bytes observed **per stream**. The capture uses the same bound per
/// stream (`MAX_CAPTURE`); progress never needs more, and this keeps the queue
/// between the drain thread and the parser thread bounded at 2 MiB per
/// execution (1 MiB of stdout plus 1 MiB of stderr).
pub const MAX_OBSERVED_BYTES: usize = 1024 * 1024;

/// The most detail events emitted per second, across both streams.
pub const MAX_EVENTS_PER_SECOND: u32 = 10;

/// Split an arbitrary byte stream into bounded, valid UTF-8 lines.
///
/// `\n` and `\r` both end a line (package managers use both: APT updates
/// `Reading database … N%` with CR). A line over [`MAX_LINE`] bytes is dropped
/// whole; so is a line that is not valid UTF-8. No state survives a dropped
/// line: parsing resumes at the next terminator.
#[derive(Debug, Default)]
pub struct LineSplitter {
    buf: Vec<u8>,
    overflow: bool,
}

impl LineSplitter {
    pub fn new() -> Self {
        LineSplitter::default()
    }

    /// Feed one chunk. `on_line` is called for every complete line, in order.
    pub fn feed<F: FnMut(&str)>(&mut self, chunk: &[u8], mut on_line: F) {
        for &byte in chunk {
            match byte {
                b'\n' | b'\r' => self.end_line(&mut on_line),
                _ if self.buf.len() < MAX_LINE => self.buf.push(byte),
                _ => self.overflow = true,
            }
        }
    }

    fn end_line<F: FnMut(&str)>(&mut self, on_line: &mut F) {
        if !self.overflow && !self.buf.is_empty() {
            if let Ok(text) = std::str::from_utf8(&self.buf) {
                on_line(text);
            }
        }
        self.buf.clear();
        self.overflow = false;
    }
}

/// One package-phase observation, before it is attached to a resource.
///
/// Every optional field means "the source measured this". A parser must not
/// derive a percent from a count, a byte count from a percent, or an ETA at
/// all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PackageObservation {
    pub phase: PackagePhase,
    pub scope: PackageScope,
    pub package: Option<String>,
    pub percent: Option<u8>,
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
}

impl PackageObservation {
    pub fn new(
        phase: PackagePhase,
        scope: PackageScope,
        source: ProgressSource,
        confidence: ProgressConfidence,
    ) -> Self {
        PackageObservation {
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
        }
    }
}

/// A backend-specific line parser. P1 ships [`SkeletonParser`]; Phase 2 and
/// Phase 3 replace it with the APT and DNF grammars.
pub trait PackageParser: Send {
    /// Observe one complete, bounded line. `None` means "not a record I know".
    fn observe(&mut self, line: &str) -> Option<PackageObservation>;
}

/// The Phase 1 parser: recognizes nothing. Every line is ignored, so a
/// package execution with the skeleton produces no detail at all.
#[derive(Debug, Default)]
pub struct SkeletonParser;

impl PackageParser for SkeletonParser {
    fn observe(&mut self, _line: &str) -> Option<PackageObservation> {
        None
    }
}

/// Whether `name` is a conservative package-name token: 1 to
/// [`PACKAGE_NAME_MAX`] printable ASCII characters drawn from the set package
/// managers actually use, starting with an alphanumeric. Anything else —
/// spaces, control characters, quotes, a leading `-`, a URL — is rejected, not
/// repaired.
pub fn valid_package_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > PACKAGE_NAME_MAX {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_alphanumeric()) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'_' | b':' | b'-'))
}

/// Sanitize a package name parsed from target output. Returns `None` rather
/// than a repaired string when the token is not a plausible package name.
pub fn sanitize_package_name(name: &str) -> Option<String> {
    valid_package_name(name).then(|| name.to_string())
}

/// The identity of a detail for de-duplication. Two observations with the same
/// key are the same event and only the first is emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DetailKey {
    source: ProgressSource,
    phase: PackagePhase,
    percent: Option<u8>,
    percent_scope: Option<PercentScope>,
    package: Option<String>,
    files_done: Option<u32>,
    files_total: Option<u32>,
    packages_done: Option<u32>,
    packages_total: Option<u32>,
    bytes_downloaded: Option<u64>,
    bytes_total: Option<u64>,
    rate_bps: Option<u64>,
}

impl DetailKey {
    fn of(o: &PackageObservation) -> Self {
        DetailKey {
            source: o.source,
            phase: o.phase,
            percent: o.percent,
            percent_scope: o.percent_scope,
            package: o.package.clone(),
            files_done: o.files_done,
            files_total: o.files_total,
            packages_done: o.packages_done,
            packages_total: o.packages_total,
            bytes_downloaded: o.bytes_downloaded,
            bytes_total: o.bytes_total,
            rate_bps: o.rate_bps,
        }
    }
}

/// De-duplication and rate limiting, owned by the parser thread.
struct Emitter {
    last: Option<DetailKey>,
    window_start: Instant,
    window_count: u32,
}

impl Emitter {
    fn new(now: Instant) -> Self {
        Emitter {
            last: None,
            window_start: now,
            window_count: 0,
        }
    }

    /// Whether this observation should become an event now.
    fn accept(&mut self, observation: &PackageObservation, now: Instant) -> bool {
        if now.saturating_duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.window_count = 0;
        }
        let key = DetailKey::of(observation);
        if self.last.as_ref() == Some(&key) {
            return false;
        }
        if self.window_count >= MAX_EVENTS_PER_SECOND {
            // The dropped observation is not remembered, so it is retried once
            // the window reopens if it is still the current state.
            return false;
        }
        self.last = Some(key);
        self.window_count += 1;
        true
    }
}

/// One chunk on its way from the drain thread to the parser thread.
enum Chunk {
    Data(Vec<u8>),
    Finish,
}

struct State {
    tx: Option<Sender<Chunk>>,
    handle: Option<JoinHandle<()>>,
    /// Whether the sink declared `is_non_blocking` at start time.
    non_blocking: bool,
}

/// The shutdown handshake between [`PackageReporter::finish`] and the parser
/// thread.
///
/// `finish` sets `stopping` and reads `busy` under the same lock the parser
/// takes before starting a chunk. If it observes `busy == false`, no chunk is
/// in flight and every future one is refused, so joining the thread is
/// bounded. If `busy == true`, a parser or sink call is executing and may never
/// return; the reporter detaches instead of waiting.
#[derive(Default)]
struct Stop {
    state: Mutex<StopState>,
}

#[derive(Default)]
struct StopState {
    stopping: bool,
    busy: bool,
}

impl Stop {
    /// Enter one chunk's processing. `None` when the reporter is stopping.
    fn enter(&self) -> Option<StopGuard<'_>> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.stopping {
            return None;
        }
        state.busy = true;
        Some(StopGuard(self))
    }

    /// Mark the reporter as stopping; returns whether a chunk is in flight.
    fn stop(&self) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.stopping = true;
        state.busy
    }
}

/// Clears `busy` on every exit path, including a panic inside a parser or sink.
struct StopGuard<'a>(&'a Stop);

impl Drop for StopGuard<'_> {
    fn drop(&mut self) {
        let mut state = match self.0.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.busy = false;
    }
}

/// Observes one execution's streams and turns parser output into
/// [`ProgressEvent::PackageDetail`] events, on its own thread.
///
/// Construct with [`PackageReporter::start`], pass it to
/// [`TargetFs::exec_with_observer`](crate::targetfs::TargetFs::exec_with_observer)
/// and call [`PackageReporter::finish`] when the command has returned. The
/// reporter owns no result and cannot influence the execution.
pub struct PackageReporter {
    state: Mutex<State>,
    /// Bytes accepted per stream: index 0 is stdout, 1 is stderr.
    observed: [AtomicUsize; 2],
    stop: Arc<Stop>,
}

impl PackageReporter {
    /// Start a reporter, or `None` when the sink is disabled (the fast path: no
    /// thread, no channel, no parser).
    pub fn start(
        resource: ItemRef,
        backend: PackageBackend,
        parser: Box<dyn PackageParser>,
        sink: Arc<dyn ProgressSink>,
    ) -> Option<Arc<PackageReporter>> {
        if !sink.is_enabled() {
            return None;
        }
        let non_blocking = sink.is_non_blocking();
        let stop = Arc::new(Stop::default());
        let thread_stop = stop.clone();
        let (tx, rx) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("sinter-pkg-progress".to_string())
            .spawn(move || {
                parser_thread(
                    parser,
                    sink,
                    resource,
                    backend,
                    rx,
                    thread_stop,
                    non_blocking,
                )
            })
            .ok()?;
        Some(Arc::new(PackageReporter {
            state: Mutex::new(State {
                tx: Some(tx),
                handle: Some(handle),
                non_blocking,
            }),
            observed: [AtomicUsize::new(0), AtomicUsize::new(0)],
            stop,
        }))
    }

    /// Queue bytes for the parser thread. Never blocks: the channel is
    /// unbounded and the copy is bounded by [`MAX_OBSERVED_BYTES`] **per
    /// stream** (2 MiB per execution in total).
    fn send(&self, stream: usize, bytes: &[u8]) {
        let counter = &self.observed[stream];
        let before = counter.fetch_add(bytes.len(), Ordering::Relaxed);
        if before >= MAX_OBSERVED_BYTES {
            return;
        }
        let room = MAX_OBSERVED_BYTES - before;
        let take = bytes.len().min(room);
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(tx) = state.tx.as_ref() {
            // A disconnected parser thread means it stopped; dropping the
            // chunk is the only right answer.
            let _ = tx.send(Chunk::Data(bytes[..take].to_vec()));
        }
    }

    /// Deliver every queued chunk, stop the parser thread and wait for it
    /// **only when that wait is bounded**.
    ///
    /// Safe to call more than once. With a sink that declared
    /// [`ProgressSink::is_non_blocking`] (the production `ChannelSink`,
    /// `NoopSink`, `RecordingSink`), the parser thread is always joined, so no
    /// detail event can be emitted after this returns and the caller may emit
    /// its own stage-end event.
    ///
    /// With an unknown sink (`is_non_blocking == false`), the reporter never
    /// waits for a sink call it cannot bound: if no chunk is in flight the
    /// thread is joined; if one is, the parser is told to stop and the thread
    /// is detached. Queued but unprocessed chunks are dropped, and at most the
    /// one in-flight [`ProgressSink::emit`] call can complete after this
    /// returns. A hung sink leaks that one thread instead of hanging the
    /// execution.
    pub fn finish(&self) {
        let (tx, handle, non_blocking) = {
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            (state.tx.take(), state.handle.take(), state.non_blocking)
        };
        let busy = self.stop.stop();
        if let Some(tx) = tx {
            let _ = tx.send(Chunk::Finish);
        }
        if let Some(handle) = handle {
            if non_blocking || !busy {
                let _ = handle.join();
            }
        }
    }
}

impl ExecObserver for PackageReporter {
    fn stdout(&self, chunk: &[u8]) {
        self.send(0, chunk);
    }

    fn stderr(&self, chunk: &[u8]) {
        self.send(1, chunk);
    }
}

impl Drop for PackageReporter {
    fn drop(&mut self) {
        // A caller that forgot to finish (an early return) must not leave the
        // parser thread waiting forever. Do not join here: dropping happens on
        // the caller's thread and must stay bounded.
        self.stop.stop();
        let state = match self.state.get_mut() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(tx) = state.tx.take() {
            let _ = tx.send(Chunk::Finish);
        }
    }
}

fn parser_thread(
    mut parser: Box<dyn PackageParser>,
    sink: Arc<dyn ProgressSink>,
    resource: ItemRef,
    backend: PackageBackend,
    rx: Receiver<Chunk>,
    stop: Arc<Stop>,
    drain_all: bool,
) {
    let mut splitter = LineSplitter::new();
    let mut emitter = Emitter::new(Instant::now());
    // A panic in a parser or a sink stops observation for this execution; it
    // never unwinds into the executor, which has already been isolated by the
    // channel.
    let mut poisoned = false;
    while let Ok(chunk) = rx.recv() {
        let Chunk::Data(bytes) = chunk else {
            break;
        };
        if poisoned {
            continue;
        }
        // A chunk is processed as one unit. For a sink that may block, the
        // reporter stops at the next chunk boundary once `finish` asks, so the
        // queued tail is dropped rather than waited for. For a sink that
        // declared `is_non_blocking`, every queued chunk is drained and
        // `finish` joins: no event is lost and the ordering is exact.
        let guard = if drain_all {
            None
        } else {
            match stop.enter() {
                Some(guard) => Some(guard),
                None => break,
            }
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            splitter.feed(&bytes, |line| {
                if let Some(observation) = parser.observe(line) {
                    if !emitter.accept(&observation, Instant::now()) {
                        return;
                    }
                    let events = to_progress(&resource, backend, &observation);
                    sink.emit(&ProgressEvent::PackageDetail(events));
                }
            });
        }));
        drop(guard);
        if result.is_err() {
            poisoned = true;
        }
    }
}

/// Attach one observation to the resource it belongs to.
fn to_progress(
    resource: &ItemRef,
    backend: PackageBackend,
    observation: &PackageObservation,
) -> PackageProgress {
    let mut progress = PackageProgress::new(
        resource.clone(),
        backend,
        observation.phase,
        observation.scope,
        observation.source,
        observation.confidence,
    );
    progress.package = observation.package.clone();
    progress.percent = observation.percent;
    progress.percent_scope = observation.percent_scope;
    progress.files_done = observation.files_done;
    progress.files_total = observation.files_total;
    progress.packages_done = observation.packages_done;
    progress.packages_total = observation.packages_total;
    progress.bytes_downloaded = observation.bytes_downloaded;
    progress.bytes_total = observation.bytes_total;
    progress.rate_bps = observation.rate_bps;
    progress
}

#[cfg(test)]
mod tests;
