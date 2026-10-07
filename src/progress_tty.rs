//! The TTY transient progress renderer (WP-PROGRESS S4).
//!
//! One consumer ([`ProgressConsumer`]) for the `Tty` progress mode: it keeps
//! **one transient line on stderr** that names the stage, the counter when one
//! exists, the item in flight and, after a quiet spell, how long nothing has
//! happened. The line is erased when the run ends, so the persistent output
//! (the report on stdout, the `sinter:` error line on stderr) is exactly what it
//! was without progress. This is library API and, like [`crate::progress`], not
//! part of the 1.x CLI/JSON compatibility promise; only the factory functions
//! and the [`Surface`] seam are public, everything else is private.
//!
//! # Display contract
//!
//! ```text
//! resolve 0/3
//! connect
//! backup 1/2
//! apply 17/42 package:nginx 8s
//! handlers 0/1 handler:reload-nginx
//! ```
//!
//! `label [done/total] [kind:id] [elapsed]`, ASCII only, one line, no spinner,
//! no percentage, no ETA, no colour.
//!
//! * **label**: the stage's own name (`resolve`, `connect`, `backup`,
//!   `handlers`); for the resource traversal the command (`plan`, `apply`,
//!   `audit`, from [`SessionInfo::kind`]). No stage is invented: between the
//!   last stage and the end of the run the line keeps showing the last stage.
//! * **counter**: `done/total` when the stage has an honest total, nothing
//!   otherwise. `done` is the number of items that already reached a terminal
//!   disposition (the item shown is the one in flight), exactly as
//!   [`ProgressEvent::Progress`] defines it; a stage that ended shows its final
//!   `done`, which for a failed stage may equal `total`. **Success is never
//!   inferred from the counter**: a stage that ended `Failed` or `Indeterminate`
//!   says so (`apply 5/5 failed`); the outcome, not `done == total`, decides.
//! * **current item**: `kind:id` only, from the event ([`ItemRef`]). Stages
//!   whose items have no safe identity (resolve, backup, connect) show none.
//! * **elapsed**: time since the last progress event of any kind, measured by
//!   the renderer's own monotonic clock, shown only once it reaches
//!   [`QUIET_AFTER`] (`8s`, `2m05s`, `1h02m`). It says Sinter has been waiting
//!   that long on the current item; it never claims the engine is alive. It
//!   restarts at every event, so it is **not** the run's total elapsed time.
//!
//! # Safety of the displayed text
//!
//! Item ids are recipe literals but are treated as untrusted terminal text:
//! every character outside printable ASCII (`0x20..=0x7e`: controls, ESC, CR,
//! LF, TAB, BEL, DEL, C1, non-ASCII) is replaced by `?`, one `?` per character,
//! before anything is laid out. The underlying event is not modified. The only
//! control sequence the renderer ever writes is [`CLEAR`] (`CR ESC [ 2 K`).
//!
//! # Width
//!
//! The line is bounded to the width of the terminal on **stderr**
//! (`ioctl(TIOCGWINSZ)`, asked again at every draw), minus one column so the
//! cursor never reaches the wrap position. A failing `ioctl` or a reported width
//! of `0` means *unknown* and uses [`FALLBACK_COLUMNS`] (60); the `COLUMNS`
//! environment variable is deliberately not consulted (one input fewer, and a
//! small fallback is the conservative choice). A terminal of one
//! column has no room for a line and draws nothing. When the line does not fit,
//! the item is shortened first (`kind:abc...`), then dropped, then the elapsed
//! text, then the label and counter are cut to the budget.
//!
//! # Transient line
//!
//! `draw` writes `CR ESC[2K <text>` in one `write`, `clear` writes `CR ESC[2K`;
//! no newline is ever written, so nothing is left behind and the next output
//! starts at column 0. No cursor hiding, no vertical movement, no alternate
//! screen, no termios change. Redraws are coalesced to one per
//! [`MIN_REDRAW`] and an unchanged line is not rewritten. A consequence of the
//! coalescing: a change that arrives within that interval of the last write is
//! held, and a run that ends first never shows it (a failure that happens within
//! 100 ms of the previous draw never displays its `failed` word; the persistent
//! `sinter:` line still carries the failure).
//!
//! # Ticking
//!
//! The consumer asks the S3 worker to wake it ([`ProgressConsumer::wake_after`])
//! at the moment the elapsed text next changes (first at [`QUIET_AFTER`], then
//! on every whole second) or when a coalesced redraw is due, and never otherwise:
//! a run that is not waiting costs no wakeups. There is no extra thread and no
//! timer dependency.
//!
//! # Secrets (owner decision OQ-5)
//!
//! When [`SessionInfo::references_secrets`] is set the factory builds the
//! [`NullConsumer`]: the surface is not even created, so no progress byte can
//! precede a passphrase prompt or a `sinter:` secret note.
//!
//! # Failure
//!
//! Progress is best effort and cannot change a result. A write error, an
//! unavailable width and a vanished terminal degrade silently: after the first
//! write error the renderer stops drawing for good. The renderer contains no
//! `unwrap`, `expect`, indexing or unchecked arithmetic on the paths taken for
//! valid events, so it cannot reach Rust's panic hook (which would write to the
//! very terminal being drawn on).
//!
//! # A stalled terminal
//!
//! A write to a terminal whose output is not being read blocks. The worker may
//! block, but only the worker:
//!
//! * The production surface writes through **its own descriptor**, a `dup` of
//!   stderr taken when the scope begins and owned by the surface, and never
//!   through [`std::io::stderr`]. `Stderr` is one process-wide lock; a blocked
//!   write that held it would hold up every `eprintln!` of the run, however
//!   short the teardown bound. No lock at all is needed on the private
//!   descriptor: a surface belongs to one worker (`&mut self`).
//! * The descriptor is **not** made non-blocking. A `dup` shares the open file
//!   description with stderr, so `O_NONBLOCK` on it would silently turn
//!   `eprintln!` non-blocking too, and a second description cannot be obtained
//!   portably (`/dev/fd/N` duplicates on macOS). A non-blocking write may also
//!   stop half way through a frame and leave part of it on the terminal.
//! * When [`ProgressSession::end`](crate::progress_session::ProgressSession::end)
//!   gives up on the worker it sets the [`AbandonLatch`]. From then on the
//!   renderer processes no event and writes nothing, not even the final erase
//!   (stderr is unbuffered, so an `eprintln!` may reach the terminal in several
//!   writes and an erase landing between them could destroy persistent text; a
//!   leftover frame only prefixes it). The one write already blocked
//!   in the kernel cannot be called back: it may still land, once, after the run
//!   has printed more. That is the whole residual, and only a terminal that has
//!   not drained for longer than the teardown bound can cause it.

use crate::progress::{ItemRef, ProgressEvent, RunKind, Stage, StageOutcome};
use crate::progress_session::{
    AbandonLatch, ConsumerFactory, NullConsumer, ProgressConsumer, SessionInfo, MIN_WAKE,
};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Erase the current line and return to column 0. The only control sequence
/// the renderer writes.
pub(crate) const CLEAR: &str = "\r\x1b[2K";

/// Width assumed when the terminal's width is unknown (`ioctl` failed or
/// reported `0`).
pub(crate) const FALLBACK_COLUMNS: usize = 60;

/// How long nothing may have happened before the elapsed time is shown.
pub(crate) const QUIET_AFTER: Duration = Duration::from_secs(3);

/// Minimum time between two writes of the line (events in between are
/// coalesced into the next draw).
pub(crate) const MIN_REDRAW: Duration = Duration::from_millis(100);

/// The elapsed time is shown in whole seconds, so it can change once a second.
const ELAPSED_STEP: Duration = Duration::from_secs(1);

/// Shortest `kind:id` text worth showing when the item has to be shortened.
const MIN_ITEM_CHARS: usize = 5;

// ---------------------------------------------------------------------------
// Surface
// ---------------------------------------------------------------------------

/// Where the line is drawn and how wide that place is. Production: stderr and
/// `ioctl(TIOCGWINSZ)`. The seam exists so tests can drive the renderer without
/// a terminal.
pub trait Surface: Send {
    /// Write `bytes` in one call. An error stops the renderer for good.
    fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    /// Width in columns, `None` when it cannot be determined.
    fn columns(&mut self) -> Option<usize>;
}

/// Builds the surface of one session (called on the caller's thread).
pub type SurfaceFactory = Arc<dyn Fn() -> Box<dyn Surface> + Send + Sync>;

/// The real surface: a private duplicate of this process's stderr. See the
/// module documentation, "A stalled terminal", for why it is not
/// [`std::io::stderr`] and not non-blocking.
struct StderrSurface {
    /// `None` when stderr could not be duplicated (closed): every write then
    /// fails and the renderer stays silent.
    file: Option<std::fs::File>,
}

impl StderrSurface {
    fn new() -> Self {
        StderrSurface {
            file: std::io::stderr()
                .as_fd()
                .try_clone_to_owned()
                .ok()
                .map(std::fs::File::from),
        }
    }
}

impl Surface for StderrSurface {
    fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        // `write_all` on a plain `File`: no std lock is held while it blocks, and
        // a failure is returned, never printed (unlike `eprint!`, which panics).
        match self.file.as_mut() {
            Some(file) => file.write_all(bytes),
            None => Err(std::io::ErrorKind::NotConnected.into()),
        }
    }

    fn columns(&mut self) -> Option<usize> {
        self.file
            .as_ref()
            .and_then(|file| columns_of_fd(file.as_raw_fd()))
    }
}

/// Width of the terminal on `fd`, `None` when `fd` is not a terminal, the
/// `ioctl` fails or the terminal reports no width.
fn columns_of_fd(fd: std::os::fd::RawFd) -> Option<usize> {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ only writes a `winsize` through the pointer, which
    // refers to a live, properly aligned local. An invalid `fd` makes the call
    // fail with an error code, never undefined behaviour.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, &mut ws as *mut libc::winsize) };
    if rc != 0 || ws.ws_col == 0 {
        return None;
    }
    Some(usize::from(ws.ws_col))
}

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

/// The production consumer factory: the transient line on stderr.
pub fn stderr_consumer_factory() -> ConsumerFactory {
    consumer_factory(Arc::new(|| Box::new(StderrSurface::new())))
}

/// A consumer factory that draws on the given surface. A session that
/// references secrets gets the [`NullConsumer`] and no surface is created.
pub fn consumer_factory(surface: SurfaceFactory) -> ConsumerFactory {
    factory_with_timing(surface, Timing::PRODUCTION)
}

fn factory_with_timing(surface: SurfaceFactory, timing: Timing) -> ConsumerFactory {
    Arc::new(move |info: &SessionInfo| -> Box<dyn ProgressConsumer> {
        if info.references_secrets {
            // OQ-5: no visual renderer at all next to a possible prompt.
            return Box::new(NullConsumer);
        }
        Box::new(TtyConsumer {
            core: Core::new(surface(), info.kind, timing, Instant::now()),
        })
    })
}

// ---------------------------------------------------------------------------
// View: what the line says, derived from events only
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StagePhase {
    Active,
    Ended(StageOutcome),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StageView {
    stage: Stage,
    phase: StagePhase,
    done: u32,
    total: Option<u32>,
    current: Option<ItemRef>,
}

/// The renderer's model of the run so far. Only closed event data goes in.
#[derive(Debug, Clone, PartialEq, Eq)]
struct View {
    command: Option<RunKind>,
    stage: Option<StageView>,
    finished: bool,
}

impl View {
    fn new(command: Option<RunKind>) -> Self {
        View {
            command,
            stage: None,
            finished: false,
        }
    }

    fn apply(&mut self, event: &ProgressEvent) {
        match event {
            ProgressEvent::RunStarted { command } => self.command = Some(*command),
            ProgressEvent::StageStarted { stage, total } => {
                self.stage = Some(StageView {
                    stage: *stage,
                    phase: StagePhase::Active,
                    done: 0,
                    total: *total,
                    current: None,
                });
            }
            ProgressEvent::Progress {
                stage,
                done,
                total,
                current,
            } => {
                self.stage = Some(StageView {
                    stage: *stage,
                    phase: StagePhase::Active,
                    done: *done,
                    total: *total,
                    current: current.clone(),
                });
            }
            ProgressEvent::StageEnded {
                stage,
                outcome,
                done,
            } => {
                // The total survives from the active stage of the same name.
                let total = match &self.stage {
                    Some(s) if s.stage == *stage => s.total,
                    _ => None,
                };
                self.stage = Some(StageView {
                    stage: *stage,
                    phase: StagePhase::Ended(*outcome),
                    done: *done,
                    total,
                    current: None,
                });
            }
            ProgressEvent::RunEnded { .. } => {
                self.finished = true;
            }
        }
    }

    /// Whether the view has anything to show at all.
    fn has_line(&self) -> bool {
        !self.finished && self.stage.is_some()
    }
}

// ---------------------------------------------------------------------------
// Pure formatting
// ---------------------------------------------------------------------------

/// Printable ASCII only; every other character becomes `?`. At most `limit`
/// characters of `s` are looked at, so a huge id costs a bounded amount of work.
fn sanitize_display(s: &str, limit: usize) -> String {
    s.chars()
        .take(limit)
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .collect()
}

fn stage_label(stage: Stage, command: Option<RunKind>) -> &'static str {
    match (stage, command) {
        (Stage::Resources, Some(RunKind::Plan)) => "plan",
        (Stage::Resources, Some(RunKind::Apply)) => "apply",
        (Stage::Resources, Some(RunKind::Audit)) => "audit",
        (Stage::Resources, None) => "resources",
        (Stage::Resolve, _) => "resolve",
        (Stage::Connect, _) => "connect",
        (Stage::Backup, _) => "backup",
        (Stage::Handlers, _) => "handlers",
    }
}

/// `8s`, `2m05s`, `1h02m`: whole units, stable, ASCII.
fn format_elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// How many characters of the line fit on a terminal `columns` wide: one less
/// than the width, with [`FALLBACK_COLUMNS`] standing in for an unknown width.
fn line_budget(columns: Option<usize>) -> usize {
    let width = match columns {
        Some(c) if c > 0 => c,
        _ => FALLBACK_COLUMNS,
    };
    width.saturating_sub(1)
}

/// Cut `s` to at most `n` characters (the strings handled here are ASCII).
fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Lay out the pieces within `max` characters. Priority, highest first: label
/// and counter, elapsed, item (shortened with `...`, then dropped).
fn fit(head: &str, item: Option<&str>, tail: Option<&str>, max: usize) -> String {
    let head_len = head.chars().count();
    let tail_len = tail.map_or(0, |t| t.chars().count() + 1);
    if head_len + tail_len > max {
        // Not even the label and the elapsed time: keep the label.
        return cut(head, max);
    }
    let mut out = String::from(head);
    let room = max - head_len - tail_len;
    if let Some(item) = item {
        let avail = room.saturating_sub(1);
        let item_len = item.chars().count();
        if item_len <= avail {
            out.push(' ');
            out.push_str(item);
        } else if avail >= MIN_ITEM_CHARS {
            out.push(' ');
            out.push_str(&cut(item, avail - 3));
            out.push_str("...");
        }
    }
    if let Some(tail) = tail {
        out.push(' ');
        out.push_str(tail);
    }
    out
}

/// The text of the line for `view`, at most `max` characters, or `None` when
/// there is nothing to show. `quiet` is the elapsed time to display (already
/// past the display threshold) or `None`. Pure: no clock, no terminal.
fn format_line(view: &View, quiet: Option<Duration>, max: usize) -> Option<String> {
    if !view.has_line() || max == 0 {
        return None;
    }
    let sv = view.stage.as_ref()?;
    let mut head = String::from(stage_label(sv.stage, view.command));
    if let Some(total) = sv.total {
        head.push_str(&format!(" {}/{}", sv.done, total));
    }
    match sv.phase {
        StagePhase::Active => {}
        StagePhase::Ended(StageOutcome::Completed) => {}
        StagePhase::Ended(StageOutcome::Failed) => head.push_str(" failed"),
        StagePhase::Ended(StageOutcome::Indeterminate) => head.push_str(" indeterminate"),
    }
    let item = sv.current.as_ref().map(|c| {
        // Bounded work for a huge id: 8 characters of slack over the budget.
        format!(
            "{}:{}",
            c.kind.label(),
            sanitize_display(&c.id, max.saturating_add(8))
        )
    });
    let tail = quiet.map(format_elapsed);
    Some(fit(&head, item.as_deref(), tail.as_deref(), max))
}

// ---------------------------------------------------------------------------
// Core: state machine with an explicit clock
// ---------------------------------------------------------------------------

/// The timing constants, parameterised so tests can run in milliseconds.
#[derive(Debug, Clone, Copy)]
struct Timing {
    quiet_after: Duration,
    min_redraw: Duration,
    step: Duration,
}

impl Timing {
    const PRODUCTION: Timing = Timing {
        quiet_after: QUIET_AFTER,
        min_redraw: MIN_REDRAW,
        step: ELAPSED_STEP,
    };
}

/// Draw/replace/clear logic. Every method takes `now` explicitly, so the
/// elapsed time comes from a monotonic clock the caller owns and tests drive.
struct Core {
    surface: Box<dyn Surface>,
    timing: Timing,
    view: View,
    /// When the last event arrived (any event moves the clock).
    last_event: Instant,
    /// The text on screen, `None` when no line is drawn.
    drawn: Option<String>,
    last_write: Option<Instant>,
    /// A change is waiting for the redraw interval to pass.
    dirty: bool,
    /// A write failed, or the session abandoned the worker: nothing more is
    /// ever written.
    dead: bool,
    /// Set by the session when it stops waiting for the worker.
    latch: AbandonLatch,
    /// The last width left no room for any text, so there is nothing to refresh
    /// until the next event asks again.
    no_room: bool,
}

impl Core {
    fn new(surface: Box<dyn Surface>, kind: RunKind, timing: Timing, now: Instant) -> Self {
        Core {
            surface,
            timing,
            view: View::new(Some(kind)),
            last_event: now,
            drawn: None,
            last_write: None,
            dirty: false,
            dead: false,
            latch: AbandonLatch::default(),
            no_room: false,
        }
    }

    /// Whether nothing may be written any more. Checked before every write, so
    /// a worker the session has abandoned stays mute, including in `Drop`.
    fn silenced(&mut self) -> bool {
        if !self.dead && self.latch.is_set() {
            self.dead = true;
            self.drawn = None;
            self.dirty = false;
        }
        self.dead
    }

    fn on_event(&mut self, event: &ProgressEvent, now: Instant) {
        if self.silenced() || self.view.finished {
            return;
        }
        self.view.apply(event);
        self.last_event = now;
        if self.view.finished {
            self.clear();
            return;
        }
        self.refresh(now);
    }

    fn tick(&mut self, now: Instant) {
        if self.silenced() || self.view.finished {
            return;
        }
        self.refresh(now);
    }

    /// Time until the line next needs attention, `None` when it never will
    /// without a new event (nothing drawn, finished, or dead).
    fn wake_after(&mut self, now: Instant) -> Option<Duration> {
        if self.silenced() || self.no_room || !self.view.has_line() {
            return None;
        }
        let mut wake = self.next_elapsed_change(now);
        if self.dirty {
            let due = match self.last_write {
                Some(t) => self
                    .timing
                    .min_redraw
                    .saturating_sub(now.saturating_duration_since(t)),
                None => Duration::ZERO,
            };
            wake = wake.min(due);
        }
        Some(wake.max(MIN_WAKE))
    }

    /// When the displayed elapsed text next changes: at the quiet threshold,
    /// then on every step boundary of the time since the last event.
    fn next_elapsed_change(&self, now: Instant) -> Duration {
        let quiet = now.saturating_duration_since(self.last_event);
        if quiet < self.timing.quiet_after {
            return self.timing.quiet_after - quiet;
        }
        let step = self.timing.step.as_nanos().max(1);
        let into_step = quiet.as_nanos() % step;
        let remaining = step - into_step;
        Duration::from_nanos(u64::try_from(remaining).unwrap_or(u64::MAX))
    }

    fn refresh(&mut self, now: Instant) {
        let quiet = now.saturating_duration_since(self.last_event);
        let shown = (quiet >= self.timing.quiet_after).then_some(quiet);
        let columns = self.surface.columns();
        let budget = line_budget(columns);
        self.no_room = budget == 0;
        let text = format_line(&self.view, shown, budget);
        match text {
            None => {
                self.dirty = false;
                self.clear();
            }
            Some(text) => {
                if self.drawn.as_deref() == Some(text.as_str()) {
                    self.dirty = false;
                    return;
                }
                let due = self
                    .last_write
                    .is_none_or(|t| now.saturating_duration_since(t) >= self.timing.min_redraw);
                if due {
                    self.draw(text, now);
                } else {
                    self.dirty = true;
                }
            }
        }
    }

    fn draw(&mut self, text: String, now: Instant) {
        let mut frame = String::with_capacity(CLEAR.len() + text.len());
        frame.push_str(CLEAR);
        frame.push_str(&text);
        if self.write(frame.as_bytes()) {
            self.drawn = Some(text);
            self.last_write = Some(now);
            self.dirty = false;
        }
    }

    /// Erase the line if one is drawn.
    fn clear(&mut self) {
        if self.silenced() || self.drawn.is_none() {
            return;
        }
        if self.write(CLEAR.as_bytes()) {
            self.drawn = None;
        }
    }

    /// One write; any error ends all drawing. `true` on success.
    fn write(&mut self, bytes: &[u8]) -> bool {
        if self.silenced() {
            return false;
        }
        match self.surface.write_frame(bytes) {
            Ok(()) => true,
            Err(_) => {
                self.dead = true;
                self.drawn = None;
                false
            }
        }
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        // The worker ends without `RunEnded` when the channel closes first.
        self.clear();
    }
}

// ---------------------------------------------------------------------------
// The consumer
// ---------------------------------------------------------------------------

struct TtyConsumer {
    core: Core,
}

impl ProgressConsumer for TtyConsumer {
    fn consume(&mut self, event: &ProgressEvent) {
        self.core.on_event(event, Instant::now());
    }

    fn wake_after(&mut self) -> Option<Duration> {
        self.core.wake_after(Instant::now())
    }

    fn tick(&mut self) {
        self.core.tick(Instant::now());
    }

    fn attach_abandon_latch(&mut self, latch: AbandonLatch) {
        self.core.latch = latch;
    }
}

#[cfg(test)]
mod tests;
