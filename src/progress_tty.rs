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
//!   that long on the current item; it never claims the engine is alive.
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
//! of `0` means *unknown* and uses [`FALLBACK_COLUMNS`] (60). A terminal of one
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
//! [`MIN_REDRAW`] and an unchanged line is not rewritten.
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
//! Progress is best effort and cannot change a result. A write or flush error,
//! an unavailable width and a vanished terminal degrade silently: after the
//! first write error the renderer stops drawing for good. The renderer contains
//! no `unwrap`, `expect`, indexing or unchecked arithmetic on the paths taken
//! for valid events, so it cannot reach Rust's panic hook (which would write to
//! the very terminal being drawn on).

use crate::progress::{ItemRef, ProgressEvent, RunKind, Stage, StageOutcome};
use crate::progress_session::{
    ConsumerFactory, NullConsumer, ProgressConsumer, SessionInfo, MIN_WAKE,
};
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Erase the current line and return to column 0. The only control sequence
/// the renderer writes.
pub const CLEAR: &str = "\r\x1b[2K";

/// Width assumed when the terminal's width is unknown (`ioctl` failed or
/// reported `0`).
pub const FALLBACK_COLUMNS: usize = 60;

/// How long nothing may have happened before the elapsed time is shown.
pub const QUIET_AFTER: Duration = Duration::from_secs(3);

/// Minimum time between two writes of the line (events in between are
/// coalesced into the next draw).
pub const MIN_REDRAW: Duration = Duration::from_millis(100);

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

/// The real surface: this process's stderr.
struct StderrSurface;

impl Surface for StderrSurface {
    fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        // `write_all` on the raw handle, never `eprint!` (which panics when the
        // write fails).
        let mut err = std::io::stderr().lock();
        err.write_all(bytes)?;
        err.flush()
    }

    fn columns(&mut self) -> Option<usize> {
        columns_of_fd(2)
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
    consumer_factory(Arc::new(|| Box::new(StderrSurface)))
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
    /// A write failed: nothing more is ever written.
    dead: bool,
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
        }
    }

    fn on_event(&mut self, event: &ProgressEvent, now: Instant) {
        if self.dead || self.view.finished {
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
        if self.dead || self.view.finished {
            return;
        }
        self.refresh(now);
    }

    /// Time until the line next needs attention, `None` when it never will
    /// without a new event (nothing drawn, finished, or dead).
    fn wake_after(&mut self, now: Instant) -> Option<Duration> {
        if self.dead || !self.view.has_line() {
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
        let text = format_line(&self.view, shown, line_budget(columns));
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
        if self.dead || self.drawn.is_none() {
            return;
        }
        if self.write(CLEAR.as_bytes()) {
            self.drawn = None;
        }
    }

    /// One write; any error ends all drawing. `true` on success.
    fn write(&mut self, bytes: &[u8]) -> bool {
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
}

#[cfg(test)]
mod tests;
