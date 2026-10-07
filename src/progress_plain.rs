//! The plain (bounded) progress renderer (WP-PROGRESS S5).
//!
//! The explicit opt-in sibling of [`crate::progress_tty`]: where the TTY renderer
//! keeps one transient line that it erases, this one writes **persistent ASCII
//! lines** to stderr, a number of them that depends on the stages and on elapsed
//! time and **never on how many resources a recipe has**. It exists for logs: a
//! CI job or a redirected run that wants to see that Sinter is moving. It is
//! only ever built for [`ProgressMode::Plain`](crate::progress_session::ProgressMode),
//! which only `SINTER_PROGRESS=plain` selects; by default a non-terminal run
//! prints exactly what it printed before progress existed. This is library API
//! and, like [`crate::progress`], not part of the 1.x CLI/JSON compatibility
//! promise; only the factory functions are public, everything else is private.
//!
//! # Line grammar
//!
//! Every line starts with `progress: ` (never `sinter:`, whose red token means
//! an error) and is a single ASCII line ended by `\n`, written with one `write`:
//!
//! ```text
//! progress: run: apply started
//! progress: connect: start
//! progress: connect: done (1s)
//! progress: apply: start 0/42
//! progress: apply: 5/42 (7s)
//! progress: apply: 17/42 on package:nginx, 2m10s since last progress
//! progress: apply: done 42/42 (3m41s)
//! progress: handlers: failed 0/1 (2s)
//! progress: run: apply completed (3m45s)
//! ```
//!
//! * **label**: the stage's own name (`resolve`, `connect`, `backup`,
//!   `handlers`); for the resource traversal the command (`plan`, `apply`,
//!   `audit`), exactly as the TTY renderer names them. `run` is the scope of one
//!   session (one execution, or the resolution phase of a multi-execution
//!   invocation); its two lines delimit the stages of that session, which is how
//!   the sequential scopes of an inventory run are told apart. No host, address,
//!   recipe or target label is in any line (none is in any event).
//! * **`N/M`** is the number of items that reached a terminal disposition out of
//!   the number that exist, when the stage has an honest total (`connect` has
//!   none and shows no counter). It is **not** a percentage and there is no ETA.
//! * **`(T)`** on a milestone or a stage end is the time since the stage started;
//!   on the `run` end line, since the run started. Both come from the renderer's
//!   own monotonic clock, never from an event.
//! * **`on kind:id`** names the item that was started last, from the event; `id`
//!   is a recipe literal shown the way every report shows it.
//! * **`T since last progress`** is the time since the last event of the stage
//!   (its start or an item start). It says Sinter has been waiting that long; it
//!   never claims the engine is alive.
//! * An outcome other than success is a word on the stage end line (`failed`,
//!   `indeterminate`) and on the `run` end line. The renderer never prints a
//!   failure message of its own: the `sinter:` line or the report is the only
//!   place one appears. Success is never inferred from the counter.
//!
//! # Bounded by construction
//!
//! Per stage and execution:
//!
//! * a start line and an end line: **2**;
//! * count milestones: **at most 10**, one when `done` first reaches
//!   `ceil(k * total / 10)` for some `k = 1..=10` (one line even when a single
//!   step crosses several thresholds; with `total <= 10` that is at most one line
//!   per item and still at most 10). This is a line-cadence rule, not a claim
//!   that N/M is a share of the work;
//! * heartbeats: a line when nothing at all was written for the current
//!   interval, `30 s` first, doubling after every heartbeat (`60`, `120`, `240`)
//!   up to a cap of `300 s`. Any other line (start, milestone, end) resets the
//!   interval. A stuck item therefore costs `log2` heartbeats up to the cap and
//!   one per `300 s` after it, and **silence never lasts longer than the cap**
//!   (below the idle-output limits of hosted CI systems, which are not verified
//!   here). A long unbroken stall (up to the 24 h command timeout) is the only
//!   thing that grows the output, linearly in time at the cap, never in items.
//!
//! Plus the `run` start and end lines, **2** per session. The bound is asserted
//! by a test that feeds 10 000 resources and a simulated 24 h wait.
//!
//! The heartbeat interval resets on a *line*, not on every item boundary: if it
//! reset on each item, a run of quick items between two milestones would print a
//! heartbeat every 30 s and the line count would again depend on the run.
//!
//! # Safety of the displayed text
//!
//! The only dynamic text is an item id (and fixed vocabulary). It is treated as
//! untrusted: every character outside printable ASCII becomes `?` (so a newline
//! in an id cannot start a second line, nor an escape sequence reach a log), and
//! an id longer than [`MAX_ID_CHARS`] is cut with `...`. The underlying event is
//! not modified. No escape sequence, carriage return or colour is ever written.
//!
//! # Secrets (owner decision OQ-5)
//!
//! When [`SessionInfo::references_secrets`] is set the factory builds the
//! [`NullConsumer`], exactly as the TTY one does: no surface is created, no
//! descriptor is opened and no byte is written. (Persistent lines would not
//! corrupt a prompt the way a transient line does, but the owner policy is one
//! rule for both renderers; relaxing it for plain progress is a separate
//! decision.)
//!
//! # A stalled stderr and a panic
//!
//! The same contract as the TTY renderer, and the same private descriptor
//! ([`crate::progress_tty`], "A stalled terminal"): the surface is a `dup` of
//! stderr owned by the worker, never [`std::io::stderr`], never non-blocking, and
//! the renderer writes nothing once the session sets the [`AbandonLatch`] (it
//! abandons the worker, or the run panics). Unlike the TTY renderer there is
//! nothing to erase at the end, so a worker that is dropped, abandoned or
//! disconnected writes no final line. Progress is best effort: after the first
//! write error nothing more is written, and no path that valid events take
//! contains `unwrap`, `expect`, indexing or unchecked arithmetic.

use crate::progress::{ItemRef, ProgressEvent, RunKind, RunOutcome, Stage, StageOutcome};
use crate::progress_session::{
    AbandonLatch, ConsumerFactory, NullConsumer, ProgressConsumer, SessionInfo, MIN_WAKE,
};
use crate::progress_tty::{
    format_elapsed, sanitize_display, stderr_surface, Surface, SurfaceFactory,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The start of every line. Not `sinter:` (see the module documentation).
pub(crate) const PREFIX: &str = "progress: ";

/// How long nothing may have been written before the first heartbeat.
pub(crate) const HEARTBEAT_BASE: Duration = Duration::from_secs(30);

/// The longest the heartbeat interval grows to, and so the longest silence.
pub(crate) const HEARTBEAT_CAP: Duration = Duration::from_secs(300);

/// How many count milestones a stage may print at most.
pub(crate) const MILESTONES: u32 = 10;

/// The longest item id shown; a longer one is cut and ends in `...`.
pub const MAX_ID_CHARS: usize = 64;

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

/// The production consumer factory: persistent lines on stderr.
pub fn stderr_plain_consumer_factory() -> ConsumerFactory {
    plain_consumer_factory(Arc::new(stderr_surface))
}

/// A consumer factory that writes lines to the given surface (its width is never
/// asked). A session that references secrets gets the [`NullConsumer`] and no
/// surface is created.
pub fn plain_consumer_factory(surface: SurfaceFactory) -> ConsumerFactory {
    factory_with_timing(surface, Timing::PRODUCTION)
}

fn factory_with_timing(surface: SurfaceFactory, timing: Timing) -> ConsumerFactory {
    Arc::new(move |info: &SessionInfo| -> Box<dyn ProgressConsumer> {
        if info.references_secrets {
            // OQ-5: one rule for both renderers.
            return Box::new(NullConsumer);
        }
        Box::new(PlainConsumer {
            core: Core::new(surface(), info.kind, timing),
        })
    })
}

// ---------------------------------------------------------------------------
// Pure formatting
// ---------------------------------------------------------------------------

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

fn command_label(command: Option<RunKind>) -> &'static str {
    match command {
        Some(RunKind::Plan) => "plan",
        Some(RunKind::Apply) => "apply",
        Some(RunKind::Audit) => "audit",
        None => "run",
    }
}

fn stage_word(outcome: StageOutcome) -> &'static str {
    match outcome {
        StageOutcome::Completed => "done",
        StageOutcome::Failed => "failed",
        StageOutcome::Indeterminate => "indeterminate",
    }
}

fn run_word(outcome: RunOutcome) -> &'static str {
    match outcome {
        RunOutcome::Completed => "completed",
        RunOutcome::Failed => "failed",
        RunOutcome::Indeterminate => "indeterminate",
    }
}

/// `kind:id` with the id reduced to printable ASCII and bounded.
fn item_text(item: &ItemRef) -> String {
    // One character of look-ahead is enough to know whether the id was cut.
    let shown = sanitize_display(&item.id, MAX_ID_CHARS.saturating_add(1));
    let id = if shown.chars().count() > MAX_ID_CHARS {
        let kept: String = shown.chars().take(MAX_ID_CHARS.saturating_sub(3)).collect();
        format!("{kept}...")
    } else {
        shown
    };
    format!("{}:{}", item.kind.label(), id)
}

/// The count at which milestone `k` (1-based) of a stage of `total` items is
/// reached: `ceil(k * total / 10)`.
fn milestone_threshold(k: u32, total: u32) -> u64 {
    (u64::from(k) * u64::from(total)).div_ceil(u64::from(MILESTONES))
}

// ---------------------------------------------------------------------------
// Core: state machine with an explicit clock
// ---------------------------------------------------------------------------

/// The timing constants, parameterised so tests can run in milliseconds.
#[derive(Debug, Clone, Copy)]
struct Timing {
    base: Duration,
    cap: Duration,
}

impl Timing {
    const PRODUCTION: Timing = Timing {
        base: HEARTBEAT_BASE,
        cap: HEARTBEAT_CAP,
    };
}

/// The stage being traversed, as far as the renderer needs to know.
#[derive(Debug)]
struct Active {
    stage: Stage,
    started: Instant,
    total: Option<u32>,
    done: u32,
    current: Option<ItemRef>,
    /// The last event of this stage (its start or an item start).
    last_progress: Instant,
    /// The next milestone (1-based) not yet reached; above [`MILESTONES`] when
    /// all were.
    next_milestone: u32,
}

/// Decides which lines exist; every method takes `now` explicitly, so all times
/// come from a clock the caller owns and tests drive.
struct Core {
    surface: Box<dyn Surface>,
    timing: Timing,
    command: Option<RunKind>,
    run_started: Option<Instant>,
    active: Option<Active>,
    /// When anything was last written (the heartbeat's reference point).
    last_line: Option<Instant>,
    /// How long a silence may last now: the base after any non-heartbeat line,
    /// doubling after each heartbeat up to the cap.
    interval: Duration,
    finished: bool,
    /// A write failed, or the session muted the worker: nothing more is written.
    dead: bool,
    latch: AbandonLatch,
}

impl Core {
    fn new(surface: Box<dyn Surface>, kind: RunKind, timing: Timing) -> Self {
        Core {
            surface,
            timing,
            command: Some(kind),
            run_started: None,
            active: None,
            last_line: None,
            interval: timing.base,
            finished: false,
            dead: false,
            latch: AbandonLatch::default(),
        }
    }

    /// Whether nothing may be written any more. Checked before every write and
    /// every decision, so a worker the session abandoned (or the run's panic
    /// detached) stays mute.
    fn silenced(&mut self) -> bool {
        if !self.dead && self.latch.is_set() {
            self.dead = true;
            self.active = None;
        }
        self.dead
    }

    fn on_event(&mut self, event: &ProgressEvent, now: Instant) {
        if self.silenced() || self.finished {
            return;
        }
        match event {
            ProgressEvent::RunStarted { command } => {
                self.command = Some(*command);
                self.run_started = Some(now);
                let text = format!("run: {} started", command_label(Some(*command)));
                self.line(&text, now, true);
            }
            ProgressEvent::StageStarted { stage, total } => {
                self.active = Some(Active {
                    stage: *stage,
                    started: now,
                    total: *total,
                    done: 0,
                    current: None,
                    last_progress: now,
                    next_milestone: 1,
                });
                let label = stage_label(*stage, self.command);
                let text = match total {
                    Some(total) => format!("{label}: start 0/{total}"),
                    None => format!("{label}: start"),
                };
                self.line(&text, now, true);
            }
            ProgressEvent::Progress {
                stage,
                done,
                total,
                current,
            } => self.on_progress(*stage, *done, *total, current.as_ref(), now),
            ProgressEvent::StageEnded {
                stage,
                outcome,
                done,
            } => {
                let label = stage_label(*stage, self.command);
                let (total, elapsed) = match &self.active {
                    Some(a) if a.stage == *stage => {
                        (a.total, Some(now.saturating_duration_since(a.started)))
                    }
                    _ => (None, None),
                };
                self.active = None;
                let mut text = format!("{label}: {}", stage_word(*outcome));
                if let Some(total) = total {
                    text.push_str(&format!(" {done}/{total}"));
                }
                if let Some(elapsed) = elapsed {
                    text.push_str(&format!(" ({})", format_elapsed(elapsed)));
                }
                self.line(&text, now, true);
            }
            ProgressEvent::RunEnded { outcome } => {
                self.active = None;
                self.finished = true;
                let mut text = format!(
                    "run: {} {}",
                    command_label(self.command),
                    run_word(*outcome)
                );
                if let Some(start) = self.run_started {
                    text.push_str(&format!(
                        " ({})",
                        format_elapsed(now.saturating_duration_since(start))
                    ));
                }
                self.line(&text, now, true);
            }
        }
    }

    fn on_progress(
        &mut self,
        stage: Stage,
        done: u32,
        total: Option<u32>,
        current: Option<&ItemRef>,
        now: Instant,
    ) {
        // A stream that skipped `StageStarted` is tolerated, not trusted.
        let active = match &mut self.active {
            Some(a) if a.stage == stage => a,
            slot => slot.insert(Active {
                stage,
                started: now,
                total,
                done,
                current: None,
                last_progress: now,
                next_milestone: 1,
            }),
        };
        active.done = done;
        if total.is_some() {
            active.total = total;
        }
        active.current = current.cloned();
        active.last_progress = now;
        let Some(total) = active.total.filter(|t| *t > 0) else {
            return;
        };
        let mut crossed = false;
        while active.next_milestone <= MILESTONES
            && u64::from(done) >= milestone_threshold(active.next_milestone, total)
        {
            active.next_milestone += 1;
            crossed = true;
        }
        if crossed {
            let label = stage_label(stage, self.command);
            let text = format!(
                "{label}: {done}/{total} ({})",
                format_elapsed(now.saturating_duration_since(active.started))
            );
            self.line(&text, now, true);
        }
    }

    /// Time until a heartbeat is due, `None` when none can be (no active stage,
    /// finished, or muted). Never below [`MIN_WAKE`].
    fn wake_after(&mut self, now: Instant) -> Option<Duration> {
        if self.silenced() || self.finished {
            return None;
        }
        let active = self.active.as_ref()?;
        let since = now.saturating_duration_since(self.last_line.unwrap_or(active.started));
        Some(self.interval.saturating_sub(since).max(MIN_WAKE))
    }

    /// A wait asked for by [`wake_after`](Self::wake_after) expired: print a
    /// heartbeat if the silence really reached the interval.
    fn tick(&mut self, now: Instant) {
        if self.silenced() || self.finished {
            return;
        }
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let since = now.saturating_duration_since(self.last_line.unwrap_or(active.started));
        if since < self.interval {
            return;
        }
        let mut text = String::from(stage_label(active.stage, self.command));
        text.push(':');
        let mut has_what = false;
        if let Some(total) = active.total {
            text.push_str(&format!(" {}/{}", active.done, total));
            has_what = true;
        }
        if let Some(item) = &active.current {
            text.push_str(&format!(" on {}", item_text(item)));
            has_what = true;
        }
        if has_what {
            text.push(',');
        }
        text.push_str(&format!(
            " {} since last progress",
            format_elapsed(now.saturating_duration_since(active.last_progress))
        ));
        self.line(&text, now, false);
    }

    /// Write one line. A start, milestone or end line (`resets`) puts the
    /// heartbeat interval back to its base; a heartbeat doubles it.
    fn line(&mut self, text: &str, now: Instant, resets: bool) {
        let mut line = String::with_capacity(PREFIX.len() + text.len() + 1);
        line.push_str(PREFIX);
        line.push_str(text);
        line.push('\n');
        if self.write(line.as_bytes()) {
            self.last_line = Some(now);
            self.interval = if resets {
                self.timing.base
            } else {
                self.interval.saturating_mul(2).min(self.timing.cap)
            };
        }
    }

    /// One write; any error ends all output. `true` on success.
    fn write(&mut self, bytes: &[u8]) -> bool {
        if self.silenced() {
            return false;
        }
        match self.surface.write_frame(bytes) {
            Ok(()) => true,
            Err(_) => {
                self.dead = true;
                self.active = None;
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The consumer
// ---------------------------------------------------------------------------

struct PlainConsumer {
    core: Core,
}

impl ProgressConsumer for PlainConsumer {
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
