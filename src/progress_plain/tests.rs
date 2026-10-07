//! Unit tests of the plain renderer: the line grammar, the bound, the heartbeat
//! schedule on a driven clock, sanitization, muting, and the worker with real
//! (millisecond) timing.

use super::*;
use crate::progress::{ItemKind, RunOutcome, StageOutcome};
use crate::progress_session::{ProgressMode, ProgressOptions, Teardown};
use crate::progress_tty::tests::{engine_stream, CANARIES};
use std::sync::mpsc;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// A surface that records every write separately; failure is scripted.
#[derive(Clone, Default)]
struct Mem {
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
    fail_after: Arc<Mutex<Option<usize>>>,
    attempts: Arc<Mutex<usize>>,
}

impl Mem {
    fn fail_after(&self, writes: usize) {
        *self.fail_after.lock().unwrap() = Some(writes);
    }

    fn attempts(&self) -> usize {
        *self.attempts.lock().unwrap()
    }

    /// One entry per `write`, each of which must be exactly one line.
    fn lines(&self) -> Vec<String> {
        self.writes
            .lock()
            .unwrap()
            .iter()
            .map(|w| {
                let text = String::from_utf8(w.clone()).unwrap();
                assert!(text.ends_with('\n'), "a write that is not a line: {text:?}");
                assert_eq!(
                    text.matches('\n').count(),
                    1,
                    "a write holds more than one line: {text:?}"
                );
                text.trim_end_matches('\n').to_string()
            })
            .collect()
    }

    fn count(&self) -> usize {
        self.writes.lock().unwrap().len()
    }

    fn factory(&self) -> SurfaceFactory {
        let m = self.clone();
        Arc::new(move || Box::new(m.clone()))
    }

    fn core(&self, kind: RunKind) -> Core {
        Core::new(Box::new(self.clone()), kind, Timing::PRODUCTION)
    }
}

impl Surface for Mem {
    fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        *self.attempts.lock().unwrap() += 1;
        let mut writes = self.writes.lock().unwrap();
        if let Some(n) = *self.fail_after.lock().unwrap() {
            if writes.len() >= n {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
        }
        writes.push(bytes.to_vec());
        Ok(())
    }

    fn columns(&mut self) -> Option<usize> {
        panic!("the plain renderer never asks for a width");
    }
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn item(kind: ItemKind, id: &str) -> Option<ItemRef> {
    Some(ItemRef {
        kind,
        id: id.to_string(),
    })
}

fn run_started(kind: RunKind) -> ProgressEvent {
    ProgressEvent::RunStarted { command: kind }
}

fn stage_started(stage: Stage, total: Option<u32>) -> ProgressEvent {
    ProgressEvent::StageStarted { stage, total }
}

fn item_started(stage: Stage, done: u32, total: Option<u32>, id: &str) -> ProgressEvent {
    ProgressEvent::Progress {
        stage,
        done,
        total,
        current: item(ItemKind::File, id),
    }
}

fn stage_ended(stage: Stage, outcome: StageOutcome, done: u32) -> ProgressEvent {
    ProgressEvent::StageEnded {
        stage,
        outcome,
        done,
    }
}

fn run_ended(outcome: RunOutcome) -> ProgressEvent {
    ProgressEvent::RunEnded { outcome }
}

// ---------------------------------------------------------------------------
// Grammar
// ---------------------------------------------------------------------------

#[test]
fn a_whole_apply_run_reads_as_documented() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    core.on_event(&run_started(RunKind::Apply), t0);
    core.on_event(&stage_started(Stage::Connect, None), t0);
    core.on_event(
        &stage_ended(Stage::Connect, StageOutcome::Completed, 0),
        t0 + secs(1),
    );
    core.on_event(&stage_started(Stage::Backup, Some(2)), t0 + secs(1));
    core.on_event(
        &ProgressEvent::Progress {
            stage: Stage::Backup,
            done: 1,
            total: Some(2),
            current: None,
        },
        t0 + secs(2),
    );
    core.on_event(
        &stage_ended(Stage::Backup, StageOutcome::Completed, 2),
        t0 + secs(3),
    );
    core.on_event(&stage_started(Stage::Resources, Some(2)), t0 + secs(3));
    core.on_event(
        &item_started(Stage::Resources, 0, Some(2), "a"),
        t0 + secs(3),
    );
    core.on_event(
        &item_started(Stage::Resources, 1, Some(2), "b"),
        t0 + secs(5),
    );
    core.on_event(
        &stage_ended(Stage::Resources, StageOutcome::Completed, 2),
        t0 + secs(9),
    );
    core.on_event(&stage_started(Stage::Handlers, Some(1)), t0 + secs(9));
    core.on_event(
        &ProgressEvent::Progress {
            stage: Stage::Handlers,
            done: 0,
            total: Some(1),
            current: item(ItemKind::Handler, "reload"),
        },
        t0 + secs(9),
    );
    core.on_event(
        &stage_ended(Stage::Handlers, StageOutcome::Completed, 1),
        t0 + secs(10),
    );
    core.on_event(&run_ended(RunOutcome::Completed), t0 + secs(11));
    assert_eq!(
        mem.lines(),
        [
            "progress: run: apply started",
            "progress: connect: start",
            "progress: connect: done (1s)",
            "progress: backup: start 0/2",
            "progress: backup: 1/2 (1s)",
            "progress: backup: done 2/2 (2s)",
            "progress: apply: start 0/2",
            "progress: apply: 1/2 (2s)",
            "progress: apply: done 2/2 (6s)",
            "progress: handlers: start 0/1",
            "progress: handlers: done 1/1 (1s)",
            "progress: run: apply completed (11s)",
        ]
    );
}

#[test]
fn the_resource_stage_is_named_after_the_command() {
    for (kind, word) in [
        (RunKind::Plan, "plan"),
        (RunKind::Apply, "apply"),
        (RunKind::Audit, "audit"),
    ] {
        let mem = Mem::default();
        let mut core = mem.core(kind);
        let t0 = Instant::now();
        core.on_event(&run_started(kind), t0);
        core.on_event(&stage_started(Stage::Resources, Some(1)), t0);
        assert_eq!(
            mem.lines(),
            [
                format!("progress: run: {word} started"),
                format!("progress: {word}: start 0/1"),
            ]
        );
    }
}

#[test]
fn a_failed_or_indeterminate_stage_and_run_say_so_and_nothing_else() {
    for (stage_outcome, run_outcome, stage_w, run_w) in [
        (StageOutcome::Failed, RunOutcome::Failed, "failed", "failed"),
        (
            StageOutcome::Indeterminate,
            RunOutcome::Indeterminate,
            "indeterminate",
            "indeterminate",
        ),
    ] {
        let mem = Mem::default();
        let mut core = mem.core(RunKind::Apply);
        let t0 = Instant::now();
        core.on_event(&run_started(RunKind::Apply), t0);
        core.on_event(&stage_started(Stage::Resources, Some(5)), t0);
        core.on_event(&item_started(Stage::Resources, 0, Some(5), "a"), t0);
        core.on_event(
            &stage_ended(Stage::Resources, stage_outcome, 5),
            t0 + secs(2),
        );
        core.on_event(&run_ended(run_outcome), t0 + secs(2));
        let lines = mem.lines();
        // The counter is whatever `done` the stage reports; the outcome word,
        // not `done == total`, says what happened.
        assert_eq!(lines[2], format!("progress: apply: {stage_w} 5/5 (2s)"));
        assert_eq!(lines[3], format!("progress: run: apply {run_w} (2s)"));
        for l in &lines {
            assert!(!l.contains("error") && !l.contains("sinter:"), "{l}");
        }
    }
}

#[test]
fn a_connection_failure_before_any_resource_reads_cleanly() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Plan);
    let t0 = Instant::now();
    core.on_event(&run_started(RunKind::Plan), t0);
    core.on_event(&stage_started(Stage::Connect, None), t0);
    core.on_event(
        &stage_ended(Stage::Connect, StageOutcome::Failed, 0),
        t0 + ms(40),
    );
    core.on_event(&run_ended(RunOutcome::Failed), t0 + ms(41));
    assert_eq!(
        mem.lines(),
        [
            "progress: run: plan started",
            "progress: connect: start",
            "progress: connect: failed (0s)",
            "progress: run: plan failed (0s)",
        ]
    );
}

#[test]
fn a_resolve_stage_counts_hosts_and_shows_no_item() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Plan);
    let t0 = Instant::now();
    core.on_event(&run_started(RunKind::Plan), t0);
    core.on_event(&stage_started(Stage::Resolve, Some(2)), t0);
    core.on_event(
        &ProgressEvent::Progress {
            stage: Stage::Resolve,
            done: 1,
            total: Some(2),
            current: None,
        },
        t0 + secs(1),
    );
    core.on_event(
        &stage_ended(Stage::Resolve, StageOutcome::Completed, 2),
        t0 + secs(2),
    );
    assert_eq!(
        mem.lines()[1..],
        [
            "progress: resolve: start 0/2",
            "progress: resolve: 1/2 (1s)",
            "progress: resolve: done 2/2 (2s)",
        ]
    );
}

#[test]
fn no_line_after_the_run_ended() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    core.on_event(&run_started(RunKind::Apply), t0);
    core.on_event(&run_ended(RunOutcome::Completed), t0);
    let n = mem.count();
    core.on_event(&stage_started(Stage::Connect, None), t0 + secs(1));
    core.on_event(&run_ended(RunOutcome::Failed), t0 + secs(1));
    core.tick(t0 + secs(1000));
    assert_eq!(core.wake_after(t0 + secs(1000)), None);
    assert_eq!(mem.count(), n);
}

// ---------------------------------------------------------------------------
// Milestones
// ---------------------------------------------------------------------------

/// Feed a stage of `total` items, one second apart, and return its lines.
fn run_stage(total: u32) -> Vec<String> {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    core.on_event(&stage_started(Stage::Resources, Some(total)), t0);
    for i in 0..total {
        core.on_event(
            &item_started(Stage::Resources, i, Some(total), &format!("r{i}")),
            t0 + secs(u64::from(i)),
        );
    }
    core.on_event(
        &stage_ended(Stage::Resources, StageOutcome::Completed, total),
        t0 + secs(u64::from(total)),
    );
    mem.lines()
}

#[test]
fn a_hundred_items_print_nine_milestones_between_start_and_end() {
    let lines = run_stage(100);
    assert_eq!(lines.len(), 11, "{lines:?}");
    assert_eq!(lines[0], "progress: apply: start 0/100");
    for (n, line) in lines[1..10].iter().enumerate() {
        let done = (n + 1) * 10;
        assert_eq!(
            *line,
            format!(
                "progress: apply: {done}/100 ({})",
                format_elapsed(secs(done as u64))
            )
        );
    }
    assert_eq!(lines[10], "progress: apply: done 100/100 (1m40s)");
}

#[test]
fn few_items_print_at_most_one_line_each_and_never_more_than_ten() {
    // total 3: thresholds ceil(k*3/10) = 1,1,1,2,2,2,3,... so items 1 and 2.
    assert_eq!(
        run_stage(3),
        [
            "progress: apply: start 0/3",
            "progress: apply: 1/3 (1s)",
            "progress: apply: 2/3 (2s)",
            "progress: apply: done 3/3 (3s)",
        ]
    );
    for total in 1..=10u32 {
        let lines = run_stage(total);
        let milestones = lines.len() - 2;
        assert!(milestones <= 10, "total {total}: {lines:?}");
        assert!(
            milestones <= total as usize,
            "total {total}: at most one per item: {lines:?}"
        );
    }
}

#[test]
fn a_step_that_crosses_several_thresholds_prints_one_line() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    core.on_event(&stage_started(Stage::Resources, Some(100)), t0);
    core.on_event(&item_started(Stage::Resources, 0, Some(100), "a"), t0);
    core.on_event(
        &item_started(Stage::Resources, 55, Some(100), "b"),
        t0 + secs(1),
    );
    core.on_event(
        &item_started(Stage::Resources, 59, Some(100), "c"),
        t0 + secs(2),
    );
    core.on_event(
        &item_started(Stage::Resources, 60, Some(100), "d"),
        t0 + secs(3),
    );
    assert_eq!(
        mem.lines(),
        [
            "progress: apply: start 0/100",
            "progress: apply: 55/100 (1s)",
            "progress: apply: 60/100 (3s)",
        ]
    );
}

#[test]
fn no_total_or_an_empty_stage_has_no_milestones() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    core.on_event(&stage_started(Stage::Connect, None), t0);
    core.on_event(&item_started(Stage::Connect, 5, None, "x"), t0 + secs(1));
    core.on_event(
        &stage_ended(Stage::Connect, StageOutcome::Completed, 0),
        t0 + secs(2),
    );
    core.on_event(&stage_started(Stage::Resources, Some(0)), t0 + secs(2));
    core.on_event(
        &stage_ended(Stage::Resources, StageOutcome::Completed, 0),
        t0 + secs(3),
    );
    assert_eq!(
        mem.lines(),
        [
            "progress: connect: start",
            "progress: connect: done (2s)",
            "progress: apply: start 0/0",
            "progress: apply: done 0/0 (1s)",
        ]
    );
}

#[test]
fn milestones_restart_with_every_stage() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    for stage in [Stage::Backup, Stage::Resources] {
        core.on_event(&stage_started(stage, Some(10)), t0);
        core.on_event(&item_started(stage, 5, Some(10), "x"), t0 + secs(1));
        core.on_event(
            &stage_ended(stage, StageOutcome::Completed, 10),
            t0 + secs(2),
        );
    }
    let lines = mem.lines();
    assert_eq!(lines.len(), 6, "{lines:?}");
    assert!(lines[1].starts_with("progress: backup: 5/10"));
    assert!(lines[4].starts_with("progress: apply: 5/10"));
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

/// Run the worker's loop on the driven clock until `until`: wait as long as the
/// core asks, then tick.
fn pump(core: &mut Core, now: &mut Instant, until: Instant) {
    while let Some(wait) = core.wake_after(*now) {
        if *now + wait > until {
            *now = until;
            return;
        }
        *now += wait;
        core.tick(*now);
    }
    *now = until;
}

#[test]
fn the_heartbeat_doubles_up_to_the_cap_and_names_the_item() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    let mut now = t0;
    core.on_event(&stage_started(Stage::Resources, Some(42)), now);
    core.on_event(&item_started(Stage::Resources, 17, Some(42), "nginx"), now);
    // First wake-up: the base interval after the last line.
    assert_eq!(core.wake_after(now), Some(secs(30)));
    pump(&mut core, &mut now, t0 + secs(1100));
    let lines = mem.lines();
    // Lines: start (t=0) and milestones (17/42 crosses 4), then heartbeats at
    // 30, 90, 210, 450, 750, 1050.
    let beats: Vec<&String> = lines.iter().filter(|l| l.contains("since last")).collect();
    assert_eq!(beats.len(), 6, "{lines:?}");
    let want = [30, 90, 210, 450, 750, 1050];
    for (b, secs_since) in beats.iter().zip(want) {
        assert_eq!(
            **b,
            format!(
                "progress: apply: 17/42 on file:nginx, {} since last progress",
                format_elapsed(secs(secs_since))
            )
        );
    }
}

#[test]
fn the_heartbeat_interval_is_30_60_120_240_then_300() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let mut now = Instant::now();
    core.on_event(&stage_started(Stage::Connect, None), now);
    let mut gaps = Vec::new();
    for _ in 0..8 {
        let wait = core.wake_after(now).unwrap();
        gaps.push(wait.as_secs());
        now += wait;
        core.tick(now);
    }
    assert_eq!(gaps, [30, 60, 120, 240, 300, 300, 300, 300]);
}

#[test]
fn a_tick_before_the_interval_is_over_prints_nothing() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    core.on_event(&stage_started(Stage::Connect, None), t0);
    let n = mem.count();
    core.tick(t0 + secs(29));
    assert_eq!(mem.count(), n);
    core.tick(t0 + secs(30));
    assert_eq!(mem.count(), n + 1);
    // The interval is now 60 s from that line.
    core.tick(t0 + secs(89));
    assert_eq!(mem.count(), n + 1);
}

#[test]
fn a_milestone_resets_the_interval_but_a_plain_item_start_does_not() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    core.on_event(&stage_started(Stage::Resources, Some(100)), t0);
    // Two heartbeats: the interval is now 120 s.
    core.tick(t0 + secs(30));
    core.tick(t0 + secs(90));
    assert_eq!(core.wake_after(t0 + secs(90)), Some(secs(120)));
    // An item start that crosses no milestone writes nothing and resets nothing.
    core.on_event(
        &item_started(Stage::Resources, 3, Some(100), "a"),
        t0 + secs(100),
    );
    assert_eq!(core.wake_after(t0 + secs(100)), Some(secs(110)));
    // A milestone is a line: the interval is back to the base, from that line.
    core.on_event(
        &item_started(Stage::Resources, 10, Some(100), "b"),
        t0 + secs(101),
    );
    assert_eq!(core.wake_after(t0 + secs(101)), Some(secs(30)));
    assert_eq!(core.wake_after(t0 + secs(120)), Some(secs(11)));
}

#[test]
fn heartbeat_wording_depends_on_what_is_known() {
    let beat = |setup: &dyn Fn(&mut Core, Instant)| {
        let mem = Mem::default();
        let mut core = mem.core(RunKind::Apply);
        let t0 = Instant::now();
        setup(&mut core, t0);
        let n = mem.count();
        core.tick(t0 + secs(135));
        let lines = mem.lines();
        assert_eq!(lines.len(), n + 1, "{lines:?}");
        lines[n].clone()
    };
    // No total, no item.
    assert_eq!(
        beat(&|c, t| c.on_event(&stage_started(Stage::Connect, None), t)),
        "progress: connect: 2m15s since last progress"
    );
    // A total and no item yet.
    assert_eq!(
        beat(&|c, t| c.on_event(&stage_started(Stage::Backup, Some(2)), t)),
        "progress: backup: 0/2, 2m15s since last progress"
    );
    // A total and an item; the time is since the last event, not the stage.
    assert_eq!(
        beat(&|c, t| {
            c.on_event(&stage_started(Stage::Resources, Some(9)), t);
            c.on_event(
                &item_started(Stage::Resources, 4, Some(9), "x"),
                t + secs(100),
            );
        }),
        "progress: apply: 4/9 on file:x, 35s since last progress"
    );
}

#[test]
fn no_wakeup_is_asked_for_without_an_active_stage() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    assert_eq!(core.wake_after(t0), None, "nothing started");
    core.on_event(&run_started(RunKind::Apply), t0);
    assert_eq!(core.wake_after(t0), None, "no stage yet");
    core.on_event(&stage_started(Stage::Connect, None), t0);
    assert!(core.wake_after(t0).is_some());
    core.on_event(&stage_ended(Stage::Connect, StageOutcome::Completed, 0), t0);
    assert_eq!(core.wake_after(t0), None, "between stages");
    core.tick(t0 + secs(10_000));
    assert_eq!(mem.count(), 3, "a tick between stages writes nothing");
}

// ---------------------------------------------------------------------------
// The bound
// ---------------------------------------------------------------------------

#[test]
fn ten_thousand_resources_and_a_day_long_wait_stay_bounded() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    let mut now = t0;
    core.on_event(&run_started(RunKind::Apply), now);
    core.on_event(&stage_started(Stage::Connect, None), now);
    core.on_event(
        &stage_ended(Stage::Connect, StageOutcome::Completed, 0),
        now,
    );
    let total = 10_000u32;
    core.on_event(&stage_started(Stage::Resources, Some(total)), now);
    for i in 0..total {
        now += ms(1);
        core.on_event(
            &item_started(Stage::Resources, i, Some(total), &format!("resource-{i}")),
            now,
        );
    }
    // 10 000 items in 10 s of run time never reach a heartbeat; the lines are the
    // stage's own: start and nine milestones.
    let busy = mem.count();
    assert_eq!(busy, 3 + 1 + 9, "{:?}", mem.lines());

    // Now the last item hangs for 24 hours.
    let stall_start = now;
    let mut previous_line_count = mem.count();
    let mut last_write = now;
    let mut longest_silence = Duration::ZERO;
    let end = stall_start + secs(24 * 3600);
    while let Some(wait) = core.wake_after(now) {
        if now + wait > end {
            break;
        }
        now += wait;
        core.tick(now);
        if mem.count() > previous_line_count {
            longest_silence = longest_silence.max(now.saturating_duration_since(last_write));
            last_write = now;
            previous_line_count = mem.count();
        }
    }
    let heartbeats = mem.count() - busy;
    // 30, 60, 120, 240 (reached at 450 s), then one per 300 s.
    let after_four = (24 * 3600 - 450) / 300;
    assert!(
        heartbeats <= 4 + 1 + after_four,
        "{heartbeats} heartbeats in 24 h"
    );
    assert!(
        heartbeats >= 4 + after_four - 1,
        "the schedule must actually beat: {heartbeats}"
    );
    assert!(
        longest_silence <= HEARTBEAT_CAP,
        "silence lasted {longest_silence:?}, longer than the cap"
    );

    // The stage ends and the run ends: still bounded, and the whole output is a
    // function of stages and time, not of the 10 000 resources.
    now = end;
    core.on_event(
        &stage_ended(Stage::Resources, StageOutcome::Completed, total),
        now,
    );
    core.on_event(&run_ended(RunOutcome::Completed), now);
    let stage_lines = mem
        .lines()
        .iter()
        .filter(|l| l.starts_with("progress: apply:") && !l.contains("since last progress"))
        .count();
    assert!(
        stage_lines <= 12,
        "{stage_lines} non-heartbeat lines in a stage"
    );
    // Every item id that was shown is bounded and the lines are short.
    assert!(mem.lines().iter().all(|l| l.len() < 120));
}

#[test]
fn a_stage_never_prints_more_than_twelve_lines_without_a_stall() {
    for total in [0u32, 1, 2, 9, 10, 11, 99, 100, 101, 1000, 100_000] {
        let lines = run_stage_fast(total);
        assert!(lines <= 12, "total {total}: {lines} lines");
    }
}

/// Like `run_stage` but cheap for very large totals; returns the line count.
fn run_stage_fast(total: u32) -> usize {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    core.on_event(&stage_started(Stage::Resources, Some(total)), t0);
    for i in 0..total {
        core.on_event(&item_started(Stage::Resources, i, Some(total), "r"), t0);
    }
    core.on_event(
        &stage_ended(Stage::Resources, StageOutcome::Completed, total),
        t0,
    );
    mem.count()
}

// ---------------------------------------------------------------------------
// Text safety
// ---------------------------------------------------------------------------

#[test]
fn control_bytes_and_non_ascii_in_an_id_never_reach_the_output() {
    let nasty = "a\x1b[2Jb\nc\rd\u{9b}e\u{7f}f\tg\u{7}h\u{e9}\u{1F600}i\0j";
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    core.on_event(&stage_started(Stage::Resources, Some(5)), t0);
    core.on_event(&item_started(Stage::Resources, 2, Some(5), nasty), t0);
    core.tick(t0 + secs(30));
    let lines = mem.lines();
    let heartbeat = lines.last().unwrap();
    assert!(
        heartbeat.contains("file:a?[2Jb?c?d?e?f?g?h??i?j"),
        "{heartbeat}"
    );
    for write in mem.writes.lock().unwrap().iter() {
        for &b in write.iter() {
            assert!(
                (0x20..=0x7e).contains(&b) || b == b'\n',
                "byte {b:#x} reached the log"
            );
        }
        assert_eq!(
            write.iter().filter(|b| **b == b'\n').count(),
            1,
            "an id must not be able to add a line"
        );
        assert!(!write.contains(&0x1b) && !write.contains(&b'\r'));
    }
}

#[test]
fn a_long_id_is_cut_and_a_short_one_is_not() {
    let at_limit = "x".repeat(MAX_ID_CHARS);
    let over = "y".repeat(MAX_ID_CHARS + 1);
    let huge = "z".repeat(1_000_000);
    let text = |id: &str| {
        item_text(&ItemRef {
            kind: ItemKind::Package,
            id: id.to_string(),
        })
    };
    assert_eq!(text(&at_limit), format!("package:{at_limit}"));
    let cut = text(&over);
    assert_eq!(cut, format!("package:{}...", "y".repeat(MAX_ID_CHARS - 3)));
    assert_eq!(text(&huge).len(), "package:".len() + MAX_ID_CHARS);
    assert_eq!(text("nginx"), "package:nginx");
}

#[test]
fn every_line_has_the_prefix_and_never_the_error_token() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    core.on_event(&run_started(RunKind::Apply), t0);
    core.on_event(&stage_started(Stage::Resources, Some(10)), t0);
    for i in 0..10 {
        core.on_event(
            &item_started(Stage::Resources, i, Some(10), "sinter: x"),
            t0,
        );
    }
    core.tick(t0 + secs(30));
    core.on_event(&run_ended(RunOutcome::Failed), t0 + secs(31));
    for line in mem.lines() {
        assert!(line.starts_with(PREFIX), "{line}");
        assert!(!line.starts_with("sinter:"));
    }
    assert!(PREFIX.is_ascii() && !PREFIX.starts_with("sinter"));
}

// ---------------------------------------------------------------------------
// Failure, muting
// ---------------------------------------------------------------------------

#[test]
fn a_write_error_ends_all_output_without_panicking() {
    let mem = Mem::default();
    mem.fail_after(2);
    let mut core = mem.core(RunKind::Apply);
    let t0 = Instant::now();
    core.on_event(&run_started(RunKind::Apply), t0);
    core.on_event(&stage_started(Stage::Connect, None), t0);
    assert_eq!(mem.count(), 2);
    core.on_event(&stage_ended(Stage::Connect, StageOutcome::Completed, 0), t0);
    let attempts = mem.attempts();
    assert_eq!(attempts, 3, "the failing write was attempted once");
    assert_eq!(
        core.wake_after(t0),
        None,
        "a dead renderer asks for nothing"
    );
    core.on_event(&stage_started(Stage::Resources, Some(1)), t0);
    core.tick(t0 + secs(1000));
    core.on_event(&run_ended(RunOutcome::Failed), t0);
    assert_eq!(mem.attempts(), attempts, "nothing is tried after an error");
    assert_eq!(mem.count(), 2);
}

#[test]
fn a_muted_renderer_is_mute_in_every_entry_point() {
    let mem = Mem::default();
    let mut core = mem.core(RunKind::Apply);
    let latch = AbandonLatch::default();
    core.latch = latch.clone();
    let t0 = Instant::now();
    core.on_event(&run_started(RunKind::Apply), t0);
    core.on_event(&stage_started(Stage::Resources, Some(10)), t0);
    let written = mem.count();
    assert_eq!(written, 2);

    latch.set();
    core.on_event(
        &item_started(Stage::Resources, 5, Some(10), "late"),
        t0 + secs(1),
    );
    core.on_event(
        &stage_ended(Stage::Resources, StageOutcome::Completed, 10),
        t0 + secs(2),
    );
    core.tick(t0 + secs(100));
    assert_eq!(core.wake_after(t0 + secs(100)), None);
    core.on_event(&run_ended(RunOutcome::Completed), t0 + secs(101));
    assert_eq!(mem.count(), written, "a muted worker writes nothing at all");
    assert_eq!(mem.attempts(), written, "and does not even try");
    drop(core);
    assert_eq!(mem.attempts(), written, "not even when it is dropped");
}

#[test]
fn dropping_a_renderer_writes_no_final_line() {
    let mem = Mem::default();
    {
        let mut core = mem.core(RunKind::Apply);
        core.on_event(&stage_started(Stage::Resources, Some(3)), Instant::now());
    }
    assert_eq!(
        mem.count(),
        1,
        "only the start line: nothing to erase, nothing to say"
    );
}

// ---------------------------------------------------------------------------
// Factory and worker (real threads)
// ---------------------------------------------------------------------------

fn fast() -> Timing {
    Timing {
        base: ms(20),
        cap: ms(80),
    }
}

fn plain_options(mem: &Mem, timing: Timing) -> ProgressOptions {
    ProgressOptions::new(ProgressMode::Plain)
        .with_consumer_factory(factory_with_timing(mem.factory(), timing))
}

fn info(references_secrets: bool) -> SessionInfo {
    SessionInfo {
        kind: RunKind::Apply,
        references_secrets,
    }
}

#[test]
fn a_session_that_references_secrets_gets_no_surface_and_writes_nothing() {
    let created = Arc::new(Mutex::new(0usize));
    let made = created.clone();
    let mem = Mem::default();
    let inner = mem.clone();
    let factory: SurfaceFactory = Arc::new(move || {
        *made.lock().unwrap() += 1;
        Box::new(inner.clone())
    });
    let opts = ProgressOptions::new(ProgressMode::Plain)
        .with_consumer_factory(plain_consumer_factory(factory));
    let session = opts.begin(info(true));
    let sink = session.sink();
    sink.emit(&stage_started(Stage::Connect, None));
    sink.emit(&stage_started(Stage::Resources, Some(3)));
    assert_eq!(session.end(RunOutcome::Completed), Teardown::Clean);
    assert_eq!(*created.lock().unwrap(), 0, "no surface for a secret run");
    assert_eq!(mem.count(), 0);
    assert_eq!(mem.attempts(), 0);

    // And a session that does not reference secrets does create one.
    let session = opts.begin(info(false));
    assert_eq!(session.end(RunOutcome::Completed), Teardown::Clean);
    assert_eq!(*created.lock().unwrap(), 1);
    assert!(mem.count() >= 2, "{:?}", mem.lines());
}

#[test]
fn the_worker_delivers_a_whole_run_in_order_and_tears_down_clean() {
    let mem = Mem::default();
    let session = plain_options(&mem, Timing::PRODUCTION).begin(info(false));
    let sink = session.sink();
    sink.emit(&stage_started(Stage::Connect, None));
    sink.emit(&stage_ended(Stage::Connect, StageOutcome::Completed, 0));
    sink.emit(&stage_started(Stage::Resources, Some(1)));
    sink.emit(&item_started(Stage::Resources, 0, Some(1), "a"));
    sink.emit(&stage_ended(Stage::Resources, StageOutcome::Completed, 1));
    drop(sink);
    assert_eq!(session.end(RunOutcome::Completed), Teardown::Clean);
    let lines: Vec<String> = mem
        .lines()
        .iter()
        .map(|l| l.split(" (").next().unwrap().to_string())
        .collect();
    assert_eq!(
        lines,
        [
            "progress: run: apply started",
            "progress: connect: start",
            "progress: connect: done",
            "progress: apply: start 0/1",
            "progress: apply: done 1/1",
            "progress: run: apply completed",
        ]
    );
}

/// A surface whose writes arrive on a channel the test reads, so it can wait
/// for a line (with a deadline) instead of sleeping.
struct Chan {
    tx: mpsc::Sender<String>,
}

impl Surface for Chan {
    fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let _ = self.tx.send(String::from_utf8_lossy(bytes).into_owned());
        Ok(())
    }

    fn columns(&mut self) -> Option<usize> {
        None
    }
}

fn wait_for(rx: &mpsc::Receiver<String>, needle: &str) -> String {
    let deadline = Instant::now() + secs(10);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let line = rx
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("no line containing {needle:?} within 10 s"));
        if line.contains(needle) {
            return line;
        }
    }
}

#[test]
fn the_worker_prints_heartbeats_by_itself_with_a_real_clock() {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let factory: SurfaceFactory = Arc::new(move || {
        let tx = tx.lock().unwrap().clone();
        Box::new(Chan { tx })
    });
    let opts = ProgressOptions::new(ProgressMode::Plain)
        .with_consumer_factory(factory_with_timing(factory, fast()));
    let session = opts.begin(info(false));
    let sink = session.sink();
    sink.emit(&stage_started(Stage::Resources, Some(8)));
    sink.emit(&item_started(Stage::Resources, 3, Some(8), "slow-one"));
    // No further event: the renderer's own timer produces the heartbeats.
    let first = wait_for(&rx, "since last progress");
    assert!(
        first.starts_with("progress: apply: 3/8 on file:slow-one, "),
        "{first:?}"
    );
    let second = wait_for(&rx, "since last progress");
    assert!(second.contains("slow-one"));
    drop(sink);
    assert_eq!(session.end(RunOutcome::Completed), Teardown::Clean);
}

/// A surface whose first write blocks until the test releases it (a stalled
/// stderr), recording everything it is asked to write.
struct Stuck {
    lines: Arc<Mutex<Vec<String>>>,
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    dropped: mpsc::Sender<()>,
    first: bool,
}

impl Surface for Stuck {
    fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if self.first {
            self.first = false;
            let _ = self.entered.send(());
            let _ = self.release.recv();
        }
        self.lines
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(bytes).into_owned());
        Ok(())
    }

    fn columns(&mut self) -> Option<usize> {
        None
    }
}

impl Drop for Stuck {
    fn drop(&mut self) {
        let _ = self.dropped.send(());
    }
}

struct StuckRig {
    lines: Arc<Mutex<Vec<String>>>,
    /// The worker is inside its first, blocked write.
    entered: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
    dropped: mpsc::Receiver<()>,
    opts: ProgressOptions,
}

fn stuck_rig(bound: Duration) -> StuckRig {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let (release_tx, release_rx) = mpsc::channel();
    let (dropped_tx, dropped_rx) = mpsc::channel();
    let (entered_tx, entered_rx) = mpsc::channel();
    let cell = Mutex::new(Some((release_rx, dropped_tx, entered_tx)));
    let seen = lines.clone();
    let factory: SurfaceFactory = Arc::new(move || {
        let (release, dropped, entered) = cell.lock().unwrap().take().expect("one surface");
        Box::new(Stuck {
            lines: seen.clone(),
            entered,
            release,
            dropped,
            first: true,
        })
    });
    StuckRig {
        lines,
        entered: entered_rx,
        release: release_tx,
        dropped: dropped_rx,
        opts: ProgressOptions::new(ProgressMode::Plain)
            .with_consumer_factory(factory_with_timing(factory, fast()))
            .with_teardown_bound(bound),
    }
}

#[test]
fn an_abandoned_plain_worker_writes_nothing_after_the_bound() {
    let rig = stuck_rig(ms(150));
    let session = rig.opts.begin(info(false));
    let sink = session.sink();
    // The worker blocks writing the first line (`run: apply started`); these
    // events queue behind it.
    rig.entered
        .recv_timeout(secs(10))
        .expect("the worker reached its first write");
    sink.emit(&stage_started(Stage::Resources, Some(10)));
    sink.emit(&item_started(Stage::Resources, 5, Some(10), "queued"));
    let teardown = session.end(RunOutcome::Failed);
    assert_eq!(teardown, Teardown::Abandoned);
    // The stalled stderr drains: only the write that was already blocked lands.
    rig.release.send(()).unwrap();
    rig.dropped
        .recv_timeout(secs(10))
        .expect("the abandoned worker exits once released");
    let lines = rig.lines.lock().unwrap().clone();
    assert_eq!(
        lines,
        ["progress: run: apply started\n"],
        "queued lines, heartbeats and the run end line must not follow"
    );
    drop(sink);
}

/// RA-L1 for the plain renderer: a run that panics detaches its worker, which
/// must be mute, not draw what is still queued after the panic message.
#[test]
fn a_panic_unwind_mutes_the_detached_plain_worker() {
    let rig = stuck_rig(secs(30));
    let opts = rig.opts.clone();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = opts.begin(info(false));
        let sink = session.sink();
        // The worker is parked in its first write; what follows queues behind it.
        rig.entered
            .recv_timeout(secs(10))
            .expect("the worker reached its first write");
        sink.emit(&stage_started(Stage::Resources, Some(10)));
        sink.emit(&item_started(Stage::Resources, 5, Some(10), "queued"));
        drop(sink);
        panic!("the run panicked (expected by this test)");
    }));
    assert!(caught.is_err());
    rig.release.send(()).unwrap();
    rig.dropped
        .recv_timeout(secs(10))
        .expect("the detached worker exits once its channel closed");
    let lines = rig.lines.lock().unwrap().clone();
    assert_eq!(
        lines,
        ["progress: run: apply started\n"],
        "a worker detached by a panic drew queued lines after the panic"
    );
}

// ---------------------------------------------------------------------------
// Secrets: nothing but the closed vocabulary reaches the log
// ---------------------------------------------------------------------------

/// The events one real engine run produces for a recipe laden with canaries
/// (file content, variables, command program/arguments/environment, secret
/// reference and plaintext, loop item, handler service, SSH user and key path),
/// in all three commands, with and without a secret reference, rendered with a
/// long quiet spell after every event so that heartbeats name the item too: the
/// most the renderer can show.
#[test]
fn no_sensitive_value_reaches_the_plain_log_of_a_real_engine_stream() {
    use crate::engine::Mode;
    let declared = ["plain", "looped[0]", "cmd", "acct", "after", "restart_it"];
    let known = [
        "progress",
        "run",
        "started",
        "completed",
        "failed",
        "indeterminate",
        "connect",
        "start",
        "done",
        "backup",
        "plan",
        "apply",
        "audit",
        "handlers",
        "file",
        "command",
        "user",
        "handler",
        "since",
        "last",
        "on",
        "",
    ];
    for (mode, label) in [
        (Some(Mode::Plan), "plan"),
        (Some(Mode::Apply), "apply"),
        (None, "audit"),
    ] {
        for with_secret in [false, true] {
            let (kind, events) = engine_stream(mode, with_secret);
            let mem = Mem::default();
            let t0 = Instant::now();
            let mut core = mem.core(kind);
            for (i, e) in events.iter().enumerate() {
                let t = t0 + secs(100 * (i as u64 + 1));
                core.on_event(e, t);
                core.tick(t + secs(40));
            }
            let lines = mem.lines();
            let text = lines.join("\n");
            for canary in CANARIES {
                assert!(
                    !text.contains(canary),
                    "{label} secret={with_secret}: {canary} leaked into {text:?}"
                );
            }
            assert!(text
                .bytes()
                .all(|b| (0x20..=0x7e).contains(&b) || b == b'\n'));
            // Positive controls: the run really named its items, by declared id
            // only, and the heartbeat really fired.
            assert!(text.contains("file:plain"), "{label}: {text:?}");
            assert!(text.contains("file:looped[0]"), "{label}: {text:?}");
            assert!(text.contains("command:cmd"), "{label}: {text:?}");
            assert!(text.contains("since last progress"), "{label}: {text:?}");
            for line in &lines {
                for word in line.split(|c: char| " :/,()".contains(c)) {
                    let numeric_or_time = word
                        .chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, 's' | 'm' | 'h'));
                    assert!(
                        known.contains(&word) || numeric_or_time || declared.contains(&word),
                        "{label}: unexpected word {word:?} in {line:?}"
                    );
                }
            }
        }
    }
}
