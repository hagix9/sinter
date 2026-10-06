//! Unit tests of the TTY renderer: pure formatting, the state machine on a
//! driven clock, the worker with real (millisecond) timing, a real pty.

use super::*;
use crate::progress::{ItemKind, RunOutcome, StageOutcome};
use crate::progress_session::{ProgressMode, ProgressOptions};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// A surface that records bytes; width and failure are scripted.
#[derive(Clone)]
struct Mem {
    bytes: Arc<Mutex<Vec<u8>>>,
    columns: Arc<Mutex<Option<usize>>>,
    fail_after: Arc<Mutex<Option<usize>>>,
    writes: Arc<Mutex<usize>>,
}

impl Mem {
    fn new(columns: Option<usize>) -> Mem {
        Mem {
            bytes: Arc::default(),
            columns: Arc::new(Mutex::new(columns)),
            fail_after: Arc::default(),
            writes: Arc::default(),
        }
    }

    fn set_columns(&self, c: Option<usize>) {
        *self.columns.lock().unwrap() = c;
    }

    fn fail_after(&self, writes: usize) {
        *self.fail_after.lock().unwrap() = Some(writes);
    }

    fn text(&self) -> String {
        String::from_utf8(self.bytes.lock().unwrap().clone()).unwrap()
    }

    fn write_count(&self) -> usize {
        *self.writes.lock().unwrap()
    }

    fn factory(&self) -> SurfaceFactory {
        let m = self.clone();
        Arc::new(move || Box::new(m.clone()))
    }
}

impl Surface for Mem {
    fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let mut writes = self.writes.lock().unwrap();
        if let Some(n) = *self.fail_after.lock().unwrap() {
            if *writes >= n {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
        }
        *writes += 1;
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(())
    }

    fn columns(&mut self) -> Option<usize> {
        *self.columns.lock().unwrap()
    }
}

fn item(kind: ItemKind, id: &str) -> Option<ItemRef> {
    Some(ItemRef {
        kind,
        id: id.to_string(),
    })
}

fn started(stage: Stage, total: Option<u32>) -> ProgressEvent {
    ProgressEvent::StageStarted { stage, total }
}

fn progress(
    stage: Stage,
    done: u32,
    total: Option<u32>,
    current: Option<ItemRef>,
) -> ProgressEvent {
    ProgressEvent::Progress {
        stage,
        done,
        total,
        current,
    }
}

fn ended(stage: Stage, outcome: StageOutcome, done: u32) -> ProgressEvent {
    ProgressEvent::StageEnded {
        stage,
        outcome,
        done,
    }
}

fn run_ended(outcome: RunOutcome) -> ProgressEvent {
    ProgressEvent::RunEnded { outcome }
}

/// The view after `events`.
fn view_of(kind: Option<RunKind>, events: &[ProgressEvent]) -> View {
    let mut v = View::new(kind);
    for e in events {
        v.apply(e);
    }
    v
}

fn line(
    kind: Option<RunKind>,
    events: &[ProgressEvent],
    quiet: Option<Duration>,
    max: usize,
) -> Option<String> {
    format_line(&view_of(kind, events), quiet, max)
}

const WIDE: usize = 200;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn core(mem: &Mem, kind: RunKind, now: Instant) -> Core {
    Core::new(Box::new(mem.clone()), kind, Timing::PRODUCTION, now)
}

fn is_printable_ascii(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// All events a stream can contain, for "never panics" sweeps.
fn sample_events() -> Vec<ProgressEvent> {
    let mut v = vec![
        ProgressEvent::RunStarted {
            command: RunKind::Apply,
        },
        run_ended(RunOutcome::Completed),
        run_ended(RunOutcome::Failed),
        run_ended(RunOutcome::Indeterminate),
    ];
    for stage in [
        Stage::Resolve,
        Stage::Connect,
        Stage::Backup,
        Stage::Resources,
        Stage::Handlers,
    ] {
        for total in [None, Some(0), Some(1), Some(42), Some(u32::MAX)] {
            v.push(started(stage, total));
            for done in [0, 1, 41, u32::MAX] {
                for cur in [
                    None,
                    item(ItemKind::Package, "nginx"),
                    item(ItemKind::Handler, "a\nb\rc\x1b[2Jd\te\x07f\u{9b}g\u{7f}"),
                    item(ItemKind::Other, &"x".repeat(5000)),
                    item(ItemKind::File, "\u{65e5}\u{672c}\u{8a9e}"),
                    item(ItemKind::File, ""),
                ] {
                    v.push(progress(stage, done, total, cur));
                }
                for o in [
                    StageOutcome::Completed,
                    StageOutcome::Failed,
                    StageOutcome::Indeterminate,
                ] {
                    v.push(ended(stage, o, done));
                }
            }
        }
    }
    v
}

// ---------------------------------------------------------------------------
// display contract
// ---------------------------------------------------------------------------

#[test]
fn run_started_and_run_ended_show_no_line() {
    let started_only = [ProgressEvent::RunStarted {
        command: RunKind::Plan,
    }];
    assert_eq!(line(None, &started_only, None, WIDE), None);
    let after = [
        started(Stage::Connect, None),
        run_ended(RunOutcome::Completed),
    ];
    assert_eq!(line(Some(RunKind::Plan), &after, None, WIDE), None);
}

#[test]
fn stage_started_shows_the_label_and_a_known_counter() {
    let k = Some(RunKind::Apply);
    assert_eq!(
        line(k, &[started(Stage::Connect, None)], None, WIDE).as_deref(),
        Some("connect")
    );
    assert_eq!(
        line(k, &[started(Stage::Resolve, Some(3))], None, WIDE).as_deref(),
        Some("resolve 0/3")
    );
    assert_eq!(
        line(k, &[started(Stage::Backup, Some(2))], None, WIDE).as_deref(),
        Some("backup 0/2")
    );
    assert_eq!(
        line(k, &[started(Stage::Handlers, Some(1))], None, WIDE).as_deref(),
        Some("handlers 0/1")
    );
}

#[test]
fn the_resource_stage_is_labelled_with_the_command() {
    let ev = [started(Stage::Resources, Some(4))];
    for (k, want) in [
        (Some(RunKind::Plan), "plan 0/4"),
        (Some(RunKind::Apply), "apply 0/4"),
        (Some(RunKind::Audit), "audit 0/4"),
        (None, "resources 0/4"),
    ] {
        assert_eq!(line(k, &ev, None, WIDE).as_deref(), Some(want));
    }
}

#[test]
fn progress_with_a_known_total_and_a_current_item() {
    let ev = [
        started(Stage::Resources, Some(42)),
        progress(
            Stage::Resources,
            17,
            Some(42),
            item(ItemKind::Package, "nginx"),
        ),
    ];
    assert_eq!(
        line(Some(RunKind::Apply), &ev, None, WIDE).as_deref(),
        Some("apply 17/42 package:nginx")
    );
    assert_eq!(
        line(Some(RunKind::Apply), &ev, Some(secs(8)), WIDE).as_deref(),
        Some("apply 17/42 package:nginx 8s")
    );
}

#[test]
fn progress_with_an_unknown_total_invents_no_denominator() {
    let ev = [progress(Stage::Connect, 0, None, None)];
    assert_eq!(
        line(Some(RunKind::Plan), &ev, Some(secs(4)), WIDE).as_deref(),
        Some("connect 4s")
    );
    let ev = [progress(
        Stage::Resources,
        3,
        None,
        item(ItemKind::File, "a"),
    )];
    let text = line(Some(RunKind::Plan), &ev, None, WIDE).unwrap();
    assert_eq!(text, "plan file:a");
    assert!(!text.contains('/') && !text.contains('%'));
}

#[test]
fn a_missing_current_item_leaves_no_placeholder() {
    let ev = [progress(Stage::Resolve, 1, Some(3), None)];
    assert_eq!(line(None, &ev, None, WIDE).as_deref(), Some("resolve 1/3"));
}

#[test]
fn every_item_kind_is_shown_by_its_label() {
    for k in [
        ItemKind::File,
        ItemKind::Directory,
        ItemKind::Link,
        ItemKind::Template,
        ItemKind::Command,
        ItemKind::Package,
        ItemKind::Service,
        ItemKind::Group,
        ItemKind::User,
        ItemKind::Other,
        ItemKind::Handler,
    ] {
        let ev = [progress(Stage::Resources, 0, Some(1), item(k, "x"))];
        assert_eq!(
            line(Some(RunKind::Plan), &ev, None, WIDE).unwrap(),
            format!("plan 0/1 {}:x", k.label())
        );
    }
}

#[test]
fn an_ended_stage_states_its_outcome_and_never_infers_success_from_the_counter() {
    let k = Some(RunKind::Apply);
    let base = |o, done| {
        [
            started(Stage::Resources, Some(5)),
            progress(Stage::Resources, 4, Some(5), item(ItemKind::File, "last")),
            ended(Stage::Resources, o, done),
        ]
    };
    assert_eq!(
        line(k, &base(StageOutcome::Completed, 5), None, WIDE).as_deref(),
        Some("apply 5/5")
    );
    // The failing item counts: done == total, but the stage failed.
    assert_eq!(
        line(k, &base(StageOutcome::Failed, 5), None, WIDE).as_deref(),
        Some("apply 5/5 failed")
    );
    assert_eq!(
        line(k, &base(StageOutcome::Indeterminate, 5), None, WIDE).as_deref(),
        Some("apply 5/5 indeterminate")
    );
    // A stage that failed early.
    assert_eq!(
        line(k, &base(StageOutcome::Failed, 2), None, WIDE).as_deref(),
        Some("apply 2/5 failed")
    );
    // The current item is gone once the stage ended.
    assert!(!line(k, &base(StageOutcome::Failed, 5), None, WIDE)
        .unwrap()
        .contains("last"));
}

#[test]
fn an_ended_stage_without_a_started_one_has_no_total() {
    let ev = [ended(Stage::Connect, StageOutcome::Failed, 0)];
    assert_eq!(
        line(None, &ev, None, WIDE).as_deref(),
        Some("connect failed")
    );
}

#[test]
fn a_zero_total_shows_zero_of_zero() {
    let ev = [
        started(Stage::Resources, Some(0)),
        ended(Stage::Resources, StageOutcome::Completed, 0),
    ];
    assert_eq!(
        line(Some(RunKind::Apply), &ev, None, WIDE).as_deref(),
        Some("apply 0/0")
    );
}

#[test]
fn the_line_between_stages_is_the_last_stage_not_an_invented_one() {
    let ev = [
        started(Stage::Resources, Some(1)),
        progress(Stage::Resources, 0, Some(1), item(ItemKind::File, "a")),
        ended(Stage::Resources, StageOutcome::Completed, 1),
    ];
    let text = line(Some(RunKind::Apply), &ev, Some(secs(5)), WIDE).unwrap();
    assert_eq!(text, "apply 1/1 5s");
    for fake in ["validate", "verify", "finaliz", "post"] {
        assert!(!text.contains(fake));
    }
}

#[test]
fn elapsed_text_is_stable_and_ascii() {
    for (d, want) in [
        (secs(0), "0s"),
        (ms(999), "0s"),
        (secs(3), "3s"),
        (secs(59), "59s"),
        (secs(60), "1m00s"),
        (secs(125), "2m05s"),
        (secs(3599), "59m59s"),
        (secs(3600), "1h00m"),
        (secs(3600 * 25 + 120), "25h02m"),
        (Duration::MAX, &format_elapsed(Duration::MAX)),
    ] {
        assert_eq!(format_elapsed(d), want);
        assert!(is_printable_ascii(&format_elapsed(d)));
    }
}

// ---------------------------------------------------------------------------
// sanitization
// ---------------------------------------------------------------------------

#[test]
fn hostile_ids_cannot_inject_lines_or_sequences() {
    for id in [
        "a\nb",
        "a\rb",
        "a\x1b[2Jb",
        "\x1b]0;title\x07",
        "a\tb",
        "a\x07b",
        "a\u{9b}31mb",
        "a\u{7f}b",
        "a\0b",
        "\u{202e}rtl",
        "\u{65e5}\u{672c}",
        "\u{1f600}",
    ] {
        let ev = [progress(
            Stage::Resources,
            0,
            Some(1),
            item(ItemKind::File, id),
        )];
        let text = line(Some(RunKind::Apply), &ev, Some(secs(4)), WIDE).unwrap();
        assert!(is_printable_ascii(&text), "{id:?} -> {text:?}");
        assert!(text.starts_with("apply 0/1 file:"), "{text:?}");
        assert!(text.ends_with(" 4s"), "{text:?}");
    }
}

#[test]
fn replacement_is_one_question_mark_per_character() {
    assert_eq!(sanitize_display("a\nb", 99), "a?b");
    assert_eq!(sanitize_display("\x1b[2J", 99), "?[2J");
    assert_eq!(sanitize_display("\u{65e5}\u{672c}", 99), "??");
    assert_eq!(sanitize_display("tab\there", 99), "tab?here");
    assert_eq!(sanitize_display("ok-id_1.2", 99), "ok-id_1.2");
    assert_eq!(sanitize_display("abcdef", 3), "abc");
}

#[test]
fn sanitization_does_not_touch_the_event() {
    let ev = progress(Stage::Resources, 0, Some(1), item(ItemKind::File, "a\x1bb"));
    let before = ev.clone();
    let _ = line(None, std::slice::from_ref(&ev), None, WIDE);
    assert_eq!(ev, before);
}

// ---------------------------------------------------------------------------
// width
// ---------------------------------------------------------------------------

#[test]
fn the_budget_is_one_less_than_the_width() {
    assert_eq!(line_budget(Some(80)), 79);
    assert_eq!(line_budget(Some(2)), 1);
    assert_eq!(line_budget(Some(1)), 0);
}

#[test]
fn an_unknown_or_zero_width_uses_the_documented_fallback() {
    assert_eq!(FALLBACK_COLUMNS, 60);
    assert_eq!(line_budget(None), 59);
    assert_eq!(line_budget(Some(0)), 59);
}

#[test]
fn extreme_widths_do_not_panic_or_allocate_the_width() {
    assert_eq!(line_budget(Some(usize::MAX)), usize::MAX - 1);
    let ev = [progress(
        Stage::Resources,
        1,
        Some(2),
        item(ItemKind::File, &"y".repeat(100_000)),
    )];
    let text = line(Some(RunKind::Apply), &ev, Some(secs(9)), usize::MAX - 1).unwrap();
    // The id is looked at only up to the (huge) budget; this just must not panic
    // and must stay printable. A bounded budget bounds the work.
    assert!(is_printable_ascii(&text));
    let text = line(Some(RunKind::Apply), &ev, Some(secs(9)), 80).unwrap();
    assert!(text.len() <= 80);
}

#[test]
fn a_long_id_is_shortened_with_dots_and_keeps_label_counter_and_elapsed() {
    let ev = [progress(
        Stage::Resources,
        17,
        Some(42),
        item(ItemKind::Package, &"n".repeat(300)),
    )];
    let text = line(Some(RunKind::Apply), &ev, Some(secs(8)), 40).unwrap();
    assert_eq!(text.len(), 40);
    assert!(text.starts_with("apply 17/42 package:nnn"), "{text}");
    assert!(text.ends_with("... 8s"), "{text}");
}

#[test]
fn when_the_item_cannot_be_shown_sensibly_it_is_dropped_first() {
    let ev = [progress(
        Stage::Resources,
        17,
        Some(42),
        item(ItemKind::Package, "nginx"),
    )];
    // "apply 17/42" (11) + " 8s" (3) = 14: no room for a useful item.
    assert_eq!(
        line(Some(RunKind::Apply), &ev, Some(secs(8)), 18).as_deref(),
        Some("apply 17/42 8s")
    );
    // Without room for the elapsed text the label and counter remain.
    assert_eq!(
        line(Some(RunKind::Apply), &ev, Some(secs(8)), 12).as_deref(),
        Some("apply 17/42")
    );
    // Narrower still: the label is cut to the budget.
    assert_eq!(
        line(Some(RunKind::Apply), &ev, Some(secs(8)), 5).as_deref(),
        Some("apply")
    );
    assert_eq!(
        line(Some(RunKind::Apply), &ev, Some(secs(8)), 3).as_deref(),
        Some("app")
    );
    assert_eq!(line(Some(RunKind::Apply), &ev, Some(secs(8)), 0), None);
}

#[test]
fn the_formatter_never_panics_and_never_exceeds_the_budget() {
    for kind in [
        None,
        Some(RunKind::Plan),
        Some(RunKind::Apply),
        Some(RunKind::Audit),
    ] {
        for ev in sample_events() {
            for quiet in [None, Some(secs(0)), Some(secs(3)), Some(secs(100_000))] {
                for max in (0..=130).chain([300, 1000]) {
                    let v = view_of(kind, std::slice::from_ref(&ev));
                    if let Some(text) = format_line(&v, quiet, max) {
                        assert!(text.chars().count() <= max, "{ev:?} max={max} {text:?}");
                        assert!(is_printable_ascii(&text), "{ev:?} {text:?}");
                        assert!(!text.is_empty());
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// transient control (Core on a driven clock)
// ---------------------------------------------------------------------------

#[test]
fn the_first_event_draws_immediately_with_one_clear_and_no_newline() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Plan, t0);
    c.on_event(
        &ProgressEvent::RunStarted {
            command: RunKind::Plan,
        },
        t0,
    );
    assert_eq!(mem.text(), "", "no stage yet, nothing to show");
    c.on_event(&started(Stage::Connect, None), t0);
    assert_eq!(mem.text(), format!("{CLEAR}connect"));
    assert!(!mem.text().contains('\n'));
}

#[test]
fn a_changed_line_replaces_the_old_one_and_an_unchanged_one_is_not_rewritten() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    c.on_event(&started(Stage::Resources, Some(3)), t0);
    c.on_event(
        &progress(Stage::Resources, 0, Some(3), item(ItemKind::File, "a")),
        t0 + ms(150),
    );
    assert_eq!(
        mem.text(),
        format!("{CLEAR}apply 0/3{CLEAR}apply 0/3 file:a")
    );
    let n = mem.write_count();
    // Same text again: no write.
    c.on_event(
        &progress(Stage::Resources, 0, Some(3), item(ItemKind::File, "a")),
        t0 + ms(300),
    );
    assert_eq!(mem.write_count(), n);
}

#[test]
fn redraws_are_coalesced_to_the_minimum_interval_and_flushed_by_a_tick() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    c.on_event(&started(Stage::Resources, Some(9)), t0);
    assert_eq!(mem.write_count(), 1);
    for i in 0..5u32 {
        c.on_event(
            &progress(
                Stage::Resources,
                i,
                Some(9),
                item(ItemKind::File, &format!("f{i}")),
            ),
            t0 + ms(10 + u64::from(i)),
        );
    }
    assert_eq!(mem.write_count(), 1, "events inside the interval are held");
    let wait = c.wake_after(t0 + ms(14)).unwrap();
    assert_eq!(wait, ms(86), "wake exactly when the redraw is due");
    c.tick(t0 + ms(100));
    assert_eq!(mem.write_count(), 2);
    assert!(
        mem.text().ends_with(&format!("{CLEAR}apply 4/9 file:f4")),
        "{}",
        mem.text()
    );
}

#[test]
fn elapsed_appears_after_the_quiet_threshold_and_refreshes_every_second() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    c.on_event(&started(Stage::Resources, Some(2)), t0);
    c.on_event(
        &progress(
            Stage::Resources,
            0,
            Some(2),
            item(ItemKind::Package, "nginx"),
        ),
        t0 + ms(200),
    );
    let t = t0 + ms(200);
    // Nothing for the first three seconds.
    assert_eq!(c.wake_after(t), Some(QUIET_AFTER));
    c.tick(t + secs(2));
    assert!(!mem.text().contains("2s"));
    // At the threshold: shown.
    c.tick(t + secs(3));
    assert!(mem
        .text()
        .ends_with(&format!("{CLEAR}apply 0/2 package:nginx 3s")));
    // Then once per whole second since the last event.
    assert_eq!(c.wake_after(t + secs(3)), Some(secs(1)));
    assert_eq!(c.wake_after(t + ms(3400)), Some(ms(600)));
    c.tick(t + secs(4));
    assert!(mem
        .text()
        .ends_with(&format!("{CLEAR}apply 0/2 package:nginx 4s")));
    c.tick(t + secs(65));
    assert!(mem
        .text()
        .ends_with(&format!("{CLEAR}apply 0/2 package:nginx 1m05s")));
}

#[test]
fn a_tick_that_changes_nothing_writes_nothing() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    c.on_event(&started(Stage::Connect, None), t0);
    c.tick(t0 + ms(1));
    c.tick(t0 + ms(2500));
    assert_eq!(mem.write_count(), 1);
    c.tick(t0 + ms(3100));
    assert_eq!(mem.write_count(), 2);
    c.tick(t0 + ms(3900));
    assert_eq!(mem.write_count(), 2, "still 3s");
}

#[test]
fn a_new_event_resets_the_quiet_clock() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    c.on_event(&started(Stage::Resources, Some(2)), t0);
    c.on_event(
        &progress(Stage::Resources, 0, Some(2), item(ItemKind::File, "a")),
        t0,
    );
    c.tick(t0 + secs(5));
    assert!(mem.text().ends_with("file:a 5s"));
    c.on_event(
        &progress(Stage::Resources, 1, Some(2), item(ItemKind::File, "b")),
        t0 + secs(6),
    );
    assert!(
        mem.text().ends_with(&format!("{CLEAR}apply 1/2 file:b")),
        "{}",
        mem.text()
    );
    assert_eq!(c.wake_after(t0 + secs(6)), Some(QUIET_AFTER));
}

#[test]
fn elapsed_comes_from_the_clock_it_is_given_and_a_backwards_clock_is_harmless() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0 + secs(10));
    c.on_event(&started(Stage::Connect, None), t0 + secs(10));
    // `now` earlier than the last event: saturates to zero, no panic, no elapsed.
    c.tick(t0);
    assert_eq!(c.wake_after(t0), Some(QUIET_AFTER));
    assert!(!mem.text().contains("0s"));
}

#[test]
fn run_ended_erases_the_line_and_nothing_is_drawn_afterwards() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    c.on_event(&started(Stage::Connect, None), t0);
    c.on_event(&run_ended(RunOutcome::Completed), t0 + ms(5));
    assert_eq!(mem.text(), format!("{CLEAR}connect{CLEAR}"));
    assert_eq!(c.wake_after(t0 + ms(6)), None);
    c.on_event(&started(Stage::Resources, Some(1)), t0 + ms(7));
    c.tick(t0 + secs(30));
    assert_eq!(mem.text(), format!("{CLEAR}connect{CLEAR}"));
    drop(c);
    assert_eq!(
        mem.text(),
        format!("{CLEAR}connect{CLEAR}"),
        "already clear: drop adds nothing"
    );
}

#[test]
fn a_failed_run_clears_the_line_just_the_same() {
    for outcome in [RunOutcome::Failed, RunOutcome::Indeterminate] {
        let mem = Mem::new(Some(80));
        let t0 = Instant::now();
        let mut c = core(&mem, RunKind::Plan, t0);
        c.on_event(&started(Stage::Resources, Some(2)), t0);
        c.on_event(
            &progress(Stage::Resources, 0, Some(2), item(ItemKind::File, "a")),
            t0 + ms(200),
        );
        c.on_event(
            &ended(Stage::Resources, StageOutcome::Failed, 1),
            t0 + ms(400),
        );
        c.on_event(&run_ended(outcome), t0 + ms(401));
        assert!(
            mem.text().ends_with(&format!("plan 1/2 failed{CLEAR}")),
            "{}",
            mem.text()
        );
    }
}

#[test]
fn dropping_a_core_with_a_line_on_screen_erases_it() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Plan, t0);
    c.on_event(&started(Stage::Connect, None), t0);
    drop(c);
    assert_eq!(mem.text(), format!("{CLEAR}connect{CLEAR}"));
}

#[test]
fn only_the_clear_sequence_and_printable_text_are_ever_written() {
    let mem = Mem::new(Some(40));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    for (i, e) in sample_events().iter().enumerate() {
        c.on_event(e, t0 + ms(150 * (i as u64 + 1)));
        c.tick(t0 + ms(150 * (i as u64 + 1) + 4000));
    }
    drop(c);
    let text = mem.text();
    let rest = text.replace(CLEAR, "");
    assert!(is_printable_ascii(&rest), "{rest:?}");
    // Every frame fits the 39-column budget and is a single line.
    for frame in text.split(CLEAR) {
        assert!(frame.chars().count() <= 39, "{frame:?}");
    }
}

#[test]
fn a_write_error_ends_all_drawing_and_never_panics() {
    let mem = Mem::new(Some(80));
    mem.fail_after(1);
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    c.on_event(&started(Stage::Connect, None), t0);
    c.on_event(&started(Stage::Resources, Some(1)), t0 + ms(500));
    assert_eq!(mem.write_count(), 1);
    assert_eq!(
        c.wake_after(t0 + ms(600)),
        None,
        "a dead renderer never asks to wake"
    );
    c.tick(t0 + secs(10));
    c.on_event(&run_ended(RunOutcome::Failed), t0 + secs(11));
    drop(c);
    assert_eq!(mem.write_count(), 1);
}

#[test]
fn a_failing_clear_is_tolerated() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    c.on_event(&started(Stage::Connect, None), t0);
    mem.fail_after(1);
    c.on_event(&run_ended(RunOutcome::Completed), t0 + ms(5));
    drop(c);
    assert_eq!(mem.text(), format!("{CLEAR}connect"));
}

#[test]
fn width_failure_falls_back_and_width_is_asked_again_at_every_draw() {
    let mem = Mem::new(None);
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    let long = item(ItemKind::Package, &"z".repeat(200));
    c.on_event(&started(Stage::Resources, Some(5)), t0);
    c.on_event(
        &progress(Stage::Resources, 1, Some(5), long.clone()),
        t0 + ms(200),
    );
    let frames: Vec<String> = mem.text().split(CLEAR).map(str::to_string).collect();
    assert_eq!(
        frames.last().unwrap().chars().count(),
        59,
        "fallback 60 minus one"
    );
    mem.set_columns(Some(30));
    c.on_event(
        &progress(Stage::Resources, 2, Some(5), long.clone()),
        t0 + ms(400),
    );
    assert_eq!(mem.text().split(CLEAR).last().unwrap().chars().count(), 29);
    mem.set_columns(Some(0));
    c.on_event(&progress(Stage::Resources, 3, Some(5), long), t0 + ms(600));
    assert_eq!(
        mem.text().split(CLEAR).last().unwrap().chars().count(),
        59,
        "0 means unknown"
    );
}

#[test]
fn a_one_column_terminal_gets_no_line_and_no_panic() {
    let mem = Mem::new(Some(1));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    c.on_event(&started(Stage::Connect, None), t0);
    c.tick(t0 + secs(9));
    c.on_event(&run_ended(RunOutcome::Completed), t0 + secs(10));
    assert_eq!(mem.text(), "");
}

#[test]
fn narrowing_the_terminal_to_nothing_erases_an_existing_line() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Apply, t0);
    c.on_event(&started(Stage::Connect, None), t0);
    mem.set_columns(Some(1));
    c.on_event(&started(Stage::Resources, Some(2)), t0 + ms(200));
    assert_eq!(mem.text(), format!("{CLEAR}connect{CLEAR}"));
}

#[test]
fn the_renderer_survives_every_event_in_any_order_at_any_width() {
    for columns in [
        None,
        Some(0),
        Some(1),
        Some(2),
        Some(5),
        Some(80),
        Some(usize::MAX),
    ] {
        let mem = Mem::new(columns);
        let t0 = Instant::now();
        let mut c = core(&mem, RunKind::Audit, t0);
        for (i, e) in sample_events().iter().enumerate() {
            let t = t0 + ms(7 * i as u64);
            c.on_event(e, t);
            let _ = c.wake_after(t);
            c.tick(t + ms(3500));
        }
    }
}

#[test]
fn wake_after_is_never_zero_and_asks_nothing_when_there_is_nothing_to_show() {
    let mem = Mem::new(Some(80));
    let t0 = Instant::now();
    let mut c = core(&mem, RunKind::Plan, t0);
    assert_eq!(c.wake_after(t0), None, "no stage: nothing to wake for");
    c.on_event(&started(Stage::Connect, None), t0);
    for k in 0..4000u64 {
        let w = c.wake_after(t0 + ms(k)).unwrap();
        assert!(w >= MIN_WAKE && w <= secs(3), "{k}: {w:?}");
    }
}

// ---------------------------------------------------------------------------
// factory: OQ-5
// ---------------------------------------------------------------------------

fn info(references_secrets: bool) -> SessionInfo {
    SessionInfo {
        kind: RunKind::Apply,
        references_secrets,
    }
}

#[test]
fn a_secret_bearing_session_never_creates_a_surface_and_writes_nothing() {
    let mem = Mem::new(Some(80));
    let created = Arc::new(Mutex::new(0usize));
    let counter = created.clone();
    let m = mem.clone();
    let surface: SurfaceFactory = Arc::new(move || {
        *counter.lock().unwrap() += 1;
        Box::new(m.clone())
    });
    let opts =
        ProgressOptions::new(ProgressMode::Tty).with_consumer_factory(consumer_factory(surface));
    let session = opts.begin(info(true));
    let sink = session.sink();
    sink.emit(&started(Stage::Connect, None));
    sink.emit(&started(Stage::Resources, Some(1)));
    sink.emit(&progress(
        Stage::Resources,
        0,
        Some(1),
        item(ItemKind::File, "k"),
    ));
    assert!(
        session.is_active(),
        "the worker runs, with the null consumer"
    );
    session.end(RunOutcome::Completed);
    assert_eq!(
        *created.lock().unwrap(),
        0,
        "no surface for a secret-bearing run"
    );
    assert_eq!(mem.text(), "");
    assert_eq!(mem.write_count(), 0);

    // The same options for a recipe without secrets do draw.
    let session = opts.begin(info(false));
    session.sink().emit(&started(Stage::Connect, None));
    session.end(RunOutcome::Completed);
    assert_eq!(*created.lock().unwrap(), 1);
    assert_eq!(mem.text(), format!("{CLEAR}connect{CLEAR}"));
}

// ---------------------------------------------------------------------------
// the worker (real threads, millisecond timing)
// ---------------------------------------------------------------------------

fn fast() -> Timing {
    Timing {
        quiet_after: ms(30),
        min_redraw: ms(5),
        step: ms(10),
    }
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + secs(10);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(ms(2));
    }
}

#[test]
fn the_worker_refreshes_the_quiet_line_without_any_event_and_ends_it_promptly() {
    let mem = Mem::new(Some(80));
    let opts = ProgressOptions::new(ProgressMode::Tty)
        .with_consumer_factory(factory_with_timing(mem.factory(), fast()));
    let session = opts.begin(info(false));
    let sink = session.sink();
    sink.emit(&started(Stage::Resources, Some(2)));
    sink.emit(&progress(
        Stage::Resources,
        0,
        Some(2),
        item(ItemKind::Package, "nginx"),
    ));
    wait_until("the first draw", || {
        mem.text().contains("apply 0/2 package:nginx")
    });
    let writes = mem.write_count();
    // No event arrives; the worker alone must produce the elapsed text.
    wait_until("the elapsed refresh", || {
        mem.text().ends_with("apply 0/2 package:nginx 0s")
    });
    assert!(mem.write_count() > writes);
    let before = Instant::now();
    let teardown = session.end(RunOutcome::Completed);
    let took = before.elapsed();
    assert_eq!(teardown, crate::progress_session::Teardown::Clean);
    assert!(took < ms(250), "teardown took {took:?}");
    assert!(mem.text().ends_with(CLEAR), "{}", mem.text());
    let n = mem.write_count();
    std::thread::sleep(ms(80));
    assert_eq!(mem.write_count(), n, "nothing is written after teardown");
}

#[test]
fn an_idle_worker_with_no_line_makes_no_wakeups_and_still_stops_at_once() {
    let mem = Mem::new(Some(80));
    let opts = ProgressOptions::new(ProgressMode::Tty)
        .with_consumer_factory(factory_with_timing(mem.factory(), fast()));
    let session = opts.begin(info(false));
    std::thread::sleep(ms(100));
    let before = Instant::now();
    assert_eq!(
        session.end(RunOutcome::Failed),
        crate::progress_session::Teardown::Clean
    );
    assert!(before.elapsed() < ms(250));
    assert_eq!(mem.write_count(), 0);
}

#[test]
fn a_stalled_surface_is_abandoned_within_the_teardown_bound() {
    struct Stuck(Arc<(Mutex<bool>, std::sync::Condvar)>);
    impl Surface for Stuck {
        fn write_frame(&mut self, _: &[u8]) -> std::io::Result<()> {
            let (m, cv) = &*self.0;
            let mut released = m.lock().unwrap();
            while !*released {
                released = cv.wait(released).unwrap();
            }
            Ok(())
        }
        fn columns(&mut self) -> Option<usize> {
            Some(80)
        }
    }
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let g = gate.clone();
    let surface: SurfaceFactory = Arc::new(move || Box::new(Stuck(g.clone())));
    let opts = ProgressOptions::new(ProgressMode::Tty)
        .with_consumer_factory(consumer_factory(surface))
        .with_teardown_bound(ms(100));
    let session = opts.begin(info(false));
    session.sink().emit(&started(Stage::Connect, None));
    let before = Instant::now();
    let teardown = session.end(RunOutcome::Completed);
    let took = before.elapsed();
    assert_eq!(teardown, crate::progress_session::Teardown::Abandoned);
    assert!(took >= ms(100) && took < secs(5), "{took:?}");
    // Release the worker so the test leaves no thread behind.
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
}

// ---------------------------------------------------------------------------
// a real terminal
// ---------------------------------------------------------------------------

/// A pty pair; the slave is the terminal drawn on, the master reads it back.
struct Pty {
    master: std::fs::File,
    slave: std::fs::File,
}

impl Pty {
    fn open(cols: u16) -> Pty {
        use std::os::fd::FromRawFd;
        let mut master = -1;
        let mut slave = -1;
        let mut ws = libc::winsize {
            ws_row: 24,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty fills two descriptors; the pointers are live locals.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut ws,
            )
        };
        assert_eq!(rc, 0, "openpty failed");
        // SAFETY: both descriptors are fresh and owned by nobody else.
        let (master, slave) = unsafe {
            (
                std::fs::File::from_raw_fd(master),
                std::fs::File::from_raw_fd(slave),
            )
        };
        Pty { master, slave }
    }

    fn resize(&self, cols: u16) {
        use std::os::fd::AsRawFd;
        let ws = libc::winsize {
            ws_row: 24,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ reads a winsize through a live pointer.
        let rc = unsafe { libc::ioctl(self.slave.as_raw_fd(), libc::TIOCSWINSZ as _, &ws) };
        assert_eq!(rc, 0);
    }

    /// Whatever the slave has written so far.
    fn read_available(&self) -> Vec<u8> {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        let fd = self.master.as_raw_fd();
        // SAFETY: plain fcntl flag manipulation on an owned descriptor.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        let mut master = &self.master;
        while let Ok(n) = master.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }
}

#[test]
fn the_width_comes_from_the_terminal_and_a_non_terminal_has_none() {
    use std::os::fd::AsRawFd;
    let pty = Pty::open(77);
    assert_eq!(columns_of_fd(pty.slave.as_raw_fd()), Some(77));
    pty.resize(133);
    assert_eq!(columns_of_fd(pty.slave.as_raw_fd()), Some(133));
    pty.resize(0);
    assert_eq!(
        columns_of_fd(pty.slave.as_raw_fd()),
        None,
        "0 columns is unknown"
    );
    let file = std::fs::File::open("/dev/null").unwrap();
    assert_eq!(
        columns_of_fd(file.as_raw_fd()),
        None,
        "not a terminal: ioctl fails"
    );
    assert_eq!(columns_of_fd(-1), None, "bad descriptor");
}

/// The surface of a pty slave, with the production width lookup.
struct PtySurface(std::fs::File);

impl Surface for PtySurface {
    fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.0.write_all(bytes)
    }
    fn columns(&mut self) -> Option<usize> {
        use std::os::fd::AsRawFd;
        columns_of_fd(self.0.as_raw_fd())
    }
}

#[test]
fn a_real_pty_receives_one_bounded_transient_line_and_is_left_clean() {
    let pty = Pty::open(20);
    let slave = pty.slave.try_clone().unwrap();
    let surface: SurfaceFactory =
        Arc::new(move || Box::new(PtySurface(slave.try_clone().unwrap())));
    let opts =
        ProgressOptions::new(ProgressMode::Tty).with_consumer_factory(consumer_factory(surface));
    let session = opts.begin(info(false));
    let sink = session.sink();
    sink.emit(&started(Stage::Resources, Some(7)));
    sink.emit(&progress(
        Stage::Resources,
        3,
        Some(7),
        item(ItemKind::Package, &"long-id-".repeat(20)),
    ));
    // The coalesced redraw is flushed by the worker's own wake-up (~100 ms).
    let mut got = Vec::new();
    wait_until("the long item to be drawn", || {
        got.extend(pty.read_available());
        String::from_utf8_lossy(&got).contains("apply 3/7 pack")
    });
    assert_eq!(
        session.end(RunOutcome::Completed),
        crate::progress_session::Teardown::Clean
    );
    got.extend(pty.read_available());
    let got = String::from_utf8(got).unwrap();
    assert!(got.starts_with(CLEAR), "{got:?}");
    assert!(got.ends_with(CLEAR), "{got:?}");
    for frame in got.split(CLEAR) {
        assert!(
            frame.chars().count() <= 19,
            "frame wider than the terminal: {frame:?}"
        );
        assert!(!frame.contains('\n'));
    }
    assert!(got.contains("apply 3/7 packag..."), "{got:?}");
    assert!(got.contains("..."), "the long id is shortened: {got:?}");
}

#[test]
fn a_normal_teardown_is_far_below_the_bound() {
    use crate::progress_session::{Teardown, DEFAULT_TEARDOWN_BOUND};
    let mem = Mem::new(Some(80));
    let opts = ProgressOptions::new(ProgressMode::Tty)
        .with_consumer_factory(consumer_factory(mem.factory()));
    let mut worst = Duration::ZERO;
    let mut total = Duration::ZERO;
    const RUNS: u32 = 200;
    for _ in 0..RUNS {
        let session = opts.begin(info(false));
        let sink = session.sink();
        sink.emit(&started(Stage::Connect, None));
        sink.emit(&ended(Stage::Connect, StageOutcome::Completed, 0));
        sink.emit(&started(Stage::Resources, Some(1)));
        sink.emit(&progress(
            Stage::Resources,
            0,
            Some(1),
            item(ItemKind::File, "a"),
        ));
        let t = Instant::now();
        assert_eq!(session.end(RunOutcome::Completed), Teardown::Clean);
        let took = t.elapsed();
        worst = worst.max(took);
        total += took;
    }
    println!(
        "teardown over {RUNS} sessions: mean {:?}, worst {:?} (bound {:?})",
        total / RUNS,
        worst,
        DEFAULT_TEARDOWN_BOUND
    );
    assert!(
        worst < DEFAULT_TEARDOWN_BOUND / 2,
        "worst normal teardown {worst:?} is not comfortably below the bound"
    );
}

#[test]
fn a_really_stalled_terminal_costs_one_bound_and_recovers_when_it_drains() {
    use crate::progress_session::Teardown;
    use std::os::fd::AsRawFd;
    let pty = Pty::open(80);
    // Fill the terminal's output buffer so the next blocking write stalls.
    {
        let fd = pty.slave.as_raw_fd();
        // SAFETY: plain fcntl flag changes on a descriptor this test owns.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        let chunk = [b'.'; 512];
        let mut slave = &pty.slave;
        let mut filled = 0usize;
        while slave.write(&chunk).is_ok() {
            filled += chunk.len();
            assert!(filled < 16 * 1024 * 1024, "the pty never filled up");
        }
        // SAFETY: as above, restoring blocking mode.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
    let slave = pty.slave.try_clone().unwrap();
    let surface: SurfaceFactory =
        Arc::new(move || Box::new(PtySurface(slave.try_clone().unwrap())));
    let opts = ProgressOptions::new(ProgressMode::Tty)
        .with_consumer_factory(consumer_factory(surface))
        .with_teardown_bound(ms(150));
    let session = opts.begin(info(false));
    session.sink().emit(&started(Stage::Connect, None));
    let t = Instant::now();
    let teardown = session.end(RunOutcome::Failed);
    let took = t.elapsed();
    assert_eq!(teardown, Teardown::Abandoned);
    assert!(
        took >= ms(150) && took < secs(3),
        "a stalled terminal must cost about one bound, took {took:?}"
    );
    // The terminal drains: the abandoned worker finishes its write, sees the
    // queued end of run and exits, leaving the erase as its last bytes.
    let mut seen = Vec::new();
    wait_until("the stalled worker to finish", || {
        seen.extend(pty.read_available());
        let s = String::from_utf8_lossy(&seen);
        s.contains("connect") && s.ends_with(CLEAR)
    });
}

// ---------------------------------------------------------------------------
// secret canary: the transient bytes of a real engine stream
// ---------------------------------------------------------------------------

const CANARIES: &[&str] = &[
    "CANARY-FILE-CONTENT-5d3a",
    "CANARY-VAR-VALUE-5d3a",
    "CANARY-CMD-ARG-5d3a",
    "CANARY-CMD-ENV-5d3a",
    "CANARY-CMD-PROGRAM-5d3a",
    "CANARYPATH5d3a",
    "CANARYBACKUP5d3a",
    "CANARYSECRETREF5d3a",
    "CANARY-LOOP-ITEM-5d3a",
    "CANARY-SVC-5d3a",
    "CANARY-SSH-USER-5d3a",
    "CANARY-SSH-KEY-5d3a",
    "CANARY-KNOWN-HOSTS-5d3a",
    "CANARY-REASON-5d3a",
    "CANARY-SECRET-PLAINTEXT-5d3a",
    "198.51.100.7",
];

fn canary_recipe(with_secret: bool) -> String {
    let acct = if with_secret {
        "  - id: acct\n    type: user\n    with:\n      name: app\n      password_hash: { secret: secrets/CANARYSECRETREF5d3a.age }\n"
    } else {
        ""
    };
    format!(
        r#"version: 1
vars:
  tok:
    value: CANARY-VAR-VALUE-5d3a
    sensitive: true
backup:
  paths: [/etc/perf/CANARYBACKUP5d3a]
resources:
  - id: plain
    type: file
    sensitive: true
    with:
      path: /etc/perf/CANARYPATH5d3a
      content: "CANARY-FILE-CONTENT-5d3a {{{{ vars.tok }}}}"
    notify: [restart_it]
  - id: looped
    type: file
    with:
      path: "/etc/perf/{{{{ item }}}}.conf"
      content: x
    loop: [CANARY-LOOP-ITEM-5d3a]
  - id: cmd
    type: command
    sensitive: true
    with:
      program: /opt/CANARY-CMD-PROGRAM-5d3a
      args: ["CANARY-CMD-ARG-5d3a"]
      env:
        K: CANARY-CMD-ENV-5d3a
{acct}  - id: after
    type: file
    with:
      path: /etc/perf/after
      content: x
handlers:
  - id: restart_it
    service: CANARY-SVC-5d3a.service
    action: restart
"#
    )
}

/// The events one real engine run produces (scripted target, canary-laden
/// recipe), framed by the run-level events the CLI adds.
fn engine_stream(
    mode: Option<crate::engine::Mode>,
    with_secret: bool,
) -> (RunKind, Vec<ProgressEvent>) {
    use crate::engine::{Engine, RunOptions, SshSpec, TargetSpec};
    use crate::executor::FakeTarget;
    use crate::progress::RecordingSink;
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("secrets")).unwrap();
    let id = crate::secrets::generate_identity();
    let ct = crate::secrets::encrypt_to_recipients(
        b"CANARY-SECRET-PLAINTEXT-5d3a",
        std::slice::from_ref(&id.recipient),
    )
    .unwrap();
    std::fs::write(dir.path().join("secrets/CANARYSECRETREF5d3a.age"), ct).unwrap();
    let recipe = dir.path().join("r.yaml");
    std::fs::write(&recipe, canary_recipe(with_secret)).unwrap();
    let target = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_fs_dir("/etc/perf")
        .with_executable("/opt/CANARY-CMD-PROGRAM-5d3a")
        .with_fs_file("/etc/perf/CANARYPATH5d3a", "CANARY-REASON-5d3a-old")
        .with_fs_dir("/var")
        .with_fs_dir("/var/lib")
        .with_fs_dir("/var/lib/sinter")
        .with_fs_dir("/etc/perf/CANARYBACKUP5d3a");
    let opts = RunOptions {
        mode: mode.unwrap_or(crate::engine::Mode::Plan),
        sudo: true,
        target: TargetSpec {
            ssh: Some(SshSpec {
                host: "198.51.100.7".into(),
                port: 2222,
                user: "CANARY-SSH-USER-5d3a".into(),
                known_hosts: "/nonexistent/CANARY-KNOWN-HOSTS-5d3a".into(),
                identity_files: vec!["/nonexistent/CANARY-SSH-KEY-5d3a".into()],
                ..Default::default()
            }),
        },
        verbose: false,
        fault: None,
        fake_target: Some(target),
    };
    let sink = RecordingSink::new();
    let model = crate::model::load_model(&recipe).unwrap();
    let engine = Engine::new_with_progress(model, opts, sink.clone()).unwrap();
    let kind = match mode {
        Some(crate::engine::Mode::Apply) => RunKind::Apply,
        Some(_) => RunKind::Plan,
        None => RunKind::Audit,
    };
    let _ = match mode {
        Some(_) => engine.run().map(|_| ()),
        None => crate::audit::run_audit(engine).map(|_| ()),
    };
    let mut events = vec![ProgressEvent::RunStarted { command: kind }];
    events.extend(sink.events());
    events.push(run_ended(RunOutcome::Completed));
    (kind, events)
}

#[test]
fn no_sensitive_value_reaches_the_transient_bytes_of_a_real_engine_stream() {
    use crate::engine::Mode;
    let declared = ["plain", "looped[0]", "cmd", "acct", "after", "restart_it"];
    for (mode, label) in [
        (Some(Mode::Plan), "plan"),
        (Some(Mode::Apply), "apply"),
        (None, "audit"),
    ] {
        for with_secret in [false, true] {
            let (kind, events) = engine_stream(mode, with_secret);
            let mem = Mem::new(Some(120));
            let t0 = Instant::now();
            let mut c = core(&mem, kind, t0);
            // Every event on its own redraw, and a long quiet spell after each
            // so the elapsed text is drawn too: the most the renderer can show.
            for (i, e) in events.iter().enumerate() {
                let t = t0 + ms(150 * (i as u64 + 1));
                c.on_event(e, t);
                c.tick(t + secs(7));
            }
            drop(c);
            let text = mem.text();
            for canary in CANARIES {
                assert!(
                    !text.contains(canary),
                    "{label} secret={with_secret}: {canary} leaked into {text:?}"
                );
            }
            assert!(is_printable_ascii(&text.replace(CLEAR, "")), "{text:?}");
            // Positive control: the run really drew its items, by declared id
            // only, so the absence above says something.
            assert!(text.contains("file:plain"), "{label}: {text:?}");
            assert!(text.contains("file:looped[0]"), "{label}: {text:?}");
            assert!(text.contains("command:cmd"), "{label}: {text:?}");
            assert!(text.contains(" 7s"), "{label}: elapsed was drawn: {text:?}");
            for frame in text.split(CLEAR) {
                for word in frame.split(|c: char| " :/".contains(c)) {
                    let known = [
                        "plan",
                        "apply",
                        "audit",
                        "connect",
                        "backup",
                        "handlers",
                        "failed",
                        "indeterminate",
                        "file",
                        "command",
                        "user",
                        "handler",
                        "7s",
                        "",
                    ];
                    let numeric = word.chars().all(|c| c.is_ascii_digit());
                    assert!(
                        known.contains(&word) || numeric || declared.contains(&word),
                        "{label}: unexpected word {word:?} in frame {frame:?}"
                    );
                }
            }
        }
    }
}
