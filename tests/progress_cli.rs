//! WP-PROGRESS S3: the CLI-layer progress plumbing (`progress_session`).
//!
//! Library-level proofs against the production engine and the scripted target:
//! the per-execution session lifecycle (`RunStarted` ... `RunEnded` on every
//! path), the channel hand-off and null consumer, bounded teardown, failure
//! isolation (a dead, panicking or blocked consumer never changes a result),
//! per-execution isolation, the mode decision and the outcome mapping.
//!
//! What the CLI binary prints is proven separately: `main.rs` unit tests drive
//! the real `run_phase` wiring, and `tests/progress_cli_output.rs` compares the
//! binary's bytes.
#![cfg(unix)]
mod common;

use common::*;
use sinter::audit::run_audit;
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, TargetSpec};
use sinter::error::{ErrorKind, SinterError};
use sinter::executor::FakeTarget;
use sinter::model::load_model;
use sinter::progress::{
    validate_stream, ProgressEvent, ProgressSink, RunKind, RunOutcome, Stage, StageOutcome,
};
use sinter::progress_session::{
    decide_mode, outcome_of_audit, outcome_of_error, outcome_of_report, references_secrets,
    ChannelSink, ModeInputs, NullConsumer, ProgressConsumer, ProgressMode, ProgressOptions,
    ProgressSession, SessionInfo, Teardown,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// scenario harness
// ---------------------------------------------------------------------------

fn base() -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_fs_dir("/etc/perf")
}

fn file(id: &str, path: &str, content: &str) -> String {
    format!("  - id: {id}\n    type: file\n    with:\n      path: {path}\n      content: \"{content}\"\n")
}

fn doc(resources: &[String]) -> String {
    let mut s = String::from("version: 1\nresources:\n");
    for r in resources {
        s.push_str(r);
    }
    if resources.is_empty() {
        s = "version: 1\nresources: []\n".to_string();
    }
    s
}

const BAD: &str = "  - id: bad\n    type: file\n    with:\n      path: /etc/perf/b\n      content: x\n    when: facts.os.family\n";
const PKG: &str = "  - id: p\n    type: package\n    with:\n      name: jq\n      state: present\n";

#[derive(Clone)]
struct Scenario {
    name: &'static str,
    dir: PathBuf,
    body: String,
    /// `None` runs an audit.
    mode: Option<Mode>,
    target: FakeTarget,
    fault: Option<&'static str>,
    /// What the CLI layer must report as the run outcome.
    expect: RunOutcome,
}

impl Scenario {
    fn new(
        name: &'static str,
        body: String,
        mode: Option<Mode>,
        target: FakeTarget,
        expect: RunOutcome,
    ) -> Self {
        Scenario {
            name,
            dir: trusted_root(name),
            body,
            mode,
            target,
            fault: None,
            expect,
        }
    }

    fn fault(mut self, f: &'static str) -> Self {
        self.fault = Some(f);
        self
    }

    fn kind(&self) -> RunKind {
        match self.mode {
            Some(Mode::Plan) => RunKind::Plan,
            Some(Mode::Apply) => RunKind::Apply,
            None => RunKind::Audit,
        }
    }

    fn opts(&self) -> RunOptions {
        RunOptions {
            mode: self.mode.unwrap_or(Mode::Plan),
            sudo: true,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: self.fault.map(|s| s.to_string()),
            fake_target: Some(self.target.clone()),
        }
    }

    fn model(&self) -> sinter::model::Model {
        write_recipe(&self.dir, "r.yaml", &self.body);
        load_model(&self.dir.join("r.yaml")).unwrap()
    }
}

fn commands_fp(cmds: &[sinter::executor::CommandRecord]) -> String {
    cmds.iter()
        .map(|c| {
            format!(
                "{} {:?} {:?} {} {}",
                c.program, c.args, c.env, c.sudo, c.sensitive
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Everything user-visible or contractual about an execution's result.
struct Done {
    fingerprint: String,
    outcome: RunOutcome,
    /// Total target commands (the command budget).
    commands: usize,
}

/// The execution exactly as `main.rs::execute` runs it, for an optional
/// session. `None` is the pre-S3 path (`Engine::new`).
fn execute(s: &Scenario, session: Option<&ProgressSession>) -> Done {
    execute_sink(s, session.map(|sess| sess.sink()))
}

fn execute_sink(s: &Scenario, sink: Option<Arc<dyn ProgressSink>>) -> Done {
    let model = s.model();
    let built = match sink {
        Some(sink) => Engine::new_with_progress(model, s.opts(), sink),
        None => Engine::new(model, s.opts()),
    };
    let engine = match built {
        Ok(e) => e.with_backup_run_id("20260101T000000Z-fixed000".to_string()),
        Err(e) => return failed(e, 0),
    };
    let handle = engine.exec_stats();
    match s.mode {
        Some(mode) => match engine.run() {
            Ok(rep) => {
                let label = if mode == Mode::Plan { "plan" } else { "apply" };
                let ro = sinter::output::RenderOptions {
                    verbose: true,
                    format: sinter::output::OutputFormat::Text,
                    color: false,
                };
                let mut text = Vec::new();
                if mode == Mode::Plan {
                    sinter::output::render_plan(&rep, &ro, &mut text).unwrap();
                } else {
                    sinter::output::render_apply(&rep, &ro, &mut text).unwrap();
                }
                Done {
                    fingerprint: format!(
                        "{:?}\n{}\n{}\n{}",
                        rep.status,
                        sinter::output::run_report_json(&rep, label),
                        String::from_utf8(text).unwrap(),
                        commands_fp(&rep.commands)
                    ),
                    outcome: outcome_of_report(&rep),
                    commands: handle.snapshot().total(),
                }
            }
            Err(e) => failed(e, handle.snapshot().total()),
        },
        None => match run_audit(engine) {
            Ok(rep) => Done {
                fingerprint: format!(
                    "{}\n{}\nexit={}\n{}",
                    sinter::output::audit_report_json(&rep),
                    rep.render_text(),
                    rep.exit_code(),
                    commands_fp(&rep.commands)
                ),
                outcome: outcome_of_audit(&rep),
                commands: handle.snapshot().total(),
            },
            Err(e) => failed(e, handle.snapshot().total()),
        },
    }
}

fn failed(e: SinterError, commands: usize) -> Done {
    Done {
        fingerprint: format!("ERR {:?} {}", e.kind, e.message),
        outcome: outcome_of_error(&e),
        commands,
    }
}

fn matrix() -> Vec<Scenario> {
    let mixed = || {
        base()
            .with_fs_file("/etc/perf/a", "x")
            .with_fs_file("/etc/perf/b", "old")
    };
    let mixed_doc = || {
        doc(&[
            file("a", "/etc/perf/a", "x"),
            file("b", "/etc/perf/b", "new"),
            file("c", "/etc/perf/c", "x"),
        ])
    };
    use RunOutcome::*;
    vec![
        Scenario::new("s3-plan", mixed_doc(), Some(Mode::Plan), mixed(), Completed),
        Scenario::new(
            "s3-apply",
            mixed_doc(),
            Some(Mode::Apply),
            mixed(),
            Completed,
        ),
        Scenario::new(
            "s3-converged",
            doc(&[file("a", "/etc/perf/a", "x")]),
            Some(Mode::Apply),
            base().with_fs_file("/etc/perf/a", "x"),
            Completed,
        ),
        Scenario::new("s3-empty", doc(&[]), Some(Mode::Apply), base(), Completed),
        Scenario::new(
            "s3-apply-fail",
            doc(&[file("a", "/etc/perf/a", "x"), file("b", "/etc/perf/b", "x")]),
            Some(Mode::Apply),
            base().with_fs_file("/etc/perf/a", "x"),
            Failed,
        )
        .fault("reobserve_fail"),
        Scenario::new(
            "s3-plan-error",
            doc(&[file("a", "/etc/perf/a", "x"), BAD.into()]),
            Some(Mode::Plan),
            base(),
            Failed,
        ),
        Scenario::new("s3-audit-drift", mixed_doc(), None, mixed(), Completed),
        Scenario::new(
            "s3-audit-error",
            doc(&[file("a", "/etc/perf/a", "x")]),
            None,
            FakeTarget::ubuntu2404(),
            Indeterminate,
        ),
        Scenario::new(
            "s3-connect-fail",
            doc(&[PKG.into()]),
            Some(Mode::Plan),
            FakeTarget::unsupported(),
            Failed,
        ),
    ]
}

// ---------------------------------------------------------------------------
// recording consumers
// ---------------------------------------------------------------------------

type Log = Arc<Mutex<Vec<ProgressEvent>>>;

struct Recorder {
    log: Log,
    live: Arc<AtomicUsize>,
}

impl ProgressConsumer for Recorder {
    fn consume(&mut self, event: &ProgressEvent) {
        self.log.lock().unwrap().push(event.clone());
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A production-shaped option set whose consumer records, plus the bookkeeping.
struct Harness {
    opts: ProgressOptions,
    logs: Arc<Mutex<Vec<Log>>>,
    infos: Arc<Mutex<Vec<SessionInfo>>>,
    /// Consumers created and not yet dropped.
    live: Arc<AtomicUsize>,
}

impl Harness {
    fn new(mode: ProgressMode) -> Self {
        let logs: Arc<Mutex<Vec<Log>>> = Arc::default();
        let infos: Arc<Mutex<Vec<SessionInfo>>> = Arc::default();
        let live = Arc::new(AtomicUsize::new(0));
        let (l, i, v) = (logs.clone(), infos.clone(), live.clone());
        let opts = ProgressOptions::new(mode).with_consumer_factory(Arc::new(move |info| {
            v.fetch_add(1, Ordering::SeqCst);
            i.lock().unwrap().push(*info);
            let log: Log = Arc::default();
            l.lock().unwrap().push(log.clone());
            Box::new(Recorder {
                log,
                live: v.clone(),
            })
        }));
        Harness {
            opts,
            logs,
            infos,
            live,
        }
    }

    /// One recorded stream per session started so far, in start order. Only
    /// meaningful once the sessions have ended.
    fn streams(&self) -> Vec<Vec<ProgressEvent>> {
        self.logs
            .lock()
            .unwrap()
            .iter()
            .map(|l| l.lock().unwrap().clone())
            .collect()
    }
}

fn info(kind: RunKind) -> SessionInfo {
    SessionInfo {
        kind,
        references_secrets: false,
    }
}

/// Run `s` inside one session and end it as `main.rs` does.
fn scoped(opts: &ProgressOptions, s: &Scenario) -> (Done, Teardown) {
    let session = opts.begin(info(s.kind()));
    let done = execute(s, Some(&session));
    let teardown = session.end(done.outcome);
    (done, teardown)
}

fn shape(events: &[ProgressEvent]) -> Vec<String> {
    events
        .iter()
        .map(|e| match e {
            ProgressEvent::RunStarted { command } => format!("run start {command:?}"),
            ProgressEvent::RunEnded { outcome } => format!("run end {outcome:?}"),
            ProgressEvent::StageStarted { stage, total } => {
                format!("{} start {total:?}", stage.label())
            }
            ProgressEvent::Progress {
                stage,
                done,
                total,
                current,
            } => format!(
                "{} {done}/{total:?} {}",
                stage.label(),
                current.as_ref().map(|c| c.id.as_str()).unwrap_or("-")
            ),
            ProgressEvent::StageEnded {
                stage,
                outcome,
                done,
            } => format!("{} end {outcome:?} {done}", stage.label()),
            _ => "other".to_string(),
        })
        .collect()
}

fn count(events: &[ProgressEvent], f: impl Fn(&ProgressEvent) -> bool) -> usize {
    events.iter().filter(|e| f(e)).count()
}

// ---------------------------------------------------------------------------
// 1-3: lifecycle
// ---------------------------------------------------------------------------

#[test]
fn every_execution_gets_exactly_one_run_started_and_one_run_ended() {
    for s in matrix() {
        let h = Harness::new(ProgressMode::Tty);
        let (done, teardown) = scoped(&h.opts, &s);
        assert_eq!(teardown, Teardown::Clean, "{}", s.name);
        assert_eq!(done.outcome, s.expect, "{}: outcome mapping", s.name);

        let streams = h.streams();
        assert_eq!(streams.len(), 1, "{}", s.name);
        let ev = &streams[0];
        validate_stream(ev).unwrap_or_else(|e| panic!("{}: {e}\n{:#?}", s.name, shape(ev)));
        assert_eq!(
            count(ev, |e| matches!(e, ProgressEvent::RunStarted { .. })),
            1,
            "{}",
            s.name
        );
        assert_eq!(
            count(ev, |e| matches!(e, ProgressEvent::RunEnded { .. })),
            1,
            "{}",
            s.name
        );
        assert_eq!(
            ev.first(),
            Some(&ProgressEvent::RunStarted { command: s.kind() }),
            "{}",
            s.name
        );
        assert_eq!(
            ev.last(),
            Some(&ProgressEvent::RunEnded { outcome: s.expect }),
            "{}",
            s.name
        );
        // The worker and its consumer are gone once `end` has returned.
        assert_eq!(h.live.load(Ordering::SeqCst), 0, "{}", s.name);
    }
}

#[test]
fn the_stream_through_the_channel_equals_the_stream_a_direct_sink_sees() {
    // Channel hand-off must neither lose, reorder nor invent events: the
    // consumer sees the engine's own events between the two run-level ones.
    for s in matrix() {
        let direct = sinter::progress::RecordingSink::new();
        let model = s.model();
        if let Ok(engine) = Engine::new_with_progress(model, s.opts(), direct.clone()) {
            match s.mode {
                Some(_) => drop(engine.run()),
                None => drop(run_audit(engine)),
            }
        }
        let h = Harness::new(ProgressMode::Tty);
        let _ = scoped(&h.opts, &s);
        let streamed = h.streams().remove(0);
        let inner = &streamed[1..streamed.len() - 1];
        assert_eq!(inner, direct.events().as_slice(), "{}", s.name);
    }
}

#[test]
fn an_err_that_skips_the_explicit_end_still_gets_run_ended() {
    // The RAII path: `?` leaves `main.rs` without calling `end`.
    let s = matrix()
        .into_iter()
        .find(|s| s.name == "s3-plan-error")
        .unwrap();
    let h = Harness::new(ProgressMode::Tty);
    {
        let session = h.opts.begin(info(RunKind::Plan));
        let _ = execute(&s, Some(&session));
        // dropped without `end`
    }
    let ev = h.streams().remove(0);
    validate_stream(&ev).unwrap();
    assert_eq!(
        ev.last(),
        Some(&ProgressEvent::RunEnded {
            outcome: RunOutcome::Failed
        })
    );
    assert_eq!(
        h.live.load(Ordering::SeqCst),
        0,
        "dropped session tears down"
    );
}

#[test]
fn a_connect_failure_is_a_complete_valid_lifecycle() {
    let s = matrix()
        .into_iter()
        .find(|s| s.name == "s3-connect-fail")
        .unwrap();
    let h = Harness::new(ProgressMode::Tty);
    let (done, _) = scoped(&h.opts, &s);
    assert!(
        done.fingerprint.starts_with("ERR Connect "),
        "{}",
        done.fingerprint
    );
    let ev = h.streams().remove(0);
    validate_stream(&ev).unwrap();
    assert_eq!(
        shape(&ev),
        vec![
            "run start Plan",
            "connect start None",
            "connect end Failed 0",
            "run end Failed"
        ]
    );
}

#[test]
fn a_returned_error_is_never_a_completed_run() {
    for kind in [
        ErrorKind::Schema,
        ErrorKind::Connect,
        ErrorKind::Plan,
        ErrorKind::Apply,
        ErrorKind::Unknown,
    ] {
        let e = SinterError {
            kind,
            message: "CANARY-ERROR-TEXT".into(),
            mutation: sinter::error::MutationState::None,
            backup: None,
        };
        assert_eq!(outcome_of_error(&e), RunOutcome::Failed, "{kind:?}");
    }
    assert_eq!(
        outcome_of_error(&SinterError::indeterminate("x")),
        RunOutcome::Indeterminate
    );
}

#[test]
fn every_aggregate_status_maps_to_a_closed_outcome() {
    let s = &matrix()[0];
    let model = s.model();
    let mut rep = Engine::new(model, s.opts()).unwrap().run().unwrap();
    for (status, want) in [
        (AggregateStatus::Success, RunOutcome::Completed),
        (AggregateStatus::PlanError, RunOutcome::Failed),
        (AggregateStatus::ApplyFailed, RunOutcome::Failed),
        (AggregateStatus::Indeterminate, RunOutcome::Indeterminate),
    ] {
        rep.status = status;
        assert_eq!(outcome_of_report(&rep), want, "{status:?}");
    }
}

// ---------------------------------------------------------------------------
// 4-6: mode
// ---------------------------------------------------------------------------

#[test]
fn mode_decision_follows_the_owner_policy() {
    let tty_text = ModeInputs {
        json: false,
        stderr_is_tty: true,
        term_is_dumb: false,
        plain_requested: false,
    };
    assert_eq!(decide_mode(&tty_text), ProgressMode::Tty);
    // non-TTY / CI: off by default
    assert_eq!(
        decide_mode(&ModeInputs {
            stderr_is_tty: false,
            ..tty_text
        }),
        ProgressMode::Disabled
    );
    // TERM=dumb
    assert_eq!(
        decide_mode(&ModeInputs {
            term_is_dumb: true,
            ..tty_text
        }),
        ProgressMode::Disabled
    );
    // JSON: off even on a terminal
    assert_eq!(
        decide_mode(&ModeInputs {
            json: true,
            ..tty_text
        }),
        ProgressMode::Disabled
    );
    // S5: only an explicit request turns plain progress on, wherever stderr
    // goes; JSON still wins over it.
    for (stderr_is_tty, term_is_dumb) in
        [(true, false), (true, true), (false, false), (false, true)]
    {
        let asked = ModeInputs {
            stderr_is_tty,
            term_is_dumb,
            plain_requested: true,
            ..tty_text
        };
        assert_eq!(decide_mode(&asked), ProgressMode::Plain, "{asked:?}");
        assert_eq!(
            decide_mode(&ModeInputs {
                json: true,
                ..asked
            }),
            ProgressMode::Disabled,
            "JSON must stay silent even when plain progress is requested: {asked:?}"
        );
    }
}

#[test]
fn a_disabled_session_has_no_consumer_no_worker_and_no_events() {
    let h = Harness::new(ProgressMode::Disabled);
    for s in matrix() {
        let session = h.opts.begin(info(s.kind()));
        assert!(!session.is_active(), "{}", s.name);
        let legacy = execute(&s, None);
        let done = execute(&s, Some(&session));
        assert_eq!(done.fingerprint, legacy.fingerprint, "{}", s.name);
        assert_eq!(done.commands, legacy.commands, "{}", s.name);
        assert_eq!(session.end(done.outcome), Teardown::Inert);
    }
    assert!(h.infos.lock().unwrap().is_empty(), "no consumer was built");
    assert!(h.streams().is_empty());
}

#[test]
fn the_production_null_consumer_is_silent_and_changes_nothing() {
    // `ProgressOptions::new(Tty)` is what the CLI builds on a terminal.
    let opts = ProgressOptions::new(ProgressMode::Tty);
    for s in matrix() {
        let legacy = execute(&s, None);
        let (done, teardown) = scoped(&opts, &s);
        assert_eq!(teardown, Teardown::Clean, "{}", s.name);
        assert_eq!(done.fingerprint, legacy.fingerprint, "{}", s.name);
        assert_eq!(done.commands, legacy.commands, "{}: command budget", s.name);
    }
    let mut c = NullConsumer;
    c.consume(&ProgressEvent::RunEnded {
        outcome: RunOutcome::Completed,
    });
}

/// S5: the production plain renderer, installed the way the CLI installs it in
/// `Plain` mode, changes no result and adds no target command in any scenario,
/// and what it writes is whole `progress:` lines only.
#[test]
fn the_plain_renderer_changes_no_result_and_adds_no_command() {
    use sinter::progress_plain::plain_consumer_factory;
    use sinter::progress_tty::Surface;

    struct Lines(Arc<Mutex<Vec<u8>>>);
    impl Surface for Lines {
        fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(())
        }
        fn columns(&mut self) -> Option<usize> {
            None
        }
    }

    let written = Arc::new(Mutex::new(Vec::new()));
    let sink_bytes = written.clone();
    let opts = ProgressOptions::new(ProgressMode::Plain).with_consumer_factory(
        plain_consumer_factory(Arc::new(move || Box::new(Lines(sink_bytes.clone())))),
    );
    for s in matrix() {
        let legacy = execute(&s, None);
        written.lock().unwrap().clear();
        let (done, teardown) = scoped(&opts, &s);
        assert_eq!(teardown, Teardown::Clean, "{}", s.name);
        assert_eq!(done.fingerprint, legacy.fingerprint, "{}", s.name);
        assert_eq!(done.commands, legacy.commands, "{}: command budget", s.name);
        let text = String::from_utf8(written.lock().unwrap().clone()).unwrap();
        assert!(text.ends_with('\n'), "{}: {text:?}", s.name);
        assert!(
            text.bytes()
                .all(|b| (0x20..=0x7e).contains(&b) || b == b'\n'),
            "{}: {text:?}",
            s.name
        );
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines.iter().all(|l| l.starts_with("progress: ")),
            "{}",
            s.name
        );
        assert!(lines.len() <= 20, "{}: {} lines", s.name, lines.len());
        assert!(
            lines
                .first()
                .is_some_and(|l| l.starts_with("progress: run: ")),
            "{}: {lines:?}",
            s.name
        );
        assert!(
            lines
                .last()
                .is_some_and(|l| l.starts_with("progress: run: ")),
            "{}: {lines:?}",
            s.name
        );
    }
}

// ---------------------------------------------------------------------------
// 7-11: isolation and teardown
// ---------------------------------------------------------------------------

#[test]
fn a_vanished_receiver_does_not_affect_execution() {
    for s in matrix() {
        let legacy = execute(&s, None);
        // The receiving end is dropped before the engine starts.
        let (sink, rx) = ChannelSink::channel();
        drop(rx);
        let done = execute_sink(&s, Some(Arc::new(sink)));
        assert_eq!(done.fingerprint, legacy.fingerprint, "{}", s.name);
        assert_eq!(done.commands, legacy.commands, "{}", s.name);
    }
}

/// Panics on its first event, killing its worker.
struct Panicker;

impl ProgressConsumer for Panicker {
    fn consume(&mut self, _event: &ProgressEvent) {
        panic!("test: renderer bug");
    }
}

#[test]
fn a_panicking_worker_does_not_affect_execution() {
    let opts = ProgressOptions::new(ProgressMode::Tty)
        .with_consumer_factory(Arc::new(|_| Box::new(Panicker)));
    for s in matrix() {
        let legacy = execute(&s, None);
        let (done, teardown) = scoped(&opts, &s);
        assert_eq!(teardown, Teardown::WorkerPanicked, "{}", s.name);
        assert_eq!(done.fingerprint, legacy.fingerprint, "{}", s.name);
        assert_eq!(done.commands, legacy.commands, "{}", s.name);
        assert_eq!(done.outcome, s.expect, "{}", s.name);
    }
}

/// Holds its worker inside `consume` until the test releases it.
struct Blocker {
    release: Mutex<mpsc::Receiver<()>>,
    dropped: mpsc::Sender<()>,
}

impl ProgressConsumer for Blocker {
    fn consume(&mut self, _event: &ProgressEvent) {
        // Ends when the test sends, or when the test's sender is gone.
        let _ = self.release.lock().unwrap().recv();
    }
}

impl Drop for Blocker {
    fn drop(&mut self) {
        let _ = self.dropped.send(());
    }
}

#[test]
fn teardown_is_bounded_and_a_blocked_consumer_never_blocks_the_run() {
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (dropped_tx, dropped_rx) = mpsc::channel::<()>();
    let slot = Mutex::new(Some(Blocker {
        release: Mutex::new(release_rx),
        dropped: dropped_tx,
    }));
    let bound = Duration::from_millis(100);
    let opts = ProgressOptions::new(ProgressMode::Tty)
        .with_teardown_bound(bound)
        .with_consumer_factory(Arc::new(move |_| {
            Box::new(slot.lock().unwrap().take().expect("one session")) as Box<_>
        }));

    let s = matrix().remove(1); // apply
    let legacy = execute(&s, None);

    // The consumer is blocked on RunStarted; the whole run still completes
    // (the channel is unbounded) with the identical result.
    let session = opts.begin(info(s.kind()));
    let done = execute(&s, Some(&session));
    assert_eq!(done.fingerprint, legacy.fingerprint);

    let started = Instant::now();
    let teardown = session.end(done.outcome);
    let waited = started.elapsed();
    assert_eq!(teardown, Teardown::Abandoned);
    assert!(waited >= bound, "waited the whole bound: {waited:?}");
    assert!(
        waited < Duration::from_secs(10),
        "teardown must be bounded, took {waited:?}"
    );

    // Release the stuck worker: it drains the queue, sees RunEnded and exits.
    // Each queued event needs one release.
    for _ in 0..10_000 {
        if release_tx.send(()).is_err() {
            break;
        }
        if dropped_rx.try_recv().is_ok() {
            return;
        }
        std::thread::yield_now();
    }
    dropped_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the abandoned worker exits once unblocked");
}

#[test]
fn repeated_sessions_do_not_accumulate_workers() {
    let h = Harness::new(ProgressMode::Tty);
    let s = matrix().remove(0);
    for i in 0..300 {
        let session = h.opts.begin(info(RunKind::Plan));
        assert!(session.is_active());
        let done = execute(&s, Some(&session));
        assert_eq!(session.end(done.outcome), Teardown::Clean, "session {i}");
        assert_eq!(
            h.live.load(Ordering::SeqCst),
            0,
            "session {i}: its worker and consumer are gone after `end`"
        );
    }
    assert_eq!(h.streams().len(), 300);
}

#[test]
fn events_after_run_ended_are_discarded_without_panic() {
    let h = Harness::new(ProgressMode::Tty);
    let session = h.opts.begin(info(RunKind::Plan));
    let late = session.sink();
    assert_eq!(session.end(RunOutcome::Completed), Teardown::Clean);
    for _ in 0..3 {
        late.emit(&ProgressEvent::RunEnded {
            outcome: RunOutcome::Failed,
        });
    }
    let ev = h.streams().remove(0);
    assert_eq!(
        shape(&ev),
        vec!["run start Plan", "run end Completed"],
        "nothing after RunEnded"
    );
}

#[test]
fn a_panicking_run_neither_waits_nor_emits_and_the_worker_still_exits() {
    let h = Harness::new(ProgressMode::Tty);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _session = h.opts.begin(info(RunKind::Apply));
        panic!("test: engine panic");
    }));
    assert!(r.is_err());
    // Drop was silent while unwinding: the stream has no RunEnded (the
    // documented exception), yet the worker exits by itself on the closed
    // channel and drops its consumer.
    let deadline = Instant::now() + Duration::from_secs(10);
    while h.live.load(Ordering::SeqCst) != 0 {
        assert!(Instant::now() < deadline, "worker did not exit");
        std::thread::yield_now();
    }
    assert_eq!(shape(&h.streams().remove(0)), vec!["run start Apply"]);
}

// ---------------------------------------------------------------------------
// 12: per-execution scoping
// ---------------------------------------------------------------------------

#[test]
fn sequential_executions_have_independent_valid_streams() {
    let h = Harness::new(ProgressMode::Tty);
    let all = matrix();
    for s in &all {
        let _ = scoped(&h.opts, s);
    }
    let streams = h.streams();
    assert_eq!(streams.len(), all.len());
    for (s, ev) in all.iter().zip(&streams) {
        validate_stream(ev).unwrap_or_else(|e| panic!("{}: {e}", s.name));
        assert_eq!(
            count(ev, |e| matches!(e, ProgressEvent::RunStarted { .. })),
            1
        );
        assert_eq!(
            count(ev, |e| matches!(e, ProgressEvent::RunEnded { .. })),
            1
        );
    }
}

#[test]
fn concurrent_executions_do_not_cross_talk() {
    // Four executions on four threads at once, each with its own session and
    // its own uniquely named resources: each stream holds only its own ids.
    let handles: Vec<_> = (0..4)
        .map(|n| {
            std::thread::spawn(move || {
                let h = Harness::new(ProgressMode::Tty);
                let ids: Vec<String> = (0..6).map(|i| format!("t{n}r{i}")).collect();
                let body = doc(&ids
                    .iter()
                    .map(|id| file(id, &format!("/etc/perf/{id}"), "x"))
                    .collect::<Vec<_>>());
                let s = Scenario::new(
                    Box::leak(format!("s3-xtalk-{n}").into_boxed_str()),
                    body,
                    Some(Mode::Plan),
                    base(),
                    RunOutcome::Completed,
                );
                for _ in 0..25 {
                    let _ = scoped(&h.opts, &s);
                }
                (ids, h.streams())
            })
        })
        .collect();
    for t in handles {
        let (ids, streams) = t.join().unwrap();
        assert_eq!(streams.len(), 25);
        for ev in streams {
            validate_stream(&ev).unwrap();
            let seen: Vec<&str> = ev
                .iter()
                .filter_map(|e| match e {
                    ProgressEvent::Progress {
                        current: Some(c), ..
                    } => Some(c.id.as_str()),
                    _ => None,
                })
                .collect();
            assert_eq!(seen.len(), ids.len());
            assert!(
                seen.iter().all(|id| ids.iter().any(|mine| mine == id)),
                "{seen:?} vs {ids:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// resolve stage
// ---------------------------------------------------------------------------

#[test]
fn the_resolve_stage_precedes_connect_in_the_same_valid_stream() {
    let h = Harness::new(ProgressMode::Tty);
    let s = matrix().remove(0);
    let session = h.opts.begin(info(RunKind::Plan));
    let mut stage = session.resolve_stage(2);
    stage.host_started();
    stage.host_started();
    stage.end();
    let done = execute(&s, Some(&session));
    session.end(done.outcome);
    let ev = h.streams().remove(0);
    validate_stream(&ev).unwrap();
    assert_eq!(
        shape(&ev)[..6],
        [
            "run start Plan",
            "resolve start Some(2)",
            "resolve 0/Some(2) -",
            "resolve 1/Some(2) -",
            "resolve end Completed 2",
            "connect start None",
        ]
    );
    assert_eq!(
        ev.iter()
            .find_map(|e| match e {
                ProgressEvent::StageStarted { stage, .. } => Some(*stage),
                _ => None,
            })
            .unwrap(),
        Stage::Resolve
    );
}

#[test]
fn an_abandoned_resolve_stage_ends_failed_and_the_run_still_ends() {
    let h = Harness::new(ProgressMode::Tty);
    let session = h.opts.begin(info(RunKind::Audit));
    {
        let mut stage = session.resolve_stage(3);
        stage.host_started();
        // `?` out of the resolution code: dropped without `end`
    }
    session.end(RunOutcome::Failed);
    let ev = h.streams().remove(0);
    validate_stream(&ev).unwrap();
    assert_eq!(
        shape(&ev),
        vec![
            "run start Audit",
            "resolve start Some(3)",
            "resolve 0/Some(3) -",
            "resolve end Failed 1",
            "run end Failed",
        ]
    );
    assert!(ev.iter().any(|e| matches!(
        e,
        ProgressEvent::StageEnded {
            outcome: StageOutcome::Failed,
            ..
        }
    )));
}

// ---------------------------------------------------------------------------
// secrets information (OQ-5 plumbing)
// ---------------------------------------------------------------------------

#[test]
fn secret_references_are_reported_to_the_consumer_and_nothing_is_displayed() {
    let dir = trusted_root("s3-secret-info");
    std::fs::create_dir_all(dir.join("secrets")).unwrap();
    let id = sinter::secrets::generate_identity();
    let ct = sinter::secrets::encrypt_to_recipients(
        b"S3-CANARY-SECRET-PLAINTEXT",
        std::slice::from_ref(&id.recipient),
    )
    .unwrap();
    std::fs::write(dir.join("secrets/S3CANARYREF.age"), ct).unwrap();
    let with = write_recipe(
        &dir,
        "with.yaml",
        "version: 1\nresources:\n  - id: acct\n    type: user\n    with:\n      name: app\n      password_hash: { secret: secrets/S3CANARYREF.age }\n",
    );
    let without = write_recipe(&dir, "without.yaml", &doc(&[file("a", "/etc/perf/a", "x")]));
    let (m_with, m_without) = (load_model(&with).unwrap(), load_model(&without).unwrap());
    assert!(references_secrets(&m_with));
    assert!(!references_secrets(&m_without));

    // The flag reaches the consumer factory; the stream and the run output
    // contain no secret data (a stream cannot carry any by construction).
    let h = Harness::new(ProgressMode::Tty);
    let session = h.opts.begin(SessionInfo {
        kind: RunKind::Plan,
        references_secrets: references_secrets(&m_with),
    });
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo: true,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(base()),
    };
    // No key for the secret: the plan fails closed, as in production.
    let result = Engine::new_with_progress(m_with, opts, session.sink()).and_then(|e| e.run());
    let outcome = match &result {
        Ok(r) => outcome_of_report(r),
        Err(e) => outcome_of_error(e),
    };
    session.end(outcome);
    assert_eq!(
        h.infos.lock().unwrap().as_slice(),
        &[SessionInfo {
            kind: RunKind::Plan,
            references_secrets: true
        }]
    );
    let ev = h.streams().remove(0);
    validate_stream(&ev).unwrap();
    let text = format!("{ev:?}");
    for canary in ["S3CANARYREF", "S3-CANARY-SECRET-PLAINTEXT", "secrets/"] {
        assert!(!text.contains(canary), "{canary} in {text}");
    }
}
