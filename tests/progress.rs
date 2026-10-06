//! WP-PROGRESS S1/S2: the internal progress event stream.
//!
//! Everything here runs the production engine against the scripted target
//! (`FakeTarget`), so the event sequences are deterministic and need no SSH.
//! Three kinds of proof:
//!
//! * the stream's lifecycle invariants hold on every path
//!   (`progress::validate_stream`), and the counters mean what the module
//!   documentation says they mean;
//! * a sink only observes: reports, errors, audit results, resource order,
//!   target-command counts and the command log are identical with the legacy
//!   `Engine::new`, a `NoopSink`, a `RecordingSink` and an observer that has
//!   already gone away;
//! * no sensitive value can appear in the stream (canary test).
#![cfg(unix)]
mod common;

use common::*;
use sinter::audit::{run_audit, AuditReport};
use sinter::engine::{Engine, Mode, RunOptions, RunReport, SshSpec, TargetSpec};
use sinter::error::{ErrorKind, SinterError};
use sinter::executor::{Completion, FakeTarget};
use sinter::model::load_model;
use sinter::progress::{
    validate_stream, ItemKind, NoopSink, ProgressEvent, ProgressSink, RecordingSink, Stage,
    StageOutcome,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn base() -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_fs_dir("/etc/perf")
}

/// A target that can hold a backup store (`--sudo`: `/var/lib/sinter/backups`).
fn with_store(t: FakeTarget) -> FakeTarget {
    t.with_fs_dir("/var")
        .with_fs_dir("/var/lib")
        .with_fs_dir("/var/lib/sinter")
}

fn file(id: &str, path: &str, content: &str) -> String {
    format!("  - id: {id}\n    type: file\n    with:\n      path: {path}\n      content: \"{content}\"\n")
}

fn doc(resources: &[String]) -> String {
    if resources.is_empty() {
        return "version: 1\nresources: []\n".to_string();
    }
    let mut s = String::from("version: 1\nresources:\n");
    for r in resources {
        s.push_str(r);
    }
    s
}

#[derive(Clone)]
struct Scenario {
    name: &'static str,
    /// One directory per scenario, so every run of it sees the same paths.
    dir: PathBuf,
    /// Written as `r.yaml`.
    body: String,
    /// Further files next to it (includes).
    extra: Vec<(&'static str, String)>,
    /// `None` runs an audit.
    mode: Option<Mode>,
    target: FakeTarget,
    fault: Option<&'static str>,
}

impl Scenario {
    fn new(name: &'static str, body: String, mode: Option<Mode>, target: FakeTarget) -> Self {
        Scenario {
            name,
            dir: trusted_root(name),
            body,
            extra: Vec::new(),
            mode,
            target,
            fault: None,
        }
    }

    fn fault(mut self, f: &'static str) -> Self {
        self.fault = Some(f);
        self
    }

    fn path(&self) -> PathBuf {
        for (n, c) in &self.extra {
            write_recipe(&self.dir, n, c);
        }
        write_recipe(&self.dir, "r.yaml", &self.body)
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
}

#[derive(Clone, Copy)]
enum Via {
    /// `Engine::new`, the path every existing caller uses.
    Legacy,
    Noop,
    Recording,
    /// A channel-backed sink whose receiver is already gone.
    DroppedObserver,
}

/// A channel sink that discards `SendError`, as the contract requires.
struct ChannelSink(Mutex<mpsc::Sender<ProgressEvent>>);

impl ProgressSink for ChannelSink {
    fn emit(&self, event: &ProgressEvent) {
        if let Ok(tx) = self.0.lock() {
            let _ = tx.send(event.clone());
        }
    }
}

/// (total commands, by scope, by program)
type CommandCounts = (usize, BTreeMap<String, usize>, BTreeMap<String, usize>);

struct Observed {
    /// Everything user-visible or contractual about the outcome.
    fingerprint: String,
    stats: Option<CommandCounts>,
    events: Vec<ProgressEvent>,
}

fn describe_err(e: &SinterError) -> String {
    format!("ERR {:?} {}", e.kind, e.message)
}

fn commands_fingerprint(cmds: &[sinter::executor::CommandRecord]) -> String {
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

fn render_run(rep: &RunReport, mode: Mode) -> String {
    let label = if mode == Mode::Plan { "plan" } else { "apply" };
    let mut text = Vec::new();
    let ro = sinter::output::RenderOptions {
        verbose: true,
        format: sinter::output::OutputFormat::Text,
        color: false,
    };
    if mode == Mode::Plan {
        sinter::output::render_plan(rep, &ro, &mut text).unwrap();
    } else {
        sinter::output::render_apply(rep, &ro, &mut text).unwrap();
    }
    format!(
        "{:?}\n{}\n{}\n{}\nresources={:?}\ncommands:\n{}",
        rep.status,
        sinter::output::run_report_json(rep, label),
        String::from_utf8(text).unwrap(),
        rep.manager_reloads.len(),
        rep.resources
            .iter()
            .map(|r| r.id.clone())
            .collect::<Vec<_>>(),
        commands_fingerprint(&rep.commands),
    )
}

fn render_audit(rep: &AuditReport) -> String {
    format!(
        "{}\n{}\nexit={}\ncommands:\n{}",
        sinter::output::audit_report_json(rep),
        rep.render_text(),
        rep.exit_code(),
        commands_fingerprint(&rep.commands),
    )
}

fn observe(s: &Scenario, via: Via) -> Observed {
    let model = load_model(&s.path()).unwrap();
    let recording = RecordingSink::new();
    let built = match via {
        Via::Legacy => Engine::new(model, s.opts()),
        Via::Noop => Engine::new_with_progress(model, s.opts(), Arc::new(NoopSink)),
        Via::Recording => Engine::new_with_progress(model, s.opts(), recording.clone()),
        Via::DroppedObserver => {
            let (tx, rx) = mpsc::channel();
            drop(rx);
            Engine::new_with_progress(model, s.opts(), Arc::new(ChannelSink(Mutex::new(tx))))
        }
    };
    let engine = match built {
        // One fixed id: the generated one is random and ends up in messages.
        Ok(e) => e.with_backup_run_id("20260101T000000Z-fixed000".to_string()),
        Err(e) => {
            return Observed {
                fingerprint: describe_err(&e),
                stats: None,
                events: recording.events(),
            }
        }
    };
    let handle = engine.exec_stats();
    let fingerprint = match s.mode {
        Some(mode) => match engine.run() {
            Ok(rep) => render_run(&rep, mode),
            Err(e) => describe_err(&e),
        },
        None => match run_audit(engine) {
            Ok(rep) => render_audit(&rep),
            Err(e) => describe_err(&e),
        },
    };
    let snap = handle.snapshot();
    Observed {
        fingerprint,
        stats: Some((
            snap.total(),
            snap.by_scope()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            snap.by_program(),
        )),
        events: recording.events(),
    }
}

fn events_of(s: &Scenario) -> Vec<ProgressEvent> {
    let o = observe(s, Via::Recording);
    validate_stream(&o.events).unwrap_or_else(|e| panic!("{}: {e}\n{:#?}", s.name, o.events));
    o.events
}

/// One line per event; compact enough to assert whole sequences.
fn shape(events: &[ProgressEvent]) -> Vec<String> {
    events
        .iter()
        .map(|e| match e {
            ProgressEvent::StageStarted { stage, total } => {
                format!("{} start total={:?}", stage.label(), total)
            }
            ProgressEvent::Progress {
                stage,
                done,
                total,
                current,
            } => format!(
                "{} item {}/{:?} {}",
                stage.label(),
                done,
                total,
                current
                    .as_ref()
                    .map(|c| format!("{}:{}", c.kind.label(), c.id))
                    .unwrap_or_else(|| "-".into())
            ),
            ProgressEvent::StageEnded {
                stage,
                outcome,
                done,
            } => format!("{} end {:?} done={}", stage.label(), outcome, done),
            other => format!("{:?}", other),
        })
        .collect()
}

fn connect_ok() -> Vec<String> {
    vec![
        "connect start total=None".into(),
        "connect end Completed done=0".into(),
    ]
}

fn with_connect(rest: &[&str]) -> Vec<String> {
    let mut v = connect_ok();
    v.extend(rest.iter().map(|s| s.to_string()));
    v
}

fn stages_started(events: &[ProgressEvent]) -> Vec<Stage> {
    events
        .iter()
        .filter_map(|e| match e {
            ProgressEvent::StageStarted { stage, .. } => Some(*stage),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// connect
// ---------------------------------------------------------------------------

#[test]
fn construction_reports_the_connect_stage_with_no_total() {
    let s = Scenario::new("pg-connect", doc(&[]), Some(Mode::Plan), base());
    let sink = RecordingSink::new();
    let e = Engine::new_with_progress(load_model(&s.path()).unwrap(), s.opts(), sink.clone());
    assert!(e.is_ok());
    assert_eq!(shape(&sink.events()), connect_ok());
    validate_stream(&sink.events()).unwrap();
}

#[test]
fn connect_failure_ends_the_connect_stage_and_returns_the_unchanged_error() {
    // A target the engine connects to but cannot use: the failure happens
    // inside the constructor, after StageStarted(connect).
    let pkg = "  - id: p\n    type: package\n    with:\n      name: jq\n      state: present\n";
    let s = Scenario::new(
        "pg-connect-unsupported",
        doc(&[pkg.to_string()]),
        Some(Mode::Plan),
        FakeTarget::unsupported(),
    );
    let legacy = observe(&s, Via::Legacy);
    let recorded = observe(&s, Via::Recording);
    assert!(
        legacy.fingerprint.starts_with("ERR Connect "),
        "{}",
        legacy.fingerprint
    );
    assert_eq!(
        legacy.fingerprint, recorded.fingerprint,
        "error must be unchanged"
    );
    assert_eq!(
        shape(&recorded.events),
        vec![
            "connect start total=None".to_string(),
            "connect end Failed done=0".to_string()
        ]
    );
    validate_stream(&recorded.events).unwrap();
}

#[test]
fn early_ssh_connect_failure_ends_the_connect_stage() {
    // Nothing listens on port 1: the executor cannot even be built, the
    // earliest failure point of the constructor. The SSH details below must
    // not surface in any event.
    let dir = trusted_root("pg-ssh-refused");
    let recipe = write_recipe(&dir, "r.yaml", &doc(&[]));
    let known_hosts = dir.join("known_hosts");
    std::fs::write(&known_hosts, "").unwrap();
    let opts = || RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: TargetSpec {
            ssh: Some(SshSpec {
                host: "127.0.0.1".into(),
                port: 1,
                user: "canary-ssh-user-4471".into(),
                known_hosts: known_hosts.clone(),
                identity_files: vec![PathBuf::from("/nonexistent/canary-identity-4471")],
                ..Default::default()
            }),
        },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let legacy = Engine::new(load_model(&recipe).unwrap(), opts())
        .err()
        .expect("nothing listens on port 1");
    let sink = RecordingSink::new();
    let err = Engine::new_with_progress(load_model(&recipe).unwrap(), opts(), sink.clone())
        .err()
        .expect("nothing listens on port 1");
    assert_eq!(err.kind, ErrorKind::Connect);
    assert_eq!((err.kind, &err.message), (legacy.kind, &legacy.message));
    assert_eq!(
        shape(&sink.events()),
        vec![
            "connect start total=None".to_string(),
            "connect end Failed done=0".to_string()
        ]
    );
    let shown = format!("{:?}", sink.events());
    assert!(
        !shown.contains("canary") && !shown.contains("127.0.0.1"),
        "{shown}"
    );
}

// ---------------------------------------------------------------------------
// resources: ordering and counters
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_connect_then_one_resources_stage() {
    let t = base()
        .with_fs_file("/etc/perf/a", "x")
        .with_fs_file("/etc/perf/b", "old");
    let s = Scenario::new(
        "pg-plan",
        doc(&[
            file("a", "/etc/perf/a", "x"),
            file("b", "/etc/perf/b", "new"),
            file("c", "/etc/perf/c", "x"),
        ]),
        Some(Mode::Plan),
        t,
    );
    let ev = events_of(&s);
    assert_eq!(
        shape(&ev),
        with_connect(&[
            "resources start total=Some(3)",
            "resources item 0/Some(3) file:a",
            "resources item 1/Some(3) file:b",
            "resources item 2/Some(3) file:c",
            "resources end Completed done=3",
        ])
    );
    // Plan has no backup stage and never runs handlers.
    assert_eq!(stages_started(&ev), vec![Stage::Connect, Stage::Resources]);
}

#[test]
fn empty_recipe_runs_an_empty_resources_stage() {
    for mode in [Mode::Plan, Mode::Apply] {
        let s = Scenario::new("pg-empty", doc(&[]), Some(mode), base());
        assert_eq!(
            shape(&events_of(&s)),
            with_connect(&[
                "resources start total=Some(0)",
                "resources end Completed done=0"
            ])
        );
    }
    let s = Scenario::new("pg-empty-audit", doc(&[]), None, base());
    assert_eq!(
        shape(&events_of(&s)),
        with_connect(&[
            "resources start total=Some(0)",
            "resources end Completed done=0"
        ])
    );
}

#[test]
fn single_resource_counts_to_one_of_one() {
    let s = Scenario::new(
        "pg-one",
        doc(&[file("only", "/etc/perf/only", "x")]),
        Some(Mode::Apply),
        base(),
    );
    assert_eq!(
        shape(&events_of(&s)),
        with_connect(&[
            "resources start total=Some(1)",
            "resources item 0/Some(1) file:only",
            "resources end Completed done=1",
        ])
    );
}

#[test]
fn skipped_and_dependency_blocked_items_reach_a_terminal_disposition() {
    use sinter::result::Disposition;
    let off = "  - id: off\n    type: file\n    with:\n      path: /etc/perf/a\n      content: x\n    when: facts.os.family == \"redhat\"\n";
    let dep = "  - id: dep\n    type: file\n    depends_on: [off]\n    with:\n      path: /etc/perf/b\n      content: x\n";
    let s = Scenario::new(
        "pg-skip-block",
        doc(&[off.into(), dep.into(), file("c", "/etc/perf/c", "x")]),
        Some(Mode::Plan),
        base(),
    );
    // Positive control: the scenario really contains a skip and a block.
    let rep = {
        let e = Engine::new(load_model(&s.path()).unwrap(), s.opts()).unwrap();
        e.run().unwrap()
    };
    assert_eq!(
        find(&rep, "off").disposition,
        Disposition::SkippedByCondition
    );
    assert_eq!(
        find(&rep, "dep").disposition,
        Disposition::BlockedByDependency
    );
    assert_eq!(
        shape(&events_of(&s)),
        with_connect(&[
            "resources start total=Some(3)",
            "resources item 0/Some(3) file:off",
            "resources item 1/Some(3) file:dep",
            "resources item 2/Some(3) file:c",
            "resources end Completed done=3",
        ])
    );
}

#[test]
fn loop_expanded_resources_are_counted_by_instance_and_never_name_the_item() {
    let body = "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: \"/etc/perf/{{ item }}.conf\"\n      content: x\n    loop: [CANARY-LOOP-A, CANARY-LOOP-B, CANARY-LOOP-C]\n";
    let s = Scenario::new("pg-loop", body.into(), Some(Mode::Plan), base());
    let ev = events_of(&s);
    assert_eq!(
        shape(&ev),
        with_connect(&[
            "resources start total=Some(3)",
            "resources item 0/Some(3) file:f[0]",
            "resources item 1/Some(3) file:f[1]",
            "resources item 2/Some(3) file:f[2]",
            "resources end Completed done=3",
        ])
    );
    assert!(!format!("{ev:?}").contains("CANARY-LOOP"));
}

#[test]
fn include_expanded_resources_are_part_of_the_total() {
    let mut s = Scenario::new(
        "pg-include",
        format!(
            "version: 1\ninclude: [base.yaml]\nresources:\n{}",
            file("main", "/etc/perf/m", "x")
        ),
        Some(Mode::Plan),
        base(),
    );
    s.extra.push((
        "base.yaml",
        format!(
            "version: 1\nresources:\n{}{}",
            file("inc1", "/etc/perf/i1", "x"),
            file("inc2", "/etc/perf/i2", "x")
        ),
    ));
    let ev = events_of(&s);
    let total = ev.iter().find_map(|e| match e {
        ProgressEvent::StageStarted {
            stage: Stage::Resources,
            total,
        } => *total,
        _ => None,
    });
    assert_eq!(total, Some(3), "{:#?}", shape(&ev));
    assert!(matches!(
        ev.last(),
        Some(ProgressEvent::StageEnded {
            stage: Stage::Resources,
            outcome: StageOutcome::Completed,
            done: 3
        })
    ));
}

#[test]
fn resource_types_map_to_the_fixed_item_vocabulary() {
    let body = "version: 1\nresources:\n  - id: d\n    type: directory\n    with:\n      path: /etc/perf/d\n  - id: g\n    type: group\n    with:\n      name: grp\n";
    let s = Scenario::new("pg-kinds", body.into(), Some(Mode::Plan), base());
    let kinds: Vec<ItemKind> = events_of(&s)
        .iter()
        .filter_map(|e| match e {
            ProgressEvent::Progress { current, .. } => current.as_ref().map(|c| c.kind),
            _ => None,
        })
        .collect();
    assert_eq!(kinds, vec![ItemKind::Directory, ItemKind::Group]);
}

// ---------------------------------------------------------------------------
// resources: failures
// ---------------------------------------------------------------------------

#[test]
fn apply_failure_ends_the_stage_failed_and_does_not_announce_fast_forwarded_items() {
    use sinter::result::Disposition;
    // `a` already converged; `b` changes and then fails its re-observation;
    // `c` is never visited.
    let s = Scenario::new(
        "pg-apply-fail",
        doc(&[
            file("a", "/etc/perf/a", "x"),
            file("b", "/etc/perf/b", "x"),
            file("c", "/etc/perf/c", "x"),
        ]),
        Some(Mode::Apply),
        base().with_fs_file("/etc/perf/a", "x"),
    )
    .fault("reobserve_fail");
    let rep = {
        let e = Engine::new(load_model(&s.path()).unwrap(), s.opts()).unwrap();
        e.run().unwrap()
    };
    assert_eq!(find(&rep, "c").disposition, Disposition::BlockedByFailFast);
    let ev = events_of(&s);
    assert_eq!(
        shape(&ev),
        with_connect(&[
            "resources start total=Some(3)",
            "resources item 0/Some(3) file:a",
            "resources item 1/Some(3) file:b",
            "resources end Failed done=2",
        ])
    );
    // No later stage after a failed one.
    assert_eq!(stages_started(&ev), vec![Stage::Connect, Stage::Resources]);
}

#[test]
fn failure_of_the_first_resource_counts_it() {
    let bad = "  - id: bad\n    type: file\n    with:\n      path: /etc/perf/b\n      content: x\n    when: facts.os.family\n";
    let s = Scenario::new(
        "pg-first-fail",
        doc(&[bad.into(), file("c", "/etc/perf/c", "x")]),
        Some(Mode::Apply),
        base(),
    );
    assert_eq!(
        shape(&events_of(&s)),
        with_connect(&[
            "resources start total=Some(2)",
            "resources item 0/Some(2) file:bad",
            "resources end Failed done=1",
        ])
    );
}

#[test]
fn plan_error_ends_the_stage_failed_before_the_error_is_returned() {
    // In plan, an unobservable resource aborts the run with an error (exit 4)
    // and no report. The stage must still end, counting the failing item.
    let bad = "  - id: bad\n    type: file\n    with:\n      path: /etc/perf/b\n      content: x\n    when: facts.os.family\n";
    let s = Scenario::new(
        "pg-plan-error",
        doc(&[file("a", "/etc/perf/a", "x"), bad.into()]),
        Some(Mode::Plan),
        base(),
    );
    let o = observe(&s, Via::Recording);
    assert!(o.fingerprint.starts_with("ERR Plan "), "{}", o.fingerprint);
    assert_eq!(
        shape(&o.events),
        with_connect(&[
            "resources start total=Some(2)",
            "resources item 0/Some(2) file:a",
            "resources item 1/Some(2) file:bad",
            "resources end Failed done=2",
        ])
    );
    validate_stream(&o.events).unwrap();
    // The error is the one the legacy path returns.
    assert_eq!(o.fingerprint, observe(&s, Via::Legacy).fingerprint);
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

const UNIT: &str = "/etc/systemd/system/foo.service";

fn foo(content: &str) -> FakeTarget {
    FakeTarget::ubuntu2404().with_fake_fs().with_loaded_unit(
        "foo.service",
        content,
        ("loaded", "active", "enabled"),
    )
}

fn unit_notifying(handlers: &[&str]) -> String {
    let mut s = format!(
        "version: 1\nresources:\n  - id: u\n    type: file\n    with:\n      path: {UNIT}\n      content: \"B\"\n    notify: [{}]\nhandlers:\n",
        handlers.join(", ")
    );
    for h in handlers {
        s.push_str(&format!(
            "  - id: {h}\n    service: foo.service\n    action: restart\n"
        ));
    }
    s
}

#[test]
fn handlers_stage_total_is_the_queue_and_counts_each_handler() {
    let s = Scenario::new(
        "pg-handlers",
        unit_notifying(&["h1", "h2"]),
        Some(Mode::Apply),
        foo("A"),
    );
    let ev = events_of(&s);
    assert_eq!(
        shape(&ev),
        with_connect(&[
            "resources start total=Some(1)",
            "resources item 0/Some(1) file:u",
            "resources end Completed done=1",
            "handlers start total=Some(2)",
            "handlers item 0/Some(2) handler:h1",
            "handlers item 1/Some(2) handler:h2",
            "handlers end Completed done=2",
        ])
    );
}

#[test]
fn no_handler_stage_when_nothing_was_queued() {
    // The unit already has the desired content: nothing changes, nothing is
    // notified, so there is no handler stage (not an empty one).
    let s = Scenario::new(
        "pg-handlers-none",
        unit_notifying(&["h1"]),
        Some(Mode::Apply),
        foo("B"),
    );
    let ev = events_of(&s);
    assert_eq!(stages_started(&ev), vec![Stage::Connect, Stage::Resources]);
}

#[test]
fn plan_never_has_a_handler_stage_even_when_handlers_would_run() {
    let s = Scenario::new(
        "pg-handlers-plan",
        unit_notifying(&["h1"]),
        Some(Mode::Plan),
        foo("A"),
    );
    assert_eq!(
        stages_started(&events_of(&s)),
        vec![Stage::Connect, Stage::Resources]
    );
}

#[test]
fn handler_failure_ends_the_stage_and_leaves_later_handlers_unvisited() {
    let mut t = foo("A");
    t.manager.reload_completion = Some(Completion::Exited(1));
    let s = Scenario::new(
        "pg-handler-fail",
        unit_notifying(&["h1", "h2"]),
        Some(Mode::Apply),
        t,
    );
    let ev = events_of(&s);
    assert_eq!(
        shape(&ev)[5..].to_vec(),
        vec![
            "handlers start total=Some(2)".to_string(),
            "handlers item 0/Some(2) handler:h1".to_string(),
            "handlers end Failed done=1".to_string(),
        ],
        "{:#?}",
        shape(&ev)
    );
}

#[test]
fn an_earlier_resource_failure_starts_no_handler_stage() {
    let s = Scenario::new(
        "pg-handlers-stopped",
        unit_notifying(&["h1"]),
        Some(Mode::Apply),
        foo("A"),
    )
    .fault("reobserve_fail");
    let ev = events_of(&s);
    assert_eq!(stages_started(&ev), vec![Stage::Connect, Stage::Resources]);
    assert!(matches!(
        ev.last(),
        Some(ProgressEvent::StageEnded {
            stage: Stage::Resources,
            outcome: StageOutcome::Failed,
            ..
        })
    ));
}

// ---------------------------------------------------------------------------
// backup
// ---------------------------------------------------------------------------

fn backup_doc(paths: &[&str]) -> String {
    format!(
        "version: 1\nbackup:\n  paths: [{}]\nresources:\n{}",
        paths.join(", "),
        file("a", "/etc/perf/a", "x")
    )
}

#[test]
fn apply_backup_is_a_stage_with_one_anonymous_item_per_path() {
    let s = Scenario::new(
        "pg-backup",
        backup_doc(&["/etc/perf/a", "/etc/perf/absent"]),
        Some(Mode::Apply),
        with_store(base().with_fs_file("/etc/perf/a", "old")),
    );
    assert_eq!(
        shape(&events_of(&s)),
        with_connect(&[
            "backup start total=Some(2)",
            "backup item 0/Some(2) -",
            "backup item 1/Some(2) -",
            "backup end Completed done=2",
            "resources start total=Some(1)",
            "resources item 0/Some(1) file:a",
            "resources end Completed done=1",
        ])
    );
}

#[test]
fn plan_lists_backups_without_a_backup_stage() {
    let s = Scenario::new(
        "pg-backup-plan",
        backup_doc(&["/etc/perf/a"]),
        Some(Mode::Plan),
        base().with_fs_file("/etc/perf/a", "old"),
    );
    assert_eq!(
        stages_started(&events_of(&s)),
        vec![Stage::Connect, Stage::Resources]
    );
}

#[test]
fn recipe_without_backup_has_no_backup_stage() {
    let s = Scenario::new(
        "pg-no-backup",
        doc(&[file("a", "/etc/perf/a", "x")]),
        Some(Mode::Apply),
        base(),
    );
    assert_eq!(
        stages_started(&events_of(&s)),
        vec![Stage::Connect, Stage::Resources]
    );
}

#[test]
fn backup_failure_while_copying_counts_the_failing_path_and_starts_nothing_after() {
    // The second path's parent directory does not exist, so copying it fails
    // after the first path was copied.
    let s = Scenario::new(
        "pg-backup-fail-copy",
        backup_doc(&["/etc/perf/a", "/etc/missing/b"]),
        Some(Mode::Apply),
        with_store(base().with_fs_file("/etc/perf/a", "old")),
    );
    let o = observe(&s, Via::Recording);
    assert!(o.fingerprint.starts_with("ERR Apply "), "{}", o.fingerprint);
    assert_eq!(
        shape(&o.events),
        with_connect(&[
            "backup start total=Some(2)",
            "backup item 0/Some(2) -",
            "backup item 1/Some(2) -",
            "backup end Failed done=2",
        ])
    );
    validate_stream(&o.events).unwrap();
    assert_eq!(o.fingerprint, observe(&s, Via::Legacy).fingerprint);
}

#[test]
fn backup_failure_during_store_setup_attempts_no_item() {
    // No backup store can be created on this target: nothing was attempted.
    let s = Scenario::new(
        "pg-backup-fail-store",
        backup_doc(&["/etc/perf/a"]),
        Some(Mode::Apply),
        base().with_fs_file("/etc/perf/a", "old"),
    );
    let o = observe(&s, Via::Recording);
    assert!(o.fingerprint.starts_with("ERR Apply "), "{}", o.fingerprint);
    assert_eq!(
        shape(&o.events),
        with_connect(&["backup start total=Some(1)", "backup end Failed done=0"])
    );
    validate_stream(&o.events).unwrap();
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_drift_is_a_completed_stage_not_a_failure() {
    let s = Scenario::new(
        "pg-audit-drift",
        doc(&[
            file("same", "/etc/perf/s", "x"),
            file("drifted", "/etc/perf/d", "new"),
        ]),
        None,
        base()
            .with_fs_file("/etc/perf/s", "x")
            .with_fs_file("/etc/perf/d", "old"),
    );
    // Positive control: the audit really reports drift (exit 7).
    let rep = run_audit(Engine::new(load_model(&s.path()).unwrap(), s.opts()).unwrap()).unwrap();
    assert_eq!(rep.exit_code(), 7);
    assert_eq!(
        shape(&events_of(&s)),
        with_connect(&[
            "resources start total=Some(2)",
            "resources item 0/Some(2) file:same",
            "resources item 1/Some(2) file:drifted",
            "resources end Completed done=2",
        ])
    );
}

#[test]
fn audit_observation_error_is_indeterminate_and_the_stage_still_completes_its_items() {
    // The scripted target without a modeled filesystem cannot stat: an
    // observation error, which audit reports as exit 6 and never as drift.
    let s = Scenario::new(
        "pg-audit-error",
        doc(&[file("a", "/etc/perf/a", "x"), file("b", "/etc/perf/b", "x")]),
        None,
        FakeTarget::ubuntu2404(),
    );
    let rep = run_audit(Engine::new(load_model(&s.path()).unwrap(), s.opts()).unwrap()).unwrap();
    assert_eq!(rep.exit_code(), 6);
    assert_eq!(
        shape(&events_of(&s)),
        with_connect(&[
            "resources start total=Some(2)",
            "resources item 0/Some(2) file:a",
            "resources item 1/Some(2) file:b",
            "resources end Indeterminate done=2",
        ])
    );
}

#[test]
fn audit_counts_not_applicable_and_not_auditable_items() {
    let cmd = "  - id: run\n    type: command\n    with:\n      program: /usr/bin/true\n";
    let off = "  - id: off\n    type: file\n    with:\n      path: /etc/perf/a\n      content: x\n    when: facts.os.family == \"redhat\"\n";
    let s = Scenario::new(
        "pg-audit-na",
        doc(&[cmd.into(), off.into()]),
        None,
        base().with_executable("/usr/bin/true"),
    );
    assert_eq!(
        shape(&events_of(&s)),
        with_connect(&[
            "resources start total=Some(2)",
            "resources item 0/Some(2) command:run",
            "resources item 1/Some(2) file:off",
            "resources end Completed done=2",
        ])
    );
}

// ---------------------------------------------------------------------------
// the sink only observes
// ---------------------------------------------------------------------------

fn matrix() -> Vec<Scenario> {
    let bad = "  - id: bad\n    type: file\n    with:\n      path: /etc/perf/b\n      content: x\n    when: facts.os.family\n";
    let off = "  - id: off\n    type: file\n    with:\n      path: /etc/perf/o\n      content: x\n    when: facts.os.family == \"redhat\"\n";
    let pkg = "  - id: p\n    type: package\n    with:\n      name: jq\n      state: present\n";
    let mixed = || {
        base()
            .with_fs_file("/etc/perf/a", "x")
            .with_fs_file("/etc/perf/b", "old")
    };
    let mixed_doc = || {
        doc(&[
            file("a", "/etc/perf/a", "x"),
            file("b", "/etc/perf/b", "new"),
            off.into(),
            file("c", "/etc/perf/c", "x"),
        ])
    };
    let mut t_fail = foo("A");
    t_fail.manager.reload_completion = Some(Completion::Exited(1));
    vec![
        Scenario::new("pg-m-plan", mixed_doc(), Some(Mode::Plan), mixed()),
        Scenario::new("pg-m-apply", mixed_doc(), Some(Mode::Apply), mixed()),
        // converged: the second run of the same recipe changes nothing
        Scenario::new(
            "pg-m-converged",
            doc(&[file("a", "/etc/perf/a", "x")]),
            Some(Mode::Apply),
            base().with_fs_file("/etc/perf/a", "x"),
        ),
        Scenario::new("pg-m-empty", doc(&[]), Some(Mode::Apply), base()),
        Scenario::new(
            "pg-m-apply-fail",
            doc(&[file("a", "/etc/perf/a", "x"), file("b", "/etc/perf/b", "x")]),
            Some(Mode::Apply),
            base().with_fs_file("/etc/perf/a", "x"),
        )
        .fault("reobserve_fail"),
        Scenario::new(
            "pg-m-first-fail",
            doc(&[bad.into(), file("c", "/etc/perf/c", "x")]),
            Some(Mode::Apply),
            base(),
        ),
        Scenario::new(
            "pg-m-plan-error",
            doc(&[file("a", "/etc/perf/a", "x"), bad.into()]),
            Some(Mode::Plan),
            base(),
        ),
        Scenario::new("pg-m-audit-drift", mixed_doc(), None, mixed()),
        Scenario::new(
            "pg-m-audit-error",
            doc(&[file("a", "/etc/perf/a", "x")]),
            None,
            FakeTarget::ubuntu2404(),
        ),
        Scenario::new(
            "pg-m-handler",
            unit_notifying(&["h1", "h2"]),
            Some(Mode::Apply),
            foo("A"),
        ),
        Scenario::new(
            "pg-m-handler-fail",
            unit_notifying(&["h1", "h2"]),
            Some(Mode::Apply),
            t_fail,
        ),
        Scenario::new(
            "pg-m-backup",
            backup_doc(&["/etc/perf/a", "/etc/perf/absent"]),
            Some(Mode::Apply),
            with_store(base().with_fs_file("/etc/perf/a", "old")),
        ),
        Scenario::new(
            "pg-m-backup-fail",
            backup_doc(&["/etc/perf/a", "/etc/missing/b"]),
            Some(Mode::Apply),
            with_store(base().with_fs_file("/etc/perf/a", "old")),
        ),
        Scenario::new(
            "pg-m-connect-fail",
            doc(&[pkg.into()]),
            Some(Mode::Plan),
            FakeTarget::unsupported(),
        ),
    ]
}

#[test]
fn every_sink_leaves_reports_errors_audits_order_and_command_counts_unchanged() {
    for s in matrix() {
        let legacy = observe(&s, Via::Legacy);
        assert!(!legacy.fingerprint.is_empty(), "{}", s.name);
        for (label, via) in [
            ("noop", Via::Noop),
            ("recording", Via::Recording),
            ("dropped observer", Via::DroppedObserver),
        ] {
            let o = observe(&s, via);
            assert_eq!(o.fingerprint, legacy.fingerprint, "{}: {label}", s.name);
            // Same number of target commands, per scope and per program: the
            // instrumentation adds none.
            assert_eq!(o.stats, legacy.stats, "{}: {label}: command counts", s.name);
        }
    }
}

#[test]
fn every_scenario_yields_a_valid_deterministic_stream() {
    for s in matrix() {
        let first = observe(&s, Via::Recording);
        validate_stream(&first.events).unwrap_or_else(|e| panic!("{}: {e}", s.name));
        assert!(!first.events.is_empty(), "{}", s.name);
        let second = observe(&s, Via::Recording);
        assert_eq!(first.events, second.events, "{}: not deterministic", s.name);
        // The legacy path emits nothing anywhere; the recording one starts at
        // connect and never contains the caller-layer events.
        assert!(matches!(
            first.events[0],
            ProgressEvent::StageStarted {
                stage: Stage::Connect,
                total: None
            }
        ));
        assert!(!first.events.iter().any(|e| matches!(
            e,
            ProgressEvent::RunStarted { .. } | ProgressEvent::RunEnded { .. }
        )));
    }
}

#[test]
fn command_counts_with_a_sink_match_the_pinned_baselines() {
    // `tests/command_budget.rs` pins the absolute numbers on the legacy path.
    // Here the same absolute facts are re-derived with a recording sink
    // attached, so the guard cannot be passed by a sink-only change.
    let t = base()
        .with_fs_file("/etc/perf/f0.conf", "x0\n")
        .with_fs_file("/etc/perf/f1.conf", "x1\n");
    let body = doc(&[
        "  - id: f0\n    type: file\n    with:\n      path: /etc/perf/f0.conf\n      content: \"x0\\n\"\n      owner: root\n      group: root\n      mode: \"0644\"\n".to_string(),
        "  - id: f1\n    type: file\n    with:\n      path: /etc/perf/f1.conf\n      content: \"x1\\n\"\n      owner: root\n      group: root\n      mode: \"0644\"\n".to_string(),
    ]);
    for mode in [Some(Mode::Plan), Some(Mode::Apply), None] {
        let s = Scenario::new("pg-budget", body.clone(), mode, t.clone());
        let legacy = observe(&s, Via::Legacy).stats.unwrap();
        let sunk = observe(&s, Via::Recording).stats.unwrap();
        assert_eq!(legacy, sunk);
        // Setup is 6 commands (see command_budget.rs); the rest is per resource.
        assert!(legacy.1.get("setup") == Some(&6), "{:?}", legacy.1);
    }
}

#[test]
fn new_delegates_to_the_progress_aware_constructor_with_a_noop_sink() {
    // `Engine::new` keeps its signature; a caller that never heard of progress
    // gets the same engine. (Compile-time: both are callable as below.)
    let s = Scenario::new("pg-new", doc(&[]), Some(Mode::Plan), base());
    let a = Engine::new(load_model(&s.path()).unwrap(), s.opts()).unwrap();
    let b = Engine::new_with_progress(load_model(&s.path()).unwrap(), s.opts(), Arc::new(NoopSink))
        .unwrap();
    assert_eq!(
        a.exec_stats().snapshot().total(),
        b.exec_stats().snapshot().total()
    );
}

// ---------------------------------------------------------------------------
// secret canaries
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
];

/// `with_secret`: also name an encrypted secret the engine has no key for. In
/// plan that aborts the run with an error (no report, so no command log to use
/// as a positive control); the variant without it runs to a report.
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

#[test]
fn no_sensitive_value_can_appear_in_any_event_on_any_path() {
    let declared: Vec<&str> = vec!["plain", "looped[0]", "cmd", "acct", "after", "restart_it"];
    for (mode, label, with_secret) in [
        (Some(Mode::Plan), "plan", false),
        (Some(Mode::Apply), "apply", false),
        (None, "audit", false),
        (Some(Mode::Plan), "plan+secret", true),
        (Some(Mode::Apply), "apply+secret", true),
        (None, "audit+secret", true),
    ] {
        let s = Scenario::new(
            if with_secret {
                "pg-canary-secret"
            } else {
                "pg-canary"
            },
            canary_recipe(with_secret),
            mode,
            with_store(
                base()
                    .with_executable("/opt/CANARY-CMD-PROGRAM-5d3a")
                    .with_fs_file("/etc/perf/CANARYPATH5d3a", "CANARY-REASON-5d3a-old"),
            )
            .with_fs_dir("/etc/perf/CANARYBACKUP5d3a"),
        );
        // Credentials of a target the scripted executor never contacts: they
        // sit in the options and must not reach the stream.
        let mut opts = s.opts();
        opts.target = TargetSpec {
            ssh: Some(SshSpec {
                host: "198.51.100.7".into(),
                port: 2222,
                user: "CANARY-SSH-USER-5d3a".into(),
                known_hosts: PathBuf::from("/nonexistent/CANARY-KNOWN-HOSTS-5d3a"),
                identity_files: vec![PathBuf::from("/nonexistent/CANARY-SSH-KEY-5d3a")],
                ..Default::default()
            }),
        };
        std::fs::create_dir_all(s.dir.join("secrets")).unwrap();
        // A well-formed encrypted file the engine has no key for: the resource
        // that names it must fail closed, and its reference must stay out.
        let id = sinter::secrets::generate_identity();
        let ct = sinter::secrets::encrypt_to_recipients(
            b"CANARY-SECRET-PLAINTEXT-5d3a",
            std::slice::from_ref(&id.recipient),
        )
        .unwrap();
        std::fs::write(s.dir.join("secrets/CANARYSECRETREF5d3a.age"), ct).unwrap();
        let sink = RecordingSink::new();
        let model = load_model(&s.path()).unwrap();
        let engine = Engine::new_with_progress(model, opts, sink.clone()).unwrap();
        let raw = match mode {
            Some(_) => match engine.run() {
                Ok(rep) => commands_fingerprint(&rep.commands),
                Err(e) => format!("{:?}", e),
            },
            None => match run_audit(engine) {
                Ok(rep) => commands_fingerprint(&rep.commands),
                Err(e) => format!("{:?}", e),
            },
        };

        let events = sink.events();
        validate_stream(&events).unwrap_or_else(|e| panic!("{label}: {e}"));
        let shown = format!("{events:?}");
        for c in CANARIES {
            assert!(
                !shown.contains(c),
                "{label}: canary {c} leaked into {shown}"
            );
        }
        assert!(!shown.contains("198.51.100.7") && !shown.contains("2222"));
        // The only free strings in the stream are declared ids.
        for e in &events {
            if let ProgressEvent::Progress {
                current: Some(c), ..
            } = e
            {
                assert!(declared.contains(&c.id.as_str()), "{label}: id {}", c.id);
            }
        }
        // Positive control: the run itself did see a canary (the loop item is
        // in the raw command log of the non-sensitive resource), so the
        // absence above is meaningful.
        assert!(
            with_secret || raw.contains("CANARY-LOOP-ITEM-5d3a"),
            "{label}: the scenario never exercised a canary: {raw}"
        );
    }
}
