//! Partial runs on the scripted target with the production engine (DESIGN §40.8):
//! the model `SkipPlan` leaves is what runs, in plan, apply and audit.
#![cfg(unix)]

use sinter::audit::run_audit;
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::executor::FakeTarget;
use sinter::model::{load_model, Model};
use sinter::skips::{SkipPlan, SkipRequest, UnitView};

const RECIPE: &str = "version: 1\nresources:\n  - id: base\n    type: file\n    with:\n      path: /etc/app/base\n      content: b\n  - id: conf\n    type: file\n    depends_on: [base]\n    notify: [restart]\n    with:\n      path: /etc/app/conf\n      content: c\n  - id: other\n    type: file\n    notify: [reload]\n    with:\n      path: /etc/app/other\n      content: o\nhandlers:\n  - id: restart\n    service: nginx\n    action: restart\n  - id: reload\n    service: nginx\n    action: reload\n";

fn model() -> (tempfile::TempDir, Model) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, RECIPE).unwrap();
    let m = load_model(&p).unwrap();
    (d, m)
}

fn target() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_service("nginx", ("loaded", "active", "enabled"))
        .as_root();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/etc", 0o755, 0, 0);
    fs.mkdir_node("/etc/app", 0o755, 0, 0);
    t
}

fn opts(mode: Mode) -> RunOptions {
    RunOptions {
        mode,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(target()),
    }
}

fn plan_for(m: &Model, resources: &[&str]) -> SkipPlan {
    SkipPlan::build(
        &SkipRequest {
            recipes: Vec::new(),
            resources: resources.iter().map(|s| s.to_string()).collect(),
        },
        &[UnitView {
            label: "r",
            unfrozen: false,
            models: vec![m],
        }],
    )
    .unwrap()
}

fn run(mode: Mode, m: Model) -> RunReport {
    Engine::new(m, opts(mode)).unwrap().run().unwrap()
}

fn ids(r: &RunReport) -> Vec<&str> {
    r.resources.iter().map(|x| x.id.as_str()).collect()
}

#[test]
fn an_excluded_resource_is_not_changed_or_reported() {
    let (_d, m) = model();
    let filtered = plan_for(&m, &["other"]).filter(0, m);
    let r = run(Mode::Apply, filtered);
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(ids(&r), ["base", "conf"]);
    let fs = r.fake_fs.as_ref().unwrap();
    assert!(fs.nodes.contains_key("/etc/app/conf"));
    assert!(
        !fs.nodes.contains_key("/etc/app/other"),
        "excluded: untouched"
    );
}

#[test]
fn a_handler_runs_only_for_an_included_resource() {
    let (_d, m) = model();
    let filtered = plan_for(&m, &["other"]).filter(0, m);
    let r = run(Mode::Apply, filtered);
    let run_ids: Vec<&str> = r.handlers_run.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(run_ids, ["restart"]);
    assert!(r.handlers_pending.is_empty());

    let (_d, m) = model();
    let filtered = plan_for(&m, &["conf"]).filter(0, m);
    let r = run(Mode::Apply, filtered);
    let run_ids: Vec<&str> = r.handlers_run.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(
        run_ids,
        ["reload"],
        "the excluded notifier starts no handler"
    );
}

#[test]
fn plan_says_the_same_as_apply() {
    let (_d, m) = model();
    let filtered = plan_for(&m, &["conf"]).filter(0, m);
    let r = run(Mode::Plan, filtered);
    assert_eq!(ids(&r), ["base", "other"]);
    assert_eq!(r.handlers_pending, ["reload"]);
    assert!(!r
        .fake_fs
        .as_ref()
        .unwrap()
        .nodes
        .contains_key("/etc/app/base"));
}

#[test]
fn audit_does_not_observe_what_is_excluded() {
    let (_d, m) = model();
    let filtered = plan_for(&m, &["conf"]).filter(0, m);
    let report = run_audit(Engine::new(filtered, opts(Mode::Plan)).unwrap()).unwrap();
    let doc = sinter::output::audit_report_json(&report).to_string();
    assert!(doc.contains("base") && doc.contains("other"), "{doc}");
    assert!(!doc.contains("/etc/app/conf"), "{doc}");
}

#[test]
fn a_dependency_on_an_excluded_resource_never_reaches_the_engine() {
    let (_d, m) = model();
    let p = plan_for(&m, &["base"]);
    let e = p.refusal().expect("refused");
    assert!(
        e.message.contains("r/conf depends on base"),
        "{}",
        e.message
    );
    // And if it did, the engine would refuse too: a missing dependency is not skipped.
    let broken = p.filter(0, m);
    assert!(Engine::new(broken, opts(Mode::Plan))
        .unwrap()
        .run()
        .is_err());
}

#[test]
fn a_register_consumer_is_covered_by_its_dependency() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(
        &p,
        "version: 1\nresources:\n  - id: probe\n    type: command\n    with:\n      program: /usr/bin/true\n      register: seen\n      creates: /etc/app/probe\n  - id: use\n    type: file\n    depends_on: [probe]\n    when: \"registers.seen.exit_code == 0\"\n    with:\n      path: /etc/app/use\n      content: x\n",
    )
    .unwrap();
    let m = load_model(&p).unwrap();
    assert!(plan_for(&m, &["probe"]).refusal().is_some());
}
