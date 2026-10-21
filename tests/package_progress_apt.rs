//! Phase 2 integration tests: an APT package mutation observed through the
//! progress seam on a scripted target.
//!
//! The fake `apt-get` emits real-shaped `status-fd` records only when the
//! `-o APT::Status-Fd=1` option is present, so these tests also prove that the
//! option is added when — and only when — a consumer is attached.

mod common;

use common::*;
use sinter::engine::{Engine, Mode, RunOptions, TargetSpec};
use sinter::executor::{Completion, FakeTarget};
use sinter::model::load_model;
use sinter::progress::{PercentScope, ProgressEvent, ProgressSink, RecordingSink, Stage};
use sinter::result::{Change, Execution, Verification};
use std::sync::Arc;

const RECIPE: &str = "version: 1\nresources:\n  - id: p\n    type: package\n    with: { name: acl, state: present }\n";

const SENSITIVE_RECIPE: &str = "version: 1\nresources:\n  - id: p\n    type: package\n    sensitive: true\n    with: { name: acl, state: present }\n";

fn target() -> FakeTarget {
    FakeTarget::ubuntu2404().with_fake_fs().as_root()
}

fn run(
    recipe: &std::path::Path,
    mode: Mode,
    sink: Arc<dyn ProgressSink>,
) -> sinter::engine::RunReport {
    let model = load_model(recipe).unwrap();
    let opts = RunOptions {
        mode,
        sudo: true,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(target()),
    };
    Engine::new_with_progress(model, opts, sink)
        .unwrap()
        .run()
        .unwrap()
}

fn details(events: &[ProgressEvent]) -> Vec<sinter::progress::PackageProgress> {
    events
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::PackageDetail(detail) => Some(detail.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn an_apply_reports_apt_download_and_install_detail_before_the_stage_ends() {
    let dir = trusted_root("phase2-apt-detail");
    let recipe = write_recipe(&dir, "r.yaml", RECIPE);
    let sink = RecordingSink::new();
    let report = run(&recipe, Mode::Apply, sink.clone());
    let events = sink.events();

    let found = details(&events);
    assert!(!found.is_empty(), "no package detail was emitted");
    assert!(
        found
            .iter()
            .any(|d| d.percent_scope == Some(PercentScope::DownloadAggregate)),
        "no download detail: {found:?}"
    );
    assert!(
        found.iter().any(|d| {
            d.percent_scope == Some(PercentScope::TransactionOperation)
                && d.package.as_deref() == Some("acl")
        }),
        "no install detail for acl: {found:?}"
    );
    assert!(
        found
            .iter()
            .all(|d| d.stage == Stage::Resources && d.resource.id == "p"),
        "detail must belong to the package item"
    );

    // Every detail precedes the resources stage end, and none follows it.
    let end = events
        .iter()
        .position(|event| {
            matches!(
                event,
                ProgressEvent::StageEnded {
                    stage: Stage::Resources,
                    ..
                }
            )
        })
        .expect("resources stage ends");
    let last = events
        .iter()
        .rposition(|event| matches!(event, ProgressEvent::PackageDetail(_)))
        .expect("a detail exists");
    assert!(last < end, "detail {last} arrived after stage end {end}");
    assert!(
        !events[end + 1..]
            .iter()
            .any(|event| matches!(event, ProgressEvent::PackageDetail(_))),
        "a detail followed the stage end"
    );

    // Progress did not change the result.
    let r = find(&report, "p");
    assert_eq!(r.execution, Execution::Succeeded);
    assert_eq!(r.change, Change::Changed);
    assert_eq!(r.verification, Verification::Verified);
}

#[test]
fn a_run_without_progress_is_unchanged() {
    let dir = trusted_root("phase2-apt-plain");
    let recipe = write_recipe(&dir, "r.yaml", RECIPE);
    let report = run(&recipe, Mode::Apply, Arc::new(sinter::progress::NoopSink));
    let r = find(&report, "p");
    assert_eq!(r.execution, Execution::Succeeded);
    assert_eq!(r.change, Change::Changed);
    assert_eq!(r.verification, Verification::Verified);
}

#[test]
fn a_sensitive_package_never_reports_detail() {
    let dir = trusted_root("phase2-apt-sensitive");
    let recipe = write_recipe(&dir, "r.yaml", SENSITIVE_RECIPE);
    let sink = RecordingSink::new();
    let report = run(&recipe, Mode::Apply, sink.clone());
    assert!(
        details(&sink.events()).is_empty(),
        "a sensitive package must not produce detail"
    );
    let r = find(&report, "p");
    assert_eq!(r.execution, Execution::Succeeded);
}

#[test]
fn a_failed_mutation_finishes_the_reporter_and_keeps_the_result() {
    let dir = trusted_root("phase2-apt-failure");
    let recipe = write_recipe(&dir, "r.yaml", RECIPE);
    let sink = RecordingSink::new();
    let model = load_model(&recipe).unwrap();
    let mut fake = target();
    fake.manager_completion = Some(Completion::Exited(100));
    let opts = RunOptions {
        mode: Mode::Apply,
        sudo: true,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake),
    };
    let report = Engine::new_with_progress(model, opts, sink.clone())
        .unwrap()
        .run()
        .unwrap();
    let r = find(&report, "p");
    assert_eq!(r.execution, Execution::Failed);
    assert_eq!(r.change, Change::Possible);
    // The reporter is finished before the stage ends: no detail may trail it.
    let events = sink.events();
    let end = events
        .iter()
        .position(|event| {
            matches!(
                event,
                ProgressEvent::StageEnded {
                    stage: Stage::Resources,
                    ..
                }
            )
        })
        .expect("resources stage ends");
    assert!(!events[end + 1..]
        .iter()
        .any(|event| matches!(event, ProgressEvent::PackageDetail(_))));
}

#[test]
fn an_indeterminate_mutation_finishes_the_reporter_and_stays_indeterminate() {
    let dir = trusted_root("phase2-apt-indeterminate");
    let recipe = write_recipe(&dir, "r.yaml", RECIPE);
    let sink = RecordingSink::new();
    let model = load_model(&recipe).unwrap();
    let mut fake = target();
    fake.manager_completion = Some(Completion::Indeterminate {
        started: true,
        reason: "injected".to_string(),
    });
    let opts = RunOptions {
        mode: Mode::Apply,
        sudo: true,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake),
    };
    let report = Engine::new_with_progress(model, opts, sink.clone())
        .unwrap()
        .run()
        .unwrap();
    let r = find(&report, "p");
    assert_eq!(r.execution, Execution::Indeterminate);
    assert_eq!(r.change, Change::Possible);
    assert_eq!(r.verification, Verification::Unknown);
}
