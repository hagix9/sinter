//! Phase 3 integration tests: the DNF progress grammar on its own, through
//! the reporter seam, and through a real apply on a scripted Rocky target.
//!
//! Provenance of `tests/fixtures/dnf/`:
//!
//! * `rhel8-dnf4-download.err` is a byte capture of the DNF4 download meter
//!   from the v1.5.1 Rocky Linux 8.10 real-host gate (dnf 4.7.0), split out
//!   of the captured stream. It is real output.
//! * `rhel9-dnf4-install.out`, `rhel9-dnf4-remove.out`,
//!   `rhel10-dnf5-install.err` and `rhel10-dnf5-download.err` are *modelled*
//!   from the upstream sources named in `src/package_progress/dnf.rs`
//!   (`dnf/cli/output.py`, `dnf/cli/progress.py`, `dnf/base.py`,
//!   `dnf5/context.cpp`, `libdnf5-cli/progressbar/*`). They are not captures
//!   from a live host and no test claims a live DNF5 run.
//!
//! No test here executes a package manager: the engine runs against
//! `FakeTarget`, which only prints text.

mod common;

use common::*;
use sinter::engine::{Engine, Mode, RunOptions, TargetSpec};
use sinter::executor::{Completion, ExecObserver, FakeTarget, Output};
use sinter::model::load_model;
use sinter::package_progress::dnf::DnfProgressParser;
use sinter::package_progress::{LineSplitter, PackageParser, PackageReporter};
use sinter::platform::PackageBackend;
use sinter::progress::{
    ItemKind, ItemRef, PackagePhase, ProgressEvent, ProgressSink, RecordingSink, Stage,
};
use sinter::result::{Change, Execution, Verification};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const INSTALL: &str = "version: 1\nresources:\n  - id: p\n    type: package\n    with: { name: python36, state: present }\n";
const REMOVE: &str = "version: 1\nresources:\n  - id: p\n    type: package\n    with: { name: python36, state: absent }\n";
const SENSITIVE: &str = "version: 1\nresources:\n  - id: p\n    type: package\n    sensitive: true\n    with: { name: python36, state: present }\n";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/dnf")
        .join(name)
}

fn observations(name: &str) -> Vec<sinter::package_progress::PackageObservation> {
    let bytes = std::fs::read(fixture(name)).expect("fixture");
    let mut splitter = LineSplitter::new();
    let mut parser = DnfProgressParser::new();
    let mut out = Vec::new();
    splitter.feed(&bytes, |line| {
        if let Some(observation) = parser.observe(line) {
            out.push(observation);
        }
    });
    out
}

fn phases(events: &[sinter::package_progress::PackageObservation]) -> Vec<PackagePhase> {
    events.iter().map(|e| e.phase).collect()
}

fn auditor_target() -> FakeTarget {
    FakeTarget::rocky9()
}

/// Apply `recipe` with `fake` and `sink`, exactly as the CLI would.
fn run(
    label: &str,
    recipe: &str,
    fake: FakeTarget,
    sink: Arc<dyn ProgressSink>,
) -> sinter::engine::RunReport {
    let dir = trusted_root(label);
    let recipe = write_recipe(&dir, "r.yaml", recipe);
    let model = load_model(&recipe).unwrap();
    let opts = RunOptions {
        mode: Mode::Apply,
        sudo: true,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake),
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

/// Assert every emitted detail obeys the DNF contract: no percent, no
/// percent scope, and the measured source vocabulary only.
fn assert_no_percent(found: &[sinter::progress::PackageProgress]) {
    for detail in found {
        assert_eq!(detail.percent, None, "{detail:?}");
        assert_eq!(detail.percent_scope, None, "{detail:?}");
        assert!(matches!(
            detail.source,
            sinter::progress::ProgressSource::DnfDownloadLine
                | sinter::progress::ProgressSource::DnfTransactionLine
                | sinter::progress::ProgressSource::DnfOutputMarker
        ));
    }
}

/// The same contract at the parser level, before the detail is attached.
fn assert_no_percent_obs(found: &[sinter::package_progress::PackageObservation]) {
    for observation in found {
        assert_eq!(observation.percent, None, "{observation:?}");
        assert_eq!(observation.percent_scope, None, "{observation:?}");
        assert!(matches!(
            observation.source,
            sinter::progress::ProgressSource::DnfDownloadLine
                | sinter::progress::ProgressSource::DnfTransactionLine
                | sinter::progress::ProgressSource::DnfOutputMarker
        ));
    }
}

fn stage_end(events: &[ProgressEvent]) -> usize {
    events
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
        .expect("resources stage ends")
}

// ---------------------------------------------------------------------------
// Fixture replay: the grammar itself
// ---------------------------------------------------------------------------

#[test]
fn a_dnf4_install_stream_reports_download_install_and_verify_without_a_percent() {
    let events = observations("rhel9-dnf4-install.out");
    let found = phases(&events);
    assert!(found.contains(&PackagePhase::Downloading), "{found:?}");
    assert!(found.contains(&PackagePhase::Installing), "{found:?}");
    assert!(found.contains(&PackagePhase::Verifying), "{found:?}");
    assert!(!found.contains(&PackagePhase::Removing), "{found:?}");
    // `Running transaction check/test` is a real pre-transaction phase.
    assert!(found.contains(&PackagePhase::Resolving), "{found:?}");
    for event in &events {
        assert_no_percent_obs(std::slice::from_ref(event));
    }

    // The first package action carries the transaction-set count DNF printed.
    let first_install = events
        .iter()
        .find(|e| e.phase == PackagePhase::Installing && e.package.is_some())
        .expect("a package install");
    assert_eq!(
        first_install.package.as_deref(),
        Some("python36-3.6.8-39.module+el8.10.0+1910+234ad790.x86_64")
    );
    assert_eq!(first_install.packages_done, Some(1));
    assert_eq!(first_install.packages_total, Some(3));

    // `Preparing` is direction-neutral and must not create an install event
    // before the first `Installing` line.
    let first = events.first().expect("an event");
    assert_eq!(first.phase, PackagePhase::Downloading);
}

#[test]
fn a_dnf4_remove_stream_never_reports_an_install() {
    let events = observations("rhel9-dnf4-remove.out");
    let found = phases(&events);
    assert!(found.contains(&PackagePhase::Removing), "{found:?}");
    assert!(found.contains(&PackagePhase::Verifying), "{found:?}");
    assert!(!found.contains(&PackagePhase::Installing), "{found:?}");
}

#[test]
fn a_real_dnf4_download_meter_reports_completion_without_rounded_bytes() {
    let events = observations("rhel8-dnf4-download.err");
    assert_eq!(events.len(), 2, "{events:?}");
    // The package file line and the `Total` line; the repository metadata
    // line is not a package and is not reported.
    assert!(events.iter().all(|e| e.phase == PackagePhase::Downloading));
    assert!(events.iter().all(|e| e.files_done.is_none()));
    // `6.5 kB` / `648 kB` are rounded displays, so no byte count is claimed.
    assert!(events.iter().all(|e| e.bytes_downloaded.is_none()));
    assert!(events.iter().all(|e| e.rate_bps.is_none()));
    for event in &events {
        assert_no_percent_obs(std::slice::from_ref(event));
    }
}

#[test]
fn a_dnf5_install_stream_reports_phases_without_item_percentages() {
    let events = observations("rhel10-dnf5-install.err");
    let found = phases(&events);
    assert!(found.contains(&PackagePhase::Resolving), "{found:?}");
    assert!(found.contains(&PackagePhase::Installing), "{found:?}");
    assert!(found.contains(&PackagePhase::Verifying), "{found:?}");
    assert!(found.contains(&PackagePhase::Triggering), "{found:?}");
    assert!(!found.contains(&PackagePhase::Removing), "{found:?}");
    for event in &events {
        assert_no_percent_obs(std::slice::from_ref(event));
        // Every bar printed `100%`; none of it is a transaction percentage.
        assert_eq!(event.percent, None);
    }
    // `Prepare transaction` carries no direction and is not reported.
    assert!(
        events
            .iter()
            .all(|e| e.package.as_deref() != Some("Prepare transaction")),
        "{events:?}"
    );
    // The scriptlet message line is not a phase of its own.
    assert!(events.iter().all(|e| e.phase != PackagePhase::Waiting));
}

#[test]
fn a_dnf5_download_stream_reports_file_counts_without_bytes() {
    let events = observations("rhel10-dnf5-download.err");
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].files_done, Some(1));
    assert_eq!(events[0].files_total, Some(2));
    assert_eq!(events[1].files_done, Some(2));
    assert_eq!(events[1].files_total, Some(2));
    assert!(events.iter().all(|e| e.bytes_downloaded.is_none()));
    assert!(events.iter().all(|e| e.rate_bps.is_none()));
    for event in &events {
        assert_no_percent_obs(std::slice::from_ref(event));
    }
}

// ---------------------------------------------------------------------------
// Engine integration: install, remove, disabled progress, sensitivity
// ---------------------------------------------------------------------------

fn install_target() -> FakeTarget {
    let mut fake = auditor_target();
    fake.dnf_downloadonly_progress = Some((
        "Downloading Packages:\n".to_string(),
        "(1/1): python36-1.0-1.el9.x86_64.rpm  1.0 MB/s | 6.5 kB  00:00\n\
         Total  648 kB/s | 6.5 kB  00:00\n"
            .to_string(),
    ));
    fake.dnf_mutation_progress = Some((
        "Running transaction check\n\
         Running transaction\n\
         \x20 Installing       : python36-1.0-1.el9.x86_64  1/1\n\
         \x20 Verifying        : python36-1.0-1.el9.x86_64  1/1\n\
         Complete!\n"
            .to_string(),
        String::new(),
    ));
    fake
}

#[test]
fn an_apply_reports_dnf_download_then_install_detail_before_the_stage_ends() {
    let sink = RecordingSink::new();
    let report = run("phase3-dnf-detail", INSTALL, install_target(), sink.clone());
    let events = sink.events();
    let found = details(&events);
    assert!(!found.is_empty(), "no package detail was emitted");

    assert!(
        found.iter().any(|d| d.phase == PackagePhase::Downloading),
        "no download detail: {found:?}"
    );
    assert!(
        found.iter().any(|d| {
            d.phase == PackagePhase::Installing
                && d.package.as_deref() == Some("python36-1.0-1.el9.x86_64")
                && d.packages_done == Some(1)
                && d.packages_total == Some(1)
        }),
        "no package install detail: {found:?}"
    );
    assert!(
        found.iter().any(|d| d.phase == PackagePhase::Verifying),
        "no verify detail: {found:?}"
    );
    assert_no_percent(&found);
    assert!(
        found
            .iter()
            .all(|d| d.stage == Stage::Resources && d.resource.id == "p"),
        "detail must belong to the package item"
    );

    let end = stage_end(&events);
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
    assert_eq!(r.execution, Execution::Succeeded, "{:?}", r.reason);
    assert_eq!(r.change, Change::Changed);
    assert_eq!(r.verification, Verification::Verified);
}

#[test]
fn a_remove_reports_a_removal_and_never_an_install() {
    let mut fake = auditor_target();
    fake.packages.insert("python36".to_string());
    fake.dnf_mutation_progress = Some((
        "Running transaction check\n\
         Running transaction\n\
         \x20 Erasing          : python36-1.0-1.el9.x86_64  1/1\n\
         \x20 Verifying        : python36-1.0-1.el9.x86_64  1/1\n\
         Complete!\n"
            .to_string(),
        String::new(),
    ));
    let sink = RecordingSink::new();
    let report = run("phase3-dnf-remove", REMOVE, fake, sink.clone());
    let found = details(&sink.events());
    assert!(!found.is_empty(), "no package detail was emitted");
    assert!(
        found.iter().any(|d| d.phase == PackagePhase::Removing),
        "no removal detail: {found:?}"
    );
    assert!(
        !found.iter().any(|d| d.phase == PackagePhase::Installing),
        "a remove reported an install: {found:?}"
    );
    assert_no_percent(&found);

    let r = find(&report, "p");
    assert_eq!(r.execution, Execution::Succeeded, "{:?}", r.reason);
    assert_eq!(r.change, Change::Changed);
    assert_eq!(r.verification, Verification::Verified);
}

#[test]
fn a_run_without_progress_is_byte_identical_and_still_succeeds() {
    let observed = run(
        "phase3-dnf-observed",
        INSTALL,
        install_target(),
        RecordingSink::new(),
    );
    let silent = run(
        "phase3-dnf-silent",
        INSTALL,
        install_target(),
        Arc::new(sinter::progress::NoopSink),
    );
    // No progress consumer: no detail at all (the sink is disabled, so no
    // reporter thread exists).
    assert!(silent
        .commands
        .iter()
        .all(|c| c.program != "/usr/bin/dnf" || !c.args.iter().any(|a| a.contains("Status-Fd"))));
    let dnf_args = |r: &sinter::engine::RunReport| -> Vec<Vec<String>> {
        r.commands
            .iter()
            .filter(|c| c.program == "/usr/bin/dnf")
            .map(|c| c.args.clone())
            .collect()
    };
    assert_eq!(
        dnf_args(&observed),
        dnf_args(&silent),
        "the DNF argv must not depend on whether progress is attached"
    );
    let r = find(&silent, "p");
    assert_eq!(r.execution, Execution::Succeeded, "{:?}", r.reason);
    assert_eq!(r.change, Change::Changed);
    assert_eq!(r.verification, Verification::Verified);
}

#[test]
fn an_indeterminate_prefetch_finishes_the_reporter_and_stays_indeterminate() {
    // A timeout/cancel is modelled as a started-but-unknown completion. The
    // prefetch is the new observed path: its reporter must still be finished
    // before the resource result is produced, and no detail may trail the
    // stage end.
    let mut fake = auditor_target();
    fake.dnf_downloadonly_output = Some(Output {
        completion: Completion::Indeterminate {
            started: true,
            reason: "injected timeout".to_string(),
        },
        stdout: b"Downloading Packages:\n".to_vec(),
        stderr: b"(1/2): python36-1.0-1.el9.x86_64.rpm  1.0 MB/s | 6.5 kB  00:00\n".to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    });
    let sink = RecordingSink::new();
    let report = run(
        "phase3-dnf-prefetch-indeterminate",
        INSTALL,
        fake,
        sink.clone(),
    );
    let r = find(&report, "p");
    assert_eq!(r.execution, Execution::Indeterminate, "{:?}", r.reason);
    // The snapshot preparation was indeterminate before any mutation: no
    // change can be claimed.
    assert_eq!(r.change, Change::None);
    assert_eq!(r.verification, Verification::NotPerformed);

    let events = sink.events();
    let end = stage_end(&events);
    assert!(
        !events[end + 1..]
            .iter()
            .any(|event| matches!(event, ProgressEvent::PackageDetail(_))),
        "a detail followed the stage end after an indeterminate prefetch"
    );
}

#[test]
fn a_sensitive_package_never_reports_detail() {
    let sink = RecordingSink::new();
    let report = run(
        "phase3-dnf-sensitive",
        SENSITIVE,
        install_target(),
        sink.clone(),
    );
    assert!(
        details(&sink.events()).is_empty(),
        "a sensitive package must not produce detail"
    );
    let r = find(&report, "p");
    assert_eq!(r.execution, Execution::Succeeded, "{:?}", r.reason);
}

#[test]
fn a_failed_mutation_finishes_the_reporter_and_keeps_the_result() {
    let mut fake = auditor_target();
    fake.manager_output = Some(Output {
        completion: Completion::Exited(1),
        stdout: b"Running transaction\n  Installing       : python36-1.0-1.el9.x86_64  1/1\n"
            .to_vec(),
        stderr: b"Error: Test transaction failed\n".to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    });
    let sink = RecordingSink::new();
    let report = run("phase3-dnf-failure", INSTALL, fake, sink.clone());
    let r = find(&report, "p");
    assert_eq!(r.execution, Execution::Failed, "{:?}", r.reason);
    assert_eq!(r.change, Change::Possible);

    let events = sink.events();
    let end = stage_end(&events);
    assert!(
        !events[end + 1..]
            .iter()
            .any(|event| matches!(event, ProgressEvent::PackageDetail(_))),
        "a detail followed the stage end even though the mutation failed"
    );
}

// ---------------------------------------------------------------------------
// Reporter contract: framing, de-duplication, rate limit, bounds
// ---------------------------------------------------------------------------

fn reporter(sink: Arc<dyn ProgressSink>) -> Arc<PackageReporter> {
    PackageReporter::start(
        ItemRef {
            kind: ItemKind::Package,
            id: "python36".to_string(),
        },
        PackageBackend::Dnf,
        Box::new(DnfProgressParser::new()),
        sink,
    )
    .expect("a reporter")
}

#[test]
fn a_line_split_across_chunks_and_cr_frames_are_parsed_once() {
    let sink = RecordingSink::new();
    let rep = reporter(sink.clone());
    let install = b"  Installing       : python36-1.0-1.el9.x86_64  1/1\n".to_vec();
    let (a, b) = install.split_at(19);
    rep.stdout(a);
    rep.stdout(b);
    // The same line again (DNF can repeat a frame) is one event.
    rep.stdout(&install);
    // DNF5 uses CR to overwrite a bar in place; each frame is a line.
    rep.stderr(
        b"[ 2/ 3] Removing python36-1.0-1.el9.x86_64  100% | 1.0 MiB/s | 10.0 MiB | 00:01\r",
    );
    rep.stderr(
        b"[ 2/ 3] Removing python36-1.0-1.el9.x86_64  100% | 1.0 MiB/s | 10.0 MiB | 00:01\r",
    );
    rep.finish();

    let found = details(&sink.events());
    let installing = found
        .iter()
        .filter(|d| d.phase == PackagePhase::Installing)
        .count();
    let removing = found
        .iter()
        .filter(|d| d.phase == PackagePhase::Removing)
        .count();
    assert_eq!(installing, 1, "{found:?}");
    assert_eq!(removing, 1, "{found:?}");
    assert_no_percent(&found);
}

#[test]
fn high_frequency_lines_are_rate_limited_and_finish_returns() {
    let sink = RecordingSink::new();
    let rep = reporter(sink.clone());
    for i in 0..500 {
        let line = format!("  Installing       : pkg{i}-1.0-1.el9.x86_64  1/500\n");
        rep.stdout(line.as_bytes());
    }
    rep.finish();
    let found = details(&sink.events());
    assert!(!found.is_empty());
    // Ten events per second across both streams; a slow machine may cross a
    // one-second window boundary, so allow two windows' worth.
    assert!(
        found.len() <= (sinter::package_progress::MAX_EVENTS_PER_SECOND as usize) * 2,
        "{} events escaped the rate limit",
        found.len()
    );
}

#[test]
fn invalid_utf8_and_overlong_lines_are_dropped_without_an_event() {
    let sink = RecordingSink::new();
    let rep = reporter(sink.clone());
    rep.stdout(b"\xff\xfe  Installing : acl  1/1\n");
    let mut long = Vec::from(&b"  Installing       : "[..]);
    long.extend(std::iter::repeat_n(b'a', 10_000));
    long.extend_from_slice(b"  1/1\n");
    rep.stdout(&long);
    rep.finish();
    assert!(
        details(&sink.events()).is_empty(),
        "hostile input produced an event"
    );
}

#[test]
fn a_disabled_sink_starts_no_reporter() {
    assert!(PackageReporter::start(
        ItemRef {
            kind: ItemKind::Package,
            id: "python36".to_string(),
        },
        PackageBackend::Dnf,
        Box::new(DnfProgressParser::new()),
        Arc::new(sinter::progress::NoopSink),
    )
    .is_none());

    // The observer interface is still implemented by the reporter; a dropped
    // chunk after finish is ignored rather than panicking.
    let sink = RecordingSink::new();
    let rep = reporter(sink.clone());
    rep.finish();
    rep.stdout(b"  Installing       : acl  1/1\n");
    assert!(details(&sink.events()).is_empty());
}

#[test]
fn the_parser_never_panics_on_arbitrary_bytes() {
    let mut parser = DnfProgressParser::new();
    let mut split = LineSplitter::new();
    let mut state = 0x1234_5678u32;
    let mut bytes = Vec::new();
    for _ in 0..4096 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        bytes.push((state >> 16) as u8);
    }
    split.feed(&bytes, |line| {
        let _ = parser.observe(line);
    });
}
