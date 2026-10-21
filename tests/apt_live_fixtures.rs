//! Replays the real APT streams captured on the C1 Ubuntu hosts through the
//! production parser and line splitter.
//!
//! The fixtures in `tests/fixtures/apt/` are byte captures of
//! `apt-get -o APT::Status-Fd=1` stdout/stderr, with the only change being the
//! public mirror hostname replaced by `<mirror>`. They are real Ubuntu 24.04.5
//! (APT 2.8.3) and Ubuntu 26.04.1 (APT 3.2.0) output, not synthetic records.

use sinter::package_progress::apt::AptProgressParser;
use sinter::package_progress::{LineSplitter, PackageObservation, PackageParser};
use sinter::progress::{PackagePhase, PercentScope};
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/apt")
        .join(name)
}

fn observations(name: &str) -> Vec<PackageObservation> {
    let bytes = std::fs::read(fixture(name)).expect("fixture");
    let mut splitter = LineSplitter::new();
    let mut parser = AptProgressParser::new();
    let mut out = Vec::new();
    splitter.feed(&bytes, |line| {
        if let Some(observation) = parser.observe(line) {
            out.push(observation);
        }
    });
    out
}

fn percents(events: &[PackageObservation], scope: PercentScope) -> Vec<u8> {
    events
        .iter()
        .filter(|e| e.percent_scope == Some(scope))
        .filter_map(|e| e.percent)
        .collect()
}

#[test]
fn ubuntu24_download_stream_yields_measured_download_progress() {
    let events = observations("ubuntu24-download.out");
    let download = percents(&events, PercentScope::DownloadAggregate);
    assert!(!download.is_empty(), "no dlstatus percent: {events:?}");
    assert!(download.iter().all(|p| *p <= 100));
    assert_eq!(download.last(), Some(&100), "{download:?}");
    assert!(
        download.contains(&24),
        "the real 24.1021% record must survive: {download:?}"
    );
    // The measured percent is what the UI shows; the human "Need to get" line
    // must not appear as a percent-less download event after it.
    assert!(
        !events.iter().any(|e| {
            e.phase == PackagePhase::Downloading && e.percent.is_none() && e.files_total == Some(1)
        }),
        "a percent-less download event leaked: {events:?}"
    );
}

#[test]
fn ubuntu26_download_stream_yields_measured_download_progress() {
    let events = observations("ubuntu26-download.out");
    let download = percents(&events, PercentScope::DownloadAggregate);
    assert!(!download.is_empty(), "no dlstatus percent: {events:?}");
    assert_eq!(download.last(), Some(&100), "{download:?}");
}

#[test]
fn ubuntu24_install_stream_reports_the_installing_message() {
    let events = observations("ubuntu24-install.out");
    assert!(
        events.iter().any(|e| e.phase == PackagePhase::Installing
            && e.percent == Some(40)
            && e.package.as_deref() == Some("hello")),
        "the `Installing hello` pmstatus record must be parsed: {events:?}"
    );
    let install = percents(&events, PercentScope::TransactionOperation);
    assert!(install.contains(&20), "{install:?}");
    assert!(install.contains(&40), "{install:?}");
    assert!(install.contains(&60), "{install:?}");
    assert!(install.contains(&80), "{install:?}");
    assert!(
        !events.iter().any(|e| e.phase == PackagePhase::Removing),
        "an install must not report a removal: {events:?}"
    );
    // The .deb was cached, so the real stream says `Need to get 0 B`; no
    // download phase exists in this run.
    assert!(
        !events.iter().any(|e| e.phase == PackagePhase::Downloading),
        "a phantom download phase: {events:?}"
    );
}

#[test]
fn ubuntu26_install_stream_reports_the_installing_message() {
    let events = observations("ubuntu26-install.out");
    assert!(
        events.iter().any(|e| e.phase == PackagePhase::Installing
            && e.percent == Some(40)
            && e.package.as_deref() == Some("hello")),
        "{events:?}"
    );
    assert!(!events.iter().any(|e| e.phase == PackagePhase::Removing));
}

#[test]
fn both_remove_streams_report_removals_and_never_installs() {
    for name in ["ubuntu24-remove.out", "ubuntu26-remove.out"] {
        let events = observations(name);
        assert!(!events.is_empty(), "{name}");
        assert!(
            events.iter().all(|e| e.phase == PackagePhase::Removing),
            "{name}: a removal reported another phase: {events:?}"
        );
        assert!(
            events.iter().any(|e| e.package.as_deref() == Some("hello")),
            "{name}"
        );
        let remove = percents(&events, PercentScope::TransactionOperation);
        assert!(remove.contains(&33), "{name}: {remove:?}");
        assert!(remove.contains(&66), "{name}: {remove:?}");
    }
}

#[test]
fn debconf_noise_on_stderr_produces_no_progress_events() {
    for name in ["ubuntu24-install.err", "ubuntu26-install.err"] {
        let events = observations(name);
        assert!(events.is_empty(), "{name}: {events:?}");
    }
}

// ---------------------------------------------------------------------------
// Through the production reporter (parse -> dedup -> rate limit -> sink)
// ---------------------------------------------------------------------------

use sinter::executor::ExecObserver;
use sinter::package_progress::PackageReporter;
use sinter::platform::PackageBackend;
use sinter::progress::{ItemKind, ItemRef, ProgressEvent, RecordingSink, Stage, StageOutcome};

fn reported(name: &str) -> Vec<ProgressEvent> {
    let sink = RecordingSink::new();
    let resource = ItemRef {
        kind: ItemKind::Package,
        id: "hello".to_string(),
    };
    let reporter = PackageReporter::start(
        resource.clone(),
        PackageBackend::Apt,
        Box::new(AptProgressParser::new()),
        sink.clone(),
    )
    .expect("enabled sink");
    reporter.stdout(&std::fs::read(fixture(name)).expect("fixture"));
    reporter.finish();
    let mut stream = vec![
        ProgressEvent::StageStarted {
            stage: Stage::Resources,
            total: Some(1),
        },
        ProgressEvent::Progress {
            stage: Stage::Resources,
            done: 0,
            total: Some(1),
            current: Some(resource),
        },
    ];
    stream.extend(sink.events());
    stream.push(ProgressEvent::StageEnded {
        stage: Stage::Resources,
        outcome: StageOutcome::Completed,
        done: 1,
    });
    sinter::progress::validate_stream(&stream).expect("a valid detail stream");
    stream
}

fn detail_phases(stream: &[ProgressEvent]) -> Vec<PackagePhase> {
    stream
        .iter()
        .filter_map(|event| match event {
            ProgressEvent::PackageDetail(detail) => Some(detail.phase),
            _ => None,
        })
        .collect()
}

#[test]
fn the_real_install_stream_survives_dedup_and_rate_limiting() {
    let stream = reported("ubuntu24-install.out");
    let phases = detail_phases(&stream);
    assert!(phases.contains(&PackagePhase::Installing), "{phases:?}");
    assert!(phases.contains(&PackagePhase::Configuring), "{phases:?}");
    assert!(!phases.contains(&PackagePhase::Downloading), "{phases:?}");
    assert!(!phases.contains(&PackagePhase::Removing), "{phases:?}");
}

#[test]
fn the_real_remove_stream_never_reaches_the_renderer_as_an_install() {
    for name in ["ubuntu24-remove.out", "ubuntu26-remove.out"] {
        let stream = reported(name);
        let phases = detail_phases(&stream);
        assert!(!phases.is_empty(), "{name}");
        assert!(
            phases.iter().all(|p| *p == PackagePhase::Removing),
            "{name}: {phases:?}"
        );
    }
}
