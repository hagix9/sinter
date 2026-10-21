//! Unit tests of the package-progress seam: line framing, name validation,
//! de-duplication, rate limiting, the reporter thread, non-blocking delivery
//! and panic isolation.

use super::*;
use crate::progress::{ItemKind, RecordingSink};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A parser that recognizes exactly one synthetic record: `pct <0-100>`.
struct PctParser;

impl PackageParser for PctParser {
    fn observe(&mut self, line: &str) -> Option<PackageObservation> {
        let percent: u8 = line.strip_prefix("pct ")?.parse().ok()?;
        let mut obs = PackageObservation::new(
            PackagePhase::Downloading,
            PackageScope::Transaction,
            ProgressSource::AptStatusFdDl,
            ProgressConfidence::Measured,
        );
        obs.percent = Some(percent);
        obs.percent_scope = Some(PercentScope::DownloadAggregate);
        obs.files_done = Some(u32::from(percent) / 25);
        obs.files_total = Some(4);
        Some(obs)
    }
}

/// A parser that panics on the line `boom`.
struct PanickingParser;

impl PackageParser for PanickingParser {
    fn observe(&mut self, line: &str) -> Option<PackageObservation> {
        if line == "boom" {
            panic!("parser panic");
        }
        PctParser.observe(line)
    }
}

fn package_item() -> ItemRef {
    ItemRef {
        kind: ItemKind::Package,
        id: "postgresql".to_string(),
    }
}

fn reporter(
    parser: Box<dyn PackageParser>,
    sink: Arc<dyn ProgressSink>,
) -> Option<Arc<PackageReporter>> {
    PackageReporter::start(
        package_item(),
        crate::platform::PackageBackend::Apt,
        parser,
        sink,
    )
}

fn details(events: &[ProgressEvent]) -> Vec<PackageProgress> {
    events
        .iter()
        .filter_map(|ev| match ev {
            ProgressEvent::PackageDetail(p) => Some(p.clone()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Line framing
// ---------------------------------------------------------------------------

#[test]
fn splitter_ends_lines_on_lf_and_cr_and_drops_empty_ones() {
    let mut split = LineSplitter::new();
    let mut out = Vec::new();
    split.feed(b"a\nb\rc\r\nd\n\n", |line| out.push(line.to_string()));
    assert_eq!(out, vec!["a", "b", "c", "d"]);
}

#[test]
fn splitter_joins_a_line_split_across_chunks() {
    let mut split = LineSplitter::new();
    let mut out = Vec::new();
    for chunk in [&b"hel"[..], &b"lo wo"[..], &b"rld\n"[..]] {
        split.feed(chunk, |line| out.push(line.to_string()));
    }
    assert_eq!(out, vec!["hello world"]);
}

#[test]
fn splitter_joins_a_multibyte_character_split_across_chunks() {
    let mut split = LineSplitter::new();
    let mut out = Vec::new();
    // "é" is 0xC3 0xA9: the chunk boundary is inside the character.
    split.feed(b"caf\xc3", |line| out.push(line.to_string()));
    split.feed(b"\xa9\n", |line| out.push(line.to_string()));
    assert_eq!(out, vec!["café"]);
}

#[test]
fn splitter_accepts_a_full_length_line_and_drops_a_longer_one_whole() {
    let mut split = LineSplitter::new();
    let mut out = Vec::new();
    let mut exact = vec![b'x'; MAX_LINE];
    exact.push(b'\n');
    split.feed(&exact, |line| out.push(line.len()));
    assert_eq!(out, vec![MAX_LINE], "a line of exactly MAX_LINE is kept");

    out.clear();
    let mut over = vec![b'y'; MAX_LINE + 1];
    over.push(b'\n');
    split.feed(&over, |line| out.push(line.len()));
    assert!(out.is_empty(), "an over-long line is dropped whole");
    // Parsing resumes cleanly on the next line.
    split.feed(b"ok\n", |line| out.push(line.len()));
    assert_eq!(out, vec![2]);
}

#[test]
fn splitter_drops_invalid_utf8_lines() {
    let mut split = LineSplitter::new();
    let mut out = Vec::new();
    split.feed(b"good\n\xff\xfe bad\nother\n", |line| {
        out.push(line.to_string())
    });
    assert_eq!(out, vec!["good", "other"]);
}

// ---------------------------------------------------------------------------
// Package names
// ---------------------------------------------------------------------------

#[test]
fn package_name_grammar_is_conservative() {
    for ok in [
        "postgresql",
        "python3.11",
        "g++",
        "libstdc++-12-dev",
        "2ping",
        "NetworkManager-config-server",
        "1:postgresql-16.3-1PGDG.rhel9.x86_64",
    ] {
        assert!(valid_package_name(ok), "{ok}");
        assert_eq!(sanitize_package_name(ok).as_deref(), Some(ok));
    }
    for bad in [
        "",
        " with-space",
        "-leading-dash",
        "name\nnewline",
        "name\u{7}bell",
        "http://example.invalid/pkg.deb",
        "quote'name",
        &"x".repeat(PACKAGE_NAME_MAX + 1),
    ] {
        assert!(!valid_package_name(bad), "{bad:?}");
        assert!(sanitize_package_name(bad).is_none(), "{bad:?}");
    }
}

// ---------------------------------------------------------------------------
// De-duplication and rate limiting
// ---------------------------------------------------------------------------

#[test]
fn identical_observations_produce_one_event() {
    let sink = RecordingSink::new();
    let r = reporter(Box::new(PctParser), sink.clone()).expect("enabled sink");
    r.stdout(b"pct 9\npct 9\npct 9\n");
    r.finish();
    assert_eq!(details(&sink.events()).len(), 1);
}

#[test]
fn a_changed_percentage_produces_a_new_event() {
    let sink = RecordingSink::new();
    let r = reporter(Box::new(PctParser), sink.clone()).expect("enabled sink");
    r.stdout(b"pct 9\npct 10\npct 72\n");
    r.finish();
    let got: Vec<u8> = details(&sink.events())
        .iter()
        .filter_map(|p| p.percent)
        .collect();
    assert_eq!(got, vec![9, 10, 72]);
}

#[test]
fn the_event_rate_is_bounded_per_second() {
    let sink = RecordingSink::new();
    let r = reporter(Box::new(PctParser), sink.clone()).expect("enabled sink");
    let mut input = Vec::new();
    for percent in 0..=100u8 {
        input.extend_from_slice(format!("pct {percent}\n").as_bytes());
    }
    r.stdout(&input);
    r.finish();
    let events = details(&sink.events());
    assert_eq!(events.len(), MAX_EVENTS_PER_SECOND as usize, "{events:?}");
    // The stream is still monotonic: no event was invented out of order.
    let percents: Vec<u8> = events.iter().filter_map(|p| p.percent).collect();
    assert!(percents.windows(2).all(|w| w[0] < w[1]), "{percents:?}");
}

// ---------------------------------------------------------------------------
// Reporter lifecycle
// ---------------------------------------------------------------------------

#[test]
fn a_disabled_sink_starts_no_reporter() {
    let sink: Arc<dyn ProgressSink> = Arc::new(crate::progress::NoopSink);
    assert!(reporter(Box::new(PctParser), sink).is_none());
}

#[test]
fn details_carry_the_resource_backend_and_stage() {
    let sink = RecordingSink::new();
    let r = reporter(Box::new(PctParser), sink.clone()).expect("enabled sink");
    r.stdout(b"pct 50\n");
    r.finish();
    let events = details(&sink.events());
    assert_eq!(events.len(), 1);
    let p = &events[0];
    assert_eq!(p.stage, crate::progress::Stage::Resources);
    assert_eq!(p.resource.kind, ItemKind::Package);
    assert_eq!(p.resource.id, "postgresql");
    assert_eq!(p.backend, crate::platform::PackageBackend::Apt);
    assert_eq!(p.attempt, 1);
    assert_eq!(p.percent, Some(50));
    assert_eq!(p.percent_scope, Some(PercentScope::DownloadAggregate));
    assert_eq!(p.files_done, Some(2));
    assert_eq!(p.files_total, Some(4));
    // The reporter's events satisfy the published invariants when surrounded
    // by the lifecycle events the engine owns.
    let mut stream = vec![
        ProgressEvent::StageStarted {
            stage: crate::progress::Stage::Resources,
            total: Some(1),
        },
        ProgressEvent::Progress {
            stage: crate::progress::Stage::Resources,
            done: 0,
            total: Some(1),
            current: Some(package_item()),
        },
    ];
    stream.extend(sink.events());
    stream.push(ProgressEvent::StageEnded {
        stage: crate::progress::Stage::Resources,
        outcome: crate::progress::StageOutcome::Completed,
        done: 1,
    });
    crate::progress::validate_stream(&stream).expect("valid detail stream");
}

#[test]
fn a_panicking_parser_is_isolated_and_stops_observation() {
    let sink = RecordingSink::new();
    let r = reporter(Box::new(PanickingParser), sink.clone()).expect("enabled sink");
    r.stdout(b"pct 10\nboom\npct 20\n");
    r.stderr(b"pct 30\n");
    r.finish();
    let events = details(&sink.events());
    assert_eq!(
        events.len(),
        1,
        "only the line before the panic is reported"
    );
    assert_eq!(events[0].percent, Some(10));
}

#[test]
fn finish_is_idempotent_and_late_chunks_are_ignored() {
    let sink = RecordingSink::new();
    let r = reporter(Box::new(PctParser), sink.clone()).expect("enabled sink");
    r.stdout(b"pct 10\n");
    r.finish();
    r.stdout(b"pct 90\n");
    r.finish();
    let events = details(&sink.events());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].percent, Some(10));
}

#[test]
fn dropping_a_reporter_without_finish_does_not_hang() {
    let sink = RecordingSink::new();
    let r = reporter(Box::new(PctParser), sink.clone()).expect("enabled sink");
    r.stdout(b"pct 10\n");
    drop(r);
    // The event may or may not have been emitted before the drop; what matters
    // is that dropping returned and the parser thread ends.
    assert!(details(&sink.events()).len() <= 1);
}

// ---------------------------------------------------------------------------
// Non-blocking delivery
// ---------------------------------------------------------------------------

/// A sink that blocks on its first event until released, then never blocks.
struct BlockingSink {
    rx: Mutex<mpsc::Receiver<()>>,
    blocked_once: AtomicBool,
}

impl ProgressSink for BlockingSink {
    fn emit(&self, _event: &ProgressEvent) {
        if !self.blocked_once.swap(true, AtomicOrdering::SeqCst) {
            let rx = self.rx.lock().unwrap_or_else(|e| e.into_inner());
            let _ = rx.recv_timeout(Duration::from_secs(2));
        }
    }
}

#[test]
fn a_blocked_sink_never_blocks_the_drain_thread() {
    let (tx, rx) = mpsc::channel();
    let sink = Arc::new(BlockingSink {
        rx: Mutex::new(rx),
        blocked_once: AtomicBool::new(false),
    });
    let r = reporter(Box::new(PctParser), sink.clone()).expect("enabled sink");
    r.stdout(b"pct 10\n");
    // Let the parser thread reach the blocking emit.
    std::thread::sleep(Duration::from_millis(50));
    let started = Instant::now();
    r.stdout(b"pct 20\n");
    let elapsed = started.elapsed();
    let _ = tx.send(());
    r.finish();
    assert!(
        elapsed < Duration::from_millis(500),
        "stdout() blocked for {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// Observed-byte bound
// ---------------------------------------------------------------------------

#[test]
fn observation_stops_at_the_byte_cap_without_panicking() {
    let sink = RecordingSink::new();
    let r = reporter(Box::new(PctParser), sink.clone()).expect("enabled sink");
    // One huge chunk: the reporter copies at most MAX_OBSERVED_BYTES.
    r.stdout(&vec![b'z'; MAX_OBSERVED_BYTES + 4096]);
    r.finish();
    assert!(details(&sink.events()).is_empty());
}

// ---------------------------------------------------------------------------
// Bounded finish (Phase 1 fix A)
// ---------------------------------------------------------------------------

/// A sink whose first event blocks until released.
struct HangSink {
    entered: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ProgressSink for HangSink {
    fn emit(&self, _event: &ProgressEvent) {
        if let Some(tx) = self
            .entered
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = tx.send(());
        }
        let rx = self.release.lock().unwrap_or_else(|e| e.into_inner());
        let _ = rx.recv_timeout(Duration::from_secs(10));
    }
}

#[test]
fn an_unknown_sink_defaults_to_may_block() {
    let sink: Arc<dyn ProgressSink> = Arc::new(crate::progress::NoopSink);
    assert!(sink.is_non_blocking(), "the no-op sink cannot block");
    let recording = RecordingSink::new();
    assert!(
        recording.is_non_blocking(),
        "the recording sink cannot block"
    );
    let (tx, rx) = mpsc::channel();
    let custom = Arc::new(HangSink {
        entered: Mutex::new(Some(tx)),
        release: Mutex::new(rx),
    });
    assert!(
        !custom.is_non_blocking(),
        "an unknown sink must be assumed to block"
    );
}

#[test]
fn finish_does_not_wait_for_a_blocking_sink() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let sink: Arc<dyn ProgressSink> = Arc::new(HangSink {
        entered: Mutex::new(Some(entered_tx)),
        release: Mutex::new(release_rx),
    });
    let r = reporter(Box::new(PctParser), sink).expect("enabled sink");

    r.stdout(b"pct 10\n");
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the parser reached the blocking sink");

    let started = Instant::now();
    r.finish();
    let elapsed = started.elapsed();
    let _ = release_tx.send(());
    assert!(
        elapsed < Duration::from_millis(500),
        "finish() waited {elapsed:?} for a blocking sink"
    );
}

#[test]
fn a_non_blocking_sink_receives_every_queued_chunk_before_finish_returns() {
    struct CountParser {
        lines: Arc<Mutex<Vec<String>>>,
    }
    impl PackageParser for CountParser {
        fn observe(&mut self, line: &str) -> Option<PackageObservation> {
            self.lines
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(line.to_string());
            None
        }
    }

    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = RecordingSink::new();
    let r = reporter(
        Box::new(CountParser {
            lines: seen.clone(),
        }),
        sink.clone(),
    )
    .expect("enabled sink");
    for i in 0..200 {
        r.stdout(format!("line-{i:03}\n").as_bytes());
    }
    r.finish();
    let lines = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(lines.len(), 200, "every queued chunk is drained");
    assert_eq!(lines.first().map(String::as_str), Some("line-000"));
    assert_eq!(lines.last().map(String::as_str), Some("line-199"));
}

#[test]
fn the_observation_bound_is_per_stream() {
    struct EndParser {
        out_end: Arc<AtomicBool>,
        err_end: Arc<AtomicBool>,
    }
    impl PackageParser for EndParser {
        fn observe(&mut self, line: &str) -> Option<PackageObservation> {
            match line {
                "OUT-END" => self.out_end.store(true, AtomicOrdering::SeqCst),
                "ERR-END" => self.err_end.store(true, AtomicOrdering::SeqCst),
                _ => {}
            }
            None
        }
    }

    let out_end = Arc::new(AtomicBool::new(false));
    let err_end = Arc::new(AtomicBool::new(false));
    let sink = RecordingSink::new();
    let r = reporter(
        Box::new(EndParser {
            out_end: out_end.clone(),
            err_end: err_end.clone(),
        }),
        sink,
    )
    .expect("enabled sink");

    // ~606 KiB on each stream: together more than the 1 MiB bound, each below
    // it. A combined bound would cut the end of stderr.
    let filler = format!("{}\n", "y".repeat(100)).repeat(6000);
    r.stdout(filler.as_bytes());
    r.stdout(b"OUT-END\n");
    r.stderr(filler.as_bytes());
    r.stderr(b"ERR-END\n");
    r.finish();

    assert!(out_end.load(AtomicOrdering::SeqCst), "stdout tail observed");
    assert!(
        err_end.load(AtomicOrdering::SeqCst),
        "stderr has its own 1 MiB bound"
    );
}
