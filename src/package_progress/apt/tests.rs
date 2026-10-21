//! Unit tests of the APT progress grammar.

use super::*;

fn parse(line: &str) -> Option<PackageObservation> {
    AptProgressParser::new().observe(line)
}

// ---------------------------------------------------------------------------
// dlstatus
// ---------------------------------------------------------------------------

#[test]
fn dlstatus_maps_percent_and_file_counts() {
    let obs = parse("dlstatus:2:72.5000:Retrieving file 2 of 3").expect("record");
    assert_eq!(obs.phase, PackagePhase::Downloading);
    assert_eq!(obs.scope, PackageScope::Transaction);
    assert_eq!(obs.source, ProgressSource::AptStatusFdDl);
    assert_eq!(obs.confidence, ProgressConfidence::Measured);
    assert_eq!(obs.percent, Some(72));
    assert_eq!(obs.percent_scope, Some(PercentScope::DownloadAggregate));
    assert_eq!(obs.files_done, Some(2));
    assert_eq!(obs.files_total, Some(3));
    // No bytes and no rate: APT does not export them live.
    assert_eq!(obs.bytes_downloaded, None);
    assert_eq!(obs.bytes_total, None);
    assert_eq!(obs.rate_bps, None);
}

#[test]
fn dlstatus_percent_is_floored_and_bounded() {
    assert_eq!(parse("dlstatus:1:0.0000:x").unwrap().percent, Some(0));
    assert_eq!(parse("dlstatus:1:100.0000:x").unwrap().percent, Some(100));
    assert_eq!(parse("dlstatus:1:99.9999:x").unwrap().percent, Some(99));
}

#[test]
fn dlstatus_rejects_invalid_percentages() {
    for bad in [
        "dlstatus:1:101.0:x",
        "dlstatus:1:-1:x",
        "dlstatus:1:NaN:x",
        "dlstatus:1:inf:x",
        "dlstatus:1::x",
        "dlstatus:1:abc:x",
        "dlstatus:only-two-fields",
    ] {
        assert!(parse(bad).is_none(), "{bad}");
    }
}

#[test]
fn dlstatus_keeps_the_percent_without_english_file_words() {
    // A localized description still yields the measured percentage; only the
    // file counter is missing.
    let obs = parse("dlstatus:1:42.0000:Datei 1 von 3 wird abgerufen").expect("record");
    assert_eq!(obs.percent, Some(42));
    assert_eq!(obs.files_done, Some(1), "the record index is the fallback");
    assert_eq!(obs.files_total, None);
}

#[test]
fn dlstatus_with_control_characters_is_still_bounded() {
    let obs = parse("dlstatus:1:50.0000:\u{1b}[31mEVIL\u{7}").expect("record");
    assert_eq!(obs.percent, Some(50));
    assert_eq!(obs.files_total, None);
    assert!(obs.package.is_none());
}

// ---------------------------------------------------------------------------
// pmstatus
// ---------------------------------------------------------------------------

#[test]
fn pmstatus_install_actions_are_transaction_wide() {
    for (action, phase) in [
        ("Preparing postgresql", PackagePhase::Installing),
        ("Unpacking postgresql", PackagePhase::Installing),
        (
            "Preparing to configure postgresql",
            PackagePhase::Configuring,
        ),
        ("Configuring postgresql", PackagePhase::Configuring),
        ("Installed postgresql", PackagePhase::Configuring),
        ("Removing postgresql", PackagePhase::Removing),
        ("Purging postgresql", PackagePhase::Removing),
    ] {
        let line = format!("pmstatus:postgresql:40.0000:{action}");
        let obs = parse(&line).unwrap_or_else(|| panic!("{action}"));
        assert_eq!(obs.phase, phase, "{action}");
        assert_eq!(obs.package.as_deref(), Some("postgresql"), "{action}");
        assert_eq!(obs.percent, Some(40), "{action}");
        assert_eq!(
            obs.percent_scope,
            Some(PercentScope::TransactionOperation),
            "{action}"
        );
        assert_eq!(obs.scope, PackageScope::Transaction, "{action}");
    }
}

#[test]
fn pmstatus_dpkg_exec_is_not_a_package_name() {
    let obs = parse("pmstatus:dpkg-exec:60.0000:Running dpkg").expect("record");
    assert_eq!(obs.package, None);
    assert_eq!(obs.phase, PackagePhase::Installing);
    assert_eq!(obs.percent, Some(60));
}

#[test]
fn pmstatus_with_an_invalid_package_name_keeps_the_phase() {
    let obs = parse("pmstatus:bad name:40.0000:Unpacking x").expect("record");
    assert_eq!(obs.package, None);
    assert_eq!(obs.phase, PackagePhase::Installing);
    assert_eq!(obs.percent, Some(40));
}

#[test]
fn pmstatus_with_an_unknown_action_is_ignored() {
    assert!(parse("pmstatus:postgresql:40.0000:Frobnicating").is_none());
    assert!(parse("pmstatus:postgresql:not-a-number:Unpacking").is_none());
    assert!(parse("pmstatus:postgresql:101:Unpacking").is_none());
}

#[test]
fn pmerror_and_pmconffile_are_never_parsed() {
    assert!(parse("pmerror:postgresql:40.0000:E: something failed").is_none());
    assert!(parse("pmconffile:postgresql:40.0000:Configuration file '/etc/x'").is_none());
}

// ---------------------------------------------------------------------------
// Human-readable fallback markers
// ---------------------------------------------------------------------------

#[test]
fn need_to_get_reports_the_exact_total() {
    let obs = parse("Need to get 80.1 MB of archives.").expect("marker");
    assert_eq!(obs.bytes_total, Some(80_100_000));
    assert_eq!(obs.phase, PackagePhase::Downloading);
    assert_eq!(obs.confidence, ProgressConfidence::Measured);
    assert_eq!(obs.percent, None, "no percentage is invented");
}

#[test]
fn need_to_get_handles_a_partially_cached_transaction() {
    let obs = parse("Need to get 0 B/80.1 MB of archives.").expect("marker");
    assert_eq!(obs.bytes_total, Some(80_100_000));
}

#[test]
fn fetched_reports_exact_bytes_and_the_printed_rate() {
    let obs = parse("Fetched 80.1 MB in 3s (23.0 MB/s)").expect("marker");
    assert_eq!(obs.bytes_downloaded, Some(80_100_000));
    assert_eq!(obs.bytes_total, Some(80_100_000));
    assert_eq!(obs.rate_bps, Some(23_000_000));
}

#[test]
fn fetched_handles_the_minutes_duration_form() {
    let obs = parse("Fetched 80.1 MB in 1min 2s (1.3 MB/s)").expect("marker");
    assert_eq!(obs.bytes_downloaded, Some(80_100_000));
    assert_eq!(obs.rate_bps, Some(1_300_000));
}

#[test]
fn fetched_without_a_printed_rate_derives_it_from_measured_values() {
    let obs = parse("Fetched 80.1 MB in 2s").expect("marker");
    assert_eq!(obs.rate_bps, Some(40_050_000));
}

#[test]
fn unpacking_and_setting_up_name_the_package() {
    let obs = parse("Unpacking acl (2.3.2-1build1.1) ...").expect("marker");
    assert_eq!(obs.phase, PackagePhase::Installing);
    assert_eq!(obs.scope, PackageScope::Package);
    assert_eq!(obs.package.as_deref(), Some("acl"));

    let obs = parse("Setting up attr (1:2.5.2-1ubuntu0.1) ...").expect("marker");
    assert_eq!(obs.phase, PackagePhase::Configuring);
    assert_eq!(obs.package.as_deref(), Some("attr"));
}

#[test]
fn processing_triggers_is_a_transaction_phase() {
    let obs = parse("Processing triggers for man-db (2.12.0-4) ...").expect("marker");
    assert_eq!(obs.phase, PackagePhase::Triggering);
    assert_eq!(obs.scope, PackageScope::Transaction);
    assert_eq!(obs.percent, None);
}

#[test]
fn unrelated_lines_and_get_lines_are_ignored() {
    for line in [
        "Get:1 http://mirror/x.deb [39.4 kB]",
        "Reading package lists...",
        "",
        "   ",
        "\u{1b}]0;title\u{7}",
        "X",
    ] {
        assert!(parse(line).is_none(), "{line:?}");
    }
}

#[test]
fn hostile_text_never_panics_or_escapes_the_line() {
    let long = format!("dlstatus:1:50.0000:{}", "a".repeat(4096));
    let obs = parse(&long).expect("the record prefix still parses");
    assert_eq!(obs.percent, Some(50));
    for bad in [
        "dlstatus::::",
        "pmstatus::",
        "pmstatus:a:b",
        "Fetched ",
        "Fetched x y in z",
        "Need to get ",
        "Unpacking ",
        "Setting up ",
        "\u{0}\u{1}\u{2}",
    ] {
        let _ = parse(bad);
    }
}

// ---------------------------------------------------------------------------
// status-fd vs. human-readable fallback (Phase 2 fix)
// ---------------------------------------------------------------------------

#[test]
fn a_status_fd_download_suppresses_the_stale_need_to_get_line() {
    let mut parser = AptProgressParser::new();
    assert!(parser
        .observe("dlstatus:1:50.0000:Retrieving file 1 of 2")
        .is_some());
    // The human line would replace "download 50%" with a percent-less event.
    assert!(parser.observe("Need to get 80.1 MB of archives.").is_none());
}

#[test]
fn a_status_fd_install_suppresses_the_duplicate_human_markers() {
    let mut parser = AptProgressParser::new();
    assert!(parser
        .observe("pmstatus:acl:40.0000:Unpacking acl")
        .is_some());
    for line in [
        "Unpacking acl (2.3.2-1build1.1) ...",
        "Setting up acl (2.3.2-1build1.1) ...",
        "Processing triggers for man-db (2.12.0-4) ...",
    ] {
        assert!(parser.observe(line).is_none(), "{line}");
    }
}

#[test]
fn a_late_fetched_line_does_not_override_the_install_phase() {
    let mut parser = AptProgressParser::new();
    assert!(parser
        .observe("pmstatus:acl:40.0000:Unpacking acl")
        .is_some());
    // APT's stdout is buffered; the human "Fetched" line can be flushed after
    // the status records and would otherwise replace "install 40%".
    assert!(parser
        .observe("Fetched 80.1 MB in 3s (23.0 MB/s)")
        .is_none());
}

#[test]
fn without_status_records_the_fallback_still_works() {
    let mut parser = AptProgressParser::new();
    for line in [
        "Need to get 80.1 MB of archives.",
        "Fetched 80.1 MB in 3s (23.0 MB/s)",
        "Unpacking acl (2.3.2-1build1.1) ...",
        "Setting up acl (2.3.2-1build1.1) ...",
        "Processing triggers for man-db (2.12.0-4) ...",
    ] {
        assert!(parser.observe(line).is_some(), "{line}");
    }
}

#[test]
fn an_invalid_status_record_does_not_make_the_fallback_stale() {
    let mut parser = AptProgressParser::new();
    assert!(parser.observe("pmstatus:acl:NaN:Unpacking acl").is_none());
    assert!(parser.observe("Unpacking acl (2.3.2) ...").is_some());
}
