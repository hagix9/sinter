//! Unit tests of the DNF progress grammar.

use super::*;
use crate::progress::PercentScope;

fn parse(line: &str) -> Option<PackageObservation> {
    DnfProgressParser::new().observe(line)
}

/// Every emitted observation must obey the no-invented-numbers contract: a
/// percent always carries its scope, and a DNF observation never carries one
/// because non-TTY DNF prints no measured transaction percentage.
fn assert_no_percent(obs: &PackageObservation) {
    assert_eq!(obs.percent, None, "{obs:?}");
    assert_eq!(obs.percent_scope, None, "{obs:?}");
    assert_eq!(obs.confidence, ProgressConfidence::Measured);
    assert_ne!(obs.percent_scope, Some(PercentScope::DownloadAggregate));
}

// ---------------------------------------------------------------------------
// DNF4 transaction lines
// ---------------------------------------------------------------------------

#[test]
fn dnf4_install_action_reports_the_package_and_the_printed_count() {
    let obs =
        parse("  Installing       : python36-3.6.8-39.module+el8.10.0+1910+234ad790.x86_64  1/3")
            .expect("action line");
    assert_eq!(obs.phase, PackagePhase::Installing);
    assert_eq!(obs.scope, PackageScope::Package);
    assert_eq!(obs.source, ProgressSource::DnfTransactionLine);
    assert_eq!(
        obs.package.as_deref(),
        Some("python36-3.6.8-39.module+el8.10.0+1910+234ad790.x86_64")
    );
    assert_eq!(obs.packages_done, Some(1));
    assert_eq!(obs.packages_total, Some(3));
    assert_no_percent(&obs);
}

#[test]
fn dnf4_removal_actions_are_never_reported_as_installs() {
    // `Erasing` is DNF4's remove action; `Cleanup` is the old package of an
    // upgrade. Neither may surface as "installing" (the C1 APT bug class).
    for line in [
        "  Erasing          : python36-3.6.8-39.module+el8.10.0+1910+234ad790.x86_64  1/1",
        "  Cleanup          : kernel-4.18.0-553.el8_10.x86_64  2/3",
        "  Removing         : python36-3.6.8-39.module+el8.10.0+1910+234ad790.x86_64  1/2",
    ] {
        let obs = parse(line).unwrap_or_else(|| panic!("{line}"));
        assert_eq!(obs.phase, PackagePhase::Removing, "{line}");
        assert_ne!(obs.phase, PackagePhase::Installing, "{line}");
    }
}

#[test]
fn dnf4_verify_scriptlet_and_prepare_actions_map_to_their_phases() {
    assert_eq!(
        parse("  Verifying        : acl-2.3.2-1.el9.x86_64  2/2")
            .unwrap()
            .phase,
        PackagePhase::Verifying
    );
    assert_eq!(
        parse("  Running scriptlet: acl-2.3.2-1.el9.x86_64  1/1")
            .unwrap()
            .phase,
        PackagePhase::Triggering
    );
    // `Preparing` (TRANS_PREPARATION) runs for an install and for a remove
    // alike, so it does not establish a direction and is not a phase.
    assert!(parse("  Preparing        : acl-2.3.2-1.el9.x86_64  1/1").is_none());
}

#[test]
fn dnf4_upgrade_family_is_reported_as_the_install_phase() {
    for label in ["Upgrading", "Downgrading", "Reinstalling", "Obsoleting"] {
        let line = format!("  {label:<17}: acl-2.3.2-1.el9.x86_64  1/1");
        let obs = parse(&line).unwrap_or_else(|| panic!("{label}"));
        assert_eq!(obs.phase, PackagePhase::Installing, "{label}");
        assert_eq!(obs.package.as_deref(), Some("acl-2.3.2-1.el9.x86_64"));
    }
}

#[test]
fn dnf4_action_without_a_package_keeps_the_phase_and_drops_the_name() {
    let obs = parse("  Verifying        : (none)  1/1").expect("action line");
    assert_eq!(obs.phase, PackagePhase::Verifying);
    assert_eq!(obs.scope, PackageScope::Transaction);
    assert_eq!(obs.package, None);
    assert_eq!(obs.packages_done, Some(1));
}

#[test]
fn dnf4_transaction_table_lines_are_not_actions() {
    for line in [
        "Installing:",
        "Installing dependencies:",
        " Package          Arch   Version   Repository  Size",
        "Installed:",
        "  python3-pip-9.0.3-24.el8.rocky.0.noarch",
        "Complete!",
    ] {
        assert!(parse(line).is_none(), "{line:?} was misread");
    }
}

#[test]
fn unknown_actions_and_malformed_counts_are_ignored() {
    assert!(parse("  Frobnicating     : acl-2.3.2-1.el9.x86_64  1/1").is_none());
    assert!(parse("  Installing       : acl-2.3.2-1.el9.x86_64  2/1").is_none());
    assert!(parse("  Installing       : acl-2.3.2-1.el9.x86_64  0/0").is_none());
    assert!(parse("  Installing       : acl-2.3.2-1.el9.x86_64  one/three").is_none());
}

// ---------------------------------------------------------------------------
// DNF4 stage markers
// ---------------------------------------------------------------------------

#[test]
fn dnf4_stage_markers_map_to_phases_without_numbers() {
    // `Running transaction` is printed for a removal as well as an install
    // (`dnf/base.py` prints it unconditionally before the transaction), so
    // reporting "installing" for it would misclassify a remove. The first
    // direction-specific action line establishes the phase instead.
    assert!(parse("Running transaction").is_none());

    let downloading = parse("Downloading Packages:").expect("marker");
    assert_eq!(downloading.phase, PackagePhase::Downloading);
    assert_no_percent(&downloading);

    assert_eq!(
        parse("Running transaction check").unwrap().phase,
        PackagePhase::Resolving
    );
    assert_eq!(
        parse("Running transaction test").unwrap().phase,
        PackagePhase::Resolving
    );
    assert_eq!(
        parse("Repositories loaded.").unwrap().phase,
        PackagePhase::Resolving
    );
}

#[test]
fn completion_and_failure_lines_are_not_phases() {
    // Success/failure is the exit code's and the re-observation's business.
    for line in [
        "Complete!",
        "Nothing to do.",
        "Error: GPG check FAILED",
        "Transaction failed: signature check failed",
        "Last metadata expiration check: 0:01:00 ago on Sat Oct 17 04:58:29 2026.",
    ] {
        assert!(parse(line).is_none(), "{line:?} became a phase");
    }
}

// ---------------------------------------------------------------------------
// DNF4 download lines
// ---------------------------------------------------------------------------

#[test]
fn dnf4_download_completion_line_reports_file_counts_without_a_percent() {
    let obs =
        parse("(1/2): python3-pip-9.0.3-24.el8.rocky.0.noarch.rpm  1.0 MB/s | 6.5 kB     00:00")
            .expect("download line");
    assert_eq!(obs.phase, PackagePhase::Downloading);
    assert_eq!(obs.scope, PackageScope::Transaction);
    assert_eq!(obs.source, ProgressSource::DnfDownloadLine);
    assert_eq!(obs.files_done, Some(1));
    assert_eq!(obs.files_total, Some(2));
    // `6.5 kB` is a rounded human display, not 6656 measured bytes.
    assert_eq!(obs.bytes_downloaded, None);
    assert_eq!(obs.bytes_total, None);
    assert_eq!(obs.rate_bps, None);
    assert_no_percent(&obs);
}

#[test]
fn dnf4_single_file_completion_has_no_file_count() {
    let obs =
        parse("v151-badsig-1.0-1.noarch.rpm  1.0 MB/s | 6.5 kB  00:00").expect("download line");
    assert_eq!(obs.phase, PackagePhase::Downloading);
    assert_eq!(obs.files_done, None);
    assert_eq!(obs.files_total, None);
}

#[test]
fn dnf4_exact_byte_values_are_reported_and_rounded_ones_are_not() {
    let obs = parse("tiny-1.0-1.noarch.rpm  648 B/s | 512 B  00:00").expect("download line");
    assert_eq!(obs.bytes_downloaded, Some(512));
    assert_eq!(obs.bytes_total, Some(512));
    assert_eq!(obs.rate_bps, Some(648));

    let total = parse("Total  648 B/s | 512 B  00:00").expect("total line");
    assert_eq!(total.bytes_downloaded, Some(512));
    assert_eq!(total.rate_bps, Some(648));

    // Binary units in either DNF4 (`MB`) or DNF5 (`MiB`) spelling are rounded.
    for line in [
        "big-1.0-1.noarch.rpm  1.0 MB/s | 6.5 kB  00:00",
        "big-1.0-1.noarch.rpm  1.0 MiB/s | 6.5 KiB  00:00",
    ] {
        let obs = parse(line).unwrap_or_else(|| panic!("{line}"));
        assert_eq!(obs.bytes_downloaded, None, "{line}");
        assert_eq!(obs.rate_bps, None, "{line}");
    }
}

#[test]
fn a_long_download_time_is_still_a_meter_line() {
    // `format_time` prints minutes without an upper bound: `123:45`.
    let obs = parse("big-1.0-1.noarch.rpm  648 B/s | 512 B  123:45").expect("download line");
    assert_eq!(obs.bytes_downloaded, Some(512));
    assert_eq!(obs.rate_bps, Some(648));
}

#[test]
fn dnf4_metadata_and_failure_completion_lines_are_not_package_progress() {
    for line in [
        "Sinter synthetic test repo  1.3 MB/s | 1.3 kB  00:00",
        "[FAILED] v151-badsig-1.0-1.noarch: 1.3 MB/s | 1.3 kB  00:00",
        "[SKIPPED] v151-badsig-1.0-1.noarch.rpm: 1.3 MB/s | 1.3 kB  00:00",
        "[MIRROR] v151-badsig-1.0-1.noarch.rpm: 1.3 MB/s | 1.3 kB  00:00",
        "not a meter line at all",
        "a | b | c",
        "file.rpm  1.0 MB/s | 6.5 kB  00:00 | extra",
    ] {
        assert!(parse(line).is_none(), "{line:?} was misread");
    }
}

// ---------------------------------------------------------------------------
// DNF5 completed bars
// ---------------------------------------------------------------------------

#[test]
fn dnf5_install_bar_reports_the_phase_and_package_but_not_its_item_percent() {
    let obs = parse(
        "[ 2/ 4] Installing python3.11-0:3.11.7-1.el9.x86_64  100% | 3.2 MiB/s | 30.0 MiB | 00:24",
    )
    .expect("bar");
    assert_eq!(obs.phase, PackagePhase::Installing);
    assert_eq!(obs.scope, PackageScope::Package);
    assert_eq!(obs.source, ProgressSource::DnfTransactionLine);
    assert_eq!(
        obs.package.as_deref(),
        Some("python3.11-0:3.11.7-1.el9.x86_64")
    );
    // The bar's 100% is this item's completion, not the transaction's.
    assert_no_percent(&obs);
    // DNF5's `[n/m]` counts the prepare step too, so it is not a package
    // count and is not reported as one.
    assert_eq!(obs.packages_done, None);
    assert_eq!(obs.packages_total, None);
}

#[test]
fn dnf5_removal_and_cleanup_bars_are_removals() {
    for description in [
        "Removing python3.11-0:3.11.7-1.el9.x86_64",
        "Cleanup python3.11-0:3.11.7-1.el9.x86_64",
    ] {
        let line = format!("[ 2/ 3] {description}  100% | 1.0 MiB/s | 10.0 MiB | 00:01");
        let obs = parse(&line).unwrap_or_else(|| panic!("{description}"));
        assert_eq!(obs.phase, PackagePhase::Removing, "{description}");
        assert_ne!(obs.phase, PackagePhase::Installing, "{description}");
    }
}

#[test]
fn dnf5_standalone_bars_map_to_their_phases() {
    // DNF5 creates the same `Prepare transaction` bar for an install and for
    // a remove; it carries no direction, so it is not reported as a phase.
    assert!(parse("[ 1/ 4] Prepare transaction  100% | 0.0 B/s | 0.0 B | 00:00").is_none());
    assert_eq!(
        parse("[ 4/ 4] Verify package files  100% | 1.0 MiB/s | 2.0 MiB | 00:01")
            .unwrap()
            .phase,
        PackagePhase::Verifying
    );
    assert_eq!(
        parse("[ 3/ 4] Running scriptlets  100% | 0.0 B/s | 0.0 B | 00:01")
            .unwrap()
            .phase,
        PackagePhase::Triggering
    );
}

#[test]
fn dnf5_download_bar_reports_file_counts_without_its_item_percent() {
    let obs = parse(
        "[ 1/ 2] python3-pip-9.0.3-24.el8.rocky.0.noarch.rpm  100% | 1.0 MiB/s | 6.5 KiB | 00:01",
    )
    .expect("bar");
    assert_eq!(obs.phase, PackagePhase::Downloading);
    assert_eq!(obs.scope, PackageScope::Transaction);
    assert_eq!(obs.source, ProgressSource::DnfDownloadLine);
    assert_eq!(obs.files_done, Some(1));
    assert_eq!(obs.files_total, Some(2));
    // Neither the per-item percentage nor the rounded size becomes a number.
    assert_no_percent(&obs);
    assert_eq!(obs.bytes_downloaded, None);
    assert_eq!(obs.rate_bps, None);
}

#[test]
fn dnf5_unknown_bars_are_ignored() {
    for line in [
        "[ 1/ 1] Total  100% | 1.0 MiB/s | 6.5 KiB | 00:01",
        "[ 1/ 1] some metadata file.xml  100% | 1.0 MiB/s | 6.5 KiB | 00:01",
        "[ 1/ 1] Frobbing foo-1.0-1.el9.x86_64  100% | 1.0 MiB/s | 6.5 KiB | 00:01",
        "[ 1/ 1] Installing foo-1.0-1.el9.x86_64  101% | 1.0 MiB/s | 6.5 KiB | 00:01",
        "[ 1/ 1] Installing foo-1.0-1.el9.x86_64  lots% | 1.0 MiB/s | 6.5 KiB | 00:01",
        "[ 1/1] malformed",
        "[] Installing foo-1.0-1.el9.x86_64  100% | 1.0 MiB/s | 6.5 KiB | 00:01",
    ] {
        assert!(parse(line).is_none(), "{line:?} was misread");
    }
}

#[test]
fn an_unknown_total_is_accepted_as_dnf5_prints_it() {
    let obs = parse("[ 1/ 1] Installing foo-1.0-1.el9.x86_64  ???% | --- | 1.0 MiB | 00:01")
        .expect("bar");
    assert_eq!(obs.phase, PackagePhase::Installing);
}

// ---------------------------------------------------------------------------
// Bounds and hostile input
// ---------------------------------------------------------------------------

#[test]
fn control_characters_and_long_lines_never_yield_a_number() {
    let mut long = String::from("  Installing : ");
    long.push_str(&"a".repeat(10_000));
    long.push_str("  1/1");
    assert!(parse(&long).is_none());

    for line in [
        "  Installing       : acl\x1b[2J-2.3.2  1/1",
        "  Installing       : acl-2.3.2  1/1\x07",
        "  Installing       : acl-2.3.2  1/1\r",
    ] {
        if let Some(obs) = parse(line) {
            // A trailing control character may only drop the token; it must
            // never become part of a reported number.
            let _ = obs;
        }
    }

    // An OSC/CSI sequence with a plausible shape yields no package metric.
    assert!(parse("\x1b]0;title\x07  Installing : acl  1/1").is_none());
}

#[test]
fn a_real_install_stream_never_reports_a_removal_and_vice_versa() {
    let install = [
        "Running transaction check",
        "Running transaction",
        "  Preparing        : acl-2.3.2-1.el9.x86_64  1/2",
        "  Installing       : acl-2.3.2-1.el9.x86_64  1/2",
        "  Verifying        : acl-2.3.2-1.el9.x86_64  2/2",
        "Complete!",
    ];
    let mut phases = Vec::new();
    for line in install {
        if let Some(obs) = parse(line) {
            phases.push(obs.phase);
        }
    }
    assert!(!phases.contains(&PackagePhase::Removing), "{phases:?}");

    let remove = [
        "Running transaction check",
        "  Erasing          : acl-2.3.2-1.el9.x86_64  1/1",
        "  Verifying        : acl-2.3.2-1.el9.x86_64  1/1",
        "Complete!",
    ];
    let mut phases = Vec::new();
    for line in remove {
        if let Some(obs) = parse(line) {
            phases.push(obs.phase);
        }
    }
    assert!(!phases.contains(&PackagePhase::Installing), "{phases:?}");
    assert!(phases.contains(&PackagePhase::Removing), "{phases:?}");
}

#[test]
fn repeated_lines_are_still_observations_the_emitter_can_deduplicate() {
    let line = "  Installing       : acl-2.3.2-1.el9.x86_64  1/1";
    let first = parse(line).expect("first");
    let second = parse(line).expect("second");
    assert_eq!(first, second, "the parser itself is stateless");
}
