//! Stage R1 unit tests: R0 real-output fixtures, fail-closed preview parsing,
//! exact-set decisions, inventory fingerprints and planned/actual deltas.

use super::inventory::{verify_stability, InventoryFingerprint, RemovalExecutionDelta};
use super::*;
use crate::error::{ErrorKind, MutationState};

const DNF5_44: &[(&str, &str, &str)] = &[
    ("unzip", "aarch64", "6.0-67.fc43"),
    ("rpm-build", "aarch64", "6.0.2-1.fc43"),
    ("zip", "aarch64", "3.0-44.fc43"),
    ("add-determinism", "aarch64", "0.6.0-3.fc43"),
    ("annobin-docs", "noarch", "12.99-1.fc43"),
    ("annobin-plugin-gcc", "aarch64", "12.99-1.fc43"),
    ("ansible-srpm-macros", "noarch", "1-18.1.fc43"),
    (
        "build-reproducibility-srpm-macros",
        "noarch",
        "0.6.0-3.fc43",
    ),
    ("bzip2", "aarch64", "1.0.8-21.fc43"),
    ("cmake-srpm-macros", "noarch", "3.31.11-1.fc43"),
    ("debugedit", "aarch64", "5.2-3.fc43"),
    ("dwz", "aarch64", "0.16-2.fc43"),
    ("ed", "aarch64", "1.22.2-1.fc43"),
    ("efi-srpm-macros", "noarch", "6-4.fc43"),
    ("elfutils", "aarch64", "0.196-1.fc43"),
    ("filesystem-srpm-macros", "noarch", "3.18-50.fc43"),
    ("fonts-srpm-macros", "noarch", "1:2.0.5-23.fc43"),
    ("forge-srpm-macros", "noarch", "0.4.0-3.fc43"),
    ("fpc-srpm-macros", "noarch", "1.3-15.fc43"),
    ("gap-srpm-macros", "noarch", "2-1.fc43"),
    ("gcc-plugin-annobin", "aarch64", "15.3.1-1.fc43"),
    ("gdb-minimal", "aarch64", "17.2-2.fc43"),
    ("ghc-srpm-macros", "noarch", "1.9.2-3.fc43"),
    ("gnat-srpm-macros", "noarch", "7-1.fc43"),
    ("gnome-srpm-macros", "noarch", "1.0-1.fc43"),
    ("go-srpm-macros", "noarch", "3.8.0-1.fc43"),
    ("gpgverify", "noarch", "2.2-3.fc43"),
    ("java-srpm-macros", "noarch", "1-7.fc43"),
    ("kernel-srpm-macros", "noarch", "1.0-27.fc43"),
    ("libpfm", "aarch64", "4.13.0-20.fc43"),
    ("lua-srpm-macros", "noarch", "1-16.fc43"),
    ("ocaml-srpm-macros", "noarch", "11-2.fc43"),
    ("openblas-srpm-macros", "noarch", "2-20.fc43"),
    ("package-notes-srpm-macros", "noarch", "0.20-1.fc43"),
    ("patch", "aarch64", "2.8-2.fc43"),
    ("perl-srpm-macros", "noarch", "1-60.fc43"),
    ("pyproject-srpm-macros", "noarch", "1.23.2-1.fc43"),
    ("python-srpm-macros", "noarch", "3.14-5.fc43"),
    ("qt5-srpm-macros", "noarch", "5.15.18-1.fc43"),
    ("qt6-srpm-macros", "noarch", "6.10.3-1.fc43"),
    ("redhat-rpm-config", "noarch", "343-14.fc43"),
    ("rust-srpm-macros", "noarch", "28.5-1.fc43"),
    ("tree-sitter-srpm-macros", "noarch", "0.4.2-1.fc43"),
    ("zig-srpm-macros", "noarch", "1-5.fc43"),
];

const DNF5_8: &[(&str, &str, &str)] = &[
    ("unzip", "aarch64", "6.0-67.fc43"),
    ("fonts-srpm-macros", "noarch", "1:2.0.5-23.fc43"),
    ("forge-srpm-macros", "noarch", "0.4.0-3.fc43"),
    ("go-srpm-macros", "noarch", "3.8.0-1.fc43"),
    ("python-srpm-macros", "noarch", "3.14-5.fc43"),
    ("redhat-rpm-config", "noarch", "343-14.fc43"),
    ("rpm-build", "aarch64", "6.0.2-1.fc43"),
    ("zip", "aarch64", "3.0-44.fc43"),
];

const DNF4_UNZIP: &[(&str, &str, &str)] = &[
    ("unzip", "aarch64", "6.0-60.el9_8"),
    ("zip", "aarch64", "3.0-35.el9"),
];

const DNF4_TCPDUMP: &[(&str, &str, &str)] = &[
    ("tcpdump", "aarch64", "14:4.99.0-9.el9"),
    ("libibverbs", "aarch64", "61.0-2.el9"),
    ("libpcap", "aarch64", "14:1.10.0-4.el9_8.1"),
];

const DNF4_TCPDUMP_NOAUTO: &[(&str, &str, &str)] = &[("tcpdump", "aarch64", "14:4.99.0-9.el9")];

const APT_REVERSE: &[(&str, Option<&str>, Option<&str>)] = &[
    ("p7zip-full", None, Some("16.02+transitional.1")),
    ("7zip", None, Some("23.01+dfsg-11")),
];

const APT_AUTO_REMOVE: &[(&str, Option<&str>, Option<&str>)] = &[
    ("p7zip-full", None, Some("16.02+transitional.1")),
    ("7zip", None, Some("23.01+dfsg-11")),
    ("fortunes-min", None, Some("1:1.99.1-7.3build1")),
    ("libcaca0", None, Some("0.99.beta20-4ubuntu0.2")),
    ("librecode0", None, Some("3.6-26")),
    ("toilet-fonts", None, Some("0.3-1.4build1")),
];

fn actual_identities(preview: &RemovalPreview) -> Vec<(String, Option<String>, Option<String>)> {
    preview
        .planned_removals()
        .iter()
        .map(|p| {
            (
                p.identity().name().to_string(),
                p.identity().architecture().map(ToOwned::to_owned),
                p.identity().version().map(ToOwned::to_owned),
            )
        })
        .collect()
}

fn expected_dnf(rows: &[(&str, &str, &str)]) -> Vec<(String, Option<String>, Option<String>)> {
    rows.iter()
        .map(|(name, arch, version)| {
            (
                (*name).to_string(),
                Some((*arch).to_string()),
                Some((*version).to_string()),
            )
        })
        .collect()
}

fn expected_apt(
    rows: &[(&str, Option<&str>, Option<&str>)],
) -> Vec<(String, Option<String>, Option<String>)> {
    rows.iter()
        .map(|(name, arch, version)| {
            (
                (*name).to_string(),
                arch.map(ToOwned::to_owned),
                version.map(ToOwned::to_owned),
            )
        })
        .collect()
}

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("../../tests/fixtures/removal_r1/", $name))
    };
}

fn input<'a>(stdout: &'a str, stderr: &'a str, exit_code: i32) -> PreviewInput<'a> {
    PreviewInput {
        exit_code,
        stdout: stdout.as_bytes(),
        stderr: stderr.as_bytes(),
        stdout_truncated: false,
        stderr_truncated: false,
        backend_version: None,
    }
}

fn parse_apt(
    requested: &str,
    stdout: &str,
    stderr: &str,
) -> Result<RemovalPreview, RemovalSafetyError> {
    parse_preview(
        RemovalBackend::Apt,
        requested,
        input(stdout, stderr, 0),
        false,
    )
}

fn parse_dnf(
    backend: RemovalBackend,
    requested: &str,
    stdout: &str,
    stderr: &str,
    exit_code: i32,
    no_autoremove: bool,
) -> Result<RemovalPreview, RemovalSafetyError> {
    parse_preview(
        backend,
        requested,
        input(stdout, stderr, exit_code),
        no_autoremove,
    )
}

fn names(preview: &RemovalPreview) -> Vec<&str> {
    preview
        .planned_removals()
        .iter()
        .map(|p| p.identity().name())
        .collect()
}

fn count_reason(preview: &RemovalPreview, reason: RemovalReason) -> usize {
    preview
        .planned_removals()
        .iter()
        .filter(|p| p.reason() == reason)
        .count()
}

fn decision(preview: &RemovalPreview, allowed: &[&str]) -> RemovalSafetyDecision {
    let allow = RemovalAllowList::from_names(allowed).expect("allow-list");
    evaluate(preview, &allow)
}

// ---------------------------------------------------------------------------
// APT
// ---------------------------------------------------------------------------

#[test]
fn apt_reverse_dependency_preview_parses_two_identities() {
    let p = parse_apt(
        "7zip",
        fixture!("apt_reverse.out"),
        fixture!("apt_reverse.err"),
    )
    .expect("apt preview");
    assert_eq!(p.backend(), RemovalBackend::Apt);
    assert_eq!(p.summary_count(), 2);
    assert_eq!(p.exit(), PreviewExit::Completed);
    assert_eq!(names(&p), vec!["p7zip-full", "7zip"]);
    assert_eq!(count_reason(&p, RemovalReason::Requested), 1);
    assert_eq!(count_reason(&p, RemovalReason::Unknown), 1);
    assert_eq!(
        p.command_identity(),
        PreviewCommandIdentity::AptSimulatedRemove
    );
    let p7zip = p
        .planned_removals()
        .iter()
        .find(|r| r.identity().name() == "p7zip-full")
        .expect("p7zip-full");
    assert_eq!(p7zip.identity().architecture(), None);
    assert_eq!(p7zip.identity().version(), Some("16.02+transitional.1"));
}

#[test]
fn apt_root_simulation_without_note_parses_the_same_set() {
    let p = parse_apt("7zip", fixture!("apt_root_reverse.out"), "").expect("root apt preview");
    assert_eq!(p.planned_removals().len(), 2);
    assert_eq!(p.exit(), PreviewExit::Completed);
}

#[test]
fn apt_single_requested_removal_is_allowed() {
    let p = parse_apt(
        "p7zip-full",
        fixture!("apt_single.out"),
        fixture!("apt_single.err"),
    )
    .expect("apt single");
    assert_eq!(p.planned_removals().len(), 1);
    assert!(decision(&p, &[]).is_allowed());
}

#[test]
fn apt_auto_remove_output_is_parsed_but_denied() {
    let p = parse_apt("p7zip-full", fixture!("apt_auto_remove.out"), "")
        .expect("apt auto-remove preview");
    assert_eq!(p.planned_removals().len(), 6);
    assert!(decision(&p, &[]).is_denied());
}

#[test]
fn apt_absent_preview_is_noop() {
    let p = parse_apt(
        "7zip",
        fixture!("apt_absent.out"),
        fixture!("apt_absent.err"),
    )
    .expect("apt absent");
    assert_eq!(p.exit(), PreviewExit::NoOp);
    assert!(p.planned_removals().is_empty());
    assert!(matches!(
        decision(&p, &[]),
        RemovalSafetyDecision::Indeterminate { .. }
    ));
}

#[test]
fn apt_noop_and_removal_records_together_are_rejected() {
    let stdout = fixture!("apt_reverse.out").replace(
        "0 upgraded, 0 newly installed, 2 to remove and 179 not upgraded.",
        "Package '7zip' is not installed, so not removed\n0 upgraded, 0 newly installed, 2 to remove and 179 not upgraded.",
    );
    assert!(parse_apt("7zip", &stdout, "").is_err());
}

#[test]
fn apt_summary_mismatch_is_rejected() {
    let stdout = fixture!("apt_reverse.out").replace("2 to remove", "3 to remove");
    let err = parse_apt("7zip", &stdout, "").expect_err("summary mismatch");
    assert_eq!(
        err.category(),
        RemovalSafetyCategory::PreviewSummaryMismatch
    );
}

#[test]
fn apt_duplicate_remv_is_rejected() {
    let stdout = fixture!("apt_reverse.out")
        .replace(
            "0 upgraded, 0 newly installed, 2 to remove and 179 not upgraded.",
            "0 upgraded, 0 newly installed, 3 to remove and 179 not upgraded.",
        )
        .replace(
            "Remv p7zip-full [16.02+transitional.1]\n",
            "Remv p7zip-full [16.02+transitional.1]\nRemv p7zip-full [16.02+transitional.1]\n",
        );
    let err = parse_apt("7zip", &stdout, "").expect_err("duplicate");
    assert_eq!(
        err.category(),
        RemovalSafetyCategory::PackageIdentityAmbiguous
    );
}

#[test]
fn apt_inst_line_is_rejected() {
    let stdout = fixture!("apt_reverse.out").replace(
        "0 upgraded, 0 newly installed, 2 to remove and 179 not upgraded.",
        "Inst extra [1.0]\n0 upgraded, 0 newly installed, 2 to remove and 179 not upgraded.",
    );
    assert!(parse_apt("7zip", &stdout, "").is_err());
}

#[test]
fn apt_conf_line_and_unknown_stderr_are_rejected() {
    let conf = fixture!("apt_reverse.out").replace(
        "0 upgraded, 0 newly installed, 2 to remove and 179 not upgraded.",
        "Conf extra\n0 upgraded, 0 newly installed, 2 to remove and 179 not upgraded.",
    );
    assert!(parse_apt("7zip", &conf, "").is_err());

    let stderr = "unexpected apt diagnostic\n";
    assert_eq!(
        parse_apt("7zip", fixture!("apt_reverse.out"), stderr)
            .expect_err("stderr")
            .category(),
        RemovalSafetyCategory::PreviewParseFailed
    );
}

#[test]
fn apt_invalid_utf8_is_rejected() {
    let err = parse_preview(
        RemovalBackend::Apt,
        "7zip",
        PreviewInput {
            exit_code: 0,
            stdout: &[0xff, 0xfe],
            stderr: b"",
            stdout_truncated: false,
            stderr_truncated: false,
            backend_version: None,
        },
        false,
    )
    .expect_err("invalid utf8");
    assert_eq!(err.category(), RemovalSafetyCategory::PreviewParseFailed);
}

#[test]
fn apt_truncation_and_unexpected_exit_are_rejected() {
    let truncated = parse_preview(
        RemovalBackend::Apt,
        "7zip",
        PreviewInput {
            exit_code: 0,
            stdout: fixture!("apt_reverse.out").as_bytes(),
            stderr: b"",
            stdout_truncated: true,
            stderr_truncated: false,
            backend_version: None,
        },
        false,
    )
    .expect_err("truncated");
    assert_eq!(
        truncated.category(),
        RemovalSafetyCategory::PreviewParseFailed
    );
    let failed = parse_preview(
        RemovalBackend::Apt,
        "7zip",
        input(fixture!("apt_reverse.out"), "", 100),
        false,
    )
    .expect_err("exit");
    assert_eq!(
        failed.category(),
        RemovalSafetyCategory::PreviewCommandFailed
    );
}

#[test]
fn apt_missing_requested_package_is_rejected() {
    let err = parse_apt("zip", fixture!("apt_reverse.out"), "").expect_err("missing requested");
    assert_eq!(
        err.category(),
        RemovalSafetyCategory::RequestedPackageMissing
    );
}

// ---------------------------------------------------------------------------
// DNF4
// ---------------------------------------------------------------------------

#[test]
fn dnf4_reverse_dependency_preview_parses_requested_and_dependent() {
    let p = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .expect("dnf4 unzip");
    assert_eq!(p.exit(), PreviewExit::Aborted);
    assert_eq!(p.summary_count(), 2);
    assert_eq!(names(&p), vec!["unzip", "zip"]);
    assert_eq!(count_reason(&p, RemovalReason::Requested), 1);
    assert_eq!(count_reason(&p, RemovalReason::Dependent), 1);
    assert_eq!(
        p.command_identity(),
        PreviewCommandIdentity::Dnf4RemoveAssumeno {
            no_autoremove: false
        }
    );
}

#[test]
fn dnf4_no_autoremove_does_not_change_reverse_dependency_set() {
    let p = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip_noauto.out"),
        fixture!("dnf4_unzip_noauto.err"),
        1,
        true,
    )
    .expect("dnf4 unzip noauto");
    assert_eq!(names(&p), vec!["unzip", "zip"]);
    assert_eq!(
        p.command_identity(),
        PreviewCommandIdentity::Dnf4RemoveAssumeno {
            no_autoremove: true
        }
    );
}

#[test]
fn dnf4_unused_dependencies_and_no_autoremove_are_distinguished() {
    let default = parse_dnf(
        RemovalBackend::Dnf4,
        "tcpdump",
        fixture!("dnf4_tcpdump.out"),
        fixture!("dnf4_tcpdump.err"),
        1,
        false,
    )
    .expect("dnf4 tcpdump");
    assert_eq!(names(&default), vec!["tcpdump", "libibverbs", "libpcap"]);
    assert_eq!(count_reason(&default, RemovalReason::Requested), 1);
    assert_eq!(count_reason(&default, RemovalReason::UnusedDependency), 2);

    let noauto = parse_dnf(
        RemovalBackend::Dnf4,
        "tcpdump",
        fixture!("dnf4_tcpdump_noauto.out"),
        fixture!("dnf4_tcpdump_noauto.err"),
        1,
        true,
    )
    .expect("dnf4 tcpdump noauto");
    assert_eq!(names(&noauto), vec!["tcpdump"]);
}

#[test]
fn dnf4_absent_preview_is_noop() {
    let p = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_absent.out"),
        fixture!("dnf4_absent.err"),
        0,
        false,
    )
    .expect("dnf4 absent");
    assert_eq!(p.exit(), PreviewExit::NoOp);
    assert!(p.planned_removals().is_empty());
}

#[test]
fn dnf4_summary_mismatch_is_rejected() {
    let stdout = fixture!("dnf4_unzip.out").replace("Remove  2 Packages", "Remove  3 Packages");
    let err = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        &stdout,
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .expect_err("summary mismatch");
    assert_eq!(
        err.category(),
        RemovalSafetyCategory::PreviewSummaryMismatch
    );
}

#[test]
fn dnf4_installing_section_is_rejected() {
    let stdout = fixture!("dnf4_unzip.out").replace(
        "Removing:\n",
        "Installing:\n foo aarch64 1.0 @baseos 1 k\nRemoving:\n",
    );
    assert!(parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        &stdout,
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .is_err());
}

#[test]
fn dnf4_unknown_stderr_and_duplicate_abort_are_rejected() {
    let err = format!("{}Unexpected diagnostic.\n", fixture!("dnf4_unzip.err"));
    assert_eq!(
        parse_dnf(
            RemovalBackend::Dnf4,
            "unzip",
            fixture!("dnf4_unzip.out"),
            &err,
            1,
            false,
        )
        .expect_err("stderr")
        .category(),
        RemovalSafetyCategory::PreviewAbortUnexpected
    );
    let duplicate = format!("{}Operation aborted.\n", fixture!("dnf4_unzip.err"));
    assert_eq!(
        parse_dnf(
            RemovalBackend::Dnf4,
            "unzip",
            fixture!("dnf4_unzip.out"),
            &duplicate,
            1,
            false,
        )
        .expect_err("duplicate abort")
        .category(),
        RemovalSafetyCategory::PreviewAbortUnexpected
    );
}

#[test]
fn dnf4_duplicate_row_and_malformed_identity_are_rejected() {
    let duplicate_row =
        " unzip          aarch64          6.0-60.el9_8            @baseos          469 k\n";
    let stdout = fixture!("dnf4_unzip.out").replace(
        "\nTransaction Summary",
        &format!("\n{duplicate_row}\nTransaction Summary"),
    );
    assert_eq!(
        parse_dnf(
            RemovalBackend::Dnf4,
            "unzip",
            &stdout,
            fixture!("dnf4_unzip.err"),
            1,
            false,
        )
        .expect_err("duplicate")
        .category(),
        RemovalSafetyCategory::PackageIdentityAmbiguous
    );

    let malformed = fixture!("dnf4_unzip.out").replace("aarch64", "bad/arch");
    assert!(parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        &malformed,
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .is_err());
    let bad_version = fixture!("dnf4_unzip.out").replace("6.0-60.el9_8", "bad/version");
    assert!(parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        &bad_version,
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .is_err());
}

#[test]
fn dnf4_unknown_section_is_rejected() {
    let stdout = fixture!("dnf4_unzip.out").replace("Removing:\n", "Frobbing:\n");
    assert!(parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        &stdout,
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .is_err());
}

#[test]
fn dnf4_invalid_repository_and_noop_stderr_with_rows_are_rejected() {
    let bad_repo = fixture!("dnf4_unzip.out").replace("@baseos", "bad repo");
    assert!(parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        &bad_repo,
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .is_err());

    assert_eq!(
        parse_dnf(
            RemovalBackend::Dnf4,
            "unzip",
            fixture!("dnf4_unzip.out"),
            "No packages marked for removal.\n",
            0,
            false,
        )
        .expect_err("noop stderr with rows")
        .category(),
        RemovalSafetyCategory::PreviewParseFailed
    );
}

#[test]
fn dnf4_truncation_invalid_utf8_and_exit_are_rejected() {
    let truncated = parse_preview(
        RemovalBackend::Dnf4,
        "unzip",
        PreviewInput {
            exit_code: 1,
            stdout: fixture!("dnf4_unzip.out").as_bytes(),
            stderr: fixture!("dnf4_unzip.err").as_bytes(),
            stdout_truncated: false,
            stderr_truncated: true,
            backend_version: None,
        },
        false,
    )
    .expect_err("truncated");
    assert_eq!(
        truncated.category(),
        RemovalSafetyCategory::PreviewParseFailed
    );

    let invalid = parse_preview(
        RemovalBackend::Dnf4,
        "unzip",
        PreviewInput {
            exit_code: 1,
            stdout: &[0xff],
            stderr: b"Operation aborted.\n",
            stdout_truncated: false,
            stderr_truncated: false,
            backend_version: None,
        },
        false,
    )
    .expect_err("utf8");
    assert_eq!(
        invalid.category(),
        RemovalSafetyCategory::PreviewParseFailed
    );

    let failed = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        2,
        false,
    )
    .expect_err("exit");
    assert_eq!(
        failed.category(),
        RemovalSafetyCategory::PreviewCommandFailed
    );
}

// ---------------------------------------------------------------------------
// DNF5
// ---------------------------------------------------------------------------

#[test]
fn dnf5_p6_06_44_identity_set_is_parsed() {
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_unzip_44.out"),
        fixture!("dnf5_unzip_44.err"),
        1,
        false,
    )
    .expect("dnf5 44");
    assert_eq!(p.exit(), PreviewExit::Aborted);
    assert_eq!(p.summary_count(), 44);
    assert_eq!(p.planned_removals().len(), 44);
    assert_eq!(count_reason(&p, RemovalReason::Requested), 1);
    assert_eq!(count_reason(&p, RemovalReason::Dependent), 2);
    assert_eq!(count_reason(&p, RemovalReason::UnusedDependency), 41);
    let names = names(&p);
    for expected in [
        "unzip",
        "rpm-build",
        "zip",
        "add-determinism",
        "redhat-rpm-config",
    ] {
        assert!(names.contains(&expected), "missing {expected}");
    }
}

#[test]
fn dnf5_p6_06_no_autoremove_8_identity_set_is_parsed() {
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_unzip_8.out"),
        fixture!("dnf5_unzip_8.err"),
        1,
        true,
    )
    .expect("dnf5 8");
    assert_eq!(p.summary_count(), 8);
    assert_eq!(
        names(&p),
        vec![
            "unzip",
            "fonts-srpm-macros",
            "forge-srpm-macros",
            "go-srpm-macros",
            "python-srpm-macros",
            "redhat-rpm-config",
            "rpm-build",
            "zip",
        ]
    );
    assert_eq!(count_reason(&p, RemovalReason::Dependent), 7);
    assert_eq!(count_reason(&p, RemovalReason::UnusedDependency), 0);
}

#[test]
fn backend_version_is_preserved_from_the_input() {
    let p = parse_preview(
        RemovalBackend::Dnf5,
        "unzip",
        PreviewInput {
            exit_code: 1,
            stdout: fixture!("dnf5_unzip_8.out").as_bytes(),
            stderr: fixture!("dnf5_unzip_8.err").as_bytes(),
            stdout_truncated: false,
            stderr_truncated: false,
            backend_version: Some("5.2.17.0"),
        },
        true,
    )
    .expect("versioned preview");
    assert_eq!(p.backend_version(), Some("5.2.17.0"));
}

#[test]
fn dnf5_tcpdump_sets_are_parsed() {
    let default = parse_dnf(
        RemovalBackend::Dnf5,
        "tcpdump",
        fixture!("dnf5_tcpdump_3.out"),
        fixture!("dnf5_tcpdump_3.err"),
        1,
        false,
    )
    .expect("dnf5 tcpdump 3");
    assert_eq!(names(&default), vec!["tcpdump", "libibverbs", "libpcap"]);
    assert_eq!(default.summary_count(), 3);

    let noauto = parse_dnf(
        RemovalBackend::Dnf5,
        "tcpdump",
        fixture!("dnf5_tcpdump_1.out"),
        fixture!("dnf5_tcpdump_1.err"),
        1,
        true,
    )
    .expect("dnf5 tcpdump 1");
    assert_eq!(names(&noauto), vec!["tcpdump"]);
    assert_eq!(noauto.summary_count(), 1);
}

#[test]
fn dnf5_absent_preview_is_noop() {
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_absent.out"),
        fixture!("dnf5_absent.err"),
        0,
        false,
    )
    .expect("dnf5 absent");
    assert_eq!(p.exit(), PreviewExit::NoOp);
    assert!(p.planned_removals().is_empty());
}

#[test]
fn dnf5_nothing_to_do_with_rows_is_rejected() {
    let stdout = fixture!("dnf5_unzip_44.out").replace(
        "Transaction Summary:",
        "Nothing to do.\nTransaction Summary:",
    );
    assert!(parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        &stdout,
        fixture!("dnf5_unzip_44.err"),
        1,
        false,
    )
    .is_err());
}

#[test]
fn dnf5_summary_mismatch_unknown_stderr_and_missing_abort_are_rejected() {
    let mismatch = fixture!("dnf5_unzip_44.out").replace("44 packages", "43 packages");
    assert_eq!(
        parse_dnf(
            RemovalBackend::Dnf5,
            "unzip",
            &mismatch,
            fixture!("dnf5_unzip_44.err"),
            1,
            false,
        )
        .expect_err("summary")
        .category(),
        RemovalSafetyCategory::PreviewSummaryMismatch
    );

    let extra_stderr = format!("{}Unexpected diagnostic.\n", fixture!("dnf5_unzip_44.err"));
    assert_eq!(
        parse_dnf(
            RemovalBackend::Dnf5,
            "unzip",
            fixture!("dnf5_unzip_44.out"),
            &extra_stderr,
            1,
            false,
        )
        .expect_err("stderr")
        .category(),
        RemovalSafetyCategory::PreviewAbortUnexpected
    );

    assert_eq!(
        parse_dnf(
            RemovalBackend::Dnf5,
            "unzip",
            fixture!("dnf5_unzip_44.out"),
            "",
            1,
            false,
        )
        .expect_err("missing abort")
        .category(),
        RemovalSafetyCategory::PreviewAbortUnexpected
    );
}

#[test]
fn dnf5_duplicate_row_and_malformed_table_are_rejected() {
    let duplicate_row =
        " unzip                             aarch64 6.0-67.fc43     fedora     470.2 KiB\n";
    let stdout = fixture!("dnf5_unzip_44.out").replace(
        "\nTransaction Summary:",
        &format!("\n{duplicate_row}\nTransaction Summary:"),
    );
    assert_eq!(
        parse_dnf(
            RemovalBackend::Dnf5,
            "unzip",
            &stdout,
            fixture!("dnf5_unzip_44.err"),
            1,
            false,
        )
        .expect_err("duplicate")
        .category(),
        RemovalSafetyCategory::PackageIdentityAmbiguous
    );

    let malformed = fixture!("dnf5_unzip_44.out").replace("aarch64 6.0-67.fc43", "bad/arch");
    assert!(parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        &malformed,
        fixture!("dnf5_unzip_44.err"),
        1,
        false,
    )
    .is_err());
}

#[test]
fn dnf5_unknown_section_is_rejected() {
    let stdout = fixture!("dnf5_unzip_44.out").replace("Removing:\n", "Frobbing:\n");
    assert!(parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        &stdout,
        fixture!("dnf5_unzip_44.err"),
        1,
        false,
    )
    .is_err());
}

#[test]
fn dnf5_truncation_and_exit_are_rejected() {
    let truncated = parse_preview(
        RemovalBackend::Dnf5,
        "unzip",
        PreviewInput {
            exit_code: 1,
            stdout: fixture!("dnf5_unzip_44.out").as_bytes(),
            stderr: fixture!("dnf5_unzip_44.err").as_bytes(),
            stdout_truncated: true,
            stderr_truncated: false,
            backend_version: None,
        },
        false,
    )
    .expect_err("truncated");
    assert_eq!(
        truncated.category(),
        RemovalSafetyCategory::PreviewParseFailed
    );
    let failed = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_unzip_44.out"),
        fixture!("dnf5_unzip_44.err"),
        2,
        false,
    )
    .expect_err("exit");
    assert_eq!(
        failed.category(),
        RemovalSafetyCategory::PreviewCommandFailed
    );
}

// ---------------------------------------------------------------------------
// Exact-set
// ---------------------------------------------------------------------------

#[test]
fn dnf5_44_is_denied_by_identity_not_by_count_alone() {
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_unzip_44.out"),
        fixture!("dnf5_unzip_44.err"),
        1,
        false,
    )
    .expect("44");
    let d = decision(&p, &[]);
    let RemovalSafetyDecision::Denied { unexpected } = d else {
        panic!("expected denial");
    };
    assert_eq!(unexpected.len(), 43);
    assert!(!unexpected.iter().any(|p| p.identity().name() == "unzip"));
    let unexpected_names: Vec<&str> = unexpected.iter().map(|p| p.identity().name()).collect();
    assert!(unexpected_names.contains(&"rpm-build"));
    assert!(unexpected_names.contains(&"zip"));
}

#[test]
fn dnf5_8_is_denied_with_seven_exact_extras() {
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_unzip_8.out"),
        fixture!("dnf5_unzip_8.err"),
        1,
        true,
    )
    .expect("8");
    let RemovalSafetyDecision::Denied { unexpected } = decision(&p, &[]) else {
        panic!("expected denial");
    };
    let unexpected_names: Vec<&str> = unexpected.iter().map(|p| p.identity().name()).collect();
    assert_eq!(
        unexpected_names,
        vec![
            "fonts-srpm-macros",
            "forge-srpm-macros",
            "go-srpm-macros",
            "python-srpm-macros",
            "redhat-rpm-config",
            "rpm-build",
            "zip",
        ]
    );
}

#[test]
fn dnf4_and_apt_reverse_dependencies_are_denied() {
    let dnf4 = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .expect("dnf4");
    let RemovalSafetyDecision::Denied { unexpected } = decision(&dnf4, &[]) else {
        panic!("dnf4 denial");
    };
    assert_eq!(
        unexpected
            .iter()
            .map(|p| p.identity().name())
            .collect::<Vec<_>>(),
        vec!["zip"]
    );

    let apt = parse_apt("7zip", fixture!("apt_reverse.out"), "").expect("apt");
    let RemovalSafetyDecision::Denied { unexpected } = decision(&apt, &[]) else {
        panic!("apt denial");
    };
    assert_eq!(
        unexpected
            .iter()
            .map(|p| p.identity().name())
            .collect::<Vec<_>>(),
        vec!["p7zip-full"]
    );
}

#[test]
fn exact_requested_is_allowed_and_explicit_extra_is_allowed() {
    let single = parse_dnf(
        RemovalBackend::Dnf4,
        "tcpdump",
        fixture!("dnf4_tcpdump_noauto.out"),
        fixture!("dnf4_tcpdump_noauto.err"),
        1,
        true,
    )
    .expect("single");
    assert!(decision(&single, &[]).is_allowed());

    let reverse = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .expect("reverse");
    let d = decision(&reverse, &["zip"]);
    let RemovalSafetyDecision::Allowed { additional, .. } = d else {
        panic!("expected allow");
    };
    assert_eq!(
        additional
            .iter()
            .map(|p| p.identity().name())
            .collect::<Vec<_>>(),
        vec!["zip"]
    );
}

#[test]
fn allowlist_rejects_wildcards_and_duplicates() {
    assert!(RemovalAllowList::from_names(["*"]).is_err());
    assert!(RemovalAllowList::from_names(["zip?"]).is_err());
    assert!(RemovalAllowList::from_names(["zip[0]"]).is_err());
    assert!(RemovalAllowList::from_names(["zip", "zip"]).is_err());
    assert!(RemovalAllowList::from_names(["zip"]).is_ok());
}

#[test]
fn requested_name_with_multiple_architectures_is_indeterminate() {
    let requested_a = PackageIdentity::new("pkg", Some("aarch64"), Some("1.0")).expect("a");
    let requested_b = PackageIdentity::new("pkg", Some("x86_64"), Some("1.0")).expect("b");
    let preview = RemovalPreview::new(
        RemovalBackend::Dnf4,
        "pkg".to_string(),
        vec![
            PlannedRemoval::new(requested_a, RemovalReason::Requested),
            PlannedRemoval::new(requested_b, RemovalReason::Requested),
        ],
        2,
        PreviewExit::Aborted,
        PreviewCommandIdentity::Dnf4RemoveAssumeno {
            no_autoremove: false,
        },
        None,
    );
    assert!(matches!(
        decision(&preview, &[]),
        RemovalSafetyDecision::Indeterminate { .. }
    ));
}

#[test]
fn architecture_ambiguity_for_an_allowed_extra_is_indeterminate() {
    let requested = PackageIdentity::new("pkg", Some("aarch64"), Some("1.0")).expect("requested");
    let extra_a = PackageIdentity::new("extra", Some("aarch64"), Some("1.0")).expect("extra a");
    let extra_b = PackageIdentity::new("extra", Some("x86_64"), Some("1.0")).expect("extra b");
    let preview = RemovalPreview::new(
        RemovalBackend::Dnf4,
        "pkg".to_string(),
        vec![
            PlannedRemoval::new(requested, RemovalReason::Requested),
            PlannedRemoval::new(extra_a, RemovalReason::Dependent),
            PlannedRemoval::new(extra_b, RemovalReason::Dependent),
        ],
        3,
        PreviewExit::Aborted,
        PreviewCommandIdentity::Dnf4RemoveAssumeno {
            no_autoremove: false,
        },
        None,
    );
    assert!(matches!(
        decision(&preview, &["extra"]),
        RemovalSafetyDecision::Indeterminate { .. }
    ));
}

// ---------------------------------------------------------------------------
// Sensitive / error contract
// ---------------------------------------------------------------------------

#[test]
fn h1_allowlist_debug_and_error_debug_do_not_leak_names() {
    let allow = RemovalAllowList::from_names(["7zip", "p7zip-full"]).expect("allowlist");
    let debug = format!("{allow:?}");
    assert!(!debug.contains("7zip"), "{debug}");
    assert!(!debug.contains("p7zip-full"), "{debug}");
    assert!(debug.contains("entry_count"), "{debug}");

    let error = RemovalSafetyError::unexpected_removal(2);
    let debug = format!("{error:?}");
    assert!(!debug.contains("7zip"), "{debug}");
    assert!(!debug.contains("p7zip-full"), "{debug}");
    let rendered = error.render(true);
    assert!(!rendered.contains("7zip"), "{rendered}");
}

#[test]
fn preview_input_debug_shows_lengths_not_bytes() {
    let input = input(fixture!("apt_reverse.out"), "", 0);
    let debug = format!("{input:?}");
    assert!(!debug.contains("Remv"), "{debug}");
    assert!(!debug.contains("unzip"), "{debug}");
    assert!(debug.contains("stdout_len"), "{debug}");
}

#[test]
fn allowed_extra_with_multiple_versions_is_indeterminate() {
    let requested = PackageIdentity::new("pkg", Some("aarch64"), Some("1.0")).expect("requested");
    let extra_a = PackageIdentity::new("extra", Some("aarch64"), Some("1.0")).expect("extra a");
    let extra_b = PackageIdentity::new("extra", Some("aarch64"), Some("2.0")).expect("extra b");
    let preview = RemovalPreview::new(
        RemovalBackend::Dnf4,
        "pkg".to_string(),
        vec![
            PlannedRemoval::new(requested, RemovalReason::Requested),
            PlannedRemoval::new(extra_a, RemovalReason::Dependent),
            PlannedRemoval::new(extra_b, RemovalReason::Dependent),
        ],
        3,
        PreviewExit::Aborted,
        PreviewCommandIdentity::Dnf4RemoveAssumeno {
            no_autoremove: false,
        },
        None,
    );
    assert!(matches!(
        decision(&preview, &["extra"]),
        RemovalSafetyDecision::Indeterminate { .. }
    ));
}

#[test]
fn debug_and_sensitive_render_never_include_package_identities() {
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_unzip_44.out"),
        fixture!("dnf5_unzip_44.err"),
        1,
        false,
    )
    .expect("44");
    let debug = format!("{p:?}");
    assert!(!debug.contains("unzip"), "{debug}");
    assert!(!debug.contains("rpm-build"), "{debug}");

    let d = decision(&p, &[]);
    let sensitive = d.render(true);
    assert!(!sensitive.contains("unzip"), "{sensitive}");
    assert!(!sensitive.contains("rpm-build"), "{sensitive}");
    assert!(sensitive.contains("43"));

    let error = RemovalSafetyError::unexpected_removal(43);
    assert!(!error.render(true).contains("unzip"));
    assert!(!format!("{error:?}").contains("unzip"));
}

#[test]
fn error_maps_to_pre_mutation_apply_contract() {
    let error = RemovalSafetyError::unexpected_removal(2);
    assert_eq!(error.category(), RemovalSafetyCategory::UnexpectedRemoval);
    let sinter = error.to_sinter_error();
    assert_eq!(sinter.kind, ErrorKind::Apply);
    assert_eq!(sinter.mutation, MutationState::None);
    assert!(!sinter.message.contains("zip"));
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

fn rpm_inventory(text: &str) -> InventoryFingerprint {
    InventoryFingerprint::from_records(RemovalBackend::Dnf5, text.as_bytes())
        .expect("rpm inventory")
}

fn rpm_inventory_for(backend: RemovalBackend, text: &str) -> InventoryFingerprint {
    InventoryFingerprint::from_records(backend, text.as_bytes()).expect("rpm inventory")
}

#[test]
fn inventory_is_canonical_and_order_independent() {
    let a = rpm_inventory("unzip\t6.0-67.fc43\taarch64\nzip\t3.0-44.fc43\taarch64\n");
    let b = rpm_inventory("zip\t3.0-44.fc43\taarch64\nunzip\t6.0-67.fc43\taarch64\n");
    assert_eq!(a.hash_hex(), b.hash_hex());
    assert_eq!(a.entry_count(), 2);
    assert_eq!(a, b);
}

#[test]
fn apt_inventory_distinguishes_installed_and_config_files() {
    let fp = InventoryFingerprint::from_records(
        RemovalBackend::Apt,
        b"7zip\t23.01+dfsg-11\tarm64\tinstall ok installed\np7zip-full\t16.02+transitional.1\tall\tdeinstall ok config-files\n",
    )
    .expect("apt inventory");
    assert_eq!(fp.entry_count(), 2);
    let installed: Vec<bool> = fp.entries().iter().map(|e| e.installed()).collect();
    assert_eq!(installed, vec![true, false]);
}

#[test]
fn apt_inventory_accepts_binary_package_arch_qualifier() {
    let fp = InventoryFingerprint::from_records(
        RemovalBackend::Apt,
        b"bind9-libs:arm64\t1:9.18.39-0ubuntu0.24.04.5\tarm64\tinstall ok installed\n",
    )
    .expect("qualified name");
    assert_eq!(fp.entries()[0].name(), "bind9-libs");
    assert_eq!(fp.entries()[0].architecture(), "arm64");
    assert!(InventoryFingerprint::from_records(
        RemovalBackend::Apt,
        b"bind9-libs:i386\t1:9.18.39\tarm64\tinstall ok installed\n",
    )
    .is_err());
}

#[test]
fn rpm_inventory_accepts_none_architecture_for_gpg_pubkey() {
    let fp =
        rpm_inventory("gpg-pubkey\tc6e7f081cf80e13146676e88829b606631645531-66b6dccf\t(none)\n");
    assert_eq!(fp.entry_count(), 1);
    assert_eq!(fp.entries()[0].architecture(), "(none)");
}

#[test]
fn evaluate_rejects_summary_mismatch_and_duplicate_planned_entries() {
    let identity = PackageIdentity::new("pkg", Some("aarch64"), Some("1.0")).expect("identity");
    let one = PlannedRemoval::new(identity.clone(), RemovalReason::Requested);
    let mismatched = RemovalPreview::new(
        RemovalBackend::Dnf4,
        "pkg".to_string(),
        vec![one.clone()],
        2,
        PreviewExit::Aborted,
        PreviewCommandIdentity::Dnf4RemoveAssumeno {
            no_autoremove: false,
        },
        None,
    );
    assert!(matches!(
        decision(&mismatched, &[]),
        RemovalSafetyDecision::Indeterminate { .. }
    ));

    let duplicated = RemovalPreview::new(
        RemovalBackend::Dnf4,
        "pkg".to_string(),
        vec![one.clone(), one],
        2,
        PreviewExit::Aborted,
        PreviewCommandIdentity::Dnf4RemoveAssumeno {
            no_autoremove: false,
        },
        None,
    );
    assert!(matches!(
        decision(&duplicated, &[]),
        RemovalSafetyDecision::Indeterminate { .. }
    ));
}

#[test]
fn inventory_rejects_duplicates_malformed_records_and_invalid_utf8() {
    assert_eq!(
        InventoryFingerprint::from_records(
            RemovalBackend::Dnf5,
            b"unzip\t1.0\taarch64\nunzip\t1.0\taarch64\n",
        )
        .expect_err("duplicate")
        .category(),
        RemovalSafetyCategory::PackageIdentityAmbiguous
    );
    assert!(InventoryFingerprint::from_records(RemovalBackend::Dnf5, b"unzip\taarch64\n").is_err());
    assert!(InventoryFingerprint::from_records(RemovalBackend::Dnf5, &[0xff]).is_err());
    assert!(InventoryFingerprint::from_records(
        RemovalBackend::Apt,
        b"pkg\t1.0\tarm64\tbroken state\n",
    )
    .is_err());
    let empty = InventoryFingerprint::from_records(RemovalBackend::Dnf5, b"").expect("empty");
    assert_eq!(empty.entry_count(), 0);
}

#[test]
fn real_r0_baseline_inventories_parse_to_known_hashes() {
    let fedora = InventoryFingerprint::from_records(
        RemovalBackend::Dnf5,
        include_bytes!("../../tests/fixtures/removal_r1/inventory_fedora_baseline.tsv"),
    )
    .expect("fedora inventory");
    assert_eq!(fedora.entry_count(), 453);
    assert_eq!(fedora.hash_hex().len(), 64);

    let rocky = InventoryFingerprint::from_records(
        RemovalBackend::Dnf4,
        include_bytes!("../../tests/fixtures/removal_r1/inventory_rocky_baseline.tsv"),
    )
    .expect("rocky inventory");
    assert_eq!(rocky.entry_count(), 447);
    assert_eq!(rocky.hash_hex().len(), 64);

    let ubuntu = InventoryFingerprint::from_records(
        RemovalBackend::Apt,
        include_bytes!("../../tests/fixtures/removal_r1/inventory_ubuntu_baseline.tsv"),
    )
    .expect("ubuntu inventory");
    assert_eq!(ubuntu.entry_count(), 724);
    assert_eq!(ubuntu.hash_hex().len(), 64);
}

#[test]
fn abc_stability_requires_identical_fingerprints() {
    let a = rpm_inventory("unzip\t6.0-67.fc43\taarch64\n");
    let b = a.clone();
    let c = a.clone();
    assert!(verify_stability(&a, &b, &c).is_ok());
    let changed = rpm_inventory("unzip\t6.0-67.fc43\taarch64\nzip\t3.0-44.fc43\taarch64\n");
    assert_eq!(
        verify_stability(&a, &changed, &c)
            .expect_err("changed")
            .category(),
        RemovalSafetyCategory::InventoryChanged
    );
}

#[test]
fn delta_clean_requires_planned_and_actual_to_match() {
    let p = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .expect("preview");
    let before = rpm_inventory_for(
        RemovalBackend::Dnf4,
        "unzip\t6.0-60.el9_8\taarch64\nzip\t3.0-35.el9\taarch64\n",
    );
    let after = rpm_inventory_for(RemovalBackend::Dnf4, "");
    let delta = RemovalExecutionDelta::compute(p.planned_removals(), p.backend(), &before, &after)
        .expect("delta");
    assert!(delta.is_clean());
    assert_eq!(delta.actual_removals().len(), 2);
    assert!(delta.require_clean().is_ok());
}

#[test]
fn delta_detects_unexpected_missing_and_added_packages() {
    let p = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .expect("preview");
    let before = rpm_inventory_for(
        RemovalBackend::Dnf4,
        "unzip\t6.0-60.el9_8\taarch64\nzip\t3.0-35.el9\taarch64\n",
    );
    let after_zip_only = rpm_inventory_for(RemovalBackend::Dnf4, "zip\t3.0-35.el9\taarch64\n");
    let delta =
        RemovalExecutionDelta::compute(p.planned_removals(), p.backend(), &before, &after_zip_only)
            .expect("delta");
    assert_eq!(delta.missing_removals().len(), 1);
    assert!(!delta.is_clean());
    assert!(delta.require_clean().is_err());

    let before_unzip = rpm_inventory_for(RemovalBackend::Dnf4, "unzip\t6.0-60.el9_8\taarch64\n");
    let after_extra = rpm_inventory_for(
        RemovalBackend::Dnf4,
        "unzip\t6.0-60.el9_8\taarch64\nextra\t1.0\taarch64\n",
    );
    let delta = RemovalExecutionDelta::compute(
        &p.planned_removals()[..1],
        p.backend(),
        &before_unzip,
        &after_extra,
    )
    .expect("delta");
    assert_eq!(delta.unexpected_additions().len(), 1);
    assert!(!delta.is_clean());
}

#[test]
fn delta_detects_an_unexpected_removal_explicitly() {
    let p = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .expect("preview");
    // Use only the requested row: zip becomes an unexpected removal.
    let before = rpm_inventory_for(
        RemovalBackend::Dnf4,
        "unzip\t6.0-60.el9_8\taarch64\nzip\t3.0-35.el9\taarch64\n",
    );
    let after = rpm_inventory_for(RemovalBackend::Dnf4, "");
    let delta =
        RemovalExecutionDelta::compute(&p.planned_removals()[..1], p.backend(), &before, &after)
            .expect("delta");
    assert_eq!(
        delta
            .unexpected_removals()
            .iter()
            .map(|e| e.name())
            .collect::<Vec<_>>(),
        vec!["zip"]
    );
    assert!(delta.missing_removals().is_empty());
    assert!(!delta.is_clean());
}

#[test]
fn inventory_and_delta_debug_never_include_identities() {
    let fp = rpm_inventory_for(
        RemovalBackend::Dnf4,
        "unzip\t6.0-60.el9_8\taarch64\nzip\t3.0-35.el9\taarch64\n",
    );
    let debug = format!("{fp:?}");
    assert!(!debug.contains("unzip"), "{debug}");
    assert!(!debug.contains("zip"), "{debug}");
    let entries = format!("{:?}", fp.entries());
    assert!(!entries.contains("unzip"), "{entries}");

    let p = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .expect("preview");
    let after = rpm_inventory_for(RemovalBackend::Dnf4, "");
    let delta = RemovalExecutionDelta::compute(p.planned_removals(), p.backend(), &fp, &after)
        .expect("delta");
    let debug = format!("{delta:?}");
    assert!(!debug.contains("unzip"), "{debug}");
    assert!(!debug.contains("zip"), "{debug}");
}

#[test]
fn delta_rejects_ambiguous_architecture_matching() {
    let planned = vec![PlannedRemoval::new(
        PackageIdentity::new("pkg", None, Some("1.0")).expect("identity"),
        RemovalReason::Requested,
    )];
    let before = rpm_inventory("pkg\t1.0\taarch64\npkg\t1.0\tx86_64\n");
    let after = rpm_inventory("");
    assert_eq!(
        RemovalExecutionDelta::compute(&planned, RemovalBackend::Dnf5, &before, &after)
            .expect_err("ambiguous")
            .category(),
        RemovalSafetyCategory::PackageIdentityAmbiguous
    );
}

// ---------------------------------------------------------------------------
// R1-FIX H2: complete identity sets and fixed inventory hashes
// ---------------------------------------------------------------------------

#[test]
fn h2_dnf5_44_complete_identity_set() {
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_unzip_44.out"),
        fixture!("dnf5_unzip_44.err"),
        1,
        false,
    )
    .expect("44");
    assert_eq!(actual_identities(&p), expected_dnf(DNF5_44));
    assert_eq!(p.backend().label(), "dnf5");
    assert_eq!(p.requested_package(), "unzip");
    assert_eq!(p.command_identity().no_autoremove(), Some(false));
}

#[test]
fn h2_dnf5_8_complete_identity_set() {
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_unzip_8.out"),
        fixture!("dnf5_unzip_8.err"),
        1,
        true,
    )
    .expect("8");
    assert_eq!(actual_identities(&p), expected_dnf(DNF5_8));
    assert_eq!(p.command_identity().no_autoremove(), Some(true));
}

#[test]
fn h2_dnf4_complete_identity_sets() {
    let unzip = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .expect("unzip");
    assert_eq!(actual_identities(&unzip), expected_dnf(DNF4_UNZIP));

    let unzip_noauto = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip_noauto.out"),
        fixture!("dnf4_unzip_noauto.err"),
        1,
        true,
    )
    .expect("unzip noauto");
    assert_eq!(actual_identities(&unzip_noauto), expected_dnf(DNF4_UNZIP));

    let tcpdump = parse_dnf(
        RemovalBackend::Dnf4,
        "tcpdump",
        fixture!("dnf4_tcpdump.out"),
        fixture!("dnf4_tcpdump.err"),
        1,
        false,
    )
    .expect("tcpdump");
    assert_eq!(actual_identities(&tcpdump), expected_dnf(DNF4_TCPDUMP));

    let tcpdump_noauto = parse_dnf(
        RemovalBackend::Dnf4,
        "tcpdump",
        fixture!("dnf4_tcpdump_noauto.out"),
        fixture!("dnf4_tcpdump_noauto.err"),
        1,
        true,
    )
    .expect("tcpdump noauto");
    assert_eq!(
        actual_identities(&tcpdump_noauto),
        expected_dnf(DNF4_TCPDUMP_NOAUTO)
    );
}

#[test]
fn h2_apt_complete_identity_sets_and_root_equivalence() {
    let reverse = parse_apt("7zip", fixture!("apt_reverse.out"), "").expect("reverse");
    assert_eq!(actual_identities(&reverse), expected_apt(APT_REVERSE));

    let root = parse_apt("7zip", fixture!("apt_root_reverse.out"), "").expect("root");
    assert_eq!(actual_identities(&root), expected_apt(APT_REVERSE));

    let auto = parse_apt("p7zip-full", fixture!("apt_auto_remove.out"), "").expect("auto");
    assert_eq!(actual_identities(&auto), expected_apt(APT_AUTO_REMOVE));
}

#[test]
fn h2_architecture_version_and_missing_identity_changes_are_detected() {
    let arch_changed =
        fixture!("dnf5_unzip_44.out").replace("aarch64 6.0-67.fc43", "x86_64 6.0-67.fc43");
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        &arch_changed,
        fixture!("dnf5_unzip_44.err"),
        1,
        false,
    )
    .expect("arch changed");
    assert_ne!(actual_identities(&p), expected_dnf(DNF5_44));

    let version_changed = fixture!("dnf5_unzip_44.out").replace("6.0-67.fc43", "6.0-68.fc43");
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        &version_changed,
        fixture!("dnf5_unzip_44.err"),
        1,
        false,
    )
    .expect("version changed");
    assert_ne!(actual_identities(&p), expected_dnf(DNF5_44));

    let missing = fixture!("dnf5_unzip_44.out")
        .lines()
        .filter(|line| !(line.contains(" add-determinism ") && line.contains("0.6.0-3.fc43")))
        .collect::<Vec<_>>()
        .join("\n")
        .replace(
            "Removing:          44 packages",
            "Removing:          43 packages",
        );
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        &missing,
        fixture!("dnf5_unzip_44.err"),
        1,
        false,
    )
    .expect("missing identity");
    assert_eq!(p.planned_removals().len(), 43);
    assert_ne!(actual_identities(&p), expected_dnf(DNF5_44));
}

#[test]
fn h2_real_inventory_canonical_hashes_are_fixed() {
    let fedora = InventoryFingerprint::from_records(
        RemovalBackend::Dnf5,
        include_bytes!("../../tests/fixtures/removal_r1/inventory_fedora_baseline.tsv"),
    )
    .expect("fedora");
    assert_eq!(fedora.entry_count(), 453);
    assert_eq!(fedora.backend(), RemovalBackend::Dnf5);
    assert_eq!(
        fedora.hash_hex(),
        "3860ebbcd66317f836c3881bc61f807b575348053871a5f2597769560170aa5a"
    );
    assert!(!fedora.entries()[0].version().is_empty());

    let rocky = InventoryFingerprint::from_records(
        RemovalBackend::Dnf4,
        include_bytes!("../../tests/fixtures/removal_r1/inventory_rocky_baseline.tsv"),
    )
    .expect("rocky");
    assert_eq!(rocky.entry_count(), 447);
    assert_eq!(rocky.backend(), RemovalBackend::Dnf4);
    assert_eq!(
        rocky.hash_hex(),
        "8079095f2ad5dcc519b1409d1e2ea4c4bd218c446274092e4f8f39ca15c8d5c4"
    );

    let ubuntu = InventoryFingerprint::from_records(
        RemovalBackend::Apt,
        include_bytes!("../../tests/fixtures/removal_r1/inventory_ubuntu_baseline.tsv"),
    )
    .expect("ubuntu");
    assert_eq!(ubuntu.entry_count(), 724);
    assert_eq!(ubuntu.backend(), RemovalBackend::Apt);
    assert_eq!(
        ubuntu.hash_hex(),
        "f6c5eeefd8bc31c0e334bd17bc31a8e4a1be8a812ab78a2004fd0d415cb3ec2a"
    );
}

#[test]
fn h2_inventory_reorder_is_stable_and_content_change_changes_hash() {
    let text = std::str::from_utf8(include_bytes!(
        "../../tests/fixtures/removal_r1/inventory_fedora_baseline.tsv"
    ))
    .expect("utf8");
    let mut lines: Vec<&str> = text.lines().collect();
    lines.reverse();
    let reversed = lines.join("\n") + "\n";
    let a = InventoryFingerprint::from_records(RemovalBackend::Dnf5, text.as_bytes()).expect("a");
    let b =
        InventoryFingerprint::from_records(RemovalBackend::Dnf5, reversed.as_bytes()).expect("b");
    assert_eq!(a.hash_hex(), b.hash_hex());

    let changed = text.replace(
        "NetworkManager\t1.54.0-2.fc43\taarch64",
        "NetworkManager\t9.9.9-1.fc43\taarch64",
    );
    assert_ne!(changed, text);
    let c =
        InventoryFingerprint::from_records(RemovalBackend::Dnf5, changed.as_bytes()).expect("c");
    assert_ne!(a.hash_hex(), c.hash_hex());
}

// ---------------------------------------------------------------------------
// R1-FIX M1/M6: classification and configuration
// ---------------------------------------------------------------------------

#[test]
fn m1_indeterminate_categories_and_mutation_certainty() {
    let errors = [
        RemovalSafetyError::command_failed(),
        RemovalSafetyError::abort_unexpected(),
        RemovalSafetyError::parse(None),
        RemovalSafetyError::summary(44, 43),
        RemovalSafetyError::identity(),
        RemovalSafetyError::inventory_changed(),
        RemovalSafetyError::requested_missing(),
        RemovalSafetyError::backend_mismatch(),
    ];
    for error in &errors {
        assert!(error.is_indeterminate(), "{:?}", error.category());
        let sinter = error.to_sinter_error();
        assert_eq!(sinter.kind, ErrorKind::Apply);
        assert_eq!(sinter.mutation, MutationState::None);
    }
    assert!(!RemovalSafetyError::unexpected_removal(1).is_indeterminate());
    assert!(!RemovalSafetyError::actual_mismatch(1).is_indeterminate());

    assert!(parse_preview(
        RemovalBackend::Apt,
        "7zip",
        input(fixture!("apt_reverse.out"), "", 0),
        false,
    )
    .is_ok());
    assert!(parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_unzip_8.out"),
        fixture!("dnf5_unzip_8.err"),
        1,
        true,
    )
    .is_ok());

    let config = parse_preview(
        RemovalBackend::Apt,
        "7zip",
        input(fixture!("apt_reverse.out"), "", 0),
        true,
    )
    .expect_err("apt no_autoremove is invalid");
    assert_eq!(
        config.category(),
        RemovalSafetyCategory::PreviewConfigurationInvalid
    );
    assert_eq!(config.category().label(), "preview_configuration_invalid");
    assert!(!config.is_indeterminate());
    assert_eq!(config.to_sinter_error().mutation, MutationState::None);
    assert!(!config.render(true).contains("7zip"));
}

#[test]
fn l7_summary_error_retains_expected_and_actual_counts() {
    let error = RemovalSafetyError::summary(44, 43);
    let text = error.render(true);
    assert!(text.contains("summary 44"), "{text}");
    assert!(text.contains("parsed 43"), "{text}");
    assert!(!text.contains("unzip"), "{text}");
}

// ---------------------------------------------------------------------------
// R1-FIX M2/M3/M4/M5
// ---------------------------------------------------------------------------

#[test]
fn m2_no_autoremove_contradiction_is_rejected() {
    assert!(parse_dnf(
        RemovalBackend::Dnf4,
        "tcpdump",
        fixture!("dnf4_tcpdump.out"),
        fixture!("dnf4_tcpdump.err"),
        1,
        true,
    )
    .is_err());
    assert!(parse_dnf(
        RemovalBackend::Dnf5,
        "tcpdump",
        fixture!("dnf5_tcpdump_3.out"),
        fixture!("dnf5_tcpdump_3.err"),
        1,
        true,
    )
    .is_err());
    assert!(parse_dnf(
        RemovalBackend::Dnf4,
        "tcpdump",
        fixture!("dnf4_tcpdump_noauto.out"),
        fixture!("dnf4_tcpdump_noauto.err"),
        1,
        true,
    )
    .is_ok());
    assert!(parse_dnf(
        RemovalBackend::Dnf5,
        "tcpdump",
        fixture!("dnf5_tcpdump_1.out"),
        fixture!("dnf5_tcpdump_1.err"),
        1,
        true,
    )
    .is_ok());
}

#[test]
fn m3_delta_binds_to_preview_backend() {
    let empty_apt = InventoryFingerprint::from_records(RemovalBackend::Apt, b"").expect("apt");
    let empty_dnf4 = InventoryFingerprint::from_records(RemovalBackend::Dnf4, b"").expect("dnf4");
    let empty_dnf5 = InventoryFingerprint::from_records(RemovalBackend::Dnf5, b"").expect("dnf5");
    assert!(
        RemovalExecutionDelta::compute(&[], RemovalBackend::Apt, &empty_apt, &empty_apt).is_ok()
    );
    assert!(
        RemovalExecutionDelta::compute(&[], RemovalBackend::Dnf4, &empty_dnf4, &empty_dnf4).is_ok()
    );
    assert!(
        RemovalExecutionDelta::compute(&[], RemovalBackend::Dnf5, &empty_dnf5, &empty_dnf5).is_ok()
    );
    assert_eq!(
        RemovalExecutionDelta::compute(&[], RemovalBackend::Apt, &empty_dnf4, &empty_dnf4)
            .expect_err("apt/dnf mismatch")
            .category(),
        RemovalSafetyCategory::BackendMismatch
    );
    assert_eq!(
        RemovalExecutionDelta::compute(&[], RemovalBackend::Dnf4, &empty_dnf5, &empty_dnf5)
            .expect_err("dnf4/dnf5 mismatch")
            .category(),
        RemovalSafetyCategory::BackendMismatch
    );

    let apt_preview = parse_apt("p7zip-full", fixture!("apt_single.out"), "").expect("apt preview");
    assert_eq!(
        RemovalExecutionDelta::compute(
            apt_preview.planned_removals(),
            RemovalBackend::Apt,
            &empty_dnf4,
            &empty_dnf4,
        )
        .expect_err("apt preview + dnf inventory")
        .category(),
        RemovalSafetyCategory::BackendMismatch
    );
    let apt_before = InventoryFingerprint::from_records(
        RemovalBackend::Apt,
        b"p7zip-full\t16.02+transitional.1\tall\tinstall ok installed\n",
    )
    .expect("apt before");
    let apt_after =
        InventoryFingerprint::from_records(RemovalBackend::Apt, b"").expect("apt after");
    let apt_delta = RemovalExecutionDelta::compute(
        apt_preview.planned_removals(),
        RemovalBackend::Apt,
        &apt_before,
        &apt_after,
    )
    .expect("apt delta");
    assert!(apt_delta.is_clean());
    assert_eq!(apt_delta.planned_removals().len(), 1);

    let dnf4_preview = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .expect("dnf4 preview");
    assert_eq!(
        RemovalExecutionDelta::compute(
            dnf4_preview.planned_removals(),
            RemovalBackend::Dnf4,
            &empty_dnf5,
            &empty_dnf5,
        )
        .expect_err("dnf4 preview + dnf5 inventory")
        .category(),
        RemovalSafetyCategory::BackendMismatch
    );
    let dnf4_before = InventoryFingerprint::from_records(
        RemovalBackend::Dnf4,
        b"unzip\t6.0-60.el9_8\taarch64\nzip\t3.0-35.el9\taarch64\n",
    )
    .expect("dnf4 before");
    let dnf4_after =
        InventoryFingerprint::from_records(RemovalBackend::Dnf4, b"").expect("dnf4 after");
    let dnf4_delta = RemovalExecutionDelta::compute(
        dnf4_preview.planned_removals(),
        RemovalBackend::Dnf4,
        &dnf4_before,
        &dnf4_after,
    )
    .expect("dnf4 delta");
    assert!(dnf4_delta.is_clean());

    let dnf5_preview = parse_dnf(
        RemovalBackend::Dnf5,
        "tcpdump",
        fixture!("dnf5_tcpdump_3.out"),
        fixture!("dnf5_tcpdump_3.err"),
        1,
        false,
    )
    .expect("dnf5 preview");
    let dnf5_before = InventoryFingerprint::from_records(
        RemovalBackend::Dnf5,
        b"tcpdump\t14:4.99.6-2.fc43\taarch64\nlibibverbs\t58.0-4.fc43\taarch64\nlibpcap\t14:1.10.7-1.fc43\taarch64\n",
    )
    .expect("dnf5 before");
    let dnf5_after =
        InventoryFingerprint::from_records(RemovalBackend::Dnf5, b"").expect("dnf5 after");
    let dnf5_delta = RemovalExecutionDelta::compute(
        dnf5_preview.planned_removals(),
        RemovalBackend::Dnf5,
        &dnf5_before,
        &dnf5_after,
    )
    .expect("dnf5 delta");
    assert!(dnf5_delta.is_clean());
}

#[test]
fn m4_noop_identity_must_match_and_be_unique() {
    let apt_wrong = fixture!("apt_absent.out").replace("'7zip'", "'other'");
    assert_eq!(
        parse_apt("7zip", &apt_wrong, "")
            .expect_err("apt wrong")
            .category(),
        RemovalSafetyCategory::RequestedPackageMissing
    );
    let apt_empty = fixture!("apt_absent.out").replace("'7zip'", "''");
    assert!(parse_apt("7zip", &apt_empty, "").is_err());
    let apt_multiple = format!(
        "{}Package '7zip' is not installed, so not removed\n",
        fixture!("apt_absent.out")
    );
    assert!(parse_apt("7zip", &apt_multiple, "").is_err());

    let dnf4_wrong = fixture!("dnf4_absent.out").replace("unzip", "other");
    assert_eq!(
        parse_dnf(
            RemovalBackend::Dnf4,
            "unzip",
            &dnf4_wrong,
            fixture!("dnf4_absent.err"),
            0,
            false,
        )
        .expect_err("dnf4 wrong")
        .category(),
        RemovalSafetyCategory::RequestedPackageMissing
    );
    let dnf4_empty = fixture!("dnf4_absent.out")
        .replace("No match for argument: unzip", "No match for argument:");
    assert!(parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        &dnf4_empty,
        fixture!("dnf4_absent.err"),
        0,
        false,
    )
    .is_err());
    let dnf4_multiple = format!(
        "{}No match for argument: unzip\n",
        fixture!("dnf4_absent.out")
    );
    assert!(parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        &dnf4_multiple,
        fixture!("dnf4_absent.err"),
        0,
        false,
    )
    .is_err());

    let dnf5_wrong = fixture!("dnf5_absent.err").replace("unzip", "other");
    assert_eq!(
        parse_dnf(
            RemovalBackend::Dnf5,
            "unzip",
            fixture!("dnf5_absent.out"),
            &dnf5_wrong,
            0,
            false,
        )
        .expect_err("dnf5 wrong")
        .category(),
        RemovalSafetyCategory::RequestedPackageMissing
    );
    let dnf5_empty = fixture!("dnf5_absent.err").replace("argument: unzip", "argument:");
    assert!(parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_absent.out"),
        &dnf5_empty,
        0,
        false,
    )
    .is_err());
    let dnf5_multiple = format!(
        "{}No packages to remove for argument: unzip\n",
        fixture!("dnf5_absent.err")
    );
    assert!(parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_absent.out"),
        &dnf5_multiple,
        0,
        false,
    )
    .is_err());
}

#[test]
fn m5_denied_maps_to_sinter_apply_with_no_mutation() {
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_unzip_44.out"),
        fixture!("dnf5_unzip_44.err"),
        1,
        false,
    )
    .expect("44");
    let d = decision(&p, &[]);
    assert!(d.is_denied());
    assert_eq!(d.unexpected_count(), Some(43));
    let sensitive = d.to_sinter_error(true).expect("error");
    assert_eq!(sensitive.kind, ErrorKind::Apply);
    assert_eq!(sensitive.mutation, MutationState::None);
    assert!(sensitive.message.contains("43"));
    assert!(!sensitive.message.contains("unzip"));
    assert!(!sensitive.message.contains("rpm-build"));
}

// ---------------------------------------------------------------------------
// R1-FIX L2/L3/L6/L8/L9
// ---------------------------------------------------------------------------

#[test]
fn l2_dnf5_abort_without_after_line_is_accepted() {
    let stderr = fixture!("dnf5_unzip_8.err")
        .lines()
        .filter(|line| !line.starts_with("After this operation"))
        .collect::<Vec<_>>()
        .join("\n");
    let p = parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf5_unzip_8.out"),
        &stderr,
        1,
        true,
    )
    .expect("abort without informational line");
    assert_eq!(actual_identities(&p), expected_dnf(DNF5_8));
}

#[test]
fn l3_apt_display_list_must_not_contradict_remv() {
    let stdout = fixture!("apt_reverse.out").replace("7zip p7zip-full", "7zip other");
    assert!(parse_apt("7zip", &stdout, "").is_err());
}

#[test]
fn l6_debug_does_not_leak_real_fixture_names() {
    let p = parse_apt("7zip", fixture!("apt_reverse.out"), "").expect("apt");
    let d = decision(&p, &["p7zip-full"]);
    let debug = format!("{d:?}");
    assert!(!debug.contains("7zip"), "{debug}");
    assert!(!debug.contains("p7zip-full"), "{debug}");
    let sensitive = d.render(true);
    assert!(!sensitive.contains("7zip"), "{sensitive}");
    assert!(!sensitive.contains("p7zip-full"), "{sensitive}");
}

#[test]
fn l8_empty_allowlist_is_the_default_and_denies() {
    let empty = RemovalAllowList::empty();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    let p = parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .expect("dnf4");
    assert!(evaluate(&p, &empty).is_denied());
}

#[test]
fn l9_dnf4_and_dnf5_grammars_are_not_cross_accepted() {
    assert!(parse_dnf(
        RemovalBackend::Dnf4,
        "unzip",
        fixture!("dnf5_unzip_8.out"),
        fixture!("dnf5_unzip_8.err"),
        1,
        true,
    )
    .is_err());
    assert!(parse_dnf(
        RemovalBackend::Dnf5,
        "unzip",
        fixture!("dnf4_unzip.out"),
        fixture!("dnf4_unzip.err"),
        1,
        false,
    )
    .is_err());
}

// ---------------------------------------------------------------------------
// R2 handoff: mutation certainty and DNF5 duplicate informational lines
// ---------------------------------------------------------------------------

#[test]
fn r2_actual_mismatch_maps_to_possible_and_config_to_schema() {
    let actual = RemovalSafetyError::actual_mismatch(2).to_sinter_error();
    assert_eq!(actual.kind, ErrorKind::Apply);
    assert_eq!(actual.mutation, MutationState::Possible);
    assert!(!actual.message.contains("unzip"));

    let config = RemovalSafetyError::configuration().to_sinter_error();
    assert_eq!(config.kind, ErrorKind::Schema);
    assert_eq!(config.mutation, MutationState::None);
}

#[test]
fn r2_dnf5_rejects_two_after_lines() {
    let stderr = "After this operation, 1 MiB will be freed (install 0 B, remove 1 MiB).\n\
                  After this operation, 1 MiB will be freed (install 0 B, remove 1 MiB).\n\
                  Operation aborted by the user.\n";
    assert_eq!(
        parse_dnf(
            RemovalBackend::Dnf5,
            "unzip",
            fixture!("dnf5_unzip_8.out"),
            stderr,
            1,
            true,
        )
        .expect_err("duplicate informational line")
        .category(),
        RemovalSafetyCategory::PreviewAbortUnexpected
    );
}
