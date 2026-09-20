//! Round-4 audit remediation regression tests (R3-A01 .. R3-A04).
//!
//! Every case drives the production parser/control path: a scripted in-process
//! FakeTarget so platform detection, backend selection, the private-snapshot
//! lifecycle, payload-URL validation, and result classification all run
//! production code. Malformed, ambiguous or uninterpretable input must fail
//! closed — no payload download and no mutation — while valid, real-looking
//! DNF output still completes. The A04 copy test exercises real filesystem
//! copy semantics on the controller.

mod common;

use common::*;
use sinter::engine::Mode;
use sinter::executor::{Completion, DnfRepo, FakeTarget, Output};
use sinter::result::{Change, Execution, Verification};

/// The private snapshot root the scripted target hands out via `mktemp`.
const FAKE_SNAP: &str = "/var/tmp/sinter-dnf.fakesnap";

/// The live DNF metadata cache root the snapshot is copied from.
const LIVE_CACHE_ROOT: &str = "/var/cache/dnf";

// ===========================================================================
// Shared helpers (mirrors remediation_r2.rs so both suites stay independent).
// ===========================================================================

fn pkg_recipe(dir: &std::path::Path, name: &str, state: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: {}\n      state: {}\n",
            name, state
        ),
    )
}

/// Records of one program in the execution audit log, in dispatch order.
fn commands_with<'a>(
    report: &'a sinter::engine::RunReport,
    prog: &str,
) -> Vec<&'a sinter::executor::CommandRecord> {
    report
        .commands
        .iter()
        .filter(|c| c.program == prog)
        .collect()
}

/// Count dispatched dnf mutations: only the real `dnf ... install -y` carries
/// `-y` (the `--assumeno` dry run and every check do not).
fn dnf_mutations(report: &sinter::engine::RunReport) -> usize {
    report
        .commands
        .iter()
        .filter(|c| {
            c.program == "/usr/bin/dnf"
                && c.args.iter().any(|a| a == "-y")
                && !c.args.iter().any(|a| a == "--downloadonly")
        })
        .count()
}

/// Payload-transport dispatches: the native `dnf install --downloadonly`
/// invocation that fills the snapshot package cache. Explicit fetchers
/// (curl/wget) are gone — librepo owns the transfer.
fn downloads(report: &sinter::engine::RunReport) -> usize {
    commands_with(report, "/usr/bin/dnf")
        .into_iter()
        .filter(|c| c.args.iter().any(|a| a == "--downloadonly"))
        .count()
}

/// The `CliError` line an `--assumeno` install leaves on stderr (R5-F04):
/// the abort is logged at ERROR level, so it lands on stderr — never stdout.
const DNF_ABORT_STDERR: &str = "Operation aborted.\n";

/// A well-formed `dnf repolist -v` body for one enabled repository.
fn dnf_repolist_text(repoid: &str, mirrors: bool) -> String {
    let mut s = format!(
        "Repo-id            : {}\nRepo-name          : {}\nRepo-status        : enabled\nRepo-revision      : 1\nRepo-updated       : Tue 16 Sep 2026\n",
        repoid, repoid
    );
    if mirrors {
        s.push_str("Repo-mirrors       : https://mirrors.example/?repo=x\n");
    }
    s.push('\n');
    s
}

/// A well-formed `dnf install --assumeno` transaction table for one package.
fn dnf_transaction_table(name: &str, repoid: &str) -> String {
    format!(
        "Dependencies resolved.\n\
         ================================================================================\n \
         Package                Arch        Version                Repository      Size\n\
         ================================================================================\n\
         Installing:\n \
         {n:<23}x86_64      1.0-1.el9              {r:<15} 1 k\n\n\
         Transaction Summary\n\
         ================================================================================\n\
         Install  1 Package\n\n\
         Total download size: 1 k\n\
         Installed size: 2 k\n",
        n = name,
        r = repoid
    )
}

fn override_output(completion: Completion, stdout: &str, stderr: &str) -> Output {
    Output {
        completion,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

/// Assert the resource was blocked by the snapshot contract: no payload
/// download and no mutation, with no change or verification claimed.
fn assert_blocked_no_mutation(r: &sinter::engine::RunReport) -> &sinter::result::ResourceResult {
    let p = find(r, "p");
    assert_eq!(p.execution, Execution::Failed, "blocked input must fail");
    assert_eq!(p.change, Change::None, "no mutation means no change claim");
    assert_eq!(
        p.verification,
        Verification::NotPerformed,
        "verification must not be claimed"
    );
    assert_eq!(
        dnf_mutations(r),
        0,
        "no mutation may be dispatched for uninterpretable input"
    );
    assert_eq!(
        downloads(r),
        0,
        "no payload download may be dispatched for uninterpretable input"
    );
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("repository metadata not locally complete"),
        "blocked reason must name the metadata contract: {:?}",
        p.reason
    );
    p
}

/// Assert the resource was blocked after payload transport but before the
/// cache-only mutation: the download-only call legitimately ran, yet no
/// mutation may be dispatched and no change or verification claimed.
fn assert_payload_rejected(r: &sinter::engine::RunReport) -> &sinter::result::ResourceResult {
    let p = find(r, "p");
    assert_eq!(p.execution, Execution::Failed, "rejected payload must fail");
    assert_eq!(p.change, Change::None, "no mutation means no change claim");
    assert_eq!(
        p.verification,
        Verification::NotPerformed,
        "verification must not be claimed"
    );
    assert_eq!(downloads(r), 1, "the payload transport did run");
    assert_eq!(dnf_mutations(r), 0, "no mutation may be dispatched");
    p
}

/// Assert the resource completed a full prefetch + mutation (the positive
/// control shape: valid input is never rejected).
fn assert_full_install(r: &sinter::engine::RunReport) {
    let p = find(r, "p");
    assert_eq!(
        p.execution,
        Execution::Succeeded,
        "valid input must succeed"
    );
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    assert_eq!(downloads(r), 1, "the payload must be prefetched");
    assert_eq!(dnf_mutations(r), 1, "the mutation must run");
}

/// Assert the private snapshot was cleaned up exactly once.
fn assert_snapshot_cleaned(r: &sinter::engine::RunReport) {
    let rm = commands_with(r, "/usr/bin/rm");
    assert_eq!(
        rm.len(),
        1,
        "the private snapshot must be removed exactly once"
    );
    assert!(rm[0].args.iter().any(|a| a == FAKE_SNAP));
}

/// A Rocky target with an additional enabled repository, so multi-block
/// output can be exercised.
fn rocky9_with_extra_repo(id: &str) -> FakeTarget {
    let mut t = FakeTarget::rocky9();
    t.dnf_repos.push(DnfRepo {
        id: id.to_string(),
        mirrors: true,
        repodata_cached: true,
        mirrorlist_cached: true,
    });
    t
}

// ===========================================================================
// R3-A01 — strict DNF diagnostic parsing. "Parse what Sinter understands
// exactly; otherwise fail closed." A recognized prefix is never enough.
// ===========================================================================

/// A01-1: a repository block repeated is not a repository set this parser can
/// interpret — one malformed block among valid ones rejects the whole output.
#[test]
fn r4_a01_duplicate_repository_block_rejected() {
    let dir = trusted_root("r4-a01-dup-block");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        &format!(
            "{}{}",
            dnf_repolist_text("baseos", true),
            dnf_repolist_text("baseos", true)
        ),
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A duplicate `Repo-id` inside one block (no blank separator) is malformed.
#[test]
fn r4_a01_duplicate_repo_id_in_block_rejected() {
    let dir = trusted_root("r4-a01-dup-id");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        "Repo-id            : baseos\nRepo-id            : baseos\nRepo-status        : enabled\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A01-2: a `Repo-status` field printed twice is malformed even when both
/// values agree.
#[test]
fn r4_a01_duplicate_repo_status_rejected() {
    let dir = trusted_root("r4-a01-dup-status");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        "Repo-id            : baseos\nRepo-name          : BaseOS\nRepo-status        : enabled\nRepo-status        : enabled\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// Contradictory statuses inside one block fail closed.
#[test]
fn r4_a01_conflicting_repo_status_rejected() {
    let dir = trusted_root("r4-a01-conflict-status");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        "Repo-id            : baseos\nRepo-status        : enabled\nRepo-status        : disabled\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A field repeated within a block (an optional one) is malformed output.
#[test]
fn r4_a01_duplicate_optional_field_rejected() {
    let dir = trusted_root("r4-a01-dup-field");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        "Repo-id            : baseos\nRepo-status        : enabled\nRepo-revision      : 1\nRepo-revision      : 2\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A field with an empty value is not a field dnf prints.
#[test]
fn r4_a01_empty_field_value_rejected() {
    let dir = trusted_root("r4-a01-empty-field");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        "Repo-id            : baseos\nRepo-status        : enabled\nRepo-name          : \n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A prefix-confusable field name is not the field it resembles.
#[test]
fn r4_a01_prefix_confusable_field_rejected() {
    let dir = trusted_root("r4-a01-prefix-field");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        "Repo-id            : baseos\nRepo-statusX       : enabled\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// One malformed block among several valid ones rejects the whole output: the
/// repository set cannot be proven, so part of it may never be trusted.
#[test]
fn r4_a01_one_bad_block_among_valid_rejected() {
    let dir = trusted_root("r4-a01-mixed-blocks");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = rocky9_with_extra_repo("appstream");
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        &format!(
            "{}Repo-id            : appstream\nRepo-status        : enabled\nRepo-status        : enabled\n",
            dnf_repolist_text("baseos", true)
        ),
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A01-3: a Transaction Summary verb printed twice is malformed.
#[test]
fn r4_a01_duplicate_summary_verb_rejected() {
    let dir = trusted_root("r4-a01-dup-verb");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    let mut table = dnf_transaction_table("nano", "baseos");
    // Insert a duplicate count line before the trailing totals.
    table = table.replacen(
        "Install  1 Package\n",
        "Install  1 Package\nInstall  1 Package\n",
        1,
    );
    t.dnf_dry_run_output = Some(override_output(Completion::Exited(1), &table, ""));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A01-4: an extra token after a grammatical summary line is unrecognized.
#[test]
fn r4_a01_extra_summary_token_rejected() {
    let dir = trusted_root("r4-a01-extra-token");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &dnf_transaction_table("nano", "baseos").replacen(
            "Install  1 Package\n",
            "Install  1 Package ATTACK\n",
            1,
        ),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A count must agree with its noun: `1 Packages` is not dnf's grammar.
#[test]
fn r4_a01_summary_singular_plural_mismatch_rejected() {
    let dir = trusted_root("r4-a01-noun");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &dnf_transaction_table("nano", "baseos").replacen(
            "Install  1 Package\n",
            "Install  1 Packages\n",
            1,
        ),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A decorated count is not a plain decimal number.
#[test]
fn r4_a01_decorated_count_rejected() {
    let dir = trusted_root("r4-a01-count");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &dnf_transaction_table("nano", "baseos").replacen(
            "Install  1 Package\n",
            "Install  +1 Package\n",
            1,
        ),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A01-5: trailing garbage after the summary counts is unrecognized structure
/// — `Totally malformed` merely starts like `Total`.
#[test]
fn r4_a01_trailing_garbage_rejected() {
    let dir = trusted_root("r4-a01-trailing");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &format!(
            "{}Totally malformed\n",
            dnf_transaction_table("nano", "baseos")
        ),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A malformed size on a known trailing line is unrecognized structure.
#[test]
fn r4_a01_malformed_total_line_rejected() {
    let dir = trusted_root("r4-a01-bad-total");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &dnf_transaction_table("nano", "baseos").replacen(
            "Total download size: 1 k\n",
            "Total download size: lots\n",
            1,
        ),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// Positive control: real-looking multi-repository repolist output and a full
/// transaction table complete the install. Alignment whitespace in the
/// summary line (which dnf pads) is accepted.
#[test]
fn r4_a01_valid_multi_repo_output_installs() {
    let dir = trusted_root("r4-a01-valid");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let t = rocky9_with_extra_repo("appstream");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

/// Positive control: a table whose summary uses padded alignment and a
/// fractional size is valid.
#[test]
fn r4_a01_valid_fractional_size_installs() {
    let dir = trusted_root("r4-a01-valid-size");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &dnf_transaction_table("nano", "baseos").replacen(
            "Total download size: 1 k\n",
            "Total download size: 1.8 M\n",
            1,
        ),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

// ===========================================================================
// R3-A02 — downloaded payload verification. The transport's own output is
// never evidence: the payload set that landed in the snapshot is proven
// against the frozen transaction — path, file name and rpm-verified
// identity — before any installation runs.
// ===========================================================================

/// An rpm whose header identity is not the transaction row's is not this
/// transaction's payload — even when its file name matches.
#[test]
fn r4_a02_payload_identity_mismatch_rejected() {
    let dir = trusted_root("r4-a02-id-mismatch");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    // The file sits at the expected path, but rpm reports a different
    // version — the header, not the name, decides.
    t.rpm_qp_results.push_back(override_output(
        Completion::Exited(0),
        "nano|(none)|9.9|1.el9|x86_64\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_payload_rejected(&r);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("payload identity mismatch"),
        "a mismatched payload identity must be reported: {:?}",
        p.reason
    );
    assert_snapshot_cleaned(&r);
}

/// Every mismatching identity dimension is rejected: wrong name, wrong
/// epoch, wrong release, wrong architecture.
#[test]
fn r4_a02_every_identity_field_is_checked() {
    for (i, record) in [
        "other|(none)|1.0|1.el9|x86_64\n", // wrong name
        "nano|1|1.0|1.el9|x86_64\n",       // wrong epoch
        "nano|(none)|1.0|9.el9|x86_64\n",  // wrong release
        "nano|(none)|1.0|1.el9|aarch64\n", // wrong architecture
    ]
    .iter()
    .enumerate()
    {
        let dir = trusted_root(&format!("r4-a02-field-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.rpm_qp_results
            .push_back(override_output(Completion::Exited(0), record, ""));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_payload_rejected(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// A payload rpm cannot read is not a usable payload — malformed metadata
/// output and a failed query both fail closed.
#[test]
fn r4_a02_malformed_or_unreadable_payload_rejected() {
    for (i, (completion, stdout, stderr)) in [
        // garbage that is not a five-field identity record
        (Completion::Exited(0), "not-an-identity\n", ""),
        // two records for one file
        (
            Completion::Exited(0),
            "nano|(none)|1.0|1.el9|x86_64\nnano|(none)|1.0|1.el9|x86_64\n",
            "",
        ),
        // rpm could not parse the file at all
        (Completion::Exited(1), "", "error: not an rpm package\n"),
        // a diagnostic on stderr is not an empty-stderr answer
        (
            Completion::Exited(0),
            "nano|(none)|1.0|1.el9|x86_64\n",
            "warning: something\n",
        ),
    ]
    .iter()
    .enumerate()
    {
        let dir = trusted_root(&format!("r4-a02-badrpm-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.rpm_qp_results
            .push_back(override_output(completion.clone(), stdout, stderr));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_payload_rejected(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// A payload placed in a different repository's cache dir cannot satisfy
/// the row — the expected path pins the repository identity.
#[test]
fn r4_a02_payload_in_wrong_repo_dir_rejected() {
    let dir = trusted_root("r4-a02-wrong-repodir");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repos.push(DnfRepo {
        id: "appstream".to_string(),
        mirrors: true,
        repodata_cached: true,
        mirrorlist_cached: true,
    });
    // The payload landed under appstream's dir — not baseos's.
    t.snap_rpm_listing = Some(format!(
        "{snap}/appstream-cafebabecafebabe/packages/nano-1.0-1.el9.x86_64.rpm\n",
        snap = FAKE_SNAP
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_payload_rejected(&r);
    assert!(
        p.reason.as_deref().unwrap_or("").contains("missing"),
        "a payload in the wrong repository dir must be reported: {:?}",
        p.reason
    );
    assert_snapshot_cleaned(&r);
}

/// Positive control: a payload whose rpm identity matches the row exactly
/// — including an epoch — completes the install.
#[test]
fn r4_a02_epoch_identity_accepted() {
    let dir = trusted_root("r4-a02-epoch");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        "Dependencies resolved.\n\
         ================================================================================\n \
         Package                Arch        Version                Repository      Size\n\
         ================================================================================\n\
         Installing:\n \
         nano                   x86_64      2:1.0-1.el9            baseos          1 k\n\n\
         Transaction Summary\n\
         ================================================================================\n\
         Install  1 Package\n\n\
         Total download size: 1 k\n\
         Installed size: 2 k\n",
        "Operation aborted.\n",
    ));
    t.rpm_qp_results.push_back(override_output(
        Completion::Exited(0),
        "nano|2|1.0|1.el9|x86_64\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    // The epoch is part of the NEVRA operand handed to the transport —
    // but never part of the payload file name.
    let dl = commands_with(&r, "/usr/bin/dnf")
        .into_iter()
        .find(|c| c.args.iter().any(|a| a == "--downloadonly"))
        .expect("a payload transport call");
    assert!(dl.args.iter().any(|a| a == "nano-2:1.0-1.el9.x86_64"));
    assert_snapshot_cleaned(&r);
}

// R3-A03 — repository/cache directory identity. A repo id and its DNF cache
// directory are related by proof, never by a name prefix.
// ===========================================================================

/// `baseos-extra-*` must never be adopted as repository `baseos`'s cache
/// directory, even when it is the only candidate.
#[test]
fn r4_a03_prefix_collision_rejected() {
    let dir = trusted_root("r4-a03-collision");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_listing = Some(format!(
        "{snap}/baseos-extra-abcdef0123456789\n{snap}/baseos-extra-abcdef0123456789/mirrorlist\n",
        snap = FAKE_SNAP
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A correct `baseos-*` directory alongside a `baseos-extra-*` one resolves
/// by identity: the extra directory is provably a different repository, so
/// the unambiguous correct directory is used and the install completes.
#[test]
fn r4_a03_correct_dir_chosen_among_prefix_confusable() {
    let dir = trusted_root("r4-a03-mixed");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_listing = Some(format!(
        "{snap}/baseos-cafebabecafebabe\n{snap}/baseos-cafebabecafebabe/repodata\n{snap}/baseos-cafebabecafebabe/repodata/repomd.xml\n{snap}/baseos-cafebabecafebabe/mirrorlist\n{snap}/baseos-extra-abcdef0123456789\n{snap}/baseos-extra-abcdef0123456789/repodata\n",
        snap = FAKE_SNAP
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

/// Similar repository ids (`baseos` vs `baseos-extra`) are never confused:
/// the transaction's repository is `baseos`, and only its own directory is
/// used.
#[test]
fn r4_a03_similar_repo_ids_disambiguated() {
    let dir = trusted_root("r4-a03-similar");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = rocky9_with_extra_repo("baseos-extra");
    // The transaction resolves from `baseos` (the first modeled repository).
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &dnf_transaction_table("nano", "baseos"),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

/// Two directories that both prove repository `baseos` (a stale hash and a
/// fresh one) are ambiguous and fail closed.
#[test]
fn r4_a03_stale_duplicate_dirs_rejected() {
    let dir = trusted_root("r4-a03-stale");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_listing = Some(format!(
        "{snap}/baseos-cafebabecafebabe\n{snap}/baseos-cafebabecafebabe/mirrorlist\n{snap}/baseos-deadbeefdeadbeef\n{snap}/baseos-deadbeefdeadbeef/mirrorlist\n",
        snap = FAKE_SNAP
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason.as_deref().unwrap_or("").contains("not unique"),
        "ambiguous repository cache dirs must be reported: {:?}",
        p.reason
    );
    assert_snapshot_cleaned(&r);
}

/// A directory listed twice is as ambiguous as two directories.
#[test]
fn r4_a03_duplicate_directory_listing_rejected() {
    let dir = trusted_root("r4-a03-dupdir");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_listing = Some(format!(
        "{snap}/baseos-cafebabecafebabe\n{snap}/baseos-cafebabecafebabe\n{snap}/baseos-cafebabecafebabe/mirrorlist\n",
        snap = FAKE_SNAP
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A malformed directory name (no hash separator / empty hash / non-hex hash)
/// proves no repository mapping at all.
#[test]
fn r4_a03_malformed_directory_name_rejected() {
    for name in ["baseos", "baseos-", "baseos-xyz", "-cafebabe"] {
        let dir = trusted_root(&format!("r4-a03-malformed-{}", name.replace('-', "_")));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.snapshot_listing = Some(format!(
            "{snap}/{n}\n{snap}/{n}/mirrorlist\n",
            snap = FAKE_SNAP,
            n = name
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// A traversal-like listing value can never be adopted as a repository
/// directory.
#[test]
fn r4_a03_traversal_like_value_rejected() {
    let dir = trusted_root("r4-a03-traversal");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_listing = Some(format!(
        "{snap}/../etc/passwd\n{snap}/..%2fetc/passwd/mirrorlist\n",
        snap = FAKE_SNAP
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// A repository id with unusual but allowed characters maps to its own
/// directory by identity.
#[test]
fn r4_a03_unusual_repo_id_accepted() {
    let dir = trusted_root("r4-a03-odd-id");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repos = vec![DnfRepo {
        id: "my_repo-2.extra".to_string(),
        mirrors: true,
        repodata_cached: true,
        mirrorlist_cached: true,
    }];
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

/// Positive control: the exact repository mapping completes the install.
#[test]
fn r4_a03_exact_mapping_accepted() {
    let dir = trusted_root("r4-a03-exact");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::rocky9());
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

// ===========================================================================
// R3-A04 — the private snapshot root must stay 0700 *while* content is copied
// into it. The copy never makes the root itself a copy target.
// ===========================================================================

/// The copy mechanism: each `cp` takes one child of the live cache root into
/// the existing snapshot root, never the root itself or a `/.` form. argv
/// boundaries are exact.
#[test]
fn r4_a04_copy_children_only_never_the_root() {
    let dir = trusted_root("r4-a04-argv");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::rocky9());
    assert_success(&r);
    let cps = commands_with(&r, "/usr/bin/cp");
    assert!(!cps.is_empty(), "the metadata cache must be copied");
    for cp in &cps {
        assert_eq!(
            cp.args.first().map(|a| a.as_str()),
            Some("-a"),
            "copy must preserve: {:?}",
            cp.args
        );
        // Every source is a discrete child entry, never the root or a `/.`
        // form that would also copy the source root's own metadata.
        let source = &cp.args[2];
        assert!(
            source.starts_with(LIVE_CACHE_ROOT),
            "copy source must be a cache child: {:?}",
            cp.args
        );
        assert_ne!(
            source.as_str(),
            LIVE_CACHE_ROOT,
            "the cache root itself must not be copied"
        );
        assert!(
            !source.ends_with("/."),
            "a `/.` source form must not be used"
        );
        // The destination is the existing snapshot root.
        assert_eq!(
            cp.args.last().map(|a| a.as_str()),
            Some(format!("{}/", FAKE_SNAP).as_str())
        );
        // No shell metacharacter or re-interpretation surface: argv only.
        assert_eq!(cp.args.len(), 4);
    }
    // The source enumeration is NUL-separated so names stay discrete.
    let finds = commands_with(&r, "/usr/bin/find");
    let source_find = finds
        .iter()
        .find(|f| f.args.first().map(|a| a.as_str()) == Some(LIVE_CACHE_ROOT))
        .expect("the live cache root must be enumerated");
    assert!(source_find.args.iter().any(|a| a == "-print0"));
    assert_snapshot_cleaned(&r);
}

/// The live cache enumeration and per-child copy, executed with real
/// filesystem copy semantics on the controller. The destination root stays
/// 0700 throughout and representative content — a regular file, a hidden
/// entry and a nested directory — is copied correctly.
#[cfg(unix)]
#[test]
fn r4_a04_real_filesystem_copy_keeps_root_private() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let work = std::env::temp_dir().join(format!("r4-a04-copy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    // A source cache root that is 0755 (as /var/cache/dnf commonly is) with
    // representative content, including a dotfile entry.
    let src = work.join("cache");
    std::fs::create_dir_all(src.join("baseos-abcdef0123456789").join("repodata")).unwrap();
    std::fs::write(
        src.join("baseos-abcdef0123456789")
            .join("repodata")
            .join("repomd.xml"),
        "<repomd/>",
    )
    .unwrap();
    std::fs::write(
        src.join("baseos-abcdef0123456789").join("mirrorlist"),
        "https://m/\n",
    )
    .unwrap();
    std::fs::write(src.join(".hidden-entry"), "secret\n").unwrap();
    let mut perm = std::fs::metadata(&src).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&src, perm).unwrap();
    // The private destination root, 0700 as mktemp + chmod enforce.
    let dst = work.join("snap");
    std::fs::create_dir_all(&dst).unwrap();
    let mut perm = std::fs::metadata(&dst).unwrap().permissions();
    perm.set_mode(0o700);
    std::fs::set_permissions(&dst, perm).unwrap();

    // Enumerate the source root's own entries, hidden ones included, exactly
    // as the production code does. (cp/find are resolved through PATH so the
    // copy semantics are exercised on whichever controller runs this.)
    let list = Command::new("find")
        .args([
            src.to_str().unwrap(),
            "-mindepth",
            "1",
            "-maxdepth",
            "1",
            "-print0",
        ])
        .output()
        .expect("find failed");
    assert!(list.status.success(), "find failed: {:?}", list);
    let children: Vec<String> = String::from_utf8_lossy(&list.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        children.len(),
        2,
        "the regular and hidden entries: {:?}",
        children
    );
    for child in &children {
        let status = Command::new("cp")
            .args(["-a", "--", child, &format!("{}/", dst.display())])
            .status()
            .expect("cp failed");
        assert!(status.success(), "copy of {} failed", child);
        // The invariant holds during the copy, not only after it.
        let mode = std::fs::metadata(&dst).unwrap().permissions().mode() & 0o7777;
        assert_eq!(
            mode, 0o700,
            "the snapshot root must stay 0700 while content is placed in it"
        );
    }

    // The content is correct: the regular file, the hidden entry, and the
    // nested directory tree with its own preserved metadata.
    assert_eq!(
        std::fs::read(dst.join(".hidden-entry")).unwrap(),
        b"secret\n",
        "hidden entries must be copied"
    );
    let repo_dir = dst.join("baseos-abcdef0123456789");
    assert!(repo_dir.is_dir());
    assert_eq!(
        std::fs::read(repo_dir.join("repodata").join("repomd.xml")).unwrap(),
        b"<repomd/>"
    );
    assert_eq!(
        std::fs::read(repo_dir.join("mirrorlist")).unwrap(),
        b"https://m/\n"
    );
    // A copied child keeps its own mode; the root does not take the source
    // root's 0755.
    let root_mode = std::fs::metadata(&dst).unwrap().permissions().mode() & 0o7777;
    assert_eq!(root_mode, 0o700);
    let _ = std::fs::remove_dir_all(&work);
}

/// The structural guarantee the copy design rests on: the destination root
/// is never itself a copy target, so no `cp -a` implementation can rewrite
/// its mode while content is being placed into it. Copying a directory *into*
/// an existing destination makes it a child entry of that destination and
/// leaves the destination's own metadata alone. (The old `cp -a <root>/.`
/// idiom instead made the destination root the copy target — BSD coreutils
/// applies the 0755 source root's mode to it — which is why the fix removes
/// that form rather than relying on any one `cp` behaving kindly.)
#[cfg(unix)]
#[test]
fn r4_a04_destination_root_is_never_a_copy_target() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let work = std::env::temp_dir().join(format!("r4-a04-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    // A source directory (mode 0755, as /var/cache/dnf commonly is) holding
    // content, and a 0700 destination root.
    let src = work.join("src");
    std::fs::create_dir_all(src.join("nested")).unwrap();
    std::fs::write(src.join("nested").join("deep"), b"x").unwrap();
    std::fs::write(src.join(".hidden"), b"y").unwrap();
    let mut perm = std::fs::metadata(&src).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&src, perm).unwrap();
    let dst = work.join("dst");
    std::fs::create_dir_all(&dst).unwrap();
    let mut perm = std::fs::metadata(&dst).unwrap().permissions();
    perm.set_mode(0o700);
    std::fs::set_permissions(&dst, perm).unwrap();

    // Copying the source directory itself into the destination — the least
    // careful form the code could take — still only creates a child entry.
    let status = Command::new("cp")
        .args([
            "-a",
            "--",
            &src.display().to_string(),
            &format!("{}/", dst.display()),
        ])
        .status()
        .expect("cp failed");
    assert!(status.success());
    let mode = std::fs::metadata(&dst).unwrap().permissions().mode() & 0o7777;
    assert_eq!(
        mode, 0o700,
        "the destination root must stay 0700 when a directory is copied into it"
    );
    // The source became a child, keeping its own mode; its content came with it.
    assert!(dst.join("src").is_dir());
    assert_eq!(
        std::fs::read(dst.join("src").join(".hidden")).unwrap(),
        b"y"
    );
    assert_eq!(
        std::fs::read(dst.join("src").join("nested").join("deep")).unwrap(),
        b"x"
    );
    let child_mode = std::fs::metadata(dst.join("src"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(child_mode, 0o755, "a copied child keeps its own mode");
    let _ = std::fs::remove_dir_all(&work);
}

// ===========================================================================
// Command/path safety boundary checks for the copy and payload paths.
// ===========================================================================

/// Transaction-derived identifiers reach the payload-transport call as
/// single argv elements; no shell metacharacter, newline or leading dash
/// can alter the command structure.
#[test]
fn r4_argv_boundaries_hold_for_payload_and_paths() {
    let dir = trusted_root("r4-argv-boundary");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::rocky9());
    assert_success(&r);
    // The payload transport is one dnf call carrying exact NEVRA operands —
    // never a bare name, never an option-like value.
    let dl = commands_with(&r, "/usr/bin/dnf")
        .into_iter()
        .find(|c| c.args.iter().any(|a| a == "--downloadonly"))
        .expect("a payload transport call");
    let pos = dl.args.iter().position(|a| a == "--downloadonly").unwrap();
    for operand in &dl.args[pos + 1..] {
        // Every operand is an exact NEVRA the frozen transaction resolved.
        assert!(!operand.starts_with('-'), "operand: {:?}", operand);
        assert!(!operand.contains('\n'), "operand: {:?}", operand);
        assert!(!operand.contains('/'), "operand: {:?}", operand);
        assert!(operand.ends_with(".x86_64"), "operand: {:?}", operand);
    }
    assert_eq!(dl.args[pos + 1..].len(), 1);
    assert_eq!(dl.args[pos + 1], "nano-1.0-1.el9.x86_64");
    // Each downloaded payload is rpm-queried by its snapshot path — one
    // argv element, inside the private snapshot, ending in `.rpm`.
    for qp in commands_with(&r, "/usr/bin/rpm")
        .into_iter()
        .filter(|c| c.args.iter().any(|a| a == "-qp"))
    {
        let path = qp.args.last().expect("a payload path operand");
        assert!(path.starts_with(FAKE_SNAP));
        assert!(path.ends_with(".rpm"));
        assert!(!path.contains('\n'));
        assert!(!path.starts_with('-'));
    }
    for mkdir in commands_with(&r, "/usr/bin/mkdir") {
        assert!(mkdir.args.iter().all(|a| a == "-p" || !a.starts_with('-')));
        assert!(mkdir.args.iter().all(|a| !a.contains('\n')));
    }
    for cp in commands_with(&r, "/usr/bin/cp") {
        // `--` ends option parsing, so no cache entry name can become one.
        assert_eq!(cp.args[1], "--");
        assert!(cp.args[2].starts_with(LIVE_CACHE_ROOT));
    }
}
