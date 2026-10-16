//! Round-3 audit remediation regression tests.
//!
//! These cover the Round-2 findings (R2-01 .. R2-05 plus snapshot-permission
//! hardening). They run on any host: sensitive-propagation and preflight-parser
//! cases are pure model/CLI checks, and DNF lifecycle cases use the scripted
//! in-process FakeTarget so the whole resource/command/classification stack
//! above the transport runs production code.

mod common;

use common::*;
use sinter::engine::{AggregateStatus, Mode, RunOptions, TargetSpec};
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::model::load_model;
use sinter::result::{Change, Execution, Verification};

/// Run the built CLI binary and capture (exit code, stdout, stderr).
fn cli(recipe: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    use std::process::Command;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sinter"));
    cmd.arg(args[0]).arg(recipe);
    for a in &args[1..] {
        cmd.arg(a);
    }
    let out = cmd.output().expect("failed to run sinter CLI");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Assert the sentinel appears nowhere in any of the captured outputs.
fn assert_no_sentinel(outputs: &[(&str, &str)], sentinel: &str, context: &str) {
    for (label, text) in outputs {
        assert!(
            !text.contains(sentinel),
            "sensitive sentinel leaked in {} ({}): {}",
            label,
            context,
            text
        );
    }
}

// ===========================================================================
// Shared helpers for the DNF lifecycle cases.
// ===========================================================================

/// The private snapshot root the scripted target hands out via `mktemp`.
const FAKE_SNAP: &str = "/var/tmp/sinter-dnf.fakesnap";

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

/// The `CliError` line an `--assumeno` install leaves on stderr (R5-F04):
/// the abort is logged at ERROR level, so it lands on stderr — never stdout.
const DNF_ABORT_STDERR: &str = "Operation aborted.\n";

/// A well-formed `dnf repolist -v` body for one enabled repository.
fn dnf_repolist_text(repoid: &str, mirrors: bool) -> String {
    let mut s = format!(
        "Repo-id            : {}\nRepo-name          : {}\nRepo-status        : enabled\n",
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

/// Assert the resource was blocked by the snapshot contract: no mutation may
/// have been dispatched.
fn assert_blocked_no_mutation(r: &sinter::engine::RunReport) -> &sinter::result::ResourceResult {
    let p = find(r, "p");
    assert_eq!(p.execution, Execution::Failed, "blocked snapshot must fail");
    assert_eq!(p.change, Change::None, "no mutation means no change claim");
    assert_eq!(
        p.verification,
        Verification::NotPerformed,
        "verification must not be claimed"
    );
    assert_eq!(
        dnf_mutations(r),
        0,
        "no mutation may be dispatched when the snapshot is not provably usable"
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

/// Assert no payload download (curl/wget) was dispatched.
fn assert_no_download(r: &sinter::engine::RunReport) {
    let downloads = commands_with(r, "/usr/bin/curl")
        .into_iter()
        .chain(commands_with(r, "/usr/bin/wget"))
        .count();
    assert_eq!(
        downloads, 0,
        "no payload download may be dispatched when the snapshot is not proven usable"
    );
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

/// An output override for one scripted dnf diagnostic command.
fn override_output(completion: Completion, stdout: &str, stderr: &str) -> Output {
    Output {
        completion,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

// ===========================================================================
// R2-01 — sensitive diagnostic propagation across every validation and
//         evaluation path.
// ===========================================================================

/// Case 1: a sensitive `changed_when` must not leak its raw token through
/// model validation. The expression is not an interpolation, so the parse
/// happens during declaration validation.
#[test]
fn r2_01_case1_sensitive_changed_when_is_redacted_everywhere() {
    let dir = trusted_root("r2-01-cw");
    let sentinel = "R2_SECRET_a649d87";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: command\n    sensitive: true\n    with:\n      program: /bin/true\n      changed_when: {sentinel}\n"
        ),
    );
    // Model-level check.
    let err = load_model(&recipe).unwrap_err();
    assert_no_sentinel(
        &[("model error", &err.message)],
        sentinel,
        "changed_when validation",
    );
    // CLI surfaces: text validate, json validate, json plan.
    let (code, out, err) = cli(&recipe, &["validate"]);
    assert_ne!(code, 0);
    assert_no_sentinel(
        &[("validate stdout", &out), ("validate stderr", &err)],
        sentinel,
        "validate",
    );
    let (code, out, err) = cli(&recipe, &["validate", "--format", "json"]);
    assert_ne!(code, 0);
    assert_no_sentinel(
        &[
            ("validate-json stdout", &out),
            ("validate-json stderr", &err),
        ],
        sentinel,
        "validate --format json",
    );
    let (code, out, err) = cli(&recipe, &["plan", "--format", "json"]);
    assert_ne!(code, 0);
    assert_no_sentinel(
        &[("plan-json stdout", &out), ("plan-json stderr", &err)],
        sentinel,
        "plan --format json",
    );
}

/// Case 2: a sensitive variable declared by the *including* parent must still
/// protect tokens inside an included file, even though includes are expanded
/// before the parent's own variables become visible. Sensitivity must not
/// depend on include ordering.
#[test]
fn r2_01_case2_include_ordering_does_not_leak_parent_secret() {
    let dir = trusted_root("r2-01-inc");
    let sentinel = "R2_FORWARD_SECRET_516fb";
    write_recipe(
        &dir,
        "child.yaml",
        &format!(
            "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n      args:\n        - \"{{{{ vars.secret == {sentinel} }}}}\""
        ),
    );
    let recipe = write_recipe(
        &dir,
        "main.yaml",
        "version: 1\nvars:\n  secret:\n    value: hunter2\n    sensitive: true\ninclude:\n  - child.yaml\n",
    );
    let err = load_model(&recipe).unwrap_err();
    assert_no_sentinel(
        &[("model error", &err.message)],
        sentinel,
        "include expansion",
    );
    let (code, out, err) = cli(&recipe, &["validate"]);
    assert_ne!(code, 0);
    assert_no_sentinel(
        &[("validate stdout", &out), ("validate stderr", &err)],
        sentinel,
        "validate",
    );
    let (code, out, err) = cli(&recipe, &["validate", "--format", "json"]);
    assert_ne!(code, 0);
    assert_no_sentinel(
        &[
            ("validate-json stdout", &out),
            ("validate-json stderr", &err),
        ],
        sentinel,
        "validate --format json",
    );
    let (code, out, err) = cli(&recipe, &["plan", "--format", "json"]);
    assert_ne!(code, 0);
    assert_no_sentinel(
        &[("plan-json stdout", &out), ("plan-json stderr", &err)],
        sentinel,
        "plan --format json",
    );
}

/// Case 3: a `when` that references a sensitive variable makes the resource's
/// diagnostics sensitive at runtime, so an evaluation error must not echo the
/// other side of the comparison.
#[test]
fn r2_01_case3_runtime_when_derived_sensitivity_redacts_token() {
    let dir = trusted_root("r2-01-when");
    let sentinel = "R2_RUNTIME_SECRET_d03e";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  secret:\n    value: hunter2\n    sensitive: true\nresources:\n  - id: c\n    type: command\n    when: vars.secret == vars.{sentinel}\n    with:\n      program: /bin/true\n"
        ),
    );
    // Runtime engine reason: the undefined-variable error must be redacted.
    let model = load_model(&recipe).expect("model must load");
    let res = &model.resources[0];
    assert!(
        res.sensitive || res.derived_sensitive,
        "when referencing a sensitive variable must set derived sensitivity"
    );
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(FakeTarget::rocky9()),
    };
    let engine = sinter::engine::Engine::new(model, opts).unwrap();
    let err = match engine.run() {
        Ok(_) => panic!("plan must fail on an unresolvable sensitive when"),
        Err(e) => e,
    };
    assert_no_sentinel(
        &[("engine reason", &err.message)],
        sentinel,
        "runtime when evaluation",
    );
    // CLI plan json must not carry the token either.
    let (code, out, err) = cli(&recipe, &["plan", "--format", "json"]);
    assert_ne!(code, 0);
    assert_no_sentinel(
        &[("plan-json stdout", &out), ("plan-json stderr", &err)],
        sentinel,
        "plan --format json",
    );
}

/// Non-sensitive malformed expressions keep their descriptive diagnostics:
/// redaction must not become a blanket information blackout.
#[test]
fn r2_01_non_sensitive_expression_keeps_descriptive_error() {
    let dir = trusted_root("r2-01-plain");
    let token = "R2_PLAIN_TOKEN_4e21";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: command\n    with:\n      program: /bin/true\n      changed_when: {token}\n"
        ),
    );
    let err = load_model(&recipe).unwrap_err();
    assert!(
        err.message.contains(token),
        "non-sensitive malformed changed_when must stay descriptive: {}",
        err.message
    );
}

// ===========================================================================
// R2-02 — once a mutation's completion cannot be established, nothing else
//         may be dispatched to the target. The remote process may still be
//         running, so cleanup, re-observation, retry, and diagnostics are all
//         forbidden. The truthfulness contract is unchanged: Indeterminate
//         completion is reported as Possible change.
// ===========================================================================

#[test]
fn r2_02_indeterminate_mutation_forbids_further_target_commands() {
    let dir = trusted_root("r2-02-indet");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.manager_completion = Some(Completion::Indeterminate {
        started: true,
        reason: "lost response after dispatch".into(),
    });
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Indeterminate);
    assert_eq!(p.change, Change::Possible);
    assert_eq!(p.verification, Verification::Unknown);
    assert_eq!(r.status, AggregateStatus::Indeterminate);
    // The mutation itself was dispatched...
    assert_eq!(dnf_mutations(&r), 1);
    // ...but nothing may follow it: no snapshot cleanup,
    assert!(
        commands_with(&r, "/usr/bin/rm").is_empty(),
        "snapshot cleanup must not be dispatched after an indeterminate mutation"
    );
    // ...and no post-mutation re-observation — the single `rpm -q` record
    // is the pre-mutation observation (payload `-qp` verification queries
    // are a separate step, before the mutation).
    assert_eq!(
        commands_with(&r, "/usr/bin/rpm")
            .into_iter()
            .filter(|c| !c.args.iter().any(|a| a == "-qp"))
            .count(),
        1,
        "re-observation must not be dispatched after an indeterminate mutation"
    );
}

#[test]
fn r2_02_completed_mutation_cleans_up_and_reobserves() {
    // The contrast case: a mutation whose completion is known is followed by
    // exactly one snapshot cleanup and a re-observation.
    let dir = trusted_root("r2-02-done");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::rocky9());
    assert_success(&r);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Succeeded);
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    assert_eq!(dnf_mutations(&r), 1);
    assert_snapshot_cleaned(&r);
    // Two `rpm -q` observations (pre/post mutation); the `-qp` payload
    // verification is a separate step.
    assert_eq!(
        commands_with(&r, "/usr/bin/rpm")
            .into_iter()
            .filter(|c| !c.args.iter().any(|a| a == "-qp"))
            .count(),
        2
    );
}

// ===========================================================================
// R2-03 — dnf diagnostic output is only interpretable when the whole capture
//         completed and dnf wrote nothing to stderr. Truncated output or
//         unexpected stderr fails closed rather than guessing at a partial
//         table.
// ===========================================================================

#[test]
fn r2_03_truncated_repolist_output_fails_closed() {
    let dir = trusted_root("r2-03-trunc-repolist");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    let mut o = override_output(
        Completion::Exited(0),
        &dnf_repolist_text("baseos", true),
        "",
    );
    o.stdout_truncated = true;
    t.dnf_repolist_output = Some(o);
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason.as_deref().unwrap_or("").contains("incomplete"),
        "truncated enumeration must be reported as incomplete: {:?}",
        p.reason
    );
    // A blocked snapshot is still cleaned up.
    assert_snapshot_cleaned(&r);
}

#[test]
fn r2_03_unexpected_stderr_on_transaction_table_fails_closed() {
    let dir = trusted_root("r2-03-stderr-table");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &dnf_transaction_table("nano", "baseos"),
        "Warning: repository metadata expired, ignoring\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("unexpected stderr"),
        "stderr-bearing resolution must be reported: {:?}",
        p.reason
    );
    assert_snapshot_cleaned(&r);
}

#[test]
fn r2_03_payload_download_failure_fails_closed() {
    let dir = trusted_root("r2-03-dlfail");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    // The native payload transport failed: nothing may proceed to the
    // cache-only mutation.
    t.dnf_downloadonly_output = Some(override_output(
        Completion::Exited(1),
        "",
        "Error: Transaction failed\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(dnf_mutations(&r), 0);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("could not download the packages required for nano"),
        "a failed payload download must be reported: {:?}",
        p.reason
    );
    assert_snapshot_cleaned(&r);
}

/// R2-03-A: a repo block that only shows a repo id proves nothing about the
/// enabled repository set — the block must be complete before any repo is
/// treated as a valid enabled repository.
#[test]
fn r2_03_incomplete_repolist_block_fails_closed() {
    let dir = trusted_root("r2-03-incomplete-repolist");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        "Repo-id            : baseos\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_no_download(&r);
    assert_snapshot_cleaned(&r);
}

/// R2-03-B: a transaction body whose actions are not fully accounted for by
/// the summary is inconsistent — the summary must be reconciled with the
/// body, not just read from.
#[test]
fn r2_03_transaction_body_summary_mismatch_fails_closed() {
    let dir = trusted_root("r2-03-summary-mismatch");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    // The body performs an Install and an Upgrade, but the summary only
    // accounts for the install: the missing Upgrade count is a mismatch.
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        "Dependencies resolved.\n\
         ================================================================================\n \
         Package                Arch        Version                Repository      Size\n\
         ================================================================================\n\
         Installing:\n \
         nano                   x86_64      1.0-1.el9              baseos          1 k\n\n\
         Upgrading:\n \
         foo                    x86_64      2.0-1.el9              baseos          1 k\n\n\
         Transaction Summary\n\
         ================================================================================\n\
         Install  1 Package\n\n\
         Total download size: 2 k\n\
         Installed size: 2 k\n",
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_no_download(&r);
    assert_snapshot_cleaned(&r);
}

/// R2-03-C: a payload file that is not part of the frozen transaction set
/// must never be accepted — the downloaded set is verified against the
/// transaction, never trusted from the transport's own output.
#[test]
fn r2_03_unexpected_payload_fails_closed() {
    let dir = trusted_root("r2-03-extra-payload");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    // The expected payload plus a second `.rpm` the transaction never
    // resolved — an unexpected payload cannot silently join the set.
    t.snap_rpm_listing = Some(format!(
        "{snap}/baseos-cafebabecafebabe/packages/nano-1.0-1.el9.x86_64.rpm\n\
         {snap}/baseos-cafebabecafebabe/packages/other-9.9-1.el9.x86_64.rpm\n",
        snap = FAKE_SNAP
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(dnf_mutations(&r), 0);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("unexpected payload"),
        "an unexpected payload must be reported: {:?}",
        p.reason
    );
    assert_snapshot_cleaned(&r);
}

// ===========================================================================
// R2-04 — structural ambiguity in the payload mapping must fail closed.
//         A payload that never lands, or multiple candidate repository
//         cache dirs for one repository id, cannot be told apart or
//         guessed, so neither is tolerated.
// ===========================================================================

#[test]
fn r2_04_missing_payload_fails_closed() {
    let dir = trusted_root("r2-04-missing-payload");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    // The transport succeeded but the transaction's payload never landed
    // in the snapshot — the frozen set is not satisfied.
    t.snap_rpm_listing = Some(String::new());
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(dnf_mutations(&r), 0);
    assert!(
        p.reason.as_deref().unwrap_or("").contains("missing"),
        "a missing payload must be reported: {:?}",
        p.reason
    );
    assert_snapshot_cleaned(&r);
}

#[test]
fn r2_04_ambiguous_repo_cache_dir_fails_closed() {
    let dir = trusted_root("r2-04-ambig-dir");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    // Two `<repoid>-<hash>` cache dirs exist for the same repository id (an
    // old hash alongside a fresh one): the destination is ambiguous.
    t.snapshot_listing = Some(format!(
        "{snap}/baseos-cafebabecafebabe\n{snap}/baseos-cafebabecafebabe/mirrorlist\n{snap}/baseos-deadbeefdeadbeef\n",
        snap = FAKE_SNAP
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason.as_deref().unwrap_or("").contains("not unique"),
        "ambiguous repository cache dir must be reported: {:?}",
        p.reason
    );
    assert_snapshot_cleaned(&r);
}

// ===========================================================================
// R2-05 — a private snapshot cleanup failure must never be swallowed, and it
//         must never weaken what the mutation already proved. A leftover
//         private snapshot is a real post-mutation defect, so the resource is
//         not cleanly successful, but Change::Changed stands.
// ===========================================================================

#[test]
fn r2_05_cleanup_failure_surfaces_without_weakening_mutation_truth() {
    let dir = trusted_root("r2-05-rmfails");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_rm_fails = true;
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    // The mutation succeeded and was verified: that truth is preserved.
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    // But the leftover snapshot is a defect the result must report.
    assert_eq!(p.execution, Execution::Failed);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("private snapshot cleanup failed"),
        "cleanup failure must be surfaced: {:?}",
        p.reason
    );
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
}

#[test]
fn r2_05_dispatch_failure_cleans_up_and_propagates_cleanup_outcome() {
    // A transport-level dispatch failure inside snapshot preparation must not
    // leak the private snapshot, and its cleanup outcome must be attached to
    // the propagated error rather than discarded by a bare `?`.
    let dir = trusted_root("r2-05-dispatch");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_rm_fails = true;
    let r = run_recipe_fake_fault(&recipe, Mode::Apply, false, t, "dnf_snapshot_dispatch_fail");
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(dnf_mutations(&r), 0, "no mutation may be dispatched");
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("failed to dispatch"),
        "dispatch failure must be surfaced: {:?}",
        p.reason
    );
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("private snapshot cleanup failed"),
        "cleanup outcome must be attached to the failure: {:?}",
        p.reason
    );
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
}

/// Assert a snapshot-preparation dispatch failure attempted the cleanup.
fn assert_cleanup_attempted(r: &sinter::engine::RunReport) {
    assert!(
        !commands_with(r, "/usr/bin/rm").is_empty(),
        "the private snapshot must be cleaned up after a pre-mutation dispatch failure"
    );
}

/// R2-05: each snapshot-preparation step that runs after the snapshot exists
/// must route a dispatch failure through the cleanup policy. A bare `?` on
/// any of them would leave the private snapshot behind.
#[test]
fn r2_05_payload_verify_dispatch_failure_cleans_up() {
    let dir = trusted_root("r2-05-verify");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake_fault(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9(),
        "payload_verify_fail",
    );
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("failed to dispatch"),
        "payload verification dispatch failure must be surfaced: {:?}",
        p.reason
    );
    assert_eq!(dnf_mutations(&r), 0);
    assert_cleanup_attempted(&r);
}

#[test]
fn r2_05_payload_directory_dispatch_failure_cleans_up() {
    let dir = trusted_root("r2-05-mkdir");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake_fault(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9(),
        "payload_mkdir_fail",
    );
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("failed to dispatch"),
        "payload directory dispatch failure must be surfaced: {:?}",
        p.reason
    );
    assert_eq!(dnf_mutations(&r), 0);
    assert_cleanup_attempted(&r);
}

#[test]
fn r2_05_payload_download_dispatch_failure_cleans_up() {
    let dir = trusted_root("r2-05-download");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake_fault(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9(),
        "payload_download_fail",
    );
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("failed to dispatch"),
        "payload download dispatch failure must be surfaced: {:?}",
        p.reason
    );
    assert_eq!(dnf_mutations(&r), 0);
    assert_cleanup_attempted(&r);
}

#[test]
fn r2_05_mutation_dispatch_failure_applies_cleanup_policy() {
    // The mutation itself never started (dispatch failed), so the cleanup
    // policy applies and no mutation truth is at stake.
    let dir = trusted_root("r2-05-mutation-dispatch");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake_fault(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9(),
        "package_mutation_dispatch_fail",
    );
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None, "a failed dispatch changed nothing");
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("failed to dispatch"),
        "mutation dispatch failure must be surfaced: {:?}",
        p.reason
    );
    assert_cleanup_attempted(&r);
}

#[test]
fn r2_05_mutation_dispatch_and_cleanup_failures_are_both_observable() {
    // A primary mutation-dispatch failure plus a cleanup failure must both be
    // reported — neither may be silently discarded.
    let dir = trusted_root("r2-05-both");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_rm_fails = true;
    let r = run_recipe_fake_fault(
        &recipe,
        Mode::Apply,
        false,
        t,
        "package_mutation_dispatch_fail",
    );
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    let reason = p.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("failed to dispatch"),
        "primary failure missing: {}",
        reason
    );
    assert!(
        reason.contains("private snapshot cleanup failed"),
        "cleanup failure missing: {}",
        reason
    );
}

// ===========================================================================
// Snapshot-permission hardening — the private snapshot root must be proven
// 0700 and owned by the execution identity before it is used. The mode is
// enforced and read back BEFORE the metadata cache is copied into the root
// and re-read afterwards, so 0700 holds across the whole snapshot lifetime.
// ===========================================================================

#[test]
fn snapshot_permission_enforcement_failure_blocks() {
    let dir = trusted_root("r2-snap-chmod");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_chmod_fails = true;
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("snapshot directory permissions"),
        "chmod failure must block the snapshot: {:?}",
        p.reason
    );
    // The failure happens before the copy, so nothing is copied into a
    // snapshot whose privacy could not be established.
    assert!(commands_with(&r, "/usr/bin/cp").is_empty());
    assert_snapshot_cleaned(&r);
}

#[test]
fn snapshot_wrong_mode_blocks() {
    let dir = trusted_root("r2-snap-mode");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    // The pre-copy verification reads a mode that is not 0700: the snapshot
    // is unusable before any content is placed in it.
    t.snapshot_mode = "755".to_string();
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason.as_deref().unwrap_or("").contains("not 0700"),
        "a non-0700 snapshot must be rejected: {:?}",
        p.reason
    );
    assert!(commands_with(&r, "/usr/bin/cp").is_empty());
    assert_snapshot_cleaned(&r);
}

/// The `stat` verification itself failing (command or executor failure)
/// must fail closed: unprovable permissions are not 0700.
#[test]
fn snapshot_permission_verification_failure_blocks() {
    let dir = trusted_root("r2-snap-stat");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_stat_fails = true;
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("snapshot directory permissions"),
        "stat failure must block the snapshot: {:?}",
        p.reason
    );
    assert_snapshot_cleaned(&r);
}

/// The copy-window guarantee (R2 hardening): if the metadata cache copy
/// widened the snapshot root away from 0700, the post-copy re-verification
/// must catch it and block before any mutation.
#[test]
fn snapshot_copy_widening_mode_blocks_after_copy() {
    let dir = trusted_root("r2-snap-copied-mode");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_mode_after_copy = Some("755".to_string());
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason.as_deref().unwrap_or("").contains("not 0700"),
        "a copy that widened the root must be rejected: {:?}",
        p.reason
    );
    // The copy did run (the guarantee covers it), but no payload download or
    // mutation may follow a snapshot whose privacy is unprovable.
    assert_no_download(&r);
    assert_snapshot_cleaned(&r);
}

// ===========================================================================
// DNF cache payload isolation — the payloads a metadata-cache copy carries
// over from the live `/var/cache/dnf` must never be mistaken for the payloads
// this transaction's own download placed.
//
// Before this contract, `copy_dnf_cache_into_snapshot` copied every child of
// the live cache verbatim while `find <snap> -name '*.rpm'` enumerated the
// whole snapshot, so a host whose dnf cache held any previously downloaded
// RPM (an earlier dnf transaction, `dnf install --downloadonly`, or an
// unattended update) could never install anything: the leftovers were already
// in the snapshot when the set equality ran, and they are not in the frozen
// transaction's payload set.
// ===========================================================================

/// The private snapshot root the scripted target hands out via `mktemp`.
const CACHE_SNAP: &str = FAKE_SNAP;
/// The repository cache directory `FakeTarget::rocky9` models.
const CACHE_REPO_DIR: &str = "baseos-cafebabecafebabe";
/// The payload file name this transaction's transport delivers.
const CACHE_NANO_RPM: &str = "nano-1.0-1.el9.x86_64.rpm";

#[test]
fn dnf_private_snapshot_disables_only_completion_cache_writer() {
    let dir = trusted_root("dnf-completion-cache-scope");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::rocky9());
    assert_eq!(r.status, AggregateStatus::Success);
    let commands = commands_with(&r, "/usr/bin/dnf");
    assert_eq!(commands.len(), 5);
    for command in commands {
        let disabled: Vec<_> = command
            .args
            .iter()
            .filter(|arg| arg.starts_with("--disableplugin="))
            .map(String::as_str)
            .collect();
        assert_eq!(disabled, ["--disableplugin=generate_completion_cache"]);
        assert!(!command.args.iter().any(|arg| arg == "--noplugins"));
    }
    let recipe = pkg_recipe(&dir, "nano", "absent");
    let mut target = FakeTarget::rocky9();
    target.packages.insert("nano".into());
    let r = run_recipe_fake(&recipe, Mode::Apply, false, target);
    assert_eq!(r.status, AggregateStatus::Success);
    assert!(commands_with(&r, "/usr/bin/dnf")
        .iter()
        .all(|c| !c.args.iter().any(|arg| arg.starts_with("--disableplugin="))));
}

#[test]
fn dnf_absent_completion_plugin_warning_is_exact_and_non_repeatable() {
    const WARNING: &str =
        "No matches found for the following disable plugin patterns: generate_completion_cache";
    for (stderr, accepted) in [
        (format!("{WARNING}\n"), true),
        (format!("{WARNING}\n{WARNING}\n"), false),
        (format!("{WARNING}_other\n"), false),
        (format!("{WARNING}\nError: unexpected failure\n"), false),
    ] {
        let dir = trusted_root("dnf-completion-cache-warning");
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut target = FakeTarget::rocky9();
        target.dnf_repolist_output = Some(override_output(
            Completion::Exited(0),
            &dnf_repolist_text("baseos", true),
            &stderr,
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, target);
        if accepted {
            assert_eq!(r.status, AggregateStatus::Success, "{:?}", find(&r, "p"));
        } else {
            assert_blocked_no_mutation(&r);
            assert!(!r
                .commands
                .iter()
                .any(|c| c.args.iter().any(|a| a == "--downloadonly")));
        }
    }
}

fn cache_nano_path() -> String {
    format!(
        "{}/{}/packages/{}",
        CACHE_SNAP, CACHE_REPO_DIR, CACHE_NANO_RPM
    )
}

/// Every `rm` that removed copied payloads, i.e. the `-f` removals as opposed
/// to the final `rm -rf <snapshot>` cleanup.
fn copied_payload_removals(report: &sinter::engine::RunReport) -> Vec<Vec<String>> {
    commands_with(report, "/usr/bin/rm")
        .into_iter()
        .filter(|c| c.args.first().map(String::as_str) == Some("-f"))
        .map(|c| c.args.clone())
        .collect()
}

/// Assert no dispatched command ever names the live cache as a write target.
fn assert_live_cache_untouched(report: &sinter::engine::RunReport) {
    for c in &report.commands {
        if c.program != "/usr/bin/rm" && c.program != "/usr/bin/cp" {
            continue;
        }
        // `cp` reads the live cache (that is the snapshot source); only a
        // removal would change it.
        if c.program == "/usr/bin/rm" {
            assert!(
                !c.args.iter().any(|a| a.starts_with("/var/cache/dnf")),
                "the live dnf cache must never be a removal target: {:?}",
                c.args
            );
        }
    }
}

/// T1 — an empty metadata cache still installs normally, and the run is
/// unchanged: no payload removal is dispatched at all.
#[test]
fn dnf_cache_payload_t1_empty_cache_installs_unchanged() {
    let dir = trusted_root("dnf-cache-t1");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let t = FakeTarget::rocky9();
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Succeeded, "install must succeed");
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    assert_eq!(dnf_mutations(&r), 1, "exactly one mutation");
    assert!(
        copied_payload_removals(&r).is_empty(),
        "an empty cache has nothing to discard, so no removal is dispatched"
    );
    assert_live_cache_untouched(&r);
}

/// T2 — the defect itself: the live cache already holds an RPM belonging to
/// no transaction row. The copy carries it into the snapshot; it must not be
/// credited to this run, and the install must succeed.
#[test]
fn dnf_cache_payload_t2_unrelated_cached_rpm_does_not_block_install() {
    let dir = trusted_root("dnf-cache-t2");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.live_cache_rpms = vec!["kernel-6.12.0-1.el9.x86_64.rpm".to_string()];
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(
        p.execution,
        Execution::Succeeded,
        "an unrelated cached RPM must not fail the install: {:?}",
        p.reason
    );
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    assert_eq!(dnf_mutations(&r), 1, "exactly one mutation");

    // The leftover really was present in the snapshot, and really was removed
    // before the download — that is what keeps it out of the payload set.
    let removals = copied_payload_removals(&r);
    assert_eq!(
        removals.len(),
        1,
        "exactly one copied-payload removal: {:?}",
        removals
    );
    assert_eq!(removals[0][0], "-f", "-f is the only removal mode used");
    assert!(
        removals[0].iter().any(|a| a == "--"),
        "option parsing must be terminated: {:?}",
        removals[0]
    );
    let leftover = format!(
        "{}/{}/packages/kernel-6.12.0-1.el9.x86_64.rpm",
        CACHE_SNAP, CACHE_REPO_DIR
    );
    assert!(
        removals[0].contains(&leftover),
        "the copied leftover must be the removal target: {:?}",
        removals[0]
    );
    assert_live_cache_untouched(&r);
}

/// T3 — the sharpest case: the live cache holds a payload with exactly the
/// name this transaction needs, and the transport delivers nothing. A stale
/// cache entry must never be credited to this run's download, so the run
/// fails closed on the missing payload.
#[test]
fn dnf_cache_payload_t3_stale_same_named_rpm_is_not_credited() {
    let dir = trusted_root("dnf-cache-t3");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    // Same file name as the transaction's payload.
    t.live_cache_rpms = vec![CACHE_NANO_RPM.to_string()];
    // The transport reports success but places no payload at all.
    t.dnf_downloadonly_output = Some(override_output(Completion::Exited(0), "", ""));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(
        p.execution,
        Execution::Failed,
        "a payload this run never downloaded must not satisfy the transaction: {:?}",
        p.reason
    );
    assert_eq!(p.change, Change::None);
    assert_eq!(p.verification, Verification::NotPerformed);
    assert_eq!(dnf_mutations(&r), 0, "no mutation may be dispatched");
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("expected payload missing from snapshot"),
        "the missing payload must be named: {:?}",
        p.reason
    );
    assert_live_cache_untouched(&r);
}

/// T4 — the rejection of a payload the TRANSPORT added beyond the frozen
/// transaction is unchanged: the fix separates the copy from the download, it
/// does not relax what the download may contribute.
#[test]
fn dnf_cache_payload_t4_transport_extra_payload_still_fails_closed() {
    let dir = trusted_root("dnf-cache-t4");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    // The live cache is clean, so nothing is discarded: whatever the listing
    // reports is exactly what the transport placed.
    t.snap_rpm_listing = Some(format!(
        "{}\n{}/{}/packages/other-9.9-1.el9.x86_64.rpm\n",
        cache_nano_path(),
        CACHE_SNAP,
        CACHE_REPO_DIR
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None);
    assert_eq!(dnf_mutations(&r), 0);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("unexpected payload in snapshot"),
        "an extra transported payload must be reported: {:?}",
        p.reason
    );
    assert!(
        copied_payload_removals(&r).is_empty(),
        "nothing may be discarded when the cache carried no payload"
    );
    assert_live_cache_untouched(&r);
}

/// T5 — a payload the frozen transaction needs but the transport did not
/// place is still a hard failure.
#[test]
fn dnf_cache_payload_t5_missing_payload_still_fails_closed() {
    let dir = trusted_root("dnf-cache-t5");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snap_rpm_listing = Some(String::new());
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(dnf_mutations(&r), 0);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("expected payload missing from snapshot"),
        "{:?}",
        p.reason
    );
    assert_live_cache_untouched(&r);
}

/// T6 — the per-payload header identity verification is still applied to
/// every expected payload after the copy has been cleaned.
#[test]
fn dnf_cache_payload_t6_payload_identity_still_verified() {
    let dir = trusted_root("dnf-cache-t6");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.live_cache_rpms = vec!["kernel-6.12.0-1.el9.x86_64.rpm".to_string()];
    t.rpm_qp_results.push_back(override_output(
        Completion::Exited(0),
        "totally|different|package|1.0|x86_64\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(dnf_mutations(&r), 0);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("payload identity mismatch"),
        "identity verification must still run and fail closed: {:?}",
        p.reason
    );
    // `rpm -q <name>` is the package-state observation; the payload identity
    // proof is the separate `rpm -qp <path>` query.
    let qp: Vec<_> = commands_with(&r, "/usr/bin/rpm")
        .into_iter()
        .filter(|c| c.args.iter().any(|a| a == "-qp"))
        .collect();
    assert_eq!(qp.len(), 1, "identity is verified for the expected payload");
    assert_eq!(
        qp[0].args.last().map(String::as_str),
        Some(cache_nano_path().as_str()),
        "identity must be checked on the transaction's own payload path"
    );
    assert_live_cache_untouched(&r);
}

/// T7 — when the copied payloads cannot be discarded, the run blocks before
/// the download, mutates nothing, cleans the private snapshot up, and never
/// reaches the live cache.
#[test]
fn dnf_cache_payload_t7_removal_failure_blocks() {
    let dir = trusted_root("dnf-cache-t7");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.live_cache_rpms = vec!["kernel-6.12.0-1.el9.x86_64.rpm".to_string()];
    t.copied_payload_rm_fails = true;
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None);
    assert_eq!(p.verification, Verification::NotPerformed);
    assert_eq!(
        dnf_mutations(&r),
        0,
        "a failed discard must stop the run before any mutation"
    );
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("cannot discard copied payloads"),
        "{:?}",
        p.reason
    );
    // The download was never dispatched.
    assert!(
        !r.commands
            .iter()
            .any(|c| c.args.iter().any(|a| a == "--downloadonly")),
        "the transport must not run after a failed discard"
    );
    let rm = commands_with(&r, "/usr/bin/rm");
    assert_eq!(
        rm.last().map(|c| c.args.clone()),
        Some(vec!["-rf".to_string(), CACHE_SNAP.to_string()]),
        "the private snapshot must still be cleaned up: {:?}",
        rm
    );
    assert_live_cache_untouched(&r);
}

/// T8 — a copied-payload listing that is not provably inside the snapshot is
/// never passed to `rm`: the run blocks instead.
#[test]
fn dnf_cache_payload_t8_escaping_prune_path_blocks() {
    for escaping in [
        // the live cache itself
        "/var/cache/dnf/baseos-cafebabecafebabe/packages/evil.rpm".to_string(),
        // the snapshot root itself
        CACHE_SNAP.to_string(),
        // traversal out of the snapshot
        format!("{}/../escape.rpm", CACHE_SNAP),
        // an absolute path that merely starts with the snapshot text
        format!("{}-other/packages/evil.rpm", CACHE_SNAP),
        // a path that is not an rpm payload
        format!("{}/{}/repodata/repomd.xml", CACHE_SNAP, CACHE_REPO_DIR),
    ] {
        let dir = trusted_root("dnf-cache-t8");
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.snap_prune_rpm_listing = Some(format!("{}\0", escaping));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        let p = find(&r, "p");
        assert_eq!(
            p.execution,
            Execution::Failed,
            "an unprovable path must block, got {:?} for {}",
            p.reason,
            escaping
        );
        assert_eq!(dnf_mutations(&r), 0);
        assert!(
            p.reason
                .as_deref()
                .unwrap_or("")
                .contains("copied payload enumeration is uninterpretable"),
            "the block must name the uninterpretable listing for {}: {:?}",
            escaping,
            p.reason
        );
        assert!(
            copied_payload_removals(&r).is_empty(),
            "an uninterpretable listing must never produce a removal: {:?}",
            copied_payload_removals(&r)
        );
        assert!(
            !r.commands
                .iter()
                .any(|c| c.args.iter().any(|a| a.contains("escape.rpm")
                    || a.contains("evil.rpm")
                    || a.contains("repomd.xml"))),
            "no unproven path may reach a dispatched command"
        );
        assert_live_cache_untouched(&r);
    }
}

/// T8b — a listing whose framing is broken is equally uninterpretable.
#[test]
fn dnf_cache_payload_t8b_malformed_prune_listing_blocks() {
    for malformed in [
        // not NUL terminated
        format!(
            "{}/{}/packages/{}\n",
            CACHE_SNAP, CACHE_REPO_DIR, CACHE_NANO_RPM
        ),
        // an empty entry
        format!("{}0", cache_nano_path()),
    ] {
        let dir = trusted_root("dnf-cache-t8b");
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.snap_prune_rpm_listing = Some(malformed.clone());
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        let p = find(&r, "p");
        assert_eq!(
            p.execution,
            Execution::Failed,
            "a malformed listing must block: {:?} for {:?}",
            p.reason,
            malformed
        );
        assert_eq!(dnf_mutations(&r), 0);
        assert!(copied_payload_removals(&r).is_empty());
        assert_live_cache_untouched(&r);
    }
}

/// T9 — the discard is payload-only: repodata and the resolved mirror list
/// stay in the snapshot, so the metadata completeness check still describes
/// this snapshot and a mirror-resolving repository still works.
#[test]
fn dnf_cache_payload_t9_metadata_is_preserved() {
    let dir = trusted_root("dnf-cache-t9");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    // The Rocky target resolves via a mirror list: its presence is proven
    // from the snapshot copy and must keep working.
    assert!(
        t.dnf_repos.iter().any(|r| r.mirrors && r.mirrorlist_cached),
        "the scripted Rocky target is expected to need a mirror list"
    );
    t.live_cache_rpms = vec![
        "kernel-6.12.0-1.el9.x86_64.rpm".to_string(),
        "curl-8.0-1.el9.x86_64.rpm".to_string(),
    ];
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(
        p.execution,
        Execution::Succeeded,
        "a cache with leftovers must still install: {:?}",
        p.reason
    );

    // Every removed path is an `*.rpm` under the snapshot: nothing else.
    let removals = copied_payload_removals(&r);
    assert_eq!(removals.len(), 1);
    let operands: Vec<&String> = removals[0].iter().skip(2).collect();
    assert_eq!(operands.len(), 2, "both leftovers are discarded");
    for o in operands {
        assert!(o.starts_with(&format!("{}/", CACHE_SNAP)), "{}", o);
        assert!(o.ends_with(".rpm"), "{}", o);
        assert!(!o.contains("repodata"), "repodata must never be removed");
        assert!(
            !o.contains("mirrorlist"),
            "mirror lists must never be removed"
        );
    }
    // The metadata usability check and the repository enumeration both ran.
    assert!(
        r.commands
            .iter()
            .any(|c| c.program == "/usr/bin/dnf" && c.args.iter().any(|a| a == "repoquery")),
        "the metadata completeness check must still run"
    );
    assert!(
        r.commands
            .iter()
            .any(|c| c.program == "/usr/bin/dnf" && c.args.iter().any(|a| a == "repolist")),
        "the repository enumeration must still run"
    );
    assert_live_cache_untouched(&r);
}

/// More copied RPMs than fit in one command must all be discarded before
/// download, rather than hitting E2BIG or accepting only a prefix.
#[test]
fn dnf_cache_payload_large_cache_is_removed_in_bounded_batches() {
    let dir = trusted_root("dnf-cache-large");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.live_cache_rpms = (0..300).map(|i| format!("leftover-{i}.rpm")).collect();
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_eq!(find(&r, "p").execution, Execution::Succeeded);
    let removals = copied_payload_removals(&r);
    assert_eq!(removals.len(), 3);
    let operands: Vec<_> = removals.iter().flat_map(|a| a[2..].iter()).collect();
    assert_eq!(operands.len(), 300);
    for i in 0..300 {
        assert_eq!(
            operands
                .iter()
                .filter(
                    |a| ***a == format!("{CACHE_SNAP}/{CACHE_REPO_DIR}/packages/leftover-{i}.rpm")
                )
                .count(),
            1
        );
    }
    let download = r
        .commands
        .iter()
        .position(|c| c.args.iter().any(|a| a == "--downloadonly"))
        .unwrap();
    for (i, c) in r.commands.iter().enumerate().filter(|(_, c)| {
        c.program == "/usr/bin/rm" && c.args.first().map(String::as_str) == Some("-f")
    }) {
        assert!(i < download);
        assert_eq!(&c.args[..2], &["-f", "--"]);
        assert!(c.args.len() - 2 <= 128);
        let mut req = sinter::executor::ExecRequest::new(&c.program);
        req.args = c.args.clone();
        for sudo in [false, true] {
            assert!(sinter::executor::build_remote_command(&req, sudo, "/root").len() < 16 * 1024);
        }
    }
    assert_eq!(dnf_mutations(&r), 1);
    assert_live_cache_untouched(&r);
}

/// A failure in the second batch cannot be salvaged by downloading or
/// installing after the first batch's private deletions already succeeded.
#[test]
fn dnf_cache_payload_later_removal_failure_stops_all_following_work() {
    for completion in [
        Completion::Exited(1),
        Completion::Indeterminate {
            started: true,
            reason: "late removal unknown".into(),
        },
    ] {
        let dir = trusted_root("dnf-cache-late-failure");
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.live_cache_rpms = (0..300).map(|i| format!("leftover-{i}.rpm")).collect();
        t.copied_payload_rm_results
            .push_back(override_output(Completion::Exited(0), "", ""));
        t.copied_payload_rm_results.push_back(override_output(
            completion,
            "",
            "injected late failure",
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_ne!(find(&r, "p").execution, Execution::Succeeded);
        assert_eq!(find(&r, "p").change, Change::None);
        assert_eq!(
            copied_payload_removals(&r).len(),
            2,
            "no third batch or retry"
        );
        assert_eq!(dnf_mutations(&r), 0);
        assert!(!r
            .commands
            .iter()
            .any(|c| c.args.iter().any(|a| a == "--downloadonly")));
        let cleanup: Vec<_> = commands_with(&r, "/usr/bin/rm")
            .into_iter()
            .filter(|c| c.args.first().map(String::as_str) == Some("-rf"))
            .collect();
        assert_eq!(cleanup.len(), 1, "exactly one private snapshot cleanup");
        assert_eq!(
            cleanup[0].args,
            vec!["-rf".to_string(), CACHE_SNAP.to_string()]
        );
        assert_live_cache_untouched(&r);
    }
}

/// The complete plan is checked before the first deletion, even if its
/// oversized path follows a normal path. No narrowing to a safe subset.
#[test]
fn dnf_cache_payload_oversized_operand_blocks_before_any_removal() {
    let dir = trusted_root("dnf-cache-oversized");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snap_prune_rpm_listing = Some(format!(
        "{CACHE_SNAP}/safe.rpm\0{CACHE_SNAP}/{}.rpm\0",
        "x".repeat(16 * 1024)
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert!(copied_payload_removals(&r).is_empty());
    assert!(!r
        .commands
        .iter()
        .any(|c| c.args.iter().any(|a| a == "--downloadonly")));
    assert_snapshot_cleaned(&r);
    assert_live_cache_untouched(&r);
}
