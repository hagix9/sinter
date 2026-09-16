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
        .filter(|c| c.program == "/usr/bin/dnf" && c.args.iter().any(|a| a == "-y"))
        .count()
}

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
         Operation aborted.\n",
        n = name,
        r = repoid
    )
}

/// The payload URL the scripted target resolves for one package.
fn dnf_payload_url(name: &str, repoid: &str) -> String {
    format!(
        "https://mirror.example/{}/Packages/{}-1.0-1.el9.x86_64.rpm",
        repoid, name
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
    // ...and no post-mutation re-observation — the single rpm record is the
    // pre-mutation observation.
    assert_eq!(
        commands_with(&r, "/usr/bin/rpm").len(),
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
    assert_eq!(commands_with(&r, "/usr/bin/rpm").len(), 2);
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
fn r2_03_truncated_payload_location_output_fails_closed() {
    let dir = trusted_root("r2-03-trunc-loc");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    let mut o = override_output(
        Completion::Exited(0),
        &dnf_payload_url("nano", "baseos"),
        "partial",
    );
    o.stderr_truncated = true;
    t.dnf_location_output = Some(o);
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason.as_deref().unwrap_or("").contains("incomplete"),
        "truncated payload locations must be reported as incomplete: {:?}",
        p.reason
    );
    assert_no_download(&r);
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
         Operation aborted.\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_no_download(&r);
    assert_snapshot_cleaned(&r);
}

/// R2-03-C: a payload location that is not a fetchable absolute http(s) URL
/// must never be handed to the downloader, even when its basename matches.
#[test]
fn r2_03_invalid_payload_location_fails_closed() {
    let dir = trusted_root("r2-03-bad-url");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_location_output = Some(override_output(
        Completion::Exited(0),
        "not-a-url/nano-1.0-1.el9.x86_64.rpm\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("payload location"),
        "an invalid payload location must be reported: {:?}",
        p.reason
    );
    assert_no_download(&r);
    assert_snapshot_cleaned(&r);
}

// ===========================================================================
// R2-04 — structural ambiguity in the payload mapping must fail closed.
//         Multiple candidate payload URLs for one transaction row, or
//         multiple candidate repository cache dirs for one repository id,
//         cannot be told apart, so neither is guessed.
// ===========================================================================

#[test]
fn r2_04_ambiguous_payload_url_fails_closed() {
    let dir = trusted_root("r2-04-ambig-url");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    // Two distinct URLs share the payload basename: the transaction row
    // cannot be mapped to exactly one location.
    let url = dnf_payload_url("nano", "baseos");
    t.dnf_location_output = Some(override_output(
        Completion::Exited(0),
        &format!(
            "{}\n{}\n",
            url,
            url.replace("mirror.example", "mirror2.example")
        ),
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason.as_deref().unwrap_or("").contains("not unique"),
        "ambiguous payload location must be reported: {:?}",
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
        "{snap}/baseos-cafebabef00d\n{snap}/baseos-cafebabef00d/mirrorlist\n{snap}/baseos-deadbeef00d\n",
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
fn r2_05_fetch_tool_detection_dispatch_failure_cleans_up() {
    let dir = trusted_root("r2-05-fetchtool");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake_fault(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9(),
        "payload_fetch_tool_fail",
    );
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("failed to dispatch"),
        "fetch-tool dispatch failure must be surfaced: {:?}",
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
