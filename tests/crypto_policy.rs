//! `crypto_policy` against the scripted in-process target.
//!
//! These run the production loader, engine, audit and output code against
//! [`FakeTarget`], whose `update-crypto-policies --show|--set` keeps one
//! policy string. They prove Sinter's own decisions, argv and order. What
//! only a real RHEL-family host can show (the tool's real output and exit
//! codes, the shipped policy modules, the effect on services and on new SSH
//! connections) is NOT verified here.
#![cfg(unix)]

mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::executor::FakeTarget;
use sinter::fake_el::{FakeChange, FakeShow};
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::{Change, Execution, Verification};
use std::path::{Path, PathBuf};

const TOOL: &str = "/usr/bin/update-crypto-policies";

fn policy(policy: &str, extra: &str) -> String {
    format!(
        "version: 1\nresources:\n  - id: c\n    type: crypto_policy\n    with:\n      policy: \"{policy}\"\n{extra}"
    )
}

fn recipe(label: &str, yaml: &str) -> PathBuf {
    let dir = trusted_root(label);
    write_recipe(&dir, "r.yaml", yaml)
}

/// A Rocky Linux 9 target as root whose current policy is `current`.
fn fake(current: &str) -> FakeTarget {
    FakeTarget::rocky9()
        .with_fake_fs()
        .as_root()
        .with_crypto_policies(current)
}

fn apply(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Apply, false, t)
}

fn plan(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Plan, false, t)
}

fn audit(r: &Path, t: FakeTarget) -> AuditReport {
    let model = sinter::model::load_model(r).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: sinter::engine::TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(t),
    };
    let engine = sinter::engine::Engine::new(model, opts).unwrap();
    sinter::audit::run_audit(engine).unwrap()
}

fn load_err(label: &str, yaml: &str) -> String {
    let p = recipe(label, yaml);
    match sinter::model::load_model(&p) {
        Ok(_) => panic!("{label}: recipe was accepted"),
        Err(e) => {
            assert_eq!(e.kind, sinter::error::ErrorKind::Schema, "{label}");
            e.message
        }
    }
}

/// The `--set` calls the scripted tool received.
fn set_calls(t: &FakeTarget) -> Vec<String> {
    t.el()
        .lock()
        .unwrap()
        .crypto_calls
        .iter()
        .filter(|a| a.first().map(String::as_str) == Some("--set"))
        .map(|a| a[1..].join(" "))
        .collect()
}

fn current(t: &FakeTarget) -> String {
    t.el().lock().unwrap().crypto_policy.clone()
}

fn reason(rep: &RunReport) -> String {
    find(rep, "c").reason.clone().unwrap_or_default()
}

/// A run that must not succeed and must not have run `--set`: why, and the
/// report when the run produced one (a plan that stops on a resource
/// returns its error instead).
fn refused(r: &Path, mode: Mode, t: FakeTarget) -> (String, Option<RunReport>) {
    let before = current(&t);
    let out = match try_run_recipe_fake(r, mode, false, t.clone()) {
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
            assert_eq!(
                find(&rep, "c").change,
                Change::None,
                "{:?}",
                find(&rep, "c")
            );
            (reason(&rep), Some(rep))
        }
        Err(e) => (e.message, None),
    };
    assert!(set_calls(&t).is_empty(), "--set ran: {:?}", set_calls(&t));
    assert_eq!(current(&t), before, "the policy changed");
    out
}

fn surfaces(rep: &RunReport, mode: &str) -> Vec<String> {
    let mut v = Vec::new();
    for fmt in [OutputFormat::Text, OutputFormat::Json] {
        let ro = RenderOptions {
            verbose: true,
            format: fmt,
            color: false,
        };
        let mut b = Vec::new();
        if mode == "plan" {
            sinter::output::render_plan(rep, &ro, &mut b).unwrap();
        } else {
            sinter::output::render_apply(rep, &ro, &mut b).unwrap();
        }
        v.push(String::from_utf8_lossy(&b).to_string());
    }
    v.push(sinter::output::run_report_json(rep, mode).to_string());
    v.push(format!("{:?}", rep.resources));
    v
}

fn has_services_note(rep: &RunReport) -> bool {
    find(rep, "c").notes.iter().any(|n| {
        n.contains("sshd")
            && n.contains("until they are restarted")
            && n.contains("NEW SSH connections")
            && n.contains("second connection")
            && n.contains("reboot")
    })
}

// ---------------------------------------------------------------------------
// load time
// ---------------------------------------------------------------------------

#[test]
fn invalid_declarations_are_rejected_at_load() {
    for (label, pol, extra, want) in [
        ("cp-l-lower", "default", "", "not a policy name"),
        ("cp-l-empty-sub", "DEFAULT:", "", "not a subpolicy name"),
        ("cp-l-option", "--show", "", "not a policy name"),
        ("cp-l-space", "DEFAULT NO-SHA1", "", "not a policy name"),
        ("cp-l-dup", "DEFAULT:NO-SHA1:NO-SHA1", "", "twice"),
        (
            "cp-l-many",
            "DEFAULT:A1:A2:A3:A4:A5:A6:A7:A8:A9",
            "      allow_weaker: true\n",
            "more than 8",
        ),
        ("cp-l-fips", "FIPS", "", "fips-mode-setup"),
        (
            "cp-l-fips-flag",
            "FIPS",
            "      allow_weaker: true\n",
            "fips-mode-setup",
        ),
        ("cp-l-legacy", "LEGACY", "", "allow_weaker: true"),
        ("cp-l-sha1", "DEFAULT:SHA1", "", "cannot tell"),
        ("cp-l-ad", "DEFAULT:AD-SUPPORT", "", "cannot tell"),
        ("cp-l-ems", "DEFAULT:NO-ENFORCE-EMS", "", "cannot tell"),
        ("cp-l-site", "DEFAULT:SITE-MODULE", "", "cannot tell"),
        (
            "cp-l-flag-string",
            "LEGACY",
            "      allow_weaker: \"true\"\n",
            "literal boolean",
        ),
        (
            "cp-l-unknown-field",
            "DEFAULT",
            "      restart: [sshd]\n",
            "unknown field with.restart",
        ),
    ] {
        let msg = load_err(label, &policy(pol, extra));
        assert!(msg.contains(want), "{label}: {msg}");
    }
    let missing = "version: 1\nresources:\n  - id: c\n    type: crypto_policy\n    with: {}\n";
    assert!(load_err("cp-l-missing", missing).contains("policy"));
    // The explicit flag accepts what the static rules refuse (except FIPS).
    for pol in ["LEGACY", "DEFAULT:SHA1", "LEGACY:AD-SUPPORT-LEGACY"] {
        let r = recipe("cp-l-flag-ok", &policy(pol, "      allow_weaker: true\n"));
        assert!(sinter::model::load_model(&r).is_ok(), "{pol}");
    }
}

#[test]
fn a_policy_from_a_variable_is_checked_at_load_and_the_flag_cannot_be_one() {
    let ok = "version: 1\nvars:\n  pol:\n    value: \"DEFAULT:NO-SHA1\"\nresources:\n  - id: c\n    type: crypto_policy\n    with:\n      policy: \"{{ vars.pol }}\"\n";
    assert!(sinter::model::load_model(&recipe("cp-l-var-ok", ok)).is_ok());
    let weak = "version: 1\nvars:\n  pol:\n    value: \"LEGACY\"\nresources:\n  - id: c\n    type: crypto_policy\n    with:\n      policy: \"{{ vars.pol }}\"\n";
    assert!(load_err("cp-l-var-weak", weak).contains("allow_weaker"));
    let flag = "version: 1\nvars:\n  weak:\n    value: true\nresources:\n  - id: c\n    type: crypto_policy\n    with:\n      policy: LEGACY\n      allow_weaker: \"{{ vars.weak }}\"\n";
    assert!(load_err("cp-l-var-flag", flag).contains("literal boolean"));
    let fact = policy("{{ facts.os.id }}", "");
    assert!(load_err("cp-l-fact", &fact).contains("policy"));
}

#[test]
fn a_second_crypto_policy_in_one_recipe_is_rejected() {
    let yaml = "version: 1\nresources:\n  - id: a\n    type: crypto_policy\n    with: { policy: DEFAULT }\n  - id: b\n    type: crypto_policy\n    with: { policy: FUTURE }\n";
    let msg = load_err("cp-l-two", yaml);
    assert!(
        msg.contains("system-wide crypto policy") && msg.contains("a and b"),
        "{msg}"
    );
}

// ---------------------------------------------------------------------------
// plan and apply
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_the_change_with_the_services_note_and_does_not_mutate() {
    let r = recipe("cp-p", &policy("DEFAULT:NO-SHA1", ""));
    let t = fake("DEFAULT");
    let before = t.fs.clone().unwrap().nodes;
    let rep = plan(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::Success);
    let c = find(&rep, "c");
    assert_eq!(c.change, Change::Changed, "{c:?}");
    assert_eq!(
        c.diff.as_ref().map(|d| d.body.clone()),
        Some(sinter::result::DiffBody::Summary {
            current: "DEFAULT".into(),
            desired: "DEFAULT:NO-SHA1".into()
        })
    );
    assert!(has_services_note(&rep), "{:?}", c.notes);
    assert!(set_calls(&t).is_empty());
    assert_eq!(current(&t), "DEFAULT");
    assert_eq!(mutation_command_count(&rep), 0);
    assert!(
        !rep.commands
            .iter()
            .any(|c| c.program == TOOL && c.args != ["--show"]),
        "{:?}",
        rep.commands
    );
    assert_eq!(
        format!("{:?}", rep.fake_fs.as_ref().unwrap().nodes),
        format!("{:?}", before)
    );
}

#[test]
fn apply_sets_the_policy_and_verifies_it_by_observing_again() {
    let r = recipe("cp-a", &policy("DEFAULT:NO-SHA1", ""));
    let t = fake("DEFAULT");
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    let c = find(&rep, "c");
    assert_eq!(
        (c.execution, c.change, c.verification),
        (
            Execution::Succeeded,
            Change::Changed,
            Verification::Verified
        ),
        "{c:?}"
    );
    assert_eq!(set_calls(&t), ["DEFAULT:NO-SHA1"]);
    assert_eq!(current(&t), "DEFAULT:NO-SHA1");
    assert!(has_services_note(&rep), "{:?}", c.notes);
    let tool: Vec<Vec<String>> = rep
        .commands
        .iter()
        .filter(|c| c.program == TOOL)
        .map(|c| c.args.clone())
        .collect();
    let set = tool.iter().position(|a| a[0] == "--set").unwrap();
    assert_eq!(tool[set], ["--set", "DEFAULT:NO-SHA1"]);
    assert!(
        tool[set + 1..].iter().any(|a| a == &["--show"]),
        "no re-observation: {tool:?}"
    );
    // Nothing restarts a service or reboots.
    assert!(
        !rep.commands.iter().any(|c| c.program.ends_with("systemctl")
            || c.program.ends_with("reboot")
            || c.program.ends_with("shutdown")),
        "{:?}",
        rep.commands
    );
}

#[test]
fn a_second_apply_changes_nothing_and_does_not_run_set() {
    let r = recipe("cp-a-idem", &policy("DEFAULT:NO-SHA1", ""));
    let t = fake("DEFAULT:NO-SHA1");
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    let c = find(&rep, "c");
    assert_eq!(c.change, Change::None, "{c:?}");
    assert!(c.notes.is_empty(), "{:?}", c.notes);
    assert!(set_calls(&t).is_empty());
    let p = plan(&r, t.clone());
    assert_eq!(find(&p, "c").change, Change::None);
}

#[test]
fn raising_the_base_needs_no_flag_and_lowering_it_does() {
    let future = recipe("cp-a-raise", &policy("FUTURE", ""));
    let t = fake("DEFAULT");
    assert_success(&apply(&future, t.clone()));
    assert_eq!(current(&t), "FUTURE");

    let default = recipe("cp-x-lower", &policy("DEFAULT", ""));
    for mode in [Mode::Plan, Mode::Apply] {
        let (why, _) = refused(&default, mode, fake("FUTURE"));
        assert!(
            why.contains("FUTURE is stronger than the declared DEFAULT")
                && why.contains("allow_weaker: true"),
            "{why}"
        );
    }
    let explicit = recipe(
        "cp-a-lower",
        &policy("DEFAULT", "      allow_weaker: true\n"),
    );
    let t = fake("FUTURE");
    assert_success(&apply(&explicit, t.clone()));
    assert_eq!(current(&t), "DEFAULT");

    let legacy = recipe(
        "cp-a-legacy",
        &policy("LEGACY", "      allow_weaker: true\n"),
    );
    let t = fake("DEFAULT");
    assert_success(&apply(&legacy, t.clone()));
    assert_eq!(set_calls(&t), ["LEGACY"]);
}

#[test]
fn unordered_bases_removed_hardening_subpolicies_and_fips_hosts_are_refused() {
    let default = recipe("cp-x-default", &policy("DEFAULT", ""));
    for (cur, want) in [
        ("EMPTY", "cannot order"),
        ("SITE1", "cannot order"),
        ("DEFAULT:NO-SHA1", "hardening subpolicy NO-SHA1"),
        ("DEFAULT:OSPP", "hardening subpolicy OSPP"),
        (
            "FUTURE:SHA1",
            "FUTURE is stronger than the declared DEFAULT",
        ),
        ("FIPS", "fips-mode-setup"),
        ("FIPS:OSPP", "fips-mode-setup"),
    ] {
        for mode in [Mode::Plan, Mode::Apply] {
            let (why, _) = refused(&default, mode, fake(cur));
            assert!(why.contains(want), "{cur}: {why}");
        }
    }
    // The flag does not open a FIPS host.
    let flagged = recipe(
        "cp-x-fips-flag",
        &policy("DEFAULT", "      allow_weaker: true\n"),
    );
    let (why, _) = refused(&flagged, Mode::Apply, fake("FIPS"));
    assert!(why.contains("fips-mode-setup"), "{why}");
    // It does accept removing a hardening subpolicy.
    let t = fake("DEFAULT:NO-SHA1");
    assert_success(&apply(&flagged, t.clone()));
    assert_eq!(current(&t), "DEFAULT");
}

#[test]
fn removing_a_subpolicy_that_is_not_hardening_needs_no_flag() {
    // DEFAULT:SHA1 -> DEFAULT: the declared policy is a plain known base.
    let default = recipe("cp-a-drop-sha1", &policy("DEFAULT", ""));
    for cur in [
        "DEFAULT:SHA1",
        "DEFAULT:AD-SUPPORT",
        "DEFAULT:NO-ENFORCE-EMS",
    ] {
        let p = plan(&default, fake(cur));
        assert_eq!(p.status, AggregateStatus::Success, "{cur}");
        assert_eq!(find(&p, "c").change, Change::Changed, "{cur}");
        let t = fake(cur);
        assert_success(&apply(&default, t.clone()));
        assert_eq!(set_calls(&t), ["DEFAULT"], "{cur}");
        assert_eq!(current(&t), "DEFAULT", "{cur}");
    }
    // Replacing it with a hardening module, or raising the base, as well.
    let hardened = recipe("cp-a-drop-sha1-harden", &policy("DEFAULT:NO-SHA1", ""));
    let t = fake("DEFAULT:SHA1");
    assert_success(&apply(&hardened, t.clone()));
    assert_eq!(current(&t), "DEFAULT:NO-SHA1");
    let future = recipe("cp-a-drop-sha1-future", &policy("FUTURE", ""));
    let t = fake("LEGACY:AD-SUPPORT-LEGACY");
    assert_success(&apply(&future, t.clone()));
    assert_eq!(current(&t), "FUTURE");
}

#[test]
fn a_policy_or_module_that_is_not_defined_is_refused_before_anything_runs() {
    // The scripted host ships no NO-CAMELLIA module.
    let r = recipe("cp-x-nomodule", &policy("DEFAULT:NO-CAMELLIA", ""));
    for mode in [Mode::Plan, Mode::Apply] {
        let (why, _) = refused(&r, mode, fake("DEFAULT"));
        assert!(
            why.contains("subpolicy NO-CAMELLIA is not defined on this host")
                && why.contains("/usr/share/crypto-policies/policies/modules/NO-CAMELLIA.pmod")
                && why.contains("/etc/crypto-policies/policies/modules/NO-CAMELLIA.pmod"),
            "{why}"
        );
    }
    let r = recipe(
        "cp-x-nobase",
        &policy("SITE9", "      allow_weaker: true\n"),
    );
    let (why, _) = refused(&r, Mode::Plan, fake("DEFAULT"));
    assert!(
        why.contains("policy SITE9 is not defined on this host"),
        "{why}"
    );
    // A definition in the local tree is accepted.
    let t =
        fake("DEFAULT").with_fs_file("/etc/crypto-policies/policies/SITE9.pol", "# synthetic\n");
    assert_success(&apply(&r, t.clone()));
    assert_eq!(current(&t), "SITE9");
    // A definition that is a symlink is not.
    let mut t = fake("DEFAULT");
    t.fs.as_mut().unwrap().put_symlink(
        "/etc/crypto-policies/policies/SITE9.pol",
        "/usr/share/crypto-policies/policies/LEGACY.pol",
        0,
        0,
    );
    let (why, _) = refused(&r, Mode::Apply, t);
    assert!(why.contains("must be a regular file"), "{why}");
}

#[test]
fn a_definition_an_earlier_resource_writes_is_a_plan_note_and_checked_at_apply() {
    let yaml = "version: 1\nresources:\n  - id: def\n    type: file\n    with:\n      path: /etc/crypto-policies/policies/modules/NO-CAMELLIA.pmod\n      content: \"cipher = -CAMELLIA-256-GCM\\n\"\n  - id: c\n    type: crypto_policy\n    depends_on: [def]\n    with:\n      policy: \"DEFAULT:NO-CAMELLIA\"\n";
    let r = recipe("cp-a-deffile", yaml);
    let p = plan(&r, fake("DEFAULT"));
    assert_eq!(p.status, AggregateStatus::Success, "{:?}", p.resources);
    let c = find(&p, "c");
    assert_eq!(c.change, Change::Changed);
    assert!(
        c.notes
            .iter()
            .any(|n| n.contains("subpolicy NO-CAMELLIA") && n.contains("checked again at apply")),
        "{:?}",
        c.notes
    );
    let t = fake("DEFAULT");
    assert_success(&apply(&r, t.clone()));
    assert_eq!(current(&t), "DEFAULT:NO-CAMELLIA");
}

// ---------------------------------------------------------------------------
// observation failures are errors, never a state
// ---------------------------------------------------------------------------

#[test]
fn an_unusable_show_answer_is_an_error_everywhere() {
    let r = recipe("cp-o-show", &policy("DEFAULT:NO-SHA1", ""));
    for (show, want) in [
        (FakeShow::Fail, "exited 1"),
        (FakeShow::Garbage, "not one policy line"),
        (FakeShow::ExtraLines, "more than one line"),
        (FakeShow::Empty, "is empty"),
        (FakeShow::StderrOnly, "is empty"),
        (FakeShow::Truncated, "truncated"),
        (FakeShow::Indeterminate, "did not complete"),
    ] {
        let t = || {
            let t = fake("DEFAULT:NO-SHA1");
            t.el().lock().unwrap().crypto_show.push_back(show);
            t
        };
        for mode in [Mode::Plan, Mode::Apply] {
            let (why, _) = refused(&r, mode, t());
            assert!(
                why.contains(want) && why.contains("could not be observed"),
                "{show:?}: {why}"
            );
        }
        // The host is in fact compliant; audit must not say so (or drift).
        let a = audit(&r, t());
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Error,
            "{show:?}"
        );
    }
}

#[test]
fn a_host_without_the_tool_is_refused_clearly() {
    let r = recipe("cp-u-notool", &policy("DEFAULT", ""));
    for t in [
        FakeTarget::ubuntu2404().with_fake_fs().as_root(),
        FakeTarget::rocky9().with_fake_fs().as_root(),
    ] {
        for mode in [Mode::Plan, Mode::Apply] {
            let (why, rep) = match try_run_recipe_fake(&r, mode, false, t.clone()) {
                Ok(rep) => (reason(&rep), Some(rep)),
                Err(e) => (e.message, None),
            };
            assert!(
                why.contains(
                    "crypto_policy is not supported on this host (update-crypto-policies was not found)"
                ),
                "{why}"
            );
            if let Some(rep) = rep {
                assert_ne!(rep.status, AggregateStatus::Success);
                assert!(!rep.commands.iter().any(|c| c.program == TOOL));
            }
        }
        let a = audit(&r, t);
        assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
        assert!(a.resources[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("not supported on this host"));
    }
}

#[test]
fn a_missing_tool_is_deferred_in_plan_when_an_earlier_package_may_bring_it() {
    let yaml = "version: 1\nresources:\n  - id: scripts\n    type: package\n    with:\n      name: crypto-policies-scripts\n      state: present\n  - id: c\n    type: crypto_policy\n    depends_on: [scripts]\n    with:\n      policy: FUTURE\n";
    let r = recipe("cp-u-deferred", yaml);
    let rep = plan(&r, FakeTarget::rocky9().with_fake_fs().as_root());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    let c = find(&rep, "c");
    assert!(c.unknown, "{c:?}");
    assert!(
        c.reason.as_deref().unwrap().contains("was not found now"),
        "{c:?}"
    );
}

// ---------------------------------------------------------------------------
// failures of the change
// ---------------------------------------------------------------------------

#[test]
fn a_failing_set_is_a_failure() {
    let r = recipe("cp-f-exit1", &policy("FUTURE", ""));
    let t = fake("DEFAULT");
    t.el().lock().unwrap().crypto_set = FakeChange::Fail;
    let rep = apply(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let c = find(&rep, "c");
    assert_eq!(
        (c.execution, c.change, c.verification),
        (Execution::Failed, Change::Possible, Verification::Unknown),
        "{c:?}"
    );
    assert!(
        reason(&rep).contains("failed with exit code 1") && reason(&rep).contains("may or may not"),
        "{}",
        reason(&rep)
    );
    assert_eq!(current(&t), "DEFAULT");
}

#[test]
fn exit_zero_without_the_declared_policy_is_a_failure() {
    let r = recipe("cp-f-noop", &policy("FUTURE", ""));
    let t = fake("DEFAULT");
    t.el().lock().unwrap().crypto_set = FakeChange::SucceedWithoutChange;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let c = find(&rep, "c");
    assert_eq!(c.execution, Execution::Failed, "{c:?}");
    assert_eq!(c.verification, Verification::Failed);
    assert_ne!(c.change, Change::Changed);
    assert!(
        reason(&rep).contains(
            "update-crypto-policies reported success but the applied policy is DEFAULT (declared: FUTURE)"
        ),
        "{}",
        reason(&rep)
    );
}

#[test]
fn exit_zero_with_a_failing_second_observation_is_not_success() {
    let r = recipe("cp-f-reobs", &policy("FUTURE", ""));
    let t = fake("DEFAULT");
    // Observation, the check right before --set, then the one after it.
    t.el().lock().unwrap().crypto_show.extend([
        FakeShow::Normal,
        FakeShow::Normal,
        FakeShow::Garbage,
    ]);
    let rep = apply(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let c = find(&rep, "c");
    assert_eq!(c.execution, Execution::Failed, "{c:?}");
    assert_ne!(c.verification, Verification::Verified);
    assert_eq!(c.change, Change::Possible);
    assert!(
        reason(&rep).contains("may or may not have been applied"),
        "{}",
        reason(&rep)
    );
    assert_eq!(set_calls(&t), ["FUTURE"]);
}

#[test]
fn a_killed_set_is_not_reported_as_success() {
    let r = recipe("cp-f-killed", &policy("FUTURE", ""));
    let t = fake("DEFAULT");
    t.el().lock().unwrap().crypto_set = FakeChange::KilledAfterChange;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let c = find(&rep, "c");
    assert_eq!(
        (c.execution, c.change, c.verification),
        (Execution::Failed, Change::Possible, Verification::Unknown),
        "{c:?}"
    );
    assert!(
        reason(&rep).contains("signal 9") && reason(&rep).contains("may or may not"),
        "{}",
        reason(&rep)
    );
}

#[test]
fn a_set_that_does_not_complete_is_indeterminate_and_nothing_else_is_sent() {
    let r = recipe("cp-f-timeout", &policy("FUTURE", ""));
    let t = fake("DEFAULT");
    t.el().lock().unwrap().crypto_set = FakeChange::IndeterminateAfterChange;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Indeterminate);
    let c = find(&rep, "c");
    assert_eq!(
        (c.execution, c.change, c.verification),
        (
            Execution::Indeterminate,
            Change::Possible,
            Verification::Unknown
        ),
        "{c:?}"
    );
    let why = reason(&rep);
    assert!(
        why.contains("did not complete") && why.contains("may or may not have been applied"),
        "{why}"
    );
    assert!(!why.contains("success"), "{why}");
    let last = rep.commands.last().unwrap();
    assert_eq!(
        (last.program.as_str(), last.args.clone()),
        (TOOL, vec!["--set".to_string(), "FUTURE".to_string()])
    );
}

#[test]
fn a_policy_change_between_observation_and_set_is_refused() {
    // Sinter saw DEFAULT and decided that FUTURE is a raise. Another
    // administrator sets DEFAULT:NO-SHA1 before Sinter runs --set: the
    // check right before the change notices and nothing is set.
    let r = recipe("cp-f-race", &policy("FUTURE", ""));
    let t = fake("DEFAULT");
    t.el().lock().unwrap().crypto_external_change = Some((1, "DEFAULT:NO-SHA1".to_string()));
    let rep = apply(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let c = find(&rep, "c");
    assert_eq!(c.change, Change::None, "{c:?}");
    assert!(
        reason(&rep).contains("changed while this resource was being handled"),
        "{}",
        reason(&rep)
    );
    assert!(set_calls(&t).is_empty());
    assert_eq!(current(&t), "DEFAULT:NO-SHA1");
}

// ---------------------------------------------------------------------------
// privilege
// ---------------------------------------------------------------------------

#[test]
fn without_root_plan_notes_it_and_apply_fails_before_set() {
    let r = recipe("cp-u-root", &policy("FUTURE", ""));
    let t = || {
        FakeTarget::rocky9()
            .with_fake_fs()
            .with_crypto_policies("DEFAULT")
    };
    let p = plan(&r, t());
    assert_eq!(p.status, AggregateStatus::Success);
    assert!(
        find(&p, "c").notes.iter().any(|n| n.contains("needs root")),
        "{:?}",
        find(&p, "c").notes
    );
    let (why, _) = refused(&r, Mode::Apply, t());
    assert!(why.contains("needs root"), "{why}");
    let target = t();
    let s = run_recipe_fake(&r, Mode::Apply, true, target.clone());
    assert_success(&s);
    assert_eq!(current(&target), "FUTURE");
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_compares_the_configured_policy_only_and_does_not_mutate() {
    let r = recipe("cp-au", &policy("DEFAULT:NO-SHA1", ""));
    let t = fake("DEFAULT:NO-SHA1");
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
    let text = a.resources[0].reason.clone().unwrap();
    assert!(
        text.contains("configured system-wide policy") && text.contains("running services"),
        "{text}"
    );

    let t = fake("DEFAULT");
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    let d = &a.resources[0].details;
    assert_eq!(d.len(), 1);
    assert_eq!(
        (
            d[0].dimension.as_str(),
            d[0].observed.as_str(),
            d[0].desired.as_str()
        ),
        ("policy", "DEFAULT", "DEFAULT:NO-SHA1")
    );
    assert!(a.resources[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("running services"));
    assert!(set_calls(&t).is_empty());
    assert_eq!(current(&t), "DEFAULT");
    assert!(
        !a.commands
            .iter()
            .any(|c| (c.program == TOOL && c.args != ["--show"])
                || is_mutation_command(&c.program, &c.args)),
        "{:?}",
        a.commands
    );
    // Audit reports drift for a weaker host without applying the plan rules.
    let a = audit(
        &recipe("cp-au-lower", &policy("DEFAULT", "")),
        fake("FUTURE"),
    );
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

#[test]
fn a_change_notifies_a_service_handler_and_sshd_is_left_alone() {
    let yaml = "version: 1\nresources:\n  - id: c\n    type: crypto_policy\n    notify: [restart-app]\n    with:\n      policy: FUTURE\nhandlers:\n  - id: restart-app\n    service: myapp\n    action: restart\n";
    let r = recipe("cp-h", yaml);
    let t = || {
        fake("DEFAULT")
            .with_service("myapp", ("loaded", "active", "enabled"))
            .with_service("sshd", ("loaded", "active", "enabled"))
    };
    let p = plan(&r, t());
    assert_eq!(p.handlers_pending, ["restart-app"]);
    let rep = apply(&r, t());
    assert_success(&rep);
    assert_eq!(rep.handlers_run.len(), 1);
    assert_eq!(rep.handlers_run[0].id, "restart-app");
    let systemctl: Vec<Vec<String>> = rep
        .commands
        .iter()
        .filter(|c| c.program.ends_with("systemctl"))
        .map(|c| c.args.clone())
        .collect();
    assert!(
        systemctl
            .iter()
            .any(|a| a.iter().any(|x| x == "restart") && a.iter().any(|x| x == "myapp")),
        "{systemctl:?}"
    );
    assert!(
        !systemctl.iter().flatten().any(|x| x.contains("sshd")),
        "{systemctl:?}"
    );
    // The handler ran after the policy was set and verified.
    let set = rep
        .commands
        .iter()
        .position(|c| c.program == TOOL && c.args[0] == "--set")
        .unwrap();
    let restart = rep
        .commands
        .iter()
        .position(|c| c.args.iter().any(|x| x == "restart"))
        .unwrap();
    assert!(set < restart);

    // No change, no handler.
    let rep = apply(&r, t().with_crypto_policies("FUTURE"));
    assert_success(&rep);
    assert!(rep.handlers_run.is_empty());
    // A failed change does not run it either.
    let failing = t();
    failing.el().lock().unwrap().crypto_set = FakeChange::Fail;
    let rep = apply(&r, failing);
    assert!(rep.handlers_run.is_empty());
}

// ---------------------------------------------------------------------------
// sensitivity
// ---------------------------------------------------------------------------

#[test]
fn a_sensitive_resource_names_no_policy_in_any_output() {
    let yaml = "version: 1\nresources:\n  - id: c\n    type: crypto_policy\n    sensitive: true\n    with:\n      policy: SYNTHPOL7\n      allow_weaker: true\n";
    let r = recipe("cp-s", yaml);
    let t = || {
        fake("SYNTHCUR3").with_fs_file(
            "/etc/crypto-policies/policies/SYNTHPOL7.pol",
            "# synthetic\n",
        )
    };
    let leaks = |texts: Vec<String>, what: &str| {
        for s in texts {
            assert!(
                !s.contains("SYNTHPOL7") && !s.contains("SYNTHCUR3"),
                "{what}: {s}"
            );
        }
    };
    leaks(surfaces(&plan(&r, t()), "plan"), "plan");
    let target = t();
    let a = apply(&r, target.clone());
    assert_success(&a);
    assert_eq!(current(&target), "SYNTHPOL7");
    leaks(surfaces(&a, "apply"), "apply");
    // The change command is recorded redacted.
    assert!(
        !a.commands
            .iter()
            .any(|c| c.args.iter().any(|x| x == "SYNTHPOL7" || x == "--set")),
        "{:?}",
        a.commands
    );
    let failing = t();
    failing.el().lock().unwrap().crypto_set = FakeChange::SucceedWithoutChange;
    let rep = apply(&r, failing);
    assert_ne!(rep.status, AggregateStatus::Success);
    leaks(surfaces(&rep, "apply"), "failure");
    // A refusal (no definition) and the audit are silent too.
    let bare = fake("SYNTHCUR3");
    match try_run_recipe_fake(&r, Mode::Plan, false, bare.clone()) {
        Ok(rep) => leaks(surfaces(&rep, "plan"), "refusal"),
        Err(e) => leaks(vec![e.message], "refusal"),
    }
    let au = audit(&r, t());
    assert_eq!(au.resources[0].status, AuditResourceStatus::Drift);
    leaks(
        vec![
            au.render_text(),
            sinter::output::audit_report_json(&au).to_string(),
            format!("{:?}", au.resources),
        ],
        "audit",
    );
}

// ---------------------------------------------------------------------------
// documentation examples
// ---------------------------------------------------------------------------

#[test]
fn the_documented_toml_examples_load_and_plan() {
    let handler = "version = 1\n\n[[resources]]\nid = \"c\"\ntype = \"crypto_policy\"\nnotify = [\"restart-app\"]\n\n[resources.with]\npolicy = \"FUTURE\"\n\n[[handlers]]\nid = \"restart-app\"\nservice = \"myapp\"\naction = \"restart\"\n";
    let legacy = "version = 1\n\n[[resources]]\nid = \"c\"\ntype = \"crypto_policy\"\n\n[resources.with]\npolicy = \"LEGACY\"\nallow_weaker = true\n";
    let sha1 = "version = 1\n\n[[resources]]\nid = \"c\"\ntype = \"crypto_policy\"\n\n[resources.with]\npolicy = \"DEFAULT:NO-SHA1\"\n";
    for (label, text, want) in [
        ("cp-d-handler", handler, "FUTURE"),
        ("cp-d-legacy", legacy, "LEGACY"),
        ("cp-d-sha1", sha1, "DEFAULT:NO-SHA1"),
    ] {
        let r = write_recipe(&trusted_root(label), "r.toml", text);
        let rep = plan(&r, fake("DEFAULT"));
        assert_eq!(rep.status, AggregateStatus::Success, "{label}");
        assert_eq!(find(&rep, "c").change, Change::Changed, "{label}");
        let t = fake("DEFAULT").with_service("myapp", ("loaded", "active", "enabled"));
        assert_success(&apply(&r, t.clone()));
        assert_eq!(current(&t), want);
    }
}
