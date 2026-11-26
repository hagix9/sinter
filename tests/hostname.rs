//! `hostname` against the scripted in-process target.
//!
//! These run the production loader, engine, audit and output code against
//! [`FakeTarget`], whose `hostnamectl` keeps a static and a transient name.
//! They prove Sinter's own decisions, argv and order. What only a real host
//! can show (the real tool's output and exit codes, what `systemd-hostnamed`
//! does to the transient name, the effect on running programs) is NOT
//! verified here.
#![cfg(unix)]

mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::executor::FakeTarget;
use sinter::fake_el::FakeChange;
use sinter::fake_host::FakeRead;
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::{Change, DiffBody, Execution, Verification};
use std::path::{Path, PathBuf};

const TOOL: &str = "/usr/bin/hostnamectl";

fn host(name: &str) -> String {
    format!(
        "version: 1\nresources:\n  - id: h\n    type: hostname\n    with:\n      name: \"{name}\"\n"
    )
}

fn recipe(label: &str, yaml: &str) -> PathBuf {
    write_recipe(&trusted_root(label), "r.yaml", yaml)
}

/// A Rocky Linux 9 target as root with these static and transient names.
fn fake(static_name: &str, transient: &str) -> FakeTarget {
    FakeTarget::rocky9()
        .with_fake_fs()
        .as_root()
        .with_hostnamectl(static_name, transient)
}

fn names(t: &FakeTarget) -> (String, String) {
    let el = t.el();
    let el = el.lock().unwrap();
    (el.host.static_name.clone(), el.host.transient_name.clone())
}

/// The `set-hostname` operands the scripted tool received.
fn sets(t: &FakeTarget) -> Vec<String> {
    t.el()
        .lock()
        .unwrap()
        .host
        .hostnamectl_calls
        .iter()
        .filter(|a| a.first().map(String::as_str) == Some("set-hostname"))
        .map(|a| a[1..].join(" "))
        .collect()
}

fn calls(t: &FakeTarget) -> usize {
    t.el().lock().unwrap().host.hostnamectl_calls.len()
}

/// Script the answers of the next observations, in order.
fn script(t: &FakeTarget, reads: &[FakeRead]) {
    t.el()
        .lock()
        .unwrap()
        .host
        .hostname_reads
        .extend(reads.iter().copied());
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

fn reason(rep: &RunReport) -> String {
    find(rep, "h").reason.clone().unwrap_or_default()
}

fn nodes(t: &FakeTarget) -> String {
    format!("{:?}", t.fs.as_ref().unwrap().nodes)
}

fn nodes_after(rep: &RunReport) -> String {
    format!("{:?}", rep.fake_fs.as_ref().unwrap().nodes)
}

/// A run that must not succeed and must not have run `set-hostname`: why.
fn refused(r: &Path, mode: Mode, t: FakeTarget) -> String {
    let before = names(&t);
    let fs_before = nodes(&t);
    let why = match try_run_recipe_fake(r, mode, false, t.clone()) {
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
            assert_eq!(find(&rep, "h").change, Change::None, "{:?}", rep.resources);
            assert_eq!(nodes_after(&rep), fs_before);
            reason(&rep)
        }
        Err(e) => e.message,
    };
    assert!(sets(&t).is_empty(), "set-hostname ran: {:?}", sets(&t));
    assert_eq!(names(&t), before, "the name changed");
    why
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
    v.push(format!("{:?}", rep.commands));
    v
}

fn has_programs_note(rep: &RunReport) -> bool {
    find(rep, "h")
        .notes
        .iter()
        .any(|n| n.contains("keep the previous name") && n.contains("/etc/hosts"))
}

fn has_transient_note(rep: &RunReport) -> bool {
    find(rep, "h")
        .notes
        .iter()
        .any(|n| n.contains("transient (running) host name is"))
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------

#[test]
fn invalid_names_are_rejected_at_load() {
    let long = format!("{}.{}", "a".repeat(32), "b".repeat(32));
    for (label, name, want) in [
        ("hn-l1", "Web01", "lower case"),
        ("hn-l2", "web_01", "not a host name"),
        ("hn-l3", "-web01", "not a host name"),
        ("hn-l4", "web01-", "not a host name"),
        ("hn-l5", "web01.", "not a host name"),
        ("hn-l6", "web..example", "not a host name"),
        ("hn-l7", "web 01", "not a host name"),
        ("hn-l8", "--static", "not a host name"),
        ("hn-l9", "", "must not be empty"),
        ("hn-l10", long.as_str(), "longer than 64 bytes"),
    ] {
        let e = load_err(label, &host(name));
        assert!(e.contains(want), "{label}: {e}");
    }
    let e = load_err(
        "hn-l11",
        "version: 1\nresources:\n  - id: h\n    type: hostname\n    with: {}\n",
    );
    assert!(e.contains("name"), "{e}");
    let e = load_err(
        "hn-l12",
        "version: 1\nresources:\n  - id: h\n    type: hostname\n    with:\n      name: web01\n      pretty: Web\n",
    );
    assert!(e.contains("pretty"), "{e}");
    let e = load_err(
        "hn-l13",
        "version: 1\nresources:\n  - id: h\n    type: hostname\n    with:\n      name: 42\n",
    );
    assert!(e.contains("string"), "{e}");
    // A variable that resolves to an upper-case name is refused at load too.
    let e = load_err(
        "hn-l14",
        "version: 1\nvars:\n  n: { value: Web01 }\nresources:\n  - id: h\n    type: hostname\n    with:\n      name: \"{{ vars.n }}\"\n",
    );
    assert!(e.contains("lower case"), "{e}");
    // The longest accepted name.
    let max = format!("{}.{}", "a".repeat(32), "b".repeat(31));
    sinter::model::load_model(&recipe("hn-l15", &host(&max))).unwrap();
}

#[test]
fn a_recipe_may_hold_one_hostname() {
    let two = "version: 1\nresources:\n  - id: first\n    type: hostname\n    with:\n      name: web01\n  - id: second\n    type: hostname\n    with:\n      name: web01\n";
    let e = load_err("hn-two", two);
    assert!(
        e.contains("conflicting ownership of the host name")
            && e.contains("first")
            && e.contains("second"),
        "{e}"
    );
}

// ---------------------------------------------------------------------------
// plan and apply
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_the_change_with_the_note_and_does_not_mutate() {
    let r = recipe("hn-p", &host("web01.example.invalid"));
    let t = fake("old.example.invalid", "old.example.invalid");
    let before = nodes(&t);
    let rep = plan(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::Success);
    let h = find(&rep, "h");
    assert_eq!(h.change, Change::Changed, "{h:?}");
    assert_eq!(
        h.diff.as_ref().map(|d| d.body.clone()),
        Some(DiffBody::Summary {
            current: "old.example.invalid".into(),
            desired: "web01.example.invalid".into()
        })
    );
    assert!(has_programs_note(&rep), "{:?}", h.notes);
    assert!(sets(&t).is_empty());
    assert_eq!(names(&t).0, "old.example.invalid");
    assert_eq!(mutation_command_count(&rep), 0);
    assert!(
        !rep.commands
            .iter()
            .any(|c| c.program == TOOL && c.args != ["--static"] && c.args != ["--transient"]),
        "{:?}",
        rep.commands
    );
    assert_eq!(nodes_after(&rep), before);
}

#[test]
fn apply_sets_the_name_and_verifies_it_by_observing_again() {
    let r = recipe("hn-a", &host("web01.example.invalid"));
    let t = fake("old.example.invalid", "old.example.invalid");
    let before = nodes(&t);
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    let h = find(&rep, "h");
    assert_eq!(
        (h.execution, h.change, h.verification),
        (
            Execution::Succeeded,
            Change::Changed,
            Verification::Verified
        ),
        "{h:?}"
    );
    assert_eq!(sets(&t), ["web01.example.invalid"]);
    assert_eq!(
        names(&t),
        (
            "web01.example.invalid".to_string(),
            "web01.example.invalid".to_string()
        )
    );
    assert!(has_programs_note(&rep));
    assert!(!has_transient_note(&rep), "{:?}", h.notes);
    // Exactly: static, transient, set-hostname <name>, static, transient.
    let argv: Vec<String> = rep
        .commands
        .iter()
        .filter(|c| c.program == TOOL)
        .map(|c| c.args.join(" "))
        .collect();
    assert_eq!(
        argv,
        [
            "--static",
            "--transient",
            "set-hostname web01.example.invalid",
            "--static",
            "--transient",
        ]
    );
    // Nothing on the filesystem is Sinter's to touch (/etc/hosts included).
    assert_eq!(nodes_after(&rep), before);
    // The fact of this run is the name observed at connect.
    assert_ne!(rep.facts.hostname, "web01.example.invalid");
}

#[test]
fn a_host_already_named_is_unchanged_in_plan_apply_and_audit() {
    let r = recipe("hn-i", &host("web01"));
    let t = fake("web01", "web01");
    for mode in [Mode::Plan, Mode::Apply] {
        let rep = run_recipe_fake(&r, mode, false, t.clone());
        assert_success(&rep);
        let h = find(&rep, "h");
        assert_eq!(h.change, Change::None, "{h:?}");
        assert!(h.notes.is_empty(), "{:?}", h.notes);
    }
    assert!(sets(&t).is_empty());
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);

    // A second apply after a change runs no set-hostname.
    let t = fake("old", "old");
    assert_success(&apply(&r, t.clone()));
    let second = apply(&r, t.clone());
    assert_success(&second);
    assert_eq!(find(&second, "h").change, Change::None);
    assert_eq!(sets(&t), ["web01"]);
}

#[test]
fn a_static_name_that_is_not_set_is_changed() {
    let r = recipe("hn-unset", &host("web01"));
    let t = fake("", "localhost");
    let p = plan(&r, t.clone());
    assert_eq!(
        find(&p, "h").diff.as_ref().map(|d| d.body.clone()),
        Some(DiffBody::Summary {
            current: "(not set)".into(),
            desired: "web01".into()
        })
    );
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(names(&t).0, "web01");
}

#[test]
fn a_different_transient_name_is_a_note_not_drift_and_not_failure() {
    let r = recipe("hn-tr", &host("web01"));
    // After the change, another source keeps the running name.
    let t = fake("old", "dhcp-192-0-2-7");
    t.el().lock().unwrap().host.hostname_transient_kept = true;
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    let h = find(&rep, "h");
    assert_eq!(
        (h.change, h.verification),
        (Change::Changed, Verification::Verified)
    );
    assert!(has_transient_note(&rep), "{:?}", h.notes);
    assert!(
        h.notes
            .iter()
            .any(|n| n.contains("\"dhcp-192-0-2-7\"") && n.contains("DHCP")),
        "{:?}",
        h.notes
    );
    assert_eq!(
        names(&t),
        ("web01".to_string(), "dhcp-192-0-2-7".to_string())
    );

    // Already set: no change, the note is still there; audit is compliant
    // and says so.
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(find(&rep, "h").change, Change::None);
    assert!(has_transient_note(&rep));
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
    assert!(a.resources[0].details.is_empty());
    assert!(
        a.resources[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("transient (running) host name is \"dhcp-192-0-2-7\""),
        "{:?}",
        a.resources[0].reason
    );

    // The transient name cannot be read after a verified change: a note.
    let t = fake("old", "old");
    script(
        &t,
        &[
            FakeRead::Normal,
            FakeRead::Normal,
            FakeRead::Normal,
            FakeRead::Fail,
        ],
    );
    let rep = apply(&r, t);
    assert_success(&rep);
    assert!(find(&rep, "h")
        .notes
        .iter()
        .any(|n| n.contains("could not be observed after the change")));
}

// ---------------------------------------------------------------------------
// what cannot be observed is an error, never a state
// ---------------------------------------------------------------------------

#[test]
fn a_failed_or_damaged_observation_is_an_error_not_a_name() {
    let r = recipe("hn-obs", &host("web01"));
    for (mode, want) in [
        (FakeRead::Fail, "exited 1"),
        (FakeRead::ExtraLines, "more than one line"),
        (FakeRead::Truncated, "truncated"),
        (FakeRead::Killed, "signal 9"),
        (FakeRead::Indeterminate, "did not complete"),
    ] {
        // Damage the static answer (first call), then the transient one.
        for nth in [0usize, 1] {
            let mut reads = vec![FakeRead::Normal; nth];
            reads.push(mode);
            for run in [Mode::Plan, Mode::Apply] {
                // Both a host that needs the change and one that does not.
                for base in [fake("old", "old"), fake("web01", "web01")] {
                    script(&base, &reads);
                    let why = match try_run_recipe_fake(&r, run, false, base.clone()) {
                        Ok(rep) => {
                            assert_ne!(rep.status, AggregateStatus::Success, "{mode:?}");
                            assert_eq!(find(&rep, "h").change, Change::None, "{mode:?}");
                            reason(&rep)
                        }
                        Err(e) => e.message,
                    };
                    assert!(why.contains(want), "{mode:?} {nth} {run:?}: {why}");
                    assert!(
                        why.contains(if nth == 0 { "static" } else { "transient" }),
                        "{why}"
                    );
                    assert!(sets(&base).is_empty(), "{mode:?}");
                }
            }
            let t = fake("web01", "web01");
            script(&t, &reads);
            let a = audit(&r, t);
            assert_eq!(
                a.resources[0].status,
                AuditResourceStatus::Error,
                "{mode:?} {nth}: {:?}",
                a.resources[0]
            );
            assert!(a.resources[0].details.is_empty());
        }
    }
}

#[test]
fn a_host_without_hostnamectl_is_refused_clearly() {
    let r = recipe("hn-notool", &host("web01"));
    // An Ubuntu host and an unrecognized OS alike: the tool decides.
    for base in [
        FakeTarget::ubuntu2404().with_fake_fs().as_root(),
        FakeTarget::unsupported().with_fake_fs().as_root(),
    ] {
        for mode in [Mode::Plan, Mode::Apply] {
            let why = match try_run_recipe_fake(&r, mode, false, base.clone()) {
                Ok(rep) => {
                    assert_ne!(rep.status, AggregateStatus::Success);
                    assert_eq!(find(&rep, "h").change, Change::None);
                    reason(&rep)
                }
                Err(e) => e.message,
            };
            assert!(
                why.contains("hostname is not supported on this host (hostnamectl was not found)"),
                "{mode:?}: {why}"
            );
        }
        assert_eq!(calls(&base), 0);
        let a = audit(&r, base);
        assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
        assert!(a.resources[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("hostnamectl was not found"));
    }
}

// ---------------------------------------------------------------------------
// failures of the change
// ---------------------------------------------------------------------------

#[test]
fn a_failing_set_hostname_is_a_failure() {
    let r = recipe("hn-fail", &host("web01"));
    let t = fake("old", "old");
    t.el().lock().unwrap().host.hostname_set = FakeChange::Fail;
    let rep = apply(&r, t.clone());
    assert_ne!(rep.status, AggregateStatus::Success);
    let h = find(&rep, "h");
    assert_eq!(h.execution, Execution::Failed, "{h:?}");
    assert_ne!(h.verification, Verification::Verified);
    assert!(reason(&rep).contains("exit code 1"), "{}", reason(&rep));
    assert_eq!(names(&t).0, "old");
}

#[test]
fn exit_zero_without_the_declared_name_is_a_failure() {
    let r = recipe("hn-noop", &host("web01"));
    let t = fake("old", "old");
    t.el().lock().unwrap().host.hostname_set = FakeChange::SucceedWithoutChange;
    let rep = apply(&r, t.clone());
    assert_ne!(rep.status, AggregateStatus::Success);
    let h = find(&rep, "h");
    assert_eq!(
        (h.execution, h.change, h.verification),
        (Execution::Failed, Change::Possible, Verification::Failed),
        "{h:?}"
    );
    assert!(
        reason(&rep).contains("reported success but the static host name is \"old\""),
        "{}",
        reason(&rep)
    );
    assert_eq!(names(&t).0, "old");
}

#[test]
fn a_signal_or_timeout_of_the_change_is_indeterminate_never_success() {
    for (label, mode) in [
        ("hn-kill", FakeChange::KilledAfterChange),
        ("hn-tmo", FakeChange::IndeterminateAfterChange),
    ] {
        let r = recipe(label, &host("web01"));
        let t = fake("old", "old");
        t.el().lock().unwrap().host.hostname_set = mode;
        let rep = apply(&r, t.clone());
        assert_ne!(rep.status, AggregateStatus::Success, "{mode:?}");
        let h = find(&rep, "h");
        assert_eq!(
            (h.execution, h.change, h.verification),
            (
                Execution::Indeterminate,
                Change::Possible,
                Verification::Unknown
            ),
            "{mode:?}: {h:?}"
        );
        assert!(reason(&rep).contains("may or may not"), "{}", reason(&rep));
        // static, transient, set-hostname: nothing more was sent.
        assert_eq!(calls(&t), 3, "{mode:?}");
    }
}

#[test]
fn a_failed_observation_after_the_change_is_not_success() {
    let r = recipe("hn-reobs", &host("web01"));
    for (mode, execution) in [
        (FakeRead::Fail, Execution::Failed),
        (FakeRead::ExtraLines, Execution::Failed),
        (FakeRead::Indeterminate, Execution::Indeterminate),
    ] {
        let t = fake("old", "old");
        script(&t, &[FakeRead::Normal, FakeRead::Normal, mode]);
        let rep = apply(&r, t);
        assert_ne!(rep.status, AggregateStatus::Success, "{mode:?}");
        let h = find(&rep, "h");
        assert_eq!(
            (h.execution, h.change),
            (execution, Change::Possible),
            "{mode:?}: {h:?}"
        );
        assert_ne!(h.verification, Verification::Verified);
    }
}

// ---------------------------------------------------------------------------
// privilege
// ---------------------------------------------------------------------------

#[test]
fn a_change_needs_root_and_plan_says_so() {
    let r = recipe("hn-root", &host("web01"));
    let user = |s: &str| FakeTarget::rocky9().with_fake_fs().with_hostnamectl(s, s);
    let p = plan(&r, user("old"));
    assert!(
        find(&p, "h").notes.iter().any(|n| n.contains("needs root")),
        "{:?}",
        find(&p, "h").notes
    );
    let why = refused(&r, Mode::Apply, user("old"));
    assert!(why.contains("needs root"), "{why}");

    // With --sudo the change runs.
    let t = user("old");
    assert_success(&run_recipe_fake(&r, Mode::Apply, true, t.clone()));
    assert_eq!(names(&t).0, "web01");

    // Nothing to change needs no root.
    let rep = apply(&r, user("web01"));
    assert_success(&rep);
    assert_eq!(find(&rep, "h").change, Change::None);
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_reports_static_drift_and_does_not_mutate() {
    let r = recipe("hn-au", &host("web01"));
    let t = fake("old", "old");
    let before = nodes(&t);
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    let d = &a.resources[0].details;
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(
        (
            d[0].dimension.as_str(),
            d[0].observed.as_str(),
            d[0].desired.as_str()
        ),
        ("static", "old", "web01")
    );
    assert!(sets(&t).is_empty());
    assert_eq!(names(&t), ("old".to_string(), "old".to_string()));
    assert_eq!(nodes(&t), before);
    assert!(
        !a.commands.iter().any(|c| (c.program == TOOL
            && c.args != ["--static"]
            && c.args != ["--transient"])
            || is_mutation_command(&c.program, &c.args)),
        "{:?}",
        a.commands
    );

    // A static name that is not set is drift too, never "compliant".
    let a = audit(&r, fake("", "localhost"));
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert_eq!(a.resources[0].details[0].observed, "(not set)");
}

// ---------------------------------------------------------------------------
// sensitive values
// ---------------------------------------------------------------------------

#[test]
fn a_sensitive_resource_names_no_host_name_in_any_output() {
    let yaml = "version: 1\nresources:\n  - id: h\n    type: hostname\n    sensitive: true\n    with:\n      name: synthname7\n";
    let r = recipe("hn-sens", yaml);
    let t = || fake("synthcur3", "synthcur3");
    let leaks = |texts: Vec<String>, what: &str| {
        for s in texts {
            assert!(
                !s.contains("synthname7") && !s.contains("synthcur3"),
                "{what}: {s}"
            );
        }
    };
    leaks(surfaces(&plan(&r, t()), "plan"), "plan");
    let target = t();
    let a = apply(&r, target.clone());
    assert_success(&a);
    assert_eq!(names(&target).0, "synthname7");
    leaks(surfaces(&a, "apply"), "apply");

    for mode in [FakeChange::SucceedWithoutChange, FakeChange::Fail] {
        let failing = t();
        failing.el().lock().unwrap().host.hostname_set = mode;
        let rep = apply(&r, failing);
        assert_ne!(rep.status, AggregateStatus::Success);
        leaks(surfaces(&rep, "apply"), "failure");
    }
    // A different transient name is not named either.
    let kept = t();
    kept.el().lock().unwrap().host.hostname_transient_kept = true;
    leaks(surfaces(&apply(&r, kept.clone()), "apply"), "transient");
    leaks(surfaces(&apply(&r, kept.clone()), "apply"), "transient 2");

    let damaged = t();
    script(&damaged, &[FakeRead::ExtraLines]);
    match try_run_recipe_fake(&r, Mode::Plan, false, damaged) {
        Ok(rep) => leaks(surfaces(&rep, "plan"), "observation"),
        Err(e) => leaks(vec![e.message], "observation"),
    }

    for target in [t(), kept] {
        let au = audit(&r, target);
        let mut texts = vec![
            au.render_text(),
            format!("{:?}", au.resources),
            format!("{:?}", au.commands),
        ];
        for fmt in [OutputFormat::Text, OutputFormat::Json] {
            let ro = RenderOptions {
                verbose: true,
                format: fmt,
                color: false,
            };
            let mut b = Vec::new();
            sinter::output::render_audit(&au, &ro, &mut b).unwrap();
            texts.push(String::from_utf8_lossy(&b).to_string());
        }
        leaks(texts, "audit");
    }
}
