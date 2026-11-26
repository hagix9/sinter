//! `tuned` against the scripted in-process target.
//!
//! These run the production loader, engine, audit and output code against
//! [`FakeTarget`], whose `tuned-adm profile|off|recommend|verify` keeps the
//! selection in `/etc/tuned/active_profile` on the scripted filesystem.
//! They prove Sinter's own decisions, argv and order. What only a host with
//! TuneD can show (the real output and exit codes of `tuned-adm`, the form
//! of the state file, the profile directories of each release, what
//! `tuned-adm verify` touches) is NOT verified here.
#![cfg(unix)]

mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::executor::FakeTarget;
use sinter::fake_el::FakeChange;
use sinter::fake_host::FakeRead;
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::{Change, Execution, Verification};
use std::path::{Path, PathBuf};

const TOOL: &str = "/usr/sbin/tuned-adm";
const STATE: &str = "/etc/tuned/active_profile";
const UNIT: &str = "tuned.service";

/// A recipe with one `tuned` resource `t` and these `with` lines.
fn tuned(with: &[&str]) -> String {
    let mut out = "version: 1\nresources:\n  - id: t\n    type: tuned\n    with:\n".to_string();
    for line in with {
        out.push_str(&format!("      {line}\n"));
    }
    out
}

fn recipe(label: &str, yaml: &str) -> PathBuf {
    let dir = trusted_root(label);
    write_recipe(&dir, "r.yaml", yaml)
}

/// A Rocky Linux 9 target as root with TuneD installed, its service active
/// and `selected` as the selected profile.
fn fake(selected: Option<&str>) -> FakeTarget {
    FakeTarget::rocky9()
        .with_fake_fs()
        .as_root()
        .with_tuned(selected)
}

fn stopped(t: FakeTarget) -> FakeTarget {
    t.with_service(UNIT, ("loaded", "inactive", "enabled"))
}

fn no_unit(mut t: FakeTarget) -> FakeTarget {
    t.services.remove(UNIT);
    t
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

/// Every `tuned-adm` argv the scripted tool received.
fn calls(t: &FakeTarget) -> Vec<String> {
    t.el()
        .lock()
        .unwrap()
        .host
        .tuned_calls
        .iter()
        .map(|a| a.join(" "))
        .collect()
}

/// The `profile` and `off` calls the scripted tool received.
fn change_calls(t: &FakeTarget) -> Vec<String> {
    calls(t)
        .into_iter()
        .filter(|c| c.starts_with("profile") || c == "off")
        .collect()
}

fn verify_calls(t: &FakeTarget) -> usize {
    calls(t).iter().filter(|c| *c == "verify").count()
}

/// The state file at the end of a run.
fn selection(rep: &RunReport) -> String {
    String::from_utf8(
        rep.fake_fs
            .as_ref()
            .unwrap()
            .file_bytes(STATE)
            .unwrap_or_default(),
    )
    .unwrap()
}

fn reason(rep: &RunReport) -> String {
    find(rep, "t").reason.clone().unwrap_or_default()
}

fn notes(rep: &RunReport) -> String {
    find(rep, "t").notes.join(" | ")
}

/// A run that must not succeed and must not have run a change: why, and the
/// report when the run produced one (a plan that stops on a resource
/// returns its error instead).
fn refused(r: &Path, mode: Mode, t: FakeTarget) -> (String, Option<RunReport>) {
    let before = t.fs.clone().unwrap().file_bytes(STATE);
    let out = match try_run_recipe_fake(r, mode, false, t.clone()) {
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
            assert_eq!(
                find(&rep, "t").change,
                Change::None,
                "{:?}",
                find(&rep, "t")
            );
            assert_eq!(rep.fake_fs.as_ref().unwrap().file_bytes(STATE), before);
            (reason(&rep), Some(rep))
        }
        Err(e) => (e.message, None),
    };
    assert!(change_calls(&t).is_empty(), "a change ran: {:?}", calls(&t));
    assert_eq!(verify_calls(&t), 0, "verify ran: {:?}", calls(&t));
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

fn dims(a: &AuditReport) -> Vec<(String, String, String)> {
    a.resources[0]
        .details
        .iter()
        .map(|d| (d.dimension.clone(), d.observed.clone(), d.desired.clone()))
        .collect()
}

// ---------------------------------------------------------------------------
// load time
// ---------------------------------------------------------------------------

#[test]
fn invalid_declarations_are_rejected_at_load() {
    let cases: &[(&str, &[&str], &str)] = &[
        ("tu-l-none", &["verify: false"], "needs exactly one"),
        ("tu-l-active-only", &["state: active"], "needs exactly one"),
        (
            "tu-l-rec-false",
            &["recommended: false"],
            "needs exactly one",
        ),
        (
            "tu-l-both",
            &["profile: balanced", "recommended: true"],
            "more than one",
        ),
        (
            "tu-l-off-profile",
            &["profile: balanced", "state: off"],
            "more than one",
        ),
        (
            "tu-l-off-rec",
            &["recommended: true", "state: off"],
            "more than one",
        ),
        (
            "tu-l-off-verify",
            &["state: off", "verify: true"],
            "nothing to verify",
        ),
        ("tu-l-state", &["state: stopped"], "active or off"),
        ("tu-l-state-bool", &["state: false"], "active or off"),
        (
            "tu-l-rec-string",
            &["recommended: \"true\""],
            "recommended must be a literal boolean",
        ),
        (
            "tu-l-verify-string",
            &["profile: balanced", "verify: \"yes\""],
            "verify must be a literal boolean",
        ),
        ("tu-l-space", &["profile: \"a b\""], "not a profile name"),
        (
            "tu-l-option",
            &["profile: \"--help\""],
            "not a profile name",
        ),
        ("tu-l-slash", &["profile: \"../x\""], "not a profile name"),
        ("tu-l-int", &["profile: 7"], "must be a string"),
        (
            "tu-l-unknown-field",
            &["profile: balanced", "restart: true"],
            "unknown field with.restart",
        ),
    ];
    for (label, with, want) in cases {
        let msg = load_err(label, &tuned(with));
        assert!(msg.contains(want), "{label}: {msg}");
    }
    let long = format!("profile: {}", "a".repeat(65));
    assert!(load_err("tu-l-long", &tuned(&[&long])).contains("not a profile name"));
    let empty = "version: 1\nresources:\n  - id: t\n    type: tuned\n    with: {}\n";
    assert!(load_err("tu-l-empty", empty).contains("needs exactly one"));
    for (label, with) in [
        ("tu-l-ok-profile", vec!["profile: virtual-guest"]),
        ("tu-l-ok-active", vec!["profile: balanced", "state: active"]),
        ("tu-l-ok-rec", vec!["recommended: true", "verify: true"]),
        ("tu-l-ok-off", vec!["state: off"]),
    ] {
        let r = recipe(label, &tuned(&with));
        assert!(sinter::model::load_model(&r).is_ok(), "{label}");
    }
}

#[test]
fn a_profile_from_a_variable_is_checked_at_load_and_the_literals_cannot_be_variables() {
    let var = |value: &str, with: &str| {
        format!(
            "version: 1\nvars:\n  v:\n    value: {value}\nresources:\n  - id: t\n    type: tuned\n    with:\n{with}"
        )
    };
    let ok = var("balanced", "      profile: \"{{ vars.v }}\"\n");
    assert!(sinter::model::load_model(&recipe("tu-l-var-ok", &ok)).is_ok());
    let bad = var("\"two names\"", "      profile: \"{{ vars.v }}\"\n");
    assert!(load_err("tu-l-var-bad", &bad).contains("not a profile name"));
    let state = var("\"off\"", "      state: \"{{ vars.v }}\"\n");
    assert!(load_err("tu-l-var-state", &state).contains("active or off"));
    let rec = var("true", "      recommended: \"{{ vars.v }}\"\n");
    assert!(load_err("tu-l-var-rec", &rec).contains("literal boolean"));
    let verify = var(
        "true",
        "      profile: balanced\n      verify: \"{{ vars.v }}\"\n",
    );
    assert!(load_err("tu-l-var-verify", &verify).contains("literal boolean"));
    let fact = tuned(&["profile: \"{{ facts.os.id }}\""]);
    assert!(load_err("tu-l-fact", &fact).contains("profile"));
}

#[test]
fn a_second_tuned_in_one_recipe_is_rejected() {
    let yaml = "version: 1\nresources:\n  - id: a\n    type: tuned\n    with: { profile: balanced }\n  - id: b\n    type: tuned\n    with: { state: off }\n";
    let msg = load_err("tu-l-two", yaml);
    assert!(
        msg.contains("TuneD profile") && msg.contains("a and b"),
        "{msg}"
    );
}

// ---------------------------------------------------------------------------
// plan and apply
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_the_change_with_the_settings_note_and_does_not_mutate() {
    let r = recipe("tu-p", &tuned(&["profile: throughput-performance"]));
    let t = fake(Some("balanced"));
    let before = t.fs.clone().unwrap().nodes;
    let rep = plan(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::Success);
    let c = find(&rep, "t");
    assert_eq!(c.change, Change::Changed, "{c:?}");
    assert_eq!(
        c.diff.as_ref().map(|d| d.body.clone()),
        Some(sinter::result::DiffBody::Summary {
            current: "balanced".into(),
            desired: "throughput-performance".into()
        })
    );
    assert!(
        notes(&rep).contains("reapply_sysctl") && notes(&rep).contains("declare each setting"),
        "{}",
        notes(&rep)
    );
    // A named profile needs no command at all in plan.
    assert!(calls(&t).is_empty(), "{:?}", calls(&t));
    assert!(!rep.commands.iter().any(|c| c.program == TOOL));
    assert_eq!(mutation_command_count(&rep), 0);
    assert_eq!(
        format!("{:?}", rep.fake_fs.as_ref().unwrap().nodes),
        format!("{:?}", before)
    );
}

#[test]
fn plan_never_runs_verify_and_says_so() {
    for with in [
        vec!["profile: throughput-performance", "verify: true"],
        vec!["profile: balanced", "verify: true"],
        vec!["recommended: true", "verify: true"],
    ] {
        let r = recipe("tu-p-verify", &tuned(&with));
        let t = fake(Some("balanced"));
        let rep = plan(&r, t.clone());
        assert_eq!(rep.status, AggregateStatus::Success, "{with:?}");
        assert_eq!(verify_calls(&t), 0, "{with:?}: {:?}", calls(&t));
        assert!(change_calls(&t).is_empty());
        assert!(
            notes(&rep).contains("verify") && notes(&rep).contains("not run"),
            "{with:?}: {}",
            notes(&rep)
        );
    }
}

#[test]
fn apply_selects_the_profile_and_reads_the_state_file_again() {
    let r = recipe("tu-a", &tuned(&["profile: throughput-performance"]));
    let t = fake(Some("balanced"));
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    let c = find(&rep, "t");
    assert_eq!(
        (c.execution, c.change, c.verification),
        (
            Execution::Succeeded,
            Change::Changed,
            Verification::Verified
        ),
        "{c:?}"
    );
    assert_eq!(calls(&t), ["profile throughput-performance"]);
    assert_eq!(selection(&rep), "throughput-performance\n");
    assert!(notes(&rep).contains("reapply_sysctl"), "{}", notes(&rep));
    let tool: Vec<&sinter::executor::CommandRecord> =
        rep.commands.iter().filter(|c| c.program == TOOL).collect();
    assert_eq!(tool.len(), 1);
    assert_eq!(tool[0].args, ["profile", "throughput-performance"]);
    // Sinter starts, restarts and enables nothing, and installs nothing.
    assert!(
        !rep.commands.iter().any(|c| {
            (c.program.ends_with("systemctl") && c.args.first().map(String::as_str) != Some("show"))
                || c.program.ends_with("dnf")
        }),
        "{:?}",
        rep.commands
    );
}

#[test]
fn a_profile_in_the_older_layout_and_from_nothing_selected_is_selected() {
    // `powersave` lives in /usr/lib/tuned/powersave on the scripted host.
    let r = recipe("tu-a-old", &tuned(&["profile: powersave"]));
    for start in [None, Some("balanced")] {
        let t = fake(start);
        let rep = apply(&r, t.clone());
        assert_success(&rep);
        assert_eq!(selection(&rep), "powersave\n");
    }
    // No state file at all is "no profile selected" as well.
    let mut t = fake(None);
    t.fs.as_mut().unwrap().nodes.remove(STATE);
    let p = plan(&r, t.clone());
    assert_eq!(
        find(&p, "t").diff.as_ref().map(|d| d.body.clone()),
        Some(sinter::result::DiffBody::Summary {
            current: "(no profile selected)".into(),
            desired: "powersave".into()
        })
    );
    assert_success(&apply(&r, t));
}

#[test]
fn an_already_selected_profile_runs_no_command_at_all() {
    let r = recipe("tu-i", &tuned(&["profile: balanced", "verify: true"]));
    for mode in [Mode::Plan, Mode::Apply] {
        let t = fake(Some("balanced"));
        let before = t.fs.clone().unwrap().nodes;
        let rep = run_recipe_fake(&r, mode, false, t.clone());
        assert_success(&rep);
        let c = find(&rep, "t");
        assert_eq!(c.change, Change::None, "{c:?}");
        assert_eq!(reason(&rep), "profile already selected");
        assert!(calls(&t).is_empty(), "{:?}", calls(&t));
        assert!(!rep.commands.iter().any(|c| c.program == TOOL));
        assert_eq!(mutation_command_count(&rep), 0);
        assert_eq!(
            format!("{:?}", rep.fake_fs.as_ref().unwrap().nodes),
            format!("{:?}", before)
        );
    }
    // Apply twice: the second run finds the first one's selection.
    let r = recipe("tu-i-twice", &tuned(&["profile: virtual-guest"]));
    let first = apply(&r, fake(Some("balanced")));
    assert_success(&first);
    let again = fake(Some("virtual-guest"));
    assert_eq!(
        again.fs.clone().unwrap().file_bytes(STATE),
        first.fake_fs.as_ref().unwrap().file_bytes(STATE)
    );
    let second = apply(&r, again.clone());
    assert_eq!(find(&second, "t").change, Change::None);
    assert!(calls(&again).is_empty());
}

#[test]
fn an_already_selected_profile_with_a_stopped_service_is_unchanged_with_a_note() {
    let r = recipe("tu-i-stopped", &tuned(&["profile: balanced"]));
    for (t, want) in [
        (stopped(fake(Some("balanced"))), "is not active (inactive)"),
        (no_unit(fake(Some("balanced"))), "was not found"),
    ] {
        for mode in [Mode::Plan, Mode::Apply] {
            let t = t.clone();
            let rep = run_recipe_fake(&r, mode, false, t.clone());
            assert_success(&rep);
            assert_eq!(find(&rep, "t").change, Change::None);
            let n = notes(&rep);
            assert!(
                n.contains(want) && n.contains("selected but not applied"),
                "{n}"
            );
            assert!(calls(&t).is_empty(), "{:?}", calls(&t));
        }
    }
    // With the service running there is no such note.
    let rep = apply(&r, fake(Some("balanced")));
    assert!(find(&rep, "t").notes.is_empty(), "{}", notes(&rep));
}

#[test]
fn state_off_switches_tuning_off_and_is_idempotent() {
    let r = recipe("tu-off", &tuned(&["state: off"]));
    let t = fake(Some("balanced"));
    let p = plan(&r, t.clone());
    assert_eq!(find(&p, "t").change, Change::Changed);
    assert_eq!(
        find(&p, "t").diff.as_ref().map(|d| d.body.clone()),
        Some(sinter::result::DiffBody::Summary {
            current: "balanced".into(),
            desired: "(no profile selected)".into()
        })
    );
    assert!(calls(&t).is_empty());
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(calls(&t), ["off"]);
    assert_eq!(selection(&rep), "");
    assert_eq!(find(&rep, "t").verification, Verification::Verified);
    // Nothing selected: nothing to do, whatever the service does.
    for t in [fake(None), stopped(fake(None)), no_unit(fake(None))] {
        let rep = apply(&r, t.clone());
        assert_success(&rep);
        assert_eq!(find(&rep, "t").change, Change::None);
        assert_eq!(reason(&rep), "no profile is selected");
        assert!(find(&rep, "t").notes.is_empty(), "{}", notes(&rep));
        assert!(calls(&t).is_empty());
    }
    // Switching off needs the running service as every change does.
    let (why, _) = refused(&r, Mode::Apply, stopped(fake(Some("balanced"))));
    assert!(why.contains("its service is not running"), "{why}");
}

#[test]
fn recommended_selects_what_tuned_recommends() {
    let r = recipe("tu-rec", &tuned(&["recommended: true"]));
    let t = fake(Some("balanced"));
    let p = plan(&r, t.clone());
    assert_eq!(
        find(&p, "t").diff.as_ref().map(|d| d.body.clone()),
        Some(sinter::result::DiffBody::Summary {
            current: "balanced".into(),
            desired: "virtual-guest".into()
        })
    );
    assert_eq!(calls(&t), ["recommend"]);
    let t = fake(Some("balanced"));
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(calls(&t), ["recommend", "profile virtual-guest"]);
    assert_eq!(selection(&rep), "virtual-guest\n");
    // Already the recommendation: only the question is asked.
    let t = fake(Some("virtual-guest"));
    let rep = apply(&r, t.clone());
    assert_eq!(find(&rep, "t").change, Change::None);
    assert_eq!(calls(&t), ["recommend"]);
    // A recommendation that is no profile on the host is refused.
    let t = fake(Some("balanced"));
    t.el().lock().unwrap().host.tuned_recommended = "synthetic-absent".to_string();
    let (why, _) = refused(&r, Mode::Apply, t);
    assert!(
        why.contains("the profile synthetic-absent is not defined on this host"),
        "{why}"
    );
}

#[test]
fn an_unusable_recommendation_is_an_error_everywhere() {
    let r = recipe("tu-rec-bad", &tuned(&["recommended: true"]));
    for (read, want) in [
        (FakeRead::Fail, "exited 1"),
        (FakeRead::ExtraLines, "more than one line"),
        (FakeRead::Empty, "it is empty"),
        (FakeRead::Truncated, "truncated"),
        (FakeRead::Killed, "signal 9"),
        (FakeRead::Indeterminate, "did not complete"),
    ] {
        let t = || {
            let t = fake(Some("virtual-guest"));
            t.el()
                .lock()
                .unwrap()
                .host
                .tuned_recommend_reads
                .push_back(read);
            t
        };
        for mode in [Mode::Plan, Mode::Apply] {
            let (why, rep) = refused(&r, mode, t());
            assert!(
                why.contains(want) && why.contains("recommended profile could not be observed"),
                "{read:?}: {why}"
            );
            // An observation that did not complete is a failure, not
            // "indeterminate": nothing was sent that could change the host.
            if let Some(rep) = rep {
                assert_eq!(rep.status, AggregateStatus::ApplyFailed, "{read:?}");
            }
        }
        // The host is in fact compliant; audit must not say so (or drift).
        let a = audit(&r, t());
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Error,
            "{read:?}"
        );
    }
    let t = fake(Some("virtual-guest"));
    t.el().lock().unwrap().host.tuned_recommended = "Recommended profile: balanced".to_string();
    let (why, _) = refused(&r, Mode::Plan, t);
    assert!(why.contains("not one profile name"), "{why}");
}

// ---------------------------------------------------------------------------
// the four "cannot" states
// ---------------------------------------------------------------------------

#[test]
fn not_installed_no_unit_stopped_service_and_missing_profile_are_told_apart() {
    let r = recipe("tu-x", &tuned(&["profile: throughput-performance"]));
    let missing = recipe("tu-x-missing", &tuned(&["profile: synthetic-absent"]));
    let not_installed = || FakeTarget::rocky9().with_fake_fs().as_root();
    let mut seen = Vec::new();
    for mode in [Mode::Plan, Mode::Apply] {
        // 1. TuneD is not installed.
        let (why, rep) = match try_run_recipe_fake(&r, mode, false, not_installed()) {
            Ok(rep) => (reason(&rep), Some(rep)),
            Err(e) => (e.message, None),
        };
        assert!(
            why.contains(
                "tuned is not supported on this host (tuned-adm was not found); install it with a package resource"
            ),
            "{why}"
        );
        if let Some(rep) = rep {
            assert_ne!(rep.status, AggregateStatus::Success);
            assert!(!rep.commands.iter().any(|c| c.program == TOOL));
        }
        seen.push(why);
        // 2. The tool is there, the unit is not.
        let (why, _) = refused(&r, mode, no_unit(fake(Some("balanced"))));
        assert!(
            why.contains("the unit tuned.service was not found") && !why.contains("not running"),
            "{why}"
        );
        seen.push(why);
        // 3. The unit is there and not active.
        let (why, _) = refused(&r, mode, stopped(fake(Some("balanced"))));
        assert!(
            why.contains(
                "TuneD is installed but its service is not running (tuned.service is inactive); start it with a service resource (Sinter does not start it)"
            ),
            "{why}"
        );
        seen.push(why);
        // 4. Everything runs, the profile does not exist.
        let (why, _) = refused(&missing, mode, fake(Some("balanced")));
        assert!(
            why.contains("the profile synthetic-absent is not defined on this host")
                && why.contains("/etc/tuned/profiles")
                && why.contains("/etc/tuned,")
                && why.contains("/usr/lib/tuned/profiles")
                && why.contains("/usr/lib/tuned)"),
            "{why}"
        );
        seen.push(why);
    }
    for (i, a) in seen.iter().enumerate() {
        for b in &seen[i + 1..] {
            if a != b {
                continue;
            }
            // The same state in plan and in apply may read the same.
            assert_eq!(seen.iter().filter(|x| *x == a).count(), 2, "{a}");
        }
    }
    // A failed service is "not active" too, with its state named.
    let failed = fake(Some("balanced")).with_service(UNIT, ("loaded", "failed", "enabled"));
    let (why, _) = refused(&r, Mode::Apply, failed);
    assert!(why.contains("tuned.service is failed"), "{why}");

    // Audit: not installed is an error; a missing unit and a stopped
    // service are differences from "profile X is active", each named.
    let a = audit(&r, not_installed());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
    assert!(a.resources[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("tuned-adm was not found"));
    let keep = recipe("tu-x-keep", &tuned(&["profile: balanced"]));
    let a = audit(&keep, no_unit(fake(Some("balanced"))));
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert_eq!(
        dims(&a),
        [(
            "service".to_string(),
            "the unit tuned.service was not found: the selected profile is not applied".to_string(),
            "tuned.service is active".to_string()
        )]
    );
    let a = audit(&keep, stopped(fake(Some("balanced"))));
    assert_eq!(
        dims(&a),
        [(
            "service".to_string(),
            "tuned.service is not active (inactive): the selected profile is not applied"
                .to_string(),
            "tuned.service is active".to_string()
        )]
    );
}

#[test]
fn a_profile_definition_that_is_not_a_regular_file_is_refused() {
    let r = recipe("tu-x-symlink", &tuned(&["profile: site-db"]));
    let mut t = fake(Some("balanced"))
        .with_fs_dir("/etc/tuned/profiles")
        .with_fs_dir("/etc/tuned/profiles/site-db");
    t.fs.as_mut().unwrap().put_symlink(
        "/etc/tuned/profiles/site-db/tuned.conf",
        "/usr/lib/tuned/profiles/balanced/tuned.conf",
        0,
        0,
    );
    for mode in [Mode::Plan, Mode::Apply] {
        let (why, _) = refused(&r, mode, t.clone());
        assert!(why.contains("must be a regular file"), "{why}");
    }
}

// ---------------------------------------------------------------------------
// deferral in plan
// ---------------------------------------------------------------------------

#[test]
fn a_missing_tool_is_deferred_in_plan_when_an_earlier_package_may_bring_it() {
    let yaml = "version: 1\nresources:\n  - id: pkg\n    type: package\n    with:\n      name: tuned\n      state: present\n  - id: t\n    type: tuned\n    depends_on: [pkg]\n    with:\n      profile: virtual-guest\n";
    let r = recipe("tu-d-package", yaml);
    let t = FakeTarget::rocky9().with_fake_fs().as_root();
    let rep = plan(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    let c = find(&rep, "t");
    assert!(c.unknown, "{c:?}");
    assert!(
        c.reason
            .as_deref()
            .unwrap()
            .contains("tuned-adm was not found now"),
        "{c:?}"
    );
    assert!(calls(&t).is_empty());
    // Without the earlier package the same host is refused in plan.
    let alone = recipe("tu-d-alone", &tuned(&["profile: virtual-guest"]));
    assert!(try_run_recipe_fake(&alone, Mode::Plan, false, t)
        .map(|rep| reason(&rep))
        .unwrap_or_else(|e| e.message)
        .contains("not supported on this host"));
}

#[test]
fn a_stopped_service_is_a_plan_note_after_an_earlier_service_resource_and_apply_selects() {
    let yaml = "version: 1\nresources:\n  - id: svc\n    type: service\n    with:\n      name: tuned.service\n      state: running\n      enabled: true\n  - id: t\n    type: tuned\n    depends_on: [svc]\n    with:\n      profile: throughput-performance\n";
    let r = recipe("tu-d-service", yaml);
    let t = || fake(Some("balanced")).with_service(UNIT, ("loaded", "inactive", "disabled"));
    let target = t();
    let p = plan(&r, target.clone());
    assert_eq!(p.status, AggregateStatus::Success, "{:?}", p.resources);
    let c = find(&p, "t");
    // Deferred: the outcome is decided at apply.
    assert!(c.unknown, "{c:?}");
    assert!(
        notes(&p).contains("tuned.service is not active (inactive) now")
            && notes(&p).contains("checked again at apply")
            && notes(&p).contains("svc runs earlier"),
        "{}",
        notes(&p)
    );
    assert!(calls(&target).is_empty());
    let target = t();
    let rep = apply(&r, target.clone());
    assert_success(&rep);
    assert_eq!(calls(&target), ["profile throughput-performance"]);
    assert_eq!(selection(&rep), "throughput-performance\n");
    // The service was started by the service resource, not by tuned.
    assert_eq!(find(&rep, "svc").change, Change::Changed);
}

#[test]
fn a_custom_profile_an_earlier_file_writes_is_a_plan_note_and_selected_at_apply() {
    let yaml = "version: 1\nresources:\n  - id: dir\n    type: directory\n    with:\n      path: /etc/tuned/profiles/site-db\n      parents: true\n  - id: conf\n    type: file\n    depends_on: [dir]\n    with:\n      path: /etc/tuned/profiles/site-db/tuned.conf\n      content: \"[main]\\ninclude=throughput-performance\\n\"\n  - id: t\n    type: tuned\n    depends_on: [conf]\n    with:\n      profile: site-db\n";
    let r = recipe("tu-d-custom", yaml);
    let target = fake(Some("balanced"));
    let p = plan(&r, target.clone());
    assert_eq!(p.status, AggregateStatus::Success, "{:?}", p.resources);
    let c = find(&p, "t");
    assert!(c.unknown, "{c:?}");
    assert!(
        notes(&p).contains("the profile site-db is not defined on this host now")
            && notes(&p).contains("checked again at apply"),
        "{}",
        notes(&p)
    );
    let target = fake(Some("balanced"));
    let rep = apply(&r, target.clone());
    assert_success(&rep);
    assert_eq!(calls(&target), ["profile site-db"]);
    assert_eq!(selection(&rep), "site-db\n");
}

// ---------------------------------------------------------------------------
// observation failures are errors, never a state
// ---------------------------------------------------------------------------

#[test]
fn a_state_file_in_another_form_is_an_error_everywhere() {
    let r = recipe("tu-o-state", &tuned(&["profile: balanced"]));
    for (content, want) in [
        ("balanced powersave\n", "not one profile name"),
        ("balanced\npowersave\n", "more than one line"),
        (" balanced\n", "not one profile name"),
        ("# synthetic comment\n", "not one profile name"),
    ] {
        let t = || fake(None).with_fs_file(STATE, content);
        for mode in [Mode::Plan, Mode::Apply] {
            let (why, _) = refused(&r, mode, t());
            assert!(
                why.contains(want) && why.contains("selected profile could not be observed"),
                "{content:?}: {why}"
            );
        }
        let a = audit(&r, t());
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Error,
            "{content:?}"
        );
    }
}

#[test]
fn a_state_file_that_is_a_symlink_or_a_directory_is_refused_and_not_followed() {
    let r = recipe("tu-o-symlink", &tuned(&["profile: balanced"]));
    let mut link = fake(None).with_fs_file("/etc/tuned/elsewhere", "balanced\n");
    {
        let fs = link.fs.as_mut().unwrap();
        fs.nodes.remove(STATE);
        fs.put_symlink(STATE, "/etc/tuned/elsewhere", 0, 0);
    }
    let mut dir = fake(None);
    {
        let fs = dir.fs.as_mut().unwrap();
        fs.nodes.remove(STATE);
        fs.mkdir_node(STATE, 0o755, 0, 0);
    }
    for (t, want) in [(link, "symlink"), (dir, "directory")] {
        for mode in [Mode::Plan, Mode::Apply] {
            let (why, _) = refused(&r, mode, t.clone());
            assert!(why.contains(want), "{why}");
        }
        let a = audit(&r, t.clone());
        assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
    }
}

#[test]
fn a_failing_service_observation_is_an_error_and_not_a_stopped_service() {
    let r = recipe("tu-o-service", &tuned(&["profile: throughput-performance"]));
    let t = || {
        let mut t = fake(Some("balanced"));
        // The answer about the unit is damaged (a record is missing).
        t.manager
            .need_override
            .insert(UNIT.to_string(), sinter::fakesys::NeedOverride::Missing);
        t
    };
    for mode in [Mode::Plan, Mode::Apply] {
        let (why, _) = refused(&r, mode, t());
        assert!(why.contains("service observation for"), "{why}");
        assert!(!why.contains("not running"), "{why}");
    }
    let a = audit(&r, t());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
}

// ---------------------------------------------------------------------------
// failures of the change
// ---------------------------------------------------------------------------

#[test]
fn a_failing_change_is_a_failure() {
    let r = recipe("tu-f-exit1", &tuned(&["profile: throughput-performance"]));
    let t = fake(Some("balanced"));
    t.el().lock().unwrap().host.tuned_change = FakeChange::Fail;
    let rep = apply(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let c = find(&rep, "t");
    assert_eq!(
        (c.execution, c.change, c.verification),
        (Execution::Failed, Change::Possible, Verification::Unknown),
        "{c:?}"
    );
    assert!(
        reason(&rep).contains("tuned-adm profile failed with exit code 1")
            && reason(&rep).contains("may or may not"),
        "{}",
        reason(&rep)
    );
    assert_eq!(selection(&rep), "balanced\n");
}

#[test]
fn exit_zero_without_the_declared_selection_is_a_failure() {
    let t = fake(Some("balanced"));
    t.el().lock().unwrap().host.tuned_change = FakeChange::SucceedWithoutChange;
    let r = recipe(
        "tu-f-noop",
        &tuned(&["profile: throughput-performance", "verify: true"]),
    );
    let rep = apply(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let c = find(&rep, "t");
    assert_eq!(c.execution, Execution::Failed, "{c:?}");
    assert_eq!(c.verification, Verification::Failed);
    assert_ne!(c.change, Change::Changed);
    assert!(
        reason(&rep).contains(
            "tuned-adm profile reported success but /etc/tuned/active_profile names balanced (declared: throughput-performance)"
        ),
        "{}",
        reason(&rep)
    );
    // The selection did not change: verify is not asked about it.
    assert_eq!(verify_calls(&t), 0);

    let off = recipe("tu-f-noop-off", &tuned(&["state: off"]));
    let t = fake(Some("balanced"));
    t.el().lock().unwrap().host.tuned_change = FakeChange::SucceedWithoutChange;
    let rep = apply(&off, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert!(
        reason(&rep).contains("tuned-adm off reported success but"),
        "{}",
        reason(&rep)
    );
}

#[test]
fn a_killed_or_unfinished_change_is_indeterminate_and_nothing_else_is_sent() {
    for (mode, want) in [
        (FakeChange::KilledAfterChange, "signal 9"),
        (FakeChange::IndeterminateAfterChange, "did not complete"),
    ] {
        let r = recipe(
            "tu-f-interrupted",
            &tuned(&["profile: throughput-performance", "verify: true"]),
        );
        let t = fake(Some("balanced"));
        t.el().lock().unwrap().host.tuned_change = mode;
        let rep = apply(&r, t.clone());
        assert_eq!(rep.status, AggregateStatus::Indeterminate, "{mode:?}");
        let c = find(&rep, "t");
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
            why.contains(want) && why.contains("may or may not have been changed"),
            "{why}"
        );
        assert!(!why.contains("success"), "{why}");
        let last = rep.commands.last().unwrap();
        assert_eq!(
            (last.program.as_str(), last.args.clone()),
            (
                TOOL,
                vec!["profile".to_string(), "throughput-performance".to_string()]
            )
        );
        assert_eq!(verify_calls(&t), 0);
    }
}

#[test]
fn a_selection_that_changes_between_observation_and_the_command_is_refused() {
    // Sinter read `balanced` and asked for the recommendation. Another
    // administrator selects `powersave` meanwhile: the look right before
    // the change notices and nothing is sent.
    let r = recipe("tu-f-race", &tuned(&["recommended: true"]));
    let t = fake(Some("balanced"));
    t.el().lock().unwrap().host.tuned_external_selection = Some("powersave\n".to_string());
    let rep = apply(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let c = find(&rep, "t");
    assert_eq!(c.change, Change::None, "{c:?}");
    assert!(
        reason(&rep).contains(
            "the selected profile changed while this resource was being handled (it was balanced, it is now powersave)"
        ),
        "{}",
        reason(&rep)
    );
    assert_eq!(calls(&t), ["recommend"]);
    assert_eq!(selection(&rep), "powersave\n");
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

#[test]
fn verify_runs_after_a_successful_change_and_only_then() {
    let r = recipe(
        "tu-v-ok",
        &tuned(&["profile: throughput-performance", "verify: true"]),
    );
    let t = fake(Some("balanced"));
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(calls(&t), ["profile throughput-performance", "verify"]);
    assert!(
        notes(&rep).contains("tuned-adm verify reports the selected profile as applied"),
        "{}",
        notes(&rep)
    );
    // Without the field it is never run.
    let plain = recipe("tu-v-off", &tuned(&["profile: throughput-performance"]));
    let t = fake(Some("balanced"));
    assert_success(&apply(&plain, t.clone()));
    assert_eq!(verify_calls(&t), 0);
}

#[test]
fn a_selection_that_changed_but_does_not_verify_is_a_failure_that_reports_the_change() {
    let r = recipe(
        "tu-v-fail",
        &tuned(&["profile: throughput-performance", "verify: true"]),
    );
    let t = fake(Some("balanced"));
    t.el().lock().unwrap().host.tuned_verify_exit = 1;
    let rep = apply(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let c = find(&rep, "t");
    assert_eq!(
        (c.execution, c.change, c.verification),
        (Execution::Failed, Change::Changed, Verification::Failed),
        "{c:?}"
    );
    assert!(
        reason(&rep).contains("the selection changed, the tuning did not verify"),
        "{}",
        reason(&rep)
    );
    assert_eq!(calls(&t), ["profile throughput-performance", "verify"]);
    assert_eq!(selection(&rep), "throughput-performance\n");
}

#[test]
fn a_verify_without_an_answer_is_a_failure_and_never_applied_or_not_applied() {
    let r = recipe(
        "tu-v-unknown",
        &tuned(&["profile: throughput-performance", "verify: true"]),
    );
    let exit2 = || {
        let t = fake(Some("balanced"));
        t.el().lock().unwrap().host.tuned_verify_exit = 2;
        t
    };
    let scripted = |read: FakeRead| {
        let t = fake(Some("balanced"));
        t.el()
            .lock()
            .unwrap()
            .host
            .tuned_verify_reads
            .push_back(read);
        t
    };
    for (t, want) in [
        (exit2(), "tuned-adm verify exited 2"),
        (scripted(FakeRead::Killed), "signal 9"),
        (scripted(FakeRead::Indeterminate), "did not complete"),
        (scripted(FakeRead::Truncated), "truncated"),
    ] {
        let rep = apply(&r, t);
        assert_eq!(rep.status, AggregateStatus::ApplyFailed, "{want}");
        let c = find(&rep, "t");
        assert_eq!(
            (c.execution, c.change, c.verification),
            (Execution::Failed, Change::Changed, Verification::Unknown),
            "{c:?}"
        );
        assert!(
            reason(&rep).contains(want) && reason(&rep).contains("is not known"),
            "{want}: {}",
            reason(&rep)
        );
    }
    // The same answers in audit are errors, not drift.
    let keep = recipe(
        "tu-v-unknown-audit",
        &tuned(&["profile: balanced", "verify: true"]),
    );
    for t in [exit2(), scripted(FakeRead::Killed)] {
        let a = audit(&keep, t);
        assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
    }
}

// ---------------------------------------------------------------------------
// privilege and platform
// ---------------------------------------------------------------------------

#[test]
fn without_root_plan_notes_it_and_apply_fails_before_the_command() {
    let r = recipe("tu-u-root", &tuned(&["profile: throughput-performance"]));
    let t = || {
        FakeTarget::rocky9()
            .with_fake_fs()
            .with_tuned(Some("balanced"))
    };
    let p = plan(&r, t());
    assert_eq!(p.status, AggregateStatus::Success);
    assert!(notes(&p).contains("needs root"), "{}", notes(&p));
    let (why, _) = refused(&r, Mode::Apply, t());
    assert!(why.contains("tuned needs root"), "{why}");
    let target = t();
    let s = run_recipe_fake(&r, Mode::Apply, true, target.clone());
    assert_success(&s);
    assert_eq!(selection(&s), "throughput-performance\n");
}

#[test]
fn the_tool_decides_support_and_not_the_os_name() {
    let r = recipe("tu-u-os", &tuned(&["profile: throughput-performance"]));
    for t in [
        FakeTarget::ubuntu2404().with_fake_fs().as_root(),
        FakeTarget::rocky10().with_fake_fs().as_root(),
    ] {
        let why = try_run_recipe_fake(&r, Mode::Apply, false, t.clone())
            .map(|rep| reason(&rep))
            .unwrap_or_else(|e| e.message);
        assert!(why.contains("tuned-adm was not found"), "{why}");
        let with = t.with_tuned(Some("balanced"));
        let rep = apply(&r, with.clone());
        assert_success(&rep);
        assert_eq!(calls(&with), ["profile throughput-performance"]);
    }
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_reports_selection_service_and_applied_separately_and_does_not_mutate() {
    let r = recipe("tu-au", &tuned(&["profile: balanced"]));
    let t = fake(Some("balanced"));
    let before = t.fs.clone().unwrap().nodes;
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
    let text = a.resources[0].reason.clone().unwrap();
    assert!(
        text.contains("selected profile matches") && text.contains("verify is not set"),
        "{text}"
    );
    assert!(calls(&t).is_empty(), "{:?}", calls(&t));
    assert_eq!(
        format!("{:?}", t.fs.clone().unwrap().nodes),
        format!("{:?}", before)
    );

    // Another profile is selected.
    let t = fake(Some("powersave"));
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert_eq!(
        dims(&a),
        [(
            "profile".to_string(),
            "powersave".to_string(),
            "balanced".to_string()
        )]
    );
    assert!(calls(&t).is_empty());
    assert!(
        !a.commands
            .iter()
            .any(|c| c.program == TOOL || is_mutation_command(&c.program, &c.args)),
        "{:?}",
        a.commands
    );
    // Nothing is selected, and the service is stopped: two dimensions.
    let a = audit(&r, stopped(fake(None)));
    let d = dims(&a);
    assert_eq!(d.len(), 2, "{d:?}");
    assert_eq!(
        (d[0].0.as_str(), d[0].1.as_str(), d[0].2.as_str()),
        ("profile", "(no profile selected)", "balanced")
    );
    assert_eq!(d[1].0, "service");
}

#[test]
fn audit_with_verify_has_its_own_applied_dimension() {
    let r = recipe(
        "tu-au-verify",
        &tuned(&["profile: balanced", "verify: true"]),
    );
    let t = fake(Some("balanced"));
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
    assert!(a.resources[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("tuned-adm verify reports the profile as applied"));
    assert_eq!(calls(&t), ["verify"]);

    let t = fake(Some("balanced"));
    t.el().lock().unwrap().host.tuned_verify_exit = 1;
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    let d = dims(&a);
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].0, "applied");
    assert!(
        d[0].1.contains("differs from the selected profile"),
        "{d:?}"
    );
    assert_eq!(calls(&t), ["verify"]);
    assert!(change_calls(&t).is_empty());

    // Another selection or a stopped service already is the difference:
    // verify is not asked about a profile that is not the declared one.
    for t in [fake(Some("powersave")), stopped(fake(Some("balanced")))] {
        let a = audit(&r, t.clone());
        assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
        assert!(dims(&a).iter().all(|d| d.0 != "applied"));
        assert_eq!(verify_calls(&t), 0);
    }
}

#[test]
fn audit_of_recommended_and_off() {
    let rec = recipe("tu-au-rec", &tuned(&["recommended: true"]));
    let t = fake(Some("virtual-guest"));
    let a = audit(&rec, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
    assert_eq!(calls(&t), ["recommend"]);
    let a = audit(&rec, fake(Some("balanced")));
    assert_eq!(
        dims(&a),
        [(
            "profile".to_string(),
            "balanced".to_string(),
            "virtual-guest".to_string()
        )]
    );

    let off = recipe("tu-au-off", &tuned(&["state: off"]));
    // Nothing selected is compliant whatever the service does.
    for t in [fake(None), stopped(fake(None)), no_unit(fake(None))] {
        let a = audit(&off, t);
        assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
        assert_eq!(
            a.resources[0].reason.as_deref(),
            Some("no profile is selected")
        );
    }
    let a = audit(&off, fake(Some("balanced")));
    assert_eq!(
        dims(&a),
        [(
            "profile".to_string(),
            "balanced".to_string(),
            "(no profile selected)".to_string()
        )]
    );
}

// ---------------------------------------------------------------------------
// handlers and sensitivity
// ---------------------------------------------------------------------------

#[test]
fn a_change_notifies_a_handler_and_an_unchanged_selection_does_not() {
    let yaml = "version: 1\nresources:\n  - id: t\n    type: tuned\n    notify: [restart-app]\n    with:\n      profile: throughput-performance\nhandlers:\n  - id: restart-app\n    service: myapp\n    action: restart\n";
    let r = recipe("tu-h", yaml);
    let t = |selected: &str| {
        fake(Some(selected)).with_service("myapp", ("loaded", "active", "enabled"))
    };
    let p = plan(&r, t("balanced"));
    assert_eq!(p.handlers_pending, ["restart-app"]);
    let rep = apply(&r, t("balanced"));
    assert_success(&rep);
    assert_eq!(rep.handlers_run.len(), 1);
    let rep = apply(&r, t("throughput-performance"));
    assert_success(&rep);
    assert!(rep.handlers_run.is_empty());
}

#[test]
fn a_sensitive_resource_names_no_profile_in_any_output() {
    let yaml = "version: 1\nresources:\n  - id: t\n    type: tuned\n    sensitive: true\n    with:\n      profile: synthpro7\n      verify: true\n";
    let r = recipe("tu-s", yaml);
    let t = || {
        fake(Some("synthcur3"))
            .with_fs_dir("/etc/tuned/synthpro7")
            .with_fs_file("/etc/tuned/synthpro7/tuned.conf", "[main]\n")
    };
    let leaks = |texts: Vec<String>, what: &str| {
        for s in texts {
            assert!(
                !s.contains("synthpro7") && !s.contains("synthcur3"),
                "{what}: {s}"
            );
        }
    };
    leaks(surfaces(&plan(&r, t()), "plan"), "plan");
    let target = t();
    let a = apply(&r, target.clone());
    assert_success(&a);
    assert_eq!(selection(&a), "synthpro7\n");
    leaks(surfaces(&a, "apply"), "apply");
    // The change command is recorded redacted.
    assert!(
        !a.commands
            .iter()
            .any(|c| c.args.iter().any(|x| x == "synthpro7" || x == "profile")),
        "{:?}",
        a.commands
    );
    for change in [FakeChange::SucceedWithoutChange, FakeChange::Fail] {
        let failing = t();
        failing.el().lock().unwrap().host.tuned_change = change;
        let rep = apply(&r, failing);
        assert_ne!(rep.status, AggregateStatus::Success);
        leaks(surfaces(&rep, "apply"), "failure");
    }
    let unverified = t();
    unverified.el().lock().unwrap().host.tuned_verify_exit = 1;
    leaks(surfaces(&apply(&r, unverified), "apply"), "verify");
    // A refusal (no definition) and the audit are silent too.
    match try_run_recipe_fake(&r, Mode::Plan, false, fake(Some("synthcur3"))) {
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
    let named = "version = 1\n\n[[resources]]\nid = \"profile\"\ntype = \"tuned\"\n\n[resources.with]\nprofile = \"throughput-performance\"\n";
    let recommended = "version = 1\n\n[[resources]]\nid = \"profile\"\ntype = \"tuned\"\n\n[resources.with]\nrecommended = true\n";
    let off = "version = 1\n\n[[resources]]\nid = \"profile\"\ntype = \"tuned\"\n\n[resources.with]\nstate = \"off\"\n";
    let verify = "version = 1\n\n[[resources]]\nid = \"profile\"\ntype = \"tuned\"\n\n[resources.with]\nprofile = \"throughput-performance\"\nverify = true\n";
    for (label, text, want) in [
        ("tu-d-named", named, "throughput-performance\n"),
        ("tu-d-recommended", recommended, "virtual-guest\n"),
        ("tu-d-off", off, ""),
        ("tu-d-verify", verify, "throughput-performance\n"),
    ] {
        let r = write_recipe(&trusted_root(label), "r.toml", text);
        let rep = plan(&r, fake(Some("balanced")));
        assert_eq!(rep.status, AggregateStatus::Success, "{label}");
        assert_eq!(find(&rep, "profile").change, Change::Changed, "{label}");
        let rep = apply(&r, fake(Some("balanced")));
        assert_success(&rep);
        assert_eq!(selection(&rep), want, "{label}");
    }
}

#[test]
fn the_documented_full_order_plans_on_a_host_without_tuned_and_applies_with_it() {
    // package -> service -> file -> tuned, as the reference page shows it.
    let yaml = "version: 1\nresources:\n  - id: tuned-package\n    type: package\n    with:\n      name: tuned\n      state: present\n  - id: tuned-service\n    type: service\n    depends_on: [tuned-package]\n    with:\n      name: tuned.service\n      state: running\n      enabled: true\n  - id: site-db-dir\n    type: directory\n    depends_on: [tuned-package]\n    with:\n      path: /etc/tuned/profiles/site-db\n      parents: true\n  - id: site-db-conf\n    type: file\n    depends_on: [site-db-dir]\n    with:\n      path: /etc/tuned/profiles/site-db/tuned.conf\n      content: \"[main]\\ninclude=throughput-performance\\n\"\n  - id: profile\n    type: tuned\n    depends_on: [tuned-service, site-db-conf]\n    with:\n      profile: site-db\n";
    let r = recipe("tu-d-full", yaml);
    // Nothing of TuneD is on the host: the plan succeeds and defers.
    let bare = FakeTarget::rocky9().with_fake_fs().as_root();
    let p = plan(&r, bare);
    assert_eq!(p.status, AggregateStatus::Success, "{:?}", p.resources);
    assert!(find(&p, "profile").unknown, "{:?}", find(&p, "profile"));
    // With the package installed and the service stopped, apply starts the
    // service, writes the profile and selects it.
    let t = fake(None)
        .with_package("tuned")
        .with_service(UNIT, ("loaded", "inactive", "disabled"));
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(calls(&t), ["profile site-db"]);
    assert_eq!(selection(&rep), "site-db\n");
}
