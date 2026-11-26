//! `systemd_timer` (DESIGN §42) against the scripted in-process target.
//!
//! These run the production loader, engine, resources, audit and output code
//! against [`FakeTarget`], whose systemd manager keeps unit files on disk,
//! the loaded state and the reload as separate facts. They prove Sinter's own
//! decisions and command order. What only a real systemd can show (that
//! `systemd-analyze calendar` changes nothing, how a real timer is enabled
//! through `timers.target`, the real FragmentPath/DropInPaths answers) is
//! PENDING REAL-OS ACCEPTANCE (Tier F) and is not claimed here.
mod common;

use common::*;
use sinter::audit::AuditResourceStatus;
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::result::{Change, Execution, Verification};
use std::path::{Path, PathBuf};

const UNIT_PATH: &str = "/etc/systemd/system/backup.timer";

/// The unit text Sinter writes for `timer()` (DESIGN §42.3).
const RENDERED: &str = "# Managed by Sinter (systemd_timer). Local changes are replaced.\n[Unit]\nDescription=Nightly backup\n\n[Timer]\nOnCalendar=*-*-* 03:00:00\nPersistent=true\nRandomizedDelaySec=10min\n\n[Install]\nWantedBy=timers.target\n";

fn timer(extra: &str) -> String {
    format!(
        "  - id: t\n    type: systemd_timer\n    with:\n      name: backup\n      description: Nightly backup\n      on_calendar: \"*-*-* 03:00:00\"\n      persistent: true\n      randomized_delay_sec: 10min\n{extra}"
    )
}

fn doc(resources: &[String], handlers: &str) -> String {
    let mut s = String::from("version: 1\nresources:\n");
    for r in resources {
        s.push_str(r);
    }
    if !handlers.is_empty() {
        s.push_str("handlers:\n");
        s.push_str(handlers);
    }
    s
}

fn recipe(label: &str, yaml: &str) -> PathBuf {
    let dir = trusted_root(label);
    write_recipe(&dir, "r.yaml", yaml)
}

/// A target with systemd-analyze and the activated `backup.service`.
fn fake() -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_systemd_analyze()
        .with_loaded_unit(
            "backup.service",
            "[Service]\nExecStart=/usr/bin/true\n",
            ("loaded", "inactive", "static"),
        )
}

/// The converged target: the timer's unit file as Sinter writes it, loaded,
/// active and enabled.
fn converged() -> FakeTarget {
    fake().with_loaded_unit("backup.timer", RENDERED, ("loaded", "active", "enabled"))
}

fn apply(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Apply, true, t)
}

fn plan(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Plan, true, t)
}

fn audit(r: &Path, t: FakeTarget) -> sinter::audit::AuditReport {
    let model = sinter::model::load_model(r).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: true,
        target: sinter::engine::TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(t),
    };
    let engine = sinter::engine::Engine::new(model, opts).unwrap();
    sinter::audit::run_audit(engine).unwrap()
}

/// Every systemctl / systemd-analyze invocation, compactly.
fn trace(report: &RunReport) -> Vec<String> {
    report
        .commands
        .iter()
        .filter(|c| c.program.ends_with("systemctl") || c.program.ends_with("systemd-analyze"))
        .map(|c| {
            let a: Vec<&str> = c.args.iter().map(|s| s.as_str()).collect();
            match a.as_slice() {
                ["daemon-reload"] => "daemon-reload".to_string(),
                ["show", "--property=UnitPath"] => "show:UnitPath".to_string(),
                ["show", "--property=FragmentPath,DropInPaths", "--", u] => format!("files:{u}"),
                ["show", _, "--", u] => format!("show:{u}"),
                ["calendar", e] => format!("calendar:{e}"),
                [verb, "--", u] => format!("{verb}:{u}"),
                other => format!("?{other:?}"),
            }
        })
        .collect()
}

fn has(report: &RunReport, entry: &str) -> bool {
    trace(report).iter().any(|t| t == entry)
}

fn forced(code: i32, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn load_err(label: &str, yaml: &str) -> String {
    let p = recipe(label, yaml);
    match sinter::model::load_model(&p) {
        Ok(_) => panic!("{label}: recipe was accepted"),
        Err(e) => e.message,
    }
}

// ---------------------------------------------------------------------------
// schema
// ---------------------------------------------------------------------------

#[test]
fn schema_accepts_each_trigger_alone() {
    for (label, body) in [
        ("tm-s-cal", "      on_calendar: daily\n"),
        ("tm-s-boot", "      on_boot_sec: 5min\n"),
        ("tm-s-active", "      on_unit_active_sec: 1h 30m\n"),
        (
            "tm-s-list",
            "      on_calendar: [daily, \"Sat 12:00\"]\n      accuracy_sec: 1min\n",
        ),
    ] {
        let p = recipe(
            label,
            &doc(
                &[format!(
                    "  - id: t\n    type: systemd_timer\n    with:\n      name: backup\n{body}"
                )],
                "",
            ),
        );
        sinter::model::load_model(&p).unwrap_or_else(|e| panic!("{label}: {}", e.message));
    }
}

#[test]
fn schema_refusals() {
    let head = "  - id: t\n    type: systemd_timer\n    with:\n";
    let cases: &[(&str, &str, &str)] = &[
        (
            "tm-r-notrigger",
            "      name: backup\n",
            "requires at least one of",
        ),
        (
            "tm-r-span",
            "      name: backup\n      on_boot_sec: 5 parsecs\n",
            "on_boot_sec is not a time span",
        ),
        (
            "tm-r-backslash",
            "      name: backup\n      on_calendar: \"daily\\\\\"\n",
            "on_calendar entries",
        ),
        (
            "tm-r-percent",
            "      name: backup\n      on_calendar: \"%H\"\n",
            "on_calendar entries",
        ),
        (
            "tm-r-space",
            "      name: backup\n      on_calendar: \" daily\"\n",
            "on_calendar entries",
        ),
        (
            "tm-r-dash",
            "      name: backup\n      on_calendar: \"-1\"\n",
            "on_calendar entries",
        ),
        (
            "tm-r-desc",
            "      name: backup\n      on_boot_sec: 1m\n      description: \"50%\"\n",
            "description is not",
        ),
        (
            "tm-r-at",
            "      name: \"backup@x\"\n      on_boot_sec: 1m\n",
            "not a valid timer name",
        ),
        (
            "tm-r-suffix",
            "      name: backup.timer\n      on_boot_sec: 1m\n",
            "not a valid timer name",
        ),
        (
            "tm-r-persist",
            "      name: backup\n      on_boot_sec: 1m\n      persistent: true\n",
            "persistent requires on_calendar",
        ),
        (
            "tm-r-absent",
            "      name: backup\n      state: absent\n      enabled: false\n",
            "allows only name",
        ),
        (
            "tm-r-state",
            "      name: backup\n      on_boot_sec: 1m\n      state: started\n",
            "state must be running, stopped or absent",
        ),
        (
            "tm-r-unit",
            "      name: backup\n      on_boot_sec: 1m\n      unit: job.timer\n",
            "unit is not",
        ),
        (
            "tm-r-field",
            "      name: backup\n      on_boot_sec: 1m\n      wanted_by: multi-user.target\n",
            "unknown",
        ),
        (
            "tm-r-enabled",
            "      name: backup\n      on_boot_sec: 1m\n      enabled: yes-please\n",
            "enabled must be a boolean",
        ),
    ];
    for (label, body, want) in cases {
        let msg = load_err(label, &doc(&[format!("{head}{body}")], ""));
        assert!(msg.contains(want), "{label}: {msg}");
    }
}

#[test]
fn name_and_unit_are_static_identifiers() {
    // Variables are known before contact (§4.9): accepted and resolved.
    let y = "version: 1\nvars:\n  n: { value: backup }\nresources:\n  - id: t\n    type: systemd_timer\n    with:\n      name: \"{{ vars.n }}\"\n      on_boot_sec: 1m\n";
    let m = sinter::model::load_model(&recipe("tm-r-var", y)).unwrap();
    let t = m.resources.iter().find(|r| r.id == "t").unwrap();
    assert_eq!(t.path.as_deref(), Some(UNIT_PATH));
    assert_eq!(t.service_name.as_deref(), Some("backup.timer"));
    // Facts and registers are not (identifiers never depend on them, §36).
    for (label, field) in [("tm-r-fact-name", "name"), ("tm-r-fact-unit", "unit")] {
        let body = if field == "name" {
            "      name: \"{{ facts.hostname }}\"\n      on_boot_sec: 1m\n".to_string()
        } else {
            "      name: backup\n      unit: \"{{ facts.hostname }}.service\"\n      on_boot_sec: 1m\n".to_string()
        };
        let msg = load_err(
            label,
            &doc(
                &[format!(
                    "  - id: t\n    type: systemd_timer\n    with:\n{body}"
                )],
                "",
            ),
        );
        assert!(msg.contains(field), "{label}: {msg}");
    }
}

#[test]
fn ownership_conflict_with_a_file_on_the_unit_path() {
    let f = format!(
        "  - id: f\n    type: file\n    with:\n      path: {UNIT_PATH}\n      content: x\n"
    );
    let msg = load_err("tm-r-owner", &doc(&[timer(""), f], ""));
    assert!(msg.contains("conflicting ownership of path"), "{msg}");
    let msg = load_err(
        "tm-r-owner2",
        &doc(&[timer(""), timer("").replace("id: t", "id: u")], ""),
    );
    assert!(msg.contains("conflicting ownership"), "{msg}");
}

// ---------------------------------------------------------------------------
// apply, plan, idempotency
// ---------------------------------------------------------------------------

#[test]
fn apply_creates_reloads_enables_and_starts() {
    let r = recipe(
        "tm-a-create",
        &doc(&[timer("      state: running\n      enabled: true\n")], ""),
    );
    let rep = apply(&r, fake());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    let t = find(&rep, "t");
    assert_eq!(t.type_, "systemd_timer");
    assert_eq!(t.change, Change::Changed);
    assert_eq!(t.verification, Verification::Verified, "{:?}", t);
    let fs = rep.fake_fs.as_ref().unwrap();
    assert_eq!(fs.file_bytes(UNIT_PATH).unwrap(), RENDERED.as_bytes());
    let tr = trace(&rep);
    let at = |e: &str| {
        tr.iter()
            .position(|x| x == e)
            .unwrap_or_else(|| panic!("{e} missing: {tr:?}"))
    };
    assert!(
        at("calendar:*-*-* 03:00:00") < at("daemon-reload"),
        "{tr:?}"
    );
    assert!(at("daemon-reload") < at("enable:backup.timer"), "{tr:?}");
    assert!(
        at("enable:backup.timer") < at("start:backup.timer"),
        "{tr:?}"
    );
    assert_eq!(
        tr.iter().filter(|x| *x == "daemon-reload").count(),
        1,
        "{tr:?}"
    );
    assert!(!has(&rep, "restart:backup.timer"), "{tr:?}");
}

#[test]
fn plan_on_a_fresh_target_shows_the_unit_and_defers_activation() {
    let r = recipe(
        "tm-p-create",
        &doc(&[timer("      state: running\n      enabled: true\n")], ""),
    );
    let rep = plan(&r, fake());
    assert_eq!(mutation_command_count(&rep), 0, "{:?}", trace(&rep));
    let t = find(&rep, "t");
    assert_eq!(t.change, Change::Changed);
    assert!(
        t.unknown,
        "activation is deferred until apply reloads: {t:?}"
    );
    assert!(t.diff.is_some(), "the unit text is shown");
}

#[test]
fn converged_target_is_unchanged_in_plan_apply_and_audit() {
    let r = recipe(
        "tm-a-idem",
        &doc(&[timer("      state: running\n      enabled: true\n")], ""),
    );
    let p = plan(&r, converged());
    assert_eq!(find(&p, "t").change, Change::None, "{:?}", find(&p, "t"));
    assert!(!find(&p, "t").unknown);
    let a = apply(&r, converged());
    let t = find(&a, "t");
    assert_eq!(t.change, Change::None, "{t:?}");
    assert_eq!(t.verification, Verification::Verified);
    assert_eq!(mutation_command_count(&a), 0, "{:?}", trace(&a));
    let u = audit(&r, converged());
    assert_eq!(
        u.resources[0].status,
        AuditResourceStatus::Compliant,
        "{:?}",
        u.resources[0]
    );
}

#[test]
fn content_change_rewrites_and_reloads_without_restarting() {
    let old = RENDERED.replace("03:00:00", "04:00:00");
    let target = || fake().with_loaded_unit("backup.timer", &old, ("loaded", "active", "enabled"));
    let r = recipe(
        "tm-a-content",
        &doc(&[timer("      state: running\n      enabled: true\n")], ""),
    );
    let p = plan(&r, target());
    assert_eq!(find(&p, "t").change, Change::Changed);
    assert_eq!(mutation_command_count(&p), 0);
    let a = apply(&r, target());
    let t = find(&a, "t");
    assert_eq!(t.change, Change::Changed, "{t:?}");
    assert_eq!(t.verification, Verification::Verified, "{t:?}");
    assert_eq!(
        a.fake_fs.as_ref().unwrap().file_bytes(UNIT_PATH).unwrap(),
        RENDERED.as_bytes()
    );
    assert!(has(&a, "daemon-reload"), "{:?}", trace(&a));
    for verb in ["restart", "stop", "start", "enable", "disable"] {
        assert!(
            !has(&a, &format!("{verb}:backup.timer")),
            "{verb}: {:?}",
            trace(&a)
        );
    }
    let u = audit(&r, target());
    assert_eq!(u.resources[0].status, AuditResourceStatus::Drift);
}

#[test]
fn stop_and_disable() {
    let r = recipe(
        "tm-a-stop",
        &doc(&[timer("      state: stopped\n      enabled: false\n")], ""),
    );
    let a = apply(&r, converged());
    let t = find(&a, "t");
    assert_eq!(t.change, Change::Changed);
    assert_eq!(t.verification, Verification::Verified, "{t:?}");
    assert!(
        has(&a, "stop:backup.timer") && has(&a, "disable:backup.timer"),
        "{:?}",
        trace(&a)
    );
    let u = audit(&r, converged());
    assert_eq!(u.resources[0].status, AuditResourceStatus::Drift);
}

#[test]
fn unit_file_only_leaves_activation_alone() {
    let r = recipe("tm-a-fileonly", &doc(&[timer("")], ""));
    let a = apply(&r, fake());
    assert_eq!(find(&a, "t").change, Change::Changed);
    for verb in ["enable", "disable", "start", "stop"] {
        assert!(!has(&a, &format!("{verb}:backup.timer")), "{:?}", trace(&a));
    }
}

#[test]
fn absent_stops_disables_removes_and_reloads() {
    let r = recipe("tm-a-absent", &doc(&["  - id: t\n    type: systemd_timer\n    with:\n      name: backup\n      state: absent\n".to_string()], ""));
    let p = plan(&r, converged());
    assert_eq!(find(&p, "t").change, Change::Changed);
    assert_eq!(mutation_command_count(&p), 0);
    let a = apply(&r, converged());
    let t = find(&a, "t");
    assert_eq!(t.change, Change::Changed, "{t:?}");
    assert_eq!(t.execution, Execution::Succeeded, "{t:?}");
    assert!(a.fake_fs.as_ref().unwrap().file_bytes(UNIT_PATH).is_none());
    let tr = trace(&a);
    let at = |e: &str| {
        tr.iter()
            .position(|x| x == e)
            .unwrap_or_else(|| panic!("{e} missing: {tr:?}"))
    };
    assert!(at("stop:backup.timer") < at("daemon-reload"), "{tr:?}");
    assert!(at("disable:backup.timer") < at("daemon-reload"), "{tr:?}");
    // Already absent: nothing to do.
    let again = apply(&r, fake());
    assert_eq!(
        find(&again, "t").change,
        Change::None,
        "{:?}",
        find(&again, "t")
    );
    assert_eq!(mutation_command_count(&again), 0, "{:?}", trace(&again));
    let u = audit(&r, fake());
    assert_eq!(
        u.resources[0].status,
        AuditResourceStatus::Compliant,
        "{:?}",
        u.resources[0]
    );
    let u = audit(&r, converged());
    assert_eq!(u.resources[0].status, AuditResourceStatus::Drift);
}

// ---------------------------------------------------------------------------
// refusals before any change
// ---------------------------------------------------------------------------

fn assert_refused_without_change(rep: &RunReport, want: &str) {
    let t = find(rep, "t");
    assert_ne!(rep.status, AggregateStatus::Success, "{t:?}");
    assert_eq!(t.change, Change::None, "{t:?}");
    assert_eq!(mutation_command_count(rep), 0, "{:?}", trace(rep));
    assert!(
        !trace(rep).iter().any(|x| x == "daemon-reload"),
        "{:?}",
        trace(rep)
    );
    assert!(
        t.reason.as_deref().unwrap_or("").contains(want),
        "{want}: {:?}",
        t.reason
    );
}

/// Plan stops on a resource it cannot complete safely (§33 exit 4).
fn assert_plan_refused(r: &Path, t: FakeTarget, want: &str) {
    match try_run_recipe_fake(r, Mode::Plan, true, t) {
        Ok(rep) => {
            let res = find(&rep, "t");
            assert!(
                res.reason.as_deref().unwrap_or("").contains(want),
                "{res:?}"
            );
            assert_eq!(mutation_command_count(&rep), 0);
        }
        Err(e) => assert!(e.message.contains(want), "{}", e.message),
    }
}

#[test]
fn masked_timer_is_refused_before_any_change() {
    let r = recipe("tm-x-masked", &doc(&[timer("      state: running\n")], ""));
    let t = || fake().with_service("backup.timer", ("masked", "inactive", "masked"));
    assert_refused_without_change(&apply(&r, t()), "masked");
    let r2 = recipe("tm-x-masked-absent", &doc(&["  - id: t\n    type: systemd_timer\n    with:\n      name: backup\n      state: absent\n".to_string()], ""));
    assert_refused_without_change(&apply(&r2, t()), "masked");
    assert_eq!(
        audit(&r, t()).resources[0].status,
        AuditResourceStatus::Error
    );
}

#[test]
fn unit_elsewhere_is_refused() {
    let r = recipe("tm-x-vendor", &doc(&[timer("      state: running\n")], ""));
    let t = || {
        fake()
            .with_service("backup.timer", ("loaded", "inactive", "disabled"))
            .with_fragment_path("backup.timer", "/usr/lib/systemd/system/backup.timer")
    };
    assert_refused_without_change(&apply(&r, t()), "outside");
    assert_plan_refused(&r, t(), "outside");
    assert_eq!(
        audit(&r, t()).resources[0].status,
        AuditResourceStatus::Error
    );
}

#[test]
fn drop_ins_are_refused() {
    let r = recipe("tm-x-dropin", &doc(&[timer("      state: running\n")], ""));
    let t = || {
        converged().with_dropin_paths(
            "backup.timer",
            "/etc/systemd/system/backup.timer.d/override.conf",
        )
    };
    assert_refused_without_change(&apply(&r, t()), "drop-ins");
    assert_eq!(
        audit(&r, t()).resources[0].status,
        AuditResourceStatus::Error
    );
}

#[test]
fn invalid_calendar_is_refused_in_plan_apply_and_audit() {
    let r = recipe("tm-x-cal", &doc(&[timer("      state: running\n")], ""));
    let t = || fake().with_invalid_calendar("*-*-* 03:00:00");
    assert_refused_without_change(&apply(&r, t()), "not a valid calendar expression");
    assert_plan_refused(&r, t(), "not a valid calendar expression");
    assert_eq!(
        audit(&r, t()).resources[0].status,
        AuditResourceStatus::Error
    );
}

#[test]
fn missing_systemd_analyze_is_refused_not_guessed() {
    let r = recipe(
        "tm-x-noanalyze",
        &doc(&[timer("      state: running\n")], ""),
    );
    let t = FakeTarget::ubuntu2404().with_fake_fs().with_loaded_unit(
        "backup.service",
        "[Service]\nExecStart=/usr/bin/true\n",
        ("loaded", "inactive", "static"),
    );
    assert_refused_without_change(&apply(&r, t), "systemd-analyze is not available");
}

#[test]
fn boot_trigger_needs_no_calendar_check() {
    let r = recipe(
        "tm-a-boot",
        &doc(&["  - id: t\n    type: systemd_timer\n    with:\n      name: backup\n      on_boot_sec: 5min\n      on_unit_active_sec: 1h\n      state: running\n".to_string()], ""),
    );
    let t = FakeTarget::ubuntu2404().with_fake_fs().with_loaded_unit(
        "backup.service",
        "[Service]\nExecStart=/usr/bin/true\n",
        ("loaded", "inactive", "static"),
    );
    let a = apply(&r, t);
    assert_eq!(a.status, AggregateStatus::Success, "{:?}", a.resources);
    assert!(!trace(&a).iter().any(|x| x.starts_with("calendar:")));
    let body =
        String::from_utf8(a.fake_fs.as_ref().unwrap().file_bytes(UNIT_PATH).unwrap()).unwrap();
    assert!(
        body.contains("OnBootSec=5min\nOnUnitActiveSec=1h\n"),
        "{body}"
    );
}

#[test]
fn missing_triggered_unit_writes_nothing_more_and_fails() {
    let r = recipe(
        "tm-x-notrigger",
        &doc(&[timer("      state: running\n      enabled: true\n")], ""),
    );
    let t = || {
        FakeTarget::ubuntu2404()
            .with_fake_fs()
            .with_systemd_analyze()
    };
    let p = plan(&r, t());
    let pt = find(&p, "t");
    assert!(
        pt.unknown
            || pt
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("does not exist"),
        "{pt:?}"
    );
    let a = apply(&r, t());
    let at = find(&a, "t");
    assert_eq!(at.execution, Execution::Failed, "{at:?}");
    assert_eq!(
        at.change,
        Change::Changed,
        "the written unit file is reported: {at:?}"
    );
    assert!(
        at.reason.as_deref().unwrap().contains("does not exist"),
        "{at:?}"
    );
    assert!(
        !has(&a, "enable:backup.timer") && !has(&a, "start:backup.timer"),
        "{:?}",
        trace(&a)
    );
}

#[test]
fn enable_failure_after_the_write_keeps_the_change() {
    let r = recipe(
        "tm-x-enablefail",
        &doc(&[timer("      state: running\n      enabled: true\n")], ""),
    );
    let mut t = fake();
    t.manager.verb_override.insert(
        "enable".to_string(),
        forced(1, "Failed to enable unit: Access denied\n"),
    );
    let a = apply(&r, t);
    let at = find(&a, "t");
    assert_ne!(a.status, AggregateStatus::Success);
    assert_ne!(at.execution, Execution::Succeeded, "{at:?}");
    assert_eq!(at.change, Change::Changed, "{at:?}");
    assert!(!has(&a, "start:backup.timer"), "{:?}", trace(&a));
}

// ---------------------------------------------------------------------------
// handlers, audit commands, service regression
// ---------------------------------------------------------------------------

#[test]
fn notifications_follow_changes_only() {
    let h = "  - id: h\n    service: backup.service\n    action: restart\n";
    let res = format!(
        "{}    notify: [h]\n",
        timer("      state: running\n      enabled: true\n")
    );
    let r = recipe("tm-h", &doc(&[res], h));
    let changed = apply(&r, fake());
    assert_eq!(changed.handlers_run.len(), 1, "{:?}", changed.handlers_run);
    let same = apply(&r, converged());
    assert!(same.handlers_run.is_empty(), "{:?}", same.handlers_run);
}

#[test]
fn audit_dispatches_only_read_only_commands() {
    let r = recipe(
        "tm-u-ro",
        &doc(&[timer("      state: running\n      enabled: true\n")], ""),
    );
    for t in [fake(), converged()] {
        let rep = audit(&r, t);
        for c in &rep.commands {
            assert!(
                !is_mutation_command(&c.program, &c.args),
                "audit dispatched {} {:?}",
                c.program,
                c.args
            );
            if c.program.ends_with("systemctl") {
                assert_eq!(c.args[0], "show", "{:?}", c.args);
            }
            if c.program.ends_with("systemd-analyze") {
                assert_eq!(c.args[0], "calendar", "{:?}", c.args);
                assert_eq!(c.args.len(), 2, "{:?}", c.args);
            }
        }
    }
    let missing = audit(&r, fake());
    assert_eq!(missing.resources[0].status, AuditResourceStatus::Drift);
}

#[test]
fn existing_service_type_manages_a_timer_unit() {
    let r = recipe(
        "tm-svc",
        "version: 1\nresources:\n  - id: s\n    type: service\n    with:\n      name: backup.timer\n      state: running\n      enabled: true\n",
    );
    let t =
        || fake().with_loaded_unit("backup.timer", RENDERED, ("loaded", "inactive", "disabled"));
    let a = apply(&r, t());
    let s = find(&a, "s");
    assert_eq!(s.change, Change::Changed);
    assert_eq!(s.verification, Verification::Verified, "{s:?}");
    assert!(
        has(&a, "enable:backup.timer") && has(&a, "start:backup.timer"),
        "{:?}",
        trace(&a)
    );
    let again = apply(&r, converged());
    assert_eq!(find(&again, "s").change, Change::None);
}

#[test]
fn state_from_a_variable_is_judged_once_evaluated() {
    let y = |st: &str| {
        format!("version: 1\nvars:\n  st: {{ value: {st} }}\nresources:\n  - id: t\n    type: systemd_timer\n    with:\n      name: backup\n      state: \"{{{{ vars.st }}}}\"\n")
    };
    // absent needs no trigger
    let a = apply(&recipe("tm-v-absent", &y("absent")), converged());
    assert_eq!(find(&a, "t").change, Change::Changed, "{:?}", find(&a, "t"));
    assert!(a.fake_fs.as_ref().unwrap().file_bytes(UNIT_PATH).is_none());
    // running without a trigger fails once evaluated, before any change
    let r = recipe("tm-v-running", &y("running"));
    let rep = try_run_recipe_fake(&r, Mode::Apply, true, fake());
    match rep {
        Ok(rep) => {
            let t = find(&rep, "t");
            assert_ne!(t.execution, Execution::Succeeded, "{t:?}");
            assert_eq!(t.change, Change::None);
            assert!(
                t.reason
                    .as_deref()
                    .unwrap_or("")
                    .contains("requires at least one of"),
                "{t:?}"
            );
            assert_eq!(mutation_command_count(&rep), 0);
        }
        Err(e) => assert!(
            e.message.contains("requires at least one of"),
            "{}",
            e.message
        ),
    }
}

#[test]
fn reload_failure_after_the_write_reports_the_change_as_certain() {
    let r = recipe(
        "tm-f-reload",
        &doc(&[timer("      state: running\n      enabled: true\n")], ""),
    );
    let mut t = fake();
    t.manager.reload_completion = Some(Completion::Exited(1));
    let a = apply(&r, t);
    let at = find(&a, "t");
    assert_ne!(a.status, AggregateStatus::Success);
    assert_ne!(at.execution, Execution::Succeeded, "{at:?}");
    assert_eq!(
        at.change,
        Change::Changed,
        "the written unit file is certain: {at:?}"
    );
    assert_eq!(
        a.fake_fs.as_ref().unwrap().file_bytes(UNIT_PATH).unwrap(),
        RENDERED.as_bytes()
    );
    assert!(!has(&a, "enable:backup.timer"), "{:?}", trace(&a));
}

#[test]
fn reload_failure_after_removal_reports_the_change_as_certain() {
    let r = recipe("tm-f-reload-absent", &doc(&["  - id: t\n    type: systemd_timer\n    with:\n      name: backup\n      state: absent\n".to_string()], ""));
    let mut t = converged();
    t.manager.reload_completion = Some(Completion::Exited(1));
    let a = apply(&r, t);
    let at = find(&a, "t");
    assert_ne!(at.execution, Execution::Succeeded, "{at:?}");
    assert_eq!(at.change, Change::Changed, "{at:?}");
    assert!(a.fake_fs.as_ref().unwrap().file_bytes(UNIT_PATH).is_none());
}

#[test]
fn removal_that_leaves_the_unit_loaded_fails_verification() {
    let r = recipe("tm-f-still", &doc(&["  - id: t\n    type: systemd_timer\n    with:\n      name: backup\n      state: absent\n".to_string()], ""));
    let mut t = converged();
    t.manager.present_after_reload.insert(
        "backup.timer".to_string(),
        (
            "loaded".to_string(),
            "inactive".to_string(),
            "disabled".to_string(),
        ),
    );
    let a = apply(&r, t);
    let at = find(&a, "t");
    assert_eq!(at.execution, Execution::Failed, "{at:?}");
    assert_eq!(at.verification, Verification::Failed, "{at:?}");
    assert_eq!(at.change, Change::Changed, "{at:?}");
    assert!(
        at.reason.as_deref().unwrap().contains("still loaded"),
        "{at:?}"
    );
}

#[test]
fn stale_loaded_definition_is_deferred_in_plan_and_drift_in_audit() {
    let r = recipe(
        "tm-f-stale",
        &doc(&[timer("      state: running\n      enabled: true\n")], ""),
    );
    let stale = || {
        let mut t = converged();
        t.manager.disk_changed("backup.timer", true);
        t
    };
    let p = plan(&r, stale());
    let pt = find(&p, "t");
    assert!(pt.unknown, "{pt:?}");
    assert!(
        pt.reason.as_deref().unwrap().contains("NeedDaemonReload"),
        "{pt:?}"
    );
    assert!(
        !trace(&p).iter().any(|x| x.starts_with("files:")),
        "{:?}",
        trace(&p)
    );
    assert_eq!(mutation_command_count(&p), 0);
    let u = audit(&r, stale());
    assert_eq!(
        u.resources[0].status,
        AuditResourceStatus::Drift,
        "{:?}",
        u.resources[0]
    );
    let a = apply(&r, stale());
    let at = find(&a, "t");
    assert_eq!(at.execution, Execution::Succeeded, "{at:?}");
    assert!(
        has(&a, "daemon-reload"),
        "apply synchronizes first: {:?}",
        trace(&a)
    );
}

fn rendered_text(rep: &RunReport) -> String {
    let mut out = Vec::new();
    sinter::output::render_plan(
        rep,
        &sinter::output::RenderOptions {
            verbose: true,
            format: sinter::output::OutputFormat::Text,
            color: false,
        },
        &mut out,
    )
    .unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn a_calendar_from_a_sensitive_variable_is_not_shown_by_plan_when_the_unit_differs() {
    // v1.15.0 behaviour fixed after release: the unit file part did not
    // inherit the sensitivity a variable gives the timer.
    let y = "version: 1\nvars:\n  cal:\n    value: \"*-*-* 04:17:00\"\n    sensitive: true\nresources:\n  - id: t\n    type: systemd_timer\n    with:\n      name: backup\n      description: Nightly backup\n      on_calendar: \"{{ vars.cal }}\"\n";
    let rep = plan(&recipe("timer-sensitive-plan", y), converged());
    let text = rendered_text(&rep);
    assert!(!text.contains("04:17"), "{text}");
    let json = serde_json::to_string(&sinter::output::run_report_json(&rep, "plan")).unwrap();
    assert!(!json.contains("04:17"), "{json}");
}
