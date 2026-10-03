//! systemd manager synchronization (`daemon-reload`) acceptance tests.
//!
//! These run the production engine, resources, audit and output code against
//! a scripted in-process target ([`FakeTarget`]) whose systemd manager keeps
//! the disk state of a unit, the manager's loaded state, `NeedDaemonReload`,
//! the reload operation and its failures as independent facts. They prove
//! Sinter's own decisions and command ordering. What only a real systemd can
//! prove (cached not-found stubs, enable/disable's native reload, load paths,
//! the same-mtime false negative, a reloaded unit's new ExecStart) is
//! `PENDING REAL-OS ACCEPTANCE` and is not claimed here; each such case is
//! named in the matching test's comment.
//!
//! Case numbers (`A01`..`A48`) refer to the acceptance matrix of
//! SINTER_SYSTEMD_DAEMON_RELOAD_FOCUSED_RESEARCH_2026-10-02.md §10.
mod common;

use common::*;
use sinter::audit::AuditResourceStatus;
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::fakesys::NeedOverride;
use sinter::manager::{ManagerReloadPhase, ManagerReloadTrigger};
use sinter::result::{Change, Execution, HandlerOutcomeState, Verification};
use std::path::{Path, PathBuf};

const UNIT: &str = "/etc/systemd/system/foo.service";

fn fake() -> FakeTarget {
    FakeTarget::ubuntu2404().with_fake_fs()
}

/// A target that already has `foo.service` on disk, loaded, running, enabled.
fn fake_with_foo(content: &str) -> FakeTarget {
    fake().with_loaded_unit("foo.service", content, ("loaded", "active", "enabled"))
}

fn recipe(label: &str, yaml: &str) -> PathBuf {
    let dir = trusted_root(label);
    write_recipe(&dir, "r.yaml", yaml)
}

fn apply(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Apply, true, t)
}

fn plan(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Plan, true, t)
}

/// Compact trace of every systemctl invocation, in order.
fn trace(report: &RunReport) -> Vec<String> {
    report
        .commands
        .iter()
        .filter(|c| c.program.ends_with("systemctl"))
        .map(|c| {
            let a: Vec<&str> = c.args.iter().map(|s| s.as_str()).collect();
            match a.as_slice() {
                ["daemon-reload"] => "daemon-reload".to_string(),
                ["show", "--property=UnitPath"] => "show:UnitPath".to_string(),
                ["show", _, "--", unit] => format!("show:{}", unit),
                [verb, "--", unit] => format!("{}:{}", verb, unit),
                other => format!("?{:?}", other),
            }
        })
        .collect()
}

fn count(report: &RunReport, entry: &str) -> usize {
    trace(report).iter().filter(|t| t.as_str() == entry).count()
}

fn reloads(report: &RunReport) -> usize {
    count(report, "daemon-reload")
}

fn pos(report: &RunReport, entry: &str) -> usize {
    trace(report)
        .iter()
        .position(|t| t == entry)
        .unwrap_or_else(|| panic!("{} not in trace {:?}", entry, trace(report)))
}

fn rpos(report: &RunReport, entry: &str) -> usize {
    trace(report)
        .iter()
        .rposition(|t| t == entry)
        .unwrap_or_else(|| panic!("{} not in trace {:?}", entry, trace(report)))
}

fn unit_file(id: &str, path: &str, content: &str) -> String {
    format!(
        "  - id: {id}\n    type: file\n    with:\n      path: {path}\n      content: \"{content}\"\n"
    )
}

fn service(id: &str, unit: &str, state: &str, enabled: Option<bool>, deps: &[&str]) -> String {
    let mut s = format!(
        "  - id: {id}\n    type: service\n    with:\n      name: {unit}\n      state: {state}\n"
    );
    if let Some(e) = enabled {
        s.push_str(&format!("      enabled: {e}\n"));
    }
    if !deps.is_empty() {
        s.push_str(&format!("    depends_on: [{}]\n", deps.join(", ")));
    }
    s
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

fn handler(id: &str, unit: &str, action: &str) -> String {
    format!("  - id: {id}\n    service: {unit}\n    action: {action}\n")
}

fn notify(res: String, h: &[&str]) -> String {
    format!("{}    notify: [{}]\n", res, h.join(", "))
}

fn assert_no_manager_mutation_commands(report: &RunReport) {
    for c in &report.commands {
        if c.program.ends_with("systemctl") {
            let verb = c.args.first().map(|s| s.as_str()).unwrap_or("");
            assert_eq!(verb, "show", "plan/audit dispatched systemctl {:?}", c.args);
        }
    }
}

// ---------------------------------------------------------------------------
// A01 / A31: nothing changed -> zero reloads (second apply)
// ---------------------------------------------------------------------------

#[test]
fn a01_a31_unchanged_service_and_second_apply_reload_zero() {
    let y = doc(
        &[
            unit_file("u", UNIT, "A"),
            service("s", "foo.service", "running", Some(true), &["u"]),
        ],
        "",
    );
    let r = recipe("dr-a01", &y);
    let rep = apply(&r, fake_with_foo("A"));
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(reloads(&rep), 0);
    assert_eq!(mutation_command_count(&rep), 0);
    assert_eq!(find(&rep, "u").change, Change::None);
    assert_eq!(find(&rep, "s").change, Change::None);
    assert!(rep.manager_reloads.is_empty());
    // plan agrees and stays read-only
    let p = plan(&r, fake_with_foo("A"));
    assert_eq!(find(&p, "s").change, Change::None);
    assert!(!find(&p, "s").unknown);
    assert_eq!(reloads(&p), 0);
    assert!(p.manager_reloads.is_empty());
}

// ---------------------------------------------------------------------------
// A02: changed unit bytes, service state already matches
// ---------------------------------------------------------------------------

#[test]
fn a02_changed_unit_reloads_then_observes_fresh_without_restart() {
    let y = doc(
        &[
            unit_file("u", UNIT, "B"),
            service("s", "foo.service", "running", Some(true), &["u"]),
        ],
        "",
    );
    let r = recipe("dr-a02", &y);
    let rep = apply(&r, fake_with_foo("A"));
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(find(&rep, "u").change, Change::Changed);
    // service unchanged: no start/restart/enable, and exactly one reload.
    assert_eq!(find(&rep, "s").change, Change::None);
    assert_eq!(reloads(&rep), 1);
    // reload happens before the service's first observation.
    assert!(pos(&rep, "daemon-reload") < pos(&rep, "show:foo.service"));
    for t in trace(&rep) {
        assert!(
            !t.starts_with("start:") && !t.starts_with("restart:") && !t.starts_with("stop:"),
            "{}",
            t
        );
    }
    let m = &rep.manager_reloads;
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].phase, ManagerReloadPhase::Resource);
    assert_eq!(m[0].trigger, ManagerReloadTrigger::PendingInput);
    assert_eq!(m[0].causes, vec!["u".to_string()]);
    assert_eq!(m[0].consumer.as_deref(), Some("s"));
    assert_eq!(m[0].execution, Execution::Succeeded);
    assert_eq!(m[0].change, Change::Changed);
    assert_eq!(m[0].verification, Verification::Verified);
    // the final end-of-run check found nothing left to reload
    assert_eq!(reloads(&rep), 1);
}

// ---------------------------------------------------------------------------
// A03: changed drop-in
// ---------------------------------------------------------------------------

#[test]
fn a03_changed_dropin_reloads_before_service_decision() {
    let y = doc(
        &[
            unit_file(
                "d",
                "/etc/systemd/system/foo.service.d/override.conf",
                "[Service]\\nNice=5\\n",
            ),
            service("s", "foo.service", "running", None, &["d"]),
        ],
        "",
    );
    let r = recipe("dr-a03", &y);
    let t = fake_with_foo("A").with_fs_dir("/etc/systemd/system/foo.service.d");
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(find(&rep, "d").change, Change::Changed);
    assert_eq!(reloads(&rep), 1);
    assert!(pos(&rep, "daemon-reload") < rpos(&rep, "show:foo.service"));
    assert_eq!(rep.manager_reloads[0].causes, vec!["d".to_string()]);
}

// ---------------------------------------------------------------------------
// A04 / A05: new unit (cached not-found / never loaded)
// ---------------------------------------------------------------------------

#[test]
fn a04_new_unit_with_cached_not_found_is_discovered_by_reload() {
    let y = doc(
        &[
            unit_file("u", "/etc/systemd/system/new.service", "N"),
            service("s", "new.service", "running", Some(true), &["u"]),
        ],
        "",
    );
    let r = recipe("dr-a04", &y);
    let mut t = fake();
    t.manager.cached_not_found.insert("new.service".to_string());
    // plan: no false missing-unit failure, service is UNKNOWN, no mutation
    let p = plan(&r, t.clone());
    assert!(find(&p, "s").unknown, "{:?}", find(&p, "s"));
    assert_eq!(p.status, AggregateStatus::Success);
    assert_eq!(mutation_command_count(&p), 0);
    assert_eq!(reloads(&p), 0);
    assert_eq!(p.manager_reloads.len(), 1);
    assert_eq!(p.manager_reloads[0].phase, ManagerReloadPhase::Planned);
    assert!(p.manager_reloads[0].unknown);
    assert_eq!(p.manager_reloads[0].execution, Execution::NotRun);
    // apply: file publish -> reload -> show (found) -> enable -> start
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(reloads(&rep), 1);
    assert!(pos(&rep, "daemon-reload") < pos(&rep, "show:new.service"));
    assert!(pos(&rep, "daemon-reload") < pos(&rep, "enable:new.service"));
    assert!(pos(&rep, "enable:new.service") < pos(&rep, "start:new.service"));
    assert_eq!(find(&rep, "s").change, Change::Changed);
    assert_eq!(find(&rep, "s").verification, Verification::Verified);
    // PENDING REAL-OS ACCEPTANCE: that a real manager's stale not-found stub
    // is cleared by this reload.
}

#[test]
fn a05_new_never_loaded_unit_is_started_after_reload() {
    let y = doc(
        &[
            unit_file("u", "/etc/systemd/system/new.service", "N"),
            service("s", "new.service", "running", None, &["u"]),
        ],
        "",
    );
    let r = recipe("dr-a05", &y);
    let rep = apply(&r, fake());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(reloads(&rep), 1);
    assert!(pos(&rep, "daemon-reload") < pos(&rep, "start:new.service"));
}

// ---------------------------------------------------------------------------
// A06 / A07: removed unit
// ---------------------------------------------------------------------------

#[test]
fn a06_removed_loaded_unit_is_not_reported_stopped() {
    let y = doc(
        &[
            "  - id: u\n    type: file\n    with:\n      path: /etc/systemd/system/foo.service\n      state: absent\n".to_string(),
            service("s", "foo.service", "running", None, &["u"]),
        ],
        "",
    );
    let r = recipe("dr-a06", &y);
    let rep = apply(&r, fake_with_foo("A"));
    assert_eq!(find(&rep, "u").change, Change::Changed);
    // fresh state after the reload says the unit is gone: failure, never a
    // fabricated "stopped" or "unchanged".
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let s = find(&rep, "s");
    assert_eq!(s.execution, Execution::Failed);
    assert!(
        s.reason.as_deref().unwrap().contains("not found"),
        "{:?}",
        s.reason
    );
    for t in trace(&rep) {
        assert!(!t.starts_with("stop:") && !t.starts_with("start:"), "{}", t);
    }
    // PENDING REAL-OS ACCEPTANCE: exact LoadState/ActiveState of a removed
    // but still-active unit per systemd version.
}

#[test]
fn a07_stop_and_disable_then_remove_succeeds_with_final_flush() {
    let y = doc(
        &[
            service("s", "foo.service", "stopped", Some(false), &[]),
            "  - id: u\n    type: file\n    with:\n      path: /etc/systemd/system/foo.service\n      state: absent\n    depends_on: [s]\n".to_string(),
        ],
        "",
    );
    let r = recipe("dr-a07", &y);
    let rep = apply(&r, fake_with_foo("A"));
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?} {:?}",
        rep.resources,
        rep.manager_reloads
    );
    assert_eq!(find(&rep, "s").change, Change::Changed);
    assert_eq!(find(&rep, "u").change, Change::Changed);
    // one explicit reload, at the end of the run
    assert_eq!(reloads(&rep), 1);
    assert_eq!(rep.manager_reloads[0].phase, ManagerReloadPhase::Final);
    assert!(pos(&rep, "stop:foo.service") < pos(&rep, "daemon-reload"));
}

// ---------------------------------------------------------------------------
// A09 - A12: package -> service
// ---------------------------------------------------------------------------

fn package_service_recipe(unit: &str) -> String {
    doc(
        &[
            "  - id: pkg\n    type: package\n    with:\n      name: nano\n      state: present\n"
                .to_string(),
            service("s", unit, "running", None, &["pkg"]),
        ],
        "",
    )
}

#[test]
fn a09_package_unit_already_loaded_needs_no_extra_reload() {
    let r = recipe("dr-a09", &package_service_recipe("nano.service"));
    let t =
        FakeTarget::ubuntu2404().with_service("nano.service", ("loaded", "inactive", "disabled"));
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(find(&rep, "pkg").change, Change::Changed);
    assert_eq!(
        reloads(&rep),
        0,
        "a changed package alone never causes a reload"
    );
}

#[test]
fn a10_changed_package_with_cached_missing_unit_gets_one_discovery_reload() {
    let r = recipe("dr-a10", &package_service_recipe("nano.service"));
    let mut t = FakeTarget::ubuntu2404();
    t.manager.disk.insert("nano.service".to_string(), 1);
    t.manager
        .cached_not_found
        .insert("nano.service".to_string());
    // plan: existing direct-package defer, no mutation
    let p = plan(&r, t.clone());
    assert!(find(&p, "s").unknown);
    assert_eq!(mutation_command_count(&p), 0);
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(reloads(&rep), 1);
    let m = &rep.manager_reloads;
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].trigger, ManagerReloadTrigger::PackageDiscovery);
    assert_eq!(m[0].causes, vec!["pkg".to_string()]);
    assert_eq!(m[0].verification, Verification::Verified);
    assert!(pos(&rep, "daemon-reload") < pos(&rep, "start:nano.service"));
}

#[test]
fn a11_wrong_unit_name_after_package_fails_without_a_retry_loop() {
    let r = recipe("dr-a11", &package_service_recipe("nosuch.service"));
    let rep = apply(&r, FakeTarget::ubuntu2404());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(reloads(&rep), 1, "exactly one bounded discovery reload");
    assert_eq!(rep.manager_reloads[0].verification, Verification::Failed);
    assert_eq!(find(&rep, "s").execution, Execution::Failed);
    for t in trace(&rep) {
        assert!(
            !t.starts_with("start:") && !t.starts_with("enable:"),
            "{}",
            t
        );
    }
}

#[test]
fn a12_changed_package_and_stale_loaded_unit_reloads_before_the_decision() {
    let r = recipe("dr-a12", &package_service_recipe("nano.service"));
    let mut t =
        FakeTarget::ubuntu2404().with_service("nano.service", ("loaded", "inactive", "disabled"));
    t.manager.disk_changed("nano.service", true); // disk newer than loaded
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(reloads(&rep), 1);
    assert_eq!(
        rep.manager_reloads[0].trigger,
        ManagerReloadTrigger::ObservedStale
    );
    assert!(pos(&rep, "daemon-reload") < pos(&rep, "start:nano.service"));
}

// ---------------------------------------------------------------------------
// A13 - A17: stale unit + start / stop / enable / disable
// ---------------------------------------------------------------------------

fn stale_foo(active: &str, enabled: &str) -> FakeTarget {
    let mut t = fake().with_loaded_unit("foo.service", "A", ("loaded", active, enabled));
    t.manager.disk_changed("foo.service", true);
    t
}

#[test]
fn a13_start_only_with_stale_unit_reloads_then_starts() {
    let r = recipe(
        "dr-a13",
        &doc(&[service("s", "foo.service", "running", None, &[])], ""),
    );
    let rep = apply(&r, stale_foo("inactive", "disabled"));
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(reloads(&rep), 1);
    assert!(pos(&rep, "daemon-reload") < pos(&rep, "start:foo.service"));
    // plan observes only: UNKNOWN, no reload
    let p = plan(&r, stale_foo("inactive", "disabled"));
    assert!(find(&p, "s").unknown);
    assert_eq!(reloads(&p), 0);
    assert_no_manager_mutation_commands(&p);
    assert_eq!(
        p.manager_reloads[0].trigger,
        ManagerReloadTrigger::ObservedStale
    );
}

#[test]
fn a14_stop_only_with_stale_unit_reloads_then_stops() {
    let r = recipe(
        "dr-a14",
        &doc(&[service("s", "foo.service", "stopped", None, &[])], ""),
    );
    let rep = apply(&r, stale_foo("active", "enabled"));
    assert_eq!(rep.status, AggregateStatus::Success);
    assert!(pos(&rep, "daemon-reload") < pos(&rep, "stop:foo.service"));
    assert!(pos(&rep, "stop:foo.service") < pos(&rep, "reset-failed:foo.service"));
}

#[test]
fn a15_a16_enable_and_disable_only_do_not_add_an_explicit_reload() {
    // Native enable/disable perform their own implicit reload; with no
    // pending input and Need=no Sinter adds none and does not suppress it.
    for (want, from, verb) in [(true, "disabled", "enable"), (false, "enabled", "disable")] {
        let r = recipe(
            "dr-a15",
            &doc(
                &[service("s", "foo.service", "running", Some(want), &[])],
                "",
            ),
        );
        let t = fake().with_loaded_unit("foo.service", "A", ("loaded", "active", from));
        let rep = apply(&r, t);
        assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
        assert_eq!(reloads(&rep), 0);
        assert_eq!(count(&rep, &format!("{}:foo.service", verb)), 1);
        // verified from a fresh show taken after the native reload
        assert!(rpos(&rep, "show:foo.service") > pos(&rep, &format!("{}:foo.service", verb)));
    }
}

#[test]
fn a17_enable_then_start_decides_from_a_fresh_observation() {
    let r = recipe(
        "dr-a17",
        &doc(
            &[service("s", "foo.service", "running", Some(true), &[])],
            "",
        ),
    );
    // Without a socket-style activation: enable, fresh show, start.
    let t = fake().with_loaded_unit("foo.service", "A", ("loaded", "inactive", "disabled"));
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Success);
    let tr = trace(&rep);
    let e = pos(&rep, "enable:foo.service");
    let s = pos(&rep, "start:foo.service");
    assert!(
        tr[e + 1..s].iter().any(|t| t == "show:foo.service"),
        "{:?}",
        tr
    );
    // When the native enable already activated the unit the stale
    // "needs start" decision is NOT acted on.
    let mut t = fake().with_loaded_unit("foo.service", "A", ("loaded", "inactive", "disabled"));
    t.manager.enable_starts.insert("foo.service".to_string());
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(count(&rep, "start:foo.service"), 0, "{:?}", trace(&rep));
    assert_eq!(find(&rep, "s").verification, Verification::Verified);
}

// ---------------------------------------------------------------------------
// A18 / A19 / A20 / A23: handlers
// ---------------------------------------------------------------------------

#[test]
fn a18_changed_unit_notify_restart_reloads_manager_first() {
    let y = doc(
        &[notify(unit_file("u", UNIT, "B"), &["restart_foo"])],
        &handler("restart_foo", "foo.service", "restart"),
    );
    let r = recipe("dr-a18", &y);
    let rep = apply(&r, fake_with_foo("A"));
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.handlers_run
    );
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Succeeded);
    assert_eq!(reloads(&rep), 1);
    let (rl, sh, rs) = (
        pos(&rep, "daemon-reload"),
        rpos(&rep, "show:foo.service"),
        pos(&rep, "restart:foo.service"),
    );
    assert!(
        rl < rs && rl < pos(&rep, "show:foo.service"),
        "{:?}",
        trace(&rep)
    );
    assert!(sh > rs, "verification after the restart: {:?}", trace(&rep));
    assert_eq!(rep.manager_reloads[0].phase, ManagerReloadPhase::Handler);
    assert_eq!(
        rep.manager_reloads[0].consumer.as_deref(),
        Some("restart_foo")
    );
}

#[test]
fn a19_changed_unit_notify_reload_keeps_manager_and_application_reload_separate() {
    let y = doc(
        &[notify(unit_file("u", UNIT, "B"), &["reload_foo"])],
        &handler("reload_foo", "foo.service", "reload"),
    );
    let r = recipe("dr-a19", &y);
    let rep = apply(&r, fake_with_foo("A"));
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(reloads(&rep), 1);
    assert_eq!(count(&rep, "reload:foo.service"), 1);
    assert!(pos(&rep, "daemon-reload") < pos(&rep, "reload:foo.service"));
    assert_ne!("daemon-reload", "reload:foo.service");
}

#[test]
fn a20_ordinary_application_config_restart_has_zero_manager_reloads() {
    let y = doc(
        &[notify(
            unit_file("c", "/etc/app/app.conf", "x=1"),
            &["restart_foo"],
        )],
        &handler("restart_foo", "foo.service", "restart"),
    );
    let r = recipe("dr-a20", &y);
    let rep = apply(&r, fake_with_foo("A"));
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Succeeded);
    assert_eq!(reloads(&rep), 0);
    // an application config never even asks the manager for its UnitPath
    assert_eq!(count(&rep, "show:UnitPath"), 0);
    assert!(rep.manager_reloads.is_empty());
}

#[test]
fn a23_one_covered_generation_is_not_reloaded_again_for_each_handler() {
    let u = notify(unit_file("u", UNIT, "B"), &["h1", "h2"]);
    let y = doc(
        &[u],
        &format!(
            "{}{}",
            handler("h1", "foo.service", "restart"),
            handler("h2", "bar.service", "restart")
        ),
    );
    let r = recipe("dr-a23", &y);
    let t = fake_with_foo("A").with_service("bar.service", ("loaded", "active", "enabled"));
    let rep = apply(&r, t);
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.handlers_run
    );
    assert_eq!(rep.handlers_run.len(), 2);
    assert_eq!(reloads(&rep), 1);
}

// ---------------------------------------------------------------------------
// A21 / A22: batching vs consumer boundaries
// ---------------------------------------------------------------------------

#[test]
fn a21_many_unit_writes_before_services_share_one_reload() {
    let y = doc(
        &[
            unit_file("ua", "/etc/systemd/system/a.service", "A"),
            unit_file("ub", "/etc/systemd/system/b.service", "B"),
            service("sa", "a.service", "running", None, &["ua"]),
            service("sb", "b.service", "running", None, &["ub"]),
        ],
        "",
    );
    let r = recipe("dr-a21", &y);
    let rep = apply(&r, fake());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(reloads(&rep), 1);
    assert_eq!(
        rep.manager_reloads[0].causes,
        vec!["ua".to_string(), "ub".to_string()]
    );
}

#[test]
fn a22_unit_service_unit_service_needs_a_reload_per_consumer_boundary() {
    let y = doc(
        &[
            unit_file("ua", "/etc/systemd/system/a.service", "A"),
            service("sa", "a.service", "running", None, &["ua"]),
            unit_file("ub", "/etc/systemd/system/b.service", "B")
                .replace("    with:", "    depends_on: [sa]\n    with:"),
            service("sb", "b.service", "running", None, &["ub"]),
        ],
        "",
    );
    let r = recipe("dr-a22", &y);
    let rep = apply(&r, fake());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(
        reloads(&rep),
        2,
        "once-per-run would be wrong: {:?}",
        trace(&rep)
    );
    assert!(pos(&rep, "daemon-reload") < pos(&rep, "start:a.service"));
    assert!(pos(&rep, "start:a.service") < rpos(&rep, "daemon-reload"));
    assert!(rpos(&rep, "daemon-reload") < pos(&rep, "start:b.service"));
}

// ---------------------------------------------------------------------------
// A24 / A47: file-only recipes
// ---------------------------------------------------------------------------

#[test]
fn a24_file_only_unit_update_is_flushed_before_a_normal_finish() {
    let y = doc(&[unit_file("u", UNIT, "B")], "");
    let r = recipe("dr-a24", &y);
    let rep = apply(&r, fake_with_foo("A"));
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.manager_reloads
    );
    assert_eq!(reloads(&rep), 1);
    let m = &rep.manager_reloads[0];
    assert_eq!(m.phase, ManagerReloadPhase::Final);
    assert_eq!(m.causes, vec!["u".to_string()]);
    assert_eq!(m.verification, Verification::Verified);
    // the state after that apply: nothing to do (second apply)
    let again = apply(&r, fake_with_foo("B"));
    assert_eq!(reloads(&again), 0);
    assert!(again.manager_reloads.is_empty());
}

#[test]
fn a24_file_only_final_flush_failure_fails_the_overall_apply() {
    let y = doc(&[unit_file("u", UNIT, "B")], "");
    let r = recipe("dr-a24f", &y);
    let mut t = fake_with_foo("A");
    t.manager.reload_completion = Some(Completion::Exited(1));
    t.manager.reload_stderr = "Failed to reload daemon: boom\n".into();
    let rep = apply(&r, t);
    // the resource itself succeeded and stays CHANGED; the failure is the
    // manager operation's, never hidden and never a fake service.
    assert_eq!(find(&rep, "u").change, Change::Changed);
    assert_eq!(find(&rep, "u").execution, Execution::Succeeded);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(rep.manager_reloads[0].execution, Execution::Failed);
    assert_eq!(rep.manager_reloads[0].change, Change::Possible);
    assert_eq!(reloads(&rep), 1);
}

#[test]
fn a47_stale_manager_after_a_previous_failed_apply_is_reloaded_when_bytes_already_match() {
    // The file already matches the recipe (a previous apply stopped before the
    // reload) but the manager still reports the unit stale.
    let y = doc(&[unit_file("u", UNIT, "B")], "");
    let r = recipe("dr-a47", &y);
    let mut t = fake_with_foo("B");
    t.manager.disk_changed("foo.service", true); // loaded copy is behind
    let rep = apply(&r, t);
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.manager_reloads
    );
    assert_eq!(find(&rep, "u").change, Change::None);
    assert_eq!(reloads(&rep), 1);
    assert_eq!(
        rep.manager_reloads[0].trigger,
        ManagerReloadTrigger::ObservedStale
    );
    assert_eq!(rep.manager_reloads[0].phase, ManagerReloadPhase::Final);
    // an unobservable Need is a failure, never "no"
    let mut t = fake_with_foo("B");
    t.manager.disk_changed("foo.service", true);
    t.manager
        .need_override
        .insert("foo.service".into(), NeedOverride::Missing);
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(reloads(&rep), 0);
    assert_eq!(rep.manager_reloads[0].verification, Verification::Failed);
}

// ---------------------------------------------------------------------------
// A25 / A26 / A45: reload failures and uncertainty
// ---------------------------------------------------------------------------

fn unit_service_recipe() -> PathBuf {
    let y = doc(
        &[
            unit_file("u", UNIT, "B"),
            service("s", "foo.service", "running", Some(true), &["u"]),
        ],
        "",
    );
    recipe("dr-fail", &y)
}

#[test]
fn a25_a45_reload_nonzero_stops_dependents_keeps_changes_and_never_retries() {
    for stderr in [
        "Failed to reload daemon: Access denied\n",
        "Failed: reload rate limit hit\n",
    ] {
        let mut t = fake_with_foo("A");
        t.manager.reload_completion = Some(Completion::Exited(1));
        t.manager.reload_stderr = stderr.into();
        let rep = apply(&unit_service_recipe(), t);
        assert_eq!(rep.status, AggregateStatus::ApplyFailed);
        // earlier successful CHANGED is kept
        assert_eq!(find(&rep, "u").change, Change::Changed);
        assert_eq!(find(&rep, "u").execution, Execution::Succeeded);
        // the dependent service did nothing
        assert_eq!(find(&rep, "s").execution, Execution::Failed);
        assert_eq!(find(&rep, "s").change, Change::None);
        for t in trace(&rep) {
            assert!(
                !t.starts_with("start:") && !t.starts_with("enable:") && !t.starts_with("restart:"),
                "{}",
                t
            );
        }
        assert_eq!(reloads(&rep), 1, "no retry loop");
        let m = &rep.manager_reloads[0];
        assert_eq!(m.execution, Execution::Failed);
        assert_eq!(m.change, Change::Possible, "no claim that nothing changed");
        assert!(m.reason.as_deref().unwrap().contains("exit code 1"));
        // no privilege switching: every command ran with the run's own sudo flag
        assert!(rep.commands.iter().all(|c| c.sudo));
    }
}

#[test]
fn a26_reload_timeout_or_signal_is_indeterminate_not_success_or_unchanged() {
    for c in [
        Completion::Indeterminate {
            started: true,
            reason: "timed out".into(),
        },
        Completion::Signaled(9),
    ] {
        let mut t = fake_with_foo("A");
        t.manager.reload_completion = Some(c);
        let rep = apply(&unit_service_recipe(), t);
        assert_eq!(rep.status, AggregateStatus::Indeterminate);
        let m = &rep.manager_reloads[0];
        assert_eq!(m.execution, Execution::Indeterminate);
        assert_eq!(m.change, Change::Possible);
        assert_eq!(m.verification, Verification::Unknown);
        assert_eq!(reloads(&rep), 1);
        assert_eq!(find(&rep, "u").change, Change::Changed);
    }
    // the handler path too: no handler action, no retry
    let y = doc(
        &[notify(unit_file("u", UNIT, "B"), &["h"])],
        &handler("h", "foo.service", "restart"),
    );
    let r = recipe("dr-a26h", &y);
    let mut t = fake_with_foo("A");
    t.manager.reload_completion = Some(Completion::Indeterminate {
        started: true,
        reason: "timed out".into(),
    });
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Indeterminate);
    assert_eq!(
        rep.handlers_run[0].state,
        HandlerOutcomeState::Indeterminate
    );
    assert_eq!(count(&rep, "restart:foo.service"), 0);
    assert_eq!(reloads(&rep), 1);
}

#[test]
fn a25_handler_does_not_run_after_a_failed_reload() {
    let y = doc(
        &[notify(unit_file("u", UNIT, "B"), &["h"])],
        &handler("h", "foo.service", "restart"),
    );
    let r = recipe("dr-a25h", &y);
    let mut t = fake_with_foo("A");
    t.manager.reload_completion = Some(Completion::Exited(1));
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Failed);
    assert_eq!(count(&rep, "restart:foo.service"), 0);
    assert_eq!(reloads(&rep), 1);
}

// ---------------------------------------------------------------------------
// A27 / A28 / A29 / A30: observation strictness
// ---------------------------------------------------------------------------

#[test]
fn a27_need_daemon_reload_that_cannot_be_read_never_becomes_no() {
    let r = recipe(
        "dr-a27",
        &doc(&[service("s", "foo.service", "running", None, &[])], ""),
    );
    for ov in [
        NeedOverride::Missing,
        NeedOverride::Duplicate,
        NeedOverride::Value("maybe".into()),
        NeedOverride::Value("".into()),
        NeedOverride::Value("YES".into()),
    ] {
        let mut t = fake().with_loaded_unit("foo.service", "A", ("loaded", "inactive", "disabled"));
        t.manager
            .need_override
            .insert("foo.service".into(), ov.clone());
        let rep = apply(&r, t);
        assert_eq!(rep.status, AggregateStatus::ApplyFailed, "{:?}", ov);
        assert_eq!(mutation_command_count(&rep), 0, "{:?}", ov);
        assert_eq!(find(&rep, "s").execution, Execution::Failed);
    }
    // non-zero exit, truncated output and malformed bytes
    let bad = [
        Output { completion: Completion::Exited(1), stdout: Vec::new(), stderr: b"nope\n".to_vec(), stdout_truncated: false, stderr_truncated: false },
        Output { completion: Completion::Exited(0), stdout: b"LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\nNeedDaemonReload=no\n".to_vec(), stderr: Vec::new(), stdout_truncated: true, stderr_truncated: false },
        Output { completion: Completion::Exited(0), stdout: vec![0xff, 0xfe, b'\n'], stderr: Vec::new(), stdout_truncated: false, stderr_truncated: false },
        Output { completion: Completion::Exited(0), stdout: b"LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n".to_vec(), stderr: Vec::new(), stdout_truncated: false, stderr_truncated: false },
    ];
    for out in bad {
        let t = fake()
            .with_loaded_unit("foo.service", "A", ("loaded", "inactive", "disabled"))
            .with_observations("systemctl", vec![out]);
        let rep = apply(&r, t);
        assert_eq!(rep.status, AggregateStatus::ApplyFailed);
        assert_eq!(mutation_command_count(&rep), 0);
    }
    // the same for plan: an error, not UNKNOWN-and-hope
    let mut t = fake().with_loaded_unit("foo.service", "A", ("loaded", "inactive", "disabled"));
    t.manager
        .need_override
        .insert("foo.service".into(), NeedOverride::Value("maybe".into()));
    let err = try_run_recipe_fake(&r, Mode::Plan, true, t);
    assert!(err.is_err());
}

#[test]
fn a28_unit_path_that_cannot_be_read_stops_before_any_mutation() {
    let y = doc(&[unit_file("u", UNIT, "B")], "");
    let r = recipe("dr-a28", &y);
    let bad_outputs = [
        "UnitPath=\"/etc/systemd/system\n",
        "UnitPath=\n",
        "garbage\n",
        "UnitPath=relative/path\n",
        "UnitPath=/etc/x\\q\n",
    ];
    for text in bad_outputs {
        let mut t = fake_with_foo("A");
        t.manager.unit_path_output = Some(Output {
            completion: Completion::Exited(0),
            stdout: text.as_bytes().to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        });
        let rep = apply(&r, t);
        assert_eq!(rep.status, AggregateStatus::ApplyFailed, "{}", text);
        assert_eq!(
            find(&rep, "u").change,
            Change::None,
            "no mutation on a guess: {}",
            text
        );
        assert_eq!(mutation_command_count(&rep), 0);
        let mut t = fake_with_foo("A");
        t.manager.unit_path_output = Some(Output {
            completion: Completion::Exited(0),
            stdout: text.as_bytes().to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        });
        assert!(
            try_run_recipe_fake(&r, Mode::Plan, true, t).is_err(),
            "plan: {}",
            text
        );
    }
    // non-zero exit
    let mut t = fake_with_foo("A");
    t.manager.unit_path_output = Some(Output {
        completion: Completion::Exited(1),
        stdout: Vec::new(),
        stderr: b"System has not been booted with systemd\n".to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    });
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(find(&rep, "u").change, Change::None);
}

#[test]
fn a29_reload_succeeds_but_the_fresh_show_fails() {
    let mut t = fake_with_foo("A");
    t.manager.show_fail_after_reload = 1;
    let rep = apply(&unit_service_recipe(), t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let m = &rep.manager_reloads[0];
    assert_eq!(m.execution, Execution::Succeeded);
    assert_eq!(m.change, Change::Changed, "the reload fact is preserved");
    assert_eq!(m.verification, Verification::Failed);
    assert_eq!(find(&rep, "s").execution, Execution::Failed);
    for t in trace(&rep) {
        assert!(
            !t.starts_with("start:") && !t.starts_with("enable:"),
            "{}",
            t
        );
    }
    assert_eq!(reloads(&rep), 1);
}

#[test]
fn a30_the_decision_uses_the_observation_taken_after_the_reload() {
    // Before the reload the unit looks inactive+disabled (would need enable
    // and start); the reloaded definition is active+enabled.
    let r = recipe(
        "dr-a30",
        &doc(
            &[service("s", "foo.service", "running", Some(true), &[])],
            "",
        ),
    );
    let mut t = stale_foo("inactive", "disabled");
    t.manager.after_reload.insert(
        "foo.service".into(),
        ("loaded".into(), "active".into(), "enabled".into()),
    );
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(find(&rep, "s").change, Change::None);
    assert_eq!(count(&rep, "enable:foo.service"), 0);
    assert_eq!(count(&rep, "start:foo.service"), 0);
    assert_eq!(reloads(&rep), 1);
}

// ---------------------------------------------------------------------------
// A32 / A33 / A37 / A44: what does NOT create manager pending state
// ---------------------------------------------------------------------------

#[test]
fn a32_metadata_only_and_unrelated_changes_do_not_reload() {
    // chmod-only on a unit file
    let y = "version: 1\nresources:\n  - id: u\n    type: file\n    with:\n      path: /etc/systemd/system/foo.service\n      content: \"A\"\n      mode: \"0600\"\n";
    let r = recipe("dr-a32", y);
    let rep = apply(&r, fake_with_foo("A"));
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(
        find(&rep, "u").change,
        Change::Changed,
        "the chmod happened"
    );
    assert_eq!(reloads(&rep), 0);
    // an unrelated directory
    let y = "version: 1\nresources:\n  - id: d\n    type: directory\n    with:\n      path: /etc/app/newdir\n";
    let rep = apply(&recipe("dr-a32d", y), fake());
    assert_eq!(reloads(&rep), 0);
}

#[test]
fn a33_same_mtime_change_by_sinter_is_still_reloaded_but_external_edit_is_not_seen() {
    // Sinter wrote the bytes, so the producer record reloads even though
    // NeedDaemonReload cannot see a same-mtime change.
    let y = doc(&[unit_file("u", UNIT, "B")], "");
    let r = recipe("dr-a33", &y);
    let mut t = fake_with_foo("A");
    t.manager.need_blind.insert("foo.service".into());
    t.fs.as_mut().unwrap().freeze_mtime = true;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(reloads(&rep), 1);
    assert_eq!(
        rep.manager_reloads[0].trigger,
        ManagerReloadTrigger::PendingInput
    );
    // KNOWN LIMIT (documented): an external same-mtime edit that Sinter did
    // not make leaves NeedDaemonReload=no, so nothing is reloaded.
    let mut t = fake_with_foo("B");
    t.manager.need_blind.insert("foo.service".into());
    t.manager.disk_changed("foo.service", true);
    let rep = apply(&r, t);
    assert_eq!(reloads(&rep), 0);
    // PENDING REAL-OS ACCEPTANCE: a real manager's mtime comparison.
}

#[test]
fn a37_unrelated_systemd_files_are_not_manager_input() {
    for path in [
        "/etc/systemd/journald.conf",
        "/etc/systemd/user.conf",
        "/etc/systemd/network/10-eth.network",
        "/etc/systemd/logind.conf",
    ] {
        let dir = path.rsplit_once('/').unwrap().0;
        let y = doc(&[unit_file("f", path, "x")], "");
        let r = recipe("dr-a37", &y);
        let rep = apply(&r, fake().with_fs_dir(dir));
        assert_eq!(
            rep.status,
            AggregateStatus::Success,
            "{} {:?}",
            path,
            rep.resources
        );
        assert_eq!(reloads(&rep), 0, "{}", path);
        assert_eq!(count(&rep, "show:UnitPath"), 0, "{}", path);
        assert!(rep.manager_reloads.is_empty());
    }
}

#[test]
fn a44_user_manager_paths_and_options_are_never_touched() {
    for path in [
        "/etc/systemd/user/foo.service",
        "/etc/systemd/user/foo.service.d/o.conf",
        "/usr/lib/systemd/user/foo.service",
    ] {
        let dir = path.rsplit_once('/').unwrap().0;
        let y = doc(&[unit_file("f", path, "x")], "");
        let r = recipe("dr-a44", &y);
        let t = fake()
            .with_fs_dir("/etc/systemd/user")
            .with_fs_dir("/usr/lib/systemd/user")
            .with_fs_dir(dir);
        let rep = apply(&r, t);
        assert_eq!(
            rep.status,
            AggregateStatus::Success,
            "{} {:?}",
            path,
            rep.resources
        );
        assert_eq!(reloads(&rep), 0, "{}", path);
    }
    // no command anywhere carries --user
    let rep = apply(&unit_service_recipe(), fake_with_foo("A"));
    assert!(rep
        .commands
        .iter()
        .all(|c| !c.args.iter().any(|a| a == "--user")));
}

// ---------------------------------------------------------------------------
// A34 / A35 / A36: links, template/type-wide/prefix drop-ins, manager config
// ---------------------------------------------------------------------------

#[test]
fn a34_alias_mask_and_wants_links_are_manager_input() {
    let link = |id: &str, path: &str, target: &str| {
        format!(
            "  - id: {id}\n    type: link\n    with:\n      path: {path}\n      target: {target}\n"
        )
    };
    // wants link, alias, and mask (a link to /dev/null) each create pending
    // manager input and are reloaded once.
    for (label, path, target) in [
        (
            "wants",
            "/etc/systemd/system/multi-user.target.wants/foo.service",
            "/etc/systemd/system/foo.service",
        ),
        (
            "alias",
            "/etc/systemd/system/alias.service",
            "/etc/systemd/system/foo.service",
        ),
        ("mask", "/etc/systemd/system/masked.service", "/dev/null"),
    ] {
        let y = doc(&[link("l", path, target)], "");
        let rep = apply(
            &recipe(&format!("dr-a34-{}", label), &y),
            fake_with_foo("A"),
        );
        assert_eq!(
            rep.status,
            AggregateStatus::Success,
            "{} {:?}",
            label,
            rep.resources
        );
        assert_eq!(find(&rep, "l").change, Change::Changed, "{}", label);
        assert_eq!(reloads(&rep), 1, "{}", label);
        assert_eq!(rep.manager_reloads[0].causes, vec!["l".to_string()]);
        // plan: projected, not executed
        let p = plan(
            &recipe(&format!("dr-a34p-{}", label), &y),
            fake_with_foo("A"),
        );
        assert_eq!(reloads(&p), 0, "{}", label);
        assert_eq!(p.manager_reloads.len(), 1);
    }
    // removal of a link is a change too; an unchanged link reloads nothing
    let y = doc(
        &[link(
            "l",
            "/etc/systemd/system/alias.service",
            "/etc/systemd/system/foo.service",
        )],
        "",
    );
    let mut t = fake_with_foo("A");
    t.fs.as_mut().unwrap().nodes.insert(
        "/etc/systemd/system/alias.service".into(),
        sinter::fakesys::FakeNode {
            kind: sinter::fakesys::FakeKind::Symlink("/etc/systemd/system/foo.service".into()),
            mode: 0o777,
            uid: 0,
            gid: 0,
            ino: 9000,
            mtime: 5,
            ctime: 5,
        },
    );
    let rep = apply(&recipe("dr-a34-same", &y), t);
    assert_eq!(find(&rep, "l").change, Change::None);
    assert_eq!(reloads(&rep), 0);
    let y = "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: /etc/systemd/system/alias.service\n      state: absent\n";
    let mut t = fake_with_foo("A");
    t.fs.as_mut().unwrap().nodes.insert(
        "/etc/systemd/system/alias.service".into(),
        sinter::fakesys::FakeNode {
            kind: sinter::fakesys::FakeKind::Symlink("/etc/systemd/system/foo.service".into()),
            mode: 0o777,
            uid: 0,
            gid: 0,
            ino: 9001,
            mtime: 5,
            ctime: 5,
        },
    );
    let rep = apply(&recipe("dr-a34-rm", y), t);
    assert_eq!(find(&rep, "l").change, Change::Changed);
    assert_eq!(reloads(&rep), 1);
    // PENDING REAL-OS ACCEPTANCE: masked-unit constraints against a real manager.
}

#[test]
fn a35_template_type_wide_and_prefix_dropins_are_recognized_without_a_unit_name() {
    for (path, dir) in [
        ("/etc/systemd/system/foo@.service", "/etc/systemd/system"),
        (
            "/etc/systemd/system/service.d/10-all.conf",
            "/etc/systemd/system/service.d",
        ),
        (
            "/etc/systemd/system/foo-.service.d/10-p.conf",
            "/etc/systemd/system/foo-.service.d",
        ),
    ] {
        let y = doc(&[unit_file("f", path, "[Service]\\nNice=1\\n")], "");
        let r = recipe("dr-a35", &y);
        let rep = apply(&r, fake().with_fs_dir(dir));
        assert_eq!(
            rep.status,
            AggregateStatus::Success,
            "{} {:?}",
            path,
            rep.resources
        );
        assert_eq!(reloads(&rep), 1, "{}", path);
        assert_eq!(rep.manager_reloads[0].phase, ManagerReloadPhase::Final);
    }
}

#[test]
fn a36_system_conf_and_dropins_reload_but_user_conf_does_not() {
    for (path, expect) in [
        ("/etc/systemd/system.conf.d/10-x.conf", 1usize),
        ("/etc/systemd/system.conf", 1),
        ("/etc/systemd/user.conf", 0),
    ] {
        let y = doc(
            &[unit_file(
                "f",
                path,
                "[Manager]\\nDefaultTimeoutStartSec=30s\\n",
            )],
            "",
        );
        let r = recipe("dr-a36", &y);
        let rep = apply(&r, fake());
        assert_eq!(
            rep.status,
            AggregateStatus::Success,
            "{} {:?}",
            path,
            rep.resources
        );
        assert_eq!(reloads(&rep), expect, "{}", path);
        // manager config roots come from a finite table, not from UnitPath
        assert_eq!(count(&rep, "show:UnitPath"), 0, "{}", path);
    }
    // PENDING REAL-OS ACCEPTANCE: the live effect of a chosen directive.
}

// ---------------------------------------------------------------------------
// A38: stop semantics
// ---------------------------------------------------------------------------

#[test]
fn a38_an_earlier_failure_runs_no_handler_and_no_final_reload() {
    let y = doc(
        &[notify(unit_file("u", UNIT, "B"), &["h"])],
        &handler("h", "foo.service", "restart"),
    );
    let r = recipe("dr-a38", &y);
    let rep = run_recipe_fake_fault(&r, Mode::Apply, true, fake_with_foo("A"), "reobserve_fail");
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(
        find(&rep, "u").change,
        Change::Changed,
        "the published change is kept"
    );
    assert_eq!(reloads(&rep), 0);
    assert!(rep.handlers_run.is_empty());
    // the left-behind input is reported, not silently dropped
    let m = &rep.manager_reloads[0];
    assert_eq!(m.execution, Execution::NotRun);
    assert!(
        m.reason.as_deref().unwrap().contains("not run"),
        "{:?}",
        m.reason
    );
}

// ---------------------------------------------------------------------------
// A39: pending unit + native enable
// ---------------------------------------------------------------------------

#[test]
fn a39_explicit_gate_and_native_enable_reload_are_separate() {
    let y = doc(
        &[
            unit_file("u", "/etc/systemd/system/new.service", "N"),
            service("s", "new.service", "running", Some(true), &["u"]),
        ],
        "",
    );
    let rep = apply(&recipe("dr-a39", &y), fake());
    assert_eq!(rep.status, AggregateStatus::Success);
    // exactly one explicit reload; the native enable reload is the target's
    assert_eq!(reloads(&rep), 1);
    assert_eq!(count(&rep, "enable:new.service"), 1);
    let tr = trace(&rep);
    let e = pos(&rep, "enable:new.service");
    assert!(
        tr[e..].iter().any(|t| t == "show:new.service"),
        "fresh obs after native reload"
    );
}

// ---------------------------------------------------------------------------
// A40 / A41: plan and audit are mutation-free
// ---------------------------------------------------------------------------

#[test]
fn a40_plan_is_mutation_free_and_defers_instead_of_inventing_state() {
    let y = doc(
        &[
            notify(unit_file("u", UNIT, "B"), &["h"]),
            service("s", "foo.service", "running", Some(true), &["u"]),
        ],
        &handler("h", "foo.service", "restart"),
    );
    let r = recipe("dr-a40", &y);
    let p = plan(&r, fake_with_foo("A"));
    assert_eq!(p.status, AggregateStatus::Success);
    assert_eq!(mutation_command_count(&p), 0);
    assert_no_manager_mutation_commands(&p);
    assert_eq!(reloads(&p), 0);
    assert!(find(&p, "s").unknown);
    assert!(find(&p, "s")
        .reason
        .as_deref()
        .unwrap()
        .contains("deferred"));
    assert!(p.handlers_run.is_empty());
    assert_eq!(p.handlers_pending, vec!["h".to_string()]);
    // the manager operation is a separate, UNKNOWN, not-run entry
    assert_eq!(p.manager_reloads.len(), 1);
    assert_eq!(p.manager_reloads[0].execution, Execution::NotRun);
    assert!(p.manager_reloads[0].unknown);
    // JSON and text both carry it
    let json = sinter::output::run_report_json(&p, "plan");
    assert_eq!(json["manager_reloads"][0]["phase"], "planned");
    assert_eq!(json["manager_reloads"][0]["execution"], "not_run");
    assert_eq!(json["manager_reloads"][0]["unknown"], true);
    let mut text = Vec::new();
    sinter::output::render_plan(
        &p,
        &sinter::output::RenderOptions {
            verbose: false,
            format: sinter::output::OutputFormat::Text,
            color: false,
        },
        &mut text,
    )
    .unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("manager reloads"), "{}", text);
}

fn audit_run(r: &Path, t: FakeTarget) -> sinter::audit::AuditReport {
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

fn assert_audit_commands_read_only(rep: &sinter::audit::AuditReport) {
    for c in &rep.commands {
        let prog = c.program.rsplit('/').next().unwrap();
        assert!(
            !["chmod", "chown", "mkdir", "rmdir", "rm", "mv", "ln", "mktemp", "dd"].contains(&prog),
            "audit dispatched {} {:?}",
            c.program,
            c.args
        );
        if prog == "systemctl" {
            let a: Vec<&str> = c.args.iter().map(|s| s.as_str()).collect();
            assert!(
                matches!(a.as_slice(), ["show", "--property=UnitPath"])
                    || matches!(a.as_slice(), ["show", p, "--", _] if *p == "--property=LoadState,ActiveState,UnitFileState,NeedDaemonReload"),
                "audit dispatched systemctl {:?}",
                c.args
            );
        }
    }
}

#[test]
fn a41_audit_reports_manager_reload_as_its_own_facet_and_never_reloads() {
    // Active and enabled match, the bytes match, but the loaded definition is
    // stale: independent drift, never "repaired", never no_drift.
    let y = doc(
        &[
            unit_file("u", UNIT, "A"),
            service("s", "foo.service", "running", Some(true), &["u"]),
        ],
        "",
    );
    let r = recipe("dr-a41", &y);
    let mut t = fake_with_foo("A");
    t.manager.disk_changed("foo.service", true);
    let rep = audit_run(&r, t);
    assert_audit_commands_read_only(&rep);
    let s = rep.resources.iter().find(|x| x.id == "s").unwrap();
    assert_eq!(s.status, AuditResourceStatus::Drift);
    assert_eq!(s.details.len(), 1);
    assert_eq!(s.details[0].dimension, "manager_reload");
    // file facet is separate: bytes are fine, but the file-only supplement
    // also sees the stale unit it manages
    let u = rep.resources.iter().find(|x| x.id == "u").unwrap();
    assert_eq!(u.status, AuditResourceStatus::Drift);
    assert!(u.details.iter().all(|d| d.dimension == "manager_reload"));
    assert_eq!(rep.aggregate_label(), "drift");
    assert_eq!(reloads_in(&rep.commands), 0);
    // synchronized: clean
    let rep = audit_run(&r, fake_with_foo("A"));
    assert_audit_commands_read_only(&rep);
    assert_eq!(rep.aggregate_label(), "no_drift");
    // an unobservable Need is an observation error, never no_drift
    let mut t = fake_with_foo("A");
    t.manager
        .need_override
        .insert("foo.service".into(), NeedOverride::Value("maybe".into()));
    let rep = audit_run(&r, t);
    assert_eq!(rep.aggregate_label(), "indeterminate");
    // a unit it cannot map to one unit is stated as unverified, not implied
    let y = doc(
        &[unit_file(
            "f",
            "/etc/systemd/system/service.d/10-all.conf",
            "x",
        )],
        "",
    );
    let r = recipe("dr-a41b", &y);
    let rep = audit_run(
        &r,
        fake()
            .with_fs_dir("/etc/systemd/system/service.d")
            .with_fs_file("/etc/systemd/system/service.d/10-all.conf", "x"),
    );
    let f = rep.resources.iter().find(|x| x.id == "f").unwrap();
    assert_eq!(f.status, AuditResourceStatus::Compliant);
    assert!(
        f.reason.as_deref().unwrap().contains("not verified"),
        "{:?}",
        f.reason
    );
    assert_audit_commands_read_only(&rep);
}

fn reloads_in(cmds: &[sinter::executor::CommandRecord]) -> usize {
    cmds.iter()
        .filter(|c| c.program.ends_with("systemctl") && c.args == ["daemon-reload"])
        .count()
}

// ---------------------------------------------------------------------------
// A42: sensitive data
// ---------------------------------------------------------------------------

#[test]
fn a42_secret_unit_content_and_names_never_reach_any_report_surface() {
    // The canary is the unit CONTENT and, for the failing run, the reload
    // stderr. Paths of managed files are ordinary observation operands in the
    // raw command log (an existing contract), so the canary stays out of them.
    let secret = "SINTER_DR_SECRET_CANARY_8841";
    let y = format!(
        "version: 1\nresources:\n  - id: u\n    type: file\n    sensitive: true\n    with:\n      path: /etc/systemd/system/foo.service\n      content: \"Environment={c}\"\n  - id: s\n    type: service\n    sensitive: true\n    depends_on: [u]\n    with:\n      name: foo.service\n      state: running\n    notify: [h]\nhandlers:\n  - id: h\n    service: foo.service\n    action: restart\n",
        c = secret
    );
    let r = recipe("dr-a42", &y);
    let t = fake_with_foo("old");
    let check = |rep: &RunReport| {
        let json = sinter::output::run_report_json(rep, "apply").to_string();
        let mut text = Vec::new();
        sinter::output::render_apply(
            rep,
            &sinter::output::RenderOptions {
                verbose: true,
                format: sinter::output::OutputFormat::Text,
                color: false,
            },
            &mut text,
        )
        .unwrap();
        let text = String::from_utf8(text).unwrap();
        for hay in [&json, &text, &format!("{:?}", rep.manager_reloads)] {
            assert!(!hay.contains(secret), "secret leaked: {}", hay);
            assert!(!hay.contains("foo.service"), "unit name leaked: {}", hay);
        }
        for c in &rep.commands {
            let all = format!("{} {:?} {:?}", c.program, c.args, c.env);
            assert!(!all.contains(secret), "{}", all);
            if c.sensitive {
                assert!(!all.contains("foo.service"), "{}", all);
            }
        }
    };
    let rep = apply(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert!(reloads(&rep) >= 1);
    assert!(rep.manager_reloads.iter().all(|m| m.sensitive));
    check(&rep);
    // failure reasons are redacted as well
    let mut tf = t.clone();
    tf.manager.reload_completion = Some(Completion::Exited(1));
    tf.manager.reload_stderr = format!("unit foo.service exploded {}\n", secret);
    let rep = apply(&r, tf);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    check(&rep);
    // plan
    let p = plan(&r, t);
    let json = sinter::output::run_report_json(&p, "plan").to_string();
    assert!(!json.contains(secret));
    assert!(!json.contains("foo.service"));
}

// ---------------------------------------------------------------------------
// A43: UnitPath-derived roots
// ---------------------------------------------------------------------------

#[test]
fn a43_roots_come_from_the_manager_not_from_a_fixed_directory() {
    let custom = Output {
        completion: Completion::Exited(0),
        stdout: b"UnitPath=/opt/units/system /usr/lib/systemd/system\n".to_vec(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    };
    // inside the manager's custom root: input
    let y = doc(&[unit_file("u", "/opt/units/system/foo.service", "A")], "");
    let mut t = fake();
    t.manager.unit_path_output = Some(custom.clone());
    let rep = apply(&recipe("dr-a43a", &y), t);
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(reloads(&rep), 1);
    // /etc/systemd/system is NOT in this manager's path: no guessing
    let y = doc(&[unit_file("u", UNIT, "A")], "");
    let mut t = fake();
    t.manager.unit_path_output = Some(custom);
    let rep = apply(&recipe("dr-a43b", &y), t);
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(reloads(&rep), 0);
    // PENDING REAL-OS ACCEPTANCE: usr-merge aliases (/lib vs /usr/lib),
    // shadowing across roots, vendor backports.
}

// ---------------------------------------------------------------------------
// output contract
// ---------------------------------------------------------------------------

#[test]
fn manager_reloads_json_is_additive_and_shaped() {
    let y = doc(
        &[
            unit_file("u", UNIT, "B"),
            service("s", "foo.service", "running", Some(true), &["u"]),
        ],
        "",
    );
    let rep = apply(&recipe("dr-json", &y), fake_with_foo("A"));
    let json = sinter::output::run_report_json(&rep, "apply");
    // existing keys are all still present and unchanged in shape
    for k in [
        "mode",
        "status",
        "facts",
        "resources",
        "handlers",
        "handlers_pending",
    ] {
        assert!(json.get(k).is_some(), "{}", k);
    }
    let m = &json["manager_reloads"][0];
    for k in [
        "phase",
        "trigger",
        "causes",
        "consumer",
        "execution",
        "change",
        "verification",
        "unknown",
        "sensitive",
        "reason",
    ] {
        assert!(m.get(k).is_some(), "manager_reloads[0].{}", k);
    }
    assert_eq!(m["phase"], "resource");
    assert_eq!(m["trigger"], "pending_input");
    assert_eq!(m["execution"], "succeeded");
    assert_eq!(m["change"], "changed");
    assert_eq!(m["verification"], "verified");
    // closed enums of existing result vocabulary are not extended
    let s = &json["resources"][1];
    assert!(["not_run", "succeeded", "failed", "indeterminate"]
        .contains(&s["execution"].as_str().unwrap()));
    // a recipe without manager input has an empty (still present) array
    let rep = apply(
        &recipe(
            "dr-json2",
            &doc(&[service("s", "foo.service", "running", None, &[])], ""),
        ),
        fake_with_foo("A"),
    );
    assert_eq!(
        sinter::output::run_report_json(&rep, "apply")["manager_reloads"],
        serde_json::json!([])
    );
}

// ---------------------------------------------------------------------------
// further failure-boundary cases
// ---------------------------------------------------------------------------

#[test]
fn a29_final_flush_reload_succeeds_but_verification_show_fails() {
    let y = doc(&[unit_file("u", UNIT, "B")], "");
    let r = recipe("dr-a29f", &y);
    let mut t = fake_with_foo("A");
    t.manager.show_fail_after_reload = 1;
    let rep = apply(&r, t);
    assert_eq!(find(&rep, "u").change, Change::Changed);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let m = &rep.manager_reloads[0];
    assert_eq!(m.phase, ManagerReloadPhase::Final);
    assert_eq!(m.execution, Execution::Succeeded);
    assert_eq!(m.change, Change::Changed);
    assert_eq!(m.verification, Verification::Failed);
    assert_eq!(reloads(&rep), 1);
}

#[test]
fn a29_handler_reload_succeeds_but_fresh_show_fails_so_no_restart() {
    let y = doc(
        &[notify(unit_file("u", UNIT, "B"), &["h"])],
        &handler("h", "foo.service", "restart"),
    );
    let r = recipe("dr-a29h", &y);
    let mut t = fake_with_foo("A");
    t.manager.show_fail_after_reload = 1;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Failed);
    assert_eq!(count(&rep, "restart:foo.service"), 0);
    assert_eq!(rep.manager_reloads[0].execution, Execution::Succeeded);
    assert_eq!(rep.manager_reloads[0].verification, Verification::Failed);
}

#[test]
fn a28_audit_with_an_unusable_unit_path_is_an_error_not_a_pass() {
    let y = doc(&[unit_file("u", UNIT, "A")], "");
    let r = recipe("dr-a28a", &y);
    let mut t = fake_with_foo("A");
    t.manager.unit_path_output = Some(Output {
        completion: Completion::Exited(0),
        stdout: b"UnitPath=\"/etc\n".to_vec(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    });
    let rep = audit_run(&r, t);
    assert_eq!(rep.aggregate_label(), "indeterminate");
    assert_audit_commands_read_only(&rep);
}

#[test]
fn plan_marks_stale_unit_unknown_and_lists_the_manager_operation_separately() {
    let y = doc(
        &[service("s", "foo.service", "running", Some(true), &[])],
        "",
    );
    let r = recipe("dr-plan-need", &y);
    let p = plan(&r, stale_foo("active", "enabled"));
    assert!(find(&p, "s").unknown);
    assert_eq!(reloads(&p), 0);
    assert_eq!(mutation_command_count(&p), 0);
    assert_eq!(p.manager_reloads.len(), 1);
    assert_eq!(
        p.manager_reloads[0].trigger,
        ManagerReloadTrigger::ObservedStale
    );
    assert_eq!(p.manager_reloads[0].consumer.as_deref(), Some("s"));
    // a synchronized unit is still decided normally in plan
    let p = plan(&r, fake_with_foo("A"));
    assert!(!find(&p, "s").unknown);
    assert!(p.manager_reloads.is_empty());
}

#[test]
fn removing_a_link_or_unit_in_plan_is_projected_but_never_executed() {
    let y = "version: 1\nresources:\n  - id: u\n    type: file\n    with:\n      path: /etc/systemd/system/foo.service\n      state: absent\n";
    let p = plan(&recipe("dr-plan-rm", y), fake_with_foo("A"));
    assert_eq!(find(&p, "u").change, Change::Changed);
    assert_eq!(p.manager_reloads.len(), 1);
    assert_eq!(mutation_command_count(&p), 0);
    assert_eq!(reloads(&p), 0);
}

#[test]
fn a17_all_state_and_enabled_combinations_end_verified_from_fresh_observations() {
    // running/stopped x enabled true/false, from every initial combination.
    for want_state in ["running", "stopped"] {
        for want_enabled in [true, false] {
            for active in ["active", "inactive"] {
                for enabled in ["enabled", "disabled"] {
                    let r = recipe(
                        "dr-a17m",
                        &doc(
                            &[service(
                                "s",
                                "foo.service",
                                want_state,
                                Some(want_enabled),
                                &[],
                            )],
                            "",
                        ),
                    );
                    let t =
                        fake().with_loaded_unit("foo.service", "A", ("loaded", active, enabled));
                    let rep = apply(&r, t);
                    let ctx = format!("{want_state}/{want_enabled} from {active}/{enabled}");
                    assert_eq!(rep.status, AggregateStatus::Success, "{}", ctx);
                    assert_eq!(reloads(&rep), 0, "{}", ctx);
                    let s = find(&rep, "s");
                    let already = (want_state == "running") == (active == "active")
                        && (want_enabled == (enabled == "enabled"));
                    assert_eq!(s.change == Change::None, already, "{}", ctx);
                    if !already {
                        assert_eq!(s.verification, Verification::Verified, "{}", ctx);
                    }
                    // an observation always follows every native enable/disable
                    // before anything else decides
                    let tr = trace(&rep);
                    for (i, entry) in tr.iter().enumerate() {
                        if entry.starts_with("enable:") || entry.starts_with("disable:") {
                            assert!(
                                tr[i + 1..].iter().any(|t| t == "show:foo.service"),
                                "{}: {:?}",
                                ctx,
                                tr
                            );
                        }
                    }
                }
            }
        }
    }
}

// ===========================================================================
// Focused remediation of the independent re-audit (F01 - F04)
//
// SINTER_SYSTEMD_DAEMON_RELOAD_INDEPENDENT_REAUDIT_2026-10-02.md. Each group
// drives the control flow that was wrong, not an expected string, and asserts
// exact command counts where a forbidden command is the point.
// ===========================================================================

fn link_res(id: &str, path: &str, target: &str) -> String {
    format!("  - id: {id}\n    type: link\n    with:\n      path: {path}\n      target: {target}\n")
}

fn link_absent(id: &str, path: &str) -> String {
    format!("  - id: {id}\n    type: link\n    with:\n      path: {path}\n      state: absent\n")
}

fn with_symlink(mut t: FakeTarget, path: &str, target: &str, ino: u64) -> FakeTarget {
    t.fs.as_mut().unwrap().nodes.insert(
        path.into(),
        sinter::fakesys::FakeNode {
            kind: sinter::fakesys::FakeKind::Symlink(target.into()),
            mode: 0o777,
            uid: 0,
            gid: 0,
            ino,
            mtime: 5,
            ctime: 5,
        },
    );
    t
}

const SERVICE_MUTATING_VERBS: [&str; 7] = [
    "start:",
    "stop:",
    "enable:",
    "disable:",
    "restart:",
    "reload:",
    "reset-failed:",
];

fn assert_no_service_mutation(report: &RunReport) {
    for t in trace(report) {
        for verb in SERVICE_MUTATING_VERBS {
            assert!(
                !t.starts_with(verb),
                "forbidden service command dispatched: {} in {:?}",
                t,
                trace(report)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// F01: manager configuration reached through a symlink
// ---------------------------------------------------------------------------

#[test]
fn f01_manager_config_symlink_create_replace_remove_and_mask_schedule_a_reload() {
    const DIR: &str = "/etc/systemd/system.conf.d";
    const CONF: &str = "/etc/systemd/system.conf.d/10-vendor.conf";
    // (label, yaml, target before the run)
    let cases: Vec<(&str, String, FakeTarget)> = vec![
        (
            "create /dev/null mask",
            doc(&[link_res("l", CONF, "/dev/null")], ""),
            fake().with_fs_dir(DIR),
        ),
        (
            "create ordinary link",
            doc(&[link_res("l", CONF, "/etc/systemd/custom.conf")], ""),
            fake().with_fs_dir(DIR),
        ),
        (
            "change target",
            doc(&[link_res("l", CONF, "/usr/lib/b.conf")], ""),
            with_symlink(fake().with_fs_dir(DIR), CONF, "/usr/lib/a.conf", 9100),
        ),
        (
            "unmask by replacement",
            doc(&[link_res("l", CONF, "/usr/lib/real.conf")], ""),
            with_symlink(fake().with_fs_dir(DIR), CONF, "/dev/null", 9101),
        ),
        (
            "remove link",
            doc(&[link_absent("l", CONF)], ""),
            with_symlink(fake().with_fs_dir(DIR), CONF, "/dev/null", 9102),
        ),
        (
            "system.conf itself",
            doc(
                &[link_res("l", "/etc/systemd/system.conf", "/dev/null")],
                "",
            ),
            fake(),
        ),
    ];
    for (label, y, t) in cases {
        let r = recipe("dr-f01", &y);
        let rep = apply(&r, t.clone());
        assert_eq!(
            rep.status,
            AggregateStatus::Success,
            "{}: {:?}",
            label,
            rep.resources
        );
        assert_eq!(find(&rep, "l").change, Change::Changed, "{}", label);
        // the former defect: Changed but manager_reloads=0
        assert_eq!(reloads(&rep), 1, "{}: {:?}", label, trace(&rep));
        assert_eq!(rep.manager_reloads.len(), 1, "{}", label);
        let m = &rep.manager_reloads[0];
        assert_eq!(m.phase, ManagerReloadPhase::Final, "{}", label);
        assert_eq!(m.trigger, ManagerReloadTrigger::PendingInput, "{}", label);
        assert_eq!(m.causes, vec!["l".to_string()], "{}", label);
        assert_eq!(m.execution, Execution::Succeeded, "{}", label);
        // a link-only recipe has no consumer: the final flush is the reload
        assert_eq!(
            trace(&rep).last().map(|s| s.as_str()),
            Some("daemon-reload")
        );
        // manager config roots are a finite table, never a UnitPath query
        assert_eq!(count(&rep, "show:UnitPath"), 0, "{}", label);
        assert_no_service_mutation(&rep);

        // plan: projected, UNKNOWN, mutation-free
        let p = plan(&r, t);
        assert_eq!(p.status, AggregateStatus::Success, "{}", label);
        assert_eq!(mutation_command_count(&p), 0, "{}", label);
        assert_no_manager_mutation_commands(&p);
        assert_eq!(reloads(&p), 0, "{}", label);
        assert_eq!(p.manager_reloads.len(), 1, "{}", label);
        assert_eq!(p.manager_reloads[0].phase, ManagerReloadPhase::Planned);
        assert!(p.manager_reloads[0].unknown, "{}", label);
    }
}

#[test]
fn f01_unchanged_unrelated_and_user_manager_links_do_not_reload() {
    const DIR: &str = "/etc/systemd/system.conf.d";
    const CONF: &str = "/etc/systemd/system.conf.d/10-vendor.conf";
    // unchanged manager-config link: nothing changed, nothing reloaded
    let y = doc(&[link_res("l", CONF, "/dev/null")], "");
    let t = with_symlink(fake().with_fs_dir(DIR), CONF, "/dev/null", 9200);
    let rep = apply(&recipe("dr-f01-same", &y), t);
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(find(&rep, "l").change, Change::None);
    assert_eq!(reloads(&rep), 0);
    assert!(rep.manager_reloads.is_empty());
    assert_eq!(mutation_command_count(&rep), 0);
    // unrelated and user-manager links change but never touch the system manager
    for (label, path, dir) in [
        ("unrelated", "/etc/app/current", "/etc/app"),
        (
            "user.conf.d",
            "/etc/systemd/user.conf.d/10-x.conf",
            "/etc/systemd/user.conf.d",
        ),
        ("user.conf", "/etc/systemd/user.conf", "/etc/systemd"),
        (
            "user unit dir",
            "/etc/systemd/user/foo.service",
            "/etc/systemd/user",
        ),
        (
            "journald drop-in",
            "/etc/systemd/journald.conf.d/10-x.conf",
            "/etc/systemd/journald.conf.d",
        ),
    ] {
        let y = doc(&[link_res("l", path, "/dev/null")], "");
        let rep = apply(&recipe("dr-f01-other", &y), fake().with_fs_dir(dir));
        assert_eq!(rep.status, AggregateStatus::Success, "{}", label);
        assert_eq!(find(&rep, "l").change, Change::Changed, "{}", label);
        assert_eq!(reloads(&rep), 0, "{}", label);
        assert!(rep.manager_reloads.is_empty(), "{}", label);
    }
}

#[test]
fn f01_a_link_and_a_file_in_manager_config_share_one_final_flush() {
    let y = doc(
        &[
            unit_file(
                "f",
                "/etc/systemd/system.conf.d/20-timeout.conf",
                "[Manager]\\nDefaultTimeoutStartSec=30s\\n",
            ),
            link_res(
                "l",
                "/etc/systemd/system.conf.d/10-vendor.conf",
                "/dev/null",
            ),
        ],
        "",
    );
    let rep = apply(
        &recipe("dr-f01-mixed", &y),
        fake().with_fs_dir("/etc/systemd/system.conf.d"),
    );
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(reloads(&rep), 1, "one reload covers file and link");
    let mut causes = rep.manager_reloads[0].causes.clone();
    causes.sort();
    assert_eq!(causes, vec!["f".to_string(), "l".to_string()]);
}

// ---------------------------------------------------------------------------
// F02: unresolved package discovery must not mutate a service
// ---------------------------------------------------------------------------

/// `nano.service` is on disk but the manager holds a cached not-found stub.
fn discovery_target() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404();
    t.manager.disk.insert("nano.service".to_string(), 1);
    t.manager
        .cached_not_found
        .insert("nano.service".to_string());
    t
}

fn assert_discovery_failed_closed(rep: &RunReport, unit: &str) {
    assert_eq!(
        rep.status,
        AggregateStatus::ApplyFailed,
        "{:?}",
        rep.resources
    );
    // exactly one bounded discovery reload, never a retry
    assert_eq!(reloads(rep), 1, "{:?}", trace(rep));
    assert_eq!(rep.manager_reloads.len(), 1);
    let m = &rep.manager_reloads[0];
    assert_eq!(m.trigger, ManagerReloadTrigger::PackageDiscovery);
    // the reload fact is kept even though the verification failed
    assert_eq!(m.execution, Execution::Succeeded);
    assert_eq!(m.change, Change::Changed);
    assert_eq!(m.verification, Verification::Failed);
    let s = find(rep, "s");
    assert_eq!(s.execution, Execution::Failed);
    assert_eq!(s.change, Change::None, "the service was never touched");
    assert_no_service_mutation(rep);
    // the only commands are the three observations/reload of this unit
    assert_eq!(
        trace(rep),
        vec![
            format!("show:{}", unit),
            "daemon-reload".to_string(),
            format!("show:{}", unit)
        ]
    );
}

#[test]
fn f02_discovery_reload_still_missing_dispatches_no_service_mutation() {
    let r = recipe("dr-f02-missing", &package_service_recipe("nosuch.service"));
    let rep = apply(&r, FakeTarget::ubuntu2404());
    assert_discovery_failed_closed(&rep, "nosuch.service");
    assert!(find(&rep, "s")
        .reason
        .as_deref()
        .unwrap()
        .contains("not found"));
}

#[test]
fn f02_discovery_reload_found_but_still_stale_dispatches_no_service_mutation() {
    // the former defect: start_count=1 although manager verification failed
    let r = recipe("dr-f02-stale", &package_service_recipe("nano.service"));
    let mut t = discovery_target();
    t.manager
        .stale_after_reload
        .insert("nano.service".to_string());
    let rep = apply(&r, t);
    assert_discovery_failed_closed(&rep, "nano.service");
    assert_eq!(count(&rep, "start:nano.service"), 0);
    let reason = find(&rep, "s").reason.clone().unwrap();
    assert!(reason.contains("still yes"), "{}", reason);
    // no further reload was attempted for the same stale unit
    assert_eq!(reloads(&rep), 1);
}

#[test]
fn f02_discovery_reload_then_observation_error_dispatches_no_service_mutation() {
    let r = recipe("dr-f02-obs", &package_service_recipe("nano.service"));
    // post-reload `show` fails with a plain error
    let mut t = discovery_target();
    t.manager.show_fail_after_reload = 1;
    let rep = apply(&r, t);
    assert_discovery_failed_closed(&rep, "nano.service");
    // post-reload `show` never completes: uncertainty, not success
    let mut t = discovery_target();
    t.manager.show_fail_after_reload = 1;
    t.manager.show_fail_completion = Some(Completion::Indeterminate {
        started: true,
        reason: "lost answer".into(),
    });
    let rep = apply(&r, t);
    assert_eq!(reloads(&rep), 1);
    assert_eq!(rep.manager_reloads[0].execution, Execution::Succeeded);
    assert_eq!(rep.manager_reloads[0].verification, Verification::Unknown);
    assert_ne!(rep.status, AggregateStatus::Success);
    assert_no_service_mutation(&rep);
}

#[test]
fn f02_discovery_reload_with_a_valid_synchronized_state_mutates_from_it() {
    let r = recipe("dr-f02-ok", &package_service_recipe("nano.service"));
    let rep = apply(&r, discovery_target());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(reloads(&rep), 1);
    assert_eq!(rep.manager_reloads[0].verification, Verification::Verified);
    assert_eq!(count(&rep, "start:nano.service"), 1);
    assert_eq!(
        trace(&rep),
        vec![
            "show:nano.service",
            "daemon-reload",
            "show:nano.service",
            "start:nano.service",
            "show:nano.service"
        ]
    );
    assert_eq!(find(&rep, "s").verification, Verification::Verified);
}

// ---------------------------------------------------------------------------
// F03: sensitivity of a manager episode reaches every diagnostic
// ---------------------------------------------------------------------------

const STDERR_CANARY: &str = "SINTER_F03_STDERR_CANARY_7Q2X";
const CONTENT_CANARY: &str = "SINTER_F03_CONTENT_CANARY_4M9K";

fn secret_recipe(label: &str, producer: bool, service: bool, handler_path: bool) -> PathBuf {
    let flag = |on: bool| if on { "    sensitive: true\n" } else { "" };
    let mut y = format!(
        "version: 1\nresources:\n  - id: u\n    type: file\n{}    with:\n      path: /etc/systemd/system/foo.service\n      content: \"Environment={}\"\n",
        flag(producer),
        CONTENT_CANARY
    );
    if handler_path {
        y.push_str("    notify: [h]\nhandlers:\n  - id: h\n    service: foo.service\n    action: restart\n");
    } else {
        y.push_str(&format!(
            "  - id: s\n    type: service\n{}    depends_on: [u]\n    with:\n      name: foo.service\n      state: running\n",
            flag(service)
        ));
    }
    recipe(label, &y)
}

/// Every externally observable rendering of a report, by surface name.
fn surfaces(rep: &RunReport) -> Vec<(&'static str, String)> {
    let mut text = Vec::new();
    sinter::output::render_apply(
        rep,
        &sinter::output::RenderOptions {
            verbose: true,
            format: sinter::output::OutputFormat::Text,
            color: false,
        },
        &mut text,
    )
    .unwrap();
    let mut reasons = String::new();
    for r in &rep.resources {
        reasons.push_str(&format!("{:?}|{:?}\n", r.reason, r.notes));
    }
    for h in &rep.handlers_run {
        reasons.push_str(&format!("{:?}\n", h.reason));
    }
    for m in &rep.manager_reloads {
        reasons.push_str(&format!("{:?}\n", m.reason));
    }
    vec![
        (
            "json",
            sinter::output::run_report_json(rep, "apply").to_string(),
        ),
        ("text", String::from_utf8(text).unwrap()),
        // the array the MCP tools embed comes from this same serializer
        (
            "manager_reloads_json",
            serde_json::Value::Array(sinter::output::manager_reloads_json(rep)).to_string(),
        ),
        (
            "debug:manager_reloads",
            format!("{:?}", rep.manager_reloads),
        ),
        ("debug:resources", format!("{:?}", rep.resources)),
        ("debug:handlers", format!("{:?}", rep.handlers_run)),
        ("reason strings", reasons),
        ("command log", format!("{:?}", rep.commands)),
    ]
}

fn assert_no_canary(rep: &RunReport, canaries: &[&str]) {
    for (name, hay) in surfaces(rep) {
        for c in canaries {
            assert!(
                !hay.contains(c),
                "{} leaked on the {} surface:\n{}",
                c,
                name,
                hay
            );
        }
    }
}

fn failing_show_target(stderr: &str) -> FakeTarget {
    let mut t = fake_with_foo("old");
    t.manager.show_fail_after_reload = 1;
    t.manager.show_fail_stderr = Some(format!("Failed to get properties: {}", stderr));
    t
}

#[test]
fn f03_post_reload_show_failure_never_leaks_for_any_sensitivity_mix() {
    // (producer sensitive, service sensitive)
    for (prod, svc) in [(true, false), (false, true), (true, true)] {
        let r = secret_recipe(&format!("dr-f03-{prod}-{svc}"), prod, svc, false);
        let rep = apply(&r, failing_show_target(STDERR_CANARY));
        let label = format!("producer={prod} service={svc}");
        assert_eq!(rep.status, AggregateStatus::ApplyFailed, "{}", label);
        // the failure is still reported truthfully
        let m = &rep.manager_reloads[0];
        assert_eq!(m.execution, Execution::Succeeded, "{}", label);
        assert_eq!(m.change, Change::Changed, "{}", label);
        assert_eq!(m.verification, Verification::Failed, "{}", label);
        assert!(m.sensitive, "{}", label);
        assert_eq!(m.reason.as_deref(), Some("<redacted>"), "raw never stored");
        let s = find(&rep, "s");
        assert_eq!(s.execution, Execution::Failed, "{}", label);
        assert!(s.reason.is_some(), "{}: failure keeps a reason", label);
        assert_no_service_mutation(&rep);
        assert_no_canary(&rep, &[STDERR_CANARY, CONTENT_CANARY]);
    }
}

#[test]
fn f03_reload_failure_with_a_sensitive_producer_never_leaks() {
    for completion in [
        Completion::Exited(1),
        Completion::Indeterminate {
            started: true,
            reason: format!("lost {}", STDERR_CANARY),
        },
    ] {
        let r = secret_recipe("dr-f03-reload", true, false, false);
        let mut t = fake_with_foo("old");
        t.manager.reload_completion = Some(completion.clone());
        t.manager.reload_stderr = format!("reload failed {}\n", STDERR_CANARY);
        let rep = apply(&r, t);
        assert_ne!(rep.status, AggregateStatus::Success);
        assert!(rep.manager_reloads[0].sensitive);
        assert_ne!(rep.manager_reloads[0].execution, Execution::Succeeded);
        assert_eq!(reloads(&rep), 1, "no retry");
        assert_no_service_mutation(&rep);
        assert_no_canary(&rep, &[STDERR_CANARY, CONTENT_CANARY]);
    }
}

#[test]
fn f03_observation_failures_in_a_sensitive_episode_never_leak() {
    // post-reload observation never completes (reason carries the canary)
    let r = secret_recipe("dr-f03-obs-indet", true, false, false);
    let mut t = failing_show_target(STDERR_CANARY);
    t.manager.show_fail_completion = Some(Completion::Indeterminate {
        started: true,
        reason: format!("no answer {}", STDERR_CANARY),
    });
    let rep = apply(&r, t);
    assert_ne!(rep.status, AggregateStatus::Success);
    assert_eq!(rep.manager_reloads[0].verification, Verification::Unknown);
    assert_no_service_mutation(&rep);
    assert_no_canary(&rep, &[STDERR_CANARY, CONTENT_CANARY]);

    // NeedDaemonReload carries a hostile value
    let mut t = fake_with_foo("old");
    t.manager.need_override.insert(
        "foo.service".into(),
        NeedOverride::Value(STDERR_CANARY.to_string()),
    );
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_no_service_mutation(&rep);
    assert_no_canary(&rep, &[STDERR_CANARY, CONTENT_CANARY]);

    // the UnitPath query fails with the canary on stderr
    let mut t = fake_with_foo("old");
    t.manager.unit_path_output = Some(Output {
        completion: Completion::Exited(1),
        stdout: Vec::new(),
        stderr: format!("boom {}", STDERR_CANARY).into_bytes(),
        stdout_truncated: false,
        stderr_truncated: false,
    });
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_no_service_mutation(&rep);
    assert_no_canary(&rep, &[STDERR_CANARY, CONTENT_CANARY]);
}

#[test]
fn f03_handler_path_with_a_sensitive_cause_never_leaks() {
    let r = secret_recipe("dr-f03-handler", true, false, true);
    let rep = apply(&r, failing_show_target(STDERR_CANARY));
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(rep.handlers_run.len(), 1);
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Failed);
    assert!(
        rep.handlers_run[0].reason.is_some(),
        "failure stays visible"
    );
    assert_eq!(rep.manager_reloads[0].phase, ManagerReloadPhase::Handler);
    assert!(rep.manager_reloads[0].sensitive);
    assert_eq!(count(&rep, "restart:foo.service"), 0);
    assert_no_canary(&rep, &[STDERR_CANARY, CONTENT_CANARY]);
}

#[test]
fn f03_final_flush_failure_with_a_sensitive_cause_never_leaks() {
    // file only: the final flush is the consumer
    let y = format!(
        "version: 1\nresources:\n  - id: u\n    type: file\n    sensitive: true\n    with:\n      path: /etc/systemd/system/foo.service\n      content: \"Environment={}\"\n",
        CONTENT_CANARY
    );
    let r = recipe("dr-f03-final", &y);
    let rep = apply(&r, failing_show_target(STDERR_CANARY));
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let m = &rep.manager_reloads[0];
    assert_eq!(m.phase, ManagerReloadPhase::Final);
    assert_eq!(m.verification, Verification::Failed);
    assert!(m.sensitive);
    assert_eq!(m.reason.as_deref(), Some("<redacted>"));
    assert_no_canary(&rep, &[STDERR_CANARY, CONTENT_CANARY]);
}

#[test]
fn f03_sensitive_package_discovery_failure_never_leaks() {
    let y = doc(
        &[
            "  - id: pkg\n    type: package\n    sensitive: true\n    with:\n      name: nano\n      state: present\n"
                .to_string(),
            service("s", "nano.service", "running", None, &["pkg"]),
        ],
        "",
    );
    let r = recipe("dr-f03-pkg", &y);
    let mut t = discovery_target();
    t.manager.show_fail_after_reload = 1;
    t.manager.show_fail_stderr = Some(format!("Failed to get properties: {}", STDERR_CANARY));
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let m = &rep.manager_reloads[0];
    assert_eq!(m.trigger, ManagerReloadTrigger::PackageDiscovery);
    assert!(
        m.sensitive,
        "a sensitive package makes the episode sensitive"
    );
    assert_eq!(m.verification, Verification::Failed);
    assert_no_service_mutation(&rep);
    assert_no_canary(&rep, &[STDERR_CANARY]);
}

#[test]
fn f03_without_a_sensitive_resource_the_diagnostic_is_kept() {
    // Redaction is not a global deletion of diagnostics.
    let r = secret_recipe("dr-f03-plain", false, false, false);
    let rep = apply(&r, failing_show_target(STDERR_CANARY));
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let m = &rep.manager_reloads[0];
    assert!(!m.sensitive);
    let reason = m.reason.clone().unwrap();
    assert!(reason.contains(STDERR_CANARY), "{}", reason);
    assert!(reason.contains("foo.service"), "{}", reason);
    let json = sinter::output::run_report_json(&rep, "apply").to_string();
    assert!(json.contains(STDERR_CANARY), "{}", json);
    assert!(find(&rep, "s")
        .reason
        .as_deref()
        .unwrap()
        .contains(STDERR_CANARY));
}

// ---------------------------------------------------------------------------
// F04: audit of a desired-absent named unit file
// ---------------------------------------------------------------------------

fn absent_file(id: &str, path: &str) -> String {
    format!("  - id: {id}\n    type: file\n    with:\n      path: {path}\n      state: absent\n")
}

/// Manager still holds `foo.service` loaded although nothing is on disk.
fn loaded_but_removed() -> FakeTarget {
    let mut t = fake().with_service("foo.service", ("loaded", "active", "enabled"));
    t.manager.loaded.insert("foo.service".to_string(), 1);
    t
}

fn audit_systemctl(rep: &sinter::audit::AuditReport) -> Vec<String> {
    rep.commands
        .iter()
        .filter(|c| c.program.ends_with("systemctl"))
        .map(|c| c.args.join(" "))
        .collect()
}

fn audit_resource<'a>(
    rep: &'a sinter::audit::AuditReport,
    id: &str,
) -> &'a sinter::audit::AuditResourceResult {
    rep.resources.iter().find(|x| x.id == id).unwrap()
}

#[test]
fn f04_desired_absent_unit_with_a_synchronized_manager_is_verified_not_assumed() {
    let r = recipe("dr-f04-sync", &doc(&[absent_file("u", UNIT)], ""));
    let rep = audit_run(&r, fake());
    assert_audit_commands_read_only(&rep);
    let u = audit_resource(&rep, "u");
    assert_eq!(u.status, AuditResourceStatus::Compliant);
    let reason = u.reason.as_deref().unwrap();
    assert!(reason.contains("path is absent as desired"), "{}", reason);
    assert!(
        reason.contains("manager consistency verified"),
        "{}",
        reason
    );
    assert_eq!(rep.aggregate_label(), "no_drift");
    // the manager was actually asked (the former defect: zero systemctl calls)
    let ctl = audit_systemctl(&rep);
    assert!(
        ctl.iter().any(|c| c.ends_with("-- foo.service")),
        "{:?}",
        ctl
    );
    assert_eq!(reloads_in(&rep.commands), 0);
}

#[test]
fn f04_desired_absent_unit_that_the_manager_still_has_loaded_is_drift() {
    let r = recipe("dr-f04-stale", &doc(&[absent_file("u", UNIT)], ""));
    let rep = audit_run(&r, loaded_but_removed());
    assert_audit_commands_read_only(&rep);
    let u = audit_resource(&rep, "u");
    assert_eq!(u.status, AuditResourceStatus::Drift);
    assert_eq!(u.details.len(), 1);
    assert_eq!(u.details[0].dimension, "manager_reload");
    assert_eq!(rep.aggregate_label(), "drift");
    assert_eq!(
        reloads_in(&rep.commands),
        0,
        "audit never repairs the manager"
    );
    // a removed drop-in of the same unit is the same facet
    let r = recipe(
        "dr-f04-dropin",
        &doc(
            &[absent_file(
                "d",
                "/etc/systemd/system/foo.service.d/override.conf",
            )],
            "",
        ),
    );
    let rep = audit_run(&r, loaded_but_removed());
    assert_eq!(audit_resource(&rep, "d").status, AuditResourceStatus::Drift);
    assert_eq!(rep.aggregate_label(), "drift");
}

#[test]
fn f04_desired_absent_with_an_unobservable_manager_is_an_error_not_no_drift() {
    let r = recipe("dr-f04-err", &doc(&[absent_file("u", UNIT)], ""));
    let mut t = loaded_but_removed();
    t.manager
        .need_override
        .insert("foo.service".into(), NeedOverride::Value("maybe".into()));
    let rep = audit_run(&r, t);
    assert_eq!(audit_resource(&rep, "u").status, AuditResourceStatus::Error);
    assert_eq!(rep.aggregate_label(), "indeterminate");
    // an unusable UnitPath is the same
    let mut t = fake();
    t.manager.unit_path_output = Some(Output {
        completion: Completion::Exited(1),
        stdout: Vec::new(),
        stderr: b"boom".to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    });
    let rep = audit_run(&r, t);
    assert_eq!(audit_resource(&rep, "u").status, AuditResourceStatus::Error);
    assert_eq!(rep.aggregate_label(), "indeterminate");
    assert_audit_commands_read_only(&rep);
}

#[test]
fn f04_desired_absent_loaded_unit_without_a_stale_signal_states_its_limit() {
    // NeedDaemonReload=no is a limited observation (also a vendor unit may
    // legitimately remain loaded): the result says so instead of implying a
    // verified match.
    let r = recipe("dr-f04-limit", &doc(&[absent_file("u", UNIT)], ""));
    let mut t = loaded_but_removed();
    t.manager.need_blind.insert("foo.service".to_string());
    let rep = audit_run(&r, t);
    let u = audit_resource(&rep, "u");
    assert_eq!(u.status, AuditResourceStatus::Compliant);
    let reason = u.reason.as_deref().unwrap();
    assert!(
        reason.contains("still reports the unit loaded"),
        "{}",
        reason
    );
    assert!(reason.contains("not verified"), "{}", reason);
    assert!(
        !reason.contains("manager consistency verified"),
        "{}",
        reason
    );
    // a path that names no single unit is stated as unverified as before
    let r = recipe(
        "dr-f04-tmpl",
        &doc(&[absent_file("t", "/etc/systemd/system/foo@.service")], ""),
    );
    let rep = audit_run(&r, fake());
    let reason = audit_resource(&rep, "t").reason.clone().unwrap();
    assert!(reason.contains("not verified"), "{}", reason);
}

#[test]
fn f04_ordinary_and_user_manager_absent_paths_are_unaffected_and_audit_stays_read_only() {
    // an ordinary absent file never reaches systemd
    let r = recipe(
        "dr-f04-plain",
        &doc(&[absent_file("f", "/etc/app.conf")], ""),
    );
    let rep = audit_run(&r, fake());
    let f = audit_resource(&rep, "f");
    assert_eq!(f.status, AuditResourceStatus::Compliant);
    assert_eq!(f.reason.as_deref(), Some("path is absent as desired"));
    assert!(
        audit_systemctl(&rep).is_empty(),
        "{:?}",
        audit_systemctl(&rep)
    );
    // a user-manager unit is outside the system manager: no unit is queried
    let r = recipe(
        "dr-f04-user",
        &doc(&[absent_file("f", "/etc/systemd/user/foo.service")], ""),
    );
    let rep = audit_run(&r, loaded_but_removed());
    let f = audit_resource(&rep, "f");
    assert_eq!(f.status, AuditResourceStatus::Compliant);
    assert_eq!(f.reason.as_deref(), Some("path is absent as desired"));
    assert!(
        audit_systemctl(&rep)
            .iter()
            .all(|c| !c.contains("foo.service")),
        "{:?}",
        audit_systemctl(&rep)
    );
    assert_audit_commands_read_only(&rep);
    // plan of the same recipe performs no mutation either
    let r = recipe("dr-f04-plan", &doc(&[absent_file("u", UNIT)], ""));
    let p = plan(&r, loaded_but_removed());
    assert_eq!(mutation_command_count(&p), 0);
    assert_no_manager_mutation_commands(&p);
    assert_eq!(reloads(&p), 0);
}

// ---------------------------------------------------------------------------
// Real-OS findings remediation (2026-10-03): R-1, R-2, R-3, R-4
//
// R-1/R-2 were seen on real systemd 252/255/257/259 (see
// SINTER_SYSTEMD_DAEMON_RELOAD_REAL_OS_ACCEPTANCE_AUTHORIZED_2026-10-03.md).
// The scripted target models only what Sinter decides; the real-systemd
// behavior is re-checked on the Linux gate host, not claimed here.
// ---------------------------------------------------------------------------

fn stop_recipe(label: &str) -> PathBuf {
    recipe(
        label,
        &doc(&[service("s", "foo.service", "stopped", None, &[])], ""),
    )
}

/// `foo.service` running, never enabled, referenced by nothing: real systemd
/// unloads it as soon as a `stop` completes.
fn unreferenced_foo() -> FakeTarget {
    let mut t = fake().with_loaded_unit("foo.service", "A", ("loaded", "active", "disabled"));
    t.manager.unload_on_stop.insert("foo.service".to_string());
    t
}

fn forced(completion: Completion, stderr: &str) -> Output {
    Output {
        completion,
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

const NOT_LOADED: &str =
    "Failed to reset failed state of unit foo.service: Unit foo.service not loaded.\n";

fn assert_failed_after_stop(rep: &RunReport, change: Change) {
    assert_eq!(
        rep.status,
        AggregateStatus::ApplyFailed,
        "{:?}",
        rep.resources
    );
    let s = find(rep, "s");
    assert_eq!(s.execution, Execution::Failed, "{:?}", s);
    assert_eq!(s.change, change, "{:?}", s);
}

#[test]
fn r2_enabled_running_unit_stop_then_reset_failed_succeeds() {
    let rep = apply(&stop_recipe("dr-r2-enabled"), fake_with_foo("A"));
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    let s = find(&rep, "s");
    assert_eq!(s.change, Change::Changed);
    assert_eq!(s.verification, Verification::Verified);
    assert!(pos(&rep, "stop:foo.service") < pos(&rep, "reset-failed:foo.service"));
    assert_eq!(count(&rep, "reset-failed:foo.service"), 1);
}

#[test]
fn r2_unreferenced_unit_unloaded_by_the_stop_is_not_a_failure() {
    let rep = apply(&stop_recipe("dr-r2-unloaded"), unreferenced_foo());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    let s = find(&rep, "s");
    assert_eq!(s.change, Change::Changed, "the stop really happened");
    assert_eq!(s.execution, Execution::Succeeded);
    assert_eq!(s.verification, Verification::Verified);
    // stop, then one reset-failed that systemd refused as "not loaded", then
    // a fresh observation proving nothing is left to clear; no retry.
    assert_eq!(count(&rep, "stop:foo.service"), 1);
    assert_eq!(count(&rep, "reset-failed:foo.service"), 1);
    assert!(pos(&rep, "stop:foo.service") < pos(&rep, "reset-failed:foo.service"));
    assert!(rpos(&rep, "show:foo.service") > pos(&rep, "reset-failed:foo.service"));
    assert_eq!(reloads(&rep), 0);
}

#[test]
fn r2_only_systemds_not_loaded_refusal_is_benign_and_everything_else_stays_a_failure() {
    // Same unloaded unit; only the reset-failed answer differs.
    let cases: Vec<(&str, Completion, &str)> = vec![
        (
            "permission",
            Completion::Exited(1),
            "Failed to reset failed state of unit foo.service: Access denied\n",
        ),
        (
            "transport",
            Completion::Exited(1),
            "Failed to connect to bus: No such file or directory\n",
        ),
        ("silent", Completion::Exited(1), ""),
        (
            "extra line",
            Completion::Exited(1),
            "warning: something\nFailed to reset failed state of unit foo.service: Unit foo.service not loaded.\n",
        ),
        (
            "bare message without the systemctl prefix",
            Completion::Exited(1),
            "Unit foo.service not loaded.\n",
        ),
        ("signal", Completion::Signaled(9), NOT_LOADED),
        (
            "timeout",
            Completion::Indeterminate {
                started: true,
                reason: "timed out".to_string(),
            },
            "",
        ),
    ];
    for (name, completion, stderr) in cases {
        let mut t = unreferenced_foo();
        t.manager
            .verb_override
            .insert("reset-failed".to_string(), forced(completion, stderr));
        let rep = apply(&stop_recipe("dr-r2-genuine"), t);
        assert!(
            rep.status != AggregateStatus::Success,
            "{name}: {:?}",
            rep.resources
        );
        let s = find(&rep, "s");
        assert_eq!(
            s.change,
            Change::Changed,
            "{name}: the stop is still reported"
        );
        assert!(s.execution != Execution::Succeeded, "{name}: {:?}", s);
    }
}

#[test]
fn r2_stop_failure_stays_a_failure_and_never_reaches_reset_failed() {
    let mut t = fake_with_foo("A");
    t.manager.verb_override.insert(
        "stop".to_string(),
        forced(
            Completion::Exited(1),
            "Failed to stop foo.service: Access denied\n",
        ),
    );
    let rep = apply(&stop_recipe("dr-r2-stopfail"), t);
    assert_failed_after_stop(&rep, Change::Possible);
    assert_eq!(
        count(&rep, "reset-failed:foo.service"),
        0,
        "{:?}",
        trace(&rep)
    );
}

#[test]
fn r2_not_loaded_without_authoritative_proof_stays_a_failure() {
    // The refusal reads as benign but the follow-up observation cannot be
    // taken: the message alone is never trusted.
    let mut t = unreferenced_foo();
    t.manager.show_fail_after_stop = 1;
    let rep = apply(&stop_recipe("dr-r2-obsfail"), t);
    assert_failed_after_stop(&rep, Change::Changed);
    assert_eq!(count(&rep, "reset-failed:foo.service"), 1);

    // The observation works but the unit is not inactive (the stop was
    // reported successful yet the unit is still active).
    let mut t = fake_with_foo("A");
    t.manager
        .verb_override
        .insert("stop".to_string(), forced(Completion::Exited(0), ""));
    t.manager.verb_override.insert(
        "reset-failed".to_string(),
        forced(Completion::Exited(1), NOT_LOADED),
    );
    let rep = apply(&stop_recipe("dr-r2-stillactive"), t);
    assert_failed_after_stop(&rep, Change::Changed);
    // refused at the reset-failed decision itself, not only by the later
    // verification
    let reason = find(&rep, "s").reason.clone().unwrap_or_default();
    assert!(reason.contains("reset-failed"), "{}", reason);
}

#[test]
fn r2_already_stopped_loaded_unit_runs_neither_stop_nor_reset_failed() {
    let t = fake().with_loaded_unit("foo.service", "A", ("loaded", "inactive", "disabled"));
    let rep = apply(&stop_recipe("dr-r2-stopped"), t);
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(find(&rep, "s").change, Change::None);
    assert_eq!(mutation_command_count(&rep), 0);
    assert_eq!(count(&rep, "stop:foo.service"), 0);
    assert_eq!(count(&rep, "reset-failed:foo.service"), 0);
}

#[test]
fn r2_r3_unit_that_is_absent_keeps_the_documented_not_found_failure() {
    // A missing unit is never read as "stopped" (docs: "Unit not found ->
    // failure"). This is also why `service stopped` + file absent applied a
    // second time fails (R-3, accepted limitation): R-2 must not change it.
    let rep = apply(&stop_recipe("dr-r2-absent"), fake());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let s = find(&rep, "s");
    assert!(
        s.reason.as_deref().unwrap().contains("was not found"),
        "{:?}",
        s
    );
    assert_eq!(s.change, Change::None);
    assert_eq!(mutation_command_count(&rep), 0);
    let e = try_run_recipe_fake(&stop_recipe("dr-r2-absent-plan"), Mode::Plan, true, fake())
        .err()
        .expect("plan error");
    assert!(e.message.contains("was not found"), "{}", e.message);
}

#[test]
fn r1_missing_service_plan_is_an_error_when_the_manager_is_synchronized() {
    // R1-A: the manager answers NeedDaemonReload=no for the missing unit.
    let r = recipe(
        "dr-r1a",
        &doc(
            &[service("s", "sinter-no-such-unit", "running", None, &[])],
            "",
        ),
    );
    let mut t = fake();
    t.manager.need_override.insert(
        "sinter-no-such-unit".to_string(),
        NeedOverride::Value("no".to_string()),
    );
    let e = try_run_recipe_fake(&r, Mode::Plan, true, t)
        .err()
        .expect("a missing unit is a plan error");
    assert_eq!(e.kind, sinter::error::ErrorKind::Plan);
    assert_eq!(e.kind.exit_code(), 4);
    assert!(e.message.contains("was not found"), "{}", e.message);
}

#[test]
fn r1_missing_service_plan_stays_unknown_and_read_only_when_the_manager_is_stale() {
    // R1-B: the same recipe and target, NeedDaemonReload=yes. A stale manager
    // makes the answer unknowable: truthful UNKNOWN, no reload, no mutation.
    // It does not contradict R1-A; only the manager's own state differs.
    let r = recipe(
        "dr-r1b",
        &doc(
            &[service("s", "sinter-no-such-unit", "running", None, &[])],
            "",
        ),
    );
    let mut t = fake();
    t.manager.need_override.insert(
        "sinter-no-such-unit".to_string(),
        NeedOverride::Value("yes".to_string()),
    );
    let p = plan(&r, t);
    assert_eq!(p.status, AggregateStatus::Success);
    let s = find(&p, "s");
    assert!(s.unknown);
    assert!(
        s.reason
            .as_deref()
            .unwrap()
            .contains("NeedDaemonReload=yes"),
        "{:?}",
        s
    );
    assert_eq!(reloads(&p), 0);
    assert_eq!(mutation_command_count(&p), 0);
    assert_no_manager_mutation_commands(&p);
    assert_eq!(p.manager_reloads.len(), 1);
    assert_eq!(
        p.manager_reloads[0].trigger,
        ManagerReloadTrigger::ObservedStale
    );
    assert_eq!(p.manager_reloads[0].execution, Execution::NotRun);
}

#[test]
fn r4_audit_of_a_removed_but_running_unit_does_not_imply_it_stopped() {
    // The manager reports no loaded definition but the process still runs
    // (real systemd: LoadState=not-found ActiveState=active). The file
    // resource states only what it verified and leaves run state to `service`.
    let r = recipe("dr-r4", &doc(&[absent_file("u", UNIT)], ""));
    let t = fake().with_service("foo.service", ("not-found", "active", ""));
    let rep = audit_run(&r, t);
    assert_audit_commands_read_only(&rep);
    let u = audit_resource(&rep, "u");
    assert_eq!(u.status, AuditResourceStatus::Compliant);
    let reason = u.reason.as_deref().unwrap();
    assert!(reason.contains("no loaded unit definition"), "{}", reason);
    assert!(reason.contains("no pending reload"), "{}", reason);
    assert!(
        reason.contains("run state is not assessed by this file resource"),
        "{}",
        reason
    );
    assert!(!reason.contains("stopped"), "{}", reason);
    assert_eq!(rep.aggregate_label(), "no_drift");
}

// ---------------------------------------------------------------------------
// Real-OS findings second focused remediation (2026-10-03): F-R2
//
// The `reset-failed` "not loaded" exception must prove the diagnostic: a
// complete UTF-8 capture whose whole text is systemd's formal sentence for the
// unit Sinter asked about. The first three `fr2_audit_*` cases are the
// counterexamples of SINTER_REAL_OS_FINDINGS_FOCUSED_INDEPENDENT_REAUDIT_
// 2026-10-03.md §10 that the prefix/suffix classifier accepted.
// ---------------------------------------------------------------------------

fn raw_output(
    completion: Completion,
    stderr: &[u8],
    stdout_trunc: bool,
    stderr_trunc: bool,
) -> Output {
    Output {
        completion,
        stdout: Vec::new(),
        stderr: stderr.to_vec(),
        stdout_truncated: stdout_trunc,
        stderr_truncated: stderr_trunc,
    }
}

/// `unit` runs, nothing references it, so the stop unloads it; the
/// `reset-failed` answer is the forced `answer`.
fn fr2_apply(unit: &str, answer: Output) -> RunReport {
    let r = recipe(
        "dr-fr2",
        &doc(&[service("s", unit, "stopped", None, &[])], ""),
    );
    let mut t = fake().with_loaded_unit(unit, "A", ("loaded", "active", "disabled"));
    t.manager.unload_on_stop.insert(unit.to_string());
    t.manager
        .verb_override
        .insert("reset-failed".to_string(), answer);
    apply(&r, t)
}

fn fr2_formal(u: &str) -> String {
    format!("Failed to reset failed state of unit {u}: Unit {u} not loaded.")
}

fn fr2_assert_accepted(label: &str, rep: &RunReport, unit: &str) {
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{label}: {:?}",
        rep.resources
    );
    let s = find(rep, "s");
    assert_eq!(s.change, Change::Changed, "{label}");
    assert_eq!(s.execution, Execution::Succeeded, "{label}");
    assert_eq!(s.verification, Verification::Verified, "{label}");
    assert_eq!(count(rep, &format!("stop:{unit}")), 1, "{label}");
    assert_eq!(count(rep, &format!("reset-failed:{unit}")), 1, "{label}");
    // the fresh observation after the refusal is the proof; no retry
    assert!(
        rpos(rep, &format!("show:{unit}")) > pos(rep, &format!("reset-failed:{unit}")),
        "{label}: {:?}",
        trace(rep)
    );
}

fn fr2_assert_rejected(label: &str, rep: &RunReport, unit: &str) {
    assert!(
        rep.status != AggregateStatus::Success,
        "{label}: accepted: {:?}",
        rep.resources
    );
    let s = find(rep, "s");
    assert_eq!(
        s.change,
        Change::Changed,
        "{label}: the stop is still reported"
    );
    assert!(s.execution != Execution::Succeeded, "{label}: {:?}", s);
    assert_eq!(count(rep, &format!("stop:{unit}")), 1, "{label}");
    assert_eq!(
        count(rep, &format!("reset-failed:{unit}")),
        1,
        "{label}: no retry"
    );
}

#[test]
fn fr2_formal_diagnostic_for_the_requested_unit_is_accepted_when_inactive() {
    let formal = fr2_formal("foo.service");
    let cases: Vec<(&str, String)> = vec![
        ("exact with newline", format!("{formal}\n")),
        ("CRLF", format!("{formal}\r\n")),
        ("no terminator", formal.clone()),
    ];
    for (label, stderr) in cases {
        let rep = fr2_apply(
            "foo.service",
            raw_output(Completion::Exited(1), stderr.as_bytes(), false, false),
        );
        fr2_assert_accepted(label, &rep, "foo.service");
    }
    // The fake manager's own (unforced) answer is the same sentence.
    let rep = apply(&stop_recipe("dr-fr2-native"), unreferenced_foo());
    fr2_assert_accepted("fake manager answer", &rep, "foo.service");
}

#[test]
fn fr2_audit_counterexamples_are_rejected() {
    // 1. malformed inner structure (reaudit §10)
    let rep = fr2_apply(
        "foo.service",
        raw_output(
            Completion::Exited(1),
            b"Failed to reset failed state of unit permission denied not loaded.\n",
            false,
            false,
        ),
    );
    fr2_assert_rejected("malformed inner structure", &rep, "foo.service");
    // 2. a diagnostic for another unit while foo.service was requested
    let rep = fr2_apply(
        "foo.service",
        raw_output(
            Completion::Exited(1),
            format!("{}\n", fr2_formal("other.service")).as_bytes(),
            false,
            false,
        ),
    );
    fr2_assert_rejected("other unit", &rep, "foo.service");
    // 3. the formal sentence with a truncated stderr capture
    let rep = fr2_apply(
        "foo.service",
        raw_output(
            Completion::Exited(1),
            format!("{}\n", fr2_formal("foo.service")).as_bytes(),
            false,
            true,
        ),
    );
    fr2_assert_rejected("stderr truncated", &rep, "foo.service");
}

#[test]
fn fr2_malformed_or_foreign_diagnostics_are_rejected() {
    let formal = fr2_formal("foo.service");
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "wrong first unit",
            b"Failed to reset failed state of unit other.service: Unit foo.service not loaded.\n"
                .to_vec(),
        ),
        (
            "wrong second unit",
            b"Failed to reset failed state of unit foo.service: Unit other.service not loaded.\n"
                .to_vec(),
        ),
        (
            "both units the same but not the requested one",
            format!("{}\n", fr2_formal("other.service")).into_bytes(),
        ),
        (
            "missing separator",
            b"Failed to reset failed state of unit foo.service Unit foo.service not loaded.\n"
                .to_vec(),
        ),
        (
            "missing period",
            b"Failed to reset failed state of unit foo.service: Unit foo.service not loaded\n"
                .to_vec(),
        ),
        (
            "prefix only",
            b"Failed to reset failed state of unit foo.service\n".to_vec(),
        ),
        ("suffix only", b"Unit foo.service not loaded.\n".to_vec()),
        (
            "embedded unrelated not-loaded text",
            b"Failed to reset failed state of unit foo.service: Access denied, policy module not loaded.\n"
                .to_vec(),
        ),
        (
            "extra line before",
            format!("warning: x\n{formal}\n").into_bytes(),
        ),
        (
            "extra line after",
            format!("{formal}\nwarning: x\n").into_bytes(),
        ),
        (
            "leading whitespace",
            format!(" {formal}\n").into_bytes(),
        ),
        (
            "trailing whitespace",
            format!("{formal} \n").into_bytes(),
        ),
        ("empty stderr", Vec::new()),
        (
            "invalid UTF-8 inside the sentence",
            b"Failed to reset failed state of unit foo.service: Unit foo.service not loaded\xff.\n"
                .to_vec(),
        ),
        (
            "invalid UTF-8 after the sentence",
            [format!("{formal}\n").as_bytes(), b"\xff"].concat(),
        ),
        (
            "permission denied",
            b"Failed to reset failed state of unit foo.service: Access denied\n".to_vec(),
        ),
        (
            "authentication",
            b"Failed to reset failed state of unit foo.service: Interactive authentication required.\n"
                .to_vec(),
        ),
        (
            "bus/transport",
            b"Failed to connect to system scope bus via local transport: No such file or directory\n"
                .to_vec(),
        ),
        ("arbitrary rc1", b"boom\n".to_vec()),
        // systemd names the requested unit as `foo.service`, never bare.
        (
            "case differs",
            format!("{}\n", fr2_formal("Foo.service")).into_bytes(),
        ),
    ];
    for (label, stderr) in cases {
        let rep = fr2_apply(
            "foo.service",
            raw_output(Completion::Exited(1), &stderr, false, false),
        );
        fr2_assert_rejected(label, &rep, "foo.service");
    }
}

#[test]
fn fr2_incomplete_capture_of_either_stream_is_rejected() {
    let formal = format!("{}\n", fr2_formal("foo.service"));
    for (label, out_trunc, err_trunc) in [
        ("stderr truncated", false, true),
        ("stdout truncated", true, false),
        ("both truncated", true, true),
    ] {
        let rep = fr2_apply(
            "foo.service",
            raw_output(
                Completion::Exited(1),
                formal.as_bytes(),
                out_trunc,
                err_trunc,
            ),
        );
        fr2_assert_rejected(label, &rep, "foo.service");
    }
}

#[test]
fn fr2_unit_identity_follows_the_requested_name_and_systemctls_mangling() {
    // A bare name is reported by systemctl as `<name>.service`.
    let rep = fr2_apply(
        "foo",
        raw_output(
            Completion::Exited(1),
            format!("{}\n", fr2_formal("foo.service")).as_bytes(),
            false,
            false,
        ),
    );
    fr2_assert_accepted("bare name, mangled diagnostic", &rep, "foo");
    // The mangled name, not the bare one, is what systemd prints.
    let rep = fr2_apply(
        "foo",
        raw_output(
            Completion::Exited(1),
            format!("{}\n", fr2_formal("foo")).as_bytes(),
            false,
            false,
        ),
    );
    fr2_assert_rejected("bare name, bare diagnostic", &rep, "foo");
    // Instances and other unit types are compared verbatim.
    for unit in ["getty@tty1.service", "backup.timer"] {
        let rep = fr2_apply(
            unit,
            raw_output(
                Completion::Exited(1),
                format!("{}\n", fr2_formal(unit)).as_bytes(),
                false,
                false,
            ),
        );
        fr2_assert_accepted(unit, &rep, unit);
        let rep = fr2_apply(
            unit,
            raw_output(
                Completion::Exited(1),
                format!("{}\n", fr2_formal("foo.service")).as_bytes(),
                false,
                false,
            ),
        );
        fr2_assert_rejected(unit, &rep, unit);
    }
}

#[test]
fn fr2_signal_and_timeout_are_not_the_benign_case() {
    let formal = format!("{}\n", fr2_formal("foo.service"));
    let rep = fr2_apply(
        "foo.service",
        raw_output(Completion::Signaled(9), formal.as_bytes(), false, false),
    );
    fr2_assert_rejected("signal", &rep, "foo.service");
    let rep = fr2_apply(
        "foo.service",
        raw_output(
            Completion::Indeterminate {
                started: true,
                reason: "timed out".to_string(),
            },
            formal.as_bytes(),
            false,
            false,
        ),
    );
    fr2_assert_rejected("timeout", &rep, "foo.service");
    assert_eq!(
        find(&rep, "s").execution,
        Execution::Indeterminate,
        "a timeout stays indeterminate"
    );
}

#[test]
fn fr2_formal_diagnostic_still_needs_a_fresh_inactive_observation() {
    let formal = format!("{}\n", fr2_formal("foo.service"));
    let answer = || raw_output(Completion::Exited(1), formal.as_bytes(), false, false);
    // active / failed after the refusal: the stop "succeeded" but did nothing.
    for state in ["active", "failed"] {
        let mut t = fake().with_loaded_unit("foo.service", "A", ("loaded", state, "disabled"));
        t.manager.verb_override.insert(
            "stop".to_string(),
            raw_output(Completion::Exited(0), b"", false, false),
        );
        t.manager
            .verb_override
            .insert("reset-failed".to_string(), answer());
        let rep = apply(&stop_recipe("dr-fr2-state"), t);
        fr2_assert_rejected(state, &rep, "foo.service");
        let reason = find(&rep, "s").reason.clone().unwrap_or_default();
        assert!(reason.contains("reset-failed"), "{state}: {reason}");
    }
    // The observation cannot be taken, or is unusable.
    let observations: Vec<(&str, Completion)> = vec![
        ("observation fails", Completion::Exited(1)),
        // exit 0 with no property records: malformed, never read as inactive
        ("observation malformed", Completion::Exited(0)),
        ("observation signal", Completion::Signaled(9)),
        (
            "observation timeout",
            Completion::Indeterminate {
                started: true,
                reason: "timed out".to_string(),
            },
        ),
    ];
    for (label, completion) in observations {
        let mut t = unreferenced_foo();
        t.manager
            .verb_override
            .insert("reset-failed".to_string(), answer());
        t.manager.show_fail_after_stop = 1;
        t.manager.show_fail_completion = Some(completion);
        t.manager.show_fail_stderr = Some(String::new());
        let rep = apply(&stop_recipe("dr-fr2-obs"), t);
        fr2_assert_rejected(label, &rep, "foo.service");
    }
}

#[test]
fn fr2_successful_reset_failed_and_failed_stop_keep_their_paths() {
    // reset-failed succeeded: ordinary success, no classification involved.
    let mut t = unreferenced_foo();
    t.manager.verb_override.insert(
        "reset-failed".to_string(),
        raw_output(Completion::Exited(0), b"", false, false),
    );
    let rep = apply(&stop_recipe("dr-fr2-ok"), t);
    fr2_assert_accepted("successful reset-failed", &rep, "foo.service");
    // stop failed: reset-failed is never dispatched, even with a formal text.
    let mut t = unreferenced_foo();
    t.manager.verb_override.insert(
        "stop".to_string(),
        raw_output(
            Completion::Exited(1),
            format!("{}\n", fr2_formal("foo.service")).as_bytes(),
            false,
            false,
        ),
    );
    let rep = apply(&stop_recipe("dr-fr2-stopfail"), t);
    assert_failed_after_stop(&rep, Change::Possible);
    assert_eq!(
        count(&rep, "reset-failed:foo.service"),
        0,
        "{:?}",
        trace(&rep)
    );
}

#[test]
fn fr2_reset_failed_runs_under_the_c_utf8_locale() {
    // The classifier matches systemd's English sentence; that holds because
    // every systemctl invocation carries LC_ALL=C.UTF-8 (baseline_env).
    let rep = apply(&stop_recipe("dr-fr2-locale"), unreferenced_foo());
    let reset: Vec<_> = rep
        .commands
        .iter()
        .filter(|c| {
            c.program.ends_with("systemctl")
                && c.args.first().map(|a| a.as_str()) == Some("reset-failed")
        })
        .collect();
    assert_eq!(reset.len(), 1);
    assert_eq!(
        reset[0].env.get("LC_ALL").map(|s| s.as_str()),
        Some("C.UTF-8")
    );
    assert_eq!(
        reset[0].env.get("LANG").map(|s| s.as_str()),
        Some("C.UTF-8")
    );
}
