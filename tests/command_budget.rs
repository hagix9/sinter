//! Target-command count baselines and budgets (performance WP-P0).
//!
//! # What this protects
//!
//! Every observation Sinter makes is one command on the target, and over SSH
//! each command is its own exec channel (about three to four network round
//! trips). Those round trips, not Sinter's own computation, dominate the wall
//! time of `plan`, `apply` and `audit` (see
//! `SINTER_PERFORMANCE_BASELINE_RESEARCH_2026-10-04.md`). The tests here count
//! the commands a run submits, through the statistics every executor keeps
//! (`Engine::exec_stats`), so that:
//!
//! * an optimization can prove it removed commands (and which ones), and
//! * an unrelated change cannot silently add round trips.
//!
//! # Two kinds of test
//!
//! * `baseline_*` tests pin **today's exact shape** of a few small scenarios.
//!   They are deliberately exact: they also prove the instrumentation counts
//!   correctly. When a change intentionally alters a count (for example
//!   memoizing account lookups), update the number *and* say why, with the
//!   before/after evidence, in the same change.
//! * `budget_*` tests are **ceilings**. A reduction passes; growth fails. They
//!   are the lasting regression guard and need no edit when a count goes down.
//!
//! Counts are not user-visible behavior and no output states them; they are a
//! cost contract only. The scripted target (`FakeTarget`) answers the real
//! command vocabulary, so a count here is the count of commands the production
//! engine would submit. Over real SSH, a non-sudo run adds three target execs
//! that the scripted target does not have (the HOME lookup made while
//! connecting, `id -u` and `id -g`); they are constant per run.
//!
//! The statistics never hold argv, environment, input or output: see
//! `sensitive_requests_are_redacted_in_the_statistics`.
#![cfg(unix)]

use sinter::audit::run_audit;
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, TargetSpec};
use sinter::executor::{CommandOutcome, ExecStats, FakeTarget};
use sinter::model::load_model;
use sinter::result::Change;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Commands every run spends before its first resource on a target that needs
/// no package backend probe: `test -r /etc/os-release`, two `test -x`
/// (getfattr, getfacl), `hostname`, `cat /etc/os-release`, `uname -m`.
const SETUP_COMMANDS: usize = 6;

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn recipe(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\nresources:\n{}", body)).unwrap();
    p
}

fn engine(path: &Path, mode: Mode, sudo: bool, target: FakeTarget) -> Engine {
    let model = load_model(path).unwrap();
    Engine::new(
        model,
        RunOptions {
            mode,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(target),
        },
    )
    .unwrap()
}

struct Observed {
    stats: ExecStats,
    /// What `Engine::new` alone cost (the setup commands).
    setup: usize,
    /// The commands the engine's own log recorded (program, args).
    log_len: usize,
    log_programs: BTreeMap<String, usize>,
    log_sudo: usize,
}

fn histogram<'a>(programs: impl Iterator<Item = &'a str>) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for p in programs {
        *m.entry(p.rsplit('/').next().unwrap().to_string())
            .or_insert(0) += 1;
    }
    m
}

fn run_plan_or_apply(path: &Path, mode: Mode, sudo: bool, target: FakeTarget) -> Observed {
    let e = engine(path, mode, sudo, target);
    let handle = e.exec_stats();
    let setup = handle.snapshot().total();
    let report = e.run().unwrap();
    assert_eq!(
        report.status,
        AggregateStatus::Success,
        "scenario must succeed"
    );
    Observed {
        stats: handle.snapshot(),
        setup,
        log_len: report.commands.len(),
        log_programs: histogram(report.commands.iter().map(|c| c.program.as_str())),
        log_sudo: report.commands.iter().filter(|c| c.sudo).count(),
    }
}

fn run_audit_of(path: &Path, sudo: bool, target: FakeTarget) -> Observed {
    let e = engine(path, Mode::Plan, sudo, target);
    let handle = e.exec_stats();
    let setup = handle.snapshot().total();
    let report = run_audit(e).unwrap();
    Observed {
        stats: handle.snapshot(),
        setup,
        log_len: report.commands.len(),
        log_programs: histogram(report.commands.iter().map(|c| c.program.as_str())),
        log_sudo: report.commands.iter().filter(|c| c.sudo).count(),
    }
}

fn target() -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_fs_dir("/etc/perf")
}

/// `n` already-compliant files, all `root:root 0644`: one owner and one group
/// shared by every resource. Returns the recipe body and the seeded target.
fn shared_owner_files(n: usize) -> (String, FakeTarget) {
    let mut body = String::new();
    let mut t = target();
    for i in 0..n {
        let path = format!("/etc/perf/f{}.conf", i);
        body.push_str(&format!(
            "  - id: f{i}\n    type: file\n    with:\n      path: {path}\n      content: \"x{i}\\n\"\n      owner: root\n      group: root\n      mode: \"0644\"\n"
        ));
        t = t.with_fs_file(&path, &format!("x{}\n", i));
    }
    (body, t)
}

fn assert_stats_agree_with_log(o: &Observed) {
    assert_eq!(
        o.stats.total(),
        o.log_len,
        "statistics vs command log: total"
    );
    assert_eq!(
        o.stats.by_program(),
        o.log_programs,
        "statistics vs command log: programs"
    );
    assert_eq!(o.stats.sudo_commands(), o.log_sudo, "sudo commands");
}

// ---------------------------------------------------------------------------
// instrumentation correctness
// ---------------------------------------------------------------------------

#[test]
fn baseline_setup_cost_is_six_commands_all_labelled_setup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("r.yaml");
    std::fs::write(&path, "version: 1\nresources: []\n").unwrap();
    let e = engine(&path, Mode::Plan, false, target());
    let s = e.exec_stats().snapshot();
    assert_eq!(s.total(), SETUP_COMMANDS);
    assert_eq!(s.count_scope("setup"), SETUP_COMMANDS);
    assert_eq!(
        s.by_program(),
        BTreeMap::from([
            ("cat".to_string(), 1),
            ("hostname".to_string(), 1),
            ("test".to_string(), 3),
            ("uname".to_string(), 1),
        ])
    );
    assert!(s.commands.iter().all(|c| !c.sudo));
    // The only setup command that may exit non-zero is a capability probe for
    // a tool the target lacks (the scripted Ubuntu ships no `getfacl`).
    assert_eq!(s.not_successful(), 1);
    assert!(s
        .commands
        .iter()
        .filter(|c| c.outcome != CommandOutcome::Success)
        .all(|c| c.program == "test" && c.outcome == CommandOutcome::NonZeroExit));
}

#[test]
fn statistics_agree_with_the_command_log_in_plan_audit_and_apply() {
    let (body, t) = shared_owner_files(3);
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &body);
    for sudo in [false, true] {
        assert_stats_agree_with_log(&run_plan_or_apply(&path, Mode::Plan, sudo, t.clone()));
        assert_stats_agree_with_log(&run_audit_of(&path, sudo, t.clone()));
        assert_stats_agree_with_log(&run_plan_or_apply(&path, Mode::Apply, sudo, t.clone()));
    }
    // Under sudo every command is a sudo command.
    let o = run_plan_or_apply(&path, Mode::Plan, true, t);
    assert_eq!(o.stats.sudo_commands(), o.stats.total());
}

#[test]
fn every_command_is_labelled_with_a_fixed_scope_and_scopes_add_up() {
    let (body, t) = shared_owner_files(2);
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &body);
    let o = run_plan_or_apply(&path, Mode::Plan, false, t);
    let by_scope = o.stats.by_scope();
    assert_eq!(by_scope.values().sum::<usize>(), o.stats.total());
    assert_eq!(by_scope.get("setup"), Some(&SETUP_COMMANDS));
    assert_eq!(
        by_scope.get("file"),
        Some(&(o.stats.total() - SETUP_COMMANDS))
    );
    // Setup comes first; resource commands never precede it.
    assert!(o.stats.commands[..SETUP_COMMANDS]
        .iter()
        .all(|c| c.scope == "setup"));
}

#[test]
fn sensitive_requests_are_redacted_in_the_statistics() {
    let dir = tempfile::tempdir().unwrap();
    let body = |sensitive: bool| {
        format!(
            "  - id: c\n    type: command\n    sensitive: {sensitive}\n    with:\n      program: /opt/CANARY-PROGRAM-91c4\n      args: [\"CANARY-ARG-91c4\"]\n"
        )
    };
    let t = || target().with_executable("/opt/CANARY-PROGRAM-91c4");

    let path = recipe(&dir, &body(true));
    let o = run_plan_or_apply(&path, Mode::Apply, false, t());
    let shown = format!("{:?}", o.stats);
    assert!(
        !shown.contains("CANARY"),
        "leaked into the statistics: {shown}"
    );
    let cmd: Vec<_> = o
        .stats
        .commands
        .iter()
        .filter(|c| c.scope == "command")
        .collect();
    assert_eq!(cmd.len(), 1);
    assert_eq!(cmd[0].program, "[redacted]");

    // The same command, not sensitive, is labelled by its program basename only
    // (the argument is never held).
    let path = recipe(&dir, &body(false));
    let o = run_plan_or_apply(&path, Mode::Apply, false, t());
    let shown = format!("{:?}", o.stats);
    assert!(!shown.contains("CANARY-ARG"), "argv leaked: {shown}");
    let cmd: Vec<_> = o
        .stats
        .commands
        .iter()
        .filter(|c| c.scope == "command")
        .collect();
    assert_eq!(cmd.len(), 1);
    assert_eq!(cmd[0].program, "CANARY-PROGRAM-91c4");
    assert_eq!(cmd[0].outcome, CommandOutcome::Success);
}

// ---------------------------------------------------------------------------
// baselines: today's exact shape
// ---------------------------------------------------------------------------

#[test]
fn baseline_compliant_owned_file_costs_four_commands_in_plan_and_audit() {
    // stat, getent passwd, getent group, sha256sum.
    let (body, t) = shared_owner_files(1);
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &body);

    let plan = run_plan_or_apply(&path, Mode::Plan, false, t.clone());
    let audit = run_audit_of(&path, false, t);
    for (what, o) in [("plan", &plan), ("audit", &audit)] {
        assert_eq!(o.setup, SETUP_COMMANDS, "{what}");
        assert_eq!(o.stats.total(), SETUP_COMMANDS + 4, "{what}");
        assert_eq!(o.stats.count_program("stat"), 1, "{what}");
        assert_eq!(o.stats.count_program("getent"), 2, "{what}");
        assert_eq!(o.stats.count_program("sha256sum"), 1, "{what}");
        assert_eq!(o.stats.count_scope("file"), 4, "{what}");
        assert_stats_agree_with_log(o);
    }
}

#[test]
fn baseline_shared_owner_and_group_are_looked_up_once_per_resource() {
    // The baseline for account-lookup memoization (WP-P1). Today every file
    // that names an owner and a group runs `getent passwd` and `getent group`
    // again, even when every resource names the same two accounts: getent is
    // exactly half of the per-resource commands and grows linearly with N.
    // A memo should turn `2 * n` into `2`; update these numbers then, with the
    // before/after evidence.
    for n in [1usize, 5, 20] {
        let (body, t) = shared_owner_files(n);
        let dir = tempfile::tempdir().unwrap();
        let path = recipe(&dir, &body);
        let plan = run_plan_or_apply(&path, Mode::Plan, false, t.clone());
        let audit = run_audit_of(&path, false, t);
        for (what, o) in [("plan", &plan), ("audit", &audit)] {
            let per_resource = o.stats.total() - SETUP_COMMANDS;
            assert_eq!(per_resource, 4 * n, "{what} n={n}");
            assert_eq!(o.stats.count_program("getent"), 2 * n, "{what} n={n}");
            assert_eq!(o.stats.count_program("stat"), n, "{what} n={n}");
            assert_eq!(o.stats.count_program("sha256sum"), n, "{what} n={n}");
            // Half of the per-resource commands are account lookups.
            assert_eq!(
                o.stats.count_program("getent") * 2,
                per_resource,
                "{what} n={n}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// budgets: ceilings
// ---------------------------------------------------------------------------

#[test]
fn budget_plan_and_audit_of_compliant_owned_files() {
    // Ceiling: setup plus four commands per resource (today's exact cost).
    for n in [1usize, 10, 40] {
        let (body, t) = shared_owner_files(n);
        let dir = tempfile::tempdir().unwrap();
        let path = recipe(&dir, &body);
        let plan = run_plan_or_apply(&path, Mode::Plan, false, t.clone());
        let audit = run_audit_of(&path, false, t.clone());
        let noop_apply = run_plan_or_apply(&path, Mode::Apply, false, t);
        for (what, o) in [("plan", &plan), ("audit", &audit)] {
            assert!(
                o.stats.total() <= SETUP_COMMANDS + 4 * n,
                "{what} n={n}: {} commands exceed the budget {}",
                o.stats.total(),
                SETUP_COMMANDS + 4 * n
            );
        }
        // A converged apply must not cost more than the plan that preceded it.
        assert!(
            noop_apply.stats.total() <= plan.stats.total(),
            "no-op apply n={n}: {} > plan {}",
            noop_apply.stats.total(),
            plan.stats.total()
        );
        let first_change = noop_apply
            .stats
            .commands
            .iter()
            .any(|c| matches!(c.program.as_str(), "mv" | "dd" | "chmod" | "chown"));
        assert!(!first_change, "a converged apply must not mutate");
    }
}

#[test]
fn budget_mixed_resources_plan() {
    // Ten resources: 4 owned files, 2 owned directories, 2 packages, 1 service
    // and 1 file without owner/group. Today: 8 setup (two extra `test -x` for
    // the package tools) + 27 resource commands = 35. Ceiling: 3 per resource.
    let mut body = String::new();
    let mut t = target();
    for i in 0..4 {
        let p = format!("/etc/perf/f{i}.conf");
        body.push_str(&format!("  - id: f{i}\n    type: file\n    with:\n      path: {p}\n      content: \"x{i}\\n\"\n      owner: root\n      group: root\n      mode: \"0644\"\n"));
        t = t.with_fs_file(&p, &format!("x{i}\n"));
    }
    for i in 0..2 {
        let p = format!("/etc/perf/d{i}");
        body.push_str(&format!("  - id: d{i}\n    type: directory\n    with:\n      path: {p}\n      owner: root\n      group: root\n      mode: \"0755\"\n"));
        t = t.with_fs_dir(&p);
    }
    for i in 0..2 {
        body.push_str(&format!("  - id: p{i}\n    type: package\n    with:\n      name: pkg{i}\n      state: present\n"));
        t = t.with_package(&format!("pkg{i}"));
    }
    body.push_str("  - id: s0\n    type: service\n    with:\n      name: svc0.service\n      state: running\n      enabled: true\n");
    t = t.with_service("svc0.service", ("active", "running", "enabled"));
    body.push_str("  - id: g0\n    type: file\n    with:\n      path: /etc/perf/g0.conf\n      content: \"y\\n\"\n");
    t = t.with_fs_file("/etc/perf/g0.conf", "y\n");

    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &body);
    let o = run_plan_or_apply(&path, Mode::Plan, false, t.clone());
    assert_eq!(
        o.setup,
        SETUP_COMMANDS + 2,
        "package recipes probe two more tools"
    );
    let resource_commands = o.stats.total() - o.setup;
    assert!(
        resource_commands <= 3 * 10,
        "mixed plan: {resource_commands} resource commands exceed 30 (today 27): {:?}",
        o.stats.by_program()
    );
    assert_stats_agree_with_log(&o);
    // The same recipe audits at the same cost.
    let a = run_audit_of(&path, false, t);
    assert!(
        a.stats.total() <= o.stats.total(),
        "audit must not cost more than plan"
    );
}

#[test]
fn budget_file_creation_apply() {
    // Creating a file three directories deep. Today: 37 commands, of which
    // only the staged write is productive; the rest is observation, chiefly
    // the trusted-parent walk (`stat` + `getfattr` per ancestor) that runs
    // three times (18 `stat`, 9 `getfattr`). The productive operations are
    // exact; the totals are ceilings so that a reduction passes.
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(
        &dir,
        "  - id: f\n    type: file\n    with:\n      path: /etc/perf/new.conf\n      content: \"x\\n\"\n      owner: root\n      group: root\n      mode: \"0644\"\n",
    );
    let o = run_plan_or_apply(&path, Mode::Apply, false, target());
    for (program, n) in [
        ("mktemp", 1),
        ("dd", 1),
        ("mv", 1),
        ("rmdir", 1),
        ("chown", 1),
    ] {
        assert_eq!(o.stats.count_program(program), n, "{program}");
    }
    let resource_commands = o.stats.total() - o.setup;
    assert!(
        resource_commands <= 37,
        "file creation: {resource_commands} commands exceed 37: {:?}",
        o.stats.by_program()
    );
    let walk = o.stats.count_program("stat") + o.stats.count_program("getfattr");
    assert!(
        walk <= 27,
        "trusted-parent observation grew to {walk} (today 27)"
    );
    assert_stats_agree_with_log(&o);

    // The converged re-run does no mutation and costs no more than a plan.
    let t = target().with_fs_file("/etc/perf/new.conf", "x\n");
    let again = run_plan_or_apply(&path, Mode::Apply, false, t.clone());
    let plan = run_plan_or_apply(&path, Mode::Plan, false, t);
    assert!(again.stats.total() <= plan.stats.total());
    assert_eq!(again.stats.count_program("dd"), 0);
}

#[test]
fn compliant_files_report_no_change_in_this_harness() {
    // Guards the scenarios above: they measure the compliant path, not a
    // change that happens to look cheap.
    let (body, t) = shared_owner_files(3);
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &body);
    let e = engine(&path, Mode::Plan, false, t);
    let report = e.run().unwrap();
    assert!(report.resources.iter().all(|r| r.change == Change::None));
}
