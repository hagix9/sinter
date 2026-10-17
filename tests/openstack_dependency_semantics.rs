//! What Sinter's dependency model does and does not give an OpenStack-style recipe. Each test is a small recipe
//! on a scripted Rocky 10 target and pins ONE behaviour the OpenStack demo relies on (or must work around):
//! `depends_on` order, failure/Unknown propagation, package-created accounts, service restart on config change,
//! service state, rerun idempotence and plan/apply/audit agreement. The tests state facts about Sinter; they do
//! not claim OpenStack works.
mod common;

use common::*;
use sinter::audit::{run_audit, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, TargetSpec};
use sinter::executor::FakeTarget;
use sinter::model::load_model;
use sinter::result::{Change, Disposition, Execution};
use std::path::{Path, PathBuf};

fn host() -> FakeTarget {
    FakeTarget::rocky10()
        .with_fake_fs()
        .as_root()
        .with_fs_dir("/etc")
        .with_fs_dir("/etc/foo")
        .with_fs_dir("/etc/systemd")
        .with_fs_dir("/etc/systemd/system")
        .with_fs_dir("/usr")
        .with_fs_dir("/usr/local")
        .with_fs_dir("/usr/local/bin")
        .with_executable("/usr/local/bin/step")
}

/// Account and unit as the foo package leaves them after the install.
fn host_with_foo_installed() -> FakeTarget {
    host()
        .with_package("foo")
        .with_group("foo", 300)
        .with_user("foo", 300, 300, "/var/lib/foo", "/sbin/nologin")
        .with_service("foo", ("loaded", "active", "enabled"))
}

fn recipe(label: &str, body: &str) -> PathBuf {
    let dir = trusted_root(label);
    write_recipe(&dir, "r.yaml", body)
}

fn audit(path: &Path, fake: FakeTarget) -> sinter::audit::AuditReport {
    let model = load_model(path).unwrap();
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake),
    };
    run_audit(Engine::new(model, opts).unwrap()).unwrap()
}

const CHAIN: &str = r#"
version: 1
handlers:
  - { id: restart_foo, service: foo, action: restart }
resources:
  - id: pkg_foo
    type: package
    with: { name: foo, state: present }
  - id: foo_conf
    type: file
    notify: [restart_foo]
    depends_on: [pkg_foo]
    with: { path: /etc/foo/foo.conf, content: "key = value\n", owner: root, group: root, mode: "0644" }
  - id: svc_foo
    type: service
    depends_on: [pkg_foo, foo_conf]
    with: { name: foo, state: running, enabled: true }
"#;

fn restarts(r: &sinter::engine::RunReport) -> usize {
    r.commands
        .iter()
        .filter(|c| c.program.ends_with("systemctl") && c.args.iter().any(|a| a == "restart"))
        .count()
}

#[test]
fn depends_on_orders_package_then_config_then_service() {
    let p = recipe("dep-order", CHAIN);
    let r = run_recipe_fake(&p, Mode::Plan, true, host_with_foo_installed());
    let pos = |id: &str| r.resources.iter().position(|x| x.id == id).unwrap();
    assert!(pos("pkg_foo") < pos("foo_conf") && pos("foo_conf") < pos("svc_foo"));
}

#[test]
fn a_package_created_account_is_not_known_to_plan_before_the_package_exists() {
    // The package is absent, so the group `foo` is absent: plan cannot resolve the owner of the config file
    // and stops the whole run with an error. Sinter does not predict accounts that a package will create
    // (user/group RESOURCES are predicted since F-3, package side effects are not). This is why the OpenStack
    // recipes keep such files behind a command dependency, which plan treats as Unknown.
    let body = CHAIN.replace(
        "owner: root, group: root, mode: \"0644\" }",
        "owner: foo, group: foo, mode: \"0644\" }",
    );
    let p = recipe("pkg-account", &body);
    let Err(e) = try_run_recipe_fake(&p, Mode::Plan, true, host()) else {
        panic!("plan must refuse an unknown owner")
    };
    assert!(e.message.contains("unknown user: foo"), "{}", e.message);
    // The same recipe on a host where the package (and so the account) already exists plans fine.
    let r = run_recipe_fake(&p, Mode::Plan, true, host_with_foo_installed());
    assert!(matches!(
        r.status,
        AggregateStatus::Success | AggregateStatus::Indeterminate
    ));
    // Apply has the same limit: the engine resolves the owner when it reaches the file, and on a real host
    // the package install has by then created the account; plan cannot know that, apply can. This is verified
    // only on a real host (see the GCE readiness report).
}

#[test]
fn a_command_in_the_chain_makes_everything_after_it_unknown_in_plan_not_an_error() {
    let body = CHAIN.replace(
        "depends_on: [pkg_foo]\n    with: { path",
        "depends_on: [pkg_foo, step]\n    with: { path",
    ) + r#"
  - id: step
    type: command
    depends_on: [pkg_foo]
    with: { program: /usr/local/bin/step, changed_when: "false" }
"#;
    let p = recipe("unknown-prop", &body);
    let r = run_recipe_fake(&p, Mode::Plan, true, host());
    assert!(matches!(
        r.status,
        AggregateStatus::Success | AggregateStatus::Indeterminate
    ));
    assert!(find(&r, "step").unknown);
    assert!(find(&r, "foo_conf").unknown);
    assert!(find(&r, "svc_foo").unknown);
    assert_eq!(mutation_command_count(&r), 0);
}

#[test]
fn apply_stops_at_the_first_failure_and_runs_nothing_after_it() {
    // `step` is not an executable on the target: it fails. Apply is FAIL-FAST: every resource after it,
    // dependent or not, is reported as blocked and not run. (Order is dependencies first, then declaration
    // order, so "after" includes resources that merely come later.)
    let body = r#"
version: 1
resources:
  - id: step
    type: command
    with: { program: /usr/local/bin/missing-step }
  - id: after_step
    type: file
    depends_on: [step]
    with: { path: /etc/foo/after.conf, content: "x\n", owner: root, group: root, mode: "0644" }
  - id: independent
    type: file
    with: { path: /etc/foo/independent.conf, content: "x\n", owner: root, group: root, mode: "0644" }
"#;
    let p = recipe("fail-fast", body);
    let r = run_recipe_fake(&p, Mode::Apply, true, host());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_eq!(find(&r, "step").execution, Execution::Failed);
    for id in ["after_step", "independent"] {
        assert_eq!(find(&r, id).execution, Execution::NotRun, "{id}");
        assert_eq!(
            find(&r, id).disposition,
            Disposition::BlockedByFailFast,
            "{id}"
        );
    }
    assert_eq!(find(&r, "independent").change, Change::None);
}

#[test]
fn a_config_change_restarts_only_through_the_declared_handler_once_and_only_when_it_changed() {
    // Unchanged file: no restart, service untouched (rerun idempotence of the config -> service pair).
    let p = recipe("restart", CHAIN);
    let same = host_with_foo_installed()
        .with_fs_file("/etc/foo/foo.conf", "key = value\n")
        .with_fs_dir("/var/lib/foo");
    let r = run_recipe_fake(&p, Mode::Apply, true, same);
    eprintln!(
        "restart/unchanged: {:?} restarts={}",
        r.status,
        restarts(&r)
    );
    assert_eq!(
        restarts(&r),
        0,
        "an unchanged config must not restart the service"
    );
    assert_eq!(find(&r, "foo_conf").change, Change::None);
    // Changed file: exactly one restart, by the handler, after the file.
    let differs = host_with_foo_installed().with_fs_file("/etc/foo/foo.conf", "key = OLD\n");
    let r = run_recipe_fake(&p, Mode::Apply, true, differs);
    eprintln!("restart/changed: {:?} restarts={}", r.status, restarts(&r));
    assert_eq!(restarts(&r), 1);
}

#[test]
fn without_notify_a_changed_config_never_restarts_the_service() {
    // depends_on is ORDER, not "restart when the dependency changes". A service whose config changes but
    // which has no notify keeps running the old configuration. This is the gap the demo recipes close with
    // explicit notify lists (verified separately for every config file).
    let body = CHAIN.replace("    notify: [restart_foo]\n", "");
    let p = recipe("no-notify", &body);
    let differs = host_with_foo_installed().with_fs_file("/etc/foo/foo.conf", "key = OLD\n");
    let r = run_recipe_fake(&p, Mode::Apply, true, differs);
    assert_eq!(restarts(&r), 0);
    assert_eq!(find(&r, "foo_conf").change, Change::Changed);
}

#[test]
fn a_stopped_or_disabled_service_is_started_and_enabled_by_the_service_resource() {
    let p = recipe("svc-state", CHAIN);
    let stopped = host_with_foo_installed()
        .with_service("foo", ("loaded", "inactive", "disabled"))
        .with_fs_file("/etc/foo/foo.conf", "key = value\n");
    let r = run_recipe_fake(&p, Mode::Plan, true, stopped.clone());
    assert_eq!(find(&r, "svc_foo").change, Change::Changed);
    let a = audit(&p, stopped);
    let s = a.resources.iter().find(|x| x.id == "svc_foo").unwrap();
    assert_eq!(s.status, AuditResourceStatus::Drift);
}

#[test]
fn a_converged_host_plans_no_change_and_audits_compliant() {
    let p = recipe("converged", CHAIN);
    let ok = host_with_foo_installed()
        .with_fs_file("/etc/foo/foo.conf", "key = value\n")
        .with_fs_dir("/var/lib/foo");
    let r = run_recipe_fake(&p, Mode::Plan, true, ok.clone());
    eprintln!(
        "converged plan: {:?} {:?}",
        r.status,
        r.resources
            .iter()
            .map(|x| (&x.id, x.change))
            .collect::<Vec<_>>()
    );
    assert!(r.resources.iter().all(|x| x.change == Change::None));
    let a = audit(&p, ok);
    for x in &a.resources {
        assert_eq!(
            x.status,
            AuditResourceStatus::Compliant,
            "{}: {:?}",
            x.id,
            x.reason
        );
    }
}

#[test]
fn a_missing_parent_directory_is_not_noticed_by_plan_but_stops_apply() {
    // package -> directory/file: the RPM creates /etc/foo; the recipe's file lives in it. On a host without the
    // directory plan still reports the file as a plain change (it does not look at the parent), and apply
    // fails when it reaches the file. Real hosts have the directory after the package install; the recipes
    // also declare `directory` resources for every path they write so that the order is explicit.
    let p = recipe("pkg-dir", CHAIN);
    let bare = || {
        FakeTarget::rocky10()
            .with_fake_fs()
            .as_root()
            .with_fs_dir("/etc")
    };
    let plan = run_recipe_fake(&p, Mode::Plan, true, bare());
    assert!(matches!(
        plan.status,
        AggregateStatus::Success | AggregateStatus::Indeterminate
    ));
    assert_eq!(find(&plan, "foo_conf").change, Change::Changed);
    let apply = try_run_recipe_fake(&p, Mode::Apply, true, bare());
    match apply {
        Err(e) => eprintln!("pkg-dir apply: error: {}", e.message),
        Ok(r) => {
            eprintln!(
                "pkg-dir apply: {:?} {:?}",
                r.status,
                r.resources
                    .iter()
                    .map(|x| (&x.id, x.execution, &x.reason))
                    .collect::<Vec<_>>()
            );
            assert_ne!(
                r.status,
                AggregateStatus::Success,
                "writing into a missing directory must not succeed"
            );
        }
    }
}

const ACCOUNTS: &str = r#"
version: 1
resources:
  - id: grp_foo
    type: group
    with: { name: foo, state: present }
  - id: usr_foo
    type: user
    depends_on: [grp_foo]
    with: { name: foo, group: foo, state: present, shell: /sbin/nologin, system: true }
  - id: foo_conf
    type: file
    depends_on: [usr_foo]
    with: { path: /etc/foo/foo.conf, content: "k=v\n", owner: foo, group: foo, mode: "0640" }
"#;

#[test]
fn a_user_and_group_resource_defers_the_file_it_owns_instead_of_failing_plan() {
    // user/group -> file (F-3): a file owned by an account that a user/group RESOURCE creates is deferred in plan
    // on a host where the account does not exist yet, because the producer runs earlier in the execution order.
    let p = recipe("acct-res", ACCOUNTS);
    let r = run_recipe_fake(&p, Mode::Plan, true, host());
    eprintln!(
        "acct-res: {:?} {:?}",
        r.status,
        r.resources
            .iter()
            .map(|x| (&x.id, x.change, x.unknown, &x.reason))
            .collect::<Vec<_>>()
    );
    assert!(matches!(
        r.status,
        AggregateStatus::Success | AggregateStatus::Indeterminate
    ));
    // the group is planned; the user (whose group is created by a dependency) and the file owned by it are
    // deferred (Unknown), not errors and not guesses
    assert_eq!(find(&r, "grp_foo").change, Change::Changed);
    assert!(find(&r, "usr_foo").unknown);
    assert!(find(&r, "foo_conf").unknown);
}

#[test]
fn plan_apply_and_audit_agree_on_which_resources_differ() {
    // A host with the package and the account but a stale config and a stopped service. Plan lists the changes,
    // apply performs exactly those, audit reports exactly those as drift.
    let p = recipe("consistency", CHAIN);
    let drifted = host_with_foo_installed()
        .with_service("foo", ("loaded", "inactive", "disabled"))
        .with_fs_file("/etc/foo/foo.conf", "key = OLD\n");
    let plan = run_recipe_fake(&p, Mode::Plan, true, drifted.clone());
    let changed = |r: &sinter::engine::RunReport| -> Vec<String> {
        r.resources
            .iter()
            .filter(|x| x.change != Change::None)
            .map(|x| x.id.clone())
            .collect()
    };
    let apply = run_recipe_fake(&p, Mode::Apply, true, drifted.clone());
    assert_eq!(apply.status, AggregateStatus::Success);
    assert_eq!(changed(&plan), changed(&apply), "plan and apply disagree");
    assert_eq!(
        changed(&plan),
        vec!["foo_conf".to_string(), "svc_foo".to_string()]
    );
    let a = audit(&p, drifted);
    let drift: Vec<String> = a
        .resources
        .iter()
        .filter(|x| x.status == AuditResourceStatus::Drift)
        .map(|x| x.id.clone())
        .collect();
    assert_eq!(drift, changed(&plan), "audit and plan disagree");
}

#[test]
fn a_partly_converged_host_after_a_failed_apply_replans_only_what_is_left() {
    // Partial failure: the package and the config made it, the service did not. A rerun plans only the service
    // (and, because nothing changed in the config, does not restart anything else).
    let p = recipe("partial", CHAIN);
    let half = host_with_foo_installed()
        .with_service("foo", ("loaded", "inactive", "disabled"))
        .with_fs_file("/etc/foo/foo.conf", "key = value\n");
    let r = run_recipe_fake(&p, Mode::Apply, true, half);
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(find(&r, "pkg_foo").change, Change::None);
    assert_eq!(find(&r, "foo_conf").change, Change::None);
    assert_eq!(find(&r, "svc_foo").change, Change::Changed);
    assert_eq!(restarts(&r), 0, "an unchanged config must not restart");
}

#[test]
fn plan_refuses_a_missing_parent_unless_a_changing_dependency_could_create_it() {
    // Without any dependency a file in a missing directory is a plan error. With a package dependency that
    // plan sees as changing (to be installed), plan tolerates the missing parent, because the package may
    // create it, and apply checks when it gets there (test above). The OpenStack recipes rely on this: the
    // RPMs create /etc/nova, /etc/neutron, ... and every file depends on its package.
    let body = r#"
version: 1
resources:
  - id: lonely
    type: file
    with: { path: /etc/nowhere/x.conf, content: "x\n", owner: root, group: root, mode: "0644" }
"#;
    let p = recipe("lonely", body);
    let bare = FakeTarget::rocky10()
        .with_fake_fs()
        .as_root()
        .with_fs_dir("/etc");
    assert!(try_run_recipe_fake(&p, Mode::Plan, true, bare).is_err());
}

#[test]
fn a_resource_skipped_by_when_silently_blocks_its_dependents_so_recipes_never_depend_on_a_conditional_one(
) {
    // `when: false` is not "satisfied": a dependent of a skipped resource is NOT run (blocked_by_dependency) and,
    // by design (DESIGN.md: a block caused solely by a condition-skipped producer does not fail the run), the
    // overall status is still success. The dependent silently does not happen. The OpenStack recipes therefore
    // keep `when` only on a leaf check (`preflight_kvm`) that nothing depends on (pinned below).
    let body = r#"
version: 1
vars:
  on: { value: "no" }
resources:
  - id: maybe
    type: file
    when: 'vars.on == "yes"'
    with: { path: /etc/foo/maybe.conf, content: "x\n", owner: root, group: root, mode: "0644" }
  - id: dependent
    type: file
    depends_on: [maybe]
    with: { path: /etc/foo/dep.conf, content: "x\n", owner: root, group: root, mode: "0644" }
"#;
    let p = recipe("when-skip", body);
    let r = run_recipe_fake(&p, Mode::Apply, true, host());
    eprintln!(
        "when-skip: {:?} {:?}",
        r.status,
        r.resources
            .iter()
            .map(|x| (&x.id, x.execution, x.disposition))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        find(&r, "maybe").disposition,
        Disposition::SkippedByCondition
    );
    assert_eq!(find(&r, "dependent").execution, Execution::NotRun);
    assert_eq!(r.status, AggregateStatus::Success);
}

#[test]
fn no_openstack_recipe_depends_on_a_resource_that_has_a_when_condition() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/openstack");
    // textual check over every recipe file: collect ids that carry `when:`, then look for them in depends_on
    let mut conditional: Vec<String> = Vec::new();
    let mut texts: Vec<String> = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "yaml") {
                let t = std::fs::read_to_string(&p).unwrap();
                let mut id = String::new();
                for l in t.lines() {
                    if let Some(x) = l.trim_start().strip_prefix("- id: ") {
                        id = x.trim().to_string();
                    }
                    if l.starts_with("    when:") {
                        conditional.push(id.clone());
                    }
                }
                texts.push(t);
            }
        }
    }
    assert!(!conditional.is_empty());
    for id in &conditional {
        for t in &texts {
            for l in t.lines().filter(|l| l.contains("depends_on:")) {
                let inner = l.split('[').nth(1).unwrap_or("").trim_end_matches(']');
                assert!(
                    !inner.split(',').any(|d| d.trim() == id),
                    "{id} has a when condition and is depended on: {l}"
                );
            }
        }
    }
}

#[test]
fn a_restart_owed_to_a_changed_config_is_lost_when_the_apply_fails_before_the_handlers_run() {
    // Handlers run once at the END of a successful apply. If a later resource fails, the config file is already
    // written but the service is never restarted, and a rerun sees an unchanged file and notifies nobody: the
    // service keeps running the old configuration until something else restarts it. Sinter has no notion of a
    // "stale" service. (Class D: automatic restart/reload on config change would need a durable record.) The
    // OpenStack acceptance run therefore checks, after any failed apply, that the services were restarted.
    let body = CHAIN.to_string()
        + r#"
  - id: later_failure
    type: command
    depends_on: [svc_foo]
    with: { program: /usr/local/bin/missing-step }
"#;
    let p = recipe("lost-restart", &body);
    let differs = host_with_foo_installed().with_fs_file("/etc/foo/foo.conf", "key = OLD\n");
    let r1 = run_recipe_fake(&p, Mode::Apply, true, differs);
    assert_eq!(r1.status, AggregateStatus::ApplyFailed);
    assert_eq!(find(&r1, "foo_conf").change, Change::Changed);
    assert_eq!(restarts(&r1), 0, "handlers do not run after a failed apply");
    // the rerun: the file now matches, so nothing is notified
    let rerun_host = host_with_foo_installed().with_fs_file("/etc/foo/foo.conf", "key = value\n");
    let r2 = run_recipe_fake(&p, Mode::Apply, true, rerun_host);
    assert_eq!(find(&r2, "foo_conf").change, Change::None);
    assert_eq!(
        restarts(&r2),
        0,
        "the lost restart is not made up on the rerun"
    );
}
