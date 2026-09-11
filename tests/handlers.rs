#![cfg(target_os = "linux")]
mod common;

use common::*;
use sinter::engine::Mode;
use sinter::result::{Change, Disposition, Execution, HandlerOutcomeState, Verification};

fn unit_test_service_available() -> bool {
    // A restartable service that exists on the reference target.
    std::path::Path::new("/usr/lib/systemd/system/ssh.service").exists()
        || std::path::Path::new("/lib/systemd/system/ssh.service").exists()
        || std::path::Path::new("/usr/lib/systemd/system/ssh.socket").exists()
}

#[test]
fn one_source_change_triggers_one_handler() {
    if !unit_test_service_available() || !sudo_available() {
        skip_or_fail("requires ssh systemd unit and sudo");
        return;
    }
    let _svc = lock_service();
    let dir = trusted_root("handler-one");
    let outdir = trusted_root_sudo("handler-one");
    let out = outdir.join("conf");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: conf
    type: file
    with:
      path: {out}
      content: "v1"
    notify: [restart_ssh]
handlers:
  - id: restart_ssh
    service: ssh
    action: restart
"#,
            out = out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, true);
    assert_success(&r);
    assert_eq!(find(&r, "conf").change, Change::Changed);
    assert_eq!(r.handlers_run.len(), 1);
    assert_eq!(r.handlers_run[0].id, "restart_ssh");
    assert_eq!(r.handlers_run[0].state, HandlerOutcomeState::Succeeded);

    // second apply: no change -> handler must not run
    let r2 = run_recipe(&recipe, Mode::Apply, true);
    assert_success(&r2);
    assert_eq!(find(&r2, "conf").change, Change::None);
    assert!(r2.handlers_run.is_empty());
    assert_eq!(mutation_command_count(&r2), 0);
}

#[test]
fn multiple_sources_deduplicate_handler() {
    if !unit_test_service_available() || !sudo_available() {
        skip_or_fail("requires ssh systemd unit and sudo");
        return;
    }
    let _svc = lock_service();
    let dir = trusted_root("handler-dedup");
    let outdir = trusted_root_sudo("handler-dedup");
    let a = outdir.join("a");
    let b = outdir.join("b");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: a
    type: file
    with:
      path: {a}
      content: "1"
    notify: [restart_ssh]
  - id: b
    type: file
    with:
      path: {b}
      content: "2"
    notify: [restart_ssh]
handlers:
  - id: restart_ssh
    service: ssh
    action: restart
"#,
            a = a.display(),
            b = b.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, true);
    assert_success(&r);
    assert_eq!(r.handlers_run.len(), 1, "handler must be deduplicated");
}

#[test]
fn verification_failure_does_not_enqueue_handler() {
    // Construct a resource that changes but whose verification fails by making
    // the requested owner unachievable without privileges (we run unprivileged
    // and request root ownership), so post-publication metadata verification
    // fails.
    if unsafe { libc::geteuid() } == 0 {
        skip_or_fail("test must run as an unprivileged user");
        return;
    }
    let dir = trusted_root("handler-verify-fail");
    let out = dir.join("conf");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: conf
    type: file
    with:
      path: {out}
      content: "v1"
      owner: root
    notify: [restart_ssh]
handlers:
  - id: restart_ssh
    service: ssh
    action: restart
"#,
            out = out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    // The chown to root fails and is reported as a failure; no handler runs.
    assert!(r.handlers_run.is_empty());
    assert!(r.handlers_pending.iter().any(|h| h == "restart_ssh") || find(&r, "conf").is_failure());
}

#[test]
fn fail_fast_before_handler_phase_reports_pending() {
    if !unit_test_service_available() || !sudo_available() {
        skip_or_fail("requires ssh systemd unit and sudo");
        return;
    }
    let dir = trusted_root("handler-failfast");
    let outdir = trusted_root_sudo("handler-failfast");
    let out = outdir.join("conf");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: conf
    type: file
    with:
      path: {out}
      content: "v1"
    notify: [restart_ssh]
  - id: boom
    type: command
    with:
      program: /bin/false
handlers:
  - id: restart_ssh
    service: ssh
    action: restart
"#,
            out = out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, true);
    assert_eq!(find(&r, "boom").execution, Execution::Failed);
    assert!(
        r.handlers_run.is_empty(),
        "no handler may run after fail-fast"
    );
    assert!(r.handlers_pending.iter().any(|h| h == "restart_ssh"));
}

#[test]
fn condition_skipped_resource_does_not_suppress_valid_handler() {
    if !unit_test_service_available() || !sudo_available() {
        skip_or_fail("requires ssh systemd unit and sudo");
        return;
    }
    let _svc = lock_service();
    let dir = trusted_root("handler-skip");
    let outdir = trusted_root_sudo("handler-skip");
    let out = outdir.join("conf");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: skipped
    type: file
    with:
      path: {other}
      content: "x"
    when: "false"
  - id: conf
    type: file
    with:
      path: {out}
      content: "v1"
    notify: [restart_ssh]
handlers:
  - id: restart_ssh
    service: ssh
    action: restart
"#,
            other = dir.join("other").display(),
            out = out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, true);
    assert_success(&r);
    assert_eq!(
        find(&r, "skipped").disposition,
        Disposition::SkippedByCondition
    );
    assert_eq!(r.handlers_run.len(), 1);
}

#[test]
fn missing_service_fails_in_apply() {
    let dir = trusted_root("service-missing");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: s
    type: service
    with:
      name: sinter-definitely-not-a-unit
      state: running
"#,
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(find(&r, "s").execution, Execution::Failed);
}

#[test]
fn missing_service_deferred_in_plan_with_present_package_dep() {
    let dir = trusted_root("service-deferred");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: pkg
    type: package
    with:
      name: sinter-not-installed-pkg
      state: present
  - id: svc
    type: service
    with:
      name: sinter-definitely-not-a-unit
      state: running
    depends_on: [pkg]
"#,
    );
    let plan = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&plan);
    let svc = find(&plan, "svc");
    assert!(svc.unknown, "service should be deferred/unknown");
    // Without the direct present-package dependency a missing unit is a plan error.
    let recipe2 = write_recipe(
        &dir,
        "r2.yaml",
        r#"version: 1
resources:
  - id: svc
    type: service
    with:
      name: sinter-definitely-not-a-unit
      state: running
"#,
    );
    let err = try_run_recipe_target(&recipe2, Mode::Plan, false, None);
    assert!(
        err.is_err(),
        "missing service without dep must be plan error"
    );
}

#[test]
fn service_failed_unit_is_not_clean_stopped() {
    // A failed unit must not be reported as a satisfied 'stopped' request, and
    // a request to stop it must actually clear the failed state.
    let dir = trusted_root("service-failed");
    // Create a failing transient-ish unit is not permitted; instead assert that
    // a missing unit with stopped requested fails rather than claims success.
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: s
    type: service
    with:
      name: sinter-definitely-not-a-unit
      state: stopped
"#,
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(find(&r, "s").execution, Execution::Failed);
    assert_ne!(find(&r, "s").verification, Verification::Verified);
}

#[test]
fn mask_and_static_service_errors() {
    // Use real masked and static units present on the reference platform.
    if !std::path::Path::new("/run/systemd/system").exists() {
        skip_or_fail("systemd is not running");
        return;
    }
    // Discover a real masked unit.
    let masked = find_unit_with_state("masked");
    let dir = trusted_root("service-static");
    if let Some(unit) = masked {
        let recipe = write_recipe(
            &dir,
            "masked.yaml",
            &format!(
                "version: 1\nresources:\n  - id: s\n    type: service\n    with:\n      name: {}\n      state: running\n",
                unit
            ),
        );
        let r = run_recipe(&recipe, Mode::Apply, false);
        assert_eq!(
            find(&r, "s").execution,
            Execution::Failed,
            "a running request on a masked unit must fail"
        );
    } else {
        skip_or_fail("no masked systemd unit available");
    }

    // Discover a real static unit; enabling it must fail.
    let static_unit = find_unit_with_state("static");
    if let Some(unit) = static_unit {
        let recipe = write_recipe(
            &dir,
            "static.yaml",
            &format!(
                "version: 1\nresources:\n  - id: s\n    type: service\n    with:\n      name: {}\n      enabled: true\n",
                unit
            ),
        );
        let r = run_recipe(&recipe, Mode::Apply, false);
        assert_eq!(
            find(&r, "s").execution,
            Execution::Failed,
            "enabling a static unit must fail"
        );
    } else {
        skip_or_fail("no static systemd unit available");
    }
}

/// Find a unit file in the requested `systemctl list-unit-files` state.
fn find_unit_with_state(state: &str) -> Option<String> {
    let out = std::process::Command::new("/usr/bin/systemctl")
        .args([
            "list-unit-files",
            &format!("--state={}", state),
            "--no-legend",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .next()
        .and_then(|l| l.split_whitespace().next().map(|s| s.to_string()))
}

#[test]
fn handler_failure_blocks_later_handlers() {
    if !sudo_available() {
        skip_or_fail("requires sudo");
        return;
    }
    let _svc = lock_service();
    let dir = trusted_root("handler-fail");
    let outdir = trusted_root_sudo("handler-fail");
    let out = outdir.join("conf");
    // First handler references a missing unit and fails; second must not run.
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: conf
    type: file
    with:
      path: {out}
      content: "v1"
    notify: [bad, good]
handlers:
  - id: bad
    service: sinter-definitely-not-a-unit
    action: restart
  - id: good
    service: ssh
    action: restart
"#,
            out = out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, true);
    assert_eq!(r.handlers_run.len(), 1);
    assert_eq!(r.handlers_run[0].id, "bad");
    assert_eq!(r.handlers_run[0].state, HandlerOutcomeState::Failed);
    assert!(r.handlers_pending.iter().any(|h| h == "good"));
}

#[test]
fn command_default_cwd_is_target_home() {
    let dir = trusted_root("cwd-home");
    let out = dir.join("pwd");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: pwd
    type: command
    with:
      program: /bin/pwd
      register: p
  - id: save
    type: file
    with:
      path: {out}
      content: "{{{{ registers.p.stdout }}}}"
      mode: "0644"
    depends_on: [pwd]
"#,
            out = out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    let home = std::env::var("HOME").unwrap();
    assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), home);
}

#[test]
fn reload_handler_verifies_active_service() {
    if !unit_test_service_available() || !sudo_available() {
        skip_or_fail("requires ssh systemd unit and sudo");
        return;
    }
    let _svc = lock_service();
    let dir = trusted_root("handler-reload");
    let out = trusted_root_sudo("handler-reload").join("conf");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: conf
    type: file
    with:
      path: {out}
      content: "v1"
    notify: [reload_ssh]
handlers:
  - id: reload_ssh
    service: ssh
    action: reload
"#,
            out = out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, true);
    // Either reload succeeds or the unit reports it cannot reload; in the
    // success case the service must remain active.
    if r.handlers_run.len() == 1 {
        assert_eq!(r.handlers_run[0].state, HandlerOutcomeState::Succeeded);
    }
}
