#![cfg(target_os = "linux")]
mod common;

use common::*;
use sinter::engine::Mode;
use sinter::result::{Change, Execution, Verification};

fn apt_available() -> bool {
    std::path::Path::new("/usr/bin/apt-get").exists()
        && std::process::Command::new("sudo")
            .args(["-n", "true"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
}

#[test]
fn package_install_remove_verify_idempotent() {
    if !apt_available() {
        skip_or_fail("requires apt and sudo");
        return;
    }
    // The whole test performs real apt-get mutations (install, remove, and
    // their verification re-observations), which take the shared dpkg
    // frontend lock. Serialize against every other such test so the default
    // parallel test runner cannot make them contend (RA2-02).
    let _pkg_db = lock_package_database();
    let dir = trusted_root("package");
    // Use a small package that is commonly absent then removable.
    let pkg = std::env::var("SINTER_TEST_PACKAGE").unwrap_or_else(|_| "cowsay".to_string());
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: {}\n      state: present\n",
            pkg
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, true);
    assert_success(&r);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Succeeded);
    assert_eq!(p.verification, Verification::Verified);

    // second apply: zero mutations
    let r2 = run_recipe(&recipe, Mode::Apply, true);
    assert_success(&r2);
    assert_eq!(find(&r2, "p").change, Change::None);
    assert_eq!(mutation_command_count(&r2), 0);

    // remove
    let recipe2 = write_recipe(
        &dir,
        "r2.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: {}\n      state: absent\n",
            pkg
        ),
    );
    let r3 = run_recipe(&recipe2, Mode::Apply, true);
    assert_success(&r3);
    assert_eq!(find(&r3, "p").change, Change::Changed);
    let r4 = run_recipe(&recipe2, Mode::Apply, true);
    assert_success(&r4);
    assert_eq!(mutation_command_count(&r4), 0);
}

#[test]
fn package_plan_does_not_mutate() {
    if !apt_available() {
        skip_or_fail("requires apt and sudo");
        return;
    }
    let dir = trusted_root("package-plan");
    let pkg = std::env::var("SINTER_TEST_PACKAGE").unwrap_or_else(|_| "cowsay".to_string());
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: {}\n      state: present\n",
            pkg
        ),
    );
    let r = run_recipe(&recipe, Mode::Plan, true);
    assert_success(&r);
    assert_eq!(mutation_command_count(&r), 0, "{:?}", r.commands);
}

#[test]
fn package_apply_then_service_reobservation() {
    if !apt_available() {
        skip_or_fail("requires apt and sudo");
        return;
    }
    // Verify that after installing a package providing a unit, the service
    // observation reflects the fresh state rather than a stale plan observation.
    // `openssh-server` is guaranteed present, but the Apply path could
    // install it if it were missing, so this test is inside the package
    // mutation critical section too (RA2-02). Lock order is package database
    // before service.
    let _pkg_db = lock_package_database();
    let _svc = lock_service();
    let dir = trusted_root("pkg-svc");
    // Use ssh as a guaranteed-present service/package pair.
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: p
    type: package
    with:
      name: openssh-server
      state: present
  - id: s
    type: service
    with:
      name: {svc}
      state: running
      enabled: true
    depends_on: [p]
"#,
            svc = local_ssh_unit()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, true);
    assert_success(&r);
    assert_eq!(find(&r, "s").verification, Verification::Verified);
    // second apply: package unchanged, service unchanged, no mutations
    let r2 = run_recipe(&recipe, Mode::Apply, true);
    assert_success(&r2);
    assert_eq!(mutation_command_count(&r2), 0, "{:?}", r2.commands);
}

#[test]
fn service_all_four_state_enabled_combinations() {
    if !apt_available() {
        skip_or_fail("requires apt and sudo");
        return;
    }
    let _svc = lock_service();
    let dir = trusted_root("svc-combos");
    for (state, enabled) in [
        ("running", true),
        ("running", false),
        ("stopped", true),
        ("stopped", false),
    ] {
        let recipe = write_recipe(
            &dir,
            "r.yaml",
            &format!(
                r#"version: 1
resources:
  - id: s
    type: service
    with:
      name: {svc}
      state: {state}
      enabled: {enabled}
"#,
                svc = local_ssh_unit()
            ),
        );
        let r = run_recipe(&recipe, Mode::Apply, true);
        assert_success(&r);
        assert_eq!(find(&r, "s").verification, Verification::Verified);
        // Restore to running/enabled. ssh is socket-activated: `enable` alone
        // can leave the unit inactive, so first request a clean stop then
        // running so the product is allowed to issue start.
        let svc_name = local_ssh_unit();
        let restore_stop = write_recipe(
            &dir,
            "r1.yaml",
            &format!(
                r#"version: 1
resources:
  - id: s
    type: service
    with:
      name: {svc}
      state: stopped
      enabled: true
"#,
                svc = svc_name
            ),
        );
        let _ = run_recipe(&restore_stop, Mode::Apply, true);
        let restore = write_recipe(
            &dir,
            "r2.yaml",
            &format!(
                r#"version: 1
resources:
  - id: s
    type: service
    with:
      name: {svc}
      state: running
      enabled: true
"#,
                svc = svc_name
            ),
        );
        let rr = run_recipe(&restore, Mode::Apply, true);
        assert_success(&rr);
    }
}

/// Controlled fixture: a unit that is initially not-found appears after an
/// earlier resource, and the dependent service must re-observe the fresh state
/// rather than fail on the stale missing-unit observation.
#[test]
fn previously_absent_unit_appears_and_service_verifies() {
    if !sudo_available() || !std::path::Path::new("/run/systemd/system").exists() {
        skip_or_fail("requires systemd and passwordless sudo");
        return;
    }
    let unit = "sinter-r4-new-unit.service";
    let unit_path = format!("/etc/systemd/system/{}", unit);
    // Ensure the unit is currently absent.
    let _ = std::process::Command::new("sudo")
        .args(["-n", "/bin/sh", "-c"])
        .arg(format!(
            "systemctl stop {unit} >/dev/null 2>&1; systemctl disable {unit} >/dev/null 2>&1; systemctl reset-failed {unit} >/dev/null 2>&1; rm -f {unit_path}; systemctl daemon-reload",
            unit = unit
        ))
        .status();
    let _svc = lock_service();
    let dir = trusted_root("absent-unit-appears");
    // Unit body is written by the test, then a command resource "installs" it
    // (controlled fixture standing in for a package that ships a new unit).
    let body = dir.join("unit");
    std::fs::write(
        &body,
        "[Unit]\nDescription=sinter r4 new unit\n[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\n",
    )
    .unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: install
    type: command
    with:
      program: /bin/sh
      args:
        - -c
        - "cp {src} {dst} && systemctl daemon-reload"
  - id: svc
    type: service
    with:
      name: {unit}
      state: running
    depends_on: [install]
"#,
            src = body.display(),
            dst = unit_path,
            unit = unit
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, true);
    assert_success(&r);
    let svc = find(&r, "svc");
    assert_eq!(svc.execution, Execution::Succeeded);
    assert_eq!(svc.verification, Verification::Verified);
    // Cleanup
    let _ = std::process::Command::new("sudo")
        .args(["-n", "/bin/sh", "-c"])
        .arg(format!(
            "systemctl stop {unit} >/dev/null 2>&1; systemctl disable {unit} >/dev/null 2>&1; rm -f {unit_path}; systemctl daemon-reload",
            unit = unit,
            unit_path = unit_path
        ))
        .status();
}

/// apt install succeeds, then post-mutation observation is Indeterminate.
/// Known mutation must remain Change::Changed, never weakened to Possible.
#[test]
fn package_install_success_then_reobserve_indeterminate_keeps_changed() {
    if !apt_available() {
        skip_or_fail("requires apt and sudo");
        return;
    }
    // The pre-test `apt-get remove`, the install mutation, and the post-test
    // cleanup all take the shared dpkg frontend lock, so the advisory guard is
    // acquired before the first apt-get call and held to the end of the test
    // (RA2-02).
    let _pkg_db = lock_package_database();
    let dir = trusted_root("r7-pkg-indet");
    let pkg = std::env::var("SINTER_TEST_PACKAGE").unwrap_or_else(|_| "cowsay".to_string());
    // Ensure package is absent so the mutation path is reached.
    let _ = std::process::Command::new("sudo")
        .args(["-n", "apt-get", "remove", "-y", &pkg])
        .status();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: {}\n      state: present\n",
            pkg
        ),
    );
    let r = run_recipe_fault_sudo(
        &recipe,
        Mode::Apply,
        "package_reobserve_indeterminate",
        true,
    );
    let p = find(&r, "p");
    // Prove apt mutation was actually dispatched after initial observation.
    assert!(
        r.commands.iter().any(|c| c.program.ends_with("apt-get")),
        "test must reach the apt mutation path: {:?}",
        r.commands
    );
    // Prove the injected post-mutation observation fault fired.
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("injected package re-observation indeterminate"),
        "injected fault must fire: {:?}",
        p.reason
    );
    assert_eq!(
        p.change,
        Change::Changed,
        "known apt mutation must remain Changed: {:?}",
        p
    );
    assert_eq!(p.execution, Execution::Indeterminate);
    // Cleanup
    let _ = std::process::Command::new("sudo")
        .args(["-n", "apt-get", "remove", "-y", &pkg])
        .status();
}

/// apt install succeeds, then post-mutation observation fails ordinarily.
/// Known mutation must remain Change::Changed.
#[test]
fn package_install_success_then_reobserve_fail_keeps_changed() {
    if !apt_available() {
        skip_or_fail("requires apt and sudo");
        return;
    }
    // Same critical section as the indeterminate variant: cleanup, mutation,
    // and final cleanup all touch the shared dpkg frontend lock (RA2-02).
    let _pkg_db = lock_package_database();
    let dir = trusted_root("r7-pkg-reobs-fail");
    let pkg = std::env::var("SINTER_TEST_PACKAGE").unwrap_or_else(|_| "cowsay".to_string());
    let _ = std::process::Command::new("sudo")
        .args(["-n", "apt-get", "remove", "-y", &pkg])
        .status();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: {}\n      state: present\n",
            pkg
        ),
    );
    let r = run_recipe_fault_sudo(&recipe, Mode::Apply, "package_reobserve_fail", true);
    let p = find(&r, "p");
    assert!(
        r.commands.iter().any(|c| c.program.ends_with("apt-get")),
        "test must reach the apt mutation path: {:?}",
        r.commands
    );
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("injected package re-observation failure"),
        "injected fault must fire: {:?}",
        p.reason
    );
    assert_eq!(
        p.change,
        Change::Changed,
        "known apt mutation must remain Changed: {:?}",
        p
    );
    assert_eq!(p.execution, Execution::Failed);
    let _ = std::process::Command::new("sudo")
        .args(["-n", "apt-get", "remove", "-y", &pkg])
        .status();
}
