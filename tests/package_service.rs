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
    let _svc = lock_service();
    let dir = trusted_root("pkg-svc");
    // Use ssh as a guaranteed-present service/package pair.
    let recipe = write_recipe(
        &dir,
        "r.yaml",
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
      name: ssh
      state: running
      enabled: true
    depends_on: [p]
"#,
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
      name: ssh
      state: {state}
      enabled: {enabled}
"#
            ),
        );
        let r = run_recipe(&recipe, Mode::Apply, true);
        assert_success(&r);
        assert_eq!(find(&r, "s").verification, Verification::Verified);
        // restore to running
        let restore = write_recipe(
            &dir,
            "r2.yaml",
            r#"version: 1
resources:
  - id: s
    type: service
    with:
      name: ssh
      state: running
      enabled: true
"#,
        );
        let rr = run_recipe(&restore, Mode::Apply, true);
        assert_success(&rr);
    }
}
