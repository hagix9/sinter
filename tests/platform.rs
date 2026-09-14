//! Deterministic platform/backend selection and dnf-behavior tests.
//!
//! These tests run against a scripted in-process target (FakeTarget) so they
//! exercise the production engine/model/targetfs/result path on any host,
//! without requiring a real Rocky Linux machine. Real-host behavior still
//! requires the documented Rocky 9 x86_64 validation run.
mod common;

use common::*;
use sinter::engine::{AggregateStatus, Mode};
use sinter::error::ErrorKind;
use sinter::executor::{Completion, FakeTarget};
use sinter::result::{Change, Disposition, Execution, Verification};

fn pkg_recipe(dir: &std::path::Path, name: &str, state: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: {}\n      state: {}\n",
            name, state
        ),
    )
}

fn commands_with<'a>(
    report: &'a sinter::engine::RunReport,
    prog: &str,
) -> Vec<&'a sinter::executor::CommandRecord> {
    report
        .commands
        .iter()
        .filter(|c| c.program == prog)
        .collect()
}

#[test]
fn ubuntu_target_selects_apt_backend() {
    let dir = trusted_root("plat-ubuntu");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake(&recipe, Mode::Plan, false, FakeTarget::ubuntu2404());
    let p = find(&r, "p");
    // Absent package on apt platform plans a change without mutation.
    assert_eq!(p.change, Change::Changed);
    assert!(!commands_with(&r, "/usr/bin/dpkg-query").is_empty());
    assert!(commands_with(&r, "/usr/bin/rpm").is_empty());
    assert!(commands_with(&r, "/usr/bin/dnf").is_empty());
    assert_eq!(mutation_command_count(&r), 0);
}

#[test]
fn rocky9_target_selects_dnf_backend() {
    let dir = trusted_root("plat-rocky");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake(&recipe, Mode::Plan, false, FakeTarget::rocky9());
    let p = find(&r, "p");
    assert_eq!(p.change, Change::Changed);
    assert!(!commands_with(&r, "/usr/bin/rpm").is_empty());
    assert!(commands_with(&r, "/usr/bin/dpkg-query").is_empty());
    assert_eq!(r.facts.os_family, "redhat");
    assert_eq!(mutation_command_count(&r), 0);
}

#[test]
fn unsupported_os_with_package_resource_fails_safely() {
    let dir = trusted_root("plat-unsupported");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let err = match try_run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::unsupported()) {
        Err(e) => e,
        Ok(_) => panic!("package recipe on unsupported OS must not run"),
    };
    // Capability error, not a silent backend guess.
    assert_eq!(err.kind, ErrorKind::Connect);
    assert!(
        err.message.contains("no supported package manager"),
        "unexpected error: {}",
        err.message
    );
}

#[test]
fn unsupported_os_without_package_resources_still_runs() {
    // A recipe that never manages packages must not require a package
    // backend: non-package recipes keep working on unrecognized platforms.
    let dir = trusted_root("plat-unsupported-nopkg");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::unsupported());
    assert_success(&r);
}

#[test]
fn supported_family_missing_dnf_is_capability_error() {
    let dir = trusted_root("plat-nodnf");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.executables.remove("/usr/bin/dnf");
    let err = match try_run_recipe_fake(&recipe, Mode::Apply, false, t) {
        Err(e) => e,
        Ok(_) => panic!("missing dnf must be a capability error"),
    };
    assert_eq!(err.kind, ErrorKind::Connect);
    assert!(err.message.contains("/usr/bin/dnf"), "err: {}", err.message);
}

#[test]
fn dnf_observes_absent_and_installs() {
    let dir = trusted_root("plat-dnf-install");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::rocky9());
    assert_success(&r);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Succeeded);
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    let dnf = commands_with(&r, "/usr/bin/dnf");
    assert_eq!(dnf.len(), 1);
    assert_eq!(
        dnf[0].args,
        vec!["--setopt=metadata_expire=-1", "-y", "install", "nano"]
    );
    // Observation used rpm -q, never dpkg-query.
    assert!(commands_with(&r, "/usr/bin/dpkg-query").is_empty());
}

#[test]
fn dnf_observes_present_and_is_unchanged() {
    let dir = trusted_root("plat-dnf-present");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9().with_package("nano"),
    );
    assert_success(&r);
    let p = find(&r, "p");
    assert_eq!(p.change, Change::None);
    // No dnf mutation was dispatched on an already-satisfied target.
    assert!(commands_with(&r, "/usr/bin/dnf").is_empty());
    assert_eq!(mutation_command_count(&r), 0);
}

#[test]
fn dnf_removes_installed_package() {
    let dir = trusted_root("plat-dnf-remove");
    let recipe = pkg_recipe(&dir, "nano", "absent");
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9().with_package("nano"),
    );
    assert_success(&r);
    let p = find(&r, "p");
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    let dnf = commands_with(&r, "/usr/bin/dnf");
    assert_eq!(dnf.len(), 1);
    assert_eq!(
        dnf[0].args,
        vec!["--setopt=metadata_expire=-1", "-y", "remove", "nano"]
    );
}

#[test]
fn dnf_absent_already_absent_is_unchanged() {
    let dir = trusted_root("plat-dnf-already-absent");
    let recipe = pkg_recipe(&dir, "nano", "absent");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::rocky9());
    assert_success(&r);
    let p = find(&r, "p");
    assert_eq!(p.change, Change::None);
    assert!(commands_with(&r, "/usr/bin/dnf").is_empty());
    assert_eq!(mutation_command_count(&r), 0);
}

#[test]
fn dnf_failure_reports_failed_possible_and_stops() {
    let dir = trusted_root("plat-dnf-fail");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: present\n  - id: marker\n    type: command\n    with:\n      program: /bin/touch\n      args: [/tmp/plat-dnf-fail-marker]\n",
    );
    let mut t = FakeTarget::rocky9();
    t.manager_completion = Some(Completion::Exited(1));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    // A dispatched package mutation that failed is conservatively possible.
    assert_eq!(p.change, Change::Possible);
    assert_eq!(p.verification, Verification::Unknown);
    // Fail-fast: the later resource must not run.
    let marker = find(&r, "marker");
    assert_eq!(marker.disposition, Disposition::BlockedByFailFast);
    assert!(commands_with(&r, "/bin/touch").is_empty());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
}

#[test]
fn dnf_indeterminate_reports_possible() {
    let dir = trusted_root("plat-dnf-ind");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.manager_completion = Some(Completion::Indeterminate {
        started: true,
        reason: "lost response after dispatch".into(),
    });
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Indeterminate);
    assert_eq!(p.change, Change::Possible);
    assert_eq!(p.verification, Verification::Unknown);
    assert_eq!(r.status, AggregateStatus::Indeterminate);
}

#[test]
fn dnf_mutation_then_reobserve_failure_keeps_changed() {
    // A completed dnf mutation followed by a failed re-observation must keep
    // Change::Changed and fail the resource (mutation truth).
    let dir = trusted_root("plat-dnf-reobs");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake_fault(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9(),
        "package_reobserve_fail",
    );
    let p = find(&r, "p");
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.verification, Verification::Failed);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
}

#[test]
fn dnf_verification_mismatch_fails_and_blocks() {
    // Mutation dispatched successfully but the package is still absent at
    // re-observation: verification failure must fail the resource and
    // fail-fast must block later resources.
    let dir = trusted_root("plat-dnf-verify");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: present\n  - id: marker\n    type: command\n    with:\n      program: /bin/touch\n      args: [/tmp/plat-dnf-verify-marker]\n",
    );
    let mut t = FakeTarget::rocky9();
    // dnf exits 0 but never installs: verification must fail.
    t.manager_completion = Some(Completion::Exited(0));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Failed);
    let marker = find(&r, "marker");
    assert_eq!(marker.disposition, Disposition::BlockedByFailFast);
    assert!(commands_with(&r, "/bin/touch").is_empty());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
}

#[test]
fn dnf_ambiguous_absent_query_is_an_error_not_absent() {
    // rpm -q exit 1 without the "is not installed" marker is an inspection
    // failure, never silently absent.
    let dir = trusted_root("plat-dnf-ambig");
    let recipe = pkg_recipe(&dir, "nano", "absent");
    let mut t = FakeTarget::rocky9();
    t.query_completion = Some(Completion::Exited(2));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None);
    assert!(commands_with(&r, "/usr/bin/dnf").is_empty());
}

#[test]
fn dnf_sudo_path_records_sudo() {
    let dir = trusted_root("plat-dnf-sudo");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake(&recipe, Mode::Apply, true, FakeTarget::rocky9());
    assert_success(&r);
    let dnf = commands_with(&r, "/usr/bin/dnf");
    assert_eq!(dnf.len(), 1);
    assert!(dnf[0].sudo, "dnf mutation must run under sudo identity");
}

#[test]
fn sensitive_package_never_records_raw_name() {
    let dir = trusted_root("plat-dnf-sens");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    sensitive: true\n    with:\n      name: secretpkg\n      state: present\n",
    );
    let mut t = FakeTarget::rocky9();
    t.manager_completion = Some(Completion::Exited(1));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    // Every recorded command line for this resource is redacted.
    for c in r.commands.iter().filter(|c| c.sensitive) {
        assert_eq!(c.program, "[redacted]");
        assert_eq!(c.args, vec!["[redacted]".to_string()]);
    }
    let leaked = r
        .commands
        .iter()
        .any(|c| c.program.contains("secretpkg") || c.args.iter().any(|a| a.contains("secretpkg")));
    assert!(!leaked, "sensitive package name leaked into CommandRecord");
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    let reason = p.reason.clone().unwrap_or_default();
    assert!(
        !reason.contains("secretpkg"),
        "reason leaked name: {}",
        reason
    );
    assert!(reason.contains("[redacted]"));
}

#[test]
fn rocky_service_uses_same_systemd_path() {
    // systemd is platform-independent: the same service logic must work on a
    // RHEL-family target without a forked implementation.
    let dir = trusted_root("plat-rocky-svc");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: s\n    type: service\n    with:\n      name: fakehttpd\n      state: running\n      enabled: true\n",
    );
    let t = FakeTarget::rocky9().with_service("fakehttpd", ("loaded", "inactive", "disabled"));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_success(&r);
    let s = find(&r, "s");
    assert_eq!(s.change, Change::Changed);
    assert_eq!(s.verification, Verification::Verified);
    // Apply ordering: enable then start (DESIGN §28).
    let ctl = commands_with(&r, "/usr/bin/systemctl");
    let verbs: Vec<String> = ctl.iter().map(|c| c.args[0].clone()).collect();
    assert_eq!(
        verbs
            .iter()
            .filter(|v| *v == "enable" || *v == "start")
            .count(),
        2
    );
    let en = verbs.iter().position(|v| v == "enable").unwrap();
    let st = verbs.iter().position(|v| v == "start").unwrap();
    assert!(en < st, "enable must precede start: {:?}", verbs);
}

#[test]
fn rocky_service_already_running_is_unchanged() {
    let dir = trusted_root("plat-rocky-svc-unchanged");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: s\n    type: service\n    with:\n      name: fakehttpd\n      state: running\n",
    );
    let t = FakeTarget::rocky9().with_service("fakehttpd", ("loaded", "active", "enabled"));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_success(&r);
    let s = find(&r, "s");
    assert_eq!(s.change, Change::None);
    // No mutating systemctl verb was issued.
    let ctl = commands_with(&r, "/usr/bin/systemctl");
    assert!(ctl
        .iter()
        .all(|c| c.args.first().map(|a| a.as_str()) == Some("show")));
}

#[test]
fn package_name_rejects_option_injection() {
    let dir = trusted_root("plat-badname");
    for bad in ["-x", "--download-only", "pkg*name", "pkg;rm", "a b", ""] {
        let recipe = write_recipe(
            &dir,
            "r.yaml",
            &format!(
                "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: {:?}\n      state: present\n",
                bad
            ),
        );
        let r = sinter::model::load_model(&recipe);
        assert!(r.is_err(), "package name {:?} must be rejected", bad);
    }
}

#[test]
fn apt_backend_mutation_args_unchanged() {
    // The v0.1 apt argv contract must be preserved exactly.
    let dir = trusted_root("plat-apt-argv");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::ubuntu2404());
    assert_success(&r);
    let apt = commands_with(&r, "/usr/bin/apt-get");
    assert_eq!(apt.len(), 1);
    assert_eq!(apt[0].args, vec!["-y", "install", "nano"]);
}
