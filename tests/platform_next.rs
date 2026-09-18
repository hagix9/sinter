//! Platform-extension coverage for Ubuntu 26.04 LTS x86_64 and Rocky Linux
//! 10 x86_64, added when those targets became supported.
//!
//! These tests run against the scripted in-process target (FakeTarget) so
//! they exercise the production engine/model/targetfs/result path on any
//! controller. They prove the two new targets resolve to the right backend
//! and that the dnf snapshot install contract is unchanged on Rocky 10.
//! Real-host evidence for both targets is recorded in
//! SINTER_UBUNTU2604_ROCKY10_COMPATIBILITY_REPORT.md; fixture coverage here
//! is not a substitute for it.
mod common;

use common::*;
use sinter::engine::Mode;
use sinter::executor::{Completion, FakeTarget};
use sinter::result::{Change, Execution, Verification};

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
fn ubuntu2604_target_selects_apt_backend() {
    let dir = trusted_root("next-ubuntu2604");
    let recipe = pkg_recipe(&dir, "hello", "present");
    let r = run_recipe_fake(&recipe, Mode::Plan, false, FakeTarget::ubuntu2604());
    // Facts come from the real Ubuntu 26.04.1 /etc/os-release: no version
    // gate exists in detection, so 26.04 resolves exactly like 24.04.
    assert_eq!(r.facts.os_name, "Ubuntu");
    assert_eq!(r.facts.os_family, "debian");
    assert_eq!(r.facts.os_version, "26.04");
    assert_eq!(r.facts.arch, "x86_64");
    let p = find(&r, "p");
    assert_eq!(p.change, Change::Changed);
    assert!(!commands_with(&r, "/usr/bin/dpkg-query").is_empty());
    assert!(commands_with(&r, "/usr/bin/rpm").is_empty());
    assert!(commands_with(&r, "/usr/bin/dnf").is_empty());
    assert!(commands_with(&r, "/usr/bin/apt-get").is_empty());
    assert_eq!(mutation_command_count(&r), 0);
}

#[test]
fn rocky10_target_selects_dnf_backend() {
    let dir = trusted_root("next-rocky10");
    let recipe = pkg_recipe(&dir, "tree", "present");
    let r = run_recipe_fake(&recipe, Mode::Plan, false, FakeTarget::rocky10());
    // Facts come from the real Rocky Linux 10.2 /etc/os-release, including
    // PLATFORM_ID="platform:el10", which detection never consults: family
    // resolution is by ID/ID_LIKE, exactly as for Rocky 9.
    assert_eq!(r.facts.os_name, "Rocky Linux");
    assert_eq!(r.facts.os_family, "redhat");
    assert_eq!(r.facts.os_version, "10.2");
    assert_eq!(r.facts.arch, "x86_64");
    let p = find(&r, "p");
    assert_eq!(p.change, Change::Changed);
    assert!(!commands_with(&r, "/usr/bin/rpm").is_empty());
    assert!(commands_with(&r, "/usr/bin/dpkg-query").is_empty());
    assert_eq!(mutation_command_count(&r), 0);
}

#[test]
fn rocky10_installs_through_the_dnf_snapshot_contract() {
    // The dnf 4.20 backend keeps the v0.2.0 contract: snapshot, completeness
    // proof, transaction resolution, payload prefetch, cache-only mutation,
    // cleanup. Rocky 10's stock image ships curl and no wget, and the fake
    // models exactly that.
    let dir = trusted_root("next-rocky10-install");
    let recipe = pkg_recipe(&dir, "tree", "present");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::rocky10());
    assert_success(&r);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Succeeded);
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    let dnf = commands_with(&r, "/usr/bin/dnf");
    assert_eq!(dnf.len(), 5);
    // Every dnf invocation is cache-only or repo-disabled.
    assert!(dnf.iter().all(|c| c.args.iter().any(|a| a == "-C")));
    assert_eq!(commands_with(&r, "/usr/bin/curl").len(), 1);
    assert!(commands_with(&r, "/usr/bin/wget").is_empty());
    assert_eq!(commands_with(&r, "/usr/bin/rm").len(), 1);
}

#[test]
fn rocky10_second_apply_is_idempotent() {
    let dir = trusted_root("next-rocky10-idem");
    let recipe = pkg_recipe(&dir, "tree", "present");
    let target = FakeTarget::rocky10().with_package("tree");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, target);
    assert_success(&r);
    let p = find(&r, "p");
    assert_eq!(p.change, Change::None);
    assert_eq!(p.execution, Execution::Succeeded);
    assert_eq!(p.verification, Verification::Verified);
    assert!(commands_with(&r, "/usr/bin/dnf").is_empty());
    assert!(commands_with(&r, "/usr/bin/curl").is_empty());
}

#[test]
fn ubuntu2604_absent_package_plans_without_mutation() {
    // apt observation on 26.04 uses the same dpkg-query contract: exit 1 with
    // no stdout is a confirmed absent, so the plan reports a change and
    // mutates nothing.
    let dir = trusted_root("next-ubuntu2604-absent");
    let recipe = pkg_recipe(&dir, "sl", "absent");
    let r = run_recipe_fake(&recipe, Mode::Plan, false, FakeTarget::ubuntu2604());
    let p = find(&r, "p");
    assert_eq!(p.change, Change::None);
    assert_eq!(mutation_command_count(&r), 0);
}

#[test]
fn ubuntu2604_apt_install_keeps_the_v021_argv() {
    // apt 3.2 on 26.04 needs no new flags: the v0.2.1 argv still installs,
    // and truth comes from re-observation, never from apt's own output.
    let dir = trusted_root("next-ubuntu2604-install");
    let recipe = pkg_recipe(&dir, "hello", "present");
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::ubuntu2604());
    assert_success(&r);
    let p = find(&r, "p");
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    let apt = commands_with(&r, "/usr/bin/apt-get");
    assert_eq!(apt.len(), 1);
    assert_eq!(apt[0].args, vec!["-y", "install", "hello"]);
}

#[test]
fn ubuntu2604_apt_remove_keeps_the_v021_argv() {
    let dir = trusted_root("next-ubuntu2604-remove");
    let recipe = pkg_recipe(&dir, "hello", "absent");
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::ubuntu2604().with_package("hello"),
    );
    assert_success(&r);
    let p = find(&r, "p");
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    let apt = commands_with(&r, "/usr/bin/apt-get");
    assert_eq!(apt.len(), 1);
    assert_eq!(apt[0].args, vec!["-y", "remove", "hello"]);
}

#[test]
fn rocky10_absent_marker_classification_matches_rpm419() {
    // Verified on a real Rocky 10.2 target: rpm 4.19.1.1 still writes the
    // exact `package <name> is not installed\n` marker to stdout with an
    // empty stderr and exit 1 — the strict contract from rpm 4.16 holds.
    use sinter::executor::Output;
    let out = Output {
        completion: Completion::Exited(1),
        stdout: b"package tree is not installed\n".to_vec(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    };
    assert!(sinter::platform::PackageBackend::Dnf
        .classify_observation(&out, "tree", "tree", false)
        .is_ok());
}
