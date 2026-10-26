//! Stage R2 static integration tests for the DNF5 removal safety gate.
//!
//! These run against FakeTarget; no package manager is executed. They assert
//! the gate's command behavior, not just its return value: a denied preview
//! must not dispatch an actual `dnf remove` without `--assumeno`.

mod common;

use common::*;
use sinter::engine::Mode;
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::result::{Change, Execution};

const PREVIEW_44: &str = include_str!("fixtures/removal_r1/dnf5_unzip_44.out");
const PREVIEW_44_ERR: &str = include_str!("fixtures/removal_r1/dnf5_unzip_44.err");
const PREVIEW_8: &str = include_str!("fixtures/removal_r1/dnf5_unzip_8.out");
const PREVIEW_8_ERR: &str = include_str!("fixtures/removal_r1/dnf5_unzip_8.err");

fn output(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn readlink_dnf5() -> Output {
    output(0, "/usr/bin/dnf5\n", "")
}

fn inventory_unzip() -> Output {
    output(
        0,
        "unzip\t6.0-67.fc43\taarch64\nzip\t3.0-44.fc43\taarch64\n",
        "",
    )
}

fn inventory_tree() -> Output {
    output(0, "tree\t1.0-1.fc43\taarch64\n", "")
}

fn single_tree_preview() -> Output {
    output(
        1,
        "Package Arch    Version     Repository      Size\nRemoving:\n tree    aarch64 1.0-1.fc43 fedora     1.0 KiB\n\nTransaction Summary:\nRemoving:           1 package\n",
        "After this operation, 1.0 KiB will be freed (install 0 B, remove 1.0 KiB).\nOperation aborted by the user.\n",
    )
}

fn pkg_recipe(dir: &std::path::Path, name: &str, sensitive: bool) -> std::path::PathBuf {
    let sensitive = if sensitive {
        "    sensitive: true\n"
    } else {
        ""
    };
    write_recipe(
        dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n{sensitive}    with:\n      name: {name}\n      state: absent\n"
        ),
    )
}

fn dnf5_fake(package: &str, previews: Vec<Output>, inventories: Vec<Output>) -> FakeTarget {
    let mut fake = FakeTarget::rocky9().with_package(package);
    fake.program_outputs
        .insert("/usr/bin/readlink".to_string(), readlink_dnf5());
    fake.dnf_remove_preview_results = previews.into();
    fake.rpm_qa_results = inventories.into();
    fake
}

fn actual_removals(report: &sinter::engine::RunReport) -> Vec<&sinter::executor::CommandRecord> {
    report
        .commands
        .iter()
        .filter(|c| {
            c.program == "/usr/bin/dnf"
                && c.args.iter().any(|a| a == "remove")
                && !c.args.iter().any(|a| a == "--assumeno")
        })
        .collect()
}

#[test]
fn r2_44_preview_is_denied_without_remove_dispatch() {
    let dir = trusted_root("r2-44");
    let recipe = pkg_recipe(&dir, "unzip", false);
    let fake = dnf5_fake(
        "unzip",
        vec![
            output(1, PREVIEW_44, PREVIEW_44_ERR),
            output(1, PREVIEW_8, PREVIEW_8_ERR),
        ],
        vec![inventory_unzip(), inventory_unzip(), inventory_unzip()],
    );
    let report = run_recipe_fake(&recipe, Mode::Apply, true, fake);
    let p = find(&report, "p");
    assert_eq!(p.change, Change::None);
    assert_eq!(p.execution, Execution::Failed);
    assert!(
        actual_removals(&report).is_empty(),
        "a remove was dispatched"
    );
}

#[test]
fn r2_8_preview_is_denied_without_remove_dispatch() {
    let dir = trusted_root("r2-8");
    let recipe = pkg_recipe(&dir, "unzip", false);
    let fake = dnf5_fake(
        "unzip",
        vec![
            output(1, PREVIEW_44, PREVIEW_44_ERR),
            output(1, PREVIEW_8, PREVIEW_8_ERR),
        ],
        vec![inventory_unzip(), inventory_unzip(), inventory_unzip()],
    );
    let report = run_recipe_fake(&recipe, Mode::Apply, true, fake);
    let p = find(&report, "p");
    assert_eq!(p.change, Change::None);
    assert!(
        actual_removals(&report).is_empty(),
        "a remove was dispatched"
    );
    assert!(
        p.reason.as_deref().unwrap_or("").contains("8")
            || p.reason.as_deref().unwrap_or("").contains("package"),
        "{:?}",
        p.reason
    );
}

#[test]
fn r2_single_removal_passes_gate_and_verifies_actual_delta() {
    let dir = trusted_root("r2-single");
    let recipe = pkg_recipe(&dir, "tree", false);
    let fake = dnf5_fake(
        "tree",
        vec![single_tree_preview(), single_tree_preview()],
        vec![
            inventory_tree(),
            inventory_tree(),
            inventory_tree(),
            output(0, "", ""),
        ],
    );
    let report = run_recipe_fake(&recipe, Mode::Apply, true, fake);
    let p = find(&report, "p");
    assert_eq!(
        p.change,
        Change::Changed,
        "reason={:?} execution={:?}",
        p.reason,
        p.execution
    );
    assert_eq!(p.execution, Execution::Succeeded);
    let removals = actual_removals(&report);
    assert_eq!(removals.len(), 1);
    assert!(removals[0].args.contains(&"--no-autoremove".to_string()));
}

#[test]
fn r2_inventory_b_change_refuses_before_mutation() {
    let dir = trusted_root("r2-inv");
    let recipe = pkg_recipe(&dir, "tree", false);
    let fake = dnf5_fake(
        "tree",
        vec![single_tree_preview(), single_tree_preview()],
        vec![
            inventory_tree(),
            output(0, "tree\t1.0-1.fc43\taarch64\nextra\t1.0\taarch64\n", ""),
            inventory_tree(),
        ],
    );
    let report = run_recipe_fake(&recipe, Mode::Apply, true, fake);
    let p = find(&report, "p");
    assert_eq!(p.change, Change::None);
    assert!(actual_removals(&report).is_empty());
}

#[test]
fn r2_malformed_preview_refuses_before_mutation() {
    let dir = trusted_root("r2-malformed");
    let recipe = pkg_recipe(&dir, "tree", false);
    let fake = dnf5_fake(
        "tree",
        vec![
            output(1, "garbage\n", "Operation aborted by the user.\n"),
            output(1, "garbage\n", "Operation aborted by the user.\n"),
        ],
        vec![inventory_tree(), inventory_tree(), inventory_tree()],
    );
    let report = run_recipe_fake(&recipe, Mode::Apply, true, fake);
    let p = find(&report, "p");
    assert_eq!(p.change, Change::None);
    assert!(actual_removals(&report).is_empty());
}

#[test]
fn r2_actual_mismatch_is_failed_never_unchanged() {
    let dir = trusted_root("r2-actual");
    let recipe = pkg_recipe(&dir, "tree", false);
    let fake = dnf5_fake(
        "tree",
        vec![single_tree_preview(), single_tree_preview()],
        vec![
            inventory_tree(),
            inventory_tree(),
            inventory_tree(),
            inventory_tree(), // D still contains tree: planned removal missing
        ],
    );
    let report = run_recipe_fake(&recipe, Mode::Apply, true, fake);
    let p = find(&report, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_ne!(p.change, Change::None);
    assert_ne!(p.verification, sinter::result::Verification::Verified);
}

#[test]
fn r2_sensitive_denial_does_not_leak_names() {
    let dir = trusted_root("r2-sensitive");
    let recipe = pkg_recipe(&dir, "unzip", true);
    let fake = dnf5_fake(
        "unzip",
        vec![
            output(1, PREVIEW_44, PREVIEW_44_ERR),
            output(1, PREVIEW_8, PREVIEW_8_ERR),
        ],
        vec![inventory_unzip(), inventory_unzip(), inventory_unzip()],
    );
    let report = run_recipe_fake(&recipe, Mode::Apply, true, fake);
    let p = find(&report, "p");
    assert_eq!(p.change, Change::None);
    let reason = p.reason.as_deref().unwrap_or("");
    assert!(!reason.contains("unzip"), "{reason}");
    assert!(!reason.contains("rpm-build"), "{reason}");
}

#[test]
fn r2_nonroot_is_refused_before_preview_and_mutation() {
    let dir = trusted_root("r2-nonroot");
    let recipe = pkg_recipe(&dir, "tree", false);
    let mut fake = FakeTarget::rocky9().with_package("tree");
    fake.program_outputs
        .insert("/usr/bin/readlink".to_string(), readlink_dnf5());
    // No preview or rpm -qa answers are configured: reaching either would
    // fail, proving the privilege gate runs first.
    let report = run_recipe_fake(&recipe, Mode::Apply, false, fake);
    let p = find(&report, "p");
    assert_eq!(p.change, Change::None);
    assert_eq!(p.execution, Execution::Failed);
    assert!(p.reason.as_deref().unwrap_or("").contains("root"));
    assert!(actual_removals(&report).is_empty());
    let dnf_commands: Vec<_> = report
        .commands
        .iter()
        .filter(|c| c.program == "/usr/bin/dnf")
        .collect();
    assert!(dnf_commands.is_empty(), "dnf commands: {dnf_commands:?}");
}
