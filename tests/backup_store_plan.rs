//! WP-2: plan and the apply-only backup stage.
//!
//! With `backup.paths` declared, apply creates the backup store chain before
//! the first resource runs (`/var/lib/sinter` and `/var/lib/sinter/backups`
//! with `--sudo`; `$HOME/.sinter` and `$HOME/.sinter/backups` without) and a
//! run directory below it. Plan lists the backup but creates nothing, so a
//! resource whose parent is one of those directories used to get a certain
//! plan refusal ("parent does not exist") that apply never makes.
//!
//! Plan now treats the first store directory that does not exist yet as a
//! change made earlier in the run: a refusal that depends on it is deferred
//! to apply with a note. Nothing else is deferred: directories that already
//! exist, the other privilege mode's store, name-prefix neighbours and
//! unrelated paths keep their certain plan errors.
//!
//! Scripted target only; the real-host run is part of the Linux acceptance.
#![cfg(unix)]

mod common;

use common::mutation_command_count;
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::FakeTarget;
use sinter::model::load_model;
use sinter::result::{Change, Execution};
use std::path::PathBuf;

const PLAN_SUFFIX: &str = "(plan: Sinter's parent path check would refuse this change at apply)";
const DEFERRED: &str = "parent path check deferred to apply";

fn target_with(store: &[&str]) -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().with_fake_fs();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/srv", 0o755, 0),
        ("/var", 0o755, 0),
        ("/var/lib", 0o755, 0),
        ("/home", 0o755, 0),
        // The connecting (non-sudo) user's home: trusted because it is owned
        // by the connecting uid and not group/other writable.
        ("/home/fake", 0o755, 1000),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    for d in store {
        let uid = if d.starts_with("/home/fake") { 1000 } else { 0 };
        fs.mkdir_node(d, 0o700, uid, uid);
    }
    t
}

fn engine(path: &std::path::Path, mode: Mode, sudo: bool, t: FakeTarget) -> Engine {
    Engine::new(
        load_model(path).unwrap(),
        RunOptions {
            mode,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap()
}

fn plan(p: &std::path::Path, sudo: bool, t: FakeTarget) -> Result<RunReport, SinterError> {
    engine(p, Mode::Plan, sudo, t).run()
}

fn apply(p: &std::path::Path, sudo: bool, t: FakeTarget) -> RunReport {
    engine(p, Mode::Apply, sudo, t)
        .run()
        .unwrap_or_else(|e| panic!("apply: {}", e.message))
}

fn recipe(dir: &tempfile::TempDir, backup: bool, managed: &str) -> PathBuf {
    let backup = if backup {
        "backup:\n  paths: [/srv/nothing]\n"
    } else {
        ""
    };
    let p = dir.path().join("r.yaml");
    std::fs::write(
        &p,
        format!(
            "version: 1\n{backup}resources:\n  - id: readme\n    type: file\n    with:\n      path: {managed}\n      content: \"x\\n\"\n"
        ),
    )
    .unwrap();
    p
}

fn readme(r: &RunReport) -> &sinter::result::ResourceResult {
    r.resources.iter().find(|r| r.id == "readme").unwrap()
}

/// Plan defers (a note naming the directory the backup stage creates, no
/// error, no mutation) and apply from the same state succeeds.
fn assert_deferred(sudo: bool, store: &[&str], managed: &str, created: &str) {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, true, managed);
    let r = plan(&p, sudo, target_with(store))
        .unwrap_or_else(|e| panic!("{managed}: plan must defer, got {}", e.message));
    assert_eq!(
        mutation_command_count(&r),
        0,
        "plan must not change the target"
    );
    let want = format!("the backup stage changes {created} earlier in this run");
    let x = readme(&r);
    assert_eq!(x.change, Change::Changed, "{managed}");
    assert!(
        x.notes
            .iter()
            .any(|n| n.starts_with(DEFERRED) && n.contains(&want)),
        "{managed}: {:?}",
        x.notes
    );
    let a = apply(&p, sudo, target_with(store));
    assert_eq!(a.status, AggregateStatus::Success, "{managed}");
    assert_eq!(readme(&a).execution, Execution::Succeeded, "{managed}");
    assert_eq!(readme(&a).change, Change::Changed, "{managed}");
}

/// Plan refuses with the certain error and apply fails the same resource.
fn assert_certain(sudo: bool, store: &[&str], backup: bool, managed: &str) {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, backup, managed);
    let e = plan(&p, sudo, target_with(store))
        .err()
        .unwrap_or_else(|| panic!("{managed}: plan must refuse"));
    assert!(e.message.starts_with("readme: "), "{}", e.message);
    assert!(e.message.ends_with(PLAN_SUFFIX), "{}", e.message);
    assert!(!e.message.contains(DEFERRED), "{}", e.message);
    let a = apply(&p, sudo, target_with(store));
    assert_eq!(a.status, AggregateStatus::ApplyFailed, "{managed}");
    assert_eq!(readme(&a).execution, Execution::Failed, "{managed}");
}

#[test]
fn a_path_below_a_store_directory_apply_creates_is_deferred_not_refused() {
    // sudo: neither /var/lib/sinter nor the backups directory exists.
    assert_deferred(
        true,
        &[],
        "/var/lib/sinter/backups/README",
        "/var/lib/sinter",
    );
    assert_deferred(true, &[], "/var/lib/sinter/README", "/var/lib/sinter");
    // non-sudo: the same chain below the connecting user's home.
    assert_deferred(
        false,
        &[],
        "/home/fake/.sinter/backups/README",
        "/home/fake/.sinter",
    );
}

#[test]
fn only_the_first_missing_store_directory_is_the_planned_change() {
    // /var/lib/sinter exists: the stage creates only `backups`.
    let store = ["/var/lib/sinter"];
    assert_deferred(
        true,
        &store,
        "/var/lib/sinter/backups/README",
        "/var/lib/sinter/backups",
    );
    // A file directly in the existing directory has nothing to defer: its
    // parent exists, so plan and apply agree without a note.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, true, "/var/lib/sinter/README");
    let r = plan(&p, true, target_with(&store)).unwrap();
    assert!(readme(&r).notes.is_empty(), "{:?}", readme(&r).notes);
    assert_eq!(
        apply(&p, true, target_with(&store)).status,
        AggregateStatus::Success
    );
}

#[test]
fn an_existing_store_defers_nothing() {
    let store = ["/var/lib/sinter", "/var/lib/sinter/backups"];
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, true, "/var/lib/sinter/backups/README");
    let r = plan(&p, true, target_with(&store)).unwrap();
    assert!(readme(&r).notes.is_empty(), "{:?}", readme(&r).notes);
    assert_eq!(
        apply(&p, true, target_with(&store)).status,
        AggregateStatus::Success
    );
}

#[test]
fn the_other_privilege_modes_store_and_unrelated_paths_stay_certain() {
    // --sudo creates /var/lib/sinter, not the user's ~/.sinter.
    assert_certain(true, &[], true, "/home/fake/.sinter/backups/README");
    // Without --sudo the store is below the home, not /var/lib/sinter.
    assert_certain(false, &[], true, "/var/lib/sinter/backups/README");
    // A name-prefix neighbour of the store is not below it.
    assert_certain(true, &[], true, "/var/lib/sinterx/README");
    assert_certain(true, &[], true, "/var/lib/sinter-old/backups/README");
    // A path the stage has nothing to do with.
    assert_certain(true, &[], true, "/srv/missing/README");
    // Below an existing store: `other` is not something the stage creates.
    assert_certain(
        true,
        &["/var/lib/sinter", "/var/lib/sinter/backups"],
        true,
        "/var/lib/sinter/other/README",
    );
}

#[test]
fn without_a_backup_section_nothing_changes() {
    assert_certain(true, &[], false, "/var/lib/sinter/backups/README");
    assert_certain(false, &[], false, "/home/fake/.sinter/backups/README");
}
