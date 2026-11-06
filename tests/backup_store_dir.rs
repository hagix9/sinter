//! A project file's `backup.directory` (DESIGN §40.6): the store
//! the operator names is held to the rules of the default store, in plan and apply.
#![cfg(unix)]

use sinter::backup::validate_store_dir;
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::FakeTarget;
use sinter::model::load_model;
use std::path::PathBuf;

fn base() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("app", 1001)
        .with_user("app", 1001, 1001, "/home/app", "/bin/bash")
        .as_root();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/var", 0o755, 0),
        ("/var/backups", 0o755, 0),
        ("/etc", 0o755, 0),
        ("/etc/app", 0o755, 0),
        ("/tmp", 0o1777, 0),
        ("/home", 0o755, 0),
        ("/home/app", 0o755, 1001),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    fs.put_file("/etc/app/conf", b"old", 0o640, 0, 0);
    t
}

fn recipe(dir: &tempfile::TempDir) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(
        &p,
        "version: 1\nbackup:\n  paths: [/etc/app/conf]\nresources:\n  - id: f\n    type: file\n    with:\n      path: /etc/app/conf\n      content: new\n",
    )
    .unwrap();
    p
}

fn run(mode: Mode, store: &str, t: FakeTarget) -> Result<RunReport, SinterError> {
    let d = tempfile::tempdir().unwrap();
    Engine::new(
        load_model(&recipe(&d)).unwrap(),
        RunOptions {
            mode,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap()
    .with_backup_run_id("run".to_string())
    .with_backup_store(Some(store.to_string()))
    .run()
}

fn refused(store: &str, t: FakeTarget, says: &str) {
    for mode in [Mode::Plan, Mode::Apply] {
        let e = match run(mode, store, t.clone()) {
            Err(e) => e,
            Ok(r) => panic!("{store} must be refused: {:?}", r.status),
        };
        assert!(e.message.contains(says), "wanted {says:?} in {}", e.message);
    }
}

#[test]
fn the_named_store_is_made_private_and_used() {
    let r = run(Mode::Apply, "/var/backups/sinter", base()).unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    let b = r.backup.as_ref().unwrap();
    assert_eq!(b.directory.as_deref(), Some("/var/backups/sinter/run"));
    assert_eq!(
        b.entries[0].destination.as_deref(),
        Some("/var/backups/sinter/run/etc/app/conf")
    );
    let fs = r.fake_fs.as_ref().unwrap();
    assert_eq!(fs.nodes["/var/backups/sinter"].mode & 0o777, 0o700);
    assert_eq!(fs.nodes["/var/backups/sinter/run"].mode & 0o777, 0o700);
    assert!(
        !fs.nodes.contains_key("/var/lib/sinter"),
        "not the default store"
    );
}

#[test]
fn an_existing_store_of_a_trusted_owner_is_used_and_left_as_it_is() {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/var/backups/sinter", 0o750, 0, 0);
    let r = run(Mode::Apply, "/var/backups/sinter", t).unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(
        r.fake_fs.as_ref().unwrap().nodes["/var/backups/sinter"].mode & 0o777,
        0o750
    );
}

#[test]
fn plan_creates_nothing_and_says_where() {
    let r = run(Mode::Plan, "/var/backups/sinter", base()).unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    assert!(!r
        .fake_fs
        .as_ref()
        .unwrap()
        .nodes
        .contains_key("/var/backups/sinter"));
    assert_eq!(
        r.backup.as_ref().unwrap().entries[0].status.label(),
        "planned"
    );
}

#[test]
fn only_the_store_itself_is_created() {
    refused(
        "/var/backups/a/b",
        base(),
        "cannot inspect the parent paths",
    );
}

#[test]
fn an_unsafe_store_is_refused_in_plan_and_apply() {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_symlink("/var/backups/ln", "/etc", 0, 0);
    refused("/var/backups/ln", t, "symlink");

    let mut t = base();
    t.fs.as_mut().unwrap().put_symlink("/var/ln", "/etc", 0, 0);
    refused("/var/ln/store", t, "is a symlink");

    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/var/backups/f", b"x", 0o600, 0, 0);
    refused("/var/backups/f", t, "not a directory");

    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/var/backups/o", 0o700, 1001, 1001);
    refused("/var/backups/o", t, "outside the trusted set");

    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/var/backups/w", 0o775, 0, 0);
    refused("/var/backups/w", t, "grants group or other write access");

    let mut t = base();
    t.fs.as_mut().unwrap().mkdir_node("/var/open", 0o777, 0, 0);
    refused("/var/open/store", t, "grants group or other write access");
}

#[test]
fn another_accounts_tree_and_a_shared_directory_cannot_hold_it() {
    refused("/home/app/store", base(), "owned by uid 1001");
    refused("/tmp/store", base(), "shared directory");
}

#[test]
fn source_and_destination_never_overlap() {
    refused("/etc/app", base(), "overlaps");
    refused("/etc/app/conf/store", base(), "overlaps");
}

#[test]
fn a_run_directory_that_exists_is_a_collision() {
    let mut t = base();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/var/backups/sinter", 0o700, 0, 0);
    fs.mkdir_node("/var/backups/sinter/run", 0o700, 0, 0);
    let e = run(Mode::Apply, "/var/backups/sinter", t)
        .err()
        .expect("collision");
    assert!(e.message.contains("collision"), "{}", e.message);
}

#[test]
fn the_path_itself_is_checked_before_anything_runs() {
    assert!(validate_store_dir("/var/backups/sinter").is_ok());
    for bad in ["", "rel", "/", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\nb"] {
        assert!(validate_store_dir(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_recipe_names_a_store_only_under_the_same_rules() {
    // tests/backup_recipe_store.rs has the rest. A directory is static, absolute and
    // normalized at load; /tmp itself is judged at run time as a shared directory.
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    for (body, ok) in [
        ("  paths: [/etc/x]\n  directory: /var/backups/x\n", true),
        ("  paths: [/etc/x]\n  directory: rel\n", false),
        ("  paths: [/etc/x]\n  directory: \"{{ x }}\"\n", false),
    ] {
        std::fs::write(&p, format!("version: 1\nbackup:\n{body}")).unwrap();
        assert_eq!(load_model(&p).is_ok(), ok, "{body}");
    }
}
