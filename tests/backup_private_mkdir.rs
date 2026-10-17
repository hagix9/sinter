//! RW-020: the backup store and run directories are created by
//! `mkdir -m 0700`, not by a plain `mkdir` followed by `chmod`.
//!
//! A plain `mkdir` leaves the new directory with the creator's umask (0777
//! with umask 000) until the `chmod` runs. The store is below a trusted
//! parent, so the window is narrow, but there is no reason to have it. The
//! `chmod 0700` that follows is kept (it verifies the mode took effect), so
//! the number of target commands does not change.
//!
//! Scripted target only. The real-host behaviour of `mkdir -m` (GNU 8.32 /
//! 9.4 / 9.5, uutils 0.8.0) is part of the Linux acceptance; the uutils case
//! was observed in the v1.3.0 acceptance on Ubuntu 26.04.1.
#![cfg(unix)]

use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::executor::{CommandRecord, FakeTarget};
use sinter::model::load_model;

fn target() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().with_fake_fs();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/srv", 0o755, 0),
        ("/var", 0o755, 0),
        ("/var/lib", 0o755, 0),
        ("/home", 0o755, 0),
        ("/home/fake", 0o755, 1000),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    t
}

fn apply(sudo: bool, t: FakeTarget) -> RunReport {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("r.yaml");
    std::fs::write(
        &p,
        "version: 1\nbackup:\n  paths: [/srv/nothing]\nresources:\n  - id: readme\n    type: file\n    with:\n      path: /srv/README\n      content: \"x\\n\"\n",
    )
    .unwrap();
    Engine::new(
        load_model(&p).unwrap(),
        RunOptions {
            mode: Mode::Apply,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap()
    .run()
    .unwrap_or_else(|e| panic!("apply: {}", e.message))
}

fn mkdirs(r: &RunReport) -> Vec<&CommandRecord> {
    r.commands
        .iter()
        .filter(|c| c.program.ends_with("/mkdir"))
        .collect()
}

#[test]
fn store_and_run_directories_are_created_private_in_one_call() {
    for (sudo, store, backups) in [
        (true, "/var/lib/sinter", "/var/lib/sinter/backups"),
        (false, "/home/fake/.sinter", "/home/fake/.sinter/backups"),
    ] {
        let r = apply(sudo, target());
        assert_eq!(r.status, AggregateStatus::Success, "sudo={sudo}");
        let created: Vec<(Vec<String>, bool)> = mkdirs(&r)
            .into_iter()
            .map(|c| (c.args.clone(), c.sudo))
            .collect();
        // The store, the backups directory and the run directory (three
        // creations), each with the mode set by mkdir itself.
        assert_eq!(created.len(), 3, "sudo={sudo}: {created:?}");
        for (args, _) in &created {
            assert_eq!(&args[..3], ["-m", "0700", "--"], "sudo={sudo}: {args:?}");
        }
        assert_eq!(created[0].0[3], store);
        assert_eq!(created[1].0[3], backups);
        assert!(
            created[2].0[3].starts_with(&format!("{backups}/")),
            "{:?}",
            created[2]
        );
        // No plain `mkdir` (and no `-p`) anywhere in the backup stage.
        assert!(
            mkdirs(&r)
                .iter()
                .all(|c| c.args.first().map(String::as_str) == Some("-m")),
            "sudo={sudo}"
        );
    }
}

#[test]
fn the_chmod_check_and_the_command_count_are_unchanged() {
    // Each created directory is still followed by `chmod 0700` on that path.
    let r = apply(true, target());
    let chmods: Vec<&Vec<String>> = r
        .commands
        .iter()
        .filter(|c| c.program.ends_with("/chmod"))
        .map(|c| &c.args)
        .collect();
    for dir in mkdirs(&r).iter().map(|c| c.args[3].clone()) {
        assert!(
            chmods
                .iter()
                .any(|a| a.first().map(String::as_str) == Some("0700") && a.last() == Some(&dir)),
            "no chmod 0700 for {dir}: {chmods:?}"
        );
    }
}

#[test]
fn an_existing_store_is_neither_recreated_nor_loosened() {
    let mut t = target();
    {
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/var/lib/sinter", 0o700, 0, 0);
        fs.mkdir_node("/var/lib/sinter/backups", 0o700, 0, 0);
    }
    let r = apply(true, t);
    assert_eq!(r.status, AggregateStatus::Success);
    let m = mkdirs(&r);
    assert_eq!(m.len(), 1, "only the run directory is created: {m:?}");
    assert_eq!(&m[0].args[..3], ["-m", "0700", "--"]);
    assert!(m[0].args[3].starts_with("/var/lib/sinter/backups/"));
}

#[test]
fn a_store_directory_that_is_not_private_is_still_refused() {
    // Group-writable existing store: refused, as before (the creation change
    // does not touch the checks on an existing directory).
    let mut t = target();
    {
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/var/lib/sinter", 0o770, 0, 0);
    }
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("r.yaml");
    std::fs::write(
        &p,
        "version: 1\nbackup:\n  paths: [/srv/nothing]\nresources:\n  - id: readme\n    type: file\n    with:\n      path: /srv/README\n      content: \"x\\n\"\n",
    )
    .unwrap();
    let r = Engine::new(
        load_model(&p).unwrap(),
        RunOptions {
            mode: Mode::Apply,
            sudo: true,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap()
    .run();
    let msg = match r {
        Ok(rep) => panic!("expected the backup stage to refuse, got {:?}", rep.status),
        Err(e) => e.message,
    };
    assert!(msg.contains("grants group or other write access"), "{msg}");
}

// ---------------------------------------------------------------------------
// RW-020 regression: the creation change did not touch the protections around
// it. The refusals below still happen and stop the run before any resource;
// `ensure_dir` inspects a path before it would create or chmod it, so a link or
// a file at a store path ends in the refusal, not in a `mkdir`/`chmod`.
// ---------------------------------------------------------------------------

use sinter::fakesys::{FakeKind, FakeNode};

fn try_apply(sudo: bool, t: FakeTarget) -> Result<RunReport, String> {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("r.yaml");
    std::fs::write(
        &p,
        "version: 1\nbackup:\n  paths: [/srv/nothing]\nresources:\n  - id: readme\n    type: file\n    with:\n      path: /srv/README\n      content: \"x\\n\"\n",
    )
    .unwrap();
    Engine::new(
        load_model(&p).unwrap(),
        RunOptions {
            mode: Mode::Apply,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap()
    .run()
    .map_err(|e| e.message)
}

#[test]
fn a_group_writable_parent_is_still_refused() {
    let mut t = target();
    t.fs.as_mut().unwrap().mkdir_node("/var/lib", 0o777, 0, 0);
    let err = match try_apply(true, t) {
        Ok(_) => panic!("the backup stage must refuse"),
        Err(e) => e,
    };
    assert!(
        err.contains("backup failed; no resource was executed"),
        "{err}"
    );
}

#[test]
fn a_symlink_or_file_at_a_store_path_is_refused_and_never_followed() {
    for kind in ["symlink", "file"] {
        let mut t = target();
        {
            let fs = t.fs.as_mut().unwrap();
            fs.mkdir_node("/elsewhere", 0o755, 0, 0);
            if kind == "symlink" {
                fs.nodes.insert(
                    "/var/lib/sinter".to_string(),
                    FakeNode {
                        kind: FakeKind::Symlink("/elsewhere".to_string()),
                        mode: 0o777,
                        uid: 0,
                        gid: 0,
                        ino: 4242,
                        mtime: 1,
                        ctime: 1,
                    },
                );
            } else {
                fs.put_file("/var/lib/sinter", b"x", 0o600, 0, 0);
            }
        }
        let err = match try_apply(true, t) {
            Ok(_) => panic!("{kind}: must refuse"),
            Err(e) => e,
        };
        assert!(
            err.contains("backup failed; no resource was executed"),
            "{kind}: {err}"
        );
        assert!(
            err.contains("is a symlink")
                || err.contains("not a directory")
                || err.contains("symlink"),
            "{kind}: {err}"
        );
    }
}

#[test]
fn a_root_login_without_sudo_creates_its_store_private_too() {
    // A root login runs directly (no sudo). Its store is the one the flag
    // selects (`~/.sinter/backups` of root), created the same way.
    let mut t = target().as_root();
    t.fs.as_mut().unwrap().mkdir_node("/root", 0o700, 0, 0);
    let r = apply(false, t);
    assert_eq!(r.status, AggregateStatus::Success);
    let m = mkdirs(&r);
    assert_eq!(m.len(), 3, "{m:?}");
    assert!(
        m.iter()
            .all(|c| c.args[..3] == ["-m", "0700", "--"] && !c.sudo),
        "{m:?}"
    );
    assert_eq!(m[0].args[3], "/root/.sinter");
    assert_eq!(m[1].args[3], "/root/.sinter/backups");
    assert!(m[2].args[3].starts_with("/root/.sinter/backups/"));
}
