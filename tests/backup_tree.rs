//! A pre-apply backup of a file in another account's tree (DESIGN §40.7), on the
//! scripted target with the production engine: which identity does what, and what
//! is refused. The script itself: `tests/backup_tree_script.rs`.
#![cfg(unix)]

use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::{CommandRecord, FakeTarget};
use sinter::fakesys::FakeKind;
use sinter::model::load_model;
use std::path::PathBuf;

const CANARY: &str = "BACKUP_TREE_CANARY_DO_NOT_PRINT";

fn base() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("postgres", 26)
        .with_user("postgres", 26, 26, "/var/lib/pgsql", "/bin/bash")
        .with_user("other", 1002, 1002, "/home/other", "/bin/bash")
        .as_root();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/var", 0o755, 0),
        ("/var/lib", 0o755, 0),
        ("/var/lib/pgsql", 0o700, 26),
        ("/root", 0o700, 0),
        ("/etc", 0o755, 0),
        ("/etc/app", 0o755, 0),
        ("/tmp", 0o1777, 0),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    fs.put_file("/var/lib/pgsql/.pgpass", CANARY.as_bytes(), 0o600, 26, 26);
    t
}

fn recipe(dir: &tempfile::TempDir, path: &str) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(
        &p,
        format!(
            "version: 1\nbackup:\n  paths: [{path}]\nresources:\n  - id: f\n    type: file\n    with:\n      path: /etc/app/conf\n      content: new\n"
        ),
    )
    .unwrap();
    p
}

fn engine(p: &std::path::Path, sudo: bool, t: FakeTarget) -> Engine {
    Engine::new(
        load_model(p).unwrap(),
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
    .with_backup_run_id("run".to_string())
}

fn apply(path: &str, t: FakeTarget) -> Result<RunReport, SinterError> {
    let d = tempfile::tempdir().unwrap();
    engine(&recipe(&d, path), false, t).run()
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn script_calls(r: &RunReport) -> Vec<&CommandRecord> {
    r.commands
        .iter()
        .filter(|c| c.args.iter().any(|a| a.starts_with("[fsbackup.sh sha256:")))
        .collect()
}

#[test]
fn a_private_file_of_postgres_is_kept_with_its_metadata() {
    let r = apply("/var/lib/pgsql/.pgpass", base()).unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    let b = r.backup.as_ref().unwrap();
    assert_eq!(b.entries[0].status.label(), "backed_up");
    assert_eq!(b.entries[0].kind, Some("file"));
    let dest = "/root/.sinter/backups/run/var/lib/pgsql/.pgpass";
    assert_eq!(b.entries[0].destination.as_deref(), Some(dest));
    let fs = r.fake_fs.as_ref().unwrap();
    let copy = &fs.nodes[dest];
    assert_eq!((copy.uid, copy.gid, copy.mode & 0o7777), (26, 26, 0o600));
    let FakeKind::File(content) = &copy.kind else {
        panic!("not a file")
    };
    assert_eq!(content, CANARY.as_bytes());
    // The run directory is root's and private, so the copy is out of the account's reach.
    let run = &fs.nodes["/root/.sinter/backups/run"];
    assert_eq!((run.uid, run.mode & 0o777), (0, 0o700));
}

#[test]
fn the_account_reads_and_root_writes() {
    let r = apply("/var/lib/pgsql/.pgpass", base()).unwrap();
    // Observed only as the account; root never opens the source.
    let as_account =
        |c: &&CommandRecord| c.program == "/usr/bin/setpriv" && c.args.iter().any(|a| a == "26");
    let mentioning: Vec<&CommandRecord> = r
        .commands
        .iter()
        .filter(|c| c.args.iter().any(|a| a == "/var/lib/pgsql/.pgpass"))
        .collect();
    assert!(!mentioning.is_empty());
    for c in &mentioning {
        let is_script = c.args.iter().any(|a| a.starts_with("[fsbackup.sh"));
        assert!(
            as_account(c) || is_script,
            "root touched the source: {} {:?}",
            c.program,
            c.args
        );
    }
    assert!(
        r.commands.iter().all(|c| base_name(&c.program) != "cp"),
        "no cp as root"
    );
    // The store is written as root: no account wrapper around any of it.
    for c in r.commands.iter().filter(|c| {
        c.args
            .iter()
            .any(|a| a.starts_with("/root/.sinter/backups"))
    }) {
        assert_ne!(c.program, "/usr/bin/setpriv", "{:?}", c.args);
    }
    let calls = script_calls(&r);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program, "/bin/sh");
    assert!(
        !format!("{:?}", calls[0].args).contains("set -eu"),
        "logged by digest"
    );
}

#[test]
fn nothing_of_the_content_reaches_the_report() {
    let r = apply("/var/lib/pgsql/.pgpass", base()).unwrap();
    let doc = sinter::output::run_report_json(&r, "apply").to_string();
    assert!(!doc.contains(CANARY));
    assert!(!format!("{:?}", r.commands).contains(CANARY));
}

#[test]
fn it_works_with_sudo_as_well() {
    let d = tempfile::tempdir().unwrap();
    let r = engine(&recipe(&d, "/var/lib/pgsql/.pgpass"), true, base())
        .run()
        .unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
}

#[test]
fn an_absent_file_is_recorded_as_absent() {
    let r = apply("/var/lib/pgsql/none", base()).unwrap();
    assert_eq!(
        r.backup.as_ref().unwrap().entries[0].status.label(),
        "absent"
    );
    assert!(script_calls(&r).is_empty());
}

fn refused(path: &str, t: FakeTarget, says: &str) {
    let e = match apply(path, t) {
        Err(e) => e,
        Ok(r) => panic!("{path} must be refused: {:?}", r.status),
    };
    assert!(e.message.contains(says), "wanted {says:?} in {}", e.message);
    assert!(
        e.message.contains("no resource was executed"),
        "{}",
        e.message
    );
}

#[test]
fn what_cannot_be_made_safe_is_refused_before_any_resource() {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/var/lib/pgsql/data", 0o700, 26, 26);
    refused(
        "/var/lib/pgsql/data",
        t,
        "a directory there is not backed up",
    );

    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_symlink("/var/lib/pgsql/link", "/etc/shadow", 26, 26);
    refused(
        "/var/lib/pgsql/link",
        t,
        "is not backed up, only a regular file",
    );

    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/var/lib/pgsql/rootfile", b"x", 0o600, 0, 0);
    refused("/var/lib/pgsql/rootfile", t, "owned by uid 0");

    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/var/lib/pgsql/other", b"x", 0o600, 1002, 1002);
    refused("/var/lib/pgsql/other", t, "owned by uid 1002");

    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_hardlink("/var/lib/pgsql/.pgpass", "/var/lib/pgsql/second");
    refused("/var/lib/pgsql/.pgpass", t, "2 hard links");

    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/var/lib/pgsql/suid", b"x", 0o4755, 26, 26);
    refused("/var/lib/pgsql/suid", t, "setuid or setgid");
}

#[test]
fn the_top_of_another_accounts_tree_is_not_walked_as_root() {
    refused(
        "/var/lib/pgsql",
        base(),
        "a directory owned by uid 26 is not backed up",
    );
}

#[test]
fn overlapping_declared_paths_are_refused_in_every_phase_and_any_order() {
    // The copy of one could plant a link that the copy of the other writes through.
    let d = tempfile::tempdir().unwrap();
    for (a, b) in [
        ("/srv/app", "/srv/app/sub/x"),
        ("/srv/app/sub/x", "/srv/app"),
        ("/srv/app", "/srv"),
        ("/srv", "/srv/app"),
    ] {
        let e = match load_model(&recipe(&d, &format!("{a}, {b}"))) {
            Err(e) => e,
            Ok(_) => panic!("{a} and {b} must be refused"),
        };
        assert_eq!(e.kind, sinter::error::ErrorKind::Schema);
        assert!(e.message.contains("overlap"), "{}", e.message);
    }
    // A name that only starts the same does not overlap.
    assert!(load_model(&recipe(&d, "/srv/app, /srv/apple")).is_ok());
}

#[test]
fn a_file_below_a_root_directory_with_an_account_directory_in_between_is_copied_alone() {
    let mut t = base();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/srv", 0o755, 0, 0);
    fs.mkdir_node("/srv/app", 0o755, 0, 0);
    fs.mkdir_node("/srv/app/sub", 0o700, 26, 26);
    fs.put_file("/srv/app/sub/x", b"x", 0o600, 26, 26);
    assert!(apply("/srv/app/sub/x", t).is_ok());
}

#[test]
fn a_squatted_tree_in_a_shared_directory_is_refused() {
    let mut t = base();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/tmp/app", 0o700, 26, 26);
    fs.put_file("/tmp/app/f", b"x", 0o600, 26, 26);
    refused("/tmp/app/f", t, "shared directory");
}

#[test]
fn an_unsafe_parent_is_still_refused() {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/var/lib/open", 0o777, 26, 26);
    t.fs.as_mut()
        .unwrap()
        .put_file("/var/lib/open/f", b"x", 0o600, 26, 26);
    refused("/var/lib/open/f", t, "grants group or other write access");

    let mut t = base();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/var/lib/pgsql/third", 0o700, 1002, 1002);
    fs.put_file("/var/lib/pgsql/third/f", b"x", 0o600, 1002, 1002);
    refused("/var/lib/pgsql/third/f", t, "one other account's tree");

    let mut t = base();
    let fs = t.fs.as_mut().unwrap();
    fs.put_symlink("/var/lib/pgsql/ln", "/etc", 26, 26);
    refused("/var/lib/pgsql/ln/passwd", t, "is a symlink");
}

#[test]
fn a_non_root_invocation_gets_no_tree() {
    let mut t = FakeTarget::ubuntu2404().with_fake_fs();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/var", 0o755, 0),
        ("/var/lib", 0o755, 0),
        ("/var/lib/pgsql", 0o700, 26),
        ("/etc", 0o755, 0),
        ("/etc/app", 0o755, 0),
        ("/home", 0o755, 0),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    let e = apply("/var/lib/pgsql/.pgpass", t).err().expect("refused");
    assert!(
        e.message.contains("owned by uid 26") || e.message.contains("no resource was executed"),
        "{}",
        e.message
    );
}

#[test]
fn a_target_without_setpriv_is_refused_not_done_as_root() {
    let t = base().without_setpriv();
    let e = apply("/var/lib/pgsql/.pgpass", t).err().expect("refused");
    assert!(e.message.contains("setpriv"), "{}", e.message);
}

#[test]
fn a_file_in_a_trusted_directory_is_copied_as_before() {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/app/old", b"x", 0o640, 0, 0);
    let r = apply("/etc/app/old", t).unwrap();
    assert!(r.commands.iter().any(|c| base_name(&c.program) == "cp"));
    assert!(script_calls(&r).is_empty());
}

#[test]
fn a_tree_cannot_hold_the_store() {
    let d = tempfile::tempdir().unwrap();
    let e = engine(&recipe(&d, "/var/lib/pgsql/.pgpass"), false, base())
        .with_backup_store(Some("/var/lib/pgsql/store".to_string()))
        .run()
        .err()
        .expect("refused");
    assert!(
        e.message.contains("overlaps") || e.message.contains("owned by uid 26"),
        "{}",
        e.message
    );
}
