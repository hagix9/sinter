//! DESIGN §63: `allow_writable_parents` and the read-only audit of a path whose
//! direct parent other accounts can write to.
//!
//! The scripted target is a modeled filesystem that answers by exact path, and
//! `with_fs_event` lets another account act between two commands. What these
//! tests show is Sinter's own decisions: which walks accept which directory,
//! which operations are refused, that nothing is read through a link, and that
//! plan, apply and audit agree. What only a real Linux host can show (the
//! staging script in a directory that is writable without the sticky bit, the
//! ctime updates of rename(2) on each file system) is not claimed here.
#![cfg(unix)]

use sinter::audit::{run_audit, AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::{CommandRecord, FakeTarget, FsEventAction};
use sinter::fakesys::{FakeFs, FakeKind};
use sinter::model::load_model;
use sinter::output::{render_apply, render_audit, OutputFormat, RenderOptions};
use sinter::result::{Change, Execution, ResourceResult};
use std::path::{Path, PathBuf};

const ALICE: u32 = 1001;
const SECRET: &str = "SYNTHETIC-ROOT-ONLY-CANARY\n";
/// The listed directory: root's, mode 0777, no sticky bit.
const D: &str = "/opt/app";
/// A directory like `D` that no recipe lists.
const U: &str = "/opt/app2";
const NOTE: &str =
    "parent /opt/app is writable by other accounts; allowed by allow_writable_parents";

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn add_dirs(t: &mut FakeTarget) {
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/opt", 0o755, 0),
        (D, 0o777, 0),
        (U, 0o777, 0),
        ("/opt/safe", 0o755, 0),
        ("/opt/w", 0o777, 0),
        ("/opt/w/sub", 0o755, 0),
        ("/opt/w/d2", 0o777, 0),
        ("/opt/alicedir", 0o777, ALICE),
        ("/home", 0o755, 0),
        ("/home/alice", 0o755, ALICE),
        ("/home/alice/rootpub", 0o777, 0),
        ("/root", 0o700, 0),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    fs.put_symlink("/opt/lnk", D, 0, 0);
    fs.put_file("/root/secret", SECRET.as_bytes(), 0o600, 0, 0);
}

/// A root login (no `--sudo`), a second account `alice`. `sequential` adds
/// `getfacl`, which makes the parent walk the sequential one; without it the
/// batched walk (one `stat`, one `getfattr`) runs.
fn target(sequential: bool) -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("alice", ALICE)
        .with_user("alice", ALICE, ALICE, "/home/alice", "/bin/bash")
        .as_root();
    if sequential {
        t = t.with_executable("/usr/bin/getfacl");
    }
    add_dirs(&mut t);
    t
}

fn base() -> FakeTarget {
    target(false)
}

/// The connecting user is uid 1000 (not root, no `--sudo`).
fn base_user() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("alice", ALICE)
        .with_user("alice", ALICE, ALICE, "/home/alice", "/bin/bash");
    add_dirs(&mut t);
    t
}

fn with_file(mut t: FakeTarget, path: &str, data: &[u8], mode: u32, uid: u32) -> FakeTarget {
    t.fs.as_mut().unwrap().put_file(path, data, mode, uid, uid);
    t
}

fn write(dir: &tempfile::TempDir, name: &str, body: &str) -> PathBuf {
    let p = dir.path().join(name);
    std::fs::write(&p, body).unwrap();
    p
}

/// A recipe listing `allow` (no field when empty) with `resources` (YAML list
/// items, already indented).
fn recipe(dir: &tempfile::TempDir, allow: &[&str], resources: &str) -> PathBuf {
    let field = if allow.is_empty() {
        String::new()
    } else {
        format!("allow_writable_parents: [{}]\n", allow.join(", "))
    };
    write(
        dir,
        "r.yaml",
        &format!("version: 1\n{field}resources:\n{resources}"),
    )
}

fn file_res(path: &str, extra: &str) -> String {
    format!(
        "  - id: f\n    type: file\n    with:\n      path: {path}\n      content: \"new\\n\"\n{extra}"
    )
}

fn engine(p: &Path, mode: Mode, sudo: bool, t: FakeTarget) -> Engine {
    Engine::new(
        load_model(p).unwrap(),
        RunOptions {
            mode,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: true,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap()
}

fn run(p: &Path, mode: Mode, t: FakeTarget) -> RunReport {
    engine(p, mode, false, t).run().unwrap()
}

fn plan_err(p: &Path, t: FakeTarget) -> SinterError {
    engine(p, Mode::Plan, false, t)
        .run()
        .err()
        .expect("plan must fail")
}

fn audit(p: &Path, t: FakeTarget) -> AuditReport {
    run_audit(engine(p, Mode::Plan, false, t)).unwrap()
}

fn res<'a>(r: &'a RunReport, id: &str) -> &'a ResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

fn ares<'a>(r: &'a AuditReport, id: &str) -> &'a sinter::audit::AuditResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

fn fs_of(r: &RunReport) -> &FakeFs {
    r.fake_fs.as_ref().expect("scripted filesystem")
}

fn bytes(fs: &FakeFs, path: &str) -> Option<Vec<u8>> {
    fs.file_bytes(path)
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

const MUTATION: [&str; 12] = [
    "mkdir", "chown", "chmod", "mv", "mktemp", "rm", "rmdir", "ln", "setfattr", "cp", "install",
    "sh",
];

fn mutations(cmds: &[CommandRecord]) -> Vec<String> {
    cmds.iter()
        .filter(|c| MUTATION.contains(&base_name(&c.program)))
        .map(|c| format!("{} {:?}", c.program, c.args))
        .collect()
}

fn publishes(cmds: &[CommandRecord], kind: &str) -> usize {
    cmds.iter()
        .filter(|c| {
            base_name(&c.program) == "sh"
                && c.args.len() >= 5
                && c.args[3] == "publish"
                && c.args[4] == kind
        })
        .count()
}

/// No command names `path` as an operand with a program that follows links
/// and returns what it read (`getfattr`/`getfacl` follow too, but they are
/// bracketed by two `lstat`s that must agree, and return only attributes).
fn nothing_followed(cmds: &[CommandRecord], path: &str) {
    for c in cmds {
        let prog = base_name(&c.program);
        if c.args.iter().any(|a| a == path) {
            assert!(
                !matches!(prog, "cat" | "sha256sum" | "cp"),
                "{prog} {:?} would follow a link at {path}",
                c.args
            );
        }
        if prog == "dd" && c.args.iter().any(|a| a == &format!("if={path}")) {
            assert!(
                c.args.iter().any(|a| a == "iflag=nofollow,nonblock"),
                "dd without nofollow: {:?}",
                c.args
            );
        }
    }
}

fn shown_apply(r: &RunReport) -> String {
    let mut shown = String::new();
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut buf = Vec::new();
        render_apply(
            r,
            &RenderOptions {
                verbose: true,
                format,
                color: false,
            },
            &mut buf,
        )
        .unwrap();
        shown.push_str(&String::from_utf8(buf).unwrap());
    }
    shown
}

fn shown_audit(r: &AuditReport) -> (String, String) {
    let mut out = Vec::new();
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut buf = Vec::new();
        render_audit(
            r,
            &RenderOptions {
                verbose: true,
                format,
                color: false,
            },
            &mut buf,
        )
        .unwrap();
        out.push(String::from_utf8(buf).unwrap());
    }
    (out.remove(0), out.remove(0))
}

/// The note is in the text form and in the JSON form of the report.
fn note_in_text_and_json(r: &RunReport) {
    let mut text = Vec::new();
    let mut json = Vec::new();
    let o = |format| RenderOptions {
        verbose: true,
        format,
        color: false,
    };
    render_apply(r, &o(OutputFormat::Text), &mut text).unwrap();
    render_apply(r, &o(OutputFormat::Json), &mut json).unwrap();
    let text = String::from_utf8(text).unwrap();
    let json = String::from_utf8(json).unwrap();
    assert!(text.contains(NOTE), "text lacks the note: {text}");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.to_string().contains(NOTE), "JSON lacks the note: {json}");
}

/// The publication in D removed its staging directory (as root it is proven by
/// owner, group G and inode, DESIGN §23.5): no note says one was left, and none
/// is in D.
fn staging_removed(r: &RunReport, id: &str) {
    let notes = &res(r, id).notes;
    assert!(
        !notes.iter().any(|n| n.contains("left in place")),
        "{notes:?}"
    );
    let left: Vec<_> = fs_of(r)
        .nodes
        .keys()
        .filter(|k| k.contains(".sinter-stage."))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

fn apply_failure(r: &RunReport, id: &str) -> String {
    let x = res(r, id);
    assert_eq!(x.execution, Execution::Failed, "{x:?}");
    assert_eq!(x.change, Change::None, "{x:?}");
    x.reason.clone().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// unchanged without the exception
// ---------------------------------------------------------------------------

#[test]
fn a_safe_parent_is_unchanged_and_carries_no_note() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &[D], &file_res("/opt/safe/x.conf", ""));
    let planned = run(&p, Mode::Plan, base());
    assert_eq!(planned.status, AggregateStatus::Success);
    assert!(res(&planned, "f")
        .notes
        .iter()
        .all(|n| !n.contains("writable")));
    let applied = run(&p, Mode::Apply, base());
    assert_eq!(applied.status, AggregateStatus::Success);
    assert_eq!(
        bytes(fs_of(&applied), "/opt/safe/x.conf").unwrap(),
        b"new\n"
    );
    assert!(!shown_apply(&applied).contains("allow_writable_parents"));
}

#[test]
fn a_missing_parent_is_decided_exactly_as_without_the_field() {
    let dir = tempfile::tempdir().unwrap();
    let with = recipe(&dir, &[D], &file_res("/opt/nothere/x.conf", ""));
    let a = plan_err(&with, base()).message;
    let dir2 = tempfile::tempdir().unwrap();
    let without = recipe(&dir2, &[], &file_res("/opt/nothere/x.conf", ""));
    let b = plan_err(&without, base()).message;
    assert_eq!(a, b);
}

#[test]
fn an_unlisted_writable_parent_is_refused_in_plan_and_apply_with_the_old_message() {
    for listed in [&[][..], &["/opt/safe"][..]] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, listed, &file_res("/opt/app2/x.conf", ""));
        let e = plan_err(&p, base()).message;
        assert!(
            e.contains("parent path /opt/app2 grants group or other write access"),
            "{e}"
        );
        assert!(!e.contains("allow_writable_parents"), "{e}");
        let applied = run(&p, Mode::Apply, base());
        let why = apply_failure(&applied, "f");
        assert!(why.contains("grants group or other write access"), "{why}");
        assert!(!why.contains("allow_writable_parents"), "{why}");
        assert!(mutations(&applied.commands).is_empty());
        assert!(bytes(fs_of(&applied), "/opt/app2/x.conf").is_none());
    }
}

// ---------------------------------------------------------------------------
// what the exception allows
// ---------------------------------------------------------------------------

#[test]
fn a_listed_direct_parent_creates_a_file_as_root_in_both_walks() {
    for sequential in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &[D], &file_res("/opt/app/x.conf", ""));
        let planned = run(&p, Mode::Plan, target(sequential));
        assert_eq!(planned.status, AggregateStatus::Success, "{sequential}");
        assert_eq!(res(&planned, "f").change, Change::Changed);
        assert!(
            res(&planned, "f").notes.iter().any(|n| n == NOTE),
            "{:?}",
            res(&planned, "f").notes
        );
        assert!(mutations(&planned.commands).is_empty(), "plan mutated");
        note_in_text_and_json(&planned);

        let applied = run(&p, Mode::Apply, target(sequential));
        assert_eq!(
            applied.status,
            AggregateStatus::Success,
            "{:?}",
            applied.resources
        );
        let r = res(&applied, "f");
        assert_eq!(r.change, Change::Changed);
        assert!(r.notes.iter().any(|n| n == NOTE), "{:?}", r.notes);
        note_in_text_and_json(&applied);
        staging_removed(&applied, "f");
        let fs = fs_of(&applied);
        assert_eq!(bytes(fs, "/opt/app/x.conf").unwrap(), b"new\n");
        let n = &fs.nodes["/opt/app/x.conf"];
        assert_eq!((n.uid, n.mode & 0o7777), (0, 0o644));
        assert_eq!(
            publishes(&applied.commands, "new"),
            1,
            "published exclusively"
        );
        nothing_followed(&applied.commands, "/opt/app/x.conf");

        // The second run converges and rewrites nothing.
        let mut t = target(sequential);
        t.fs = applied.fake_fs.clone();
        let again = run(&p, Mode::Apply, t);
        assert_eq!(again.status, AggregateStatus::Success);
        assert_eq!(res(&again, "f").change, Change::None);
        assert!(mutations(&again.commands).is_empty());
    }
}

#[test]
fn a_listed_direct_parent_replaces_a_file_and_keeps_its_owner_and_mode() {
    for sequential in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &[D], &file_res("/opt/app/x.conf", ""));
        let t = || with_file(target(sequential), "/opt/app/x.conf", b"old\n", 0o640, 0);
        let planned = run(&p, Mode::Plan, t());
        assert_eq!(planned.status, AggregateStatus::Success);
        assert_eq!(res(&planned, "f").change, Change::Changed);
        assert!(res(&planned, "f").notes.iter().any(|n| n == NOTE));
        let applied = run(&p, Mode::Apply, t());
        assert_eq!(
            applied.status,
            AggregateStatus::Success,
            "{:?}",
            applied.resources
        );
        assert!(res(&applied, "f").notes.iter().any(|n| n == NOTE));
        staging_removed(&applied, "f");
        let fs = fs_of(&applied);
        assert_eq!(bytes(fs, "/opt/app/x.conf").unwrap(), b"new\n");
        assert_eq!(fs.nodes["/opt/app/x.conf"].mode & 0o7777, 0o640);
        assert_eq!(publishes(&applied.commands, "replace"), 1);
        nothing_followed(&applied.commands, "/opt/app/x.conf");
    }
}

#[test]
fn a_listed_direct_parent_publishes_a_template_and_a_file_merge() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir, "t.tmpl", "from a template\n");
    let p = recipe(
        &dir,
        &[D],
        "  - id: t\n    type: template\n    with:\n      path: /opt/app/t.conf\n      source: t.tmpl\n  - id: m\n    type: file_merge\n    with:\n      path: /opt/app/m.conf\n      merge: line\n      line: 'added = yes'\n",
    );
    let t = || with_file(base(), "/opt/app/m.conf", b"kept = 1\n", 0o644, 0);
    let planned = run(&p, Mode::Plan, t());
    assert_eq!(planned.status, AggregateStatus::Success);
    for id in ["t", "m"] {
        assert_eq!(res(&planned, id).change, Change::Changed, "{id}");
        assert!(res(&planned, id).notes.iter().any(|n| n == NOTE), "{id}");
    }
    let applied = run(&p, Mode::Apply, t());
    assert_eq!(
        applied.status,
        AggregateStatus::Success,
        "{:?}",
        applied.resources
    );
    let fs = fs_of(&applied);
    assert_eq!(bytes(fs, "/opt/app/t.conf").unwrap(), b"from a template\n");
    assert_eq!(
        bytes(fs, "/opt/app/m.conf").unwrap(),
        b"kept = 1\nadded = yes\n"
    );
    for id in ["t", "m"] {
        assert!(res(&applied, id).notes.iter().any(|n| n == NOTE), "{id}");
        staging_removed(&applied, id);
    }
    nothing_followed(&applied.commands, "/opt/app/m.conf");
}

#[test]
fn a_listed_direct_parent_removes_a_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &[D],
        "  - id: f\n    type: file\n    with:\n      path: /opt/app/x.conf\n      state: absent\n",
    );
    let t = || with_file(base(), "/opt/app/x.conf", b"old\n", 0o644, 0);
    let planned = run(&p, Mode::Plan, t());
    assert_eq!(planned.status, AggregateStatus::Success);
    assert_eq!(res(&planned, "f").change, Change::Changed);
    assert!(res(&planned, "f").notes.iter().any(|n| n == NOTE));
    let applied = run(&p, Mode::Apply, t());
    assert_eq!(applied.status, AggregateStatus::Success);
    assert!(res(&applied, "f").notes.iter().any(|n| n == NOTE));
    assert!(!fs_of(&applied).nodes.contains_key("/opt/app/x.conf"));
}

#[test]
fn a_sensitive_resource_carries_the_note_and_no_content() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &[D],
        "  - id: f\n    type: file\n    sensitive: true\n    with:\n      path: /opt/app/s.conf\n      content: \"SYNTHETIC-SENSITIVE-VALUE\\n\"\n",
    );
    let t = || {
        with_file(
            base(),
            "/opt/app/s.conf",
            b"SYNTHETIC-OLD-VALUE\n",
            0o600,
            0,
        )
    };
    let planned = run(&p, Mode::Plan, t());
    let applied = run(&p, Mode::Apply, t());
    assert_eq!(
        applied.status,
        AggregateStatus::Success,
        "{:?}",
        applied.resources
    );
    for r in [&planned, &applied] {
        assert!(res(r, "f").notes.iter().any(|n| n == NOTE));
        let shown = shown_apply(r);
        assert!(!shown.contains("SYNTHETIC-SENSITIVE-VALUE"), "{shown}");
        assert!(!shown.contains("SYNTHETIC-OLD-VALUE"), "{shown}");
    }
}

// ---------------------------------------------------------------------------
// conditions of the exception
// ---------------------------------------------------------------------------

#[test]
fn a_listed_directory_that_is_not_the_direct_parent_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &["/opt/w"], &file_res("/opt/w/sub/x.conf", ""));
    for sequential in [false, true] {
        let e = plan_err(&p, target(sequential)).message;
        assert!(
            e.contains("parent path /opt/w grants group or other write access"),
            "{e}"
        );
        assert!(e.contains("allow_writable_parents lists /opt/w"), "{e}");
        assert!(e.contains("not the direct parent"), "{e}");
        let applied = run(&p, Mode::Apply, target(sequential));
        assert!(apply_failure(&applied, "f").contains("not the direct parent"));
        assert!(mutations(&applied.commands).is_empty());
    }
}

#[test]
fn another_unlisted_writable_parent_in_the_same_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &["/opt/w/d2"], &file_res("/opt/w/d2/x.conf", ""));
    let e = plan_err(&p, base()).message;
    assert!(
        e.contains("parent path /opt/w grants group or other write access"),
        "{e}"
    );
    let applied = run(&p, Mode::Apply, base());
    assert!(apply_failure(&applied, "f").contains("/opt/w grants"));
    assert!(bytes(fs_of(&applied), "/opt/w/d2/x.conf").is_none());
}

#[test]
fn a_listed_directory_that_is_a_symlink_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &["/opt/lnk"], &file_res("/opt/lnk/x.conf", ""));
    for sequential in [false, true] {
        let e = plan_err(&p, target(sequential)).message;
        assert!(e.contains("parent path /opt/lnk is a symlink"), "{e}");
        assert!(e.contains("allow_writable_parents lists it"), "{e}");
    }
    let applied = run(&p, Mode::Apply, base());
    assert!(apply_failure(&applied, "f").contains("symlink"));
    assert!(bytes(fs_of(&applied), "/opt/app/x.conf").is_none());
}

#[test]
fn a_listed_directory_owned_by_another_account_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &["/opt/alicedir"],
        &file_res("/opt/alicedir/x.conf", ""),
    );
    for sequential in [false, true] {
        let e = plan_err(&p, target(sequential)).message;
        assert!(
            e.contains("allow_writable_parents lists /opt/alicedir"),
            "{e}"
        );
        assert!(e.contains("owned by uid 1001"), "{e}");
    }
    let applied = run(&p, Mode::Apply, base());
    assert!(apply_failure(&applied, "f").contains("owned by uid 1001"));
    assert!(mutations(&applied.commands).is_empty());
}

#[test]
fn a_listed_directory_inside_another_accounts_tree_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &["/home/alice/rootpub"],
        &file_res("/home/alice/rootpub/x.conf", "      owner: alice\n"),
    );
    let e = plan_err(&p, base()).message;
    assert!(
        e.contains("allow_writable_parents lists /home/alice/rootpub"),
        "{e}"
    );
    assert!(e.contains("inside another account's directory"), "{e}");
    let applied = run(&p, Mode::Apply, base());
    assert!(apply_failure(&applied, "f").contains("inside another account's directory"));
    assert!(mutations(&applied.commands).is_empty());
}

#[test]
fn an_unprivileged_run_is_refused_with_the_root_condition() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &[D], &file_res("/opt/app/x.conf", ""));
    let e = plan_err(&p, base_user()).message;
    assert!(e.contains("allow_writable_parents lists /opt/app"), "{e}");
    assert!(e.contains("not as root"), "{e}");
    let applied = run(&p, Mode::Apply, base_user());
    assert!(apply_failure(&applied, "f").contains("not as root"));
    assert!(mutations(&applied.commands).is_empty());
}

#[test]
fn an_entry_that_is_a_symlink_another_accounts_or_hard_linked_is_refused() {
    let cases: Vec<(&str, FakeTarget, &str)> = vec![
        (
            "symlink",
            {
                let mut t = base();
                t.fs.as_mut()
                    .unwrap()
                    .put_symlink("/opt/app/x.conf", "/root/secret", 0, 0);
                t
            },
            "is a symlink in /opt/app, a directory other accounts can write to",
        ),
        (
            "alice's",
            with_file(base(), "/opt/app/x.conf", b"alice\n", 0o644, ALICE),
            "belongs to uid 1001",
        ),
        (
            "two links",
            {
                let mut t = with_file(base(), "/opt/app/x.conf", b"old\n", 0o644, 0);
                t.fs.as_mut()
                    .unwrap()
                    .put_hardlink("/opt/app/x.conf", "/opt/app/other");
                t
            },
            "hard links",
        ),
    ];
    for (what, t, want) in cases {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &[D], &file_res("/opt/app/x.conf", ""));
        let e = plan_err(&p, t.clone()).message;
        assert!(e.contains(want), "{what}: {e}");
        let applied = run(&p, Mode::Apply, t);
        assert!(apply_failure(&applied, "f").contains(want), "{what}");
        assert!(mutations(&applied.commands).is_empty(), "{what}");
        assert!(!format!("{:?}", applied.resources).contains("SYNTHETIC-ROOT-ONLY"));
        assert_eq!(
            bytes(fs_of(&applied), "/root/secret").unwrap(),
            SECRET.as_bytes()
        );
    }
}

// ---------------------------------------------------------------------------
// operations the exception does not allow
// ---------------------------------------------------------------------------

#[test]
fn a_metadata_only_change_is_refused_in_plan_and_apply() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &[D],
        &file_res("/opt/app/x.conf", "      mode: \"0600\"\n"),
    );
    let t = || with_file(base(), "/opt/app/x.conf", b"new\n", 0o644, 0);
    let e = plan_err(&p, t()).message;
    assert!(
        e.contains("a change of owner, group or mode alone is not supported there"),
        "{e}"
    );
    let applied = run(&p, Mode::Apply, t());
    let why = apply_failure(&applied, "f");
    assert!(
        why.contains("a change of owner, group or mode alone"),
        "{why}"
    );
    assert!(mutations(&applied.commands).is_empty());
    assert_eq!(
        fs_of(&applied).nodes["/opt/app/x.conf"].mode & 0o7777,
        0o644
    );
    // The same content with a new mode in one publication is allowed.
    let dir2 = tempfile::tempdir().unwrap();
    let p2 = recipe(
        &dir2,
        &[D],
        &file_res("/opt/app/x.conf", "      mode: \"0600\"\n"),
    );
    let t2 = with_file(base(), "/opt/app/x.conf", b"old\n", 0o644, 0);
    let applied = run(&p2, Mode::Apply, t2);
    assert_eq!(
        applied.status,
        AggregateStatus::Success,
        "{:?}",
        applied.resources
    );
    assert_eq!(
        fs_of(&applied).nodes["/opt/app/x.conf"].mode & 0o7777,
        0o600
    );
}

#[test]
fn a_validate_command_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &[D],
        &file_res(
            "/opt/app/x.conf",
            "      validate:\n        program: /usr/bin/true\n",
        ),
    );
    let e = plan_err(&p, base()).message;
    assert!(e.contains("a validate command"), "{e}");
    let applied = run(&p, Mode::Apply, base());
    assert!(apply_failure(&applied, "f").contains("a validate command"));
    assert!(mutations(&applied.commands).is_empty());
}

#[test]
fn a_directory_and_a_link_in_a_listed_directory_are_refused() {
    for (body, want) in [
        (
            "  - id: f\n    type: directory\n    with:\n      path: /opt/app/sub\n",
            "a directory is not supported there",
        ),
        (
            "  - id: f\n    type: link\n    with:\n      path: /opt/app/l\n      target: /etc/hostname\n",
            "a link is not supported there",
        ),
        (
            "  - id: f\n    type: directory\n    with:\n      path: /opt/app/a/b\n      parents: true\n",
            "/opt/app",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &[D], body);
        let e = plan_err(&p, base()).message;
        assert!(e.contains(want), "{body}: {e}");
        let applied = run(&p, Mode::Apply, base());
        let why = apply_failure(&applied, "f");
        assert!(why.contains(want), "{body}: {why}");
        assert!(mutations(&applied.commands).is_empty(), "{body}");
        assert!(
            !fs_of(&applied).nodes.keys().any(|k| k.starts_with("/opt/app/")),
            "{body}"
        );
    }
}

#[test]
fn a_backup_of_a_path_in_a_listed_directory_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = write(
        &dir,
        "r.yaml",
        "version: 1\nallow_writable_parents: [/opt/app]\nbackup:\n  paths:\n    - /opt/app/x.conf\nresources:\n  - id: f\n    type: file\n    with:\n      path: /opt/app/x.conf\n      content: \"new\\n\"\n",
    );
    let t = with_file(base(), "/opt/app/x.conf", b"old\n", 0o644, 0);
    let e = engine(&p, Mode::Apply, false, t).run();
    let msg = match e {
        Err(e) => e.message,
        Ok(r) => format!(
            "{:?} {:?}",
            r.backup,
            r.resources.iter().map(|x| &x.reason).collect::<Vec<_>>()
        ),
    };
    assert!(msg.contains("a backup is not supported there"), "{msg}");
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------

#[test]
fn a_replacement_of_the_entry_before_publication_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &[D], &file_res("/opt/app/x.conf", ""));
    // Another account replaces the file (a new inode) right before staging.
    let t = with_file(base(), "/opt/app/x.conf", b"old\n", 0o644, 0).with_fs_event(
        "sh",
        "stage",
        0,
        vec![
            FsEventAction::Remove {
                path: "/opt/app/x.conf".into(),
            },
            FsEventAction::PutFile {
                path: "/opt/app/x.conf".into(),
                data: b"swapped\n".to_vec(),
                mode: 0o644,
                uid: 0,
                gid: 0,
            },
        ],
    );
    let applied = run(&p, Mode::Apply, t);
    let why = apply_failure(&applied, "f");
    assert!(why.contains("drift"), "{why}");
    assert_eq!(publishes(&applied.commands, "replace"), 0);
    assert_eq!(
        bytes(fs_of(&applied), "/opt/app/x.conf").unwrap(),
        b"swapped\n"
    );
}

#[test]
fn a_change_of_the_entry_while_it_is_read_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &[D], &file_res("/opt/app/x.conf", ""));
    let t = with_file(base(), "/opt/app/x.conf", b"old\n", 0o644, 0).with_fs_event(
        "dd",
        "if=/opt/app/x.conf",
        0,
        vec![FsEventAction::WriteInPlace {
            path: "/opt/app/x.conf".into(),
            data: b"oth\n".to_vec(),
        }],
    );
    let applied = run(&p, Mode::Apply, t);
    let why = apply_failure(&applied, "f");
    assert!(why.contains("changed while it was read"), "{why}");
    assert!(mutations(&applied.commands).is_empty());
}

#[test]
fn a_symlink_swapped_in_before_the_read_is_never_followed() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &[D], &file_res("/opt/app/x.conf", ""));
    let t = with_file(base(), "/opt/app/x.conf", b"old\n", 0o644, 0).with_fs_event(
        "dd",
        "if=/opt/app/x.conf",
        0,
        vec![
            FsEventAction::Remove {
                path: "/opt/app/x.conf".into(),
            },
            FsEventAction::PutSymlink {
                path: "/opt/app/x.conf".into(),
                target: "/root/secret".into(),
                uid: ALICE,
                gid: ALICE,
            },
        ],
    );
    let applied = run(&p, Mode::Apply, t);
    let why = apply_failure(&applied, "f");
    assert!(!why.contains("SYNTHETIC-ROOT-ONLY"), "{why}");
    assert!(!shown_apply(&applied).contains("SYNTHETIC-ROOT-ONLY"));
    nothing_followed(&applied.commands, "/opt/app/x.conf");
    assert!(mutations(&applied.commands).is_empty());
}

// ---------------------------------------------------------------------------
// the field itself
// ---------------------------------------------------------------------------

#[test]
fn loading_the_field_warns_once_per_directory_in_yaml_and_toml() {
    let dir = tempfile::tempdir().unwrap();
    let y = write(
        &dir,
        "r.yaml",
        "version: 1\nallow_writable_parents: [/opt/app, /srv/drop]\nresources: []\n",
    );
    let t = write(
        &dir,
        "r.toml",
        "version = 1\nallow_writable_parents = [\"/opt/app\", \"/srv/drop\"]\nresources = []\n",
    );
    for p in [y, t] {
        let m = load_model(&p).unwrap();
        assert_eq!(m.writable_parents, vec!["/opt/app", "/srv/drop"]);
        for d in ["/opt/app", "/srv/drop"] {
            assert_eq!(
                m.warnings
                    .iter()
                    .filter(|w| w.contains(&format!("allow_writable_parents lists {d}:")))
                    .count(),
                1,
                "{:?}",
                m.warnings
            );
        }
    }
}

#[test]
fn invalid_forms_of_the_field_are_refused_at_load() {
    let many: Vec<String> = (0..33).map(|i| format!("/opt/d{i}")).collect();
    let many = format!("[{}]", many.join(", "));
    for (value, want) in [
        ("/opt/app", "must be a list"),
        ("[]", "at least one"),
        ("[opt/app]", "absolute"),
        ("[/]", "root directory"),
        ("[/opt/app/]", "trailing slash"),
        ("[/opt//app]", "repeated separators"),
        ("[/opt/./app]", ". or .."),
        ("[/opt/../app]", ". or .."),
        ("[/opt/app, /opt/app]", "more than once"),
        ("[1]", "strings"),
        ("[\"/opt/{{ vars.x }}\"]", "not a static path"),
        (many.as_str(), "at most 32"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            &dir,
            "r.yaml",
            &format!("version: 1\nvars:\n  x: {{ value: app }}\nallow_writable_parents: {value}\nresources: []\n"),
        );
        let e = load_model(&p)
            .err()
            .unwrap_or_else(|| panic!("{value} accepted"));
        assert!(
            e.message.contains("allow_writable_parents"),
            "{value}: {}",
            e.message
        );
        assert!(e.message.contains(want), "{value}: {}", e.message);
    }
}

#[test]
fn the_field_is_refused_in_an_included_file() {
    let dir = tempfile::tempdir().unwrap();
    write(
        &dir,
        "inc.yaml",
        "version: 1\nallow_writable_parents: [/opt/app]\nresources: []\n",
    );
    let p = write(
        &dir,
        "r.yaml",
        "version: 1\ninclude: [inc.yaml]\nresources: []\n",
    );
    let e = load_model(&p).expect_err("included field accepted");
    assert!(
        e.message
            .contains("allow_writable_parents may only be declared in the top-level recipe"),
        "{}",
        e.message
    );
}

#[test]
fn a_bundle_recipe_never_gets_another_recipes_list() {
    let dir = tempfile::tempdir().unwrap();
    write(
        &dir,
        "a.yaml",
        "version: 1\nallow_writable_parents: [/opt/app]\nresources:\n  - id: a\n    type: file\n    with:\n      path: /opt/app/a.conf\n      content: \"a\\n\"\n",
    );
    write(
        &dir,
        "b.yaml",
        "version: 1\nresources:\n  - id: b\n    type: file\n    with:\n      path: /opt/app/b.conf\n      content: \"b\\n\"\n",
    );
    let bundle = write(
        &dir,
        "bundle.yaml",
        "version: 1\nname: synthetic\nrecipes:\n  - a.yaml\n  - b.yaml\n",
    );
    let sinter::bundle::Source::Bundle(b) = sinter::bundle::load_source(&bundle).unwrap() else {
        panic!("not a bundle");
    };
    assert_eq!(b.recipes[0].model.writable_parents, vec![D]);
    assert!(b.recipes[1].model.writable_parents.is_empty());
    let mut fs = None;
    for unit in &b.recipes {
        let mut t = base();
        if fs.is_some() {
            t.fs = fs.clone();
        }
        let r = Engine::new(
            unit.model.clone(),
            RunOptions {
                mode: Mode::Apply,
                sudo: false,
                target: TargetSpec { ssh: None },
                verbose: true,
                fault: None,
                fake_target: Some(t),
            },
        )
        .unwrap()
        .run()
        .unwrap();
        fs = r.fake_fs.clone();
        if unit.label == "a" {
            assert_eq!(r.status, AggregateStatus::Success, "{:?}", r.resources);
        } else {
            assert!(apply_failure(&r, "b").contains("grants group or other write access"));
        }
    }
    let fs = fs.unwrap();
    assert!(fs.file_bytes("/opt/app/a.conf").is_some());
    assert!(fs.file_bytes("/opt/app/b.conf").is_none());

    // A bundle file has no such field.
    let bad = write(
        &dir,
        "bad.yaml",
        "version: 1\nname: synthetic\nallow_writable_parents: [/opt/app]\nrecipes:\n  - b.yaml\n",
    );
    assert!(sinter::bundle::load_source(&bad).is_err());
}

// ---------------------------------------------------------------------------
// audit (§63.3)
// ---------------------------------------------------------------------------

const UNOTE: &str = "parent /opt/app2 is writable by other accounts: observed without following links; Sinter refuses to change this path unless allow_writable_parents lists /opt/app2";

fn audit_file(allow: &[&str], path: &str, extra: &str, t: FakeTarget) -> AuditReport {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, allow, &file_res(path, extra));
    audit(&p, t)
}

/// Audit reads only, and reads the file only with `dd iflag=nofollow`.
fn audit_read_only(r: &AuditReport, path: &str) {
    assert!(
        mutations(&r.commands).is_empty(),
        "{:?}",
        mutations(&r.commands)
    );
    nothing_followed(&r.commands, path);
}

#[test]
fn audit_of_an_unlisted_writable_parent_is_compliant_or_drift_with_the_note() {
    let x = "/opt/app2/x.conf";
    // compliant
    let r = audit_file(&[], x, "", with_file(base(), x, b"new\n", 0o644, 0));
    let a = ares(&r, "f");
    assert_eq!(a.status, AuditResourceStatus::Compliant, "{a:?}");
    assert!(a.reason.as_deref().unwrap_or("").contains(UNOTE), "{a:?}");
    let (text, json) = shown_audit(&r);
    assert!(
        text.contains("COMPLIANT") || text.contains("compliant"),
        "{text}"
    );
    assert!(json.contains("observed without following links"), "{json}");
    assert!(!text.contains("new\n") && !json.contains("new\\n"));
    audit_read_only(&r, x);
    assert!(r.commands.iter().any(|c| base_name(&c.program) == "dd"));

    // drift: content, mode, owner
    for (data, extra, dim) in [
        (&b"old\n"[..], "", "content"),
        (&b"new\n"[..], "      mode: \"0600\"\n", "mode"),
        (&b"new\n"[..], "      owner: alice\n", "owner"),
    ] {
        let r = audit_file(&[], x, extra, with_file(base(), x, data, 0o644, 0));
        let a = ares(&r, "f");
        assert_eq!(a.status, AuditResourceStatus::Drift, "{dim}: {a:?}");
        assert!(a.details.iter().any(|d| d.dimension == dim), "{dim}: {a:?}");
        assert!(a.reason.as_deref().unwrap_or("").contains(UNOTE), "{dim}");
        audit_read_only(&r, x);
    }
    // A listed directory says that publishing is allowed.
    let r = audit_file(
        &[D],
        "/opt/app/x.conf",
        "",
        with_file(base(), "/opt/app/x.conf", b"new\n", 0o644, 0),
    );
    let a = ares(&r, "f");
    assert_eq!(a.status, AuditResourceStatus::Compliant, "{a:?}");
    assert!(
        a.reason
            .as_deref()
            .unwrap_or("")
            .contains("allowed by allow_writable_parents for publishing"),
        "{a:?}"
    );
}

#[test]
fn audit_in_a_writable_parent_keeps_every_other_fault_an_error() {
    let x = "/opt/app2/x.conf";
    let big = vec![b'a'; 300 * 1024];
    let cases: Vec<(&str, &str, FakeTarget)> = vec![
        ("entry symlink", x, {
            let mut t = base();
            t.fs.as_mut().unwrap().put_symlink(x, "/root/secret", 0, 0);
            t
        }),
        ("two hard links", x, {
            let mut t = with_file(base(), x, b"new\n", 0o644, 0);
            t.fs.as_mut().unwrap().put_hardlink(x, "/opt/app2/y");
            t
        }),
        (
            "untrusted owner",
            x,
            with_file(base(), x, b"new\n", 0o644, ALICE),
        ),
        ("oversize", x, with_file(base(), x, &big, 0o644, 0)),
        (
            "deeper writable ancestor",
            "/opt/w/sub/x.conf",
            with_file(base(), "/opt/w/sub/x.conf", b"new\n", 0o644, 0),
        ),
        (
            "changed between the lstats",
            x,
            with_file(base(), x, b"new\n", 0o644, 0).with_fs_event(
                "dd",
                &format!("if={x}"),
                0,
                vec![FsEventAction::WriteInPlace {
                    path: x.into(),
                    data: b"new\n".to_vec(),
                }],
            ),
        ),
        (
            "failed read",
            x,
            with_file(base(), x, b"new\n", 0o644, 0).with_fs_event(
                "dd",
                &format!("if={x}"),
                0,
                vec![FsEventAction::FailCommand {
                    code: 1,
                    stderr: "dd: error reading: Input/output error\n".into(),
                }],
            ),
        ),
    ];
    for (what, path, t) in cases {
        let r = audit_file(&[], path, "", t);
        let a = ares(&r, "f");
        assert_eq!(a.status, AuditResourceStatus::Error, "{what}: {a:?}");
        audit_read_only(&r, path);
        assert!(!format!("{a:?}").contains("SYNTHETIC-ROOT-ONLY"), "{what}");
    }
}

#[test]
fn audit_of_a_missing_parent_is_still_absence() {
    // The direct parent does not exist, every ancestor above it is trusted.
    let r = audit_file(&[], "/opt/nothere/x.conf", "", base());
    assert_eq!(ares(&r, "f").status, AuditResourceStatus::Drift);
    // A missing directory below a writable one is not the direct parent's
    // fault alone: still an error, as before.
    let r = audit_file(&[], "/opt/app2/none/x.conf", "", base());
    assert_eq!(ares(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_of_a_template_a_file_merge_and_a_directory_in_a_writable_parent() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir, "t.tmpl", "tpl\n");
    let p = recipe(
        &dir,
        &[],
        "  - id: t\n    type: template\n    with:\n      path: /opt/app2/t.conf\n      source: t.tmpl\n  - id: m\n    type: file_merge\n    with:\n      path: /opt/app2/m.conf\n      merge: line\n      line: 'a = 1'\n  - id: d\n    type: directory\n    with:\n      path: /opt/app2/sub\n      mode: \"0755\"\n",
    );
    let mut t = with_file(base(), "/opt/app2/t.conf", b"tpl\n", 0o644, 0);
    t = with_file(t, "/opt/app2/m.conf", b"a = 1\n", 0o644, 0);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/opt/app2/sub", 0o755, 0, 0);
    let r = audit(&p, t);
    for id in ["t", "m", "d"] {
        let a = ares(&r, id);
        assert_eq!(a.status, AuditResourceStatus::Compliant, "{id}: {a:?}");
        assert!(
            a.reason
                .as_deref()
                .unwrap_or("")
                .contains("observed without following links"),
            "{id}"
        );
    }
    audit_read_only(&r, "/opt/app2/t.conf");
    audit_read_only(&r, "/opt/app2/m.conf");
}

#[test]
fn plan_is_not_relaxed_by_the_audit_rule() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &[], &file_res("/opt/app2/x.conf", ""));
    let t = || with_file(base(), "/opt/app2/x.conf", b"old\n", 0o644, 0);
    let e = plan_err(&p, t()).message;
    assert!(e.contains("grants group or other write access"), "{e}");
    // Audit of the same recipe observes it.
    let r = audit(&p, t());
    assert_eq!(ares(&r, "f").status, AuditResourceStatus::Drift);
    assert!(matches!(
        fs_of(&run(&p, Mode::Apply, t())).nodes["/opt/app2/x.conf"].kind,
        FakeKind::File(ref b) if b == b"old\n"
    ));
}

#[test]
fn an_owner_other_than_a_trusted_principal_is_refused_in_a_listed_directory() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &[D],
        &file_res("/opt/app/x.conf", "      owner: alice\n"),
    );
    let e = plan_err(&p, base()).message;
    assert!(
        e.contains("cannot give /opt/app/x.conf to uid 1001: it lies in /opt/app, a directory other accounts can write to, where"),
        "{e}"
    );
    let applied = run(&p, Mode::Apply, base());
    assert!(apply_failure(&applied, "f").contains("cannot give"));
    assert!(mutations(&applied.commands).is_empty());
}

#[test]
fn listing_a_directory_nobody_else_can_write_to_changes_nothing() {
    // A large file in a safe directory is still compared by `sha256sum`: the
    // reads that never follow a link (and their size limit) apply only where
    // a walk accepted a writable directory.
    let big = vec![b'a'; 300 * 1024];
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &["/opt/safe"], &file_res("/opt/safe/big", ""));
    let t = || with_file(base(), "/opt/safe/big", &big, 0o644, 0);
    let planned = run(&p, Mode::Plan, t());
    assert_eq!(planned.status, AggregateStatus::Success);
    assert!(res(&planned, "f")
        .notes
        .iter()
        .all(|n| !n.contains("writable")));
    let applied = run(&p, Mode::Apply, t());
    assert_eq!(
        applied.status,
        AggregateStatus::Success,
        "{:?}",
        applied.resources
    );
    assert!(applied
        .commands
        .iter()
        .any(|c| base_name(&c.program) == "sha256sum"));
}

#[test]
fn a_file_over_the_read_limit_in_a_listed_directory_is_refused_before_anything_is_written() {
    let big = vec![b'a'; 300 * 1024];
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &[D], &file_res("/opt/app/big", ""));
    let t = || with_file(base(), "/opt/app/big", &big, 0o644, 0);
    let e = plan_err(&p, t()).message;
    assert!(e.contains("is larger than 262144 bytes"), "{e}");
    let applied = run(&p, Mode::Apply, t());
    assert!(apply_failure(&applied, "f").contains("larger than"));
    assert!(mutations(&applied.commands).is_empty());
}

// ---------------------------------------------------------------------------
// D-1: a file another account renamed (or linked) into a listed directory
// ---------------------------------------------------------------------------

const CANARY: &str = "SYNTHETIC-ROOT-ONLY";
const WITHHELD: &str =
    "content diff not shown: the file is in a directory other accounts can write to";

/// Another account renamed a root-only 0600 file into the managed name
/// (`mv D/secret.conf D/x.conf`, or from another directory it can write on
/// the same file system): to the entry gate it is a root file with one link.
fn planted(t: FakeTarget, path: &str) -> FakeTarget {
    with_file(t, path, SECRET.as_bytes(), 0o600, 0)
}

fn merge_res(id: &str, path: &str, extra: &str) -> String {
    format!(
        "  - id: {id}\n    type: file_merge\n    with:\n      path: {path}\n      merge: line\n      line: 'added = yes'\n{extra}"
    )
}

#[test]
fn a_file_planted_in_a_listed_directory_is_never_shown_by_plan_or_apply() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir, "t.tmpl", "from a template\n");
    let p = recipe(
        &dir,
        &[D],
        &format!(
            "{}  - id: t\n    type: template\n    with:\n      path: /opt/app/t.conf\n      source: t.tmpl\n{}",
            file_res("/opt/app/x.conf", ""),
            merge_res("m", "/opt/app/m.conf", "")
        ),
    );
    let t = || {
        let mut t = base();
        for path in ["/opt/app/x.conf", "/opt/app/t.conf", "/opt/app/m.conf"] {
            t = planted(t, path);
        }
        t
    };
    for sequential in [false, true] {
        let mut t0 = t();
        if sequential {
            t0 = t0.with_executable("/usr/bin/getfacl");
        }
        let planned = run(&p, Mode::Plan, t0.clone());
        assert_eq!(
            planned.status,
            AggregateStatus::Success,
            "{:?}",
            planned.resources
        );
        let shown = shown_apply(&planned);
        assert!(
            !shown.contains(CANARY),
            "plan shows the planted file: {shown}"
        );
        for id in ["f", "t", "m"] {
            let r = res(&planned, id);
            assert_eq!(r.change, Change::Changed, "{id}");
            assert!(
                r.notes.iter().any(|n| n.starts_with(WITHHELD)),
                "{id}: {:?}",
                r.notes
            );
            match &r.diff.as_ref().expect("a diff").body {
                sinter::result::DiffBody::Summary { current, .. } => {
                    assert_eq!(
                        current,
                        &format!("{} bytes, content differs (not shown)", SECRET.len()),
                        "{id}"
                    )
                }
                other => panic!("{id}: not a summary: {other:?}"),
            }
        }
        assert!(shown.contains("content differs (not shown)"), "{shown}");
        assert!(mutations(&planned.commands).is_empty());

        let applied = run(&p, Mode::Apply, t0);
        assert_eq!(
            applied.status,
            AggregateStatus::Success,
            "{:?}",
            applied.resources
        );
        assert!(!shown_apply(&applied).contains(CANARY));
        // file_merge keeps the planted content, readable by no more accounts
        // than before: root's, 0600.
        let fs = fs_of(&applied);
        let n = &fs.nodes["/opt/app/m.conf"];
        assert_eq!((n.uid, n.gid, n.mode & 0o7777), (0, 0, 0o600));
        assert_eq!(
            bytes(fs, "/opt/app/m.conf").unwrap(),
            format!("{SECRET}added = yes\n").into_bytes()
        );
    }
}

#[test]
fn file_merge_does_not_widen_the_readers_of_a_planted_file() {
    // The audit's reproduction: root 0600 planted, `mode: "0644"` declared.
    for (extra, want) in [
        (
            "      mode: \"0644\"\n",
            "the declared mode 0644 adds read permission (0044) that the existing mode 0600 does not grant",
        ),
        (
            "      mode: \"0640\"\n",
            "the declared mode 0640 adds read permission (0040)",
        ),
        (
            "      group: alice\n",
            "the declared group (gid 1001) is not the existing group (gid 0)",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &[D], &merge_res("m", "/opt/app/m.conf", extra));
        let t = || planted(base(), "/opt/app/m.conf");
        let e = plan_err(&p, t()).message;
        assert!(e.contains(want), "{extra}: {e}");
        assert!(e.contains("a directory other accounts can write to"), "{e}");
        assert!(!e.contains(CANARY), "{e}");
        let applied = run(&p, Mode::Apply, t());
        let why = apply_failure(&applied, "m");
        assert!(why.contains(want), "{extra}: {why}");
        assert_eq!(publishes(&applied.commands, "replace"), 0, "{extra}");
        let fs = fs_of(&applied);
        assert_eq!(bytes(fs, "/opt/app/m.conf").unwrap(), SECRET.as_bytes());
        assert_eq!(fs.nodes["/opt/app/m.conf"].mode & 0o7777, 0o600);
    }
    // Unchanged (or narrower) metadata is allowed and the result stays root's.
    for (extra, mode) in [
        ("", 0o600),
        (
            "      mode: \"0600\"\n      owner: root\n      group: root\n",
            0o600,
        ),
        ("      mode: \"0400\"\n", 0o400),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &[D], &merge_res("m", "/opt/app/m.conf", extra));
        let applied = run(&p, Mode::Apply, planted(base(), "/opt/app/m.conf"));
        assert_eq!(
            applied.status,
            AggregateStatus::Success,
            "{extra}: {:?}",
            applied.resources
        );
        let n = &fs_of(&applied).nodes["/opt/app/m.conf"];
        assert_eq!((n.uid, n.gid, n.mode & 0o7777), (0, 0, mode), "{extra}");
    }
    // A file that does not exist: the declared metadata applies.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &[D],
        &merge_res(
            "m",
            "/opt/app/new.conf",
            "      create: true\n      mode: \"0644\"\n",
        ),
    );
    let applied = run(&p, Mode::Apply, base());
    assert_eq!(
        applied.status,
        AggregateStatus::Success,
        "{:?}",
        applied.resources
    );
    let fs = fs_of(&applied);
    assert_eq!(bytes(fs, "/opt/app/new.conf").unwrap(), b"added = yes\n");
    assert_eq!(fs.nodes["/opt/app/new.conf"].mode & 0o7777, 0o644);
}

#[test]
fn audit_of_a_file_merge_value_in_a_writable_parent_does_not_show_it() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &[],
        "  - id: m\n    type: file_merge\n    with:\n      path: /opt/app2/m.conf\n      merge: key_value\n      key: token\n      value: wanted\n",
    );
    let t = with_file(
        base(),
        "/opt/app2/m.conf",
        format!("token = {CANARY}-CANARY\n").as_bytes(),
        0o600,
        0,
    );
    let r = audit(&p, t);
    let a = ares(&r, "m");
    assert_eq!(a.status, AuditResourceStatus::Drift, "{a:?}");
    assert!(a.details.iter().any(|d| d.dimension == "value"), "{a:?}");
    let (text, json) = shown_audit(&r);
    assert!(!text.contains(CANARY), "{text}");
    assert!(!json.contains(CANARY), "{json}");
    assert!(text.contains("not shown"), "{text}");
    audit_read_only(&r, "/opt/app2/m.conf");
}

/// The 0-based index, among the `stat` commands naming `path`, of the `lstat`
/// that opens the first read of `path` (the `stat` right before the first
/// `dd if=<path>`): an event there happens after every entry gate of that
/// observation and before the read.
fn stat_before_first_read(cmds: &[CommandRecord], path: &str) -> usize {
    let mut seen = 0;
    let mut last = None;
    for c in cmds {
        let prog = base_name(&c.program);
        if prog == "dd" && c.args.iter().any(|a| a == &format!("if={path}")) {
            return last.expect("a stat before the read");
        }
        if prog == "stat" && c.args.iter().any(|a| a == path) {
            last = Some(seen);
            seen += 1;
        }
    }
    panic!("no read of {path}");
}

#[test]
fn an_entry_swapped_in_after_the_entry_gate_is_never_read() {
    let x = "/opt/app/x.conf";
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &[D], &file_res(x, ""));
    let t = || with_file(base(), x, b"old\n", 0o644, 0);
    let nth = stat_before_first_read(&run(&p, Mode::Plan, t()).commands, x);
    let swap = |actions: Vec<FsEventAction>| t().with_fs_event("stat", x, nth, actions);
    let cases: Vec<(&str, Vec<FsEventAction>, &str)> = vec![
        (
            "renamed in",
            vec![
                FsEventAction::Remove { path: x.into() },
                FsEventAction::PutFile {
                    path: x.into(),
                    data: SECRET.as_bytes().to_vec(),
                    mode: 0o600,
                    uid: 0,
                    gid: 0,
                },
            ],
            "changed after it was checked",
        ),
        (
            "hard link",
            vec![
                FsEventAction::Remove { path: x.into() },
                FsEventAction::PutHardlink {
                    src: "/root/secret".into(),
                    dst: x.into(),
                },
            ],
            "has 2 hard links",
        ),
        (
            "owner not trusted",
            vec![FsEventAction::Chown {
                path: x.into(),
                uid: ALICE,
                gid: ALICE,
            }],
            "is not owned by root",
        ),
    ];
    for (what, actions, want) in cases {
        let r = engine(&p, Mode::Plan, false, swap(actions.clone())).run();
        let e = r.err().unwrap_or_else(|| panic!("{what}: plan must fail"));
        assert!(e.message.contains(want), "{what}: {}", e.message);
        assert!(!e.message.contains(CANARY), "{what}");
        // No read of the swapped entry ran.
        let applied = run(&p, Mode::Apply, swap(actions));
        let why = apply_failure(&applied, "f");
        assert!(why.contains(want), "{what}: {why}");
        assert!(!shown_apply(&applied).contains(CANARY), "{what}");
        assert!(mutations(&applied.commands).is_empty(), "{what}");
        assert_eq!(
            bytes(fs_of(&applied), "/root/secret").unwrap(),
            SECRET.as_bytes()
        );
    }
}

#[test]
fn file_merge_never_republishes_an_entry_swapped_in_after_the_gate() {
    let m = "/opt/app/m.conf";
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &[D], &merge_res("m", m, ""));
    let t = || with_file(base(), m, b"kept = 1\n", 0o644, 0);
    let nth = stat_before_first_read(&run(&p, Mode::Apply, t()).commands, m);
    let applied = run(
        &p,
        Mode::Apply,
        t().with_fs_event(
            "stat",
            m,
            nth,
            vec![
                FsEventAction::Remove { path: m.into() },
                FsEventAction::PutFile {
                    path: m.into(),
                    data: SECRET.as_bytes().to_vec(),
                    mode: 0o600,
                    uid: 0,
                    gid: 0,
                },
            ],
        ),
    );
    let why = apply_failure(&applied, "m");
    assert!(why.contains("changed after it was checked"), "{why}");
    assert_eq!(publishes(&applied.commands, "replace"), 0);
    let fs = fs_of(&applied);
    assert_eq!(bytes(fs, m).unwrap(), SECRET.as_bytes());
    assert_eq!(fs.nodes[m].mode & 0o7777, 0o600);
}

// ---------------------------------------------------------------------------
// NB-D1: what surviving mutants showed was untested
// ---------------------------------------------------------------------------

/// The walk memo is keyed by the operation scope too: a `file` accepted in
/// a listed directory must not let a later `directory` or `link` of the same
/// recipe in the same directory reuse that verdict in plan.
#[test]
fn a_directory_or_link_after_a_file_in_the_same_listed_directory_is_refused_in_plan() {
    for (body, want) in [
        (
            "  - id: d\n    type: directory\n    with:\n      path: /opt/app/sub\n      mode: \"0755\"\n",
            "a directory is not supported there",
        ),
        (
            "  - id: l\n    type: link\n    with:\n      path: /opt/app/l\n      target: /etc/hostname\n",
            "a link is not supported there",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(
            &dir,
            &[D],
            &format!("{}{}", file_res("/opt/app/x.conf", ""), body),
        );
        let e = plan_err(&p, base()).message;
        assert!(e.contains(want), "{body}: {e}");
    }
}

/// `getfattr`/`getfacl` follow a final link: an entry swapped while they run
/// makes the attribute inspection incomplete, so the replacement is refused.
#[test]
fn an_entry_swapped_while_its_attributes_are_read_is_refused() {
    let x = "/opt/app/x.conf";
    for sequential in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &[D], &file_res(x, ""));
        let t = || {
            with_file(target(sequential), x, b"old\n", 0o644, 0).with_fs_event(
                "getfattr",
                x,
                0,
                vec![
                    FsEventAction::Remove { path: x.into() },
                    FsEventAction::PutSymlink {
                        path: x.into(),
                        target: "/root/secret".into(),
                        uid: ALICE,
                        gid: ALICE,
                    },
                ],
            )
        };
        let e = plan_err(&p, t()).message;
        assert!(
            e.contains("cannot inspect security metadata"),
            "{sequential}: {e}"
        );
        let applied = run(&p, Mode::Apply, t());
        let why = apply_failure(&applied, "f");
        assert!(
            why.contains("cannot inspect security metadata"),
            "{sequential}: {why}"
        );
        assert_eq!(publishes(&applied.commands, "replace"), 0);
        assert_eq!(
            bytes(fs_of(&applied), "/root/secret").unwrap(),
            SECRET.as_bytes()
        );
    }
}
