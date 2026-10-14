//! FS-2: shared (sticky) directories such as `/tmp` and `/var/tmp`.
//!
//! A directory owned by a trusted principal with the sticky bit is accepted as
//! a parent even though others can write to it. What that buys is only that an
//! entry owned by a trusted principal cannot be removed or replaced by anyone
//! else, so Sinter works on those entries (and creates new ones exclusively)
//! and never reads, changes or removes an entry of another account.
//!
//! The scripted target is a modeled filesystem that answers by exact path, and
//! `with_fs_event` lets another account act between two commands. A concurrent
//! actor is judged by two things: nothing it owns is replaced, removed or
//! changed, and nothing only root can read is reached through what it placed.
#![cfg(unix)]

use sinter::audit::{run_audit, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::{CommandRecord, Completion, FakeTarget, FsEventAction};
use sinter::fakesys::{FakeFs, FakeKind, FakeNode};
use sinter::model::load_model;
use sinter::output::{render_apply, render_audit, OutputFormat, RenderOptions};
use sinter::result::{Change, Execution, ResourceResult};
use std::path::PathBuf;

const ALICE: u32 = 1001;
const SECRET: &str = "TOPSECRET-ROOT-ONLY\n";

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn add_shared_dirs(t: &mut FakeTarget) {
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/tmp", 0o1777, 0),
        ("/var", 0o755, 0),
        ("/var/tmp", 0o1777, 0),
        ("/home", 0o755, 0),
        ("/root", 0o700, 0),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    fs.put_file("/root/secret", SECRET.as_bytes(), 0o600, 0, 0);
}

/// A root login (no `--sudo`), a second account `alice`, and the usual shared
/// directories.
fn base() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("alice", ALICE)
        .with_user("alice", ALICE, ALICE, "/home/alice", "/bin/bash")
        .as_root();
    add_shared_dirs(&mut t);
    t
}

/// The connecting user is uid 1000 (not root).
fn base_user() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("alice", ALICE)
        .with_user("alice", ALICE, ALICE, "/home/alice", "/bin/bash");
    add_shared_dirs(&mut t);
    t
}

fn recipe(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\n{}", body)).unwrap();
    p
}

fn file_recipe(dir: &tempfile::TempDir, path: &str) -> PathBuf {
    recipe(
        dir,
        &format!(
            "resources:\n  - id: f\n    type: file\n    with:\n      path: {path}\n      content: \"x\\n\"\n"
        ),
    )
}

/// A file below `path`'s directory with `owner: alice` set. Inside alice's own
/// directory directly in a shared directory an `owner` is required (FS-3 C-1):
/// without one nothing says the directory is the one the recipe's author meant
/// (`tests/fs3_c1_shared_tree.rs` covers the refusal).
fn alice_file_recipe(dir: &tempfile::TempDir, path: &str) -> PathBuf {
    recipe(
        dir,
        &format!(
            "resources:\n  - id: f\n    type: file\n    with:\n      path: {path}\n      content: \"x\\n\"\n      owner: alice\n"
        ),
    )
}

fn engine_with(
    p: &std::path::Path,
    mode: Mode,
    sudo: bool,
    fault: Option<&str>,
    t: FakeTarget,
) -> Engine {
    Engine::new(
        load_model(p).unwrap(),
        RunOptions {
            mode,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: true,
            fault: fault.map(|s| s.to_string()),
            fake_target: Some(t),
        },
    )
    .unwrap()
}

fn run_as(p: &std::path::Path, mode: Mode, sudo: bool, t: FakeTarget) -> RunReport {
    engine_with(p, mode, sudo, None, t).run().unwrap()
}

fn run(p: &std::path::Path, mode: Mode, t: FakeTarget) -> RunReport {
    run_as(p, mode, false, t)
}

fn plan_err(p: &std::path::Path, t: FakeTarget) -> SinterError {
    engine_with(p, Mode::Plan, false, None, t)
        .run()
        .err()
        .expect("plan must fail")
}

fn audit(p: &std::path::Path, t: FakeTarget) -> sinter::audit::AuditReport {
    run_audit(engine_with(p, Mode::Plan, false, None, t)).unwrap()
}

fn res<'a>(r: &'a RunReport, id: &str) -> &'a ResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

fn afind<'a>(
    r: &'a sinter::audit::AuditReport,
    id: &str,
) -> &'a sinter::audit::AuditResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

fn fs_of(r: &RunReport) -> &FakeFs {
    r.fake_fs.as_ref().expect("scripted filesystem")
}

/// The target as the previous run left it.
fn continue_from(r: &RunReport) -> FakeTarget {
    let mut t = base();
    t.fs = r.fake_fs.clone();
    t
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// The program a record really runs, and its arguments, behind `setpriv`.
fn inner(c: &CommandRecord) -> (&str, &[String]) {
    if c.program == "/usr/bin/setpriv" {
        (base_name(&c.args[7]), &c.args[8..])
    } else {
        (base_name(&c.program), &c.args[..])
    }
}

// `sh` is the fixed staging script (FS-2): it stages, publishes and cleans up.
const MUTATION: [&str; 13] = [
    "mkdir", "chown", "chmod", "dd", "mv", "mktemp", "rm", "rmdir", "ln", "setfattr", "cp",
    "install", "sh",
];

/// One step of the fixed staging script: its operation and the arguments after
/// it (`sh -c <script> sh <op> <args...>`, behind `setpriv` in an account's tree).
fn fsstage(c: &CommandRecord) -> Option<(&str, &[String])> {
    let (prog, args) = inner(c);
    (prog == "sh" && args.len() >= 4 && args[0] == "-c" && args[2] == "sh")
        .then(|| (args[3].as_str(), &args[4..]))
}

/// How many steps of this operation (`stage`, `stagelink`, `publish`, `discard`) ran.
fn steps(cmds: &[CommandRecord], op: &str) -> usize {
    cmds.iter()
        .filter(|c| fsstage(c).is_some_and(|(o, _)| o == op))
        .count()
}

/// How many publications of this kind ran: `new` (an exclusive hard link,
/// `ln -T`) or `replace` (a rename, `mv -T -f`).
fn publishes(cmds: &[CommandRecord], kind: &str) -> usize {
    cmds.iter()
        .filter(|c| fsstage(c).is_some_and(|(o, a)| o == "publish" && a[0] == kind))
        .count()
}

fn mutations(cmds: &[CommandRecord]) -> Vec<String> {
    cmds.iter()
        .filter(|c| MUTATION.contains(&inner(c).0))
        .map(|c| format!("{} {:?}", inner(c).0, inner(c).1))
        .collect()
}

/// Programs (basenames) of the commands that name `path` as an operand.
fn programs_on(cmds: &[CommandRecord], path: &str) -> Vec<String> {
    cmds.iter()
        .filter(|c| inner(c).1.iter().any(|a| a == path))
        .map(|c| inner(c).0.to_string())
        .collect()
}

/// The commands as `program args`, for assertion messages.
fn trace(cmds: &[CommandRecord]) -> String {
    cmds.iter()
        .map(|c| format!("{} {:?}", inner(c).0, inner(c).1))
        .collect::<Vec<_>>()
        .join("\n")
}

fn count(cmds: &[CommandRecord], prog: &str) -> usize {
    cmds.iter().filter(|c| inner(c).0 == prog).count()
}

fn runs_as(c: &CommandRecord, uid: u32) -> bool {
    c.program == "/usr/bin/setpriv" && c.args[1] == uid.to_string()
}

fn node<'a>(fs: &'a FakeFs, path: &str) -> &'a FakeNode {
    fs.nodes
        .get(path)
        .unwrap_or_else(|| panic!("{path} is missing"))
}

fn same_node(a: &FakeNode, b: &FakeNode) -> bool {
    a.kind == b.kind && a.mode == b.mode && a.uid == b.uid && a.gid == b.gid && a.ino == b.ino
}

fn nlink(fs: &FakeFs, path: &str) -> usize {
    let n = node(fs, path);
    fs.nodes
        .values()
        .filter(|m| m.ino == n.ino && matches!(m.kind, FakeKind::File(_)))
        .count()
}

fn no_staging_left(fs: &FakeFs) {
    let left: Vec<_> = fs
        .nodes
        .keys()
        .filter(|k| k.contains(".sinter-stage."))
        .collect();
    assert!(left.is_empty(), "staging left behind: {left:?}");
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

fn shown_audit(r: &sinter::audit::AuditReport) -> String {
    let mut shown = String::new();
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
        shown.push_str(&String::from_utf8(buf).unwrap());
    }
    shown
}

fn assert_no_trace_of_the_secret(shown: &str) {
    for needle in ["TOPSECRET", "0600", "20 bytes"] {
        assert!(!shown.contains(needle), "{needle:?} leaked in: {shown}");
    }
}

// ---------------------------------------------------------------------------
// S: what must work
// ---------------------------------------------------------------------------

#[test]
fn s01_s02_a_new_file_in_tmp_and_var_tmp_is_created_exclusively_and_converges() {
    for path in ["/tmp/example.conf", "/var/tmp/example.conf"] {
        let dir = tempfile::tempdir().unwrap();
        let p = file_recipe(&dir, path);
        let planned = run(&p, Mode::Plan, base());
        assert_eq!(planned.status, AggregateStatus::Success, "{path}");
        assert_eq!(res(&planned, "f").change, Change::Changed, "{path}");
        assert_eq!(mutations(&planned.commands), Vec::<String>::new());

        let applied = run(&p, Mode::Apply, base());
        assert_eq!(applied.status, AggregateStatus::Success, "{path}");
        let fs = fs_of(&applied);
        let n = node(fs, path);
        assert_eq!(n.kind, FakeKind::File(b"x\n".to_vec()), "{path}");
        assert_eq!((n.uid, n.mode & 0o7777), (0, 0o644), "{path}");
        assert_eq!(nlink(fs, path), 1, "the staging name is gone");
        no_staging_left(fs);

        // Published exclusively: one `publish new` step (the staging script's
        // `ln -T`), and no rename.
        assert_eq!(publishes(&applied.commands, "new"), 1, "{path}");
        let (_, a) = applied
            .commands
            .iter()
            .filter_map(fsstage)
            .find(|(o, _)| *o == "publish")
            .unwrap();
        // publish <new|replace> <file|link> <dir> <dir-id> <S> <G> <S-id> <payload-id> <base>
        assert_eq!((a[0].as_str(), a[1].as_str()), ("new", "file"), "{path}");
        assert_eq!(a[2], path.rsplit_once('/').unwrap().0, "{path}");
        assert!(a[4].starts_with(".sinter-stage."), "{a:?}");
        assert_eq!(a[8], "example.conf", "{path}");
        assert_eq!(
            publishes(&applied.commands, "replace"),
            0,
            "no rename for a new entry"
        );

        // Converged: plan rc 0, apply changes nothing, audit Compliant.
        let again = run(&p, Mode::Plan, continue_from(&applied));
        assert_eq!(again.status, AggregateStatus::Success);
        assert_eq!(res(&again, "f").change, Change::None, "{path}");
        let again_apply = run(&p, Mode::Apply, continue_from(&applied));
        assert_eq!(res(&again_apply, "f").change, Change::None, "{path}");
        assert_eq!(mutations(&again_apply.commands), Vec::<String>::new());
        let a = audit(&p, continue_from(&applied));
        assert_eq!(
            afind(&a, "f").status,
            AuditResourceStatus::Compliant,
            "{path}"
        );
        assert_eq!(a.exit_code(), 0);
    }
}

#[test]
fn s03_a_converged_root_file_plans_unchanged_and_audits_compliant() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/example.conf", b"x\n", 0o644, 0, 0);
    let r = run(&p, Mode::Plan, t.clone());
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(res(&r, "f").change, Change::None);
    let a = audit(&p, t);
    assert_eq!(afind(&a, "f").status, AuditResourceStatus::Compliant);
    assert_eq!(mutations(&a.commands), Vec::<String>::new());
}

#[test]
fn s04_s05_an_existing_root_file_is_updated_by_rename_and_a_mode_change_by_chmod() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/example.conf", b"old\n", 0o644, 0, 0);
    let old_ino = t.fs.as_ref().unwrap().nodes["/tmp/example.conf"].ino;
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::Success);
    let fs = fs_of(&r);
    assert_eq!(
        node(fs, "/tmp/example.conf").kind,
        FakeKind::File(b"x\n".to_vec())
    );
    assert_ne!(
        node(fs, "/tmp/example.conf").ino,
        old_ino,
        "replaced, not rewritten"
    );
    assert_eq!(publishes(&r.commands, "replace"), 1);
    assert_eq!(
        publishes(&r.commands, "new"),
        0,
        "an update is not an exclusive create"
    );
    no_staging_left(fs);

    // S-05: only the mode differs.
    let p2 = recipe(
        &dir,
        "resources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/example.conf\n      content: \"x\\n\"\n      mode: \"0600\"\n",
    );
    let r2 = run(&p2, Mode::Apply, continue_from(&r));
    assert_eq!(r2.status, AggregateStatus::Success);
    assert_eq!(node(fs_of(&r2), "/tmp/example.conf").mode & 0o7777, 0o600);
    assert_eq!(
        node(fs_of(&r2), "/tmp/example.conf").ino,
        node(fs, "/tmp/example.conf").ino,
        "a mode change keeps the inode"
    );
    assert_eq!(steps(&r2.commands, "stage"), 0);
    assert_eq!(steps(&r2.commands, "publish"), 0);
    assert_eq!(count(&r2.commands, "chmod"), 1);
}

#[test]
fn s06_q03_state_absent_removes_a_root_file_and_is_unchanged_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/example.conf\n      state: absent\n",
    );
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/example.conf", b"x\n", 0o644, 0, 0);
    let planned = run(&p, Mode::Plan, t.clone());
    assert_eq!(res(&planned, "f").change, Change::Changed);
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::Success);
    assert!(!fs_of(&r).nodes.contains_key("/tmp/example.conf"));
    let again = run(&p, Mode::Apply, continue_from(&r));
    assert_eq!(res(&again, "f").change, Change::None);
    let a = audit(&p, continue_from(&r));
    assert_eq!(afind(&a, "f").status, AuditResourceStatus::Compliant);
}

#[test]
fn s07_a_directory_in_tmp_is_made_by_mkdir_and_converges() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: d\n    type: directory\n    with:\n      path: /tmp/newdir\n",
    );
    let r = run(&p, Mode::Apply, base());
    assert_eq!(r.status, AggregateStatus::Success);
    let n = node(fs_of(&r), "/tmp/newdir");
    assert_eq!(n.kind, FakeKind::Dir);
    assert_eq!(n.uid, 0);
    let again = run(&p, Mode::Plan, continue_from(&r));
    assert_eq!(res(&again, "d").change, Change::None);
    let a = audit(&p, continue_from(&r));
    assert_eq!(afind(&a, "d").status, AuditResourceStatus::Compliant);
}

#[test]
fn s08_a_link_in_tmp_is_created_exclusively_and_replaced_through_staging() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: l\n    type: link\n    with:\n      path: /tmp/lnk\n      target: /etc/one\n",
    );
    let r = run(&p, Mode::Apply, base());
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(
        node(fs_of(&r), "/tmp/lnk").kind,
        FakeKind::Symlink("/etc/one".to_string())
    );
    // The link was made with `ln -sT` (the argv of a sensitive request is not
    // recorded; `r16` observes it on the wire and `r16b` shows what the old
    // form would have done).
    assert_eq!(publishes(&r.commands, "replace"), 0);
    // Converged, then retargeted (root's own symlink: replaced via staging).
    let again = run(&p, Mode::Plan, continue_from(&r));
    assert_eq!(res(&again, "l").change, Change::None);
    let p2 = recipe(
        &dir,
        "resources:\n  - id: l\n    type: link\n    with:\n      path: /tmp/lnk\n      target: /etc/two\n",
    );
    let r2 = run(&p2, Mode::Apply, continue_from(&r));
    assert_eq!(r2.status, AggregateStatus::Success);
    assert_eq!(
        node(fs_of(&r2), "/tmp/lnk").kind,
        FakeKind::Symlink("/etc/two".to_string())
    );
    no_staging_left(fs_of(&r2));
}

#[test]
fn s09_a_template_in_tmp_is_created_like_a_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("t.conf"), "hello\n").unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: t\n    type: template\n    with:\n      path: /tmp/t.conf\n      source: t.conf\n",
    );
    let r = run(&p, Mode::Apply, base());
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(
        node(fs_of(&r), "/tmp/t.conf").kind,
        FakeKind::File(b"hello\n".to_vec())
    );
    assert_eq!(publishes(&r.commands, "new"), 1);
    let again = run(&p, Mode::Plan, continue_from(&r));
    assert_eq!(res(&again, "t").change, Change::None);
}

#[test]
fn s10_s11_a_nested_root_sticky_directory_is_shared_and_a_root_0755_one_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = base();
    {
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/tmp/pub", 0o1777, 0, 0);
        fs.mkdir_node("/tmp/rootdir", 0o755, 0, 0);
    }
    let shared = run(
        &file_recipe(&dir, "/tmp/pub/a.conf"),
        Mode::Apply,
        t.clone(),
    );
    assert_eq!(shared.status, AggregateStatus::Success);
    assert_eq!(
        publishes(&shared.commands, "new"),
        1,
        "shared: exclusive create"
    );

    let dir2 = tempfile::tempdir().unwrap();
    let plain = run(&file_recipe(&dir2, "/tmp/rootdir/a.conf"), Mode::Apply, t);
    assert_eq!(plain.status, AggregateStatus::Success);
    assert_eq!(
        publishes(&plain.commands, "new"),
        0,
        "not shared: unchanged publication"
    );
    assert_eq!(publishes(&plain.commands, "replace"), 1);
    // The entry gate (a hard link count) is only asked in a shared directory.
    assert!(
        plain
            .commands
            .iter()
            .all(|c| !inner(c).1.iter().any(|a| a == "%h")),
        "no hard link count outside a shared directory"
    );
}

#[test]
fn s12_a_directory_and_a_file_below_it_plan_and_apply_in_tmp() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: d\n    type: directory\n    with:\n      path: /tmp/newdir\n  - id: f\n    type: file\n    depends_on: [d]\n    with:\n      path: /tmp/newdir/a.conf\n      content: \"a\\n\"\n",
    );
    let planned = run(&p, Mode::Plan, base());
    assert_eq!(planned.status, AggregateStatus::Success);
    assert_eq!(res(&planned, "d").change, Change::Changed);
    assert_eq!(res(&planned, "f").change, Change::Changed);
    assert!(!res(&planned, "f").unknown);
    let applied = run(&p, Mode::Apply, base());
    assert_eq!(applied.status, AggregateStatus::Success);
    assert_eq!(
        node(fs_of(&applied), "/tmp/newdir/a.conf").kind,
        FakeKind::File(b"a\n".to_vec())
    );
}

#[test]
fn s13_a_sudo_login_is_as_safe_as_a_root_login() {
    for path in ["/tmp/example.conf", "/var/tmp/example.conf"] {
        let dir = tempfile::tempdir().unwrap();
        let p = file_recipe(&dir, path);
        let r = run_as(&p, Mode::Apply, true, base_user());
        assert_eq!(r.status, AggregateStatus::Success, "{path}");
        let n = node(fs_of(&r), path);
        assert_eq!(n.uid, 0, "created by root through sudo");
        assert_eq!(publishes(&r.commands, "new"), 1);
        assert_eq!(publishes(&r.commands, "replace"), 0);
        // And what a plain user owns there is not root's to manage.
        let mut t = base_user();
        t.fs.as_mut()
            .unwrap()
            .put_file(path, b"x\n", 0o644, 1000, 1000);
        let e = engine_with(&p, Mode::Plan, true, None, t)
            .run()
            .err()
            .unwrap_or_else(|| panic!("{path}: an entry of uid 1000 is not root's under --sudo"));
        assert!(
            e.message.contains("belongs to uid 1000") && e.message.contains("shared directory"),
            "{path}: {}",
            e.message
        );
    }
}

#[test]
fn s14_a_plain_user_manages_their_own_files_in_tmp() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/mine.conf");
    let planned = run(&p, Mode::Plan, base_user());
    assert_eq!(planned.status, AggregateStatus::Success);
    assert!(
        res(&planned, "f")
            .notes
            .iter()
            .all(|n| !n.contains("needs root")),
        "a user can create entries in a world-writable directory: {:?}",
        res(&planned, "f").notes
    );
    let r = run(&p, Mode::Apply, base_user());
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(node(fs_of(&r), "/tmp/mine.conf").uid, 1000);
    let mut again = base_user();
    again.fs = r.fake_fs.clone();
    let p2 = run(&p, Mode::Plan, again.clone());
    assert_eq!(res(&p2, "f").change, Change::None);
    let a = audit(&p, again);
    assert_eq!(afind(&a, "f").status, AuditResourceStatus::Compliant);
}

// ---------------------------------------------------------------------------
// R: what must be refused
// ---------------------------------------------------------------------------

/// An entry of another account at `/tmp/example.conf`, per kind.
fn with_foreign_entry(kind: &str) -> FakeTarget {
    let mut t = base();
    let fs = t.fs.as_mut().unwrap();
    match kind {
        "file" => fs.put_file("/tmp/example.conf", b"theirs\n", 0o644, ALICE, ALICE),
        "symlink" => fs.put_symlink("/tmp/example.conf", "/root/secret", ALICE, ALICE),
        "dir" => fs.mkdir_node("/tmp/example.conf", 0o755, ALICE, ALICE),
        other => panic!("{other}"),
    }
    t
}

#[test]
fn r01_r02_r03_p01_an_entry_of_another_account_is_refused_unread_unchanged() {
    for kind in ["file", "symlink", "dir"] {
        let dir = tempfile::tempdir().unwrap();
        let p = file_recipe(&dir, "/tmp/example.conf");
        let before = with_foreign_entry(kind);
        let before_node = before.fs.as_ref().unwrap().nodes["/tmp/example.conf"].clone();

        // plan: the refusal apply would give.
        let e = plan_err(&p, before.clone());
        assert!(
            e.message.contains("belongs to uid 1001"),
            "{kind}: {}",
            e.message
        );
        assert!(
            e.message.contains("shared directory"),
            "{kind}: {}",
            e.message
        );
        assert_no_trace_of_the_secret(&e.message);

        // apply: failed, nothing changed.
        let r = run(&p, Mode::Apply, before.clone());
        assert_eq!(r.status, AggregateStatus::ApplyFailed, "{kind}");
        assert_eq!(res(&r, "f").execution, Execution::Failed, "{kind}");
        assert_eq!(res(&r, "f").change, Change::None, "{kind}");
        assert_eq!(mutations(&r.commands), Vec::<String>::new(), "{kind}");
        assert!(
            same_node(node(fs_of(&r), "/tmp/example.conf"), &before_node),
            "{kind}"
        );
        assert_no_trace_of_the_secret(&shown_apply(&r));

        // audit: an observation error (never drift), exit 6, nothing shown.
        let a = audit(&p, before.clone());
        assert_eq!(afind(&a, "f").status, AuditResourceStatus::Error, "{kind}");
        assert_eq!(a.exit_code(), 6, "{kind}");
        assert_eq!(mutations(&a.commands), Vec::<String>::new());
        assert_no_trace_of_the_secret(&shown_audit(&a));

        // Nothing but `lstat` ever named the entry: no read, no digest, no
        // link text, no mode change, and the secret behind a symlink was
        // never named at all.
        for cmds in [&r.commands, &a.commands] {
            for prog in programs_on(cmds, "/tmp/example.conf") {
                assert_eq!(prog, "stat", "{kind}: only lstat may name it");
            }
            assert!(programs_on(cmds, "/root/secret").is_empty(), "{kind}");
        }
    }
}

#[test]
fn r04_u02_a_root_file_with_two_hard_links_is_refused_unread() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let mut t = base();
    {
        let fs = t.fs.as_mut().unwrap();
        fs.put_file("/etc/other", SECRET.as_bytes(), 0o600, 0, 0);
        fs.put_hardlink("/etc/other", "/tmp/example.conf");
    }
    let e = plan_err(&p, t.clone());
    assert!(e.message.contains("2 hard links"), "{}", e.message);
    assert_no_trace_of_the_secret(&e.message);
    let r = run(&p, Mode::Apply, t.clone());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
    assert_eq!(count(&r.commands, "sha256sum"), 0, "{}", trace(&r.commands));
    assert!(
        !programs_on(&r.commands, "/tmp/example.conf").contains(&"cat".to_string()),
        "{}",
        trace(&r.commands)
    );
    let a = audit(&p, t);
    assert_eq!(afind(&a, "f").status, AuditResourceStatus::Error);
    assert_eq!(count(&a.commands, "sha256sum"), 0);
    assert_no_trace_of_the_secret(&shown_audit(&a));
}

#[test]
fn r05_q02_state_absent_never_removes_an_entry_of_another_account() {
    for kind in ["file", "symlink", "dir"] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(
            &dir,
            "resources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/example.conf\n      state: absent\n",
        );
        let t = with_foreign_entry(kind);
        let before = t.fs.as_ref().unwrap().nodes["/tmp/example.conf"].clone();
        let e = plan_err(&p, t.clone());
        assert!(
            e.message.contains("belongs to uid 1001"),
            "{kind}: {}",
            e.message
        );
        let r = run(&p, Mode::Apply, t.clone());
        assert_eq!(r.status, AggregateStatus::ApplyFailed, "{kind}");
        assert_eq!(count(&r.commands, "rm"), 0, "{kind}");
        assert_eq!(count(&r.commands, "rmdir"), 0, "{kind}");
        assert!(
            same_node(node(fs_of(&r), "/tmp/example.conf"), &before),
            "{kind}"
        );
        let a = audit(&p, t);
        assert_eq!(afind(&a, "f").status, AuditResourceStatus::Error, "{kind}");
    }
}

#[test]
fn r06_q01_an_owner_other_than_root_is_refused_in_a_shared_directory() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/example.conf\n      content: \"x\\n\"\n      owner: alice\n",
    );
    // New file.
    let e = plan_err(&p, base());
    assert!(
        e.message
            .contains("cannot give /tmp/example.conf to uid 1001"),
        "{}",
        e.message
    );
    assert!(e.message.contains("shared directory"), "{}", e.message);
    let r = run(&p, Mode::Apply, base());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert!(
        !fs_of(&r).nodes.contains_key("/tmp/example.conf"),
        "nothing created"
    );
    assert_eq!(steps(&r.commands, "stage"), 0, "nothing was staged");
    // Existing root file: plan and apply refuse, audit reports the difference.
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/example.conf", b"x\n", 0o644, 0, 0);
    assert!(plan_err(&p, t.clone()).message.contains("shared directory"));
    let r2 = run(&p, Mode::Apply, t.clone());
    assert_eq!(r2.status, AggregateStatus::ApplyFailed);
    assert_eq!(
        node(fs_of(&r2), "/tmp/example.conf").uid,
        0,
        "not handed to alice"
    );
    let a = audit(&p, t);
    assert_eq!(
        afind(&a, "f").status,
        AuditResourceStatus::Drift,
        "{:?}",
        afind(&a, "f")
    );
    // A directory resource is refused the same way.
    let pd = recipe(
        &dir,
        "resources:\n  - id: d\n    type: directory\n    with:\n      path: /tmp/newdir\n      owner: alice\n",
    );
    assert!(plan_err(&pd, base()).message.contains("shared directory"));
    let rd = run(&pd, Mode::Apply, base());
    assert_eq!(rd.status, AggregateStatus::ApplyFailed);
    assert!(!fs_of(&rd).nodes.contains_key("/tmp/newdir"));
    assert_eq!(count(&rd.commands, "mkdir"), 0);
}

#[test]
fn r07_r08_a_world_writable_directory_without_sticky_or_with_another_owner_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let mut t = base();
    t.fs.as_mut().unwrap().nodes.get_mut("/tmp").unwrap().mode = 0o777;
    let e = plan_err(&p, t);
    assert!(
        e.message.contains("grants group or other write access"),
        "{}",
        e.message
    );
    assert!(e.message.contains("no sticky bit"), "{}", e.message);

    let mut t = base();
    t.fs.as_mut().unwrap().nodes.get_mut("/tmp").unwrap().uid = ALICE;
    let e = plan_err(&p, t);
    assert!(
        e.message.contains("sticky but owned by another account"),
        "{}",
        e.message
    );
}

#[test]
fn r09_an_ancestor_symlink_in_tmp_is_refused_and_nothing_behind_it_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/lnkdir/secret");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_symlink("/tmp/lnkdir", "/root", 0, 0);
    let e = plan_err(&p, t.clone());
    assert!(e.message.contains("is a symlink"), "{}", e.message);
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert!(programs_on(&r.commands, "/tmp/lnkdir/secret").is_empty());
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
}

#[test]
fn r12_a_shared_directory_inside_another_accounts_tree_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/alice/pub/f");
    let mut t = base();
    {
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/tmp/alice", 0o755, ALICE, ALICE);
        fs.mkdir_node("/tmp/alice/pub", 0o1777, 0, 0);
    }
    let e = plan_err(&p, t);
    assert!(
        e.message.contains("inside another account's directory"),
        "{}",
        e.message
    );
}

#[test]
fn r17_an_existing_directory_where_a_file_is_wanted_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/tmp/example.conf", 0o755, 0, 0);
    let e = plan_err(&p, t.clone());
    assert!(e.message.contains("refusing to replace"), "{}", e.message);
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
}

#[test]
fn r14_p03_a_sensitive_resource_names_neither_path_nor_uid() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: f\n    type: file\n    sensitive: true\n    with:\n      path: /tmp/topsecret-name.conf\n      content: \"x\\n\"\n",
    );
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/topsecret-name.conf", b"theirs\n", 0o644, ALICE, ALICE);
    let e = plan_err(&p, t.clone());
    for needle in ["topsecret-name", "1001"] {
        assert!(!e.message.contains(needle), "{needle}: {}", e.message);
    }
    let r = run(&p, Mode::Apply, t.clone());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let shown = shown_apply(&r);
    for needle in ["topsecret-name", "1001"] {
        assert!(!shown.contains(needle), "{needle}: {shown}");
    }
    let a = audit(&p, t);
    let shown = shown_audit(&a);
    for needle in ["topsecret-name", "1001"] {
        assert!(!shown.contains(needle), "{needle}: {shown}");
    }
    assert_eq!(afind(&a, "f").status, AuditResourceStatus::Error);
}

// ---------------------------------------------------------------------------
// C / U: another account acts between two commands
// ---------------------------------------------------------------------------

/// Before the exclusive publication, `actions` happen.
fn racing(actions: Vec<FsEventAction>) -> FakeTarget {
    base().with_fs_event("sh", "publish", 0, actions)
}

#[test]
fn c01_to_c04_a_name_taken_before_the_exclusive_publication_is_not_replaced() {
    let cases: Vec<(&str, Vec<FsEventAction>)> = vec![
        (
            "a file of another account",
            vec![FsEventAction::PutFile {
                path: "/tmp/example.conf".into(),
                data: b"theirs\n".to_vec(),
                mode: 0o644,
                uid: ALICE,
                gid: ALICE,
            }],
        ),
        (
            "a symlink of another account to a root-only file",
            vec![FsEventAction::PutSymlink {
                path: "/tmp/example.conf".into(),
                target: "/root/secret".into(),
                uid: ALICE,
                gid: ALICE,
            }],
        ),
        (
            "a directory of another account",
            vec![FsEventAction::MkDir {
                path: "/tmp/example.conf".into(),
                mode: 0o755,
                uid: ALICE,
                gid: ALICE,
            }],
        ),
        (
            "a root file written by someone else",
            vec![FsEventAction::PutFile {
                path: "/tmp/example.conf".into(),
                data: b"x\n".to_vec(),
                mode: 0o644,
                uid: 0,
                gid: 0,
            }],
        ),
    ];
    for (what, actions) in cases {
        let dir = tempfile::tempdir().unwrap();
        let p = file_recipe(&dir, "/tmp/example.conf");
        let secret_before = racing(actions.clone());
        let r = run(&p, Mode::Apply, secret_before);
        assert_eq!(r.status, AggregateStatus::ApplyFailed, "{what}");
        let x = res(&r, "f");
        assert_eq!(x.execution, Execution::Failed, "{what}");
        assert_eq!(x.change, Change::None, "{what}");
        let reason = x.reason.clone().unwrap_or_default();
        assert!(
            reason.contains("created by another process") && reason.contains("did not replace"),
            "{what}: {reason}"
        );
        assert!(!reason.contains("1001"), "{what}: no uid: {reason}");
        let fs = fs_of(&r);
        // The name still holds exactly what the other account put there.
        let n = node(fs, "/tmp/example.conf");
        match what {
            "a file of another account" => {
                assert_eq!(
                    (n.uid, &n.kind),
                    (ALICE, &FakeKind::File(b"theirs\n".to_vec()))
                );
            }
            "a symlink of another account to a root-only file" => {
                assert_eq!(n.kind, FakeKind::Symlink("/root/secret".to_string()));
                assert_eq!(
                    node(fs, "/root/secret").kind,
                    FakeKind::File(SECRET.as_bytes().to_vec()),
                    "the root-only file is untouched"
                );
            }
            "a directory of another account" => {
                assert_eq!(n.kind, FakeKind::Dir);
                assert!(!fs.nodes.keys().any(|k| k.starts_with("/tmp/example.conf/")));
            }
            _ => assert_eq!((n.uid, n.mode & 0o7777), (0, 0o644)),
        }
        // No rename or removal of the final path, no fallback to a rename: the
        // one publication was the exclusive link, and Sinter itself ran no
        // `mv` / `rm` at all (the script removes only its own staging).
        assert_eq!(publishes(&r.commands, "new"), 1, "{what}");
        assert_eq!(publishes(&r.commands, "replace"), 0, "{what}: no fallback");
        assert_eq!(count(&r.commands, "mv"), 0, "{what}: no fallback to mv");
        assert_eq!(count(&r.commands, "rm"), 0, "{what}: no rm by Sinter");
        assert!(
            programs_on(&r.commands, "/root/secret").is_empty(),
            "{what}"
        );
        no_staging_left(fs);
        assert_no_trace_of_the_secret(&shown_apply(&r));
        // Run again: it converges or refuses, never replaces.
        let again = run(&p, Mode::Apply, continue_from(&r));
        if what == "a root file written by someone else" {
            assert_eq!(res(&again, "f").change, Change::None, "{what}");
        } else {
            assert_eq!(again.status, AggregateStatus::ApplyFailed, "{what}");
        }
    }
}

#[test]
fn c05_a_file_system_without_hard_links_fails_and_never_falls_back_to_a_rename() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let mut t = base();
    t.fs.as_mut().unwrap().no_hard_links = true;
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let reason = res(&r, "f").reason.clone().unwrap_or_default();
    assert!(
        reason.contains("could not be created exclusively"),
        "{reason}"
    );
    assert!(!fs_of(&r).nodes.contains_key("/tmp/example.conf"));
    assert_eq!(publishes(&r.commands, "replace"), 0, "no fallback");
    assert_eq!(count(&r.commands, "mv"), 0, "no fallback");
    no_staging_left(fs_of(&r));
}

#[test]
fn c06_a_failed_staging_cleanup_after_publication_is_reported_as_such() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    // The payload name cannot be removed (an immutable file): the staging
    // directory keeps a second name of the published file.
    let mut t = base();
    t.fs.as_mut().unwrap().payload_undeletable = true;
    let r = run(&p, Mode::Apply, t);
    let x = res(&r, "f");
    assert_eq!(x.change, Change::Changed, "the file is published");
    assert_eq!(x.execution, Execution::Failed);
    let reason = x.reason.clone().unwrap_or_default();
    assert!(reason.contains("could not be removed"), "{reason}");
    assert!(reason.contains("second name"), "{reason}");
    let fs = fs_of(&r);
    assert_eq!(
        nlink(fs, "/tmp/example.conf"),
        2,
        "the staging name remains"
    );
    // The next run refuses the file until that name is gone.
    let e = plan_err(&p, continue_from(&r));
    assert!(e.message.contains("2 hard links"), "{}", e.message);
}

#[test]
fn u03_an_entry_replaced_by_another_account_before_the_final_check_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/example.conf", b"old\n", 0o644, 0, 0);
    // Between the first walk and the staging write, a root-owned entry cannot
    // really be replaced by another account (sticky); were it to be, the walk
    // before the rename must refuse rather than rename over it.
    let t = t.with_fs_event(
        "sh",
        "stage",
        0,
        vec![
            FsEventAction::Remove {
                path: "/tmp/example.conf".into(),
            },
            FsEventAction::PutFile {
                path: "/tmp/example.conf".into(),
                data: b"theirs\n".to_vec(),
                mode: 0o644,
                uid: ALICE,
                gid: ALICE,
            },
        ],
    );
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let n = node(fs_of(&r), "/tmp/example.conf");
    assert_eq!(
        (n.uid, &n.kind),
        (ALICE, &FakeKind::File(b"theirs\n".to_vec()))
    );
    assert_eq!(
        publishes(&r.commands, "replace"),
        0,
        "never renamed over it"
    );
}

#[test]
fn r16_a_directory_symlink_put_at_the_link_name_is_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: l\n    type: link\n    with:\n      path: /tmp/lnk\n      target: /etc/one\n",
    );
    let mut t = base();
    t.fs.as_mut().unwrap().mkdir_node("/etc/dest", 0o755, 0, 0);
    let t = t.with_fs_event(
        "ln",
        "-sT",
        0,
        vec![FsEventAction::PutSymlink {
            path: "/tmp/lnk".into(),
            target: "/etc/dest".into(),
            uid: ALICE,
            gid: ALICE,
        }],
    );
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let fs = fs_of(&r);
    assert!(
        !fs.nodes.keys().any(|k| k.starts_with("/etc/dest/")),
        "nothing was created inside the directory the link points to: {:?}",
        fs.nodes
            .keys()
            .filter(|k| k.starts_with("/etc/dest"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        node(fs, "/tmp/lnk").kind,
        FakeKind::Symlink("/etc/dest".to_string()),
        "their symlink is untouched"
    );
}

#[test]
fn r16b_the_model_does_create_inside_a_directory_for_the_old_form_of_ln() {
    // The test above is only meaningful because the model reproduces what
    // `ln -s` (without -T) does to a directory symlink.
    let mut fs = FakeFs::default();
    fs.mkdir_node("/tmp", 0o1777, 0, 0);
    fs.mkdir_node("/etc/dest", 0o755, 0, 0);
    fs.put_symlink("/tmp/lnk", "/etc/dest", ALICE, ALICE);
    let args: Vec<String> = ["-s", "--", "/etc/one", "/tmp/lnk"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (out, _) = fs.run("ln", &args, None, 0, 0).unwrap();
    assert_eq!(out.completion, Completion::Exited(0));
    assert!(
        fs.nodes.contains_key("/etc/dest/one"),
        "the link landed inside"
    );
    let args: Vec<String> = ["-sT", "--", "/etc/one", "/tmp/lnk"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (out, _) = fs.run("ln", &args, None, 0, 0).unwrap();
    assert_ne!(
        out.completion,
        Completion::Exited(0),
        "-T refuses an existing name"
    );
}

#[test]
fn the_sticky_model_forbids_a_plain_user_to_replace_or_remove_roots_entry() {
    // P1, as the model has it: what the other tests rely on.
    let mut fs = FakeFs::default();
    fs.mkdir_node("/tmp", 0o1777, 0, 0);
    fs.put_file("/tmp/rootfile", b"x", 0o644, 0, 0);
    fs.put_file("/tmp/mine", b"y", 0o644, ALICE, ALICE);
    let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let (out, _) = fs
        .run("rm", &a(&["-f", "--", "/tmp/rootfile"]), None, ALICE, ALICE)
        .unwrap();
    assert_ne!(out.completion, Completion::Exited(0), "rm");
    assert!(fs.nodes.contains_key("/tmp/rootfile"));
    // ...nor can a rename of the fixed staging script (`publish replace`) take
    // the name: alice stages in the sticky directory, then asks to replace it.
    let step = |op: &str, rest: &[&str]| {
        let mut v = vec![
            "-c".to_string(),
            sinter::fsstage::SCRIPT.to_string(),
            "sh".to_string(),
            op.to_string(),
        ];
        v.extend(rest.iter().map(|s| s.to_string()));
        v
    };
    let (out, _) = fs
        .run(
            "sh",
            &step("stage", &["/tmp", "-", "0644", "1001", "1001"]),
            Some(b"theirs"),
            ALICE,
            ALICE,
        )
        .unwrap();
    assert_eq!(out.completion, Completion::Exited(0));
    let answer = String::from_utf8(out.stdout).unwrap();
    let f: Vec<&str> = answer.trim().split(' ').collect();
    let (out, _) = fs
        .run(
            "sh",
            &step(
                "publish",
                &[
                    "replace", "file", "/tmp", "-", f[0], f[1], f[2], f[3], "rootfile",
                ],
            ),
            None,
            ALICE,
            ALICE,
        )
        .unwrap();
    assert_eq!(
        out.completion,
        Completion::Exited(4),
        "the rename is refused"
    );
    assert_eq!(
        node(&fs, "/tmp/rootfile").kind,
        FakeKind::File(b"x".to_vec()),
        "root's entry is untouched"
    );
    let (out, _) = fs
        .run("rm", &a(&["-f", "--", "/tmp/mine"]), None, ALICE, ALICE)
        .unwrap();
    assert_eq!(out.completion, Completion::Exited(0), "their own entry");
}

// ---------------------------------------------------------------------------
// T: another account's tree below a shared directory (FS-3)
// ---------------------------------------------------------------------------

fn with_alice_tree() -> FakeTarget {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/tmp/alice", 0o755, ALICE, ALICE);
    t
}

#[test]
fn t03_t04_a_path_in_alices_tree_below_tmp_is_managed_as_alice_without_the_entry_gate() {
    // C-1: the tree is alice's, directly in /tmp, so the recipe names the owner
    // (before C-1 this recipe had no `owner` and was accepted; a directory any
    // local account could have made first was taken for the author's own).
    let dir = tempfile::tempdir().unwrap();
    let p = alice_file_recipe(&dir, "/tmp/alice/file");
    let r = run(&p, Mode::Apply, with_alice_tree());
    assert_eq!(r.status, AggregateStatus::Success);
    let n = node(fs_of(&r), "/tmp/alice/file");
    assert_eq!((n.uid, n.gid), (ALICE, ALICE));
    // Operations ran as alice; the shared-directory rules did not apply.
    let as_alice = r.commands.iter().filter(|c| runs_as(c, ALICE)).count();
    assert!(as_alice > 0);
    assert_eq!(publishes(&r.commands, "new"), 0, "no exclusive link");
    assert_eq!(
        publishes(&r.commands, "replace"),
        1,
        "an ordinary rename inside the tree"
    );
    assert!(
        r.commands
            .iter()
            .all(|c| !inner(c).1.iter().any(|a| a == "%h")),
        "no entry gate inside a tree"
    );
    // owner: alice is fine; owner: root is FS-3's conflict, not FS-2's.
    let dir_root_owner = tempfile::tempdir().unwrap();
    let p2 = recipe(
        &dir_root_owner,
        "resources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/alice/file\n      content: \"x\\n\"\n      owner: root\n",
    );
    let e = plan_err(&p2, with_alice_tree());
    assert!(e.message.contains("belongs to uid 1001"), "{}", e.message);
    assert!(!e.message.contains("shared directory"), "{}", e.message);
    // Converged afterwards.
    let again = run(&p, Mode::Plan, {
        let mut t = with_alice_tree();
        t.fs = r.fake_fs.clone();
        t
    });
    assert_eq!(res(&again, "f").change, Change::None);
}

#[test]
fn t02_a_file_of_alice_directly_in_tmp_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/alice.conf");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/alice.conf", b"theirs\n", 0o644, ALICE, ALICE);
    let e = plan_err(&p, t.clone());
    assert!(e.message.contains("belongs to uid 1001"), "{}", e.message);
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert!(r.commands.iter().all(|c| c.program != "/usr/bin/setpriv"));
}

#[test]
fn t05_the_directory_of_alice_itself_is_not_managed_but_the_message_points_below() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: d\n    type: directory\n    with:\n      path: /tmp/alice\n",
    );
    let e = plan_err(&p, with_alice_tree());
    assert!(e.message.contains("belongs to uid 1001"), "{}", e.message);
    assert!(
        e.message
            .contains("can still be managed as that account when the recipe sets `owner`"),
        "{}",
        e.message
    );
    let r = run(&p, Mode::Apply, with_alice_tree());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
}

#[test]
fn t06_t07_a_symlink_of_alice_is_neither_a_tree_nor_followed() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = base();
    {
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/home/alice", 0o755, ALICE, ALICE);
        fs.put_symlink("/tmp/alice", "/home/alice", ALICE, ALICE);
    }
    // As an ancestor.
    let p = file_recipe(&dir, "/tmp/alice/file");
    let e = plan_err(&p, t.clone());
    assert!(e.message.contains("is a symlink"), "{}", e.message);
    let r = run(&p, Mode::Apply, t.clone());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert!(r.commands.iter().all(|c| c.program != "/usr/bin/setpriv"));
    assert!(
        r.commands
            .iter()
            .all(|c| inner(c).0 != "getent" || !inner(c).1.contains(&"1001".to_string())),
        "it never became alice's tree"
    );
    // As the managed path.
    let pl = recipe(
        &dir,
        "resources:\n  - id: l\n    type: link\n    with:\n      path: /tmp/alice\n      target: /etc/x\n",
    );
    let e = plan_err(&pl, t.clone());
    assert!(e.message.contains("belongs to uid 1001"), "{}", e.message);
    let a = audit(&pl, t);
    assert_eq!(afind(&a, "l").status, AuditResourceStatus::Error);
    assert_eq!(
        count(&a.commands, "readlink"),
        0,
        "the link text was not read"
    );
}

#[test]
fn t08_alices_directory_that_others_can_write_is_not_a_tree() {
    for mode in [0o775u32, 0o777, 0o1777] {
        let dir = tempfile::tempdir().unwrap();
        let p = file_recipe(&dir, "/tmp/alice/file");
        let mut t = with_alice_tree();
        t.fs.as_mut()
            .unwrap()
            .nodes
            .get_mut("/tmp/alice")
            .unwrap()
            .mode = mode;
        let e = plan_err(&p, t.clone());
        assert!(
            e.message.contains("grants group or other write access"),
            "{mode:o}: {}",
            e.message
        );
        let r = run(&p, Mode::Apply, t);
        assert_eq!(r.status, AggregateStatus::ApplyFailed, "{mode:o}");
        assert!(
            r.commands.iter().all(|c| c.program != "/usr/bin/setpriv"),
            "{mode:o}"
        );
    }
}

#[test]
fn t09_a_file_where_a_directory_is_needed_never_reaches_the_owner_decision() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/alice.conf/x");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/alice.conf", b"theirs\n", 0o644, ALICE, ALICE);
    let e = plan_err(&p, t.clone());
    assert!(e.message.contains("unexpected type"), "{}", e.message);
    let r = run(&p, Mode::Apply, t);
    assert!(r
        .commands
        .iter()
        .all(|c| inner(c).0 != "getent" || !inner(c).1.contains(&"1001".to_string())));
}

#[test]
fn t10_an_entry_that_is_alices_by_the_time_it_is_judged_is_refused_unread() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/root.conf");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/root.conf", b"x\n", 0o644, 0, 0);
    // Before the first `stat` that names the entry itself, it changes hands.
    let t = t.with_fs_event(
        "stat",
        "/tmp/root.conf",
        0,
        vec![
            FsEventAction::Remove {
                path: "/tmp/root.conf".into(),
            },
            FsEventAction::PutSymlink {
                path: "/tmp/root.conf".into(),
                target: "/root/secret".into(),
                uid: ALICE,
                gid: ALICE,
            },
        ],
    );
    let e = plan_err(&p, t);
    assert!(e.message.contains("belongs to uid 1001"), "{}", e.message);
    assert_no_trace_of_the_secret(&e.message);
}

// ---------------------------------------------------------------------------
// G / P: nothing else changes
// ---------------------------------------------------------------------------

#[test]
fn g01_g02_g05_outside_a_shared_directory_nothing_changes_and_inside_it_costs_the_gate() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = base();
    t.fs.as_mut().unwrap().mkdir_node("/etc/app2", 0o755, 0, 0);
    {
        let fs = t.fs.as_mut().unwrap();
        fs.put_file("/etc/app2/a.conf", b"x\n", 0o644, 0, 0);
        fs.put_file("/tmp/a.conf", b"x\n", 0o644, 0, 0);
    }
    let dir2 = tempfile::tempdir().unwrap();
    let plain = file_recipe(&dir, "/etc/app2/a.conf");
    let shared = file_recipe(&dir2, "/tmp/a.conf");
    let a = run(&plain, Mode::Plan, t.clone());
    let b = run(&shared, Mode::Plan, t.clone());
    assert_eq!(res(&a, "f").change, Change::None);
    assert_eq!(res(&b, "f").change, Change::None);
    // The gate is an `lstat` and a hard link count. The type observation *is*
    // the gate's own `lstat` (FS2-A1: no second `lstat`), so it costs one
    // command more than a plain path; the digest runs the gate again (two more).
    assert_eq!(
        b.commands.len(),
        a.commands.len() + 3,
        "plain: {:?}\nshared: {:?}",
        a.commands.iter().map(|c| inner(c).0).collect::<Vec<_>>(),
        b.commands.iter().map(|c| inner(c).0).collect::<Vec<_>>()
    );
    assert!(a
        .commands
        .iter()
        .all(|c| !inner(c).1.iter().any(|x| x == "%h")));
    // Audit: the same, and it changes nothing.
    let aa = audit(&plain, t.clone());
    let ab = audit(&shared, t);
    assert_eq!(ab.commands.len(), aa.commands.len() + 3);
    assert_eq!(mutations(&ab.commands), Vec::<String>::new());
}

#[test]
fn p02_a_new_file_outside_a_shared_directory_still_publishes_by_rename() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = base();
    t.fs.as_mut().unwrap().mkdir_node("/etc/app2", 0o755, 0, 0);
    let r = run(&file_recipe(&dir, "/etc/app2/a.conf"), Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(publishes(&r.commands, "replace"), 1);
    assert_eq!(publishes(&r.commands, "new"), 0);
}

// ---------------------------------------------------------------------------
// The gate is asked again where a change is decided or made
// ---------------------------------------------------------------------------

/// Before the `nth` `stat` that names `/tmp/example.conf`, the entry changes
/// hands (root's file becomes a file of another account).
fn handed_over_before_stat(nth: usize, t: FakeTarget) -> FakeTarget {
    t.with_fs_event(
        "stat",
        "/tmp/example.conf",
        nth,
        vec![
            FsEventAction::Remove {
                path: "/tmp/example.conf".into(),
            },
            FsEventAction::PutFile {
                path: "/tmp/example.conf".into(),
                data: b"theirs\n".to_vec(),
                mode: 0o644,
                uid: ALICE,
                gid: ALICE,
            },
        ],
    )
}

fn root_file(content: &[u8], mode: u32) -> FakeTarget {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/example.conf", content, mode, 0, 0);
    t
}

#[test]
fn u04_apply_judges_the_entry_again_before_it_removes_or_changes_it() {
    // The walk that precedes a removal or a chmod re-judges the entry; the
    // earlier observation does not stand in for it. Judged by what is left of
    // the other account's file.
    let dir = tempfile::tempdir().unwrap();
    let absent = recipe(
        &dir,
        "resources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/example.conf\n      state: absent\n",
    );
    let dir2 = tempfile::tempdir().unwrap();
    let mode_only = recipe(
        &dir2,
        "resources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/example.conf\n      content: \"x\\n\"\n      mode: \"0600\"\n",
    );
    for (what, p, t, prog) in [
        ("removal", &absent, root_file(b"x\n", 0o644), "rm"),
        ("chmod", &mode_only, root_file(b"x\n", 0o644), "chmod"),
    ] {
        let mut stopped_by_the_gate = false;
        // The observation asks four times (the gate's lstat and link count,
        // twice over); the walk of the change is the next to name the entry.
        // A root-owned entry cannot really change hands in a sticky directory;
        // the hand-over is modeled at each moment the gate is about to look at
        // the entry (an `lstat`, then the hard link count).
        let quiet = run(p, Mode::Apply, t.clone());
        let looks: Vec<bool> = quiet
            .commands
            .iter()
            .filter(|c| inner(c).0 == "stat" && inner(c).1.iter().any(|a| a == "/tmp/example.conf"))
            .map(|c| inner(c).1[1] == "%h")
            .collect();
        // The gate is an `lstat` followed by the hard link count.
        let gates: Vec<usize> = (1..looks.len())
            .filter(|i| looks[*i])
            .map(|i| i - 1)
            .collect();
        assert!(gates.len() >= 2, "{looks:?}");
        for nth in gates {
            let r = run(p, Mode::Apply, handed_over_before_stat(nth, t.clone()));
            let first = r.commands.iter().position(|c| inner(c).0 == prog);
            if let Some(at) = first {
                // It ran. The entry must have been root's when it did: the
                // hand-over comes before the `nth` `stat` naming the entry.
                let looked = r.commands[..at]
                    .iter()
                    .filter(|c| {
                        inner(c).0 == "stat" && inner(c).1.iter().any(|a| a == "/tmp/example.conf")
                    })
                    .count();
                assert!(
                    nth >= looked,
                    "{what} nth={nth}: `{prog}` ran after the entry had changed hands:\n{}",
                    trace(&r.commands)
                );
            } else {
                let n = node(fs_of(&r), "/tmp/example.conf");
                assert_eq!(n.uid, ALICE, "{what} nth={nth}");
                assert_eq!(
                    n.kind,
                    FakeKind::File(b"theirs\n".to_vec()),
                    "{what} nth={nth}"
                );
                assert_eq!(n.mode & 0o7777, 0o644, "{what} nth={nth}: not chmod-ed");
                stopped_by_the_gate = true;
            }
        }
        assert!(
            stopped_by_the_gate,
            "{what}: the hand-over was never met by the gate"
        );
    }
}

#[test]
fn p04_plan_judges_the_entry_again_where_it_decides_a_change() {
    // A plan that would show the content of the entry (a diff) or plan a
    // change does not rely on the observation having passed the gate: whatever
    // the moment the entry changes hands, plan never succeeds and never reads
    // the other account's file (cat) afterwards.
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let quiet = run(&p, Mode::Plan, root_file(b"old\n", 0o644));
    let looks: Vec<bool> = quiet
        .commands
        .iter()
        .filter(|c| inner(c).0 == "stat" && inner(c).1.iter().any(|a| a == "/tmp/example.conf"))
        .map(|c| inner(c).1[1] == "%h")
        .collect();
    let gates: Vec<usize> = (1..looks.len())
        .filter(|i| looks[*i])
        .map(|i| i - 1)
        .collect();
    let mut refused_at = Vec::new();
    for nth in gates.iter().copied() {
        let t = handed_over_before_stat(nth, root_file(b"old\n", 0o644));
        match engine_with(&p, Mode::Plan, false, None, t).run() {
            Err(e) => {
                assert!(
                    e.message.contains("belongs to uid 1001"),
                    "nth={nth}: {}",
                    e.message
                );
                refused_at.push(nth);
            }
            Ok(r) => {
                // Only when the change happened after everything plan reads.
                assert!(
                    programs_on(&r.commands, "/tmp/example.conf")
                        .iter()
                        .all(|prog| prog != "cat"),
                    "nth={nth}: {}",
                    trace(&r.commands)
                );
            }
        }
    }
    assert!(
        !refused_at.is_empty(),
        "plan must refuse when the entry changes hands before a look at it"
    );
    // Every gate before plan's last one is met by a refusal; only a hand-over
    // after plan's last gate can go unseen.
    let last_gate = *gates.last().unwrap();
    for nth in gates.iter().copied().filter(|n| *n < last_gate) {
        assert!(
            refused_at.contains(&nth),
            "nth={nth} of {gates:?}: {refused_at:?}"
        );
    }
}

#[test]
fn p05_plan_does_not_show_the_content_of_an_entry_that_changed_hands_after_the_digest() {
    // The digest is taken, then the entry changes hands before plan decides the
    // change and would read the current content for its diff: that decision
    // is behind its own gate, so the other account's file is never read.
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let t = root_file(b"old\n", 0o644).with_fs_event(
        "sha256sum",
        "/tmp/example.conf",
        0,
        vec![
            FsEventAction::Remove {
                path: "/tmp/example.conf".into(),
            },
            FsEventAction::PutFile {
                path: "/tmp/example.conf".into(),
                data: b"theirs\n".to_vec(),
                mode: 0o644,
                uid: ALICE,
                gid: ALICE,
            },
        ],
    );
    let e = engine_with(&p, Mode::Plan, false, None, t)
        .run()
        .err()
        .expect("plan must refuse");
    assert!(e.message.contains("belongs to uid 1001"), "{}", e.message);
    assert!(!e.message.contains("theirs"), "{}", e.message);
}

#[test]
fn c08_the_lost_race_of_a_sensitive_resource_names_no_path() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: f\n    type: file\n    sensitive: true\n    with:\n      path: /tmp/topsecret-name.conf\n      content: \"x\\n\"\n",
    );
    let t = base().with_fs_event(
        "sh",
        "publish",
        0,
        vec![FsEventAction::PutFile {
            path: "/tmp/topsecret-name.conf".into(),
            data: b"theirs\n".to_vec(),
            mode: 0o644,
            uid: ALICE,
            gid: ALICE,
        }],
    );
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let shown = shown_apply(&r);
    for needle in ["topsecret-name", "1001", "theirs"] {
        assert!(!shown.contains(needle), "{needle}: {shown}");
    }
    let n = node(fs_of(&r), "/tmp/topsecret-name.conf");
    assert_eq!(
        (n.uid, &n.kind),
        (ALICE, &FakeKind::File(b"theirs\n".to_vec()))
    );
}

#[test]
fn b01_a_backup_of_a_path_in_a_shared_directory_goes_through_the_entry_gate() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "backup:\n  paths: [/tmp/example.conf]\nresources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/other.conf\n      content: \"x\\n\"\n",
    );
    // Root's own file is backed up.
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/example.conf", b"mine\n", 0o644, 0, 0);
    let r = run(&p, Mode::Apply, t);
    assert_eq!(count(&r.commands, "cp"), 1, "{}", trace(&r.commands));
    // Another account's file, or a symlink of theirs, is not copied: the
    // backup stage refuses the path (apply stops before any resource runs).
    for kind in ["file", "symlink"] {
        let e = engine_with(&p, Mode::Apply, false, None, with_foreign_entry(kind))
            .run()
            .err()
            .unwrap_or_else(|| panic!("{kind}: the backup must refuse"));
        assert!(
            e.message.contains("backup failed") && e.message.contains("belongs to uid 1001"),
            "{kind}: {}",
            e.message
        );
        assert!(!e.message.contains("TOPSECRET"), "{kind}: {}", e.message);
        let report = e.backup.as_ref().expect("a backup report");
        assert_eq!(report.entries.len(), 1, "{kind}");
        assert_eq!(
            report.entries[0].status,
            sinter::backup::BackupStatus::Failed,
            "{kind}"
        );
    }
}

// ---------------------------------------------------------------------------
// R1 — FS2-A1: the observation is the gate's own `lstat`
// ---------------------------------------------------------------------------

fn rootonly(mut t: FakeTarget) -> FakeTarget {
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/rootonly", b"SECRET\n", 0o600, 0, 0);
    t
}

fn stats_on(cmds: &[CommandRecord], path: &str) -> usize {
    cmds.iter()
        .filter(|c| inner(c).0 == "stat" && inner(c).1.iter().any(|a| a == path))
        .count()
}

fn hardlink_to_rootonly_appears() -> Vec<FsEventAction> {
    vec![FsEventAction::PutHardlink {
        src: "/etc/rootonly".into(),
        dst: "/tmp/example.conf".into(),
    }]
}

const MODE_ONLY: &str = "resources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/example.conf\n      mode: \"0644\"\n";

#[test]
fn a1_the_observation_of_an_entry_is_the_gates_own_lstat() {
    // Absent: one `lstat` names the entry. Present (root's): the `lstat` and the
    // hard link count, nothing else. There is no second look whose result could
    // differ from what the gate judged.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, MODE_ONLY);
    let a = audit(&p, rootonly(base()));
    assert_eq!(afind(&a, "f").status, AuditResourceStatus::Drift);
    assert_eq!(
        stats_on(&a.commands, "/tmp/example.conf"),
        1,
        "{}",
        trace(&a.commands)
    );

    let mut t = rootonly(base());
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/example.conf", b"x\n", 0o644, 0, 0);
    let a = audit(&p, t.clone());
    assert_eq!(afind(&a, "f").status, AuditResourceStatus::Compliant);
    assert_eq!(
        stats_on(&a.commands, "/tmp/example.conf"),
        2,
        "{}",
        trace(&a.commands)
    );
    let r = run(&p, Mode::Plan, t);
    assert_eq!(res(&r, "f").change, Change::None);
    assert_eq!(
        stats_on(&r.commands, "/tmp/example.conf"),
        2,
        "{}",
        trace(&r.commands)
    );
}

#[test]
fn a1_no_metadata_of_an_entry_that_appears_after_the_gate_reaches_the_output() {
    // The metadata of the root-only file a hard link would reveal (mode 0600)
    // reaches neither the audit nor the plan, whenever the link appears.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, MODE_ONLY);
    let mut seen_refusal = 0;
    for nth in 0..4 {
        let t = rootonly(base()).with_fs_event(
            "stat",
            "/tmp/example.conf",
            nth,
            hardlink_to_rootonly_appears(),
        );
        let a = audit(&p, t.clone());
        let shown = shown_audit(&a);
        for needle in ["0600", "observed=0600", "rootonly"] {
            assert!(
                !shown.contains(needle),
                "audit nth={nth}: {needle}: {shown}"
            );
        }
        let x = afind(&a, "f");
        if x.status == AuditResourceStatus::Error {
            seen_refusal += 1;
        } else {
            // Nothing was there when the gate looked, and that is all it says.
            assert_eq!(x.status, AuditResourceStatus::Drift, "nth={nth}");
            assert_eq!(x.details.len(), 1, "{x:?}");
            assert_eq!(x.details[0].dimension, "state", "{x:?}");
        }
        match engine_with(&p, Mode::Plan, false, None, t).run() {
            Err(e) => {
                for needle in ["0600", "rootonly"] {
                    assert!(!e.message.contains(needle), "plan nth={nth}: {}", e.message);
                }
            }
            Ok(r) => assert!(!shown_apply(&r).contains("0600"), "plan nth={nth}"),
        }
    }
    assert!(
        seen_refusal >= 1,
        "a link present when the gate looks is refused"
    );
}

#[test]
fn a1_a_content_read_never_runs_for_an_entry_that_was_not_there_at_the_gate() {
    // Present at the observation of the type, gone at the gate of the digest:
    // the digest is not asked for (Gone), and a symlink put there is refused.
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/example.conf", b"x\n", 0o644, 0, 0);
    // stat #0 and #1: the observation (lstat, link count); #2: the digest's gate.
    let gone = t.clone().with_fs_event(
        "stat",
        "/tmp/example.conf",
        2,
        vec![FsEventAction::Remove {
            path: "/tmp/example.conf".into(),
        }],
    );
    let a = audit(&p, gone.clone());
    assert_eq!(afind(&a, "f").status, AuditResourceStatus::Error);
    assert_eq!(count(&a.commands, "sha256sum"), 0, "{}", trace(&a.commands));
    let e = plan_err(&p, gone);
    assert!(
        e.message.contains("changed during observation"),
        "{}",
        e.message
    );

    let linked = t.with_fs_event(
        "stat",
        "/tmp/example.conf",
        2,
        vec![
            FsEventAction::Remove {
                path: "/tmp/example.conf".into(),
            },
            FsEventAction::PutSymlink {
                path: "/tmp/example.conf".into(),
                target: "/root/secret".into(),
                uid: ALICE,
                gid: ALICE,
            },
        ],
    );
    let a = audit(&p, linked.clone());
    assert_eq!(afind(&a, "f").status, AuditResourceStatus::Error);
    assert_eq!(count(&a.commands, "sha256sum"), 0);
    assert!(programs_on(&a.commands, "/root/secret").is_empty());
    assert_no_trace_of_the_secret(&shown_audit(&a));
    let e = plan_err(&p, linked);
    assert!(e.message.contains("belongs to uid 1001"), "{}", e.message);
}

#[test]
fn a1_the_sensitive_text_and_json_name_no_path_and_no_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: f\n    type: file\n    sensitive: true\n    with:\n      path: /tmp/topsecret-name.conf\n      mode: \"0644\"\n",
    );
    for nth in 0..3 {
        let t = rootonly(base()).with_fs_event(
            "stat",
            "/tmp/topsecret-name.conf",
            nth,
            vec![FsEventAction::PutHardlink {
                src: "/etc/rootonly".into(),
                dst: "/tmp/topsecret-name.conf".into(),
            }],
        );
        let a = audit(&p, t.clone());
        let shown = shown_audit(&a);
        for needle in ["topsecret-name", "0600", "rootonly", "uid"] {
            assert!(
                !shown.contains(needle),
                "audit nth={nth}: {needle}: {shown}"
            );
        }
        if let Err(e) = engine_with(&p, Mode::Plan, false, None, t).run() {
            for needle in ["topsecret-name", "0600", "rootonly"] {
                assert!(!e.message.contains(needle), "plan nth={nth}: {}", e.message);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// R1 — FS2-A1: apply confirms the entry it changes is the one it observed
// ---------------------------------------------------------------------------

/// For each moment `/tmp/example.conf` could be swapped for another object of
/// the same kind that root owns (a different inode), the change is either made
/// on the swapped-in object after it was looked at again, or refused as drift
/// without being made. The explicit confirmation is what refuses it.
fn swapped_entry_is_never_changed_unseen(
    what: &str,
    body: &str,
    setup: impl Fn(&mut FakeFs),
    replace: Vec<FsEventAction>,
    swap_keeps_the_object: bool,
    mutation: &str,
) {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, body);
    let mut t = base();
    setup(t.fs.as_mut().unwrap());
    let before_ino = t.fs.as_ref().unwrap().nodes["/tmp/example.conf"].ino;
    let quiet = run(&p, Mode::Apply, t.clone());
    assert_eq!(
        quiet.status,
        AggregateStatus::Success,
        "{what}: {}",
        trace(&quiet.commands)
    );
    assert!(count(&quiet.commands, mutation) >= 1, "{what}");
    let looks = stats_on(&quiet.commands, "/tmp/example.conf");
    let mut refused = Vec::new();
    for nth in 0..looks {
        let r = run(
            &p,
            Mode::Apply,
            t.clone()
                .with_fs_event("stat", "/tmp/example.conf", nth, replace.clone()),
        );
        let x = res(&r, "f");
        let reason = x.reason.clone().unwrap_or_default();
        if reason.contains("target drift detected") {
            assert_eq!(
                count(&r.commands, mutation),
                0,
                "{what} nth={nth}: {}",
                trace(&r.commands)
            );
            assert_eq!(x.change, Change::None, "{what} nth={nth}");
            let n = node(fs_of(&r), "/tmp/example.conf");
            if swap_keeps_the_object {
                assert_eq!(
                    n.ino, before_ino,
                    "{what} nth={nth}: the object is untouched"
                );
            } else {
                assert_ne!(
                    n.ino, before_ino,
                    "{what} nth={nth}: the swapped-in object is untouched"
                );
            }
            refused.push(nth);
        }
    }
    assert!(
        !refused.is_empty(),
        "{what}: no look at the entry met a swap with a refusal ({looks} looks)"
    );
}

fn swap_for_root_file(path: &str) -> Vec<FsEventAction> {
    vec![
        FsEventAction::Remove { path: path.into() },
        FsEventAction::PutFile {
            path: path.into(),
            data: b"x\n".to_vec(),
            mode: 0o644,
            uid: 0,
            gid: 0,
        },
    ]
}

#[test]
fn a1_apply_refuses_a_swapped_entry_before_removing_or_changing_it() {
    let p = "/tmp/example.conf";
    swapped_entry_is_never_changed_unseen(
        "file absent",
        "resources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/example.conf\n      state: absent\n",
        |fs| fs.put_file("/tmp/example.conf", b"x\n", 0o644, 0, 0),
        swap_for_root_file(p),
        false,
        "rm",
    );
    swapped_entry_is_never_changed_unseen(
        "file metadata only",
        "resources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/example.conf\n      content: \"x\\n\"\n      mode: \"0600\"\n",
        |fs| fs.put_file("/tmp/example.conf", b"x\n", 0o644, 0, 0),
        swap_for_root_file(p),
        false,
        "chmod",
    );
    swapped_entry_is_never_changed_unseen(
        "directory absent",
        "resources:\n  - id: f\n    type: directory\n    with:\n      path: /tmp/example.conf\n      state: absent\n",
        |fs| fs.mkdir_node("/tmp/example.conf", 0o755, 0, 0),
        vec![
            FsEventAction::Remove { path: p.into() },
            FsEventAction::MkDir { path: p.into(), mode: 0o755, uid: 0, gid: 0 },
        ],
        false,
        "rmdir",
    );
    swapped_entry_is_never_changed_unseen(
        "directory metadata",
        "resources:\n  - id: f\n    type: directory\n    with:\n      path: /tmp/example.conf\n      mode: \"0700\"\n",
        |fs| fs.mkdir_node("/tmp/example.conf", 0o755, 0, 0),
        vec![
            FsEventAction::Remove { path: p.into() },
            FsEventAction::MkDir { path: p.into(), mode: 0o755, uid: 0, gid: 0 },
        ],
        false,
        "chmod",
    );
    swapped_entry_is_never_changed_unseen(
        "link absent",
        "resources:\n  - id: f\n    type: link\n    with:\n      path: /tmp/example.conf\n      state: absent\n",
        |fs| fs.put_symlink("/tmp/example.conf", "/etc/x", 0, 0),
        vec![
            FsEventAction::Remove { path: p.into() },
            FsEventAction::PutSymlink { path: p.into(), target: "/etc/x".into(), uid: 0, gid: 0 },
        ],
        false,
        "rm",
    );
}

#[test]
fn a1_apply_refuses_an_entry_whose_owner_changed_between_the_gate_and_the_change() {
    // The same object, now owned by another account: refused as drift, not
    // removed. (Only a privileged actor could do this; the check is explicit.)
    swapped_entry_is_never_changed_unseen(
        "file absent, owner changed",
        "resources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/example.conf\n      state: absent\n",
        |fs| fs.put_file("/tmp/example.conf", b"x\n", 0o644, 0, 0),
        vec![FsEventAction::Chown {
            path: "/tmp/example.conf".into(),
            uid: ALICE,
            gid: ALICE,
        }],
        true,
        "rm",
    );
}

// ---------------------------------------------------------------------------
// R1 — FS2-A3: a directory directly in a shared directory is not backed up
// ---------------------------------------------------------------------------

#[test]
fn a3_a_directory_directly_in_a_shared_directory_stops_the_backup_before_any_copy() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "backup:\n  paths: [/tmp/pub]\nresources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/other.conf\n      content: \"x\\n\"\n",
    );
    let mut t = base();
    {
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/tmp/pub", 0o1777, 0, 0);
        fs.put_file("/tmp/pub/theirs", b"alice data\n", 0o644, ALICE, ALICE);
    }
    let e = engine_with(&p, Mode::Apply, false, None, t)
        .run()
        .err()
        .expect("the backup must refuse a directory in a shared directory");
    assert!(
        e.message.contains("backup failed") && e.message.contains("directly in a shared directory"),
        "{}",
        e.message
    );
    assert!(
        !e.message.contains("1001") && !e.message.contains("alice"),
        "{}",
        e.message
    );
    let report = e.backup.as_ref().expect("a backup report");
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].status,
        sinter::backup::BackupStatus::Failed
    );
    assert!(
        report.entries[0].destination.is_none(),
        "nothing was copied"
    );
    // No resource ran: this is an error of the backup stage.
    assert!(
        e.message.contains("no resource was executed"),
        "{}",
        e.message
    );
}

#[test]
fn a3_a_directory_elsewhere_and_a_file_in_a_shared_directory_are_backed_up_as_before() {
    for (path, make) in [
        ("/etc/app2", "dir elsewhere"),
        ("/tmp/example.conf", "file in a shared directory"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(
            &dir,
            &format!(
                "backup:\n  paths: [{path}]\nresources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/other.conf\n      content: \"x\\n\"\n"
            ),
        );
        let mut t = base();
        {
            let fs = t.fs.as_mut().unwrap();
            fs.mkdir_node("/etc/app2", 0o755, 0, 0);
            fs.put_file("/etc/app2/a", b"z\n", 0o644, 0, 0);
            fs.put_file("/tmp/example.conf", b"mine\n", 0o644, 0, 0);
        }
        let r = run(&p, Mode::Apply, t);
        assert_eq!(r.status, AggregateStatus::Success, "{make}");
        assert_eq!(
            count(&r.commands, "cp"),
            1,
            "{make}: {}",
            trace(&r.commands)
        );
        let report = r.backup.as_ref().expect("a backup report");
        assert_eq!(
            report.entries[0].status,
            sinter::backup::BackupStatus::BackedUp,
            "{make}"
        );
    }
}

// ---------------------------------------------------------------------------
// FS2-L1: staging is removed when the re-check after staging fails
// ---------------------------------------------------------------------------
//
// Found on a real host: a refusal after the private staging directory was
// created (another account took the name, the sticky bit went away, a read
// failed) returned without removing `.sinter-stage.*/payload`, which holds the
// desired content. Whatever the re-check says, the staging directory Sinter
// made must be gone, the original reason must stay visible, and a cleanup that
// itself fails must be reported. Since FS-2 I4/I5 the staging, the publication
// and the cleanup are steps of the fixed staging script (`stage`, `publish`,
// `discard`); the scripted target models the script, and the script itself is
// proven on a real host (see the I4/I5 reports).

/// Index of the step that stages the payload (`stage`): the re-check under test
/// is everything after it.
fn l1_stage_step(cmds: &[CommandRecord]) -> usize {
    cmds.iter()
        .position(|c| fsstage(c).is_some_and(|(o, _)| o == "stage"))
        .expect("a staged payload")
}

fn l1_matches(c: &CommandRecord, prog: &str, arg: &str) -> bool {
    inner(c).0 == prog && inner(c).1.iter().any(|a| a == arg)
}

/// The `nth` that makes a `with_fs_event` fire on the `k`-th (0-based)
/// `prog`-command naming `arg` after the payload is staged.
fn l1_nth_after_payload(cmds: &[CommandRecord], prog: &str, arg: &str, k: usize) -> usize {
    let at = l1_stage_step(cmds);
    cmds[..at]
        .iter()
        .filter(|c| l1_matches(c, prog, arg))
        .count()
        + k
}

/// The `nth` of the last `prog`-command naming `arg` before the publication
/// step: the final `inspect` of the target.
fn l1_nth_last_before_publish(cmds: &[CommandRecord], prog: &str, arg: &str) -> usize {
    let at = l1_stage_step(cmds);
    let publish = at
        + cmds[at..]
            .iter()
            .position(|c| fsstage(c).is_some_and(|(o, _)| o == "publish"))
            .expect("a publication");
    cmds[..publish]
        .iter()
        .rposition(|c| l1_matches(c, prog, arg))
        .map(|last| {
            cmds[..last]
                .iter()
                .filter(|c| l1_matches(c, prog, arg))
                .count()
        })
        .expect("an inspect before the publication")
}

fn l1_stage_dirs(fs: &FakeFs) -> Vec<String> {
    fs.nodes
        .keys()
        .filter(|k| k.contains(".sinter-stage.") && !k.ends_with("/payload"))
        .cloned()
        .collect()
}

const L1_IO: &str = "stat: cannot statx: Input/output error\n";

fn l1_fail(code: i32) -> Vec<FsEventAction> {
    vec![FsEventAction::FailCommand {
        code,
        stderr: L1_IO.to_string(),
    }]
}

/// How the re-check after staging goes wrong.
#[derive(Clone, Copy, Debug)]
enum L1 {
    /// Another account takes the name after the payload was staged.
    ForeignEntry,
    /// The walk of the parents fails (a read that errors).
    ParentsRead,
    /// The entry gate's `lstat` of the target fails.
    GateRead,
    /// The final `inspect` of the target fails.
    InspectRead,
}

const L1_ALL: [L1; 4] = [
    L1::ForeignEntry,
    L1::ParentsRead,
    L1::GateRead,
    L1::InspectRead,
];

/// An ordinary publication of `path` to learn the command order, then the same
/// recipe on a target where `how` happens after the payload is staged.
fn l1_scenario(path: &str, how: L1, sudo: bool, base_t: impl Fn() -> FakeTarget) -> FakeTarget {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, path);
    let probe = run_as(&p, Mode::Apply, sudo, base_t());
    assert_eq!(
        probe.status,
        AggregateStatus::Success,
        "the probe publishes"
    );
    let cmds = &probe.commands;
    let parent = path.rsplit_once('/').map(|x| x.0).unwrap_or("/");
    let t = base_t();
    match how {
        L1::ForeignEntry => {
            // Before the first look at the target after staging, another
            // account takes the name.
            let nth = l1_nth_after_payload(cmds, "stat", path, 0);
            t.with_fs_event(
                "stat",
                path,
                nth,
                vec![FsEventAction::PutFile {
                    path: path.to_string(),
                    data: b"theirs\n".to_vec(),
                    mode: 0o644,
                    uid: ALICE,
                    gid: ALICE,
                }],
            )
        }
        L1::ParentsRead => {
            let nth = l1_nth_after_payload(cmds, "stat", parent, 0);
            t.with_fs_event("stat", parent, nth, l1_fail(1))
        }
        L1::GateRead => {
            let nth = l1_nth_after_payload(cmds, "stat", path, 0);
            t.with_fs_event("stat", path, nth, l1_fail(1))
        }
        L1::InspectRead => {
            let nth = l1_nth_last_before_publish(cmds, "stat", path);
            t.with_fs_event("stat", path, nth, l1_fail(1))
        }
    }
}

fn l1_run(path: &str, how: L1, fault: Option<&str>) -> RunReport {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, path);
    engine_with(
        &p,
        Mode::Apply,
        false,
        fault,
        l1_scenario(path, how, false, base),
    )
    .run()
    .unwrap()
}

#[test]
fn l1_a_failed_recheck_after_staging_leaves_no_staging_directory() {
    for how in L1_ALL {
        let r = l1_run("/tmp/example.conf", how, None);
        assert_eq!(r.status, AggregateStatus::ApplyFailed, "{how:?}");
        let fs = fs_of(&r);
        assert!(
            l1_stage_dirs(fs).is_empty(),
            "{how:?}: staging left behind: {:?}\n{}",
            l1_stage_dirs(fs),
            trace(&r.commands)
        );
        no_staging_left(fs);
        // Nothing was published by Sinter and nothing of anyone's was touched;
        // the staging went down in one `discard` step.
        assert_eq!(publishes(&r.commands, "new"), 0, "{how:?}: no publication");
        assert_eq!(publishes(&r.commands, "replace"), 0, "{how:?}: no rename");
        assert_eq!(steps(&r.commands, "discard"), 1, "{how:?}");
        match how {
            L1::ForeignEntry => {
                let n = node(fs, "/tmp/example.conf");
                assert_eq!(n.uid, ALICE, "{how:?}: their entry is theirs");
                assert_eq!(n.kind, FakeKind::File(b"theirs\n".to_vec()), "{how:?}");
            }
            _ => assert!(!fs.nodes.contains_key("/tmp/example.conf"), "{how:?}"),
        }
        let reason = res(&r, "f").reason.clone().unwrap_or_default();
        assert!(!reason.is_empty(), "{how:?}: the reason is kept");
        assert!(
            !reason.contains("staging cleanup"),
            "{how:?}: a clean cleanup adds nothing to the reason: {reason}"
        );
    }
}

#[test]
fn l1_the_original_reason_is_kept_and_a_failed_cleanup_is_reported_with_it() {
    for how in L1_ALL {
        let clean = l1_run("/tmp/example.conf", how, None);
        let original = res(&clean, "f").reason.clone().unwrap_or_default();
        let r = l1_run("/tmp/example.conf", how, Some("cleanup_stage"));
        assert_eq!(r.status, AggregateStatus::ApplyFailed, "{how:?}");
        let reason = res(&r, "f").reason.clone().unwrap_or_default();
        assert!(
            reason.starts_with(&original),
            "{how:?}: the original reason comes first.\n  original: {original}\n  got:      {reason}"
        );
        assert!(
            reason.contains("staging cleanup failed"),
            "{how:?}: {reason}"
        );
        let fs = fs_of(&r);
        let left = l1_stage_dirs(fs);
        assert_eq!(left.len(), 1, "{how:?}: the injected failure leaves it");
        assert!(
            reason.contains(&left[0]),
            "{how:?}: the reason names what may remain ({}): {reason}",
            left[0]
        );
        // Still nothing published and nothing of anyone's touched.
        assert_eq!(publishes(&r.commands, "new"), 0, "{how:?}");
        if let L1::ForeignEntry = how {
            assert_eq!(node(fs, "/tmp/example.conf").uid, ALICE, "{how:?}");
        }
    }
}

#[test]
fn l1_the_next_run_after_a_failed_recheck_does_not_go_wrong() {
    // The entry another account took stays refused; one that merely failed to
    // be read converges.
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let r = l1_run("/tmp/example.conf", L1::ForeignEntry, None);
    let again = run(&p, Mode::Apply, continue_from(&r));
    assert_eq!(again.status, AggregateStatus::ApplyFailed);
    assert_eq!(
        node(fs_of(&again), "/tmp/example.conf").kind,
        FakeKind::File(b"theirs\n".to_vec())
    );
    no_staging_left(fs_of(&again));
    for how in [L1::ParentsRead, L1::GateRead, L1::InspectRead] {
        let r = l1_run("/tmp/example.conf", how, None);
        let again = run(&p, Mode::Apply, continue_from(&r));
        assert_eq!(again.status, AggregateStatus::Success, "{how:?}");
        let n = node(fs_of(&again), "/tmp/example.conf");
        assert_eq!(n.uid, 0, "{how:?}");
        assert_eq!(n.kind, FakeKind::File(b"x\n".to_vec()), "{how:?}");
        no_staging_left(fs_of(&again));
        assert_eq!(
            nlink(fs_of(&again), "/tmp/example.conf"),
            1,
            "{how:?}: no second name"
        );
    }
}

#[test]
fn l1_the_final_identity_check_reports_its_cleanup_too() {
    // The other re-check after staging: the entry at the target is no longer
    // what was observed (a root-owned file appeared). It refused before, but
    // a failed cleanup was swallowed.
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let probe = run(&p, Mode::Apply, base());
    let nth = l1_nth_last_before_publish(&probe.commands, "stat", "/tmp/example.conf");
    let mk = || {
        base().with_fs_event(
            "stat",
            "/tmp/example.conf",
            nth,
            vec![FsEventAction::PutFile {
                path: "/tmp/example.conf".into(),
                data: b"root's\n".to_vec(),
                mode: 0o644,
                uid: 0,
                gid: 0,
            }],
        )
    };
    let clean = engine_with(&p, Mode::Apply, false, None, mk())
        .run()
        .unwrap();
    let reason = res(&clean, "f").reason.clone().unwrap_or_default();
    assert!(
        reason.contains("immediately before publication"),
        "{reason}"
    );
    assert!(reason.contains("staging cleanup succeeded"), "{reason}");
    no_staging_left(fs_of(&clean));
    assert_eq!(
        node(fs_of(&clean), "/tmp/example.conf").kind,
        FakeKind::File(b"root's\n".to_vec()),
        "what appeared is not replaced"
    );
    let failed = engine_with(&p, Mode::Apply, false, Some("cleanup_stage"), mk())
        .run()
        .unwrap();
    let reason = res(&failed, "f").reason.clone().unwrap_or_default();
    assert!(
        reason.contains("immediately before publication"),
        "{reason}"
    );
    assert!(reason.contains("staging cleanup failed"), "{reason}");
    assert_eq!(l1_stage_dirs(fs_of(&failed)).len(), 1);
}

#[test]
fn l1_a_failed_recheck_below_an_existing_root_file_also_cleans_up() {
    // Updates go through the same staging (a rename instead of `ln -T`).
    for how in [L1::ParentsRead, L1::InspectRead] {
        let existing = || {
            let mut t = base();
            t.fs.as_mut()
                .unwrap()
                .put_file("/tmp/example.conf", b"old\n", 0o644, 0, 0);
            t
        };
        let dir = tempfile::tempdir().unwrap();
        let p = file_recipe(&dir, "/tmp/example.conf");
        let probe = run(&p, Mode::Apply, existing());
        assert_eq!(probe.status, AggregateStatus::Success);
        assert_eq!(publishes(&probe.commands, "new"), 0, "an update renames");
        assert_eq!(
            publishes(&probe.commands, "replace"),
            1,
            "an update renames"
        );
        let cmds = &probe.commands;
        let t = match how {
            L1::ParentsRead => {
                let nth = l1_nth_after_payload(cmds, "stat", "/tmp", 0);
                existing().with_fs_event("stat", "/tmp", nth, l1_fail(1))
            }
            _ => {
                let nth = l1_nth_last_before_publish(cmds, "stat", "/tmp/example.conf");
                existing().with_fs_event("stat", "/tmp/example.conf", nth, l1_fail(1))
            }
        };
        let r = engine_with(&p, Mode::Apply, false, None, t).run().unwrap();
        assert_eq!(r.status, AggregateStatus::ApplyFailed, "{how:?}");
        no_staging_left(fs_of(&r));
        assert_eq!(
            node(fs_of(&r), "/tmp/example.conf").kind,
            FakeKind::File(b"old\n".to_vec()),
            "{how:?}: the file is as it was"
        );
    }
}

#[test]
fn l1_a_failed_recheck_in_an_accounts_tree_cleans_up_as_that_account() {
    for how in [L1::ParentsRead, L1::InspectRead] {
        // `owner: alice` is required in a tree directly in /tmp (C-1); the
        // clean-up behaviour under test is unchanged by it.
        let dir = tempfile::tempdir().unwrap();
        let p = alice_file_recipe(&dir, "/tmp/alice/file");
        let probe = run(&p, Mode::Apply, with_alice_tree());
        assert_eq!(probe.status, AggregateStatus::Success);
        let cmds = &probe.commands;
        let t = match how {
            L1::ParentsRead => {
                let nth = l1_nth_after_payload(cmds, "stat", "/tmp/alice", 0);
                with_alice_tree().with_fs_event("stat", "/tmp/alice", nth, l1_fail(1))
            }
            _ => {
                let nth = l1_nth_last_before_publish(cmds, "stat", "/tmp/alice/file");
                with_alice_tree().with_fs_event("stat", "/tmp/alice/file", nth, l1_fail(1))
            }
        };
        let r = engine_with(&p, Mode::Apply, false, None, t).run().unwrap();
        assert_eq!(r.status, AggregateStatus::ApplyFailed, "{how:?}");
        no_staging_left(fs_of(&r));
        assert!(!fs_of(&r).nodes.contains_key("/tmp/alice/file"), "{how:?}");
        // The removal ran as the account, like everything else in its tree.
        let removals: Vec<_> = r
            .commands
            .iter()
            .filter(|c| fsstage(c).is_some_and(|(o, _)| o == "discard"))
            .collect();
        assert_eq!(removals.len(), 1, "{how:?}: the staging was removed");
        assert!(
            removals.iter().all(|c| runs_as(c, ALICE)),
            "{how:?}: {}",
            trace(&r.commands)
        );
        // ...and no other command removes anything.
        assert!(
            r.commands
                .iter()
                .all(|c| !matches!(inner(c).0, "rm" | "rmdir" | "find")),
            "{how:?}: {}",
            trace(&r.commands)
        );
    }
}

#[test]
fn l1_an_ordinary_publication_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let r = run(&p, Mode::Apply, base());
    assert_eq!(r.status, AggregateStatus::Success);
    let n = node(fs_of(&r), "/tmp/example.conf");
    assert_eq!((n.uid, n.gid, n.mode & 0o7777), (0, 0, 0o644));
    assert_eq!(n.kind, FakeKind::File(b"x\n".to_vec()));
    no_staging_left(fs_of(&r));
    // Two calls of the fixed script do all of it: `stage`, then `publish`
    // (which also removes the staging directory).
    for (op, want) in [("stage", 1), ("publish", 1), ("discard", 0)] {
        assert_eq!(steps(&r.commands, op), want, "{op}\n{}", trace(&r.commands));
    }
    assert_eq!(publishes(&r.commands, "new"), 1);
    for prog in ["mktemp", "ln", "rm", "rmdir", "mv", "dd", "chown"] {
        assert_eq!(
            count(&r.commands, prog),
            0,
            "{prog}\n{}",
            trace(&r.commands)
        );
    }
    assert_eq!(nlink(fs_of(&r), "/tmp/example.conf"), 1);
    let again = run(&p, Mode::Apply, continue_from(&r));
    assert_eq!(res(&again, "f").change, Change::None, "idempotent");
    assert_eq!(steps(&again.commands, "stage"), 0, "nothing staged");
}

#[test]
fn l1_sensitive_resources_still_name_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: f\n    type: file\n    sensitive: true\n    with:\n      path: /tmp/topsecret-name.conf\n      content: \"x\\n\"\n",
    );
    for how in [L1::ForeignEntry, L1::InspectRead] {
        for fault in [None, Some("cleanup_stage")] {
            let probe = run(&p, Mode::Apply, base());
            let cmds = &probe.commands;
            let t = match how {
                L1::ForeignEntry => base().with_fs_event(
                    "stat",
                    "/tmp/topsecret-name.conf",
                    l1_nth_after_payload(cmds, "stat", "/tmp/topsecret-name.conf", 0),
                    vec![FsEventAction::PutFile {
                        path: "/tmp/topsecret-name.conf".into(),
                        data: b"theirs\n".to_vec(),
                        mode: 0o644,
                        uid: ALICE,
                        gid: ALICE,
                    }],
                ),
                _ => base().with_fs_event(
                    "stat",
                    "/tmp/topsecret-name.conf",
                    l1_nth_last_before_publish(cmds, "stat", "/tmp/topsecret-name.conf"),
                    l1_fail(1),
                ),
            };
            let r = engine_with(&p, Mode::Apply, false, fault, t).run().unwrap();
            assert_eq!(r.status, AggregateStatus::ApplyFailed, "{how:?} {fault:?}");
            let shown = shown_apply(&r);
            assert!(
                !shown.contains("topsecret-name") && !shown.contains(".sinter-stage"),
                "{how:?} {fault:?}: {shown}"
            );
        }
    }
}

/// What another account does when the re-check fails: the staging name now
/// leads somewhere else. `then` is what stands under the name.
fn l1_takeover(then: Vec<FsEventAction>) -> Vec<FsEventAction> {
    let mut v = vec![
        FsEventAction::Remove {
            path: "/tmp/.sinter-stage.fk1/payload".into(),
        },
        FsEventAction::Remove {
            path: "/tmp/.sinter-stage.fk1".into(),
        },
    ];
    v.extend(then);
    v.push(FsEventAction::FailCommand {
        code: 1,
        stderr: L1_IO.to_string(),
    });
    v
}

#[test]
fn l1_a_staging_name_taken_over_by_another_account_is_left_alone() {
    // The re-check fails and, at that very moment, the staging directory
    // Sinter made has been replaced by a directory of another account (only
    // possible where the sticky bit is gone). Sinter does not remove what is
    // not its own, and says the staging may remain.
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let probe = run(&p, Mode::Apply, base());
    let nth = l1_nth_after_payload(&probe.commands, "stat", "/tmp", 0);
    let t = base().with_fs_event(
        "stat",
        "/tmp",
        nth,
        l1_takeover(vec![
            FsEventAction::MkDir {
                path: "/tmp/.sinter-stage.fk1".into(),
                mode: 0o700,
                uid: ALICE,
                gid: ALICE,
            },
            FsEventAction::PutFile {
                path: "/tmp/.sinter-stage.fk1/payload".into(),
                data: b"theirs\n".to_vec(),
                mode: 0o644,
                uid: ALICE,
                gid: ALICE,
            },
        ]),
    );
    let r = engine_with(&p, Mode::Apply, false, None, t).run().unwrap();
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let fs = fs_of(&r);
    let their_dir = node(fs, "/tmp/.sinter-stage.fk1");
    assert_eq!(
        (their_dir.kind.clone(), their_dir.uid),
        (FakeKind::Dir, ALICE)
    );
    assert_eq!(
        node(fs, "/tmp/.sinter-stage.fk1/payload").kind,
        FakeKind::File(b"theirs\n".to_vec()),
        "their file is untouched"
    );
    // The script refused to act on a directory it did not make; Sinter itself
    // removed nothing.
    assert_eq!(steps(&r.commands, "discard"), 1);
    assert_eq!(count(&r.commands, "rm"), 0, "nothing was removed");
    assert_eq!(count(&r.commands, "rmdir"), 0);
    let reason = res(&r, "f").reason.clone().unwrap_or_default();
    assert!(reason.contains("staging cleanup failed"), "{reason}");
    assert!(!fs.nodes.contains_key("/tmp/example.conf"));
}

#[test]
fn l1_the_staging_is_removed_as_its_owner_for_a_non_root_login_with_and_without_sudo() {
    // With `--sudo` the staging directory belongs to root, not to the
    // connecting user; without it, to the connecting user. Either way it is
    // taken down as its owner.
    for sudo in [true, false] {
        for how in L1_ALL {
            let dir = tempfile::tempdir().unwrap();
            let p = file_recipe(&dir, "/tmp/example.conf");
            let probe = run_as(&p, Mode::Apply, sudo, base_user());
            if !sudo && probe.status != AggregateStatus::Success {
                // A plain non-root login cannot publish into /tmp here.
                continue;
            }
            let t = l1_scenario("/tmp/example.conf", how, sudo, base_user);
            let r = engine_with(&p, Mode::Apply, sudo, None, t).run().unwrap();
            assert_eq!(r.status, AggregateStatus::ApplyFailed, "{sudo} {how:?}");
            no_staging_left(fs_of(&r));
            assert_eq!(publishes(&r.commands, "new"), 0, "{sudo} {how:?}");
            let reason = res(&r, "f").reason.clone().unwrap_or_default();
            assert!(
                !reason.contains("staging cleanup"),
                "{sudo} {how:?}: {reason}"
            );
        }
    }
}

#[test]
fn l1_a_staging_name_that_is_no_longer_a_directory_is_left_alone() {
    // Same, but what stands under the staging name is not a directory at all
    // (here a file of root's own): it is not removed either.
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let probe = run(&p, Mode::Apply, base());
    let nth = l1_nth_after_payload(&probe.commands, "stat", "/tmp", 0);
    let t = base().with_fs_event(
        "stat",
        "/tmp",
        nth,
        l1_takeover(vec![FsEventAction::PutFile {
            path: "/tmp/.sinter-stage.fk1".into(),
            data: b"not a directory\n".to_vec(),
            mode: 0o600,
            uid: 0,
            gid: 0,
        }]),
    );
    let r = engine_with(&p, Mode::Apply, false, None, t).run().unwrap();
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_eq!(
        node(fs_of(&r), "/tmp/.sinter-stage.fk1").kind,
        FakeKind::File(b"not a directory\n".to_vec())
    );
    assert_eq!(count(&r.commands, "rm"), 0);
    assert_eq!(count(&r.commands, "rmdir"), 0);
    let reason = res(&r, "f").reason.clone().unwrap_or_default();
    assert!(reason.contains("staging cleanup failed"), "{reason}");
}

// ---------------------------------------------------------------------------
// FS2-L1-I3: the cleanup after a failed re-check must not follow a swapped
// staging directory
// ---------------------------------------------------------------------------
//
// The re-check fails when the directory it lives in can no longer be trusted
// (the sticky bit is gone, it became writable by others). From then on
// another account can rename the staging directory Sinter made and put a
// symlink under its name. A path-based `rm -f <staging>/payload` would follow
// that symlink and remove a file called `payload` wherever it points. The
// fixed staging script never resolves the staging name afresh: it proves the
// directory it enters (owner, creation-time group, device:inode) and works on
// the open directory.

const DUMMY_PAYLOAD: &[u8] = b"a file that is not Sinter's\n";

fn l1_with_dummy(mut t: FakeTarget) -> FakeTarget {
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/srv", 0o755, 0, 0);
    fs.mkdir_node("/srv/dummy", 0o755, 0, 0);
    fs.put_file("/srv/dummy/payload", DUMMY_PAYLOAD, 0o644, 0, 0);
    t
}

#[test]
fn l1_i3_a_staging_directory_swapped_for_a_symlink_before_the_cleanup_reaches_nothing_behind_it() {
    let dir = tempfile::tempdir().unwrap();
    let p = file_recipe(&dir, "/tmp/example.conf");
    let probe = run(&p, Mode::Apply, base());
    let nth = l1_nth_after_payload(&probe.commands, "stat", "/tmp", 0);
    // The re-check fails; right before the `discard` step the staging name is
    // swapped for a symlink to a directory holding a file called `payload`.
    let t = l1_with_dummy(base())
        .with_fs_event("stat", "/tmp", nth, l1_fail(1))
        .with_fs_event(
            "sh",
            "discard",
            0,
            vec![
                FsEventAction::Remove {
                    path: "/tmp/.sinter-stage.fk1/payload".into(),
                },
                FsEventAction::Remove {
                    path: "/tmp/.sinter-stage.fk1".into(),
                },
                FsEventAction::PutSymlink {
                    path: "/tmp/.sinter-stage.fk1".into(),
                    target: "/srv/dummy".into(),
                    uid: ALICE,
                    gid: ALICE,
                },
            ],
        );
    let r = engine_with(&p, Mode::Apply, false, None, t).run().unwrap();
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let fs = fs_of(&r);
    assert_eq!(
        fs.nodes.get("/srv/dummy/payload").map(|n| n.kind.clone()),
        Some(FakeKind::File(DUMMY_PAYLOAD.to_vec())),
        "the file the symlink leads to is still there\n{}",
        trace(&r.commands)
    );
    // The symlink is theirs and stays; the cleanup says it could not finish.
    assert_eq!(
        node(fs, "/tmp/.sinter-stage.fk1").kind,
        FakeKind::Symlink("/srv/dummy".to_string())
    );
    let reason = res(&r, "f").reason.clone().unwrap_or_default();
    assert!(reason.contains("staging cleanup failed"), "{reason}");
    assert!(!fs.nodes.contains_key("/tmp/example.conf"));
}

#[test]
fn l1_i3_the_cleanup_is_one_step_that_names_the_staging_directory_by_identity() {
    // The payload goes with the directory in one call of the fixed script,
    // which is given the identity of the directory it made (name, creation-time
    // group, device:inode), never a path Sinter resolves afresh.
    let r = l1_run("/tmp/example.conf", L1::ParentsRead, None);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    no_staging_left(fs_of(&r));
    let removing: Vec<String> = r
        .commands
        .iter()
        .filter(|c| matches!(inner(c).0, "rm" | "rmdir" | "find"))
        .map(|c| format!("{} {:?}", inner(c).0, inner(c).1))
        .collect();
    assert!(removing.is_empty(), "{removing:?}");
    let discards: Vec<&[String]> = r
        .commands
        .iter()
        .filter_map(fsstage)
        .filter(|(o, _)| *o == "discard")
        .map(|(_, a)| a)
        .collect();
    assert_eq!(discards.len(), 1);
    // discard <dir> <dir-id> <S> <G> <S-id>
    let a = discards[0];
    assert_eq!(a.len(), 5, "{a:?}");
    assert_eq!(a[0], "/tmp");
    assert_eq!(a[1], "-");
    assert!(a[2].starts_with(".sinter-stage."), "{a:?}");
    assert!(
        a[3].parse::<u64>().is_ok_and(|g| g >= 3_000_000_000),
        "root identifies the directory by its creation-time group: {a:?}"
    );
    assert!(a[4].contains(':'), "{a:?}");
}

// ---------------------------------------------------------------------------
// The model of the fixed staging script (what the tests above rely on)
// ---------------------------------------------------------------------------

fn script(op: &str, rest: &[&str]) -> Vec<String> {
    let mut v = vec![
        "-c".to_string(),
        sinter::fsstage::SCRIPT.to_string(),
        "sh".to_string(),
        op.to_string(),
    ];
    v.extend(rest.iter().map(|s| s.to_string()));
    v
}

/// Run one step as `uid`; the answer's stdout as text, stderr, and the exit code.
fn script_run(
    fs: &mut FakeFs,
    uid: u32,
    op: &str,
    rest: &[&str],
    stdin: Option<&[u8]>,
) -> (String, String, i32) {
    let (out, _) = fs.run("sh", &script(op, rest), stdin, uid, uid).unwrap();
    let Completion::Exited(code) = out.completion else {
        panic!("{:?}", out.completion)
    };
    (
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
        code,
    )
}

fn model_fs() -> FakeFs {
    let mut fs = FakeFs::default();
    fs.mkdir_node("/tmp", 0o1777, 0, 0);
    fs.mkdir_node("/open", 0o777, 0, 0);
    fs.mkdir_node("/plain", 0o755, 0, 0);
    fs.mkdir_node("/sgid", 0o2755, 0, 0);
    fs.mkdir_node("/srv", 0o755, 0, 0);
    fs.mkdir_node("/srv/dummy", 0o755, 0, 0);
    fs.put_file("/srv/dummy/payload", DUMMY_PAYLOAD, 0o644, 0, 0);
    fs
}

fn staged(fs: &mut FakeFs, uid: u32, dir: &str) -> Vec<String> {
    let (out, err, code) = script_run(
        fs,
        uid,
        "stage",
        &[dir, "-", "0644", &uid.to_string(), &uid.to_string()],
        Some(b"data"),
    );
    assert_eq!(code, 0, "{err}");
    out.trim().split(' ').map(|s| s.to_string()).collect()
}

#[test]
fn model_a_staging_directory_that_is_not_the_one_made_is_refused_and_nothing_is_removed() {
    // Every way the name can stop leading to the directory `stage` made:
    // exit 3 (REJECT), nothing written, nothing removed.
    for how in [
        "symlink",
        "other-owner",
        "same-name-new-directory",
        "file",
        "gone",
    ] {
        let mut fs = model_fs();
        let f = staged(&mut fs, 0, "/plain");
        let s = format!("/plain/{}", f[0]);
        fs.nodes.remove(&format!("{s}/payload"));
        fs.nodes.remove(&s);
        match how {
            "symlink" => fs.put_symlink(&s, "/srv/dummy", ALICE, ALICE),
            "other-owner" => fs.mkdir_node(&s, 0o700, ALICE, ALICE),
            "same-name-new-directory" => fs.mkdir_node(&s, 0o700, 0, f[1].parse().unwrap()),
            "file" => fs.put_file(&s, b"x", 0o600, 0, 0),
            _ => {}
        }
        for (op, rest) in [
            (
                "discard",
                vec!["/plain", "-", f[0].as_str(), f[1].as_str(), f[2].as_str()],
            ),
            (
                "publish",
                vec![
                    "new",
                    "file",
                    "/plain",
                    "-",
                    f[0].as_str(),
                    f[1].as_str(),
                    f[2].as_str(),
                    f[3].as_str(),
                    "target",
                ],
            ),
        ] {
            let (_, err, code) = script_run(&mut fs, 0, op, &rest, None);
            assert_eq!(code, 3, "{how} {op}: {err}");
            assert!(err.starts_with("REJECT: "), "{how} {op}: {err}");
            assert!(!fs.nodes.contains_key("/plain/target"), "{how} {op}");
        }
        assert_eq!(
            fs.nodes.get("/srv/dummy/payload").map(|n| n.kind.clone()),
            Some(FakeKind::File(DUMMY_PAYLOAD.to_vec())),
            "{how}"
        );
        if how != "gone" {
            assert!(fs.nodes.contains_key(&s), "{how}: what stands there stays");
        }
    }
}

#[test]
fn model_the_cleanup_removes_by_name_only_where_nobody_else_can_rename() {
    // Trusted directory: the staging directory is removed (CLEANUP:clean).
    // A directory others can write to: it is left and reported; the exit code
    // is still 0 for a publication that took place.
    for (dir, trusted) in [("/plain", true), ("/tmp", true), ("/open", false)] {
        let mut fs = model_fs();
        let f = staged(&mut fs, 0, dir);
        let (out, err, code) = script_run(
            &mut fs,
            0,
            "publish",
            &[
                "new", "file", dir, "-", &f[0], &f[1], &f[2], &f[3], "target",
            ],
            None,
        );
        assert_eq!(code, 0, "{dir}: {err}");
        assert!(fs.nodes.contains_key(&format!("{dir}/target")), "{dir}");
        if trusted {
            assert_eq!(out, "CLEANUP:clean\n", "{dir}");
            no_staging_left(&fs);
        } else {
            assert_eq!(out, format!("CLEANUP:left:{dir}/{}\n", f[0]), "{dir}");
            assert!(fs.nodes.contains_key(&format!("{dir}/{}", f[0])));
        }
    }
}

#[test]
fn model_the_publication_result_and_the_cleanup_result_are_separate() {
    // A payload name that cannot be removed: the file is published (the second
    // name is the same inode), the exit code says attention (5), and the
    // staging directory is not removed.
    let mut fs = model_fs();
    fs.payload_undeletable = true;
    let f = staged(&mut fs, 0, "/plain");
    let (out, _, code) = script_run(
        &mut fs,
        0,
        "publish",
        &[
            "new", "file", "/plain", "-", &f[0], &f[1], &f[2], &f[3], "target",
        ],
        None,
    );
    assert_eq!(code, 5);
    assert_eq!(out, format!("CLEANUP:link-remains:/plain/{}\n", f[0]));
    assert_eq!(
        fs.nodes["/plain/target"].ino,
        fs.nodes[&format!("/plain/{}/payload", f[0])].ino
    );
    // The state cannot be read: unknown, attention.
    let mut fs = model_fs();
    fs.cleanup_unknown = true;
    let f = staged(&mut fs, 0, "/plain");
    let (out, _, code) = script_run(
        &mut fs,
        0,
        "publish",
        &[
            "new", "file", "/plain", "-", &f[0], &f[1], &f[2], &f[3], "target",
        ],
        None,
    );
    assert_eq!((out.as_str(), code), ("CLEANUP:unknown\n", 5));
    assert!(fs.nodes.contains_key("/plain/target"));
    // A name taken first: nothing is published (4) and the cleanup is its own line.
    let mut fs = model_fs();
    let f = staged(&mut fs, 0, "/plain");
    fs.put_file("/plain/target", b"theirs", 0o644, ALICE, ALICE);
    let (out, err, code) = script_run(
        &mut fs,
        0,
        "publish",
        &[
            "new", "file", "/plain", "-", &f[0], &f[1], &f[2], &f[3], "target",
        ],
        None,
    );
    assert_eq!((out.as_str(), code), ("CLEANUP:clean\n", 4), "{err}");
    assert_eq!(
        fs.nodes["/plain/target"].kind,
        FakeKind::File(b"theirs".to_vec())
    );
}

#[test]
fn model_a_setgid_directory_and_an_unsafe_parent_are_refused_before_anything_is_written() {
    let mut fs = model_fs();
    let (_, err, code) = script_run(
        &mut fs,
        0,
        "stage",
        &["/sgid", "-", "0644", "0", "0"],
        Some(b"x"),
    );
    assert_eq!(code, 3);
    assert!(err.contains("setgid"), "{err}");
    // A plain user needs a parent nobody else can rename entries in.
    let (_, err, code) = script_run(
        &mut fs,
        1000,
        "stage",
        &["/open", "-", "0644", "1000", "1000"],
        Some(b"x"),
    );
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("could be changed by others"), "{err}");
    let (_, _, code) = script_run(
        &mut fs,
        1000,
        "stage",
        &["/tmp", "-", "0644", "1000", "1000"],
        Some(b"x"),
    );
    assert_eq!(code, 0, "a sticky directory of root is fine");
    assert!(
        !fs.nodes
            .keys()
            .any(|k| k.starts_with("/sgid/") || k.starts_with("/open/")),
        "nothing was created in the refused directories"
    );
}
