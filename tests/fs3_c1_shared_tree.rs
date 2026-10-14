//! FS-3 C-1: another account's directory directly inside a shared directory.
//!
//! In `/tmp` (or `/var/tmp`) any local account can create a directory before
//! the recipe's author does. When the recipe then writes `/tmp/app/x.conf` as
//! root without a `directory` resource for `/tmp/app`, the first non-root
//! ancestor used to become "the account's tree": Sinter wrote there as that
//! account, so the account could read the file and replace it afterwards.
//!
//! The rule under test: an entry that Sinter would create, replace or change
//! inside a tree whose root is a direct entry of a shared directory needs an
//! explicit `owner`; an `owner` of anyone but the tree's account is refused
//! (as in every account's tree). The scripted target runs the production
//! engine, the walk and the identity switch; that `setpriv` really drops
//! privileges and the races are real-Linux matters
//! (`SINTER_FS3_C1_LINUX_VERIFICATION`).
#![cfg(unix)]

use sinter::audit::{run_audit, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::{CommandRecord, Completion, FakeTarget, FsEventAction, Output};
use sinter::fakesys::{FakeFs, FakeKind};
use sinter::model::load_model;
use sinter::output::{render_apply, render_audit, OutputFormat, RenderOptions};
use sinter::result::{Change, Execution, ResourceResult};
use std::path::PathBuf;

const ALICE: u32 = 1001;
const BOB: u32 = 1002;
const SECRET: &str = "TOPSECRET-FROM-THE-RECIPE";

// `sh` is the fixed staging script (FS-2).
const MUTATION: [&str; 13] = [
    "mkdir", "chown", "chmod", "dd", "mv", "mktemp", "rm", "rmdir", "ln", "setfattr", "cp",
    "install", "sh",
];

fn base(root: bool) -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("alice", ALICE)
        .with_user("alice", ALICE, ALICE, "/home/alice", "/bin/bash")
        .with_group("bob", BOB)
        .with_user("bob", BOB, BOB, "/home/bob", "/bin/bash");
    if root {
        t = t.as_root();
    }
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/tmp", 0o1777, 0),
        ("/var", 0o755, 0),
        ("/var/tmp", 0o1777, 0),
        ("/home", 0o755, 0),
        ("/home/alice", 0o755, ALICE),
        ("/opt", 0o755, 0),
        ("/root", 0o700, 0),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    t
}

/// A directory of `uid` made first (mode 0755) directly in `parent`.
fn squatted(parent: &str, name: &str, uid: u32) -> FakeTarget {
    let mut t = base(true);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node(&format!("{parent}/{name}"), 0o755, uid, uid);
    t
}

fn recipe(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\nresources:\n{body}")).unwrap();
    std::fs::create_dir_all(dir.path().join("t")).unwrap();
    std::fs::write(dir.path().join("t/x.tpl"), "v={{ template.v }}\n").unwrap();
    p
}

/// A `file` resource `f` at `path`; `extra` are more `with:` lines.
fn file(path: &str, sensitive: bool, extra: &str) -> String {
    format!(
        "  - id: f\n    type: file\n{}    with:\n      path: {path}\n      content: \"{SECRET}\\n\"\n{extra}",
        if sensitive { "    sensitive: true\n" } else { "" }
    )
}

fn engine(p: &std::path::Path, mode: Mode, sudo: bool, t: FakeTarget) -> Engine {
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

fn run(p: &std::path::Path, mode: Mode, t: FakeTarget) -> RunReport {
    engine(p, mode, false, t).run().unwrap()
}

fn plan_result(p: &std::path::Path, t: FakeTarget) -> Result<RunReport, SinterError> {
    engine(p, Mode::Plan, false, t).run()
}

fn plan_err(p: &std::path::Path, t: FakeTarget) -> SinterError {
    plan_result(p, t).err().expect("plan must refuse")
}

fn audit(p: &std::path::Path, t: FakeTarget) -> sinter::audit::AuditReport {
    run_audit(engine(p, Mode::Plan, false, t)).unwrap()
}

fn res<'a>(r: &'a RunReport, id: &str) -> &'a ResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

fn fs_of(r: &RunReport) -> &FakeFs {
    r.fake_fs.as_ref().expect("scripted filesystem")
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn inner(c: &CommandRecord) -> (&str, &[String]) {
    if c.program == "/usr/bin/setpriv" {
        (base_name(&c.args[7]), &c.args[8..])
    } else {
        (base_name(&c.program), &c.args[..])
    }
}

/// Mutating commands that ran, with who ran them (`None` = the invocation).
fn mutations(cmds: &[CommandRecord]) -> Vec<(Option<String>, String)> {
    cmds.iter()
        .filter(|c| MUTATION.contains(&inner(c).0))
        .map(|c| {
            let who = (c.program == "/usr/bin/setpriv").then(|| c.args[1].clone());
            (who, format!("{} {:?}", inner(c).0, inner(c).1))
        })
        .collect()
}

fn assert_nothing_was_written(r: &RunReport) {
    assert_eq!(mutations(&r.commands), vec![], "a mutating command ran");
}

fn assert_no_detail(text: &str, what: &str) {
    for needle in [
        "/tmp/app",
        "/tmp/alice",
        "x.conf",
        "1001",
        "1002",
        "alice",
        "bob",
        SECRET,
    ] {
        assert!(
            !text.contains(needle),
            "{what}: {needle:?} appears in the refusal: {text}"
        );
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

// ---------------------------------------------------------------------------
// 1. the attack, and the recipe that closes it
// ---------------------------------------------------------------------------

#[test]
fn c1_01_a_directory_made_first_by_another_account_is_refused_without_an_owner() {
    for sensitive in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &file("/tmp/app/x.conf", sensitive, ""));
        // plan refuses ...
        let e = plan_err(&p, squatted("/tmp", "app", ALICE));
        if sensitive {
            assert_no_detail(&e.message, "plan");
        } else {
            assert!(e.message.contains("sets `owner`"), "{}", e.message);
            assert!(e.message.contains("/tmp/app"), "{}", e.message);
        }
        // ... and so does apply, before anything is written by anybody.
        let r = run(&p, Mode::Apply, squatted("/tmp", "app", ALICE));
        assert_eq!(r.status, AggregateStatus::ApplyFailed, "{sensitive}");
        assert_eq!(res(&r, "f").execution, Execution::Failed);
        assert_eq!(res(&r, "f").change, Change::None);
        assert_nothing_was_written(&r);
        assert!(!fs_of(&r).nodes.contains_key("/tmp/app/x.conf"));
        assert!(
            !shown_apply(&r).contains(&format!("{SECRET}\\n")) || !sensitive,
            "the content stays out of a sensitive result"
        );
        if sensitive {
            assert_no_detail(res(&r, "f").reason.as_deref().unwrap(), "apply");
        }
    }
}

#[test]
fn c1_02_the_same_in_var_tmp_and_for_a_file_the_account_made_first() {
    // /var/tmp is a shared directory too.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &file("/var/tmp/app/x.conf", false, ""));
    plan_err(&p, squatted("/var/tmp", "app", ALICE));
    let r = run(&p, Mode::Apply, squatted("/var/tmp", "app", ALICE));
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_nothing_was_written(&r);
    // The account made the file as well, with other content: replacing it would
    // write the recipe's content into the account's own file.
    let mut t = squatted("/tmp", "app", ALICE);
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/app/x.conf", b"theirs\n", 0o644, ALICE, ALICE);
    let p = recipe(&dir, &file("/tmp/app/x.conf", true, ""));
    plan_err(&p, t.clone());
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_nothing_was_written(&r);
    assert_eq!(
        fs_of(&r).nodes["/tmp/app/x.conf"].kind,
        FakeKind::File(b"theirs\n".to_vec()),
        "their file is untouched"
    );
}

#[test]
fn c1_03_naming_root_or_a_third_account_as_owner_is_refused_too() {
    for owner in ["root", "0", "bob", "1002"] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(
            &dir,
            &file(
                "/tmp/app/x.conf",
                false,
                &format!("      owner: \"{owner}\"\n"),
            ),
        );
        let e = plan_err(&p, squatted("/tmp", "app", ALICE));
        assert!(
            e.message.contains("belongs to uid 1001"),
            "{owner}: {}",
            e.message
        );
        let r = run(&p, Mode::Apply, squatted("/tmp", "app", ALICE));
        assert_eq!(r.status, AggregateStatus::ApplyFailed, "{owner}");
        assert_nothing_was_written(&r);
    }
}

#[test]
fn c1_04_the_owner_of_the_directory_may_be_named_and_the_run_converges() {
    for owner in ["alice", "1001"] {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(
            &dir,
            &file(
                "/tmp/app/x.conf",
                true,
                &format!("      owner: \"{owner}\"\n"),
            ),
        );
        let planned = run(&p, Mode::Plan, squatted("/tmp", "app", ALICE));
        assert_eq!(res(&planned, "f").change, Change::Changed, "{owner}");
        let r = run(&p, Mode::Apply, squatted("/tmp", "app", ALICE));
        assert_eq!(r.status, AggregateStatus::Success, "{owner}");
        let n = &fs_of(&r).nodes["/tmp/app/x.conf"];
        assert_eq!(n.uid, ALICE, "{owner}");
        // Everything that changed anything ran as that account.
        let m = mutations(&r.commands);
        assert!(!m.is_empty());
        assert!(
            m.iter().all(|(who, _)| who.as_deref() == Some("1001")),
            "{owner}: {m:?}"
        );
        // Converged: no further change in plan, apply or audit.
        let mut again = base(true);
        again.fs = r.fake_fs.clone();
        let r2 = run(&p, Mode::Apply, again.clone());
        assert_eq!(res(&r2, "f").change, Change::None, "{owner}");
        assert_nothing_was_written(&r2);
        let a = audit(&p, again);
        assert_eq!(a.exit_code(), 0, "{owner}: {}", shown_audit(&a));
    }
}

#[test]
fn c1_05_an_owner_that_is_not_the_account_of_the_directory_found_is_refused() {
    // The author meant bob's directory; alice made it first.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &file("/tmp/app/x.conf", false, "      owner: bob\n"));
    let e = plan_err(&p, squatted("/tmp", "app", ALICE));
    assert!(e.message.contains("belongs to uid 1001"), "{}", e.message);
    // ... and the other way round.
    let p = recipe(
        &dir,
        &file("/tmp/app/x.conf", false, "      owner: alice\n"),
    );
    plan_err(&p, squatted("/tmp", "app", BOB));
    let r = run(&p, Mode::Apply, squatted("/tmp", "app", BOB));
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_nothing_was_written(&r);
}

// ---------------------------------------------------------------------------
// 2. what stays as it was
// ---------------------------------------------------------------------------

#[test]
fn c1_06_a_users_home_needs_no_owner() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &file("/home/alice/page.conf", true, ""));
    let r = run(&p, Mode::Apply, base(true));
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(fs_of(&r).nodes["/home/alice/page.conf"].uid, ALICE);
    assert!(mutations(&r.commands)
        .iter()
        .all(|(who, _)| who.as_deref() == Some("1001")));
}

#[test]
fn c1_07_a_root_owned_directory_needs_no_owner_even_in_a_shared_directory() {
    for path in ["/opt/app/x.conf", "/tmp/rootdir/x.conf"] {
        let mut t = base(true);
        let parent = path.rsplit_once('/').unwrap().0;
        t.fs.as_mut().unwrap().mkdir_node(parent, 0o755, 0, 0);
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &file(path, true, ""));
        let r = run(&p, Mode::Apply, t);
        assert_eq!(r.status, AggregateStatus::Success, "{path}");
        assert_eq!(fs_of(&r).nodes[path].uid, 0, "{path}");
        assert!(
            r.commands.iter().all(|c| c.program != "/usr/bin/setpriv"
                || !MUTATION.contains(&inner(c).0)
                || inner(c).1.iter().all(|a| !a.starts_with(parent))),
            "{path}: root's own directory is not alice's tree"
        );
    }
}

#[test]
fn c1_08_a_directory_resource_makes_the_directory_root_s_and_the_file_follows() {
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "  - id: d\n    type: directory\n    with:\n      path: /tmp/app\n      mode: \"0755\"\n  - id: f\n    type: file\n    sensitive: true\n    depends_on: [d]\n    with:\n      path: /tmp/app/x.conf\n      content: \"{SECRET}\\n\"\n"
    );
    let p = recipe(&dir, &body);
    let r = run(&p, Mode::Apply, base(true));
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(fs_of(&r).nodes["/tmp/app"].uid, 0);
    assert_eq!(fs_of(&r).nodes["/tmp/app/x.conf"].uid, 0);
    assert!(
        r.commands.iter().all(|c| c.program != "/usr/bin/setpriv"),
        "nothing ran as another account"
    );
    // A directory another account made first is refused as a directory, and the
    // file behind it never runs (the existing entry gate; C-1 does not need to
    // intervene).
    let mut t = base(true);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/tmp/app", 0o755, ALICE, ALICE);
    let e = plan_err(&p, t.clone());
    assert!(e.message.contains("belongs to uid 1001"), "{}", e.message);
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_nothing_was_written(&r);
}

#[test]
fn c1_09_a_non_root_login_with_sudo_is_covered_in_the_same_way() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = base(false);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/tmp/app", 0o755, ALICE, ALICE);
    let p = recipe(&dir, &file("/tmp/app/x.conf", false, ""));
    let e = engine(&p, Mode::Plan, true, t.clone())
        .run()
        .err()
        .expect("plan must refuse");
    assert!(e.message.contains("sets `owner`"), "{}", e.message);
    let r = engine(&p, Mode::Apply, true, t.clone()).run().unwrap();
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_nothing_was_written(&r);
    let p = recipe(
        &dir,
        &file("/tmp/app/x.conf", false, "      owner: alice\n"),
    );
    let r = engine(&p, Mode::Apply, true, t).run().unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(fs_of(&r).nodes["/tmp/app/x.conf"].uid, ALICE);
    // Without `--sudo` a non-root login still does not enter the tree at all.
    let mut t = base(false);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/tmp/app", 0o755, ALICE, ALICE);
    let e = plan_err(&p, t);
    assert!(
        e.message.contains("outside the trusted set"),
        "{}",
        e.message
    );
}

// ---------------------------------------------------------------------------
// 3. other resource types and other ways in
// ---------------------------------------------------------------------------

#[test]
fn c1_10_a_template_needs_the_owner_like_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let tpl = |extra: &str| {
        format!(
            "  - id: f\n    type: template\n    sensitive: true\n    with:\n      path: /tmp/app/x.conf\n      source: t/x.tpl\n      vars: {{ v: \"{SECRET}\" }}\n{extra}"
        )
    };
    let p = recipe(&dir, &tpl(""));
    let e = plan_err(&p, squatted("/tmp", "app", ALICE));
    assert_no_detail(&e.message, "plan");
    let r = run(&p, Mode::Apply, squatted("/tmp", "app", ALICE));
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_nothing_was_written(&r);
    let p = recipe(&dir, &tpl("      owner: alice\n"));
    let r = run(&p, Mode::Apply, squatted("/tmp", "app", ALICE));
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(fs_of(&r).nodes["/tmp/app/x.conf"].uid, ALICE);
}

#[test]
fn c1_11_a_directory_in_the_tree_needs_the_owner_too_new_or_changed() {
    let dir = tempfile::tempdir().unwrap();
    let d = |extra: &str| {
        format!("  - id: d\n    type: directory\n    with:\n      path: /tmp/app/sub\n{extra}")
    };
    // new
    let p = recipe(&dir, &d(""));
    plan_err(&p, squatted("/tmp", "app", ALICE));
    let r = run(&p, Mode::Apply, squatted("/tmp", "app", ALICE));
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_nothing_was_written(&r);
    // a mode change on one that is there
    let mut t = squatted("/tmp", "app", ALICE);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/tmp/app/sub", 0o755, ALICE, ALICE);
    let p = recipe(&dir, &d("      mode: \"0700\"\n"));
    plan_err(&p, t.clone());
    let r = run(&p, Mode::Apply, t.clone());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_nothing_was_written(&r);
    // with the owner named, both go through (as the account)
    let p = recipe(&dir, &d("      mode: \"0700\"\n      owner: alice\n"));
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(fs_of(&r).nodes["/tmp/app/sub"].mode & 0o7777, 0o700);
    assert!(mutations(&r.commands)
        .iter()
        .all(|(who, _)| who.as_deref() == Some("1001")));
}

#[test]
fn c1_12_a_link_and_a_removal_write_no_content_and_run_as_the_account() {
    // They have no `owner` to ask for and carry no content: the account could do
    // the same itself. Pinned so that a change here is a decision.
    let dir = tempfile::tempdir().unwrap();
    let mut t = squatted("/tmp", "app", ALICE);
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/app/gone.conf", b"theirs\n", 0o644, ALICE, ALICE);
    let p = recipe(
        &dir,
        "  - id: l\n    type: link\n    with:\n      path: /tmp/app/lnk\n      target: /etc/hostname\n  - id: g\n    type: file\n    with:\n      path: /tmp/app/gone.conf\n      state: absent\n",
    );
    let r = run(&p, Mode::Apply, t);
    assert_eq!(
        r.status,
        AggregateStatus::Success,
        "{:?}",
        res(&r, "l").reason
    );
    assert!(fs_of(&r).nodes.contains_key("/tmp/app/lnk"));
    assert!(!fs_of(&r).nodes.contains_key("/tmp/app/gone.conf"));
    let m = mutations(&r.commands);
    assert!(!m.is_empty());
    assert!(
        m.iter().all(|(who, _)| who.as_deref() == Some("1001")),
        "{m:?}"
    );
}

#[test]
fn c1_13_the_state_of_a_file_that_is_already_right_is_not_a_write() {
    // Nothing is written, so nothing is exposed: plan, apply and audit agree
    // that it is converged (the owner is not managed when it is not named).
    let dir = tempfile::tempdir().unwrap();
    let mut t = squatted("/tmp", "app", ALICE);
    t.fs.as_mut().unwrap().put_file(
        "/tmp/app/x.conf",
        format!("{SECRET}\n").as_bytes(),
        0o644,
        ALICE,
        ALICE,
    );
    let p = recipe(&dir, &file("/tmp/app/x.conf", false, ""));
    let planned = run(&p, Mode::Plan, t.clone());
    assert_eq!(res(&planned, "f").change, Change::None);
    let r = run(&p, Mode::Apply, t.clone());
    assert_eq!(res(&r, "f").change, Change::None);
    assert_nothing_was_written(&r);
    let a = audit(&p, t);
    assert_eq!(a.exit_code(), 0, "{}", shown_audit(&a));
}

// ---------------------------------------------------------------------------
// 4. plan, apply and audit say the same
// ---------------------------------------------------------------------------

#[test]
fn c1_14_plan_and_apply_refuse_and_accept_the_same_recipes() {
    let tpl = |extra: &str| {
        format!(
            "  - id: f\n    type: template\n    with:\n      path: /tmp/app/x.conf\n      source: t/x.tpl\n      vars: {{ v: 1 }}\n{extra}"
        )
    };
    let dirr = |extra: &str| {
        format!("  - id: f\n    type: directory\n    with:\n      path: /tmp/app/d\n{extra}")
    };
    let cases: Vec<(&str, String, bool)> = vec![
        ("file, no owner", file("/tmp/app/x.conf", false, ""), false),
        (
            "file, owner alice",
            file("/tmp/app/x.conf", false, "      owner: alice\n"),
            true,
        ),
        (
            "file, owner root",
            file("/tmp/app/x.conf", false, "      owner: root\n"),
            false,
        ),
        (
            "file, group only",
            file("/tmp/app/x.conf", false, "      group: alice\n"),
            false,
        ),
        (
            "file, mode only",
            file("/tmp/app/x.conf", false, "      mode: \"0600\"\n"),
            false,
        ),
        ("template, no owner", tpl(""), false),
        ("template, owner alice", tpl("      owner: alice\n"), true),
        ("directory, no owner", dirr(""), false),
        ("directory, owner alice", dirr("      owner: alice\n"), true),
    ];
    for (what, body, accepted) in cases {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &body);
        let planned = plan_result(&p, squatted("/tmp", "app", ALICE));
        let applied = run(&p, Mode::Apply, squatted("/tmp", "app", ALICE));
        assert_eq!(planned.is_ok(), accepted, "{what}: plan");
        assert_eq!(
            applied.status == AggregateStatus::Success,
            accepted,
            "{what}: apply"
        );
        if !accepted {
            assert_nothing_was_written(&applied);
        }
        // Audit never writes, whatever it concludes.
        let a = audit(&p, squatted("/tmp", "app", ALICE));
        assert_eq!(mutations(&a.commands), vec![], "{what}: audit wrote");
    }
}

#[test]
fn c1_15_audit_reports_what_is_missing_and_never_writes_or_leaks() {
    // A file that is not there is drift, with or without the owner (audit
    // cannot create it). What apply refuses is not hidden: it is what a plan
    // of the same recipe reports.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &file("/tmp/app/x.conf", true, ""));
    let a = audit(&p, squatted("/tmp", "app", ALICE));
    assert_ne!(a.exit_code(), 0);
    assert_ne!(
        sinter_audit_status(&a, "f"),
        AuditResourceStatus::Compliant,
        "{}",
        shown_audit(&a)
    );
    assert_eq!(mutations(&a.commands), vec![]);
    assert_no_trace(&shown_audit(&a));
}

fn sinter_audit_status(a: &sinter::audit::AuditReport, id: &str) -> AuditResourceStatus {
    a.resources.iter().find(|x| x.id == id).unwrap().status
}

fn assert_no_trace(shown: &str) {
    for needle in [SECRET, "TOPSECRET"] {
        assert!(!shown.contains(needle), "{needle:?} leaked in: {shown}");
    }
}

// ---------------------------------------------------------------------------
// 5. secrecy of the refusal
// ---------------------------------------------------------------------------

#[test]
fn c1_16_a_sensitive_refusal_names_no_path_uid_or_content_anywhere_it_appears() {
    let dir = tempfile::tempdir().unwrap();
    for extra in ["", "      owner: root\n"] {
        let p = recipe(&dir, &file("/tmp/app/x.conf", true, extra));
        let e = plan_err(&p, squatted("/tmp", "app", ALICE));
        // Owner `root`: the conflict is the ordinary tree one, which since
        // LOW-3 is withheld as well for a sensitive resource.
        assert_no_detail(&e.message, "plan");
        let r = run(&p, Mode::Apply, squatted("/tmp", "app", ALICE));
        assert_no_detail(res(&r, "f").reason.as_deref().unwrap_or(""), "apply");
        assert_no_trace(&shown_apply(&r));
        let a = audit(&p, squatted("/tmp", "app", ALICE));
        for x in &a.resources {
            assert_no_detail(x.reason.as_deref().unwrap_or(""), "audit");
        }
        assert_no_trace(&shown_audit(&a));
    }
    // A non-sensitive one explains itself in full (the same message names the way out).
    let p = recipe(&dir, &file("/tmp/app/x.conf", false, ""));
    let e = plan_err(&p, squatted("/tmp", "app", ALICE));
    for want in ["/tmp/app", "uid 1001", "directory resource", "/opt"] {
        assert!(e.message.contains(want), "{want}: {}", e.message);
    }
}

// ---------------------------------------------------------------------------
// 6. a race: the directory appears after the plan
// ---------------------------------------------------------------------------

#[test]
fn c1_17_a_directory_another_account_makes_between_plan_and_apply_gets_nothing() {
    // The recipe makes /tmp/app itself. The planned run finds it absent; before
    // `mkdir` another account makes it. The directory resource fails (it is not
    // Sinter's to adopt) and the file behind it never runs.
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "  - id: d\n    type: directory\n    with:\n      path: /tmp/app\n  - id: f\n    type: file\n    sensitive: true\n    depends_on: [d]\n    with:\n      path: /tmp/app/x.conf\n      content: \"{SECRET}\\n\"\n"
    );
    let p = recipe(&dir, &body);
    let planned = run(&p, Mode::Plan, base(true));
    assert_eq!(res(&planned, "d").change, Change::Changed);
    let t = base(true).with_fs_event(
        "mkdir",
        "/tmp/app",
        0,
        vec![FsEventAction::MkDir {
            path: "/tmp/app".into(),
            mode: 0o755,
            uid: ALICE,
            gid: ALICE,
        }],
    );
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert!(!fs_of(&r).nodes.contains_key("/tmp/app/x.conf"));
    assert_eq!(fs_of(&r).nodes["/tmp/app"].uid, ALICE, "still theirs");
    assert!(
        mutations(&r.commands)
            .iter()
            .all(|(who, c)| who.is_none() && c.starts_with("mkdir")),
        "only root's own failed mkdir: {:?}",
        mutations(&r.commands)
    );
}

#[test]
fn c1_18_a_converged_run_is_stable() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &file(
            "/tmp/app/x.conf",
            true,
            "      owner: alice\n      mode: \"0640\"\n",
        ),
    );
    let r = run(&p, Mode::Apply, squatted("/tmp", "app", ALICE));
    assert_eq!(r.status, AggregateStatus::Success);
    let mut t = base(true);
    t.fs = r.fake_fs.clone();
    for mode in [Mode::Plan, Mode::Apply] {
        let again = run(&p, mode, t.clone());
        assert_eq!(res(&again, "f").change, Change::None, "{mode:?}");
        assert_nothing_was_written(&again);
    }
}

#[test]
fn c1_19_the_sequential_walk_decides_like_the_batched_one() {
    // A target with `getfacl` keeps the per-ancestor walk (`tests/path_c.rs`);
    // the shared-directory fact the rule needs must come out of both.
    let with_acl = |mut t: FakeTarget| {
        t = t.with_executable("/usr/bin/getfacl");
        t
    };
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &file("/tmp/app/x.conf", true, ""));
    plan_err(&p, with_acl(squatted("/tmp", "app", ALICE)));
    let r = run(&p, Mode::Apply, with_acl(squatted("/tmp", "app", ALICE)));
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_nothing_was_written(&r);
    let p = recipe(&dir, &file("/tmp/app/x.conf", true, "      owner: alice\n"));
    let r = run(&p, Mode::Apply, with_acl(squatted("/tmp", "app", ALICE)));
    assert_eq!(r.status, AggregateStatus::Success);
    // and a root-owned directory is still no tree on that walk
    let mut t = with_acl(base(true));
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/tmp/rootdir", 0o755, 0, 0);
    let p = recipe(&dir, &file("/tmp/rootdir/x.conf", true, ""));
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::Success);
}

#[test]
fn c1_20_a_directory_that_is_not_directly_in_a_shared_directory_is_not_a_squat() {
    // The rule needs the tree's root to be an entry of a shared directory
    // (sticky, trusted owner, writable by others). An account's directory below
    // a root-owned directory is not one, even inside /tmp, and a sticky parent
    // that nobody else can write to is not shared either. (Audit: two mutants
    // of the `in_shared` predicate survived without these.)
    for (parent, mode) in [("/tmp/rootdir", 0o755u32), ("/tmp/stk", 0o1755)] {
        let mut t = base(true);
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node(parent, mode, 0, 0);
        fs.mkdir_node(&format!("{parent}/app"), 0o755, ALICE, ALICE);
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &file(&format!("{parent}/app/x.conf"), true, ""));
        let r = run(&p, Mode::Apply, t);
        assert_eq!(r.status, AggregateStatus::Success, "{parent}");
        assert_eq!(fs_of(&r).nodes[&format!("{parent}/app/x.conf")].uid, ALICE);
    }
}

#[test]
fn c1_21_content_that_is_sensitive_only_at_run_time_gets_the_fixed_refusal_too() {
    // The file is not marked `sensitive`; its content comes from the register of
    // a sensitive command, which is known only when the command has run. The
    // refusal must still name no path or uid (audit finding F2).
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("t")).unwrap();
    std::fs::write(dir.path().join("t/reg.tpl"), "v={{ registers.p.stdout }}\n").unwrap();
    let body = "  - id: p\n    type: command\n    sensitive: true\n    with:\n      program: /bin/echo\n      args: [\"x\"]\n      register: p\n  - id: f\n    type: template\n    depends_on: [p]\n    with:\n      path: /tmp/app/x.conf\n      source: t/reg.tpl\n";
    let p = recipe(&dir, body);
    let t = squatted("/tmp", "app", ALICE).with_observations(
        "echo",
        vec![Output {
            completion: Completion::Exited(0),
            stdout: SECRET.as_bytes().to_vec(),
            stderr: vec![],
            stdout_truncated: false,
            stderr_truncated: false,
        }],
    );
    let r = run(&p, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let reason = res(&r, "f").reason.clone().unwrap_or_default();
    assert!(reason.contains("details withheld"), "{reason}");
    assert_no_detail(&reason, "apply");
    assert_no_trace(&shown_apply(&r));
}
