//! FS-3: root creates and updates entries inside an unprivileged user's
//! directory tree, e.g. `/home/mogemoge/page`, without `--sudo` and without
//! weakening the parent-path trust boundary (DESIGN §23).
//!
//! The mechanism under test: when the invocation is root (a root login or
//! `--sudo`) and the first untrusted ancestor of a managed path is a plain
//! directory of an unprivileged account, every file operation on the path runs
//! as that account (`setpriv`), so a tree the account controls cannot be used
//! to make root write somewhere only root can. Everything the account could
//! not do itself fails, and anything this cannot make safe is refused.
//!
//! The scripted target ([`FakeTarget`]) runs the production engine, trust
//! walk, identity switch and result code. That `setpriv` really drops
//! privileges, and the races a hostile owner can run, are real-Linux matters.
#![cfg(unix)]

use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::{CommandRecord, FakeTarget};
use sinter::model::load_model;
use sinter::result::{Change, Execution, ResourceResult, Verification};
use std::path::PathBuf;

// `sh` is the fixed staging script (FS-2): it stages, publishes and cleans up.
const MUTATION: [&str; 10] = [
    "mkdir", "chown", "chmod", "dd", "mv", "mktemp", "rm", "rmdir", "ln", "sh",
];

fn base(root: bool) -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("mogemoge", 1001)
        .with_user("mogemoge", 1001, 1001, "/home/mogemoge", "/bin/bash")
        .with_user("other", 1002, 1002, "/home/other", "/bin/bash");
    if root {
        t = t.as_root();
    }
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/home", 0o755, 0),
        ("/home/mogemoge", 0o755, 1001),
        ("/etc", 0o755, 0),
        ("/etc/fs3", 0o755, 0),
        ("/root", 0o700, 0),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    t
}

fn recipe(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\n{}", body)).unwrap();
    p
}

fn engine(p: &std::path::Path, mode: Mode, sudo: bool, t: FakeTarget) -> Engine {
    Engine::new(
        load_model(p).unwrap(),
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

fn run(p: &std::path::Path, mode: Mode, sudo: bool, t: FakeTarget) -> RunReport {
    engine(p, mode, sudo, t).run().unwrap()
}

fn plan_err(p: &std::path::Path, sudo: bool, t: FakeTarget) -> SinterError {
    engine(p, Mode::Plan, sudo, t)
        .run()
        .err()
        .expect("plan must fail")
}

fn res<'a>(r: &'a RunReport, id: &str) -> &'a ResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

/// The page directory and index file of the acceptance recipe.
const PAGE: &str = "resources:\n  - id: page\n    type: directory\n    with:\n      path: /home/mogemoge/page\n      owner: mogemoge\n      group: mogemoge\n      mode: \"0755\"\n  - id: index\n    type: file\n    depends_on: [page]\n    with:\n      path: /home/mogemoge/page/index.html\n      content: \"<h1>hi</h1>\\n\"\n      owner: mogemoge\n      group: mogemoge\n      mode: \"0644\"\n";

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Mutation commands that went out without the account wrapper.
fn bare_mutations(r: &RunReport) -> Vec<String> {
    r.commands
        .iter()
        .filter(|c| MUTATION.contains(&base_name(&c.program)))
        .map(|c| format!("{} {:?}", c.program, c.args))
        .collect()
}

/// Mutation commands wrapped by `setpriv` for the given account.
fn wrapped_mutations(r: &RunReport, uid: u32, gid: u32) -> Vec<&CommandRecord> {
    r.commands
        .iter()
        .filter(|c| c.program == "/usr/bin/setpriv")
        .inspect(|c| {
            let head: Vec<&str> = c.args.iter().take(7).map(|s| s.as_str()).collect();
            assert_eq!(
                head,
                [
                    "--reuid",
                    &uid.to_string(),
                    "--regid",
                    &gid.to_string(),
                    "--init-groups",
                    "--no-new-privs",
                    "--"
                ],
                "{:?}",
                c.args
            );
        })
        .filter(|c| MUTATION.contains(&base_name(&c.args[7])))
        .collect()
}

// ---------------------------------------------------------------------------
// the acceptance recipe
// ---------------------------------------------------------------------------

#[test]
fn root_creates_the_page_in_a_users_home_without_any_option() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, PAGE);
    let r = run(&p, Mode::Apply, false, base(true));
    assert_eq!(r.status, AggregateStatus::Success);
    for id in ["page", "index"] {
        let x = res(&r, id);
        assert_eq!(
            (x.execution, x.change, x.verification),
            (
                Execution::Succeeded,
                Change::Changed,
                Verification::Verified
            ),
            "{id}: {:?}",
            x.reason
        );
    }
    // Every change was made by a process that is mogemoge; nothing mutating ran
    // as root, and root's identity was never given up for the walk.
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
    let w = wrapped_mutations(&r, 1001, 1001);
    assert!(w.len() >= 4, "{} wrapped mutations", w.len());
    assert!(
        r.commands.iter().all(|c| !c.sudo),
        "no sudo wrapper for root"
    );
    // The account's own group came from the account database, not from the
    // directory's group.
    assert!(r
        .commands
        .iter()
        .any(|c| c.program == "/usr/bin/getent" && c.args == ["passwd", "1001"]));
}

#[test]
fn plan_names_the_changes_and_agrees_with_apply() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, PAGE);
    let plan = run(&p, Mode::Plan, false, base(true));
    assert_eq!(plan.status, AggregateStatus::Success);
    assert_eq!(res(&plan, "page").change, Change::Changed);
    assert_eq!(res(&plan, "index").change, Change::Changed);
    // Plan observes and mutates nothing.
    assert_eq!(bare_mutations(&plan), Vec::<String>::new());
    assert!(wrapped_mutations(&plan, 1001, 1001).is_empty());
}

#[test]
fn a_converged_page_is_unchanged_in_plan_apply_and_audit() {
    let mut t = base(true);
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/home/mogemoge/page", 0o755, 1001, 1001);
    fs.put_file(
        "/home/mogemoge/page/index.html",
        b"<h1>hi</h1>\n",
        0o644,
        1001,
        1001,
    );
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, PAGE);
    for mode in [Mode::Plan, Mode::Apply] {
        let r = run(&p, mode, false, t.clone());
        assert_eq!(r.status, AggregateStatus::Success, "{:?}", mode);
        for id in ["page", "index"] {
            assert_eq!(res(&r, id).change, Change::None, "{id} {:?}", mode);
        }
        assert_eq!(bare_mutations(&r), Vec::<String>::new(), "{:?}", mode);
    }
    let a = sinter::audit::run_audit(engine(&p, Mode::Plan, false, t)).unwrap();
    assert_eq!(a.exit_code(), 0, "{}", a.render_text());
}

#[test]
fn root_updates_an_existing_file_and_its_mode() {
    let mut t = base(true);
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/home/mogemoge/page", 0o755, 1001, 1001);
    fs.put_file(
        "/home/mogemoge/page/index.html",
        b"old\n",
        0o644,
        1001,
        1001,
    );
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &PAGE.replace("\"0644\"", "\"0600\""));
    let r = run(&p, Mode::Apply, false, t);
    let x = res(&r, "index");
    assert_eq!(
        (x.execution, x.change, x.verification),
        (
            Execution::Succeeded,
            Change::Changed,
            Verification::Verified
        ),
        "{:?}",
        x.reason
    );
    assert_eq!(res(&r, "page").change, Change::None);
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
    assert!(!wrapped_mutations(&r, 1001, 1001).is_empty());
}

#[test]
fn defaults_belong_to_the_account_when_the_recipe_names_no_owner() {
    let dir = tempfile::tempdir().unwrap();
    let body = "resources:\n  - id: page\n    type: directory\n    with:\n      path: /home/mogemoge/page\n  - id: index\n    type: file\n    depends_on: [page]\n    with:\n      path: /home/mogemoge/page/index.html\n      content: \"x\\n\"\n";
    let p = recipe(&dir, body);
    let r = run(&p, Mode::Apply, false, base(true));
    for id in ["page", "index"] {
        let x = res(&r, id);
        assert_eq!(
            (x.execution, x.verification),
            (Execution::Succeeded, Verification::Verified),
            "{id}: {:?}",
            x.reason
        );
    }
    // Nothing was ever handed to uid 0 or to another uid.
    for c in wrapped_mutations(&r, 1001, 1001) {
        // The owner is applied by the staging script's `stage` step:
        // `sh -c <script> sh stage <dir> <dir-id> <mode> <uid> <gid> ...`.
        if base_name(&c.args[7]) == "sh" && c.args.get(11).map(String::as_str) == Some("stage") {
            assert_eq!(
                (c.args[15].as_str(), c.args[16].as_str()),
                ("1001", "1001"),
                "{:?}",
                c.args
            );
        }
    }
}

#[test]
fn root_with_sudo_on_a_non_root_login_does_the_same_through_both_wrappers() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, PAGE);
    let r = run(&p, Mode::Apply, true, base(false));
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
    let w = wrapped_mutations(&r, 1001, 1001);
    assert!(!w.is_empty());
    // sudo is the outer wrapper (root), setpriv the inner one (the account).
    assert!(w.iter().all(|c| c.sudo));
}

// ---------------------------------------------------------------------------
// who may do this, and what stays refused
// ---------------------------------------------------------------------------

#[test]
fn a_non_root_login_is_still_refused_in_another_users_directory() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, PAGE);
    // The scripted login is uid 1000: Linux, not Sinter, decides what it may do
    // in uid 1001's home, and Sinter's own rule has not changed.
    let r = run(&p, Mode::Apply, false, base(false));
    let x = res(&r, "page");
    assert_eq!(x.execution, Execution::Failed);
    assert!(
        x.reason
            .as_deref()
            .unwrap()
            .contains("is owned by uid 1001"),
        "{:?}",
        x.reason
    );
    assert!(r.commands.iter().all(|c| c.program != "/usr/bin/setpriv"));
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
}

#[test]
fn a_group_or_other_writable_directory_stays_refused() {
    let mut t = base(true);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/home/mogemoge", 0o775, 1001, 1001);
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, PAGE);
    let r = run(&p, Mode::Apply, false, t.clone());
    let x = res(&r, "page");
    assert_eq!(x.execution, Execution::Failed);
    assert!(x
        .reason
        .as_deref()
        .unwrap()
        .contains("grants group or other write access"));
    assert!(plan_err(&p, false, t)
        .message
        .contains("grants group or other write access"));
    assert!(r.commands.iter().all(|c| c.program != "/usr/bin/setpriv"));
}

#[test]
fn a_symlink_inside_the_tree_is_never_followed() {
    use sinter::fakesys::{FakeKind, FakeNode};
    let link = |t: &mut FakeTarget, path: &str, to: &str| {
        t.fs.as_mut().unwrap().nodes.insert(
            path.to_string(),
            FakeNode {
                kind: FakeKind::Symlink(to.to_string()),
                mode: 0o777,
                uid: 1001,
                gid: 1001,
                ino: 9100,
                mtime: 5,
                ctime: 5,
            },
        );
    };
    // A parent that is a symlink to somewhere only root can write.
    let mut t = base(true);
    link(&mut t, "/home/mogemoge/page", "/etc");
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /home/mogemoge/page/evil.conf\n      content: \"x\\n\"\n");
    let r = run(&p, Mode::Apply, false, t);
    let x = res(&r, "f");
    assert_eq!(x.execution, Execution::Failed);
    assert!(x
        .reason
        .as_deref()
        .unwrap()
        .contains("is a symlink; refusing to follow"));
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
    // A final component that is a symlink.
    let mut t = base(true);
    link(&mut t, "/home/mogemoge/index.html", "/etc/shadow");
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /home/mogemoge/index.html\n      content: \"x\\n\"\n");
    let r = run(&p, Mode::Apply, false, t);
    let x = res(&r, "f");
    assert_ne!(x.execution, Execution::Succeeded);
    assert!(
        x.reason.as_deref().unwrap().contains("symlink"),
        "{:?}",
        x.reason
    );
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
}

#[test]
fn a_third_accounts_directory_inside_the_tree_is_refused() {
    let mut t = base(true);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/home/mogemoge/shared", 0o755, 1002, 1002);
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /home/mogemoge/shared/x.conf\n      content: \"x\\n\"\n");
    let r = run(&p, Mode::Apply, false, t);
    let x = res(&r, "f");
    assert_eq!(x.execution, Execution::Failed);
    assert!(
        x.reason
            .as_deref()
            .unwrap()
            .contains("one other account's tree at a time"),
        "{:?}",
        x.reason
    );
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
}

#[test]
fn an_owner_the_account_cannot_hand_over_is_refused_in_plan_and_apply() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /home/mogemoge/x.conf\n      content: \"x\\n\"\n      owner: root\n");
    let r = run(&p, Mode::Apply, false, base(true));
    let x = res(&r, "f");
    assert_eq!(x.execution, Execution::Failed);
    let reason = x.reason.clone().unwrap();
    assert!(
        reason.contains("only entries owned by uid 1001 are supported"),
        "{reason}"
    );
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
    assert!(wrapped_mutations(&r, 1001, 1001).is_empty());
    let e = plan_err(&p, false, base(true));
    assert!(
        e.message
            .contains("only entries owned by uid 1001 are supported"),
        "{}",
        e.message
    );
}

#[test]
fn an_existing_entry_owned_by_someone_else_is_not_adopted() {
    let mut t = base(true);
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/home/mogemoge/page", 0o755, 0, 0);
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: page\n    type: directory\n    with:\n      path: /home/mogemoge/page\n      mode: \"0700\"\n");
    let e = plan_err(&p, false, t.clone());
    assert!(
        e.message
            .contains("only entries owned by uid 1001 are supported"),
        "{}",
        e.message
    );
    let r = run(&p, Mode::Apply, false, t);
    assert_eq!(res(&r, "page").execution, Execution::Failed);
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
}

#[test]
fn an_owner_without_an_account_entry_is_refused() {
    let mut t = base(true);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/home/ghost", 0o755, 1005, 1005);
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /home/ghost/x.conf\n      content: \"x\\n\"\n");
    let r = run(&p, Mode::Apply, false, t);
    let x = res(&r, "f");
    assert_eq!(x.execution, Execution::Failed);
    assert!(
        x.reason
            .as_deref()
            .unwrap()
            .contains("no entry in the account database"),
        "{:?}",
        x.reason
    );
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
}

#[test]
fn a_missing_setpriv_fails_closed_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, PAGE);
    let r = run(&p, Mode::Apply, false, base(true).without_setpriv());
    let x = res(&r, "page");
    assert_eq!(x.execution, Execution::Failed);
    assert!(
        x.reason
            .as_deref()
            .unwrap()
            .contains("setpriv from util-linux is required"),
        "{:?}",
        x.reason
    );
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
}

#[test]
fn the_account_identity_does_not_leak_into_the_next_resource() {
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "{}  - id: etc\n    type: file\n    with:\n      path: /etc/fs3/a.conf\n      content: \"a\\n\"\n  - id: cmd\n    type: command\n    with:\n      program: /usr/bin/id\n      args: [\"-u\"]\n",
        PAGE
    );
    let p = recipe(&dir, &body);
    let r = run(&p, Mode::Apply, false, base(true));
    assert_eq!(
        r.status,
        AggregateStatus::Success,
        "{:?}",
        res(&r, "etc").reason
    );
    // Nothing that touches /etc/fs3 was wrapped, and the command resource ran
    // as the invocation.
    for c in &r.commands {
        let touches_etc = c.args.iter().any(|a| a.contains("/etc/fs3"));
        if touches_etc {
            assert_ne!(c.program, "/usr/bin/setpriv", "{:?}", c.args);
        }
        if c.program == "/usr/bin/id" {
            assert_eq!(c.args, ["-u"]);
        }
    }
    assert!(wrapped_mutations(&r, 1001, 1001).len() >= 4);
}

#[test]
fn a_backup_of_a_path_in_the_tree_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = base(true);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/home/mogemoge/page", 0o755, 1001, 1001);
    let body = format!(
        "backup:\n  paths: [/home/mogemoge/page]\n{}",
        PAGE.replace("\"0755\"", "\"0700\"")
    );
    let p = recipe(&dir, &body);
    match engine(&p, Mode::Apply, false, t).run() {
        Err(e) => assert!(e.message.contains("is owned by uid 1001"), "{}", e.message),
        Ok(r) => {
            assert_ne!(r.status, AggregateStatus::Success);
            assert!(r.commands.iter().all(|c| c.program != "/usr/bin/setpriv"));
        }
    }
}

#[test]
fn audit_does_not_change_anything() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, PAGE);
    let a = sinter::audit::run_audit(engine(&p, Mode::Plan, false, base(true))).unwrap();
    assert_ne!(a.exit_code(), 0);
    assert_eq!(
        a.commands
            .iter()
            .filter(|c| MUTATION.contains(&base_name(&c.program)))
            .count(),
        0
    );
}

#[test]
fn the_accounts_own_primary_group_is_used_not_the_directorys_group() {
    // The directory's group (1500) is not the account's primary group (1001):
    // borrowing it would give the operations a group the account may not have.
    let mut t = base(true);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/home/mogemoge", 0o755, 1001, 1500);
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, PAGE);
    let r = run(&p, Mode::Apply, false, t);
    assert_eq!(r.status, AggregateStatus::Success);
    assert!(!wrapped_mutations(&r, 1001, 1001).is_empty());
    assert!(r
        .commands
        .iter()
        .filter(|c| c.program == "/usr/bin/setpriv")
        .all(|c| !c.args.iter().any(|a| a == "1500")));
}

// ---------------------------------------------------------------------------
// the account identity is dropped after a failure and after an observation
// (FS-3 C-3)
// ---------------------------------------------------------------------------

/// A resource inside the account's tree that fails after the account's identity
/// was settled (the owner asked for cannot be handed over), then one that
/// belongs to root.
const FAILED_TREE_THEN_ROOT: &str = "resources:\n  - id: bad\n    type: file\n    with:\n      path: /home/mogemoge/x.conf\n      content: \"x\\n\"\n      owner: other\n  - id: etc\n    type: file\n    with:\n      path: /etc/fs3/a.conf\n      content: \"a\\n\"\n      owner: root\n";

fn inner_program(c: &CommandRecord) -> &str {
    base_name(&c.args[7])
}

#[test]
fn an_audit_resource_after_a_refused_tree_resource_observes_as_root() {
    // apply stops at the first failure (fail-fast), but audit goes on after a
    // resource it could not observe: the one that follows must not inherit
    // the account the refused one was walked as.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FAILED_TREE_THEN_ROOT);
    let a = sinter::audit::run_audit(engine(&p, Mode::Plan, false, base(true))).unwrap();
    let touching_etc: Vec<&CommandRecord> = a
        .commands
        .iter()
        .filter(|c| c.args.iter().any(|x| x.contains("/etc/fs3")))
        .collect();
    assert!(
        !touching_etc.is_empty(),
        "the root resource was not observed"
    );
    for c in touching_etc {
        assert_ne!(c.program, "/usr/bin/setpriv", "{:?}", c.args);
    }
    assert!(
        a.commands
            .iter()
            .filter(|c| c.program == "/usr/bin/setpriv")
            .all(|c| !c.args.iter().any(|x| x.contains("/etc/fs3"))),
        "an account wrapper reached /etc/fs3"
    );
}

#[test]
fn apply_stops_at_a_refused_tree_resource_and_nothing_runs_as_the_account_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FAILED_TREE_THEN_ROOT);
    let r = run(&p, Mode::Apply, false, base(true));
    assert_eq!(res(&r, "bad").execution, Execution::Failed);
    assert_eq!(res(&r, "etc").execution, Execution::NotRun);
    assert!(
        wrapped_mutations(&r, 1001, 1001).is_empty(),
        "the refused owner reached the target"
    );
    assert_eq!(bare_mutations(&r), Vec::<String>::new());
}

#[test]
fn plan_and_audit_hold_no_identity_once_an_observation_is_done() {
    // An account lookup is the one command that is not part of an observation
    // or a change; it must never run as the account of a tree observed just
    // before. Owner names are resolved for the tree file and for the root
    // file in turn, in plan and in audit.
    let dir = tempfile::tempdir().unwrap();
    let body = "resources:\n  - id: tree\n    type: file\n    with:\n      path: /home/mogemoge/a.conf\n      content: \"a\\n\"\n      owner: mogemoge\n  - id: etc1\n    type: file\n    with:\n      path: /etc/fs3/a.conf\n      content: \"a\\n\"\n      owner: root\n  - id: tree2\n    type: file\n    with:\n      path: /home/mogemoge/b.conf\n      content: \"b\\n\"\n      owner: mogemoge\n  - id: etc2\n    type: file\n    with:\n      path: /etc/fs3/b.conf\n      content: \"b\\n\"\n      owner: root\n";
    let p = recipe(&dir, body);
    // Every file is there, so the content of each is read (an observation that
    // reads, as opposed to one that finds nothing).
    let mut t = base(true);
    let fs = t.fs.as_mut().unwrap();
    fs.put_file("/home/mogemoge/a.conf", b"old\n", 0o644, 1001, 1001);
    fs.put_file("/home/mogemoge/b.conf", b"old\n", 0o644, 1001, 1001);
    fs.put_file("/etc/fs3/a.conf", b"old\n", 0o644, 0, 0);
    fs.put_file("/etc/fs3/b.conf", b"old\n", 0o644, 0, 0);
    let planned = run(&p, Mode::Plan, false, t.clone());
    let audited = sinter::audit::run_audit(engine(&p, Mode::Plan, false, t)).unwrap();
    for (what, commands) in [("plan", &planned.commands), ("audit", &audited.commands)] {
        assert!(
            commands.iter().any(|c| c.program.ends_with("sha256sum")),
            "{what}: no content was read"
        );
        let lookups = commands
            .iter()
            .filter(|c| c.program.ends_with("getent"))
            .count();
        assert!(lookups > 0, "{what}: the recipe resolves no account");
        for c in commands.iter().filter(|c| c.program == "/usr/bin/setpriv") {
            assert_ne!(inner_program(c), "getent", "{what}: {:?}", c.args);
        }
    }
}

#[test]
fn a_sensitive_resource_in_the_tree_does_not_name_the_path_or_uid_it_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let body = "resources:\n  - id: s\n    type: file\n    sensitive: true\n    with:\n      path: /home/mogemoge/secret-name.conf\n      content: \"x\\n\"\n      owner: other\n";
    let p = recipe(&dir, body);
    let e = plan_err(&p, false, base(true));
    assert!(!e.message.contains("secret-name"), "{}", e.message);
    assert!(!e.message.contains("1002"), "{}", e.message);
    assert!(!e.message.contains("/home/mogemoge"), "{}", e.message);
    let r = run(&p, Mode::Apply, false, base(true));
    let x = res(&r, "s");
    assert_eq!(x.execution, Execution::Failed);
    let why = x.reason.as_deref().unwrap_or("");
    assert!(
        !why.contains("secret-name") && !why.contains("1002"),
        "{why}"
    );
    // An ordinary resource still gets the full explanation.
    let p = recipe(&dir, &body.replace("    sensitive: true\n", ""));
    let e = plan_err(&p, false, base(true));
    assert!(e.message.contains("cannot give"), "{}", e.message);
}
