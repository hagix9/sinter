//! L-1 / L-2: nothing about a managed path is observed before the parent walk
//! of DESIGN §23 has accepted its parents, and inside another account's tree
//! the observation runs as that account.
//!
//! Before this gate `plan` and `audit` read a path (`stat`, `readlink`,
//! `sha256sum`) as the invocation, root, *before* (plan) or *without* (audit)
//! the walk, so a symlink planted in a directory another account controls
//! could make root look at a file only root can read, and what it saw (mode,
//! owner, size, a link text, whether a digest matched) could reach the output.
//!
//! The scripted target is a modeled filesystem that answers by exact path. A
//! file placed at the path *behind* a planted symlink is therefore what the
//! kernel would have shown root had the symlink been followed: any trace of it
//! in the output, or any command that reads that path, is a leak. That the real
//! kernel and `setpriv` behave this way is a real-Linux matter.
#![cfg(unix)]

mod common;

use sinter::audit::{run_audit, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::{CommandRecord, Completion, FakeTarget, Output};
use sinter::fakesys::FakeKind;
use sinter::model::load_model;
use sinter::output::{render_audit, render_plan, OutputFormat, RenderOptions};
use sinter::result::{Change, Execution, ResourceResult};
use std::path::PathBuf;

const MUTATION: [&str; 11] = [
    "mkdir", "chown", "chmod", "dd", "mv", "mktemp", "rm", "rmdir", "ln", "setfattr", "cp",
];
const OBSERVATION: [&str; 6] = [
    "stat",
    "sha256sum",
    "readlink",
    "cat",
    "getfattr",
    "getfacl",
];

/// What lies behind the planted link, and the text that must never show.
const SECRET_PATH: &str = "/home/mogemoge/link/secret";
const SECRET_CONTENT: &str = "TOPSECRET-ROOT-ONLY\n";

fn base() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("mogemoge", 1001)
        .with_user("mogemoge", 1001, 1001, "/home/mogemoge", "/bin/bash")
        .as_root();
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

/// `/home/mogemoge/link` is a symlink to `/root` planted by the account; the
/// file behind it is root's, mode 0600.
fn with_planted_link(mut t: FakeTarget) -> FakeTarget {
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/home/mogemoge/link", 0o777, 1001, 1001);
    fs.nodes.get_mut("/home/mogemoge/link").unwrap().kind = FakeKind::Symlink("/root".to_string());
    fs.put_file(SECRET_PATH, SECRET_CONTENT.as_bytes(), 0o600, 0, 0);
    t
}

fn recipe(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\n{}", body)).unwrap();
    p
}

fn engine(p: &std::path::Path, mode: Mode, t: FakeTarget) -> Engine {
    Engine::new(
        load_model(p).unwrap(),
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
}

fn run(p: &std::path::Path, mode: Mode, t: FakeTarget) -> RunReport {
    engine(p, mode, t).run().unwrap()
}

fn plan_err(p: &std::path::Path, t: FakeTarget) -> SinterError {
    engine(p, Mode::Plan, t)
        .run()
        .err()
        .expect("plan must fail")
}

fn res<'a>(r: &'a RunReport, id: &str) -> &'a ResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
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

/// Commands that read `path` itself (not a directory above it).
fn reads_of<'a>(cmds: &'a [CommandRecord], path: &str) -> Vec<&'a CommandRecord> {
    cmds.iter()
        .filter(|c| {
            let (prog, args) = inner(c);
            OBSERVATION.contains(&prog) && args.last().map(String::as_str) == Some(path)
        })
        .collect()
}

fn mutations(cmds: &[CommandRecord]) -> Vec<String> {
    cmds.iter()
        .filter(|c| MUTATION.contains(&inner(c).0))
        .map(|c| format!("{} {:?}", c.program, c.args))
        .collect()
}

/// Whether a record runs as the account `uid`/`gid` (and as nobody else).
fn runs_as(c: &CommandRecord, uid: u32, gid: u32) -> bool {
    c.program == "/usr/bin/setpriv"
        && c.args[..7]
            == [
                "--reuid",
                &uid.to_string(),
                "--regid",
                &gid.to_string(),
                "--init-groups",
                "--no-new-privs",
                "--",
            ]
}

fn exited(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

/// The whole rendered output (text and JSON) of a plan or an audit.
fn assert_no_trace_of_the_secret(shown: &str) {
    for needle in [
        "TOPSECRET",
        "0600",
        "mode=600",
        "mode=0600",
        "20 bytes",
        "owner=0",
    ] {
        assert!(!shown.contains(needle), "{needle:?} leaked in: {shown}");
    }
}

fn plan_text_and_json(r: &RunReport) -> String {
    let mut shown = String::new();
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut buf = Vec::new();
        render_plan(
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

const LEAK: &str = "resources:\n  - id: leak\n    type: file\n    with:\n      path: /home/mogemoge/link/secret\n      content: \"x\\n\"\n";

// ---------------------------------------------------------------------------
// L-1: plan
// ---------------------------------------------------------------------------

#[test]
fn plan_walks_the_parents_before_it_observes_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /etc/fs3/a.conf\n      content: \"a\\n\"\n");
    let r = run(&p, Mode::Plan, base());
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(res(&r, "f").change, Change::Changed);
    let walk = r
        .commands
        .iter()
        .position(|c| inner(c).0 == "stat" && inner(c).1[0].starts_with("--printf="))
        .expect("a batched parent walk");
    let first_read = r
        .commands
        .iter()
        .position(|c| !reads_of(std::slice::from_ref(c), "/etc/fs3/a.conf").is_empty())
        .expect("the file is observed");
    assert!(
        walk < first_read,
        "walk {walk} before the file's stat {first_read}"
    );
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
}

#[test]
fn a_converged_file_is_unchanged_and_costs_one_walk() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /etc/fs3/a.conf\n      content: \"a\\n\"\n");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/fs3/a.conf", b"a\n", 0o644, 0, 0);
    let r = run(&p, Mode::Plan, t);
    assert_eq!(res(&r, "f").change, Change::None);
    let walks = r
        .commands
        .iter()
        .filter(|c| inner(c).0 == "stat" && inner(c).1[0].starts_with("--printf="))
        .count();
    assert_eq!(walks, 1);
}

#[test]
fn in_a_users_tree_plan_observes_the_path_as_that_user() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /home/mogemoge/page.html\n      content: \"new\\n\"\n");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/home/mogemoge/page.html", b"old\n", 0o644, 1001, 1001);
    let r = run(&p, Mode::Plan, t);
    assert_eq!(res(&r, "f").change, Change::Changed);
    let reads = reads_of(&r.commands, "/home/mogemoge/page.html");
    let programs: Vec<&str> = reads.iter().map(|c| inner(c).0).collect();
    assert!(
        programs.contains(&"stat") && programs.contains(&"sha256sum"),
        "{programs:?}"
    );
    for c in &reads {
        assert!(runs_as(c, 1001, 1001), "{:?} must run as the account", c);
    }
    // The walk itself is the invocation's, and nothing is changed.
    for c in r
        .commands
        .iter()
        .filter(|c| inner(c).0 == "stat" && inner(c).1[0].starts_with("--printf="))
    {
        assert_ne!(c.program, "/usr/bin/setpriv");
    }
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
}

#[test]
fn a_planted_ancestor_symlink_is_refused_and_nothing_behind_it_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, LEAK);
    let e = plan_err(&p, with_planted_link(base()));
    assert!(e.message.contains("symlink"), "{}", e.message);
    assert_no_trace_of_the_secret(&e.message);
}

#[test]
fn a_planted_symlink_hides_nothing_even_when_the_desired_content_matches() {
    // Without the gate the digest of the file behind the link equals the
    // recipe's content: plan answered "unchanged", i.e. it reported whether
    // root's file had this content.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &format!(
            "resources:\n  - id: leak\n    type: file\n    with:\n      path: {SECRET_PATH}\n      content: \"{}\"\n",
            SECRET_CONTENT.replace('\n', "\\n")
        ),
    );
    let e = plan_err(&p, with_planted_link(base()));
    assert!(e.message.contains("symlink"), "{}", e.message);
}

#[test]
fn a_refused_parent_that_an_earlier_change_may_alter_is_unknown_and_unread() {
    // The package may change what the walk refuses now, so plan cannot call
    // the refusal certain: the resource is Unknown (never a guess from reading
    // through the link).
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "resources:\n  - id: pkg\n    type: package\n    with:\n      name: nginx\n      state: present\n{}",
        &LEAK["resources:\n".len()..]
    );
    let p = recipe(&dir, &body);
    let r = run(&p, Mode::Plan, with_planted_link(base()));
    let x = res(&r, "leak");
    assert!(x.unknown, "{x:?}");
    assert_eq!(x.change, Change::None);
    assert!(
        x.reason
            .as_deref()
            .unwrap()
            .starts_with("parent path check deferred to apply"),
        "{:?}",
        x.reason
    );
    assert!(
        reads_of(&r.commands, SECRET_PATH).is_empty(),
        "{:?}",
        r.commands
    );
    assert_no_trace_of_the_secret(&plan_text_and_json(&r));
}

#[test]
fn a_parent_that_does_not_exist_yet_still_plans_as_a_creation() {
    // The dependency contract: a directory planned earlier creates the parent.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: d\n    type: directory\n    with:\n      path: /etc/fs3/new\n  - id: f\n    type: file\n    depends_on: [d]\n    with:\n      path: /etc/fs3/new/a.conf\n      content: \"a\\n\"\n",
    );
    let r = run(&p, Mode::Plan, base());
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(res(&r, "d").change, Change::Changed);
    assert_eq!(res(&r, "f").change, Change::Changed);
    assert!(!res(&r, "f").unknown);
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
}

#[test]
fn a_link_resource_does_not_read_a_link_behind_a_planted_ancestor() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: l\n    type: link\n    with:\n      path: /home/mogemoge/link/secret\n      target: /etc/fs3\n",
    );
    // Root's link behind the planted one already has the desired target: read
    // through the link, plan would have called the resource converged.
    let mut t = with_planted_link(base());
    {
        let fs = t.fs.as_mut().unwrap();
        fs.nodes.remove(SECRET_PATH);
        fs.mkdir_node(SECRET_PATH, 0o777, 0, 0);
        fs.nodes.get_mut(SECRET_PATH).unwrap().kind = FakeKind::Symlink("/etc/fs3".to_string());
    }
    let e = plan_err(&p, t);
    assert!(e.message.contains("symlink"), "{}", e.message);
}

#[test]
fn a_directory_resource_does_not_stat_behind_a_planted_ancestor() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: d\n    type: directory\n    with:\n      path: /home/mogemoge/link/secret\n      owner: root\n      group: root\n      mode: \"0700\"\n",
    );
    // Root's own 0700 directory behind the link matches the recipe exactly.
    let mut t = with_planted_link(base());
    {
        let fs = t.fs.as_mut().unwrap();
        fs.nodes.remove(SECRET_PATH);
        fs.mkdir_node(SECRET_PATH, 0o700, 0, 0);
    }
    let e = plan_err(&p, t);
    assert!(e.message.contains("symlink"), "{}", e.message);
}

#[test]
fn a_fifo_is_never_hashed() {
    // A path that is not a regular file is refused before any digest is
    // requested, so `sha256sum` can never wait on a pipe.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /etc/fs3/pipe\n      content: \"x\\n\"\n");
    let t = base().with_observations_at(
        "stat",
        "/etc/fs3/pipe",
        vec![exited(0, "fifo|644|0|0|0|2049|77|2026-10-13 00:00:00.000000000 +0000|2026-10-13 00:00:00.000000000 +0000\n", "")],
    );
    let e = plan_err(&p, t);
    assert!(e.message.contains("refusing"), "{}", e.message);
}

#[test]
fn apply_refuses_a_planted_ancestor_symlink_without_reading_or_changing_anything() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, LEAK);
    let r = run(&p, Mode::Apply, with_planted_link(base()));
    let x = res(&r, "leak");
    assert_eq!(x.execution, Execution::Failed);
    assert!(
        x.reason.as_deref().unwrap().contains("symlink"),
        "{:?}",
        x.reason
    );
    assert!(
        reads_of(&r.commands, SECRET_PATH).is_empty(),
        "{:?}",
        r.commands
    );
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
}

#[test]
fn a_sensitive_resource_names_no_path_when_its_parent_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: leak\n    type: file\n    sensitive: true\n    with:\n      path: /home/mogemoge/link/secret\n      content: \"x\\n\"\n",
    );
    let e = plan_err(&p, with_planted_link(base()));
    assert!(!e.message.contains("mogemoge"), "{}", e.message);
}

// ---------------------------------------------------------------------------
// L-2: audit
// ---------------------------------------------------------------------------

fn audit(p: &std::path::Path, t: FakeTarget) -> sinter::audit::AuditReport {
    run_audit(engine(p, Mode::Plan, t)).unwrap()
}

fn audit_text_and_json(r: &sinter::audit::AuditReport) -> String {
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

fn afind<'a>(
    r: &'a sinter::audit::AuditReport,
    id: &str,
) -> &'a sinter::audit::AuditResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

#[test]
fn audit_of_a_converged_file_is_compliant_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /etc/fs3/a.conf\n      content: \"a\\n\"\n");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/fs3/a.conf", b"a\n", 0o644, 0, 0);
    let r = audit(&p, t);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Compliant);
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
    assert!(r.commands.iter().all(|c| !c.sudo));
    let walk = r
        .commands
        .iter()
        .position(|c| inner(c).0 == "stat" && inner(c).1[0].starts_with("--printf="))
        .expect("audit walks the parents");
    let first_read = r
        .commands
        .iter()
        .position(|c| !reads_of(std::slice::from_ref(c), "/etc/fs3/a.conf").is_empty())
        .unwrap();
    assert!(walk < first_read);
}

#[test]
fn audit_in_a_users_tree_observes_as_that_user() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /home/mogemoge/page.html\n      content: \"old\\n\"\n      owner: mogemoge\n      group: mogemoge\n  - id: l\n    type: link\n    with:\n      path: /home/mogemoge/cur\n      target: page.html\n  - id: d\n    type: directory\n    with:\n      path: /home/mogemoge/site\n      owner: mogemoge\n      group: mogemoge\n");
    let mut t = base();
    {
        let fs = t.fs.as_mut().unwrap();
        fs.put_file("/home/mogemoge/page.html", b"old\n", 0o644, 1001, 1001);
        fs.mkdir_node("/home/mogemoge/site", 0o755, 1001, 1001);
        fs.mkdir_node("/home/mogemoge/cur", 0o777, 1001, 1001);
        fs.nodes.get_mut("/home/mogemoge/cur").unwrap().kind =
            FakeKind::Symlink("page.html".to_string());
    }
    let r = audit(&p, t);
    for id in ["f", "l", "d"] {
        assert_eq!(
            afind(&r, id).status,
            AuditResourceStatus::Compliant,
            "{id}: {:?}",
            afind(&r, id)
        );
    }
    for path in [
        "/home/mogemoge/page.html",
        "/home/mogemoge/cur",
        "/home/mogemoge/site",
    ] {
        let reads = reads_of(&r.commands, path);
        assert!(!reads.is_empty(), "{path}");
        for c in reads {
            assert!(runs_as(c, 1001, 1001), "{path}: {:?}", c);
        }
    }
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
}

#[test]
fn audit_does_not_follow_a_planted_ancestor_symlink() {
    let dir = tempfile::tempdir().unwrap();
    // The secret equals the desired content: a digest comparison through the
    // link would have said "compliant".
    let p = recipe(
        &dir,
        &format!(
            "resources:\n  - id: leak\n    type: file\n    with:\n      path: {SECRET_PATH}\n      content: \"{}\"\n      mode: \"0644\"\n",
            SECRET_CONTENT.replace('\n', "\\n")
        ),
    );
    let r = audit(&p, with_planted_link(base()));
    let x = afind(&r, "leak");
    assert_eq!(x.status, AuditResourceStatus::Error, "{x:?}");
    assert!(
        x.details.is_empty(),
        "no drift is derived from the unread file"
    );
    assert!(
        x.reason.as_deref().unwrap().contains("symlink"),
        "{:?}",
        x.reason
    );
    assert!(
        reads_of(&r.commands, SECRET_PATH).is_empty(),
        "{:?}",
        r.commands
    );
    assert_no_trace_of_the_secret(&audit_text_and_json(&r));
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
    // An observation that could not be made is indeterminate, not drift.
    assert_eq!(r.exit_code(), 6);
}

#[test]
fn audit_of_link_and_directory_does_not_follow_a_planted_ancestor_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: l\n    type: link\n    with:\n      path: /home/mogemoge/link/secret\n      target: /etc\n  - id: d\n    type: directory\n    with:\n      path: /home/mogemoge/link/secdir\n      mode: \"0755\"\n",
    );
    let mut t = with_planted_link(base());
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/home/mogemoge/link/secdir", 0o700, 0, 0);
    let r = audit(&p, t);
    for id in ["l", "d"] {
        assert_eq!(afind(&r, id).status, AuditResourceStatus::Error, "{id}");
    }
    for path in [SECRET_PATH, "/home/mogemoge/link/secdir"] {
        assert!(
            reads_of(&r.commands, path).is_empty(),
            "{path}: {:?}",
            r.commands
        );
    }
    assert_no_trace_of_the_secret(&audit_text_and_json(&r));
}

#[test]
fn audit_of_a_sensitive_resource_names_neither_path_nor_reason() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: leak\n    type: file\n    sensitive: true\n    with:\n      path: /home/mogemoge/link/secret\n      content: \"x\\n\"\n",
    );
    let r = audit(&p, with_planted_link(base()));
    assert_eq!(afind(&r, "leak").status, AuditResourceStatus::Error);
    let shown = audit_text_and_json(&r);
    assert!(!shown.contains("mogemoge"), "{shown}");
    assert!(!shown.contains("symlink"), "{shown}");
}

#[test]
fn audit_of_a_path_below_a_missing_parent_is_drift_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /etc/fs3/not/yet/a.conf\n      content: \"a\\n\"\n");
    let r = audit(&p, base());
    let x = afind(&r, "f");
    assert_eq!(x.status, AuditResourceStatus::Drift, "{x:?}");
    assert_eq!(mutations(&r.commands), Vec::<String>::new());
}

#[test]
fn audit_in_a_tree_of_an_account_without_an_entry_is_an_error_and_unread() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, "resources:\n  - id: f\n    type: file\n    with:\n      path: /home/ghost/x.conf\n      content: \"x\\n\"\n");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/home/ghost", 0o755, 1005, 1005);
    let r = audit(&p, t);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
    assert!(
        afind(&r, "f")
            .reason
            .as_deref()
            .unwrap()
            .contains("no entry in the account database"),
        "{:?}",
        afind(&r, "f").reason
    );
    assert!(reads_of(&r.commands, "/home/ghost/x.conf").is_empty());
}
