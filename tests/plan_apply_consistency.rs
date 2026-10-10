//! WP-2: plan reports the parent path refusals that apply would make.
//!
//! Apply checks the parent path trust boundary (DESIGN §23) before every
//! file, directory, link and template mutation. Plan used to return
//! `changed` before that check, so a recipe could plan cleanly and then fail
//! at apply. Plan now runs the same read-only check for every change it
//! plans:
//!
//! * when nothing apply does earlier can change what plan observed, the
//!   refusal is the plan's error (exit 4), with apply's reason;
//! * when an earlier planned change may (a directory this run creates, a
//!   package, a command), the change stands with a note, and apply decides;
//! * a path that passes the check plans exactly as before.
//!
//! These tests drive the production engine through the scripted target
//! (`FakeTarget` with its in-memory filesystem). Real tools, filesystems and
//! SSH are covered by the separate Linux acceptance run, not here.
//!
//! (HEAD port: the scripted filesystem of this tree models no ACL, so the
//! ACL parent case of the WP-1 tree is not part of this file.)
#![cfg(unix)]

mod common;

use common::mutation_command_count;
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::{ErrorKind, SinterError};
use sinter::executor::FakeTarget;
use sinter::fakesys::{FakeKind, FakeNode};
use sinter::model::load_model;
use sinter::result::{Change, DiffBody, Execution, ResourceResult};
use std::path::PathBuf;

const PLAN_SUFFIX: &str = "(plan: Sinter's parent path check would refuse this change at apply)";
const DEFERRED: &str = "parent path check deferred to apply";

fn target() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().with_fake_fs();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode) in [("/srv", 0o755), ("/home", 0o755)] {
        fs.mkdir_node(path, mode, 0, 0);
    }
    t
}

fn engine(path: &std::path::Path, mode: Mode, sudo: bool, t: FakeTarget) -> Engine {
    engine_fault(path, mode, sudo, t, None)
}

fn engine_fault(
    path: &std::path::Path,
    mode: Mode,
    sudo: bool,
    t: FakeTarget,
    fault: Option<&str>,
) -> Engine {
    Engine::new(
        load_model(path).unwrap(),
        RunOptions {
            mode,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: fault.map(String::from),
            fake_target: Some(t),
        },
    )
    .unwrap()
}

fn plan(path: &std::path::Path, sudo: bool, t: FakeTarget) -> Result<RunReport, SinterError> {
    engine(path, Mode::Plan, sudo, t).run()
}

fn apply(path: &std::path::Path, sudo: bool, t: FakeTarget) -> RunReport {
    engine(path, Mode::Apply, sudo, t)
        .run()
        .unwrap_or_else(|e| panic!("apply: {}", e.message))
}

fn res<'a>(r: &'a RunReport, id: &str) -> &'a ResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

/// A recipe directory with a template source next to the recipe.
fn recipe(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    std::fs::write(dir.path().join("t.tmpl"), "templated\n").unwrap();
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\nresources:\n{}", body)).unwrap();
    p
}

/// One resource of `kind` at `path`, id `r`.
fn resource(kind: &str, path: &str) -> String {
    let with = match kind {
        "file" => "      content: \"x\\n\"\n",
        "directory" => "",
        "link" => "      target: /etc/hostname\n",
        "template" => "      source: t.tmpl\n",
        _ => unreachable!(),
    };
    format!("  - id: r\n    type: {kind}\n    with:\n      path: {path}\n{with}")
}

const KINDS: [&str; 4] = ["file", "directory", "link", "template"];

fn symlink(t: &mut FakeTarget, path: &str, to: &str) {
    t.fs.as_mut().unwrap().nodes.insert(
        path.to_string(),
        FakeNode {
            kind: FakeKind::Symlink(to.to_string()),
            mode: 0o777,
            uid: 0,
            gid: 0,
            ino: 9100,
            mtime: 5,
            ctime: 5,
        },
    );
}

/// A parent that apply refuses: (name, --sudo, target, directory to place
/// the managed entry in).
fn refused_parents() -> Vec<(&'static str, bool, FakeTarget, &'static str)> {
    let mut owned = target();
    owned
        .fs
        .as_mut()
        .unwrap()
        .mkdir_node("/home/moge", 0o750, 1001, 1001);

    let mut writable = target();
    writable
        .fs
        .as_mut()
        .unwrap()
        .mkdir_node("/srv/drop", 0o777, 0, 0);

    let mut via_symlink = target();
    symlink(&mut via_symlink, "/srv/via", "/opt");

    vec![
        ("user-owned parent under --sudo", true, owned, "/home/moge"),
        ("world-writable parent", true, writable, "/srv/drop"),
        ("symlink parent", true, via_symlink, "/srv/via"),
        ("missing parent", true, target(), "/srv/missing"),
    ]
}

// ---------------------------------------------------------------------------
// A refusal apply would certainly make is the plan's error, with apply's reason.
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_each_parent_refusal_that_apply_makes_with_the_same_reason() {
    for (case, sudo, t, parent) in refused_parents() {
        for kind in KINDS {
            let dir = tempfile::tempdir().unwrap();
            let p = recipe(&dir, &resource(kind, &format!("{parent}/entry")));

            let r = apply(&p, sudo, t.clone());
            let a = res(&r, "r");
            assert_eq!(a.execution, Execution::Failed, "{case} / {kind}: apply");
            assert_eq!(a.change, Change::None, "{case} / {kind}: apply");
            assert_eq!(mutation_command_count(&r), 0, "{case} / {kind}: apply");
            let reason = a.reason.clone().unwrap();

            let e = plan(&p, sudo, t.clone())
                .err()
                .unwrap_or_else(|| panic!("{case} / {kind}: plan must fail"));
            assert_eq!(e.kind, ErrorKind::Plan, "{case} / {kind}");
            assert_eq!(e.kind.exit_code(), 4);
            assert_eq!(
                e.message,
                format!("r: {reason} {PLAN_SUFFIX}"),
                "{case} / {kind}: plan gives apply's reason"
            );
        }
    }
}

#[test]
fn refusals_name_the_cause_and_what_to_do() {
    let expect = [
        (
            "user-owned parent under --sudo",
            "connect as that user without --sudo",
        ),
        ("world-writable parent", "remove that write access"),
        ("symlink parent", "use the path the symlink resolves to"),
        ("missing parent", "parent directory may be missing"),
    ];
    for (case, sudo, t, parent) in refused_parents() {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &resource("file", &format!("{parent}/entry")));
        let e = plan(&p, sudo, t).err().unwrap();
        let hint = expect.iter().find(|(c, _)| *c == case).unwrap().1;
        assert!(e.message.contains(hint), "{case}: {}", e.message);
    }
}

#[test]
fn removal_and_replacement_are_checked_like_creation() {
    let mut t = target();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/home/moge", 0o750, 1001, 1001);
    fs.mkdir_node("/home/moge/olddir", 0o755, 1001, 1001);
    fs.put_file("/home/moge/old.conf", b"old\n", 0o644, 1001, 1001);
    symlink(&mut t, "/home/moge/oldlink", "/etc/hosts");
    let cases = [
        "  - id: r\n    type: file\n    with:\n      path: /home/moge/old.conf\n      state: absent\n",
        "  - id: r\n    type: file\n    with:\n      path: /home/moge/old.conf\n      content: \"new\\n\"\n",
        "  - id: r\n    type: file\n    with:\n      path: /home/moge/old.conf\n      mode: \"0600\"\n",
        "  - id: r\n    type: directory\n    with:\n      path: /home/moge/olddir\n      state: absent\n",
        "  - id: r\n    type: directory\n    with:\n      path: /home/moge/olddir\n      mode: \"0700\"\n",
        "  - id: r\n    type: link\n    with:\n      path: /home/moge/oldlink\n      state: absent\n",
        "  - id: r\n    type: link\n    with:\n      path: /home/moge/oldlink\n      target: /etc/hostname\n",
    ];
    for body in cases {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, body);
        let r = apply(&p, true, t.clone());
        let reason = res(&r, "r").reason.clone().unwrap();
        assert!(
            reason.contains("/home/moge is owned by uid 1001"),
            "{body}: {reason}"
        );
        let e = plan(&p, true, t.clone()).err().unwrap();
        assert_eq!(e.message, format!("r: {reason} {PLAN_SUFFIX}"), "{body}");
    }
}

#[test]
fn an_earlier_unrelated_change_does_not_hide_a_certain_refusal() {
    let (_, sudo, t, parent) = refused_parents().remove(0);
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "  - id: other\n    type: file\n    with:\n      path: /opt/other.conf\n      content: \"x\\n\"\n{}",
        resource("file", &format!("{parent}/entry"))
    );
    let p = recipe(&dir, &body);
    let e = plan(&p, sudo, t).err().unwrap();
    assert!(
        e.message.starts_with("r: parent path /home/moge"),
        "{}",
        e.message
    );
}

#[test]
fn a_sensitive_resource_is_refused_without_its_details() {
    let (_, sudo, t, parent) = refused_parents().remove(0);
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "  - id: r\n    type: file\n    sensitive: true\n    with:\n      path: {parent}/secret.conf\n      content: \"SECRET-CANARY-2b7d\\n\"\n"
    );
    let p = recipe(&dir, &body);
    let e = plan(&p, sudo, t).err().unwrap();
    assert_eq!(e.kind, ErrorKind::Plan);
    assert!(
        e.message.contains("would refuse this change at apply"),
        "{}",
        e.message
    );
    for leak in ["SECRET-CANARY", "1001", "/home/moge"] {
        assert!(!e.message.contains(leak), "{leak} in {}", e.message);
    }
}

// ---------------------------------------------------------------------------
// When an earlier change may alter the parent, apply decides.
// ---------------------------------------------------------------------------

#[test]
fn a_parent_this_run_creates_is_deferred_and_apply_then_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let body = "  - id: d\n    type: directory\n    with:\n      path: /srv/app\n\
                \x20 - id: f\n    type: file\n    depends_on: [d]\n    with:\n      path: /srv/app/app.conf\n      content: \"x\\n\"\n\
                \x20 - id: l\n    type: link\n    depends_on: [d]\n    with:\n      path: /srv/app/current\n      target: /srv/app/app.conf\n";
    let p = recipe(&dir, body);

    let r = plan(&p, true, target()).unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(mutation_command_count(&r), 0, "plan never mutates");
    assert!(res(&r, "d").notes.is_empty(), "/srv passes the check");
    for id in ["f", "l"] {
        let x = res(&r, id);
        assert_eq!(x.change, Change::Changed, "{id}");
        assert!(
            x.notes
                .iter()
                .any(|n| n.starts_with(DEFERRED) && n.contains("d changes /srv/app earlier")),
            "{id}: {:?}",
            x.notes
        );
    }

    let a = apply(&p, true, target());
    assert_eq!(a.status, AggregateStatus::Success);
}

#[test]
fn a_package_or_command_planned_earlier_defers_the_check() {
    let dir = tempfile::tempdir().unwrap();
    // nginx is not installed on the scripted target, so it is a planned
    // change, and plan cannot know which directories its installation makes.
    let body = "  - id: nginx\n    type: package\n    with:\n      name: nginx\n      state: present\n\
                \x20 - id: conf\n    type: file\n    depends_on: [nginx]\n    with:\n      path: /etc/nginx/conf.d/app.conf\n      content: \"x\\n\"\n";
    let p = recipe(&dir, body);
    let r = plan(&p, true, target()).unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(mutation_command_count(&r), 0, "plan never mutates");
    let c = res(&r, "conf");
    assert_eq!(c.change, Change::Changed);
    assert!(
        c.notes
            .iter()
            .any(|n| n.starts_with(DEFERRED) && n.contains("nginx runs earlier")),
        "{:?}",
        c.notes
    );

    // A command is never run by plan, so its effect is unknown as well (with
    // depends_on the file is already unknown through the dependency).
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "  - id: prep\n    type: command\n    with:\n      program: /bin/true\n\
         \x20 - id: conf\n    type: file\n    with:\n      path: /etc/nginx/conf.d/app.conf\n      content: \"x\\n\"\n",
    );
    let r = plan(&p, true, target().with_executable("/bin/true")).unwrap();
    let c = res(&r, "conf");
    assert!(
        c.notes
            .iter()
            .any(|n| n.starts_with(DEFERRED) && n.contains("prep runs earlier")),
        "{:?}",
        c.notes
    );

    // With nothing planned to change before it, the missing parent is certain.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "  - id: conf\n    type: file\n    with:\n      path: /etc/nginx/conf.d/app.conf\n      content: \"x\\n\"\n",
    );
    let e = plan(&p, true, target()).err().unwrap();
    assert!(e.message.starts_with("conf: "), "{}", e.message);
}

// ---------------------------------------------------------------------------
// Ordinary safe paths plan and apply as before.
// ---------------------------------------------------------------------------

#[test]
fn safe_paths_plan_without_notes_and_apply_succeeds() {
    for (sudo, parent) in [
        (true, "/srv"),
        (true, "/opt"),
        (true, "/etc/app"),
        (false, "/home/ubuntu"),
    ] {
        let mut t = target();
        if parent == "/home/ubuntu" {
            // The connecting user's own home, without --sudo.
            t.fs.as_mut()
                .unwrap()
                .mkdir_node("/home/ubuntu", 0o750, 1000, 1000);
        }
        for kind in KINDS {
            let dir = tempfile::tempdir().unwrap();
            let p = recipe(&dir, &resource(kind, &format!("{parent}/entry")));
            let r = plan(&p, sudo, t.clone())
                .unwrap_or_else(|e| panic!("{parent} {kind}: {}", e.message));
            let x = res(&r, "r");
            assert_eq!(x.change, Change::Changed, "{parent} {kind}");
            assert!(x.notes.is_empty(), "{parent} {kind}: {:?}", x.notes);
            assert_eq!(
                mutation_command_count(&r),
                0,
                "{parent} {kind}: plan never mutates"
            );

            let a = apply(&p, sudo, t.clone());
            assert_eq!(a.status, AggregateStatus::Success, "{parent} {kind}");
        }
    }
}

// ---------------------------------------------------------------------------
// Removing a directory that is not empty (apply removes only empty ones).
// ---------------------------------------------------------------------------

fn dir_absent(id: &str, path: &str) -> String {
    format!(
        "  - id: {id}\n    type: directory\n    with:\n      path: {path}\n      state: absent\n"
    )
}

#[test]
fn removing_a_directory_that_is_not_empty_fails_at_plan_like_apply() {
    let mut t = target();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/srv/old", 0o755, 0, 0);
    fs.put_file("/srv/old/data.db", b"x", 0o644, 0, 0);
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &dir_absent("r", "/srv/old"));

    let a = apply(&p, true, t.clone());
    let x = res(&a, "r");
    assert_eq!(x.execution, Execution::Failed);
    assert_eq!(x.change, Change::None);
    let reason = x.reason.clone().unwrap();
    assert!(
        reason.contains("directory /srv/old is not empty"),
        "{reason}"
    );

    let e = plan(&p, true, t).err().expect("plan must fail");
    assert_eq!(e.kind, ErrorKind::Plan);
    assert_eq!(
        e.message,
        "r: directory /srv/old is not empty; Sinter removes only empty directories \
         (remove its entries first) (plan: apply would fail to remove it)"
    );
}

#[test]
fn an_empty_directory_is_removed_as_before() {
    let mut t = target();
    t.fs.as_mut().unwrap().mkdir_node("/srv/old", 0o755, 0, 0);
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &dir_absent("r", "/srv/old"));
    let r = plan(&p, true, t.clone()).unwrap();
    assert_eq!(res(&r, "r").change, Change::Changed);
    assert!(res(&r, "r").notes.is_empty());
    assert_eq!(mutation_command_count(&r), 0, "plan never mutates");
    assert_eq!(apply(&p, true, t).status, AggregateStatus::Success);
}

#[test]
fn entries_removed_earlier_in_the_run_defer_the_emptiness_check() {
    let mut t = target();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/srv/old", 0o755, 0, 0);
    fs.put_file("/srv/old/app.conf", b"x", 0o644, 0, 0);
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "  - id: f\n    type: file\n    with:\n      path: /srv/old/app.conf\n      state: absent\n{}    depends_on: [f]\n",
        dir_absent("d", "/srv/old")
    );
    let p = recipe(&dir, &body);
    let r = plan(&p, true, t.clone()).unwrap();
    let d = res(&r, "d");
    assert_eq!(d.change, Change::Changed);
    assert!(
        d.notes
            .iter()
            .any(|n| n.contains("is not empty now")
                && n.contains("f changes /srv/old/app.conf earlier")),
        "{:?}",
        d.notes
    );
    assert_eq!(apply(&p, true, t).status, AggregateStatus::Success);
}

// ---------------------------------------------------------------------------
// Replacing a file whose security metadata apply cannot preserve or inspect.
// ---------------------------------------------------------------------------

#[test]
fn an_uninspectable_replaced_file_fails_at_plan_like_apply() {
    let mut t = target();
    t.fs.as_mut()
        .unwrap()
        .put_file("/srv/app.conf", b"old\n", 0o644, 0, 0);
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &resource("file", "/srv/app.conf"));
    let fault = Some("uninspectable_metadata");

    let a = engine_fault(&p, Mode::Apply, true, t.clone(), fault)
        .run()
        .unwrap();
    let x = res(&a, "r");
    assert_eq!(x.execution, Execution::Failed);
    assert_eq!(x.change, Change::None);
    assert_eq!(mutation_command_count(&a), 0);
    let reason = x.reason.clone().unwrap();
    assert!(
        reason.starts_with("r: cannot inspect security metadata of /srv/app.conf"),
        "{reason}"
    );

    let e = engine_fault(&p, Mode::Plan, true, t.clone(), fault)
        .run()
        .err()
        .expect("plan must fail");
    assert_eq!(
        e.message,
        format!(
            "{reason} (plan: Sinter's security metadata check would refuse this change at apply)"
        )
    );

    // A new file replaces nothing: unaffected.
    let p = recipe(&dir, &resource("file", "/srv/new.conf"));
    let r = engine_fault(&p, Mode::Plan, true, t, fault).run().unwrap();
    assert!(res(&r, "r").notes.is_empty());
}

#[test]
fn an_earlier_change_defers_the_metadata_check_and_keeps_the_diff() {
    let mut t = target().with_executable("/bin/true");
    t.fs.as_mut()
        .unwrap()
        .put_file("/srv/app.conf", b"old\n", 0o644, 0, 0);
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "  - id: prep\n    type: command\n    with:\n      program: /bin/true\n{}",
        resource("file", "/srv/app.conf")
    );
    let p = recipe(&dir, &body);
    let r = engine_fault(&p, Mode::Plan, true, t, Some("uninspectable_metadata"))
        .run()
        .unwrap();
    let x = res(&r, "r");
    assert_eq!(x.change, Change::Changed);
    assert!(
        x.notes.iter().any(
            |n| n.starts_with("security metadata check deferred to apply")
                && n.contains("prep runs earlier")
        ),
        "{:?}",
        x.notes
    );
    assert!(
        matches!(x.diff.as_ref().unwrap().body, DiffBody::Text { .. }),
        "the content diff is still shown"
    );
}

// ---------------------------------------------------------------------------
// Which earlier resources defer a later refusal, and which do not.
//
// The soundness rule: when plan reports a refusal as certain (a plan error),
// apply must refuse the same resource for the same reason. When an earlier
// resource could change the outcome, plan must not claim a failure.
// ---------------------------------------------------------------------------

/// `later` refuses on its own: its parent `/home/moge` is owned by another
/// user under `--sudo`.
const LATER: &str = "  - id: later\n    type: file\n    with:\n      path: /home/moge/app.conf\n      content: \"x\\n\"\n";

fn refused_home_target() -> FakeTarget {
    let mut t = target().with_executable("/bin/true");
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/home/moge", 0o750, 1001, 1001);
    t
}

fn file_res_at(id: &str, path: &str) -> String {
    format!(
        "  - id: {id}\n    type: file\n    with:\n      path: {path}\n      content: \"y\\n\"\n"
    )
}

fn dir_res_at(id: &str, path: &str) -> String {
    format!("  - id: {id}\n    type: directory\n    with:\n      path: {path}\n")
}

/// `Ok(note)` when plan keeps `later` as a change (with the deferral note if
/// any); `Err(message)` when plan reports it as a certain failure.
fn plan_of_later(earlier: &str, t: FakeTarget) -> Result<Vec<String>, String> {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &format!("{earlier}{LATER}"));
    match plan(&p, true, t) {
        Ok(r) => Ok(res(&r, "later").notes.clone()),
        Err(e) => Err(e.message),
    }
}

#[test]
fn only_an_earlier_change_that_can_affect_the_path_defers() {
    // (label, earlier resources, deferred?)
    let cases: Vec<(&str, String, bool)> = vec![
        ("unrelated file", file_res_at("e", "/srv/other.conf"), false),
        ("unrelated directory", dir_res_at("e", "/srv/other"), false),
        ("sibling of the parent", file_res_at("e", "/home/other.conf"), false),
        (
            "a link at an unrelated path",
            "  - id: e\n    type: link\n    with:\n      path: /srv/lnk\n      target: /srv\n".to_string(),
            false,
        ),
        (
            "a template at an unrelated path",
            "  - id: e\n    type: template\n    with:\n      path: /srv/t.conf\n      source: t.tmpl\n".to_string(),
            false,
        ),
        (
            "a package that changes",
            "  - id: e\n    type: package\n    with:\n      name: nginx\n      state: present\n".to_string(),
            true,
        ),
        (
            "a command (never run by plan)",
            "  - id: e\n    type: command\n    with:\n      program: /bin/true\n".to_string(),
            true,
        ),
        (
            "a user that changes",
            "  - id: e\n    type: user\n    with:\n      name: newsvc\n".to_string(),
            true,
        ),
        // Not planned to change, or not planned to run.
        (
            "a package already installed",
            "  - id: e\n    type: package\n    with:\n      name: nginx\n      state: absent\n".to_string(),
            false,
        ),
        (
            "a command skipped by its condition",
            "  - id: e\n    type: command\n    when: \"false\"\n    with:\n      program: /bin/true\n".to_string(),
            false,
        ),
        // A group changes /etc/group only: no path, no ownership of any path,
        // and no input of the parent path check, which reads owner, mode and
        // access metadata of the ancestors and never a group name.
        (
            "a group that changes",
            "  - id: e\n    type: group\n    with:\n      name: newgrp\n".to_string(),
            false,
        ),
    ];
    for (label, earlier, deferred) in cases {
        let r = plan_of_later(&earlier, refused_home_target());
        let r2 = r.clone();
        if deferred {
            let notes = r.unwrap_or_else(|m| panic!("{label}: must defer, got error {m}"));
            assert!(
                notes.iter().any(|n| n.starts_with(DEFERRED)),
                "{label}: {notes:?}"
            );
        } else {
            let m = r2
                .err()
                .unwrap_or_else(|| panic!("{label}: must be certain"));
            assert!(
                m.starts_with("later: parent path /home/moge is owned by uid 1001"),
                "{label}: {m}"
            );
            // Soundness: apply refuses the same resource for the same reason.
            let dir = tempfile::tempdir().unwrap();
            let p = recipe(&dir, &format!("{earlier}{LATER}"));
            let a = engine(&p, Mode::Apply, true, refused_home_target())
                .run()
                .unwrap();
            let x = res(&a, "later");
            assert_eq!(x.execution, Execution::Failed, "{label}: apply");
            assert!(
                m.starts_with(&format!("later: {}", x.reason.clone().unwrap())),
                "{label}: plan {m} / apply {:?}",
                x.reason
            );
        }
    }
}

#[test]
fn a_package_already_present_is_not_a_planned_change() {
    // Sanity for the "already installed" row above.
    let t = refused_home_target().with_package("nginx");
    let r = plan_of_later(
        "  - id: e\n    type: package\n    with:\n      name: nginx\n      state: present\n",
        t,
    );
    assert!(r.is_err(), "{r:?}");
}

#[test]
fn a_command_guard_that_an_earlier_change_flips_does_not_hide_its_effect() {
    // `rm` removes the guard file, so apply runs `mk` (the guard no longer
    // holds), which creates /srv/app; `conf` then succeeds. Plan sees the
    // guard file present now and reports `mk` as already satisfied, so
    // /srv/app looks missing: that refusal is not certain.
    let mut t = target().with_executable("/bin/mkdir");
    t.fs.as_mut()
        .unwrap()
        .put_file("/srv/guard", b"g", 0o644, 0, 0);
    let body = "  - id: rm\n    type: file\n    with:\n      path: /srv/guard\n      state: absent\n\
                \x20 - id: mk\n    type: command\n    depends_on: [rm]\n    with:\n      creates: /srv/guard\n      program: /bin/mkdir\n      args: [\"--\", \"/srv/app\"]\n\
                \x20 - id: conf\n    type: file\n    depends_on: [mk]\n    with:\n      path: /srv/app/app.conf\n      content: \"x\\n\"\n";
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, body);
    let planned = plan(&p, true, t.clone()).unwrap_or_else(|e| panic!("plan: {}", e.message));
    assert!(
        res(&planned, "conf")
            .notes
            .iter()
            .any(|n| n.starts_with(DEFERRED)),
        "{:?}",
        res(&planned, "conf").notes
    );
    let applied = apply(&p, true, t);
    assert_eq!(applied.status, AggregateStatus::Success);
}

#[test]
fn a_command_guard_nothing_flips_stays_satisfied_and_defers_nothing() {
    let mut t = target().with_executable("/bin/mkdir");
    t.fs.as_mut()
        .unwrap()
        .put_file("/srv/guard", b"g", 0o644, 0, 0);
    let body = "  - id: mk\n    type: command\n    with:\n      creates: /srv/guard\n      program: /bin/mkdir\n      args: [\"--\", \"/srv/app\"]\n\
                \x20 - id: conf\n    type: file\n    with:\n      path: /srv/app/app.conf\n      content: \"x\\n\"\n";
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, body);
    let e = plan(&p, true, t.clone())
        .err()
        .expect("certain: nothing creates /srv/app");
    assert!(e.message.starts_with("conf: "), "{}", e.message);
    let a = apply(&p, true, t);
    assert_eq!(res(&a, "conf").execution, Execution::Failed);
}

/// H1 (Linux acceptance, Ubuntu 24.04): a `creates` guard spelled through a
/// symlinked ancestor is observed by `stat` through the symlink, while the
/// earlier change names the resolved spelling. The scripted filesystem is a
/// flat path map that cannot resolve an intermediate symlink, so a fake node
/// at the guard path stands in for what the real `stat` sees at plan time;
/// the apply half is the real-host H1 scenario of the Linux acceptance.
#[test]
fn a_guard_seen_through_a_symlinked_ancestor_may_be_flipped_by_any_earlier_change() {
    let body = "  - id: rm
    type: file
    with:
      path: /srv/real/c
      state: absent
\
                \x20 - id: mk
    type: command
    depends_on: [rm]
    with:
      creates: /srv/alias/c
      program: /bin/mkdir
      args: [\"--\", \"/srv/app\"]
\
                \x20 - id: conf
    type: file
    depends_on: [mk]
    with:
      path: /srv/app/app.conf
      content: \"x\\n\"
";
    let build = |alias_is_symlink: bool| {
        let mut t = target().with_executable("/bin/mkdir");
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/srv/real", 0o755, 0, 0);
        fs.put_file("/srv/real/c", b"c", 0o644, 0, 0);
        if alias_is_symlink {
            fs.nodes.insert(
                "/srv/alias".to_string(),
                FakeNode {
                    kind: FakeKind::Symlink("/srv/real".to_string()),
                    mode: 0o777,
                    uid: 0,
                    gid: 0,
                    ino: 9100,
                    mtime: 5,
                    ctime: 5,
                },
            );
        } else {
            fs.mkdir_node("/srv/alias", 0o755, 0, 0);
        }
        // What `stat -- /srv/alias/c` observes at plan time.
        fs.put_file("/srv/alias/c", b"c", 0o644, 0, 0);
        t
    };
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, body);

    // Alias: the lexical comparison cannot tell, so the command may run.
    let r = plan(&p, true, build(true)).unwrap_or_else(|e| panic!("must defer: {}", e.message));
    assert!(
        res(&r, "conf")
            .notes
            .iter()
            .any(|n| n.starts_with(DEFERRED) && n.contains("mk runs earlier")),
        "{:?}",
        res(&r, "conf").notes
    );
    assert_eq!(mutation_command_count(&r), 0, "plan never mutates");

    // The same recipe with a plain directory at /srv/alias: /srv/real/c is a
    // different object, nothing flips the guard, the refusal is certain.
    let e = plan(&p, true, build(false))
        .err()
        .expect("certain: no alias, nothing creates /srv/app");
    assert!(e.message.starts_with("conf: "), "{}", e.message);
    assert!(e.message.ends_with(PLAN_SUFFIX), "{}", e.message);
}

#[test]
fn an_earlier_change_at_a_missing_parent_defers_and_an_unrelated_one_does_not() {
    let later = "  - id: later\n    type: file\n    with:\n      path: /srv/new/app.conf\n      content: \"x\\n\"\n";
    let deferred = [
        ("a directory", dir_res_at("e", "/srv/new")),
        (
            "a link",
            "  - id: e\n    type: link\n    with:\n      path: /srv/new\n      target: /srv\n"
                .to_string(),
        ),
        (
            "a link above it",
            "  - id: e\n    type: link\n    with:\n      path: /srv/new\n      target: /opt\n"
                .to_string(),
        ),
    ];
    for (label, earlier) in deferred {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &format!("{earlier}{later}"));
        let r = plan(&p, true, target()).unwrap_or_else(|e| panic!("{label}: {}", e.message));
        assert!(
            res(&r, "later")
                .notes
                .iter()
                .any(|n| n.starts_with(DEFERRED)),
            "{label}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        &format!("{}{later}", dir_res_at("e", "/srv/elsewhere")),
    );
    let e = plan(&p, true, target()).err().expect("certain");
    assert!(e.message.starts_with("later: "), "{}", e.message);
    // The link variant is refused by apply (a symlink parent), so deferring
    // is the right call: plan cannot claim either outcome.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &format!("{}{later}", dir_res_at("e", "/srv/new")));
    assert_eq!(apply(&p, true, target()).status, AggregateStatus::Success);
}

#[test]
fn a_path_that_only_shares_a_name_prefix_is_not_an_ancestor_or_a_descendant() {
    // /srv/new is not an ancestor of /srv/newer/app.conf.
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "{}  - id: later\n    type: file\n    with:\n      path: /srv/newer/app.conf\n      content: \"x\\n\"\n",
        dir_res_at("e", "/srv/new")
    );
    let p = recipe(&dir, &body);
    let e = plan(&p, true, target()).err().expect("certain");
    assert!(e.message.starts_with("later: "), "{}", e.message);

    // /srv/old2/x is not below /srv/old: its removal does not make /srv/old empty.
    let mut t = target();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/srv/old", 0o755, 0, 0);
    fs.put_file("/srv/old/data", b"x", 0o644, 0, 0);
    fs.mkdir_node("/srv/old2", 0o755, 0, 0);
    fs.put_file("/srv/old2/x", b"x", 0o644, 0, 0);
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "  - id: f\n    type: file\n    with:\n      path: /srv/old2/x\n      state: absent\n{}",
        dir_absent("r", "/srv/old")
    );
    let p = recipe(&dir, &body);
    let e = plan(&p, true, t).err().expect("certain");
    assert!(e.message.contains("is not empty"), "{}", e.message);
}
