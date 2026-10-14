//! FS-2 I4/I5: how the product uses the fixed staging script.
//!
//! Staging, publication and cleanup of a file or a link are calls of one
//! constant shell script (`src/fsstage.sh`), one process per step. These tests
//! pin the contract on the Rust side, against the scripted target (whose model
//! of the script is itself pinned in `fs2_shared_directory.rs`): the script is a
//! constant and values reach it only as arguments; a refusal is reported before
//! anything is written; the publication result and the cleanup result are kept
//! apart; nothing is removed that the script did not prove to be its own.
//!
//! That the script really does this on a Linux host is proven there, not here
//! (see the I4/I5 reports and `docs/fs2-i4-i5-*-evidence`).
#![cfg(unix)]

use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::executor::{CommandRecord, Completion, FakeTarget, FsEventAction, Output};
use sinter::fakesys::{FakeFs, FakeKind};
use sinter::model::load_model;
use sinter::output::{render_apply, OutputFormat, RenderOptions};
use sinter::result::{Change, Execution, ResourceResult};
use std::path::PathBuf;

const ALICE: u32 = 1001;

fn base() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("alice", ALICE)
        .with_user("alice", ALICE, ALICE, "/home/alice", "/bin/bash")
        .as_root();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/tmp", 0o1777, 0),
        ("/var", 0o755, 0),
        ("/var/tmp", 0o1777, 0),
        ("/sg", 0o2755, 0),
        ("/etc/app", 0o755, 0),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    t
}

fn recipe(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\nresources:\n{}", body)).unwrap();
    p
}

fn file_body(path: &str) -> String {
    format!("  - id: f\n    type: file\n    with:\n      path: {path}\n      content: \"x\\n\"\n")
}

fn apply(body: &str, t: FakeTarget) -> RunReport {
    apply_fault(body, t, None)
}

fn apply_fault(body: &str, t: FakeTarget, fault: Option<&str>) -> RunReport {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, body);
    Engine::new(
        load_model(&p).unwrap(),
        RunOptions {
            mode: Mode::Apply,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: true,
            fault: fault.map(|f| f.to_string()),
            fake_target: Some(t),
        },
    )
    .unwrap()
    .run()
    .unwrap()
}

fn res<'a>(r: &'a RunReport, id: &str) -> &'a ResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

fn fs_of(r: &RunReport) -> &FakeFs {
    r.fake_fs.as_ref().expect("scripted filesystem")
}

/// The script steps of a run: operation and the arguments after it.
fn steps(cmds: &[CommandRecord]) -> Vec<(String, Vec<String>)> {
    cmds.iter()
        .filter(|c| c.program == "/bin/sh" && c.args.len() >= 4 && c.args[0] == "-c")
        .map(|c| (c.args[3].clone(), c.args[4..].to_vec()))
        .collect()
}

fn count_ops(cmds: &[CommandRecord], op: &str) -> usize {
    steps(cmds).iter().filter(|(o, _)| o == op).count()
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

const STAGED: &str = ".sinter-stage.AbCd1234 3000000001 2049:50 2049:51\n";

// ---------------------------------------------------------------------------
// the script is a constant; values are arguments
// ---------------------------------------------------------------------------

#[test]
fn every_step_runs_the_constant_script_and_values_are_only_arguments() {
    // Shell syntax in the path and in the content never reaches the script text.
    let path = "/tmp/a b;$(touch pwned)`x`|\"q\"&>z.conf";
    let body = format!(
        "  - id: f\n    type: file\n    with:\n      path: '{path}'\n      content: \"$(touch pwned2)\\n`id`\\n\"\n"
    );
    let r = apply(&body, base());
    assert_eq!(
        r.status,
        AggregateStatus::Success,
        "{:?}",
        res(&r, "f").reason
    );
    assert_eq!(
        fs_of(&r).nodes[path].kind,
        FakeKind::File(b"$(touch pwned2)\n`id`\n".to_vec())
    );
    let sh: Vec<&CommandRecord> = r
        .commands
        .iter()
        .filter(|c| c.program == "/bin/sh")
        .collect();
    assert_eq!(sh.len(), 2, "stage, publish");
    let digest = format!("[fsstage.sh sha256:{}]", sinter::fsstage::SCRIPT_SHA256);
    for c in &sh {
        assert_eq!(c.args[0], "-c");
        assert_eq!(
            c.args[1], digest,
            "the constant script, named by its digest"
        );
        assert_eq!(c.args[2], "sh");
        assert!(!c.sudo && !c.sensitive);
    }
    let st = steps(&r.commands);
    assert_eq!(st[0].0, "stage");
    assert_eq!(st[0].1[0], "/tmp", "the directory is its own argument");
    assert_eq!(st[1].0, "publish");
    assert_eq!(
        st[1].1.last().map(String::as_str),
        Some("a b;$(touch pwned)`x`|\"q\"&>z.conf"),
        "the final name is its own argument"
    );
    // Nothing the values spell out happened.
    assert!(!fs_of(&r).nodes.contains_key("/tmp/pwned"));
    assert!(!fs_of(&r).nodes.contains_key("pwned"));
    // The old path-based staging commands are not issued at all.
    for prog in [
        "mktemp", "dd", "mv", "ln", "rm", "rmdir", "find", "chown", "chmod",
    ] {
        assert!(
            r.commands
                .iter()
                .all(|c| !c.program.ends_with(&format!("/{prog}"))),
            "{prog} must not be issued by the staging"
        );
    }
}

#[test]
fn a_leading_dash_and_an_odd_name_publish_exactly() {
    for name in ["-rf.conf", "--version", " lead.conf", "a\tb.conf"] {
        let path = format!("/tmp/{name}");
        let body = format!(
            "  - id: f\n    type: file\n    with:\n      path: {}\n      content: \"x\\n\"\n",
            serde_json::to_string(&path).unwrap()
        );
        let r = apply(&body, base());
        assert_eq!(
            r.status,
            AggregateStatus::Success,
            "{name:?}: {:?}",
            res(&r, "f").reason
        );
        assert!(fs_of(&r).nodes.contains_key(&path), "{name:?}");
    }
}

#[test]
fn content_never_appears_in_any_command_and_a_link_target_is_redacted() {
    let canary = "CANARY-CONTENT-7f3a";
    let body = format!(
        "  - id: f\n    type: file\n    with:\n      path: /tmp/c.conf\n      content: \"{canary}\\n\"\n  - id: l\n    type: link\n    sensitive: true\n    with:\n      path: /tmp/lnk\n      target: /etc/TOPSECRET-TARGET\n"
    );
    // The link already exists, so it is replaced through staging.
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_symlink("/tmp/lnk", "/etc/one", 0, 0);
    let r = apply(&body, t);
    assert_eq!(r.status, AggregateStatus::Success, "{:?}", r.resources);
    let shown = format!("{:?}", r.commands);
    assert!(!shown.contains(canary), "content must travel on stdin only");
    assert!(
        !shown.contains("TOPSECRET-TARGET"),
        "the link target is redacted"
    );
    // A sensitive link's steps (stagelink, publish) are recorded as redacted,
    // never as arguments.
    assert_eq!(r.commands.iter().filter(|c| c.sensitive).count(), 2);
}

// ---------------------------------------------------------------------------
// refusals: before anything is written, and only for this staging
// ---------------------------------------------------------------------------

#[test]
fn a_setgid_directory_refuses_staged_publication_and_nothing_else() {
    let r = apply(&file_body("/sg/f.conf"), base());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let x = res(&r, "f");
    assert_eq!((x.execution, x.change), (Execution::Failed, Change::None));
    let reason = x.reason.clone().unwrap_or_default();
    assert!(reason.contains("setgid"), "{reason}");
    assert_eq!(count_ops(&r.commands, "stage"), 1, "one attempt");
    assert_eq!(count_ops(&r.commands, "publish"), 0);
    assert!(
        !fs_of(&r).nodes.keys().any(|k| k.starts_with("/sg/")),
        "nothing was created in the directory"
    );

    // The rule is the staging's, not a ban on setgid directories: a directory,
    // a link and a metadata-only change there are managed as before.
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/sg/old.conf", b"x\n", 0o600, 0, 0);
    let body = "  - id: d\n    type: directory\n    with:\n      path: /sg/sub\n  - id: l\n    type: link\n    with:\n      path: /sg/lnk\n      target: /etc/one\n  - id: m\n    type: file\n    with:\n      path: /sg/old.conf\n      content: \"x\\n\"\n      mode: \"0644\"\n";
    let r = apply(body, t);
    assert_eq!(r.status, AggregateStatus::Success, "{:?}", r.resources);
    let fs = fs_of(&r);
    assert_eq!(fs.nodes["/sg/sub"].kind, FakeKind::Dir);
    assert_eq!(
        fs.nodes["/sg/lnk"].kind,
        FakeKind::Symlink("/etc/one".into())
    );
    assert_eq!(fs.nodes["/sg/old.conf"].mode & 0o7777, 0o644);
    assert_eq!(count_ops(&r.commands, "stage"), 0, "no staging was needed");
}

#[test]
fn root_without_setpriv_fails_closed_and_writes_nothing() {
    let mut t = base();
    t.fs.as_mut().unwrap().setpriv_missing = true;
    let r = apply(&file_body("/etc/app/a.conf"), t);
    let x = res(&r, "f");
    assert_eq!((x.execution, x.change), (Execution::Failed, Change::None));
    assert!(
        x.reason.clone().unwrap_or_default().contains("setpriv"),
        "{:?}",
        x.reason
    );
    assert!(!fs_of(&r).nodes.contains_key("/etc/app/a.conf"));
    no_staging_left(fs_of(&r));
}

#[test]
fn a_parent_that_stopped_being_safe_before_staging_is_refused_for_a_plain_user() {
    // A plain user, in a directory of their own. Between the walk and the
    // staging the directory is handed to another account: the script refuses.
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("alice", ALICE)
        .with_user("alice", ALICE, ALICE, "/home/alice", "/bin/bash");
    t.fs.as_mut().unwrap().mkdir_node("/home", 0o755, 0, 0);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/home/u", 0o755, 1000, 1000);
    let ok = apply(&file_body("/home/u/a.conf"), t.clone());
    assert_eq!(
        ok.status,
        AggregateStatus::Success,
        "{:?}",
        res(&ok, "f").reason
    );
    let st = steps(&ok.commands);
    assert_eq!(st[0].1[2..4], ["0644".to_string(), "1000".to_string()]);
    // The identity of a plain user is the directory itself: no group is given.
    assert_eq!(st[1].1[5], "-", "{:?}", st[1].1);

    let t = t.with_fs_event(
        "sh",
        "stage",
        0,
        vec![
            FsEventAction::Chown {
                path: "/home/u".into(),
                uid: ALICE,
                gid: ALICE,
            },
            FsEventAction::Chown {
                path: "/home/u".into(),
                uid: ALICE,
                gid: ALICE,
            },
        ],
    );
    let r = apply(&file_body("/home/u/a.conf"), t);
    let x = res(&r, "f");
    assert_eq!((x.execution, x.change), (Execution::Failed, Change::None));
    assert!(
        x.reason
            .clone()
            .unwrap_or_default()
            .contains("could be changed by others"),
        "{:?}",
        x.reason
    );
    assert!(!fs_of(&r).nodes.keys().any(|k| k.contains(".sinter-stage.")));
}

fn no_staging_left(fs: &FakeFs) {
    let left: Vec<_> = fs
        .nodes
        .keys()
        .filter(|k| k.contains(".sinter-stage."))
        .collect();
    assert!(left.is_empty(), "staging left behind: {left:?}");
}

// ---------------------------------------------------------------------------
// the publication result and the cleanup result are kept apart
// ---------------------------------------------------------------------------

fn published(r: &RunReport) {
    let x = res(r, "f");
    assert_eq!(x.change, Change::Changed, "the file is published: {x:?}");
    assert_eq!(
        fs_of(r).nodes["/tmp/example.conf"].kind,
        FakeKind::File(b"x\n".to_vec())
    );
}

#[test]
fn a_clean_cleanup_is_an_ordinary_success() {
    let r = apply(&file_body("/tmp/example.conf"), base());
    assert_eq!(r.status, AggregateStatus::Success);
    published(&r);
    assert!(res(&r, "f").notes.is_empty(), "{:?}", res(&r, "f").notes);
    no_staging_left(fs_of(&r));
}

#[test]
fn an_empty_staging_directory_left_in_place_does_not_undo_the_publication() {
    // At the moment of the cleanup the directory is no longer one nobody else
    // can rename entries in: the script publishes, leaves the empty staging
    // directory and says where. The publication stands; the path is reported.
    let t = base().with_fs_event(
        "sh",
        "publish",
        0,
        vec![FsEventAction::Chown {
            path: "/tmp".into(),
            uid: ALICE,
            gid: ALICE,
        }],
    );
    let r = apply(&file_body("/tmp/example.conf"), t);
    assert_eq!(r.status, AggregateStatus::Success, "{:?}", res(&r, "f"));
    published(&r);
    let x = res(&r, "f");
    assert_eq!(x.execution, Execution::Succeeded);
    let note = x.notes.join(" | ");
    assert!(
        note.contains("left in place") && note.contains("/tmp/.sinter-stage."),
        "{note}"
    );
    // Left alone: not removed by Sinter, not removed by a later sweep.
    let stray: Vec<_> = fs_of(&r)
        .nodes
        .keys()
        .filter(|k| k.contains(".sinter-stage."))
        .collect();
    assert_eq!(stray.len(), 1, "{stray:?}");
    assert_eq!(count_ops(&r.commands, "discard"), 0, "no second attempt");
}

#[test]
fn a_second_name_left_behind_is_a_failure_that_needs_attention_after_a_publication() {
    let mut t = base();
    t.fs.as_mut().unwrap().payload_undeletable = true;
    let r = apply(&file_body("/tmp/example.conf"), t);
    let x = res(&r, "f");
    published(&r);
    assert_eq!(x.execution, Execution::Failed);
    let reason = x.reason.clone().unwrap_or_default();
    assert!(
        reason.contains("published successfully") && reason.contains("second name"),
        "{reason}"
    );
    assert!(
        reason.contains("/tmp/.sinter-stage."),
        "the path is reported: {reason}"
    );
    // The staging directory is never removed again behind the report's back.
    assert_eq!(count_ops(&r.commands, "discard"), 0);
    assert_eq!(count_ops(&r.commands, "publish"), 1);
}

#[test]
fn an_unknown_cleanup_state_is_a_failure_that_needs_attention_after_a_publication() {
    let mut t = base();
    t.fs.as_mut().unwrap().cleanup_unknown = true;
    let r = apply(&file_body("/tmp/example.conf"), t);
    let x = res(&r, "f");
    published(&r);
    assert_eq!(x.execution, Execution::Failed);
    let reason = x.reason.clone().unwrap_or_default();
    assert!(reason.contains("could not be determined"), "{reason}");
    assert_eq!(count_ops(&r.commands, "discard"), 0);
}

#[test]
fn answers_the_script_cannot_have_given_are_never_taken_for_a_clean_cleanup() {
    // (exit code, stdout of the publish step) -> published, but needs attention
    for (what, code, stdout) in [
        ("no cleanup line", 0, ""),
        (
            "a cleanup line that contradicts the exit code",
            5,
            "CLEANUP:clean\n",
        ),
        (
            "a clean line with exit 5 and noise",
            5,
            "x\nCLEANUP:left:/tmp/.sinter-stage.AbCd1234\n",
        ),
        (
            "a left line with a relative path",
            0,
            "CLEANUP:left:relative\n",
        ),
        ("a damaged line", 0, "CLEANUP:cleaned\n"),
    ] {
        let t =
            base().with_observations("sh", vec![exited(0, STAGED, ""), exited(code, stdout, "")]);
        let r = apply(&file_body("/tmp/example.conf"), t);
        let x = res(&r, "f");
        assert_eq!(x.change, Change::Changed, "{what}: published");
        assert_eq!(x.execution, Execution::Failed, "{what}: {x:?}");
        assert!(
            x.reason
                .clone()
                .unwrap_or_default()
                .contains("could not be determined"),
            "{what}: {:?}",
            x.reason
        );
    }
}

#[test]
fn a_refused_or_failed_publication_is_not_a_publication() {
    // exit 4: the exclusive link or the rename failed; the cleanup line says what
    // became of the staging.
    let t = base().with_observations(
        "sh",
        vec![
            exited(0, STAGED, ""),
            exited(
                4,
                "CLEANUP:clean\n",
                "ln: failed to create hard link: File exists\n",
            ),
        ],
    );
    let r = apply(&file_body("/tmp/example.conf"), t);
    let x = res(&r, "f");
    assert_eq!(
        (x.execution, x.change),
        (Execution::Failed, Change::None),
        "{x:?}"
    );
    assert!(x
        .reason
        .clone()
        .unwrap_or_default()
        .contains("staging cleanup succeeded"));

    // exit 3: the script could not prove the staging directory; nothing was
    // published, and the directory is left as it is.
    let t = base().with_observations(
        "sh",
        vec![
            exited(0, STAGED, ""),
            exited(
                3,
                "",
                "REJECT: the staging directory is not the one made by stage\n",
            ),
        ],
    );
    let r = apply(&file_body("/tmp/example.conf"), t);
    let x = res(&r, "f");
    assert_eq!(
        (x.execution, x.change),
        (Execution::Failed, Change::None),
        "{x:?}"
    );
    let reason = x.reason.clone().unwrap_or_default();
    assert!(
        reason.contains("not proven") && reason.contains("left as it is"),
        "{reason}"
    );
}

#[test]
fn an_unexpected_publication_exit_may_follow_a_publication_and_is_indeterminate() {
    // Only 3 and 4 prove that nothing was published. Any other exit (a script
    // failure after a successful `ln` / `mv`, a signal-like 128+n, 127, 1, ...)
    // may come after the name was given: not "nothing changed", and nothing is
    // cleaned up behind it.
    for code in [1, 2, 6, 7, 126, 127, 137, 153] {
        let t = base().with_observations(
            "sh",
            vec![exited(0, STAGED, ""), exited(code, "", "boom\n")],
        );
        let r = apply(&file_body("/tmp/example.conf"), t);
        let x = res(&r, "f");
        assert_eq!(
            (x.execution, x.change),
            (Execution::Indeterminate, Change::Possible),
            "exit {code}: {x:?}"
        );
        let reason = x.reason.clone().unwrap_or_default();
        assert!(
            reason.contains("may have been published"),
            "exit {code}: {reason}"
        );
        assert!(
            !reason.contains("nothing changed") && !reason.contains("before publication"),
            "exit {code}: {reason}"
        );
        assert_eq!(
            count_ops(&r.commands, "discard"),
            0,
            "exit {code}: evidence is not destroyed"
        );
    }
}

#[test]
fn a_publication_that_was_lost_is_indeterminate_and_is_not_cleaned_up_behind_it() {
    let lost = Output {
        completion: Completion::Signaled(9),
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    };
    let t = base().with_observations("sh", vec![exited(0, STAGED, ""), lost]);
    let r = apply(&file_body("/tmp/example.conf"), t);
    let x = res(&r, "f");
    assert_eq!(x.execution, Execution::Indeterminate, "{x:?}");
    assert_eq!(x.change, Change::Possible);
    assert_eq!(
        count_ops(&r.commands, "discard"),
        0,
        "evidence is not destroyed"
    );
}

#[test]
fn a_stage_answer_that_is_not_understood_writes_nothing_more() {
    for bad in [
        "",
        "garbage\n",
        ".sinter-stage.AbCd1234 - 2049:1\n",
        ".sinter-stage.A/b - 2049:1 2049:2\n",
    ] {
        let t = base().with_observations("sh", vec![exited(0, bad, "")]);
        let r = apply(&file_body("/tmp/example.conf"), t);
        let x = res(&r, "f");
        assert_eq!(
            (x.execution, x.change),
            (Execution::Failed, Change::None),
            "{bad:?}: {x:?}"
        );
        assert_eq!(count_ops(&r.commands, "publish"), 0, "{bad:?}");
    }
}

// ---------------------------------------------------------------------------
// links
// ---------------------------------------------------------------------------

fn link_body(target: &str) -> String {
    format!("  - id: l\n    type: link\n    with:\n      path: /tmp/lnk\n      target: {target}\n")
}

fn with_old_link() -> FakeTarget {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_symlink("/tmp/lnk", "/etc/one", 0, 0);
    t
}

#[test]
fn a_link_is_replaced_by_staging_and_a_rename_through_the_script() {
    let r = apply(&link_body("/etc/two"), with_old_link());
    assert_eq!(r.status, AggregateStatus::Success, "{:?}", res(&r, "l"));
    assert_eq!(
        fs_of(&r).nodes["/tmp/lnk"].kind,
        FakeKind::Symlink("/etc/two".into())
    );
    no_staging_left(fs_of(&r));
    // The link's steps are recorded redacted (its target may be a secret).
    assert_eq!(
        r.commands
            .iter()
            .filter(|c| c.program == "[redacted]")
            .count(),
        2
    );
    for prog in ["ln", "mv", "rm", "rmdir", "mktemp"] {
        assert!(
            r.commands
                .iter()
                .all(|c| !c.program.ends_with(&format!("/{prog}"))),
            "{prog}"
        );
    }
}

#[test]
fn a_link_cleanup_that_leaves_something_follows_the_same_rules() {
    // Left in place: the link is published, the result is a success with a note.
    let t = with_old_link().with_fs_event(
        "sh",
        "publish",
        0,
        vec![FsEventAction::Chown {
            path: "/tmp".into(),
            uid: ALICE,
            gid: ALICE,
        }],
    );
    // (the walk before the publication happens before the event)
    let r = apply(&link_body("/etc/two"), t);
    let x = res(&r, "l");
    assert_eq!(x.execution, Execution::Succeeded, "{x:?}");
    assert_eq!(
        fs_of(&r).nodes["/tmp/lnk"].kind,
        FakeKind::Symlink("/etc/two".into())
    );
    assert!(x.notes.join(" ").contains("left in place"), "{:?}", x.notes);

    // A second name stays / the state is unknown: published, and a failure.
    // (A rename leaves no payload name behind in the staging directory, so the
    // report is injected for the link; the file's own case is real above.)
    let r = apply_fault(
        &link_body("/etc/two"),
        with_old_link(),
        Some("symlink_cleanup_fail"),
    );
    let x = res(&r, "l");
    assert_eq!(x.execution, Execution::Failed, "{x:?}");
    assert_eq!(x.change, Change::Changed);
    assert_eq!(
        fs_of(&r).nodes["/tmp/lnk"].kind,
        FakeKind::Symlink("/etc/two".into())
    );
    let mut t = with_old_link();
    t.fs.as_mut().unwrap().cleanup_unknown = true;
    let r = apply(&link_body("/etc/two"), t);
    let x = res(&r, "l");
    assert_eq!(x.change, Change::Changed, "{x:?}");
    assert_ne!(x.execution, Execution::Succeeded);
}

// ---------------------------------------------------------------------------
// nothing sweeps what Sinter did not just make
// ---------------------------------------------------------------------------

#[test]
fn a_stray_staging_directory_from_before_is_not_swept() {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/tmp/.sinter-stage.OldOne12", 0o700, 0, 3_000_000_099);
    let r = apply(&file_body("/tmp/example.conf"), t);
    assert_eq!(r.status, AggregateStatus::Success);
    assert!(
        fs_of(&r).nodes.contains_key("/tmp/.sinter-stage.OldOne12"),
        "a leftover is reported by its owner, never swept by a later run"
    );
    assert_eq!(count_ops(&r.commands, "discard"), 0);
}

// ---------------------------------------------------------------------------
// a sensitive resource names nothing the target said
// ---------------------------------------------------------------------------

fn shown(r: &RunReport) -> String {
    let mut out = String::new();
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
        out.push_str(&String::from_utf8(buf).unwrap());
    }
    out
}

#[test]
fn a_failed_step_of_a_sensitive_resource_names_neither_the_path_nor_what_the_target_said() {
    let body = "  - id: f\n    type: file\n    sensitive: true\n    with:\n      path: /tmp/topsecret-name.conf\n      content: \"x\\n\"\n";
    // exit 1 of `publish` may follow a publication (indeterminate); 4 is "not published".
    for (op, code, status) in [
        ("stage", 1, AggregateStatus::ApplyFailed),
        ("publish", 1, AggregateStatus::Indeterminate),
        ("publish", 4, AggregateStatus::ApplyFailed),
    ] {
        let t = base().with_fs_event(
            "sh",
            op,
            0,
            vec![FsEventAction::FailCommand {
                code,
                stderr: "mktemp: cannot create /tmp/topsecret-name.conf CANARYSTDERR\n".into(),
            }],
        );
        let r = apply(body, t);
        assert_eq!(r.status, status, "{op} {code}");
        let text = shown(&r);
        for needle in ["topsecret-name", "CANARYSTDERR", ".sinter-stage"] {
            assert!(!text.contains(needle), "{op}: {needle:?} leaked: {text}");
        }
        let logged = format!("{:?}", r.commands);
        assert!(!logged.contains("CANARYSTDERR"));
    }
}

// ---------------------------------------------------------------------------
// the controlled failure injections still reach the publication step
// ---------------------------------------------------------------------------

fn with_old_file() -> FakeTarget {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/tmp/example.conf", b"old\n", 0o644, 0, 0);
    t
}

#[test]
fn an_injected_rename_failure_publishes_nothing_and_cleans_up() {
    let r = apply_fault(
        &file_body("/tmp/example.conf"),
        with_old_file(),
        Some("rename_fail"),
    );
    let x = res(&r, "f");
    assert_eq!(
        (x.execution, x.change),
        (Execution::Failed, Change::None),
        "{x:?}"
    );
    assert_eq!(
        fs_of(&r).nodes["/tmp/example.conf"].kind,
        FakeKind::File(b"old\n".to_vec())
    );
    no_staging_left(fs_of(&r));
    assert_eq!(count_ops(&r.commands, "discard"), 1);
    assert_eq!(
        count_ops(&r.commands, "publish"),
        0,
        "the injection is before the step"
    );
}

#[test]
fn an_injected_lost_rename_is_indeterminate_and_is_not_cleaned_up() {
    let r = apply_fault(
        &file_body("/tmp/example.conf"),
        with_old_file(),
        Some("rename_indeterminate"),
    );
    let x = res(&r, "f");
    assert_eq!(
        (x.execution, x.change),
        (Execution::Indeterminate, Change::Possible),
        "{x:?}"
    );
    assert_eq!(
        count_ops(&r.commands, "discard"),
        0,
        "evidence is not destroyed"
    );
}

#[test]
fn an_abnormal_end_after_a_successful_rename_keeps_the_change() {
    let r = apply_fault(
        &file_body("/tmp/example.conf"),
        with_old_file(),
        Some("rename_success_then_abnormal"),
    );
    let x = res(&r, "f");
    assert_eq!(x.change, Change::Changed, "{x:?}");
    assert_ne!(x.execution, Execution::Succeeded);
    assert_eq!(
        fs_of(&r).nodes["/tmp/example.conf"].kind,
        FakeKind::File(b"x\n".to_vec())
    );
}

#[test]
fn a_link_that_drifted_before_publication_is_not_replaced_and_its_staging_is_removed() {
    let r = apply_fault(
        &link_body("/etc/two"),
        with_old_link(),
        Some("symlink_drift_before_publish"),
    );
    let x = res(&r, "l");
    assert_eq!(
        (x.execution, x.change),
        (Execution::Failed, Change::None),
        "{x:?}"
    );
    assert_eq!(
        fs_of(&r).nodes["/tmp/lnk"].kind,
        FakeKind::Symlink("/sinter-injected-drift".into()),
        "what stands there is not overwritten"
    );
    no_staging_left(fs_of(&r));
    // (a link's steps are recorded redacted: `stagelink`, the injected drift's
    // `ln -sT`, then `discard`)
    assert_eq!(
        r.commands
            .iter()
            .filter(|c| c.program == "[redacted]")
            .count(),
        3
    );
    // And a cleanup that fails is added to the original reason, never the other way round.
    let r = apply_fault(
        &link_body("/etc/two"),
        with_old_link(),
        Some("symlink_drift_cleanup_fail"),
    );
    let x = res(&r, "l");
    assert_eq!(
        (x.execution, x.change),
        (Execution::Failed, Change::None),
        "{x:?}"
    );
    let reason = x.reason.clone().unwrap_or_default();
    assert!(
        reason.contains("target drift detected") && reason.contains("staging cleanup"),
        "{reason}"
    );
}
