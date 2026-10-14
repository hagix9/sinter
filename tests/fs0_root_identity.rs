//! WP-FS FS-0: root is a fact about the target, not a flag.
//!
//! * FS-0a: a target user that is already root needs no `sudo` wrapper, with
//!   or without `--sudo`, and no sudo binary.
//! * FS-0c: a failing `sudo -n` wrapper is reported as what it is, not as
//!   "not a supported Linux system"; a real Linux-probe failure still is.
//! * FS-0d: plan says, in a note, that a change needs root when the target
//!   user is not root and `--sudo` was not given. Never an error, a status or
//!   a command.
//! * Unchanged: the identity of every existing successful run, the backup
//!   store location, the JSON shape.
//!
//! The scripted target ([`FakeTarget`]) runs the production engine, executor
//! wrapper decision, trust check, plan and result code. What only a real host
//! can show (a real `sudo`'s messages, a real root login, the SSH user id
//! lookup) is not claimed here; see the FS-0 report.
#![cfg(unix)]

use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::{ErrorKind, SinterError};
use sinter::executor::{CommandRecord, FakeSudoFailure, FakeTarget, Output};
use sinter::model::load_model;
use sinter::result::{Change, Execution};
use std::path::PathBuf;

fn base() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().with_fake_fs();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/etc", 0o755, 0),
        ("/etc/fs0", 0o755, 0),
        ("/var", 0o755, 0),
        ("/var/lib", 0o755, 0),
        ("/root", 0o700, 0),
        ("/srv", 0o755, 0),
        ("/home", 0o755, 0),
        ("/home/fake", 0o755, 1000),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    t
}

fn root_target() -> FakeTarget {
    base().as_root()
}

fn user_target() -> FakeTarget {
    base()
}

fn recipe(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\n{}", body)).unwrap();
    p
}

fn try_engine(
    p: &std::path::Path,
    mode: Mode,
    sudo: bool,
    t: FakeTarget,
) -> Result<Engine, SinterError> {
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
}

fn run(p: &std::path::Path, mode: Mode, sudo: bool, t: FakeTarget) -> RunReport {
    try_engine(p, mode, sudo, t)
        .unwrap_or_else(|e| panic!("connect: {}", e.message))
        .run()
        .unwrap_or_else(|e| panic!("run: {}", e.message))
}

const FILES: &str = "resources:\n  - id: f\n    type: file\n    with:\n      path: /etc/fs0/a.conf\n      content: \"a\\n\"\n  - id: d\n    type: directory\n    with:\n      path: /etc/fs0/d\n";

fn sudo_flags(r: &RunReport) -> Vec<bool> {
    r.commands.iter().map(|c: &CommandRecord| c.sudo).collect()
}

fn err_message(r: Result<Engine, SinterError>) -> SinterError {
    match r {
        Ok(_) => panic!("connect must fail"),
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// FS-0a: transport
// ---------------------------------------------------------------------------

#[test]
fn root_without_the_flag_runs_directly() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    for mode in [Mode::Plan, Mode::Apply] {
        let r = run(&p, mode, false, root_target());
        assert_eq!(r.status, AggregateStatus::Success, "{:?}", mode);
        assert!(!sudo_flags(&r).is_empty());
        assert!(sudo_flags(&r).iter().all(|s| !s), "no wrapper for root");
    }
}

#[test]
fn root_with_the_flag_uses_no_wrapper_and_the_same_results() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    for mode in [Mode::Plan, Mode::Apply] {
        let with_flag = run(&p, mode, true, root_target());
        let without = run(&p, mode, false, root_target());
        assert_eq!(with_flag.status, AggregateStatus::Success, "{:?}", mode);
        // --sudo asks for root; a root target is already there. No command is
        // sent through `sudo -n`.
        assert!(sudo_flags(&with_flag).iter().all(|s| !s), "{:?}", mode);
        // Same outcome and same commands as the run without the flag.
        let shape = |r: &RunReport| {
            r.resources
                .iter()
                .map(|x| (x.id.clone(), x.execution, x.change, x.verification))
                .collect::<Vec<_>>()
        };
        assert_eq!(shape(&with_flag), shape(&without), "{:?}", mode);
        let progs = |r: &RunReport| {
            r.commands
                .iter()
                .map(|c| c.program.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(progs(&with_flag), progs(&without), "{:?}", mode);
    }
}

#[test]
fn root_with_the_flag_needs_no_sudo_binary() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    // Every wrapped command on this target fails as "sudo: not found". A root
    // target never reaches the wrapper, so the run succeeds all the same.
    let t = root_target().with_sudo_failure(FakeSudoFailure::Missing);
    for mode in [Mode::Plan, Mode::Apply] {
        let r = run(&p, mode, true, t.clone());
        assert_eq!(r.status, AggregateStatus::Success, "{:?}", mode);
        assert!(sudo_flags(&r).iter().all(|s| !s));
    }
    // The same target for a non-root user is a failure, and says so.
    let e = err_message(try_engine(
        &p,
        Mode::Plan,
        true,
        user_target().with_sudo_failure(FakeSudoFailure::Missing),
    ));
    assert_eq!(e.kind, ErrorKind::Connect);
    assert!(e.message.contains("sudo is not installed"), "{}", e.message);
}

#[test]
fn a_non_root_user_without_the_flag_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    // A wrapper that would fail is irrelevant without --sudo.
    let t = user_target().with_sudo_failure(FakeSudoFailure::NotAuthorized);
    let r = run(&p, Mode::Plan, false, t);
    assert!(sudo_flags(&r).iter().all(|s| !s));
}

#[test]
fn a_non_root_user_with_authorized_sudo_wraps_every_command() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    for mode in [Mode::Plan, Mode::Apply] {
        let r = run(&p, mode, true, user_target());
        assert_eq!(r.status, AggregateStatus::Success, "{:?}", mode);
        assert!(sudo_flags(&r).iter().all(|s| *s), "{:?}", mode);
        assert!(!sudo_flags(&r).is_empty());
    }
}

// ---------------------------------------------------------------------------
// FS-0c: sudo failure versus Linux failure
// ---------------------------------------------------------------------------

#[test]
fn every_sudo_failure_is_named_and_none_is_called_non_linux() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    let cases = [
        (FakeSudoFailure::Missing, "sudo is not installed"),
        (
            FakeSudoFailure::PasswordRequired,
            "reported that a password is required",
        ),
        (FakeSudoFailure::NotAuthorized, "sudoers does not allow"),
        (
            FakeSudoFailure::Unrecognized,
            "The cause was not identified",
        ),
    ];
    for (failure, want) in cases {
        let e = err_message(try_engine(
            &p,
            Mode::Plan,
            true,
            user_target().with_sudo_failure(failure),
        ));
        assert_eq!(e.kind, ErrorKind::Connect, "{:?}", failure);
        assert!(e.message.contains(want), "{:?}: {}", failure, e.message);
        assert!(
            !e.message
                .contains("does not appear to be a supported Linux system"),
            "{:?}: {}",
            failure,
            e.message
        );
    }
}

fn exited(code: i32, stderr: &str) -> Output {
    Output {
        completion: sinter::executor::Completion::Exited(code),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn ended(c: sinter::executor::Completion) -> Output {
    Output {
        completion: c,
        ..exited(0, "")
    }
}

const LINUX: &str = "does not appear to be a supported Linux system";
const CANARY: &str = "CANARY-7c41-token";

/// The connect error of a non-root `--sudo` run whose `test` answers are
/// scripted in order: the first is the command through sudo, the second (if
/// any) the diagnostic without sudo; once the script is used up `test` is the
/// ordinary scripted target, which succeeds.
fn probe_error(script: Vec<Output>) -> SinterError {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    err_message(try_engine(
        &p,
        Mode::Plan,
        true,
        user_target().with_observations("test", script),
    ))
}

#[test]
fn a_linux_probe_failure_without_sudo_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    // Without --sudo, and as a root login with --sudo: no wrapper, the
    // existing verdict and message, no diagnostic.
    for (sudo, t) in [(false, user_target()), (true, root_target())] {
        let e = err_message(try_engine(
            &p,
            Mode::Plan,
            sudo,
            t.with_observations("test", vec![exited(1, "")]),
        ));
        assert_eq!(e.kind, ErrorKind::Connect);
        assert!(e.message.contains(LINUX), "sudo={}: {}", sudo, e.message);
        assert!(!e.message.contains("--sudo was requested"), "{}", e.message);
        assert!(
            !e.message.contains("checked with and without sudo"),
            "{}",
            e.message
        );
    }
}

#[test]
fn a_silent_failure_through_sudo_is_not_blamed_on_either_side_without_proof() {
    // The command through sudo fails silently. Without sudo the user reads
    // /etc/os-release, so the failure lies in the sudo path or in running as
    // root: the cause is not identified, and Linux is not doubted.
    let e = probe_error(vec![exited(1, "")]);
    assert_eq!(e.kind, ErrorKind::Connect);
    assert!(
        e.message
            .contains("although /etc/os-release is readable without sudo"),
        "{}",
        e.message
    );
    assert!(
        e.message.contains("The cause was not identified"),
        "{}",
        e.message
    );
    assert!(!e.message.contains(LINUX), "{}", e.message);
    assert!(
        !e.message.contains("sudoers does not allow"),
        "{}",
        e.message
    );
    assert!(!e.message.contains("password is required"), "{}", e.message);
}

#[test]
fn a_real_linux_probe_failure_after_a_working_sudo_is_reported_as_linux() {
    // Through sudo and without it, /etc/os-release is not readable.
    let e = probe_error(vec![exited(1, ""), exited(1, "")]);
    assert!(e.message.contains(LINUX), "{}", e.message);
    assert!(
        e.message.contains("checked with and without sudo"),
        "{}",
        e.message
    );
    assert!(!e.message.contains("sudoers"), "{}", e.message);
    assert!(
        !e.message.contains("The cause was not identified"),
        "{}",
        e.message
    );
}

#[test]
fn stderr_alone_never_decides_sudo_authorization() {
    // stderr from the command through sudo, in the wording of neither sudo nor
    // sudoers: not a refusal. With the file unreadable without sudo too, the
    // Linux verdict stands; with it readable, the cause is not identified.
    let words = format!("test: {} could not be examined", CANARY);
    let linux = probe_error(vec![exited(1, &words), exited(1, "")]);
    assert!(linux.message.contains(LINUX), "{}", linux.message);
    let unknown = probe_error(vec![exited(1, &words)]);
    assert!(
        unknown.message.contains("The cause was not identified"),
        "{}",
        unknown.message
    );
    for e in [&linux, &unknown] {
        assert!(
            !e.message.contains("sudoers does not allow"),
            "{}",
            e.message
        );
        assert!(!e.message.contains("password is required"), "{}", e.message);
        assert!(!e.message.contains("not installed"), "{}", e.message);
    }
}

#[test]
fn an_unknown_sudo_wording_is_reported_without_repeating_it() {
    // A sudo-rs (or localized) sentence Sinter has no pattern for, carrying a
    // canary: the message says what could be observed and nothing else.
    let words = format!(
        "sudo-rs: {} nouveau message\nsecond line {}",
        CANARY, CANARY
    );
    let e = probe_error(vec![exited(1, &words)]);
    assert!(
        e.message.contains("The cause was not identified"),
        "{}",
        e.message
    );
    assert!(e.message.contains("exit 1"), "{}", e.message);
    for text in [
        e.message.clone(),
        format!("{:?}", e.message),
        format!("{:?}", e.kind),
    ] {
        assert!(!text.contains(CANARY), "{}", text);
        assert!(!text.contains("nouveau"), "{}", text);
    }
    // The same through the scripted sudo failure that is not recognized.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    let e = err_message(try_engine(
        &p,
        Mode::Plan,
        true,
        user_target().with_sudo_failure(FakeSudoFailure::Unrecognized),
    ));
    assert!(
        e.message.contains("The cause was not identified"),
        "{}",
        e.message
    );
    assert!(!e.message.contains("policy plugin"), "{}", e.message);
}

#[test]
fn a_command_that_did_not_finish_is_reported_as_that() {
    use sinter::executor::Completion;
    for c in [
        Completion::Signaled(9),
        Completion::Indeterminate {
            started: true,
            reason: format!("{} timed out", CANARY),
        },
    ] {
        let e = probe_error(vec![ended(c)]);
        assert!(
            e.message.contains("did not finish normally"),
            "{}",
            e.message
        );
        assert!(
            e.message.contains("The cause was not identified"),
            "{}",
            e.message
        );
        assert!(!e.message.contains(CANARY), "{}", e.message);
        assert!(!e.message.contains(LINUX), "{}", e.message);
    }
}

#[test]
fn an_unsettled_diagnostic_is_not_turned_into_a_verdict() {
    // Through sudo: exit 1. Without sudo: exit 127 (no `test` there at all):
    // not a Linux verdict, not a sudo verdict.
    let e = probe_error(vec![exited(1, ""), exited(127, "")]);
    assert!(
        e.message.contains("could not settle why (exit 127)"),
        "{}",
        e.message
    );
    assert!(!e.message.contains(LINUX), "{}", e.message);
}

#[test]
fn a_named_sudo_failure_needs_no_diagnostic() {
    // The sentence names the cause: no further command is run, whatever
    // follows in the script (a second answer would be Linux).
    let e = probe_error(vec![
        exited(1, "sudo: a password is required"),
        exited(1, ""),
    ]);
    assert!(
        e.message.contains("reported that a password is required"),
        "{}",
        e.message
    );
    assert!(!e.message.contains(LINUX), "{}", e.message);
}

// ---------------------------------------------------------------------------
// identity of existing runs
// ---------------------------------------------------------------------------

const ID_COMMAND: &str = "resources:\n  - id: who\n    type: command\n    with:\n      program: /usr/bin/id\n      args: [\"-u\"]\n";

fn id_record(r: &RunReport) -> &CommandRecord {
    r.commands
        .iter()
        .find(|c| c.program == "/usr/bin/id" && c.args == ["-u"])
        .expect("the command resource ran id -u")
}

#[test]
fn the_identity_of_a_command_resource_is_the_runs_identity_and_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, ID_COMMAND);
    // (target, --sudo) -> was the command sent through sudo?
    let cases = [
        (user_target(), false, false), // the connecting user, as before
        (user_target(), true, true),   // root through sudo, as before
        (root_target(), false, false), // root itself
        (root_target(), true, false),  // root itself: no wrapper, still root
    ];
    for (t, sudo, wrapped) in cases {
        let r = run(&p, Mode::Apply, sudo, t.clone());
        assert_eq!(r.status, AggregateStatus::Success);
        assert_eq!(id_record(&r).sudo, wrapped, "uid {} sudo {}", t.uid, sudo);
    }
}

#[test]
fn plan_apply_and_audit_choose_the_same_transport() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    for (t, sudo) in [
        (root_target(), false),
        (root_target(), true),
        (user_target(), false),
        (user_target(), true),
    ] {
        let want = sudo && t.uid != 0;
        let plan = run(&p, Mode::Plan, sudo, t.clone());
        let apply = run(&p, Mode::Apply, sudo, t.clone());
        let audit =
            sinter::audit::run_audit(try_engine(&p, Mode::Plan, sudo, t.clone()).unwrap()).unwrap();
        for (what, flags) in [
            ("plan", sudo_flags(&plan)),
            ("apply", sudo_flags(&apply)),
            (
                "audit",
                audit.commands.iter().map(|c| c.sudo).collect::<Vec<_>>(),
            ),
        ] {
            assert!(!flags.is_empty(), "{}", what);
            assert!(
                flags.iter().all(|s| *s == want),
                "{} uid {} sudo {}: {:?}",
                what,
                t.uid,
                sudo,
                flags
            );
        }
    }
}

// ---------------------------------------------------------------------------
// backup store location (unchanged contract)
// ---------------------------------------------------------------------------

#[test]
fn the_backup_store_follows_the_flag_not_the_user() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "backup:\n  paths: [/srv/nothing]\nresources:\n  - id: f\n    type: file\n    with:\n      path: /etc/fs0/a.conf\n      content: \"a\\n\"\n",
    );
    let store = |sudo: bool, t: FakeTarget| -> String {
        let r = run(&p, Mode::Apply, sudo, t);
        assert_eq!(r.status, AggregateStatus::Success);
        r.backup
            .as_ref()
            .and_then(|b| b.directory.clone())
            .expect("apply made a backup run directory")
    };
    // --sudo: /var/lib/sinter, for root and for a user with sudo alike.
    assert!(store(true, root_target()).starts_with("/var/lib/sinter/backups/"));
    assert!(store(true, user_target()).starts_with("/var/lib/sinter/backups/"));
    // No flag: the target user's home, root's included (the existing contract).
    assert!(store(false, root_target()).starts_with("/root/.sinter/backups/"));
    assert!(store(false, user_target()).starts_with("/home/fake/.sinter/backups/"));
}

// ---------------------------------------------------------------------------
// FS-0d: plan notes
// ---------------------------------------------------------------------------

fn notes(r: &RunReport, id: &str) -> Vec<String> {
    r.resources
        .iter()
        .find(|x| x.id == id)
        .unwrap()
        .notes
        .clone()
}

fn needs_root(n: &[String]) -> bool {
    n.iter()
        .any(|x| x.contains("needs root") || x.contains("no owner write permission"))
}

#[test]
fn plan_says_which_changes_need_root_when_the_user_is_not_root() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: file_in_etc\n    type: file\n    with:\n      path: /etc/fs0/a.conf\n      content: \"a\\n\"\n  - id: dir_in_etc\n    type: directory\n    with:\n      path: /etc/fs0/d\n  - id: link_in_etc\n    type: link\n    with:\n      path: /etc/fs0/l\n      target: /etc/hostname\n  - id: pkg\n    type: package\n    with:\n      name: nginx\n      state: present\n  - id: usr\n    type: user\n    with:\n      name: svc\n  - id: grp\n    type: group\n    with:\n      name: svcg\n  - id: cmd\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let r = run(&p, Mode::Plan, false, user_target());
    // Plan still succeeds and reports the same changes as before.
    assert_eq!(r.status, AggregateStatus::Success);
    for id in [
        "file_in_etc",
        "dir_in_etc",
        "link_in_etc",
        "pkg",
        "usr",
        "grp",
    ] {
        let x = r.resources.iter().find(|x| x.id == id).unwrap();
        assert_eq!(x.change, Change::Changed, "{}", id);
        assert!(needs_root(&notes(&r, id)), "{}: {:?}", id, notes(&r, id));
    }
    // A command's identity is the run's; nothing is claimed about it.
    assert!(!needs_root(&notes(&r, "cmd")), "{:?}", notes(&r, "cmd"));
    // Plan neither ran sudo nor looked for it.
    assert!(r
        .commands
        .iter()
        .all(|c| !c.sudo && c.program != "/usr/bin/sudo"));
    assert!(!r
        .commands
        .iter()
        .any(|c| c.args.iter().any(|a| a.contains("sudo"))));
}

#[test]
fn no_note_for_root_for_sudo_or_for_a_directory_the_user_owns() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: file_in_etc\n    type: file\n    with:\n      path: /etc/fs0/a.conf\n      content: \"a\\n\"\n  - id: pkg\n    type: package\n    with:\n      name: nginx\n      state: present\n  - id: mine\n    type: file\n    with:\n      path: /home/fake/a.conf\n      content: \"a\\n\"\n",
    );
    // /home/fake belongs to uid 1000, whose account exists: for root (a root
    // login or --sudo) it is a directory inside that account's tree (FS-3).
    let fake_user = |t: FakeTarget| t.with_user("fake", 1000, 1000, "/home/fake", "/bin/bash");
    for (t, sudo) in [
        (fake_user(root_target()), false),
        (fake_user(root_target()), true),
        (fake_user(user_target()), true),
    ] {
        let r = run(&p, Mode::Plan, sudo, t);
        for id in ["file_in_etc", "pkg", "mine"] {
            assert!(!needs_root(&notes(&r, id)), "{}: {:?}", id, notes(&r, id));
        }
    }
    // The user's own writable directory: nothing to say, even without sudo.
    let r = run(&p, Mode::Plan, false, user_target());
    assert!(!needs_root(&notes(&r, "mine")), "{:?}", notes(&r, "mine"));
    assert_eq!(
        r.resources.iter().find(|x| x.id == "mine").unwrap().change,
        Change::Changed
    );
}

#[test]
fn a_metadata_only_change_is_not_a_parent_directory_write() {
    // Changing the mode of a file that exists writes the file, not /etc/fs0.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: f\n    type: file\n    with:\n      path: /etc/fs0/a.conf\n      mode: \"0600\"\n",
    );
    let t = user_target().with_fs_file("/etc/fs0/a.conf", "a\n");
    let r = run(&p, Mode::Plan, false, t);
    let x = r.resources.iter().find(|x| x.id == "f").unwrap();
    assert_eq!(x.change, Change::Changed);
    assert!(!needs_root(&x.notes), "{:?}", x.notes);
}

#[test]
fn a_sensitive_resource_names_no_path_in_the_note() {
    let dir = tempfile::tempdir().unwrap();
    let t = user_target().with_fs_dir("/etc/very-secret-dir");
    let named = recipe(
        &dir,
        "resources:\n  - id: s\n    type: file\n    with:\n      path: /etc/very-secret-dir/a.conf\n      content: \"a\\n\"\n",
    );
    // The note of an ordinary resource names the directory (the control case:
    // the check below could not fail otherwise)...
    let r = run(&named, Mode::Plan, false, t.clone());
    assert!(
        notes(&r, "s").iter().any(|x| x.contains("very-secret-dir")),
        "{:?}",
        notes(&r, "s")
    );
    // ...and a sensitive one does not.
    let sensitive = recipe(
        &dir,
        "resources:\n  - id: s\n    type: file\n    sensitive: true\n    with:\n      path: /etc/very-secret-dir/a.conf\n      content: \"a\\n\"\n",
    );
    let r = run(&sensitive, Mode::Plan, false, t);
    let n = notes(&r, "s");
    assert!(needs_root(&n), "{:?}", n);
    assert!(n.iter().all(|x| !x.contains("very-secret-dir")), "{:?}", n);
}

#[test]
fn the_note_adds_no_status_no_field_and_no_command() {
    use sinter::output::run_report_json;
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    // Same recipe: as a user (notes) and as root (none).
    let user = run(&p, Mode::Plan, false, user_target());
    let root = run(&p, Mode::Plan, false, root_target());
    // The aggregate and per-resource statuses are the same either way.
    assert_eq!(user.status, root.status);
    for (u, r) in user.resources.iter().zip(root.resources.iter()) {
        assert_eq!(
            (u.execution, u.change, u.verification),
            (r.execution, r.change, r.verification)
        );
    }
    // No extra command beyond the identity-dependent setup.
    assert_eq!(user.commands.len(), root.commands.len());
    // JSON: the same keys at every level; only the notes array differs.
    let json = |r: &RunReport| -> serde_json::Value { run_report_json(r, "plan") };
    fn keys(v: &serde_json::Value, path: String, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    out.push(format!("{}/{}", path, k));
                    keys(x, format!("{}/{}", path, k), out);
                }
            }
            serde_json::Value::Array(a) => {
                for x in a {
                    keys(x, format!("{}[]", path), out);
                }
            }
            _ => {}
        }
    }
    let (mut ku, mut kr) = (Vec::new(), Vec::new());
    let (ju, jr) = (json(&user), json(&root));
    keys(&ju, String::new(), &mut ku);
    keys(&jr, String::new(), &mut kr);
    ku.sort();
    ku.dedup();
    kr.sort();
    kr.dedup();
    // Differences may only be inside facts/identity-free fields; the note
    // text lives in the existing `notes` array.
    let only_user: Vec<_> = ku.iter().filter(|k| !kr.contains(k)).collect();
    let only_root: Vec<_> = kr.iter().filter(|k| !ku.contains(k)).collect();
    assert!(only_user.is_empty(), "{:?}", only_user);
    assert!(only_root.is_empty(), "{:?}", only_root);
    let notes_json = ju["resources"][0]["notes"].as_array().unwrap();
    assert!(notes_json
        .iter()
        .any(|n| n.as_str().unwrap().contains("needs root")));
}

#[test]
fn apply_after_a_planned_note_still_fails_exactly_as_before() {
    // The note is information. What apply does is unchanged: the scripted
    // filesystem does not model write permission, so apply is only compared
    // with the same run before the note existed: same statuses.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, FILES);
    let r = run(&p, Mode::Apply, false, user_target());
    for x in &r.resources {
        assert_eq!(x.execution, Execution::Succeeded, "{}", x.id);
        assert!(
            !needs_root(&x.notes),
            "apply carries no plan note: {:?}",
            x.notes
        );
    }
}
