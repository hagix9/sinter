//! Regression tests for release-test *precondition integrity*: a fixture step
//! that fails, or that "succeeds" without producing the state the test
//! depends on, must never let the test go on to report a pass.
//!
//! They exercise the real fixture helpers in `tests/common` against fake
//! tools, so they need neither root, systemd nor an SSH target and run on any
//! host. The real service test that uses `require_unit_not_found` is covered
//! for strict/non-strict behavior in `tests/package_service.rs`.

mod common;

use common::*;
use std::cell::RefCell;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Linux refuses `execve` (ETXTBSY) of a file that any process still holds
/// open for writing, and a child forked while such a handle is open inherits
/// it until its own exec. The tests here write fake tools and spawn children
/// on parallel threads, so a fork from one test could make another test's
/// fake tool "text file busy". Writing a fake tool and every spawn of a fake
/// tool (`Lab::establish`, the only place these tests fork) therefore never
/// overlap; nothing else is serialized.
static FAKE_TOOL_SPAWN: Mutex<()> = Mutex::new(());

fn fake_tool_section() -> MutexGuard<'static, ()> {
    // A failed test must not turn into failures of every later test.
    FAKE_TOOL_SPAWN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn script(dir: &Path, name: &str, body: &str) -> String {
    let _section = fake_tool_section();
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.to_str().unwrap().to_string()
}

/// A hermetic stand-in for "systemd plus sudo". The unit file is a plain file;
/// like the real `systemctl`, `stop`/`disable`/`reset-failed` fail (exit 5) for
/// a unit that is not there, and `show` reports what the file says.
struct Lab {
    dir: PathBuf,
    unit_path: String,
    tools: UnitSetupTools,
}

const UNIT: &str = "sinter-precondition-test.service";

impl Lab {
    fn new(label: &str) -> Lab {
        let dir = trusted_root(label);
        let unit_path = dir.join(UNIT).to_str().unwrap().to_string();
        let systemctl = script(
            &dir,
            "systemctl",
            &format!(
                r#"UNIT_FILE='{unit_path}'
case "$1" in
show)
  if [ -e "$UNIT_FILE" ]; then echo LoadState=loaded; echo ActiveState=active
  else echo LoadState=not-found; echo ActiveState=inactive; fi
  exit 0 ;;
stop|disable|reset-failed) [ -e "$UNIT_FILE" ] || exit 5; exit 0 ;;
daemon-reload) exit 0 ;;
esac
exit 2"#
            ),
        );
        let sudo = script(&dir, "sudo", r#"[ "$1" = -n ] && shift; exec "$@""#);
        Lab {
            dir,
            unit_path,
            tools: UnitSetupTools {
                sudo,
                admin_systemctl: systemctl.clone(),
                query_systemctl: systemctl,
            },
        }
    }

    fn leave_stale_unit(&self) {
        std::fs::write(&self.unit_path, "[Unit]\n").unwrap();
    }

    fn establish(&self) -> Result<(), UnitPreconditionError> {
        let _section = fake_tool_section();
        establish_unit_not_found(&self.tools, UNIT, &self.unit_path)
    }
}

// ---- F-03: the "unit is not-found" precondition ---------------------------

#[test]
fn already_absent_unit_satisfies_the_precondition() {
    // The fake `stop`/`disable`/`reset-failed` exit non-zero for an absent
    // unit, as systemctl does: that must not turn a correct state into a
    // failure.
    let lab = Lab::new("pre-absent");
    assert_eq!(lab.establish(), Ok(()));
}

#[test]
fn stale_unit_is_removed_and_absence_is_proven() {
    let lab = Lab::new("pre-stale");
    lab.leave_stale_unit();
    assert_eq!(lab.establish(), Ok(()));
    assert!(!Path::new(&lab.unit_path).exists());
}

#[test]
fn failing_removal_command_is_a_failure_even_if_the_unit_is_absent() {
    let mut lab = Lab::new("pre-remove-fails");
    lab.tools.sudo = script(&lab.dir, "sudo-fails", "exit 1");
    lab.leave_stale_unit();
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::RemovalFailed(_))
    ));
    assert!(Path::new(&lab.unit_path).exists(), "nothing was removed");

    let fresh = {
        let mut l = Lab::new("pre-remove-fails-absent");
        l.tools.sudo = script(&l.dir, "sudo-fails", "exit 1");
        l
    };
    assert!(matches!(
        fresh.establish(),
        Err(UnitPreconditionError::RemovalFailed(_))
    ));
}

#[test]
fn failing_daemon_reload_is_a_removal_failure() {
    let mut lab = Lab::new("pre-reload-fails");
    lab.tools.admin_systemctl = script(&lab.dir, "systemctl-no-reload", "exit 1");
    lab.leave_stale_unit();
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::RemovalFailed(_))
    ));
}

#[test]
fn removal_tool_that_cannot_run_is_a_failure() {
    let mut lab = Lab::new("pre-no-sudo");
    lab.tools.sudo = "/nonexistent/sudo".to_string();
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::RemovalNotRun(_))
    ));
}

#[test]
fn removal_reporting_success_while_the_unit_remains_is_a_failure() {
    let mut lab = Lab::new("pre-noop-removal");
    // Exits 0 and does nothing.
    lab.tools.sudo = script(&lab.dir, "sudo-noop", "exit 0");
    lab.leave_stale_unit();
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::UnitFileStillPresent(_))
    ));
}

#[test]
fn unit_still_reported_loaded_or_active_is_a_failure() {
    let mut lab = Lab::new("pre-still-loaded");
    // The file is gone, but systemd still reports the unit as loaded.
    lab.tools.query_systemctl = script(
        &lab.dir,
        "systemctl-loaded",
        "echo LoadState=loaded; echo ActiveState=active",
    );
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::NotAbsent(_))
    ));
    // Not-found but still running (a ghost of a deleted unit) is not the
    // required initial state either.
    lab.tools.query_systemctl = script(
        &lab.dir,
        "systemctl-ghost",
        "echo LoadState=not-found; echo ActiveState=active",
    );
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::NotAbsent(_))
    ));
}

#[test]
fn unreadable_state_is_never_treated_as_absent() {
    let mut lab = Lab::new("pre-query-fails");
    // The query cannot run.
    lab.tools.query_systemctl = "/nonexistent/systemctl".to_string();
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::StateUnknown(_))
    ));
    // The query runs and fails.
    lab.tools.query_systemctl = script(&lab.dir, "systemctl-fails", "exit 1");
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::StateUnknown(_))
    ));
    // The query succeeds but says nothing usable.
    lab.tools.query_systemctl = script(&lab.dir, "systemctl-silent", "exit 0");
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::StateUnknown(_))
    ));
    lab.tools.query_systemctl = script(&lab.dir, "systemctl-partial", "echo LoadState=not-found");
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::StateUnknown(_))
    ));
}

// ---- R-1: the "manager is synchronized" precondition ----------------------

/// A hermetic manager whose `NeedDaemonReload` answer is a flag file: present
/// is `yes` for every unit (a stale manager), `daemon-reload` removes it.
struct SyncLab {
    dir: PathBuf,
    stale_flag: String,
    tools: UnitSetupTools,
}

const SYNC_UNIT: &str = "sinter-no-such-unit.service";

impl SyncLab {
    fn new(label: &str, stale: bool) -> SyncLab {
        let dir = trusted_root(label);
        let stale_flag = dir.join("stale").to_str().unwrap().to_string();
        if stale {
            std::fs::write(&stale_flag, "").unwrap();
        }
        let systemctl = script(
            &dir,
            "systemctl",
            &format!(
                r#"FLAG='{stale_flag}'
case "$1" in
show)
  if [ -e "$FLAG" ]; then need=yes; else need=no; fi
  echo LoadState=not-found; echo NeedDaemonReload=$need; exit 0 ;;
daemon-reload) rm -f "$FLAG"; exit 0 ;;
esac
exit 2"#
            ),
        );
        let sudo = script(&dir, "sudo", r#"[ "$1" = -n ] && shift; exec "$@""#);
        SyncLab {
            dir,
            stale_flag,
            tools: UnitSetupTools {
                sudo,
                admin_systemctl: systemctl.clone(),
                query_systemctl: systemctl,
            },
        }
    }

    fn establish(&self) -> Result<(), UnitPreconditionError> {
        let _section = fake_tool_section();
        establish_synchronized_manager(&self.tools, SYNC_UNIT)
    }

    fn is_stale(&self) -> bool {
        Path::new(&self.stale_flag).exists()
    }
}

#[test]
fn synchronized_manager_is_left_alone_and_needs_no_privilege() {
    let mut lab = SyncLab::new("sync-already", false);
    // A privilege wrapper that always fails proves nothing was run with it.
    lab.tools.sudo = script(&lab.dir, "sudo-fails", "exit 1");
    assert_eq!(lab.establish(), Ok(()));
}

#[test]
fn stale_manager_is_reloaded_and_the_synchronized_state_is_proven() {
    let lab = SyncLab::new("sync-stale", true);
    assert!(lab.is_stale());
    assert_eq!(lab.establish(), Ok(()));
    assert!(!lab.is_stale());
}

#[test]
fn failing_or_missing_reload_is_a_failure_and_leaves_the_manager_stale() {
    let mut lab = SyncLab::new("sync-reload-fails", true);
    lab.tools.sudo = script(&lab.dir, "sudo-fails", "exit 1");
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::SyncFailed(_))
    ));
    assert!(lab.is_stale());

    lab.tools.sudo = "/nonexistent/sudo".to_string();
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::SyncFailed(_))
    ));
}

#[test]
fn reload_reporting_success_while_the_manager_stays_stale_is_a_failure() {
    let mut lab = SyncLab::new("sync-noop-reload", true);
    // Exits 0 and does nothing.
    lab.tools.sudo = script(&lab.dir, "sudo-noop", "exit 0");
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::NotSynchronized(_))
    ));
    assert!(lab.is_stale());
}

#[test]
fn unreadable_or_unexpected_manager_state_is_never_treated_as_synchronized() {
    let mut lab = SyncLab::new("sync-unreadable", false);
    lab.tools.query_systemctl = "/nonexistent/systemctl".to_string();
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::StateUnknown(_))
    ));
    lab.tools.query_systemctl = script(&lab.dir, "systemctl-fails", "exit 1");
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::StateUnknown(_))
    ));
    // NeedDaemonReload missing from an otherwise good answer.
    lab.tools.query_systemctl = script(&lab.dir, "systemctl-partial", "echo LoadState=not-found");
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::StateUnknown(_))
    ));
    // A value that is neither yes nor no.
    lab.tools.query_systemctl = script(
        &lab.dir,
        "systemctl-maybe",
        "echo LoadState=not-found; echo NeedDaemonReload=maybe",
    );
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::NotSynchronized(_))
    ));
    // The probe unit exists after all: not the missing-unit precondition.
    lab.tools.query_systemctl = script(
        &lab.dir,
        "systemctl-loaded",
        "echo LoadState=loaded; echo NeedDaemonReload=no",
    );
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::NotAbsent(_))
    ));
}

// ---- F-R1: the synchronized-manager observation must be exact -------------

/// The helper run against a query tool that prints `printf_arg` (a `printf`
/// format, so raw bytes can be planted) and a privilege wrapper that records
/// whether it was ever used. Returns the result and whether a reload ran.
fn establish_with_answer(
    label: &str,
    printf_arg: &str,
) -> (Result<(), UnitPreconditionError>, bool) {
    let mut lab = SyncLab::new(label, false);
    let ran = lab.dir.join("sudo-ran").to_str().unwrap().to_string();
    lab.tools.query_systemctl = script(
        &lab.dir,
        "systemctl-answer",
        &format!("printf '{printf_arg}'"),
    );
    lab.tools.sudo = script(&lab.dir, "sudo-marks", &format!("touch '{ran}'; exit 0"));
    let r = lab.establish();
    (r, Path::new(&ran).exists())
}

#[test]
fn fr1_valid_answers_are_parsed_exactly() {
    assert_eq!(
        parse_load_and_need(b"LoadState=not-found\nNeedDaemonReload=no\n").unwrap(),
        ("not-found".to_string(), "no".to_string())
    );
    assert_eq!(
        parse_load_and_need(b"NeedDaemonReload=yes\nLoadState=not-found\n").unwrap(),
        ("not-found".to_string(), "yes".to_string())
    );
}

#[test]
fn fr1_valid_answers_through_the_helper() {
    let (r, reloaded) =
        establish_with_answer("fr1-no", "LoadState=not-found\nNeedDaemonReload=no\n");
    assert_eq!(r, Ok(()));
    assert!(!reloaded, "a synchronized manager is not reloaded");
    // not-found + yes: reloaded once by the helper; this answer never changes,
    // so the re-proof must fail (the reload did not synchronize it).
    let (r, reloaded) =
        establish_with_answer("fr1-yes", "LoadState=not-found\nNeedDaemonReload=yes\n");
    assert!(reloaded);
    assert!(
        matches!(r, Err(UnitPreconditionError::NotSynchronized(_))),
        "{r:?}"
    );
}

#[test]
fn fr1_ambiguous_or_unprovable_answers_fail_closed_without_a_reload() {
    // (label, raw answer, error is a StateUnknown)
    let cases: Vec<(&str, &str)> = vec![
        // the independent audit's counterexample: first match said "no"
        (
            "audit counterexample",
            "LoadState=not-found\nNeedDaemonReload=no\nNeedDaemonReload=yes\n",
        ),
        (
            "reversed conflicting need",
            "LoadState=not-found\nNeedDaemonReload=yes\nNeedDaemonReload=no\n",
        ),
        ("missing LoadState", "NeedDaemonReload=no\n"),
        ("missing NeedDaemonReload", "LoadState=not-found\n"),
        ("nothing", ""),
        (
            "identical duplicate LoadState",
            "LoadState=not-found\nLoadState=not-found\nNeedDaemonReload=no\n",
        ),
        (
            "conflicting duplicate LoadState",
            "LoadState=not-found\nLoadState=loaded\nNeedDaemonReload=no\n",
        ),
        (
            "identical duplicate NeedDaemonReload",
            "LoadState=not-found\nNeedDaemonReload=no\nNeedDaemonReload=no\n",
        ),
        (
            "conflicting duplicate NeedDaemonReload",
            "LoadState=not-found\nNeedDaemonReload=yes\nNeedDaemonReload=no\n",
        ),
        (
            "malformed line",
            "LoadState=not-found\nNeedDaemonReload=no\ngarbage\n",
        ),
        ("blank line", "LoadState=not-found\n\nNeedDaemonReload=no\n"),
        ("empty LoadState", "LoadState=\nNeedDaemonReload=no\n"),
        (
            "empty NeedDaemonReload",
            "LoadState=not-found\nNeedDaemonReload=\n",
        ),
        (
            "unexpected extra property",
            "LoadState=not-found\nNeedDaemonReload=no\nActiveState=inactive\n",
        ),
        (
            "key prefix is not the key",
            "LoadState=not-found\nXNeedDaemonReload=no\n",
        ),
        (
            "invalid UTF-8",
            "LoadState=not-found\nNeedDaemonReload=no\n\\377",
        ),
        (
            "CR is not trimmed",
            "LoadState=not-found\r\nNeedDaemonReload=no\r\n",
        ),
    ];
    for (label, answer) in cases {
        let (r, reloaded) = establish_with_answer("fr1-bad", answer);
        assert!(r.is_err(), "{label}: accepted ({r:?})");
        assert!(
            !reloaded,
            "{label}: a reload was run on an unprovable answer"
        );
    }
    // structural problems (including an empty value) are StateUnknown, as for
    // the other unreadable states
    for empty in [
        "LoadState=\nNeedDaemonReload=no\n",
        "LoadState=not-found\nNeedDaemonReload=\n",
    ] {
        let (r, _) = establish_with_answer("fr1-empty", empty);
        assert!(
            matches!(r, Err(UnitPreconditionError::StateUnknown(_))),
            "{empty:?}: {r:?}"
        );
    }
    let (r, _) = establish_with_answer(
        "fr1-audit",
        "LoadState=not-found\nNeedDaemonReload=no\nNeedDaemonReload=yes\n",
    );
    assert!(
        matches!(r, Err(UnitPreconditionError::StateUnknown(_))),
        "{r:?}"
    );
}

#[test]
fn fr1_need_values_other_than_yes_and_no_are_errors() {
    for v in ["maybe", "No", "YES", "true", "1", "no ", "yes\\t"] {
        let (r, reloaded) = establish_with_answer(
            "fr1-need",
            &format!("LoadState=not-found\nNeedDaemonReload={v}\n"),
        );
        assert!(r.is_err(), "{v:?} accepted: {r:?}");
        assert!(!reloaded, "{v:?}");
    }
}

#[test]
fn fr1_unexpectedly_loaded_probe_is_not_the_precondition() {
    for need in ["no", "yes"] {
        let (r, reloaded) = establish_with_answer(
            "fr1-loaded",
            &format!("LoadState=loaded\nNeedDaemonReload={need}\n"),
        );
        assert!(
            matches!(r, Err(UnitPreconditionError::NotAbsent(_))),
            "{need}: {r:?}"
        );
        assert!(!reloaded);
    }
}

/// A manager that is stale until the helper's reload, after which `show`
/// answers `after` (`printf` format, or `FAIL` for a failing `show`).
fn establish_after_reload(label: &str, after: &str) -> Result<(), UnitPreconditionError> {
    let mut lab = SyncLab::new(label, true);
    let reloaded = lab.dir.join("reloaded").to_str().unwrap().to_string();
    let post = if after == "FAIL" {
        "exit 1".to_string()
    } else {
        format!("printf '{after}'; exit 0")
    };
    lab.tools.query_systemctl = script(
        &lab.dir,
        "systemctl-two-phase",
        &format!(
            "if [ -e '{reloaded}' ]; then {post}; fi\nprintf 'LoadState=not-found\\nNeedDaemonReload=yes\\n'"
        ),
    );
    lab.tools.sudo = script(
        &lab.dir,
        "sudo-reloads",
        &format!("touch '{reloaded}'; exit 0"),
    );
    lab.establish()
}

#[test]
fn fr1_the_state_after_the_helpers_reload_is_proven_with_the_same_strict_parser() {
    // reload succeeded and the manager now says no: proven
    assert_eq!(
        establish_after_reload(
            "fr1-after-ok",
            "LoadState=not-found\\nNeedDaemonReload=no\\n"
        ),
        Ok(())
    );
    // reload succeeded but the manager still says yes
    assert!(matches!(
        establish_after_reload(
            "fr1-after-yes",
            "LoadState=not-found\\nNeedDaemonReload=yes\\n"
        ),
        Err(UnitPreconditionError::NotSynchronized(_))
    ));
    // the observation after the reload fails
    assert!(matches!(
        establish_after_reload("fr1-after-fail", "FAIL"),
        Err(UnitPreconditionError::StateUnknown(_))
    ));
    // ... or is ambiguous (the first-match reader would have said "no")
    assert!(matches!(
        establish_after_reload(
            "fr1-after-dup",
            "LoadState=not-found\\nNeedDaemonReload=no\\nNeedDaemonReload=yes\\n"
        ),
        Err(UnitPreconditionError::StateUnknown(_))
    ));
    // ... or the probe appeared
    assert!(matches!(
        establish_after_reload(
            "fr1-after-loaded",
            "LoadState=loaded\\nNeedDaemonReload=no\\n"
        ),
        Err(UnitPreconditionError::NotAbsent(_))
    ));
}

#[test]
fn fr1_reload_failure_is_a_failure() {
    let mut lab = SyncLab::new("fr1-reload-fails", true);
    lab.tools.sudo = script(&lab.dir, "sudo-fails", "exit 1");
    assert!(matches!(
        lab.establish(),
        Err(UnitPreconditionError::SyncFailed(_))
    ));
    assert!(lab.is_stale());
}

// ---- F-04 / F-05: target fixture steps ------------------------------------

type Call = (String, Vec<String>, bool);

fn recorded(
    calls: &RefCell<Vec<Call>>,
    replies: Vec<TargetRunResult>,
) -> impl FnMut(&str, &[&str], bool) -> TargetRunResult + '_ {
    let mut replies = replies.into_iter();
    move |program, args, sudo| {
        calls.borrow_mut().push((
            program.to_string(),
            args.iter().map(|a| a.to_string()).collect(),
            sudo,
        ));
        replies.next().expect("unexpected extra target command")
    }
}

fn exited(code: i32, stdout: &str) -> TargetRunResult {
    Ok((code, stdout.to_string(), String::new()))
}

#[test]
fn target_private_dir_is_created_when_both_steps_succeed() {
    let calls = RefCell::new(Vec::new());
    let mut run = recorded(&calls, vec![exited(0, ""), exited(0, "")]);
    let dir = target_private_dir_with("label", true, &mut run);
    assert_eq!(
        dir,
        format!("/root/.sinter-tests/label-{}", std::process::id())
    );
    assert_eq!(calls.borrow().len(), 2);
}

#[test]
#[should_panic(expected = "creating the target test root failed with exit 1")]
fn target_private_dir_rejects_a_failed_root_creation() {
    // `install -d` ran and exited 1: `Ok((1, ..))`, which `is_ok()` accepted.
    let calls = RefCell::new(Vec::new());
    let mut run = recorded(&calls, vec![exited(1, "")]);
    target_private_dir_with("label", true, &mut run);
}

#[test]
#[should_panic(expected = "creating the target test dir failed with exit 1")]
fn target_private_dir_rejects_a_failed_dir_creation() {
    let calls = RefCell::new(Vec::new());
    let mut run = recorded(&calls, vec![exited(0, ""), exited(1, "")]);
    target_private_dir_with("label", true, &mut run);
}

#[test]
#[should_panic(expected = "creating the target test root could not run")]
fn target_private_dir_rejects_a_command_that_could_not_run() {
    let calls = RefCell::new(Vec::new());
    let mut run = recorded(&calls, vec![Err("no route".to_string())]);
    target_private_dir_with("label", true, &mut run);
}

#[test]
fn seeded_target_file_is_read_back() {
    let calls = RefCell::new(Vec::new());
    let mut run = recorded(&calls, vec![exited(0, ""), exited(0, "initial")]);
    target_seed_file_with("/root/x/conf", "initial", true, &mut run);
    let calls = calls.borrow();
    assert_eq!(calls[0].0, "/bin/sh");
    assert!(calls[0].1[1].contains("'/root/x/conf'"), "{:?}", calls[0]);
    assert_eq!(calls[1].0, "/bin/cat");
}

#[test]
#[should_panic(expected = "seeding the target fixture file failed with exit 1")]
fn seed_that_exits_non_zero_is_a_failure() {
    let calls = RefCell::new(Vec::new());
    let mut run = recorded(&calls, vec![exited(1, "")]);
    target_seed_file_with("/root/x/conf", "initial", true, &mut run);
}

#[test]
#[should_panic(expected = "the target fixture file must hold the seeded content")]
fn seed_that_did_not_produce_the_content_is_a_failure() {
    // The seed command "succeeded", but the file does not hold the content.
    let calls = RefCell::new(Vec::new());
    let mut run = recorded(&calls, vec![exited(0, ""), exited(0, "")]);
    target_seed_file_with("/root/x/conf", "initial", true, &mut run);
}

#[test]
#[should_panic(expected = "reading the seeded target fixture file back failed with exit 1")]
fn seed_that_cannot_be_read_back_is_a_failure() {
    let calls = RefCell::new(Vec::new());
    let mut run = recorded(&calls, vec![exited(0, ""), exited(1, "")]);
    target_seed_file_with("/root/x/conf", "initial", true, &mut run);
}
