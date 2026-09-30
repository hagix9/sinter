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

fn script(dir: &Path, name: &str, body: &str) -> String {
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
