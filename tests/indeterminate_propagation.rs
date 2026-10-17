//! RW-068 / X-7: a command that was started but whose outcome the controller
//! lost (the completion a failed wait produces) must reach the resource layer
//! as "possible change, outcome unknown" - never as "failed, nothing changed" -
//! and must not be dispatched twice or followed by further changes.
//!
//! The completion is injected below the resource layer (`FakeTarget::
//! program_outputs`), exactly the value `LocalExecutor` returns after a failed
//! wait (its own tests drive a real child through that path). Everything above
//! it - the command resource, fail-fast, dependency blocking and the aggregate
//! status (whose exit-code mapping, 6, is pinned in `json_contract.rs`) - is
//! production code.
#![cfg(unix)]

mod common;

use common::{find, run_recipe_fake, trusted_root, write_recipe};
use sinter::engine::{AggregateStatus, Mode};
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::result::{Change, Disposition, Execution, Verification};

const REASON: &str = "failed to wait for child after dispatch: injected";

fn out(c: Completion) -> Output {
    Output {
        completion: c,
        stdout: b"partial output\n".to_vec(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn lost_wait() -> Output {
    out(Completion::Indeterminate {
        started: true,
        reason: REASON.to_string(),
    })
}

fn target(forced: &[(&str, Output)]) -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404();
    for (p, o) in forced {
        t.executables.insert((*p).to_string());
        t.program_outputs.insert((*p).to_string(), o.clone());
    }
    for p in [
        "/opt/fake/first",
        "/opt/fake/second",
        "/opt/fake/third",
        "/opt/fake/after",
    ] {
        t.executables.insert(p.to_string());
    }
    t
}

const RECIPE: &str = "version: 1
resources:
  - id: first
    type: command
    with:
      program: /opt/fake/first
      register: r1
  - id: second
    type: command
    depends_on: [first]
    with:
      program: /opt/fake/second
  - id: third
    type: command
    with:
      program: /opt/fake/third
  - id: user
    type: command
    depends_on: [first]
    with:
      program: /opt/fake/after
      args: [\"{{ registers.r1.stdout }}\"]
";

fn count(r: &sinter::engine::RunReport, program: &str) -> usize {
    r.commands.iter().filter(|c| c.program == program).count()
}

#[test]
fn a_lost_wait_is_possible_change_and_stops_the_run_without_a_second_dispatch() {
    let dir = trusted_root("indet-prop-command");
    let recipe = write_recipe(&dir, "r.yaml", RECIPE);
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        target(&[("/opt/fake/first", lost_wait())]),
    );

    let first = find(&r, "first");
    assert_eq!(first.execution, Execution::Indeterminate, "{first:?}");
    assert_eq!(
        first.change,
        Change::Possible,
        "must not be 'nothing changed'"
    );
    // A command has no verification step of its own; the contract is NotApplicable.
    assert_eq!(first.verification, Verification::NotApplicable);
    assert_eq!(first.reason.as_deref(), Some(REASON));
    assert_eq!(r.status, AggregateStatus::Indeterminate);

    // Nothing after it ran: every later resource, dependent or not, is blocked.
    for id in ["second", "third", "user"] {
        assert!(
            matches!(
                find(&r, id).disposition,
                Disposition::BlockedByFailFast | Disposition::BlockedByDependency
            ),
            "{id}: {:?}",
            find(&r, id).disposition
        );
        assert_eq!(find(&r, id).execution, Execution::NotRun, "{id}");
        assert_eq!(find(&r, id).change, Change::None, "{id}");
    }

    // Exactly one dispatch of the lost command, and no dispatch of any other
    // program of the recipe.
    assert_eq!(count(&r, "/opt/fake/first"), 1, "no retry");
    for p in ["/opt/fake/second", "/opt/fake/third", "/opt/fake/after"] {
        assert_eq!(count(&r, p), 0, "{p} must not run after an unknown outcome");
    }
    // The last command the run issued is the lost one: nothing mutating followed.
    assert_eq!(r.commands.last().unwrap().program, "/opt/fake/first");
}

#[test]
fn the_register_of_a_lost_command_is_not_usable_by_a_consumer() {
    // `user` reads registers.r1.stdout; it must be blocked, and the partial
    // stdout of the lost command must never reach a later command line.
    let dir = trusted_root("indet-prop-register");
    let recipe = write_recipe(&dir, "r.yaml", RECIPE);
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        target(&[("/opt/fake/first", lost_wait())]),
    );
    assert_eq!(count(&r, "/opt/fake/after"), 0);
    assert!(
        r.commands
            .iter()
            .all(|c| !c.args.iter().any(|a| a.contains("partial output"))),
        "{:?}",
        r.commands
    );
}

#[test]
fn the_same_completion_in_sudo_mode_is_handled_the_same_way() {
    let dir = trusted_root("indet-prop-sudo");
    let recipe = write_recipe(&dir, "r.yaml", RECIPE);
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        true,
        target(&[("/opt/fake/first", lost_wait())]),
    );
    assert_eq!(find(&r, "first").change, Change::Possible);
    assert_eq!(r.status, AggregateStatus::Indeterminate);
    assert_eq!(count(&r, "/opt/fake/first"), 1);
    assert_eq!(count(&r, "/opt/fake/third"), 0);
}

#[test]
fn contrast_a_definite_failure_is_failed_with_no_claim_of_change_only_where_it_is_definite() {
    // A non-zero exit is a definite failure, a signal is "failed, possible change",
    // an unknown outcome is "indeterminate, possible change": three different results.
    let dir = trusted_root("indet-prop-contrast");
    let recipe = write_recipe(&dir, "r.yaml", RECIPE);

    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        target(&[("/opt/fake/first", out(Completion::Exited(3)))]),
    );
    let f = find(&r, "first");
    assert_eq!(f.execution, Execution::Failed);
    assert_eq!(count(&r, "/opt/fake/first"), 1);

    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        target(&[("/opt/fake/first", out(Completion::Signaled(9)))]),
    );
    let f = find(&r, "first");
    assert_eq!(f.execution, Execution::Failed);
    assert_eq!(f.change, Change::Possible);

    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        target(&[("/opt/fake/first", lost_wait())]),
    );
    let f = find(&r, "first");
    assert_eq!(f.execution, Execution::Indeterminate);
    assert_eq!(f.change, Change::Possible);
}

#[test]
fn plan_never_dispatches_the_command_so_the_lost_wait_cannot_occur() {
    let dir = trusted_root("indet-prop-plan");
    let recipe = write_recipe(&dir, "r.yaml", RECIPE);
    let r = run_recipe_fake(
        &recipe,
        Mode::Plan,
        false,
        target(&[("/opt/fake/first", lost_wait())]),
    );
    assert_eq!(count(&r, "/opt/fake/first"), 0);
}
