//! `--sudo` asks sudo for root explicitly (`sudo -n -u root --`).
//!
//! Without `-u root`, sudo runs a command as the sudoers `runas_default` user,
//! which is root only by default. Sinter treats a `--sudo` run as root, so the
//! wrapper must make sudo either run the command as root or refuse it.
//!
//! What this file checks, on the scripted target ([`FakeTarget`], which runs the
//! production engine, wrapper decision and result code):
//!
//! * the connection matrix: a user with sudo, root with and without `--sudo`, a
//!   user without `--sudo`, and every way sudo can refuse. A site whose sudoers
//!   allows only another user (`runas_default` not root) now gets sudo's
//!   refusal of `-u root`, which Sinter names at connect and never works
//!   around;
//! * that the wrapper costs no command: the same run on the same target sends
//!   as many commands with `--sudo` as without.
//!
//! The command line itself (`-u root` over SSH and locally, quoting, no wrapper
//! for a root target or without `--sudo`) is pinned by unit tests in
//! `src/executor.rs`. What only a real host can show (that a given sudo accepts
//! `-u root` under a given sudoers rule, `(#0)` rules, `targetpw`/`rootpw`,
//! sudo-rs) is not claimed here.
#![cfg(unix)]

use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::{ErrorKind, SinterError};
use sinter::executor::{FakeSudoFailure, FakeTarget};
use sinter::model::load_model;
use std::path::PathBuf;

fn base() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().with_fake_fs();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/etc", 0o755, 0),
        ("/etc/rootfix", 0o755, 0),
        ("/var", 0o755, 0),
        ("/var/lib", 0o755, 0),
        ("/root", 0o700, 0),
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

const BODY: &str = "resources:\n  - id: f\n    type: file\n    with:\n      path: /etc/rootfix/a.conf\n      content: \"a\\n\"\n  - id: d\n    type: directory\n    with:\n      path: /etc/rootfix/d\n";

fn recipe(dir: &tempfile::TempDir) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\n{}", BODY)).unwrap();
    p
}

fn engine(
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

fn run(p: &std::path::Path, mode: Mode, sudo: bool, t: FakeTarget) -> (RunReport, usize) {
    let e = engine(p, mode, sudo, t).unwrap_or_else(|e| panic!("connect: {}", e.message));
    let stats = e.exec_stats();
    let r = e.run().unwrap_or_else(|e| panic!("run: {}", e.message));
    (r, stats.snapshot().total())
}

fn wrapped(r: &RunReport) -> Vec<bool> {
    r.commands.iter().map(|c| c.sudo).collect()
}

#[test]
fn a_user_with_working_sudo_goes_through_the_wrapper() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir);
    for mode in [Mode::Plan, Mode::Apply] {
        let (r, _) = run(&p, mode, true, user_target());
        assert_eq!(r.status, AggregateStatus::Success, "{:?}", mode);
        assert!(!wrapped(&r).is_empty());
        assert!(wrapped(&r).iter().all(|w| *w), "{:?}", mode);
    }
}

#[test]
fn root_with_and_without_the_flag_never_uses_the_wrapper() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir);
    for sudo in [true, false] {
        for mode in [Mode::Plan, Mode::Apply] {
            // Even a sudo that refuses everything is never reached.
            let t = root_target().with_sudo_failure(FakeSudoFailure::NotAuthorized);
            let (r, _) = run(&p, mode, sudo, t);
            assert_eq!(r.status, AggregateStatus::Success, "{sudo} {:?}", mode);
            assert!(wrapped(&r).iter().all(|w| !*w), "{sudo} {:?}", mode);
        }
    }
}

#[test]
fn a_user_without_the_flag_never_uses_the_wrapper() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir);
    let t = user_target().with_sudo_failure(FakeSudoFailure::NotAuthorized);
    let (r, _) = run(&p, Mode::Plan, false, t);
    assert!(wrapped(&r).iter().all(|w| !*w));
}

#[test]
fn every_way_sudo_can_refuse_stops_the_run_at_connect_in_every_mode() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir);
    // (failure, what the error says)
    let cases = [
        (FakeSudoFailure::Missing, "sudo is not installed"),
        (FakeSudoFailure::PasswordRequired, "a password is required"),
        // sudoers does not allow this user to run commands as root: no rule at
        // all for root, or (runas_default not root) a rule that allows another
        // user only, which `-u root` makes sudo refuse.
        (
            FakeSudoFailure::NotAuthorized,
            "sudoers does not allow this user to run commands as root",
        ),
        (
            FakeSudoFailure::Unrecognized,
            "The cause was not identified",
        ),
    ];
    for (failure, want) in cases {
        for mode in [Mode::Plan, Mode::Apply] {
            let e = match engine(&p, mode, true, user_target().with_sudo_failure(failure)) {
                Ok(_) => panic!("{:?} {:?}: connect must fail", failure, mode),
                Err(e) => e,
            };
            assert_eq!(e.kind, ErrorKind::Connect, "{:?} {:?}", failure, mode);
            assert!(e.message.contains(want), "{:?}: {}", failure, e.message);
            // Never "not Linux", never a retry without sudo.
            assert!(
                !e.message.contains("supported Linux system"),
                "{:?}: {}",
                failure,
                e.message
            );
        }
    }
}

#[test]
fn the_wrapper_costs_no_command() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir);
    for mode in [Mode::Plan, Mode::Apply] {
        let (with_sudo, n_sudo) = run(&p, mode, true, user_target());
        let (without, n_plain) = run(&p, mode, false, user_target());
        assert_eq!(n_sudo, n_plain, "{:?}: statistics", mode);
        assert_eq!(
            with_sudo.commands.len(),
            without.commands.len(),
            "{:?}: command log",
            mode
        );
        let programs = |r: &RunReport| {
            r.commands
                .iter()
                .map(|c| c.program.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(programs(&with_sudo), programs(&without), "{:?}", mode);
    }
}
