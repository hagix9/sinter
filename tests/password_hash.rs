//! `user.password_hash: { secret: <path> }` (Phase D) tests.
//!
//! The production model, engine, account, audit and output code runs against
//! the scripted in-process target ([`FakeTarget`]) with an injected secret
//! source. The scripted shadow-utils model follows the documented facts the
//! contract rests on: `chpasswd -e` reads `name:hash` lines on standard input,
//! needs root, validates nothing; `getent -s files shadow` is readable by root
//! only. What only a real Linux host can prove (the real `chpasswd`, real
//! `/etc/shadow` modes, sudo and sudo-rs stdin pass-through) is
//! `PENDING REAL-OS ACCEPTANCE` and is not claimed here.
#![cfg(unix)]
mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::model::load_model;
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::{Change, DiffBody, Execution, Verification};
use sinter::secret_source::{ProcessSecrets, SharedSecrets};
use sinter::secrets::{self};
use sinter::secrets_cli::{Env, Prompter};
use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const PASS: &str = "canary hash passphrase 3b7e-5d20";

fn b64(n: usize, seed: usize) -> String {
    const A: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    (0..n)
        .map(|i| A[(i * 7 + seed) % A.len()] as char)
        .collect()
}

/// A well-formed sha512crypt hash; `seed` makes distinct ones.
fn sha(seed: usize) -> String {
    format!("$6${}${}", b64(8, seed), b64(86, seed + 3))
}

fn yes(seed: usize) -> String {
    format!("$y$j9T${}${}", b64(22, seed), b64(43, seed + 5))
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

struct Quiet(Rc<RefCell<Vec<u8>>>);

impl Write for Quiet {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct NoTty;

impl Prompter for NoTty {
    fn interactive(&self) -> bool {
        false
    }
    fn read_secret(&mut self, _p: &str) -> std::io::Result<zeroize::Zeroizing<String>> {
        Err(std::io::ErrorKind::UnexpectedEof.into())
    }
    fn read_line(&mut self, _p: &str) -> std::io::Result<String> {
        Err(std::io::ErrorKind::UnexpectedEof.into())
    }
}

struct Fx {
    dir: PathBuf,
    key: PathBuf,
    recipient: secrets::Recipient,
    key_text: String,
}

fn fx(label: &str) -> Fx {
    let dir = trusted_root(label);
    std::fs::create_dir_all(dir.join("secrets")).unwrap();
    let id = secrets::generate_identity();
    let key = dir.join("key.txt");
    std::fs::write(&key, id.identity_file.expose()).unwrap();
    set_mode(&key, 0o600);
    Fx {
        key,
        recipient: id.recipient,
        key_text: String::from_utf8(id.identity_file.expose().to_vec()).unwrap(),
        dir,
    }
}

impl Fx {
    /// Encrypt `plain` as `secrets/<name>`.
    fn put(&self, name: &str, plain: &[u8]) {
        let ct =
            secrets::encrypt_to_recipients(plain, std::slice::from_ref(&self.recipient)).unwrap();
        std::fs::write(self.dir.join("secrets").join(name), ct).unwrap();
    }

    fn env(&self, with_key: bool) -> Env {
        Env {
            identity_env: with_key.then(|| self.key.clone().into_os_string()),
            xdg_config_home: None,
            home: Some(self.dir.join("home")),
            cwd: self.dir.clone(),
            euid: unsafe { libc::geteuid() },
        }
    }

    fn src(&self, with_key: bool) -> (SharedSecrets, Rc<RefCell<Vec<u8>>>) {
        let notes = Rc::new(RefCell::new(Vec::new()));
        let s: SharedSecrets = Rc::new(RefCell::new(ProcessSecrets::new(
            self.env(with_key),
            Box::new(NoTty),
            Box::new(Quiet(notes.clone())),
        )));
        (s, notes)
    }

    fn recipe(&self, body: &str) -> PathBuf {
        write_recipe(
            &self.dir,
            "r.yaml",
            &format!("version: 1\nresources:\n{}", body),
        )
    }

    /// One user resource `u` for `app` with `extra` fields.
    fn user(&self, extra: &str) -> PathBuf {
        self.recipe(&user_res("u", "app", "secrets/pw.age", extra))
    }
}

fn user_res(id: &str, name: &str, secret: &str, extra: &str) -> String {
    format!(
        "  - id: {id}\n    type: user\n    with:\n      name: {name}\n      password_hash: {{ secret: {secret} }}\n{extra}",
        id = id,
        name = name,
        secret = secret,
        extra = extra
    )
}

/// A scripted target with an existing local user `app` (uid 990, shell nologin).
fn target() -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("app", 990)
        .with_user("app", 990, 990, "/home/app", "/usr/sbin/nologin")
}

/// No `app` yet.
fn empty_target() -> FakeTarget {
    FakeTarget::ubuntu2404().with_fake_fs()
}

fn engine(
    r: &Path,
    mode: Mode,
    sudo: bool,
    src: Option<SharedSecrets>,
    t: FakeTarget,
) -> Result<Engine, SinterError> {
    let model = load_model(r)?;
    let opts = RunOptions {
        mode,
        sudo,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(t),
    };
    let e = Engine::new(model, opts)?;
    Ok(match src {
        Some(s) => e.with_secrets(s),
        None => e,
    })
}

fn run(
    r: &Path,
    mode: Mode,
    sudo: bool,
    src: Option<SharedSecrets>,
    t: &FakeTarget,
) -> Result<RunReport, SinterError> {
    engine(r, mode, sudo, src, t.clone())?.run()
}

fn audit(r: &Path, sudo: bool, src: Option<SharedSecrets>, t: &FakeTarget) -> AuditReport {
    sinter::audit::run_audit(engine(r, Mode::Plan, sudo, src, t.clone()).unwrap()).unwrap()
}

/// The modeled account commands the target received, as `prog args`.
fn calls(t: &FakeTarget) -> Vec<String> {
    t.accounts
        .calls
        .lock()
        .unwrap()
        .iter()
        .map(|(p, a, _)| format!("{} {}", p, a.join(" ")).trim().to_string())
        .collect()
}

/// The exact standard inputs `chpasswd` received.
fn chpasswd_inputs(t: &FakeTarget) -> Vec<String> {
    t.accounts
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(p, _, _)| p == "chpasswd")
        .map(|(_, _, i)| String::from_utf8_lossy(i.as_deref().unwrap_or(b"")).to_string())
        .collect()
}

fn ran(t: &FakeTarget, prog: &str) -> usize {
    t.accounts
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(p, _, _)| p == prog)
        .count()
}

fn surfaces(rep: &RunReport, mode: &str) -> Vec<String> {
    let mut v = Vec::new();
    for fmt in [OutputFormat::Text, OutputFormat::Json] {
        let ro = RenderOptions {
            verbose: true,
            format: fmt,
            color: false,
        };
        let mut b = Vec::new();
        if mode == "plan" {
            sinter::output::render_plan(rep, &ro, &mut b).unwrap();
        } else {
            sinter::output::render_apply(rep, &ro, &mut b).unwrap();
        }
        v.push(String::from_utf8_lossy(&b).to_string());
    }
    v.push(sinter::output::run_report_json(rep, mode).to_string());
    v.push(format!("{:?}", rep.resources));
    v.push(format!("{:?}", rep.commands));
    v
}

fn audit_surfaces(rep: &AuditReport) -> Vec<String> {
    let mut v = vec![
        rep.render_text(),
        sinter::output::audit_report_json(rep).to_string(),
        format!("{:?}", rep.resources),
    ];
    for fmt in [OutputFormat::Text, OutputFormat::Json] {
        let ro = RenderOptions {
            verbose: true,
            format: fmt,
            color: false,
        };
        let mut b = Vec::new();
        sinter::output::render_audit(rep, &ro, &mut b).unwrap();
        v.push(String::from_utf8_lossy(&b).to_string());
    }
    v
}

/// No hash (desired or stored), no identity and no passphrase on any surface.
fn clean(f: &Fx, hashes: &[&str], texts: &[String]) {
    for t in texts {
        for h in hashes {
            // the whole value and its salt-free body
            for needle in [*h, h.rsplit('$').next().unwrap_or(h)] {
                assert!(!t.contains(needle), "leaked a hash in: {}", t);
            }
        }
        for needle in [PASS, "AGE-SECRET-KEY-", f.key_text.trim()] {
            assert!(!t.contains(needle), "leaked {:?} in: {}", needle, t);
        }
    }
}

fn err_text(r: Result<RunReport, SinterError>) -> String {
    match r {
        Err(e) => e.message,
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
            rep.resources[0].reason.clone().unwrap_or_default()
        }
    }
}

// ---------------------------------------------------------------------------
// schema / validate
// ---------------------------------------------------------------------------

#[test]
fn a_reference_loads_without_any_key_and_makes_the_user_sensitive() {
    let f = fx("pw-load");
    f.put("pw.age", sha(1).as_bytes());
    let m = load_model(&f.user("")).unwrap();
    let fr = &m.resources[0];
    assert!(fr.secret.is_some());
    assert!(fr.derived_sensitive);
}

#[test]
fn only_a_secret_reference_is_accepted_as_password_hash() {
    let f = fx("pw-schema");
    f.put("pw.age", sha(1).as_bytes());
    let h = sha(2);
    for (with, want) in [
        (
            format!("      password_hash: \"{}\"\n", h),
            "password_hash must be",
        ),
        (
            "      password_hash: hunter2hunter2\n".to_string(),
            "password_hash must be",
        ),
        (
            "      password_hash: 5\n".to_string(),
            "password_hash must be",
        ),
        (
            "      password_hash: [a]\n".to_string(),
            "password_hash must be",
        ),
        (
            "      password_hash: { secret: 1 }\n".to_string(),
            "password_hash must be",
        ),
        (
            "      password_hash: { other: secrets/pw.age }\n".to_string(),
            "password_hash must be",
        ),
        (
            "      password_hash: { secret: secrets/pw.age, x: y }\n".to_string(),
            "password_hash must be",
        ),
        ("      password: hunter2\n".to_string(), "password"),
        (
            "      password_hash: { secret: ../pw.age }\n".to_string(),
            "'..'",
        ),
        (
            "      password_hash: { secret: /etc/shadow }\n".to_string(),
            "relative",
        ),
        (
            "      password_hash: { secret: secrets/missing.age }\n".to_string(),
            "not found",
        ),
        (
            "      password_hash: \"{{ vars.h }}\"\n".to_string(),
            "password_hash must be",
        ),
    ] {
        let r = f.recipe(&format!(
            "  - id: u\n    type: user\n    with:\n      name: app\n{}",
            with
        ));
        let e = load_model(&r)
            .err()
            .unwrap_or_else(|| panic!("accepted {}", with));
        assert!(e.message.contains(want), "{:?}: {}", with, e.message);
        assert!(!e.message.contains(&h), "{}", e.message);
    }
    // password_hash with a literal `state: absent` is contradictory
    let r = f.user("      state: absent\n");
    assert!(load_model(&r)
        .err()
        .unwrap()
        .message
        .contains("state: absent"));
    // a group resource has no password_hash
    let r = f.recipe(
        "  - id: g\n    type: group\n    with:\n      name: app\n      password_hash: { secret: secrets/pw.age }\n",
    );
    assert!(load_model(&r).is_err());
}

#[test]
fn a_sensitive_user_redacts_reference_errors() {
    let f = fx("pw-redact-ref");
    let r = f.recipe(
        "  - id: u\n    sensitive: true\n    type: user\n    with:\n      name: app\n      password_hash: { secret: secrets/missing-CANARYNAME.age }\n",
    );
    let e = load_model(&r).err().unwrap().message;
    assert!(
        e.contains("value redacted") && !e.contains("CANARYNAME"),
        "{}",
        e
    );
}

// ---------------------------------------------------------------------------
// apply / idempotence / drift
// ---------------------------------------------------------------------------

#[test]
fn setting_a_password_on_an_existing_user_runs_exactly_one_chpasswd() {
    let f = fx("pw-apply");
    let want = sha(1);
    f.put("pw.age", format!("{}\n", want).as_bytes());
    let r = f.user("");
    let (src, notes) = f.src(true);

    let t = target(); // field `!`: no password yet
    let plan = run(&r, Mode::Plan, true, Some(src.clone()), &t).unwrap();
    let p = &plan.resources[0];
    assert_eq!(p.change, Change::Changed);
    assert!(p.sensitive);
    assert!(matches!(p.diff.as_ref().unwrap().body, DiffBody::Redacted));
    assert!(
        calls(&t).is_empty(),
        "plan runs no account command: {:?}",
        calls(&t)
    );
    clean(&f, &[&want], &surfaces(&plan, "plan"));

    let applied = run(&r, Mode::Apply, true, Some(src), &t).unwrap();
    let a = &applied.resources[0];
    assert_eq!(a.execution, Execution::Succeeded);
    assert_eq!(a.verification, Verification::Verified);
    assert_eq!(a.change, Change::Changed);
    // exact mechanism: one chpasswd -e, hash on stdin as `name:hash\n`, and
    // nothing else mutated
    assert_eq!(calls(&t), vec!["chpasswd -e".to_string()]);
    assert_eq!(chpasswd_inputs(&t), vec![format!("app:{}\n", want)]);
    clean(&f, &[&want], &surfaces(&applied, "apply"));
    let n = String::from_utf8_lossy(&notes.borrow()).to_string();
    clean(&f, &[&want], &[n]);
}

#[test]
fn a_converged_user_is_a_no_op_in_plan_apply_and_audit() {
    let f = fx("pw-idem");
    let want = sha(1);
    f.put("pw.age", want.as_bytes());
    let r = f.user("");
    let (src, _) = f.src(true);
    let t = target().with_shadow("app", &want);

    let plan = run(&r, Mode::Plan, true, Some(src.clone()), &t).unwrap();
    assert_eq!(plan.resources[0].change, Change::None);
    let applied = run(&r, Mode::Apply, true, Some(src.clone()), &t).unwrap();
    assert_eq!(applied.resources[0].change, Change::None);
    assert!(calls(&t).is_empty(), "{:?}", calls(&t));
    let a = audit(&r, true, Some(src), &t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
    clean(&f, &[&want], &audit_surfaces(&a));
}

#[test]
fn a_different_hash_is_replaced_by_chpasswd_alone() {
    let f = fx("pw-drift");
    let (want, old) = (sha(1), sha(9));
    f.put("pw.age", want.as_bytes());
    let r = f.user("");
    let (src, _) = f.src(true);
    let t = target().with_shadow("app", &old);

    let a = audit(&r, true, Some(src.clone()), &t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert_eq!(a.exit_code(), 7);
    let d = &a.resources[0].details;
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].dimension, "password_hash");
    clean(&f, &[&want, &old], &audit_surfaces(&a));

    let plan = run(&r, Mode::Plan, true, Some(src.clone()), &t).unwrap();
    assert_eq!(plan.resources[0].change, Change::Changed);
    clean(&f, &[&want, &old], &surfaces(&plan, "plan"));
    let applied = run(&r, Mode::Apply, true, Some(src), &t).unwrap();
    assert_eq!(applied.resources[0].verification, Verification::Verified);
    assert_eq!(
        calls(&t),
        vec!["chpasswd -e".to_string()],
        "no usermod for a password-only change"
    );
    assert_eq!(chpasswd_inputs(&t), vec![format!("app:{}\n", want)]);
    clean(&f, &[&want, &old], &surfaces(&applied, "apply"));
}

#[test]
fn every_no_password_state_is_set_normally() {
    let f = fx("pw-nopw");
    let want = sha(1);
    f.put("pw.age", want.as_bytes());
    let r = f.user("");
    for field in ["", "!", "!!", "*", "!*"] {
        let (src, _) = f.src(true);
        let t = target().with_shadow("app", field);
        let rep = run(&r, Mode::Apply, true, Some(src), &t).unwrap();
        assert_eq!(
            rep.resources[0].verification,
            Verification::Verified,
            "{:?}",
            field
        );
        assert_eq!(
            chpasswd_inputs(&t),
            vec![format!("app:{}\n", want)],
            "{:?}",
            field
        );
    }
}

#[test]
fn a_locked_account_keeps_its_lock_and_is_never_silently_unlocked() {
    let f = fx("pw-locked");
    let (want, other) = (sha(1), sha(9));
    f.put("pw.age", want.as_bytes());
    let r = f.user("");
    let (src, _) = f.src(true);

    // same hash, locked: the lock marker is ignored, nothing to do
    let t = target().with_shadow("app", &format!("!{}", want));
    let rep = run(&r, Mode::Apply, true, Some(src.clone()), &t).unwrap();
    assert_eq!(rep.resources[0].change, Change::None);
    assert!(calls(&t).is_empty());
    assert_eq!(
        audit(&r, true, Some(src.clone()), &t).resources[0].status,
        AuditResourceStatus::Compliant
    );

    // different hash, locked: chpasswd -e would drop the `!` and unlock it
    let t = target().with_shadow("app", &format!("!{}", other));
    for mode in [Mode::Plan, Mode::Apply] {
        let text = err_text(run(&r, mode, true, Some(src.clone()), &t));
        assert!(text.contains("locked"), "{}", text);
        clean(&f, &[&want, &other], &[text]);
    }
    assert!(calls(&t).is_empty(), "nothing may run: {:?}", calls(&t));
    // audit still reports the drift truthfully
    let a = audit(&r, true, Some(src), &t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
}

#[test]
fn creating_a_user_sets_the_password_after_useradd() {
    let f = fx("pw-create");
    let want = sha(1);
    f.put("pw.age", want.as_bytes());
    let r = f.recipe(&user_res(
        "u",
        "app",
        "secrets/pw.age",
        "      shell: /usr/sbin/nologin\n",
    ));
    let (src, _) = f.src(true);
    let t = empty_target();

    let plan = run(&r, Mode::Plan, true, Some(src.clone()), &t).unwrap();
    assert_eq!(plan.resources[0].change, Change::Changed);
    assert!(calls(&t).is_empty());
    let rep = run(&r, Mode::Apply, true, Some(src), &t).unwrap();
    assert_eq!(rep.resources[0].verification, Verification::Verified);
    let c = calls(&t);
    assert_eq!(c.len(), 2, "{:?}", c);
    assert!(
        c[0].starts_with("useradd ") && c[0].ends_with(" app"),
        "{:?}",
        c
    );
    assert!(
        !c[0].contains("$6$") && !c[1].contains("$6$"),
        "no hash on argv: {:?}",
        c
    );
    assert_eq!(c[1], "chpasswd -e");
    assert_eq!(chpasswd_inputs(&t), vec![format!("app:{}\n", want)]);
    clean(&f, &[&want], &surfaces(&rep, "apply"));
}

#[test]
fn account_changes_come_before_the_password() {
    let f = fx("pw-order");
    let want = sha(1);
    f.put("pw.age", want.as_bytes());
    let r = f.user("      shell: /bin/sh\n");
    let (src, _) = f.src(true);
    let t = target(); // shell nologin, no password
    let rep = run(&r, Mode::Apply, true, Some(src), &t).unwrap();
    assert_eq!(rep.resources[0].verification, Verification::Verified);
    let c = calls(&t);
    assert_eq!(c.len(), 2, "{:?}", c);
    assert!(c[0].starts_with("usermod "), "{:?}", c);
    assert_eq!(c[1], "chpasswd -e");
}

#[test]
fn a_failed_chpasswd_after_useradd_is_reported_as_a_partial_change() {
    let f = fx("pw-partial");
    f.put("pw.age", sha(1).as_bytes());
    let r = f.user("");
    let (src, _) = f.src(true);
    let mut t = empty_target();
    t.accounts.forced.insert(
        "chpasswd".into(),
        Output {
            completion: Completion::Exited(1),
            stdout: Vec::new(),
            stderr: b"chpasswd: (line 1, user app) password not changed CANARY-STDERR".to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    );
    let rep = run(&r, Mode::Apply, true, Some(src), &t).unwrap();
    let x = &rep.resources[0];
    assert_eq!(x.execution, Execution::Failed);
    assert_eq!(x.change, Change::Changed, "the account was created");
    assert_ne!(x.verification, Verification::Verified);
    let reason = x.reason.clone().unwrap_or_default();
    assert!(reason.contains("password could not be set"), "{}", reason);
    assert_eq!(ran(&t, "useradd"), 1);
    // a sensitive resource never forwards the tool's stderr
    for s in surfaces(&rep, "apply") {
        assert!(!s.contains("CANARY-STDERR"), "{}", s);
    }
}

#[test]
fn a_failed_password_only_change_is_not_reported_as_done() {
    let f = fx("pw-fail");
    f.put("pw.age", sha(1).as_bytes());
    let r = f.user("");
    let (src, _) = f.src(true);
    let mut t = target();
    t.accounts.fail_after_effect.insert("chpasswd".into());
    let rep = run(&r, Mode::Apply, true, Some(src), &t).unwrap();
    let x = &rep.resources[0];
    assert_eq!(x.execution, Execution::Failed);
    assert_ne!(x.verification, Verification::Verified);
    assert_ne!(rep.status, AggregateStatus::Success);
}

#[test]
#[should_panic(expected = "leaked a hash")]
fn the_leak_detector_would_see_a_hash() {
    // Control for `clean`: it must fail when a hash is on a surface.
    let f = fx("pw-control");
    let h = sha(1);
    clean(&f, &[&h], &[format!("password is {}", h)]);
}

#[test]
fn an_absent_user_is_drift_in_audit_and_a_create_in_plan() {
    let f = fx("pw-absent");
    f.put("pw.age", sha(1).as_bytes());
    let r = f.user("");
    let (src, _) = f.src(true);
    let t = empty_target();
    let a = audit(&r, true, Some(src.clone()), &t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert_eq!(a.resources[0].details[0].dimension, "state");
    let p = run(&r, Mode::Plan, true, Some(src), &t).unwrap();
    assert_eq!(p.resources[0].change, Change::Changed);
    assert!(calls(&t).is_empty());
}

// ---------------------------------------------------------------------------
// privilege, platform, hash format
// ---------------------------------------------------------------------------

#[test]
fn password_hash_needs_sudo_in_plan_apply_and_audit_never_no_change() {
    let f = fx("pw-sudo");
    f.put("pw.age", sha(1).as_bytes());
    let r = f.user("");
    // No key at all: if the secret were opened before the sudo check, the
    // source would write a "no identity found" diagnostic.
    let (src, shared_notes) = f.src(false);
    let t = target().with_shadow("app", &sha(1)); // would otherwise be a no-op
    for mode in [Mode::Plan, Mode::Apply] {
        let text = err_text(run(&r, mode, false, Some(src.clone()), &t));
        assert!(text.contains("--sudo"), "{}", text);
    }
    let a = audit(&r, false, Some(src), &t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
    assert_ne!(a.exit_code(), 0);
    assert!(calls(&t).is_empty());
    // the secret was never opened without sudo
    assert!(shared_notes.borrow().is_empty());
}

#[test]
fn an_unreadable_shadow_record_is_an_error_not_a_no_change() {
    let f = fx("pw-shadow-read");
    f.put("pw.age", sha(1).as_bytes());
    let r = f.user("");
    let (src, _) = f.src(true);

    let mut missing = target();
    missing.accounts.no_shadow_users.insert("app".into());
    let mut denied = target();
    denied.accounts.forced_shadow = Some(Output {
        completion: Completion::Exited(1),
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    });
    let mut garbled = target();
    garbled.accounts.forced_shadow = Some(Output {
        completion: Completion::Exited(0),
        stdout: b"someone-else:$6$x:1::::::\n".to_vec(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    });
    for (name, t) in [
        ("missing", missing),
        ("denied", denied),
        ("garbled", garbled),
    ] {
        for mode in [Mode::Plan, Mode::Apply] {
            let text = err_text(run(&r, mode, true, Some(src.clone()), &t));
            assert!(
                text.contains("password database"),
                "{} {:?}: {}",
                name,
                mode,
                text
            );
            clean(&f, &[], &[text]);
        }
        assert_eq!(ran(&t, "chpasswd"), 0, "{}", name);
        let a = audit(&r, true, Some(src.clone()), &t);
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Error,
            "{}",
            name
        );
    }
}

#[test]
fn a_non_local_user_is_refused_and_nothing_is_written() {
    let f = fx("pw-nss");
    f.put("pw.age", sha(1).as_bytes());
    let r = f.user("");
    let (src, _) = f.src(true);
    let mut t = empty_target();
    t.accounts.nss_users.push(sinter::fakesys::FakeUser {
        name: "app".into(),
        uid: 5000,
        gid: 5000,
        home: "/home/app".into(),
        shell: "/bin/sh".into(),
    });
    let text = err_text(run(&r, Mode::Apply, true, Some(src), &t));
    assert!(
        text.contains("NSS") || text.contains("non-local"),
        "{}",
        text
    );
    assert!(calls(&t).is_empty());
}

#[test]
fn yescrypt_is_refused_on_el9_and_accepted_elsewhere() {
    let f = fx("pw-el9");
    let y = yes(4);
    f.put("pw.age", y.as_bytes());
    let r = f.user("");
    let (src, _) = f.src(true);

    let mut el9 = FakeTarget::rocky9()
        .with_fake_fs()
        .with_group("app", 990)
        .with_user("app", 990, 990, "/home/app", "/usr/sbin/nologin");
    el9.accounts.initial_shadow = "!!".into();
    for mode in [Mode::Plan, Mode::Apply] {
        let text = err_text(run(&r, mode, true, Some(src.clone()), &el9));
        assert!(text.contains("not supported"), "{}", text);
        clean(&f, &[&y], &[text]);
    }
    assert_eq!(ran(&el9, "chpasswd"), 0);

    // $6$ is fine on EL9
    let g = fx("pw-el9-sha");
    let s = sha(2);
    g.put("pw.age", s.as_bytes());
    let (src2, _) = g.src(true);
    let rep = run(&g.user(""), Mode::Apply, true, Some(src2), &el9).unwrap();
    assert_eq!(rep.resources[0].verification, Verification::Verified);
    assert_eq!(chpasswd_inputs(&el9), vec![format!("app:{}\n", s)]);

    // yescrypt works on Ubuntu / EL10
    for t in [target(), {
        FakeTarget::rocky10()
            .with_fake_fs()
            .with_group("app", 990)
            .with_user("app", 990, 990, "/home/app", "/usr/sbin/nologin")
    }] {
        let (src3, _) = f.src(true);
        let rep = run(&r, Mode::Apply, true, Some(src3), &t).unwrap();
        assert_eq!(rep.resources[0].verification, Verification::Verified);
        assert_eq!(chpasswd_inputs(&t), vec![format!("app:{}\n", y)]);
    }
}

#[test]
fn a_secret_that_is_not_an_accepted_hash_is_refused_without_echoing_it() {
    let f = fx("pw-badhash");
    let r = f.user("");
    for bad in [
        "hunter2hunter2-CANARYPW".to_string(),
        format!("{} extra", sha(1)),
        format!("{}\n\n", sha(1)),
        format!("!{}", sha(1)),
        "$1$salt$abcdefghijklmnopqrstuv".to_string(),
        "$5$salt$abcdefghijklmnopqrstuvwxyzabcdefghijklmnopq".to_string(),
        String::new(),
    ] {
        f.put("pw.age", bad.as_bytes());
        let (src, _) = f.src(true);
        let t = target();
        for mode in [Mode::Plan, Mode::Apply] {
            let text = err_text(run(&r, mode, true, Some(src.clone()), &t));
            assert!(
                text.contains("not an accepted password hash"),
                "{:?}: {}",
                bad,
                text
            );
            assert!(!text.contains("CANARYPW"), "{}", text);
        }
        assert!(calls(&t).is_empty());
        let a = audit(&r, true, Some(src), &t);
        assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
        for s in audit_surfaces(&a) {
            assert!(!s.contains("CANARYPW"), "{}", s);
        }
    }
}

// ---------------------------------------------------------------------------
// the secret itself: unavailable / wrong / damaged keys, confinement
// ---------------------------------------------------------------------------

#[test]
fn an_unavailable_wrong_or_damaged_key_fails_closed_without_touching_the_account() {
    let f = fx("pw-keys");
    let want = sha(1);
    f.put("pw.age", want.as_bytes());
    let r = f.user("");

    let other = secrets::generate_identity();
    let wrong = f.dir.join("wrong.txt");
    std::fs::write(&wrong, other.identity_file.expose()).unwrap();
    set_mode(&wrong, 0o600);
    let mut env = f.env(true);
    env.identity_env = Some(wrong.into_os_string());
    let notes = Rc::new(RefCell::new(Vec::new()));
    let wrong_src: SharedSecrets = Rc::new(RefCell::new(ProcessSecrets::new(
        env,
        Box::new(NoTty),
        Box::new(Quiet(notes)),
    )));
    let (bare, bare_notes) = f.src(false);

    for (name, s) in [
        ("wrong", Some(wrong_src)),
        ("none", Some(bare)),
        ("no source", None),
    ] {
        let t = target();
        for mode in [Mode::Plan, Mode::Apply] {
            let text = err_text(run(&r, mode, true, s.clone(), &t));
            assert!(
                text.contains("secret unavailable"),
                "{} {:?}: {}",
                name,
                mode,
                text
            );
            clean(&f, &[&want], &[text]);
        }
        assert!(calls(&t).is_empty(), "{}: {:?}", name, calls(&t));
        let a = audit(&r, true, s, &t);
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Error,
            "{}",
            name
        );
        assert_ne!(a.exit_code(), 0);
        clean(&f, &[&want], &audit_surfaces(&a));
    }
    // the operator learns the cause on the diagnostics channel
    let n = String::from_utf8_lossy(&bare_notes.borrow()).to_string();
    assert!(n.contains("no identity found"), "{}", n);
    clean(&f, &[&want], &[n]);

    // damaged ciphertext after loading
    let p = f.dir.join("secrets/pw.age");
    let mut ct = std::fs::read(&p).unwrap();
    let n = ct.len();
    ct[n - 5] ^= 0x55;
    std::fs::write(&p, &ct).unwrap();
    let (good, _) = f.src(true);
    let t = target();
    let text = err_text(run(&r, Mode::Apply, true, Some(good), &t));
    assert!(text.contains("secret unavailable"), "{}", text);
    assert!(calls(&t).is_empty());
}

#[test]
fn a_secret_swapped_for_a_symlink_after_loading_is_refused() {
    let f = fx("pw-toctou");
    f.put("pw.age", sha(1).as_bytes());
    let r = f.user("");
    let (src, _) = f.src(true);
    let t = target();
    let eng = engine(&r, Mode::Apply, true, Some(src), t.clone()).unwrap();
    let other = f.dir.join("other.age");
    std::fs::copy(f.dir.join("secrets/pw.age"), &other).unwrap();
    std::fs::remove_file(f.dir.join("secrets/pw.age")).unwrap();
    std::os::unix::fs::symlink(&other, f.dir.join("secrets/pw.age")).unwrap();
    let text = err_text(eng.run());
    assert!(text.contains("symbolic link"), "{}", text);
    assert!(calls(&t).is_empty());
}

#[test]
fn an_interpolated_state_that_evaluates_to_absent_is_refused_at_run_time() {
    let f = fx("pw-interp-absent");
    f.put("pw.age", sha(1).as_bytes());
    let r = write_recipe(
        &f.dir,
        "r.yaml",
        "version: 1\nvars:\n  s:\n    value: absent\nresources:\n  - id: u\n    type: user\n    with:\n      name: app\n      state: \"{{ vars.s }}\"\n      password_hash: { secret: secrets/pw.age }\n",
    );
    let (src, _) = f.src(true);
    let t = target();
    for mode in [Mode::Plan, Mode::Apply] {
        let text = err_text(run(&r, mode, true, Some(src.clone()), &t));
        assert!(text.contains("state: absent"), "{}", text);
    }
    assert!(calls(&t).is_empty());
}

#[test]
fn a_user_without_password_hash_is_unchanged_by_phase_d() {
    // no secret, no sudo, no shadow read: Phase `user` behavior is untouched
    let f = fx("pw-none");
    let r =
        f.recipe("  - id: u\n    type: user\n    with:\n      name: app\n      shell: /bin/sh\n");
    let t = target();
    let rep = run(&r, Mode::Apply, false, None, &t).unwrap();
    assert_eq!(rep.resources[0].verification, Verification::Verified);
    assert_eq!(ran(&t, "chpasswd"), 0);
    assert_eq!(ran(&t, "usermod"), 1);
}

#[test]
fn a_skipped_user_never_opens_its_secret() {
    let f = fx("pw-when");
    f.put("pw.age", sha(1).as_bytes());
    let r = f.recipe(
        "  - id: u\n    type: user\n    when: facts.os.family == \"redhat\"\n    with:\n      name: app\n      password_hash: { secret: secrets/pw.age }\n",
    );
    let (src, notes) = f.src(false);
    let t = target();
    let rep = run(&r, Mode::Apply, true, Some(src), &t).unwrap();
    assert_eq!(rep.resources[0].execution, Execution::NotRun);
    assert!(notes.borrow().is_empty());
}

// ---------------------------------------------------------------------------
// real binary and MCP
// ---------------------------------------------------------------------------

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sinter")
}

#[test]
fn the_binary_validates_a_user_secret_without_decrypting() {
    use std::os::unix::process::CommandExt;
    let f = fx("pw-bin");
    f.put("pw.age", sha(1).as_bytes());
    let r = f.user("");
    for env in [None, Some("/nonexistent/identity")] {
        let mut c = std::process::Command::new(bin());
        c.env_clear()
            .env("HOME", f.dir.join("home"))
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        if let Some(v) = env {
            c.env("SINTER_IDENTITY", v);
        }
        let o = c.args(["validate", r.to_str().unwrap()]).output().unwrap();
        assert_eq!(o.status.code(), Some(0), "{:?}", o);
    }
}

#[test]
fn mcp_refuses_a_password_hash_secret_in_manifest_text() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    let mut child = Command::new(bin())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut call = |v: serde_json::Value| -> serde_json::Value {
        writeln!(stdin, "{}", v).unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    };
    call(
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
    );
    let manifest = "version: 1\nresources:\n  - id: u\n    type: user\n    with:\n      name: app\n      password_hash: { secret: secrets/CANARYREF.age }\n";
    for (i, tool) in [
        "sinter_validate_manifest",
        "sinter_inspect_manifest",
        "sinter_plan",
        "sinter_plan_host",
        "sinter_audit_host",
    ]
    .iter()
    .enumerate()
    {
        let resp = call(
            serde_json::json!({"jsonrpc":"2.0","id":10 + i,"method":"tools/call","params":{
            "name": tool, "arguments": {"manifest": manifest, "target": "ubuntu2404"}}}),
        );
        let body = resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(resp["result"]["isError"], true, "{}: {}", tool, body);
        assert!(body.contains("encrypted secrets"), "{}: {}", tool, body);
        assert!(!body.contains("CANARYREF"), "{}: {}", tool, body);
    }
    let _ = child.kill();
    let _ = child.wait();
}
