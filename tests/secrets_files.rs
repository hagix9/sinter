//! `file.content: { secret: <path> }` (Phase C) tests.
//!
//! Library tests run the production model, engine, resource and audit code
//! against the scripted in-process target ([`FakeTarget`]) with an injected
//! secret source (terminal and environment are fakes). The scripted target
//! checks the written bytes by SHA-256 exactly as the real flow does, and
//! seeded files show what counts as "already correct". Real-binary tests cover
//! `validate`, the MCP refusal and (Linux only, where the local target runs)
//! plan/apply/audit. Every output surface is searched for canary material.
#![cfg(unix)]
mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::FakeTarget;
use sinter::model::load_model;
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::{Change, DiffBody, Execution, Verification};
use sinter::secret_source::{ProcessSecrets, SharedSecrets};
use sinter::secrets::{self, Passphrase};
use sinter::secrets_cli::{Env, Prompter};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const TARGET_PATH: &str = "/etc/app.key";
const CANARY: &str = "CANARY-FILE-PLAINTEXT-5e8d21";
const PASS: &str = "canary file passphrase 7c2b-91f0";

/// Binary, with NUL, CRLF and no trailing newline: nothing may normalize it.
fn payload() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(CANARY.as_bytes());
    v.extend_from_slice(b"\r\n\x00\xff\x01 tail-without-newline");
    v
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Shared {
    asked: Vec<String>,
    notes: Vec<u8>,
}

struct FakePrompter {
    interactive: bool,
    secrets: VecDeque<String>,
    shared: Rc<RefCell<Shared>>,
}

impl Prompter for FakePrompter {
    fn interactive(&self) -> bool {
        self.interactive
    }
    fn read_secret(&mut self, prompt: &str) -> std::io::Result<zeroize::Zeroizing<String>> {
        self.shared.borrow_mut().asked.push(prompt.to_string());
        self.secrets
            .pop_front()
            .map(zeroize::Zeroizing::new)
            .ok_or_else(|| std::io::ErrorKind::UnexpectedEof.into())
    }
    fn read_line(&mut self, prompt: &str) -> std::io::Result<String> {
        self.shared.borrow_mut().asked.push(prompt.to_string());
        Err(std::io::ErrorKind::UnexpectedEof.into())
    }
}

struct Notes(Rc<RefCell<Shared>>);

impl Write for Notes {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().notes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Fx {
    dir: PathBuf,
    /// Plaintext identity file (mode 0600), the matching recipient, and the
    /// identity text (kept to search outputs for it).
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
    /// Encrypt `plain` to this fixture's recipient as `secrets/<name>`.
    fn put(&self, name: &str, plain: &[u8]) -> PathBuf {
        let ct =
            secrets::encrypt_to_recipients(plain, std::slice::from_ref(&self.recipient)).unwrap();
        let p = self.dir.join("secrets").join(name);
        std::fs::write(&p, ct).unwrap();
        p
    }

    /// The managed file on the scripted target.
    fn out(&self) -> PathBuf {
        PathBuf::from(TARGET_PATH)
    }

    fn env(&self) -> Env {
        Env {
            identity_env: Some(self.key.clone().into_os_string()),
            xdg_config_home: None,
            home: Some(self.dir.join("home")),
            cwd: self.dir.clone(),
            euid: unsafe { libc::geteuid() },
        }
    }

    /// An environment with no identity anywhere.
    fn bare_env(&self) -> Env {
        Env {
            identity_env: None,
            ..self.env()
        }
    }

    fn resource(&self, id: &str, secret: &str, extra: &str) -> String {
        format!(
            "  - id: {id}\n    type: file\n    with:\n      path: {out}\n      content: {{ secret: {secret} }}\n{extra}",
            id = id,
            out = self.out().display(),
            secret = secret,
            extra = extra
        )
    }

    fn recipe(&self, body: &str) -> PathBuf {
        write_recipe(
            &self.dir,
            "r.yaml",
            &format!("version: 1\nresources:\n{}", body),
        )
    }

    /// One file resource `f` writing `out` from `secrets/s.age`.
    fn simple(&self) -> PathBuf {
        self.put("s.age", &payload());
        self.recipe(&self.resource("f", "secrets/s.age", ""))
    }
}

fn source(env: Env, interactive: bool, typed: &[&str]) -> (SharedSecrets, Rc<RefCell<Shared>>) {
    let shared = Rc::new(RefCell::new(Shared::default()));
    let p = FakePrompter {
        interactive,
        secrets: typed.iter().map(|s| s.to_string()).collect(),
        shared: shared.clone(),
    };
    let src: SharedSecrets = Rc::new(RefCell::new(ProcessSecrets::new(
        env,
        Box::new(p),
        Box::new(Notes(shared.clone())),
    )));
    (src, shared)
}

/// An empty scripted target with `/etc` present.
fn fake() -> FakeTarget {
    FakeTarget::ubuntu2404().with_fake_fs().with_fs_dir("/etc")
}

/// A scripted target already holding `bytes` at the managed path, as the
/// controller would have left it (owned by the target user, mode 0600).
fn seeded(bytes: &[u8]) -> FakeTarget {
    let mut t = fake();
    let (uid, gid) = (t.uid, t.gid);
    t.fs.as_mut()
        .unwrap()
        .put_file(TARGET_PATH, bytes, 0o600, uid, gid);
    t
}

/// A scripted target holding `bytes` at both managed paths.
fn seeded_both(bytes: &[u8]) -> FakeTarget {
    let mut t = seeded(bytes);
    let (uid, gid) = (t.uid, t.gid);
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/app2.key", bytes, 0o600, uid, gid);
    t
}

fn engine(
    r: &Path,
    mode: Mode,
    src: Option<SharedSecrets>,
    t: FakeTarget,
) -> Result<Engine, SinterError> {
    let model = load_model(r)?;
    let opts = RunOptions {
        mode,
        sudo: false,
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
    src: Option<SharedSecrets>,
    t: FakeTarget,
) -> Result<RunReport, SinterError> {
    engine(r, mode, src, t)?.run()
}

fn audit(r: &Path, src: Option<SharedSecrets>, t: FakeTarget) -> AuditReport {
    sinter::audit::run_audit(engine(r, Mode::Plan, src, t).unwrap()).unwrap()
}

/// Whether the run executed anything that writes file content.
fn wrote_anything(rep: &RunReport) -> bool {
    rep.commands.iter().any(|c| {
        let prog = c.program.rsplit('/').next().unwrap_or("");
        matches!(prog, "dd" | "mv" | "tee" | "rm")
    })
}

/// The reason text of a run that must have failed (as a resource failure or
/// an engine error), after checking it did not succeed and wrote nothing.
fn failure_text(r: Result<RunReport, SinterError>) -> String {
    match r {
        Err(e) => e.message,
        Ok(rep) => {
            assert_ne!(rep.status, sinter::engine::AggregateStatus::Success);
            assert!(
                !wrote_anything(&rep),
                "nothing may be written: {:?}",
                rep.commands
            );
            rep.resources[0].reason.clone().unwrap_or_default()
        }
    }
}

/// Every string a report can reach an operator or a log through.
fn run_surfaces(rep: &RunReport, mode: &str) -> Vec<String> {
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
    ];
    v.push(format!("{:?}", rep.resources));
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

fn assert_clean(fx: &Fx, surfaces: &[String]) {
    for s in surfaces {
        for needle in [CANARY, PASS, "AGE-SECRET-KEY-", fx.key_text.trim()] {
            assert!(!s.contains(needle), "leaked {:?} in: {}", needle, s);
        }
    }
}

fn load_err(r: &Path) -> String {
    match load_model(r) {
        Err(e) => e.message,
        Ok(_) => panic!("expected the recipe to be rejected"),
    }
}

// ---------------------------------------------------------------------------
// loading / validate: the reference, never the plaintext
// ---------------------------------------------------------------------------

#[test]
fn a_reference_loads_without_any_key_and_makes_the_resource_sensitive() {
    let f = fx("sf-load");
    let r = f.simple();
    // No identity exists anywhere and nothing is asked: loading never decrypts.
    let m = load_model(&r).unwrap();
    let fr = &m.resources[0];
    assert!(fr.secret.is_some());
    assert!(
        fr.derived_sensitive,
        "a secret-holding resource is sensitive"
    );
    assert!(!fr.sensitive, "the declared flag is left as written");
    assert_eq!(fr.secret.as_ref().unwrap().reference, "secrets/s.age");
}

#[test]
fn malformed_and_unsafe_references_are_refused_while_loading() {
    let f = fx("sf-refs");
    f.put("ok.age", b"x");
    std::fs::write(f.dir.join("secrets/plain.age"), b"just text, not age").unwrap();
    std::fs::write(
        f.dir.join("secrets/trunc.age"),
        b"age-encryption.org/v1\n-> X25519 ",
    )
    .unwrap();
    std::fs::create_dir_all(f.dir.join("secrets/sub")).unwrap();
    // symlinks: a leaf, and a directory component
    let outside = trusted_root("sf-refs-outside");
    std::fs::write(
        outside.join("elsewhere.age"),
        secrets::encrypt_to_recipients(b"x", std::slice::from_ref(&f.recipient)).unwrap(),
    )
    .unwrap();
    symlink(
        outside.join("elsewhere.age"),
        f.dir.join("secrets/leaf.age"),
    )
    .unwrap();
    symlink(&outside, f.dir.join("linkdir")).unwrap();

    let long = format!("secrets/{}.age", "a".repeat(2000));
    let cases: Vec<(String, &str)> = vec![
        ("\"\"".into(), "non-empty"),
        ("/etc/passwd".into(), "relative"),
        ("../ok.age".into(), "'..'"),
        ("secrets/../secrets/ok.age".into(), "'..'"),
        ("./secrets/ok.age".into(), "'.'"),
        ("secrets//ok.age".into(), "empty"),
        ("secrets/ok.age/".into(), "empty"),
        ("\"secrets\\\\ok.age\"".into(), "relative"),
        ("\"secrets/{{ x }}.age\"".into(), "interpolation"),
        ("\"secrets/o\\tk.age\"".into(), "control"),
        ("secrets/missing.age".into(), "not found"),
        ("secrets/sub".into(), "regular file"),
        ("secrets/plain.age".into(), "valid age file"),
        ("secrets/trunc.age".into(), "valid age file"),
        ("secrets/leaf.age".into(), "symbolic link"),
        ("linkdir/elsewhere.age".into(), "symbolic link"),
        (long, "non-empty"),
    ];
    for (reference, want) in cases {
        let r = f.recipe(&f.resource("f", &reference, ""));
        let msg = load_err(&r);
        assert!(
            msg.contains(want),
            "reference {:?}: expected {:?} in {:?}",
            reference,
            want,
            msg
        );
    }
    // The good one still loads.
    f.recipe(&f.resource("f", "secrets/ok.age", ""));
    load_model(&f.dir.join("r.yaml")).unwrap();
}

#[test]
fn only_the_exact_reference_shape_is_accepted() {
    let f = fx("sf-shape");
    f.put("ok.age", b"x");
    let out = f.out();
    for content in [
        "{ secret: 1 }",
        "{ secret: [a] }",
        "{ other: secrets/ok.age }",
        "{ secret: secrets/ok.age, extra: y }",
        "{}",
        "[secrets/ok.age]",
        "5",
    ] {
        let r = f.recipe(&format!(
            "  - id: f\n    type: file\n    with:\n      path: {}\n      content: {}\n",
            out.display(),
            content
        ));
        let msg = load_err(&r);
        assert!(msg.contains("content"), "{:?} -> {}", content, msg);
    }
}

#[test]
fn content_and_source_stay_mutually_exclusive_and_templates_take_no_secret() {
    let f = fx("sf-excl");
    f.put("ok.age", b"x");
    std::fs::write(f.dir.join("plain.txt"), "hello").unwrap();
    let both = f.recipe(&f.resource("f", "secrets/ok.age", "      source: plain.txt\n"));
    assert!(load_err(&both).contains("mutually exclusive"));
    let tpl = f.recipe(&format!(
        "  - id: t\n    type: template\n    with:\n      path: {}\n      source: plain.txt\n      content: {{ secret: secrets/ok.age }}\n",
        f.out().display()
    ));
    assert!(load_err(&tpl).contains("template does not support content"));
}

#[test]
fn a_sensitive_resource_redacts_reference_errors() {
    let f = fx("sf-redact-ref");
    let r = f.recipe(&format!(
        "  - id: f\n    sensitive: true\n    type: file\n    with:\n      path: {}\n      content: {{ secret: secrets/missing-CANARYNAME.age }}\n",
        f.out().display()
    ));
    let msg = load_err(&r);
    assert!(msg.contains("value redacted"), "{}", msg);
    assert!(!msg.contains("CANARYNAME"), "{}", msg);
}

#[test]
fn a_reference_is_relative_to_the_recipe_that_names_it() {
    let f = fx("sf-include");
    std::fs::create_dir_all(f.dir.join("sub/secrets")).unwrap();
    let ct = secrets::encrypt_to_recipients(b"inc", std::slice::from_ref(&f.recipient)).unwrap();
    std::fs::write(f.dir.join("sub/secrets/i.age"), ct).unwrap();
    // Not at the including recipe's secrets/ directory: only under sub/.
    write_recipe(
        &f.dir.join("sub"),
        "inc.yaml",
        &format!(
            "version: 1\nresources:\n{}",
            f.resource("inc", "secrets/i.age", "")
        ),
    );
    let r = write_recipe(
        &f.dir,
        "r.yaml",
        "version: 1\ninclude: [sub/inc.yaml]\nresources: []\n",
    );
    let m = load_model(&r).unwrap();
    let sref = m.resources[0].secret.as_ref().unwrap();
    assert_eq!(sref.path, f.dir.join("sub").join("secrets/i.age"));
}

// ---------------------------------------------------------------------------
// plan / apply / audit
// ---------------------------------------------------------------------------

#[test]
fn apply_writes_and_verifies_the_decrypted_bytes_and_is_idempotent() {
    let f = fx("sf-apply");
    let r = f.simple();
    let (src, _) = source(f.env(), false, &[]);

    let plan = run(&r, Mode::Plan, Some(src.clone()), fake()).unwrap();
    let pf = &plan.resources[0];
    assert_eq!(pf.change, Change::Changed);
    assert!(pf.sensitive);
    assert!(matches!(pf.diff.as_ref().unwrap().body, DiffBody::Redacted));
    assert!(!wrote_anything(&plan), "plan writes nothing");
    assert_clean(&f, &run_surfaces(&plan, "plan"));

    // Apply publishes through the unchanged file pipeline; `Verified` means
    // the target's SHA-256 matched the controller's SHA-256 of the plaintext.
    let applied = run(&r, Mode::Apply, Some(src.clone()), fake()).unwrap();
    let af = &applied.resources[0];
    assert_eq!(af.execution, Execution::Succeeded);
    assert_eq!(af.verification, Verification::Verified);
    assert_eq!(af.change, Change::Changed);
    assert!(wrote_anything(&applied));
    assert_clean(&f, &run_surfaces(&applied, "apply"));

    // Against an existing file a non-sensitive change would show a text diff;
    // here it is redacted and nothing leaks.
    let old = seeded(b"old content");
    let plan_old = run(&r, Mode::Plan, Some(src.clone()), old.clone()).unwrap();
    assert!(matches!(
        plan_old.resources[0].diff.as_ref().unwrap().body,
        DiffBody::Redacted
    ));
    assert_clean(&f, &run_surfaces(&plan_old, "plan"));
    let applied_old = run(&r, Mode::Apply, Some(src.clone()), old).unwrap();
    assert_eq!(
        applied_old.resources[0].verification,
        Verification::Verified
    );
    assert_clean(&f, &run_surfaces(&applied_old, "apply"));

    // A target that already holds the exact bytes is a no-op.
    let again = run(&r, Mode::Apply, Some(src.clone()), seeded(&payload())).unwrap();
    assert_eq!(again.resources[0].change, Change::None);
    assert!(
        !wrote_anything(&again),
        "an idempotent second apply writes nothing"
    );
    let plan2 = run(&r, Mode::Plan, Some(src), seeded(&payload())).unwrap();
    assert_eq!(plan2.resources[0].change, Change::None);
}

#[test]
fn bytes_are_compared_exactly_with_no_newline_or_line_ending_normalization() {
    let f = fx("sf-exact");
    let r = f.simple();
    let (src, _) = source(f.env(), false, &[]);
    let p = payload();
    let mut with_newline = p.clone();
    with_newline.push(b'\n');
    let lf_only: Vec<u8> = p.iter().copied().filter(|b| *b != b'\r').collect();
    let truncated = p[..p.len() - 1].to_vec();
    let mut nul_dropped = p.clone();
    nul_dropped.retain(|b| *b != 0);
    for (name, other) in [
        ("trailing newline added", with_newline),
        ("CRLF turned into LF", lf_only),
        ("last byte missing", truncated),
        ("NUL byte dropped", nul_dropped),
        ("empty", Vec::new()),
    ] {
        let rep = run(&r, Mode::Plan, Some(src.clone()), seeded(&other)).unwrap();
        assert_eq!(rep.resources[0].change, Change::Changed, "{}", name);
        let a = audit(&r, Some(src.clone()), seeded(&other));
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Drift,
            "{}",
            name
        );
    }
    let exact = audit(&r, Some(src), seeded(&p));
    assert_eq!(exact.resources[0].status, AuditResourceStatus::Compliant);
}

#[test]
fn an_explicit_mode_and_a_content_change_are_applied_and_verified() {
    let f = fx("sf-mode");
    f.put("s.age", &payload());
    let r = f.recipe(&f.resource("f", "secrets/s.age", "      mode: \"0640\"\n"));
    let (src, _) = source(f.env(), false, &[]);
    let old = seeded(b"old content");
    let p = run(&r, Mode::Plan, Some(src.clone()), old.clone()).unwrap();
    assert_eq!(p.resources[0].change, Change::Changed);
    assert!(!wrote_anything(&p));
    let a = run(&r, Mode::Apply, Some(src), old).unwrap();
    assert_eq!(a.resources[0].execution, Execution::Succeeded);
    assert_eq!(a.resources[0].verification, Verification::Verified);
}

#[test]
fn audit_reports_compliant_drift_and_error_never_the_content() {
    let f = fx("sf-audit");
    let r = f.simple();
    let (src, _) = source(f.env(), false, &[]);

    let ok = audit(&r, Some(src.clone()), seeded(&payload()));
    assert_eq!(ok.resources[0].status, AuditResourceStatus::Compliant);
    assert!(ok.resources[0].sensitive);
    assert_clean(&f, &audit_surfaces(&ok));

    let drift = audit(&r, Some(src), seeded(b"tampered"));
    assert_eq!(drift.resources[0].status, AuditResourceStatus::Drift);
    assert_eq!(drift.exit_code(), 7);
    assert_clean(&f, &audit_surfaces(&drift));

    // No key: ERROR, never COMPLIANT, even though the file would match.
    let (bare, shared_bare) = source(f.bare_env(), false, &[]);
    let err = audit(&r, Some(bare), seeded(&payload()));
    assert_eq!(err.resources[0].status, AuditResourceStatus::Error);
    assert!(
        String::from_utf8_lossy(&shared_bare.borrow().notes).contains("no identity found"),
        "the audit error must come from the missing key"
    );
    assert_ne!(err.exit_code(), 0);
    assert_clean(&f, &audit_surfaces(&err));
    // And with no source configured at all.
    let none = audit(&r, None, seeded(&payload()));
    assert_eq!(none.resources[0].status, AuditResourceStatus::Error);
    assert_ne!(none.exit_code(), 0);
    assert_clean(&f, &audit_surfaces(&none));
}

#[test]
fn without_a_source_the_resource_fails_closed() {
    let f = fx("sf-nosrc");
    let r = f.simple();
    for mode in [Mode::Plan, Mode::Apply] {
        let text = failure_text(run(&r, mode, None, fake()));
        assert!(text.contains("secret unavailable"), "{}", text);
        assert!(text.contains("value redacted"), "{}", text);
    }
}

#[test]
fn the_cause_goes_to_the_diagnostics_channel_while_the_report_stays_redacted() {
    let f = fx("sf-cause");
    let r = f.simple();
    let (bare, shared) = source(f.bare_env(), false, &[]);
    let rep = run(&r, Mode::Apply, Some(bare), seeded(b"x")).unwrap();
    // The rendered report says nothing about why (a secret-holding resource is
    // sensitive) ...
    // (the first three surfaces are the rendered ones; the internal Debug
    // dumps after them carry the fixed text and are not an operator output)
    for s in run_surfaces(&rep, "apply").iter().take(3) {
        assert!(!s.contains("no identity found"), "{}", s);
    }
    // ... the operator learns the cause from the diagnostics line, once.
    let notes = String::from_utf8_lossy(&shared.borrow().notes).to_string();
    assert_eq!(notes.matches("no identity found").count(), 1, "{}", notes);
    assert!(
        notes.contains("secret unavailable: secrets/s.age:"),
        "{}",
        notes
    );
    assert!(notes.contains("SINTER_IDENTITY"), "{}", notes);
    assert_clean(&f, &[notes]);
}

#[test]
fn a_failed_unlock_or_passphrase_is_not_asked_again_and_a_good_one_is_remembered() {
    let f = fx("sf-neg-cache");
    f.put("a.age", b"first");
    f.put("b.age", &payload());
    let prot = secrets::protect_identity(
        &secrets::Secret::new(std::fs::read(&f.key).unwrap()),
        &Passphrase::for_encryption(PASS.to_string()).unwrap(),
    )
    .unwrap();
    std::fs::write(f.dir.join("secrets/identity.age"), prot).unwrap();
    let r = f.recipe(&format!(
        "{}  - id: g\n    type: file\n    with:\n      path: /etc/app2.key\n      content: {{ secret: secrets/a.age }}\n",
        f.resource("f", "secrets/b.age", ""),
    ));
    // Wrong passphrase: asked once for the whole run (audit continues past a
    // failed resource, so the second one would ask again without the memory).
    let (src, shared) = source(f.bare_env(), true, &["wrong wrong wrong", PASS]);
    let a = audit(&r, Some(src), seeded_both(b"first"));
    assert!(a
        .resources
        .iter()
        .all(|x| x.status == AuditResourceStatus::Error));
    assert_eq!(
        shared.borrow().asked.len(),
        1,
        "{:?}",
        shared.borrow().asked
    );

    // A passphrase-encrypted secret used by two resources is asked once.
    let ct = secrets::encrypt_with_passphrase(
        &payload(),
        &Passphrase::for_encryption(PASS.to_string()).unwrap(),
    )
    .unwrap();
    std::fs::write(f.dir.join("secrets/p.age"), ct).unwrap();
    let r2 = f.recipe(&format!(
        "{}  - id: g\n    type: file\n    with:\n      path: /etc/app2.key\n      content: {{ secret: secrets/p.age }}\n",
        f.resource("f", "secrets/p.age", ""),
    ));
    let (src, shared) = source(f.bare_env(), true, &[PASS]);
    let rep = run(&r2, Mode::Plan, Some(src), fake()).unwrap();
    assert!(rep.resources.iter().all(|x| x.change == Change::Changed));
    assert_eq!(shared.borrow().asked.len(), 1);
    // A wrong passphrase for a file is not retried for the same file.
    let (src, shared) = source(f.bare_env(), true, &["wrong wrong wrong", PASS]);
    let a = audit(&r2, Some(src), seeded_both(b"x"));
    assert!(a
        .resources
        .iter()
        .all(|x| x.status == AuditResourceStatus::Error));
    assert_eq!(shared.borrow().asked.len(), 1);
}

#[test]
fn a_resource_that_is_skipped_never_opens_its_secret() {
    let f = fx("sf-when");
    f.put("s.age", &payload());
    let r = f.recipe(&f.resource(
        "f",
        "secrets/s.age",
        "    when: facts.os.family == \"redhat\"\n",
    ));
    // The extra field belongs to the resource, not `with`: rebuild properly.
    let body = format!(
        "  - id: f\n    type: file\n    when: facts.os.family == \"redhat\"\n    with:\n      path: {}\n      content: {{ secret: secrets/s.age }}\n",
        TARGET_PATH
    );
    let _ = r;
    let r = f.recipe(&body);
    let (src, shared) = source(f.bare_env(), true, &[]);
    let rep = run(&r, Mode::Apply, Some(src), fake()).unwrap();
    assert_eq!(rep.resources[0].execution, Execution::NotRun);
    assert!(shared.borrow().asked.is_empty());
    assert!(shared.borrow().notes.is_empty());
}

#[test]
fn every_loop_expanded_resource_is_sensitive() {
    let f = fx("sf-loop");
    f.put("s.age", &payload());
    let r = f.recipe(
        "  - id: f\n    type: file\n    loop: [one, two]\n    with:\n      path: /etc/app-{{ item }}.key\n      content: { secret: secrets/s.age }\n",
    );
    let m = load_model(&r).unwrap();
    assert_eq!(m.resources.len(), 2);
    for fr in &m.resources {
        assert!(fr.secret.is_some() && fr.derived_sensitive, "{}", fr.id);
    }
    let (src, _) = source(f.env(), false, &[]);
    let rep = run(&r, Mode::Apply, Some(src), fake()).unwrap();
    for x in &rep.resources {
        assert_eq!(x.verification, Verification::Verified, "{}", x.id);
        assert!(x.sensitive, "{}", x.id);
    }
}

#[test]
fn audit_of_a_missing_target_file_is_drift_without_needing_the_key() {
    // Absent is drift whatever the content would be, so audit does not need
    // the plaintext there (plan and apply still do, to describe the change).
    let f = fx("sf-audit-absent");
    let r = f.simple();
    let (bare, shared) = source(f.bare_env(), false, &[]);
    let a = audit(&r, Some(bare), fake());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert!(shared.borrow().notes.is_empty());
}

#[test]
fn a_missing_wrong_or_damaged_key_fails_without_writing_or_leaking() {
    let f = fx("sf-keys");
    let r = f.simple();

    // wrong identity
    let other = secrets::generate_identity();
    let wrong = f.dir.join("wrong.txt");
    std::fs::write(&wrong, other.identity_file.expose()).unwrap();
    set_mode(&wrong, 0o600);
    let mut env = f.env();
    env.identity_env = Some(wrong.into_os_string());
    let (src, _) = source(env, false, &[]);
    // missing identity
    let (bare, _) = source(f.bare_env(), false, &[]);
    for (name, s) in [("wrong identity", src), ("no identity", bare)] {
        for mode in [Mode::Plan, Mode::Apply] {
            let text = failure_text(run(&r, mode, Some(s.clone()), seeded(b"keep me")));
            assert!(text.contains("secret unavailable"), "{}: {}", name, text);
            assert!(text.contains("value redacted"), "{}: {}", name, text);
            assert_clean(&f, &[text]);
        }
    }

    // damaged ciphertext (after loading): the existing target is not touched
    let ct_path = f.dir.join("secrets/s.age");
    let mut ct = std::fs::read(&ct_path).unwrap();
    let n = ct.len();
    ct[n - 5] ^= 0x55;
    std::fs::write(&ct_path, &ct).unwrap();
    let (good, _) = source(f.env(), false, &[]);
    let text = failure_text(run(&r, Mode::Apply, Some(good), seeded(b"keep me")));
    assert!(text.contains("secret unavailable"), "{}", text);
    assert_clean(&f, &[text]);
}

#[test]
fn a_secret_swapped_for_a_symlink_after_loading_is_refused() {
    let f = fx("sf-toctou");
    let r = f.simple();
    let (src, _) = source(f.env(), false, &[]);
    let eng = engine(&r, Mode::Apply, Some(src), fake()).unwrap();
    // The recipe was validated; now replace the file with a link to another
    // (valid) age file before it is opened.
    let target = f.dir.join("other.age");
    std::fs::copy(f.dir.join("secrets/s.age"), &target).unwrap();
    std::fs::remove_file(f.dir.join("secrets/s.age")).unwrap();
    symlink(&target, f.dir.join("secrets/s.age")).unwrap();
    let text = failure_text(eng.run());
    assert!(text.contains("secret unavailable"), "{}", text);
    assert!(text.contains("symbolic link"), "{}", text);
}

#[test]
fn removing_a_file_does_not_need_its_secret() {
    let f = fx("sf-absent");
    f.put("s.age", &payload());
    let r = f.recipe(&f.resource("f", "secrets/s.age", "      state: absent\n"));
    let (bare, shared) = source(f.bare_env(), false, &[]);
    let rep = run(&r, Mode::Apply, Some(bare), seeded(b"x")).unwrap();
    assert_eq!(rep.resources[0].execution, Execution::Succeeded);
    assert_eq!(rep.resources[0].change, Change::Changed);
    assert!(shared.borrow().asked.is_empty());
}

#[test]
fn the_leak_detector_would_see_an_unprotected_value() {
    // Control for `assert_clean`: the same canary as plain, non-sensitive
    // content does reach the plan output, so a clean secret run means the
    // secret path really keeps it out. (The secret tests also use an existing
    // target file, where a non-redacted diff would show the content.)
    let f = fx("sf-control");
    let r = f.recipe(&format!(
        "  - id: f\n    type: file\n    with:\n      path: {}\n      content: {}\n",
        TARGET_PATH, CANARY
    ));
    // A text diff against an existing file is where plain content shows.
    let plan = run(&r, Mode::Plan, None, seeded(b"old content")).unwrap();
    let all = run_surfaces(&plan, "plan").join("\n");
    assert!(
        all.contains(CANARY),
        "the harness must be able to see a leak"
    );
}

#[test]
fn request_and_content_carriers_never_print_their_bytes() {
    let req = sinter::executor::ExecRequest::new("/bin/dd").stdin(payload());
    let shown = format!("{:?}", req);
    assert!(shown.contains("redacted"), "{}", shown);
    assert!(
        !shown.contains(CANARY) && !shown.contains("255"),
        "{}",
        shown
    );
    let cloned = format!("{:?}", req.clone());
    assert!(!cloned.contains(CANARY), "{}", cloned);
    let secret = secrets::Secret::new(payload());
    assert!(!format!("{:?}", secret).contains(CANARY));
    assert_eq!(secret.into_zeroizing().len(), payload().len());
}

// ---------------------------------------------------------------------------
// identity handling (the Phase B order, minus the SSH-colliding flag)
// ---------------------------------------------------------------------------

#[test]
fn a_plaintext_identity_must_be_private() {
    let f = fx("sf-idperm");
    let r = f.simple();
    set_mode(&f.key, 0o644);
    let (src, _) = source(f.env(), false, &[]);
    let text = failure_text(run(&r, Mode::Apply, Some(src), fake()));
    assert!(text.contains("secret unavailable"), "{}", text);
    assert!(text.contains("accessible by other users"), "{}", text);
}

#[test]
fn the_external_default_identity_is_used_when_the_environment_names_none() {
    let f = fx("sf-extdefault");
    let r = f.simple();
    let cfg = f.dir.join("home/.config/sinter");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::copy(&f.key, cfg.join("identity")).unwrap();
    set_mode(&cfg.join("identity"), 0o600);
    let (src, _) = source(f.bare_env(), false, &[]);
    let rep = run(&r, Mode::Apply, Some(src), fake()).unwrap();
    assert_eq!(rep.resources[0].verification, Verification::Verified);
}

#[test]
fn a_protected_repository_identity_is_unlocked_once_per_run() {
    let f = fx("sf-protected");
    f.put("a.age", b"first");
    f.put("b.age", &payload());
    // identity.age next to the secrets, protected by a passphrase.
    let prot = secrets::protect_identity(
        &secrets::Secret::new(std::fs::read(&f.key).unwrap()),
        &Passphrase::for_encryption(PASS.to_string()).unwrap(),
    )
    .unwrap();
    std::fs::write(f.dir.join("secrets/identity.age"), prot).unwrap();
    let r = f.recipe(&format!(
        "{}  - id: g\n    type: file\n    with:\n      path: /etc/app2.key\n      content: {{ secret: secrets/a.age }}\n",
        f.resource("f", "secrets/b.age", ""),
    ));
    let (src, shared) = source(f.bare_env(), true, &[PASS]);
    let plan = run(&r, Mode::Plan, Some(src.clone()), fake()).unwrap();
    assert_clean(&f, &run_surfaces(&plan, "plan"));
    let applied = run(&r, Mode::Apply, Some(src), fake()).unwrap();
    assert_clean(&f, &run_surfaces(&applied, "apply"));
    for x in &applied.resources {
        assert_eq!(x.verification, Verification::Verified, "{}", x.id);
    }
    let sh = shared.borrow();
    assert_eq!(
        sh.asked.len(),
        1,
        "one prompt for two secrets across two runs: {:?}",
        sh.asked
    );
    let notes = String::from_utf8_lossy(&sh.notes).to_string();
    for needle in [PASS, CANARY, "AGE-SECRET-KEY-"] {
        assert!(!notes.contains(needle));
    }
}

#[test]
fn a_protected_identity_needs_a_terminal_and_the_right_passphrase() {
    let f = fx("sf-protected-fail");
    f.put("s.age", &payload());
    let prot = secrets::protect_identity(
        &secrets::Secret::new(std::fs::read(&f.key).unwrap()),
        &Passphrase::for_encryption(PASS.to_string()).unwrap(),
    )
    .unwrap();
    std::fs::write(f.dir.join("secrets/identity.age"), prot).unwrap();
    let r = f.recipe(&f.resource("f", "secrets/s.age", ""));

    let (no_tty, shared) = source(f.bare_env(), false, &[]);
    let text = failure_text(run(&r, Mode::Apply, Some(no_tty), fake()));
    assert!(text.contains("no terminal"), "{}", text);
    assert!(
        shared.borrow().asked.is_empty(),
        "never prompts without a terminal"
    );

    let (wrong, _) = source(f.bare_env(), true, &["not the passphrase at all"]);
    let text = failure_text(run(&r, Mode::Apply, Some(wrong), fake()));
    assert!(text.contains("could not unlock"), "{}", text);
    assert_clean(&f, &[text]);
}

#[test]
fn a_plaintext_identity_in_a_repository_is_never_discovered() {
    let f = fx("sf-repo-plain");
    f.put("s.age", &payload());
    // an unprotected identity named like the protected one
    std::fs::copy(&f.key, f.dir.join("secrets/identity.age")).unwrap();
    set_mode(&f.dir.join("secrets/identity.age"), 0o600);
    let r = f.recipe(&f.resource("f", "secrets/s.age", ""));
    let (src, _) = source(f.bare_env(), true, &[]);
    let text = failure_text(run(&r, Mode::Apply, Some(src), fake()));
    assert!(text.contains("secret unavailable"), "{}", text);
    assert!(text.contains("never used automatically"), "{}", text);
}

#[test]
fn a_passphrase_secret_asks_on_the_terminal_and_never_without_one() {
    let f = fx("sf-pass");
    let ct = secrets::encrypt_with_passphrase(
        &payload(),
        &Passphrase::for_encryption(PASS.to_string()).unwrap(),
    )
    .unwrap();
    std::fs::write(f.dir.join("secrets/p.age"), ct).unwrap();
    let r = f.recipe(&f.resource("f", "secrets/p.age", ""));

    let (no_tty, shared) = source(f.bare_env(), false, &[]);
    let text = failure_text(run(&r, Mode::Apply, Some(no_tty), fake()));
    assert!(text.contains("only be typed on a terminal"), "{}", text);
    assert!(shared.borrow().asked.is_empty());

    let (tty, shared) = source(f.bare_env(), true, &["wrong wrong wrong"]);
    let text = failure_text(run(&r, Mode::Apply, Some(tty), fake()));
    assert!(text.contains("secret unavailable"), "{}", text);
    assert_eq!(shared.borrow().asked.len(), 1);

    let (tty, shared) = source(f.bare_env(), true, &[PASS]);
    let rep = run(&r, Mode::Apply, Some(tty), fake()).unwrap();
    assert_eq!(rep.resources[0].verification, Verification::Verified);
    assert_clean(&f, &run_surfaces(&rep, "apply"));
    let asked = shared.borrow().asked.clone();
    assert_eq!(asked.len(), 1);
    assert!(
        asked[0].contains("secrets/p.age"),
        "the prompt names the secret: {:?}",
        asked
    );
}

#[test]
fn a_large_secret_round_trips() {
    let f = fx("sf-large");
    let big: Vec<u8> = (0..(2 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
    f.put("s.age", &big);
    let r = f.recipe(&f.resource("f", "secrets/s.age", ""));
    let (src, _) = source(f.env(), false, &[]);
    let rep = run(&r, Mode::Apply, Some(src.clone()), fake()).unwrap();
    assert_eq!(rep.resources[0].verification, Verification::Verified);
    let a = audit(&r, Some(src), seeded(&big));
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
}

// ---------------------------------------------------------------------------
// real binary: validate everywhere; plan/apply/audit where the local target runs
// ---------------------------------------------------------------------------

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sinter")
}

/// A command with no controlling terminal and a minimal environment.
fn detached(f: &Fx) -> std::process::Command {
    use std::os::unix::process::CommandExt;
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
    c
}

fn text(o: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn the_binary_validates_without_decrypting_anything() {
    let f = fx("sf-bin-validate");
    let r = f.simple();
    // No identity at all, and a SINTER_IDENTITY that points nowhere: validate
    // must not care, because it never opens the secret.
    for env in [None, Some("/nonexistent/identity")] {
        let mut c = detached(&f);
        if let Some(v) = env {
            c.env("SINTER_IDENTITY", v);
        }
        let v = c.args(["validate", r.to_str().unwrap()]).output().unwrap();
        assert_eq!(v.status.code(), Some(0), "{}", text(&v));
        assert_clean(&f, &[text(&v)]);
    }
    // A bad reference is a validation error (exit 2), without echoing a path.
    let bad = f.recipe(&f.resource("f", "../escape.age", ""));
    let v = detached(&f)
        .args(["validate", bad.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(v.status.code(), Some(2), "{}", text(&v));
    assert!(text(&v).contains("'..'"), "{}", text(&v));
}

/// plan / apply / audit through the real binary against the local target.
/// The local target needs Linux tooling (`getent`, GNU `stat`), so these run
/// on Linux only; the same code paths run on the scripted target above.
#[cfg(target_os = "linux")]
#[test]
fn the_binary_plans_applies_and_audits_with_an_identity_and_fails_closed_without() {
    use std::os::unix::fs::PermissionsExt;
    let f = fx("sf-bin-run");
    f.put("s.age", &payload());
    let out = f.dir.join("cli-out");
    let r = f.recipe(&format!(
        "  - id: f\n    type: file\n    with:\n      path: {}\n      content: {{ secret: secrets/s.age }}\n",
        out.display()
    ));

    // Without any identity: closed, quiet, nothing written.
    for sub in ["plan", "apply"] {
        let o = detached(&f)
            .args([sub, r.to_str().unwrap()])
            .output()
            .unwrap();
        assert_ne!(o.status.code(), Some(0), "{}: {}", sub, text(&o));
        assert!(
            text(&o).contains("secret unavailable"),
            "{}: {}",
            sub,
            text(&o)
        );
        assert_clean(&f, &[text(&o)]);
        assert!(!out.exists());
    }
    // audit needs the plaintext only when the target file exists (a missing
    // file is drift whatever it should contain).
    std::fs::write(&out, b"present").unwrap();
    set_mode(&out, 0o600);
    let o = detached(&f)
        .args(["audit", r.to_str().unwrap()])
        .output()
        .unwrap();
    assert_ne!(o.status.code(), Some(0), "audit: {}", text(&o));
    assert!(
        text(&o).contains("secret unavailable"),
        "audit: {}",
        text(&o)
    );
    assert_clean(&f, &[text(&o)]);
    std::fs::remove_file(&out).unwrap();

    // `--identity` on plan/apply/audit names an SSH key; it is never taken for
    // a secret identity.
    let o = detached(&f)
        .args([
            "plan",
            r.to_str().unwrap(),
            "--identity",
            f.key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_ne!(o.status.code(), Some(0), "{}", text(&o));
    assert_clean(&f, &[text(&o)]);

    // SINTER_IDENTITY (a path) supplies the key.
    let p = detached(&f)
        .env("SINTER_IDENTITY", &f.key)
        .args(["plan", r.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(p.status.code(), Some(0), "{}", text(&p));
    assert_clean(&f, &[text(&p)]);
    assert!(!out.exists(), "plan writes nothing");
    let a = detached(&f)
        .env("SINTER_IDENTITY", &f.key)
        .args(["apply", r.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(a.status.code(), Some(0), "{}", text(&a));
    assert_clean(&f, &[text(&a)]);
    assert_eq!(std::fs::read(&out).unwrap(), payload());
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let au = detached(&f)
        .env("SINTER_IDENTITY", &f.key)
        .args(["audit", r.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(au.status.code(), Some(0), "{}", text(&au));
    assert_clean(&f, &[text(&au)]);
}

// ---------------------------------------------------------------------------
// MCP: manifest text may not ask the gateway to decrypt anything
// ---------------------------------------------------------------------------

#[test]
fn mcp_refuses_secret_references_in_manifest_text() {
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
    let manifest = "version: 1\nresources:\n  - id: k\n    type: file\n    with:\n      path: /etc/k\n      content: { secret: secrets/CANARYREF.age }\n";
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
