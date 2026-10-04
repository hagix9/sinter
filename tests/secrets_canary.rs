//! Secrets Phase E: the canary-in-all-outputs suite, the `Debug` hygiene audit
//! of secret carriers, and threat-model tests.
//!
//! One set of unmistakable synthetic canaries (file plaintext, a password
//! hash, a passphrase, a private identity, and the *previous* content/hash on
//! the target) is pushed through every Phase A–D surface in every key state,
//! and every string a report, error, note, `Debug` rendering or process
//! stream can produce is searched for them. Assertions are made on the
//! target state as well, so a failure is proven to fail closed rather than
//! merely to print nothing.
#![cfg(unix)]
mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::FakeTarget;
use sinter::model::load_model;
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::Execution;
use sinter::secret_source::{ProcessSecrets, SharedSecrets};
use sinter::secrets::{self, Keys, Passphrase, Secret};
use sinter::secrets_cli::{Env, Prompter};
use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::rc::Rc;

const FILE_CANARY: &str = "CANARY-FILE-BYTES-3a91c7e2";
const OLD_FILE_CANARY: &str = "CANARY-OLD-TARGET-CONTENT-77d0b1";
const PASS_CANARY: &str = "canary passphrase 5d83-0e6a-b214";
const PATH_CANARY: &str = "CanaryTargetDir-9e41";

const B64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// A well-formed sha512crypt hash whose body is recognisable.
fn hash_with(marker: &str) -> String {
    let body: String = marker
        .chars()
        .filter(|c| B64.contains(&(*c as u8)))
        .cycle()
        .take(86)
        .collect();
    format!("$6$saltsalt${}", body)
}

fn new_hash() -> String {
    hash_with("NewHashCanary7")
}

fn old_hash() -> String {
    hash_with("OldHashCanary3")
}

fn file_payload() -> Vec<u8> {
    format!("{}\r\n\x00tail", FILE_CANARY).into_bytes()
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

struct Notes(Rc<RefCell<Vec<u8>>>);

impl Write for Notes {
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

struct Lab {
    dir: PathBuf,
    key: PathBuf,
    other_key: PathBuf,
    recipient: secrets::Recipient,
    key_text: String,
    other_key_text: String,
}

fn lab(label: &str) -> Lab {
    let dir = trusted_root(label);
    std::fs::create_dir_all(dir.join("secrets")).unwrap();
    let a = secrets::generate_identity();
    let b = secrets::generate_identity();
    let key = dir.join("key.txt");
    let other_key = dir.join("other-key.txt");
    std::fs::write(&key, a.identity_file.expose()).unwrap();
    std::fs::write(&other_key, b.identity_file.expose()).unwrap();
    set_mode(&key, 0o600);
    set_mode(&other_key, 0o600);
    Lab {
        key,
        other_key,
        recipient: a.recipient,
        key_text: String::from_utf8(a.identity_file.expose().to_vec()).unwrap(),
        other_key_text: String::from_utf8(b.identity_file.expose().to_vec()).unwrap(),
        dir,
    }
}

#[derive(Clone, Copy, Debug)]
enum Key {
    Right,
    None,
    Wrong,
}

impl Lab {
    fn put(&self, name: &str, plain: &[u8]) -> PathBuf {
        let ct =
            secrets::encrypt_to_recipients(plain, std::slice::from_ref(&self.recipient)).unwrap();
        let p = self.dir.join("secrets").join(name);
        std::fs::write(&p, ct).unwrap();
        p
    }

    fn env(&self, key: Key) -> Env {
        Env {
            identity_env: match key {
                Key::Right => Some(self.key.clone().into_os_string()),
                Key::Wrong => Some(self.other_key.clone().into_os_string()),
                Key::None => None,
            },
            xdg_config_home: None,
            home: Some(self.dir.join("home")),
            cwd: self.dir.clone(),
            euid: unsafe { libc::geteuid() },
        }
    }

    fn source(&self, key: Key) -> (SharedSecrets, Rc<RefCell<Vec<u8>>>) {
        let notes = Rc::new(RefCell::new(Vec::new()));
        let s: SharedSecrets = Rc::new(RefCell::new(ProcessSecrets::new(
            self.env(key),
            Box::new(NoTty),
            Box::new(Notes(notes.clone())),
        )));
        (s, notes)
    }

    /// A file resource and a user resource, both secret-backed.
    fn recipe(&self) -> PathBuf {
        write_recipe(
            &self.dir,
            "r.yaml",
            &format!(
                "version: 1\nresources:\n  - id: keyfile\n    type: file\n    with:\n      path: /etc/{PATH_CANARY}.key\n      content: {{ secret: secrets/f.age }}\n  - id: acct\n    type: user\n    with:\n      name: app\n      password_hash: {{ secret: secrets/pw.age }}\n"
            ),
        )
    }

    /// Every string needle that must never appear.
    fn needles(&self) -> Vec<String> {
        vec![
            FILE_CANARY.to_string(),
            OLD_FILE_CANARY.to_string(),
            new_hash(),
            new_hash().rsplit('$').next().unwrap().to_string(),
            old_hash(),
            old_hash().rsplit('$').next().unwrap().to_string(),
            PASS_CANARY.to_string(),
            "AGE-SECRET-KEY-".to_string(),
            self.key_text.trim().to_string(),
            self.other_key_text.trim().to_string(),
        ]
    }
}

/// A target with `/etc`, user `app` holding the previous hash, and the
/// previous file content in place (so drift redaction is exercised too).
fn target() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_fs_dir("/etc")
        .with_group("app", 990)
        .with_user("app", 990, 990, "/home/app", "/usr/sbin/nologin")
        .with_shadow("app", &old_hash());
    let (uid, gid) = (t.uid, t.gid);
    t.fs.as_mut().unwrap().put_file(
        &format!("/etc/{PATH_CANARY}.key"),
        OLD_FILE_CANARY.as_bytes(),
        0o600,
        uid,
        gid,
    );
    t
}

fn engine(r: &Path, mode: Mode, src: SharedSecrets, t: FakeTarget) -> Result<Engine, SinterError> {
    let model = load_model(r)?;
    let opts = RunOptions {
        mode,
        sudo: true,
        target: TargetSpec { ssh: None },
        verbose: true,
        fault: None,
        fake_target: Some(t),
    };
    Ok(Engine::new(model, opts)?.with_secrets(src))
}

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
    v.push(format!("{:#?}", rep.resources));
    v.push(format!("{:?}", rep.commands));
    v
}

fn audit_surfaces(rep: &AuditReport) -> Vec<String> {
    let mut v = vec![
        rep.render_text(),
        sinter::output::audit_report_json(rep).to_string(),
        format!("{:?}", rep.resources),
        format!("{:#?}", rep.resources),
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

fn error_surfaces(e: &SinterError) -> Vec<String> {
    vec![e.message.clone(), format!("{:?}", e), format!("{:#?}", e)]
}

fn assert_clean(l: &Lab, what: &str, surfaces: &[String]) {
    for s in surfaces {
        for n in l.needles() {
            assert!(!s.contains(&n), "{what}: leaked {n:?} in:\n{s}");
        }
    }
}

fn chpasswd_calls(t: &FakeTarget) -> usize {
    t.accounts
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(p, _, _)| p == "chpasswd")
        .count()
}

fn account_argv(t: &FakeTarget) -> Vec<String> {
    t.accounts
        .calls
        .lock()
        .unwrap()
        .iter()
        .map(|(p, a, _)| format!("{} {}", p, a.join(" ")))
        .collect()
}

fn wrote_file(rep: &RunReport) -> bool {
    rep.commands.iter().any(|c| {
        matches!(
            c.program.rsplit('/').next().unwrap_or(""),
            "dd" | "mv" | "tee" | "rm"
        )
    })
}

/// How the ciphertexts are damaged *after* the recipe has been validated.
#[derive(Clone, Copy, Debug)]
enum Damage {
    None,
    /// Body bit flipped: the header still parses, the MAC/payload does not.
    Tampered,
    /// Cut in half.
    Truncated,
}

fn damage(path: &Path, how: Damage) {
    let mut b = std::fs::read(path).unwrap();
    match how {
        Damage::None => return,
        Damage::Tampered => {
            let n = b.len();
            b[n - 3] ^= 0x01;
        }
        Damage::Truncated => b.truncate(b.len() / 2),
    }
    std::fs::write(path, b).unwrap();
}

// ---------------------------------------------------------------------------
// canary: plan / apply / audit in every key state and damage state
// ---------------------------------------------------------------------------

#[test]
fn no_surface_of_plan_apply_or_audit_ever_carries_a_canary() {
    let cases: &[(Key, Damage)] = &[
        (Key::Right, Damage::None),
        (Key::None, Damage::None),
        (Key::Wrong, Damage::None),
        (Key::Right, Damage::Tampered),
        (Key::Right, Damage::Truncated),
    ];
    for (n, (key, dmg)) in cases.iter().enumerate() {
        let l = lab(&format!("canary-engine-{n}"));
        let f = l.put("f.age", &file_payload());
        let p = l.put("pw.age", new_hash().as_bytes());
        let r = l.recipe();
        let healthy = matches!((key, dmg), (Key::Right, Damage::None));
        for mode in ["plan", "apply", "audit"] {
            let what = format!("{key:?}/{dmg:?}/{mode}");
            let (src, notes) = l.source(*key);
            let t = target();
            // validated first, damaged afterwards: the failure is at use time
            let m = if mode == "apply" {
                Mode::Apply
            } else {
                Mode::Plan
            };
            let eng = engine(&r, m, src, t.clone()).unwrap();
            damage(&f, *dmg);
            damage(&p, *dmg);
            let mut surfaces: Vec<String> = Vec::new();
            if mode == "audit" {
                let rep = sinter::audit::run_audit(eng).unwrap();
                surfaces.extend(audit_surfaces(&rep));
                if healthy {
                    // not vacuous: both resources are seen as drifted
                    assert!(rep
                        .resources
                        .iter()
                        .all(|x| x.status == AuditResourceStatus::Drift));
                } else {
                    // never "compliant" when the secret could not be used
                    assert!(
                        rep.resources
                            .iter()
                            .all(|x| x.status != AuditResourceStatus::Compliant),
                        "{what}: {:?}",
                        rep.resources
                    );
                }
            } else {
                match eng.run() {
                    Ok(rep) => {
                        surfaces.extend(run_surfaces(&rep, mode));
                        if healthy && mode == "apply" {
                            assert!(wrote_file(&rep), "{what}: not vacuous");
                            assert_eq!(chpasswd_calls(&t), 1, "{what}");
                        } else if !healthy {
                            // fail closed: nothing written, no account command
                            assert!(!wrote_file(&rep), "{what}: {:?}", rep.commands);
                            assert_eq!(chpasswd_calls(&t), 0, "{what}");
                            assert!(
                                rep.resources
                                    .iter()
                                    .all(|x| x.execution != Execution::Succeeded),
                                "{what}: {:?}",
                                rep.resources
                            );
                        }
                    }
                    Err(e) => {
                        surfaces.extend(error_surfaces(&e));
                        assert!(!healthy, "{what}: {}", e.message);
                        assert_eq!(chpasswd_calls(&t), 0, "{what}");
                    }
                }
            }
            surfaces.push(String::from_utf8_lossy(&notes.borrow()).to_string());
            // nothing secret was ever on an account command line
            surfaces.extend(account_argv(&t));
            assert_clean(&l, &what, &surfaces);
            // the next mode starts from undamaged ciphertext
            l.put("f.age", &file_payload());
            l.put("pw.age", new_hash().as_bytes());
        }
    }
}

#[test]
fn the_leak_detector_sees_a_leak() {
    let l = lab("canary-self");
    for leaked in [
        FILE_CANARY.to_string(),
        new_hash(),
        format!("x {} y", PASS_CANARY),
        l.key_text.trim().to_string(),
        "AGE-SECRET-KEY-1ABC".to_string(),
    ] {
        let l = &l;
        let hit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_clean(l, "self", std::slice::from_ref(&leaked));
        }));
        assert!(hit.is_err(), "the detector missed {leaked:?}");
    }
    assert_clean(&l, "self", &["nothing to see".to_string()]);
}

// ---------------------------------------------------------------------------
// canary: the binary (validate, secrets encrypt/decrypt/list, MCP)
// ---------------------------------------------------------------------------

fn bin(l: &Lab, args: &[&str]) -> Output {
    use std::os::unix::process::CommandExt;
    let mut c = Command::new(env!("CARGO_BIN_EXE_sinter"));
    c.args(args)
        .current_dir(&l.dir)
        .env_clear()
        .env("HOME", l.dir.join("home"))
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    c.output().unwrap()
}

fn streams(o: &Output) -> Vec<String> {
    vec![
        String::from_utf8_lossy(&o.stdout).to_string(),
        String::from_utf8_lossy(&o.stderr).to_string(),
    ]
}

#[test]
fn the_cli_never_prints_a_canary_except_decrypt_writing_the_plaintext_it_was_asked_for() {
    let l = lab("canary-cli");
    let plain = l.dir.join("plain.txt");
    std::fs::write(&plain, file_payload()).unwrap();
    let rcpt = l.recipient.to_text();
    // encrypt
    let o = bin(&l, &["secrets", "encrypt", "-r", &rcpt, "plain.txt"]);
    assert_eq!(o.status.code(), Some(0), "{:?}", streams(&o));
    assert_clean(&l, "encrypt", &streams(&o));
    let ct = std::fs::read(l.dir.join("plain.txt.age")).unwrap();
    assert!(!ct
        .windows(FILE_CANARY.len())
        .any(|w| w == FILE_CANARY.as_bytes()));
    // decrypt: stdout is the one intended plaintext stream; stderr is clean
    let o = bin(
        &l,
        &[
            "secrets",
            "decrypt",
            "-i",
            l.key.to_str().unwrap(),
            "plain.txt.age",
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{:?}", streams(&o));
    assert_eq!(o.stdout, file_payload());
    assert_clean(
        &l,
        "decrypt stderr",
        &[String::from_utf8_lossy(&o.stderr).to_string()],
    );
    // decrypt failures: wrong identity, no identity, tampered, truncated
    let mut broken = ct.clone();
    let n = broken.len();
    broken[n - 3] ^= 1;
    std::fs::write(l.dir.join("tampered.age"), &broken).unwrap();
    std::fs::write(l.dir.join("truncated.age"), &ct[..ct.len() / 2]).unwrap();
    for (args, what) in [
        (
            vec![
                "secrets",
                "decrypt",
                "-i",
                l.other_key.to_str().unwrap(),
                "plain.txt.age",
            ],
            "wrong key",
        ),
        (vec!["secrets", "decrypt", "plain.txt.age"], "no key"),
        (
            vec![
                "secrets",
                "decrypt",
                "-i",
                l.key.to_str().unwrap(),
                "tampered.age",
            ],
            "tampered",
        ),
        (
            vec![
                "secrets",
                "decrypt",
                "-i",
                l.key.to_str().unwrap(),
                "truncated.age",
            ],
            "truncated",
        ),
    ] {
        let o = bin(&l, &args);
        assert_ne!(o.status.code(), Some(0), "{what}");
        assert!(o.stdout.is_empty(), "{what}: no partial plaintext");
        assert_clean(&l, what, &streams(&o));
    }
    // list, plain and with recipes
    l.put("f.age", &file_payload());
    l.put("pw.age", new_hash().as_bytes());
    l.recipe();
    for extra in [
        vec!["secrets", "list"],
        vec!["secrets", "list", "--format", "json"],
        vec!["secrets", "list", "--recipe", "r.yaml"],
        vec!["secrets", "list", "--format", "json", "--recipe", "r.yaml"],
    ] {
        let o = bin(&l, &extra);
        assert_eq!(o.status.code(), Some(0), "{extra:?}: {:?}", streams(&o));
        let mut all = streams(&o);
        assert_clean(&l, &format!("{extra:?}"), &all);
        // recipient public keys are never shown either
        all.push(String::new());
        for s in &all {
            assert!(!s.contains(&rcpt), "{extra:?}: recipient shown: {s}");
            assert!(!s.contains("age1"), "{extra:?}: {s}");
            assert!(
                !s.contains(PATH_CANARY),
                "{extra:?}: target path shown: {s}"
            );
        }
    }
    // validate: success and every kind of failure
    let o = bin(&l, &["validate", "r.yaml"]);
    assert_eq!(o.status.code(), Some(0), "{:?}", streams(&o));
    assert_clean(&l, "validate", &streams(&o));
    for (i, reference) in ["secrets/gone.age", "../x.age", "secrets/f.age/"]
        .iter()
        .enumerate()
    {
        let name = format!("bad{i}.yaml");
        std::fs::write(
            l.dir.join(&name),
            format!("version: 1\nresources:\n  - id: k\n    type: user\n    with:\n      name: app\n      password_hash: {{ secret: {reference} }}\n"),
        )
        .unwrap();
        let o = bin(&l, &["validate", &name]);
        assert_eq!(o.status.code(), Some(2));
        assert_clean(&l, "validate bad", &streams(&o));
    }
}

#[test]
fn a_secret_that_is_not_a_valid_hash_is_refused_without_echoing_it() {
    let l = lab("canary-badhash");
    let junk = format!("not-a-hash-{}", "NewHashCanary7");
    l.put("pw.age", junk.as_bytes());
    l.put("f.age", &file_payload());
    let r = l.recipe();
    let (src, notes) = l.source(Key::Right);
    let t = target();
    let rep = engine(&r, Mode::Apply, src, t.clone()).unwrap().run();
    let mut s = Vec::new();
    match rep {
        Ok(rep) => {
            s.extend(run_surfaces(&rep, "apply"));
            let u = rep.resources.iter().find(|x| x.id == "acct").unwrap();
            assert_ne!(u.execution, Execution::Succeeded);
        }
        Err(e) => s.extend(error_surfaces(&e)),
    }
    assert_eq!(chpasswd_calls(&t), 0);
    s.push(String::from_utf8_lossy(&notes.borrow()).to_string());
    assert_clean(&l, "bad hash", &s);
    for x in &s {
        assert!(!x.contains(&junk) && !x.contains("not-a-hash"), "{x}");
    }
}

#[test]
fn mcp_refuses_every_secret_reference_form_on_every_manifest_tool_without_echoing_it() {
    use std::io::{BufRead, BufReader};
    let mut child = Command::new(env!("CARGO_BIN_EXE_sinter"))
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
    let manifests = [
        "version: 1\nresources:\n  - id: k\n    type: file\n    with:\n      path: /etc/k\n      content: { secret: secrets/CANARYREF-file.age }\n",
        "version: 1\nresources:\n  - id: u\n    type: user\n    with:\n      name: app\n      password_hash: { secret: secrets/CANARYREF-user.age }\n",
        // a reference of any malformed shape is refused as well
        "version: 1\nresources:\n  - id: u\n    type: user\n    with:\n      name: app\n      password_hash: { secret: ../../etc/CANARYREF-shadow }\n",
    ];
    let mut id = 10;
    for manifest in manifests {
        for tool in [
            "sinter_validate_manifest",
            "sinter_inspect_manifest",
            "sinter_plan",
            "sinter_plan_host",
            "sinter_audit_host",
        ] {
            id += 1;
            let resp = call(
                serde_json::json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
                "name": tool, "arguments": {"manifest": manifest, "target": "ubuntu2404"}}}),
            );
            let body = resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(resp["result"]["isError"], true, "{tool}: {body}");
            assert!(body.contains("encrypted secrets"), "{tool}: {body}");
            assert!(!body.contains("CANARYREF"), "{tool}: {body}");
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Debug / Display / Serialize hygiene of secret carriers
// ---------------------------------------------------------------------------

/// Compile-time-resolved "does `T` implement the trait?" probes (inherent
/// associated constants shadow the blanket trait ones when the bound holds).
macro_rules! implements {
    ($t:ty, $tr:path) => {{
        #[allow(dead_code)]
        trait No {
            const YES: bool = false;
        }
        impl<T: ?Sized> No for T {}
        struct Probe<T: ?Sized>(std::marker::PhantomData<T>);
        #[allow(dead_code)]
        impl<T: ?Sized + $tr> Probe<T> {
            const YES: bool = true;
        }
        <Probe<$t>>::YES
    }};
}

#[test]
fn carriers_redact_in_debug_and_expose_no_display_or_serialize() {
    use serde::Serialize;
    // Display and Serialize do not exist for any carrier.
    assert!(!implements!(Secret, std::fmt::Display));
    assert!(!implements!(Passphrase, std::fmt::Display));
    assert!(!implements!(Keys, std::fmt::Display));
    assert!(!implements!(secrets::Recipient, std::fmt::Display));
    assert!(!implements!(Secret, Serialize));
    assert!(!implements!(Passphrase, Serialize));
    assert!(!implements!(Keys, Serialize));
    assert!(!implements!(secrets::GeneratedIdentity, Serialize));
    assert!(!implements!(secrets::GeneratedIdentity, std::fmt::Debug));
    assert!(!implements!(ProcessSecrets, std::fmt::Debug));
    // The probe itself detects the positive case.
    assert!(implements!(String, std::fmt::Display));

    let l = lab("canary-debug");
    let secret = Secret::new(file_payload());
    let pass = Passphrase::for_decryption(PASS_CANARY.to_string());
    let mut keys = Keys::new();
    keys.add_identity_file(&std::fs::read(&l.key).unwrap())
        .unwrap();
    let id = secrets::generate_identity();
    let id_text = String::from_utf8(id.identity_file.expose().to_vec()).unwrap();
    let mut req = sinter::executor::ExecRequest::new("chpasswd");
    req.stdin = Some(format!("app:{}\n", new_hash()).into_bytes());
    req.args = vec!["-e".into()];

    let renders = vec![
        format!("{:?}", secret),
        format!("{:#?}", secret),
        format!("{:?}", pass),
        format!("{:#?}", pass),
        format!("{:?}", keys),
        format!("{:#?}", keys),
        format!("{:?}", id.recipient),
        format!("{:?}", id.identity_file),
        format!("{:?}", req),
        format!("{:#?}", req),
        // containers
        format!("{:?}", vec![&secret]),
        format!("{:?}", Some(&secret)),
        format!("{:?}", (&secret, &pass, &keys)),
        format!("{:#?}", [&id.identity_file]),
        format!("{:?}", Box::new(Secret::new(file_payload()))),
    ];
    for s in &renders {
        for needle in [
            FILE_CANARY,
            PASS_CANARY,
            "AGE-SECRET-KEY-",
            &new_hash(),
            id_text.trim(),
            l.key_text.trim(),
        ] {
            assert!(!s.contains(needle), "Debug leaked {needle:?}: {s}");
        }
    }
    assert!(!format!("{:?}", id.recipient).contains("age1"));
    assert!(!format!("{:?}", req).contains("chpasswd -e app"));
}

#[test]
#[allow(clippy::unnecessary_literal_unwrap)]
fn a_panic_message_built_from_a_carrier_or_its_error_holds_no_secret() {
    use std::panic::catch_unwind;
    fn message(p: Box<dyn std::any::Any + Send>) -> String {
        if let Some(s) = p.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = p.downcast_ref::<&str>() {
            s.to_string()
        } else {
            String::new()
        }
    }
    let l = lab("canary-panic");
    let ct = secrets::encrypt_to_recipients(&file_payload(), std::slice::from_ref(&l.recipient))
        .unwrap();
    let wrong = {
        let mut k = Keys::new();
        k.add_identity_file(&std::fs::read(&l.other_key).unwrap())
            .unwrap();
        k
    };
    let mut broken = ct.clone();
    let n = broken.len();
    broken[n - 3] ^= 1;
    let right = {
        let mut k = Keys::new();
        k.add_identity_file(&std::fs::read(&l.key).unwrap())
            .unwrap();
        k
    };
    let msgs = vec![
        // an Ok(secret) unwrapped as an error
        message(
            catch_unwind(|| {
                let r: Result<Secret, secrets::SecretError> = Ok(Secret::new(file_payload()));
                r.unwrap_err();
            })
            .unwrap_err(),
        ),
        // the real error values, unwrapped
        message(catch_unwind(|| secrets::decrypt(&ct, &wrong).unwrap()).unwrap_err()),
        message(catch_unwind(|| secrets::decrypt(&broken, &right).unwrap()).unwrap_err()),
        message(
            catch_unwind(|| secrets::decrypt(&ct[..ct.len() / 2], &right).unwrap()).unwrap_err(),
        ),
        message(
            catch_unwind(|| {
                let p = Passphrase::for_decryption(PASS_CANARY.to_string());
                Ok::<Passphrase, ()>(p).unwrap_err();
            })
            .unwrap_err(),
        ),
        message(
            catch_unwind(|| {
                Passphrase::for_encryption("short".into()).unwrap();
            })
            .unwrap_err(),
        ),
    ];
    for m in &msgs {
        assert!(!m.is_empty(), "the probe must produce a message");
        for needle in [
            FILE_CANARY,
            PASS_CANARY,
            "AGE-SECRET-KEY-",
            l.key_text.trim(),
        ] {
            assert!(!m.contains(needle), "panic message leaked {needle:?}: {m}");
        }
    }
}

// ---------------------------------------------------------------------------
// threat model (research §24): what the design claims, checked on the target
// ---------------------------------------------------------------------------

#[test]
fn nothing_secret_reaches_argv_environment_or_a_recipe_derived_path() {
    let l = lab("threat-argv");
    l.put("f.age", &file_payload());
    l.put("pw.age", new_hash().as_bytes());
    let r = l.recipe();
    let (src, _) = l.source(Key::Right);
    let t = target();
    let rep = engine(&r, Mode::Apply, src, t.clone())
        .unwrap()
        .run()
        .unwrap();
    // The scripted target recorded every command: program, args, env.
    for c in &rep.commands {
        let line = format!("{:?}", c);
        for n in l.needles() {
            assert!(!line.contains(&n), "command record leaked {n:?}: {line}");
        }
    }
    // chpasswd takes the hash on stdin only; the account argv is just `-e`.
    for line in account_argv(&t) {
        for n in l.needles() {
            assert!(!line.contains(&n), "argv leaked: {line}");
        }
    }
    assert!(account_argv(&t).iter().any(|a| a.trim() == "chpasswd -e"));
}

#[test]
fn a_hostile_ciphertext_is_rejected_with_fixed_text_and_no_partial_plaintext() {
    let l = lab("threat-hostile");
    for (name, bytes) in [
        ("huge-header.age", {
            let mut v = b"age-encryption.org/v1\n".to_vec();
            for _ in 0..50_000 {
                v.extend_from_slice(b"-> X25519 AAAA\nAAAA\n");
            }
            v
        }),
        ("not-age.age", b"just some text".to_vec()),
        (
            "future.age",
            b"age-encryption.org/v2\n-> x\n--- AAAA\n".to_vec(),
        ),
        ("empty.age", Vec::new()),
        ("binary.age", (0..=255u8).cycle().take(4096).collect()),
    ] {
        std::fs::write(l.dir.join(name), &bytes).unwrap();
        let o = bin(
            &l,
            &["secrets", "decrypt", "-i", l.key.to_str().unwrap(), name],
        );
        assert_ne!(o.status.code(), Some(0), "{name}");
        assert!(o.stdout.is_empty(), "{name}");
        assert_clean(&l, name, &streams(&o));
        // and the inventory classifies it without trusting it
        let o = bin(&l, &["secrets", "list", "--format", "json", name]);
        assert_eq!(o.status.code(), Some(0), "{name}: {:?}", streams(&o));
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_ne!(v["secrets"][0]["status"], "ok", "{name}");
    }
}

#[test]
fn a_reference_that_is_not_a_clean_relative_path_is_refused_before_any_open() {
    let l = lab("threat-ref");
    l.put("f.age", &file_payload());
    let outside = trusted_root("threat-ref-outside");
    std::fs::write(
        outside.join("stolen.age"),
        std::fs::read(l.dir.join("secrets/f.age")).unwrap(),
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, l.dir.join("escape")).unwrap();
    std::os::unix::fs::symlink(outside.join("stolen.age"), l.dir.join("secrets/l.age")).unwrap();
    for reference in [
        "../stolen.age",
        "/etc/passwd",
        "escape/stolen.age",
        "secrets/l.age",
        "secrets/../secrets/f.age",
    ] {
        let name = "t.yaml";
        std::fs::write(
            l.dir.join(name),
            format!("version: 1\nresources:\n  - id: k\n    type: file\n    with:\n      path: /etc/k\n      content: {{ secret: {reference} }}\n"),
        )
        .unwrap();
        // strict: refused; inventory: refused structurally (text) or reported
        // as a refused link, never read through it
        let v = bin(&l, &["validate", name]);
        assert_eq!(v.status.code(), Some(2), "{reference}");
        let o = bin(
            &l,
            &[
                "secrets", "list", "--format", "json", "--recipe", name, "secrets",
            ],
        );
        let all = streams(&o).join("\n");
        assert!(!all.contains(FILE_CANARY), "{reference}");
        if o.status.code() == Some(0) {
            let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
            for e in j["secrets"].as_array().unwrap() {
                if e["referenced_by"].as_array().is_some_and(|a| !a.is_empty()) {
                    assert_eq!(e["status"], "unreadable", "{reference}: {j:#}");
                }
            }
        } else {
            assert_eq!(o.status.code(), Some(2), "{reference}");
            assert!(o.stdout.is_empty());
        }
    }
}

#[test]
fn an_unavailable_key_leaves_the_target_untouched_for_both_resources() {
    let l = lab("threat-nokey");
    l.put("f.age", &file_payload());
    l.put("pw.age", new_hash().as_bytes());
    let r = l.recipe();
    for key in [Key::None, Key::Wrong] {
        let (src, _) = l.source(key);
        let t = target();
        let res = engine(&r, Mode::Apply, src, t.clone()).unwrap().run();
        if let Ok(rep) = res {
            assert!(!wrote_file(&rep), "{key:?}: {:?}", rep.commands);
            assert!(rep
                .resources
                .iter()
                .all(|x| x.execution != Execution::Succeeded));
        }
        assert_eq!(chpasswd_calls(&t), 0, "{key:?}");
        // audit says error/drift, never compliant
        let (src, _) = l.source(key);
        let a = sinter::audit::run_audit(engine(&r, Mode::Plan, src, t).unwrap()).unwrap();
        assert!(a
            .resources
            .iter()
            .all(|x| x.status != AuditResourceStatus::Compliant));
    }
}
