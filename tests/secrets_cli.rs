//! `sinter secrets encrypt | decrypt | list` (Phase B) tests.
//!
//! Library-level tests inject the terminal, stdin/stdout/stderr and the
//! environment ([`Io`], [`Env`], [`Prompter`]); a handful of real-binary tests
//! (with the controlling terminal removed) and one real pseudo-terminal test
//! cover what injection cannot: exit codes, `/dev/tty` prompting with echo off,
//! and the stdout-is-a-terminal guard. They run on macOS and Linux.
#![cfg(unix)]

use sinter::error::SinterError;
use sinter::secrets::{self, Keys, Method, Passphrase, MAX_SECRET_BYTES};
use sinter::secrets_cli::*;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const CANARY: &str = "CANARY-PLAINTEXT-7f3a9c";
const PASS: &str = "canary passphrase 4d1e-8b2c";

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

struct FakePrompter {
    interactive: bool,
    secrets: VecDeque<String>,
    lines: VecDeque<String>,
    asked: Vec<String>,
}

impl FakePrompter {
    fn new(interactive: bool) -> Self {
        FakePrompter {
            interactive,
            secrets: VecDeque::new(),
            lines: VecDeque::new(),
            asked: Vec::new(),
        }
    }
    fn secrets(mut self, s: &[&str]) -> Self {
        self.secrets = s.iter().map(|x| x.to_string()).collect();
        self
    }
    fn lines(mut self, s: &[&str]) -> Self {
        self.lines = s.iter().map(|x| x.to_string()).collect();
        self
    }
}

impl Prompter for FakePrompter {
    fn interactive(&self) -> bool {
        self.interactive
    }
    fn read_secret(&mut self, prompt: &str) -> std::io::Result<zeroize::Zeroizing<String>> {
        self.asked.push(prompt.to_string());
        self.secrets
            .pop_front()
            .map(zeroize::Zeroizing::new)
            .ok_or_else(|| std::io::ErrorKind::UnexpectedEof.into())
    }
    fn read_line(&mut self, prompt: &str) -> std::io::Result<String> {
        self.asked.push(prompt.to_string());
        self.lines
            .pop_front()
            .ok_or_else(|| std::io::ErrorKind::UnexpectedEof.into())
    }
}

struct Out {
    result: Result<u8, SinterError>,
    stdout: Vec<u8>,
    stderr: String,
    asked: Vec<String>,
}

impl Out {
    fn ok(&self) -> bool {
        matches!(self.result, Ok(0))
    }
    fn err(&self) -> String {
        match &self.result {
            Err(e) => e.message.clone(),
            Ok(c) => format!("(ok {})", c),
        }
    }
    fn code(&self) -> i32 {
        match &self.result {
            Ok(c) => *c as i32,
            Err(e) => e.kind.exit_code(),
        }
    }
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

fn env_in(root: &Path) -> Env {
    Env {
        identity_env: None,
        xdg_config_home: None,
        home: Some(root.join("home")),
        cwd: root.to_path_buf(),
        euid: euid(),
    }
}

fn exec(
    env: &Env,
    mut prompter: FakePrompter,
    stdin: &[u8],
    stdin_tty: bool,
    stdout_tty: bool,
    f: impl FnOnce(&mut Io<'_>) -> Result<u8, SinterError>,
) -> Out {
    let mut stdin_r = stdin;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = {
        let mut io = Io {
            stdin: &mut stdin_r,
            stdin_is_tty: stdin_tty,
            stdout: &mut stdout,
            stdout_is_tty: stdout_tty,
            stderr: &mut stderr,
            prompter: &mut prompter,
            env,
        };
        f(&mut io)
    };
    Out {
        result,
        stdout,
        stderr: String::from_utf8_lossy(&stderr).to_string(),
        asked: prompter.asked,
    }
}

fn enc(env: &Env, p: FakePrompter, stdin: &[u8], args: EncryptArgs) -> Out {
    exec(env, p, stdin, false, false, |io| encrypt(&args, io))
}

fn dec(env: &Env, p: FakePrompter, args: DecryptArgs) -> Out {
    exec(env, p, b"", false, false, |io| decrypt(&args, io))
}

fn lst(env: &Env, args: ListArgs) -> Out {
    exec(env, FakePrompter::new(false), b"", false, false, |io| {
        list(&args, io)
    })
}

fn ea(file: &Path) -> EncryptArgs {
    EncryptArgs {
        file: file.to_path_buf(),
        ..Default::default()
    }
}

fn da(file: &Path) -> DecryptArgs {
    DecryptArgs {
        file: file.to_path_buf(),
        identity: None,
    }
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

struct Ident {
    text: Vec<u8>,
    recipient: String,
}

fn ident() -> Ident {
    let g = secrets::generate_identity();
    Ident {
        text: g.identity_file.expose().to_vec(),
        recipient: g.recipient.to_text(),
    }
}

/// One passphrase-protected identity for the whole test binary (the default
/// scrypt work factor makes each protection take about a second).
fn protected() -> &'static (Vec<u8>, String, Vec<u8>) {
    static P: OnceLock<(Vec<u8>, String, Vec<u8>)> = OnceLock::new();
    P.get_or_init(|| {
        let g = secrets::generate_identity();
        let pass = Passphrase::for_encryption(PASS.to_string()).unwrap();
        let ct = secrets::protect_identity(&g.identity_file, &pass).unwrap();
        (ct, g.recipient.to_text(), g.identity_file.expose().to_vec())
    })
}

fn sandbox() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("home")).unwrap();
    d
}

/// All `.sinter-tmp` leftovers under `dir`.
fn tmp_leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".sinter-tmp"))
        .collect()
}

/// The secrets that must never appear in any non-decrypt output.
fn assert_clean(label: &str, text: &str) {
    for needle in [CANARY, PASS, "AGE-SECRET-KEY-"] {
        assert!(
            !text.contains(needle),
            "{} leaked {:?}: {}",
            label,
            needle,
            text
        );
    }
}

fn note_surfaces(surfaces: &mut Vec<(String, String)>, label: &str, o: &Out) {
    surfaces.push((format!("{} stderr", label), o.stderr.clone()));
    surfaces.push((
        format!("{} error", label),
        match &o.result {
            Err(e) => format!("{} / {:?}", e.message, e),
            Ok(_) => String::new(),
        },
    ));
}

fn all_bytes() -> Vec<u8> {
    let mut v: Vec<u8> = (0..=255u8).collect();
    v.extend_from_slice(b"\r\nCRLF no newline");
    v
}

// ---------------------------------------------------------------------------
// encrypt
// ---------------------------------------------------------------------------

#[test]
fn encrypt_binary_roundtrip_with_a_recipient() {
    let d = sandbox();
    let id = ident();
    let src = d.path().join("blob.bin");
    std::fs::write(&src, all_bytes()).unwrap();
    let env = env_in(d.path());
    let mut a = ea(&src);
    a.recipients = vec![id.recipient.clone()];
    let o = enc(&env, FakePrompter::new(false), b"", a);
    assert!(o.ok(), "{}", o.err());
    assert!(o.stdout.is_empty(), "encrypt must not write to stdout");
    let out = d.path().join("blob.bin.age");
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(tmp_leftovers(d.path()).is_empty());
    // The source was not touched and no plaintext is in the ciphertext.
    assert_eq!(std::fs::read(&src).unwrap(), all_bytes());
    assert!(
        o.stderr.contains("was not changed or deleted"),
        "{}",
        o.stderr
    );
    let ct = std::fs::read(&out).unwrap();
    assert!(!ct.windows(16).any(|w| w == &all_bytes()[..16]));
    // Decrypt with the identity.
    let idf = d.path().join("id.txt");
    write_mode(&idf, &id.text, 0o600);
    let mut da = da(&out);
    da.identity = Some(idf);
    let r = dec(&env, FakePrompter::new(false), da);
    assert!(r.ok(), "{}", r.err());
    assert_eq!(r.stdout, all_bytes());
}

#[test]
fn encrypt_empty_file_and_size_boundary() {
    let d = sandbox();
    let id = ident();
    let env = env_in(d.path());
    let mk = |name: &str, len: usize| {
        let p = d.path().join(name);
        std::fs::write(&p, vec![7u8; len]).unwrap();
        let mut a = ea(&p);
        a.recipients = vec![id.recipient.clone()];
        a
    };
    assert!(enc(&env, FakePrompter::new(false), b"", mk("empty", 0)).ok());
    assert!(enc(
        &env,
        FakePrompter::new(false),
        b"",
        mk("max", MAX_SECRET_BYTES)
    )
    .ok());
    let o = enc(
        &env,
        FakePrompter::new(false),
        b"",
        mk("over", MAX_SECRET_BYTES + 1),
    );
    assert_eq!(o.code(), 2, "{}", o.err());
    assert!(o.err().contains("larger than"), "{}", o.err());
    assert!(!d.path().join("over.age").exists());
    // The same limit applies to stdin.
    let mut a = ea(Path::new("-"));
    a.output = Some(d.path().join("stdin.age"));
    a.recipients = vec![id.recipient.clone()];
    let big = vec![1u8; MAX_SECRET_BYTES + 1];
    let o = enc(&env, FakePrompter::new(false), &big, a);
    assert_eq!(o.code(), 2);
    assert!(!d.path().join("stdin.age").exists());
}

#[test]
fn encrypt_multiple_recipients_and_malformed_recipient_is_not_echoed() {
    let d = sandbox();
    let (a, b) = (ident(), ident());
    let src = d.path().join("s");
    std::fs::write(&src, CANARY).unwrap();
    let env = env_in(d.path());
    let mut args = ea(&src);
    args.recipients = vec![a.recipient.clone(), b.recipient.clone()];
    assert!(enc(&env, FakePrompter::new(false), b"", args).ok());
    let ct = std::fs::read(d.path().join("s.age")).unwrap();
    assert_eq!(secrets::inspect(&ct).unwrap().recipients, 2);

    let bad = "age1notarealrecipientXYZ-SECRET-LOOKING";
    let mut args = ea(&src);
    args.output = Some(d.path().join("other.age"));
    args.recipients = vec![a.recipient.clone(), bad.to_string()];
    let o = enc(&env, FakePrompter::new(false), b"", args);
    assert_eq!(o.code(), 2);
    assert!(!o.err().contains("XYZ-SECRET-LOOKING"), "{}", o.err());
    assert!(o.err().contains("recipient #2"), "{}", o.err());
    assert!(!d.path().join("other.age").exists());
}

#[test]
fn encrypt_passphrase_mode_prompts_twice_and_enforces_policy() {
    let d = sandbox();
    let src = d.path().join("s");
    std::fs::write(&src, CANARY).unwrap();
    let env = env_in(d.path());
    // Success.
    let mut a = ea(&src);
    a.passphrase = true;
    let o = enc(&env, FakePrompter::new(true).secrets(&[PASS, PASS]), b"", a);
    assert!(o.ok(), "{}", o.err());
    assert_eq!(o.asked, ["Enter passphrase: ", "Confirm passphrase: "]);
    assert_clean("stderr", &o.stderr);
    let ct = std::fs::read(d.path().join("s.age")).unwrap();
    assert_eq!(secrets::inspect(&ct).unwrap().method, Method::Passphrase);
    // Mismatch, too short, and no terminal each leave nothing behind.
    for (label, p, code) in [
        (
            "mismatch",
            FakePrompter::new(true).secrets(&[PASS, "another passphrase"]),
            2,
        ),
        (
            "short",
            FakePrompter::new(true).secrets(&["short", "short"]),
            2,
        ),
        ("no tty", FakePrompter::new(false), 2),
    ] {
        let mut a = ea(&src);
        a.passphrase = true;
        a.output = Some(d.path().join(format!("{}.age", label.replace(' ', "-"))));
        let o = enc(&env, p, b"", a);
        assert_eq!(o.code(), code, "{}: {}", label, o.err());
        assert_clean(label, &o.err());
        assert!(!d
            .path()
            .join(format!("{}.age", label.replace(' ', "-")))
            .exists());
    }
}

#[test]
fn encrypt_passphrase_and_recipient_cannot_be_combined() {
    let d = sandbox();
    let src = d.path().join("s");
    std::fs::write(&src, "x").unwrap();
    let mut a = ea(&src);
    a.passphrase = true;
    a.recipients = vec![ident().recipient];
    let o = enc(&env_in(d.path()), FakePrompter::new(true), b"", a);
    assert_eq!(o.code(), 2);
}

#[test]
fn encrypt_from_stdin_needs_an_output_and_refuses_a_terminal() {
    let d = sandbox();
    let id = ident();
    let env = env_in(d.path());
    let mut a = ea(Path::new("-"));
    a.recipients = vec![id.recipient.clone()];
    let o = enc(&env, FakePrompter::new(false), CANARY.as_bytes(), a.clone());
    assert_eq!(o.code(), 2, "{}", o.err());
    assert!(o.err().contains("-o"), "{}", o.err());
    a.output = Some(d.path().join("from-stdin.age"));
    let o = exec(&env, FakePrompter::new(false), b"", true, false, |io| {
        encrypt(&a, io)
    });
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("terminal"), "{}", o.err());
    let o = enc(&env, FakePrompter::new(false), CANARY.as_bytes(), a);
    assert!(o.ok(), "{}", o.err());
    assert!(
        !o.stderr.contains("was not changed"),
        "no original file to mention"
    );
    let ct = std::fs::read(d.path().join("from-stdin.age")).unwrap();
    assert!(secrets::inspect(&ct).is_ok());
}

#[test]
fn encrypt_never_writes_ciphertext_to_stdout() {
    let d = sandbox();
    let id = ident();
    let src = d.path().join("s");
    std::fs::write(&src, "x").unwrap();
    let mut a = ea(&src);
    a.recipients = vec![id.recipient];
    a.output = Some(PathBuf::from("-"));
    let o = enc(&env_in(d.path()), FakePrompter::new(false), b"", a);
    assert_eq!(o.code(), 2);
    assert!(o.stdout.is_empty());
}

#[test]
fn encrypt_output_collision_force_and_symlink_rules() {
    let d = sandbox();
    let id = ident();
    let env = env_in(d.path());
    let src = d.path().join("s");
    std::fs::write(&src, CANARY).unwrap();
    let base = |out: &Path| {
        let mut a = ea(&src);
        a.recipients = vec![id.recipient.clone()];
        a.output = Some(out.to_path_buf());
        a
    };
    let out = d.path().join("out.age");
    assert!(enc(&env, FakePrompter::new(false), b"", base(&out)).ok());
    let first = std::fs::read(&out).unwrap();
    // Collision: refused, untouched.
    let o = enc(&env, FakePrompter::new(false), b"", base(&out));
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("--force"), "{}", o.err());
    assert_eq!(std::fs::read(&out).unwrap(), first);
    // --force replaces an age file.
    let mut a = base(&out);
    a.force = true;
    assert!(enc(&env, FakePrompter::new(false), b"", a).ok());
    assert_ne!(std::fs::read(&out).unwrap(), first);
    assert!(tmp_leftovers(d.path()).is_empty());
    // --force never replaces a non-age file.
    let plain = d.path().join("plain.txt");
    std::fs::write(&plain, "do not clobber").unwrap();
    let mut a = base(&plain);
    a.force = true;
    let o = enc(&env, FakePrompter::new(false), b"", a);
    assert_eq!(o.code(), 2);
    assert_eq!(std::fs::read(&plain).unwrap(), b"do not clobber");
    // A symlink output is refused, with or without --force; its target is untouched.
    let link = d.path().join("link.age");
    symlink(&plain, &link).unwrap();
    for force in [false, true] {
        let mut a = base(&link);
        a.force = force;
        let o = enc(&env, FakePrompter::new(false), b"", a);
        assert_eq!(o.code(), 2);
        assert!(o.err().contains("symbolic link"), "{}", o.err());
    }
    assert_eq!(std::fs::read(&plain).unwrap(), b"do not clobber");
    // A dangling symlink output is refused too (no write through it).
    let dangling = d.path().join("dangling.age");
    symlink(d.path().join("nowhere"), &dangling).unwrap();
    assert_eq!(
        enc(&env, FakePrompter::new(false), b"", base(&dangling)).code(),
        2
    );
    assert!(!d.path().join("nowhere").exists());
    // Missing output directory.
    let o = enc(
        &env,
        FakePrompter::new(false),
        b"",
        base(&d.path().join("no/such/dir/x.age")),
    );
    assert_eq!(o.code(), 2);
}

#[test]
fn encrypt_refuses_unsafe_sources() {
    let d = sandbox();
    let id = ident();
    let env = env_in(d.path());
    let real = d.path().join("real");
    std::fs::write(&real, "x").unwrap();
    let link = d.path().join("link");
    symlink(&real, &link).unwrap();
    let fifo = d.path().join("fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    std::fs::create_dir(d.path().join("dir")).unwrap();
    for src in [
        &link,
        &fifo,
        &d.path().join("dir"),
        &d.path().join("missing"),
    ] {
        let mut a = ea(src);
        a.recipients = vec![id.recipient.clone()];
        a.output = Some(d.path().join("o.age"));
        let o = enc(&env, FakePrompter::new(false), b"", a);
        assert_ne!(o.code(), 0, "{:?}", src);
        assert!(!d.path().join("o.age").exists());
    }
}

#[test]
fn encrypt_discovers_the_nearest_recipients_file_inside_the_repository() {
    let d = sandbox();
    let (near, far) = (ident(), ident());
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(repo.join("a/b")).unwrap();
    std::fs::write(
        repo.join(RECIPIENTS_FILE),
        format!("# far\n{}\n", far.recipient),
    )
    .unwrap();
    std::fs::write(
        repo.join("a").join(RECIPIENTS_FILE),
        format!("{}\n", near.recipient),
    )
    .unwrap();
    let src = repo.join("a/b/secret");
    std::fs::write(&src, CANARY).unwrap();
    let env = env_in(d.path());
    let o = enc(&env, FakePrompter::new(false), b"", ea(&src));
    assert!(o.ok(), "{}", o.err());
    let ct = std::fs::read(repo.join("a/b/secret.age")).unwrap();
    let mut k = Keys::new();
    k.add_identity_file(&near.text).unwrap();
    assert!(
        secrets::decrypt(&ct, &k).is_ok(),
        "nearest recipients.txt must win"
    );
    let mut k = Keys::new();
    k.add_identity_file(&far.text).unwrap();
    assert!(secrets::decrypt(&ct, &k).is_err());
}

#[test]
fn encrypt_does_not_search_above_a_non_repository_directory() {
    let d = sandbox();
    let id = ident();
    // A recipients.txt two levels up, but no .git anywhere: not used.
    std::fs::create_dir_all(d.path().join("x/y")).unwrap();
    std::fs::write(
        d.path().join("x").join(RECIPIENTS_FILE),
        format!("{}\n", id.recipient),
    )
    .unwrap();
    let src = d.path().join("x/y/s");
    std::fs::write(&src, "v").unwrap();
    let o = enc(&env_in(d.path()), FakePrompter::new(false), b"", ea(&src));
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("no recipients"), "{}", o.err());
    assert!(!d.path().join("x/y/s.age").exists());
}

#[test]
fn encrypt_without_configuration_and_without_a_terminal_fails_clearly() {
    let d = sandbox();
    let src = d.path().join("s");
    std::fs::write(&src, "v").unwrap();
    let o = enc(&env_in(d.path()), FakePrompter::new(false), b"", ea(&src));
    assert_eq!(o.code(), 2);
    assert!(
        o.err().contains("--passphrase") && o.err().contains("-r"),
        "{}",
        o.err()
    );
    assert!(
        o.asked.is_empty(),
        "nothing may be asked without a terminal"
    );
}

#[test]
fn encrypt_interactive_choice_passphrase() {
    let d = sandbox();
    let src = d.path().join("s");
    std::fs::write(&src, CANARY).unwrap();
    let o = enc(
        &env_in(d.path()),
        FakePrompter::new(true).lines(&["1"]).secrets(&[PASS, PASS]),
        b"",
        ea(&src),
    );
    assert!(o.ok(), "{}", o.err());
    let ct = std::fs::read(d.path().join("s.age")).unwrap();
    assert_eq!(secrets::inspect(&ct).unwrap().method, Method::Passphrase);
}

#[test]
fn encrypt_interactive_key_pair_outside_the_repository_is_the_default_choice() {
    let d = sandbox();
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let src = repo.join("secret");
    std::fs::write(&src, CANARY).unwrap();
    let env = env_in(d.path());
    let o = enc(
        &env,
        FakePrompter::new(true)
            .lines(&["2", "1"])
            .secrets(&[PASS, PASS]),
        b"",
        ea(&src),
    );
    assert!(o.ok(), "{}", o.err());
    assert_clean("stderr", &o.stderr);
    let ext = env.external_identity_path().unwrap();
    assert!(ext.starts_with(d.path().join("home/.config/sinter")));
    assert!(ext.exists() && !repo.join(REPO_IDENTITY_FILE).exists());
    assert_eq!(
        std::fs::metadata(&ext).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(ext.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let stored = std::fs::read(&ext).unwrap();
    assert_eq!(
        secrets::inspect(&stored).unwrap().method,
        Method::Passphrase,
        "stored protected"
    );
    assert!(repo.join(RECIPIENTS_FILE).exists());
    // The menu told the operator which choice is recommended and why.
    let menu = o.asked.iter().find(|p| p.contains("Where should")).unwrap();
    assert!(
        menu.contains("(recommended)") && menu.contains("guess its passphrase"),
        "{}",
        menu
    );
    // And it can be decrypted with that identity.
    let r = dec(
        &env,
        FakePrompter::new(true).secrets(&[PASS]),
        da(&repo.join("secret.age")),
    );
    assert!(r.ok(), "{}", r.err());
    assert_eq!(r.stdout, CANARY.as_bytes());
}

#[test]
fn encrypt_interactive_key_pair_in_the_repository_is_explicit_and_protected() {
    let d = sandbox();
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let src = repo.join("secret");
    std::fs::write(&src, CANARY).unwrap();
    let env = env_in(d.path());
    let o = enc(
        &env,
        FakePrompter::new(true)
            .lines(&["2", "2"])
            .secrets(&[PASS, PASS]),
        b"",
        ea(&src),
    );
    assert!(o.ok(), "{}", o.err());
    let idf = repo.join(REPO_IDENTITY_FILE);
    let stored = std::fs::read(&idf).unwrap();
    assert_eq!(
        secrets::inspect(&stored).unwrap().method,
        Method::Passphrase
    );
    assert!(!String::from_utf8_lossy(&stored).contains("AGE-SECRET-KEY"));
    assert!(!env.external_identity_path().unwrap().exists());
    // Repository-local discovery then works, with the passphrase.
    let r = dec(
        &env,
        FakePrompter::new(true).secrets(&[PASS]),
        da(&repo.join("secret.age")),
    );
    assert!(r.ok(), "{}", r.err());
    assert!(
        r.stderr.contains("the repository's protected identity"),
        "{}",
        r.stderr
    );
}

#[test]
fn encrypt_interactive_key_pair_never_overwrites_an_existing_identity() {
    let d = sandbox();
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let src = repo.join("secret");
    std::fs::write(&src, "v").unwrap();
    let env = env_in(d.path());
    let ext = env.external_identity_path().unwrap();
    write_mode(&ext, b"existing identity bytes", 0o600);
    let o = enc(
        &env,
        FakePrompter::new(true)
            .lines(&["2", "1"])
            .secrets(&[PASS, PASS]),
        b"",
        ea(&src),
    );
    assert_eq!(o.code(), 2, "{}", o.err());
    assert_eq!(std::fs::read(&ext).unwrap(), b"existing identity bytes");
    assert!(!repo.join(RECIPIENTS_FILE).exists());
    // A bad menu answer creates nothing.
    let o = enc(&env, FakePrompter::new(true).lines(&["9"]), b"", ea(&src));
    assert_eq!(o.code(), 2);
}

// ---------------------------------------------------------------------------
// decrypt
// ---------------------------------------------------------------------------

fn make_secret(dir: &Path, name: &str, plain: &[u8], recipients: &[&str]) -> PathBuf {
    let rs = secrets::parse_recipients(&recipients.join("\n")).unwrap();
    let ct = secrets::encrypt_to_recipients(plain, &rs).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, ct).unwrap();
    p
}

#[test]
fn decrypt_with_a_protected_identity() {
    let d = sandbox();
    let (prot, recipient, _) = protected();
    let secret = make_secret(d.path(), "s.age", CANARY.as_bytes(), &[recipient]);
    let idf = d.path().join("prot.age");
    std::fs::write(&idf, prot).unwrap();
    let mut a = da(&secret);
    a.identity = Some(idf.clone());
    let env = env_in(d.path());
    let o = dec(&env, FakePrompter::new(true).secrets(&[PASS]), a.clone());
    assert!(o.ok(), "{}", o.err());
    assert_eq!(o.stdout, CANARY.as_bytes(), "exact bytes, no added newline");
    assert_clean("stderr", &o.stderr);
    // Wrong passphrase: fixed message, nothing on stdout.
    let o = dec(
        &env,
        FakePrompter::new(true).secrets(&["wrong wrong wrong"]),
        a.clone(),
    );
    assert_eq!(o.code(), 5);
    assert!(
        o.err().contains("could not unlock the identity"),
        "{}",
        o.err()
    );
    assert!(o.stdout.is_empty());
    assert_clean("error", &o.err());
    // No terminal: refuse and say what automation needs.
    let o = dec(&env, FakePrompter::new(false), a);
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("unprotected identity"), "{}", o.err());
    assert!(o.asked.is_empty());
}

#[test]
fn decrypt_passphrase_ciphertext() {
    let d = sandbox();
    let secret = d.path().join("p.age");
    let p = Passphrase::for_encryption(PASS.to_string()).unwrap();
    std::fs::write(
        &secret,
        secrets::encrypt_with_passphrase(CANARY.as_bytes(), &p).unwrap(),
    )
    .unwrap();
    let env = env_in(d.path());
    let o = dec(&env, FakePrompter::new(true).secrets(&[PASS]), da(&secret));
    assert!(o.ok(), "{}", o.err());
    assert_eq!(o.stdout, CANARY.as_bytes());
    assert_eq!(o.asked, ["Passphrase: "]);
    let o = dec(
        &env,
        FakePrompter::new(true).secrets(&["not the passphrase"]),
        da(&secret),
    );
    assert_eq!(o.code(), 5);
    assert!(o.stdout.is_empty());
    assert_clean("err", &o.err());
    let o = dec(&env, FakePrompter::new(false), da(&secret));
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("terminal"), "{}", o.err());
    // --identity does not apply to a passphrase secret.
    let mut a = da(&secret);
    a.identity = Some(d.path().join("whatever"));
    let o = dec(&env, FakePrompter::new(true), a);
    assert_eq!(o.code(), 2);
    assert!(o.asked.is_empty());
}

#[test]
fn decrypt_wrong_identity_and_malformed_inputs() {
    let d = sandbox();
    let (owner, stranger) = (ident(), ident());
    let secret = make_secret(d.path(), "s.age", CANARY.as_bytes(), &[&owner.recipient]);
    let idf = d.path().join("stranger");
    write_mode(&idf, &stranger.text, 0o600);
    let mut a = da(&secret);
    a.identity = Some(idf);
    let env = env_in(d.path());
    let o = dec(&env, FakePrompter::new(false), a);
    assert_eq!(o.code(), 5, "{}", o.err());
    assert!(o.err().contains("none of the supplied keys"), "{}", o.err());
    assert!(o.stdout.is_empty());
    // Not an age file, empty, and a directory.
    for (name, bytes) in [("junk.age", &b"definitely not age"[..]), ("empty.age", b"")] {
        let p = d.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        let o = dec(&env, FakePrompter::new(false), da(&p));
        assert_ne!(o.code(), 0, "{}", name);
        assert!(o.stdout.is_empty());
    }
    assert_ne!(dec(&env, FakePrompter::new(false), da(d.path())).code(), 0);
    // Corrupt payload.
    let mut ct = std::fs::read(&secret).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 1;
    let bad = d.path().join("bad.age");
    std::fs::write(&bad, ct).unwrap();
    let idf2 = d.path().join("owner");
    write_mode(&idf2, &owner.text, 0o600);
    let mut a = da(&bad);
    a.identity = Some(idf2);
    let o = dec(&env, FakePrompter::new(false), a);
    assert_eq!(o.code(), 5, "{}", o.err());
    assert!(o.stdout.is_empty());
}

#[test]
fn decrypt_hostile_header_fails_fast() {
    let d = sandbox();
    let mut v = b"age-encryption.org/v1\n".to_vec();
    for _ in 0..5000 {
        v.extend_from_slice(b"-> a-grease\n");
    }
    v.extend_from_slice(b"--- AAAA\n");
    let p = d.path().join("hostile.age");
    std::fs::write(&p, v).unwrap();
    let t = std::time::Instant::now();
    let o = dec(
        &env_in(d.path()),
        FakePrompter::new(true).secrets(&[PASS]),
        da(&p),
    );
    assert_ne!(o.code(), 0);
    assert!(t.elapsed() < std::time::Duration::from_secs(3));
    assert!(o.asked.is_empty(), "must fail before asking for anything");
}

#[test]
fn decrypt_refuses_a_terminal_stdout_before_prompting() {
    let d = sandbox();
    let id = ident();
    let secret = make_secret(d.path(), "s.age", CANARY.as_bytes(), &[&id.recipient]);
    let o = exec(
        &env_in(d.path()),
        FakePrompter::new(true),
        b"",
        false,
        true,
        |io| decrypt(&da(&secret), io),
    );
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("terminal"), "{}", o.err());
    assert!(o.asked.is_empty() && o.stdout.is_empty());
}

#[test]
fn decrypt_output_failure_reports_no_content() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let d = sandbox();
    let id = ident();
    let secret = make_secret(d.path(), "s.age", CANARY.as_bytes(), &[&id.recipient]);
    let idf = d.path().join("id");
    write_mode(&idf, &id.text, 0o600);
    let env = env_in(d.path());
    let mut p = FakePrompter::new(false);
    let mut stdin: &[u8] = b"";
    let mut err = Vec::new();
    let mut w = Broken;
    let mut io = Io {
        stdin: &mut stdin,
        stdin_is_tty: false,
        stdout: &mut w,
        stdout_is_tty: false,
        stderr: &mut err,
        prompter: &mut p,
        env: &env,
    };
    let mut a = da(&secret);
    a.identity = Some(idf);
    let e = decrypt(&a, &mut io).unwrap_err();
    assert_eq!(e.kind.exit_code(), 5);
    assert_clean("error", &e.message);
}

// ---------------------------------------------------------------------------
// identity discovery
// ---------------------------------------------------------------------------

#[test]
fn external_default_path_follows_xdg_then_home() {
    let mut e = Env {
        home: Some(PathBuf::from("/home/u")),
        ..Default::default()
    };
    assert_eq!(
        e.external_identity_path().unwrap(),
        Path::new("/home/u/.config/sinter/identity")
    );
    e.xdg_config_home = Some(PathBuf::from("/xdg"));
    assert_eq!(
        e.external_identity_path().unwrap(),
        Path::new("/xdg/sinter/identity")
    );
    // A relative XDG_CONFIG_HOME is ignored (per the XDG specification).
    e.xdg_config_home = Some(PathBuf::from("relative/xdg"));
    assert_eq!(
        e.external_identity_path().unwrap(),
        Path::new("/home/u/.config/sinter/identity")
    );
    e.home = None;
    assert!(e.external_identity_path().is_none());
    e.home = Some(PathBuf::from("relative-home"));
    assert!(e.external_identity_path().is_none());
}

#[test]
fn identity_precedence_flag_env_external_repository() {
    let d = sandbox();
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let (flag, envi, ext) = (ident(), ident(), ident());
    let (prot, prot_recipient, _) = protected();
    let secret = make_secret(
        &repo,
        "s.age",
        CANARY.as_bytes(),
        &[
            &flag.recipient,
            &envi.recipient,
            &ext.recipient,
            prot_recipient,
        ],
    );
    let mut env = env_in(d.path());
    let flag_p = d.path().join("flag.id");
    let env_p = d.path().join("env.id");
    write_mode(&flag_p, &flag.text, 0o600);
    write_mode(&env_p, &envi.text, 0o600);
    write_mode(&env.external_identity_path().unwrap(), &ext.text, 0o600);
    write_mode(&repo.join(REPO_IDENTITY_FILE), prot, 0o644);
    env.identity_env = Some(env_p.clone().into_os_string());
    let used = |o: &Out| {
        o.stderr
            .lines()
            .find(|l| l.contains("using the identity from"))
            .unwrap_or("")
            .to_string()
    };
    // 1. --identity beats everything.
    let mut a = da(&secret);
    a.identity = Some(flag_p.clone());
    let o = dec(&env, FakePrompter::new(false), a);
    assert!(o.ok(), "{}", o.err());
    assert!(used(&o).contains("--identity"), "{}", o.stderr);
    // 2. SINTER_IDENTITY next.
    let o = dec(&env, FakePrompter::new(false), da(&secret));
    assert!(o.ok(), "{}", o.err());
    assert!(used(&o).contains("SINTER_IDENTITY"), "{}", o.stderr);
    // 3. The external default next; the repository identity is not even asked about.
    env.identity_env = None;
    let o = dec(&env, FakePrompter::new(false), da(&secret));
    assert!(o.ok(), "{}", o.err());
    assert!(used(&o).contains("the default identity"), "{}", o.stderr);
    assert!(o.asked.is_empty());
    // 4. Finally the repository's protected identity, with a passphrase.
    std::fs::remove_file(env.external_identity_path().unwrap()).unwrap();
    let o = dec(&env, FakePrompter::new(true).secrets(&[PASS]), da(&secret));
    assert!(o.ok(), "{}", o.err());
    assert!(
        used(&o).contains("the repository's protected identity"),
        "{}",
        o.stderr
    );
    // 5. Nothing at all: a clear error naming the options.
    std::fs::remove_file(repo.join(REPO_IDENTITY_FILE)).unwrap();
    let o = dec(&env, FakePrompter::new(true), da(&secret));
    assert_eq!(o.code(), 2);
    assert!(
        o.err().contains("--identity") && o.err().contains("SINTER_IDENTITY"),
        "{}",
        o.err()
    );
}

#[test]
fn identity_candidates_never_fall_back_to_each_other() {
    let d = sandbox();
    let (a, b) = (ident(), ident());
    let secret = make_secret(d.path(), "s.age", CANARY.as_bytes(), &[&b.recipient]);
    let mut env = env_in(d.path());
    // The flag names a wrong identity while a right one exists elsewhere.
    let wrong = d.path().join("wrong");
    write_mode(&wrong, &a.text, 0o600);
    write_mode(&env.external_identity_path().unwrap(), &b.text, 0o600);
    let mut args = da(&secret);
    args.identity = Some(wrong);
    let o = dec(&env, FakePrompter::new(false), args);
    assert_eq!(o.code(), 5, "no trial and error across candidates");
    // A missing --identity file is an error, not a fallback.
    let mut args = da(&secret);
    args.identity = Some(d.path().join("missing"));
    assert_ne!(dec(&env, FakePrompter::new(false), args).code(), 0);
    // An empty SINTER_IDENTITY is an error.
    env.identity_env = Some("".into());
    assert_eq!(dec(&env, FakePrompter::new(false), da(&secret)).code(), 2);
}

#[test]
fn repository_identity_must_be_protected_and_is_never_a_symlink() {
    let d = sandbox();
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let id = ident();
    let secret = make_secret(&repo, "s.age", CANARY.as_bytes(), &[&id.recipient]);
    let env = env_in(d.path());
    // A plaintext identity.age in the repository is refused, even if 0600.
    write_mode(&repo.join(REPO_IDENTITY_FILE), &id.text, 0o600);
    let o = dec(&env, FakePrompter::new(true), da(&secret));
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("never used automatically"), "{}", o.err());
    assert!(o.stdout.is_empty());
    assert_clean("err", &o.err());
    // A symlinked identity.age is refused.
    std::fs::remove_file(repo.join(REPO_IDENTITY_FILE)).unwrap();
    let real = d.path().join("elsewhere");
    write_mode(&real, &protected().0, 0o600);
    symlink(&real, repo.join(REPO_IDENTITY_FILE)).unwrap();
    let o = dec(&env, FakePrompter::new(true).secrets(&[PASS]), da(&secret));
    assert_eq!(o.code(), 2, "{}", o.err());
    assert!(o.err().contains("symbolic link"), "{}", o.err());
    // An encrypted-but-not-passphrase identity.age is refused.
    std::fs::remove_file(repo.join(REPO_IDENTITY_FILE)).unwrap();
    let rs = secrets::parse_recipients(&id.recipient).unwrap();
    std::fs::write(
        repo.join(REPO_IDENTITY_FILE),
        secrets::encrypt_to_recipients(&id.text, &rs).unwrap(),
    )
    .unwrap();
    let o = dec(&env, FakePrompter::new(true), da(&secret));
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("protected by a passphrase"), "{}", o.err());
}

#[test]
fn repository_protected_identity_needs_a_terminal() {
    let d = sandbox();
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let (prot, recipient, _) = protected();
    let secret = make_secret(&repo, "s.age", CANARY.as_bytes(), &[recipient]);
    write_mode(&repo.join(REPO_IDENTITY_FILE), prot, 0o644);
    let o = dec(&env_in(d.path()), FakePrompter::new(false), da(&secret));
    assert_eq!(o.code(), 2);
    assert!(
        o.err()
            .contains("unprotected identity kept outside the repository"),
        "{}",
        o.err()
    );
}

#[test]
fn plaintext_identity_permissions_and_ownership_are_enforced() {
    let d = sandbox();
    let id = ident();
    let secret = make_secret(d.path(), "s.age", CANARY.as_bytes(), &[&id.recipient]);
    let idf = d.path().join("id");
    let mut a = da(&secret);
    a.identity = Some(idf.clone());
    let env = env_in(d.path());
    for mode in [0o644, 0o640, 0o604, 0o666] {
        write_mode(&idf, &id.text, mode);
        let o = dec(&env, FakePrompter::new(false), a.clone());
        assert_eq!(o.code(), 2, "mode {:o}", mode);
        assert!(o.err().contains("chmod 600"), "{}", o.err());
        assert!(o.stdout.is_empty());
        assert_clean("err", &o.err());
    }
    for mode in [0o600, 0o400] {
        write_mode(&idf, &id.text, mode);
        assert!(
            dec(&env, FakePrompter::new(false), a.clone()).ok(),
            "mode {:o}",
            mode
        );
    }
    // Owned by someone else (simulated by the injected effective uid).
    let mut other = env.clone();
    other.euid = euid().wrapping_add(1);
    let o = dec(&other, FakePrompter::new(false), a.clone());
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("owned by another user"), "{}", o.err());
    // A symlinked explicit identity is followed; the target's mode counts.
    let link = d.path().join("id-link");
    symlink(&idf, &link).unwrap();
    let mut a2 = da(&secret);
    a2.identity = Some(link);
    assert!(dec(&env, FakePrompter::new(false), a2).ok());
}

#[test]
fn malformed_and_oversized_identity_files_are_refused() {
    let d = sandbox();
    let id = ident();
    let secret = make_secret(d.path(), "s.age", CANARY.as_bytes(), &[&id.recipient]);
    let env = env_in(d.path());
    let run = |bytes: &[u8]| {
        let idf = d.path().join("badid");
        write_mode(&idf, bytes, 0o600);
        let mut a = da(&secret);
        a.identity = Some(idf);
        dec(&env, FakePrompter::new(false), a)
    };
    // Valid line followed by garbage: nothing is used.
    let mut partial = id.text.clone();
    partial.extend_from_slice(b"AGE-SECRET-KEY-1NOTVALID\n");
    for (label, bytes) in [
        ("garbage", b"not an identity\n".to_vec()),
        ("empty", Vec::new()),
        ("comment only", b"# nothing\n".to_vec()),
        ("partial", partial),
        ("binary", vec![0xff, 0xfe, 0x00]),
    ] {
        let o = run(&bytes);
        assert_eq!(o.code(), 2, "{}: {}", label, o.err());
        assert!(o.stdout.is_empty(), "{}", label);
        assert_clean(label, &o.err());
    }
    let o = run(&vec![b'#'; 1024 * 1024 + 1]);
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("larger than"), "{}", o.err());
    // A directory and a FIFO are not identity files (and the FIFO does not block).
    let mut a = da(&secret);
    a.identity = Some(d.path().to_path_buf());
    assert_eq!(dec(&env, FakePrompter::new(false), a).code(), 2);
    let fifo = d.path().join("fifo-id");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let mut a = da(&secret);
    a.identity = Some(fifo);
    assert_eq!(dec(&env, FakePrompter::new(false), a).code(), 2);
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

#[test]
fn list_describes_files_without_decrypting_and_in_a_stable_order() {
    let d = sandbox();
    let root = d.path().join("proj");
    std::fs::create_dir_all(root.join("sub/deeper")).unwrap();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    let (a, b) = (ident(), ident());
    make_secret(&root, "one.age", CANARY.as_bytes(), &[&a.recipient]);
    make_secret(
        &root.join("sub"),
        "two.age",
        CANARY.as_bytes(),
        &[&a.recipient, &b.recipient],
    );
    // Armored recipient file.
    let mut armored = Vec::new();
    {
        let rs = secrets::parse_recipients(&a.recipient).unwrap();
        let ct = secrets::encrypt_to_recipients(b"x", &rs).unwrap();
        let mut w =
            age::armor::ArmoredWriter::wrap_output(&mut armored, age::armor::Format::AsciiArmor)
                .unwrap();
        w.write_all(&ct).unwrap();
        w.finish().unwrap();
    }
    std::fs::write(root.join("sub/deeper/armored.age"), &armored).unwrap();
    // Passphrase file.
    let p = Passphrase::for_encryption(PASS.to_string()).unwrap();
    std::fs::write(
        root.join("pass.age"),
        secrets::encrypt_with_passphrase(b"x", &p).unwrap(),
    )
    .unwrap();
    // Not age, wrong version, ignored files, a .git decoy and a symlink.
    std::fs::write(root.join("junk.age"), b"not age").unwrap();
    std::fs::write(
        root.join("future.age"),
        b"age-encryption.org/v2\n-> x\n--- AAAA\n",
    )
    .unwrap();
    std::fs::write(root.join("notes.txt"), "ignored").unwrap();
    std::fs::write(root.join(".git/decoy.age"), b"ignored").unwrap();
    symlink(root.join("one.age"), root.join("link.age")).unwrap();

    let env = env_in(d.path());
    let o = exec(&env, FakePrompter::new(true), b"", false, false, |io| {
        list(
            &ListArgs {
                paths: vec![root.clone()],
                json: false,
            },
            io,
        )
    });
    assert!(o.ok(), "{}", o.err());
    assert!(o.asked.is_empty(), "list never prompts");
    let text = String::from_utf8(o.stdout.clone()).unwrap();
    assert_clean("list", &text);
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with("STATUS"), "{}", text);
    let row = |name: &str| {
        lines
            .iter()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("{} in {}", name, text))
            .to_string()
    };
    assert!(
        row("one.age").contains("recipients") && row("one.age").contains(" 1 "),
        "{}",
        row("one.age")
    );
    assert!(
        row("one.age").contains("single recipient"),
        "{}",
        row("one.age")
    );
    assert!(
        row("two.age").contains(" 2 ") && !row("two.age").contains("single recipient"),
        "{}",
        row("two.age")
    );
    assert!(row("armored.age").starts_with("ok") && row("armored.age").contains(" 1 "));
    assert!(
        row("pass.age").contains("passphrase") && row("pass.age").contains("cannot be recovered")
    );
    assert!(row("junk.age").starts_with("not-age"));
    assert!(row("future.age").starts_with("unsupported"));
    assert!(row("link.age").contains("symbolic link not followed"));
    assert!(!text.contains("notes.txt") && !text.contains("decoy.age"));
    // Deterministic: the same listing twice, sorted by path.
    let again = exec(&env, FakePrompter::new(false), b"", false, false, |io| {
        list(
            &ListArgs {
                paths: vec![root.clone()],
                json: false,
            },
            io,
        )
    });
    assert_eq!(again.stdout, o.stdout);
    let paths: Vec<&str> = lines[1..]
        .iter()
        .map(|l| l.split_whitespace().nth(3).unwrap_or(""))
        .collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted);
}

#[test]
fn list_recipient_count_ignores_the_decoy_stanza_and_json_is_structured() {
    let d = sandbox();
    let id = ident();
    let p = make_secret(d.path(), "x.age", b"v", &[&id.recipient]);
    // The raw header has two stanza lines (recipient + decoy); the listing says 1.
    let raw = std::fs::read(&p).unwrap();
    let end = raw.windows(4).position(|w| w == b"\n---").unwrap();
    assert_eq!(raw[..end].windows(4).filter(|w| *w == b"\n-> ").count(), 2);
    let o = lst(
        &env_in(d.path()),
        ListArgs {
            paths: vec![p.clone()],
            json: true,
        },
    );
    assert!(o.ok(), "{}", o.err());
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let e = &v["secrets"][0];
    assert_eq!(
        (
            e["status"].as_str(),
            e["method"].as_str(),
            e["recipients"].as_u64()
        ),
        (Some("ok"), Some("recipients"), Some(1))
    );
    assert!(e["note"].as_str().unwrap().contains("single recipient"));
}

#[test]
fn list_inspects_an_explicit_file_by_content_not_name() {
    let d = sandbox();
    let id = ident();
    let p = make_secret(d.path(), "secret.bin", b"v", &[&id.recipient]);
    let o = lst(
        &env_in(d.path()),
        ListArgs {
            paths: vec![p],
            json: false,
        },
    );
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("ok"),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    let missing = lst(
        &env_in(d.path()),
        ListArgs {
            paths: vec![d.path().join("nope")],
            json: false,
        },
    );
    assert_eq!(missing.code(), 2);
    let empty_dir = d.path().join("emptydir");
    std::fs::create_dir(&empty_dir).unwrap();
    let o = lst(
        &env_in(d.path()),
        ListArgs {
            paths: vec![empty_dir],
            json: false,
        },
    );
    assert!(String::from_utf8_lossy(&o.stdout).contains("no age files found"));
}

// ---------------------------------------------------------------------------
// canary regression across every command
// ---------------------------------------------------------------------------

#[test]
fn no_secret_reaches_any_non_decrypt_surface() {
    let d = sandbox();
    let env = env_in(d.path());
    let id = ident();
    let src = d.path().join("canary.txt");
    std::fs::write(&src, CANARY).unwrap();
    let idf = d.path().join("id");
    write_mode(&idf, &id.text, 0o600);
    let mut surfaces: Vec<(String, String)> = Vec::new();
    // encrypt: recipient, passphrase, interactive key pair, failures.
    let mut a = ea(&src);
    a.recipients = vec![id.recipient.clone()];
    let o = enc(&env, FakePrompter::new(false), b"", a.clone());
    assert!(o.stdout.is_empty());
    note_surfaces(&mut surfaces, "encrypt -r", &o);
    let o = enc(&env, FakePrompter::new(false), b"", a);
    assert!(o.stdout.is_empty());
    note_surfaces(&mut surfaces, "encrypt collision", &o);
    let mut a = ea(&src);
    a.passphrase = true;
    a.output = Some(d.path().join("p.age"));
    let o = enc(
        &env,
        FakePrompter::new(true).secrets(&[PASS, PASS]),
        b"",
        a.clone(),
    );
    assert!(o.stdout.is_empty());
    note_surfaces(&mut surfaces, "encrypt --passphrase", &o);
    let o = enc(
        &env,
        FakePrompter::new(true).secrets(&[PASS, "mismatch mismatch"]),
        b"",
        a,
    );
    note_surfaces(&mut surfaces, "encrypt mismatch", &o);
    let mut a = ea(&src);
    a.output = Some(d.path().join("kp.age"));
    let o = enc(
        &env,
        FakePrompter::new(true)
            .lines(&["2", "1"])
            .secrets(&[PASS, PASS]),
        b"",
        a,
    );
    assert!(o.stdout.is_empty());
    note_surfaces(&mut surfaces, "encrypt key pair", &o);
    // decrypt failures and the verbose identity path (stdout excluded on success).
    for (label, args, p) in [
        (
            "decrypt wrong pass",
            da(&d.path().join("p.age")),
            FakePrompter::new(true).secrets(&["wrong wrong wrong"]),
        ),
        (
            "decrypt no tty",
            da(&d.path().join("p.age")),
            FakePrompter::new(false),
        ),
        (
            "decrypt missing",
            da(&d.path().join("nope.age")),
            FakePrompter::new(false),
        ),
    ] {
        let o = dec(&env, p, args);
        assert!(o.stdout.is_empty(), "{}", label);
        note_surfaces(&mut surfaces, label, &o);
    }
    let mut a = da(&d.path().join("canary.txt.age"));
    a.identity = Some(idf);
    let o = dec(&env, FakePrompter::new(false), a);
    assert!(o.ok(), "{}", o.err());
    note_surfaces(&mut surfaces, "decrypt ok (stderr only)", &o);
    // list over everything.
    let o = lst(
        &env,
        ListArgs {
            paths: vec![d.path().to_path_buf()],
            json: false,
        },
    );
    surfaces.push((
        "list stdout".into(),
        String::from_utf8_lossy(&o.stdout).to_string(),
    ));
    note_surfaces(&mut surfaces, "list", &o);
    let o = lst(
        &env,
        ListArgs {
            paths: vec![d.path().to_path_buf()],
            json: true,
        },
    );
    surfaces.push((
        "list json".into(),
        String::from_utf8_lossy(&o.stdout).to_string(),
    ));
    for (label, text) in &surfaces {
        assert_clean(label, text);
    }
    // And no ciphertext file contains the plaintext, passphrase or identity.
    for e in std::fs::read_dir(d.path()).unwrap().filter_map(|e| e.ok()) {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "age") {
            assert_clean(
                &p.display().to_string(),
                &String::from_utf8_lossy(&std::fs::read(&p).unwrap()),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// independent-review regressions
// ---------------------------------------------------------------------------

#[test]
fn key_material_in_an_identity_setting_is_never_echoed() {
    let d = sandbox();
    let id = ident();
    let secret = make_secret(d.path(), "s.age", CANARY.as_bytes(), &[&id.recipient]);
    let key = String::from_utf8_lossy(&id.text)
        .lines()
        .last()
        .unwrap()
        .to_string();
    assert!(key.starts_with("AGE-SECRET-KEY-"));
    let mut env = env_in(d.path());
    for value in [key.clone(), format!("# c\n{}", key), format!("x/{}", key)] {
        env.identity_env = Some(value.clone().into());
        let o = dec(&env, FakePrompter::new(false), da(&secret));
        assert_eq!(o.code(), 2, "{}", o.err());
        assert!(o.err().contains("not the key itself"), "{}", o.err());
        assert!(!o.err().contains("AGE-SECRET-KEY") && o.stdout.is_empty());
        let mut a = da(&secret);
        a.identity = Some(PathBuf::from(&value));
        env.identity_env = None;
        let o = dec(&env, FakePrompter::new(false), a);
        assert_eq!(o.code(), 2);
        assert!(!o.err().contains("AGE-SECRET-KEY") && !o.stderr.contains("AGE-SECRET-KEY"));
    }
}

#[test]
fn discovered_recipients_are_announced_and_confirmed_on_a_terminal() {
    let d = sandbox();
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let planted = ident();
    std::fs::write(
        repo.join(RECIPIENTS_FILE),
        format!("{}\n", planted.recipient),
    )
    .unwrap();
    let src = repo.join("secret");
    std::fs::write(&src, CANARY).unwrap();
    let env = env_in(d.path());
    // Non-interactive: proceeds, but says which file and which key.
    let o = enc(&env, FakePrompter::new(false), b"", ea(&src));
    assert!(o.ok(), "{}", o.err());
    assert!(o.stderr.contains("recipients.txt"), "{}", o.stderr);
    assert!(
        o.stderr.contains(&planted.recipient[..10])
            && o.stderr
                .contains(&planted.recipient[planted.recipient.len() - 6..]),
        "{}",
        o.stderr
    );
    assert!(
        !o.stderr.contains(&planted.recipient),
        "only a fingerprint is shown"
    );
    std::fs::remove_file(repo.join("secret.age")).unwrap();
    // On a terminal: asks, and "no" (or anything but yes) writes nothing.
    for (answer, written) in [("n", false), ("", false), ("y", true), ("YES", true)] {
        let _ = std::fs::remove_file(repo.join("secret.age"));
        let o = enc(
            &env,
            FakePrompter::new(true).lines(&[answer]),
            b"",
            ea(&src),
        );
        assert_eq!(o.ok(), written, "answer {:?}: {}", answer, o.err());
        assert_eq!(repo.join("secret.age").exists(), written);
        assert!(o
            .asked
            .iter()
            .any(|p| p.contains("Encrypt to these 1 recipient")));
    }
    // -r skips discovery entirely: no notice, no question.
    let _ = std::fs::remove_file(repo.join("secret.age"));
    let mut a = ea(&src);
    a.recipients = vec![ident().recipient];
    let o = enc(&env, FakePrompter::new(true), b"", a);
    assert!(o.ok());
    assert!(o.asked.is_empty() && !o.stderr.contains("using the recipients"));
}

#[test]
fn long_names_double_extensions_and_odd_paths_are_handled() {
    let d = sandbox();
    let id = ident();
    let env = env_in(d.path());
    // A source name near the filesystem limit: the temp name does not grow with it.
    let long = "n".repeat(240);
    let src = d.path().join(&long);
    std::fs::write(&src, CANARY).unwrap();
    let mut a = ea(&src);
    a.recipients = vec![id.recipient.clone()];
    let o = enc(&env, FakePrompter::new(false), b"", a);
    assert!(o.ok(), "{}", o.err());
    assert!(tmp_leftovers(d.path()).is_empty());
    // Encrypting something that already ends in .age warns.
    let src2 = d.path().join("x.age");
    std::fs::write(&src2, CANARY).unwrap();
    let mut a = ea(&src2);
    a.recipients = vec![id.recipient.clone()];
    let o = enc(&env, FakePrompter::new(false), b"", a);
    assert!(o.ok());
    assert!(
        o.stderr.contains("already has the .age extension"),
        "{}",
        o.stderr
    );
}

#[test]
fn unsafe_permission_hint_quotes_the_path() {
    let d = sandbox();
    let id = ident();
    let secret = make_secret(d.path(), "s.age", CANARY.as_bytes(), &[&id.recipient]);
    let idf = d.path().join("my id; touch pwned");
    write_mode(&idf, &id.text, 0o644);
    let mut a = da(&secret);
    a.identity = Some(idf.clone());
    let o = dec(&env_in(d.path()), FakePrompter::new(false), a);
    assert_eq!(o.code(), 2);
    let quoted = format!("chmod 600 '{}'", idf.display());
    assert!(o.err().contains(&quoted), "{}", o.err());
}

#[test]
fn bidi_and_control_characters_in_names_are_neutralised_in_listings() {
    let d = sandbox();
    let id = ident();
    let name = "a\u{202E}b\u{200B}c.age";
    let p = make_secret(d.path(), name, b"v", &[&id.recipient]);
    assert!(p.exists());
    let o = lst(
        &env_in(d.path()),
        ListArgs {
            paths: vec![d.path().to_path_buf()],
            json: false,
        },
    );
    let text = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(
        !text.contains('\u{202E}') && !text.contains('\u{200B}'),
        "{:?}",
        text
    );
    assert!(text.contains("a?b?c.age"), "{:?}", text);
}

#[test]
fn an_unreachable_default_identity_fails_closed() {
    let d = sandbox();
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let (prot, recipient, _) = protected();
    let secret = make_secret(&repo, "s.age", CANARY.as_bytes(), &[recipient]);
    write_mode(&repo.join(REPO_IDENTITY_FILE), prot, 0o644);
    let env = env_in(d.path());
    let ext = env.external_identity_path().unwrap();
    write_mode(&ext, b"whatever", 0o600);
    let dir = ext.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let o = dec(&env, FakePrompter::new(true).secrets(&[PASS]), da(&secret));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    if euid() != 0 {
        assert_eq!(o.code(), 2, "{}", o.err());
        assert!(
            o.err().contains("cannot access the default identity"),
            "{}",
            o.err()
        );
        assert!(
            o.asked.is_empty(),
            "must not fall through to the repository identity"
        );
    }
}

#[test]
fn stdin_input_at_the_limit_works() {
    let d = sandbox();
    let id = ident();
    let mut a = ea(Path::new("-"));
    a.output = Some(d.path().join("big.age"));
    a.recipients = vec![id.recipient.clone()];
    let big = vec![9u8; MAX_SECRET_BYTES];
    let o = enc(&env_in(d.path()), FakePrompter::new(false), &big, a);
    assert!(o.ok(), "{}", o.err());
    let ct = std::fs::read(d.path().join("big.age")).unwrap();
    let mut k = Keys::new();
    k.add_identity_file(&id.text).unwrap();
    assert_eq!(secrets::decrypt(&ct, &k).unwrap().len(), MAX_SECRET_BYTES);
}

// ---------------------------------------------------------------------------
// real binary (no controlling terminal) and real pseudo-terminal
// ---------------------------------------------------------------------------

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sinter")
}

/// A command with the controlling terminal removed, so `/dev/tty` cannot be
/// opened and nothing can block on a prompt.
fn detached(root: &Path) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    let mut c = std::process::Command::new(bin());
    c.env_clear()
        .env("HOME", root.join("home"))
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

#[test]
fn binary_round_trip_exit_codes_and_environment_identity() {
    let d = sandbox();
    let id = ident();
    let src = d.path().join("blob");
    std::fs::write(&src, all_bytes()).unwrap();
    let idf = d.path().join("home/.config/sinter/identity");
    write_mode(&idf, &id.text, 0o600);
    // encrypt with -r
    let o = detached(d.path())
        .args(["secrets", "encrypt", "-r", &id.recipient])
        .arg(&src)
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.stdout.is_empty());
    // decrypt via the default external identity
    let o = detached(d.path())
        .args(["secrets", "decrypt"])
        .arg(d.path().join("blob.age"))
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(o.stdout, all_bytes());
    // SINTER_IDENTITY (a path) works too, and a bad path is a usage-class failure.
    let o = detached(d.path())
        .env("SINTER_IDENTITY", &idf)
        .args(["secrets", "decrypt"])
        .arg(d.path().join("blob.age"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o.stderr).contains("SINTER_IDENTITY"));
    let o = detached(d.path())
        .env("SINTER_IDENTITY", d.path().join("missing"))
        .args(["secrets", "decrypt"])
        .arg(d.path().join("blob.age"))
        .output()
        .unwrap();
    assert_ne!(o.status.code(), Some(0));
    assert!(o.stdout.is_empty());
    // a passphrase is not accepted from the environment or stdin: no terminal => refusal
    let o = detached(d.path())
        .env("SINTER_PASSPHRASE", PASS)
        .args(["secrets", "encrypt", "--passphrase", "-o"])
        .arg(d.path().join("np.age"))
        .arg(&src)
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(!d.path().join("np.age").exists());
    assert!(!String::from_utf8_lossy(&o.stderr).contains(PASS));
    // list
    let o = detached(d.path())
        .args(["secrets", "list"])
        .arg(d.path())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o.stdout).contains("blob.age"));
    // usage errors are exit 2 with the standard prefix
    let o = detached(d.path())
        .args(["secrets", "encrypt", "-"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&o.stderr).starts_with("sinter:"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    // --passphrase VALUE is not a thing: the value is just a (missing) file.
    let o = detached(d.path())
        .args(["secrets", "encrypt", "--passphrase", PASS])
        .output()
        .unwrap();
    assert_ne!(o.status.code(), Some(0));
    assert!(
        !String::from_utf8_lossy(&o.stderr).contains(PASS)
            || String::from_utf8_lossy(&o.stderr).contains("cannot open")
    );
}

/// A pseudo-terminal pair; the slave becomes the child's controlling terminal.
struct Pty {
    master: std::fs::File,
    slave: std::fs::File,
}

fn open_pty() -> Pty {
    use std::os::fd::FromRawFd;
    let (mut m, mut s) = (0, 0);
    let r = unsafe {
        libc::openpty(
            &mut m,
            &mut s,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(r, 0);
    Pty {
        master: unsafe { std::fs::File::from_raw_fd(m) },
        slave: unsafe { std::fs::File::from_raw_fd(s) },
    }
}

fn with_controlling_tty(c: &mut std::process::Command, slave: &std::fs::File) {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let fd = slave.as_raw_fd();
    unsafe {
        c.pre_exec(move || {
            libc::setsid();
            libc::ioctl(fd, libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }
}

/// Collects everything the terminal shows. A reader thread drains the master
/// continuously: `tcsetattr(TCSAFLUSH)` on a pty waits for its output to be
/// consumed, so an undrained master would deadlock the child.
struct Screen(std::sync::Arc<std::sync::Mutex<String>>);

impl Screen {
    fn start(master: &std::fs::File) -> Screen {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let mut m = master.try_clone().unwrap();
        let b = buf.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 1024];
            loop {
                match m.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => b
                        .lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&chunk[..n])),
                }
            }
        });
        Screen(buf)
    }

    fn text(&self) -> String {
        self.0.lock().unwrap().clone()
    }

    fn wait_for(&self, needle: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !self.text().contains(needle) {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {:?}; screen: {:?}",
                needle,
                self.text()
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[test]
fn real_terminal_prompts_without_echo_and_decrypt_refuses_a_terminal_stdout() {
    let d = sandbox();
    let src = d.path().join("canary.txt");
    std::fs::write(&src, CANARY).unwrap();
    let pty = open_pty();
    let mut master = pty.master.try_clone().unwrap();
    let screen = Screen::start(&pty.master);

    // encrypt --passphrase: stdin/stdout/stderr are pipes; only /dev/tty is the pty.
    let mut c = detached(d.path());
    c.args(["secrets", "encrypt", "--passphrase"]).arg(&src);
    with_controlling_tty(&mut c, &pty.slave);
    let child = c.spawn().unwrap();
    screen.wait_for("Enter passphrase: ");
    master.write_all(format!("{}\n", PASS).as_bytes()).unwrap();
    screen.wait_for("Confirm passphrase: ");
    master.write_all(format!("{}\n", PASS).as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{} / {}",
        String::from_utf8_lossy(&out.stderr),
        screen.text()
    );
    std::thread::sleep(std::time::Duration::from_millis(300));
    let shown = screen.text();
    assert!(
        !shown.contains(PASS),
        "the passphrase was echoed: {:?}",
        shown
    );
    assert_clean("encrypt stdout", &String::from_utf8_lossy(&out.stdout));
    assert_clean("encrypt stderr", &String::from_utf8_lossy(&out.stderr));
    let ct = std::fs::read(d.path().join("canary.txt.age")).unwrap();
    assert_eq!(secrets::inspect(&ct).unwrap().method, Method::Passphrase);

    // decrypt with a terminal as stdout: refused, nothing printed, no prompt.
    // (A pty can be the controlling terminal of one session at a time, so each
    // scenario gets its own.)
    let pty = open_pty();
    let screen = Screen::start(&pty.master);
    let before = screen.text().len();
    let mut c = std::process::Command::new(bin());
    c.env_clear()
        .env("HOME", d.path().join("home"))
        .stdin(std::process::Stdio::null())
        .stdout(pty.slave.try_clone().unwrap())
        .stderr(std::process::Stdio::piped())
        .args(["secrets", "decrypt"])
        .arg(d.path().join("canary.txt.age"));
    with_controlling_tty(&mut c, &pty.slave);
    let out = c.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("refusing to write decrypted data to a terminal"),
        "stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::thread::sleep(std::time::Duration::from_millis(300));
    let new_screen = screen.text()[before..].to_string();
    assert!(
        !new_screen.contains(CANARY) && !new_screen.contains("Passphrase"),
        "{:?}",
        new_screen
    );

    // decrypt with stdout redirected to a pipe prompts on the terminal and works.
    let pty = open_pty();
    let mut master = pty.master.try_clone().unwrap();
    let screen = Screen::start(&pty.master);
    let mut c = detached(d.path());
    c.args(["secrets", "decrypt"])
        .arg(d.path().join("canary.txt.age"));
    with_controlling_tty(&mut c, &pty.slave);
    let child = c.spawn().unwrap();
    screen.wait_for("Passphrase: ");
    master.write_all(format!("{}\n", PASS).as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, CANARY.as_bytes());
    std::thread::sleep(std::time::Duration::from_millis(300));
    let all = screen.text();
    assert!(!all.contains(CANARY) && !all.contains(PASS), "{:?}", all);
}

#[test]
fn a_fatal_signal_at_the_prompt_restores_the_terminal() {
    use std::os::fd::AsRawFd;
    let d = sandbox();
    let src = d.path().join("s");
    std::fs::write(&src, "v").unwrap();
    let pty = open_pty();
    let screen = Screen::start(&pty.master);
    let echo_on = |fd: i32| -> bool {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(fd, &mut t) }, 0);
        t.c_lflag & libc::ECHO != 0
    };
    let master_fd = pty.master.as_raw_fd();
    assert!(echo_on(master_fd), "a fresh terminal echoes");
    let mut c = detached(d.path());
    c.args(["secrets", "encrypt", "--passphrase"]).arg(&src);
    with_controlling_tty(&mut c, &pty.slave);
    let mut child = c.spawn().unwrap();
    screen.wait_for("Enter passphrase: ");
    assert!(
        !echo_on(master_fd),
        "echo must be off while the prompt is shown"
    );
    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let status = child.wait().unwrap();
    assert!(!status.success());
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
        echo_on(master_fd),
        "the terminal must be restored after the signal"
    );
    assert!(!d.path().join("s.age").exists());
}
