//! `sinter secrets keygen` tests (DESIGN §65).
//!
//! Library-level tests inject the terminal and stdio ([`Io`], [`Prompter`]);
//! real-binary tests run without a controlling terminal, and one real
//! pseudo-terminal test covers the passphrase prompt. All keys are generated
//! here; nothing outside the test's temporary directory is read.
#![cfg(unix)]

use sinter::error::SinterError;
use sinter::secrets::{self, Method};
use sinter::secrets_cli::*;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

const CANARY: &str = "KEYGEN-CANARY-PLAINTEXT-5e2b";
const PASS: &str = "keygen canary passphrase 91c4";

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

struct FakePrompter {
    interactive: bool,
    secrets: VecDeque<String>,
    asked: Vec<String>,
}

impl FakePrompter {
    fn new(interactive: bool, secrets: &[&str]) -> Self {
        FakePrompter {
            interactive,
            secrets: secrets.iter().map(|x| x.to_string()).collect(),
            asked: Vec::new(),
        }
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
        Err(std::io::ErrorKind::UnexpectedEof.into())
    }
}

struct Out {
    result: Result<u8, SinterError>,
    stdout: String,
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
    /// Everything a non-decrypt command shows: stdout, stderr, the error and
    /// its Debug form.
    fn all(&self) -> String {
        format!(
            "{}\n{}\n{}",
            self.stdout,
            self.stderr,
            match &self.result {
                Err(e) => format!("{} / {:?}", e.message, e),
                Ok(_) => String::new(),
            }
        )
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
            stdout_is_tty: false,
            stderr: &mut stderr,
            prompter: &mut prompter,
            env,
        };
        f(&mut io)
    };
    Out {
        result,
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
        asked: prompter.asked,
    }
}

fn gen(env: &Env, p: FakePrompter, out: &Path, passphrase: bool) -> Out {
    let args = KeygenArgs {
        output: Some(out.to_path_buf()),
        passphrase,
        public: None,
    };
    exec(env, p, b"", false, |io| keygen(&args, io))
}

fn public(env: &Env, p: FakePrompter, input: &Path, stdin: &[u8], stdin_tty: bool) -> Out {
    let args = KeygenArgs {
        public: Some(input.to_path_buf()),
        ..Default::default()
    };
    exec(env, p, stdin, stdin_tty, |io| keygen(&args, io))
}

fn quiet() -> FakePrompter {
    FakePrompter::new(false, &[])
}

/// A private (0700) sandbox with a `home` directory.
fn sandbox() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir_all(d.path().join("home")).unwrap();
    d
}

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".sinter-tmp"))
        .collect()
}

fn assert_no_secret(label: &str, text: &str) {
    for needle in ["AGE-SECRET-KEY-", PASS, CANARY] {
        assert!(!text.contains(needle), "{label} leaked {needle:?}: {text}");
    }
}

/// The recipient printed by generation (`Public key: age1...` on stderr).
fn printed_recipient(o: &Out) -> String {
    let line = o
        .stderr
        .lines()
        .find(|l| l.starts_with("Public key: "))
        .unwrap_or_else(|| panic!("no Public key line: {}", o.stderr));
    line["Public key: ".len()..].to_string()
}

/// The single `AGE-SECRET-KEY-1` line of a plaintext identity file.
fn secret_line(text: &str) -> String {
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("AGE-SECRET-KEY-1"))
        .collect();
    assert_eq!(lines.len(), 1, "one key line expected");
    lines[0].to_string()
}

// ---------------------------------------------------------------------------
// generation
// ---------------------------------------------------------------------------

#[test]
fn keygen_writes_an_age_keygen_format_identity_0600_and_round_trips() {
    let d = sandbox();
    let env = env_in(d.path());
    let key = d.path().join("identity.txt");
    let o = gen(&env, quiet(), &key, false);
    assert!(o.ok(), "{}", o.err());
    assert!(o.stdout.is_empty(), "stdout: {}", o.stdout);
    assert_no_secret("keygen", &o.all());
    assert_eq!(mode(&key), 0o600);
    assert!(leftovers(d.path()).is_empty());
    let recipient = printed_recipient(&o);
    assert!(recipient.starts_with("age1"));

    // age-keygen format: `# created:`, `# public key:`, the key line.
    let text = std::fs::read_to_string(&key).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{} lines", lines.len());
    assert!(lines[0].starts_with("# created: ") && lines[0].ends_with('Z'));
    assert_eq!(lines[1], format!("# public key: {}", recipient));
    assert!(lines[2].starts_with("AGE-SECRET-KEY-1"));
    assert!(text.ends_with('\n'));
    // Format interop: the age library's own parser derives the same recipient.
    let id = age::x25519::Identity::from_str(&secret_line(&text)).unwrap();
    assert_eq!(id.to_public().to_string(), recipient);

    // -y prints the same recipient, and only it.
    let y = public(&env, quiet(), &key, b"", false);
    assert!(y.ok(), "{}", y.err());
    assert_eq!(y.stdout, format!("{}\n", recipient));
    assert_no_secret("keygen -y", &y.all());

    // encrypt -r with it, decrypt -i with the new identity.
    let src = d.path().join("canary.txt");
    std::fs::write(&src, CANARY).unwrap();
    let e = exec(&env, quiet(), b"", false, |io| {
        encrypt(
            &EncryptArgs {
                file: src.clone(),
                recipients: vec![recipient.clone()],
                ..Default::default()
            },
            io,
        )
    });
    assert!(e.ok(), "{}", e.err());
    let mut plain = Vec::new();
    let mut err = Vec::new();
    let r = {
        let mut stdin: &[u8] = b"";
        let mut p = quiet();
        let mut io = Io {
            stdin: &mut stdin,
            stdin_is_tty: false,
            stdout: &mut plain,
            stdout_is_tty: false,
            stderr: &mut err,
            prompter: &mut p,
            env: &env,
        };
        decrypt(
            &DecryptArgs {
                file: d.path().join("canary.txt.age"),
                identity: Some(key.clone()),
            },
            &mut io,
        )
    };
    assert!(r.is_ok(), "{}", String::from_utf8_lossy(&err));
    assert_eq!(plain, CANARY.as_bytes());

    // ...and through a recipients.txt made from `-y` output.
    let sub = d.path().join("repo");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("recipients.txt"), &y.stdout).unwrap();
    let src2 = sub.join("s.txt");
    std::fs::write(&src2, CANARY).unwrap();
    let e = exec(&env, quiet(), b"", false, |io| encrypt(&ea(&src2), io));
    assert!(e.ok(), "{}", e.err());
    let ct = std::fs::read(sub.join("s.txt.age")).unwrap();
    let mut keys = secrets::Keys::new();
    keys.add_identity_file(text.as_bytes()).unwrap();
    assert_eq!(
        secrets::decrypt(&ct, &keys).unwrap().expose(),
        CANARY.as_bytes()
    );
}

fn ea(file: &Path) -> EncryptArgs {
    EncryptArgs {
        file: file.to_path_buf(),
        ..Default::default()
    }
}

#[test]
fn keygen_generates_a_new_key_each_time() {
    let d = sandbox();
    let env = env_in(d.path());
    let a = gen(&env, quiet(), &d.path().join("a"), false);
    let b = gen(&env, quiet(), &d.path().join("b"), false);
    assert!(a.ok() && b.ok());
    assert_ne!(printed_recipient(&a), printed_recipient(&b));
}

#[test]
fn keygen_passphrase_variant_is_a_protected_identity_decrypt_accepts() {
    let d = sandbox();
    let env = env_in(d.path());
    let key = d.path().join("identity.age");
    let o = gen(&env, FakePrompter::new(true, &[PASS, PASS]), &key, true);
    assert!(o.ok(), "{}", o.err());
    assert_eq!(o.asked, vec!["Enter passphrase: ", "Confirm passphrase: "]);
    assert!(o.stdout.is_empty());
    assert_no_secret("keygen --passphrase", &o.all());
    assert!(o.stderr.contains("passphrase-protected"));
    assert_eq!(mode(&key), 0o600);
    let recipient = printed_recipient(&o);
    let bytes = std::fs::read(&key).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("AGE-SECRET-KEY-"));
    assert_eq!(secrets::inspect(&bytes).unwrap().method, Method::Passphrase);

    // -y asks for the passphrase on the (fake) terminal and prints the recipient.
    let y = public(&env, FakePrompter::new(true, &[PASS]), &key, b"", false);
    assert!(y.ok(), "{}", y.err());
    assert_eq!(y.stdout, format!("{}\n", recipient));
    assert_eq!(y.asked.len(), 1);
    assert!(y.asked[0].starts_with("Passphrase for "));
    assert_no_secret("keygen -y protected", &y.all());
    // wrong passphrase / no terminal: refused, nothing on stdout.
    let y = public(
        &env,
        FakePrompter::new(true, &["not the passphrase at all"]),
        &key,
        b"",
        false,
    );
    assert!(!y.ok() && y.stdout.is_empty());
    assert!(
        y.err().contains("could not unlock the identity"),
        "{}",
        y.err()
    );
    let y = public(&env, quiet(), &key, b"", false);
    assert_eq!(y.code(), 2, "{}", y.err());
    assert!(y.stdout.is_empty());
    assert!(y.err().contains("no terminal"), "{}", y.err());
    // the protected identity also works on stdin (passphrase still on the terminal).
    let y = public(
        &env,
        FakePrompter::new(true, &[PASS]),
        Path::new("-"),
        &bytes,
        false,
    );
    assert!(y.ok(), "{}", y.err());
    assert_eq!(y.stdout, format!("{}\n", recipient));

    // decrypt -i accepts it.
    let ct = secrets::encrypt_to_recipients(
        CANARY.as_bytes(),
        &secrets::parse_recipients(&recipient).unwrap(),
    )
    .unwrap();
    let sec = d.path().join("s.age");
    std::fs::write(&sec, ct).unwrap();
    let mut plain = Vec::new();
    let mut err = Vec::new();
    let r = {
        let mut stdin: &[u8] = b"";
        let mut p = FakePrompter::new(true, &[PASS]);
        let mut io = Io {
            stdin: &mut stdin,
            stdin_is_tty: false,
            stdout: &mut plain,
            stdout_is_tty: false,
            stderr: &mut err,
            prompter: &mut p,
            env: &env,
        };
        decrypt(
            &DecryptArgs {
                file: sec,
                identity: Some(key.clone()),
            },
            &mut io,
        )
    };
    assert!(r.is_ok(), "{}", String::from_utf8_lossy(&err));
    assert_eq!(plain, CANARY.as_bytes());
}

#[test]
fn keygen_passphrase_policy_and_no_terminal_create_nothing() {
    let d = sandbox();
    let env = env_in(d.path());
    let key = d.path().join("identity.age");
    // no terminal
    let o = gen(&env, quiet(), &key, true);
    assert_eq!(o.code(), 2, "{}", o.err());
    assert!(o.err().contains("terminal"), "{}", o.err());
    // mismatch
    let o = gen(
        &env,
        FakePrompter::new(true, &[PASS, "keygen canary passphrase 91c5"]),
        &key,
        true,
    );
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("do not match"), "{}", o.err());
    // too short
    let o = gen(
        &env,
        FakePrompter::new(true, &["short", "short"]),
        &key,
        true,
    );
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("at least"), "{}", o.err());
    // prompt read failure
    let o = gen(&env, FakePrompter::new(true, &[]), &key, true);
    assert!(!o.ok());
    assert_no_secret("keygen refusal", &o.all());
    assert!(!key.exists());
    assert!(leftovers(d.path()).is_empty());
}

#[test]
fn keygen_output_rules() {
    let d = sandbox();
    let env = env_in(d.path());

    // -o is required; `-o -` is not stdout.
    for output in [None, Some(PathBuf::from("-"))] {
        let args = KeygenArgs {
            output,
            ..Default::default()
        };
        let o = exec(&env, quiet(), b"", false, |io| keygen(&args, io));
        assert_eq!(o.code(), 2);
        assert!(o.err().contains("-o"), "{}", o.err());
        assert!(o.stdout.is_empty() && o.stderr.is_empty());
    }

    // An existing file is never replaced (no --force exists), whatever it holds.
    let existing = d.path().join("existing");
    std::fs::write(&existing, "keep me\n").unwrap();
    let o = gen(&env, quiet(), &existing, false);
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("already exists"), "{}", o.err());
    assert_eq!(std::fs::read_to_string(&existing).unwrap(), "keep me\n");
    let first = d.path().join("first");
    assert!(gen(&env, quiet(), &first, false).ok());
    let before = std::fs::read(&first).unwrap();
    let o = gen(&env, FakePrompter::new(true, &[PASS, PASS]), &first, true);
    assert_eq!(o.code(), 2);
    assert!(o.asked.is_empty(), "prompted before refusing");
    assert_eq!(std::fs::read(&first).unwrap(), before);

    // Symbolic links (dangling or not) are refused, the target untouched.
    let target = d.path().join("target");
    std::fs::write(&target, "t").unwrap();
    let link = d.path().join("link");
    symlink(&target, &link).unwrap();
    let dangling = d.path().join("dangling");
    symlink(d.path().join("nowhere"), &dangling).unwrap();
    for l in [&link, &dangling] {
        let o = gen(&env, quiet(), l, false);
        assert_eq!(o.code(), 2);
        assert!(o.err().contains("symbolic link"), "{}", o.err());
    }
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "t");
    assert!(!d.path().join("nowhere").exists());

    // A directory, a missing directory, a path without a file name.
    let o = gen(&env, quiet(), d.path(), false);
    assert_eq!(o.code(), 2, "{}", o.err());
    let o = gen(&env, quiet(), &d.path().join("missing/key"), false);
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("does not exist"), "{}", o.err());
    assert!(!d.path().join("missing").exists());

    // Group- or other-writable directories are refused (no other user may
    // rename or replace the new key).
    for m in [0o770, 0o707, 0o1777] {
        let shared = d.path().join(format!("shared{:o}", m));
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(m)).unwrap();
        let o = gen(&env, quiet(), &shared.join("key"), false);
        assert_eq!(o.code(), 2);
        assert!(
            o.err().contains("writable by group or others"),
            "{}",
            o.err()
        );
        assert!(std::fs::read_dir(&shared).unwrap().next().is_none());
    }
    // ...also when reached through a symbolic link to such a directory.
    let shared_link = d.path().join("shared-link");
    symlink(d.path().join("shared770"), &shared_link).unwrap();
    let o = gen(&env, quiet(), &shared_link.join("key"), false);
    assert!(
        o.err().contains("writable by group or others"),
        "{}",
        o.err()
    );
    // A private directory reached through a symbolic link is fine.
    let private = d.path().join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let private_link = d.path().join("private-link");
    symlink(&private, &private_link).unwrap();
    assert!(gen(&env, quiet(), &private_link.join("key"), false).ok());
    assert_eq!(mode(&private.join("key")), 0o600);

    assert!(leftovers(d.path()).is_empty());
}

#[test]
fn keygen_warns_about_plaintext_keys_in_a_repository_or_named_age() {
    let d = sandbox();
    let env = env_in(d.path());
    let repo = d.path().join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::set_permissions(&repo, std::fs::Permissions::from_mode(0o700)).unwrap();
    let o = gen(&env, quiet(), &repo.join("identity.age"), false);
    assert!(o.ok(), "{}", o.err());
    assert!(o.stderr.contains("inside a git repository"), "{}", o.stderr);
    assert!(o.stderr.contains(".age extension"), "{}", o.stderr);
    let o = gen(&env, quiet(), &d.path().join("plain.txt"), false);
    assert!(!o.stderr.contains("warning"), "{}", o.stderr);
}

#[test]
fn keygen_y_combinations_are_refused() {
    let d = sandbox();
    let env = env_in(d.path());
    for (output, passphrase) in [(Some(d.path().join("x")), false), (None, true)] {
        let args = KeygenArgs {
            output,
            passphrase,
            public: Some(d.path().join("k")),
        };
        let o = exec(&env, quiet(), b"", false, |io| keygen(&args, io));
        assert_eq!(o.code(), 2);
        assert!(o.err().contains("-y cannot be combined"), "{}", o.err());
    }
    assert!(!d.path().join("x").exists());
}

// ---------------------------------------------------------------------------
// -y input rules
// ---------------------------------------------------------------------------

fn write_mode(path: &Path, bytes: &[u8], m: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(m)).unwrap();
}

#[test]
fn keygen_y_prints_every_identity_in_order_and_skips_comments() {
    let d = sandbox();
    let env = env_in(d.path());
    let a = secrets::generate_identity();
    let b = secrets::generate_identity();
    let text = format!(
        "# created: 2000-01-01T00:00:00Z\n\n{}\n   \n# second\n{}\r\n",
        String::from_utf8_lossy(a.identity_file.expose()).trim_end(),
        secret_line(&String::from_utf8_lossy(b.identity_file.expose())),
    );
    let f = d.path().join("two");
    write_mode(&f, text.as_bytes(), 0o600);
    let y = public(&env, quiet(), &f, b"", false);
    assert!(y.ok(), "{}", y.err());
    assert_eq!(
        y.stdout,
        format!("{}\n{}\n", a.recipient.to_text(), b.recipient.to_text())
    );
    assert_no_secret("keygen -y two", &y.all());
    // The same through stdin.
    let y = public(&env, quiet(), Path::new("-"), text.as_bytes(), false);
    assert!(y.ok(), "{}", y.err());
    assert_eq!(y.stdout.lines().count(), 2);
    assert_no_secret("keygen -y stdin", &y.all());
}

#[test]
fn keygen_y_refuses_bad_input_without_echoing_it() {
    let d = sandbox();
    let env = env_in(d.path());
    let good = secrets::generate_identity();
    let good_text = String::from_utf8_lossy(good.identity_file.expose()).to_string();
    // A key-looking but invalid line must not be echoed in any form.
    let bad_key = "AGE-SECRET-KEY-1KEYGENCANARYNOTAKEY";
    let cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("comments only", "# nothing here\n\n".into()),
        (
            "malformed",
            format!("{}\n{}\n", good_text.trim_end(), bad_key),
        ),
        ("recipient file", format!("{}\n", good.recipient.to_text())),
        ("garbage", format!("{} trailing\n", secret_line(&good_text))),
        ("plugin", "AGE-PLUGIN-YUBIKEY-1QQQQQQ\n".into()),
    ];
    for (label, text) in &cases {
        let f = d.path().join(label.replace(' ', "-"));
        write_mode(&f, text.as_bytes(), 0o600);
        for o in [
            public(&env, quiet(), &f, b"", false),
            public(&env, quiet(), Path::new("-"), text.as_bytes(), false),
        ] {
            assert_eq!(o.code(), 2, "{label}: {}", o.err());
            assert!(o.stdout.is_empty(), "{label}");
            assert!(
                o.err().contains("no valid age identity"),
                "{label}: {}",
                o.err()
            );
            assert_no_secret(label, &o.all());
            assert!(!o.all().contains("KEYGENCANARY"), "{label}: {}", o.all());
        }
    }
    // Invalid UTF-8.
    let f = d.path().join("binary");
    write_mode(&f, &[0xff, 0xfe, b'\n'], 0o600);
    assert_eq!(public(&env, quiet(), &f, b"", false).code(), 2);

    // A plaintext identity readable by others, as for decrypt -i.
    let f = d.path().join("loose");
    write_mode(&f, good_text.as_bytes(), 0o644);
    let o = public(&env, quiet(), &f, b"", false);
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("accessible by other users"), "{}", o.err());
    assert!(o.stdout.is_empty());

    // An age file encrypted to recipients is not a protected identity.
    let f = d.path().join("recipient-encrypted.age");
    let ct = secrets::encrypt_to_recipients(
        good_text.as_bytes(),
        &secrets::parse_recipients(&good.recipient.to_text()).unwrap(),
    )
    .unwrap();
    write_mode(&f, &ct, 0o600);
    let o = public(&env, FakePrompter::new(true, &[PASS]), &f, b"", false);
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("protected by a passphrase"), "{}", o.err());
    assert!(o.asked.is_empty());

    // Missing file, a directory, a FIFO, key material given as the path.
    assert_eq!(
        public(&env, quiet(), &d.path().join("nope"), b"", false).code(),
        2
    );
    assert_eq!(public(&env, quiet(), d.path(), b"", false).code(), 2);
    let fifo = d.path().join("fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let o = public(&env, quiet(), &fifo, b"", false);
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("not a regular file"), "{}", o.err());
    let o = public(
        &env,
        quiet(),
        Path::new(&secret_line(&good_text)),
        b"",
        false,
    );
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("not the key itself"), "{}", o.err());
    assert_no_secret("key as path", &o.all());

    // stdin: never a terminal, and size-limited.
    let o = public(&env, quiet(), Path::new("-"), good_text.as_bytes(), true);
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("stdin is a terminal"), "{}", o.err());
    let big = vec![b'#'; 1024 * 1024 + 1];
    let o = public(&env, quiet(), Path::new("-"), &big, false);
    assert_eq!(o.code(), 2);
    assert!(o.err().contains("byte limit"), "{}", o.err());
}

// ---------------------------------------------------------------------------
// MCP boundary
// ---------------------------------------------------------------------------

#[test]
fn keygen_is_not_an_mcp_tool() {
    for n in sinter::mcp::tool_names() {
        assert!(
            !n.contains("keygen") && !n.contains("secret") && !n.contains("key"),
            "{n}"
        );
    }
}

// ---------------------------------------------------------------------------
// real binary (no controlling terminal) and a real pseudo-terminal
// ---------------------------------------------------------------------------

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sinter")
}

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

fn text(o: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn binary_keygen_round_trip_and_refusals() {
    let d = sandbox();
    let key = d.path().join("identity.txt");
    let o = detached(d.path())
        .args(["secrets", "keygen", "-o"])
        .arg(&key)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(o.stdout.is_empty());
    assert_no_secret("binary keygen", &text(&o));
    let stderr = String::from_utf8_lossy(&o.stderr).to_string();
    let recipient = stderr
        .lines()
        .find_map(|l| l.strip_prefix("Public key: "))
        .unwrap()
        .to_string();
    assert_eq!(mode(&key), 0o600);

    let o = detached(d.path())
        .args(["secrets", "keygen", "-y"])
        .arg(&key)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        format!("{}\n", recipient)
    );
    assert_no_secret("binary keygen -y", &text(&o));

    // -y - from a pipe.
    let mut c = detached(d.path());
    c.args(["secrets", "keygen", "-y", "-"])
        .stdin(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&std::fs::read(&key).unwrap())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        format!("{}\n", recipient)
    );

    // encrypt -r / decrypt -i with the binary.
    let src = d.path().join("c.txt");
    std::fs::write(&src, CANARY).unwrap();
    let o = detached(d.path())
        .args(["secrets", "encrypt", "-r", &recipient])
        .arg(&src)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let o = detached(d.path())
        .args(["secrets", "decrypt", "-i"])
        .arg(&key)
        .arg(d.path().join("c.txt.age"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert_eq!(o.stdout, CANARY.as_bytes());

    // Refusals: exit 2, nothing on stdout, nothing created or changed.
    let before = std::fs::read(&key).unwrap();
    let np = d.path().join("np.age");
    for args in [
        vec!["secrets".into(), "keygen".into()],
        vec!["secrets".into(), "keygen".into(), "-o".into(), "-".into()],
        vec![
            "secrets".into(),
            "keygen".into(),
            "-o".into(),
            key.to_string_lossy().to_string(),
        ],
        vec![
            "secrets".into(),
            "keygen".into(),
            "--force".into(),
            "-o".into(),
            key.to_string_lossy().to_string(),
        ],
        vec![
            "secrets".into(),
            "keygen".into(),
            "--passphrase".into(),
            "-o".into(),
            np.to_string_lossy().to_string(),
        ],
    ] {
        let o = detached(d.path())
            .env("SINTER_PASSPHRASE", PASS)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", text(&o));
        assert!(o.stdout.is_empty(), "{args:?}");
        assert_no_secret("binary refusal", &text(&o));
    }
    assert_eq!(std::fs::read(&key).unwrap(), before);
    assert!(!np.exists());
    assert!(leftovers(d.path()).is_empty());
}

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

/// Drains the pty master continuously (an undrained master would block the
/// child's `tcsetattr(TCSAFLUSH)`).
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
fn real_terminal_keygen_passphrase_prompts_without_echo() {
    let d = sandbox();
    let key = d.path().join("identity.age");
    let pty = open_pty();
    let mut master = pty.master.try_clone().unwrap();
    let screen = Screen::start(&pty.master);
    let mut c = detached(d.path());
    c.args(["secrets", "keygen", "--passphrase", "-o"])
        .arg(&key);
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
        text(&out),
        screen.text()
    );
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(!screen.text().contains(PASS), "echoed: {:?}", screen.text());
    assert_no_secret("pty keygen", &text(&out));
    assert!(out.stdout.is_empty());
    assert_eq!(mode(&key), 0o600);
    let bytes = std::fs::read(&key).unwrap();
    assert_eq!(secrets::inspect(&bytes).unwrap().method, Method::Passphrase);
    let mut keys = secrets::Keys::new();
    keys.add_protected_identity(
        &bytes,
        &secrets::Passphrase::for_decryption(PASS.to_string()),
    )
    .unwrap();
    let recipient = String::from_utf8_lossy(&out.stderr)
        .lines()
        .find_map(|l| l.strip_prefix("Public key: ").map(str::to_string))
        .unwrap();
    assert_eq!(keys.recipients()[0].to_text(), recipient);
}
