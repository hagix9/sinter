//! `sinter secrets encrypt | decrypt | list` (Phase B).
//!
//! Operator-facing commands over the Phase A secret core ([`crate::secrets`]).
//! These commands work on files; recipes use secrets through
//! [`crate::secret_source`] (`file.content` and `user.password_hash`, opened by
//! plan/apply/audit), and `list` can read recipes (`--recipe`). MCP has no
//! secret integration: its manifest tools refuse secret references.
//!
//! Boundaries (see SINTER_SECRETS_PHASE_B_2026-10-04.md):
//!
//! * `decrypt` writes plaintext to **stdout only**, and refuses a terminal.
//!   No other command ever prints decrypted bytes, a passphrase or a private
//!   identity.
//! * Passphrases come only from the controlling terminal (`/dev/tty`), with
//!   echo off; never argv, environment or stdin.
//! * Identities live outside the repository by default. A passphrase-protected
//!   identity inside the repository is an explicit, conscious choice; a
//!   plaintext identity is never discovered automatically.
//! * Ciphertext is written to a same-directory temporary file (0600, exclusive
//!   create), synced, and published atomically; an existing file is never
//!   replaced silently.
//! * Everything is I/O-injected ([`Io`], [`Env`], [`Prompter`]) so behavior is
//!   testable without a terminal.
//!
//! Errors use the existing exit-code convention: [`SinterError::schema`]
//! (exit 2) for usage, policy and input problems; [`SinterError::apply`]
//! (exit 5) for operation failures. Messages are fixed text plus
//! operator-supplied paths; library strings, recipients and secret material
//! are never included.

use crate::bundle::load_source_with;
use crate::diff::sanitize_line;
use crate::error::{Result, SinterError};
use crate::secret_source::{observe_reference, ReferenceCheck, ReferenceState, SecretRef};
use crate::secrets::{self, Keys, Method, Passphrase, Recipient, SecretError, MAX_SECRET_BYTES};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// File name of the recipients file (public recipients, age `-R` format).
pub const RECIPIENTS_FILE: &str = "recipients.txt";
/// File name of a passphrase-protected identity kept in a repository.
pub const REPO_IDENTITY_FILE: &str = "identity.age";
/// File name of the external (outside any repository) default identity.
pub const EXTERNAL_IDENTITY_FILE: &str = "identity";
/// Directory of the external default identity, below the user config dir.
pub const EXTERNAL_IDENTITY_DIR: &str = "sinter";

/// Longest passphrase read from the terminal, in bytes.
const MAX_PASSPHRASE_BYTES: usize = 1024;
/// How far `list` descends and how many files it reports.
const LIST_MAX_DEPTH: usize = 32;
const LIST_MAX_FILES: usize = 10_000;
/// Directory entries visited and bytes read by one `list`.
const LIST_MAX_ENTRIES: usize = 100_000;
const LIST_MAX_BYTES: u64 = 512 * 1024 * 1024;
/// Levels searched upward for `recipients.txt` / `identity.age`.
const MAX_ASCENT: usize = 64;
/// Largest identity / recipients text file read.
const MAX_KEY_FILE_BYTES: usize = 1024 * 1024;

/// A path (or any operator-supplied text) for display: control characters are
/// escaped by [`sanitize_line`] and Unicode bidirectional / invisible format
/// characters, which could make a name look like another, are replaced.
pub(crate) fn show(path: &Path) -> String {
    neutralize(&sanitize_line(&path.display().to_string()))
}

fn neutralize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}' => '?',
            c => c,
        })
        .collect()
}

/// `'…'`-quote text for a shell command shown as a hint.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// An identity value that is really key material (a common mistake: putting the
/// key itself in `SINTER_IDENTITY`) must never be echoed or opened as a path.
fn looks_like_key_material(v: &std::ffi::OsStr) -> bool {
    let t = v.to_string_lossy();
    t.contains("AGE-SECRET-KEY-")
        || t.contains("AGE-PLUGIN-")
        || t.contains('\n')
        || t.contains('\r')
}

fn usage(msg: impl Into<String>) -> SinterError {
    SinterError::schema(msg)
}

fn failure(msg: impl Into<String>) -> SinterError {
    SinterError::apply(msg)
}

/// Map a core error to a CLI error: input/policy problems are usage errors,
/// the rest are operation failures. The text is the core's fixed text.
fn secret_error(what: &str, e: SecretError) -> SinterError {
    let msg = format!("{}: {}", what, e);
    match e {
        SecretError::Corrupt
        | SecretError::DecryptionFailed
        | SecretError::NoMatchingKey
        | SecretError::Internal => failure(msg),
        _ => usage(msg),
    }
}

// ---------------------------------------------------------------------------
// environment, terminal, I/O
// ---------------------------------------------------------------------------

/// The slice of the process environment these commands consult.
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// `SINTER_IDENTITY`: a **path** to an identity file, never key material.
    pub identity_env: Option<OsString>,
    pub xdg_config_home: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub cwd: PathBuf,
    /// Effective uid, for ownership checks of plaintext identity files.
    pub euid: u32,
}

impl Env {
    pub fn from_process() -> Env {
        Env {
            identity_env: std::env::var_os("SINTER_IDENTITY"),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            home: std::env::var_os("HOME").map(PathBuf::from),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            euid: unsafe { libc::geteuid() },
        }
    }

    /// The external default identity path: `$XDG_CONFIG_HOME/sinter/identity`
    /// (if `XDG_CONFIG_HOME` is an absolute path), else
    /// `$HOME/.config/sinter/identity`. `None` when neither is available.
    pub fn external_identity_path(&self) -> Option<PathBuf> {
        let base = match &self.xdg_config_home {
            Some(x) if x.is_absolute() => x.clone(),
            _ => self
                .home
                .as_ref()
                .filter(|h| h.is_absolute())?
                .join(".config"),
        };
        Some(
            base.join(EXTERNAL_IDENTITY_DIR)
                .join(EXTERNAL_IDENTITY_FILE),
        )
    }
}

/// Interaction with the operator. Real implementation: [`TtyPrompter`].
pub trait Prompter {
    /// Whether a controlling terminal is available for prompts.
    fn interactive(&self) -> bool;
    /// Read a secret (no echo).
    fn read_secret(&mut self, prompt: &str) -> std::io::Result<Zeroizing<String>>;
    /// Read an ordinary line (echoed).
    fn read_line(&mut self, prompt: &str) -> std::io::Result<String>;
}

/// Prompts on `/dev/tty`, never on stdin/stdout/stderr.
pub struct TtyPrompter;

struct TermRestore {
    fd: i32,
    original: libc::termios,
}

impl Drop for TermRestore {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original);
        }
    }
}

/// The terminal settings to put back if a fatal signal arrives while the
/// prompt has echo off. Written before the handlers are installed and read only
/// by the handler (async-signal-safe: `tcsetattr`, `signal`, `raise`).
static SAVED_TTY_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
static mut SAVED_TERMIOS: std::mem::MaybeUninit<libc::termios> = std::mem::MaybeUninit::uninit();

extern "C" fn restore_terminal_and_reraise(sig: libc::c_int) {
    let fd = SAVED_TTY_FD.load(std::sync::atomic::Ordering::SeqCst);
    if fd >= 0 {
        unsafe {
            libc::tcsetattr(
                fd,
                libc::TCSANOW,
                std::ptr::addr_of!(SAVED_TERMIOS).cast::<libc::termios>(),
            );
        }
    }
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// While alive, SIGINT/SIGTERM/SIGHUP/SIGQUIT restore the terminal's echo
/// before the process dies of the signal (a `Drop` would not run).
struct SignalGuard {
    previous: Vec<(libc::c_int, libc::sighandler_t)>,
}

impl SignalGuard {
    fn install(fd: i32, original: &libc::termios) -> SignalGuard {
        unsafe {
            std::ptr::addr_of_mut!(SAVED_TERMIOS).write(std::mem::MaybeUninit::new(*original));
        }
        SAVED_TTY_FD.store(fd, std::sync::atomic::Ordering::SeqCst);
        let handler =
            restore_terminal_and_reraise as extern "C" fn(libc::c_int) as libc::sighandler_t;
        let previous = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT]
            .into_iter()
            .map(|sig| (sig, unsafe { libc::signal(sig, handler) }))
            .collect();
        SignalGuard { previous }
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (sig, old) in &self.previous {
            unsafe {
                libc::signal(*sig, *old);
            }
        }
        SAVED_TTY_FD.store(-1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn open_tty() -> std::io::Result<File> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    if unsafe { libc::isatty(tty.as_raw_fd()) } != 1 {
        return Err(std::io::Error::other("not a terminal"));
    }
    Ok(tty)
}

fn read_tty_line(tty: &File, limit: usize) -> std::io::Result<Zeroizing<Vec<u8>>> {
    // Pre-sized so the buffer never reallocates (a reallocation would leave an
    // unzeroized copy behind).
    let mut buf = Zeroizing::new(Vec::with_capacity(limit));
    let fd = tty.as_raw_fd();
    loop {
        let mut b = 0u8;
        let n = unsafe { libc::read(fd, (&mut b as *mut u8).cast(), 1) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            if buf.is_empty() {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            break;
        }
        if b == b'\n' {
            break;
        }
        if buf.len() >= limit {
            return Err(std::io::Error::other("input too long"));
        }
        buf.push(b);
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(buf)
}

impl Prompter for TtyPrompter {
    fn interactive(&self) -> bool {
        open_tty().is_ok()
    }

    fn read_secret(&mut self, prompt: &str) -> std::io::Result<Zeroizing<String>> {
        let mut tty = open_tty()?;
        let fd = tty.as_raw_fd();
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut term) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let _restore = TermRestore { fd, original: term };
        let _signals = SignalGuard::install(fd, &term);
        term.c_lflag &= !(libc::ECHO | libc::ECHONL);
        // Echo goes off BEFORE the prompt is shown, so nothing typed once the
        // prompt is visible can be echoed (and anything typed ahead is
        // discarded by TCSAFLUSH rather than taken as the passphrase).
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &term) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        tty.write_all(prompt.as_bytes())?;
        tty.flush()?;
        let line = read_tty_line(&tty, MAX_PASSPHRASE_BYTES);
        let _ = tty.write_all(b"\n");
        let mut bytes = line?;
        match String::from_utf8(std::mem::take(&mut *bytes)) {
            Ok(s) => Ok(Zeroizing::new(s)),
            Err(e) => {
                drop(Zeroizing::new(e.into_bytes()));
                Err(std::io::Error::other("input is not valid UTF-8"))
            }
        }
    }

    fn read_line(&mut self, prompt: &str) -> std::io::Result<String> {
        let mut tty = open_tty()?;
        tty.write_all(prompt.as_bytes())?;
        tty.flush()?;
        let bytes = read_tty_line(&tty, 256)?;
        Ok(String::from_utf8_lossy(&bytes).trim().to_string())
    }
}

/// Everything a command touches, injected for tests.
pub struct Io<'a> {
    pub stdin: &'a mut dyn Read,
    pub stdin_is_tty: bool,
    pub stdout: &'a mut dyn Write,
    pub stdout_is_tty: bool,
    pub stderr: &'a mut dyn Write,
    pub prompter: &'a mut dyn Prompter,
    pub env: &'a Env,
}

impl Io<'_> {
    fn note(&mut self, msg: &str) {
        let _ = writeln!(self.stderr, "sinter: {}", sanitize_line(msg));
    }

    /// Best-effort process hardening before secrets are handled; a partial
    /// result is reported, never silent.
    fn harden(&mut self) {
        if !secrets::harden_process() {
            self.note(
                "warning: process hardening (core dumps / tracing) could not be fully applied",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// safe file reading
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Follow {
    /// A final symlink is refused (sources, repository files).
    No,
    /// A final symlink is followed; the *target* must be a regular file
    /// (user-chosen or user-configured paths, which may be symlinked by a
    /// dotfile manager).
    Yes,
}

/// Open a regular file, check it is one on the opened descriptor, and read at
/// most `limit` bytes (more is an error). Never blocks on a FIFO.
pub(crate) fn read_regular(
    path: &Path,
    follow: Follow,
    limit: usize,
) -> Result<(Zeroizing<Vec<u8>>, std::fs::Metadata)> {
    let shown = show(path);
    let mut oo = OpenOptions::new();
    oo.read(true);
    let flags = libc::O_NONBLOCK
        | if follow == Follow::No {
            libc::O_NOFOLLOW
        } else {
            0
        };
    oo.custom_flags(flags);
    let mut f = oo.open(path).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            usage(format!("{}: refusing to follow a symbolic link", shown))
        } else if matches!(
            e.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
        ) {
            usage(format!("cannot open {}: {}", shown, e.kind()))
        } else {
            failure(format!("cannot open {}: {}", shown, e.kind()))
        }
    })?;
    let md = f
        .metadata()
        .map_err(|e| failure(format!("cannot inspect {}: {}", shown, e.kind())))?;
    if !md.file_type().is_file() {
        return Err(usage(format!("{}: not a regular file", shown)));
    }
    if md.len() > limit as u64 {
        return Err(usage(format!(
            "{}: larger than the {} byte limit",
            shown, limit
        )));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(md.len() as usize + 1));
    (&mut f)
        .take(limit as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| failure(format!("cannot read {}: {}", shown, e.kind())))?;
    if buf.len() > limit {
        return Err(usage(format!(
            "{}: larger than the {} byte limit",
            shown, limit
        )));
    }
    Ok((buf, md))
}

/// Read at most `limit` bytes of a stream; more is an error.
fn read_stream(r: &mut dyn Read, limit: usize, what: &str) -> Result<Zeroizing<Vec<u8>>> {
    // One allocation of the full limit (+1 to detect excess): the buffer never
    // reallocates, so no unzeroized copy of partial input is left behind.
    let mut buf = Zeroizing::new(vec![0u8; limit + 1]);
    let mut n = 0usize;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(failure(format!("cannot read {}: {}", what, e.kind()))),
        }
    }
    if n > limit {
        return Err(usage(format!(
            "{} is larger than the {} byte limit",
            what, limit
        )));
    }
    buf.truncate(n);
    Ok(buf)
}

fn is_age_prefix(bytes: &[u8]) -> bool {
    bytes.starts_with(b"age-encryption.org/")
        || bytes.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----")
}

/// Directory chain from `start` upward, bounded: stops after the directory
/// that contains `.git` (the repository root). Without a repository only
/// `start` itself is searched. Symlinks in the chain are resolved.
fn search_chain(start: &Path) -> Vec<PathBuf> {
    let Ok(start) = std::fs::canonicalize(start) else {
        return Vec::new();
    };
    // First find whether a repository root exists above.
    let mut chain = Vec::new();
    let mut found_root = false;
    let mut cur = Some(start.as_path());
    let mut n = 0;
    while let Some(d) = cur {
        chain.push(d.to_path_buf());
        if d.join(".git").exists() {
            found_root = true;
            break;
        }
        n += 1;
        if n >= MAX_ASCENT {
            break;
        }
        cur = d.parent();
    }
    if found_root {
        chain
    } else {
        chain.truncate(1);
        chain
    }
}

pub(crate) fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

// ---------------------------------------------------------------------------
// ciphertext output
// ---------------------------------------------------------------------------

struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// `fsync`, and on macOS `F_FULLFSYNC` (plain `fsync` there does not force the
/// drive to flush its cache).
fn full_sync(f: &File) -> std::io::Result<()> {
    f.sync_all()?;
    #[cfg(target_os = "macos")]
    unsafe {
        libc::fcntl(f.as_raw_fd(), libc::F_FULLFSYNC);
    }
    Ok(())
}

/// Create `out` exclusively (it must not exist) and write `data` into it. Used
/// only on filesystems without hard links; the file is visible while it is
/// being written, so a failure removes it again.
fn create_exclusive(out: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(out)?;
    let r = f.write_all(data).and_then(|_| full_sync(&f));
    if r.is_err() {
        drop(f);
        let _ = std::fs::remove_file(out);
    }
    r
}

/// Write `data` to `out` atomically. An existing file is never replaced unless
/// `replace` is set, and then only if it is a regular (non-symlink) age file.
fn write_atomic(out: &Path, data: &[u8], mode: u32, replace: bool) -> Result<()> {
    let shown = show(out);
    let name = out
        .file_name()
        .ok_or_else(|| usage(format!("{}: not a file path", shown)))?;
    let _ = name;
    let parent = parent_dir(out);
    // Decided once: a file that appears later is never replaced.
    let existed = match std::fs::symlink_metadata(out) {
        Ok(md) => {
            if md.file_type().is_symlink() {
                return Err(usage(format!(
                    "{}: refusing to write through a symbolic link",
                    shown
                )));
            }
            if !md.file_type().is_file() {
                return Err(usage(format!(
                    "{}: exists and is not a regular file",
                    shown
                )));
            }
            if !replace {
                return Err(usage(format!(
                    "{} already exists; use --force to replace an existing age file",
                    shown
                )));
            }
            let (old, _) = read_regular(out, Follow::No, secrets::max_file_bytes())?;
            if secrets::inspect(&old).is_err() {
                return Err(usage(format!(
                    "{} exists and is not an age file; refusing to replace it",
                    shown
                )));
            }
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(failure(format!("cannot inspect {}: {}", shown, e.kind()))),
    };

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // A short fixed-length name: it does not depend on the output's name length.
    let tmp_path = parent.join(format!(".sinter-tmp-{:x}-{:x}", std::process::id(), nanos));
    let mut oo = OpenOptions::new();
    oo.write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW);
    let mut f = oo.open(&tmp_path).map_err(|e| {
        failure(format!(
            "cannot create a temporary file next to {}: {}",
            shown,
            e.kind()
        ))
    })?;
    let mut tmp = TempFile {
        path: tmp_path,
        armed: true,
    };
    f.write_all(data)
        .and_then(|_| full_sync(&f))
        .map_err(|e| failure(format!("cannot write {}: {}", shown, e.kind())))?;
    drop(f);

    if existed {
        // Replacement was requested and the old file was verified to be age.
        std::fs::rename(&tmp.path, out)
            .map_err(|e| failure(format!("cannot replace {}: {}", shown, e.kind())))?;
        tmp.armed = false;
    } else {
        // Atomic no-clobber publish: a hard link fails if the name exists.
        // Where hard links are unavailable (exFAT, some network or FUSE
        // filesystems) fall back to an exclusive create + write, which is still
        // never a replacement but is not atomic.
        match std::fs::hard_link(&tmp.path, out) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(usage(format!("{} already exists", shown)));
            }
            Err(_) => match create_exclusive(out, data, mode) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(usage(format!("{} already exists", shown)));
                }
                Err(e) => return Err(failure(format!("cannot create {}: {}", shown, e.kind()))),
            },
        }
    }
    drop(tmp);
    // Make the new directory entry durable; best effort.
    if let Ok(d) = File::open(&parent) {
        let _ = full_sync(&d);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// encrypt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct EncryptArgs {
    /// Input file, or `-` for stdin.
    pub file: PathBuf,
    pub output: Option<PathBuf>,
    pub passphrase: bool,
    /// `age1…` recipients.
    pub recipients: Vec<String>,
    /// Replace an existing age file at the output.
    pub force: bool,
}

enum Mode {
    Passphrase,
    Recipients(Vec<Recipient>),
}

fn prompt_new_passphrase(io: &mut Io<'_>, what: &str) -> Result<Passphrase> {
    if !io.prompter.interactive() {
        return Err(usage(format!(
            "{} needs a passphrase, which can only be typed on a terminal; \
             use a recipient (-r) for non-interactive use",
            what
        )));
    }
    let mut first = io
        .prompter
        .read_secret("Enter passphrase: ")
        .map_err(|_| failure("could not read the passphrase from the terminal"))?;
    let second = io
        .prompter
        .read_secret("Confirm passphrase: ")
        .map_err(|_| failure("could not read the passphrase from the terminal"))?;
    if first.as_bytes() != second.as_bytes() {
        return Err(usage("the passphrases do not match"));
    }
    drop(second);
    Passphrase::for_encryption(std::mem::take(&mut *first)).map_err(|e| {
        usage(format!(
            "{} (at least {} characters are required)",
            e,
            secrets::MIN_PASSPHRASE_CHARS
        ))
    })
}

/// A short, recognisable form of a recipient (`age1abcdefg…xyz123`).
fn fingerprint(r: &Recipient) -> String {
    let t = r.to_text();
    if t.len() > 20 {
        format!("{}…{}", &t[..10], &t[t.len() - 6..])
    } else {
        t
    }
}

fn parse_recipient_args(args: &[String]) -> Result<Vec<Recipient>> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        let mut one = secrets::parse_recipients(a)
            .map_err(|_| usage(format!("recipient #{} is not a valid age recipient", i + 1)))?;
        if one.len() != 1 {
            return Err(usage(format!(
                "recipient #{} must be a single age recipient",
                i + 1
            )));
        }
        out.push(one.remove(0));
    }
    if out.len() > secrets::MAX_RECIPIENTS {
        return Err(usage("too many recipients"));
    }
    Ok(out)
}

/// The nearest `recipients.txt` from `dir` upward within the repository.
fn find_recipients_file(dir: &Path) -> Option<PathBuf> {
    search_chain(dir)
        .into_iter()
        .map(|d| d.join(RECIPIENTS_FILE))
        .find(|p| std::fs::symlink_metadata(p).is_ok())
}

fn load_recipients_file(path: &Path) -> Result<Vec<Recipient>> {
    let (bytes, _) = read_regular(path, Follow::No, MAX_KEY_FILE_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| usage(format!("{}: not valid UTF-8", show(path))))?;
    secrets::parse_recipients(text).map_err(|e| secret_error(&show(path), e))
}

/// Interactive creation of a key pair when nothing is configured. Returns the
/// recipient to encrypt to. Writes the passphrase-protected identity (outside
/// the repository by default, or beside the output on explicit choice) and a
/// `recipients.txt` next to the output.
fn create_key_pair(io: &mut Io<'_>, out_dir: &Path) -> Result<Vec<Recipient>> {
    let external = io.env.external_identity_path();
    let repo_local = out_dir.join(REPO_IDENTITY_FILE);
    let recipients_path = out_dir.join(RECIPIENTS_FILE);
    if std::fs::symlink_metadata(&recipients_path).is_ok() {
        return Err(usage(format!(
            "{} already exists; pass -r or --passphrase",
            show(&recipients_path)
        )));
    }
    let mut menu = String::from("Where should the new private key be stored?\n");
    if let Some(e) = &external {
        menu.push_str(&format!(
            "  1. Outside the repository: {} (recommended)\n",
            show(e)
        ));
    } else {
        menu.push_str("  1. Outside the repository: unavailable (no home directory)\n");
    }
    menu.push_str(&format!(
        "  2. In this repository: {} -- anyone who gets a copy of the repository can then try to guess its passphrase\n",
        show(&repo_local)
    ));
    let choice = io
        .prompter
        .read_line(&format!("{}Choice [1/2]: ", menu))
        .map_err(|_| failure("could not read the answer from the terminal"))?;
    let identity_path = match choice.as_str() {
        "1" => external.ok_or_else(|| {
            usage("no home directory: cannot place the key outside the repository")
        })?,
        "2" => repo_local,
        _ => return Err(usage("no key location chosen")),
    };
    if std::fs::symlink_metadata(&identity_path).is_ok() {
        return Err(usage(format!(
            "{} already exists; pass -r or --passphrase",
            show(&identity_path)
        )));
    }
    let passphrase = prompt_new_passphrase(io, "the private key")?;
    let g = secrets::generate_identity();
    let protected = secrets::protect_identity(&g.identity_file, &passphrase)
        .map_err(|e| secret_error("cannot protect the identity", e))?;
    if let Some(dir) = identity_path.parent() {
        if !dir.exists() {
            std::fs::create_dir_all(dir)
                .map_err(|e| failure(format!("cannot create {}: {}", show(dir), e.kind())))?;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    write_atomic(&identity_path, &protected, 0o600, false)?;
    let recipients_text = format!(
        "# Public age recipients (not secret). Added by `sinter secrets encrypt`.\n{}\n",
        g.recipient.to_text()
    );
    write_atomic(&recipients_path, recipients_text.as_bytes(), 0o644, false)?;
    io.note(&format!(
        "created the passphrase-protected private key {} and {}",
        show(&identity_path),
        show(&recipients_path)
    ));
    Ok(vec![g.recipient])
}

pub fn encrypt(args: &EncryptArgs, io: &mut Io<'_>) -> Result<u8> {
    let from_stdin = args.file.as_os_str() == "-";
    if args.passphrase && !args.recipients.is_empty() {
        return Err(usage("--passphrase and --recipient cannot be combined"));
    }
    // Output path: explicit, else FILE.age; stdin needs -o.
    let out = match (&args.output, from_stdin) {
        (Some(o), _) => o.clone(),
        (None, true) => return Err(usage("reading from stdin needs an output file (-o)")),
        (None, false) => {
            if args.file.extension().is_some_and(|x| x == "age") {
                io.note("warning: the input already has the .age extension; the output will be encrypted again");
            }
            let mut s = args.file.as_os_str().to_os_string();
            s.push(".age");
            PathBuf::from(s)
        }
    };
    if out.as_os_str() == "-" {
        return Err(usage(
            "ciphertext is never written to the terminal or stdout; give an output file",
        ));
    }
    // Fail early on an unusable output, before reading or prompting.
    match std::fs::symlink_metadata(&out) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(usage(format!(
                "{}: refusing to write through a symbolic link",
                show(&out)
            )))
        }
        Ok(_) if !args.force => {
            return Err(usage(format!(
                "{} already exists; use --force to replace an existing age file",
                show(&out)
            )))
        }
        _ => {}
    }
    let out_dir = std::fs::canonicalize(parent_dir(&out)).map_err(|_| {
        usage(format!(
            "{}: the output directory does not exist",
            show(&parent_dir(&out))
        ))
    })?;

    // Plaintext. Harden the process before it holds any.
    io.harden();
    let plaintext = if from_stdin {
        if io.stdin_is_tty {
            return Err(usage(
                "stdin is a terminal; pipe the data in or name a file",
            ));
        }
        read_stream(io.stdin, MAX_SECRET_BYTES, "the input")?
    } else {
        read_regular(&args.file, Follow::No, MAX_SECRET_BYTES)?.0
    };

    // Mode.
    let mode = if args.passphrase {
        Mode::Passphrase
    } else if !args.recipients.is_empty() {
        Mode::Recipients(parse_recipient_args(&args.recipients)?)
    } else if let Some(rf) = find_recipients_file(&out_dir) {
        let rs = load_recipients_file(&rf)?;
        // A recipients.txt that arrived with a cloned repository decides who can
        // read the result: always say which file and which keys, and on a
        // terminal ask before using them.
        let fps: Vec<String> = rs.iter().map(fingerprint).collect();
        io.note(&format!(
            "using the recipients in {}: {}",
            show(&rf),
            fps.join(", ")
        ));
        if io.prompter.interactive() {
            let ans = io
                .prompter
                .read_line(&format!(
                    "Encrypt to these {} recipient(s)? [y/N]: ",
                    rs.len()
                ))
                .map_err(|_| failure("could not read the answer from the terminal"))?;
            if !matches!(ans.to_ascii_lowercase().as_str(), "y" | "yes") {
                return Err(usage(
                    "not confirmed; review the recipients file, or pass -r RECIPIENT or --passphrase",
                ));
            }
        }
        Mode::Recipients(rs)
    } else if io.prompter.interactive() {
        let ans = io
            .prompter
            .read_line(
                "No recipients are configured. Protect this secret with:\n  1. A passphrase (this file only)\n  2. A new key pair (private key protected by a passphrase)\nChoice [1/2]: ",
            )
            .map_err(|_| failure("could not read the answer from the terminal"))?;
        match ans.as_str() {
            "1" => Mode::Passphrase,
            "2" => Mode::Recipients(create_key_pair(io, &out_dir)?),
            _ => return Err(usage("no method chosen")),
        }
    } else {
        return Err(usage(
            "no recipients are configured and there is no terminal to ask: \
             pass --passphrase (terminal only) or -r RECIPIENT",
        ));
    };

    let (ciphertext, summary) = match &mode {
        Mode::Passphrase => {
            let p = prompt_new_passphrase(io, "the secret")?;
            (
                secrets::encrypt_with_passphrase(&plaintext, &p)
                    .map_err(|e| secret_error("cannot encrypt", e))?,
                "passphrase".to_string(),
            )
        }
        Mode::Recipients(rs) => (
            secrets::encrypt_to_recipients(&plaintext, rs)
                .map_err(|e| secret_error("cannot encrypt", e))?,
            format!("{} recipient(s)", rs.len()),
        ),
    };
    drop(plaintext);

    write_atomic(&out, &ciphertext, 0o600, args.force)?;
    io.note(&format!("encrypted to {} ({})", show(&out), summary));
    if !from_stdin {
        io.note(&format!(
            "the original {} was not changed or deleted; remove it yourself \
             (secure deletion cannot be guaranteed on SSDs and copy-on-write filesystems)",
            show(&args.file)
        ));
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// decrypt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct DecryptArgs {
    pub file: PathBuf,
    /// `--identity PATH`.
    pub identity: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOrigin {
    Flag,
    Environment,
    External,
    Repository,
}

impl IdentityOrigin {
    fn label(self) -> &'static str {
        match self {
            IdentityOrigin::Flag => "--identity",
            IdentityOrigin::Environment => "SINTER_IDENTITY",
            IdentityOrigin::External => "the default identity",
            IdentityOrigin::Repository => "the repository's protected identity",
        }
    }
}

/// Identity discovery, in priority order:
///
/// 1. `--identity PATH`
/// 2. `SINTER_IDENTITY` (a path)
/// 3. the external default (`$XDG_CONFIG_HOME/sinter/identity` or
///    `~/.config/sinter/identity`), if it exists
/// 4. `identity.age` in the secret's directory or a parent up to the
///    repository root (accepted only if passphrase-protected)
///
/// No fallback between candidates: the first match is the only one used.
pub fn find_identity(
    flag: Option<&Path>,
    secret_dir: &Path,
    env: &Env,
) -> Result<Option<(PathBuf, IdentityOrigin)>> {
    if let Some(p) = flag {
        if looks_like_key_material(p.as_os_str()) {
            return Err(usage(
                "--identity must be the path of an identity file, not the key itself",
            ));
        }
        return Ok(Some((p.to_path_buf(), IdentityOrigin::Flag)));
    }
    if let Some(v) = &env.identity_env {
        if looks_like_key_material(v) {
            return Err(usage(
                "SINTER_IDENTITY must be the path of an identity file, not the key itself",
            ));
        }
        if v.is_empty() {
            return Err(usage(
                "SINTER_IDENTITY is set but empty; it must be the path of an identity file",
            ));
        }
        return Ok(Some((PathBuf::from(v), IdentityOrigin::Environment)));
    }
    if let Some(p) = env.external_identity_path() {
        match std::fs::metadata(&p) {
            Ok(_) => return Ok(Some((p, IdentityOrigin::External))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Present but unreachable: fail closed rather than fall through to
            // a different identity.
            Err(_) => {
                return Err(usage(format!(
                    "cannot access the default identity {}",
                    show(&p)
                )))
            }
        }
    }
    for dir in search_chain(secret_dir) {
        let p = dir.join(REPO_IDENTITY_FILE);
        if std::fs::symlink_metadata(&p).is_ok() {
            return Ok(Some((p, IdentityOrigin::Repository)));
        }
    }
    Ok(None)
}

/// Load the identity at `path` into `keys`. A plaintext identity is accepted
/// only from an explicit source and only if private to the user; a
/// passphrase-protected one is unlocked with a terminal passphrase.
pub(crate) fn load_identity(
    path: &Path,
    origin: IdentityOrigin,
    keys: &mut Keys,
    io: &mut Io<'_>,
) -> Result<()> {
    let shown = show(path);
    let follow = if origin == IdentityOrigin::Repository {
        Follow::No
    } else {
        Follow::Yes
    };
    let (bytes, md) = read_regular(path, follow, MAX_KEY_FILE_BYTES)?;
    if is_age_prefix(&bytes) {
        // Protected identity: must be a passphrase file, never a recipient file.
        match secrets::inspect(&bytes) {
            Ok(h) if h.method == Method::Passphrase => {}
            _ => {
                return Err(usage(format!(
                    "{}: an encrypted identity must be protected by a passphrase",
                    shown
                )))
            }
        }
        if !io.prompter.interactive() {
            return Err(usage(format!(
                "{} is passphrase-protected and there is no terminal to ask for the passphrase; \
                 automation needs an unprotected identity kept outside the repository",
                shown
            )));
        }
        io.harden();
        let pass = io
            .prompter
            .read_secret(&format!("Passphrase for {}: ", shown))
            .map_err(|_| failure("could not read the passphrase from the terminal"))?;
        let pass = Passphrase::for_decryption(pass.as_str().to_string());
        keys.add_protected_identity(&bytes, &pass).map_err(|_| {
            failure("could not unlock the identity (wrong passphrase, or the file is damaged)")
        })?;
        Ok(())
    } else {
        if origin == IdentityOrigin::Repository {
            return Err(usage(format!(
                "{}: a plaintext identity inside a repository is never used automatically; \
                 protect it with a passphrase, or pass it with --identity",
                shown
            )));
        }
        // A plaintext private key must be private to this user.
        if md.mode() & 0o077 != 0 {
            return Err(usage(format!(
                "{}: the identity file is accessible by other users (mode {:o}); restrict it{}",
                shown,
                md.mode() & 0o777,
                if path.to_string_lossy().chars().any(|c| c.is_control()) {
                    " to mode 600".to_string()
                } else {
                    format!(": chmod 600 {}", shell_quote(&path.to_string_lossy()))
                }
            )));
        }
        if md.uid() != io.env.euid {
            return Err(usage(format!(
                "{}: the identity file is owned by another user",
                shown
            )));
        }
        keys.add_identity_file(&bytes)
            .map_err(|e| secret_error(&shown, e))
    }
}

pub fn decrypt(args: &DecryptArgs, io: &mut Io<'_>) -> Result<u8> {
    // Never print decrypted data to a terminal: refuse before any prompt.
    if io.stdout_is_tty {
        return Err(usage(
            "refusing to write decrypted data to a terminal; redirect or pipe the output",
        ));
    }
    let (ciphertext, _) = read_regular(&args.file, Follow::Yes, secrets::max_file_bytes())?;
    let header =
        secrets::inspect(&ciphertext).map_err(|e| secret_error("cannot read the secret", e))?;
    let mut keys = Keys::new();
    match header.method {
        Method::Passphrase => {
            if args.identity.is_some() {
                return Err(usage(
                    "this secret is protected by a passphrase; --identity does not apply",
                ));
            }
            if !io.prompter.interactive() {
                return Err(usage(
                    "this secret is protected by a passphrase, which can only be typed on a terminal",
                ));
            }
            io.harden();
            let p = io
                .prompter
                .read_secret("Passphrase: ")
                .map_err(|_| failure("could not read the passphrase from the terminal"))?;
            keys.set_passphrase(Passphrase::for_decryption(p.as_str().to_string()));
        }
        Method::Recipients => {
            let secret_dir = parent_dir(&args.file);
            let found = find_identity(args.identity.as_deref(), &secret_dir, io.env)?;
            let Some((path, origin)) = found else {
                let hint = io
                    .env
                    .external_identity_path()
                    .map(|p| show(&p))
                    .unwrap_or_else(|| "(no home directory)".to_string());
                return Err(usage(format!(
                    "no identity found for this secret; give --identity PATH, set SINTER_IDENTITY, \
                     or place one at {}",
                    hint
                )));
            };
            io.note(&format!("using the identity from {}", origin.label()));
            io.harden();
            load_identity(&path, origin, &mut keys, io)?;
        }
    }
    let plain =
        secrets::decrypt(&ciphertext, &keys).map_err(|e| secret_error("cannot decrypt", e))?;
    io.stdout
        .write_all(plain.expose())
        .and_then(|_| io.stdout.flush())
        .map_err(|e| failure(format!("cannot write the output: {}", e.kind())))?;
    Ok(0)
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ListArgs {
    pub paths: Vec<PathBuf>,
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    pub path: String,
    /// `ok`, `not-age`, `unsupported`, `too-large`, `unreadable`, `invalid`.
    pub status: &'static str,
    pub method: Option<&'static str>,
    pub recipients: Option<usize>,
    pub armored: bool,
    pub note: Option<&'static str>,
}

fn classify_unread(path: &Path) -> ListEntry {
    ListEntry {
        path: show(path),
        status: "unreadable",
        method: None,
        recipients: None,
        armored: false,
        note: None,
    }
}

fn classify(path: &Path) -> ListEntry {
    let shown = show(path);
    let mut e = ListEntry {
        path: shown,
        status: "unreadable",
        method: None,
        recipients: None,
        armored: false,
        note: None,
    };
    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return e,
    };
    if md.file_type().is_symlink() {
        e.note = Some("symbolic link not followed");
        return e;
    }
    if !md.file_type().is_file() {
        e.note = Some("not a regular file");
        return e;
    }
    if md.len() > secrets::max_file_bytes() as u64 {
        e.status = "too-large";
        return e;
    }
    let Ok((bytes, _)) = read_regular(path, Follow::No, secrets::max_file_bytes()) else {
        return e;
    };
    match secrets::inspect(&bytes) {
        Ok(h) => {
            e.status = "ok";
            e.armored = h.armored;
            e.method = Some(match h.method {
                Method::Passphrase => "passphrase",
                Method::Recipients => "recipients",
            });
            e.recipients = Some(h.recipients);
            e.note = match (h.method, h.recipients) {
                (Method::Passphrase, _) => Some("a forgotten passphrase cannot be recovered"),
                (Method::Recipients, 1) => {
                    Some("single recipient: losing that identity loses the secret")
                }
                _ => None,
            };
        }
        Err(SecretError::NotAgeFile) => e.status = "not-age",
        Err(SecretError::UnsupportedFormat) => e.status = "unsupported",
        Err(SecretError::TooLarge) => e.status = "too-large",
        Err(_) => e.status = "invalid",
    }
    e
}

fn walk(
    dir: &Path,
    depth: usize,
    out: &mut BTreeSet<PathBuf>,
    entries_seen: &mut usize,
    truncated: &mut bool,
) {
    if depth > LIST_MAX_DEPTH {
        *truncated = true;
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        *entries_seen += 1;
        if *entries_seen > LIST_MAX_ENTRIES {
            *truncated = true;
            return;
        }
        let p = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_dir() {
            if e.file_name() == ".git" {
                continue;
            }
            walk(&p, depth + 1, out, entries_seen, truncated);
        } else if (ft.is_file() || ft.is_symlink()) && p.extension().is_some_and(|x| x == "age") {
            if out.len() >= LIST_MAX_FILES {
                *truncated = true;
                return;
            }
            out.insert(p);
        }
    }
}

/// One resource, in one of the recipes given with `--recipe`, that names a
/// secret. Labels only: nothing derived from a `with` value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UsedBy {
    /// The `--recipe` argument as the operator wrote it.
    pub recipe: String,
    /// `type:id` of the resource.
    pub resource: String,
}

/// A secret reference found in an analysed recipe.
struct Reference {
    used_by: UsedBy,
    secret: SecretRef,
    /// Where to show it: the recipe argument's directory joined with the
    /// reference when the declaring file lies below it, else the resolved path.
    shown: PathBuf,
}

/// The `--recipe` files, all structurally analysed (never a partial set).
struct Analysis {
    labels: Vec<String>,
    /// Distinct recipe files (`a.yaml` and `./a.yaml` are one).
    distinct: usize,
    references: Vec<Reference>,
}

/// `(device, inode)` of a regular file: the identity two spellings of the same
/// path share. `None` when it cannot be established (not a regular file, no
/// metadata, or a filesystem that reports inode 0).
type FileId = Option<(u64, u64)>;

fn file_id(path: &Path) -> FileId {
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.file_type().is_file() || md.ino() == 0 {
        return None;
    }
    Some((md.dev(), md.ino()))
}

/// The directory part of the operator's recipe argument, as written.
fn shown_base(arg: &Path, secret: &SecretRef) -> PathBuf {
    let dir = parent_dir(arg);
    if let Ok(canon) = std::fs::canonicalize(&dir) {
        if let Ok(rel) = secret.base.strip_prefix(&canon) {
            return dir.join(rel).join(&secret.reference);
        }
    }
    secret.path.clone()
}

/// Load every `--recipe` through the authoritative loader with only the
/// filesystem state of secret references deferred. Any structural error in any
/// recipe makes the whole analysis fail: every failing recipe is reported and
/// `None` is returned, so no inventory (and no "not referenced" conclusion)
/// is ever built from a partial recipe set.
fn analyze_recipes(recipes: &[PathBuf], io: &mut Io<'_>) -> Option<Analysis> {
    let mut labels = Vec::new();
    let mut files: BTreeSet<PathBuf> = BTreeSet::new();
    let mut references = Vec::new();
    let mut failed = false;
    for arg in recipes {
        let label = show(arg);
        files.insert(std::fs::canonicalize(arg).unwrap_or_else(|_| arg.clone()));
        if !labels.contains(&label) {
            labels.push(label.clone());
        }
        match load_source_with(arg, ReferenceCheck::ReferenceOnly) {
            Ok(source) => {
                for unit in source.units() {
                    for fr in &unit.model.resources {
                        if let Some(secret) = &fr.secret {
                            references.push(Reference {
                                used_by: UsedBy {
                                    recipe: label.clone(),
                                    resource: neutralize(&sanitize_line(&format!(
                                        "{}:{}",
                                        fr.type_, fr.id
                                    ))),
                                },
                                shown: shown_base(arg, secret),
                                secret: secret.clone(),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                failed = true;
                io.note(&format!("--recipe {}: {}", label, e.message));
            }
        }
    }
    if failed {
        io.note("no inventory was produced: every --recipe must load without a structural error");
        return None;
    }
    Some(Analysis {
        labels,
        distinct: files.len(),
        references,
    })
}

/// One line of the inventory with the recipe-derived facts attached.
struct Row {
    path: PathBuf,
    entry: ListEntry,
    id: FileId,
    /// Canonical parent joined with the file name (no link in the last part).
    canon: Option<PathBuf>,
    used_by: std::collections::BTreeSet<UsedBy>,
}

fn canon_of(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    Some(std::fs::canonicalize(parent_dir(path)).ok()?.join(name))
}

/// A file that Sinter's identity discovery could pick: the very file
/// `<its directory>/identity.age` (compared by file identity, so a different
/// spelling or case on a case-insensitive filesystem is recognised too).
fn possible_identity_file(row: &Row) -> bool {
    if row
        .path
        .file_name()
        .is_some_and(|n| n == REPO_IDENTITY_FILE)
    {
        return true;
    }
    let Some(id) = row.id else { return false };
    file_id(&parent_dir(&row.path).join(REPO_IDENTITY_FILE)) == Some(id)
}

fn missing_entry(path: &Path, status: &'static str, note: &'static str) -> ListEntry {
    ListEntry {
        path: show(path),
        status,
        method: None,
        recipients: None,
        armored: false,
        note: Some(note),
    }
}

/// Attach the references to the listed files and add the referenced files that
/// were not listed (or are absent).
/// Returns `true` when some existing referenced file could not be matched
/// reliably (no file identity and no path match): "not referenced"
/// conclusions are then withheld for the whole listing.
fn merge_references(
    rows: &mut Vec<Row>,
    refs: &[Reference],
    budget: &mut u64,
    truncated: &mut bool,
) -> bool {
    let mut uncertain = false;
    for r in refs {
        let state = observe_reference(&r.secret);
        let id = if state == ReferenceState::Present {
            file_id(&r.secret.path)
        } else {
            None
        };
        let lexical = &r.secret.path;
        if state == ReferenceState::Unreadable {
            uncertain = true;
        }
        // Every listed name of the same file (hard links, other spellings)
        // is referenced, not only the first one found.
        let mut matched = false;
        for row in rows.iter_mut() {
            if (id.is_some() && row.id == id) || row.canon.as_deref() == Some(lexical.as_path()) {
                row.used_by.insert(r.used_by.clone());
                matched = true;
            }
        }
        if matched {
            continue;
        }
        // A reference that could not be inspected (permission denied) or
        // whose identity is unknown may still be the very file a listed name
        // points to (a hard link): withhold every "not referenced" conclusion.
        if (state == ReferenceState::Present && id.is_none()) || state == ReferenceState::Unreadable
        {
            uncertain = true;
        }
        let entry = match state {
            ReferenceState::Present => {
                let size = std::fs::symlink_metadata(&r.secret.path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                if size > *budget {
                    *truncated = true;
                    let mut e = classify_unread(&r.shown);
                    e.note = Some("skipped: read budget reached");
                    e
                } else {
                    *budget -= size;
                    let mut e = classify(&r.secret.path);
                    e.path = show(&r.shown);
                    e
                }
            }
            ReferenceState::Missing => missing_entry(
                &r.shown,
                "missing",
                "referenced by a recipe, but the file does not exist",
            ),
            ReferenceState::Link => {
                missing_entry(&r.shown, "unreadable", "symbolic link not followed")
            }
            ReferenceState::NotRegular => {
                missing_entry(&r.shown, "unreadable", "not a regular file")
            }
            ReferenceState::Unreadable => {
                missing_entry(&r.shown, "unreadable", "cannot be inspected")
            }
        };
        let mut used_by = std::collections::BTreeSet::new();
        used_by.insert(r.used_by.clone());
        rows.push(Row {
            path: r.shown.clone(),
            entry,
            id,
            canon: Some(lexical.clone()),
            used_by,
        });
    }
    uncertain
}

/// `true`/`false` only where a conclusion is justified, else `None`: a parsed
/// age file that is not a possible identity file, whose file identity is known.
fn not_referenced(row: &Row, uncertain: bool) -> Option<bool> {
    if uncertain || row.entry.status != "ok" || row.id.is_none() || possible_identity_file(row) {
        return None;
    }
    Some(row.used_by.is_empty())
}

pub fn list(args: &ListArgs, io: &mut Io<'_>) -> Result<u8> {
    list_for_recipes(args, &[], io)
}

/// `secrets list`, optionally with recipe-derived facts (`--recipe`). Without
/// recipes the output is exactly the Phase B listing.
pub fn list_for_recipes(args: &ListArgs, recipes: &[PathBuf], io: &mut Io<'_>) -> Result<u8> {
    let roots: Vec<PathBuf> = if args.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        args.paths.clone()
    };
    let mut files: BTreeSet<PathBuf> = BTreeSet::new();
    let mut explicit: BTreeSet<PathBuf> = BTreeSet::new();
    let mut truncated = false;
    let mut entries_seen = 0usize;
    for r in &roots {
        let md = std::fs::symlink_metadata(r)
            .map_err(|_| usage(format!("{}: no such file or directory", show(r))))?;
        if md.file_type().is_dir() {
            walk(r, 0, &mut files, &mut entries_seen, &mut truncated);
        } else {
            explicit.insert(r.clone());
        }
    }
    files.extend(explicit.iter().cloned());
    // Analyse the recipes before anything is classified or printed: a failure
    // must leave stdout empty.
    let analysis = if recipes.is_empty() {
        None
    } else {
        match analyze_recipes(recipes, io) {
            Some(a) => Some(a),
            None => return Ok(2),
        }
    };
    let mut budget = LIST_MAX_BYTES;
    let mut rows: Vec<Row> = files
        .iter()
        .map(|p| {
            let size = std::fs::symlink_metadata(p).map(|m| m.len()).unwrap_or(0);
            let entry = if size > budget {
                truncated = true;
                let mut e = classify_unread(p);
                e.note = Some("skipped: read budget reached");
                e
            } else {
                budget -= size;
                classify(p)
            };
            let analysed = analysis.is_some();
            Row {
                path: p.clone(),
                entry,
                id: if analysed { file_id(p) } else { None },
                canon: if analysed { canon_of(p) } else { None },
                used_by: BTreeSet::new(),
            }
        })
        .collect();
    let mut uncertain = false;
    if let Some(a) = &analysis {
        uncertain = merge_references(&mut rows, &a.references, &mut budget, &mut truncated);
        rows.sort_by(|x, y| x.path.cmp(&y.path));
    }
    if args.json {
        let docs: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                let e = &r.entry;
                let mut v = serde_json::json!({
                    "path": e.path,
                    "status": e.status,
                    "method": e.method,
                    "recipients": e.recipients,
                    "armored": e.armored,
                    "note": e.note,
                });
                if analysis.is_some() {
                    v["referenced_by"] = r
                        .used_by
                        .iter()
                        .map(|u| serde_json::json!({ "recipe": u.recipe, "resource": u.resource }))
                        .collect();
                    v["not_referenced"] = serde_json::json!(not_referenced(r, uncertain));
                    v["possible_identity_file"] = serde_json::json!(possible_identity_file(r));
                }
                v
            })
            .collect();
        let mut doc = serde_json::json!({ "command": "secrets list", "secrets": docs, "truncated": truncated });
        if let Some(a) = &analysis {
            doc["recipes"] = serde_json::json!(a.labels);
        }
        writeln!(
            io.stdout,
            "{}",
            serde_json::to_string_pretty(&doc).unwrap_or_default()
        )
        .map_err(|e| failure(format!("cannot write the output: {}", e.kind())))?;
    } else {
        let w = |s: &str, n: usize| format!("{:<n$}", s, n = n);
        let mut text = String::new();
        if rows.is_empty() {
            text.push_str("no age files found\n");
        } else {
            for r in &rows {
                let e = &r.entry;
                let mut tail = e.note.map(|n| format!("  ({})", n)).unwrap_or_default();
                if let Some(a) = &analysis {
                    if !r.used_by.is_empty() {
                        let list: Vec<String> = r
                            .used_by
                            .iter()
                            .map(|u| format!("{} in {}", u.resource, u.recipe))
                            .collect();
                        tail.push_str(&format!("  [referenced by {}]", list.join(", ")));
                    }
                    if not_referenced(r, uncertain) == Some(true) {
                        tail.push_str(&format!(
                            "  (not referenced by the {} recipe(s) given)",
                            a.distinct
                        ));
                    }
                    if possible_identity_file(r) {
                        tail.push_str(
                            "  (possible Sinter identity file: identity discovery uses this name; \
                             not a recipe secret)",
                        );
                    }
                }
                text.push_str(&format!(
                    "{}{}{}{}{}\n",
                    w(e.status, 12),
                    w(e.method.unwrap_or("-"), 12),
                    w(
                        &e.recipients
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "-".into()),
                        12
                    ),
                    e.path,
                    tail
                ));
            }
            text.insert_str(0, "STATUS      METHOD      RECIPIENTS  PATH\n");
        }
        if truncated {
            text.push_str("(listing truncated: depth or file-count limit reached)\n");
        }
        if let Some(a) = &analysis {
            text.push_str(&format!(
                "recipe analysis covers only the {} recipe(s) given ({}); references from other \
                 recipes are not considered\n",
                a.distinct,
                a.labels.join(", ")
            ));
        }
        io.stdout
            .write_all(text.as_bytes())
            .map_err(|e| failure(format!("cannot write the output: {}", e.kind())))?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusive_create_never_replaces_and_cleans_up() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("out");
        create_exclusive(&p, b"first", 0o600).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"first");
        let e = create_exclusive(&p, b"second", 0o600).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b"first",
            "an existing file is untouched"
        );
        // A dangling symlink is not written through.
        let link = d.path().join("link");
        std::os::unix::fs::symlink(d.path().join("target"), &link).unwrap();
        assert!(create_exclusive(&link, b"x", 0o600).is_err());
        assert!(!d.path().join("target").exists());
    }

    #[test]
    fn display_helpers() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(neutralize("a\u{202E}b\u{FEFF}"), "a?b?");
        assert!(looks_like_key_material(std::ffi::OsStr::new(
            "AGE-SECRET-KEY-1X"
        )));
        assert!(looks_like_key_material(std::ffi::OsStr::new("a\nb")));
        assert!(!looks_like_key_material(std::ffi::OsStr::new(
            "/home/u/.config/sinter/identity"
        )));
    }
}
