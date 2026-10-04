//! Encrypted secrets as recipe values: the reference, its confinement, and the
//! source that opens it.
//!
//! A recipe names a secret as `content: { secret: <relative path> }`. Loading
//! checks the *reference* (shape, confinement, an age file is there) and never
//! decrypts. Plan, apply and audit open it through a [`SecretSource`].
//!
//! The method (passphrase or recipients) is never part of the recipe: the age
//! header says how a file opens, and [`ProcessSecrets`] follows it.

use crate::error::{Result, SinterError};
use crate::secrets::{self, Keys, Method, Passphrase, Secret, SecretError};
use crate::secrets_cli::{
    find_identity, load_identity, parent_dir, read_regular, show, Env, Follow, Io, Prompter,
    TtyPrompter,
};
use crate::value::Value;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

/// The only key of a secret reference map.
pub const SECRET_KEY: &str = "secret";

/// Longest accepted reference text.
const MAX_REFERENCE_BYTES: usize = 1024;

/// A secret named by a recipe, resolved against the recipe that names it.
/// Holds paths only, never key material or plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    /// The reference as written (a relative path; safe to display).
    pub reference: String,
    /// The recipe's directory the reference is confined to.
    pub base: PathBuf,
    /// `base` joined with `reference`.
    pub path: PathBuf,
}

/// What the value of `content` is, shape only.
pub enum ContentShape<'a> {
    /// Not a secret reference (a plain string, or null).
    Plain,
    /// `{ secret: <string> }`.
    Secret(&'a str),
}

/// Classify a `content` value: a string or null is plain; a map must be
/// exactly `{ secret: <string> }`, anything else is an error.
pub fn content_shape(v: &Value) -> std::result::Result<ContentShape<'_>, &'static str> {
    match v {
        Value::Map(m) => {
            if m.len() != 1 || !m.contains_key(SECRET_KEY) {
                return Err("content must be a string or { secret: <path> }");
            }
            match m.get(SECRET_KEY) {
                Some(Value::Str(s)) => Ok(ContentShape::Secret(s)),
                _ => Err("content.secret must be a string path"),
            }
        }
        _ => Ok(ContentShape::Plain),
    }
}

fn reference_error(sensitive: bool, ctx: &str, what: &str) -> SinterError {
    if sensitive {
        SinterError::schema(format!(
            "{}: secret reference invalid (value redacted)",
            ctx
        ))
    } else {
        SinterError::schema(format!("{}: {}", ctx, what))
    }
}

/// How strictly a secret reference is checked while a recipe loads.
///
/// The reference *text* rules are the same in both modes; only the checks that
/// depend on the state of the referenced file differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ReferenceCheck {
    /// The file must exist as a regular, link-free, well-formed age file. Used
    /// by `validate`, `plan`, `apply`, `audit` and MCP, which never see any
    /// other mode.
    #[default]
    Strict,
    /// Only the reference text is checked. The state of the file is observed
    /// afterwards by [`observe_reference`] (`sinter secrets list --recipe`,
    /// which has to be able to report a reference whose file is absent).
    ReferenceOnly,
}

/// Resolve and check a secret reference ([`ReferenceCheck::Strict`]).
///
/// The reference must be a static, relative path of plain components, inside
/// the directory of the recipe that names it: no absolute path, no `.`/`..`,
/// no interpolation, and no symbolic link anywhere below that directory. The
/// target must be a regular file holding a well-formed age header. Nothing is
/// decrypted.
pub fn resolve_reference(
    origin: &str,
    reference: &str,
    ctx: &str,
    sensitive: bool,
) -> Result<SecretRef> {
    resolve_reference_with(ReferenceCheck::Strict, origin, reference, ctx, sensitive)
}

/// [`resolve_reference`] in an explicit mode.
pub(crate) fn resolve_reference_with(
    mode: ReferenceCheck,
    origin: &str,
    reference: &str,
    ctx: &str,
    sensitive: bool,
) -> Result<SecretRef> {
    let bad = |what: &str| reference_error(sensitive, ctx, what);
    check_reference_text(reference).map_err(bad)?;
    let base = parent_dir(Path::new(origin));
    let path = base.join(reference);
    let found = SecretRef {
        reference: reference.to_string(),
        base,
        path,
    };
    if mode == ReferenceCheck::ReferenceOnly {
        return Ok(found);
    }
    let shown = || neutralize_reference(reference);
    check_confined(&found.base, &found.path).map_err(bad)?;
    let (bytes, _) =
        read_regular(&found.path, Follow::No, secrets::max_file_bytes()).map_err(|_| {
            reference_error(
                sensitive,
                ctx,
                &format!("secret {} is not a readable regular file", shown()),
            )
        })?;
    secrets::inspect(&bytes).map_err(|_| {
        reference_error(
            sensitive,
            ctx,
            &format!("secret {} is not a valid age file", shown()),
        )
    })?;
    Ok(found)
}

/// The reference *text* rules: pure, no filesystem access.
fn check_reference_text(reference: &str) -> std::result::Result<(), &'static str> {
    if reference.is_empty() || reference.len() > MAX_REFERENCE_BYTES {
        return Err("secret reference must be a non-empty path");
    }
    if reference.chars().any(|c| c.is_control()) {
        return Err("secret reference may not contain control characters");
    }
    // Sinter's interpolation marker is `{{`; no spelling of it is accepted,
    // escaped or not, so the path is exactly what is written.
    if reference.contains("{{") || reference.contains("}}") {
        return Err("secret reference must be a static path (no interpolation)");
    }
    if reference.starts_with('/') || reference.contains('\\') {
        return Err("secret reference must be relative to the recipe (no absolute path)");
    }
    if reference
        .split('/')
        .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err("secret reference may not contain empty, '.' or '..' components");
    }
    Ok(())
}

/// What the filesystem says about a structurally valid reference, observed
/// with `lstat` only (no link is followed, nothing is read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReferenceState {
    /// A regular file, reached without passing through a symbolic link.
    Present,
    /// Some component is absent (`ENOENT` / `ENOTDIR`).
    Missing,
    /// A component is a symbolic link (refused by policy).
    Link,
    /// The final component is not a regular file, or an intermediate one is
    /// not a directory.
    NotRegular,
    /// A component could not be inspected for another reason (for example
    /// permission denied). Never reported as missing.
    Unreadable,
}

/// Observe the file a reference resolves to, component by component.
pub(crate) fn observe_reference(r: &SecretRef) -> ReferenceState {
    match walk_reference(&r.base, &r.path) {
        Walk::Present => ReferenceState::Present,
        Walk::Absent => ReferenceState::Missing,
        Walk::Link => ReferenceState::Link,
        Walk::NotFinalFile | Walk::NotDirectory => ReferenceState::NotRegular,
        Walk::Unreadable => ReferenceState::Unreadable,
        // Cannot happen for a reference that passed the text rules.
        Walk::Escapes | Walk::NotPlain => ReferenceState::Unreadable,
    }
}

fn neutralize_reference(reference: &str) -> String {
    show(Path::new(reference))
}

/// The outcome of walking a reference below its base directory.
enum Walk {
    Present,
    Absent,
    Link,
    NotFinalFile,
    NotDirectory,
    Unreadable,
    Escapes,
    NotPlain,
}

/// Inspect every component below `base` with `lstat`, never following a link.
fn walk_reference(base: &Path, path: &Path) -> Walk {
    let Ok(rel) = path.strip_prefix(base) else {
        return Walk::Escapes;
    };
    let mut cur = base.to_path_buf();
    let comps: Vec<Component<'_>> = rel.components().collect();
    for (i, c) in comps.iter().enumerate() {
        let Component::Normal(name) = c else {
            return Walk::NotPlain;
        };
        cur.push(name);
        let md = match std::fs::symlink_metadata(&cur) {
            Ok(md) => md,
            Err(e) => {
                return match e.raw_os_error() {
                    Some(libc::ENOENT) | Some(libc::ENOTDIR) => Walk::Absent,
                    _ => Walk::Unreadable,
                }
            }
        };
        if md.file_type().is_symlink() {
            return Walk::Link;
        }
        let last = i + 1 == comps.len();
        if last && !md.file_type().is_file() {
            return Walk::NotFinalFile;
        }
        if !last && !md.file_type().is_dir() {
            return Walk::NotDirectory;
        }
    }
    Walk::Present
}

/// Every component below `base` must exist, be a directory (the last: a file)
/// and not be a symbolic link. This is also what keeps a reference from
/// escaping `base`.
fn check_confined(base: &Path, path: &Path) -> std::result::Result<(), &'static str> {
    match walk_reference(base, path) {
        Walk::Present => Ok(()),
        Walk::Escapes => Err("secret reference escapes the recipe directory"),
        Walk::NotPlain => Err("secret reference may only contain plain path components"),
        // Any component that cannot be reached is reported as not found, as
        // before the typed walk existed.
        Walk::Absent | Walk::Unreadable => Err("secret file not found"),
        Walk::Link => Err("secret reference may not pass through a symbolic link"),
        Walk::NotFinalFile => Err("secret reference must name a regular file"),
        Walk::NotDirectory => {
            Err("secret reference passes through something that is not a directory")
        }
    }
}

// ---------------------------------------------------------------------------
// opening
// ---------------------------------------------------------------------------

/// Where decrypted secrets come from. Implementations never print, log or
/// retain plaintext; failures carry fixed, non-secret text.
pub trait SecretSource {
    fn open(&mut self, r: &SecretRef) -> Result<Secret>;
}

/// A source shared by every engine of one invocation, so an unlocked identity
/// is asked for once.
pub type SharedSecrets = Rc<RefCell<dyn SecretSource>>;

/// Opens secrets the way `sinter secrets decrypt` does, minus the `--identity`
/// flag (on plan/apply/audit that flag means an SSH key): `SINTER_IDENTITY`,
/// then the external default identity, then a passphrase-protected
/// `identity.age` in the repository. Passphrases are read from the terminal
/// only.
pub struct ProcessSecrets {
    env: Env,
    prompter: Box<dyn Prompter>,
    notes: Box<dyn Write>,
    /// Unlocked identities, by identity file: one prompt per identity per run.
    identities: BTreeMap<PathBuf, Keys>,
    /// Typed passphrases of passphrase-encrypted secrets, by secret file.
    passphrases: BTreeMap<PathBuf, Keys>,
    /// Identities and secret files that already failed this run: the same
    /// failure is returned again without asking again.
    failed_identities: BTreeMap<PathBuf, String>,
    failed_secrets: BTreeMap<PathBuf, String>,
    /// Diagnostics already written, so a loop does not repeat them.
    reported: BTreeSet<String>,
    hardened: bool,
}

impl ProcessSecrets {
    pub fn new(env: Env, prompter: Box<dyn Prompter>, notes: Box<dyn Write>) -> Self {
        ProcessSecrets {
            env,
            prompter,
            notes,
            identities: BTreeMap::new(),
            passphrases: BTreeMap::new(),
            failed_identities: BTreeMap::new(),
            failed_secrets: BTreeMap::new(),
            reported: BTreeSet::new(),
            hardened: false,
        }
    }

    /// The process environment, the controlling terminal and standard error.
    pub fn from_process() -> Self {
        ProcessSecrets::new(
            Env::from_process(),
            Box::new(TtyPrompter),
            Box::new(std::io::stderr()),
        )
    }

    fn note(&mut self, msg: &str) {
        let _ = writeln!(self.notes, "sinter: {}", crate::diff::sanitize_line(msg));
    }

    fn harden_once(&mut self) {
        if self.hardened {
            return;
        }
        self.hardened = true;
        if !secrets::harden_process() {
            self.note(
                "warning: process hardening (core dumps / tracing) could not be fully applied",
            );
        }
    }

    /// The unlocked identity for a secret in `secret_dir`, loading it on first
    /// use.
    fn identity_for(&mut self, secret_dir: &Path) -> Result<PathBuf> {
        let found = find_identity(None, secret_dir, &self.env)?;
        let Some((path, origin)) = found else {
            let hint = self
                .env
                .external_identity_path()
                .map(|p| show(&p))
                .unwrap_or_else(|| "(no home directory)".to_string());
            return Err(SinterError::apply(format!(
                "no identity found for this secret; set SINTER_IDENTITY to an identity file, \
                 or place one at {}",
                hint
            )));
        };
        if let Some(msg) = self.failed_identities.get(&path) {
            return Err(SinterError::apply(msg.clone()));
        }
        if !self.identities.contains_key(&path) {
            self.harden_once();
            let mut keys = Keys::new();
            let mut stdin = std::io::empty();
            let mut stdout = std::io::sink();
            let mut io = Io {
                stdin: &mut stdin,
                stdin_is_tty: false,
                stdout: &mut stdout,
                stdout_is_tty: false,
                stderr: &mut *self.notes,
                prompter: &mut *self.prompter,
                env: &self.env,
            };
            if let Err(e) = load_identity(&path, origin, &mut keys, &mut io) {
                self.failed_identities.insert(path, e.message.clone());
                return Err(e);
            }
            self.identities.insert(path.clone(), keys);
        }
        Ok(path)
    }
}

impl ProcessSecrets {
    /// Write the cause of a failure once. The resource report keeps it
    /// redacted (a secret-holding resource is sensitive); this is the one
    /// place an operator learns *why*, and it carries fixed text and
    /// operator-chosen paths only.
    fn report(&mut self, r: &SecretRef, message: &str) {
        let line = format!(
            "secret unavailable: {}: {}",
            neutralize_reference(&r.reference),
            message
        );
        if self.reported.insert(line.clone()) {
            self.note(&line);
        }
    }

    fn open_inner(&mut self, r: &SecretRef) -> Result<Secret> {
        // The reference was checked when the recipe was loaded; check again,
        // because the tree can change in between.
        check_confined(&r.base, &r.path).map_err(|what| SinterError::apply(what.to_string()))?;
        let (ciphertext, _) = read_regular(&r.path, Follow::No, secrets::max_file_bytes())?;
        let header = secrets::inspect(&ciphertext)
            .map_err(|e| SinterError::apply(format!("cannot read the secret: {}", e)))?;
        let plain = match header.method {
            Method::Passphrase => {
                if let Some(msg) = self.failed_secrets.get(&r.path) {
                    return Err(SinterError::apply(msg.clone()));
                }
                if !self.passphrases.contains_key(&r.path) {
                    if !self.prompter.interactive() {
                        return Err(SinterError::apply(
                            "this secret is protected by a passphrase, which can only be typed \
                             on a terminal; use a recipient-encrypted secret for unattended runs",
                        ));
                    }
                    self.harden_once();
                    let p = self
                        .prompter
                        .read_secret(&format!(
                            "Passphrase for {}: ",
                            neutralize_reference(&r.reference)
                        ))
                        .map_err(|_| {
                            let msg = "could not read the passphrase from the terminal";
                            self.failed_secrets.insert(r.path.clone(), msg.to_string());
                            SinterError::apply(msg)
                        })?;
                    let mut keys = Keys::new();
                    keys.set_passphrase(Passphrase::for_decryption(p.as_str().to_string()));
                    self.passphrases.insert(r.path.clone(), keys);
                }
                let keys = &self.passphrases[&r.path];
                let res = secrets::decrypt(&ciphertext, keys);
                if res.is_err() {
                    // A wrong passphrase is not retried for the same file.
                    self.passphrases.remove(&r.path);
                    self.failed_secrets.insert(
                        r.path.clone(),
                        format!(
                            "cannot decrypt the secret: {}",
                            SecretError::DecryptionFailed
                        ),
                    );
                }
                res
            }
            Method::Recipients => {
                let id = self.identity_for(&parent_dir(&r.path))?;
                let keys = &self.identities[&id];
                secrets::decrypt(&ciphertext, keys)
            }
        };
        plain.map_err(|e| SinterError::apply(format!("cannot decrypt the secret: {}", e)))
    }
}

impl SecretSource for ProcessSecrets {
    fn open(&mut self, r: &SecretRef) -> Result<Secret> {
        match self.open_inner(r) {
            Ok(s) => Ok(s),
            Err(e) => {
                self.report(r, &e.message);
                Err(e)
            }
        }
    }
}

/// The shared source of this process, created on first use.
pub fn process_secrets() -> SharedSecrets {
    thread_local! {
        static SOURCE: SharedSecrets = Rc::new(RefCell::new(ProcessSecrets::from_process()));
    }
    SOURCE.with(Rc::clone)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, Value)]) -> Value {
        Value::Map(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn shape_accepts_only_the_exact_reference_form() {
        let ok = map(&[("secret", Value::Str("a.age".into()))]);
        assert!(matches!(
            content_shape(&ok),
            Ok(ContentShape::Secret("a.age"))
        ));
        assert!(matches!(
            content_shape(&Value::Str("x".into())),
            Ok(ContentShape::Plain)
        ));
        assert!(matches!(
            content_shape(&Value::Null),
            Ok(ContentShape::Plain)
        ));
        for bad in [
            map(&[]),
            map(&[("secret", Value::Int(1))]),
            map(&[("other", Value::Str("a".into()))]),
            map(&[
                ("secret", Value::Str("a".into())),
                ("extra", Value::Str("b".into())),
            ]),
        ] {
            assert!(content_shape(&bad).is_err());
        }
    }

    /// A directory with a recipe file and one well-formed age file.
    fn tree() -> (tempfile::TempDir, String) {
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir_all(base.join("s")).unwrap();
        let id = secrets::generate_identity();
        let ct = secrets::encrypt_to_recipients(b"x", std::slice::from_ref(&id.recipient)).unwrap();
        std::fs::write(base.join("s/ok.age"), ct).unwrap();
        std::fs::write(base.join("s/plain.age"), b"text").unwrap();
        std::os::unix::fs::symlink(base.join("s/ok.age"), base.join("s/link.age")).unwrap();
        let origin = base.join("r.yaml").display().to_string();
        (d, origin)
    }

    fn load(mode: ReferenceCheck, origin: &str, r: &str) -> Result<SecretRef> {
        resolve_reference_with(mode, origin, r, "res", false)
    }

    #[test]
    fn strict_is_the_default_and_the_public_function_is_strict() {
        assert_eq!(ReferenceCheck::default(), ReferenceCheck::Strict);
        let (_d, origin) = tree();
        assert!(resolve_reference(&origin, "s/ok.age", "res", false).is_ok());
        for gone in [
            "s/gone.age",
            "s/plain.age",
            "s/link.age",
            "s",
            "nodir/x.age",
        ] {
            assert!(
                resolve_reference(&origin, gone, "res", false).is_err(),
                "{gone}"
            );
        }
    }

    #[test]
    fn reference_only_defers_exactly_the_filesystem_checks() {
        let (_d, origin) = tree();
        // state of the file: accepted without looking
        for state_only in [
            "s/gone.age",
            "s/plain.age",
            "s/link.age",
            "s",
            "nodir/x.age",
        ] {
            let strict = load(ReferenceCheck::Strict, &origin, state_only);
            let loose = load(ReferenceCheck::ReferenceOnly, &origin, state_only);
            assert!(strict.is_err(), "{state_only}");
            let r = loose.unwrap_or_else(|e| panic!("{state_only}: {}", e.message));
            assert_eq!(r.reference, state_only);
        }
        // the text of the reference: the same error, byte for byte, in both
        for text in [
            "",
            "/abs",
            "../x",
            "a/../b",
            "./a",
            "a//b",
            "a/",
            "a\\b",
            "a/{{ v }}",
            "a/\tb",
        ] {
            let a = load(ReferenceCheck::Strict, &origin, text).unwrap_err();
            let b = load(ReferenceCheck::ReferenceOnly, &origin, text).unwrap_err();
            assert_eq!(a.message, b.message, "{text:?}");
        }
        let long = "a".repeat(MAX_REFERENCE_BYTES + 1);
        assert_eq!(
            load(ReferenceCheck::Strict, &origin, &long)
                .unwrap_err()
                .message,
            load(ReferenceCheck::ReferenceOnly, &origin, &long)
                .unwrap_err()
                .message
        );
        // a good reference resolves to the same value in both
        assert_eq!(
            load(ReferenceCheck::Strict, &origin, "s/ok.age").unwrap(),
            load(ReferenceCheck::ReferenceOnly, &origin, "s/ok.age").unwrap()
        );
    }

    #[test]
    fn observation_distinguishes_absent_from_refused() {
        let (d, origin) = tree();
        let base = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir_all(base.join("sealed")).unwrap();
        std::fs::write(base.join("sealed/x.age"), b"x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let obs =
            |r: &str| observe_reference(&load(ReferenceCheck::ReferenceOnly, &origin, r).unwrap());
        assert_eq!(obs("s/ok.age"), ReferenceState::Present);
        assert_eq!(obs("s/plain.age"), ReferenceState::Present);
        assert_eq!(obs("s/gone.age"), ReferenceState::Missing);
        assert_eq!(obs("nodir/x.age"), ReferenceState::Missing);
        assert_eq!(obs("s/link.age"), ReferenceState::Link);
        assert_eq!(obs("s"), ReferenceState::NotRegular);
        assert_eq!(obs("s/ok.age/inside"), ReferenceState::NotRegular);
        // restored even if an assertion below fails
        struct Restore(std::path::PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
        }
        let _restore = Restore(base.join("sealed"));
        std::fs::set_permissions(base.join("sealed"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(obs("sealed/x.age"), ReferenceState::Unreadable);
        }
    }
}
