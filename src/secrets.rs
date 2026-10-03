//! Encrypted-secret core (Phase A).
//!
//! Opaque bytes in, standard [age](https://age-encryption.org/v1) files out,
//! and back. This module is deliberately small and does only four things:
//!
//! * encrypt bytes to a passphrase **or** to recipients (never both: the age
//!   format forbids mixing an scrypt stanza with any other stanza);
//! * decrypt with a passphrase, with identities, or with a passphrase-protected
//!   identity;
//! * inspect an age header without decrypting (method, recipient count);
//! * keep decrypted material in a zeroizing carrier that cannot be printed.
//!
//! Hard rules (see the pre-implementation research, §22):
//!
//! * No custom cryptography. Every primitive and the file format come from the
//!   `age` crate. This module composes `Encryptor` / `Decryptor` and nothing
//!   else.
//! * Content is opaque: no UTF-8 assumption, no newline normalization, no
//!   parsing.
//! * Decrypted material, passphrases and private identities never appear in
//!   any error text, `Debug` output or log. Library error strings are never
//!   forwarded; [`SecretError`] has fixed messages.
//! * Bounded: a plaintext cap ([`MAX_SECRET_BYTES`]), a ciphertext cap derived
//!   from it, a header cap, a recipient cap and a ceiling on the scrypt work
//!   factor accepted on decryption.
//!
//! Nothing here reads files, prompts, or touches the CLI; those are later
//! phases. Callers hand in bytes and keys.

use age::secrecy::{ExposeSecret, SecretString};
use age::{scrypt, x25519, Decryptor, Encryptor};
use std::fmt;
use std::io::{Read, Write};
use std::str::FromStr;
use zeroize::Zeroizing;

/// Largest plaintext accepted or produced, in bytes. Provisional until the
/// Phase A measurements justify it (see SINTER_SECRETS_PHASE_A_2026-10-04.md).
pub const MAX_SECRET_BYTES: usize = 16 * 1024 * 1024;

/// Shortest passphrase accepted for *encryption*, in characters. Decryption
/// never enforces it (existing files must stay readable).
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// scrypt work factor (`N = 2^log_n`) used when encrypting to a passphrase.
/// Fixed rather than "about one second on this machine" (the library
/// default): the library's benchmark picks a different value on different
/// machines and even on different runs (19 or 20 were observed on one
/// laptop), which makes memory needs and strength unpredictable. 19 costs
/// about 0.75 s and 540 MiB on a 2023 laptop (Phase A measurements).
pub const PASSPHRASE_LOG_N: u8 = 19;

/// Highest scrypt work factor accepted on decryption: 2^20 is about 1.5 s and
/// 1 GiB on the measured laptop (cost doubles with each step; 21 is 2 GiB,
/// 22 is 4 GiB). Allocation failure aborts a Rust process instead of returning
/// an error, so the ceiling is also a memory-safety bound on small hosts. It
/// leaves one step above [`PASSPHRASE_LOG_N`] for files made by other age tools
/// on faster machines.
pub const MAX_SCRYPT_LOG_N: u8 = 20;

/// Most recipients accepted for one file.
pub const MAX_RECIPIENTS: usize = 256;

/// Most identities accepted in one identity file.
pub const MAX_IDENTITIES: usize = 64;

/// Largest recipients/identity file text, in bytes.
const MAX_KEY_TEXT_BYTES: usize = 1024 * 1024;

/// Largest age header accepted (the plaintext part before the payload), and
/// the most lines and stanzas it may have. The library's header parser
/// re-parses the accumulated header after every line (quadratic), so the
/// header is bounded by this module *before* the library sees it. A header
/// for [`MAX_RECIPIENTS`] recipients is about 50 KiB.
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADER_LINES: usize = 1024;
/// Every stanza counts, decoy ("grease") stanzas included.
const MAX_HEADER_STANZAS: usize = MAX_RECIPIENTS + 8;

const ARMOR_BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
const AGE_V1_MAGIC: &[u8] = b"age-encryption.org/v1";

/// Why a secret operation failed. Fixed text only: no variant carries, and no
/// message contains, plaintext, a passphrase, a key, a path or any text from
/// the underlying library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    /// Plaintext or ciphertext exceeds the size limit.
    TooLarge,
    /// The bytes are not an age file.
    NotAgeFile,
    /// An age file of a version or structure this build does not support.
    UnsupportedFormat,
    /// The header or payload failed authentication, or the file is truncated.
    Corrupt,
    /// The passphrase or identity could not open the file.
    DecryptionFailed,
    /// None of the supplied identities is a recipient of the file.
    NoMatchingKey,
    /// The file needs a passphrase and none was supplied.
    NeedsPassphrase,
    /// The file needs an identity and none was supplied.
    NeedsIdentity,
    /// The file asks for more scrypt work than this build accepts.
    ExcessiveWork,
    /// The passphrase is shorter than [`MIN_PASSPHRASE_CHARS`].
    PassphraseTooShort,
    /// No recipients were supplied.
    NoRecipients,
    /// Too many recipients were supplied.
    TooManyRecipients,
    /// A recipient line is not a valid native age recipient.
    InvalidRecipient,
    /// An identity line is not a valid native age identity, or none was found.
    InvalidIdentity,
    /// An identity file lists too many identities.
    TooManyIdentities,
    /// An I/O or internal failure with no further detail.
    Internal,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SecretError::TooLarge => "secret is larger than the size limit",
            SecretError::NotAgeFile => "the data is not an age encrypted file",
            SecretError::UnsupportedFormat => "unsupported age file format",
            SecretError::Corrupt => "the encrypted data is corrupt or truncated",
            SecretError::DecryptionFailed => {
                "the secret could not be decrypted (wrong passphrase or key, or corrupt data)"
            }
            SecretError::NoMatchingKey => "none of the supplied keys can open this secret",
            SecretError::NeedsPassphrase => "this secret requires a passphrase",
            SecretError::NeedsIdentity => "this secret requires an identity (private key)",
            SecretError::ExcessiveWork => {
                "the secret asks for more passphrase-hashing work than is allowed"
            }
            SecretError::PassphraseTooShort => "the passphrase is too short",
            SecretError::NoRecipients => "no recipients were given",
            SecretError::TooManyRecipients => "too many recipients were given",
            SecretError::InvalidRecipient => "a recipient is not a valid age recipient",
            SecretError::InvalidIdentity => "no valid age identity was found",
            SecretError::TooManyIdentities => "too many identities were given",
            SecretError::Internal => "secret operation failed",
        })
    }
}

impl std::error::Error for SecretError {}

/// Decrypted bytes. Zeroized when dropped; never printable, comparable by
/// `==`, cloneable or serializable. The only way to read it is
/// [`Secret::expose`].
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Take ownership of `bytes`.
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(Zeroizing::new(bytes))
    }

    /// The bytes. Callers must not log, format or copy them without need.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

/// A human passphrase. Zeroized when dropped; never printable.
pub struct Passphrase(SecretString);

impl Passphrase {
    /// A passphrase for encrypting: must be at least
    /// [`MIN_PASSPHRASE_CHARS`] characters.
    pub fn for_encryption(text: String) -> Result<Self, SecretError> {
        let text = Zeroizing::new(text);
        if text.chars().count() < MIN_PASSPHRASE_CHARS {
            return Err(SecretError::PassphraseTooShort);
        }
        Ok(Passphrase(SecretString::from(text.as_str())))
    }

    /// A passphrase for decrypting. No length policy: files made elsewhere
    /// must stay readable.
    pub fn for_decryption(text: String) -> Self {
        // Copy into an exactly-sized box and zeroize the caller's `String`
        // (converting the `String` itself could reallocate and leave the old
        // buffer behind unzeroized).
        let text = Zeroizing::new(text);
        Passphrase(SecretString::from(text.as_str()))
    }

    fn to_age(&self) -> SecretString {
        SecretString::from(self.0.expose_secret())
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase([redacted])")
    }
}

/// A public age recipient (`age1…`). Public data, but its text is not echoed
/// by `Debug` so that logs never correlate files with recipients by accident.
pub struct Recipient(x25519::Recipient);

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Recipient(..)")
    }
}

impl Recipient {
    /// The `age1…` text, for writing a recipients file.
    pub fn to_text(&self) -> String {
        self.0.to_string()
    }
}

/// Parse a recipients file in age's `-R` format: one native recipient per
/// line, blank lines and `#` comments ignored. Plugin, SSH and other
/// recipient types are rejected (not enabled in this build).
pub fn parse_recipients(text: &str) -> Result<Vec<Recipient>, SecretError> {
    if text.len() > MAX_KEY_TEXT_BYTES {
        return Err(SecretError::TooLarge);
    }
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let r = x25519::Recipient::from_str(line).map_err(|_| SecretError::InvalidRecipient)?;
        out.push(Recipient(r));
        if out.len() > MAX_RECIPIENTS {
            return Err(SecretError::TooManyRecipients);
        }
    }
    if out.is_empty() {
        return Err(SecretError::NoRecipients);
    }
    Ok(out)
}

/// A newly generated key pair.
pub struct GeneratedIdentity {
    /// The identity file text in age-keygen format (a `# public key:` comment
    /// and the `AGE-SECRET-KEY-1…` line). Secret.
    pub identity_file: Secret,
    /// The matching recipient.
    pub recipient: Recipient,
}

/// Generate an X25519 key pair with the age library's generator.
pub fn generate_identity() -> GeneratedIdentity {
    let id = x25519::Identity::generate();
    let recipient = id.to_public();
    // Large enough that the secret line never forces a reallocation (which
    // would leave an unzeroized copy of the partial text).
    let mut text = Zeroizing::new(String::with_capacity(512));
    text.push_str("# public key: ");
    text.push_str(&recipient.to_string());
    text.push('\n');
    text.push_str(id.to_string().expose_secret());
    text.push('\n');
    GeneratedIdentity {
        identity_file: Secret::new(text.as_bytes().to_vec()),
        recipient: Recipient(recipient),
    }
}

/// The keys available for opening secrets: identities (private keys) and/or
/// a passphrase. Which one is used is decided by the file's header, never by
/// the caller.
#[derive(Default)]
pub struct Keys {
    identities: Vec<x25519::Identity>,
    passphrase: Option<Passphrase>,
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Keys({} identities, passphrase: {})",
            self.identities.len(),
            if self.passphrase.is_some() {
                "yes"
            } else {
                "no"
            }
        )
    }
}

impl Keys {
    pub fn new() -> Self {
        Keys::default()
    }

    /// Add the identities of an identity file (age-keygen format). Comments
    /// and blank lines are skipped. Only native `AGE-SECRET-KEY-1…`
    /// identities are accepted.
    pub fn add_identity_file(&mut self, text: &[u8]) -> Result<(), SecretError> {
        if text.len() > MAX_KEY_TEXT_BYTES {
            return Err(SecretError::TooLarge);
        }
        let text = std::str::from_utf8(text).map_err(|_| SecretError::InvalidIdentity)?;
        // Parse everything first; `self` changes only if the whole file is good.
        let mut parsed: Vec<x25519::Identity> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            parsed
                .push(x25519::Identity::from_str(line).map_err(|_| SecretError::InvalidIdentity)?);
            if self.identities.len() + parsed.len() > MAX_IDENTITIES {
                return Err(SecretError::TooManyIdentities);
            }
        }
        if parsed.is_empty() {
            return Err(SecretError::InvalidIdentity);
        }
        self.identities.append(&mut parsed);
        Ok(())
    }

    pub fn set_passphrase(&mut self, passphrase: Passphrase) {
        self.passphrase = Some(passphrase);
    }

    /// Open a passphrase-protected identity file (an age file encrypted to a
    /// passphrase whose plaintext is an identity file) and add its identities.
    pub fn add_protected_identity(
        &mut self,
        ciphertext: &[u8],
        passphrase: &Passphrase,
    ) -> Result<(), SecretError> {
        let mut unlock = Keys::new();
        unlock.passphrase = Some(Passphrase(passphrase.to_age()));
        let plain = decrypt(ciphertext, &unlock)?;
        self.add_identity_file(plain.expose())
    }
}

/// How an age file is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// scrypt: a passphrase opens it.
    Passphrase,
    /// X25519 (or another native recipient type): an identity opens it.
    Recipients,
}

/// What can be learned from an age header without decrypting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub method: Method,
    /// Recipient stanzas, not counting the decoy ("grease") stanza the age
    /// format adds to recipient files on purpose (its tag ends in `-grease`).
    /// Anonymous: age does not say *which* recipients, only how many.
    pub recipients: usize,
    /// The file was ASCII-armored.
    pub armored: bool,
}

/// Maximum ciphertext size for a given plaintext cap: the plaintext, one
/// 16-byte tag per 64 KiB chunk (plus one), the 16-byte nonce, and a header.
fn max_ciphertext(cap: usize) -> usize {
    cap + (cap / (64 * 1024) + 1) * 16 + 16 + MAX_HEADER_BYTES
}

/// Binary age bytes from possibly armored input. Ciphertext is not secret.
fn dearmor(
    ciphertext: &[u8],
    cap: usize,
) -> Result<(std::borrow::Cow<'_, [u8]>, bool), SecretError> {
    let limit = max_ciphertext(cap);
    // Armor inflates by 4/3, plus a line break every 64 characters (CRLF
    // doubles that); allow for both. The bounded read below is the real limit.
    if ciphertext.len() > limit / 3 * 4 * 67 / 64 + 4096 {
        return Err(SecretError::TooLarge);
    }
    if ciphertext.starts_with(ARMOR_BEGIN) {
        let mut reader = age::armor::ArmoredReader::new(ciphertext);
        let mut bin = Vec::new();
        reader
            .by_ref()
            .take(limit as u64 + 1)
            .read_to_end(&mut bin)
            .map_err(|_| SecretError::Corrupt)?;
        if bin.len() > limit {
            return Err(SecretError::TooLarge);
        }
        Ok((std::borrow::Cow::Owned(bin), true))
    } else {
        if ciphertext.len() > limit {
            return Err(SecretError::TooLarge);
        }
        Ok((std::borrow::Cow::Borrowed(ciphertext), false))
    }
}

/// Largest age file (binary or armored) that [`decrypt`] and [`inspect`] will
/// accept for the default plaintext cap. Callers reading a file should read at
/// most this many bytes (plus one, to detect excess).
pub fn max_file_bytes() -> usize {
    max_ciphertext(MAX_SECRET_BYTES) / 3 * 4 * 67 / 64 + 4096
}

fn map_decrypt(e: age::DecryptError) -> SecretError {
    use age::DecryptError as D;
    match e {
        D::DecryptionFailed | D::KeyDecryptionFailed => SecretError::DecryptionFailed,
        D::InvalidHeader => SecretError::NotAgeFile,
        D::InvalidMac => SecretError::Corrupt,
        D::NoMatchingKeys => SecretError::NoMatchingKey,
        D::ExcessiveWork { .. } => SecretError::ExcessiveWork,
        D::UnknownFormat => SecretError::UnsupportedFormat,
        D::Io(_) => SecretError::Corrupt,
        _ => SecretError::Internal,
    }
}

/// Describe an age file without decrypting it.
pub fn inspect(ciphertext: &[u8]) -> Result<Header, SecretError> {
    inspect_with_cap(ciphertext, MAX_SECRET_BYTES)
}

/// What the pre-scan learned. The scan runs before the library parses the
/// header (see [`MAX_HEADER_BYTES`]); the numbers are claims of an
/// unauthenticated header.
struct Scan {
    /// Stanzas other than the decoy ("grease") ones.
    recipients: usize,
}

/// Bound and count the header of binary age bytes without any library parse.
fn scan_header(bin: &[u8]) -> Result<Scan, SecretError> {
    let mut lines = bin.split(|b| *b == b'\n');
    let first = lines.next().ok_or(SecretError::NotAgeFile)?;
    if first != AGE_V1_MAGIC {
        return Err(if first.starts_with(b"age-encryption.org/") {
            SecretError::UnsupportedFormat
        } else {
            SecretError::NotAgeFile
        });
    }
    let (mut all, mut recipients, mut count) = (0usize, 0usize, 1usize);
    let mut seen = AGE_V1_MAGIC.len() + 1;
    for line in lines {
        seen += line.len() + 1;
        count += 1;
        if seen > MAX_HEADER_BYTES || count > MAX_HEADER_LINES {
            return Err(SecretError::NotAgeFile);
        }
        if let Some(rest) = line.strip_prefix(b"-> ") {
            all += 1;
            if all > MAX_HEADER_STANZAS {
                return Err(SecretError::NotAgeFile);
            }
            let tag = rest.split(|b| *b == b' ').next().unwrap_or(&[]);
            if !tag.ends_with(b"-grease") {
                recipients += 1;
            }
        } else if line.starts_with(b"---") {
            if recipients == 0 || recipients > MAX_RECIPIENTS {
                return Err(SecretError::NotAgeFile);
            }
            return Ok(Scan { recipients });
        }
    }
    Err(SecretError::NotAgeFile)
}

fn inspect_with_cap(ciphertext: &[u8], cap: usize) -> Result<Header, SecretError> {
    let (bin, armored) = dearmor(ciphertext, cap)?;
    let bin: &[u8] = &bin;
    let scan = scan_header(bin)?;
    // The library validates the structure (including that an scrypt stanza is
    // the only stanza) and tells the method.
    let d = Decryptor::new_buffered(bin).map_err(map_decrypt)?;
    Ok(Header {
        method: if d.is_scrypt() {
            Method::Passphrase
        } else {
            Method::Recipients
        },
        recipients: scan.recipients,
        armored,
    })
}

/// Encrypt `plaintext` to a passphrase (age scrypt, work factor
/// [`PASSPHRASE_LOG_N`]).
pub fn encrypt_with_passphrase(
    plaintext: &[u8],
    passphrase: &Passphrase,
) -> Result<Vec<u8>, SecretError> {
    encrypt_passphrase_inner(plaintext, passphrase, None, MAX_SECRET_BYTES)
}

fn encrypt_passphrase_inner(
    plaintext: &[u8],
    passphrase: &Passphrase,
    log_n: Option<u8>,
    cap: usize,
) -> Result<Vec<u8>, SecretError> {
    if plaintext.len() > cap {
        return Err(SecretError::TooLarge);
    }
    if passphrase.0.expose_secret().chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(SecretError::PassphraseTooShort);
    }
    let mut recipient = scrypt::Recipient::new(passphrase.to_age());
    recipient.set_work_factor(log_n.unwrap_or(PASSPHRASE_LOG_N));
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|_| SecretError::Internal)?;
    write_age(encryptor, plaintext)
}

/// Encrypt `plaintext` to one or more recipients. Any one matching identity
/// opens the file.
pub fn encrypt_to_recipients(
    plaintext: &[u8],
    recipients: &[Recipient],
) -> Result<Vec<u8>, SecretError> {
    encrypt_recipients_inner(plaintext, recipients, MAX_SECRET_BYTES)
}

fn encrypt_recipients_inner(
    plaintext: &[u8],
    recipients: &[Recipient],
    cap: usize,
) -> Result<Vec<u8>, SecretError> {
    if plaintext.len() > cap {
        return Err(SecretError::TooLarge);
    }
    if recipients.is_empty() {
        return Err(SecretError::NoRecipients);
    }
    if recipients.len() > MAX_RECIPIENTS {
        return Err(SecretError::TooManyRecipients);
    }
    let encryptor =
        Encryptor::with_recipients(recipients.iter().map(|r| &r.0 as &dyn age::Recipient))
            .map_err(|_| SecretError::Internal)?;
    write_age(encryptor, plaintext)
}

fn write_age(encryptor: Encryptor, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
    let mut out = Vec::with_capacity(plaintext.len() + plaintext.len() / 4096 + 4096);
    let mut w = encryptor
        .wrap_output(&mut out)
        .map_err(|_| SecretError::Internal)?;
    w.write_all(plaintext).map_err(|_| SecretError::Internal)?;
    w.finish().map_err(|_| SecretError::Internal)?;
    Ok(out)
}

/// Protect an identity file with a passphrase: an ordinary age passphrase
/// file whose plaintext is the identity file. This is the "protected
/// identity" of the hybrid model; it needs no format of its own.
pub fn protect_identity(
    identity_file: &Secret,
    passphrase: &Passphrase,
) -> Result<Vec<u8>, SecretError> {
    encrypt_with_passphrase(identity_file.expose(), passphrase)
}

/// Decrypt an age file (binary or armored) with the supplied keys. The header
/// decides which key is used: a passphrase for scrypt files, identities for
/// recipient files.
pub fn decrypt(ciphertext: &[u8], keys: &Keys) -> Result<Secret, SecretError> {
    decrypt_with_cap(ciphertext, keys, MAX_SECRET_BYTES)
}

fn decrypt_with_cap(ciphertext: &[u8], keys: &Keys, cap: usize) -> Result<Secret, SecretError> {
    let (bin, _) = dearmor(ciphertext, cap)?;
    // Bound the header before the (quadratic) library parser sees it.
    scan_header(&bin)?;
    let decryptor = Decryptor::new_buffered(&bin[..]).map_err(map_decrypt)?;
    let scrypt_identity;
    let mut refs: Vec<&dyn age::Identity> = Vec::new();
    if decryptor.is_scrypt() {
        let pass = keys
            .passphrase
            .as_ref()
            .ok_or(SecretError::NeedsPassphrase)?;
        let mut id = scrypt::Identity::new(pass.to_age());
        id.set_max_work_factor(MAX_SCRYPT_LOG_N);
        scrypt_identity = id;
        refs.push(&scrypt_identity);
    } else {
        if keys.identities.is_empty() {
            return Err(SecretError::NeedsIdentity);
        }
        refs.extend(keys.identities.iter().map(|i| i as &dyn age::Identity));
    }
    let mut reader = decryptor.decrypt(refs.into_iter()).map_err(map_decrypt)?;
    // The plaintext can never be longer than the ciphertext, so reserving that
    // much up front means the buffer never reallocates (a reallocation would
    // leave an unzeroized copy behind).
    let reserve = bin.len().min(cap.saturating_add(1));
    let mut out = Zeroizing::new(Vec::with_capacity(reserve));
    (&mut reader)
        .take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| SecretError::Corrupt)?;
    if out.len() > cap {
        return Err(SecretError::TooLarge);
    }
    Ok(Secret(out))
}

/// Process-level hardening to call before decrypting: no core dumps, and on
/// Linux the process is made non-dumpable (no same-user ptrace or
/// `/proc/<pid>/mem` read of decrypted buffers). Returns `true` only if every
/// step took effect. Idempotent.
///
/// Side effects, by design: `RLIMIT_CORE = 0` (soft and hard) cannot be raised
/// again by this process and is inherited by its children; on Linux
/// `PR_SET_DUMPABLE = 0` makes `/proc/self/*` root-owned and blocks
/// gdb/strace/perf attach (children started with `exec` are dumpable again).
/// It does not stop a root user, swap, or memory other libraries copied; see
/// the threat model.
pub fn harden_process() -> bool {
    #[cfg(unix)]
    unsafe {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut ok = libc::setrlimit(libc::RLIMIT_CORE, &zero) == 0;
        #[cfg(target_os = "linux")]
        {
            ok &= libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
        }
        ok
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery";
    /// Fast scrypt for tests (N = 2^10).
    const FAST: Option<u8> = Some(10);

    fn pass() -> Passphrase {
        Passphrase::for_encryption(PASS.to_string()).unwrap()
    }

    fn keys_pass(p: &str) -> Keys {
        let mut k = Keys::new();
        k.set_passphrase(Passphrase::for_decryption(p.to_string()));
        k
    }

    fn keys_id(g: &GeneratedIdentity) -> Keys {
        let mut k = Keys::new();
        k.add_identity_file(g.identity_file.expose()).unwrap();
        k
    }

    /// Deterministic pseudo-random bytes.
    fn noise(n: usize) -> Vec<u8> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn pass_ct(plain: &[u8]) -> Vec<u8> {
        encrypt_passphrase_inner(plain, &pass(), FAST, MAX_SECRET_BYTES).unwrap()
    }

    #[test]
    fn opaque_bytes_roundtrip_exactly() {
        let all: Vec<u8> = (0..=255u8).collect();
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            b"no trailing newline".to_vec(),
            b"crlf\r\nline\r\n".to_vec(),
            b"trailing newline\n".to_vec(),
            vec![0, 0, 0],
            all.clone(),
            vec![0xff, 0xfe, 0x80, 0xc0, 0xc1],
            noise(1 << 20),
            noise(64 * 1024),
            noise(64 * 1024 + 1),
            noise(64 * 1024 - 1),
        ];
        let g = generate_identity();
        for plain in cases {
            let ct = encrypt_to_recipients(&plain, std::slice::from_ref(&g.recipient)).unwrap();
            let back = decrypt(&ct, &keys_id(&g)).unwrap();
            assert_eq!(
                back.expose(),
                &plain[..],
                "recipient, {} bytes",
                plain.len()
            );
            let ct = pass_ct(&plain);
            let back = decrypt(&ct, &keys_pass(PASS)).unwrap();
            assert_eq!(
                back.expose(),
                &plain[..],
                "passphrase, {} bytes",
                plain.len()
            );
        }
    }

    #[test]
    fn multiple_recipients_any_one_opens_and_a_stranger_does_not() {
        let (a, b, c) = (
            generate_identity(),
            generate_identity(),
            generate_identity(),
        );
        let rs = vec![
            Recipient(x25519::Recipient::from_str(&a.recipient.to_text()).unwrap()),
            Recipient(x25519::Recipient::from_str(&b.recipient.to_text()).unwrap()),
        ];
        let ct = encrypt_to_recipients(b"payload", &rs).unwrap();
        assert_eq!(decrypt(&ct, &keys_id(&a)).unwrap().expose(), b"payload");
        assert_eq!(decrypt(&ct, &keys_id(&b)).unwrap().expose(), b"payload");
        assert_eq!(
            decrypt(&ct, &keys_id(&c)).unwrap_err(),
            SecretError::NoMatchingKey
        );
        let h = inspect(&ct).unwrap();
        assert_eq!(
            (h.method, h.recipients, h.armored),
            (Method::Recipients, 2, false)
        );
    }

    #[test]
    fn passphrase_mode_wrong_passphrase_and_missing_key() {
        let ct = pass_ct(b"secret");
        assert_eq!(
            decrypt(&ct, &keys_pass("another passphrase")).unwrap_err(),
            SecretError::DecryptionFailed
        );
        assert_eq!(
            decrypt(&ct, &Keys::new()).unwrap_err(),
            SecretError::NeedsPassphrase
        );
        // An identity does not open a passphrase file, and a passphrase does
        // not open a recipient file.
        let g = generate_identity();
        assert_eq!(
            decrypt(&ct, &keys_id(&g)).unwrap_err(),
            SecretError::NeedsPassphrase
        );
        let ct2 = encrypt_to_recipients(b"x", std::slice::from_ref(&g.recipient)).unwrap();
        assert_eq!(
            decrypt(&ct2, &keys_pass(PASS)).unwrap_err(),
            SecretError::NeedsIdentity
        );
        let h = inspect(&ct).unwrap();
        assert_eq!((h.method, h.recipients), (Method::Passphrase, 1));
    }

    #[test]
    fn short_passphrases_are_refused_for_encryption_only() {
        assert_eq!(
            Passphrase::for_encryption("short".into()).unwrap_err(),
            SecretError::PassphraseTooShort
        );
        assert!(Passphrase::for_encryption("exactly12chr".into()).is_ok());
        // Decryption never applies the policy.
        let _ = Passphrase::for_decryption("x".into());
    }

    #[test]
    fn tampering_and_truncation_fail_closed() {
        let g = generate_identity();
        let ct =
            encrypt_to_recipients(&noise(200_000), std::slice::from_ref(&g.recipient)).unwrap();
        let keys = keys_id(&g);
        assert!(decrypt(&ct, &keys).is_ok());
        // Flip every region: header, payload start, payload end.
        for pos in [30usize, 80, ct.len() / 2, ct.len() - 1] {
            let mut bad = ct.clone();
            bad[pos] ^= 0x01;
            assert!(decrypt(&bad, &keys).is_err(), "flip at {}", pos);
        }
        // Truncation at several points, including exactly one chunk boundary.
        for cut in [ct.len() - 1, ct.len() - 17, ct.len() / 2, 100, 10, 0] {
            assert!(decrypt(&ct[..cut], &keys).is_err(), "cut at {}", cut);
        }
        // Appended bytes are not silently ignored.
        let mut extended = ct.clone();
        extended.extend_from_slice(&[0u8; 32]);
        assert!(decrypt(&extended, &keys).is_err());
    }

    #[test]
    fn errors_are_fixed_text_and_never_carry_secrets() {
        let canary_pass = "canary-passphrase-ZXCV-1234";
        let canary_plain = b"canary-plaintext-QWER-5678";
        let p = Passphrase::for_encryption(canary_pass.to_string()).unwrap();
        let ct = encrypt_passphrase_inner(canary_plain, &p, FAST, MAX_SECRET_BYTES).unwrap();
        let outputs = vec![
            format!("{:?}", p),
            format!("{:?}", Secret::new(canary_plain.to_vec())),
            format!("{:?}", keys_pass(canary_pass)),
            format!(
                "{}",
                decrypt(&ct, &keys_pass("wrong wrong wrong")).unwrap_err()
            ),
            format!(
                "{:?}",
                decrypt(&ct, &keys_pass("wrong wrong wrong")).unwrap_err()
            ),
            format!(
                "{}",
                decrypt(&ct[..20], &keys_pass(canary_pass)).unwrap_err()
            ),
            format!("{}", decrypt(b"not an age file", &Keys::new()).unwrap_err()),
        ];
        for o in outputs {
            assert!(!o.contains("canary"), "{}", o);
        }
        // Every variant has fixed, non-empty text.
        for e in [
            SecretError::TooLarge,
            SecretError::NotAgeFile,
            SecretError::UnsupportedFormat,
            SecretError::Corrupt,
            SecretError::DecryptionFailed,
            SecretError::NoMatchingKey,
            SecretError::NeedsPassphrase,
            SecretError::NeedsIdentity,
            SecretError::ExcessiveWork,
            SecretError::PassphraseTooShort,
            SecretError::NoRecipients,
            SecretError::TooManyRecipients,
            SecretError::InvalidRecipient,
            SecretError::InvalidIdentity,
            SecretError::TooManyIdentities,
            SecretError::Internal,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn inspect_classifies_without_trusting_names_or_decrypting() {
        for junk in [
            &b""[..],
            b"plain text",
            b"age-encryption.org/v1",
            b"age-encryption.org/v1\n",
            b"age-encryption.org/v1\n--- \n",
            &[0u8; 64][..],
        ] {
            assert!(inspect(junk).is_err(), "{:?}", junk);
        }
        assert_eq!(
            inspect(b"age-encryption.org/v2\n-> x\n--- AAAA\n").unwrap_err(),
            SecretError::UnsupportedFormat
        );
        let g = generate_identity();
        let ct = encrypt_to_recipients(b"x", std::slice::from_ref(&g.recipient)).unwrap();
        // One recipient, even though the file carries an extra decoy stanza.
        assert_eq!(inspect(&ct).unwrap().recipients, 1);
        let header_end = ct.windows(4).position(|w| w == b"\n---").unwrap();
        let all_stanzas = ct[..header_end]
            .windows(4)
            .filter(|w| *w == b"\n-> ")
            .count();
        assert_eq!(all_stanzas, 2, "one recipient stanza plus the decoy");
    }

    #[test]
    fn armored_files_are_accepted_for_inspect_and_decrypt() {
        let g = generate_identity();
        let mut armored = Vec::new();
        {
            let w = age::armor::ArmoredWriter::wrap_output(
                &mut armored,
                age::armor::Format::AsciiArmor,
            )
            .unwrap();
            let enc =
                Encryptor::with_recipients(std::iter::once(&g.recipient.0 as &dyn age::Recipient))
                    .unwrap();
            let mut sw = enc.wrap_output(w).unwrap();
            sw.write_all(b"armored payload").unwrap();
            sw.finish().unwrap().finish().unwrap();
        }
        assert!(armored.starts_with(ARMOR_BEGIN));
        let h = inspect(&armored).unwrap();
        assert!(h.armored);
        assert_eq!(
            decrypt(&armored, &keys_id(&g)).unwrap().expose(),
            b"armored payload"
        );
        // A damaged armor is rejected.
        let mut bad = armored.clone();
        let mid = bad.len() / 2;
        bad[mid] = b'!';
        assert!(decrypt(&bad, &keys_id(&g)).is_err());
    }

    #[test]
    fn size_caps_apply_to_plaintext_and_ciphertext() {
        let g = generate_identity();
        let rs = std::slice::from_ref(&g.recipient);
        assert_eq!(
            encrypt_recipients_inner(&noise(1001), rs, 1000).unwrap_err(),
            SecretError::TooLarge
        );
        let ct = encrypt_recipients_inner(&noise(1000), rs, 1000).unwrap();
        assert!(decrypt_with_cap(&ct, &keys_id(&g), 1000).is_ok());
        // The same file read under a smaller cap is refused, whether the
        // plaintext or the ciphertext limit trips first.
        assert_eq!(
            decrypt_with_cap(&ct, &keys_id(&g), 999).unwrap_err(),
            SecretError::TooLarge
        );
        let big = encrypt_recipients_inner(&noise(300_000), rs, MAX_SECRET_BYTES).unwrap();
        assert_eq!(
            decrypt_with_cap(&big, &keys_id(&g), 1000).unwrap_err(),
            SecretError::TooLarge
        );
        assert_eq!(
            inspect_with_cap(&big, 1000).unwrap_err(),
            SecretError::TooLarge
        );
    }

    #[test]
    fn excessive_scrypt_work_is_refused_before_it_is_done() {
        let ct = pass_ct(b"x");
        let text = String::from_utf8_lossy(
            &ct[..ct.iter().position(|b| *b == b'\n').map(|_| 160).unwrap()],
        )
        .to_string();
        assert!(text.contains("-> scrypt"));
        // Rewrite the work factor in the stanza ("... 10") to 40. The library
        // checks the factor before spending any time on it; the MAC would
        // fail afterwards, but we must get ExcessiveWork first.
        let needle = b" 10\n";
        let pos = ct
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("scrypt log_n argument");
        let mut forged = ct.clone();
        forged[pos + 1] = b'4';
        forged[pos + 2] = b'0';
        let started = std::time::Instant::now();
        assert_eq!(
            decrypt(&forged, &keys_pass(PASS)).unwrap_err(),
            SecretError::ExcessiveWork
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn passphrase_work_factor_is_fixed_and_ceiling_is_enforced() {
        // The default path writes exactly PASSPHRASE_LOG_N (no per-machine
        // benchmark): read it back from the stanza ("-> scrypt <salt> <n>").
        let p = pass();
        let ct = encrypt_with_passphrase(b"x", &p).unwrap();
        let line_end = ct[22..].iter().position(|b| *b == b'\n').unwrap() + 22;
        let stanza = String::from_utf8_lossy(&ct[22..line_end]).to_string();
        assert!(stanza.starts_with("-> scrypt "), "{}", stanza);
        assert_eq!(
            stanza.rsplit(' ').next().unwrap(),
            PASSPHRASE_LOG_N.to_string()
        );
        assert_eq!(decrypt(&ct, &keys_pass(PASS)).unwrap().expose(), b"x");
        // One step above the ceiling is refused before any work is done.
        let low = pass_ct(b"x");
        let pos = low.windows(4).position(|w| w == b" 10\n").unwrap();
        let mut forged = low.clone();
        forged[pos + 1] = b'2';
        forged[pos + 2] = b'1';
        assert_eq!(MAX_SCRYPT_LOG_N + 1, 21);
        let started = std::time::Instant::now();
        assert_eq!(
            decrypt(&forged, &keys_pass(PASS)).unwrap_err(),
            SecretError::ExcessiveWork
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn age_forbids_mixing_a_passphrase_with_recipients() {
        // Evidence for the hybrid decision: the library (like the spec)
        // refuses a header that mixes an scrypt stanza with another stanza.
        let g = generate_identity();
        let s = scrypt::Recipient::new(pass().to_age());
        let both: Vec<&dyn age::Recipient> = vec![&s, &g.recipient.0];
        assert!(Encryptor::with_recipients(both.into_iter()).is_err());
    }

    #[test]
    fn identity_file_parsing_is_strict() {
        let g = generate_identity();
        let mut k = Keys::new();
        assert!(k.add_identity_file(g.identity_file.expose()).is_ok());
        for bad in [
            &b""[..],
            b"# only a comment\n",
            b"not an identity\n",
            b"AGE-SECRET-KEY-1INVALID\n",
            &[0xff, 0xfe][..],
            b"AGE-PLUGIN-YUBIKEY-1QQQQQ\n",
        ] {
            assert_eq!(
                Keys::new().add_identity_file(bad).unwrap_err(),
                SecretError::InvalidIdentity,
                "{:?}",
                bad
            );
        }
    }

    #[test]
    fn recipient_parsing_is_strict() {
        let g = generate_identity();
        let ok = format!("# team\n\n{}\n", g.recipient.to_text());
        assert_eq!(parse_recipients(&ok).unwrap().len(), 1);
        for bad in [
            "",
            "# only comments\n",
            "age1invalid",
            "ssh-ed25519 AAAA",
            "age1plugin1abc",
        ] {
            assert!(parse_recipients(bad).is_err(), "{:?}", bad);
        }
        let many: String = (0..MAX_RECIPIENTS + 1)
            .map(|_| format!("{}\n", g.recipient.to_text()))
            .collect();
        assert_eq!(
            parse_recipients(&many).unwrap_err(),
            SecretError::TooManyRecipients
        );
    }

    #[test]
    fn protected_identity_and_the_two_way_recovery_construction() {
        // The hybrid model: secrets are encrypted to a team identity (kept
        // passphrase-protected) AND to an automation identity.
        let team = generate_identity();
        let automation = generate_identity();
        let protected = {
            let p = pass();
            // fast scrypt for the test
            encrypt_passphrase_inner(team.identity_file.expose(), &p, FAST, MAX_SECRET_BYTES)
                .unwrap()
        };
        let secret = b"-----BEGIN OPENSSH PRIVATE KEY-----\r\n\x00\x01\x02\r\n-----END";
        let rs = vec![
            Recipient(x25519::Recipient::from_str(&team.recipient.to_text()).unwrap()),
            Recipient(x25519::Recipient::from_str(&automation.recipient.to_text()).unwrap()),
        ];
        let ct = encrypt_to_recipients(secret, &rs).unwrap();

        // 1. Operator with only the passphrase: unlock the protected identity.
        let mut keys = Keys::new();
        keys.add_protected_identity(&protected, &Passphrase::for_decryption(PASS.into()))
            .unwrap();
        assert_eq!(decrypt(&ct, &keys).unwrap().expose(), &secret[..]);
        // 2. Automation with only its identity file.
        assert_eq!(
            decrypt(&ct, &keys_id(&automation)).unwrap().expose(),
            &secret[..]
        );
        // 3. Recovery A: passphrase lost -> automation identity re-encrypts to
        //    a replacement identity.
        let replacement = generate_identity();
        let plain = decrypt(&ct, &keys_id(&automation)).unwrap();
        let ct2 = encrypt_to_recipients(
            plain.expose(),
            &[Recipient(
                x25519::Recipient::from_str(&replacement.recipient.to_text()).unwrap(),
            )],
        )
        .unwrap();
        assert_eq!(
            decrypt(&ct2, &keys_id(&replacement)).unwrap().expose(),
            &secret[..]
        );
        // 4. Recovery B: automation identity lost -> the passphrase recovers.
        let plain = decrypt(&ct, &keys).unwrap();
        assert_eq!(plain.expose(), &secret[..]);
        // Wrong passphrase for the protected identity.
        let mut bad = Keys::new();
        assert_eq!(
            bad.add_protected_identity(
                &protected,
                &Passphrase::for_decryption("not the pass".into())
            )
            .unwrap_err(),
            SecretError::DecryptionFailed
        );
        // A protected identity is an ordinary passphrase age file.
        assert_eq!(inspect(&protected).unwrap().method, Method::Passphrase);
    }

    #[test]
    fn protect_identity_uses_the_default_work_factor_path() {
        // Smoke: the public API (default ~1 s scrypt) works end to end.
        let g = generate_identity();
        let protected = protect_identity(&g.identity_file, &pass()).unwrap();
        let mut keys = Keys::new();
        keys.add_protected_identity(&protected, &Passphrase::for_decryption(PASS.into()))
            .unwrap();
        let ct = encrypt_to_recipients(b"x", std::slice::from_ref(&g.recipient)).unwrap();
        assert_eq!(decrypt(&ct, &keys).unwrap().expose(), b"x");
    }

    #[test]
    fn plaintext_buffer_does_not_reallocate() {
        // The reserve covers the whole plaintext, so the zeroizing buffer is
        // never reallocated (a reallocation would leave an unzeroed copy).
        let g = generate_identity();
        let plain = noise(300_000);
        let ct = encrypt_to_recipients(&plain, std::slice::from_ref(&g.recipient)).unwrap();
        let s = decrypt(&ct, &keys_id(&g)).unwrap();
        assert_eq!(s.expose(), &plain[..]);
        // Exactly the reserve: a reallocation would have grown it.
        assert_eq!(s.0.capacity(), ct.len());
    }

    /// Fixtures produced by the reference Go implementation (filippo.io/age
    /// v1.3.2) with `tests/fixtures/secrets/` as the only source of truth:
    /// `go-identity.age` is an identity file protected with a passphrase,
    /// `go-recipient*.age` are encrypted to that identity (the binary one also
    /// to a second, unrelated recipient), `go-passphrase.age` is a passphrase
    /// file, and `plain.bin` is the expected plaintext (all 256 byte values,
    /// CRLF, no trailing newline). No private key is committed in the clear.
    #[test]
    fn files_made_by_the_reference_implementation_open_here() {
        const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/secrets/");
        let read = |n: &str| std::fs::read(format!("{}{}", DIR, n)).unwrap();
        let plain = read("plain.bin");
        assert_eq!(plain.len(), 287);

        let mut keys = Keys::new();
        keys.add_protected_identity(
            &read("go-identity.age"),
            &Passphrase::for_decryption("interop identity passphrase".into()),
        )
        .unwrap();

        let bin = read("go-recipient.age");
        let h = inspect(&bin).unwrap();
        assert_eq!(
            (h.method, h.recipients, h.armored),
            (Method::Recipients, 2, false)
        );
        assert_eq!(decrypt(&bin, &keys).unwrap().expose(), &plain[..]);

        let arm = read("go-recipient.armor.age");
        let h = inspect(&arm).unwrap();
        assert_eq!(
            (h.method, h.recipients, h.armored),
            (Method::Recipients, 1, true)
        );
        assert_eq!(decrypt(&arm, &keys).unwrap().expose(), &plain[..]);

        let pw = read("go-passphrase.age");
        assert_eq!(inspect(&pw).unwrap().method, Method::Passphrase);
        assert_eq!(
            decrypt(&pw, &keys_pass("interop secret passphrase"))
                .unwrap()
                .expose(),
            &plain[..]
        );
        assert!(decrypt(&pw, &keys_pass("interop secret passphrasf")).is_err());
    }

    fn hostile(header_lines: &[u8], count: usize) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(AGE_V1_MAGIC);
        v.push(b'\n');
        for _ in 0..count {
            v.extend_from_slice(header_lines);
        }
        v.extend_from_slice(b"--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
        v.extend_from_slice(&[0u8; 64]);
        v
    }

    #[test]
    fn hostile_headers_are_rejected_fast_by_decrypt_and_inspect() {
        // The library's header parser is quadratic; these must never reach it.
        let started = std::time::Instant::now();
        let keys = keys_pass(PASS);
        let mut cases: Vec<Vec<u8>> = vec![
            hostile(b"-> a\n", 5_000),        // many plain stanzas
            hostile(b"-> a-grease\n", 5_000), // grease flood
            hostile(b"-> X25519 abc\nAAAA\n", 2_000),
            hostile(
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
                2_000,
            ), // body lines
        ];
        // An oversized single header line.
        let mut big = Vec::new();
        big.extend_from_slice(AGE_V1_MAGIC);
        big.extend_from_slice(b"\n-> X25519 ");
        big.extend_from_slice(&vec![b'A'; MAX_HEADER_BYTES + 10]);
        big.extend_from_slice(b"\n--- x\n");
        cases.push(big);
        for c in &cases {
            assert!(decrypt(c, &keys).is_err());
            assert!(inspect(c).is_err());
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        // The same applies to armored input.
        let mut armored = Vec::new();
        {
            let mut w = age::armor::ArmoredWriter::wrap_output(
                &mut armored,
                age::armor::Format::AsciiArmor,
            )
            .unwrap();
            w.write_all(&cases[0]).unwrap();
            w.finish().unwrap();
        }
        assert!(decrypt(&armored, &keys).is_err());
    }

    #[test]
    fn truncation_at_chunk_boundaries_is_detected() {
        let g = generate_identity();
        let keys = keys_id(&g);
        for plain_len in [65_536usize, 131_072, 200_000] {
            let ct = encrypt_to_recipients(&noise(plain_len), std::slice::from_ref(&g.recipient))
                .unwrap();
            let header_len = ct.windows(4).position(|w| w == b"\n---").unwrap();
            // Payload starts after the header line, MAC and 16-byte nonce.
            let payload_start = header_len
                + ct[header_len..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map(|_| 0)
                    .unwrap()
                + 1;
            let mac_end = payload_start
                + ct[payload_start..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .unwrap()
                + 1;
            let chunk = 64 * 1024 + 16;
            for k in 1..=2usize {
                let cut = mac_end + 16 + k * chunk;
                if cut < ct.len() {
                    assert_eq!(
                        decrypt(&ct[..cut], &keys).unwrap_err(),
                        SecretError::Corrupt,
                        "cut {}",
                        cut
                    );
                }
            }
            let mut ext = ct.clone();
            ext.extend_from_slice(&[0u8; 16]);
            assert_eq!(decrypt(&ext, &keys).unwrap_err(), SecretError::Corrupt);
        }
    }

    #[test]
    fn tamper_error_classes_are_accurate() {
        let g = generate_identity();
        let keys = keys_id(&g);
        let ct =
            encrypt_to_recipients(&noise(100_000), std::slice::from_ref(&g.recipient)).unwrap();
        // Payload damage is corruption.
        let mut bad = ct.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(decrypt(&bad, &keys).unwrap_err(), SecretError::Corrupt);
        let mut bad = ct.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        assert_eq!(decrypt(&bad, &keys).unwrap_err(), SecretError::Corrupt);
        // A damaged passphrase-file header is a failure, never a success.
        let pct = pass_ct(b"x");
        let mut bad = pct.clone();
        bad[40] ^= 1;
        assert!(decrypt(&bad, &keys_pass(PASS)).is_err());
    }

    #[test]
    fn armored_size_boundary_for_many_recipients() {
        // A cap-size plaintext with many recipients (a larger header) and
        // armor line breaks must still pass the size pre-check.
        let cap = 100_000usize;
        let ids: Vec<GeneratedIdentity> = (0..50).map(|_| generate_identity()).collect();
        let rs: Vec<Recipient> = ids
            .iter()
            .map(|g| Recipient(x25519::Recipient::from_str(&g.recipient.to_text()).unwrap()))
            .collect();
        let ct = encrypt_recipients_inner(&noise(cap), &rs, cap).unwrap();
        for crlf in [false, true] {
            let mut armored = Vec::new();
            {
                let mut w = age::armor::ArmoredWriter::wrap_output(
                    &mut armored,
                    age::armor::Format::AsciiArmor,
                )
                .unwrap();
                w.write_all(&ct).unwrap();
                w.finish().unwrap();
            }
            if crlf {
                armored = String::from_utf8(armored)
                    .unwrap()
                    .replace('\n', "\r\n")
                    .into_bytes();
            }
            // LF armor decrypts; CRLF armor is not valid strict armor and must
            // fail cleanly, not by tripping the size check.
            let r = decrypt_with_cap(&armored, &keys_id(&ids[7]), cap);
            if crlf {
                assert_ne!(r.err(), Some(SecretError::TooLarge));
            } else {
                assert_eq!(r.unwrap().len(), cap);
            }
        }
    }

    #[test]
    fn identity_file_errors_leave_keys_unchanged() {
        let g = generate_identity();
        let mut text = g.identity_file.expose().to_vec();
        text.extend_from_slice(b"AGE-SECRET-KEY-1NOTVALID\n");
        let mut k = Keys::new();
        assert_eq!(
            k.add_identity_file(&text).unwrap_err(),
            SecretError::InvalidIdentity
        );
        assert_eq!(
            k.identities.len(),
            0,
            "a failed parse must not leave identities behind"
        );
        // Too many identities is its own error and also leaves nothing.
        let many: String = (0..MAX_IDENTITIES + 1)
            .map(|_| {
                let g = generate_identity();
                String::from_utf8_lossy(g.identity_file.expose()).to_string()
            })
            .collect();
        assert_eq!(
            k.add_identity_file(many.as_bytes()).unwrap_err(),
            SecretError::TooManyIdentities
        );
        assert_eq!(k.identities.len(), 0);
    }

    #[test]
    fn process_hardening_disables_core_dumps() {
        assert!(harden_process());
        assert!(harden_process());
        #[cfg(unix)]
        unsafe {
            let mut r = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_CORE, &mut r), 0);
            assert_eq!((r.rlim_cur, r.rlim_max), (0, 0));
            #[cfg(target_os = "linux")]
            assert_eq!(libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0), 0);
        }
    }
}
