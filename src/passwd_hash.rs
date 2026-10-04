//! Password hashes for `user.password_hash`.
//!
//! A hash is **secret material** (offline-crackable); it is never printed or
//! logged. This module only decides what a hash looks like and how a stored
//! shadow field relates to a desired hash. Sinter does not generate or verify
//! passwords and never sees a plaintext password: the operator produces a hash
//! with their own tooling (`mkpasswd`, `openssl passwd -6`, ...) and keeps it
//! as an encrypted secret.
//!
//! The accepted formats are a subset of what shadow 4.19's `chkhash.c`
//! accepts, so a later shadow-utils will not reject what Sinter accepted:
//!
//! * `$y$<params>$<salt>$<43 chars>` (yescrypt),
//! * `$6$[rounds=N$]<1-16 chars>$<86 chars>` (sha512crypt, N in 1000..=999999999),
//!
//! with every field drawn from `[./0-9A-Za-z]`. DES, bigcrypt, `$1$`, `$5$`,
//! bcrypt and the like are refused, and so is anything that could be a
//! plaintext password.

use zeroize::Zeroizing;

/// Longest accepted secret file content.
const MAX_HASH_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Yescrypt,
    Sha512,
}

/// Why a secret is not an acceptable hash. The text is fixed and never
/// contains the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rejected;

impl Rejected {
    pub(crate) const TEXT: &'static str =
        "the secret is not an accepted password hash (one $y$ yescrypt or $6$ sha512crypt hash, \
         optionally followed by a single newline)";
}

fn b64(c: u8) -> bool {
    c == b'.' || c == b'/' || c.is_ascii_alphanumeric()
}

fn all_b64(s: &str) -> bool {
    s.bytes().all(b64)
}

/// `$6$[rounds=N$]salt$hash`, after the `$6$` prefix.
fn sha512_ok(rest: &str) -> bool {
    let mut parts: Vec<&str> = rest.split('$').collect();
    if parts.len() == 3 {
        // `rounds=N`, `salt`, `hash`
        let rounds = parts.remove(0);
        let Some(n) = rounds.strip_prefix("rounds=") else {
            return false;
        };
        if n.is_empty()
            || n.starts_with('0')
            || !n.bytes().all(|b| b.is_ascii_digit())
            || n.len() > 9
        {
            return false;
        }
        match n.parse::<u32>() {
            Ok(v) if (1000..=999_999_999).contains(&v) => {}
            _ => return false,
        }
    }
    parts.len() == 2
        && (1..=16).contains(&parts[0].len())
        && all_b64(parts[0])
        && parts[1].len() == 86
        && all_b64(parts[1])
}

/// `$y$params$salt$hash`, after the `$y$` prefix.
fn yescrypt_ok(rest: &str) -> bool {
    let parts: Vec<&str> = rest.split('$').collect();
    parts.len() == 3
        && !parts[0].is_empty()
        && parts[0].len() <= 16
        && all_b64(parts[0])
        && (1..=86).contains(&parts[1].len())
        && all_b64(parts[1])
        && parts[2].len() == 43
        && all_b64(parts[2])
}

/// The format of an exact hash text, or `None`.
fn format_of(hash: &str) -> Option<Format> {
    if hash.len() > MAX_HASH_BYTES {
        return None;
    }
    if let Some(rest) = hash.strip_prefix("$6$") {
        return sha512_ok(rest).then_some(Format::Sha512);
    }
    if let Some(rest) = hash.strip_prefix("$y$") {
        return yescrypt_ok(rest).then_some(Format::Yescrypt);
    }
    None
}

/// Read a hash from decrypted secret bytes: UTF-8, at most one trailing
/// newline removed, the rest exactly one allowed hash with no whitespace.
pub(crate) fn parse_secret(bytes: &[u8]) -> Result<(Format, Zeroizing<String>), Rejected> {
    if bytes.len() > MAX_HASH_BYTES + 1 {
        return Err(Rejected);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Rejected)?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let kind = format_of(text).ok_or(Rejected)?;
    Ok((kind, Zeroizing::new(text.to_string())))
}

/// What a stored shadow password field holds.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stored<'a> {
    /// No usable password: empty, `!`, `!!`, `*`, `!*`, ...
    NoPassword,
    /// A password hash, possibly locked by a leading `!` (`usermod -L`).
    Hash { locked: bool, value: &'a str },
}

pub(crate) fn classify(field: &str) -> Stored<'_> {
    let rest = field.trim_start_matches('!');
    if rest.is_empty() || rest.starts_with('*') {
        Stored::NoPassword
    } else {
        Stored::Hash {
            locked: field.starts_with('!'),
            value: rest,
        }
    }
}

/// How the stored field relates to the desired hash.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Relation {
    /// Same hash (a lock marker is ignored: a locked account stays locked).
    Same,
    /// Different, and setting the desired hash is a normal change.
    Differs,
    /// Different, but the account is locked with a real hash: `chpasswd -e`
    /// would replace the field and silently unlock it.
    DiffersLocked,
}

pub(crate) fn relate(field: &str, desired: &str) -> Relation {
    match classify(field) {
        Stored::Hash { value, .. } if value == desired => Relation::Same,
        Stored::Hash { locked: true, .. } => Relation::DiffersLocked,
        _ => Relation::Differs,
    }
}

/// The exact `chpasswd -e` input: `name:hash\n`. The name is a validated
/// account name and the hash contains no `:`, so one line is one record.
pub(crate) fn chpasswd_input(name: &str, hash: &str) -> Zeroizing<Vec<u8>> {
    debug_assert!(
        !name.contains([':', '\n', '\r', '\0']) && !hash.contains([':', '\n', '\r', '\0']),
        "chpasswd input must be one record"
    );
    let mut v = Zeroizing::new(Vec::with_capacity(name.len() + hash.len() + 2));
    v.extend_from_slice(name.as_bytes());
    v.push(b':');
    v.extend_from_slice(hash.as_bytes());
    v.push(b'\n');
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(n: usize) -> String {
        "A1./".chars().cycle().take(n).collect()
    }

    fn sha(salt: &str) -> String {
        format!("$6${}${}", salt, b(86))
    }

    fn yes() -> String {
        format!("$y$j9T${}${}", b(22), b(43))
    }

    #[test]
    fn accepts_the_two_formats_and_one_trailing_newline() {
        assert_eq!(
            parse_secret(sha("saltsalt").as_bytes()).unwrap().0,
            Format::Sha512
        );
        assert_eq!(parse_secret(yes().as_bytes()).unwrap().0, Format::Yescrypt);
        let with_nl = format!("{}\n", sha("s"));
        assert_eq!(&**parse_secret(with_nl.as_bytes()).unwrap().1, &sha("s"));
        let rounds = format!("$6$rounds=5000${}${}", b(8), b(86));
        assert!(parse_secret(rounds.as_bytes()).is_ok());
    }

    #[test]
    fn refuses_everything_else_without_echoing_it() {
        let long_salt = sha(&b(17));
        let bad_rounds = [
            format!("$6$rounds=999${}${}", b(8), b(86)),
            format!("$6$rounds=0500000${}${}", b(8), b(86)),
            format!("$6$rounds=1000000000${}${}", b(8), b(86)),
            format!("$6$rounds=${}${}", b(8), b(86)),
        ];
        let mut cases: Vec<String> = vec![
            String::new(),
            "\n".into(),
            "hunter2".into(),
            "hunter2hunt2".into(), // looks like DES
            format!("{}\n\n", sha("s")),
            format!(" {}", sha("s")),
            format!("{} ", sha("s")),
            format!("{}\r\n", sha("s")),
            format!("!{}", sha("s")),
            format!("*{}", sha("s")),
            format!("{}:x", sha("s")),
            long_salt,
            sha(""),
            format!("$6$s${}", b(85)),
            format!("$6$s${}", b(87)),
            format!("$5$s${}", b(43)),
            format!("$1$salt${}", b(22)),
            format!("$2b$12${}", b(53)),
            format!("$y$j9T${}${}", b(22), b(42)),
            format!("$y$${}${}", b(22), b(43)),
            format!("$y$j9T$${}", b(43)),
            "$y$".into(),
            "$6$".into(),
            format!("{}é", sha("s")),
        ];
        cases.extend(bad_rounds);
        for c in cases {
            assert!(parse_secret(c.as_bytes()).is_err(), "accepted {:?}", c);
        }
        assert!(parse_secret(&[0xff, 0xfe]).is_err());
        assert!(parse_secret(&vec![b'a'; 300]).is_err());
        assert_eq!(
            format!("{:?}", Rejected),
            "Rejected",
            "the rejection carries no value"
        );
    }

    #[test]
    fn stored_fields_are_classified_and_compared() {
        let h = sha("salt");
        assert_eq!(relate(&h, &h), Relation::Same);
        assert_eq!(
            relate(&format!("!{}", h), &h),
            Relation::Same,
            "lock ignored"
        );
        assert_eq!(relate(&format!("!!{}", h), &h), Relation::Same);
        for none in ["", "!", "!!", "*", "!*", "*LK*"] {
            assert_eq!(classify(none), Stored::NoPassword, "{:?}", none);
            assert_eq!(relate(none, &h), Relation::Differs, "{:?}", none);
        }
        assert_eq!(relate(&sha("other"), &h), Relation::Differs);
        assert_eq!(
            relate(&format!("!{}", sha("other")), &h),
            Relation::DiffersLocked
        );
    }

    #[test]
    fn chpasswd_input_is_one_record() {
        let v = chpasswd_input("app", "$6$x$y");
        assert_eq!(&v[..], b"app:$6$x$y\n");
    }
}
