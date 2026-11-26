//! `locale`: the system default locale of a host (`LANG` and `LC_*`), as
//! the OS keeps it in its locale file, changed with `localectl`.
//!
//! Everything here is pure: the grammar of locale names and keys, the
//! closed parser of the locale file, the parser of `locale -a` and the fixed
//! argv of the change. The engine part (`locale_engine`) observes and
//! changes.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Result, SinterError};
use crate::value::Value;

/// `with` fields of a `locale`.
pub const FIELDS: &[&str] = &["lang", "lc"];

/// The program that changes the default.
pub const TOOL: &str = "/usr/bin/localectl";

/// The program that lists the locales the host has (`locale -a`).
pub const LIST_TOOL: &str = "/usr/bin/locale";

/// Where the default lives on the Red Hat family (and other systemd hosts).
pub const RHEL_CONF: &str = "/etc/locale.conf";

/// Where the default lives on the Debian family.
pub const DEBIAN_CONF: &str = "/etc/default/locale";

/// Where compiled locales live (glibc); a planned change below it may
/// provide a locale.
pub const LOCALE_DIR: &str = "/usr/lib/locale";

/// The `LC_*` keys that may be declared under `lc`.
pub const LC_KEYS: &[&str] = &[
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
    "LC_PAPER",
    "LC_NAME",
    "LC_ADDRESS",
    "LC_TELEPHONE",
    "LC_MEASUREMENT",
    "LC_IDENTIFICATION",
];

/// Longest accepted locale name, in bytes.
pub const MAX_VALUE: usize = 64;

/// Longest accepted `locale -a` answer, in lines.
pub const MAX_LIST: usize = 20_000;

/// Seconds `localectl set-locale` may take.
pub const TIMEOUT_SECS: u64 = 60;

/// Carried by every plan and apply result that changes the default.
pub const SESSIONS_NOTE: &str = "the default applies to new logins and to services started afterwards; existing sessions and running services keep their locale, and Sinter restarts nothing";

/// The locale file of an OS family (`Facts::os_family`), or `None` when
/// Sinter does not know where that family keeps the default.
pub fn conf_path(os_family: &str) -> Option<&'static str> {
    match os_family {
        "redhat" => Some(RHEL_CONF),
        "debian" => Some(DEBIAN_CONF),
        _ => None,
    }
}

/// Every path the type owns, whatever the OS (§59).
pub fn owned_paths() -> Vec<String> {
    vec![RHEL_CONF.to_string(), DEBIAN_CONF.to_string()]
}

const VALUE_RULE: &str = "C, POSIX, or ll[_CC][.codeset][@modifier] such as en_US.UTF-8, C.UTF-8 or sr_RS@latin (letters, digits, _ . @ -; at most 64 bytes)";

/// Whether `s` is a locale name Sinter accepts: `C` or `POSIX` (optionally
/// with a codeset, `C.UTF-8`), or `ll[_CC][.codeset][@modifier]` with `ll`
/// 2 or 3 lower-case letters, `CC` 2 upper-case letters or 3 digits, the
/// codeset `[A-Za-z0-9-]+` and the modifier `[A-Za-z0-9]+`. At most
/// [`MAX_VALUE`] bytes; only `[A-Za-z0-9_.@-]`, so never a leading `-`.
pub fn valid_locale(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_VALUE {
        return false;
    }
    let (rest, modifier) = match s.split_once('@') {
        Some((r, m)) => (r, Some(m)),
        None => (s, None),
    };
    if let Some(m) = modifier {
        if m.is_empty() || !m.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return false;
        }
    }
    let (base, codeset) = match rest.split_once('.') {
        Some((b, c)) => (b, Some(c)),
        None => (rest, None),
    };
    if let Some(c) = codeset {
        if c.is_empty() || !c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return false;
        }
    }
    if base == "C" || base == "POSIX" {
        return modifier.is_none();
    }
    let (lang, territory) = match base.split_once('_') {
        Some((l, t)) => (l, Some(t)),
        None => (base, None),
    };
    let lang_ok = (2..=3).contains(&lang.len()) && lang.bytes().all(|b| b.is_ascii_lowercase());
    let territory_ok = territory.is_none_or(|t| {
        t.len() == 2 && t.bytes().all(|b| b.is_ascii_uppercase())
            || t.len() == 3 && t.bytes().all(|b| b.is_ascii_digit())
    });
    lang_ok && territory_ok
}

/// The form two locale names are compared in for availability: the codeset
/// in lower case with `-` removed (`en_US.UTF-8` and `en_US.utf8` are the
/// same locale). The rest is kept as it is.
pub fn availability_key(s: &str) -> String {
    let (rest, modifier) = match s.split_once('@') {
        Some((r, m)) => (r, Some(m)),
        None => (s, None),
    };
    let mut out = match rest.split_once('.') {
        Some((b, c)) => format!("{}.{}", b, c.to_ascii_lowercase().replace('-', "")),
        None => rest.to_string(),
    };
    if let Some(m) = modifier {
        out.push('@');
        out.push_str(m);
    }
    out
}

/// `C` and `POSIX` (with any codeset) need no check: glibc has them built
/// in.
pub fn always_available(s: &str) -> bool {
    let base = s.split(['.', '@']).next().unwrap_or("");
    base == "C" || base == "POSIX"
}

/// A fully checked `locale` declaration: key (`LANG`, `LC_*`) -> value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocaleSpec {
    pub settings: BTreeMap<String, String>,
}

fn bad(ctx: &str, msg: &str) -> SinterError {
    SinterError::schema(format!("{}: locale {}", ctx, msg))
}

fn value_error(ctx: &str, key: &str, redact: bool) -> SinterError {
    if redact {
        bad(
            ctx,
            &format!(
                "{} is not accepted (details withheld for a sensitive resource)",
                key
            ),
        )
    } else {
        bad(
            ctx,
            &format!("{} is not a locale name ({})", key, VALUE_RULE),
        )
    }
}

/// Check one `lc` key.
fn check_key(key: &str, ctx: &str) -> Result<()> {
    if key == "LC_ALL" {
        return Err(bad(
            ctx,
            "lc.LC_ALL is not accepted: LC_ALL overrides every other setting and is not meant as a system default; declare lang and the LC_* keys you need",
        ));
    }
    if key == "LANGUAGE" {
        return Err(bad(
            ctx,
            "lc.LANGUAGE is not accepted: it is a list of languages for messages, not a locale; Sinter does not manage it",
        ));
    }
    if key == "LANG" {
        return Err(bad(ctx, "lc.LANG is not accepted: declare it as lang"));
    }
    if !LC_KEYS.contains(&key) {
        return Err(bad(
            ctx,
            &format!(
                "lc key {:?} is not one of {}",
                key.chars().take(40).collect::<String>(),
                LC_KEYS.join(", ")
            ),
        ));
    }
    Ok(())
}

/// One declared value as written: a string, judged now unless it still
/// holds an interpolation.
fn check_written(v: &Value, key: &str, ctx: &str, redact: bool) -> Result<()> {
    match v {
        Value::Str(s) if crate::expressions::has_interpolation(s) => Ok(()),
        Value::Str(s) if valid_locale(s) => Ok(()),
        Value::Str(_) => Err(value_error(ctx, key, redact)),
        _ => Err(bad(ctx, &format!("{} must be a string", key))),
    }
}

impl LocaleSpec {
    /// Load-time check of the written `with` map (schema error, exit 2). A
    /// value that still holds an interpolation is judged once resolved.
    pub fn check_literals(with: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<()> {
        let mut any = false;
        match with.get("lang") {
            None | Some(Value::Null) => {}
            Some(v) => {
                check_written(v, "lang", ctx, redact)?;
                any = true;
            }
        }
        match with.get("lc") {
            None | Some(Value::Null) => {}
            Some(Value::Map(m)) => {
                for (k, v) in m {
                    check_key(k, ctx)?;
                    if matches!(v, Value::Str(s) if crate::expressions::has_interpolation(s)) {
                        return Err(bad(
                            ctx,
                            &format!(
                                "lc.{} must be a literal locale name (variables are accepted in lang only)",
                                k
                            ),
                        ));
                    }
                    check_written(v, &format!("lc.{}", k), ctx, redact)?;
                    any = true;
                }
            }
            Some(_) => return Err(bad(ctx, "lc must be a map of LC_* keys to locale names")),
        }
        if !any {
            return Err(bad(ctx, "declares nothing: set lang, lc, or both"));
        }
        Ok(())
    }

    /// The spec of an evaluated (or resolved) resource.
    pub fn from_values(vals: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<Self> {
        let mut settings = BTreeMap::new();
        let mut take = |key: &str, field: &str, v: &Value| -> Result<()> {
            match v {
                Value::Str(s) if valid_locale(s) => {
                    settings.insert(key.to_string(), s.clone());
                    Ok(())
                }
                Value::Str(_) => Err(value_error(ctx, field, redact)),
                _ => Err(bad(ctx, &format!("{} must be a string", field))),
            }
        };
        match vals.get("lang") {
            None | Some(Value::Null) => {}
            Some(v) => take("LANG", "lang", v)?,
        }
        match vals.get("lc") {
            None | Some(Value::Null) => {}
            Some(Value::Map(m)) => {
                for (k, v) in m {
                    check_key(k, ctx)?;
                    take(k, &format!("lc.{}", k), v)?;
                }
            }
            Some(_) => return Err(bad(ctx, "lc must be a map of LC_* keys to locale names")),
        }
        if settings.is_empty() {
            return Err(bad(ctx, "declares nothing: set lang, lc, or both"));
        }
        Ok(LocaleSpec { settings })
    }

    /// The declared keys whose value in `current` is not the declared one.
    pub fn differing(&self, current: &BTreeMap<String, String>) -> Vec<String> {
        self.settings
            .iter()
            .filter(|(k, v)| current.get(*k) != Some(*v))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// The fixed argv of the change, after the program [`TOOL`]: every
    /// declared key, each `KEY=value` one operand. Declared keys that
    /// already match are passed too, so a tool that replaces the whole set
    /// keeps them. No `--`: every operand starts with `L`.
    pub fn set_args(&self) -> Vec<String> {
        let mut v = vec!["set-locale".to_string()];
        v.extend(
            self.settings
                .iter()
                .map(|(k, val)| format!("{}={}", k, val)),
        );
        v
    }
}

/// A value as shown for one key: `(not set)` when absent.
pub fn shown_setting(map: &BTreeMap<String, String>, key: &str) -> String {
    map.get(key)
        .cloned()
        .unwrap_or_else(|| "(not set)".to_string())
}

fn valid_key(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

fn plain_value_char(c: char) -> bool {
    c.is_ascii_graphic() && !matches!(c, '"' | '\'' | '\\' | '$' | '`' | '#' | ';' | '&' | '|')
}

/// Parse a locale file (`/etc/locale.conf`, `/etc/default/locale`) with a
/// closed grammar: lines `KEY=value` or `KEY="value"` (`KEY` of upper-case
/// letters, digits and `_`; the value printable ASCII without quotes,
/// backslash, `$`, backtick, `#`, `;`, `&` or `|`, and without spaces when
/// unquoted), blank lines and lines whose first non-blank character is `#`.
/// A duplicate key, another quoting form, a carriage return or anything
/// else is refused; Sinter does not guess what a shell would make of it.
pub fn parse_conf(bytes: &[u8]) -> std::result::Result<BTreeMap<String, String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "it is not valid UTF-8".to_string())?;
    let mut out = BTreeMap::new();
    for (i, line) in text.split('\n').enumerate() {
        let n = i + 1;
        if line.contains('\r') {
            return Err(format!("line {} contains a carriage return", n));
        }
        let trimmed = line.trim_matches([' ', '\t']);
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            return Err(format!("line {} is not KEY=value", n));
        };
        if !valid_key(key) {
            return Err(format!(
                "line {} does not start with a key (A-Z, 0-9, _)",
                n
            ));
        }
        let value = if let Some(inner) = raw.strip_prefix('"') {
            let Some(inner) = inner.strip_suffix('"') else {
                return Err(format!(
                    "line {}: the quoted value is not closed at the end of the line",
                    n
                ));
            };
            if !inner.chars().all(|c| plain_value_char(c) || c == ' ') {
                return Err(format!(
                    "line {}: the quoted value contains a character Sinter does not interpret",
                    n
                ));
            }
            inner
        } else {
            if !raw.chars().all(plain_value_char) {
                return Err(format!("line {}: the value contains a space, a quote or a character Sinter does not interpret", n));
            }
            raw
        };
        if out.insert(key.to_string(), value.to_string()).is_some() {
            return Err(format!("key {} is set more than once (line {})", key, n));
        }
    }
    Ok(out)
}

/// Parse the standard output of `locale -a` into the set of availability
/// keys ([`availability_key`]). One name per line; an empty line, a control
/// character, invalid UTF-8 or more than [`MAX_LIST`] lines is refused.
pub fn parse_locale_list(stdout: &[u8]) -> std::result::Result<BTreeSet<String>, String> {
    let text = std::str::from_utf8(stdout).map_err(|_| "it is not valid UTF-8".to_string())?;
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.is_empty() {
        return Err("it is empty".to_string());
    }
    let mut out = BTreeSet::new();
    for (i, line) in body.split('\n').enumerate() {
        if i >= MAX_LIST {
            return Err(format!("it has more than {} lines", MAX_LIST));
        }
        if line.is_empty() || !line.chars().all(|c| c.is_ascii_graphic()) {
            return Err(format!("line {} is not one locale name", i + 1));
        }
        out.insert(availability_key(line));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn s(v: &str) -> Value {
        Value::Str(v.to_string())
    }

    fn map(pairs: &[(&str, &str)]) -> Value {
        Value::Map(pairs.iter().map(|(k, v)| (k.to_string(), s(v))).collect())
    }

    #[test]
    fn locale_names() {
        for ok in [
            "C",
            "POSIX",
            "C.UTF-8",
            "C.utf8",
            "en_US.UTF-8",
            "en_US.utf8",
            "en_US",
            "en_US.ISO-8859-15",
            "ja_JP.UTF-8",
            "sr_RS@latin",
            "ca_ES.UTF-8@valencia",
            "ber_DZ",
            "es_419.UTF-8",
            "de",
        ] {
            assert!(valid_locale(ok), "{ok}");
        }
        let long = format!("en_US.{}", "A".repeat(60));
        for bad in [
            "",
            "c",
            "C@x",
            "-en_US",
            "en_us",
            "EN_US",
            "e_US",
            "engl_US",
            "en_USA",
            "en_US.",
            "en_US.UTF_8",
            "en_US@",
            "en_US@a-b",
            "en_US.UTF-8 ",
            "en US",
            "en_US.UTF-8\n",
            "en_US:en",
            "en_US/x",
            "$(id)",
            long.as_str(),
        ] {
            assert!(!valid_locale(bad), "{bad:?}");
        }
    }

    #[test]
    fn availability_compares_the_codeset_loosely() {
        assert_eq!(availability_key("en_US.UTF-8"), "en_US.utf8");
        assert_eq!(availability_key("en_US.utf8"), "en_US.utf8");
        assert_eq!(
            availability_key("ca_ES.UTF-8@valencia"),
            "ca_ES.utf8@valencia"
        );
        assert_eq!(availability_key("en_US"), "en_US");
        assert_ne!(
            availability_key("en_GB.UTF-8"),
            availability_key("en_US.utf8")
        );
        for a in ["C", "POSIX", "C.UTF-8", "C.utf8", "POSIX.UTF-8"] {
            assert!(always_available(a), "{a}");
        }
        assert!(!always_available("en_US.UTF-8"));
        let list =
            parse_locale_list(b"C\nC.utf8\nPOSIX\nen_US\nen_US.iso885915\nen_US.utf8\n").unwrap();
        assert!(list.contains(&availability_key("en_US.UTF-8")));
        assert!(list.contains(&availability_key("en_US.ISO-8859-15")));
        assert!(!list.contains(&availability_key("ja_JP.UTF-8")));
        for bad in [
            &b""[..],
            b"\n",
            b"C\n\nen_US\n",
            b"C\x1b\n",
            b"\xff\n",
            b"a b\n",
        ] {
            assert!(parse_locale_list(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn conf_files() {
        let m = parse_conf(b"LANG=en_US.UTF-8\n").unwrap();
        assert_eq!(m.get("LANG").unwrap(), "en_US.UTF-8");
        let m = parse_conf(
            b"#  File generated by update-locale\n\nLANG=\"ja_JP.UTF-8\"\n  # note\nLC_TIME=en_GB.UTF-8\nLANGUAGE=\"en_US:en\"",
        )
        .unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m.get("LANGUAGE").unwrap(), "en_US:en");
        assert!(parse_conf(b"").unwrap().is_empty());
        for bad in [
            &b"LANG=en_US.UTF-8\nLANG=C\n"[..],
            b"LANG='en_US.UTF-8'\n",
            b"export LANG=C\n",
            b" LANG=C\n",
            b"LANG =C\n",
            b"LANG=\"C\n",
            b"LANG=\"C\" # x\n",
            b"LANG=C # x\n",
            b"LANG=$(id)\n",
            b"LANG=`id`\n",
            b"LANG=a\\b\n",
            b"LANG=C\r\n",
            b"lang=C\n",
            b"LANG\n",
            b"\xff=C\n",
            b"LANG=C;id\n",
        ] {
            assert!(
                parse_conf(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(conf_path("redhat"), Some("/etc/locale.conf"));
        assert_eq!(conf_path("debian"), Some("/etc/default/locale"));
        assert_eq!(conf_path(""), None);
        assert_eq!(conf_path("suse"), None);
    }

    #[test]
    fn spec_and_argv() {
        let sp = LocaleSpec::from_values(
            &with(&[
                ("lang", s("en_US.UTF-8")),
                ("lc", map(&[("LC_TIME", "en_GB.UTF-8")])),
            ]),
            "r",
            false,
        )
        .unwrap();
        assert_eq!(
            sp.set_args(),
            ["set-locale", "LANG=en_US.UTF-8", "LC_TIME=en_GB.UTF-8"]
        );
        let mut cur = BTreeMap::new();
        cur.insert("LANG".to_string(), "en_US.UTF-8".to_string());
        assert_eq!(sp.differing(&cur), ["LC_TIME"]);
        cur.insert("LC_TIME".to_string(), "en_GB.UTF-8".to_string());
        assert!(sp.differing(&cur).is_empty());

        let e = |pairs: &[(&str, Value)]| {
            LocaleSpec::check_literals(&with(pairs), "r", false)
                .unwrap_err()
                .message
        };
        assert!(e(&[]).contains("declares nothing"));
        assert!(e(&[("lc", Value::Map(BTreeMap::new()))]).contains("declares nothing"));
        assert!(e(&[("lc", map(&[("LC_ALL", "C")]))]).contains("LC_ALL is not accepted"));
        assert!(e(&[("lc", map(&[("LANGUAGE", "en")]))]).contains("LANGUAGE is not accepted"));
        assert!(e(&[("lc", map(&[("LANG", "C")]))]).contains("declare it as lang"));
        assert!(e(&[("lc", map(&[("LC_FOO", "C")]))]).contains("is not one of"));
        assert!(e(&[("lc", s("C"))]).contains("must be a map"));
        assert!(e(&[("lang", Value::Int(1))]).contains("must be a string"));
        assert!(e(&[("lang", s("en_US.UTF-8 x"))]).contains("not a locale name"));
        assert!(e(&[("lc", map(&[("LC_TIME", "bad value")]))]).contains("lc.LC_TIME"));
        // An interpolation is judged once resolved (lang only).
        assert!(
            LocaleSpec::check_literals(&with(&[("lang", s("{{ vars.l }}"))]), "r", false).is_ok()
        );
        assert!(e(&[("lc", map(&[("LC_TIME", "{{ vars.l }}")]))]).contains("literal locale name"));
    }

    #[test]
    fn a_sensitive_value_error_names_nothing() {
        let e = LocaleSpec::check_literals(&with(&[("lang", s("synthetic value"))]), "r", true)
            .unwrap_err()
            .message;
        assert!(e.contains("withheld") && !e.contains("synthetic"), "{e}");
    }
}
