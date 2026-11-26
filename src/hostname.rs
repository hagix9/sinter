//! `hostname`: the static host name of a host, through `hostnamectl`.
//!
//! Everything here is pure: the name grammar, the fixed argv of the three
//! `hostnamectl` calls and the parser of their one-line answers. The engine
//! part (`hostname_engine`) observes and changes.

use std::collections::BTreeMap;

use crate::error::{Result, SinterError};
use crate::value::Value;

/// `with` fields of a `hostname`.
pub const FIELDS: &[&str] = &["name"];

/// The one program this type runs.
pub const TOOL: &str = "/usr/bin/hostnamectl";

/// Longest accepted name, in bytes (Linux `HOST_NAME_MAX`).
pub const MAX_NAME: usize = 64;

/// Seconds `hostnamectl set-hostname` may take.
pub const TIMEOUT_SECS: u64 = 60;

/// Carried by every plan and apply result that changes the name.
pub const PROGRAMS_NOTE: &str = "programs that read the host name when they start keep the previous name until they are restarted, and Sinter restarts nothing; /etc/hosts is not changed; facts.hostname of this run stays the name observed at connect";

/// Check a declared name: RFC 1123 labels
/// `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?` separated by `.`, 1 to
/// [`MAX_NAME`] bytes in total, lower case only. The error names no value.
pub fn check_name(s: &str) -> std::result::Result<(), String> {
    if s.is_empty() {
        return Err("name must not be empty".to_string());
    }
    if s.len() > MAX_NAME {
        return Err(format!(
            "name is longer than {} bytes (the limit of a Linux host name)",
            MAX_NAME
        ));
    }
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(
            "name contains upper-case letters; write the host name in lower case".to_string(),
        );
    }
    for label in s.split('.') {
        let b = label.as_bytes();
        let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        let ok = !b.is_empty()
            && b.len() <= 63
            && edge(b[0])
            && edge(b[b.len() - 1])
            && b.iter().all(|c| edge(*c) || *c == b'-');
        if !ok {
            return Err(
                "name is not a host name: labels of a-z, 0-9 and - (1 to 63 bytes, not starting or ending with -) separated by single dots"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn bad(ctx: &str, why: &str, redact: bool) -> SinterError {
    SinterError::schema(if redact {
        format!(
            "{}: hostname name is not accepted (details withheld for a sensitive resource)",
            ctx
        )
    } else {
        format!("{}: hostname {}", ctx, why)
    })
}

/// Load-time check of the written `with` map (schema error, exit 2). A
/// `name` that still holds an interpolation is judged when the recipe is
/// frozen.
pub fn check_literals(with: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<()> {
    match with.get("name") {
        None | Some(Value::Null) => Err(SinterError::schema(format!(
            "{}: hostname name is required",
            ctx
        ))),
        Some(Value::Str(s)) if crate::expressions::has_interpolation(s) => Ok(()),
        Some(Value::Str(s)) => check_name(s).map_err(|why| bad(ctx, &why, redact)),
        Some(_) => Err(SinterError::schema(format!(
            "{}: hostname name must be a string",
            ctx
        ))),
    }
}

/// The declared name of an evaluated (or resolved) resource.
pub fn name_from_values(vals: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<String> {
    match vals.get("name") {
        Some(Value::Str(s)) => {
            check_name(s).map_err(|why| bad(ctx, &why, redact))?;
            Ok(s.clone())
        }
        _ => Err(SinterError::schema(format!(
            "{}: hostname name must be a string",
            ctx
        ))),
    }
}

/// Which name `hostnamectl` is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    /// The configured name (`/etc/hostname`), the one Sinter manages.
    Static,
    /// The name the kernel uses now; reported, not managed.
    Transient,
}

impl Which {
    /// The option of the observation.
    pub fn flag(self) -> &'static str {
        match self {
            Which::Static => "--static",
            Which::Transient => "--transient",
        }
    }
}

/// The fixed argv of the change, after the program [`TOOL`]. No `--`: the
/// name grammar excludes a leading `-`.
pub fn set_args(name: &str) -> Vec<String> {
    vec!["set-hostname".to_string(), name.to_string()]
}

/// Parse the standard output of `hostnamectl --static` / `--transient`: at
/// most one line. No output, or one empty line, is "not set" (the empty
/// string). A second line, a control character or more than 255 bytes is
/// refused.
pub fn parse_name(stdout: &[u8]) -> std::result::Result<String, String> {
    let text = std::str::from_utf8(stdout).map_err(|_| "it is not valid UTF-8".to_string())?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.contains('\n') {
        return Err("it has more than one line".to_string());
    }
    if line.chars().any(|c| c.is_control()) {
        return Err("it contains control characters".to_string());
    }
    if line.len() > 255 {
        return Err("it is longer than 255 bytes".to_string());
    }
    Ok(line.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let label63 = "a".repeat(63);
        let max = format!("{}.{}", "a".repeat(32), "b".repeat(31));
        assert_eq!(max.len(), 64);
        for ok in [
            "web01",
            "a",
            "0",
            "web-01.example.invalid",
            "db.internal",
            "3com",
            label63.as_str(),
            max.as_str(),
        ] {
            assert!(check_name(ok).is_ok(), "{ok}");
        }
        let long_label = format!("{}.b", "a".repeat(64));
        let too_long = format!("{}.{}", "a".repeat(32), "b".repeat(32));
        for bad in [
            "",
            "-web",
            "web-",
            "web..example",
            ".web",
            "web.",
            "web_01",
            "web 01",
            "web01\n",
            "--static",
            "wéb",
            "web/01",
            long_label.as_str(),
            too_long.as_str(),
        ] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        let e = check_name("Web01").unwrap_err();
        assert!(e.contains("lower case"), "{e}");
    }

    #[test]
    fn answers() {
        assert_eq!(parse_name(b"web01\n").unwrap(), "web01");
        assert_eq!(parse_name(b"web01").unwrap(), "web01");
        assert_eq!(parse_name(b"\n").unwrap(), "");
        assert_eq!(parse_name(b"").unwrap(), "");
        for bad in [&b"a\nb\n"[..], b"a\n\n", b"\xff\n", b"a\x1bb\n"] {
            assert!(parse_name(bad).is_err(), "{bad:?}");
        }
        assert!(parse_name("a".repeat(256).as_bytes()).is_err());
        assert_eq!(set_args("web01"), ["set-hostname", "web01"]);
        assert_eq!(Which::Static.flag(), "--static");
        assert_eq!(Which::Transient.flag(), "--transient");
    }

    #[test]
    fn a_sensitive_name_error_names_nothing() {
        let mut with = BTreeMap::new();
        with.insert("name".to_string(), Value::Str("Synthetic_Name".to_string()));
        let e = check_literals(&with, "r", true).unwrap_err().message;
        assert!(e.contains("withheld") && !e.contains("Synthetic"), "{e}");
        let e = check_literals(&with, "r", false).unwrap_err().message;
        assert!(e.contains("lower case"), "{e}");
    }
}
