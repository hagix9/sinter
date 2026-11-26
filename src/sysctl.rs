//! `sysctl`: one kernel parameter, as the running value and as a persistent
//! setting in a file of its own (`/etc/sysctl.d/90-sinter-<name>.conf`).
//!
//! Everything here is pure: the grammar of names and values, the file
//! Sinter writes, the fixed argv of the two `sysctl` calls and the parser of
//! `sysctl -n`. The engine part (`sysctl_engine`) observes and changes.

use std::collections::BTreeMap;

use crate::error::{Result, SinterError};
use crate::model::FrozenResource;
use crate::value::Value;

/// `with` fields of a `sysctl`.
pub const FIELDS: &[&str] = &["name", "value", "state", "runtime", "persist"];

/// The one program this type runs.
pub const TOOL: &str = "/usr/sbin/sysctl";

/// Where the persistent setting lives.
pub const CONF_DIR: &str = "/etc/sysctl.d";

/// First line of every file Sinter writes there.
pub const HEADER: &str = "# Managed by Sinter (sysctl). Local changes are replaced.\n";

/// Longest accepted parameter name, in bytes.
pub const MAX_NAME: usize = 128;

/// Longest accepted value, in bytes (after normalization).
pub const MAX_VALUE: usize = 1024;

/// Seconds `sysctl -w` may take.
pub const TIMEOUT_SECS: u64 = 60;

/// Carried by a plan or apply result that changes the persistent file.
pub const BOOT_NOTE: &str = "the persistent setting is Sinter's own file; a file that sorts later in /etc/sysctl.d, or /etc/sysctl.conf, can still set another value at boot: Sinter does not evaluate that order, and the value after a reboot is not verified";

/// Carried by a result that changes the persistent file while the running
/// value is not managed.
pub const NOT_RUNNING_NOTE: &str = "the running value is not changed (runtime: false); the file takes effect at the next boot or when the administrator runs sysctl --system";

/// Carried by a result that removes the persistent file.
pub const ABSENT_NOTE: &str = "only Sinter's file is removed; the running value is not reset (there is no previous value to restore) and keeps its current value until a reboot or another change";

const NAME_RULE: &str = "[a-z0-9_]+(\\.[A-Za-z0-9_-]+)+, at most 128 bytes";

/// A kernel parameter name in the dotted form:
/// `[a-z0-9_]+(\.[A-Za-z0-9_-]+)+`, at most [`MAX_NAME`] bytes. No `/`, no
/// `*`, no leading `-`, no empty segment.
pub fn valid_name(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_NAME {
        return false;
    }
    let mut segments = s.split('.');
    let first = segments.next().unwrap_or("");
    if first.is_empty()
        || !first
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return false;
    }
    let mut more = 0;
    for seg in segments {
        if seg.is_empty()
            || !seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return false;
        }
        more += 1;
    }
    more >= 1
}

/// The file Sinter owns for one parameter.
pub fn conf_path(name: &str) -> String {
    format!("{}/90-sinter-{}.conf", CONF_DIR, name)
}

/// The form values are compared in: trimmed, and every run of spaces and
/// tabs collapsed to one space (the kernel prints the fields of a
/// multi-value parameter separated by tabs).
pub fn normalize_value(s: &str) -> String {
    s.split([' ', '\t'])
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Check a declared value and return it normalized. The error names no
/// value.
pub fn check_value(s: &str) -> std::result::Result<String, String> {
    if !s.bytes().all(|b| (0x20..=0x7e).contains(&b) || b == b'\t') {
        return Err(
            "value must be one line of printable ASCII (no control characters, no line break)"
                .to_string(),
        );
    }
    if s.contains("{{") {
        return Err("value must not contain {{".to_string());
    }
    let v = normalize_value(s);
    if v.is_empty() {
        return Err("value must not be empty".to_string());
    }
    if v.len() > MAX_VALUE {
        return Err(format!("value is longer than {} bytes", MAX_VALUE));
    }
    Ok(v)
}

/// A fully checked `sysctl` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysctlSpec {
    pub name: String,
    /// The declared value, normalized. Empty with `absent`.
    pub value: String,
    pub absent: bool,
    /// Manage the running value (never with `absent`).
    pub runtime: bool,
    /// Manage the persistent file (always with `absent`).
    pub persist: bool,
}

fn bad(ctx: &str, msg: &str) -> SinterError {
    SinterError::schema(format!("{}: sysctl {}", ctx, msg))
}

fn value_error(ctx: &str, why: &str, redact: bool) -> SinterError {
    if redact {
        bad(
            ctx,
            "value is not accepted (details withheld for a sensitive resource)",
        )
    } else {
        bad(ctx, why)
    }
}

fn literal_bool(with: &BTreeMap<String, Value>, key: &str, ctx: &str) -> Result<Option<bool>> {
    match with.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(bad(
            ctx,
            &format!("{} must be a literal boolean (true or false)", key),
        )),
    }
}

/// `state` as written: only the literal `present` (the default) or `absent`,
/// so what the resource does is visible in the recipe text.
fn literal_absent(with: &BTreeMap<String, Value>, ctx: &str) -> Result<bool> {
    match with.get("state") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Str(s)) if s == "present" => Ok(false),
        Some(Value::Str(s)) if s == "absent" => Ok(true),
        Some(_) => Err(bad(ctx, "state must be the literal present or absent")),
    }
}

impl SysctlSpec {
    /// The rules that do not depend on the evaluated `name` and `value`.
    /// Returns `(absent, runtime, persist)`.
    fn flags(with: &BTreeMap<String, Value>, ctx: &str) -> Result<(bool, bool, bool)> {
        let absent = literal_absent(with, ctx)?;
        let runtime = literal_bool(with, "runtime", ctx)?;
        let persist = literal_bool(with, "persist", ctx)?;
        let has_value = !matches!(with.get("value"), None | Some(Value::Null));
        if absent {
            for (key, given) in [
                ("value", has_value),
                ("runtime", runtime.is_some()),
                ("persist", persist.is_some()),
            ] {
                if given {
                    return Err(bad(
                        ctx,
                        &format!(
                            "{} is not accepted with state: absent (absent removes Sinter's file only and never changes the running value)",
                            key
                        ),
                    ));
                }
            }
            return Ok((true, false, true));
        }
        if !has_value {
            return Err(bad(ctx, "value is required"));
        }
        let (runtime, persist) = (runtime.unwrap_or(true), persist.unwrap_or(true));
        if !runtime && !persist {
            return Err(bad(
                ctx,
                "runtime and persist are both false: nothing would be managed",
            ));
        }
        Ok((false, runtime, persist))
    }

    /// Whether the declaration, as written, manages Sinter's file: always
    /// with `absent`, and with `present` unless `persist: false`.
    pub fn manages_file(with: &BTreeMap<String, Value>) -> bool {
        !matches!(with.get("persist"), Some(Value::Bool(false)))
    }

    /// The value of a `value` field that holds no interpolation.
    fn value_text(v: &Value, ctx: &str, redact: bool) -> Result<String> {
        match v {
            Value::Str(s) => check_value(s).map_err(|why| value_error(ctx, &why, redact)),
            Value::Int(i) => Ok(i.to_string()),
            _ => Err(bad(
                ctx,
                "value must be a string or an integer (write other values as a string)",
            )),
        }
    }

    /// Load-time check of the written `with` map (schema error, exit 2). A
    /// `name` or `value` that still holds an interpolation is judged once it
    /// is resolved.
    pub fn check_literals(with: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<()> {
        let (absent, _, _) = Self::flags(with, ctx)?;
        match with.get("name") {
            None | Some(Value::Null) => return Err(bad(ctx, "name is required")),
            Some(Value::Str(s)) if crate::expressions::has_interpolation(s) => {}
            Some(Value::Str(s)) => Self::check_name(s, ctx)?,
            Some(_) => return Err(bad(ctx, "name must be a string")),
        }
        if !absent {
            match with.get("value") {
                Some(Value::Str(s)) if crate::expressions::has_interpolation(s) => {}
                Some(v) => {
                    Self::value_text(v, ctx, redact)?;
                }
                None => {}
            }
        }
        Ok(())
    }

    /// The name rule, as a schema error.
    pub fn check_name(name: &str, ctx: &str) -> Result<()> {
        if valid_name(name) {
            return Ok(());
        }
        Err(bad(
            ctx,
            &format!(
                "name is not a kernel parameter name in dotted form ({}; no /, no *)",
                NAME_RULE
            ),
        ))
    }

    /// The spec of an evaluated resource.
    pub fn from_values(vals: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<Self> {
        let (absent, runtime, persist) = Self::flags(vals, ctx)?;
        let name = match vals.get("name") {
            Some(Value::Str(s)) => {
                Self::check_name(s, ctx)?;
                s.clone()
            }
            _ => return Err(bad(ctx, "name must be a string")),
        };
        let value = if absent {
            String::new()
        } else {
            match vals.get("value") {
                Some(v) => Self::value_text(v, ctx, redact)?,
                None => return Err(bad(ctx, "value is required")),
            }
        };
        Ok(SysctlSpec {
            name,
            value,
            absent,
            runtime,
            persist,
        })
    }

    /// The exact content of Sinter's file.
    pub fn render(&self) -> String {
        format!("{}{} = {}\n", HEADER, self.name, self.value)
    }

    /// The synthetic `file` resource for Sinter's file: the whole file,
    /// root:root 0644, or its absence.
    pub fn file_part(&self, res: &FrozenResource) -> FrozenResource {
        let mut f = res.clone();
        f.type_ = "file".to_string();
        f.notify = Vec::new();
        f.depends_on = Vec::new();
        f.when = None;
        f.register = None;
        let path = conf_path(&self.name);
        f.path = Some(path.clone());
        let mut with = BTreeMap::new();
        with.insert("path".to_string(), Value::Str(path));
        if self.absent {
            with.insert("state".to_string(), Value::Str("absent".to_string()));
        } else {
            with.insert("state".to_string(), Value::Str("present".to_string()));
            with.insert("content".to_string(), Value::Str(self.render()));
            with.insert("owner".to_string(), Value::Str("root".to_string()));
            with.insert("group".to_string(), Value::Str("root".to_string()));
            with.insert("mode".to_string(), Value::Str("0644".to_string()));
        }
        f.with = with;
        f
    }

    /// The fixed argv of the observation, after the program [`TOOL`].
    pub fn read_args(name: &str) -> Vec<String> {
        vec!["-n".to_string(), "--".to_string(), name.to_string()]
    }

    /// The fixed argv of the change, after the program [`TOOL`].
    pub fn write_args(&self) -> Vec<String> {
        vec![
            "-w".to_string(),
            "--".to_string(),
            format!("{}={}", self.name, self.value),
        ]
    }
}

/// Parse the standard output of `sysctl -n -- <name>`: exactly one line
/// ending in a newline, returned normalized (an empty line is an empty
/// value). No output at all, a missing final newline or a second line is
/// refused.
pub fn parse_value(stdout: &[u8]) -> std::result::Result<String, String> {
    let text = std::str::from_utf8(stdout).map_err(|_| "it is not valid UTF-8".to_string())?;
    let Some(line) = text.strip_suffix('\n') else {
        return Err(if text.is_empty() {
            "it is empty".to_string()
        } else {
            "it does not end with a line break".to_string()
        });
    };
    if line.contains('\n') {
        return Err("it has more than one line".to_string());
    }
    if line.chars().any(|c| c.is_control() && c != '\t') {
        return Err("it contains control characters".to_string());
    }
    Ok(normalize_value(line))
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

    #[test]
    fn names() {
        for ok in [
            "vm.swappiness",
            "net.ipv4.ip_forward",
            "net.ipv4.conf.eth0.rp_filter",
            "net.ipv6.conf.all.disable_ipv6",
            "net.ipv4.conf.br-lan.rp_filter",
            "kernel.core_pattern",
            "net.ipv4.conf.Eth0.rp_filter",
        ] {
            assert!(valid_name(ok), "{ok}");
        }
        let long = format!("a.{}", "b".repeat(127));
        for bad in [
            "",
            "vm",
            "vm.",
            ".vm",
            "vm..swappiness",
            "Vm.swappiness",
            "vm/swappiness",
            "net.ipv4.conf.*.rp_filter",
            "net.ipv4.conf.eth0/1.rp_filter",
            "-vm.swappiness",
            "vm.swappiness ",
            "vm.swap piness",
            "vm.swappiness=1",
            "vm.swappiness\n",
            long.as_str(),
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert!(valid_name(&format!("a.{}", "b".repeat(126))));
    }

    #[test]
    fn values_are_compared_normalized() {
        assert_eq!(
            normalize_value(" 4096\t87380   6291456 "),
            "4096 87380 6291456"
        );
        assert_eq!(
            check_value("4096 87380 6291456").unwrap(),
            parse_value(b"4096\t87380\t6291456\n").unwrap()
        );
        assert_eq!(parse_value(b"\n").unwrap(), "");
        assert_eq!(parse_value(b"60\n").unwrap(), "60");
        for bad in [
            &b""[..],
            b"60",
            b"60\n61\n",
            b"60\n\n",
            b"\xff\n",
            b"6\x1b0\n",
        ] {
            assert!(parse_value(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn declared_values() {
        for bad in ["", "  ", "a\nb", "a\rb", "a\u{7f}", "é", "{{ x }}", "a{{b"] {
            assert!(check_value(bad).is_err(), "{bad:?}");
        }
        assert!(check_value(&"1".repeat(MAX_VALUE)).is_ok());
        assert!(check_value(&"1".repeat(MAX_VALUE + 1)).is_err());
        assert_eq!(
            check_value("|/usr/lib/core %p %u").unwrap(),
            "|/usr/lib/core %p %u"
        );
    }

    #[test]
    fn spec_defaults_and_flags() {
        let sp = SysctlSpec::from_values(
            &with(&[("name", s("vm.swappiness")), ("value", Value::Int(10))]),
            "r",
            false,
        )
        .unwrap();
        assert_eq!(
            (sp.value.as_str(), sp.absent, sp.runtime, sp.persist),
            ("10", false, true, true)
        );
        assert_eq!(
            sp.render(),
            "# Managed by Sinter (sysctl). Local changes are replaced.\nvm.swappiness = 10\n"
        );
        assert_eq!(sp.write_args(), ["-w", "--", "vm.swappiness=10"]);
        assert_eq!(
            SysctlSpec::read_args("vm.swappiness"),
            ["-n", "--", "vm.swappiness"]
        );
        assert_eq!(
            conf_path("vm.swappiness"),
            "/etc/sysctl.d/90-sinter-vm.swappiness.conf"
        );

        let absent = SysctlSpec::from_values(
            &with(&[("name", s("vm.swappiness")), ("state", s("absent"))]),
            "r",
            false,
        )
        .unwrap();
        assert_eq!(
            (absent.absent, absent.runtime, absent.persist),
            (true, false, true)
        );

        let e = |pairs: &[(&str, Value)]| {
            SysctlSpec::check_literals(&with(pairs), "r", false)
                .unwrap_err()
                .message
        };
        assert!(e(&[("name", s("vm.swappiness"))]).contains("value is required"));
        assert!(e(&[("value", s("1"))]).contains("name is required"));
        assert!(e(&[
            ("name", s("vm.swappiness")),
            ("value", s("1")),
            ("state", s("absent"))
        ])
        .contains("value is not accepted with state: absent"));
        assert!(e(&[
            ("name", s("vm.swappiness")),
            ("runtime", Value::Bool(false)),
            ("state", s("absent"))
        ])
        .contains("runtime is not accepted with state: absent"));
        assert!(e(&[
            ("name", s("vm.swappiness")),
            ("value", s("1")),
            ("runtime", Value::Bool(false)),
            ("persist", Value::Bool(false))
        ])
        .contains("both false"));
        assert!(e(&[
            ("name", s("vm.swappiness")),
            ("value", s("1")),
            ("runtime", s("false"))
        ])
        .contains("literal boolean"));
        assert!(e(&[
            ("name", s("vm.swappiness")),
            ("value", s("1")),
            ("state", s("{{ st }}"))
        ])
        .contains("literal present or absent"));
        assert!(
            e(&[("name", s("vm.swappiness")), ("value", Value::Bool(true))])
                .contains("string or an integer")
        );
        assert!(e(&[("name", s("vm/swappiness")), ("value", s("1"))]).contains("dotted form"));
    }

    #[test]
    fn a_sensitive_value_error_names_nothing() {
        let e = SysctlSpec::check_literals(
            &with(&[("name", s("kernel.x")), ("value", s("synthetic\nvalue"))]),
            "r",
            true,
        )
        .unwrap_err()
        .message;
        assert!(e.contains("withheld") && !e.contains("synthetic"), "{e}");
    }
}
