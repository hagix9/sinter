//! `sysctl`: one kernel parameter, as the running value and as a persistent
//! setting in a file of its own (`/etc/sysctl.d/90-sinter-<name>.conf`).
//!
//! Everything here is pure: the grammar of names and values, the file
//! Sinter writes, the fixed argv of the two `sysctl` calls, the parser of
//! `sysctl -n` and the parser of `systemd-analyze cat-config sysctl.d` (the
//! boot-time files in the order systemd-sysctl applies them) with the view
//! of one key in that order. The engine part (`sysctl_engine`) observes and
//! changes.

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

/// Carried by a plan or apply result that changes the persistent file when
/// the boot-time configuration could not be examined.
pub const BOOT_NOTE: &str = "the persistent setting is Sinter's own file; a file that sorts later in /etc/sysctl.d, or /etc/sysctl.conf, can still set another value at boot: Sinter does not evaluate that order, and the value after a reboot is not verified";

/// The program that lists the boot-time configuration (read-only).
pub const ANALYZE: &str = "/usr/bin/systemd-analyze";

/// Its fixed argv: every file of the sysctl.d directories, in the order
/// systemd-sysctl applies them, each after a `# <path>` line.
pub const CAT_CONFIG_ARGS: [&str; 2] = ["cat-config", "sysctl.d"];

/// The directories a header of that output may name.
pub const BOOT_DIRS: [&str; 4] = [
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
];

/// TuneD's state file: a selected profile can set kernel parameters too.
pub const TUNED_STATE: &str = "/etc/tuned/active_profile";

/// Carried by plan, apply and audit when a TuneD profile is selected.
pub const TUNED_NOTE: &str = "a TuneD profile is selected on this host; TuneD may set kernel parameters after boot-time sysctl files (its reapply_sysctl option decides); Sinter does not evaluate profile contents";

/// One setting of a boot-time file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootSetting {
    /// `key = value` for one key (dotted form), value normalized.
    Plain { key: String, value: String },
    /// A key with a glob character (`*`, `?`, `[`), value normalized.
    Pattern { pattern: String, value: String },
}

/// One file of the boot-time configuration as `cat-config` printed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootFile {
    pub path: String,
    /// The settings in file order.
    pub settings: Vec<BootSetting>,
    /// Lines that are neither blank, a comment nor a setting.
    pub unclassified: Vec<String>,
}

/// The whole boot-time configuration, in the order it is applied.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BootConfig {
    pub files: Vec<BootFile>,
}

/// The path of a `cat-config` header line, or `None`: exactly `# ` and an
/// absolute path ending in `.conf` directly inside one of [`BOOT_DIRS`],
/// with nothing else on the line. A comment that merely starts with `# /`
/// (`# /usr/lib/sysctl.d/, /run/sysctl.d/, and /etc/sysctl.d/.`) is not a
/// header.
pub fn header_path(line: &str) -> Option<&str> {
    let path = line.strip_prefix("# ")?;
    if !path.starts_with('/')
        || !path.ends_with(".conf")
        || path
            .chars()
            .any(|c| c == ' ' || c == ',' || c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let (dir, base) = path.rsplit_once('/')?;
    if base.len() <= ".conf".len() || !BOOT_DIRS.contains(&dir) {
        return None;
    }
    Some(path)
}

/// The dotted form of a key: when the first separator is `/`, every `/`
/// and `.` are swapped (the rule of sysctl.d(5)), so `net/ipv4/ip_forward`
/// is `net.ipv4.ip_forward`.
pub fn dotted_key(key: &str) -> String {
    match key.find(['/', '.']) {
        Some(i) if key.as_bytes()[i] == b'/' => key
            .chars()
            .map(|c| match c {
                '/' => '.',
                '.' => '/',
                other => other,
            })
            .collect(),
        _ => key.to_string(),
    }
}

/// One line of a boot-time file: `Ok(None)` for a blank line or a comment,
/// `Ok(Some(..))` for a setting, `Err(())` for anything else.
fn parse_setting(line: &str) -> std::result::Result<Option<BootSetting>, ()> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') || t.starts_with(';') {
        return Ok(None);
    }
    let (k, v) = t.split_once('=').ok_or(())?;
    let k = k.trim();
    let k = k.strip_prefix('-').unwrap_or(k);
    if k.is_empty()
        || k.starts_with('-')
        || k.starts_with('!')
        || k.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(());
    }
    let key = dotted_key(k);
    let value = normalize_value(v);
    Ok(Some(if key.contains(['*', '?', '[']) {
        BootSetting::Pattern {
            pattern: key,
            value,
        }
    } else {
        BootSetting::Plain { key, value }
    }))
}

/// Whether `line` has the shape of a `cat-config` header for one of
/// [`BOOT_DIRS`] — `# ` and a path with no blank, comma or control character
/// directly inside one of them — whatever its file name. A line of that
/// shape that [`header_path`] does not accept (a name not ending in `.conf`)
/// cannot be told apart from a header of a file systemd-sysctl does not read,
/// or from a comment, so the whole output is refused.
fn header_shaped(line: &str) -> bool {
    let Some(path) = line.strip_prefix("# ") else {
        return false;
    };
    if path
        .chars()
        .any(|c| c == ',' || c.is_whitespace() || c.is_control())
    {
        return false;
    }
    match path.rsplit_once('/') {
        Some((dir, base)) => !base.is_empty() && BOOT_DIRS.contains(&dir),
        None => false,
    }
}

/// Parse the standard output of `systemd-analyze cat-config sysctl.d`.
/// Before the first header only blank lines are accepted; output that is
/// not UTF-8, or text before the first header, is refused.
///
/// A comment inside a file can look exactly like a header. systemd-sysctl
/// applies the files sorted by file name across the directories, each name
/// once (a file of the same name in a later directory is masked), so the
/// headers it prints are strictly increasing by file name. Output whose
/// headers are not (a header naming a file again, or out of that order), or
/// with a header-shaped line whose name does not end in `.conf`, is refused:
/// the caller then reports the boot-time configuration as not examined. A
/// header-shaped comment that happens to keep the order is still taken as a
/// header (it cannot be told apart without reading each file).
pub fn parse_cat_config(stdout: &[u8]) -> std::result::Result<BootConfig, String> {
    let text = std::str::from_utf8(stdout).map_err(|_| "it is not valid UTF-8".to_string())?;
    let mut cfg = BootConfig::default();
    for line in text.lines() {
        if let Some(path) = header_path(line) {
            if let Some(prev) = cfg.files.last() {
                if base_name(path) <= base_name(&prev.path) {
                    return Err(if cfg.files.iter().any(|f| f.path == path) {
                        format!("the file header {} appears more than once", path)
                    } else {
                        format!(
                            "the file header {} is not in the order systemd-sysctl applies \
                             the files (by file name, after {})",
                            path, prev.path
                        )
                    });
                }
            }
            cfg.files.push(BootFile {
                path: path.to_string(),
                settings: Vec::new(),
                unclassified: Vec::new(),
            });
            continue;
        }
        if header_shaped(line) {
            return Err(
                "a line has the form of a file header of a sysctl.d directory but names a file \
                 whose name does not end in .conf"
                    .to_string(),
            );
        }
        let Some(file) = cfg.files.last_mut() else {
            if line.trim().is_empty() {
                continue;
            }
            return Err("it does not start with a file header".to_string());
        };
        match parse_setting(line) {
            Ok(Some(s)) => file.settings.push(s),
            Ok(None) => {}
            Err(()) => file.unclassified.push(line.to_string()),
        }
    }
    Ok(cfg)
}

/// Whether a glob pattern of sysctl.d can match `key`: `*` any run, `?`
/// one character; a pattern with `[` is taken as matching (not evaluated).
pub fn pattern_may_match(pattern: &str, key: &str) -> bool {
    if pattern.contains('[') {
        return true;
    }
    fn go(p: &[u8], k: &[u8]) -> bool {
        match p.split_first() {
            None => k.is_empty(),
            Some((b'*', rest)) => (0..=k.len()).any(|i| go(rest, &k[i..])),
            Some((b'?', rest)) => !k.is_empty() && go(rest, &k[1..]),
            Some((c, rest)) => k.first() == Some(c) && go(rest, &k[1..]),
        }
    }
    go(pattern.as_bytes(), key.as_bytes())
}

fn base_name(path: &str) -> &str {
    path.rsplit_once('/').map(|(_, b)| b).unwrap_or(path)
}

/// What the boot-time configuration says about one key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BootView {
    /// Files applied after Sinter's own that set the key: `(path, value)`,
    /// the last setting in each file, in order.
    pub later: Vec<(String, String)>,
    /// Pattern settings after Sinter's file matching the key:
    /// `(path, pattern, value)`.
    pub later_patterns: Vec<(String, String, String)>,
    /// The last plain setting of the key in the whole order.
    pub effective: Option<(String, String)>,
    /// The last plain setting of the key in a file other than Sinter's.
    pub without_own: Option<(String, String)>,
    /// A file after Sinter's own with a line that mentions the key and
    /// could not be classified.
    pub undecided_later: Option<String>,
    /// The same for any file other than Sinter's own.
    pub undecided_any: Option<String>,
}

impl BootView {
    /// The view of `name` (dotted form) in `cfg`. Sinter's file is placed
    /// where it is listed or, when it is not (yet) listed, where its file
    /// name sorts; a file of the same name elsewhere is masked by it.
    pub fn of(cfg: &BootConfig, name: &str) -> Self {
        let own = conf_path(name);
        let own_base = base_name(&own);
        let slash = name.replace('.', "/");
        let own_at = cfg.files.iter().position(|f| f.path == own);
        let mut v = BootView::default();
        for (i, f) in cfg.files.iter().enumerate() {
            let is_own = f.path == own;
            let base = base_name(&f.path);
            let after = match own_at {
                Some(at) => i > at,
                None => base > own_base,
            };
            let mentions = f
                .unclassified
                .iter()
                .any(|l| l.contains(name) || l.contains(&slash));
            if mentions && !is_own {
                v.undecided_any.get_or_insert_with(|| f.path.clone());
                if after {
                    v.undecided_later.get_or_insert_with(|| f.path.clone());
                }
            }
            let mut last_here = None;
            for s in &f.settings {
                match s {
                    BootSetting::Plain { key, value } if key == name => {
                        last_here = Some(value.clone());
                    }
                    BootSetting::Pattern { pattern, value }
                        if after && pattern_may_match(pattern, name) =>
                    {
                        v.later_patterns
                            .push((f.path.clone(), pattern.clone(), value.clone()));
                    }
                    _ => {}
                }
            }
            if let Some(value) = last_here {
                v.effective = Some((f.path.clone(), value.clone()));
                if !is_own {
                    v.without_own = Some((f.path.clone(), value.clone()));
                }
                if after && !is_own && base != own_base {
                    v.later.push((f.path.clone(), value));
                }
            }
        }
        v
    }
}

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
        // The rendered content is a literal: whether it came from a sensitive
        // variable is known only from the declaring resource, so carry that
        // into the file part, which decides redaction by `sensitive`.
        f.sensitive = res.sensitive || res.derived_sensitive;
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
    fn cat_config_headers_are_matched_strictly() {
        for ok in [
            "# /usr/lib/sysctl.d/50-default.conf",
            "# /etc/sysctl.d/99-sysctl.conf",
            "# /run/sysctl.d/10-x.conf",
            "# /usr/local/lib/sysctl.d/20-y.conf",
        ] {
            assert_eq!(header_path(ok), Some(&ok[2..]), "{ok}");
        }
        for bad in [
            "# /usr/lib/sysctl.d/, /run/sysctl.d/, and /etc/sysctl.d/.",
            "# /etc/sysctl.conf",
            "# /etc/sysctl.d/sub/x.conf",
            "# /etc/sysctl.d/.conf",
            "# /etc/sysctl.d/x.conf trailing",
            "#  /etc/sysctl.d/x.conf",
            "# /etc/sysctl.d/x.conf.bak",
            "# /etc/sysctl.d/a,b.conf",
            "# /tmp/x.conf",
            "/etc/sysctl.d/x.conf",
            "# etc/sysctl.d/x.conf",
        ] {
            assert_eq!(header_path(bad), None, "{bad}");
        }
    }

    #[test]
    fn cat_config_lines_are_classified() {
        let out = b"\n# /usr/lib/sysctl.d/50-default.conf\n# comment\n; other comment\n\nkernel.sysrq = 16\n-net.ipv4.conf.*.rp_filter = 2\nnet/ipv4/conf/eth0.1/rp_filter=1\nvm.swappiness=30\nvm.swappiness = 40\nnot a setting vm.swappiness\n# /usr/lib/sysctl.d/, /run/sysctl.d/, and /etc/sysctl.d/.\n# /etc/sysctl.d/99-sysctl.conf\n  fs.file-max =  100\t200 \n";
        let cfg = parse_cat_config(out).unwrap();
        assert_eq!(cfg.files.len(), 2);
        let f = &cfg.files[0];
        assert_eq!(f.path, "/usr/lib/sysctl.d/50-default.conf");
        let plain = |k: &str, v: &str| BootSetting::Plain {
            key: k.into(),
            value: v.into(),
        };
        assert_eq!(
            f.settings,
            vec![
                plain("kernel.sysrq", "16"),
                BootSetting::Pattern {
                    pattern: "net.ipv4.conf.*.rp_filter".into(),
                    value: "2".into()
                },
                plain("net.ipv4.conf.eth0/1.rp_filter", "1"),
                plain("vm.swappiness", "30"),
                plain("vm.swappiness", "40"),
            ]
        );
        assert_eq!(f.unclassified, ["not a setting vm.swappiness"]);
        assert_eq!(cfg.files[1].settings, vec![plain("fs.file-max", "100 200")]);

        assert!(parse_cat_config(b"").unwrap().files.is_empty());
        assert!(parse_cat_config(b"garbage\n# /etc/sysctl.d/a.conf\n").is_err());
        assert!(parse_cat_config(b"# /etc/sysctl.d/a.conf\n\xff\n").is_err());
    }

    /// NB-D4: a comment in a later file that has exactly the form of the
    /// header of Sinter's own file would make the override after it look like
    /// a line of Sinter's file. Out of order, repeated or not naming a
    /// `.conf` file, the whole output is refused (the caller: not examined).
    #[test]
    fn a_header_shaped_comment_out_of_order_refuses_the_whole_output() {
        let own = "# /etc/sysctl.d/90-sinter-vm.swappiness.conf\nvm.swappiness = 10\n";
        // Without the fake header the override is seen.
        let honest = format!("# /usr/lib/sysctl.d/10-a.conf\nkernel.x = 1\n{own}# /etc/sysctl.d/95-b.conf\nvm.swappiness = 20\n");
        let v = BootView::of(
            &parse_cat_config(honest.as_bytes()).unwrap(),
            "vm.swappiness",
        );
        assert_eq!(
            v.effective,
            Some(("/etc/sysctl.d/95-b.conf".to_string(), "20".to_string()))
        );
        for (label, text) in [
            (
                "own header repeated later",
                format!(
                    "# /usr/lib/sysctl.d/10-a.conf\nkernel.x = 1\n{own}# /etc/sysctl.d/95-b.conf\n# /etc/sysctl.d/90-sinter-vm.swappiness.conf\nvm.swappiness = 20\n"
                ),
            ),
            (
                // Sinter's file not written yet: the fake header comes after
                // a file that sorts later.
                "own header out of order",
                "# /usr/lib/sysctl.d/10-a.conf\nkernel.x = 1\n# /etc/sysctl.d/95-b.conf\n# /etc/sysctl.d/90-sinter-vm.swappiness.conf\nvm.swappiness = 20\n".to_string(),
            ),
            (
                "same name in another directory",
                format!(
                    "{own}# /etc/sysctl.d/95-b.conf\n# /usr/lib/sysctl.d/90-sinter-vm.swappiness.conf\nvm.swappiness = 20\n"
                ),
            ),
            (
                "header-shaped line not naming a .conf file",
                format!("{own}# /etc/sysctl.d/95-b.conf\n# /etc/sysctl.d/zz.conf.disabled\nvm.swappiness = 20\n"),
            ),
        ] {
            let e = parse_cat_config(text.as_bytes()).expect_err(label);
            assert!(!e.is_empty(), "{label}");
        }
        // A file name that sorts later in a directory listed earlier is in
        // order (the order is by file name across the directories).
        assert!(parse_cat_config(
            b"# /etc/sysctl.d/10-a.conf\n# /usr/lib/sysctl.d/50-b.conf\n# /run/sysctl.d/60-c.conf\n"
        )
        .is_ok());
        // An ordinary comment naming a directory is still a comment.
        assert!(parse_cat_config(
            b"# /etc/sysctl.d/10-a.conf\n# See /etc/sysctl.d/ for more\n# /etc/sysctl.d/\n"
        )
        .is_ok());
    }

    #[test]
    fn the_last_setting_in_the_order_wins() {
        let cfg = parse_cat_config(
            b"# /usr/lib/sysctl.d/10-a.conf\nvm.swappiness = 1\n\
              # /etc/sysctl.d/90-sinter-vm.swappiness.conf\nvm.swappiness = 10\n\
              # /etc/sysctl.d/95-b.conf\nvm.swappiness = 20\nvm.swappiness = 21\nvm.* = 5\n\
              # /etc/sysctl.d/99-sysctl.conf\nkernel.x = 1\n",
        )
        .unwrap();
        let v = BootView::of(&cfg, "vm.swappiness");
        assert_eq!(
            v.later,
            vec![("/etc/sysctl.d/95-b.conf".to_string(), "21".to_string())]
        );
        assert_eq!(
            v.effective,
            Some(("/etc/sysctl.d/95-b.conf".to_string(), "21".to_string()))
        );
        assert_eq!(v.later_patterns.len(), 1);
        assert_eq!(v.undecided_later, None);

        // Sinter's file not listed yet: placed by its file name.
        let cfg = parse_cat_config(
            b"# /usr/lib/sysctl.d/10-a.conf\nvm.swappiness = 1\n# /etc/sysctl.d/99-sysctl.conf\nvm/swappiness = 2\n",
        )
        .unwrap();
        let v = BootView::of(&cfg, "vm.swappiness");
        assert_eq!(
            v.later,
            vec![("/etc/sysctl.d/99-sysctl.conf".to_string(), "2".to_string())]
        );
        assert_eq!(
            v.without_own,
            Some(("/etc/sysctl.d/99-sysctl.conf".to_string(), "2".to_string()))
        );

        // Earlier files do not count as later; an unclassified mention later does.
        let cfg = parse_cat_config(
            b"# /usr/lib/sysctl.d/10-a.conf\nvm.swappiness 1\n# /etc/sysctl.d/99-z.conf\nvm/swappiness\n",
        )
        .unwrap();
        let v = BootView::of(&cfg, "vm.swappiness");
        assert!(v.later.is_empty());
        assert_eq!(
            v.undecided_any.as_deref(),
            Some("/usr/lib/sysctl.d/10-a.conf")
        );
        assert_eq!(
            v.undecided_later.as_deref(),
            Some("/etc/sysctl.d/99-z.conf")
        );
    }

    #[test]
    fn patterns() {
        assert!(pattern_may_match(
            "net.ipv4.conf.*.rp_filter",
            "net.ipv4.conf.all.rp_filter"
        ));
        assert!(pattern_may_match("vm.*", "vm.swappiness"));
        assert!(pattern_may_match("vm.swappines?", "vm.swappiness"));
        assert!(pattern_may_match("vm.[sx]wappiness", "vm.swappiness"));
        assert!(!pattern_may_match("net.*", "vm.swappiness"));
        assert!(!pattern_may_match("vm.?", "vm.swappiness"));
        assert_eq!(
            dotted_key("net/ipv4/conf/eth0.1/rp_filter"),
            "net.ipv4.conf.eth0/1.rp_filter"
        );
        assert_eq!(dotted_key("vm.swappiness"), "vm.swappiness");
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
