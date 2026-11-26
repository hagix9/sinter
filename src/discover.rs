//! `sinter discover` (DESIGN §46): read-only collection of an existing
//! host's state into a candidate recipe and its provenance.
//!
//! The collector runs on an engine built in plan mode, so its `TargetFs`
//! has `allow_mutation = false` and no mutation permit can exist (§23). Every
//! observation is a fixed argv form of `TargetFs::discover_observe` or an
//! existing read-only observation (`stat`, `readlink`, `cat` of
//! `/etc/login.defs`); nothing from a command line or a recipe becomes a
//! program or an option.
//!
//! Nothing is guessed: what Sinter cannot read exactly, or cannot declare
//! with an existing resource type, is reported as unsupported with a reason
//! class. File content is taken in only when it is positively classified as
//! not secret; the classifier is a heuristic, so a reviewer must check every
//! candidate before use. Of an excluded file nothing but its path and the
//! reason class is written anywhere: no content, fragment or digest.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Value as J};

use crate::engine::{Engine, Mode, RunOptions};
use crate::error::{Result, SinterError};
use crate::executor::{Completion, Output};
use crate::targetfs::{DiscoverQuery, ObjKind, Stat};
use crate::value::Value;

/// Largest file whose content discover takes in (64 KiB).
pub const MAX_FILE: usize = 64 * 1024;
/// At most this many `--include-path` values.
pub const MAX_INCLUDE_PATHS: usize = 64;
pub const PROVENANCE_SCHEMA: &str = "sinter-discover-provenance/1";

/// A collector profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Profile {
    Packages,
    Units,
    Accounts,
    Files,
}

impl Profile {
    pub fn parse_list(s: &str) -> Result<BTreeSet<Profile>> {
        let mut out = BTreeSet::new();
        for p in s.split(',') {
            let v = match p {
                "packages" => Profile::Packages,
                "units" => Profile::Units,
                "accounts" => Profile::Accounts,
                "files" => Profile::Files,
                _ => {
                    return Err(SinterError::schema(format!(
                        "--profile: unknown profile {:?} (packages, units, accounts, files)",
                        p
                    )))
                }
            };
            if !out.insert(v) {
                return Err(SinterError::schema(format!(
                    "--profile: {} is given twice",
                    p
                )));
            }
        }
        Ok(out)
    }

    pub fn all() -> BTreeSet<Profile> {
        [
            Profile::Packages,
            Profile::Units,
            Profile::Accounts,
            Profile::Files,
        ]
        .into_iter()
        .collect()
    }
}

/// What the CLI asks for.
#[derive(Debug, Clone)]
pub struct DiscoverConfig {
    pub profiles: BTreeSet<Profile>,
    pub include_paths: Vec<String>,
    /// Inventory name of the host, never an address.
    pub host_label: String,
    /// RFC 3339 UTC.
    pub collected_at: String,
}

/// An absolute, normalized path of printable ASCII: no `//`, `/./`, `/../`,
/// trailing `/`, backslash or control character, at most 4096 bytes.
pub fn valid_include_path(p: &str) -> bool {
    p.starts_with('/')
        && p.len() > 1
        && p.len() <= 4096
        && !p.ends_with('/')
        && !p.contains("//")
        && !p.contains('\\')
        && p.split('/').skip(1).all(|c| c != "." && c != "..")
        && p.bytes().all(|b| (0x21..0x7f).contains(&b))
}

/// One generated resource with its traceability.
#[derive(Debug, Clone, PartialEq)]
pub struct IrResource {
    pub id: String,
    pub type_: String,
    pub with: BTreeMap<String, Value>,
    pub collector: String,
    pub source_key: String,
    /// SHA-256 of the observed value, `None` for file content.
    pub value_sha256: Option<String>,
}

/// One command a collector ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorRun {
    pub id: String,
    pub argv: Vec<String>,
    pub exit_status: Option<i32>,
    /// `None` when the output holds file content or personal data, or the
    /// command did not complete.
    pub output_sha256: Option<String>,
}

/// One item discover did not take in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    pub kind: String,
    pub key: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct Discovery {
    pub resources: Vec<IrResource>,
    pub collectors: Vec<CollectorRun>,
    pub unsupported: Vec<Unsupported>,
    pub warnings: Vec<String>,
}

impl Discovery {
    fn unsupported(&mut self, kind: &str, key: &str, reason: &str) {
        self.unsupported.push(Unsupported {
            kind: kind.into(),
            key: key.into(),
            reason: reason.into(),
        });
    }
}

fn sha256(b: &[u8]) -> String {
    crate::risk::approval::sha256_hex(b)
}

fn exit_of(o: &Output) -> Option<i32> {
    match o.completion {
        Completion::Exited(c) => Some(c),
        _ => None,
    }
}

/// The complete UTF-8 stdout of a command that exited 0.
fn ok_text(o: &Output) -> Option<String> {
    if o.completion == Completion::Exited(0) && !o.stdout_truncated && !o.stderr_truncated {
        String::from_utf8(o.stdout.clone()).ok()
    } else {
        None
    }
}

fn lines(text: &str) -> Vec<&str> {
    let t = text.strip_suffix('\n').unwrap_or(text);
    if t.is_empty() {
        Vec::new()
    } else {
        t.split('\n').collect()
    }
}

// ---------------------------------------------------------------------------
// classifiers (pure)
// ---------------------------------------------------------------------------

/// A Debian/RPM package name as the `package` resource accepts it.
pub fn valid_package_name(n: &str) -> bool {
    n.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && n.len() <= 128
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~'))
}

/// A service or timer unit name Sinter can declare: no template (`@`), no
/// escape, a `.service` or `.timer` suffix.
pub fn valid_unit_name(n: &str) -> bool {
    (n.ends_with(".service") || n.ends_with(".timer"))
        && n.len() <= 200
        && !n.starts_with('.')
        && !n.starts_with('-')
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '-'))
}

/// Recipe template syntax: a generated string with `{{` (also `\{{`) would
/// be evaluated by plan, apply and audit instead of being taken literally,
/// so such a value is never generated (fail closed).
pub fn has_template(v: &str) -> bool {
    v.contains("{{")
}

/// Names whose content is never taken in (§46.3).
pub fn secret_name(path: &str) -> bool {
    let base = path.rsplit('/').next().unwrap_or(path);
    let lower = base.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "shadow" | "shadow-" | "gshadow" | "gshadow-" | "authorized_keys" | "known_hosts"
    ) || (path.starts_with("/etc/ssh/") && lower.starts_with("ssh_host_"))
        || lower.starts_with("id_")
        || path.contains("/.ssh/")
        || [".key", ".pem", ".p12", ".pfx", ".jks", ".keystore"]
            .iter()
            .any(|e| lower.ends_with(e))
}

/// Why a file's content is not taken in, or `None`. Every uncertain case is
/// a reason (fail closed).
pub fn classify_content(b: &[u8]) -> std::result::Result<String, &'static str> {
    let text = std::str::from_utf8(b).map_err(|_| "undecodable content")?;
    if text.starts_with('\u{feff}') || text.contains('\u{fffd}') {
        return Err("undecodable content");
    }
    if text.chars().any(|c| {
        (c.is_control() && c != '\n' && c != '\t')
            || matches!(
                c,
                '\u{2028}' | '\u{2029}' | '\u{00ad}' | '\u{061c}' | '\u{180e}'
            )
            || ('\u{200b}'..='\u{200f}').contains(&c)
            || ('\u{202a}'..='\u{202e}').contains(&c)
            || ('\u{2060}'..='\u{206f}').contains(&c)
            || ('\u{fff9}'..='\u{fffb}').contains(&c)
            || ('\u{e0000}'..='\u{e007f}').contains(&c)
            || c == '\u{feff}'
    }) {
        return Err("control characters");
    }
    if has_template(text) {
        return Err("template syntax");
    }
    if text.contains("-----BEGIN") || text.contains("PRIVATE KEY") {
        return Err("private key or certificate block");
    }
    if credential_assignment(text) || crypt_hash(text) || url_userinfo(text) {
        return Err("credential assignment");
    }
    if high_entropy_token(text) || long_mixed_token(text) {
        return Err("high-entropy token");
    }
    Ok(text.to_string())
}

/// A crypt(3) hash: `$1$`, `$2a$`/`$2b$`/`$2x$`/`$2y$`, `$5$`, `$6$`, `$y$`,
/// `$apr1$`, `$7$`, `$gy$` followed by more text.
pub fn crypt_hash(text: &str) -> bool {
    [
        "$1$", "$2$", "$2a$", "$2b$", "$2x$", "$2y$", "$5$", "$6$", "$7$", "$y$", "$gy$", "$apr1$",
        "$argon2",
    ]
    .iter()
    .any(|p| {
        text.match_indices(p).any(|(i, _)| {
            text[i + p.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '$' | '='))
        })
    })
}

/// A URL with a password in its user information (`scheme://user:pass@`).
pub fn url_userinfo(text: &str) -> bool {
    text.match_indices("://").any(|(i, _)| {
        let rest = &text[i + 3..];
        let end = rest
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '"' | '\''))
            .unwrap_or(rest.len());
        let auth = &rest[..end];
        auth.find('@')
            .is_some_and(|at| auth[..at].contains(':') && at > 0)
    })
}

/// A run of at least 40 characters of `[A-Za-z0-9+/=_-]` with lower case,
/// upper case and a digit (base64 keys that contain `/`).
pub fn long_mixed_token(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-')))
        .any(|r| {
            r.len() >= 40
                && r.chars().any(|c| c.is_ascii_lowercase())
                && r.chars().any(|c| c.is_ascii_uppercase())
                && r.chars().any(|c| c.is_ascii_digit())
        })
}

const CREDENTIAL_KEYS: &[&str] = &[
    "pass",
    "psk",
    "bearer",
    "authorization",
    "community",
    "password",
    "passwd",
    "passphrase",
    "pwd",
    "secret",
    "token",
    "api_key",
    "api-key",
    "apikey",
    "access_key",
    "access-key",
    "private_key",
    "private-key",
    "credential",
    "auth_key",
];

/// A credential key followed by `=` or `:` and a value on the same line.
pub fn credential_assignment(text: &str) -> bool {
    for line in text.lines() {
        let l = line.to_ascii_lowercase();
        let b = l.as_bytes();
        for k in CREDENTIAL_KEYS {
            let mut from = 0;
            while let Some(i) = l[from..].find(k) {
                let mut j = from + i + k.len();
                while j < b.len()
                    && (b[j].is_ascii_alphanumeric() || matches!(b[j], b'_' | b'-' | b'.'))
                {
                    j += 1;
                }
                while j < b.len() && matches!(b[j], b' ' | b'\t' | b'"' | b'\'') {
                    j += 1;
                }
                // `community <value>` (SNMP) and `Bearer <token>` take their
                // value after whitespace.
                let spaced = matches!(*k, "community" | "bearer")
                    && j > from + i + k.len() - 1
                    && j < b.len()
                    && b[j - 1].is_ascii_whitespace()
                    && b[j] != b'#';
                if spaced {
                    return true;
                }
                if j < b.len() && matches!(b[j], b'=' | b':') {
                    j += 1;
                    while j < b.len() && matches!(b[j], b' ' | b'\t' | b'"' | b'\'') {
                        j += 1;
                    }
                    if j < b.len() && b[j] != b'#' {
                        return true;
                    }
                }
                from += i + 1;
            }
        }
    }
    false
}

/// A run of at least 24 token characters (letters, digits, `+ = _ -`) with
/// Shannon entropy of at least 3.5 bits per character (keys, tokens,
/// hashes).
pub fn high_entropy_token(text: &str) -> bool {
    // `/` and `.` split runs, so paths and dotted names are not tokens.
    let tok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '=' | '_' | '-');
    let mut run = String::new();
    let check = |r: &str| {
        if r.len() < 24 {
            return false;
        }
        let mut counts: BTreeMap<char, usize> = BTreeMap::new();
        for c in r.chars() {
            *counts.entry(c).or_default() += 1;
        }
        let n = r.len() as f64;
        let h: f64 = counts
            .values()
            .map(|&k| {
                let p = k as f64 / n;
                -p * p.log2()
            })
            .sum();
        h >= 3.5
    };
    for c in text.chars() {
        if tok(c) {
            run.push(c);
        } else {
            if check(&run) {
                return true;
            }
            run.clear();
        }
    }
    check(&run)
}

/// `UID_MIN`, `UID_MAX`, `GID_MIN`, `GID_MAX` of `/etc/login.defs`; each
/// exactly once, decimal, min ≤ max. Anything else is `None`.
pub fn parse_login_defs(text: &str) -> Option<(u32, u32, u32, u32)> {
    let mut m: BTreeMap<&str, u32> = BTreeMap::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let mut w = l.split_whitespace();
        let (Some(k), Some(v)) = (w.next(), w.next()) else {
            continue;
        };
        if !matches!(k, "UID_MIN" | "UID_MAX" | "GID_MIN" | "GID_MAX") {
            continue;
        }
        if w.next().is_some_and(|x| !x.starts_with('#')) {
            return None;
        }
        let n: u32 = v.parse().ok()?;
        if v != n.to_string() || m.insert(k, n).is_some() {
            return None;
        }
    }
    let (a, b, c, d) = (
        *m.get("UID_MIN")?,
        *m.get("UID_MAX")?,
        *m.get("GID_MIN")?,
        *m.get("GID_MAX")?,
    );
    (a <= b && c <= d).then_some((a, b, c, d))
}

/// A generated id: `prefix-` and the key with characters outside
/// `[A-Za-z0-9._-]` replaced by `-`.
fn slug(prefix: &str, key: &str) -> String {
    let s: String = key
        .trim_start_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("{}-{}", prefix, s)
}

fn s(v: &str) -> Value {
    Value::Str(v.to_string())
}

fn value_digest(with: &BTreeMap<String, Value>) -> String {
    let j: BTreeMap<&String, J> = with
        .iter()
        .map(|(k, v)| {
            (
                k,
                match v {
                    Value::Str(x) => J::String(x.clone()),
                    Value::Bool(b) => J::Bool(*b),
                    Value::Int(n) => json!(n),
                    other => J::String(format!("{:?}", other)),
                },
            )
        })
        .collect();
    sha256(crate::risk::approval::canonical(&json!(j)).as_bytes())
}

// ---------------------------------------------------------------------------
// collectors
// ---------------------------------------------------------------------------

impl Engine {
    fn discover_run(
        &mut self,
        d: &mut Discovery,
        id: &str,
        q: &DiscoverQuery,
        argv: Vec<String>,
        digest_ok: bool,
    ) -> Option<String> {
        let out = self.fs.discover_observe(q);
        match out {
            Ok(o) => {
                let text = ok_text(&o);
                d.collectors.push(CollectorRun {
                    id: id.into(),
                    argv,
                    exit_status: exit_of(&o),
                    output_sha256: if digest_ok && text.is_some() {
                        Some(sha256(&o.stdout))
                    } else {
                        None
                    },
                });
                text
            }
            Err(_) => {
                d.collectors.push(CollectorRun {
                    id: id.into(),
                    argv,
                    exit_status: None,
                    output_sha256: None,
                });
                None
            }
        }
    }

    fn collect_packages(&mut self, d: &mut Discovery) {
        match self.facts.os_family.as_str() {
            "debian" => {}
            "redhat" => {
                // DESIGN §46.2: a cache-only user-installed query of the
                // installed dnf, measured per target. Not measured yet, so the
                // profile is unsupported; no dnf command is run (so no
                // metadata can be refreshed) and nothing falls back to the
                // list of every installed package.
                d.unsupported(
                    "profile",
                    "packages",
                    "the cache-only user-installed dnf query is not measured on this platform yet",
                );
                return;
            }
            _ => {
                d.unsupported("profile", "packages", "unsupported operating system family");
                return;
            }
        }
        let Some(text) = self.discover_run(
            d,
            "packages.apt-mark",
            &DiscoverQuery::AptMarkShowmanual,
            vec!["/usr/bin/apt-mark".into(), "showmanual".into()],
            true,
        ) else {
            d.unsupported("profile", "packages", "apt-mark showmanual did not answer");
            return;
        };
        let mut seen = BTreeSet::new();
        for (n, line) in lines(&text).into_iter().enumerate() {
            if line.contains(':') && valid_package_name(line.split(':').next().unwrap_or("")) {
                d.unsupported("package", line, "architecture-qualified name");
                continue;
            }
            if !valid_package_name(line) {
                d.unsupported(
                    "package",
                    &format!("(line {})", n + 1),
                    "unreadable package name",
                );
                continue;
            }
            if !seen.insert(line.to_string()) {
                continue;
            }
            let mut with = BTreeMap::new();
            with.insert("name".into(), s(line));
            with.insert("state".into(), s("present"));
            d.resources.push(IrResource {
                id: slug("pkg", line),
                type_: "package".into(),
                value_sha256: Some(value_digest(&with)),
                with,
                collector: "packages.apt-mark".into(),
                source_key: format!("package:{}", line),
            });
        }
    }

    fn collect_units(&mut self, d: &mut Discovery) {
        let argv: Vec<String> = [
            "/usr/bin/systemctl",
            "list-unit-files",
            "--type=service",
            "--type=timer",
            "--state=enabled",
            "--no-legend",
            "--plain",
            "--no-pager",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let Some(text) = self.discover_run(
            d,
            "units.list-unit-files",
            &DiscoverQuery::ListUnitFiles,
            argv,
            true,
        ) else {
            d.unsupported(
                "profile",
                "units",
                "systemctl list-unit-files did not answer",
            );
            return;
        };
        let rows: Vec<Vec<&str>> = lines(&text)
            .into_iter()
            .map(|l| l.split_whitespace().collect())
            .collect();
        let cols: BTreeSet<usize> = rows.iter().map(|r| r.len()).collect();
        let with_preset = match cols.iter().copied().collect::<Vec<_>>().as_slice() {
            [] => true,
            [2] => false,
            [3] => true,
            _ => {
                d.unsupported("profile", "units", "unexpected systemctl output");
                return;
            }
        };
        if !with_preset {
            d.warnings.push(
                "units: systemctl shows no vendor preset column; every enabled unit was taken in (review which are distribution defaults)".into(),
            );
        }
        let mut seen = BTreeSet::new();
        for (n, r) in rows.iter().enumerate() {
            let name = r[0];
            if !valid_unit_name(name) {
                let reason = if name.contains('@') {
                    "template unit"
                } else {
                    "unit name Sinter cannot declare"
                };
                let key = if name.chars().all(|c| c.is_ascii_graphic()) && name.len() <= 200 {
                    name.to_string()
                } else {
                    format!("(line {})", n + 1)
                };
                d.unsupported("unit", &key, reason);
                continue;
            }
            if r[1] != "enabled" {
                d.unsupported("unit", name, "state is not enabled");
                continue;
            }
            if with_preset && r[2] == "enabled" {
                continue;
            }
            if !seen.insert(name.to_string()) {
                d.unsupported("unit", name, "listed twice");
                continue;
            }
            let mut with = BTreeMap::new();
            with.insert("name".into(), s(name));
            with.insert("enabled".into(), Value::Bool(true));
            d.resources.push(IrResource {
                id: slug("svc", name),
                type_: "service".into(),
                value_sha256: Some(value_digest(&with)),
                with,
                collector: "units.list-unit-files".into(),
                source_key: format!("unit:{}", name),
            });
        }
    }

    fn collect_accounts(&mut self, d: &mut Discovery) {
        let defs = self
            .fs
            .read_file("/etc/login.defs")
            .ok()
            .and_then(|b| String::from_utf8(b).ok());
        d.collectors.push(CollectorRun {
            id: "accounts.login-defs".into(),
            argv: vec!["/bin/cat".into(), "--".into(), "/etc/login.defs".into()],
            exit_status: defs.as_ref().map(|_| 0),
            output_sha256: defs.as_ref().map(|t| sha256(t.as_bytes())),
        });
        let Some((uid_min, uid_max, gid_min, gid_max)) = defs.as_deref().and_then(parse_login_defs)
        else {
            d.unsupported(
                "profile",
                "accounts",
                "UID_MIN, UID_MAX, GID_MIN and GID_MAX could not be read exactly from /etc/login.defs",
            );
            return;
        };
        // The passwd output holds GECOS (personal data): no digest of it.
        let passwd = self.discover_run(
            d,
            "accounts.passwd",
            &DiscoverQuery::GetentPasswd,
            vec![
                "/usr/bin/getent".into(),
                "-s".into(),
                "files".into(),
                "passwd".into(),
            ],
            false,
        );
        let group = self.discover_run(
            d,
            "accounts.group",
            &DiscoverQuery::GetentGroup,
            vec![
                "/usr/bin/getent".into(),
                "-s".into(),
                "files".into(),
                "group".into(),
            ],
            false,
        );
        let (Some(passwd), Some(group)) = (passwd, group) else {
            d.unsupported("profile", "accounts", "getent -s files did not answer");
            return;
        };
        // Every group (any range) for primary group names.
        let mut groups: Vec<(String, u32)> = Vec::new();
        let mut gnames = BTreeMap::new();
        for (n, l) in lines(&group).into_iter().enumerate() {
            let f: Vec<&str> = l.split(':').collect();
            let parsed = (f.len() == 4)
                .then(|| f[2].parse::<u32>().ok().filter(|g| f[2] == g.to_string()))
                .flatten();
            match parsed {
                Some(gid) if crate::accounts::valid_account_name(f[0]) => {
                    *gnames.entry(f[0].to_string()).or_insert(0) += 1;
                    groups.push((f[0].to_string(), gid));
                }
                _ => d.unsupported(
                    "group",
                    &format!("(line {})", n + 1),
                    "unreadable group record",
                ),
            }
        }
        let by_gid = |gid: u32| -> Option<&String> {
            let hits: Vec<&String> = groups
                .iter()
                .filter(|(_, g)| *g == gid)
                .map(|(n, _)| n)
                .collect();
            match hits.as_slice() {
                [one] => Some(*one),
                _ => None,
            }
        };
        let mut out_groups = Vec::new();
        for (name, gid) in &groups {
            if !(gid_min..=gid_max).contains(gid) {
                continue;
            }
            if gnames[name] > 1 {
                d.unsupported("group", name, "listed more than once");
                continue;
            }
            let mut with = BTreeMap::new();
            with.insert("name".into(), s(name));
            with.insert("gid".into(), Value::Int(i64::from(*gid)));
            out_groups.push(IrResource {
                id: slug("group", name),
                type_: "group".into(),
                value_sha256: Some(value_digest(&with)),
                with,
                collector: "accounts.group".into(),
                source_key: format!("group:{}", name),
            });
        }
        let mut out_users = Vec::new();
        let mut unames: BTreeMap<String, usize> = BTreeMap::new();
        let mut rows = Vec::new();
        for (n, l) in lines(&passwd).into_iter().enumerate() {
            let f: Vec<&str> = l.split(':').collect();
            // name:x:uid:gid:gecos:home:shell; the password field and GECOS
            // are never used or emitted.
            let ids = (f.len() == 7)
                .then(|| {
                    let u = f[2].parse::<u32>().ok().filter(|u| f[2] == u.to_string())?;
                    let g = f[3].parse::<u32>().ok().filter(|g| f[3] == g.to_string())?;
                    Some((u, g))
                })
                .flatten();
            match ids {
                Some((uid, gid)) if crate::accounts::valid_account_name(f[0]) => {
                    *unames.entry(f[0].to_string()).or_insert(0) += 1;
                    rows.push((
                        f[0].to_string(),
                        uid,
                        gid,
                        f[5].to_string(),
                        f[6].to_string(),
                    ));
                }
                _ => d.unsupported(
                    "user",
                    &format!("(line {})", n + 1),
                    "unreadable passwd record",
                ),
            }
        }
        for (name, uid, gid, home, shell) in rows {
            if !(uid_min..=uid_max).contains(&uid) {
                continue;
            }
            if unames[&name] > 1 {
                d.unsupported("user", &name, "listed more than once");
                continue;
            }
            let Some(gname) = by_gid(gid) else {
                d.unsupported(
                    "user",
                    &name,
                    "primary group not found exactly once in the local group database",
                );
                continue;
            };
            if !crate::accounts::valid_account_path(&home)
                || !crate::accounts::valid_account_path(&shell)
                || has_template(&home)
                || has_template(&shell)
            {
                d.unsupported("user", &name, "home or shell Sinter cannot declare");
                continue;
            }
            let mut with = BTreeMap::new();
            with.insert("name".into(), s(&name));
            with.insert("uid".into(), Value::Int(i64::from(uid)));
            with.insert("group".into(), s(gname));
            with.insert("home".into(), s(&home));
            with.insert("shell".into(), s(&shell));
            out_users.push(IrResource {
                id: slug("user", &name),
                type_: "user".into(),
                value_sha256: Some(value_digest(&with)),
                with,
                collector: "accounts.passwd".into(),
                source_key: format!("user:{}", name),
            });
        }
        // Groups before users (a user names its primary group).
        d.resources.extend(out_groups);
        d.resources.extend(out_users);
    }

    fn collect_file(&mut self, d: &mut Discovery, path: &str) {
        if has_template(path) {
            d.unsupported("file", path, "template syntax");
            return;
        }
        let st1 = match self.fs.inspect(path) {
            Ok(st) => st,
            Err(_) => {
                d.unsupported("file", path, "could not be inspected");
                return;
            }
        };
        d.collectors.push(CollectorRun {
            id: format!("files.stat:{}", path),
            argv: vec![
                "/usr/bin/stat".into(),
                "-c".into(),
                "%F|%a|%u|%g|%s|%d|%i|%y|%z".into(),
                "--".into(),
                path.into(),
            ],
            exit_status: Some(0),
            output_sha256: None,
        });
        let meta = |st: &Stat| {
            let mut with = BTreeMap::new();
            with.insert("path".into(), s(path));
            with.insert("owner".into(), s(&st.uid.to_string()));
            with.insert("group".into(), s(&st.gid.to_string()));
            with.insert("mode".into(), s(&format!("{:04o}", st.mode & 0o7777)));
            with
        };
        match st1.kind {
            ObjKind::Dir => {
                let with = meta(&st1);
                d.resources.push(IrResource {
                    id: slug("dir", path),
                    type_: "directory".into(),
                    value_sha256: Some(value_digest(&with)),
                    with,
                    collector: format!("files.stat:{}", path),
                    source_key: format!("directory:{}", path),
                });
            }
            ObjKind::Symlink => {
                let target = match self.fs.readlink(path) {
                    Ok(t)
                        if !t.is_empty()
                            && t.len() <= 4096
                            && !has_template(&t)
                            && t.bytes().all(|b| (0x20..0x7f).contains(&b)) =>
                    {
                        t
                    }
                    _ => {
                        d.unsupported("file", path, "symbolic link target Sinter cannot declare");
                        return;
                    }
                };
                d.collectors.push(CollectorRun {
                    id: format!("files.readlink:{}", path),
                    argv: vec![
                        "/usr/bin/readlink".into(),
                        "-n".into(),
                        "--".into(),
                        path.into(),
                    ],
                    exit_status: Some(0),
                    output_sha256: None,
                });
                let mut with = BTreeMap::new();
                with.insert("path".into(), s(path));
                with.insert("target".into(), s(&target));
                d.resources.push(IrResource {
                    id: slug("link", path),
                    type_: "link".into(),
                    value_sha256: Some(value_digest(&with)),
                    with,
                    collector: format!("files.readlink:{}", path),
                    source_key: format!("link:{}", path),
                });
            }
            ObjKind::File => self.collect_regular(d, path, &st1, meta(&st1)),
            ObjKind::Absent => d.unsupported("file", path, "absent"),
            ObjKind::Other => d.unsupported(
                "file",
                path,
                "not a regular file, directory or symbolic link",
            ),
        }
    }

    fn collect_regular(
        &mut self,
        d: &mut Discovery,
        path: &str,
        st1: &Stat,
        mut with: BTreeMap<String, Value>,
    ) {
        if secret_name(path) {
            d.unsupported("file", path, "excluded: secret-bearing name");
            return;
        }
        if st1.mode & 0o004 == 0 {
            d.unsupported("file", path, "excluded: not readable by others");
            return;
        }
        if st1.size > MAX_FILE as u64 {
            d.unsupported("file", path, "larger than 64 KiB");
            return;
        }
        let out = self
            .fs
            .discover_observe(&DiscoverQuery::Read(path.to_string()));
        d.collectors.push(CollectorRun {
            id: format!("files.read:{}", path),
            argv: vec![
                "/usr/bin/dd".into(),
                format!("if={}", path),
                "iflag=nofollow,nonblock".into(),
                format!("bs={}", MAX_FILE + 1),
                "count=1".into(),
                "status=none".into(),
            ],
            exit_status: out.as_ref().ok().and_then(exit_of),
            output_sha256: None,
        });
        let bytes = match out {
            Ok(o) if o.completion == Completion::Exited(0) && !o.stdout_truncated => o.stdout,
            _ => {
                d.unsupported("file", path, "could not be read");
                return;
            }
        };
        let same = match self.fs.inspect(path) {
            Ok(st2) => {
                st2.kind == st1.kind
                    && st2.mode == st1.mode
                    && st2.uid == st1.uid
                    && st2.gid == st1.gid
                    && st2.size == st1.size
                    && st2.dev == st1.dev
                    && st2.ino == st1.ino
                    && st2.mtime == st1.mtime
                    && st2.ctime == st1.ctime
            }
            Err(_) => false,
        };
        if !same || bytes.len() as u64 != st1.size || bytes.len() > MAX_FILE {
            d.unsupported("file", path, "changed while it was read");
            return;
        }
        match classify_content(&bytes) {
            Ok(text) => {
                with.insert("content".into(), Value::Str(text));
                d.resources.push(IrResource {
                    id: slug("file", path),
                    type_: "file".into(),
                    with,
                    collector: format!("files.read:{}", path),
                    source_key: format!("file:{}", path),
                    // File content: never a digest.
                    value_sha256: None,
                });
            }
            Err(class) => d.unsupported("file", path, &format!("excluded: {}", class)),
        }
    }

    /// Run the collectors of `cfg` (DESIGN §46.2). The engine must be a
    /// plan-mode engine: a mutation-capable one is refused.
    pub fn discover(&mut self, cfg: &DiscoverConfig) -> Result<Discovery> {
        if self.opts.mode != Mode::Plan || self.fs.mutation_permit().is_ok() {
            return Err(SinterError::schema(
                "internal error: discover needs a read-only engine",
            ));
        }
        let mut d = Discovery::default();
        if cfg.profiles.contains(&Profile::Packages) {
            self.collect_packages(&mut d);
        }
        if cfg.profiles.contains(&Profile::Units) {
            self.collect_units(&mut d);
        }
        if cfg.profiles.contains(&Profile::Accounts) {
            self.collect_accounts(&mut d);
        }
        if cfg.profiles.contains(&Profile::Files) {
            for p in &cfg.include_paths {
                self.collect_file(&mut d, p);
            }
        }
        unique_ids(&mut d.resources);
        Ok(d)
    }
}

/// Make ids unique in order: a repeat gets `-2`, `-3`, …
fn unique_ids(rs: &mut [IrResource]) {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for r in rs.iter_mut() {
        if seen.insert(r.id.clone()) {
            continue;
        }
        let mut n = 2;
        loop {
            let cand = format!("{}-{}", r.id, n);
            if seen.insert(cand.clone()) {
                r.id = cand;
                break;
            }
            n += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// YAML and provenance
// ---------------------------------------------------------------------------

/// A YAML double-quoted scalar.
pub fn quote(v: &str) -> String {
    let mut o = String::with_capacity(v.len() + 2);
    o.push('"');
    for c in v.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                o.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if (0x80..=0x9f).contains(&(c as u32))
                || matches!(c, '\u{2028}' | '\u{2029}' | '\u{feff}') =>
            {
                o.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn scalar(v: &Value) -> String {
    match v {
        Value::Str(x) => quote(x),
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        other => quote(&format!("{:?}", other)),
    }
}

/// The candidate recipe (DESIGN §46.4).
pub fn render_yaml(d: &Discovery, cfg: &DiscoverConfig) -> String {
    let mut y = String::new();
    y.push_str("# Sinter discover candidate recipe: NOT APPLIED to any host.\n");
    y.push_str("# Review every resource before use; the secret classifier is a heuristic.\n");
    y.push_str(&format!("# host: {}\n", cfg.host_label));
    y.push_str(&format!("# collected: {}\n", cfg.collected_at));
    y.push_str("version: 1\n");
    if d.resources.is_empty() {
        y.push_str("resources: []\n");
        return y;
    }
    y.push_str("resources:\n");
    for r in &d.resources {
        y.push_str(&format!("  - id: {}\n", quote(&r.id)));
        y.push_str(&format!("    type: {}\n", quote(&r.type_)));
        y.push_str("    with:\n");
        for (k, v) in &r.with {
            y.push_str(&format!("      {}: {}\n", quote(k), scalar(v)));
        }
    }
    y
}

/// The provenance document (DESIGN §46.5).
pub fn provenance(d: &Discovery, cfg: &DiscoverConfig) -> J {
    json!({
        "schema": PROVENANCE_SCHEMA,
        "sinter_version": env!("CARGO_PKG_VERSION"),
        "host": cfg.host_label,
        "collected_at": cfg.collected_at,
        "applied": false,
        "review": "candidate recipe: review before use; the secret classifier is a heuristic and can be wrong",
        "collectors": d.collectors.iter().map(|c| json!({
            "id": c.id,
            "argv": c.argv,
            "exit_status": c.exit_status,
            "output_sha256": c.output_sha256,
        })).collect::<Vec<_>>(),
        "resources": d.resources.iter().map(|r| json!({
            "id": r.id,
            "type": r.type_,
            "collector": r.collector,
            "source_key": r.source_key,
            "value_sha256": r.value_sha256,
        })).collect::<Vec<_>>(),
        "unsupported": d.unsupported.iter().map(|u| json!({
            "kind": u.kind,
            "key": u.key,
            "reason": u.reason,
        })).collect::<Vec<_>>(),
        "warnings": d.warnings,
    })
}

/// Parse the generated text back with the recipe loader (`document` and
/// `model`) in a private temporary directory under `dir`; it must yield
/// exactly the generated resources (DESIGN §46.4). Exit 4 otherwise.
pub fn round_trip(yaml: &str, d: &Discovery, dir: &Path) -> Result<()> {
    let tmp = tempfile::Builder::new()
        .prefix(".sinter-discover-")
        .tempdir_in(dir)
        .map_err(|e| {
            SinterError::plan(format!(
                "discover: cannot create a private check directory: {}",
                e
            ))
        })?;
    let p = tmp.path().join("candidate.yaml");
    crate::securefile::create_exclusive(&p, yaml.as_bytes(), 0o600)
        .map_err(|e| SinterError::plan(format!("discover: cannot write the check copy: {}", e)))?;
    let model = crate::model::load_model(&p).map_err(|e| {
        SinterError::plan(format!(
            "discover: the generated recipe does not load ({}); nothing was written",
            e.message
        ))
    })?;
    let templated = d.resources.iter().any(|r| {
        r.with
            .values()
            .any(|v| matches!(v, Value::Str(x) if has_template(x)))
    });
    if templated {
        return Err(SinterError::plan(
            "discover: a generated value holds template syntax; nothing was written",
        ));
    }
    let same = model.resources.len() == d.resources.len()
        && model.resources.iter().zip(&d.resources).all(|(m, r)| {
            m.id == r.id
                && m.type_ == r.type_
                && m.with == r.with
                && m.when.is_none()
                && m.depends_on.is_empty()
                && m.notify.is_empty()
        })
        && model.handlers.is_empty()
        && model.vars.is_empty();
    if !same {
        return Err(SinterError::plan(
            "discover: the generated recipe does not load back to the collected resources; nothing was written",
        ));
    }
    Ok(())
}

/// What was published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub recipe: PathBuf,
    pub provenance: PathBuf,
}

/// The provenance path of an output: `<file>.discover.json`.
pub fn provenance_path(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(".discover.json");
    PathBuf::from(s)
}

/// Check the two output paths before anything is collected: neither may
/// exist (a symbolic link included), and the parent must be a real
/// directory owned by this account and not writable by group or others.
pub fn check_outputs(out: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let name_ok = out.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        !n.is_empty() && !n.starts_with('.') && n.bytes().all(|b| (0x21..0x7f).contains(&b))
    });
    if !name_ok {
        return Err(SinterError::schema(
            "--output: the file name must be printable ASCII without spaces and must not start with a dot",
        ));
    }
    for p in [out.to_path_buf(), provenance_path(out)] {
        match std::fs::symlink_metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(SinterError::schema(format!(
                    "--output: {} already exists (discover never overwrites)",
                    p.display()
                )))
            }
        }
    }
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let m = std::fs::symlink_metadata(&parent).map_err(|e| {
        SinterError::schema(format!(
            "--output: the directory {} cannot be used: {}",
            parent.display(),
            e
        ))
    })?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !m.file_type().is_dir() || m.uid() != euid || m.mode() & 0o022 != 0 {
        return Err(SinterError::schema(format!(
            "--output: the directory {} must be a real directory owned by this account and not writable by group or others",
            parent.display()
        )));
    }
    Ok(())
}

/// Publish the recipe and the provenance (both 0600, never a replacement,
/// `securefile::publish_new`). Both texts are complete before either is
/// written. A failure of the second leaves the first in place and says so.
pub fn publish(out: &Path, yaml: &str, prov: &J) -> Result<Published> {
    check_outputs(out)?;
    publish_files(out, yaml, prov)
}

/// The two `publish_new` calls of [`publish`] (separate for the partial
/// publication test). A failure of the second is exit 5 and names both.
fn publish_files(out: &Path, yaml: &str, prov: &J) -> Result<Published> {
    let pp = provenance_path(out);
    let prov_text = format!(
        "{}\n",
        serde_json::to_string_pretty(prov)
            .map_err(|e| SinterError::plan(format!("discover: provenance: {}", e)))?
    );
    crate::securefile::publish_new(out, yaml.as_bytes(), 0o600).map_err(|e| {
        SinterError::apply(format!(
            "discover: {} was not written ({}); nothing was written",
            out.display(),
            e
        ))
    })?;
    crate::securefile::publish_new(&pp, prov_text.as_bytes(), 0o600).map_err(|e| {
        SinterError::apply(format!(
            "discover: the recipe {} was written, but its provenance {} was not ({}); review or remove the recipe",
            out.display(),
            pp.display(),
            e
        ))
    })?;
    Ok(Published {
        recipe: out.to_path_buf(),
        provenance: pp,
    })
}

/// RFC 3339 UTC of a Unix time.
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// The host label of an inventory host: its name, unless the name is an IP
/// address or equals the host's address (a label is never an address).
pub fn host_label(name: &str, address: &str) -> String {
    if name.parse::<std::net::IpAddr>().is_ok() || name == address {
        "inventory-host".to_string()
    } else {
        name.to_string()
    }
}

/// An empty model: discover builds a plan-mode engine with no resource.
pub fn empty_model() -> crate::model::Model {
    crate::model::Model {
        vars: BTreeMap::new(),
        resources: Vec::new(),
        handlers: Vec::new(),
        handler_index: BTreeMap::new(),
        register_producers: BTreeMap::new(),
        backups: Vec::new(),
        backup_stores: BTreeMap::new(),
        backup_resources: BTreeMap::new(),
        backups_skipped: Vec::new(),
        targets: None,
        warnings: Vec::new(),
        plugins: None,
        writable_parents: Vec::new(),
    }
}

/// The whole discover run after the CLI chose the host: build a plan-mode
/// engine (never apply), collect, render, check the round trip, publish.
pub fn run(opts: RunOptions, cfg: &DiscoverConfig, out: &Path) -> Result<(Discovery, Published)> {
    if opts.mode != Mode::Plan {
        return Err(SinterError::schema(
            "internal error: discover runs only a plan-mode engine",
        ));
    }
    check_outputs(out)?;
    let mut engine = Engine::new(empty_model(), opts)?;
    let d = engine.discover(cfg)?;
    let yaml = render_yaml(&d, cfg);
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    round_trip(&yaml, &d, &parent)?;
    let prov = provenance(&d, cfg);
    let p = publish(out, &yaml, &prov)?;
    Ok((d, p))
}

#[cfg(test)]
#[path = "discover_tests.rs"]
mod tests;
