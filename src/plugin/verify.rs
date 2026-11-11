//! Verification of the three plugin data files into a sealed model
//! (DESIGN §38.6). Nothing here contacts a target or runs a program.
//!
//! The rules are Core-fixed: a data file can tighten them (shorter operand
//! limits, fewer operations) but never loosen them.

use super::format::{
    CatalogFile, CatalogRef, OpDef, PluginFile, TrustFile, TrustedCatalog, TrustedPlugin,
    FORMAT_VERSION,
};
use crate::error::{Result, SinterError};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_TRUST_ENTRIES: usize = 64;
const MAX_OPS: usize = 32;
const MAX_ARGV: usize = 16;
const MAX_SLOTS: usize = 4;
const MAX_EXIT_ENTRIES: usize = 16;
const MAX_STDOUT_ENTRIES: usize = 16;
const MAX_LITERAL: usize = 128;
const MAX_TEMPLATE: usize = 256;
const MAX_TIMEOUT_SECS: u64 = 120;
const MAX_TYPES: usize = 16;
const MAX_FIELDS: usize = 8;
const MAX_ENUM_VALUES: usize = 16;
const MAX_PRECHECKS: usize = 8;
const MAX_FACETS: usize = 8;
const MAX_DENY: usize = 8;
const MAX_OPERAND: usize = 64;
/// The longest `port_spec` operand: `65534-65535/sctp`.
const MAX_PORT_SPEC: usize = 16;
/// Transport protocols a `port_spec` operand may name.
const PORT_PROTOCOLS: &[&str] = &["tcp", "udp", "sctp", "dccp"];

/// Directories a catalog program may live in (the basename follows directly).
const PROGRAM_DIRS: &[&str] = &["/usr/bin/", "/usr/sbin/"];

/// Programs that would make an operation a general execution, privilege,
/// file-transfer or network channel. Refused in every class.
const FORBIDDEN_PROGRAMS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "mksh",
    "csh",
    "tcsh",
    "fish",
    "busybox",
    "toybox",
    "env",
    "sudo",
    "su",
    "doas",
    "pkexec",
    "setpriv",
    "runuser",
    "chroot",
    "nsenter",
    "unshare",
    "systemd-run",
    "machinectl",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "nc",
    "ncat",
    "socat",
    "curl",
    "wget",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "php",
    "lua",
    "tclsh",
    "awk",
    "gawk",
    "mawk",
    "sed",
    "xargs",
    "find",
    "nohup",
    "timeout",
    "nice",
    "ionice",
    "watch",
    "script",
    "expect",
    "tee",
    "dd",
    "install",
    "cp",
    "mv",
    "rm",
    "ln",
    "chmod",
    "chown",
    "eval",
    "exec",
];

/// Supplementary lint for observe operations: option prefixes and words that
/// usually mean a change. A denylist is incomplete by nature; it is not the
/// safety argument (DESIGN §38.11).
const MUTATING_OPTION_PREFIXES: &[&str] = &[
    "--add",
    "--remove",
    "--delete",
    "--set",
    "--new",
    "--change",
    "--modify",
    "--reload",
    "--complete-reload",
    "--runtime-to-permanent",
    "--load",
    "--reset",
    "--panic",
    "--enable",
    "--disable",
    "--lockdown",
    "--write",
    "--create",
    "--destroy",
];
const MUTATING_WORDS: &[&str] = &[
    "add", "remove", "delete", "del", "set", "modify", "mod", "up", "down", "start", "stop",
    "restart", "reload", "enable", "disable", "mask", "unmask", "kill", "on", "off", "create",
    "destroy", "write", "apply",
];

/// Built-in resource type names (DESIGN §4). A plugin type is always
/// `<plugin>.<name>`, so it cannot equal one of these; the check is kept
/// explicit so a future built-in with a dot could not be shadowed silently.
pub const BUILTIN_RESOURCE_TYPES: &[&str] = &[
    "file",
    "directory",
    "link",
    "template",
    "command",
    "package",
    "service",
    "postgresql_role",
    "user",
    "group",
];

fn refuse(msg: impl Into<String>) -> SinterError {
    SinterError::schema(format!("plugin: {}", msg.into()))
}

// ---------------------------------------------------------------------------
// Names and operands
// ---------------------------------------------------------------------------

/// `[a-z][a-z0-9_]*`, 1..=max bytes.
fn lower_ident(s: &str, max: usize) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// `MAJOR.MINOR.PATCH`, decimal, no leading zeros, each part at most 9 digits.
pub(crate) fn version_ok(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 9
                && p.bytes().all(|c| c.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

pub(crate) fn id_ok(s: &str) -> bool {
    lower_ident(s, 32)
}

fn sha_ok(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// The operand class `ident`: 1..=max bytes, first an ASCII letter or digit,
/// then letters, digits, `_`, `.` or `-`. It can therefore never be an
/// option, a list, a path, an assignment or shell syntax.
pub fn operand_ok(v: &str, max: usize) -> bool {
    let b = v.as_bytes();
    !b.is_empty()
        && b.len() <= max.min(MAX_OPERAND)
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// The operand classes a catalog slot may declare (DESIGN §38.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotClass {
    /// [`operand_ok`].
    Ident,
    /// [`port_spec_ok`].
    PortSpec,
}

/// One decimal port 1..=65535 in canonical form (no sign, no leading zero).
fn port_number(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|c| c.is_ascii_digit()) || s.starts_with('0') {
        return None;
    }
    let n: u32 = s.parse().ok()?;
    (1..=65535).contains(&n).then_some(n)
}

/// The operand class `port_spec`: `PORT/PROTOCOL` or `LOW-HIGH/PROTOCOL`,
/// ports 1..=65535 in canonical decimal with LOW < HIGH, and PROTOCOL one of
/// tcp, udp, sctp, dccp. Like `ident` it can never be an option (it starts
/// with a digit), a list, a path (one `/`, between a port and a protocol
/// word), an assignment or shell syntax.
pub fn port_spec_ok(v: &str, max: usize) -> bool {
    if v.is_empty() || v.len() > max.min(MAX_PORT_SPEC) {
        return false;
    }
    let Some((ports, proto)) = v.split_once('/') else {
        return false;
    };
    if !PORT_PROTOCOLS.contains(&proto) {
        return false;
    }
    match ports.split_once('-') {
        None => port_number(ports).is_some(),
        Some((lo, hi)) => match (port_number(lo), port_number(hi)) {
            (Some(l), Some(h)) => l < h,
            _ => false,
        },
    }
}

/// A `port_spec` operand that names one port, not a range (`80/tcp`). Used
/// by the field kind `port_single`, which fills `port_spec` slots.
pub fn port_single_ok(v: &str, max: usize) -> bool {
    port_spec_ok(v, max) && v.split_once('/').is_some_and(|(p, _)| !p.contains('-'))
}

/// Whether `v` is a valid operand of `class` for a slot of `max` bytes.
pub fn operand_ok_for(class: SlotClass, v: &str, max: usize) -> bool {
    match class {
        SlotClass::Ident => operand_ok(v, max),
        SlotClass::PortSpec => port_spec_ok(v, max),
    }
}

fn program_ok(p: &str) -> bool {
    PROGRAM_DIRS.iter().any(|dir| {
        p.strip_prefix(dir).is_some_and(|base| {
            let b = base.as_bytes();
            !b.is_empty()
                && b.len() <= 64
                && b[0].is_ascii_alphanumeric()
                && b.iter()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'-'))
                && !FORBIDDEN_PROGRAMS.contains(&base)
        })
    })
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Header {
    format: u32,
}

/// Drop double-quoted fragments from a parser message: serde reports the
/// offending *value* in double quotes, keys in backticks. Data files are not
/// supposed to hold secrets, but a message must never be the way one leaks.
fn without_values(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut quoted = false;
    for c in msg.chars() {
        if c == '"' {
            if !quoted {
                out.push_str("\"…\"");
            }
            quoted = !quoted;
        } else if !quoted {
            out.push(c);
        }
    }
    out.lines().next().unwrap_or("").to_string()
}

fn parse<T: DeserializeOwned>(bytes: &[u8], shown: &str) -> Result<T> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| refuse(format!("{}: not valid UTF-8", shown)))?;
    let fail = |e: toml::de::Error| {
        let line = e
            .span()
            .map(|r| text[..r.start.min(text.len())].matches('\n').count() + 1)
            .unwrap_or(0);
        refuse(format!(
            "{}: invalid format (line {}): {}",
            shown,
            line,
            without_values(e.message())
        ))
    };
    let header: Header = toml::from_str(text).map_err(fail)?;
    if header.format != FORMAT_VERSION {
        return Err(refuse(format!(
            "{}: unsupported format {} (this Sinter reads format {})",
            shown, header.format, FORMAT_VERSION
        )));
    }
    toml::from_str(text).map_err(fail)
}

// ---------------------------------------------------------------------------
// Sealed verified model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpClass {
    Observe,
    Mutate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgToken {
    Literal(String),
    /// A whole-token operand; only after a literal `--`.
    Slot(String),
    /// `--option=` followed by an operand.
    Prefixed {
        prefix: String,
        slot: String,
    },
}

/// One catalog operation that passed every Core rule. Only verification
/// constructs it.
#[derive(Debug, Clone)]
pub struct VerifiedOp {
    id: String,
    class: OpClass,
    program: String,
    argv: Vec<ArgToken>,
    slots: BTreeMap<String, (SlotClass, usize)>,
    timeout_secs: u64,
    exit: BTreeMap<i32, String>,
    stdout_map: BTreeMap<String, String>,
    /// Attested (observe) or allowed (mutate) by the Owner's trust file.
    enabled: bool,
}

impl VerifiedOp {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn class(&self) -> OpClass {
        self.class
    }
    pub fn program(&self) -> &str {
        &self.program
    }
    pub fn argv(&self) -> &[ArgToken] {
        &self.argv
    }
    pub fn slot_max_len(&self, slot: &str) -> Option<usize> {
        self.slots.get(slot).map(|(_, m)| *m)
    }
    pub fn slot_class(&self, slot: &str) -> Option<SlotClass> {
        self.slots.get(slot).map(|(c, _)| *c)
    }
    pub fn slots(&self) -> impl Iterator<Item = (&str, usize)> {
        self.slots.iter().map(|(k, (_, m))| (k.as_str(), *m))
    }
    pub fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }
    pub fn exit_map(&self) -> &BTreeMap<i32, String> {
        &self.exit
    }
    pub fn stdout_map(&self) -> &BTreeMap<String, String> {
        &self.stdout_map
    }
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    /// The states an observation through this operation can report.
    pub fn states(&self) -> BTreeSet<&str> {
        if self.stdout_map.is_empty() {
            self.exit.values().map(String::as_str).collect()
        } else {
            self.stdout_map.values().map(String::as_str).collect()
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedCatalog {
    id: String,
    version: String,
    sha256: String,
    ops: BTreeMap<String, VerifiedOp>,
}

impl VerifiedCatalog {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn op(&self, id: &str) -> Option<&VerifiedOp> {
        self.ops.get(id)
    }
    pub fn ops(&self) -> impl Iterator<Item = &VerifiedOp> {
        self.ops.values()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    Ident,
    /// Fills `port_spec` slots only.
    PortSpec,
    /// A single port (no range); fills `port_spec` slots only.
    PortSingle,
    Enum(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Want {
    State(String),
    /// The desired state is the value of this enum field.
    Field(String),
}

#[derive(Debug, Clone)]
pub struct Facet {
    name: String,
    observe: String,
    want: Want,
    ensure: BTreeMap<String, String>,
}

impl Facet {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn observe_op(&self) -> &str {
        &self.observe
    }
    pub fn want(&self) -> &Want {
        &self.want
    }
    pub fn ensure_op(&self, state: &str) -> Option<&str> {
        self.ensure.get(state).map(String::as_str)
    }
}

/// A plugin resource type. Only verification constructs it.
#[derive(Debug, Clone)]
pub struct ResourceType {
    name: String,
    fields: BTreeMap<String, FieldKind>,
    /// Field -> the shortest `max_len` of every slot it is bound to.
    operand_limit: BTreeMap<String, usize>,
    prechecks: Vec<(String, String)>,
    facets: Vec<Facet>,
    /// Refused combinations: a resource whose values equal every pair of
    /// one entry is refused before anything runs.
    deny: Vec<BTreeMap<String, String>>,
}

impl ResourceType {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn fields(&self) -> &BTreeMap<String, FieldKind> {
        &self.fields
    }
    pub fn prechecks(&self) -> &[(String, String)] {
        &self.prechecks
    }
    pub fn facets(&self) -> &[Facet] {
        &self.facets
    }

    /// Check a resource's `with` values against this type: exactly the
    /// declared fields, each a valid operand for every slot it fills. Error
    /// messages name the field, never the value (DESIGN §38.9).
    pub fn check_values(&self, values: &BTreeMap<String, String>) -> Result<()> {
        self.check_field_names(values.keys().map(String::as_str), &self.name)?;
        for (k, v) in values {
            self.check_field(k, v, &self.name)?;
        }
        self.check_deny(values, &self.name)
    }

    /// Refuse a combination the type denies (DESIGN §38.6). Called with
    /// every evaluated value before anything runs, and at load time when all
    /// values are literals. The message names the fields, never the values.
    pub fn check_deny(&self, values: &BTreeMap<String, String>, ctx: &str) -> Result<()> {
        for rule in &self.deny {
            if rule.iter().all(|(k, v)| values.get(k) == Some(v)) {
                let fields: Vec<&str> = rule.keys().map(String::as_str).collect();
                return Err(refuse(format!(
                    "{}: this combination of {} is refused by the plugin, because it could cut access to the host (the values are not shown)",
                    ctx,
                    fields.join(", ")
                )));
            }
        }
        Ok(())
    }

    /// The refused combinations, for inspection and tests.
    pub fn deny_rules(&self) -> &[BTreeMap<String, String>] {
        &self.deny
    }

    /// The given field names must be exactly the type's fields.
    pub fn check_field_names<'a>(
        &self,
        names: impl Iterator<Item = &'a str>,
        ctx: &str,
    ) -> Result<()> {
        let given: BTreeSet<&str> = names.collect();
        let declared: BTreeSet<&str> = self.fields.keys().map(String::as_str).collect();
        if let Some(extra) = given.difference(&declared).next() {
            return Err(refuse(format!("{}: unknown field {}", ctx, extra)));
        }
        if let Some(missing) = declared.difference(&given).next() {
            return Err(refuse(format!("{}: missing field {}", ctx, missing)));
        }
        Ok(())
    }

    /// One field's value: a valid operand of its class for every slot it
    /// fills (ident, port_spec) or one of the declared values (enum). The
    /// value is never shown.
    pub fn check_field(&self, field: &str, value: &str, ctx: &str) -> Result<()> {
        let limit = *self.operand_limit.get(field).unwrap_or(&MAX_OPERAND);
        let ok = match self.fields.get(field) {
            None => return Err(refuse(format!("{}: unknown field {}", ctx, field))),
            Some(FieldKind::Ident) => operand_ok(value, limit),
            Some(FieldKind::PortSpec) => port_spec_ok(value, limit),
            Some(FieldKind::PortSingle) => port_single_ok(value, limit),
            Some(FieldKind::Enum(allowed)) => allowed.iter().any(|a| a == value),
        };
        if !ok {
            return Err(refuse(format!(
                "{}: field {} is not a valid value for this type (the value is not shown)",
                ctx, field
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedPlugin {
    id: String,
    version: String,
    sha256: String,
    catalog: CatalogRef,
    types: BTreeMap<String, ResourceType>,
}

impl VerifiedPlugin {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn catalog(&self) -> &CatalogRef {
        &self.catalog
    }
    pub fn resource_type(&self, name: &str) -> Option<&ResourceType> {
        self.types.get(name)
    }
    pub fn resource_types(&self) -> impl Iterator<Item = &ResourceType> {
        self.types.values()
    }
}

// ---------------------------------------------------------------------------
// trust.toml
// ---------------------------------------------------------------------------

pub(crate) struct TrustIndex {
    pub catalogs: BTreeMap<(String, String), TrustedCatalog>,
    pub plugins: BTreeMap<(String, String), TrustedPlugin>,
}

pub(crate) fn verify_trust(bytes: &[u8], shown: &str) -> Result<TrustIndex> {
    let t: TrustFile = parse(bytes, shown)?;
    if t.catalog.len() > MAX_TRUST_ENTRIES || t.plugin.len() > MAX_TRUST_ENTRIES {
        return Err(refuse(format!("{}: too many entries", shown)));
    }
    let mut catalogs = BTreeMap::new();
    for c in t.catalog {
        if !id_ok(&c.id) || !version_ok(&c.version) || !sha_ok(&c.sha256) {
            return Err(refuse(format!(
                "{}: catalog entry needs a valid id, version and lowercase hex sha256",
                shown
            )));
        }
        let mut seen = BTreeSet::new();
        for op in c.attested_observe.iter().chain(c.allowed_mutate.iter()) {
            if !lower_ident(op, 64) {
                return Err(refuse(format!(
                    "{}: catalog {}: invalid operation id",
                    shown, c.id
                )));
            }
            if !seen.insert(op.clone()) {
                return Err(refuse(format!(
                    "{}: catalog {}: operation {} is listed more than once",
                    shown, c.id, op
                )));
            }
        }
        let key = (c.id.clone(), c.version.clone());
        if catalogs.insert(key, c).is_some() {
            return Err(refuse(format!("{}: duplicate catalog entry", shown)));
        }
    }
    let mut plugins = BTreeMap::new();
    for p in t.plugin {
        if !id_ok(&p.id) || !version_ok(&p.version) || !sha_ok(&p.sha256) {
            return Err(refuse(format!(
                "{}: plugin entry needs a valid id, version and lowercase hex sha256",
                shown
            )));
        }
        let key = (p.id.clone(), p.version.clone());
        if plugins.insert(key, p).is_some() {
            return Err(refuse(format!("{}: duplicate plugin entry", shown)));
        }
    }
    Ok(TrustIndex { catalogs, plugins })
}

// ---------------------------------------------------------------------------
// catalogs
// ---------------------------------------------------------------------------

fn parse_token(t: &str, after_dashdash: bool, op: &str) -> Result<ArgToken> {
    let bad = |why: &str| {
        refuse(format!(
            "operation {}: argv token {:?}: {}",
            op,
            t.escape_debug().to_string(),
            why
        ))
    };
    if !t.contains('{') && !t.contains('}') {
        if t.is_empty() || t.len() > MAX_LITERAL || !t.bytes().all(|c| c.is_ascii_graphic()) {
            return Err(bad(
                "a literal must be 1..=128 printable ASCII characters without spaces",
            ));
        }
        return Ok(ArgToken::Literal(t.to_string()));
    }
    let open = t.find('{').ok_or_else(|| bad("unbalanced braces"))?;
    if !t.ends_with('}') || t[open + 1..].contains('{') || t[..t.len() - 1].contains('}') {
        return Err(bad("a slot must be `{name}` at the end of the token"));
    }
    let slot = &t[open + 1..t.len() - 1];
    if !lower_ident(slot, 32) {
        return Err(bad("invalid slot name"));
    }
    if open == 0 {
        if !after_dashdash {
            return Err(bad("a whole-token slot must follow a literal \"--\""));
        }
        return Ok(ArgToken::Slot(slot.to_string()));
    }
    let prefix = &t[..open];
    let pb = prefix.as_bytes();
    let prefix_ok = pb.len() >= 4
        && prefix.starts_with("--")
        && prefix.ends_with('=')
        && pb[2].is_ascii_lowercase()
        && pb[2..pb.len() - 1]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
    if !prefix_ok {
        return Err(bad("a prefixed slot must look like `--option={name}`"));
    }
    Ok(ArgToken::Prefixed {
        prefix: prefix.to_string(),
        slot: slot.to_string(),
    })
}

fn template_ok(tmpl: &str, slots: &BTreeMap<String, usize>) -> bool {
    if tmpl.is_empty()
        || tmpl.len() > MAX_TEMPLATE
        || !tmpl.bytes().all(|c| c == b' ' || c.is_ascii_graphic())
    {
        return false;
    }
    let mut rest = tmpl;
    while let Some(i) = rest.find(['{', '}']) {
        if rest.as_bytes()[i] == b'}' {
            return false;
        }
        let Some(j) = rest[i..].find('}') else {
            return false;
        };
        let name = &rest[i + 1..i + j];
        if !slots.contains_key(name) {
            return false;
        }
        rest = &rest[i + j + 1..];
    }
    true
}

fn verify_op(d: &OpDef, trusted: &TrustedCatalog) -> Result<VerifiedOp> {
    if !lower_ident(&d.id, 64) {
        return Err(refuse("invalid operation id"));
    }
    let op = d.id.as_str();
    let class = match d.class.as_str() {
        "observe" => OpClass::Observe,
        "mutate" => OpClass::Mutate,
        _ => {
            return Err(refuse(format!(
                "operation {}: class must be observe or mutate",
                op
            )))
        }
    };
    if !program_ok(&d.program) {
        return Err(refuse(format!(
            "operation {}: program must be a permitted program directly under /usr/bin or /usr/sbin",
            op
        )));
    }
    if d.argv.len() > MAX_ARGV {
        return Err(refuse(format!(
            "operation {}: more than {} argv tokens",
            op, MAX_ARGV
        )));
    }
    let mut argv = Vec::with_capacity(d.argv.len());
    let mut after_dashdash = false;
    for t in &d.argv {
        let tok = parse_token(t, after_dashdash, op)?;
        if tok == ArgToken::Literal("--".to_string()) {
            if after_dashdash {
                return Err(refuse(format!(
                    "operation {}: \"--\" may appear only once",
                    op
                )));
            }
            after_dashdash = true;
        }
        argv.push(tok);
    }
    if d.slots.len() > MAX_SLOTS {
        return Err(refuse(format!(
            "operation {}: more than {} slots",
            op, MAX_SLOTS
        )));
    }
    let mut used = BTreeSet::new();
    for t in &argv {
        if let ArgToken::Slot(s) | ArgToken::Prefixed { slot: s, .. } = t {
            if !used.insert(s.clone()) {
                return Err(refuse(format!(
                    "operation {}: slot {} is used twice",
                    op, s
                )));
            }
        }
    }
    let declared: BTreeSet<String> = d.slots.keys().cloned().collect();
    if used != declared {
        return Err(refuse(format!(
            "operation {}: the slots used in argv and declared differ",
            op
        )));
    }
    let mut slots = BTreeMap::new();
    for (k, s) in &d.slots {
        let class = match (s.class.as_str(), s.max_len) {
            ("ident", 1..=MAX_OPERAND) => SlotClass::Ident,
            ("port_spec", 1..=MAX_PORT_SPEC) => SlotClass::PortSpec,
            _ => {
                return Err(refuse(format!(
                    "operation {}: slot {} must be class ident with max_len 1..=64 or class port_spec with max_len 1..=16",
                    op, k
                )))
            }
        };
        slots.insert(k.clone(), (class, s.max_len));
    }
    if d.timeout_secs == 0 || d.timeout_secs > MAX_TIMEOUT_SECS {
        return Err(refuse(format!(
            "operation {}: timeout_secs must be 1..=120",
            op
        )));
    }
    if d.exit.is_empty() || d.exit.len() > MAX_EXIT_ENTRIES {
        return Err(refuse(format!(
            "operation {}: the exit map needs 1..=16 entries",
            op
        )));
    }
    let mut exit = BTreeMap::new();
    for (k, v) in &d.exit {
        let code_ok = !k.is_empty()
            && k.len() <= 3
            && k.bytes().all(|c| c.is_ascii_digit())
            && (k == "0" || !k.starts_with('0'));
        let code: i32 = if code_ok { k.parse().unwrap_or(-1) } else { -1 };
        if !(0..=255).contains(&code) || !lower_ident(v, 32) {
            return Err(refuse(format!(
                "operation {}: exit map entries are 0..=255 -> state name",
                op
            )));
        }
        exit.insert(code, v.clone());
    }
    if d.stdout_map.len() > MAX_STDOUT_ENTRIES {
        return Err(refuse(format!(
            "operation {}: too many stdout_map entries",
            op
        )));
    }
    match class {
        OpClass::Mutate => {
            if exit.values().any(|v| v != "ok") {
                return Err(refuse(format!(
                    "operation {}: a mutate operation maps exit codes to \"ok\" only",
                    op
                )));
            }
            if !d.stdout_map.is_empty() {
                return Err(refuse(format!(
                    "operation {}: a mutate operation has no stdout_map",
                    op
                )));
            }
        }
        OpClass::Observe => {
            for t in &argv {
                if let ArgToken::Literal(l) | ArgToken::Prefixed { prefix: l, .. } = t {
                    let low = l.to_ascii_lowercase();
                    if MUTATING_OPTION_PREFIXES.iter().any(|p| low.starts_with(p))
                        || MUTATING_WORDS.contains(&low.as_str())
                    {
                        return Err(refuse(format!(
                            "operation {}: an observe operation carries the mutating-looking token {:?} (lint)",
                            op, l
                        )));
                    }
                }
            }
            if !d.stdout_map.is_empty() {
                if exit.values().any(|v| v != "ok") {
                    return Err(refuse(format!(
                        "operation {}: with stdout_map, every exit code maps to \"ok\"",
                        op
                    )));
                }
                let slot_limits: BTreeMap<String, usize> =
                    slots.iter().map(|(k, (_, m))| (k.clone(), *m)).collect();
                for (tmpl, state) in &d.stdout_map {
                    if !template_ok(tmpl, &slot_limits) || !lower_ident(state, 32) {
                        return Err(refuse(format!(
                            "operation {}: invalid stdout_map entry",
                            op
                        )));
                    }
                }
            }
        }
    }
    let enabled = match class {
        OpClass::Observe => trusted.attested_observe.contains(&d.id),
        OpClass::Mutate => trusted.allowed_mutate.contains(&d.id),
    };
    Ok(VerifiedOp {
        id: d.id.clone(),
        class,
        program: d.program.clone(),
        argv,
        slots,
        timeout_secs: d.timeout_secs,
        exit,
        stdout_map: d.stdout_map.clone(),
        enabled,
    })
}

pub(crate) fn verify_catalog(
    bytes: &[u8],
    sha256: &str,
    shown: &str,
    trusted: &TrustedCatalog,
    first_party: &[super::FirstPartyCatalog],
) -> Result<VerifiedCatalog> {
    if sha256 != trusted.sha256 {
        return Err(refuse(format!(
            "{}: does not match the sha256 pinned in the trust file",
            shown
        )));
    }
    if !first_party
        .iter()
        .any(|f| f.id == trusted.id && f.version == trusted.version && f.sha256 == sha256)
    {
        return Err(refuse(format!(
            "{}: not a reviewed first-party catalog of this Sinter (other catalogs are not supported)",
            shown
        )));
    }
    let c: CatalogFile = parse(bytes, shown)?;
    if c.id != trusted.id || c.version != trusted.version {
        return Err(refuse(format!(
            "{}: the file names a different catalog id or version",
            shown
        )));
    }
    if c.op.is_empty() || c.op.len() > MAX_OPS {
        return Err(refuse(format!(
            "{}: a catalog has 1..={} operations",
            shown, MAX_OPS
        )));
    }
    let mut ops = BTreeMap::new();
    for d in &c.op {
        let op = verify_op(d, trusted).map_err(|e| {
            refuse(format!(
                "{}: {}",
                shown,
                e.message.trim_start_matches("plugin: ")
            ))
        })?;
        if ops.insert(op.id.clone(), op).is_some() {
            return Err(refuse(format!("{}: duplicate operation {}", shown, d.id)));
        }
    }
    for (list, class) in [
        (&trusted.attested_observe, OpClass::Observe),
        (&trusted.allowed_mutate, OpClass::Mutate),
    ] {
        for id in list {
            match ops.get(id) {
                None => {
                    return Err(refuse(format!(
                        "{}: the trust file names operation {}, which the catalog does not define",
                        shown, id
                    )))
                }
                Some(op) if op.class != class => {
                    return Err(refuse(format!(
                        "{}: the trust file lists {} operation {} under the wrong class",
                        shown,
                        if op.class == OpClass::Observe {
                            "observe"
                        } else {
                            "mutate"
                        },
                        id
                    )))
                }
                Some(_) => {}
            }
        }
    }
    Ok(VerifiedCatalog {
        id: c.id,
        version: c.version,
        sha256: sha256.to_string(),
        ops,
    })
}

// ---------------------------------------------------------------------------
// plugins
// ---------------------------------------------------------------------------

/// An operation the catalog defines with this class and the trust file
/// enables (attested observe or allowed mutate).
fn usable<'a>(
    catalog: &'a VerifiedCatalog,
    id: &str,
    class: OpClass,
    ctx: &str,
) -> Result<&'a VerifiedOp> {
    let op = defined(catalog, id, class, ctx)?;
    if !op.enabled {
        return Err(refuse(format!(
            "{}: operation {} is not {} in the trust file",
            ctx,
            id,
            if class == OpClass::Observe {
                "attested"
            } else {
                "allowed"
            }
        )));
    }
    Ok(op)
}

/// An operation the catalog defines with this class, enabled or not.
fn defined<'a>(
    catalog: &'a VerifiedCatalog,
    id: &str,
    class: OpClass,
    ctx: &str,
) -> Result<&'a VerifiedOp> {
    let op = catalog.ops.get(id).ok_or_else(|| {
        refuse(format!(
            "{}: operation {} is not in catalog {}",
            ctx, id, catalog.id
        ))
    })?;
    if op.class != class {
        return Err(refuse(format!(
            "{}: operation {} is {} operation; {} operation is required here",
            ctx,
            id,
            if op.class == OpClass::Observe {
                "an observe"
            } else {
                "a mutate"
            },
            if class == OpClass::Observe {
                "an observe"
            } else {
                "a mutate"
            }
        )));
    }
    Ok(op)
}

pub(crate) fn verify_plugin(
    bytes: &[u8],
    sha256: &str,
    shown: &str,
    trusted: &TrustedPlugin,
    catalogs: &BTreeMap<(String, String), VerifiedCatalog>,
) -> Result<VerifiedPlugin> {
    if sha256 != trusted.sha256 {
        return Err(refuse(format!(
            "{}: does not match the sha256 pinned in the trust file",
            shown
        )));
    }
    let p: PluginFile = parse(bytes, shown)?;
    if p.id != trusted.id || p.version != trusted.version {
        return Err(refuse(format!(
            "{}: the file names a different plugin id or version",
            shown
        )));
    }
    let catalog = catalogs
        .get(&(p.catalog.id.clone(), p.catalog.version.clone()))
        .ok_or_else(|| refuse(format!("{}: its catalog is not trusted", shown)))?;
    if p.types.is_empty() || p.types.len() > MAX_TYPES {
        return Err(refuse(format!(
            "{}: a plugin defines 1..={} types",
            shown, MAX_TYPES
        )));
    }
    let mut types = BTreeMap::new();
    for t in p.types {
        let ctx = format!("{}: type {}", shown, t.name.escape_debug());
        let suffix = t.name.strip_prefix(&format!("{}.", p.id)).unwrap_or("");
        if !lower_ident(suffix, 32) || BUILTIN_RESOURCE_TYPES.contains(&t.name.as_str()) {
            return Err(refuse(format!(
                "{}: a type name must be `{}.<name>`",
                ctx, p.id
            )));
        }
        if t.fields.is_empty() || t.fields.len() > MAX_FIELDS {
            return Err(refuse(format!("{}: 1..={} fields", ctx, MAX_FIELDS)));
        }
        let mut fields = BTreeMap::new();
        for (name, f) in &t.fields {
            if !lower_ident(name, 32) {
                return Err(refuse(format!("{}: invalid field name", ctx)));
            }
            let kind = match (f.kind.as_str(), f.values.is_empty()) {
                ("ident", true) => FieldKind::Ident,
                ("port_spec", true) => FieldKind::PortSpec,
                ("port_single", true) => FieldKind::PortSingle,
                ("enum", false) => {
                    let set: BTreeSet<&String> = f.values.iter().collect();
                    if f.values.len() > MAX_ENUM_VALUES
                        || set.len() != f.values.len()
                        || !f.values.iter().all(|v| lower_ident(v, 32))
                    {
                        return Err(refuse(format!(
                            "{}: field {}: enum values are 1..=16 distinct names",
                            ctx, name
                        )));
                    }
                    FieldKind::Enum(f.values.clone())
                }
                _ => {
                    return Err(refuse(format!(
                        "{}: field {}: kind is ident, port_spec or port_single (no values) or enum (values)",
                        ctx, name
                    )))
                }
            };
            fields.insert(name.clone(), kind);
        }
        if t.precheck.len() > MAX_PRECHECKS {
            return Err(refuse(format!(
                "{}: more than {} prechecks",
                ctx, MAX_PRECHECKS
            )));
        }
        let mut referenced: Vec<&VerifiedOp> = Vec::new();
        let mut prechecks = Vec::new();
        for pc in &t.precheck {
            let op = usable(catalog, &pc.op, OpClass::Observe, &ctx)?;
            if !op.states().contains(pc.expect.as_str()) {
                return Err(refuse(format!(
                    "{}: precheck {} expects a state it cannot report",
                    ctx, pc.op
                )));
            }
            referenced.push(op);
            prechecks.push((pc.op.clone(), pc.expect.clone()));
        }
        if t.facet.is_empty() || t.facet.len() > MAX_FACETS {
            return Err(refuse(format!("{}: 1..={} facets", ctx, MAX_FACETS)));
        }
        let mut facet_names = BTreeSet::new();
        let mut facets = Vec::new();
        for f in &t.facet {
            if !lower_ident(&f.name, 32) || !facet_names.insert(f.name.clone()) {
                return Err(refuse(format!("{}: facet names are distinct names", ctx)));
            }
            let fctx = format!("{} facet {}", ctx, f.name);
            let observe = usable(catalog, &f.observe, OpClass::Observe, &fctx)?;
            referenced.push(observe);
            let states = observe.states();
            let (want, wanted): (Want, Vec<String>) = match f.want.strip_prefix("field:") {
                Some(field) => match fields.get(field) {
                    Some(FieldKind::Enum(values)) => {
                        (Want::Field(field.to_string()), values.clone())
                    }
                    _ => {
                        return Err(refuse(format!(
                            "{}: want field:<name> must name an enum field",
                            fctx
                        )))
                    }
                },
                None => (Want::State(f.want.clone()), vec![f.want.clone()]),
            };
            for w in &wanted {
                if !states.contains(w.as_str()) {
                    return Err(refuse(format!(
                        "{}: wants a state its observation cannot report",
                        fctx
                    )));
                }
                if !f.ensure.contains_key(w) {
                    return Err(refuse(format!(
                        "{}: no ensure operation for a wanted state",
                        fctx
                    )));
                }
            }
            let mut ensure = BTreeMap::new();
            for (state, op_id) in &f.ensure {
                if !states.contains(state.as_str()) {
                    return Err(refuse(format!(
                        "{}: ensure names a state its observation cannot report",
                        fctx
                    )));
                }
                // A mutate operation the trust file does not allow keeps the
                // type loadable for observation (C1, DESIGN §38.4): it must
                // still be a mutate operation of the catalog and is verified
                // like any other, but it stays disabled. plan and apply refuse
                // a resource that could need it before anything is contacted
                // (`run::require_allowed_mutations`), and the mutate channel
                // refuses it again (`MutateCall::new`).
                let op = defined(catalog, op_id, OpClass::Mutate, &fctx)?;
                referenced.push(op);
                ensure.insert(state.clone(), op_id.clone());
            }
            facets.push(Facet {
                name: f.name.clone(),
                observe: f.observe.clone(),
                want,
                ensure,
            });
        }
        // Every slot of every referenced operation is filled by the field of
        // the same name; a field's operands must fit the shortest slot.
        // The field's kind must match the class of every slot it fills: an
        // ident or enum field fills ident slots, a port_spec or port_single
        // field fills port_spec slots.
        let mut operand_limit: BTreeMap<String, usize> = BTreeMap::new();
        for op in &referenced {
            for (slot, (class, max)) in &op.slots {
                let Some(kind) = fields.get(slot) else {
                    return Err(refuse(format!(
                        "{}: operation {} slot {} is not filled by a field",
                        ctx, op.id, slot
                    )));
                };
                let matches = match class {
                    SlotClass::Ident => matches!(kind, FieldKind::Ident | FieldKind::Enum(_)),
                    SlotClass::PortSpec => {
                        matches!(kind, FieldKind::PortSpec | FieldKind::PortSingle)
                    }
                };
                if !matches {
                    return Err(refuse(format!(
                        "{}: field {}: its kind does not match the class of slot {} in operation {}",
                        ctx, slot, slot, op.id
                    )));
                }
                let e = operand_limit.entry(slot.to_string()).or_insert(*max);
                *e = (*e).min(*max);
            }
        }
        for (name, kind) in &fields {
            if let (FieldKind::Enum(values), Some(max)) = (kind, operand_limit.get(name)) {
                if !values.iter().all(|v| operand_ok(v, *max)) {
                    return Err(refuse(format!(
                        "{}: field {}: an enum value does not fit its slot",
                        ctx, name
                    )));
                }
            }
        }
        let mut rt = ResourceType {
            name: t.name.clone(),
            fields,
            operand_limit,
            prechecks,
            facets,
            deny: Vec::new(),
        };
        // Refused combinations: each names declared fields with values the
        // type would otherwise accept, so a rule can only tighten.
        if t.deny.len() > MAX_DENY {
            return Err(refuse(format!(
                "{}: more than {} deny entries",
                ctx, MAX_DENY
            )));
        }
        for rule in &t.deny {
            if rule.is_empty() {
                return Err(refuse(format!("{}: a deny entry names no field", ctx)));
            }
            for (field, value) in rule {
                rt.check_field(field, value, &format!("{} deny entry", ctx))?;
            }
            rt.deny.push(rule.clone());
        }
        if types.insert(t.name.clone(), rt).is_some() {
            return Err(refuse(format!("{}: defined twice", ctx)));
        }
    }
    Ok(VerifiedPlugin {
        id: p.id,
        version: p.version,
        sha256: sha256.to_string(),
        catalog: p.catalog,
        types,
    })
}
