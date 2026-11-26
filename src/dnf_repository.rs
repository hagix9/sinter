//! `dnf_repository`: the declared keys of one `[id]` section of a `.repo`
//! file under `/etc/yum.repos.d/`.
//!
//! Pure: field rules, value rules and the decision what to write. The
//! decision is made from the repository file alone (read by
//! [`crate::inifile`]); no DNF command is consulted. Three rules keep
//! package signature checking from being weakened through this type:
//!
//! * `gpgcheck: false` and `repo_gpgcheck: false` are not accepted, so
//!   Sinter never writes `gpgcheck=0`;
//! * a section Sinter creates always gets `gpgcheck=1`;
//! * an edit that enables a repository, or writes one of its package
//!   sources (`baseurl`, `mirrorlist`, `metalink`), is refused unless the
//!   section has an explicit true `gpgcheck` afterwards.
//!
//! No message built here quotes a declared value or file content: both can
//! hold credentials.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Result, SinterError};
use crate::inifile::{self, Doc, Section};
use crate::value::Value;

/// The `with` fields of a `dnf_repository`.
pub const FIELDS: &[&str] = &[
    "name",
    "state",
    "file",
    "description",
    "baseurl",
    "mirrorlist",
    "metalink",
    "enabled",
    "gpgcheck",
    "repo_gpgcheck",
    "gpgkey",
];

/// The fields that become keys of the section (everything but the
/// identifiers and `state`).
const KEY_FIELDS: &[&str] = &[
    "description",
    "baseurl",
    "mirrorlist",
    "metalink",
    "enabled",
    "gpgcheck",
    "repo_gpgcheck",
    "gpgkey",
];

/// The section keys this type can manage, in the order a new section gets
/// them.
const MANAGED_KEYS: [&str; 8] = [
    "name",
    "baseurl",
    "mirrorlist",
    "metalink",
    "enabled",
    "gpgcheck",
    "repo_gpgcheck",
    "gpgkey",
];

/// The only directory a repository file may be in.
pub const REPO_DIR: &str = "/etc/yum.repos.d";

const MAX_URL_BYTES: usize = 2048;
const MAX_LIST_ENTRIES: usize = 32;
const MAX_DESCRIPTION_BYTES: usize = 256;

/// A repository id: `[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}`.
pub fn valid_repo_id(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && s.len() <= 64
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

/// The file a repository is managed in when `file` is not declared.
pub fn default_file(name: &str) -> String {
    format!("{}/{}.repo", REPO_DIR, name)
}

/// A repository file path: directly inside [`REPO_DIR`], a plain name that
/// ends in `.repo` (no subdirectory, no `..`, no hidden file).
pub fn valid_repo_file(path: &str) -> bool {
    let Some(base) = path
        .strip_prefix(REPO_DIR)
        .and_then(|r| r.strip_prefix('/'))
    else {
        return false;
    };
    let mut chars = base.chars();
    base.len() <= 255
        && base.len() > ".repo".len()
        && base.ends_with(".repo")
        && matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '+' | '-'))
}

/// The text written as the section's `name` key: one line of printable
/// characters without leading or trailing space.
///
/// Besides control characters, the Unicode line and paragraph separators
/// (a reader might end the line there) and the bidirectional controls (the
/// line would be displayed in another order than it is stored) are refused.
pub fn valid_description(s: &str) -> bool {
    let unsafe_char = |c: char| {
        c.is_control()
            || matches!(
                c,
                '\u{0085}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
            )
    };
    !s.is_empty()
        && s.len() <= MAX_DESCRIPTION_BYTES
        && !s.chars().any(unsafe_char)
        && s.trim() == s
}

/// What a URL field is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlKind {
    /// `baseurl`, `mirrorlist`, `metalink`.
    Source,
    /// `gpgkey`.
    Key,
}

/// Check one URL value. The refusal names the rule, never the value.
pub fn check_url(s: &str, kind: UrlKind, in_list: bool) -> std::result::Result<(), &'static str> {
    if s.is_empty() {
        return Err("must not be empty");
    }
    if s.len() > MAX_URL_BYTES {
        return Err("is longer than 2048 bytes");
    }
    if !s.chars().all(|c| c.is_ascii_graphic()) {
        return Err(
            "may hold only printable ASCII without spaces (no whitespace, control character or line break)",
        );
    }
    if s.contains('\\') {
        return Err("may not contain a backslash");
    }
    if in_list && s.contains(',') {
        return Err("may not contain a comma (DNF splits a list value at commas)");
    }
    let rest = if let Some(r) = s.strip_prefix("https://") {
        Some(r)
    } else if let Some(r) = s.strip_prefix("http://") {
        if kind == UrlKind::Key {
            return Err(
                "must be a file:/// or https:// URL (a key fetched over http:// would make an unauthenticated channel the trust root)",
            );
        }
        Some(r)
    } else if s.starts_with("file:///") {
        None
    } else {
        return Err(match kind {
            UrlKind::Source => "must start with https://, http:// or file:///",
            UrlKind::Key => "must start with file:/// or https://",
        });
    };
    if let Some(rest) = rest {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.contains('@') {
            return Err(
                "contains credentials (user or user:password before the host); credentials in repository URLs are not supported",
            );
        }
        if authority.is_empty() {
            return Err("has no host");
        }
    }
    Ok(())
}

/// A checked `dnf_repository` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSpec {
    pub name: String,
    pub file: String,
    pub absent: bool,
    pub description: Option<String>,
    pub baseurl: Option<Vec<String>>,
    pub mirrorlist: Option<String>,
    pub metalink: Option<String>,
    pub enabled: Option<bool>,
    /// `Some(true)` or undeclared; `false` is refused.
    pub gpgcheck: Option<bool>,
    /// `Some(true)` or undeclared; `false` is refused.
    pub repo_gpgcheck: Option<bool>,
    pub gpgkey: Option<Vec<String>>,
}

fn interpolated(v: &Value) -> bool {
    matches!(v, Value::Str(s) if crate::expressions::has_interpolation(s))
}

fn bad(ctx: &str, msg: &str) -> SinterError {
    SinterError::schema(format!("{}: dnf_repository {}", ctx, msg))
}

const NEVER_OFF: &str =
    "Sinter never writes gpgcheck=0 or repo_gpgcheck=0; leave the field out to \
     keep the file's value, and manage a repository that is not signature-checked as a file \
     resource with your own content";

/// Check a resolved static identifier: `name` (the repository id) or
/// `file` (the repository file).
pub fn check_identifier(key: &str, value: &str, ctx: &str) -> Result<()> {
    if key == "file" {
        if !valid_repo_file(value) {
            return Err(bad(
                ctx,
                "file must be an absolute path directly inside /etc/yum.repos.d/ that ends in \
                 .repo (a plain file name, no subdirectory)",
            ));
        }
        return Ok(());
    }
    if value == "main" {
        return Err(bad(
            ctx,
            "name main is not a repository: [main] is DNF's own configuration section",
        ));
    }
    if !valid_repo_id(value) {
        return Err(bad(
            ctx,
            "name is not a valid repository id ([A-Za-z0-9][A-Za-z0-9_.:-]{0,63})",
        ));
    }
    Ok(())
}

impl RepoSpec {
    /// Check the fields. With `literal_only`, a field that still holds an
    /// interpolation is accepted unchecked and `Ok(None)` is returned; it is
    /// checked once evaluated (`literal_only = false`).
    pub fn check(
        map: &BTreeMap<String, Value>,
        ctx: &str,
        literal_only: bool,
    ) -> Result<Option<RepoSpec>> {
        for k in map.keys() {
            if !FIELDS.contains(&k.as_str()) {
                return Err(bad(ctx, &format!("has unknown field {}", k)));
            }
        }
        let mut deferred = false;
        let mut text = |key: &str| -> Result<Option<String>> {
            match map.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(v) if literal_only && interpolated(v) => {
                    deferred = true;
                    Ok(None)
                }
                Some(Value::Str(s)) => Ok(Some(s.clone())),
                Some(other) => Err(bad(
                    ctx,
                    &format!("{} must be a string, got {}", key, other.type_name()),
                )),
            }
        };
        let name = text("name")?;
        let file = text("file")?;
        let state = text("state")?;
        let description = text("description")?;
        let mirrorlist = text("mirrorlist")?;
        let metalink = text("metalink")?;
        let state_deferred = matches!(map.get("state"), Some(v) if literal_only && interpolated(v));

        if !matches!(map.get("name"), Some(v) if !matches!(v, Value::Null)) {
            return Err(bad(ctx, "requires name"));
        }
        if let Some(n) = &name {
            check_identifier("name", n, ctx)?;
        }
        if let Some(f) = &file {
            check_identifier("file", f, ctx)?;
        }
        let absent = match state.as_deref() {
            None | Some("present") => false,
            Some("absent") => true,
            Some(_) => return Err(bad(ctx, "state must be present or absent")),
        };
        if let Some(d) = &description {
            if !valid_description(d) {
                return Err(bad(
                    ctx,
                    "description must be one line of 1-256 bytes without control characters, \
                     Unicode line or paragraph separators or bidirectional controls, and \
                     without leading or trailing space",
                ));
            }
        }
        for (key, v) in [("mirrorlist", &mirrorlist), ("metalink", &metalink)] {
            if let Some(u) = v {
                check_url(u, UrlKind::Source, false)
                    .map_err(|why| bad(ctx, &format!("{} {}", key, why)))?;
            }
        }
        let mut list = |key: &str, kind: UrlKind| -> Result<Option<Vec<String>>> {
            let shape = || {
                bad(
                    ctx,
                    &format!("{} must be a string or a list of strings", key),
                )
            };
            let items: Vec<&Value> = match map.get(key) {
                None | Some(Value::Null) => return Ok(None),
                Some(v @ Value::Str(_)) => vec![v],
                Some(Value::List(items)) => {
                    if items.is_empty() {
                        return Err(bad(ctx, &format!("{} must not be an empty list", key)));
                    }
                    if items.len() > MAX_LIST_ENTRIES {
                        return Err(bad(
                            ctx,
                            &format!("{} has more than {} entries", key, MAX_LIST_ENTRIES),
                        ));
                    }
                    items.iter().collect()
                }
                Some(_) => return Err(shape()),
            };
            let mut out = Vec::new();
            for v in items {
                match v {
                    v if literal_only && interpolated(v) => deferred = true,
                    Value::Str(s) => {
                        check_url(s, kind, true)
                            .map_err(|why| bad(ctx, &format!("{} {}", key, why)))?;
                        out.push(s.clone());
                    }
                    _ => return Err(shape()),
                }
            }
            Ok(Some(out))
        };
        let baseurl = list("baseurl", UrlKind::Source)?;
        let gpgkey = list("gpgkey", UrlKind::Key)?;
        let mut boolean = |key: &str| -> Result<Option<bool>> {
            match map.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Bool(b)) => Ok(Some(*b)),
                Some(v) if literal_only && interpolated(v) => {
                    deferred = true;
                    Ok(None)
                }
                Some(_) => Err(bad(ctx, &format!("{} must be a boolean", key))),
            }
        };
        let enabled = boolean("enabled")?;
        let gpgcheck = boolean("gpgcheck")?;
        let repo_gpgcheck = boolean("repo_gpgcheck")?;
        for (key, v) in [("gpgcheck", gpgcheck), ("repo_gpgcheck", repo_gpgcheck)] {
            if v == Some(false) {
                return Err(bad(
                    ctx,
                    &format!("{}: false is not accepted: {}", key, NEVER_OFF),
                ));
            }
        }
        let declared = |k: &str| matches!(map.get(k), Some(v) if !matches!(v, Value::Null));
        if absent {
            if let Some(other) = KEY_FIELDS.iter().find(|k| declared(k)) {
                return Err(bad(
                    ctx,
                    &format!("state absent allows only name and file, not {}", other),
                ));
            }
        } else if !state_deferred && !KEY_FIELDS.iter().any(|k| declared(k)) {
            return Err(bad(
                ctx,
                "declares nothing to manage: set at least one of description, baseurl, \
                 mirrorlist, metalink, enabled, gpgcheck, repo_gpgcheck, gpgkey (or state: absent)",
            ));
        }
        if deferred {
            return Ok(None);
        }
        let name = name.ok_or_else(|| bad(ctx, "requires name"))?;
        let file = file.unwrap_or_else(|| default_file(&name));
        Ok(Some(RepoSpec {
            name,
            file,
            absent,
            description,
            baseurl,
            mirrorlist,
            metalink,
            enabled,
            gpgcheck,
            repo_gpgcheck,
            gpgkey,
        }))
    }

    /// Whether a package source is declared (needed to create a section).
    fn declares_source(&self) -> bool {
        self.baseurl.is_some() || self.mirrorlist.is_some() || self.metalink.is_some()
    }

    /// The declared keys as `(section key, values, is a list)`, in the order
    /// a new section gets them.
    fn declared_keys(&self) -> Vec<(&'static str, Vec<String>, bool)> {
        let flag = |b: bool| vec![if b { "1" } else { "0" }.to_string()];
        let mut out = Vec::new();
        if let Some(d) = &self.description {
            out.push(("name", vec![d.clone()], false));
        }
        if let Some(b) = &self.baseurl {
            out.push(("baseurl", b.clone(), true));
        }
        if let Some(m) = &self.mirrorlist {
            out.push(("mirrorlist", vec![m.clone()], false));
        }
        if let Some(m) = &self.metalink {
            out.push(("metalink", vec![m.clone()], false));
        }
        if let Some(e) = self.enabled {
            out.push(("enabled", flag(e), false));
        }
        if let Some(g) = self.gpgcheck {
            out.push(("gpgcheck", flag(g), false));
        }
        if let Some(g) = self.repo_gpgcheck {
            out.push(("repo_gpgcheck", flag(g), false));
        }
        if let Some(k) = &self.gpgkey {
            out.push(("gpgkey", k.clone(), true));
        }
        out
    }
}

impl RepoSpec {
    /// The declared keys as `field: value` lines (a list as its entries
    /// separated by one space), for the display of a section that is
    /// created. Declared values only: nothing of the file.
    pub(crate) fn declared_lines(&self) -> Vec<String> {
        self.declared_keys()
            .into_iter()
            .map(|(key, values, _)| format!("{}: {}", field_of(key), values.join(" ")))
            .collect()
    }
}

/// A boolean as a repository file states it: `1`, `true`, `yes` and `0`,
/// `false`, `no` in any letter case. Anything else (also `on`/`off`, an
/// empty or multi-line value) is not a usable state.
pub fn observed_bool(text: &str) -> Option<bool> {
    match text.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

/// One declared key that differs from the file: `(field, observed, desired)`.
/// The field is the `with` field name, or `state` for a missing or present
/// section.
pub type Drift = (String, String, String);

/// What a `dnf_repository` means for the file as it is now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Empty when the section is as declared.
    pub drift: Vec<Drift>,
    /// The whole new file, when it has to change.
    pub new_content: Option<String>,
    pub notes: Vec<String>,
    /// The existing file holds credentials: nothing of it may be shown.
    pub credentials: bool,
}

/// Said when a repository that is not disabled has no explicit true
/// `gpgcheck` and the resource does not change that.
pub const NOTE_UNCHECKED: &str = "package signature checking is not on for this repository: its section has no gpgcheck=1; Sinter leaves that as it is (declare gpgcheck: true to turn it on)";

const NOT_SET: &str = "(not set)";

fn field_of(key: &str) -> &str {
    if key == "name" {
        "description"
    } else {
        key
    }
}

/// The file's lines and the repository's section, read strictly.
fn read<'a>(
    spec: &RepoSpec,
    text: &'a str,
) -> std::result::Result<(Doc<'a>, Option<Section>), String> {
    let refused = |e: inifile::IniError| format!("{} is not read: {}", spec.file, e.0);
    let doc = Doc::parse(text).map_err(refused)?;
    let section = doc.section(&spec.name).map_err(refused)?;
    if let Some(sec) = &section {
        // A key that differs from a managed key only in letter case would
        // make it unclear which of the two a reader uses.
        for k in &sec.keys {
            if MANAGED_KEYS
                .iter()
                .any(|m| *m != k.name && m.eq_ignore_ascii_case(&k.name))
            {
                return Err(format!(
                    "{} is not read: section [{}] has a key that differs from a key Sinter \
                     manages only in letter case (line {})",
                    spec.file,
                    spec.name,
                    k.first + 1
                ));
            }
        }
    }
    Ok((doc, section))
}

/// The declared keys that differ from the section: the drift and what to
/// write. Booleans are compared by meaning, lists as sequences of entries,
/// everything else as text.
fn compare(spec: &RepoSpec, sec: &Section) -> (Vec<Drift>, Vec<(String, Vec<String>)>) {
    let mut drift = Vec::new();
    let mut sets = Vec::new();
    for (key, values, is_list) in spec.declared_keys() {
        let found = sec.get(key);
        let same = match found {
            None => false,
            Some(k) if is_list => k.entries() == values,
            Some(k) if matches!(key, "enabled" | "gpgcheck" | "repo_gpgcheck") => {
                observed_bool(&k.text()) == Some(values[0] == "1")
            }
            Some(k) => k.text() == values[0],
        };
        if same {
            continue;
        }
        let observed = match found {
            None => NOT_SET.to_string(),
            Some(k) if is_list => k.entries().join(" "),
            Some(k) => k.text().replace('\n', " "),
        };
        drift.push((field_of(key).to_string(), observed, values.join(" ")));
        sets.push((key.to_string(), values));
    }
    (drift, sets)
}

fn flag(sec: &Section, key: &str) -> Option<bool> {
    sec.get(key).and_then(|k| observed_bool(&k.text()))
}

/// The read-only comparison for audit: drift per declared key, `state` for
/// a section that is missing or should be gone. Nothing is decided about a
/// change, so the rules that refuse an edit do not apply; a file that
/// cannot be read with certainty is still a refusal.
pub fn audit(spec: &RepoSpec, existing: Option<&str>) -> std::result::Result<Decision, String> {
    let text = existing.unwrap_or("");
    let (_, section) = read(spec, text)?;
    let mut d = Decision {
        drift: Vec::new(),
        new_content: None,
        notes: Vec::new(),
        credentials: inifile::has_credentials(text),
    };
    let state = |observed: &str, desired: &str| {
        (
            "state".to_string(),
            observed.to_string(),
            desired.to_string(),
        )
    };
    match (&section, spec.absent) {
        (Some(_), true) => d.drift.push(state("present", "absent")),
        (None, true) => {}
        (None, false) => d.drift.push(state(
            if existing.is_some() {
                "absent"
            } else {
                "absent (the file does not exist)"
            },
            "present",
        )),
        (Some(sec), false) => {
            d.drift = compare(spec, sec).0;
            if spec.gpgcheck.is_none()
                && flag(sec, "gpgcheck") != Some(true)
                && flag(sec, "enabled") != Some(false)
            {
                d.notes.push(NOTE_UNCHECKED.to_string());
            }
        }
    }
    Ok(d)
}

/// Decide from the file alone (`None`: the file does not exist) what the
/// declaration requires. A refusal is text that names rules, line numbers,
/// the repository id and the file path only.
pub fn decide(spec: &RepoSpec, existing: Option<&str>) -> std::result::Result<Decision, String> {
    let text = existing.unwrap_or("");
    let credentials = inifile::has_credentials(text);
    let (doc, section) = read(spec, text)?;
    let mut d = Decision {
        drift: Vec::new(),
        new_content: None,
        notes: Vec::new(),
        credentials,
    };
    if spec.absent {
        if let Some(sec) = &section {
            d.drift
                .push(("state".into(), "present".into(), "absent".into()));
            d.new_content = Some(doc.remove_section(sec));
        }
        return Ok(d);
    }
    let Some(sec) = section else {
        return create(spec, &doc, existing.is_some(), d);
    };
    edit(spec, &doc, &sec, d)
}

fn create(
    spec: &RepoSpec,
    doc: &Doc,
    file_exists: bool,
    mut d: Decision,
) -> std::result::Result<Decision, String> {
    if !spec.declares_source() {
        return Err(format!(
            "the repository {} is not defined in {}{}; set file to the file that defines the \
             repository (for example the distribution's own .repo file), or declare baseurl, \
             mirrorlist or metalink to define it here",
            spec.name,
            spec.file,
            if file_exists {
                ""
            } else {
                " (the file does not exist)"
            }
        ));
    }
    // A new section is always signature-checked and, unless declared
    // otherwise, enabled. The keys come in one fixed order.
    let declared: BTreeMap<&str, Vec<String>> = spec
        .declared_keys()
        .into_iter()
        .map(|(key, values, _)| (key, values))
        .collect();
    let mut keys: Vec<(String, Vec<String>)> = Vec::new();
    for key in MANAGED_KEYS {
        match declared.get(key) {
            Some(values) => keys.push((key.to_string(), values.clone())),
            None if matches!(key, "enabled" | "gpgcheck") => {
                keys.push((key.to_string(), vec!["1".to_string()]))
            }
            None => {}
        }
    }
    d.drift
        .push(("state".into(), "absent".into(), "present".into()));
    d.new_content = Some(doc.append_section(&spec.name, &keys));
    Ok(d)
}

fn edit(
    spec: &RepoSpec,
    doc: &Doc,
    sec: &Section,
    mut d: Decision,
) -> std::result::Result<Decision, String> {
    let (drift, sets) = compare(spec, sec);
    d.drift = drift;
    let enabled_now = flag(sec, "enabled");
    let enabled_after = spec.enabled.or(enabled_now);
    let checked_after = spec.gpgcheck == Some(true) || flag(sec, "gpgcheck") == Some(true);
    let enables = spec.enabled == Some(true) && enabled_now != Some(true);
    let writes_source = sets
        .iter()
        .any(|(k, _)| matches!(k.as_str(), "baseurl" | "mirrorlist" | "metalink"));
    if !checked_after && (enables || writes_source) {
        return Err(format!(
            "refusing to {} the repository {} in {}: its section has no gpgcheck=1; declare \
             gpgcheck: true; Sinter does not enable a repository whose packages are not \
             signature-checked",
            if enables {
                "enable"
            } else {
                "change the package source of"
            },
            spec.name,
            spec.file
        ));
    }
    // Not Sinter's decision: a repository that is not disabled and not
    // explicitly signature-checked, which this resource leaves that way.
    if !checked_after && enabled_after != Some(false) {
        d.notes.push(NOTE_UNCHECKED.to_string());
    }
    if !sets.is_empty() {
        d.new_content = Some(doc.set_keys(sec, &sets));
    }
    Ok(d)
}

/// Which repositories and repository files the `dnf_repository` resources
/// of one recipe have claimed so far.
#[derive(Debug, Default)]
pub(crate) struct Owners {
    names: BTreeMap<String, String>,
    files: BTreeSet<String>,
}

/// Record that resource `id` manages repository `name` in `file`, and say
/// when that conflicts with an earlier resource: a second `dnf_repository`
/// with the same name, or a `file`, `template`, `link` or `directory` (or
/// any other path owner) on the same path. Several repositories in one file
/// are allowed. Returns `(own field, other resource, message)`.
///
/// The file is entered into `path_owner`, so a path resource declared later
/// on the same path meets the ordinary path conflict.
pub(crate) fn claim(
    owners: &mut Owners,
    path_owner: &mut BTreeMap<String, String>,
    name: &str,
    file: &str,
    id: &str,
) -> Option<(&'static str, String, String)> {
    if let Some(prev) = owners.names.insert(name.to_string(), id.to_string()) {
        return Some((
            "name",
            prev.clone(),
            format!(
                "conflicting ownership of DNF repository {:?} by resources {} and {}",
                name, prev, id
            ),
        ));
    }
    if !owners.files.contains(file) {
        if let Some(prev) = path_owner.get(file) {
            return Some((
                "file",
                prev.clone(),
                format!(
                    "conflicting ownership of path {} by resources {} and {} (a dnf_repository \
                     edits one section of that file; another resource manages the whole path)",
                    file, prev, id
                ),
            ));
        }
        owners.files.insert(file.to_string());
    }
    path_owner.insert(file.to_string(), id.to_string());
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Value {
        Value::Str(v.to_string())
    }

    fn map(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn spec(pairs: &[(&str, Value)]) -> RepoSpec {
        let mut all = vec![("name", s("example"))];
        all.extend(pairs.iter().cloned());
        RepoSpec::check(&map(&all), "r", false).unwrap().unwrap()
    }

    fn err(pairs: &[(&str, Value)]) -> String {
        RepoSpec::check(&map(pairs), "r", true).unwrap_err().message
    }

    const URL: &str = "https://repo.example.invalid/el$releasever/$basearch/";
    const KEY: &str = "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-example";

    #[test]
    fn ids_and_files() {
        for ok in [
            "crb",
            "a",
            "epel-testing",
            "pgdg17",
            "Repo_1.2:x",
            &"a".repeat(64),
        ] {
            assert!(valid_repo_id(ok), "{ok}");
        }
        for no in [
            "",
            "-x",
            ".x",
            "_x",
            "a b",
            "a/b",
            "a]",
            "a\n",
            "é",
            &"a".repeat(65),
        ] {
            assert!(!valid_repo_id(no), "{no:?}");
        }
        assert_eq!(default_file("crb"), "/etc/yum.repos.d/crb.repo");
        for ok in [
            "/etc/yum.repos.d/rocky.repo",
            "/etc/yum.repos.d/a-b_c.1+x.repo",
        ] {
            assert!(valid_repo_file(ok), "{ok}");
        }
        for no in [
            "/etc/yum.repos.d/.repo",
            "/etc/yum.repos.d/.hidden.repo",
            "/etc/yum.repos.d/sub/x.repo",
            "/etc/yum.repos.d/../x.repo",
            "/etc/yum.repos.d/x.conf",
            "/etc/yum.repos.d/x.repo/",
            "/etc/yum.repos.d/x y.repo",
            "/etc/yum.repos.d//x.repo",
            "/etc/yum.repos.dx/x.repo",
            "/etc/other/x.repo",
            "yum.repos.d/x.repo",
            "x.repo",
            "",
        ] {
            assert!(!valid_repo_file(no), "{no:?}");
        }
    }

    #[test]
    fn url_rules() {
        for ok in [
            URL,
            "http://mirror.example.invalid/pub",
            "file:///srv/repo",
            "https://[2001:db8::1]:8443/x",
            "https://repo.example.invalid/x@y/?a=b#c",
        ] {
            assert_eq!(check_url(ok, UrlKind::Source, false), Ok(()), "{ok}");
        }
        for (no, want) in [
            ("", "empty"),
            ("ftp://mirror.example.invalid/", "must start with"),
            ("file://host/srv", "must start with"),
            ("/srv/repo", "must start with"),
            ("https://", "no host"),
            ("https:///x", "no host"),
            (
                "https://user:synthetic@repo.example.invalid/",
                "credentials",
            ),
            ("http://user@repo.example.invalid/", "credentials"),
            ("https://repo.example.invalid/ x", "printable ASCII"),
            (
                "https://repo.example.invalid/\nenabled=0",
                "printable ASCII",
            ),
            ("https://repo.example.invalid/\r", "printable ASCII"),
            ("https://repo.example.invalid/\t", "printable ASCII"),
            ("https://repo.example.invalid/\u{0}", "printable ASCII"),
            ("https://répo.example.invalid/", "printable ASCII"),
            (
                "https://repo.example.invalid\\@evil.example.invalid/",
                "backslash",
            ),
        ] {
            let e = check_url(no, UrlKind::Source, false).unwrap_err();
            assert!(e.contains(want), "{no:?}: {e}");
        }
        assert!(check_url(
            &format!("https://h/{}", "a".repeat(2048)),
            UrlKind::Source,
            false
        )
        .is_err());
        // Lists: no comma. Keys: no http.
        assert!(check_url("https://h.example.invalid/a,b", UrlKind::Source, true).is_err());
        assert!(check_url("https://h.example.invalid/a,b", UrlKind::Source, false).is_ok());
        assert_eq!(check_url(KEY, UrlKind::Key, true), Ok(()));
        assert_eq!(
            check_url("https://k.example.invalid/key", UrlKind::Key, true),
            Ok(())
        );
        let e = check_url("http://k.example.invalid/key", UrlKind::Key, true).unwrap_err();
        assert!(e.contains("unauthenticated"), "{e}");
    }

    #[test]
    fn a_refused_url_is_never_quoted() {
        let secret = "SYNTHETIC-CREDENTIAL";
        let e = err(&[
            ("name", s("example")),
            (
                "baseurl",
                s(&format!("https://user:{secret}@repo.example.invalid/")),
            ),
        ]);
        assert!(
            e.contains("credentials in repository URLs are not supported"),
            "{e}"
        );
        assert!(
            !e.contains(secret) && !e.contains("repo.example.invalid"),
            "{e}"
        );
    }

    #[test]
    fn field_rules() {
        assert!(err(&[("enabled", Value::Bool(true))]).contains("requires name"));
        assert!(
            err(&[("name", s("bad name")), ("enabled", Value::Bool(true))])
                .contains("valid repository id")
        );
        assert!(err(&[("name", s("x")), ("bogus", s("1"))]).contains("unknown field bogus"));
        assert!(err(&[("name", s("main")), ("enabled", Value::Bool(true))])
            .contains("DNF's own configuration section"));
        assert!(err(&[("name", s("x"))]).contains("declares nothing to manage"));
        assert!(err(&[("name", s("x")), ("state", s("gone"))]).contains("present or absent"));
        assert!(err(&[("name", s("x")), ("enabled", s("yes"))]).contains("must be a boolean"));
        assert!(err(&[
            ("name", s("x")),
            ("file", s("/etc/x.repo")),
            ("enabled", Value::Bool(true))
        ])
        .contains("directly inside /etc/yum.repos.d/"));
        assert!(err(&[("name", s("x")), ("description", s("two\nlines"))]).contains("one line"));
        assert!(err(&[("name", s("x")), ("description", s(" padded"))]).contains("one line"));
        assert!(err(&[("name", s("x")), ("baseurl", Value::List(vec![]))]).contains("empty list"));
        assert!(err(&[("name", s("x")), ("baseurl", Value::Int(1))]).contains("string or a list"));
        assert!(err(&[
            ("name", s("x")),
            ("gpgkey", Value::List(vec![Value::Int(1)]))
        ])
        .contains("string or a list"));
        assert!(
            err(&[("name", s("x")), ("mirrorlist", Value::List(vec![s(URL)]))])
                .contains("must be a string")
        );
        assert!(err(&[
            ("name", s("x")),
            ("gpgkey", s("http://k.example.invalid/k"))
        ])
        .contains("file:/// or https://"));
        assert!(err(&[
            ("name", s("x")),
            ("state", s("absent")),
            ("enabled", Value::Bool(false))
        ])
        .contains("state absent allows only name and file"));
        for key in ["gpgcheck", "repo_gpgcheck"] {
            let e = err(&[("name", s("x")), (key, Value::Bool(false))]);
            assert!(
                e.contains("never writes gpgcheck=0") && e.contains("file"),
                "{e}"
            );
        }
    }

    #[test]
    fn interpolated_fields_are_deferred_and_checked_once_evaluated() {
        let m = map(&[
            ("name", s("x")),
            ("baseurl", s("{{ vars.url }}")),
            ("gpgcheck", s("{{ vars.g }}")),
        ]);
        assert_eq!(RepoSpec::check(&m, "r", true).unwrap(), None);
        // Evaluated to a bad value: refused.
        let m = map(&[
            ("name", s("x")),
            ("baseurl", s("ftp://h.example.invalid/")),
            ("gpgcheck", Value::Bool(false)),
        ]);
        assert!(RepoSpec::check(&m, "r", false).is_err());
        // A literal rule still applies beside a deferred field.
        let m = map(&[
            ("name", s("x")),
            ("baseurl", s("{{ vars.url }}")),
            ("gpgcheck", Value::Bool(false)),
        ]);
        assert!(RepoSpec::check(&m, "r", true).is_err());
        let sp = spec(&[("enabled", Value::Bool(true)), ("state", Value::Null)]);
        assert_eq!(sp.file, "/etc/yum.repos.d/example.repo");
        assert!(!sp.absent);
    }

    fn go(sp: &RepoSpec, text: Option<&str>) -> Decision {
        decide(sp, text).unwrap()
    }

    #[test]
    fn creating_a_section_always_writes_gpgcheck_and_defaults_to_enabled() {
        let sp = spec(&[("baseurl", s(URL))]);
        let d = go(&sp, None);
        assert_eq!(
            d.new_content.as_deref(),
            Some(&*format!(
                "[example]\nbaseurl={URL}\nenabled=1\ngpgcheck=1\n"
            ))
        );
        assert_eq!(
            d.drift,
            [(
                "state".to_string(),
                "absent".to_string(),
                "present".to_string()
            )]
        );
        assert!(d.notes.is_empty() && !d.credentials);

        let sp = spec(&[
            ("description", s("Example packages")),
            (
                "baseurl",
                Value::List(vec![s(URL), s("file:///srv/mirror")]),
            ),
            ("enabled", Value::Bool(false)),
            ("repo_gpgcheck", Value::Bool(true)),
            ("gpgkey", s(KEY)),
        ]);
        let d = go(&sp, Some("[other]\nenabled=1\n"));
        assert_eq!(
            d.new_content.as_deref(),
            Some(&*format!("[other]\nenabled=1\n\n[example]\nname=Example packages\nbaseurl={URL}\n        file:///srv/mirror\nenabled=0\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey={KEY}\n"))
        );
        // The result is as declared: a second decision changes nothing.
        let again = go(&sp, d.new_content.as_deref());
        assert_eq!((again.new_content, again.drift.len()), (None, 0));

        let sp = spec(&[
            ("metalink", s(URL)),
            ("gpgcheck", Value::Bool(true)),
            ("gpgkey", s(KEY)),
        ]);
        assert_eq!(
            go(&sp, Some("")).new_content.as_deref(),
            Some(&*format!(
                "[example]\nmetalink={URL}\nenabled=1\ngpgcheck=1\ngpgkey={KEY}\n"
            ))
        );
    }

    #[test]
    fn a_missing_section_without_a_source_points_at_the_file_field() {
        let sp = spec(&[("enabled", Value::Bool(true))]);
        for text in [None, Some("[other]\nenabled=0\n")] {
            let e = decide(&sp, text).unwrap_err();
            assert!(
                e.contains("set file to the file that defines the repository"),
                "{e}"
            );
        }
    }

    #[test]
    fn enabling_requires_an_explicit_gpgcheck_after_the_edit() {
        let enable = spec(&[("enabled", Value::Bool(true))]);
        for text in [
            "[example]\nenabled=0\n",
            "[example]\nenabled=0\ngpgcheck=0\n",
            "[example]\ngpgcheck=0\n",
            "[example]\nenabled=0\ngpgcheck=on\n",
            "[example]\nenabled=maybe\ngpgcheck=\n",
        ] {
            let e = decide(&enable, Some(text)).unwrap_err();
            assert!(
                e.contains("declare gpgcheck: true") && e.contains("refusing to enable"),
                "{text:?}: {e}"
            );
        }
        for value in ["1", "true", "yes", "True", "YES"] {
            let text = format!("[example]\nenabled=0\ngpgcheck = {value}\n");
            let d = go(&enable, Some(&text));
            assert_eq!(
                d.new_content.as_deref(),
                Some(&*format!("[example]\nenabled=1\ngpgcheck = {value}\n"))
            );
            assert!(d.notes.is_empty());
        }
        let both = spec(&[
            ("enabled", Value::Bool(true)),
            ("gpgcheck", Value::Bool(true)),
        ]);
        let d = go(&both, Some("[example]\nenabled=0\ngpgcheck=0\n"));
        assert_eq!(
            d.new_content.as_deref(),
            Some("[example]\nenabled=1\ngpgcheck=1\n")
        );
        assert_eq!(d.drift.len(), 2);
        // No enabled key at all: written explicitly, and gpgcheck is required.
        assert!(decide(&enable, Some("[example]\nbaseurl=x\n")).is_err());
        let d = go(&enable, Some("[example]\ngpgcheck=1\n"));
        assert_eq!(
            d.new_content.as_deref(),
            Some("[example]\ngpgcheck=1\nenabled=1\n")
        );
    }

    #[test]
    fn writing_a_package_source_requires_an_explicit_gpgcheck_too() {
        let sp = spec(&[("baseurl", s(URL))]);
        for text in [
            "[example]\nenabled=1\ngpgcheck=0\n",
            "[example]\nenabled=0\n",
        ] {
            let e = decide(&sp, Some(text)).unwrap_err();
            assert!(
                e.contains("change the package source") && e.contains("declare gpgcheck: true"),
                "{e}"
            );
        }
        // The same source already there: nothing is written, so no refusal.
        let text = format!("[example]\nbaseurl={URL}\nenabled=1\ngpgcheck=0\n");
        let d = go(&sp, Some(&text));
        assert_eq!(d.new_content, None);
        assert_eq!(d.notes, [NOTE_UNCHECKED]);
    }

    #[test]
    fn an_unchecked_repository_the_resource_does_not_change_gets_a_note_only() {
        let sp = spec(&[("description", s("Example"))]);
        let d = go(
            &sp,
            Some("[example]\nname=Example\nenabled=1\ngpgcheck=0\n"),
        );
        assert_eq!(
            (d.new_content, d.notes.as_slice()),
            (None, &[NOTE_UNCHECKED.to_string()][..])
        );
        // No enabled key means DNF's default (enabled): the note is given.
        let d = go(&sp, Some("[example]\nname=Example\n"));
        assert_eq!(d.notes, [NOTE_UNCHECKED]);
        // Disabled, or disabled by this resource: no note.
        let d = go(
            &sp,
            Some("[example]\nname=Example\nenabled=0\ngpgcheck=0\n"),
        );
        assert!(d.notes.is_empty());
        let off = spec(&[("enabled", Value::Bool(false))]);
        let d = go(&off, Some("[example]\nenabled=1\ngpgcheck=0\n"));
        assert!(d.notes.is_empty());
        assert_eq!(
            d.new_content.as_deref(),
            Some("[example]\nenabled=0\ngpgcheck=0\n")
        );
    }

    #[test]
    fn only_declared_keys_are_compared_and_formatting_alone_is_not_a_change() {
        let text = "[example]\nname = Example\nbaseurl = https://a.example.invalid/x   https://b.example.invalid/x\nenabled = True\ngpgcheck = yes\nsslverify=0\nmirrorlist=https://m.example.invalid/\n";
        let sp = spec(&[
            ("description", s("Example")),
            (
                "baseurl",
                Value::List(vec![
                    s("https://a.example.invalid/x"),
                    s("https://b.example.invalid/x"),
                ]),
            ),
            ("enabled", Value::Bool(true)),
            ("gpgcheck", Value::Bool(true)),
        ]);
        let d = go(&sp, Some(text));
        assert_eq!((d.new_content, d.drift.len(), d.notes.len()), (None, 0, 0));
        // A different order of list entries is a difference.
        let sp = spec(&[(
            "baseurl",
            Value::List(vec![
                s("https://b.example.invalid/x"),
                s("https://a.example.invalid/x"),
            ]),
        )]);
        let d = go(&sp, Some(text));
        assert_eq!(d.drift.len(), 1);
        assert_eq!(d.drift[0].0, "baseurl");
        let out = d.new_content.unwrap();
        assert!(out.contains(
            "baseurl=https://b.example.invalid/x\n        https://a.example.invalid/x\n"
        ));
        // The undeclared mirrorlist and sslverify stay.
        assert!(out.contains("sslverify=0\nmirrorlist=https://m.example.invalid/\n"));
    }

    #[test]
    fn drift_names_the_with_field_and_both_values() {
        let sp = spec(&[
            ("description", s("New")),
            ("enabled", Value::Bool(false)),
            ("gpgkey", s(KEY)),
        ]);
        let d = go(
            &sp,
            Some("[example]\nname=Old\n  more\nenabled=1\ngpgcheck=1\n"),
        );
        assert_eq!(
            d.drift,
            [
                (
                    "description".to_string(),
                    "Old more".to_string(),
                    "New".to_string()
                ),
                ("enabled".to_string(), "1".to_string(), "0".to_string()),
                ("gpgkey".to_string(), NOT_SET.to_string(), KEY.to_string()),
            ]
        );
        assert_eq!(
            d.new_content.as_deref(),
            Some(&*format!(
                "[example]\nname=New\nenabled=0\ngpgcheck=1\ngpgkey={KEY}\n"
            ))
        );
    }

    #[test]
    fn absent_removes_the_section_and_nothing_else() {
        let sp = spec(&[("state", s("absent"))]);
        assert_eq!(go(&sp, None).new_content, None);
        assert_eq!(go(&sp, Some("[other]\nx=1\n")).new_content, None);
        let d = go(&sp, Some("# c\n[example]\nenabled=1\n[other]\nx=1\n"));
        assert_eq!(d.new_content.as_deref(), Some("# c\n[other]\nx=1\n"));
        assert_eq!(
            d.drift,
            [(
                "state".to_string(),
                "present".to_string(),
                "absent".to_string()
            )]
        );
        // The last section: the file stays (empty here).
        assert_eq!(
            go(&sp, Some("[example]\nenabled=1\n"))
                .new_content
                .as_deref(),
            Some("")
        );
    }

    #[test]
    fn an_ambiguous_file_is_refused_for_every_state() {
        for sp in [
            spec(&[("enabled", Value::Bool(false))]),
            spec(&[("state", s("absent"))]),
        ] {
            for (text, want) in [
                (
                    "[example]\nenabled=1\n[example]\nenabled=0\n",
                    "more than once",
                ),
                ("[example]\nenabled=1\nenabled=0\n", "more than once"),
                ("[example]\nsomething odd\n", "not a key=value line"),
                ("[example]\nEnabled=1\n", "letter case"),
                ("[example\n", "not a section header"),
            ] {
                let e = decide(&sp, Some(text)).unwrap_err();
                assert!(
                    e.contains(want) && e.contains("is not read"),
                    "{text:?}: {e}"
                );
            }
        }
    }

    #[test]
    fn credentials_in_the_file_are_flagged_and_never_quoted() {
        let secret = "SYNTHETIC-PASSWORD";
        let text = format!("[other]\nbaseurl=https://user:{secret}@r.example.invalid/\n[example]\nenabled=1\ngpgcheck=1\n");
        let d = go(&spec(&[("enabled", Value::Bool(false))]), Some(&text));
        assert!(d.credentials);
        let text = format!("[example]\npassword={secret}\npassword={secret}\n");
        let e = decide(&spec(&[("enabled", Value::Bool(false))]), Some(&text)).unwrap_err();
        assert!(!e.contains(secret), "{e}");
    }

    #[test]
    fn ownership_claims() {
        let mut owners = Owners::default();
        let mut paths: BTreeMap<String, String> = BTreeMap::new();
        paths.insert("/etc/yum.repos.d/taken.repo".into(), "a_file".into());
        assert!(claim(
            &mut owners,
            &mut paths,
            "a",
            "/etc/yum.repos.d/x.repo",
            "r1"
        )
        .is_none());
        // A second repository in the same file is fine.
        assert!(claim(
            &mut owners,
            &mut paths,
            "b",
            "/etc/yum.repos.d/x.repo",
            "r2"
        )
        .is_none());
        let (field, peer, msg) = claim(
            &mut owners,
            &mut paths,
            "a",
            "/etc/yum.repos.d/y.repo",
            "r3",
        )
        .unwrap();
        assert_eq!((field, peer.as_str()), ("name", "r1"));
        assert!(msg.contains("DNF repository \"a\""), "{msg}");
        let (field, peer, msg) = claim(
            &mut owners,
            &mut paths,
            "c",
            "/etc/yum.repos.d/taken.repo",
            "r4",
        )
        .unwrap();
        assert_eq!((field, peer.as_str()), ("file", "a_file"));
        assert!(msg.contains("conflicting ownership of path"), "{msg}");
        // The claimed file is a path owner for resources that come later.
        assert!(paths.contains_key("/etc/yum.repos.d/x.repo"));
    }
}
