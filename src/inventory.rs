//! Inventory: which hosts exist, and named groups of them.
//!
//! An inventory never selects anything by itself. A recipe run with
//! `--inventory` executes only on the hosts its own `targets` declaration
//! selects ([`resolve`]); a recipe without `targets`, a name the inventory
//! does not define, and a selection that matches no host are all errors
//! raised before anything connects.
//!
//! Format (YAML, or TOML by extension):
//!
//! ```yaml
//! hosts:
//!   web01:
//!     address: 10.0.0.11      # optional; defaults to the host name
//!     user: ubuntu            # optional
//!     port: 22                # optional
//!     known_hosts: ~/.ssh/known_hosts_lab   # optional
//!     identity_files: [~/.ssh/id_lab]       # optional
//!   web02: {}                 # address = "web02" (e.g. an ~/.ssh/config alias)
//! groups:
//!   web:
//!     hosts: [web01, web02]
//! ```
//!
//! `--limit` ([`parse_limit`], [`match_limit`], DESIGN §19.2) only ever
//! *narrows* the hosts the recipes' `targets` select; it never adds one.
//!
//! Deliberately absent: nested groups, variables in the inventory file,
//! patterns in the inventory or in `targets` (a `--limit` glob only narrows),
//! an implicit "all" group, dynamic inventory, per-host sudo
//! (privilege is an invocation-level `--sudo`, DESIGN §21). Group and host
//! variable values come from a separate variables file
//! ([`crate::varsfile`], DESIGN §19.5) that refers to these names.

use crate::document::{valid_name, TargetSelector};
use crate::error::{Result, SinterError};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEntry {
    address: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    known_hosts: Option<PathBuf>,
    #[serde(default)]
    identity_files: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupEntry {
    hosts: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryFile {
    hosts: BTreeMap<String, HostEntry>,
    #[serde(default)]
    groups: BTreeMap<String, GroupEntry>,
}

/// One inventory host. `None`/empty fields were not stated and are resolved
/// later (OpenSSH client configuration, then built-in defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryHost {
    pub name: String,
    /// Network address or `~/.ssh/config` alias; the host name when omitted.
    pub address: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub known_hosts: Option<PathBuf>,
    pub identity_files: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Inventory {
    pub path: PathBuf,
    /// Sorted by name (the execution order).
    pub hosts: BTreeMap<String, InventoryHost>,
    /// Group name -> member host names, in declaration order.
    pub groups: BTreeMap<String, Vec<String>>,
}

fn value_to_json(v: &crate::value::Value) -> serde_json::Value {
    use crate::value::Value;
    match v {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Int(i) => serde_json::Value::from(*i),
        Value::Float(f) => serde_json::Value::from(*f),
        Value::Str(s) => serde_json::Value::String(s.clone()),
        Value::List(l) => serde_json::Value::Array(l.iter().map(value_to_json).collect()),
        Value::Map(m) => serde_json::Value::Object(
            m.iter()
                .map(|(k, v)| (k.clone(), value_to_json(v)))
                .collect(),
        ),
    }
}

fn expand_home(p: PathBuf) -> PathBuf {
    match (p.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(h)) => PathBuf::from(h).join(rest),
        _ => p,
    }
}

/// Load and validate an inventory. Every problem is a validation error
/// (exit 2) raised before any connection is attempted.
pub fn load_inventory(path: &Path) -> Result<Inventory> {
    let ctx = path.display();
    let text = std::fs::read_to_string(path)
        .map_err(|e| SinterError::schema(format!("cannot read inventory {ctx}: {e}")))?;
    let is_yaml = matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("yaml" | "yml")
    );
    let parsed: InventoryFile = if is_yaml {
        let v = crate::yaml::parse_yaml(&text)
            .map_err(|e| SinterError::schema(format!("invalid inventory {ctx}: {}", e.message)))?;
        serde_json::from_value(value_to_json(&v))
            .map_err(|e| SinterError::schema(format!("invalid inventory {ctx}: {e}")))?
    } else {
        toml::from_str(&text)
            .map_err(|e| SinterError::schema(format!("invalid inventory {ctx}: {e}")))?
    };
    if parsed.hosts.is_empty() {
        return Err(SinterError::schema(format!(
            "inventory {ctx} defines no hosts"
        )));
    }
    let bad_name = |kind: &str, name: &str| {
        SinterError::schema(format!(
            "inventory {ctx}: invalid {kind} name {name:?} (allowed: [A-Za-z0-9._-], start alphanumeric, max 64 chars)"
        ))
    };
    let mut hosts = BTreeMap::new();
    for (name, h) in parsed.hosts {
        if !valid_name(&name) {
            return Err(bad_name("host", &name));
        }
        let address = h.address.unwrap_or_else(|| name.clone());
        crate::sshconfig::validate_host_arg(&address).map_err(|e| {
            SinterError::schema(format!("inventory {ctx}: host {name}: {}", e.message))
        })?;
        if h.user.as_deref().is_some_and(|u| u.trim().is_empty()) {
            return Err(SinterError::schema(format!(
                "inventory {ctx}: host {name}: user must not be empty"
            )));
        }
        hosts.insert(
            name.clone(),
            InventoryHost {
                name,
                address,
                port: h.port,
                user: h.user,
                known_hosts: h.known_hosts.map(expand_home),
                identity_files: h.identity_files.into_iter().map(expand_home).collect(),
            },
        );
    }
    let mut groups = BTreeMap::new();
    for (name, g) in parsed.groups {
        if !valid_name(&name) {
            return Err(bad_name("group", &name));
        }
        if g.hosts.is_empty() {
            return Err(SinterError::schema(format!(
                "inventory {ctx}: group {name} has no hosts"
            )));
        }
        let mut members: Vec<String> = Vec::new();
        for m in g.hosts {
            if !hosts.contains_key(&m) {
                return Err(SinterError::schema(format!(
                    "inventory {ctx}: group {name} lists unknown host {m}"
                )));
            }
            if members.contains(&m) {
                return Err(SinterError::schema(format!(
                    "inventory {ctx}: group {name} lists host {m} more than once"
                )));
            }
            members.push(m);
        }
        groups.insert(name, members);
    }
    Ok(Inventory {
        path: path.to_path_buf(),
        hosts,
        groups,
    })
}

/// Why one inventory host was or was not selected for one recipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMatch {
    pub name: String,
    /// `host:<name>` / `group:<name>` for each matching selector; empty when
    /// the recipe's `targets` do not select the host (SKIP). Kept as is when
    /// `--limit` leaves a matching host out.
    pub reasons: Vec<String>,
    /// Matched by `targets` but left out by `--limit` (only
    /// [`Resolution::apply_allowed`] sets it, and it never unsets it).
    limit_excluded: bool,
}

impl HostMatch {
    /// The recipe's `targets` select the host (before `--limit`).
    pub fn targeted(&self) -> bool {
        !self.reasons.is_empty()
    }

    /// The host will be resolved and run: targeted and not left out by
    /// `--limit`.
    pub fn selected(&self) -> bool {
        self.targeted() && !self.limit_excluded
    }

    /// Targeted, but left out by `--limit`.
    pub fn excluded_by_limit(&self) -> bool {
        self.targeted() && self.limit_excluded
    }
}

/// Target resolution of one recipe against an inventory: every inventory
/// host, in name order, with its match reasons.
#[derive(Debug, Clone)]
pub struct Resolution {
    pub hosts: Vec<HostMatch>,
}

impl Resolution {
    /// The hosts that will be resolved and run (after `--limit`, if any).
    pub fn selected(&self) -> impl Iterator<Item = &str> {
        self.hosts
            .iter()
            .filter(|h| h.selected())
            .map(|h| h.name.as_str())
    }

    /// The hosts the recipe's `targets` select (before `--limit`).
    pub fn targeted(&self) -> impl Iterator<Item = &str> {
        self.hosts
            .iter()
            .filter(|h| h.targeted())
            .map(|h| h.name.as_str())
    }

    /// Leave out every targeted host that is not in `allowed`. Only ever
    /// adds exclusions: calling it again can never bring a host back.
    pub fn apply_allowed(&mut self, allowed: &BTreeSet<String>) {
        for h in &mut self.hosts {
            if h.targeted() && !allowed.contains(&h.name) {
                h.limit_excluded = true;
            }
        }
    }
}

/// Resolve a recipe's `targets` against the inventory. Fails closed:
///
/// * no `targets` declaration -> error (an inventory never implies "all");
/// * a host or group name the inventory does not define -> error;
/// * a selection matching no host -> error.
pub fn resolve(inv: &Inventory, sel: Option<&TargetSelector>, recipe: &str) -> Result<Resolution> {
    let sel = sel.ok_or_else(|| {
        SinterError::schema(format!(
            "recipe {recipe} declares no targets; with --inventory every recipe must name the hosts or groups it may run on (Sinter never selects all inventory hosts implicitly)"
        ))
    })?;
    for h in &sel.hosts {
        if !inv.hosts.contains_key(h) {
            return Err(SinterError::schema(format!(
                "recipe {recipe}: target host {h} is not defined in inventory {}",
                inv.path.display()
            )));
        }
    }
    for g in &sel.groups {
        if !inv.groups.contains_key(g) {
            return Err(SinterError::schema(format!(
                "recipe {recipe}: target group {g} is not defined in inventory {}",
                inv.path.display()
            )));
        }
    }
    let hosts: Vec<HostMatch> = inv
        .hosts
        .keys()
        .map(|name| {
            let mut reasons = Vec::new();
            if sel.hosts.contains(name) {
                reasons.push(format!("host:{name}"));
            }
            for g in &sel.groups {
                if inv.groups[g].contains(name) {
                    reasons.push(format!("group:{g}"));
                }
            }
            HostMatch {
                name: name.clone(),
                reasons,
                limit_excluded: false,
            }
        })
        .collect();
    if !hosts.iter().any(HostMatch::targeted) {
        return Err(SinterError::schema(format!(
            "recipe {recipe}: targets select no inventory host"
        )));
    }
    Ok(Resolution { hosts })
}

/// Most items one `--limit` may name.
pub const MAX_LIMIT_ITEMS: usize = 256;
/// Longest name or glob of one `--limit` item (the `host:`/`group:` prefix not
/// counted); the inventory's own name limit.
pub const MAX_LIMIT_ITEM_CHARS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimitKind {
    /// A bare name: a host or a group (an error if it is both).
    Bare,
    /// `host:<name-or-glob>`.
    Host,
    /// `group:<name>`.
    Group,
}

/// One item of a `--limit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitItem {
    kind: LimitKind,
    /// The name or glob, without a `host:`/`group:` prefix.
    text: String,
    glob: bool,
    /// As the user wrote it.
    raw: String,
}

/// A syntactically valid `--limit`, or none (`given() == false`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedLimit {
    given: bool,
    items: Vec<LimitItem>,
}

impl ParsedLimit {
    /// `--limit` was given.
    pub fn given(&self) -> bool {
        self.given
    }

    /// The items as written, without repeats, in order of first appearance.
    pub fn items(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for i in &self.items {
            if !out.contains(&i.raw) {
                out.push(i.raw.clone());
            }
        }
        out
    }
}

fn limit_error(raw: &str, what: &str) -> SinterError {
    // An item can be as long as the command line allows: show its start.
    let shown: String = if raw.chars().count() > MAX_LIMIT_ITEM_CHARS + 8 {
        let mut s: String = raw.chars().take(MAX_LIMIT_ITEM_CHARS + 8).collect();
        s.push('…');
        s
    } else {
        raw.to_string()
    };
    SinterError::schema(format!("--limit item {shown:?}: {what}"))
}

/// Check the syntax of `--limit` (DESIGN §19.2). Items are separated by `,`;
/// each is a name, `host:<name>`, `group:<name>`, or a glob (`*` any run of
/// characters, `?` one character) that matches host names only. Nothing about
/// the inventory is checked here.
pub fn parse_limit(value: Option<&str>) -> Result<ParsedLimit> {
    let Some(value) = value else {
        return Ok(ParsedLimit::default());
    };
    if value.is_empty() {
        return Err(SinterError::schema("--limit must not be empty"));
    }
    let mut items = Vec::new();
    for raw in value.split(',') {
        if items.len() >= MAX_LIMIT_ITEMS {
            return Err(SinterError::schema(format!(
                "--limit names more than {MAX_LIMIT_ITEMS} items"
            )));
        }
        if raw.is_empty() {
            return Err(SinterError::schema(
                "--limit has an empty item (a doubled or trailing comma)",
            ));
        }
        let (kind, text) = if let Some(rest) = raw.strip_prefix("host:") {
            (LimitKind::Host, rest)
        } else if let Some(rest) = raw.strip_prefix("group:") {
            (LimitKind::Group, rest)
        } else {
            (LimitKind::Bare, raw)
        };
        if text.is_empty() {
            return Err(limit_error(raw, "a name is missing after the prefix"));
        }
        if text.chars().count() > MAX_LIMIT_ITEM_CHARS {
            return Err(limit_error(
                raw,
                &format!("longer than {MAX_LIMIT_ITEM_CHARS} characters"),
            ));
        }
        if text.contains(':') {
            return Err(limit_error(
                raw,
                "':' is only allowed in the host: and group: prefixes",
            ));
        }
        let glob = text.contains(['*', '?']);
        let allowed = |c: char| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '_' | '-')
                || (glob && matches!(c, '*' | '?'))
        };
        if !text.chars().all(allowed) {
            return Err(limit_error(
                raw,
                "only letters, digits, '.', '_', '-' (and '*', '?' in a pattern) are allowed",
            ));
        }
        if glob {
            if kind == LimitKind::Group {
                return Err(limit_error(
                    raw,
                    "a pattern matches host names only; name a group without '*' or '?'",
                ));
            }
            let first = text.chars().next().unwrap_or('-');
            if !(first.is_ascii_alphanumeric() || matches!(first, '*' | '?')) {
                return Err(limit_error(
                    raw,
                    "must start with a letter, a digit, '*' or '?'",
                ));
            }
        } else if !valid_name(text) {
            return Err(limit_error(
                raw,
                "not a valid host or group name (letters, digits, '.', '_', '-'; start alphanumeric)",
            ));
        }
        items.push(LimitItem {
            kind,
            text: text.to_string(),
            glob,
            raw: raw.to_string(),
        });
    }
    Ok(ParsedLimit { given: true, items })
}

/// `*` matches any run of characters (also none), `?` exactly one; the whole
/// of `name` must match. Iterative, with one backtrack point: O(pattern x name).
fn glob_match(pattern: &str, name: &str) -> bool {
    let (p, s) = (pattern.as_bytes(), name.as_bytes());
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while si < s.len() {
        if pi < p.len() && p[pi] != b'*' && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Evaluate a `--limit` against the inventory and the recipes' target
/// resolutions, and return the set of hosts a run may touch. Every item must
/// name something the inventory defines, must not be ambiguous (a bare name
/// that is both a host and a group), and must reach at least one host some
/// recipe's `targets` select; otherwise the whole `--limit` is refused
/// (exit 2) and nothing has been contacted. The result is always a subset of
/// the hosts the recipes target: `--limit` narrows, never widens.
pub fn match_limit(
    inv: &Inventory,
    resolutions: &[Resolution],
    limit: &ParsedLimit,
) -> Result<BTreeSet<String>> {
    let targeted: BTreeSet<&str> = resolutions.iter().flat_map(|r| r.targeted()).collect();
    let mut allowed = BTreeSet::new();
    for item in &limit.items {
        let hosts: BTreeSet<String> = if item.glob {
            inv.hosts
                .keys()
                .filter(|h| glob_match(&item.text, h))
                .cloned()
                .collect()
        } else {
            let as_host = inv.hosts.contains_key(&item.text);
            let as_group = inv.groups.get(&item.text);
            match (item.kind, as_host, as_group) {
                (LimitKind::Host, true, _) | (LimitKind::Bare, true, None) => {
                    BTreeSet::from([item.text.clone()])
                }
                (LimitKind::Group, _, Some(members)) | (LimitKind::Bare, false, Some(members)) => {
                    members.iter().cloned().collect()
                }
                (LimitKind::Bare, true, Some(_)) => {
                    return Err(limit_error(
                        &item.raw,
                        &format!(
                            "is both a host and a group of inventory {}; write host:{} or group:{}",
                            inv.path.display(),
                            item.text,
                            item.text
                        ),
                    ));
                }
                _ => BTreeSet::new(),
            }
        };
        if hosts.is_empty() {
            let what = if item.glob {
                "matches no host of inventory"
            } else {
                match item.kind {
                    LimitKind::Host => "is not a host of inventory",
                    LimitKind::Group => "is not a group of inventory",
                    LimitKind::Bare => "is neither a host nor a group of inventory",
                }
            };
            return Err(limit_error(
                &item.raw,
                &format!("{what} {}", inv.path.display()),
            ));
        }
        if !hosts.iter().any(|h| targeted.contains(h.as_str())) {
            return Err(limit_error(
                &item.raw,
                "names inventory hosts, but no recipe's targets select any of them, so it would run nothing",
            ));
        }
        allowed.extend(hosts);
    }
    Ok(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv(body: &str, name: &str) -> Result<Inventory> {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(name);
        std::fs::write(&p, body).unwrap();
        load_inventory(&p)
    }

    const INV: &str = "hosts:\n  web01:\n    address: 10.0.0.11\n    user: ubuntu\n  web02:\n    address: 10.0.0.12\n  db01:\n    address: 10.0.0.21\n    user: rocky\n    port: 2222\ngroups:\n  web:\n    hosts: [web01, web02]\n  db:\n    hosts: [db01]\n";

    fn sel(hosts: &[&str], groups: &[&str]) -> TargetSelector {
        TargetSelector {
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            groups: groups.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn loads_hosts_and_groups() {
        let i = inv(INV, "h.yaml").unwrap();
        assert_eq!(
            i.hosts.keys().collect::<Vec<_>>(),
            vec!["db01", "web01", "web02"]
        );
        assert_eq!(i.hosts["db01"].port, Some(2222));
        assert_eq!(i.hosts["web02"].user, None);
        assert_eq!(i.groups["web"], vec!["web01", "web02"]);
    }

    #[test]
    fn toml_inventory_is_equivalent() {
        let t = "[hosts.web01]\naddress = \"10.0.0.11\"\nuser = \"ubuntu\"\n[hosts.web02]\naddress = \"10.0.0.12\"\n[hosts.db01]\naddress = \"10.0.0.21\"\nuser = \"rocky\"\nport = 2222\n[groups.web]\nhosts = [\"web01\", \"web02\"]\n[groups.db]\nhosts = [\"db01\"]\n";
        let a = inv(INV, "h.yaml").unwrap();
        let b = inv(t, "h.toml").unwrap();
        assert_eq!(a.hosts, b.hosts);
        assert_eq!(a.groups, b.groups);
    }

    #[test]
    fn address_defaults_to_the_host_name() {
        let i = inv("hosts:\n  web01: {}\n", "h.yaml").unwrap();
        assert_eq!(i.hosts["web01"].address, "web01");
    }

    #[test]
    fn invalid_inventories_fail_closed() {
        for body in [
            "hosts: {}\n",
            "groups:\n  web:\n    hosts: [a]\n",
            "hosts:\n  a:\n    host: h\n",
            "hosts:\n  a:\n    address: \"-oProxyCommand=x\"\n",
            "hosts:\n  a:\n    user: \"\"\n",
            "hosts:\n  a:\n    port: 70000\n",
            "hosts:\n  a:\n    sudo: true\n",
            "hosts:\n  a: {}\n  a: {}\n",
            "hosts:\n  \"bad/name\": {}\n",
            "hosts:\n  a: {}\ngroups:\n  web:\n    hosts: [b]\n",
            "hosts:\n  a: {}\ngroups:\n  web:\n    hosts: [a, a]\n",
            "hosts:\n  a: {}\ngroups:\n  web:\n    hosts: []\n",
            "hosts:\n  a: {}\ngroups:\n  web: [a]\n",
            "hosts:\n  a: {}\ngroups:\n  web:\n    hosts: [a]\n    vars: {}\n",
            "hosts:\n  a: {}\nvars: {}\n",
            "hosts: [\n",
        ] {
            let e = inv(body, "h.yaml").expect_err(body);
            assert_eq!(
                e.kind,
                crate::error::ErrorKind::Schema,
                "{body}: {}",
                e.message
            );
        }
        let e = load_inventory(Path::new("/nonexistent/hosts.yaml")).unwrap_err();
        assert_eq!(e.kind, crate::error::ErrorKind::Schema);
    }

    #[test]
    fn group_target_selects_members_only() {
        let i = inv(INV, "h.yaml").unwrap();
        let r = resolve(&i, Some(&sel(&[], &["web"])), "nginx").unwrap();
        assert_eq!(r.selected().collect::<Vec<_>>(), vec!["web01", "web02"]);
        let db = r.hosts.iter().find(|h| h.name == "db01").unwrap();
        assert!(!db.selected());
        assert_eq!(
            r.hosts.iter().find(|h| h.name == "web01").unwrap().reasons,
            vec!["group:web"]
        );
    }

    #[test]
    fn host_and_group_targets_union() {
        let i = inv(INV, "h.yaml").unwrap();
        let r = resolve(&i, Some(&sel(&["db01", "web01"], &["web"])), "x").unwrap();
        assert_eq!(
            r.selected().collect::<Vec<_>>(),
            vec!["db01", "web01", "web02"]
        );
        assert_eq!(
            r.hosts.iter().find(|h| h.name == "web01").unwrap().reasons,
            vec!["host:web01", "group:web"]
        );
    }

    #[test]
    fn missing_targets_fail_closed() {
        let i = inv(INV, "h.yaml").unwrap();
        let e = resolve(&i, None, "common").unwrap_err();
        assert_eq!(e.kind, crate::error::ErrorKind::Schema);
        assert!(e.message.contains("declares no targets"), "{}", e.message);
    }

    #[test]
    fn unknown_target_names_fail_closed() {
        let i = inv(INV, "h.yaml").unwrap();
        assert!(resolve(&i, Some(&sel(&["web03"], &[])), "x").is_err());
        assert!(resolve(&i, Some(&sel(&[], &["cache"])), "x").is_err());
        // One unknown name poisons the whole selection.
        assert!(resolve(&i, Some(&sel(&["web01"], &["cache"])), "x").is_err());
    }

    fn parsed(value: &str) -> ParsedLimit {
        parse_limit(Some(value)).unwrap_or_else(|e| panic!("{value}: {}", e.message))
    }

    #[test]
    fn no_limit_is_not_given() {
        let l = parse_limit(None).unwrap();
        assert!(!l.given());
        assert!(l.items().is_empty());
    }

    #[test]
    fn limit_syntax_accepts_names_prefixes_and_globs() {
        for v in [
            "web01",
            "web01,web02",
            "web",
            "host:web01",
            "group:web",
            "web*",
            "*",
            "?eb0?",
            "host:web*",
            "web.example_1-a",
            "a,a",
        ] {
            assert!(parse_limit(Some(v)).unwrap().given(), "{v}");
        }
        // Repeats collapse, order of first appearance is kept.
        assert_eq!(parsed("b,a,b").items(), vec!["b", "a"]);
    }

    #[test]
    fn a_long_item_is_shown_by_its_start_only() {
        let long = "x".repeat(5000);
        let e = parse_limit(Some(&long)).unwrap_err();
        assert!(e.message.len() < 300, "{}", e.message.len());
        assert!(e.message.contains('…'), "{}", e.message);
    }

    #[test]
    fn limit_syntax_rejects_everything_else() {
        let long = "x".repeat(MAX_LIMIT_ITEM_CHARS + 1);
        let many = vec!["a"; MAX_LIMIT_ITEMS + 1].join(",");
        for v in [
            "",
            ",",
            "a,",
            ",a",
            "a,,b",
            "host:",
            "group:",
            "group:web*",
            "group:w?",
            "host:group:web",
            "a:b",
            "!web01",
            "web01,!web02",
            "-web",
            ".web",
            "_web",
            "-*",
            "we b",
            "web 01",
            "web/01",
            "web[0-9]",
            "web{1,2}",
            "w\u{e9}b",
            "web\n01",
            "web01\0",
            "a=b",
            "a;b",
            "$(x)",
            "~",
            long.as_str(),
            many.as_str(),
        ] {
            let e = parse_limit(Some(v)).expect_err(v);
            assert_eq!(e.kind, crate::error::ErrorKind::Schema, "{v:?}");
        }
        // The size limits are exact.
        let max_name = "x".repeat(MAX_LIMIT_ITEM_CHARS);
        assert!(parse_limit(Some(&max_name)).is_ok());
        let max_items = vec!["a"; MAX_LIMIT_ITEMS].join(",");
        assert!(parse_limit(Some(&max_items)).is_ok());
    }

    /// A deliberately naive matcher: try every way to spend each `*`.
    fn naive_glob(p: &[u8], s: &[u8]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((b'*', rest)) => (0..=s.len()).any(|k| naive_glob(rest, &s[k..])),
            Some((b'?', rest)) => !s.is_empty() && naive_glob(rest, &s[1..]),
            Some((c, rest)) => s.first() == Some(c) && naive_glob(rest, &s[1..]),
        }
    }

    #[test]
    fn glob_matches_like_a_naive_reference() {
        // Every pattern up to length 5 over {a, b, *, ?} against every name up
        // to length 6 over {a, b}.
        fn all(alphabet: &[u8], max: usize) -> Vec<Vec<u8>> {
            let mut out = vec![Vec::new()];
            let mut layer = vec![Vec::new()];
            for _ in 0..max {
                let mut next = Vec::new();
                for w in &layer {
                    for c in alphabet {
                        let mut n = w.clone();
                        n.push(*c);
                        next.push(n);
                    }
                }
                out.extend(next.iter().cloned());
                layer = next;
            }
            out
        }
        let patterns = all(b"ab*?", 5);
        let names = all(b"ab", 6);
        for p in &patterns {
            for n in &names {
                let (ps, ns) = (
                    std::str::from_utf8(p).unwrap(),
                    std::str::from_utf8(n).unwrap(),
                );
                assert_eq!(glob_match(ps, ns), naive_glob(p, n), "{ps:?} vs {ns:?}");
            }
        }
    }

    #[test]
    fn glob_is_linear_enough_for_hostile_patterns() {
        let name = "a".repeat(MAX_LIMIT_ITEM_CHARS);
        let pat = format!("{}b", "a*".repeat(31));
        assert!(!glob_match(&pat, &name));
        assert!(glob_match("*", ""));
        assert!(!glob_match("?", ""));
    }

    fn resolutions(i: &Inventory, recipes: &[TargetSelector]) -> Vec<Resolution> {
        recipes
            .iter()
            .map(|s| resolve(i, Some(s), "r").unwrap())
            .collect()
    }

    fn allowed_by(i: &Inventory, rs: &[Resolution], v: &str) -> Result<Vec<String>> {
        match_limit(i, rs, &parsed(v)).map(|s| s.into_iter().collect())
    }

    #[test]
    fn limit_selects_hosts_groups_and_globs() {
        let i = inv(INV, "h.yaml").unwrap();
        let rs = resolutions(&i, &[sel(&[], &["web", "db"])]);
        assert_eq!(allowed_by(&i, &rs, "web01").unwrap(), vec!["web01"]);
        assert_eq!(allowed_by(&i, &rs, "host:web01").unwrap(), vec!["web01"]);
        assert_eq!(
            allowed_by(&i, &rs, "web01,db01").unwrap(),
            vec!["db01", "web01"]
        );
        assert_eq!(allowed_by(&i, &rs, "web").unwrap(), vec!["web01", "web02"]);
        assert_eq!(
            allowed_by(&i, &rs, "group:web").unwrap(),
            vec!["web01", "web02"]
        );
        assert_eq!(
            allowed_by(&i, &rs, "web0*").unwrap(),
            vec!["web01", "web02"]
        );
        assert_eq!(
            allowed_by(&i, &rs, "*").unwrap(),
            vec!["db01", "web01", "web02"]
        );
        // Overlap and repeats collapse.
        assert_eq!(
            allowed_by(&i, &rs, "web,web01,web*,web01").unwrap(),
            vec!["web01", "web02"]
        );
    }

    #[test]
    fn limit_fails_closed_on_what_it_cannot_resolve() {
        let i = inv(INV, "h.yaml").unwrap();
        let rs = resolutions(&i, &[sel(&[], &["web"])]);
        for v in [
            "nosuch",
            "host:web",
            "group:web01",
            "host:nosuch",
            "group:nosuch",
            "zz*",
            // One bad item poisons the others.
            "web01,nosuch",
            // db01 exists, but no recipe targets it: it would run nothing.
            "db01",
            "group:db",
            "d*",
        ] {
            let e = allowed_by(&i, &rs, v).expect_err(v);
            assert_eq!(e.kind, crate::error::ErrorKind::Schema, "{v}");
            assert!(e.message.contains("--limit"), "{v}: {}", e.message);
        }
    }

    #[test]
    fn limit_never_names_a_host_a_recipe_does_not_target() {
        let i = inv(INV, "h.yaml").unwrap();
        // `web` selects web01 and web02 only; `*` also reaches db01 but the
        // result stays inside the targeted hosts' union via apply_allowed.
        let rs = resolutions(&i, &[sel(&[], &["web"])]);
        let allowed = match_limit(&i, &rs, &parsed("*")).unwrap();
        let mut rs = rs;
        for r in &mut rs {
            r.apply_allowed(&allowed);
        }
        assert_eq!(rs[0].selected().collect::<Vec<_>>(), vec!["web01", "web02"]);
        assert!(!rs[0]
            .hosts
            .iter()
            .find(|h| h.name == "db01")
            .unwrap()
            .targeted());
    }

    #[test]
    fn a_name_that_is_a_host_and_a_group_is_ambiguous() {
        let body = "hosts:\n  web: {}\n  web01: {}\n  web02: {}\ngroups:\n  web:\n    hosts: [web01, web02]\n";
        let i = inv(body, "h.yaml").unwrap();
        let rs = resolutions(&i, &[sel(&["web"], &["web"])]);
        let e = allowed_by(&i, &rs, "web").expect_err("ambiguous");
        assert!(
            e.message.contains("both a host and a group"),
            "{}",
            e.message
        );
        assert_eq!(allowed_by(&i, &rs, "host:web").unwrap(), vec!["web"]);
        assert_eq!(
            allowed_by(&i, &rs, "group:web").unwrap(),
            vec!["web01", "web02"]
        );
        // A glob matches host names only, so `web*` is not the group.
        assert!(
            allowed_by(&i, &rs, "web").is_err(),
            "ambiguity is not decided by what is targeted"
        );
        assert_eq!(
            allowed_by(&i, &rs, "web0*").unwrap(),
            vec!["web01", "web02"]
        );
    }

    #[test]
    fn every_item_must_reach_a_targeted_host_in_some_recipe() {
        let i = inv(INV, "h.yaml").unwrap();
        let rs = resolutions(&i, &[sel(&[], &["web"]), sel(&["db01"], &[])]);
        assert_eq!(
            allowed_by(&i, &rs, "db01,web02").unwrap(),
            vec!["db01", "web02"]
        );
        let one = resolutions(&i, &[sel(&["web01"], &[])]);
        let e = allowed_by(&i, &one, "web01,web02").expect_err("web02 targeted by none");
        assert!(e.message.contains("web02"), "{}", e.message);
    }

    #[test]
    fn apply_allowed_only_ever_excludes() {
        let i = inv(INV, "h.yaml").unwrap();
        let mut r = resolve(&i, Some(&sel(&[], &["web"])), "x").unwrap();
        r.apply_allowed(&BTreeSet::from(["web01".to_string(), "db01".to_string()]));
        assert_eq!(r.selected().collect::<Vec<_>>(), vec!["web01"]);
        assert_eq!(r.targeted().collect::<Vec<_>>(), vec!["web01", "web02"]);
        let web02 = r.hosts.iter().find(|h| h.name == "web02").unwrap();
        assert!(web02.excluded_by_limit() && !web02.selected() && web02.targeted());
        // The reasons are kept; the untargeted host is neither selected nor
        // "excluded by --limit".
        assert_eq!(web02.reasons, vec!["group:web"]);
        let db = r.hosts.iter().find(|h| h.name == "db01").unwrap();
        assert!(!db.excluded_by_limit() && !db.selected() && !db.targeted());
        // A wider set afterwards cannot bring a host back.
        r.apply_allowed(&BTreeSet::from([
            "web01".to_string(),
            "web02".to_string(),
            "db01".to_string(),
        ]));
        assert_eq!(r.selected().collect::<Vec<_>>(), vec!["web01"]);
        // An empty set excludes every targeted host and nothing else.
        r.apply_allowed(&BTreeSet::new());
        assert_eq!(r.selected().count(), 0);
        assert_eq!(r.targeted().collect::<Vec<_>>(), vec!["web01", "web02"]);
    }
}
