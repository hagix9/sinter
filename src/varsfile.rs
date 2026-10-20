//! Variables files: common, group and host values for declared recipe
//! variables (DESIGN §19.5).
//!
//! ```yaml
//! version: 1
//! vars:                 # common: every host
//!   app_port: 8080
//! groups:               # inventory group names
//!   web:
//!     app_port: 8081
//! hosts:                # inventory host names (--host: that string; local: localhost)
//!   web01:
//!     app_root: /srv/web01
//! ```
//!
//! Precedence, lowest to highest: the recipe default, `vars`, `groups`,
//! `hosts`. Everything here runs before anything connects, and no message
//! built here contains a value from the file: the YAML/TOML front ends echo
//! source text in their errors, so this module reads the file through a
//! parser of its own that reports a fixed description and a position only.

use crate::bundle::Loaded;
use crate::document::valid_name;
use crate::inventory::Inventory;
use crate::model::{Model, Prepared, VarOverrides};
use crate::value::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Largest variables file accepted.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Most problems listed by one static gate; the rest are counted.
pub const MAX_REPORTED: usize = 50;

const TOP_LEVEL_FIELDS: &[&str] = &["version", "vars", "groups", "hosts"];

/// A variables file that passed its own checks (not yet the recipes').
#[derive(Debug, Clone)]
pub struct VarsFile {
    pub path: PathBuf,
    /// `vars`: common values.
    pub common: BTreeMap<String, Value>,
    /// `groups.<name>`.
    pub groups: BTreeMap<String, BTreeMap<String, Value>>,
    /// `hosts.<name>`.
    pub hosts: BTreeMap<String, BTreeMap<String, Value>>,
}

/// Why a variables file or a run's variables were refused: every problem
/// found, one line each, none carrying a value from the file.
#[derive(Debug, Clone, PartialEq)]
pub struct Problems(pub Vec<String>);

/// How the hosts of a run are named (DESIGN §19.5, modes).
pub enum Mode<'a> {
    /// `--inventory`: inventory names and group membership.
    Inventory(&'a Inventory),
    /// `--host <H>` or the local target (`localhost`): no group membership.
    Single,
}

/// Variable names a file may set: `[A-Za-z0-9_]`, 1–128 characters.
pub fn valid_var_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A name from the file for a message: shown only when it is a valid name of
/// its kind, so text that is not a name (possibly a misplaced value) never is.
fn shown(name: &str, valid: bool) -> String {
    if valid {
        name.to_string()
    } else {
        "(invalid name, not shown)".to_string()
    }
}

/// Read and check a variables file. An unreadable or unparsable file is one
/// problem (nothing else is checked); otherwise every schema problem is
/// collected.
pub fn load_vars_file(path: &Path) -> Result<VarsFile, Problems> {
    let ctx = format!("variables file {}", path.display());
    let fail = |what: String| Problems(vec![format!("{ctx}: {what}")]);
    let meta = std::fs::metadata(path).map_err(|e| fail(format!("cannot read: {e}")))?;
    if !meta.is_file() {
        return Err(fail("is not a regular file".into()));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(fail(format!(
            "is larger than {MAX_FILE_BYTES} bytes (1 MiB)"
        )));
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    let yaml = match ext.as_deref() {
        Some("yaml" | "yml") => true,
        Some("toml") => false,
        _ => {
            return Err(fail(
                "has an unsupported extension (use .yaml, .yml or .toml)".into(),
            ))
        }
    };
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| fail(format!("cannot read: {e}")))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(fail(format!(
            "is larger than {MAX_FILE_BYTES} bytes (1 MiB)"
        )));
    }
    let text = match std::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(e) => {
            let (line, col) = line_col(&bytes[..e.valid_up_to()]);
            return Err(fail(format!(
                "is not valid UTF-8 (line {line}, column {col}); the content is not shown"
            )));
        }
    };
    let root = if yaml {
        parse_yaml_quiet(text)
    } else {
        parse_toml_quiet(text)
    }
    .map_err(fail)?;
    check_schema(path, &ctx, &root)
}

/// Line and column (both from 1) just after `prefix`.
fn line_col(prefix: &[u8]) -> (usize, usize) {
    let line = prefix.iter().filter(|b| **b == b'\n').count() + 1;
    let start = prefix
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    let col = String::from_utf8_lossy(&prefix[start..]).chars().count() + 1;
    (line, col)
}

/// YAML through the strict front end, reporting a fixed description and a
/// position only. A scanner error carries its position; a problem the front
/// end finds afterwards (duplicate key, anchor, tag, number range, several
/// documents) has none that is free of content, so none is given.
fn parse_yaml_quiet(text: &str) -> Result<Value, String> {
    let mut parser = saphyr_parser::Parser::new_from_str(text);
    while let Some(ev) = parser.next_event() {
        if let Err(e) = ev {
            let m = e.marker();
            return Err(format!(
                "YAML syntax error at line {}, column {}; the content is not shown",
                m.line(),
                m.col() + 1
            ));
        }
    }
    crate::yaml::parse_yaml(text).map_err(|_| {
        "unsupported or invalid YAML content (a duplicate key, an anchor, alias or \
         merge key, a tag, an out-of-range number, or several documents); the position \
         and the content are not shown"
            .to_string()
    })
}

/// TOML likewise: a syntax error with its position, a datetime or non-finite
/// number (refused by the front end) without one.
fn parse_toml_quiet(text: &str) -> Result<Value, String> {
    if let Err(e) = text.parse::<toml::Value>() {
        return Err(match e.span() {
            Some(span) => {
                let (line, col) = line_col(&text.as_bytes()[..span.start.min(text.len())]);
                format!("TOML syntax error at line {line}, column {col}; the content is not shown")
            }
            None => "TOML syntax error; the content is not shown".to_string(),
        });
    }
    crate::toml_front::parse_toml(text).map_err(|_| {
        "unsupported TOML value (a datetime or a non-finite number); the position and the \
         content are not shown"
            .to_string()
    })
}

fn check_schema(path: &Path, ctx: &str, root: &Value) -> Result<VarsFile, Problems> {
    let mut problems = Vec::new();
    let mut out = VarsFile {
        path: path.to_path_buf(),
        common: BTreeMap::new(),
        groups: BTreeMap::new(),
        hosts: BTreeMap::new(),
    };
    let Some(map) = root.as_map() else {
        return Err(Problems(vec![format!(
            "{ctx}: the top level must be a map"
        )]));
    };
    // An unknown key is never shown: only four are allowed, so its text
    // adds nothing a reader needs, and it could be a misplaced value.
    for k in map.keys() {
        if !TOP_LEVEL_FIELDS.contains(&k.as_str()) {
            problems.push(format!(
                "{ctx}: unknown top-level field (not shown; allowed: version, vars, groups, hosts)"
            ));
        }
    }
    match map.get("version") {
        Some(Value::Int(1)) => {}
        Some(_) => problems.push(format!("{ctx}: version must be 1")),
        None => problems.push(format!("{ctx}: missing required field version")),
    }
    if let Some(v) = map.get("vars") {
        out.common = layer(ctx, "vars", v, &mut problems);
    }
    for (key, target) in [("groups", &mut out.groups), ("hosts", &mut out.hosts)] {
        let Some(v) = map.get(key) else { continue };
        let Some(entries) = v.as_map() else {
            problems.push(format!("{ctx}: {key} must be a map of names to variables"));
            continue;
        };
        for (name, vars) in entries {
            if !valid_name(name) {
                problems.push(format!(
                    "{ctx}: {key}: {} (names match [A-Za-z0-9._-], start alphanumeric, \
                     at most 64 characters)",
                    shown(name, false)
                ));
                continue;
            }
            let label = format!("{key}.{name}");
            let vars = layer(ctx, &label, vars, &mut problems);
            target.insert(name.clone(), vars);
        }
    }
    if problems.is_empty() {
        Ok(out)
    } else {
        Err(Problems(problems))
    }
}

/// One layer: a map of variable name to a non-null value.
fn layer(ctx: &str, label: &str, v: &Value, problems: &mut Vec<String>) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let Some(m) = v.as_map() else {
        problems.push(format!(
            "{ctx}: {label} must be a map of variable names to values"
        ));
        return out;
    };
    for (name, value) in m {
        if !valid_var_name(name) {
            problems.push(format!(
                "{ctx}: {label}: {} (variable names match [A-Za-z0-9_], 1-128 characters)",
                shown(name, false)
            ));
        } else if value.is_null() {
            problems.push(format!("{ctx}: {label}: variable {name} may not be null"));
        } else {
            out.insert(name.clone(), value.clone());
        }
    }
    out
}

/// Which layer of a variables file a value is in.
#[derive(Debug, Clone, Copy)]
enum Layer<'a> {
    Common,
    Group(&'a str),
    Host(&'a str),
}

/// How much of the file's host-specific layers the static gate checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Every layer of the file, whichever hosts run (the checks of v1.6.0;
    /// what a run without `--limit` uses).
    All,
    /// Only the layers that apply to the hosts in `pairs`: the common layer,
    /// the groups those hosts belong to and the hosts themselves. A type
    /// mismatch or an undeclared name in any other `groups.*`/`hosts.*` layer
    /// is not a reason to stop (DESIGN §19.5, `--limit`). The structure of
    /// the file and the inventory, the common layer, the ban on overriding a
    /// sensitive variable (in every layer) and group conflicts of the listed
    /// hosts are checked as always.
    Selected,
}

impl VarsFile {
    /// Every (layer, label, name, value) of the file, in a fixed order.
    fn entries(&self) -> Vec<(Layer<'_>, String, &String, &Value)> {
        let mut out: Vec<(Layer<'_>, String, &String, &Value)> = self
            .common
            .iter()
            .map(|(n, v)| (Layer::Common, "vars".to_string(), n, v))
            .collect();
        for (g, vars) in &self.groups {
            for (n, v) in vars {
                out.push((Layer::Group(g), format!("groups.{g}"), n, v));
            }
        }
        for (h, vars) in &self.hosts {
            for (n, v) in vars {
                out.push((Layer::Host(h), format!("hosts.{h}"), n, v));
            }
        }
        out
    }

    /// The values for host `host` of a recipe declaring `declared`: common,
    /// then the host's groups (`groups_of_host`, conflicts already refused),
    /// then the host layer.
    pub fn overrides_for(
        &self,
        declared: &BTreeSet<&str>,
        host: &str,
        groups_of_host: &[String],
    ) -> VarOverrides {
        let mut values: BTreeMap<&str, (&Value, String)> = BTreeMap::new();
        for (n, v) in &self.common {
            values.insert(n, (v, "vars".to_string()));
        }
        let mut from_groups: BTreeMap<&str, (&Value, Vec<&str>)> = BTreeMap::new();
        for g in groups_of_host {
            for (n, v) in self.groups.get(g).into_iter().flatten() {
                from_groups.entry(n).or_insert((v, Vec::new())).1.push(g);
            }
        }
        for (n, (v, gs)) in from_groups {
            let label = gs
                .iter()
                .map(|g| format!("groups.{g}"))
                .collect::<Vec<_>>()
                .join("+");
            values.insert(n, (v, label));
        }
        for (n, v) in self.hosts.get(host).into_iter().flatten() {
            values.insert(n, (v, format!("hosts.{host}")));
        }
        let mut out = VarOverrides::default();
        for (n, (v, label)) in values {
            if declared.contains(n) {
                out.insert(n, v.clone(), &label);
            }
        }
        out
    }
}

/// The inventory groups that contain `host`, by name.
pub fn groups_of(inv: &Inventory, host: &str) -> Vec<String> {
    inv.groups
        .iter()
        .filter(|(_, members)| members.iter().any(|m| m == host))
        .map(|(g, _)| g.clone())
        .collect()
}

/// The static gate of a run with a variables file (DESIGN §19.5): check the
/// file against the recipes, the inventory and the mode, then freeze every
/// (recipe, host) execution of `pairs` with its own values. Returns one model
/// per pair, in order, or every problem found (deduplicated, at most
/// [`MAX_REPORTED`] listed). Nothing here contacts a host.
pub fn freeze_executions(
    units: &[Loaded<Prepared>],
    vf: &VarsFile,
    mode: &Mode,
    pairs: &[(usize, String)],
) -> Result<Vec<Model>, Problems> {
    freeze_executions_in(units, vf, mode, pairs, Scope::All)
}

/// [`freeze_executions`] with a choice of how many host-specific layers of
/// the file are checked ([`Scope`]).
pub fn freeze_executions_in(
    units: &[Loaded<Prepared>],
    vf: &VarsFile,
    mode: &Mode,
    pairs: &[(usize, String)],
    scope: Scope,
) -> Result<Vec<Model>, Problems> {
    // The layers that apply to the executions of `pairs`.
    let applicable: Option<(BTreeSet<&str>, BTreeSet<String>)> = match scope {
        Scope::All => None,
        Scope::Selected => {
            let hosts: BTreeSet<&str> = pairs.iter().map(|(_, h)| h.as_str()).collect();
            let groups = match mode {
                Mode::Inventory(inv) => hosts.iter().flat_map(|h| groups_of(inv, h)).collect(),
                Mode::Single => BTreeSet::new(),
            };
            Some((hosts, groups))
        }
    };
    let declared: Vec<BTreeMap<&str, (&Value, bool)>> = units
        .iter()
        .map(|u| u.item.declared().map(|(n, v, s)| (n, (v, s))).collect())
        .collect();

    // Override problems: names, types, sensitivity, layers and the mode.
    let mut problems = Vec::new();
    for (layer, label, name, value) in vf.entries() {
        let in_scope = match (&applicable, layer) {
            (None, _) | (Some(_), Layer::Common) => true,
            (Some((hosts, _)), Layer::Host(h)) => hosts.contains(h),
            (Some((_, groups)), Layer::Group(g)) => groups.contains(g),
        };
        let mut declaring = 0;
        for (u, decl) in units.iter().zip(&declared) {
            let Some((default, sensitive)) = decl.get(name.as_str()) else {
                continue;
            };
            declaring += 1;
            if *sensitive {
                problems.push(format!(
                    "{label}: variable {name} is declared sensitive by recipe {}; a variables \
                     file cannot override a sensitive variable",
                    u.label
                ));
            } else if in_scope && default.type_name() != value.type_name() {
                problems.push(format!(
                    "{label}: variable {name}: recipe {} declares {} {}, the variables file \
                     gives {} {}",
                    u.label,
                    article(default.type_name()),
                    default.type_name(),
                    article(value.type_name()),
                    value.type_name()
                ));
            }
        }
        if in_scope && declaring == 0 {
            problems.push(format!(
                "{label}: variable {name} is not declared by any recipe of this run"
            ));
        }
    }
    match mode {
        Mode::Inventory(inv) => {
            for g in vf.groups.keys() {
                if !inv.groups.contains_key(g) {
                    problems.push(format!(
                        "groups.{g}: group {g} is not defined in inventory {}",
                        inv.path.display()
                    ));
                }
            }
            for h in vf.hosts.keys() {
                if !inv.hosts.contains_key(h) {
                    problems.push(format!(
                        "hosts.{h}: host {h} is not defined in inventory {}",
                        inv.path.display()
                    ));
                }
            }
            let hosts: BTreeSet<&str> = pairs.iter().map(|(_, h)| h.as_str()).collect();
            for h in hosts {
                problems.extend(group_conflicts(vf, h, &groups_of(inv, h)));
            }
        }
        Mode::Single => {
            for g in vf.groups.keys() {
                problems.push(format!(
                    "groups.{g}: group variables need --inventory; with --host or the local \
                     target there is no group membership (a one-host inventory gives a single \
                     host its groups)"
                ));
            }
        }
    }
    if !problems.is_empty() {
        return Err(Problems(capped(problems)));
    }

    // Per-execution freeze. Executions of one recipe with identical values
    // share a model; nothing else is shared.
    let mut frozen: Vec<(usize, VarOverrides, Result<Model, String>)> = Vec::new();
    let mut failures: BTreeMap<(usize, String), Vec<&str>> = BTreeMap::new();
    let mut out = Vec::with_capacity(pairs.len());
    for (unit, host) in pairs {
        let names: BTreeSet<&str> = declared[*unit].keys().copied().collect();
        let groups = match mode {
            Mode::Inventory(inv) => groups_of(inv, host),
            Mode::Single => Vec::new(),
        };
        let ov = vf.overrides_for(&names, host, &groups);
        let i = match frozen.iter().position(|(u, o, _)| u == unit && *o == ov) {
            Some(i) => i,
            None => {
                let prepared = &units[*unit].item;
                let model = if ov.is_empty() {
                    prepared.clone().freeze_default()
                } else {
                    prepared.freeze_with(&ov)
                };
                frozen.push((*unit, ov, model.map_err(|e| e.message)));
                frozen.len() - 1
            }
        };
        match &frozen[i].2 {
            Ok(m) => out.push(m.clone()),
            Err(msg) => failures.entry((*unit, msg.clone())).or_default().push(host),
        }
    }
    if failures.is_empty() {
        return Ok(out);
    }
    let lines = failures
        .into_iter()
        .map(|((unit, msg), hosts)| {
            format!(
                "recipe {} @ {}: {}",
                units[unit].label,
                hosts.join(", "),
                msg
            )
        })
        .collect();
    Err(Problems(capped(lines)))
}

/// Two of the host's groups giving one variable different values, with no
/// host value to settle it.
fn group_conflicts(vf: &VarsFile, host: &str, groups: &[String]) -> Vec<String> {
    let mut by_var: BTreeMap<&str, Vec<(&str, &Value)>> = BTreeMap::new();
    for g in groups {
        for (n, v) in vf.groups.get(g).into_iter().flatten() {
            by_var.entry(n).or_default().push((g, v));
        }
    }
    let host_vars = vf.hosts.get(host);
    let mut out = Vec::new();
    for (n, given) in by_var {
        let differ = given.windows(2).any(|w| w[0].1 != w[1].1);
        if differ && !host_vars.is_some_and(|h| h.contains_key(n)) {
            let gs: Vec<&str> = given.iter().map(|(g, _)| *g).collect();
            out.push(format!(
                "hosts.{host}: variable {n} is given different values by groups {}; set it in \
                 hosts.{host} to decide",
                gs.join(", ")
            ));
        }
    }
    out
}

/// The indefinite article for a [`Value::type_name`] ("an integer", "a string").
fn article(type_name: &str) -> &'static str {
    if type_name.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    }
}

fn capped(mut lines: Vec<String>) -> Vec<String> {
    if lines.len() > MAX_REPORTED {
        let more = lines.len() - MAX_REPORTED;
        lines.truncate(MAX_REPORTED);
        lines.push(format!("... and {more} more problem(s) not listed"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::InventoryHost;

    /// A fictitious value that must never reach a message.
    const CANARY: &str = "SINTER_VARS_CANARY_DO_NOT_PRINT_20261019";

    fn file(dir: &tempfile::TempDir, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    fn load(name: &str, body: &str) -> Result<VarsFile, Problems> {
        let d = tempfile::tempdir().unwrap();
        load_vars_file(&file(&d, name, body.as_bytes()))
    }

    fn problems(r: Result<VarsFile, Problems>) -> Vec<String> {
        let p = r.unwrap_err().0;
        for line in &p {
            assert!(!line.contains(CANARY), "LEAK: {line}");
        }
        p
    }

    fn s(v: &str) -> Value {
        Value::Str(v.to_string())
    }

    #[test]
    fn yaml_and_toml_read_the_same_layers() {
        let y = load(
            "v.yaml",
            "version: 1\nvars: { a: 1, b: x }\ngroups:\n  web: { a: 2 }\nhosts:\n  web01: { b: \"{{ not.evaluated }}\" }\n",
        )
        .unwrap();
        let t = load(
            "v.toml",
            "version = 1\n[vars]\na = 1\nb = \"x\"\n[groups.web]\na = 2\n[hosts.web01]\nb = \"{{ not.evaluated }}\"\n",
        )
        .unwrap();
        for v in [&y, &t] {
            assert_eq!(v.common["a"], Value::Int(1));
            assert_eq!(v.groups["web"]["a"], Value::Int(2));
            assert_eq!(v.hosts["web01"]["b"], s("{{ not.evaluated }}"));
        }
        // An empty file of layers is valid.
        assert!(load("v.yml", "version: 1\n").is_ok());
    }

    #[test]
    fn unreadable_files_are_one_problem() {
        let d = tempfile::tempdir().unwrap();
        let p = problems(load_vars_file(&d.path().join("missing.yaml")));
        assert!(p.len() == 1 && p[0].contains("cannot read"), "{p:?}");
        let p = problems(load_vars_file(d.path()));
        assert!(p[0].contains("is not a regular file"), "{p:?}");
        let big = file(&d, "big.yaml", &vec![b'#'; MAX_FILE_BYTES as usize + 1]);
        assert!(problems(load_vars_file(&big))[0].contains("larger than"));
        let at_limit = file(&d, "limit.yaml", &{
            let mut b = b"version: 1\n".to_vec();
            b.resize(MAX_FILE_BYTES as usize, b'#');
            b
        });
        assert!(load_vars_file(&at_limit).is_ok());
        let json = file(&d, "v.json", b"{}");
        assert!(problems(load_vars_file(&json))[0].contains("unsupported extension"));
    }

    #[test]
    fn parse_errors_show_a_position_and_never_the_content() {
        // (file, body, expected fragment)
        let cases: Vec<(&str, String, &str)> = vec![
            (
                "a.yaml",
                format!("version: 1\nhosts:\n  web01: {{ x: \"{CANARY}\n"),
                "YAML syntax error at line 3, column 15",
            ),
            (
                "b.yaml",
                format!("version: 1\nvars:\n  x: [{CANARY}\n"),
                "YAML syntax error at line",
            ),
            (
                "c.yaml",
                format!("version: 1\nvars:\n  x: 9{}\n", "9".repeat(40)),
                "unsupported or invalid YAML content",
            ),
            (
                "d.yaml",
                format!("version: 1\nvars:\n  x: !!bool {CANARY}\n"),
                "unsupported or invalid YAML content",
            ),
            (
                "e.yaml",
                format!("version: 1\nvars:\n  {CANARY}: 1\n  {CANARY}: 2\n"),
                "unsupported or invalid YAML content",
            ),
            (
                "f.yaml",
                format!("version: 1\nvars:\n  x: !custom {CANARY}\n"),
                "unsupported or invalid YAML content",
            ),
            (
                "g.yaml",
                format!("version: 1\nvars:\n  x: &a {CANARY}\n  y: *a\n"),
                "unsupported or invalid YAML content",
            ),
            (
                "h.toml",
                format!("version = 1\n[vars]\nx = \"{CANARY}\" trailing\n"),
                "TOML syntax error at line 3, column 48",
            ),
            (
                "i.toml",
                format!("version = 1\n[vars]\nx = \"{CANARY}\"\nx = \"{CANARY}\"\n"),
                "TOML syntax error at line 4",
            ),
            (
                "j.toml",
                "version = 1\n[vars]\nx = 1979-05-27\n".to_string(),
                "unsupported TOML value",
            ),
        ];
        for (name, body, want) in cases {
            let p = problems(load(name, &body));
            assert_eq!(p.len(), 1, "{name}: {p:?}");
            assert!(p[0].contains(want), "{name}: want {want:?}: {p:?}");
            assert!(p[0].contains("not shown"), "{name}: {p:?}");
        }
        // The shared front ends do echo content: why this module has its own.
        let toml = format!("x = \"{CANARY}\" trailing\n");
        assert!(crate::toml_front::parse_toml(&toml)
            .unwrap_err()
            .message
            .contains(CANARY));
        let yaml = format!("x: 9{}\n", "9".repeat(40));
        assert!(crate::yaml::parse_yaml(&yaml)
            .unwrap_err()
            .message
            .contains(&"9".repeat(40)));
    }

    #[test]
    fn invalid_utf8_is_reported_with_a_position_only() {
        let d = tempfile::tempdir().unwrap();
        let mut body = format!("version: 1\nvars:\n  x: \"{CANARY}").into_bytes();
        body.extend_from_slice(&[0xff, 0xfe]);
        let p = problems(load_vars_file(&file(&d, "u.yaml", &body)));
        assert!(
            p[0].contains("not valid UTF-8 (line 3, column 47)"),
            "{p:?}"
        );
    }

    #[test]
    fn schema_problems_are_all_reported_and_names_that_are_not_names_are_hidden() {
        let body = format!(
            "version: 2\nextra: 1\n\"{CANARY} x\": 1\nvars:\n  ok: 1\n  \"{CANARY} bad\": 1\n  nothing: null\ngroups:\n  \"{CANARY}!\": {{ a: 1 }}\n  web: [1]\nhosts: 5\n"
        );
        let p = problems(load("v.yaml", &body));
        let all = p.join("\n");
        for want in [
            "unknown top-level field (not shown; allowed: version, vars, groups, hosts)",
            "version must be 1",
            "vars: (invalid name, not shown)",
            "vars: variable nothing may not be null",
            "groups: (invalid name, not shown)",
            "groups.web must be a map of variable names to values",
            "hosts must be a map of names to variables",
        ] {
            assert!(all.contains(want), "want {want:?} in:\n{all}");
        }
        assert_eq!(p.len(), 8, "{all}");
        let p = problems(load("v.yaml", "vars: { a: 1 }\n"));
        assert_eq!(p.len(), 1);
        assert!(p[0].contains("missing required field version"));
        assert!(problems(load("v.yaml", "[1]\n"))[0].contains("top level must be a map"));
    }

    // ---- the static gate ------------------------------------------------

    fn recipe(dir: &tempfile::TempDir, name: &str, body: &str) -> Loaded<Prepared> {
        let p = file(dir, name, body.as_bytes());
        Loaded {
            label: name.trim_end_matches(".yaml").to_string(),
            path: p.clone(),
            item: crate::model::prepare(&p).unwrap(),
        }
    }

    fn vars(body: &str) -> VarsFile {
        load("v.yaml", body).unwrap()
    }

    fn inventory(groups: &[(&str, &[&str])]) -> Inventory {
        let mut hosts = BTreeMap::new();
        for (_, members) in groups {
            for h in *members {
                hosts.insert(
                    h.to_string(),
                    InventoryHost {
                        name: h.to_string(),
                        address: h.to_string(),
                        port: None,
                        user: None,
                        known_hosts: None,
                        identity_files: Vec::new(),
                    },
                );
            }
        }
        Inventory {
            path: PathBuf::from("hosts.yaml"),
            hosts,
            groups: groups
                .iter()
                .map(|(g, m)| (g.to_string(), m.iter().map(|h| h.to_string()).collect()))
                .collect(),
        }
    }

    fn pairs(list: &[(usize, &str)]) -> Vec<(usize, String)> {
        list.iter().map(|(u, h)| (*u, h.to_string())).collect()
    }

    const SITE: &str = "version: 1\ntargets: { groups: [web] }\nvars:\n  root: { value: CHANGE_ME }\n  port: { value: 80 }\n  tier: { value: none }\nresources:\n  - id: index\n    type: file\n    with: { path: \"{{ vars.root }}/index.html\", content: \"{{ vars.port }} {{ vars.tier }}\" }\n";

    fn var(m: &Model, n: &str) -> Value {
        m.vars[n].value.clone()
    }

    #[test]
    fn precedence_is_default_common_group_host() {
        let d = tempfile::tempdir().unwrap();
        let units = vec![recipe(&d, "site.yaml", SITE)];
        let inv = inventory(&[("web", &["web01", "web02"]), ("eu", &["web02"])]);
        let vf = vars(
            "version: 1\nvars: { root: /srv/common, port: 8080 }\ngroups:\n  web: { port: 8081 }\n  eu: { tier: gold }\nhosts:\n  web02: { root: /srv/web02 }\n",
        );
        let m = freeze_executions(
            &units,
            &vf,
            &Mode::Inventory(&inv),
            &pairs(&[(0, "web01"), (0, "web02")]),
        )
        .unwrap();
        assert_eq!(
            m[0].resources[0].path.as_deref(),
            Some("/srv/common/index.html")
        );
        assert_eq!(var(&m[0], "port"), Value::Int(8081));
        assert_eq!(var(&m[0], "tier"), s("none"));
        assert_eq!(
            m[1].resources[0].path.as_deref(),
            Some("/srv/web02/index.html")
        );
        assert_eq!(var(&m[1], "port"), Value::Int(8081));
        assert_eq!(var(&m[1], "tier"), s("gold"));
    }

    #[test]
    fn each_layer_alone_applies() {
        let d = tempfile::tempdir().unwrap();
        let units = vec![recipe(&d, "site.yaml", SITE)];
        let inv = inventory(&[("web", &["web01", "web02"])]);
        let p = pairs(&[(0, "web01"), (0, "web02")]);
        for (body, w1, w2) in [
            ("version: 1\nvars: { root: /c }\n", "/c", "/c"),
            ("version: 1\ngroups: { web: { root: /g } }\n", "/g", "/g"),
            (
                "version: 1\nhosts: { web01: { root: /h1 }, web02: { root: /h2 } }\n",
                "/h1",
                "/h2",
            ),
        ] {
            let m = freeze_executions(&units, &vars(body), &Mode::Inventory(&inv), &p).unwrap();
            assert_eq!(var(&m[0], "root"), s(w1));
            assert_eq!(var(&m[1], "root"), s(w2));
            assert_eq!(var(&m[0], "port"), Value::Int(80), "default kept");
        }
    }

    /// `Scope::Selected` checks only the layers that apply to the hosts in
    /// `pairs`; everything structural, the common layer and the ban on
    /// overriding a sensitive variable stay global. `Scope::All` is v1.6.0.
    #[test]
    fn a_selected_scope_checks_only_the_layers_of_the_selected_hosts() {
        let d = tempfile::tempdir().unwrap();
        let sens = "version: 1\nvars:\n  root: { value: /ok }\n  port: { value: 80 }\n  tok: { value: s, sensitive: true }\nresources:\n  - id: index\n    type: file\n    with: { path: \"{{ vars.root }}/index.html\", content: \"{{ vars.port }} {{ vars.tok }}\" }\n";
        let units = vec![recipe(&d, "site.yaml", &SITE.replace("CHANGE_ME", "/ok"))];
        let sunits = vec![recipe(&d, "sens.yaml", sens)];
        let inv = inventory(&[
            ("web", &["web01", "web02"]),
            ("db", &["db01"]),
            ("linux", &["web01", "web02", "db01"]),
            ("ops", &["web01"]),
        ]);
        let mode = Mode::Inventory(&inv);
        let web = pairs(&[(0, "web01"), (0, "web02")]);
        let run = |units: &[Loaded<Prepared>], body: &str, scope: Scope| {
            freeze_executions_in(units, &vars(body), &mode, &web, scope)
        };
        // (file, outcome with Scope::Selected, outcome with Scope::All) for
        // the hosts web01 and web02; true = accepted.
        let cases: [(&str, bool, bool); 12] = [
            // db01 is not selected: its own layer and its group's layer are
            // not checked ...
            ("version: 1\nhosts: { db01: { port: x } }\n", true, false),
            ("version: 1\ngroups: { db: { port: x } }\n", true, false),
            ("version: 1\nhosts: { db01: { typo: 1 } }\n", true, false),
            // ... a selected host's, a selected group's and the common layer are.
            ("version: 1\nhosts: { web01: { port: x } }\n", false, false),
            ("version: 1\ngroups: { web: { port: x } }\n", false, false),
            ("version: 1\ngroups: { ops: { port: x } }\n", false, false),
            ("version: 1\ngroups: { linux: { port: x } }\n", false, false),
            ("version: 1\nvars: { port: x }\n", false, false),
            ("version: 1\nvars: { nope: 1 }\n", false, false),
            // The structure stays global: a host the inventory does not
            // define, a group it does not define.
            ("version: 1\nhosts: { ghost: { port: 1 } }\n", false, false),
            ("version: 1\ngroups: { ghost: { port: 1 } }\n", false, false),
            // Valid values for an unselected host change nothing.
            ("version: 1\nhosts: { db01: { port: 9 } }\n", true, true),
        ];
        for (i, (body, selected, all)) in cases.iter().enumerate() {
            assert_eq!(
                run(&units, body, Scope::Selected).is_ok(),
                *selected,
                "selected, case {i}"
            );
            assert_eq!(run(&units, body, Scope::All).is_ok(), *all, "all, case {i}");
        }
        // A sensitive variable cannot be overridden in any layer, selected or not.
        for body in [
            "version: 1\nhosts: { db01: { tok: x } }\n",
            "version: 1\ngroups: { db: { tok: x } }\n",
            "version: 1\nvars: { tok: x }\n",
        ] {
            for scope in [Scope::Selected, Scope::All] {
                let p = run(&sunits, body, scope).unwrap_err().0;
                assert!(p.iter().any(|l| l.contains("sensitive")), "{body}: {p:?}");
            }
        }
        // Group conflicts are only looked for in the selected hosts.
        let conflict = "version: 1\ngroups: { web: { port: 1 }, ops: { port: 2 } }\n";
        assert!(
            run(&units, conflict, Scope::Selected).is_err(),
            "web01 is in both"
        );
        let only_web02 = pairs(&[(0, "web02")]);
        assert!(
            freeze_executions_in(&units, &vars(conflict), &mode, &only_web02, Scope::Selected)
                .is_ok(),
            "web02 is only in web"
        );
        assert!(
            freeze_executions_in(&units, &vars(conflict), &mode, &only_web02, Scope::All).is_ok()
        );
    }

    #[test]
    fn group_conflicts_need_a_host_value() {
        let d = tempfile::tempdir().unwrap();
        let units = vec![recipe(&d, "site.yaml", SITE)];
        let inv = inventory(&[("web", &["web01", "web02"]), ("db", &["web01"])]);
        let p = pairs(&[(0, "web01"), (0, "web02")]);
        // Equal values are no conflict.
        let vf =
            vars("version: 1\nvars: { root: /r }\ngroups: { web: { port: 1 }, db: { port: 1 } }\n");
        assert!(freeze_executions(&units, &vf, &Mode::Inventory(&inv), &p).is_ok());
        // Different values: an error for web01 only.
        let vf = vars(&format!(
            "version: 1\nvars: {{ root: /r }}\ngroups: {{ web: {{ tier: a{CANARY} }}, db: {{ tier: b{CANARY} }} }}\n"
        ));
        let e = freeze_executions(&units, &vf, &Mode::Inventory(&inv), &p)
            .unwrap_err()
            .0;
        assert_eq!(
            e,
            vec!["hosts.web01: variable tier is given different values by groups db, web; set it in hosts.web01 to decide".to_string()]
        );
        // The host layer decides.
        let vf = vars(&format!(
            "version: 1\nvars: {{ root: /r }}\ngroups: {{ web: {{ tier: a{CANARY} }}, db: {{ tier: b{CANARY} }} }}\nhosts: {{ web01: {{ tier: c }} }}\n"
        ));
        let m = freeze_executions(&units, &vf, &Mode::Inventory(&inv), &p).unwrap();
        assert_eq!(var(&m[0], "tier"), s("c"));
        assert_eq!(var(&m[1], "tier"), s(&format!("a{CANARY}")));
        // Same type, different kind of number is a different value.
        let vf =
            vars("version: 1\nvars: { root: /r }\ngroups: { web: { port: 1 }, db: { port: 2 } }\n");
        assert_eq!(
            freeze_executions(&units, &vf, &Mode::Inventory(&inv), &p)
                .unwrap_err()
                .0
                .len(),
            1
        );
    }

    #[test]
    fn override_problems_are_collected_without_values() {
        let d = tempfile::tempdir().unwrap();
        let units = vec![recipe(
            &d,
            "site.yaml",
            "version: 1\nvars:\n  root: { value: /r }\n  port: { value: 80 }\n  tok: { value: t, sensitive: true }\nresources: []\n",
        )];
        let inv = inventory(&[("web", &["web01"])]);
        let vf = vars(&format!(
            "version: 1\nvars: {{ nope: {CANARY}, tok: {CANARY}, port: \"{CANARY}\" }}\ngroups: {{ ghost: {{ root: /x }} }}\nhosts: {{ web99: {{ root: /y }} }}\n"
        ));
        let e = freeze_executions(&units, &vf, &Mode::Inventory(&inv), &pairs(&[(0, "web01")]))
            .unwrap_err()
            .0;
        assert_eq!(
            e,
            vec![
                "vars: variable nope is not declared by any recipe of this run".to_string(),
                "vars: variable port: recipe site declares an integer, the variables file gives a string".to_string(),
                "vars: variable tok is declared sensitive by recipe site; a variables file cannot override a sensitive variable".to_string(),
                "groups.ghost: group ghost is not defined in inventory hosts.yaml".to_string(),
                "hosts.web99: host web99 is not defined in inventory hosts.yaml".to_string(),
            ]
        );
        // Deterministic.
        let again = freeze_executions(&units, &vf, &Mode::Inventory(&inv), &pairs(&[(0, "web01")]))
            .unwrap_err()
            .0;
        assert_eq!(e, again);
    }

    #[test]
    fn single_target_mode_has_no_groups() {
        let d = tempfile::tempdir().unwrap();
        let units = vec![recipe(&d, "site.yaml", SITE)];
        let vf = vars(
            "version: 1\nvars: { root: /c }\nhosts: { web01: { root: /h }, other: { root: /o } }\n",
        );
        for (host, want) in [("web01", "/h"), ("localhost", "/c"), ("192.0.2.1", "/c")] {
            let m = freeze_executions(&units, &vf, &Mode::Single, &pairs(&[(0, host)])).unwrap();
            assert_eq!(var(&m[0], "root"), s(want), "{host}");
        }
        let vf = vars("version: 1\nhosts: { localhost: { root: /local } }\n");
        let m = freeze_executions(&units, &vf, &Mode::Single, &pairs(&[(0, "localhost")])).unwrap();
        assert_eq!(var(&m[0], "root"), s("/local"));
        // Any group entry is refused, even an empty one.
        for body in [
            "version: 1\nvars: { root: /c }\ngroups: { web: { port: 1 } }\n",
            "version: 1\nvars: { root: /c }\ngroups: { web: {} }\n",
        ] {
            let e = freeze_executions(&units, &vars(body), &Mode::Single, &pairs(&[(0, "web01")]))
                .unwrap_err()
                .0;
            assert_eq!(e.len(), 1);
            assert!(
                e[0].starts_with("groups.web: group variables need --inventory"),
                "{e:?}"
            );
        }
        // `groups: {}` defines no group layer.
        let vf = vars("version: 1\nvars: { root: /c }\ngroups: {}\n");
        assert!(freeze_executions(&units, &vf, &Mode::Single, &pairs(&[(0, "web01")])).is_ok());
    }

    #[test]
    fn bundle_recipes_receive_the_hosts_values_by_declared_name() {
        let d = tempfile::tempdir().unwrap();
        let a = "version: 1\nvars:\n  port: { value: 80 }\n  root: { value: /a }\nresources:\n  - id: a\n    type: file\n    with: { path: \"{{ vars.root }}/a\", content: \"{{ vars.port }}\" }\n";
        let b = "version: 1\nvars:\n  port: { value: 9000 }\nresources:\n  - id: b\n    type: file\n    with: { path: /etc/b, content: \"{{ vars.port }}\" }\n";
        let c = "version: 1\nvars:\n  other: { value: 1 }\nresources: []\n";
        let units = vec![
            recipe(&d, "a.yaml", a),
            recipe(&d, "b.yaml", b),
            recipe(&d, "c.yaml", c),
        ];
        let vf = vars("version: 1\nhosts: { h1: { port: 1 }, h2: { port: 2, root: /two } }\n");
        let p = pairs(&[
            (0, "h1"),
            (0, "h2"),
            (1, "h1"),
            (1, "h2"),
            (2, "h1"),
            (2, "h2"),
        ]);
        let m = freeze_executions(&units, &vf, &Mode::Single, &p).unwrap();
        assert_eq!(var(&m[0], "port"), Value::Int(1));
        assert_eq!(m[0].resources[0].path.as_deref(), Some("/a/a"));
        assert_eq!(var(&m[1], "port"), Value::Int(2));
        assert_eq!(m[1].resources[0].path.as_deref(), Some("/two/a"));
        assert_eq!(var(&m[2], "port"), Value::Int(1));
        assert_eq!(var(&m[3], "port"), Value::Int(2));
        assert!(!m[4].vars.contains_key("port"));
        assert_eq!(var(&m[5], "other"), Value::Int(1));
        // A name declared with different types: the recipe that disagrees.
        let units = vec![
            recipe(&d, "a.yaml", a),
            recipe(
                &d,
                "s.yaml",
                "version: 1\nvars:\n  port: { value: \"80\" }\nresources: []\n",
            ),
        ];
        let e = freeze_executions(&units, &vf, &Mode::Single, &pairs(&[(0, "h1"), (1, "h1")]))
            .unwrap_err()
            .0;
        assert_eq!(
            e,
            vec![
                "hosts.h1: variable port: recipe s declares a string, the variables file gives an integer".to_string(),
                "hosts.h2: variable port: recipe s declares a string, the variables file gives an integer".to_string(),
            ]
        );
    }

    #[test]
    fn per_execution_failures_are_collected_merged_and_withheld() {
        let d = tempfile::tempdir().unwrap();
        let units = vec![
            recipe(&d, "site.yaml", SITE),
            recipe(&d, "dup.yaml", "version: 1\nvars:\n  root: { value: /r }\nresources:\n  - id: x\n    type: file\n    with: { path: /etc/x, content: a }\n  - id: x\n    type: file\n    with: { path: /etc/y, content: b }\n"),
        ];
        let inv = inventory(&[("web", &["web01", "web02", "web03"])]);
        let vf = vars(&format!(
            "version: 1\nvars: {{ root: rel{CANARY} }}\nhosts: {{ web03: {{ root: /ok }} }}\n"
        ));
        let p = pairs(&[
            (0, "web01"),
            (0, "web02"),
            (0, "web03"),
            (1, "web01"),
            (1, "web02"),
        ]);
        let e = freeze_executions(&units, &vf, &Mode::Inventory(&inv), &p)
            .unwrap_err()
            .0;
        assert_eq!(
            e,
            vec![
                "recipe site @ web01, web02: index: file static check failed: field path; it depends on variables from the variables file: root (vars); the value is withheld".to_string(),
                "recipe dup @ web01, web02: duplicate resource id: x".to_string(),
            ]
        );
        assert!(!e.join("\n").contains(CANARY));
        // Problems with the file itself come first and stop before freezing.
        let vf = vars("version: 1\nvars: { root: rel, nope: 1 }\n");
        let e = freeze_executions(&units, &vf, &Mode::Inventory(&inv), &p)
            .unwrap_err()
            .0;
        assert_eq!(
            e,
            vec!["vars: variable nope is not declared by any recipe of this run".to_string()]
        );
    }

    #[test]
    fn at_most_fifty_problems_are_listed() {
        let d = tempfile::tempdir().unwrap();
        let units = vec![recipe(&d, "site.yaml", SITE)];
        let mut body = String::from("version: 1\nvars:\n");
        for i in 0..60 {
            body.push_str(&format!("  v{i:02}: 1\n"));
        }
        let e = freeze_executions(&units, &vars(&body), &Mode::Single, &pairs(&[(0, "h")]))
            .unwrap_err()
            .0;
        assert_eq!(e.len(), MAX_REPORTED + 1);
        assert_eq!(e[MAX_REPORTED], "... and 10 more problem(s) not listed");
        assert!(e[0].contains("v00") && e[49].contains("v49"));
    }

    #[test]
    fn identical_values_share_one_model_and_others_do_not() {
        let d = tempfile::tempdir().unwrap();
        let units = vec![recipe(&d, "site.yaml", SITE)];
        let inv = inventory(&[("web", &["a", "b", "c"])]);
        let vf = vars("version: 1\nvars: { root: /same }\nhosts: { c: { root: /own } }\n");
        let m = freeze_executions(
            &units,
            &vf,
            &Mode::Inventory(&inv),
            &pairs(&[(0, "a"), (0, "b"), (0, "c")]),
        )
        .unwrap();
        assert_eq!(format!("{:?}", m[0]), format!("{:?}", m[1]));
        assert_eq!(m[2].resources[0].path.as_deref(), Some("/own/index.html"));
        // Nothing overridden: the established model.
        let vf = vars("version: 1\n");
        let units = vec![recipe(&d, "plain.yaml", "version: 1\nvars:\n  x: { value: 1 }\nresources:\n  - id: f\n    type: file\n    with: { path: /etc/f, content: \"{{ vars.x }}\" }\n")];
        let m = freeze_executions(&units, &vf, &Mode::Single, &pairs(&[(0, "h")])).unwrap();
        let established = crate::model::load_model(&units[0].path).unwrap();
        assert_eq!(format!("{:?}", m[0]), format!("{established:?}"));
    }

    #[test]
    fn group_membership_comes_from_the_inventory() {
        let inv = inventory(&[("web", &["web01", "web02"]), ("db", &["db01", "web01"])]);
        assert_eq!(groups_of(&inv, "web01"), vec!["db", "web"]);
        assert_eq!(groups_of(&inv, "web02"), vec!["web"]);
        assert!(groups_of(&inv, "nope").is_empty());
    }

    #[test]
    fn variable_names_are_identifiers() {
        assert!(
            valid_var_name("app_port") && valid_var_name("A1") && valid_var_name(&"x".repeat(128))
        );
        for bad in ["", "a-b", "a.b", "a b", "ä", &"x".repeat(129)] {
            assert!(!valid_var_name(bad), "{bad}");
        }
    }

    #[test]
    fn every_type_name_takes_its_article() {
        let all = [
            Value::Null,
            Value::Bool(true),
            Value::Int(1),
            Value::Float(1.5),
            Value::Str(String::new()),
            Value::List(Vec::new()),
            Value::Map(BTreeMap::new()),
        ];
        let phrases: Vec<String> = all
            .iter()
            .map(|v| format!("{} {}", article(v.type_name()), v.type_name()))
            .collect();
        assert_eq!(
            phrases,
            [
                "a null",
                "a boolean",
                "an integer",
                "a float",
                "a string",
                "a list",
                "a map"
            ]
        );
    }
}
