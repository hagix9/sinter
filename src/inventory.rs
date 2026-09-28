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
//! Deliberately absent: nested groups, group or host variables, patterns,
//! an implicit "all" group, dynamic inventory, per-host sudo (privilege is
//! an invocation-level `--sudo`, DESIGN §21).

use crate::document::{valid_name, TargetSelector};
use crate::error::{Result, SinterError};
use serde::Deserialize;
use std::collections::BTreeMap;
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
    /// the host is not selected (SKIP).
    pub reasons: Vec<String>,
}

impl HostMatch {
    pub fn selected(&self) -> bool {
        !self.reasons.is_empty()
    }
}

/// Target resolution of one recipe against an inventory: every inventory
/// host, in name order, with its match reasons.
#[derive(Debug, Clone)]
pub struct Resolution {
    pub hosts: Vec<HostMatch>,
}

impl Resolution {
    pub fn selected(&self) -> impl Iterator<Item = &str> {
        self.hosts
            .iter()
            .filter(|h| h.selected())
            .map(|h| h.name.as_str())
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
            }
        })
        .collect();
    if !hosts.iter().any(HostMatch::selected) {
        return Err(SinterError::schema(format!(
            "recipe {recipe}: targets select no inventory host"
        )));
    }
    Ok(Resolution { hosts })
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
}
