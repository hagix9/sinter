//! Connection-risk control (DESIGN §43).
//!
//! Some changes can cut the SSH connection Sinter manages a host through
//! (firewalld zones, sources, interfaces, reload; NetworkManager profiles).
//! This module fixes what Sinter does about them:
//!
//! * [`classify`]: before contact, every resource of a connection-risk type is
//!   R (always needs an approval), C (needs one only if it is found on the
//!   management path) or N. The classification is bound to the registered
//!   catalog digest; a catalog that can run `firewall-cmd`, `nmcli`, `ip` or
//!   `busctl` mutate operations but is not classified is refused.
//! * [`static_gate`]: the before-contact gate (exit 2) for unclassified
//!   catalogs, register-dependent values and R resources without approval.
//! * [`path`]: after contact, which interfaces and which firewalld zone carry
//!   the management connection; anything it cannot determine is unknown.
//! * [`rules`]: whether one change is `clear`, `affects` or `unknown`, and
//!   the decision table of §43.3.
//! * [`approval`]: approval requests, approvals, the plan digest, use markers
//!   and the ledger (§43.4).
//!
//! Nothing here guarantees that a host stays reachable; it only refuses what
//! it cannot show to be safe and asks for an approval for the rest.

pub mod approval;
pub mod engine;
pub mod path;
pub mod rules;

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Result, SinterError};
use crate::model::{FrozenResource, Model};
use crate::plugin::PluginSet;
use crate::value::Value;

/// Static class of a connection-risk resource (DESIGN §43.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskClass {
    /// Never touches the management path (for example adding a service).
    N,
    /// Needs an approval only when found on the management path.
    C,
    /// Always needs an approval.
    R,
}

impl RiskClass {
    pub fn label(self) -> &'static str {
        match self {
            RiskClass::N => "N",
            RiskClass::C => "C",
            RiskClass::R => "R",
        }
    }
}

/// Whether the control is in force for a classified catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    Enforced,
    /// Classified, but the new control is not in force until the Owner
    /// decides (firewalld 0.2.0: decision D-13). Plan reports the class.
    PendingOwner(&'static str),
}

/// One resource type of a classified catalog.
pub struct TypeRule {
    pub type_name: &'static str,
    pub classify: fn(&BTreeMap<String, Value>) -> RiskClass,
    pub rule: rules::RuleKind,
}

/// A registered catalog's classification, bound to its digest.
pub struct CatalogRules {
    pub id: &'static str,
    pub version: &'static str,
    pub sha256: &'static str,
    pub enforcement: Enforcement,
    pub types: &'static [TypeRule],
    /// The class of every mutate operation of the catalog. A resource type
    /// the table does not list (another plugin built on the same catalog) is
    /// classified by the operations it can run: only N operations make it N;
    /// anything else, or an operation missing here, is refused.
    pub ops: &'static [(&'static str, RiskClass)],
}

fn always_n(_: &BTreeMap<String, Value>) -> RiskClass {
    RiskClass::N
}

/// `state: absent` is C, anything else N (firewalld service, port, protocol).
fn absent_is_c(v: &BTreeMap<String, Value>) -> RiskClass {
    match v.get("state") {
        Some(Value::Str(s)) if s == "absent" => RiskClass::C,
        Some(Value::Str(_)) => RiskClass::N,
        _ => RiskClass::C,
    }
}

const FIREWALLD_010: &[TypeRule] = &[TypeRule {
    type_name: "firewalld.service",
    classify: always_n,
    rule: rules::RuleKind::None,
}];

const FIREWALLD_020: &[TypeRule] = &[
    TypeRule {
        type_name: "firewalld.service",
        classify: absent_is_c,
        rule: rules::RuleKind::FwServiceAbsent,
    },
    TypeRule {
        type_name: "firewalld.port",
        classify: absent_is_c,
        rule: rules::RuleKind::FwPortAbsent,
    },
    TypeRule {
        type_name: "firewalld.port_range",
        classify: always_n,
        rule: rules::RuleKind::None,
    },
    TypeRule {
        type_name: "firewalld.protocol",
        classify: absent_is_c,
        rule: rules::RuleKind::FwProtocolAbsent,
    },
];

const OPS_010: &[(&str, RiskClass)] = &[
    ("add_service_runtime", RiskClass::N),
    ("add_service_permanent", RiskClass::N),
];

pub(crate) const OPS_020: &[(&str, RiskClass)] = &[
    ("add_service_runtime", RiskClass::N),
    ("add_service_permanent", RiskClass::N),
    ("remove_service_runtime", RiskClass::C),
    ("remove_service_permanent", RiskClass::C),
    ("add_port_runtime", RiskClass::N),
    ("add_port_permanent", RiskClass::N),
    ("remove_port_runtime", RiskClass::C),
    ("remove_port_permanent", RiskClass::C),
    ("add_protocol_runtime", RiskClass::N),
    ("add_protocol_permanent", RiskClass::N),
    ("remove_protocol_runtime", RiskClass::C),
    ("remove_protocol_permanent", RiskClass::C),
];

/// The classified first-party catalogs (DESIGN §43.2). firewalld 0.3.0 is
/// added here, with its digest, when it is registered (P3).
pub const CATALOG_RULES: &[CatalogRules] = &[
    CatalogRules {
        id: "firewalld",
        version: "0.1.0",
        sha256: "27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff",
        enforcement: Enforcement::Enforced,
        types: FIREWALLD_010,
        ops: OPS_010,
    },
    CatalogRules {
        id: "firewalld",
        version: "0.2.0",
        sha256: "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641",
        enforcement: Enforcement::PendingOwner("D-13"),
        types: FIREWALLD_020,
        ops: OPS_020,
    },
];

/// Built-in connection-risk types: every change is C (§45.6).
pub const BUILTIN_RISK_TYPES: &[(&str, rules::RuleKind)] =
    &[("nm_connection", rules::RuleKind::NmConnection)];

/// Program names whose mutate operations can change the management path.
/// Compared with the final path component of a catalog operation's verified
/// program (a structured field), never searched for in text.
pub const CONNECTION_PROGRAMS: &[&str] = &["firewall-cmd", "nmcli", "ip", "busctl"];

/// The classification of one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    /// Not a connection-risk type.
    NotRisk,
    /// A classified connection-risk resource.
    Risk {
        class: RiskClass,
        enforcement: Enforcement,
        rule: rules::RuleKind,
        /// `firewalld@0.3.0` or `builtin`.
        source: String,
    },
    /// Refused before contact.
    Refused(String),
}

/// The table in force: the production table, or (unit tests only) one a
/// test installed for the current thread.
fn with_table<R>(f: impl FnOnce(&[CatalogRules]) -> R) -> R {
    #[cfg(test)]
    {
        if let Some(t) = test_table::get() {
            return f(t);
        }
    }
    f(CATALOG_RULES)
}

#[cfg(test)]
pub(crate) mod test_table {
    use super::CatalogRules;
    use std::cell::Cell;
    thread_local! {
        static TABLE: Cell<Option<&'static [CatalogRules]>> = const { Cell::new(None) };
    }
    /// Install a classification table for the current test thread.
    pub(crate) fn set(t: Option<&'static [CatalogRules]>) {
        TABLE.with(|c| c.set(t));
    }
    pub(crate) fn get() -> Option<&'static [CatalogRules]> {
        TABLE.with(|c| c.get())
    }
}

fn program_name(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// Does a catalog have a mutate operation of a connection program?
pub fn catalog_can_change_connection(catalog: &crate::plugin::VerifiedCatalog) -> bool {
    catalog.ops().any(|op| {
        op.class() == crate::plugin::OpClass::Mutate
            && CONNECTION_PROGRAMS.contains(&program_name(op.program()))
    })
}

/// Classify one resource (DESIGN §43.2).
pub fn classify(set: Option<&PluginSet>, res: &FrozenResource) -> Classification {
    if let Some((_, rule)) = BUILTIN_RISK_TYPES.iter().find(|(t, _)| *t == res.type_) {
        return Classification::Risk {
            class: RiskClass::C,
            enforcement: Enforcement::Enforced,
            rule: *rule,
            source: "builtin".to_string(),
        };
    }
    if !crate::plugin::run::is_plugin_type(&res.type_) {
        return Classification::NotRisk;
    }
    let Some(set) = set else {
        return Classification::NotRisk;
    };
    let Ok((_, catalog, _)) = crate::plugin::run::resolve(set, res) else {
        return Classification::NotRisk;
    };
    let dangerous = catalog_can_change_connection(catalog);
    let entry = with_table(|t| {
        t.iter()
            .find(|c| c.id == catalog.id() && c.version == catalog.version())
            .map(|c| {
                (
                    c.sha256 == catalog.sha256(),
                    c.enforcement,
                    c.types
                        .iter()
                        .find(|r| r.type_name == res.type_)
                        .map(|r| (r.classify, r.rule)),
                    c.ops,
                )
            })
    });
    let source = format!("{}@{}", catalog.id(), catalog.version());
    match entry {
        Some((true, enforcement, Some((classify, rule)), ops)) => {
            // The class is the larger of the type rule's and that of every
            // operation the resource can run: a plugin definition cannot
            // make a C or R operation look N (its facets choose the ops).
            let Some(op_class) = ops_class(set, res, ops) else {
                return Classification::Refused(format!(
                    "{}: resource type {} of catalog {} can run an operation that has no connection-risk classification",
                    res.id, res.type_, source
                ));
            };
            let class = classify(&res.with).max(op_class);
            if class != RiskClass::N && rule == rules::RuleKind::None {
                return Classification::Refused(format!(
                    "{}: resource type {} of catalog {} can run {} operations but has no rule to judge them",
                    res.id,
                    res.type_,
                    source,
                    class.label()
                ));
            }
            Classification::Risk {
                class,
                enforcement,
                rule,
                source,
            }
        }
        Some((true, _, None, _)) if !dangerous => Classification::NotRisk,
        Some((true, enforcement, None, ops)) => {
            // Another type on a classified catalog: by its operations.
            let used = crate::plugin::run::wanted_ensure_ops(set, res);
            let all_n = used.as_ref().is_ok_and(|u| {
                u.iter()
                    .all(|op| ops.iter().any(|(o, c)| o == op && *c == RiskClass::N))
            });
            if all_n {
                Classification::Risk {
                    class: RiskClass::N,
                    enforcement,
                    rule: rules::RuleKind::None,
                    source,
                }
            } else {
                Classification::Refused(format!(
                    "{}: resource type {} of catalog {} has no connection-risk classification and can run operations that are not classified N",
                    res.id, res.type_, source
                ))
            }
        }
        Some((false, _, _, _)) if dangerous => Classification::Refused(format!(
            "{}: catalog {} does not have the classified digest; it can change the management connection and is refused",
            res.id, source
        )),
        _ if dangerous => Classification::Refused(format!(
            "{}: catalog {} can change the management connection ({} mutate operations) but has no connection-risk classification",
            res.id,
            source,
            CONNECTION_PROGRAMS.join(", ")
        )),
        _ => Classification::NotRisk,
    }
}

/// The largest class of the operations a plugin resource can run, or `None`
/// when one of them is not in the catalog's classification.
fn ops_class(
    set: &PluginSet,
    res: &FrozenResource,
    ops: &[(&str, RiskClass)],
) -> Option<RiskClass> {
    let used = crate::plugin::run::wanted_ensure_ops(set, res).ok()?;
    let mut c = RiskClass::N;
    for op in used {
        let (_, k) = ops.iter().find(|(o, _)| *o == op)?;
        c = c.max(*k);
    }
    Some(c)
}

/// What a value refers to inside `{{ … }}`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Refs {
    facts: bool,
    registers: bool,
}

fn refs_in(v: &Value, registers: &BTreeSet<String>, out: &mut Refs) {
    match v {
        Value::Str(s) => {
            let mut rest = s.as_str();
            while let Some(i) = rest.find("{{") {
                let after = &rest[i + 2..];
                let end = after.find("}}").unwrap_or(after.len());
                let expr = &after[..end];
                for word in
                    expr.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                {
                    let head = word.split('.').next().unwrap_or("");
                    if head == "facts" {
                        out.facts = true;
                    }
                    // Registers are read as `registers.<name>`; a bare
                    // register name is refused by the expression parser,
                    // but is treated as a register here too.
                    if head == "registers" || registers.contains(head) {
                        out.registers = true;
                    }
                }
                rest = &after[end.min(after.len())..];
            }
        }
        Value::List(items) => items.iter().for_each(|i| refs_in(i, registers, out)),
        Value::Map(m) => m.values().for_each(|i| refs_in(i, registers, out)),
        _ => {}
    }
}

/// One resource the static gate looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticItem {
    pub id: String,
    pub class: RiskClass,
    pub enforcement: Enforcement,
    pub rule: rules::RuleKind,
    pub source: String,
}

/// The before-contact gate (DESIGN §43.2), for plan and apply. `approved`
/// lists the resource ids the run's approvals cover for this host; `None`
/// for plan (which never needs one). Returns the classified resources.
pub fn static_gate(model: &Model, approved: Option<&BTreeSet<String>>) -> Result<Vec<StaticItem>> {
    let registers: BTreeSet<String> = model
        .resources
        .iter()
        .filter_map(|r| r.register.clone())
        .collect();
    let mut out = Vec::new();
    let mut missing = Vec::new();
    for res in &model.resources {
        match classify(model.plugins.as_deref(), res) {
            Classification::NotRisk => {}
            Classification::Refused(why) => return Err(SinterError::schema(why)),
            Classification::Risk {
                mut class,
                enforcement,
                rule,
                source,
            } => {
                // The new restrictions apply only where the control is in
                // force and the resource can do more than N operations
                // (whose worst case already counts every possible state).
                if enforcement == Enforcement::Enforced && class != RiskClass::N {
                    let mut refs = Refs::default();
                    for v in res.with.values() {
                        refs_in(v, &registers, &mut refs);
                    }
                    if refs.registers {
                        return Err(SinterError::schema(format!(
                            "{}: a connection-risk resource may not depend on a register: its change could not be reviewed before contact",
                            res.id
                        )));
                    }
                    if refs.facts {
                        // Facts are known only after contact: worst case.
                        class = RiskClass::R;
                    }
                }
                if enforcement == Enforcement::Enforced && class == RiskClass::R {
                    if let Some(set) = approved {
                        if !set.contains(&res.id) {
                            missing.push(res.id.clone());
                        }
                    }
                }
                out.push(StaticItem {
                    id: res.id.clone(),
                    class,
                    enforcement,
                    rule,
                    source,
                });
            }
        }
    }
    if !missing.is_empty() {
        return Err(SinterError::schema(format!(
            "connection-risk resources {} need an approval (sinter plan --approval-request, sinter approve, then sinter apply --approval); nothing was contacted",
            missing.join(", ")
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
