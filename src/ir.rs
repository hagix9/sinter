use crate::value::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct Recipe {
    pub version: i64,
    pub vars: Vec<VarDecl>,
    pub includes: Vec<String>,
    pub resources: Vec<ResourceDecl>,
    pub handlers: Vec<HandlerDecl>,
}

#[derive(Debug, Clone)]
pub struct VarDecl {
    pub name: String,
    pub value: Value,
    pub sensitive: bool,
    pub origin: String,
}

#[derive(Debug, Clone)]
pub struct ResourceDecl {
    pub id: String,
    pub type_: String,
    pub with: BTreeMap<String, Value>,
    pub when: Option<String>,
    pub loop_values: Option<Vec<Value>>,
    pub depends_on: Vec<String>,
    pub notify: Vec<String>,
    pub sensitive: bool,
    pub origin: String,
}

#[derive(Debug, Clone)]
pub struct HandlerDecl {
    pub id: String,
    /// The handler's type (`type:`; absent means `service`).
    pub kind: HandlerKind,
    /// The systemd unit of a `service` handler. Meaningful only when `kind`
    /// is [`HandlerKind::Service`]; no other kind has a service name.
    pub service: String,
    /// The action of a `service` handler (same rule as `service`).
    pub action: HandlerAction,
    pub sensitive: bool,
    pub origin: String,
}

/// The type of a handler (DESIGN §4.3).
///
/// The foundation knows three types so that the engine, the model and the
/// output dispatch on one value. Only [`HandlerKind::Service`] is implemented:
/// the recipe parser refuses a recipe that declares any other type (see
/// [`HandlerKind::is_implemented`]), so no unimplemented handler can be
/// frozen, queued, or reported as run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerKind {
    /// Restart or reload a systemd unit (the original handler).
    Service,
    /// Refresh the system CA trust store. Not implemented yet.
    CaTrust,
    /// Run a program after a change. Not implemented yet.
    Command,
}

impl HandlerKind {
    /// The `type:` value as written in a recipe (and in JSON output).
    pub fn label(self) -> &'static str {
        match self {
            HandlerKind::Service => "service",
            HandlerKind::CaTrust => "ca_trust",
            HandlerKind::Command => "command",
        }
    }

    pub fn from_label(label: &str) -> Option<HandlerKind> {
        match label {
            "service" => Some(HandlerKind::Service),
            "ca_trust" => Some(HandlerKind::CaTrust),
            "command" => Some(HandlerKind::Command),
            _ => None,
        }
    }

    /// Whether this version of Sinter can execute handlers of this type.
    pub fn is_implemented(self) -> bool {
        matches!(self, HandlerKind::Service)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerAction {
    Restart,
    Reload,
}

pub const TOP_LEVEL_FIELDS: &[&str] = &[
    "version",
    "vars",
    "include",
    "resources",
    "handlers",
    "backup",
    "targets",
    // Recipe-wide default environment for `package`/`command` resources.
    "env",
];
/// Fields of the top-level `backup` map.
pub const BACKUP_FIELDS: &[&str] = &["paths"];
/// Fields of the top-level `targets` map.
pub const TARGET_FIELDS: &[&str] = &["hosts", "groups"];
pub const COMMON_RESOURCE_FIELDS: &[&str] = &[
    "id",
    "type",
    "with",
    "when",
    "loop",
    "depends_on",
    "notify",
    "sensitive",
];
/// Fields accepted on a handler. `type` selects the handler type; `service`
/// and `action` belong to the `service` type, the only implemented one.
pub const HANDLER_FIELDS: &[&str] = &["id", "type", "service", "action", "sensitive"];
pub const VAR_FIELDS: &[&str] = &["value", "sensitive"];
