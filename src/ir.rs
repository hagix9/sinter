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
    /// is [`HandlerKind::Service`]; no other kind has a service name (it is
    /// empty, and output never invents one).
    pub service: String,
    /// The action of a `service` handler (same rule as `service`). Any other
    /// kind carries a placeholder that nothing reads; its action word comes
    /// from `FrozenHandler::action_label`.
    pub action: HandlerAction,
    /// The program of a `command` handler (present exactly when `kind` is
    /// [`HandlerKind::Command`]).
    pub command: Option<CommandHandlerSpec>,
    pub sensitive: bool,
    pub origin: String,
}

/// What a `command` handler runs (DESIGN §4.3). Every value is static text
/// taken from the recipe at validation: nothing is evaluated later, so what is
/// validated is what runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandHandlerSpec {
    /// Absolute path of the program (never searched for in PATH).
    pub program: String,
    /// Exact arguments; no shell is involved.
    pub args: Vec<String>,
    pub timeout_secs: u64,
}

/// The most arguments a `command` handler may have.
pub const HANDLER_MAX_ARGS: usize = 64;
/// The longest single argument of a `command` handler, in bytes.
pub const HANDLER_MAX_ARG_BYTES: usize = 4096;
/// A `command` handler's timeout when the recipe gives none, and its ceiling.
pub const HANDLER_DEFAULT_TIMEOUT_SECS: u64 = 300;
pub const HANDLER_MAX_TIMEOUT_SECS: u64 = 3600;
/// The fields of a `command` handler's `with` block.
pub const HANDLER_COMMAND_FIELDS: &[&str] = &["program", "args", "timeout_seconds"];

/// The type of a handler (DESIGN §4.3).
///
/// The engine, the model and the output dispatch on one value. The recipe
/// parser refuses every other `type:` value, so a handler of an unknown type
/// can never be frozen, queued, or reported as run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerKind {
    /// Restart or reload a systemd unit (the original handler).
    Service,
    /// Refresh the system CA trust store with the operating system's own tool.
    CaTrust,
    /// Run one program after a change (an absolute path and exact arguments).
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
/// and `action` belong to the `service` type, `with` to the `command` type. The
/// parser rejects a field that does not belong to the handler's type.
pub const HANDLER_FIELDS: &[&str] = &["id", "type", "service", "action", "with", "sensitive"];
pub const VAR_FIELDS: &[&str] = &["value", "sensitive"];
