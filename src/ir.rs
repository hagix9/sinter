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
    pub service: String,
    pub action: HandlerAction,
    pub sensitive: bool,
    pub origin: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerAction {
    Restart,
    Reload,
}

pub const TOP_LEVEL_FIELDS: &[&str] = &["version", "vars", "include", "resources", "handlers"];
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
pub const HANDLER_FIELDS: &[&str] = &["id", "service", "action", "sensitive"];
pub const VAR_FIELDS: &[&str] = &["value", "sensitive"];
