use crate::error::{Result, SinterError};
use crate::ir::{
    CommandHandlerSpec, HandlerAction, HandlerDecl, HandlerKind, ResourceDecl, VarDecl,
    BACKUP_FIELDS, COMMON_RESOURCE_FIELDS, HANDLER_COMMAND_FIELDS, HANDLER_DEFAULT_TIMEOUT_SECS,
    HANDLER_FIELDS, HANDLER_MAX_ARGS, HANDLER_MAX_ARG_BYTES, HANDLER_MAX_TIMEOUT_SECS,
    TARGET_FIELDS, TOP_LEVEL_FIELDS, VAR_FIELDS,
};
use crate::toml_front::parse_toml;
use crate::value::Value;
use crate::yaml::parse_yaml;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A single parsed recipe file, before include expansion.
#[derive(Debug, Clone)]
pub struct Document {
    pub path: PathBuf,
    pub version: i64,
    pub vars: Vec<VarDecl>,
    pub includes: Vec<IncludeRef>,
    pub resources: Vec<ResourceDecl>,
    pub handlers: Vec<HandlerDecl>,
    /// Paths declared under `backup.paths`, in declaration order.
    pub backup_paths: Vec<String>,
    /// Inventory hosts/groups this recipe may be applied to (`targets`).
    pub targets: Option<TargetSelector>,
    /// Recipe-wide default environment for `package`/`command` resources
    /// (`env`), from the entry recipe only.
    pub env: Option<Value>,
}

/// A recipe's explicit execution targets, by inventory host and group
/// name. The selected set is the union. Names are resolved only against an
/// inventory (`--inventory`); they never name network hosts directly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetSelector {
    pub hosts: Vec<String>,
    pub groups: Vec<String>,
}

/// Inventory host / group / bundle name rule: ASCII alphanumerics, `-`, `_`
/// and `.`, starting alphanumeric, at most 64 characters.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
}

#[derive(Debug, Clone)]
pub struct IncludeRef {
    pub path: String,
    pub origin: String,
}

pub fn parse_document(path: &Path) -> Result<Document> {
    let root = parse_file_value(path)?;
    let origin = path.display().to_string();
    document_from_value(root, path, &origin)
}

/// Read a recipe or bundle file into the common value model, choosing the
/// YAML or TOML front end by extension.
pub fn parse_file_value(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        SinterError::schema(format!("cannot read recipe {}: {}", path.display(), e))
    })?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "yaml" | "yml" => parse_yaml(&text),
        "toml" => parse_toml(&text),
        other => Err(SinterError::schema(format!(
            "unsupported recipe extension .{}: {}",
            other,
            path.display()
        ))),
    }
}

pub fn document_from_value(root: Value, path: &Path, origin: &str) -> Result<Document> {
    let map = root.as_map().ok_or_else(|| {
        SinterError::schema(format!("{}: recipe top level must be a map", origin))
    })?;
    only_fields(map, TOP_LEVEL_FIELDS, origin)?;

    let version = match map.get("version") {
        Some(Value::Int(v)) => *v,
        Some(_) => {
            return Err(SinterError::schema(format!(
                "{}: version must be an integer",
                origin
            )))
        }
        None => {
            return Err(SinterError::schema(format!(
                "{}: missing required field version",
                origin
            )))
        }
    };
    if version != 1 {
        return Err(SinterError::schema(format!(
            "{}: unsupported recipe version {} (v0.1 requires version: 1)",
            origin, version
        )));
    }

    let mut vars = Vec::new();
    if let Some(v) = map.get("vars") {
        let vm = v
            .as_map()
            .ok_or_else(|| SinterError::schema(format!("{}: vars must be a map", origin)))?;
        let mut seen = std::collections::HashSet::new();
        for (name, decl) in vm {
            if !seen.insert(name.clone()) {
                return Err(SinterError::schema(format!(
                    "{}: duplicate variable {}",
                    origin, name
                )));
            }
            let dm = decl.as_map().ok_or_else(|| {
                SinterError::schema(format!(
                    "{}: variable {} must be a map with value",
                    origin, name
                ))
            })?;
            only_fields(dm, VAR_FIELDS, &format!("{}: variable {}", origin, name))?;
            let value = dm.get("value").ok_or_else(|| {
                SinterError::schema(format!(
                    "{}: variable {} is missing required field value",
                    origin, name
                ))
            })?;
            if value.is_null() {
                return Err(SinterError::schema(format!(
                    "{}: variable {} may not be null",
                    origin, name
                )));
            }
            let sensitive = match dm.get("sensitive") {
                None => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => {
                    return Err(SinterError::schema(format!(
                        "{}: variable {} sensitive must be a boolean",
                        origin, name
                    )))
                }
            };
            vars.push(VarDecl {
                name: name.clone(),
                value: value.clone(),
                sensitive,
                origin: origin.to_string(),
            });
        }
    }

    let mut includes = Vec::new();
    if let Some(v) = map.get("include") {
        let list = v
            .as_list()
            .ok_or_else(|| SinterError::schema(format!("{}: include must be a list", origin)))?;
        for item in list {
            match item {
                Value::Str(s) => includes.push(IncludeRef {
                    path: s.clone(),
                    origin: origin.to_string(),
                }),
                _ => {
                    return Err(SinterError::schema(format!(
                        "{}: include entries must be strings",
                        origin
                    )))
                }
            }
        }
    }

    let mut resources = Vec::new();
    if let Some(v) = map.get("resources") {
        let list = v
            .as_list()
            .ok_or_else(|| SinterError::schema(format!("{}: resources must be a list", origin)))?;
        for (idx, item) in list.iter().enumerate() {
            resources.push(parse_resource(item, origin, idx)?);
        }
    }

    let mut handlers = Vec::new();
    if let Some(v) = map.get("handlers") {
        let list = v
            .as_list()
            .ok_or_else(|| SinterError::schema(format!("{}: handlers must be a list", origin)))?;
        for (idx, item) in list.iter().enumerate() {
            handlers.push(parse_handler(item, origin, idx)?);
        }
    }

    let backup_paths = match map.get("backup") {
        None => Vec::new(),
        Some(v) => parse_backup(v, origin)?,
    };
    let targets = match map.get("targets") {
        None => None,
        Some(v) => Some(parse_targets(v, origin)?),
    };
    // Recipe-wide default environment for `package`/`command` resources. A
    // resource's own `env` overrides these per variable name (see
    // `merge_recipe_env` in the model freeze step).
    let env = match map.get("env") {
        None | Some(Value::Null) => None,
        Some(v) => {
            validate_recipe_env(v, origin)?;
            Some(v.clone())
        }
    };

    Ok(Document {
        path: path.to_path_buf(),
        version,
        vars,
        includes,
        resources,
        handlers,
        backup_paths,
        targets,
        env,
    })
}

/// Validate a recipe-level `env` map: string keys that are valid environment
/// variable names and not reserved by Sinter's command baseline, with string
/// values. The same rules a `command`/`package` `env` map follows.
fn validate_recipe_env(v: &Value, origin: &str) -> Result<()> {
    let m = v
        .as_map()
        .ok_or_else(|| SinterError::schema(format!("{}: env must be a map of strings", origin)))?;
    for (key, val) in m {
        let mut chars = key.chars();
        let valid = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(SinterError::schema(format!(
                "{}: invalid environment variable name {:?}",
                origin, key
            )));
        }
        if crate::model::RESERVED_ENV.contains(&key.as_str()) {
            return Err(SinterError::schema(format!(
                "{}: env name {} is reserved by the command baseline",
                origin, key
            )));
        }
        if !matches!(val, Value::Str(_)) {
            return Err(SinterError::schema(format!(
                "{}: env values must be strings",
                origin
            )));
        }
    }
    Ok(())
}

/// Parse the top-level `targets` declaration:
///
/// ```yaml
/// targets:
///   groups: [web]
///   hosts: [special01]
/// ```
///
/// At least one name is required; names are static (no interpolation) and
/// unique within each list.
fn parse_targets(v: &Value, origin: &str) -> Result<TargetSelector> {
    let ctx = format!("{}: targets", origin);
    let map = v.as_map().ok_or_else(|| {
        SinterError::schema(format!("{} must be a map with hosts and/or groups", ctx))
    })?;
    only_fields(map, TARGET_FIELDS, &ctx)?;
    let list = |key: &str| -> Result<Vec<String>> {
        let Some(v) = map.get(key) else {
            return Ok(Vec::new());
        };
        let items = v
            .as_list()
            .ok_or_else(|| SinterError::schema(format!("{}.{} must be a list", ctx, key)))?;
        let mut out: Vec<String> = Vec::new();
        for (i, item) in items.iter().enumerate() {
            let name = item.as_str().ok_or_else(|| {
                SinterError::schema(format!("{}.{}[{}] must be a string", ctx, key, i))
            })?;
            if !valid_name(name) {
                return Err(SinterError::schema(format!(
                    "{}.{}[{}]: invalid name {:?} (allowed: [A-Za-z0-9._-], start alphanumeric, max 64 chars)",
                    ctx, key, i, name
                )));
            }
            if out.iter().any(|n| n == name) {
                return Err(SinterError::schema(format!(
                    "{}.{}: duplicate name {}",
                    ctx, key, name
                )));
            }
            out.push(name.to_string());
        }
        Ok(out)
    };
    let sel = TargetSelector {
        hosts: list("hosts")?,
        groups: list("groups")?,
    };
    if sel.hosts.is_empty() && sel.groups.is_empty() {
        return Err(SinterError::schema(format!(
            "{} must name at least one host or group",
            ctx
        )));
    }
    Ok(sel)
}

/// Parse the top-level `backup` declaration:
///
/// ```yaml
/// backup:
///   paths:
///     - /etc/ssh/sshd_config
/// ```
///
/// Paths are static target identifiers (DESIGN §4.9): literal canonical
/// absolute paths, never interpolated. `/` is rejected because a whole-root
/// copy would contain the backup store itself.
fn parse_backup(v: &Value, origin: &str) -> Result<Vec<String>> {
    let ctx = format!("{}: backup", origin);
    let map = v
        .as_map()
        .ok_or_else(|| SinterError::schema(format!("{} must be a map with paths", ctx)))?;
    only_fields(map, BACKUP_FIELDS, &ctx)?;
    let list = match map.get("paths") {
        None => {
            return Err(SinterError::schema(format!(
                "{} is missing required field paths",
                ctx
            )))
        }
        Some(p) => p
            .as_list()
            .ok_or_else(|| SinterError::schema(format!("{}.paths must be a list", ctx)))?,
    };
    if list.is_empty() {
        return Err(SinterError::schema(format!(
            "{}.paths must not be empty",
            ctx
        )));
    }
    let mut out = Vec::new();
    for (i, item) in list.iter().enumerate() {
        let p = item
            .as_str()
            .ok_or_else(|| SinterError::schema(format!("{}.paths[{}] must be a string", ctx, i)))?;
        if p.contains("{{") || p.contains("}}") {
            return Err(SinterError::schema(format!(
                "{}.paths[{}] must be a static path; interpolation is not allowed",
                ctx, i
            )));
        }
        crate::paths::validate_path(p)
            .map_err(|e| SinterError::schema(format!("{}.paths[{}]: {}", ctx, i, e.message)))?;
        if p == "/" {
            return Err(SinterError::schema(format!(
                "{}.paths[{}]: the root directory cannot be backed up",
                ctx, i
            )));
        }
        out.push(p.to_string());
    }
    Ok(out)
}

fn parse_resource(item: &Value, origin: &str, idx: usize) -> Result<ResourceDecl> {
    let ctx = format!("{}: resources[{}]", origin, idx);
    let map = item
        .as_map()
        .ok_or_else(|| SinterError::schema(format!("{}: resource must be a map", ctx)))?;
    only_fields(map, COMMON_RESOURCE_FIELDS, &ctx)?;

    let id = match map.get("id") {
        Some(Value::Str(s)) => s.clone(),
        _ => {
            return Err(SinterError::schema(format!(
                "{}: id is required and must be a string",
                ctx
            )))
        }
    };
    if id.is_empty() {
        return Err(SinterError::schema(format!(
            "{}: id must not be empty",
            ctx
        )));
    }
    if id.contains("{{") {
        return Err(SinterError::schema(format!(
            "{}: resource id must be a static literal, not an interpolated value",
            ctx
        )));
    }
    let type_ = match map.get("type") {
        Some(Value::Str(s)) => s.clone(),
        _ => {
            return Err(SinterError::schema(format!(
                "{}: type is required and must be a string",
                ctx
            )))
        }
    };
    let with = match map.get("with") {
        Some(v) => v
            .as_map()
            .ok_or_else(|| SinterError::schema(format!("{}: with must be a map", ctx)))?
            .clone(),
        None => BTreeMap::new(),
    };
    let when = match map.get("when") {
        None => None,
        Some(Value::Str(s)) => Some(s.clone()),
        Some(_) => {
            return Err(SinterError::schema(format!(
                "{}: when must be a string",
                ctx
            )))
        }
    };
    let loop_values = match map.get("loop") {
        None => None,
        Some(Value::List(l)) => Some(l.clone()),
        Some(_) => return Err(SinterError::schema(format!("{}: loop must be a list", ctx))),
    };
    let depends_on = string_list(map.get("depends_on"), &format!("{}: depends_on", ctx))?;
    let notify = string_list(map.get("notify"), &format!("{}: notify", ctx))?;
    let sensitive = match map.get("sensitive") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            return Err(SinterError::schema(format!(
                "{}: sensitive must be a boolean",
                ctx
            )))
        }
    };

    Ok(ResourceDecl {
        id,
        type_,
        with,
        when,
        loop_values,
        depends_on,
        notify,
        sensitive,
        origin: origin.to_string(),
    })
}

fn parse_handler(item: &Value, origin: &str, idx: usize) -> Result<HandlerDecl> {
    let ctx = format!("{}: handlers[{}]", origin, idx);
    let map = item
        .as_map()
        .ok_or_else(|| SinterError::schema(format!("{}: handler must be a map", ctx)))?;
    // `type` is optional and defaults to `service`, so every recipe written
    // before handler types existed keeps its meaning. Any other value must be
    // one of the known types: an unknown or malformed type is refused here, at
    // validation, and is never frozen, queued by a notification or run.
    let kind = match map.get("type") {
        None => HandlerKind::Service,
        Some(Value::Str(s)) => HandlerKind::from_label(s).ok_or_else(|| {
            SinterError::schema(format!(
                "{}: unknown handler type {} (supported: service, ca_trust, command)",
                ctx,
                printable_token(s)
            ))
        })?,
        Some(_) => {
            return Err(SinterError::schema(format!(
                "{}: type must be a string",
                ctx
            )))
        }
    };
    only_fields(map, HANDLER_FIELDS, &ctx)?;
    let id = match map.get("id") {
        Some(Value::Str(s)) => s.clone(),
        _ => {
            return Err(SinterError::schema(format!(
                "{}: id is required and must be a string",
                ctx
            )))
        }
    };
    let sensitive = match map.get("sensitive") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            return Err(SinterError::schema(format!(
                "{}: sensitive must be a boolean",
                ctx
            )))
        }
    };
    // Each field belongs to a type, and a field on the wrong type is mistaken
    // and refused rather than ignored: `service` and `action` are the service
    // handler's, `with` is the command handler's. A `ca_trust` handler has none
    // of them (it refreshes the trust store with a fixed, OS-chosen tool).
    let foreign: &[&str] = match kind {
        HandlerKind::Service => &["with"],
        HandlerKind::CaTrust => &["service", "action", "with"],
        HandlerKind::Command => &["service", "action"],
    };
    for f in foreign {
        if map.contains_key(*f) {
            return Err(SinterError::schema(format!(
                "{}: {} is not a field of a {} handler",
                ctx,
                f,
                kind.label()
            )));
        }
    }
    let (service, action) = if kind == HandlerKind::Service {
        let service = match map.get("service") {
            Some(Value::Str(s)) if s.is_empty() => {
                return Err(SinterError::schema(format!(
                    "{}: service must not be empty",
                    ctx
                )))
            }
            Some(Value::Str(s)) => s.clone(),
            _ => {
                return Err(SinterError::schema(format!(
                    "{}: service is required and must be a string",
                    ctx
                )))
            }
        };
        let action = match map.get("action") {
            Some(Value::Str(s)) if s == "restart" => HandlerAction::Restart,
            Some(Value::Str(s)) if s == "reload" => HandlerAction::Reload,
            _ => {
                return Err(SinterError::schema(format!(
                    "{}: action is required and must be restart or reload",
                    ctx
                )))
            }
        };
        (service, action)
    } else {
        // No unit, and a placeholder action that nothing reads.
        (String::new(), HandlerAction::Restart)
    };
    let command = if kind == HandlerKind::Command {
        Some(parse_command_handler(map.get("with"), &ctx, sensitive)?)
    } else {
        None
    };
    Ok(HandlerDecl {
        id,
        kind,
        service,
        action,
        command,
        sensitive,
        origin: origin.to_string(),
    })
}

/// The `with` block of a `command` handler: `program` (an absolute path),
/// `args` and `timeout_seconds`, nothing else. Every value is static text. The
/// limits are the handler's own (DESIGN §4.3); the `command` resource keeps its
/// existing ones. A sensitive handler never has a value of its own echoed in an
/// error message.
fn parse_command_handler(
    with: Option<&Value>,
    ctx: &str,
    sensitive: bool,
) -> Result<CommandHandlerSpec> {
    let ctx = format!("{ctx}: with");
    let map = match with {
        Some(Value::Map(m)) => m,
        Some(_) => {
            return Err(SinterError::schema(format!(
                "{ctx} must be a map (program, args, timeout_seconds)"
            )))
        }
        None => {
            return Err(SinterError::schema(format!(
                "{}: a command handler needs a with block (program, args, timeout_seconds)",
                ctx.trim_end_matches(": with")
            )))
        }
    };
    only_fields(map, HANDLER_COMMAND_FIELDS, &ctx)?;
    let program = match map.get("program") {
        Some(Value::Str(p)) => p.clone(),
        _ => {
            return Err(SinterError::schema(format!(
                "{ctx}: program is required and must be a string"
            )))
        }
    };
    if let Err(e) = crate::paths::validate_path(&program) {
        return Err(SinterError::schema(if sensitive {
            format!("{ctx}: program must be a valid absolute path")
        } else {
            format!("{ctx}: program: {}", e.message)
        }));
    }
    if program == "/" {
        return Err(SinterError::schema(format!(
            "{ctx}: program must name a file, not the root directory"
        )));
    }
    reject_expression(&program, &ctx, "program")?;
    let args = match map.get("args") {
        None => Vec::new(),
        Some(Value::List(items)) => {
            if items.len() > HANDLER_MAX_ARGS {
                return Err(SinterError::schema(format!(
                    "{ctx}: args has {} entries; at most {HANDLER_MAX_ARGS} are allowed",
                    items.len()
                )));
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                let Value::Str(a) = item else {
                    return Err(SinterError::schema(format!(
                        "{ctx}: args[{i}] must be a string"
                    )));
                };
                if a.contains('\0') {
                    return Err(SinterError::schema(format!(
                        "{ctx}: args[{i}] may not contain NUL"
                    )));
                }
                if a.len() > HANDLER_MAX_ARG_BYTES {
                    return Err(SinterError::schema(format!(
                        "{ctx}: args[{i}] is {} bytes; at most {HANDLER_MAX_ARG_BYTES} are allowed",
                        a.len()
                    )));
                }
                reject_expression(a, &ctx, "args")?;
                out.push(a.clone());
            }
            out
        }
        Some(_) => {
            return Err(SinterError::schema(format!(
                "{ctx}: args must be a list of strings"
            )))
        }
    };
    let timeout_secs = match map.get("timeout_seconds") {
        None => HANDLER_DEFAULT_TIMEOUT_SECS,
        Some(Value::Int(n)) if (1..=HANDLER_MAX_TIMEOUT_SECS as i64).contains(n) => *n as u64,
        Some(_) => {
            return Err(SinterError::schema(format!(
                "{ctx}: timeout_seconds must be an integer in 1..{HANDLER_MAX_TIMEOUT_SECS}"
            )))
        }
    };
    Ok(CommandHandlerSpec {
        program,
        args,
        timeout_secs,
    })
}

/// Handler values are static: a `{{ ... }}` would be run literally, which is
/// never what the author meant, so it is refused instead.
fn reject_expression(value: &str, ctx: &str, field: &str) -> Result<()> {
    if value.contains("{{") {
        return Err(SinterError::schema(format!(
            "{ctx}: {field} is static text in a handler; expressions ({{{{ ... }}}}) are not supported"
        )));
    }
    Ok(())
}

/// A recipe-supplied token for an error message: short and printable, or a
/// fixed placeholder, so an odd value cannot inject text into diagnostics.
fn printable_token(s: &str) -> String {
    if !s.is_empty() && s.chars().count() <= 64 && s.chars().all(|c| c.is_ascii_graphic()) {
        s.to_string()
    } else {
        "<invalid>".to_string()
    }
}

fn string_list(v: Option<&Value>, ctx: &str) -> Result<Vec<String>> {
    match v {
        None => Ok(Vec::new()),
        Some(Value::List(l)) => {
            let mut out = Vec::with_capacity(l.len());
            for item in l {
                match item {
                    Value::Str(s) => out.push(s.clone()),
                    _ => {
                        return Err(SinterError::schema(format!(
                            "{}: entries must be strings",
                            ctx
                        )))
                    }
                }
            }
            Ok(out)
        }
        Some(_) => Err(SinterError::schema(format!("{}: must be a list", ctx))),
    }
}

pub fn only_fields(map: &BTreeMap<String, Value>, allowed: &[&str], ctx: &str) -> Result<()> {
    for k in map.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(SinterError::schema(format!("{}: unknown field {}", ctx, k)));
        }
    }
    Ok(())
}
