use crate::error::{Result, SinterError};
use crate::ir::{
    HandlerAction, HandlerDecl, ResourceDecl, VarDecl, COMMON_RESOURCE_FIELDS, HANDLER_FIELDS,
    TOP_LEVEL_FIELDS, VAR_FIELDS,
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
}

#[derive(Debug, Clone)]
pub struct IncludeRef {
    pub path: String,
    pub origin: String,
}

pub fn parse_document(path: &Path) -> Result<Document> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        SinterError::schema(format!("cannot read recipe {}: {}", path.display(), e))
    })?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let root = match ext.as_str() {
        "yaml" | "yml" => parse_yaml(&text)?,
        "toml" => parse_toml(&text)?,
        other => {
            return Err(SinterError::schema(format!(
                "unsupported recipe extension .{}: {}",
                other,
                path.display()
            )))
        }
    };
    let origin = path.display().to_string();
    document_from_value(root, path, &origin)
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

    Ok(Document {
        path: path.to_path_buf(),
        version,
        vars,
        includes,
        resources,
        handlers,
    })
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
    let service = match map.get("service") {
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
    Ok(HandlerDecl {
        id,
        service,
        action,
        sensitive,
        origin: origin.to_string(),
    })
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
