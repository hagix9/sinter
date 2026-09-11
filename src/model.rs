use crate::document::{parse_document, Document};
use crate::error::{Result, SinterError};
use crate::expressions::{
    collect_register_refs, eval_value_interpolated, parse_expr, EvalVal, Expr, Scope,
};
use crate::ir::{HandlerAction, ResourceDecl};
use crate::paths::{parse_mode, validate_path};
use crate::value::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct VarDef {
    pub name: String,
    pub value: Value,
    pub sensitive: bool,
    pub origin: String,
}

#[derive(Debug, Clone)]
pub struct FrozenResource {
    pub id: String,
    pub type_: String,
    pub with: BTreeMap<String, Value>,
    pub when: Option<String>,
    pub depends_on: Vec<String>,
    pub notify: Vec<String>,
    pub sensitive: bool,
    /// Conservative static sensitivity: true when `sensitive: true` is set, or
    /// when any interpolated field or the template body references a sensitive
    /// variable. Used to redact early diagnostics that occur before runtime
    /// evaluation.
    pub derived_sensitive: bool,
    pub origin: String,
    pub loop_index: Option<usize>,
    pub loop_item: Option<Value>,

    // Resolved static identifiers.
    pub path: Option<String>,
    pub program: Option<String>,
    pub creates: Option<String>,
    pub removes: Option<String>,
    pub package_name: Option<String>,
    pub service_name: Option<String>,
    pub controller_source: Option<PathBuf>,
    pub register: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FrozenHandler {
    pub id: String,
    pub service: String,
    pub action: HandlerAction,
    pub sensitive: bool,
    pub origin: String,
}

#[derive(Debug, Clone)]
pub struct Model {
    pub vars: BTreeMap<String, VarDef>,
    pub resources: Vec<FrozenResource>,
    pub handlers: Vec<FrozenHandler>,
    pub handler_index: BTreeMap<String, usize>,
    pub register_producers: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RawResource {
    pub id: String,
    pub type_: String,
    pub with: BTreeMap<String, Value>,
    pub when: Option<String>,
    pub depends_on: Vec<String>,
    pub notify: Vec<String>,
    pub sensitive: bool,
    pub origin: String,
    pub loop_index: Option<usize>,
    pub loop_item: Option<Value>,
    /// Register names referenced by this resource's `when` and interpolated
    /// `with` values. Collected at load time so validation is independent of
    /// whether a static loop expanded to zero instances.
    pub register_refs: BTreeSet<String>,
}

impl Model {
    pub fn resource_index(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for (i, r) in self.resources.iter().enumerate() {
            m.insert(r.id.clone(), i);
        }
        m
    }
}

/// Load and expand the recipe starting at `entry`.
pub fn load_model(entry: &Path) -> Result<Model> {
    let mut state = LoadState {
        seen: HashSet::new(),
        vars: Vec::new(),
        resources: Vec::new(),
        handlers: Vec::new(),
        var_names: HashSet::new(),
        declarations: Vec::new(),
    };
    state.load(entry)?;
    freeze(state, entry)
}

struct LoadState {
    seen: HashSet<PathBuf>,
    vars: Vec<VarDef>,
    resources: Vec<RawResource>,
    handlers: Vec<FrozenHandler>,
    var_names: HashSet<String>,
    /// Every resource declaration, recorded independently of loop expansion so
    /// invalid declarations are rejected even when their loop is empty.
    declarations: Vec<Declaration>,
}

/// A resource declaration as written, retained for declaration-level
/// validation that must not be erased by static loop expansion.
struct Declaration {
    id: String,
    type_: String,
    with: BTreeMap<String, Value>,
    depends_on: Vec<String>,
    is_loop: bool,
    /// Number of concrete resource instances this declaration produced.
    instances: usize,
    register_refs: BTreeSet<String>,
    sensitive: bool,
}

impl LoadState {
    fn load(&mut self, path: &Path) -> Result<()> {
        let canon = canonicalize(path)?;
        if !self.seen.insert(canon.clone()) {
            return Err(SinterError::schema(format!(
                "recipe {} is included more than once (include cycle or duplicate include)",
                canon.display()
            )));
        }
        let doc = parse_document(&canon)?;
        expand_document(&canon, doc, self)
    }
}

fn canonicalize(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path)
        .map_err(|e| SinterError::schema(format!("cannot resolve {}: {}", path.display(), e)))
}

fn expand_document(canon: &Path, doc: Document, state: &mut LoadState) -> Result<()> {
    let base_dir = canon.parent().unwrap_or_else(|| Path::new("."));
    // Includes first, depth-first in declaration order.
    for inc in &doc.includes {
        let inc_path = if Path::new(&inc.path).is_absolute() {
            PathBuf::from(&inc.path)
        } else {
            base_dir.join(&inc.path)
        };
        state.load(&inc_path)?;
    }
    // Then the declaring document's own variables, resources, handlers.
    for v in &doc.vars {
        if !state.var_names.insert(v.name.clone()) {
            return Err(SinterError::schema(format!(
                "duplicate variable name {} (declared at {})",
                v.name, v.origin
            )));
        }
        state.vars.push(VarDef {
            name: v.name.clone(),
            value: v.value.clone(),
            sensitive: v.sensitive,
            origin: v.origin.clone(),
        });
    }
    for r in &doc.resources {
        expand_resource(canon, r, state)?;
    }
    for h in &doc.handlers {
        state.handlers.push(FrozenHandler {
            id: h.id.clone(),
            service: h.service.clone(),
            action: h.action,
            sensitive: h.sensitive,
            origin: h.origin.clone(),
        });
    }
    Ok(())
}

fn expand_resource(canon: &Path, decl: &ResourceDecl, state: &mut LoadState) -> Result<()> {
    let _ = canon;
    // Collect register references from `when` and interpolated `with` values at
    // declaration time. This runs even when the loop is empty, so a forbidden
    // reference can never escape validation merely because no instance exists.
    let mut register_refs: BTreeSet<String> = BTreeSet::new();
    if let Some(w) = &decl.when {
        let expr = parse_expr(w).map_err(|e| {
            SinterError::schema(format!("{}: invalid when expression: {}", decl.id, e))
        })?;
        let mut names = BTreeSet::new();
        collect_register_refs(&expr, &mut register_refs, &mut names);
    }
    for v in decl.with.values() {
        collect_value_register_refs(v, &mut register_refs)?;
    }

    match &decl.loop_values {
        None => {
            state.resources.push(RawResource {
                id: decl.id.clone(),
                type_: decl.type_.clone(),
                with: decl.with.clone(),
                when: decl.when.clone(),
                depends_on: decl.depends_on.clone(),
                notify: decl.notify.clone(),
                sensitive: decl.sensitive,
                origin: decl.origin.clone(),
                loop_index: None,
                loop_item: None,
                register_refs: register_refs.clone(),
            });
            state.declarations.push(Declaration {
                id: decl.id.clone(),
                type_: decl.type_.clone(),
                with: decl.with.clone(),
                depends_on: decl.depends_on.clone(),
                is_loop: false,
                instances: 1,
                register_refs,
                sensitive: decl.sensitive,
            });
        }
        Some(items) => {
            for (i, item) in items.iter().enumerate() {
                state.resources.push(RawResource {
                    id: format!("{}[{}]", decl.id, i),
                    type_: decl.type_.clone(),
                    with: decl.with.clone(),
                    when: decl.when.clone(),
                    depends_on: decl.depends_on.clone(),
                    notify: decl.notify.clone(),
                    sensitive: decl.sensitive,
                    origin: decl.origin.clone(),
                    loop_index: Some(i),
                    loop_item: Some(item.clone()),
                    register_refs: register_refs.clone(),
                });
            }
            state.declarations.push(Declaration {
                id: decl.id.clone(),
                type_: decl.type_.clone(),
                with: decl.with.clone(),
                depends_on: decl.depends_on.clone(),
                is_loop: true,
                instances: items.len(),
                register_refs,
                sensitive: decl.sensitive,
            });
        }
    }
    Ok(())
}

/// Validate resource declarations as written, independent of static loop
/// expansion. This guarantees that a declaration is rejected for an invalid
/// shape or reference even when its loop expands to zero instances.
fn validate_declarations(
    declarations: &[Declaration],
    _handlers: &[FrozenHandler],
    sensitive_var_names: &BTreeSet<String>,
) -> Result<()> {
    // Register producers: declared by non-loop command resources.
    let mut register_producers: BTreeSet<String> = BTreeSet::new();
    let mut hidden_loop_register = false;
    for d in declarations {
        if let Some(reg) = d.with.get("register").and_then(|v| v.as_str()) {
            if reg.is_empty() {
                return Err(SinterError::schema(format!(
                    "{}: register must be a non-empty identifier",
                    d.id
                )));
            }
            if d.is_loop {
                hidden_loop_register = true;
            } else {
                register_producers.insert(reg.to_string());
            }
        }
    }
    if hidden_loop_register {
        for d in declarations {
            if d.is_loop && d.with.contains_key("register") {
                return Err(SinterError::schema(format!(
                    "{}: register is forbidden inside a loop",
                    d.id
                )));
            }
        }
    }

    // Duplicate register names across non-loop declarations.
    {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for d in declarations {
            if d.is_loop {
                continue;
            }
            if let Some(reg) = d.with.get("register").and_then(|v| v.as_str()) {
                if !seen.insert(reg.to_string()) {
                    return Err(SinterError::schema(format!(
                        "duplicate register name {} (declared by {})",
                        reg, d.id
                    )));
                }
            }
        }
    }

    // Dependency references to unexpanded loop parents are forbidden, and
    // register references require a direct dependency on the producer.
    let all_resource_ids: BTreeSet<String> = declarations
        .iter()
        .flat_map(|d| {
            if d.is_loop {
                (0..d.instances)
                    .map(|i| format!("{}[{}]", d.id, i))
                    .collect::<Vec<_>>()
            } else {
                vec![d.id.clone()]
            }
        })
        .collect();
    let loop_parent_ids: BTreeSet<String> = declarations
        .iter()
        .filter(|d| d.is_loop)
        .map(|d| d.id.clone())
        .collect();

    for d in declarations {
        for dep in &d.depends_on {
            if loop_parent_ids.contains(dep) {
                return Err(SinterError::schema(format!(
                    "{}: dependency on unexpanded loop id {} is forbidden",
                    d.id, dep
                )));
            }
            if !all_resource_ids.contains(dep) {
                return Err(SinterError::schema(format!(
                    "{}: depends_on references unknown resource {}",
                    d.id, dep
                )));
            }
        }
    }

    // Shape validation per declaration type. This uses the literal IR values
    // only; facts/registers are rejected as static identifiers by construction.
    for d in declarations {
        validate_declaration_shape(d, sensitive_var_names)?;
    }

    // Register reference validation must not be skipped for empty loops.
    let producer_for: BTreeMap<String, String> = declarations
        .iter()
        .filter(|d| !d.is_loop)
        .filter_map(|d| {
            d.with
                .get("register")
                .and_then(|v| v.as_str())
                .map(|r| (r.to_string(), d.id.clone()))
        })
        .collect();
    for d in declarations {
        for reg in &d.register_refs {
            let producer = producer_for.get(reg).ok_or_else(|| {
                SinterError::schema(format!("{}: references unknown register {}", d.id, reg))
            })?;
            if !d.depends_on.contains(producer) {
                return Err(SinterError::schema(format!(
                    "{}: register {} must be listed directly in depends_on",
                    d.id, reg
                )));
            }
        }
    }

    Ok(())
}

/// Validate a single declaration's field types and static identifiers without
/// evaluating loops. Mirrors the per-instance validation so the same errors are
/// reported whether or not the loop is empty.
fn validate_declaration_shape(
    d: &Declaration,
    sensitive_var_names: &BTreeSet<String>,
) -> Result<()> {
    let ctx = &d.id;
    match d.type_.as_str() {
        "file" => {
            validate_with_fields(&d.with, FILE_FIELDS, ctx)?;
            require_static_string_field(&d.with, "path", ctx)?;
            require_optional_static_string(&d.with, "source", ctx)?;
            require_optional_mode(
                &d.with,
                ctx,
                d.sensitive
                    || d.with
                        .get("mode")
                        .is_some_and(|v| value_references_sensitive_var(v, sensitive_var_names)),
            )?;
            require_content_type(&d.with, ctx)?;
        }
        "directory" => {
            validate_with_fields(&d.with, DIR_FIELDS, ctx)?;
            require_static_string_field(&d.with, "path", ctx)?;
            require_optional_mode(
                &d.with,
                ctx,
                d.sensitive
                    || d.with
                        .get("mode")
                        .is_some_and(|v| value_references_sensitive_var(v, sensitive_var_names)),
            )?;
        }
        "link" => {
            validate_with_fields(&d.with, LINK_FIELDS, ctx)?;
            require_static_string_field(&d.with, "path", ctx)?;
            require_optional_static_string(&d.with, "target", ctx)?;
        }
        "template" => {
            validate_with_fields(&d.with, TEMPLATE_FIELDS, ctx)?;
            require_static_string_field(&d.with, "path", ctx)?;
            require_static_string_field(&d.with, "source", ctx)?;
            require_optional_mode(
                &d.with,
                ctx,
                d.sensitive
                    || d.with
                        .get("mode")
                        .is_some_and(|v| value_references_sensitive_var(v, sensitive_var_names)),
            )?;
            if d.with.contains_key("content") {
                return Err(SinterError::schema(format!(
                    "{}: template does not support content; use source",
                    ctx
                )));
            }
        }
        "command" => {
            validate_with_fields(&d.with, COMMAND_FIELDS, ctx)?;
            require_static_string_field(&d.with, "program", ctx)?;
            if let Some(Value::Str(p)) = d.with.get("program") {
                if !p.starts_with('/') {
                    return Err(SinterError::schema(format!(
                        "{}: program must be an absolute path",
                        ctx
                    )));
                }
            }
            if let Some(v) = d.with.get("args") {
                match v {
                    Value::List(items) => {
                        for i in items {
                            if !matches!(i, Value::Str(_)) {
                                return Err(SinterError::schema(format!(
                                    "{}: command args must be strings",
                                    ctx
                                )));
                            }
                            if let Value::Str(s) = i {
                                if s.contains('\0') {
                                    return Err(SinterError::schema(format!(
                                        "{}: command args may not contain NUL",
                                        ctx
                                    )));
                                }
                            }
                        }
                    }
                    Value::Null => {}
                    _ => {
                        return Err(SinterError::schema(format!(
                            "{}: command args must be a list of strings",
                            ctx
                        )))
                    }
                }
            }
            if let Some(v) = d.with.get("timeout_seconds") {
                match v.as_int() {
                    Some(n) if (1..=86400).contains(&n) => {}
                    _ => {
                        return Err(SinterError::schema(format!(
                            "{}: timeout_seconds must be an integer in 1..86400",
                            ctx
                        )))
                    }
                }
            }
            if let Some(v) = d.with.get("env") {
                match v {
                    Value::Map(m) => {
                        for (k, val) in m {
                            if crate::model::RESERVED_ENV.contains(&k.as_str()) {
                                return Err(SinterError::schema(format!(
                                    "{}: env name {} is reserved by the command baseline",
                                    ctx, k
                                )));
                            }
                            if !matches!(val, Value::Str(_)) {
                                return Err(SinterError::schema(format!(
                                    "{}: env values must be strings",
                                    ctx
                                )));
                            }
                        }
                    }
                    Value::Null => {}
                    _ => {
                        return Err(SinterError::schema(format!(
                            "{}: env must be a map of strings",
                            ctx
                        )))
                    }
                }
            }
        }
        "package" => {
            validate_with_fields(&d.with, PACKAGE_FIELDS, ctx)?;
            require_static_string_field(&d.with, "name", ctx)?;
            validate_desired_enum(
                &d.with,
                "state",
                &["present", "absent"],
                ctx,
                "package state is required and must be present or absent",
            )?;
        }
        "service" => {
            validate_with_fields(&d.with, SERVICE_FIELDS, ctx)?;
            require_static_string_field(&d.with, "name", ctx)?;
            let state = d.with.get("state");
            let enabled = d.with.get("enabled");
            if state.is_none() && enabled.is_none() {
                return Err(SinterError::schema(format!(
                    "{}: service requires at least one of state or enabled",
                    ctx
                )));
            }
            if state.is_some() {
                validate_desired_enum(
                    &d.with,
                    "state",
                    &["running", "stopped"],
                    ctx,
                    "service state must be running or stopped",
                )?;
            }
            if let Some(e) = enabled {
                if e.as_bool().is_none() && !matches!(e, Value::Str(_)) {
                    return Err(SinterError::schema(format!(
                        "{}: service enabled must be a boolean",
                        ctx
                    )));
                }
            }
        }
        other => {
            return Err(SinterError::schema(format!(
                "{}: unknown resource type {}",
                ctx, other
            )));
        }
    }
    Ok(())
}

fn require_static_string_field(with: &BTreeMap<String, Value>, key: &str, ctx: &str) -> Result<()> {
    match with.get(key) {
        Some(Value::Str(s)) => {
            if s.is_empty() {
                return Err(SinterError::schema(format!(
                    "{}: {} must not be empty",
                    ctx, key
                )));
            }
            require_static_identifier_string(s, key, ctx)
        }
        Some(Value::Null) => Err(SinterError::schema(format!("{}: {} is required", ctx, key))),
        Some(_) => Err(SinterError::schema(format!(
            "{}: {} must be a string",
            ctx, key
        ))),
        None => Err(SinterError::schema(format!(
            "{}: missing required field {}",
            ctx, key
        ))),
    }
}

fn validate_desired_enum(
    with: &BTreeMap<String, Value>,
    key: &str,
    allowed: &[&str],
    ctx: &str,
    message: &str,
) -> Result<()> {
    match with.get(key) {
        Some(Value::Str(s)) if crate::expressions::has_interpolation(s) => Ok(()),
        Some(Value::Str(s)) if allowed.contains(&s.as_str()) => Ok(()),
        _ => Err(SinterError::schema(format!("{}: {}", ctx, message))),
    }
}

fn require_optional_static_string(
    with: &BTreeMap<String, Value>,
    key: &str,
    ctx: &str,
) -> Result<()> {
    match with.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Str(s)) => {
            if s.is_empty() {
                return Err(SinterError::schema(format!(
                    "{}: {} must not be empty",
                    ctx, key
                )));
            }
            require_static_identifier_string(s, key, ctx)
        }
        Some(_) => Err(SinterError::schema(format!(
            "{}: {} must be a string",
            ctx, key
        ))),
    }
}

/// A static-identifier string may interpolate only statically-known values
/// (`vars.<name>` and, inside a loop, `item`). Facts, registers, and command
/// results may not form target identifiers.
fn require_static_identifier_string(s: &str, key: &str, ctx: &str) -> Result<()> {
    if s.contains('\0') {
        return Err(SinterError::schema(format!(
            "{}: {} may not contain NUL",
            ctx, key
        )));
    }
    if !crate::expressions::has_interpolation(s) {
        return Ok(());
    }
    for tok in extract_interpolation_exprs(s) {
        let expr = parse_expr(&tok).map_err(|e| {
            SinterError::schema(format!("{}: {} has invalid interpolation: {}", ctx, key, e))
        })?;
        let mut regs = BTreeSet::new();
        let mut dynamic_names = BTreeSet::new();
        collect_dynamic_refs(&expr, &mut regs, &mut dynamic_names);
        if !regs.is_empty() {
            return Err(SinterError::schema(format!(
                "{}: {} may not reference registers",
                ctx, key
            )));
        }
        if !dynamic_names.is_empty() {
            return Err(SinterError::schema(format!(
                "{}: {} may not be built from facts or command results",
                ctx, key
            )));
        }
    }
    Ok(())
}

fn value_references_sensitive_var(v: &Value, sensitive_vars: &BTreeSet<String>) -> bool {
    match v {
        Value::Str(s) => {
            for tok in extract_interpolation_exprs(s) {
                if let Ok(expr) = parse_expr(&tok) {
                    if expr_references_sensitive_var(&expr, sensitive_vars) {
                        return true;
                    }
                }
            }
            false
        }
        Value::List(items) => items
            .iter()
            .any(|i| value_references_sensitive_var(i, sensitive_vars)),
        Value::Map(m) => m
            .values()
            .any(|i| value_references_sensitive_var(i, sensitive_vars)),
        _ => false,
    }
}

fn expr_references_sensitive_var(e: &Expr, sensitive_vars: &BTreeSet<String>) -> bool {
    collect_var_refs(e, sensitive_vars)
}

fn collect_var_refs(e: &Expr, sensitive_vars: &BTreeSet<String>) -> bool {
    match e {
        Expr::Or(a, b) | Expr::And(a, b) | Expr::Cmp(a, _, b) => {
            collect_var_refs(a, sensitive_vars) || collect_var_refs(b, sensitive_vars)
        }
        Expr::Not(a) => collect_var_refs(a, sensitive_vars),
        Expr::Var(name) => sensitive_vars.contains(name),
        Expr::Fact(_)
        | Expr::Register(_, _)
        | Expr::Item
        | Expr::ResultField(_)
        | Expr::TemplateVar(_)
        | Expr::Str(_)
        | Expr::Int(_)
        | Expr::Float(_)
        | Expr::Bool(_)
        | Expr::Null => false,
    }
}

fn collect_dynamic_refs(
    e: &Expr,
    registers: &mut BTreeSet<String>,
    dynamic_names: &mut BTreeSet<String>,
) {
    match e {
        Expr::Or(a, b) | Expr::And(a, b) | Expr::Cmp(a, _, b) => {
            collect_dynamic_refs(a, registers, dynamic_names);
            collect_dynamic_refs(b, registers, dynamic_names);
        }
        Expr::Not(a) => collect_dynamic_refs(a, registers, dynamic_names),
        Expr::Register(name, _) => {
            registers.insert(name.clone());
        }
        Expr::Fact(path) => {
            dynamic_names.insert(format!("facts.{}", path.join(".")));
        }
        Expr::ResultField(name) => {
            dynamic_names.insert(format!("result.{}", name));
        }
        Expr::Var(_)
        | Expr::Item
        | Expr::Str(_)
        | Expr::Int(_)
        | Expr::Float(_)
        | Expr::Bool(_)
        | Expr::Null
        | Expr::TemplateVar(_) => {}
    }
}

fn require_optional_mode(with: &BTreeMap<String, Value>, ctx: &str, sensitive: bool) -> Result<()> {
    match with.get("mode") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Str(s)) => crate::paths::parse_mode(s).map(|_| ()).map_err(|e| {
            if sensitive {
                SinterError::schema(format!("{}: invalid mode", ctx))
            } else {
                SinterError::schema(format!("{}: {}", ctx, e.message))
            }
        }),
        Some(_) => Err(SinterError::schema(format!(
            "{}: mode must be a quoted four-digit octal string",
            ctx
        ))),
    }
}

fn require_content_type(with: &BTreeMap<String, Value>, ctx: &str) -> Result<()> {
    match with.get("content") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Str(_)) => Ok(()),
        Some(_) => Err(SinterError::schema(format!(
            "{}: content must be a string",
            ctx
        ))),
    }
}

fn freeze(state: LoadState, entry: &Path) -> Result<Model> {
    // Duplicate resource and handler ID detection.
    let mut resource_ids: BTreeSet<String> = BTreeSet::new();
    for r in &state.resources {
        if !resource_ids.insert(r.id.clone()) {
            return Err(SinterError::schema(format!(
                "duplicate resource id: {}",
                r.id
            )));
        }
    }
    let mut handler_ids: BTreeSet<String> = BTreeSet::new();
    for h in &state.handlers {
        if !handler_ids.insert(h.id.clone()) {
            return Err(SinterError::schema(format!(
                "duplicate handler id: {}",
                h.id
            )));
        }
        if resource_ids.contains(&h.id) {
            return Err(SinterError::schema(format!(
                "handler id {} collides with a resource id",
                h.id
            )));
        }
    }
    let mut handler_index = BTreeMap::new();
    for (i, h) in state.handlers.iter().enumerate() {
        handler_index.insert(h.id.clone(), i);
    }

    // Build variables.
    let mut vars = BTreeMap::new();
    let mut static_vars: BTreeMap<String, EvalVal> = BTreeMap::new();
    let mut sensitive_var_names: BTreeSet<String> = BTreeSet::new();
    for v in &state.vars {
        if v.sensitive {
            sensitive_var_names.insert(v.name.clone());
        }
        vars.insert(
            v.name.clone(),
            VarDef {
                name: v.name.clone(),
                value: v.value.clone(),
                sensitive: v.sensitive,
                origin: v.origin.clone(),
            },
        );
        static_vars.insert(
            v.name.clone(),
            if v.sensitive {
                EvalVal::known_sensitive(v.value.clone())
            } else {
                EvalVal::known(v.value.clone())
            },
        );
    }
    validate_declarations(&state.declarations, &state.handlers, &sensitive_var_names)?;

    // Register producer map + validation of loop+register.
    let mut register_producers: BTreeMap<String, String> = BTreeMap::new();
    for r in &state.resources {
        if let Some(reg) = r.with.get("register").and_then(|v| v.as_str()) {
            if reg.is_empty() {
                return Err(SinterError::schema(format!(
                    "{}: register must be a non-empty identifier",
                    r.id
                )));
            }
            if r.loop_index.is_some() {
                return Err(SinterError::schema(format!(
                    "{}: register is forbidden inside a loop",
                    r.id
                )));
            }
            if let Some(prev) = register_producers.insert(reg.to_string(), r.id.clone()) {
                return Err(SinterError::schema(format!(
                    "duplicate register name {} (used by {} and {})",
                    reg, prev, r.id
                )));
            }
        }
    }

    // Resolve static identifiers, validate dependencies and ownership conflicts.
    let mut frozen: Vec<FrozenResource> = Vec::with_capacity(state.resources.len());
    let mut path_owner: BTreeMap<String, String> = BTreeMap::new();

    for r in &state.resources {
        // Dependency / notify reference validation.
        for dep in &r.depends_on {
            if !resource_ids.contains(dep) {
                return Err(SinterError::schema(format!(
                    "{}: depends_on references unknown or unexpanded resource {}",
                    r.id, dep
                )));
            }
        }
        for n in &r.notify {
            if !handler_ids.contains(n) {
                return Err(SinterError::schema(format!(
                    "{}: notify references unknown handler {}",
                    r.id, n
                )));
            }
        }

        let item_eval = r.loop_item.as_ref().map(|v| EvalVal::known(v.clone()));
        let scope = Scope {
            vars: Some(&static_vars),
            facts: None,
            registers: None,
            item: item_eval.as_ref(),
            result: None,
            template: None,
        };

        // Validate `when` parses and gather register references.
        let mut expr_register_refs: BTreeSet<String> = BTreeSet::new();
        let mut scratch_names = BTreeSet::new();
        if let Some(w) = &r.when {
            let expr = parse_expr(w).map_err(|e| {
                SinterError::schema(format!("{}: invalid when expression: {}", r.id, e))
            })?;
            collect_register_refs(&expr, &mut expr_register_refs, &mut scratch_names);
        }
        // Gather register references from interpolated `with` values.
        for v in r.with.values() {
            collect_value_register_refs(v, &mut expr_register_refs)?;
        }
        for reg in &expr_register_refs {
            let producer = register_producers.get(reg).ok_or_else(|| {
                SinterError::schema(format!("{}: references unknown register {}", r.id, reg))
            })?;
            if !r.depends_on.contains(producer) {
                return Err(SinterError::schema(format!(
                    "{}: register {} must be listed directly in depends_on",
                    r.id, reg
                )));
            }
        }

        let mut fr = FrozenResource {
            id: r.id.clone(),
            type_: r.type_.clone(),
            with: r.with.clone(),
            when: r.when.clone(),
            depends_on: r.depends_on.clone(),
            notify: r.notify.clone(),
            sensitive: r.sensitive,
            derived_sensitive: false,
            origin: r.origin.clone(),
            loop_index: r.loop_index,
            loop_item: r.loop_item.clone(),
            path: None,
            program: None,
            creates: None,
            removes: None,
            package_name: None,
            service_name: None,
            controller_source: None,
            register: r
                .with
                .get("register")
                .and_then(|v| v.as_str())
                .map(String::from),
        };

        let resource_ctx = r.id.clone();
        match r.type_.as_str() {
            "file" => {
                validate_with_fields(&r.with, FILE_FIELDS, &resource_ctx)?;
                let path = static_string(&r.with, "path", &scope, &resource_ctx, true)?;
                validate_path(&path)
                    .map_err(|e| SinterError::schema(format!("{}: {}", resource_ctx, e.message)))?;
                fr.path = Some(path);
                validate_file_common(&r.with, &scope, &resource_ctx, &mut fr)?;
            }
            "directory" => {
                validate_with_fields(&r.with, DIR_FIELDS, &resource_ctx)?;
                let path = static_string(&r.with, "path", &scope, &resource_ctx, true)?;
                validate_path(&path)
                    .map_err(|e| SinterError::schema(format!("{}: {}", resource_ctx, e.message)))?;
                fr.path = Some(path);
            }
            "link" => {
                validate_with_fields(&r.with, LINK_FIELDS, &resource_ctx)?;
                let path = static_string(&r.with, "path", &scope, &resource_ctx, true)?;
                validate_path(&path)
                    .map_err(|e| SinterError::schema(format!("{}: {}", resource_ctx, e.message)))?;
                fr.path = Some(path);
            }
            "template" => {
                validate_with_fields(&r.with, TEMPLATE_FIELDS, &resource_ctx)?;
                let path = static_string(&r.with, "path", &scope, &resource_ctx, true)?;
                validate_path(&path)
                    .map_err(|e| SinterError::schema(format!("{}: {}", resource_ctx, e.message)))?;
                fr.path = Some(path);
                let source = static_string(&r.with, "source", &scope, &resource_ctx, true)?;
                let source_sensitive = r.sensitive
                    || value_references_sensitive_var(&r.with["source"], &sensitive_var_names);
                fr.controller_source = Some(resolve_source(&r.origin, &source).map_err(|e| {
                    if source_sensitive {
                        SinterError::schema(format!(
                            "{}: source validation failed (value redacted)",
                            resource_ctx
                        ))
                    } else {
                        e
                    }
                })?);
                if r.with.contains_key("content") {
                    return Err(SinterError::schema(format!(
                        "{}: template does not support content; use source",
                        resource_ctx
                    )));
                }
                validate_file_common(&r.with, &scope, &resource_ctx, &mut fr)?;
            }
            "command" => {
                validate_with_fields(&r.with, COMMAND_FIELDS, &resource_ctx)?;
                let program = static_string(&r.with, "program", &scope, &resource_ctx, true)?;
                if !program.starts_with('/') {
                    return Err(SinterError::schema(format!(
                        "{}: program must be an absolute path",
                        resource_ctx
                    )));
                }
                fr.program = Some(program);
                if let Some(v) = r.with.get("creates") {
                    if !v.is_null() {
                        let s = static_string(&r.with, "creates", &scope, &resource_ctx, true)?;
                        validate_path(&s).map_err(|e| {
                            SinterError::schema(format!("{}: creates: {}", resource_ctx, e.message))
                        })?;
                        fr.creates = Some(s);
                    }
                }
                if let Some(v) = r.with.get("removes") {
                    if !v.is_null() {
                        let s = static_string(&r.with, "removes", &scope, &resource_ctx, true)?;
                        validate_path(&s).map_err(|e| {
                            SinterError::schema(format!("{}: removes: {}", resource_ctx, e.message))
                        })?;
                        fr.removes = Some(s);
                    }
                }
                validate_command_fields(&r.with, &scope, &resource_ctx, &mut fr)?;
            }
            "package" => {
                validate_with_fields(&r.with, PACKAGE_FIELDS, &resource_ctx)?;
                let name = static_string(&r.with, "name", &scope, &resource_ctx, true)?;
                fr.package_name = Some(name);
                validate_desired_enum(
                    &r.with,
                    "state",
                    &["present", "absent"],
                    &resource_ctx,
                    "package state is required and must be present or absent",
                )?;
            }
            "service" => {
                validate_with_fields(&r.with, SERVICE_FIELDS, &resource_ctx)?;
                let name = static_string(&r.with, "name", &scope, &resource_ctx, true)?;
                fr.service_name = Some(name);
                let state = r.with.get("state");
                let enabled = r.with.get("enabled");
                if state.is_none() && enabled.is_none() {
                    return Err(SinterError::schema(format!(
                        "{}: service requires at least one of state or enabled",
                        resource_ctx
                    )));
                }
                if state.is_some() {
                    validate_desired_enum(
                        &r.with,
                        "state",
                        &["running", "stopped"],
                        &resource_ctx,
                        "service state must be running or stopped",
                    )?;
                }
                if let Some(e) = enabled {
                    if e.as_bool().is_none() && !matches!(e, Value::Str(_)) {
                        return Err(SinterError::schema(format!(
                            "{}: service enabled must be a boolean",
                            resource_ctx
                        )));
                    }
                }
            }
            other => {
                return Err(SinterError::schema(format!(
                    "{}: unknown resource type {}",
                    resource_ctx, other
                )));
            }
        }

        // Ownership conflicts for filesystem resources.
        if matches!(r.type_.as_str(), "file" | "template" | "directory" | "link") {
            if let Some(p) = &fr.path {
                if let Some(prev) = path_owner.insert(p.clone(), r.id.clone()) {
                    return Err(SinterError::schema(format!(
                        "conflicting ownership of path {} by resources {} and {}",
                        p, prev, r.id
                    )));
                }
            }
        }

        // Template bodies can reference registers; those references require the
        // same direct-dependency validation as `with`/`when` interpolations.
        if fr.type_ == "template" {
            if let Some(src) = &fr.controller_source {
                let body = std::fs::read_to_string(src).map_err(|e| {
                    if r.sensitive {
                        SinterError::schema(format!(
                            "{}: cannot read template (value redacted): {}",
                            resource_ctx,
                            e.kind()
                        ))
                    } else {
                        SinterError::schema(format!(
                            "{}: cannot read template {}: {}",
                            resource_ctx,
                            src.display(),
                            e
                        ))
                    }
                })?;
                let mut body_regs: BTreeSet<String> = BTreeSet::new();
                for tok in extract_interpolation_exprs(&body) {
                    let expr = parse_expr(&tok).map_err(|e| {
                        SinterError::schema(format!(
                            "{}: invalid template interpolation: {}",
                            resource_ctx, e
                        ))
                    })?;
                    let mut names = BTreeSet::new();
                    collect_register_refs(&expr, &mut body_regs, &mut names);
                }
                for reg in &body_regs {
                    let producer = register_producers.get(reg).ok_or_else(|| {
                        SinterError::schema(format!(
                            "{}: template references unknown register {}",
                            resource_ctx, reg
                        ))
                    })?;
                    if !r.depends_on.contains(producer) {
                        return Err(SinterError::schema(format!(
                            "{}: template register {} must be listed directly in depends_on",
                            resource_ctx, reg
                        )));
                    }
                }
            }
        }

        // Conservative static sensitivity: explicit flag, any sensitive
        // variable referenced by interpolated fields, or a sensitive variable in
        // a template body. This lets early diagnostics redact before runtime.
        let mut derived = r.sensitive;
        for v in r.with.values() {
            if value_references_sensitive_var(v, &sensitive_var_names) {
                derived = true;
            }
        }
        if let Some(src) = &fr.controller_source {
            if let Ok(body) = std::fs::read_to_string(src) {
                for tok in extract_interpolation_exprs(&body) {
                    if let Ok(expr) = parse_expr(&tok) {
                        if expr_references_sensitive_var(&expr, &sensitive_var_names) {
                            derived = true;
                        }
                    }
                }
            }
        }
        fr.derived_sensitive = derived;

        frozen.push(fr);
    }

    // Static loop input must be statically known: already guaranteed by IR being
    // literal values (facts/registers cannot form loop input).
    let _ = entry;

    // Dependency graph must be acyclic. Detect it during static validation.
    detect_dependency_cycle(&frozen)?;

    Ok(Model {
        vars,
        resources: frozen,
        handlers: state.handlers,
        handler_index,
        register_producers,
    })
}

fn detect_dependency_cycle(resources: &[FrozenResource]) -> Result<()> {
    let index: BTreeMap<&str, usize> = resources
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.as_str(), i))
        .collect();
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        White,
        Gray,
        Black,
    }
    let mut marks = vec![Mark::White; resources.len()];
    fn visit(
        i: usize,
        resources: &[FrozenResource],
        index: &BTreeMap<&str, usize>,
        marks: &mut Vec<Mark>,
    ) -> Result<()> {
        marks[i] = Mark::Gray;
        for d in &resources[i].depends_on {
            let di = *index.get(d.as_str()).ok_or_else(|| {
                SinterError::schema(format!("{}: unknown dependency {}", resources[i].id, d))
            })?;
            match marks[di] {
                Mark::Gray => {
                    return Err(SinterError::schema(format!(
                        "dependency cycle detected involving {}",
                        resources[di].id
                    )))
                }
                Mark::White => visit(di, resources, index, marks)?,
                Mark::Black => {}
            }
        }
        marks[i] = Mark::Black;
        Ok(())
    }
    for i in 0..resources.len() {
        if marks[i] == Mark::White {
            visit(i, resources, &index, &mut marks)?;
        }
    }
    Ok(())
}

fn resolve_source(origin: &str, source: &str) -> Result<PathBuf> {
    resolve_source_pub(origin, source)
}

pub fn resolve_source_pub(origin: &str, source: &str) -> Result<PathBuf> {
    let p = Path::new(source);
    if p.is_absolute() {
        if !p.exists() {
            return Err(SinterError::schema(format!(
                "template/source file not found: {}",
                source
            )));
        }
        return Ok(p.to_path_buf());
    }
    let base = Path::new(origin).parent().unwrap_or_else(|| Path::new("."));
    let joined = base.join(p);
    if !joined.exists() {
        return Err(SinterError::schema(format!(
            "template/source file not found: {}",
            joined.display()
        )));
    }
    Ok(joined)
}

fn collect_value_register_refs(v: &Value, out: &mut BTreeSet<String>) -> Result<()> {
    match v {
        Value::Str(s) => {
            if crate::expressions::has_interpolation(s) {
                // Parse tokens to find registers.
                let scope = Scope::empty();
                let _ = scope;
                for tok in extract_interpolation_exprs(s) {
                    let expr = parse_expr(&tok).map_err(|e| {
                        SinterError::schema(format!("invalid interpolation expression: {}", e))
                    })?;
                    let mut names = BTreeSet::new();
                    collect_register_refs(&expr, out, &mut names);
                }
            }
        }
        Value::List(items) => {
            for i in items {
                collect_value_register_refs(i, out)?;
            }
        }
        Value::Map(m) => {
            for i in m.values() {
                collect_value_register_refs(i, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn extract_interpolation_exprs(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 2 < chars.len() && chars[i + 1] == '{' && chars[i + 2] == '{' {
            i += 3;
            continue;
        }
        if chars[i] == '{' && i + 1 < chars.len() && chars[i + 1] == '{' {
            let start = i + 2;
            if let Some(end) = find_close(&chars, start) {
                out.push(chars[start..end].iter().collect());
                i = end + 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn find_close(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    let mut quote: Option<char> = None;
    while i < chars.len() {
        let c = chars[i];
        match quote {
            Some(q) => {
                if c == '\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                } else if c == '}' && i + 1 < chars.len() && chars[i + 1] == '}' {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

fn validate_file_common(
    with: &BTreeMap<String, Value>,
    scope: &Scope,
    ctx: &str,
    fr: &mut FrozenResource,
) -> Result<()> {
    let content = with.get("content");
    let source = with.get("source");
    if content.is_some() && source.is_some() {
        return Err(SinterError::schema(format!(
            "{}: content and source are mutually exclusive",
            ctx
        )));
    }
    if let Some(Value::Str(s)) = with.get("mode") {
        let _ = parse_mode(s).map_err(|e| {
            if fr.sensitive {
                SinterError::schema(format!("{}: invalid mode", ctx))
            } else {
                SinterError::schema(format!("{}: {}", ctx, e.message))
            }
        })?;
    } else if let Some(v) = with.get("mode") {
        if !v.is_null() {
            return Err(SinterError::schema(format!(
                "{}: mode must be a quoted four-digit octal string",
                ctx
            )));
        }
    }
    if let Some(Value::Str(s)) = with.get("owner") {
        if crate::value::has_nul(s) || s.is_empty() {
            return Err(SinterError::schema(format!("{}: invalid owner", ctx)));
        }
    }
    if let Some(Value::Str(s)) = with.get("group") {
        if crate::value::has_nul(s) || s.is_empty() {
            return Err(SinterError::schema(format!("{}: invalid group", ctx)));
        }
    }
    let _ = fr;
    // Validate that `source` is static when present.
    if source.is_some() {
        let _ = static_string(with, "source", scope, ctx, true)?;
    }
    Ok(())
}

fn validate_command_fields(
    with: &BTreeMap<String, Value>,
    scope: &Scope,
    ctx: &str,
    fr: &mut FrozenResource,
) -> Result<()> {
    if let Some(v) = with.get("args") {
        match v {
            Value::List(items) => {
                for i in items {
                    if !matches!(i, Value::Str(_)) {
                        return Err(SinterError::schema(format!(
                            "{}: command args must be strings",
                            ctx
                        )));
                    }
                    if let Value::Str(s) = i {
                        if crate::value::has_nul(s) {
                            return Err(SinterError::schema(format!(
                                "{}: command args may not contain NUL",
                                ctx
                            )));
                        }
                    }
                }
            }
            _ => {
                return Err(SinterError::schema(format!(
                    "{}: command args must be a list of strings",
                    ctx
                )))
            }
        }
    }
    if let Some(v) = with.get("timeout_seconds") {
        match v.as_int() {
            Some(n) if (1..=86400).contains(&n) => {}
            _ => {
                return Err(SinterError::schema(format!(
                    "{}: timeout_seconds must be an integer in 1..86400",
                    ctx
                )))
            }
        }
    }
    if let Some(v) = with.get("success_codes") {
        match v {
            Value::List(items) if !items.is_empty() => {
                for i in items {
                    match i.as_int() {
                        Some(n) if (0..=255).contains(&n) => {}
                        _ => {
                            return Err(SinterError::schema(format!(
                                "{}: success_codes must be integers in 0..255",
                                ctx
                            )))
                        }
                    }
                }
            }
            _ => {
                return Err(SinterError::schema(format!(
                    "{}: success_codes must be a non-empty list of integers",
                    ctx
                )))
            }
        }
    }
    if let Some(v) = with.get("changed_when") {
        if !v.is_null() {
            match v.as_str() {
                Some(s) => {
                    let expr = parse_expr(s).map_err(|e| {
                        SinterError::schema(format!("{}: invalid changed_when: {}", ctx, e))
                    })?;
                    validate_changed_when(&expr, ctx)?;
                }
                None => {
                    return Err(SinterError::schema(format!(
                        "{}: changed_when must be a string or null",
                        ctx
                    )))
                }
            }
        }
    }
    if fr.creates.is_some() && fr.removes.is_some() {
        return Err(SinterError::schema(format!(
            "{}: creates and removes are mutually exclusive",
            ctx
        )));
    }
    // Validate cwd statically if present (must be an absolute path, no facts
    // permitted for the identifier, no sensitive).
    if let Some(v) = with.get("cwd") {
        if !v.is_null() {
            let s = static_string(with, "cwd", scope, ctx, true)?;
            validate_path(&s)
                .map_err(|e| SinterError::schema(format!("{}: cwd: {}", ctx, e.message)))?;
        }
    }
    // env: keys must be strings, reserved names rejected.
    if let Some(v) = with.get("env") {
        match v {
            Value::Map(m) => {
                for (k, val) in m {
                    if RESERVED_ENV.contains(&k.as_str()) {
                        return Err(SinterError::schema(format!(
                            "{}: env name {} is reserved by the command baseline",
                            ctx, k
                        )));
                    }
                    if !matches!(val, Value::Str(_)) {
                        return Err(SinterError::schema(format!(
                            "{}: env values must be strings",
                            ctx
                        )));
                    }
                }
            }
            _ => {
                return Err(SinterError::schema(format!(
                    "{}: env must be a map of strings",
                    ctx
                )))
            }
        }
    }
    Ok(())
}

const RESERVED_ENV: &[&str] = &["PATH", "LANG", "LC_ALL", "HOME"];

fn validate_changed_when(e: &Expr, ctx: &str) -> Result<()> {
    let mut regs = BTreeSet::new();
    let mut names = BTreeSet::new();
    collect_register_refs(e, &mut regs, &mut names);
    if !regs.is_empty() {
        return Err(SinterError::schema(format!(
            "{}: changed_when may not reference registers",
            ctx
        )));
    }
    validate_changed_when_fields(e, ctx)
}

fn validate_changed_when_fields(e: &Expr, ctx: &str) -> Result<()> {
    match e {
        Expr::Or(a, b) | Expr::And(a, b) | Expr::Cmp(a, _, b) => {
            validate_changed_when_fields(a, ctx)?;
            validate_changed_when_fields(b, ctx)
        }
        Expr::Not(a) => validate_changed_when_fields(a, ctx),
        Expr::ResultField(name) => match name.as_str() {
            "executed" | "exit_code" | "stdout" | "stderr" | "stdout_complete"
            | "stderr_complete" => Ok(()),
            other => Err(SinterError::schema(format!(
                "{}: changed_when may not read result.{}",
                ctx, other
            ))),
        },
        Expr::Var(_)
        | Expr::Fact(_)
        | Expr::Register(_, _)
        | Expr::Item
        | Expr::TemplateVar(_)
        | Expr::Str(_)
        | Expr::Int(_)
        | Expr::Float(_)
        | Expr::Bool(_)
        | Expr::Null => Ok(()),
    }
}

fn static_string(
    with: &BTreeMap<String, Value>,
    key: &str,
    scope: &Scope,
    ctx: &str,
    require: bool,
) -> Result<String> {
    let raw = match with.get(key) {
        Some(v) => v,
        None => {
            if require {
                return Err(SinterError::schema(format!(
                    "{}: missing required field {}",
                    ctx, key
                )));
            } else {
                return Ok(String::new());
            }
        }
    };
    if raw.is_null() {
        return Ok(String::new());
    }
    let ev = eval_value_interpolated(raw, scope).map_err(|e| {
        SinterError::schema(format!(
            "{}: {} must be a statically-known string ({}); facts and registers may not form identifiers",
            ctx, key, e
        ))
    })?;
    if ev.sensitive {
        return Err(SinterError::schema(format!(
            "{}: {} may not be built from sensitive values",
            ctx, key
        )));
    }
    match ev.val {
        Some(Value::Str(s)) => {
            if s.contains('\0') {
                return Err(SinterError::schema(format!(
                    "{}: {} may not contain NUL bytes",
                    ctx, key
                )));
            }
            Ok(s)
        }
        Some(other) => Err(SinterError::schema(format!(
            "{}: {} must be a string, got {}",
            ctx,
            key,
            other.type_name()
        ))),
        None => Err(SinterError::schema(format!(
            "{}: {} must be statically known",
            ctx, key
        ))),
    }
}

fn validate_with_fields(with: &BTreeMap<String, Value>, allowed: &[&str], ctx: &str) -> Result<()> {
    for k in with.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(SinterError::schema(format!(
                "{}: unknown field with.{}",
                ctx, k
            )));
        }
    }
    Ok(())
}

pub const FILE_FIELDS: &[&str] = &[
    "path", "state", "content", "source", "owner", "group", "mode",
];
pub const DIR_FIELDS: &[&str] = &["path", "state", "owner", "group", "mode"];
pub const LINK_FIELDS: &[&str] = &["path", "target", "state"];
pub const TEMPLATE_FIELDS: &[&str] = &[
    "path", "state", "content", "source", "owner", "group", "mode", "vars",
];
pub const COMMAND_FIELDS: &[&str] = &[
    "program",
    "args",
    "cwd",
    "env",
    "timeout_seconds",
    "success_codes",
    "creates",
    "removes",
    "changed_when",
    "register",
];
pub const PACKAGE_FIELDS: &[&str] = &["name", "state"];
pub const SERVICE_FIELDS: &[&str] = &["name", "state", "enabled"];

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn expands_loop_ids() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "r.yaml",
            "version: 1\nresources:\n  - id: pkg\n    type: package\n    with:\n      name: \"{{ item }}\"\n      state: present\n    loop:\n      - a\n      - b\n",
        );
        let m = load_model(&p).unwrap();
        assert_eq!(m.resources.len(), 2);
        assert_eq!(m.resources[0].id, "pkg[0]");
        assert_eq!(m.resources[1].id, "pkg[1]");
    }

    #[test]
    fn include_order_and_dup_detection() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "base.yaml",
            "version: 1\nvars:\n  x:\n    value: 1\n",
        );
        let p = write(
            d.path(),
            "main.yaml",
            "version: 1\ninclude:\n  - base.yaml\nresources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/x\n",
        );
        let m = load_model(&p).unwrap();
        assert!(m.vars.contains_key("x"));
    }

    #[test]
    fn duplicate_include_is_error() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "base.yaml", "version: 1\n");
        let p = write(
            d.path(),
            "main.yaml",
            "version: 1\ninclude:\n  - base.yaml\n  - base.yaml\n",
        );
        assert!(load_model(&p).is_err());
    }

    #[test]
    fn ownership_conflict_detected() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "r.yaml",
            "version: 1\nresources:\n  - id: a\n    type: file\n    with:\n      path: /tmp/x\n  - id: b\n    type: directory\n    with:\n      path: /tmp/x\n",
        );
        assert!(load_model(&p).is_err());
    }

    #[test]
    fn loop_register_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "r.yaml",
            "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n      register: r\n    loop:\n      - a\n",
        );
        assert!(load_model(&p).is_err());
    }

    #[test]
    fn register_direct_dependency_required() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "r.yaml",
            "version: 1\nresources:\n  - id: c1\n    type: command\n    with:\n      program: /bin/true\n      register: r\n  - id: c2\n    type: command\n    with:\n      program: /bin/true\n    when: registers.r.exit_code == 0\n",
        );
        assert!(load_model(&p).is_err());
    }

    #[test]
    fn reserved_env_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "r.yaml",
            "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n      env:\n        PATH: /evil\n",
        );
        assert!(load_model(&p).is_err());
    }

    #[test]
    fn facts_cannot_form_path() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "r.yaml",
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: \"{{ facts.hostname }}.conf\"\n",
        );
        assert!(load_model(&p).is_err());
    }

    #[test]
    fn sensitive_path_rejected() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "r.yaml",
            "version: 1\nvars:\n  p:\n    value: /tmp/x\n    sensitive: true\nresources:\n  - id: f\n    type: file\n    with:\n      path: \"{{ vars.p }}\"\n",
        );
        assert!(load_model(&p).is_err());
    }
}
