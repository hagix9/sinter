use crate::document::{parse_document, Document, TargetSelector};
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
    /// Static `name` of a `user` or `group` resource.
    pub account_name: Option<String>,
    pub controller_source: Option<PathBuf>,
    /// The encrypted secret named by `content: { secret: <path> }`, resolved
    /// against the recipe that names it. Such a resource is always sensitive.
    pub secret: Option<crate::secret_source::SecretRef>,
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
    /// Paths to back up on the target before apply mutates anything
    /// (`backup.paths`, include-expanded in document order, unique).
    pub backups: Vec<String>,
    /// Explicit execution targets (`targets`), from the entry recipe only.
    pub targets: Option<TargetSelector>,
    /// Load-time warnings: likely mistakes that are still valid recipes
    /// (shown by `validate`; they never change what a run does).
    pub warnings: Vec<String>,
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
    /// A model of nothing: no resource, handler or variable, only the
    /// recipe's `targets`. It stands in for a recipe that is parsed and
    /// checked but never frozen because no host runs it (`--limit` left every
    /// host of its `targets` out, DESIGN §19.2), so that display code has a
    /// `Model` to read. It must never be executed: the recipe's unit is marked
    /// [`crate::bundle::RecipeUnit::unfrozen`] and no execution may name it.
    pub fn unfrozen_stub(targets: Option<TargetSelector>) -> Model {
        Model {
            vars: BTreeMap::new(),
            resources: Vec::new(),
            handlers: Vec::new(),
            handler_index: BTreeMap::new(),
            register_producers: BTreeMap::new(),
            backups: Vec::new(),
            targets,
            warnings: Vec::new(),
        }
    }

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
    load_model_with(entry, crate::secret_source::ReferenceCheck::Strict)
}

/// [`load_model`] with an explicit secret-reference mode. Every caller except
/// `secrets list --recipe` uses the strict one through [`load_model`].
pub(crate) fn load_model_with(
    entry: &Path,
    refs: crate::secret_source::ReferenceCheck,
) -> Result<Model> {
    prepare_with(entry, refs)?.freeze_default()
}

/// Parse the recipe at `entry` and expand its include graph without freezing
/// it: no variable value is used yet (DESIGN §19.5). [`Prepared::freeze_default`]
/// then gives exactly what [`load_model`] gives.
pub fn prepare(entry: &Path) -> Result<Prepared> {
    prepare_with(entry, crate::secret_source::ReferenceCheck::Strict)
}

pub(crate) fn prepare_with(
    entry: &Path,
    refs: crate::secret_source::ReferenceCheck,
) -> Result<Prepared> {
    // Pre-pass: collect every sensitive variable name across the whole
    // include graph before any resource is expanded. Sensitivity of an
    // expression must not depend on include ordering — a resource in an
    // included file may reference a sensitive variable declared by the
    // including parent, and includes are expanded before the parent's own
    // variables become visible. Using the complete, order-independent set
    // everywhere keeps diagnostics redacted on every path (DESIGN §31).
    let mut global_sensitive_vars: BTreeSet<String> = BTreeSet::new();
    let mut pre_seen: HashSet<PathBuf> = HashSet::new();
    collect_sensitive_vars(entry, &mut pre_seen, &mut global_sensitive_vars)?;
    let mut state = LoadState {
        seen: HashSet::new(),
        vars: Vec::new(),
        resources: Vec::new(),
        handlers: Vec::new(),
        var_names: HashSet::new(),
        declarations: Vec::new(),
        global_sensitive_vars,
        backups: Vec::new(),
        entry: None,
        targets: None,
        recipe_env: None,
        refs,
    };
    state.load(entry)?;
    Ok(Prepared {
        state,
        entry: entry.to_path_buf(),
    })
}

/// A loaded recipe whose variable values are not applied yet. Freezing a
/// copy never changes it, so one prepared recipe yields independent models
/// for any number of hosts.
#[derive(Clone)]
pub struct Prepared {
    state: LoadState,
    entry: PathBuf,
}

/// The variable values a variables file gives one execution (DESIGN §19.5):
/// name -> (value, layer). The layer (`vars`, `groups.<g>`, `hosts.<h>`) is
/// for diagnostics only; it never changes sensitivity.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VarOverrides {
    entries: BTreeMap<String, (Value, String)>,
    /// Only [`Prepared::check_structure`] sets it: a field whose static check
    /// fails *because of what a variable holds* is left out of the check
    /// instead of failing it, and the resource's other checks go on (see
    /// [`Tolerance`]); every other failure still fails.
    structure_only: bool,
}

impl VarOverrides {
    pub fn insert(&mut self, name: &str, value: Value, layer: &str) {
        self.entries
            .insert(name.to_string(), (value, layer.to_string()));
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The layer an overridden variable came from.
    pub fn layer(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(|(_, l)| l.as_str())
    }

    pub fn value(&self, name: &str) -> Option<&Value> {
        self.entries.get(name).map(|(v, _)| v)
    }
}

impl Prepared {
    /// `targets` of the entry recipe.
    pub fn targets(&self) -> Option<&TargetSelector> {
        self.state.targets.as_ref()
    }

    /// Declared variables, include graph included: (name, default, sensitive).
    pub fn declared(&self) -> impl Iterator<Item = (&str, &Value, bool)> {
        self.state
            .vars
            .iter()
            .map(|v| (v.name.as_str(), &v.value, v.sensitive))
    }

    /// The checks that do not depend on what a variable holds: the recipe's
    /// resources are frozen with the recipe's own defaults, and a field that
    /// references a variable and fails its static check with them is left
    /// out (its value is not this recipe's to judge here) unless it fails
    /// whatever the variables hold (an undeclared variable, a fact, a
    /// sensitive value, a variable of another type). The resource's other
    /// checks go on, and so do those of the other resources. Everything else
    /// fails as it would when the recipe runs: unknown resource types and
    /// fields, duplicate ids, `depends_on`/`notify` references and cycles,
    /// secret references, declarations, literal fields, ownership conflicts
    /// no variable takes part in, and a check on a field that references no
    /// variable. Not judged: a failure that depends on a variable's value, a
    /// conflict over a path or a name that a variable decides, and a template
    /// file a variable chooses. This is what a recipe no host runs is held to
    /// (DESIGN §19.2): it is neither frozen nor given any variable value.
    pub fn check_structure(&self) -> Result<()> {
        let mut overrides = VarOverrides {
            structure_only: true,
            ..VarOverrides::default()
        };
        for v in self.state.vars.iter().filter(|v| !v.sensitive) {
            overrides.insert(&v.name, v.value.clone(), "recipe default");
        }
        freeze(self.state.clone(), &self.entry, &overrides).map(|_| ())
    }

    /// Freeze with the recipe's own values: the established path.
    pub fn freeze_default(self) -> Result<Model> {
        freeze(self.state, &self.entry, &VarOverrides::default())
    }

    /// Freeze a copy with `overrides` applied. Every override must name a
    /// declared, non-sensitive variable and keep the declared type; errors
    /// name the variable and the types, never a value. A static check that
    /// fails on a field depending on an override reports the field and the
    /// variables instead of its own message (DESIGN §19.5).
    pub fn freeze_with(&self, overrides: &VarOverrides) -> Result<Model> {
        let mut state = self.state.clone();
        for (name, (value, layer)) in &overrides.entries {
            let Some(v) = state.vars.iter_mut().find(|v| &v.name == name) else {
                return Err(SinterError::schema(format!(
                    "{}: variable {} is not declared by the recipe",
                    layer, name
                )));
            };
            if v.sensitive {
                return Err(SinterError::schema(format!(
                    "{}: variable {} is sensitive and cannot be overridden",
                    layer, name
                )));
            }
            if v.value.type_name() != value.type_name() {
                return Err(SinterError::schema(format!(
                    "{}: variable {} must be {}, not {}",
                    layer,
                    name,
                    v.value.type_name(),
                    value.type_name()
                )));
            }
            v.value = value.clone();
        }
        freeze(state, &self.entry, overrides)
    }
}

/// The static check a resource is in, for value-free diagnostics (DESIGN
/// §19.5). Anything not marked is `Unattributed`, which withholds whenever
/// the resource references an overridden variable anywhere.
#[derive(Debug, Clone)]
enum Stage {
    Unattributed,
    /// Evaluates no variable value: its message is kept.
    ValueFree,
    /// Evaluates this `with` field (and checks the result).
    Field(&'static str),
    /// Ownership of this field's value conflicts with resource `peer`.
    Ownership {
        field: &'static str,
        peer: String,
    },
}

/// Run `check` in stage `at`. On success the stage returns to
/// `Unattributed`, so a check added later without a stage of its own is
/// treated conservatively; on failure `at` stays for the boundary.
fn staged<T>(stage: &mut Stage, at: Stage, check: impl FnOnce() -> Result<T>) -> Result<T> {
    *stage = at;
    let out = check()?;
    *stage = Stage::Unattributed;
    Ok(out)
}

/// What a structure-only check (DESIGN §19.2) may leave unjudged, so that a
/// field it cannot judge does not stop the resource's other checks. Off for
/// every freeze that runs a recipe: there a failure of any check fails.
struct Tolerance<'a> {
    on: bool,
    /// Field -> declared variables its value references (this resource).
    refs: &'a BTreeMap<String, BTreeSet<String>>,
    /// The variables of a probe: every declared variable holds a neutral
    /// value of its declared type, so only what holds for any value is left
    /// to judge.
    probe_vars: &'a BTreeMap<String, EvalVal>,
    item: Option<&'a EvalVal>,
    with: &'a BTreeMap<String, Value>,
    ctx: &'a str,
}

/// The most boolean variables one field may name for [`Tolerance`] to try every
/// combination of them; a field naming more is left undecided.
const MAX_PROBED_BOOLS: usize = 8;

impl Tolerance<'_> {
    /// Whether a failure of the static check of `field` may depend on what a
    /// variable holds. It does not when the field cannot be evaluated to a
    /// string whatever the variables hold: an undeclared variable, a fact or
    /// register, a sensitive value, a variable of another type. Evaluating
    /// with neutral values is the same evaluation the check starts with, so
    /// the answer never rests on a message. A boolean variable can decide
    /// which side of `||` or `&&` is evaluated at all, so every combination of
    /// the booleans the field names is tried: the failure holds whatever the
    /// variables hold only if it holds for each of them.
    fn may_depend_on_values(&self, field: &str) -> bool {
        let Some(named) = self.refs.get(field).filter(|_| self.on) else {
            return false;
        };
        let bools: Vec<&String> = named
            .iter()
            .filter(|n| {
                matches!(
                    self.probe_vars.get(*n).and_then(|v| v.val.as_ref()),
                    Some(Value::Bool(_))
                ) && self.probe_vars.get(*n).is_some_and(|v| !v.sensitive)
            })
            .collect();
        if bools.len() > MAX_PROBED_BOOLS {
            return true;
        }
        let mut vars = self.probe_vars.clone();
        (0..1u32 << bools.len()).any(|combo| {
            for (i, n) in bools.iter().enumerate() {
                vars.insert(
                    (*n).clone(),
                    EvalVal::known(Value::Bool(combo >> i & 1 == 1)),
                );
            }
            let scope = Scope::static_scope(&vars, self.item);
            static_string(self.with, field, &scope, self.ctx, true, true).is_ok()
        })
    }
}

/// [`staged`] for a check of one `with` field. The judgement rests on
/// `static_string` alone: a check of the field that is not a failure of
/// `static_string` and does not depend on a variable's value would be left
/// undecided too, so such a check belongs outside the closure given here.
/// A structure-only check goes on
/// past a failure that may depend on what a variable holds, and the field has
/// no value (`None`); every other failure fails.
fn staged_field<T>(
    stage: &mut Stage,
    tol: &Tolerance,
    field: &'static str,
    check: impl FnOnce() -> Result<T>,
) -> Result<Option<T>> {
    match staged(stage, Stage::Field(field), check) {
        Ok(v) => Ok(Some(v)),
        Err(_) if tol.may_depend_on_values(field) => {
            *stage = Stage::Unattributed;
            Ok(None)
        }
        Err(e) => {
            // It fails whatever the variables hold: the boundary keeps it.
            if tol.on {
                *stage = Stage::ValueFree;
            }
            Err(e)
        }
    }
}

/// Whether an ownership conflict over `field` with resource `peer` may depend
/// on what a variable holds: the field of either side references one.
fn ownership_may_depend_on_values(
    tol: &Tolerance,
    peer_refs: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    field: &str,
    peer: &str,
) -> bool {
    tol.on
        && (tol.refs.contains_key(field)
            || peer_refs.get(peer).is_some_and(|m| m.contains_key(field)))
}

/// The neutral value of a declared type, for a [`Tolerance`] probe.
fn neutral_value(v: &Value) -> Value {
    match v {
        Value::Null => Value::Null,
        Value::Bool(_) => Value::Bool(false),
        Value::Int(_) => Value::Int(0),
        Value::Float(_) => Value::Float(0.0),
        Value::Str(_) => Value::Str(String::new()),
        Value::List(_) => Value::List(Vec::new()),
        Value::Map(_) => Value::Map(BTreeMap::new()),
    }
}

/// Field -> overridden variables its value references. Conservative: the
/// same structural-or-textual test sensitive redaction uses.
fn override_refs(
    with: &BTreeMap<String, Value>,
    overrides: &VarOverrides,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for (k, v) in with {
        let names: BTreeSet<String> = overrides
            .entries
            .keys()
            .filter(|n| value_may_be_sensitive(v, &BTreeSet::from([(*n).clone()])))
            .cloned()
            .collect();
        if !names.is_empty() {
            out.insert(k.clone(), names);
        }
    }
    out
}

/// The single boundary every failure of a resource's static checks passes.
/// The original error is kept unless the failing stage reads a field that
/// references an overridden variable; then a diagnostic is built from the
/// resource id, the check and the variable names. The original message is
/// never inspected.
fn withhold_override_values(
    r: &RawResource,
    stage: &Stage,
    refs: &BTreeMap<String, BTreeSet<String>>,
    peer_refs: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    overrides: &VarOverrides,
    e: SinterError,
) -> SinterError {
    let mut names: BTreeSet<&String> = BTreeSet::new();
    let check = match stage {
        Stage::ValueFree => return e,
        Stage::Unattributed => {
            names.extend(refs.values().flatten());
            "check not attributed to one field".to_string()
        }
        Stage::Field(f) => {
            names.extend(refs.get(*f).into_iter().flatten());
            format!("field {f}")
        }
        Stage::Ownership { field, peer } => {
            names.extend(refs.get(*field).into_iter().flatten());
            names.extend(
                peer_refs
                    .get(peer)
                    .and_then(|m| m.get(*field))
                    .into_iter()
                    .flatten(),
            );
            format!("ownership of field {field} (conflicts with resource {peer})")
        }
    };
    if names.is_empty() {
        return e;
    }
    let vars: Vec<String> = names
        .iter()
        .map(|n| format!("{} ({})", n, overrides.layer(n).unwrap_or("variables file")))
        .collect();
    SinterError {
        message: format!(
            "{}: {} static check failed: {}; it depends on variables from the variables file: {}; the value is withheld",
            r.id,
            r.type_,
            check,
            vars.join(", ")
        ),
        ..e
    }
}

/// Recursively collect every sensitive variable name in the include graph.
/// This runs before expansion so sensitivity decisions are independent of
/// include ordering.
fn collect_sensitive_vars(
    path: &Path,
    seen: &mut HashSet<PathBuf>,
    names: &mut BTreeSet<String>,
) -> Result<()> {
    let canon = canonicalize(path)?;
    if !seen.insert(canon.clone()) {
        return Err(SinterError::schema(format!(
            "recipe {} is included more than once (include cycle or duplicate include)",
            canon.display()
        )));
    }
    let doc = parse_document(&canon)?;
    for v in &doc.vars {
        if v.sensitive {
            names.insert(v.name.clone());
        }
    }
    let base_dir = canon.parent().unwrap_or_else(|| Path::new("."));
    for inc in &doc.includes {
        let inc_path = if Path::new(&inc.path).is_absolute() {
            PathBuf::from(&inc.path)
        } else {
            base_dir.join(&inc.path)
        };
        collect_sensitive_vars(&inc_path, seen, names)?;
    }
    Ok(())
}

#[derive(Clone)]
struct LoadState {
    seen: HashSet<PathBuf>,
    vars: Vec<VarDef>,
    resources: Vec<RawResource>,
    handlers: Vec<FrozenHandler>,
    var_names: HashSet<String>,
    /// Every resource declaration, recorded independently of loop expansion so
    /// invalid declarations are rejected even when their loop is empty.
    declarations: Vec<Declaration>,
    /// Sensitive variable names across the entire include graph, collected in
    /// a pre-pass. Sensitivity decisions use this set so they never depend on
    /// the order in which documents happen to be expanded.
    global_sensitive_vars: BTreeSet<String>,
    /// `backup.paths` across the include graph: (path, declaring origin).
    backups: Vec<(String, String)>,
    /// Canonical path of the entry recipe (the first document loaded).
    entry: Option<PathBuf>,
    /// `targets` of the entry recipe.
    targets: Option<TargetSelector>,
    /// Recipe-wide default `env` of the entry recipe (DESIGN §27.1).
    recipe_env: Option<Value>,
    /// How strictly secret references are checked (strict unless listing).
    refs: crate::secret_source::ReferenceCheck,
}

/// A resource declaration as written, retained for declaration-level
/// validation that must not be erased by static loop expansion.
#[derive(Clone)]
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
        if self.entry.is_none() {
            self.entry = Some(canon.clone());
            self.targets = doc.targets.clone();
            self.recipe_env = doc.env.clone();
        } else if doc.targets.is_some() {
            // Execution targets belong to the recipe that is run, never to a
            // fragment pulled in by `include` (no implicit merging).
            return Err(SinterError::schema(format!(
                "{}: targets may only be declared in the top-level recipe, not in an included file",
                canon.display()
            )));
        } else if doc.env.is_some() {
            // The recipe-wide default environment belongs to the recipe that
            // is run; an included fragment may not add or override it.
            return Err(SinterError::schema(format!(
                "{}: env may only be declared in the top-level recipe, not in an included file",
                canon.display()
            )));
        }
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
    // Then the declaring document's own backups, variables, resources,
    // handlers.
    for p in &doc.backup_paths {
        if let Some((_, first)) = state.backups.iter().find(|(q, _)| q == p) {
            return Err(SinterError::schema(format!(
                "duplicate backup path {} (declared in {} and {})",
                p,
                first,
                canon.display()
            )));
        }
        state.backups.push((p.clone(), canon.display().to_string()));
    }
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

/// The internal marker a `{{ staged }}` placeholder of `validate.args` is
/// lowered to (COM-07). NUL can never occur in a recipe-supplied argument —
/// one is rejected before lowering, and NUL cannot cross an exec boundary —
/// so a NUL in a lowered argument is always, and only, this placeholder.
pub(crate) const STAGED_PLACEHOLDER_MARK: char = '\0';

/// The length of a `{{ staged }}` placeholder (`{{`, optional blanks,
/// `staged`, optional blanks, `}}`) starting at `chars[i]`, if one does.
fn staged_placeholder_len(chars: &[char], i: usize) -> Option<usize> {
    if chars.get(i) != Some(&'{') || chars.get(i + 1) != Some(&'{') {
        return None;
    }
    let mut j = i + 2;
    while matches!(chars.get(j), Some(' ' | '\t')) {
        j += 1;
    }
    for c in "staged".chars() {
        if chars.get(j) != Some(&c) {
            return None;
        }
        j += 1;
    }
    while matches!(chars.get(j), Some(' ' | '\t')) {
        j += 1;
    }
    if chars.get(j) != Some(&'}') || chars.get(j + 1) != Some(&'}') {
        return None;
    }
    Some(j + 2 - i)
}

/// Replace every `{{ staged }}` placeholder in `s` with
/// [`STAGED_PLACEHOLDER_MARK`]. An escaped `\{{` is copied unchanged (it stays
/// literal text for the interpolation that follows). Returns the lowered
/// string and the number of placeholders.
fn lower_staged_placeholders(s: &str) -> (String, usize) {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut n = 0;
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && chars.get(i + 1) == Some(&'{') && chars.get(i + 2) == Some(&'{') {
            out.push_str("\\{{");
            i += 3;
            continue;
        }
        if let Some(len) = staged_placeholder_len(&chars, i) {
            out.push(STAGED_PLACEHOLDER_MARK);
            n += 1;
            i += len;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    (out, n)
}

/// COM-07: lower the `{{ staged }}` placeholders of a `file`/`template`
/// `validate.args` list to the internal marker, so the argument that carries
/// the staged path is fixed at load time and every later interpolation scan
/// sees only ordinary expressions. A NUL already present in an argument is
/// rejected first (it would otherwise be indistinguishable from the marker),
/// and a placeholder anywhere else in the `validate` map is rejected: only an
/// argument can name the staged file.
fn lower_validate_placeholders(
    type_: &str,
    with: &BTreeMap<String, Value>,
    ctx: &str,
) -> Result<BTreeMap<String, Value>> {
    if type_ != "file" && type_ != "template" {
        return Ok(with.clone());
    }
    let Some(Value::Map(spec)) = with.get("validate") else {
        return Ok(with.clone());
    };
    let mut spec = spec.clone();
    for (k, v) in spec.iter() {
        if k == "args" {
            continue;
        }
        if let Value::Str(s) = v {
            if lower_staged_placeholders(s).1 > 0 {
                return Err(SinterError::schema(format!(
                    "{}: validate.{} may not contain the {{{{ staged }}}} placeholder; only \
                     validate.args can name the staged file",
                    ctx, k
                )));
            }
        }
    }
    if let Some(Value::List(items)) = spec.get("args") {
        let mut lowered = Vec::with_capacity(items.len());
        for item in items {
            match item {
                Value::Str(s) => {
                    if crate::value::has_nul(s) {
                        return Err(SinterError::schema(format!(
                            "{}: validate.args may not contain NUL",
                            ctx
                        )));
                    }
                    lowered.push(Value::Str(lower_staged_placeholders(s).0));
                }
                other => lowered.push(other.clone()),
            }
        }
        spec.insert("args".to_string(), Value::List(lowered));
    }
    let mut out = with.clone();
    out.insert("validate".to_string(), Value::Map(spec));
    Ok(out)
}

fn expand_resource(canon: &Path, decl: &ResourceDecl, state: &mut LoadState) -> Result<()> {
    let _ = canon;
    // COM-07: `{{ staged }}` in validate.args is lowered before anything scans
    // the declaration's interpolations.
    let lowered_with = lower_validate_placeholders(&decl.type_, &decl.with, &decl.id)?;
    let decl_with = &lowered_with;
    // Collect register references from `when` and interpolated `with` values at
    // declaration time. This runs even when the loop is empty, so a forbidden
    // reference can never escape validation merely because no instance exists.
    // Sensitivity uses the global pre-pass set so redaction does not depend on
    // include ordering.
    let sensitive_var_names: BTreeSet<String> = state.global_sensitive_vars.clone();
    let mut register_refs: BTreeSet<String> = BTreeSet::new();
    if let Some(w) = &decl.when {
        let when_sensitive =
            decl.sensitive || value_may_be_sensitive(&Value::Str(w.clone()), &sensitive_var_names);
        let expr = parse_expr(w).map_err(|e| {
            if when_sensitive {
                SinterError::schema(format!(
                    "{}: invalid when expression (value redacted): {}",
                    decl.id,
                    e.category()
                ))
            } else {
                SinterError::schema(format!("{}: invalid when expression: {}", decl.id, e))
            }
        })?;
        let mut names = BTreeSet::new();
        collect_register_refs(&expr, &mut register_refs, &mut names);
    }
    for v in decl_with.values() {
        collect_value_register_refs(v, &mut register_refs, decl.sensitive, &sensitive_var_names)?;
    }

    match &decl.loop_values {
        None => {
            state.resources.push(RawResource {
                id: decl.id.clone(),
                type_: decl.type_.clone(),
                with: decl_with.clone(),
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
                with: decl_with.clone(),
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
                    with: decl_with.clone(),
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
                with: decl_with.clone(),
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
    // Whether diagnostics about a `with` field must be redacted: sensitive
    // resources redact everything; otherwise a field that references (or
    // textually names, in unparseable form) a sensitive variable is treated
    // as sensitive so its contents never reach diagnostics.
    let field_sensitive = |key: &str| {
        d.sensitive
            || d.with
                .get(key)
                .is_some_and(|v| value_may_be_sensitive(v, sensitive_var_names))
    };
    match d.type_.as_str() {
        "file" => {
            validate_with_fields(&d.with, FILE_FIELDS, ctx)?;
            validate_path_state(&d.with, "file", ctx)?;
            require_static_string_field(&d.with, "path", ctx, field_sensitive("path"))?;
            require_optional_static_string(&d.with, "source", ctx, field_sensitive("source"))?;
            require_optional_mode(
                &d.with,
                ctx,
                d.sensitive
                    || d.with
                        .get("mode")
                        .is_some_and(|v| value_references_sensitive_var(v, sensitive_var_names)),
            )?;
            require_content_type(&d.with, ctx)?;
            if let Some(v) = d.with.get("validate") {
                validate_validate_spec(v, ctx)?;
            }
        }
        "directory" => {
            validate_with_fields(&d.with, DIR_FIELDS, ctx)?;
            validate_path_state(&d.with, "directory", ctx)?;
            require_static_string_field(&d.with, "path", ctx, field_sensitive("path"))?;
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
            require_static_string_field(&d.with, "path", ctx, field_sensitive("path"))?;
            require_optional_static_string(&d.with, "target", ctx, field_sensitive("target"))?;
            validate_path_state(&d.with, "link", ctx)?;
            // Execution requires `target` unless `state` is `absent`
            // (`run_link`). Enforce it here whenever the state is statically
            // known; an interpolated state is still checked when evaluated.
            let state_present = match d.with.get("state") {
                None | Some(Value::Null) => true,
                Some(Value::Str(s)) if !crate::expressions::has_interpolation(s) => s != "absent",
                Some(_) => false,
            };
            if state_present && matches!(d.with.get("target"), None | Some(Value::Null)) {
                return Err(SinterError::schema(format!(
                    "{}: link target is required when present",
                    ctx
                )));
            }
        }
        "template" => {
            if d.with.contains_key("content") {
                return Err(SinterError::schema(format!(
                    "{}: template does not support content; use source",
                    ctx
                )));
            }
            validate_with_fields(&d.with, TEMPLATE_FIELDS, ctx)?;
            validate_path_state(&d.with, "template", ctx)?;
            require_static_string_field(&d.with, "path", ctx, field_sensitive("path"))?;
            require_static_string_field(&d.with, "source", ctx, field_sensitive("source"))?;
            require_optional_mode(
                &d.with,
                ctx,
                d.sensitive
                    || d.with
                        .get("mode")
                        .is_some_and(|v| value_references_sensitive_var(v, sensitive_var_names)),
            )?;
            if let Some(v) = d.with.get("validate") {
                validate_validate_spec(v, ctx)?;
            }
        }
        "command" => {
            validate_with_fields(&d.with, COMMAND_FIELDS, ctx)?;
            require_static_string_field(&d.with, "program", ctx, field_sensitive("program"))?;
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
            if let Some(v) = d.with.get("env") {
                validate_env_map(v, ctx)?;
            }
            require_static_string_field(&d.with, "name", ctx, field_sensitive("name"))?;
            if let Some(Value::Str(s)) = d.with.get("name") {
                // Literal names are validated here; interpolated names are
                // resolved and validated again at freeze time. A rejected
                // name never appears raw when the resource is sensitive or
                // the name derives from a sensitive variable.
                if !crate::expressions::has_interpolation(s) {
                    validate_package_name(s, ctx, field_sensitive("name"))?;
                }
            }
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
            require_static_string_field(&d.with, "name", ctx, field_sensitive("name"))?;
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
                if e.as_bool().is_none()
                    && !matches!(e, Value::Str(s) if crate::expressions::has_interpolation(s))
                {
                    return Err(SinterError::schema(format!(
                        "{}: service enabled must be a boolean",
                        ctx
                    )));
                }
            }
        }
        "postgresql_role" => {
            validate_with_fields(&d.with, crate::pgrole::PGROLE_FIELDS, ctx)?;
            require_static_string_field(&d.with, "name", ctx, field_sensitive("name"))?;
            if let Some(Value::Str(s)) = d.with.get("name") {
                if !crate::expressions::has_interpolation(s) && !crate::pgrole::valid_role_name(s) {
                    return Err(SinterError::schema(format!(
                        "{}: postgresql_role name {} is not a valid role name ([a-z_][a-z0-9_]*, \
                         at most 63 bytes, not pg_*)",
                        ctx,
                        if field_sensitive("name") {
                            "(value redacted)".to_string()
                        } else {
                            format!("{:?}", s)
                        }
                    )));
                }
            }
            crate::pgrole::validate_literals(&d.with, ctx)?;
        }
        "group" | "user" => {
            let kind = d.type_.as_str();
            validate_with_fields(
                &d.with,
                if kind == "group" {
                    GROUP_FIELDS
                } else {
                    USER_FIELDS
                },
                ctx,
            )?;
            require_static_string_field(&d.with, "name", ctx, field_sensitive("name"))?;
            if let Some(Value::Str(s)) = d.with.get("name") {
                if !crate::expressions::has_interpolation(s)
                    && !crate::accounts::valid_account_name(s)
                {
                    return Err(SinterError::schema(format!(
                        "{}: {} name {} is not a valid account name",
                        ctx,
                        kind,
                        if field_sensitive("name") {
                            "(value redacted)".to_string()
                        } else {
                            format!("{:?}", s)
                        }
                    )));
                }
            }
            if d.with.contains_key("state") {
                validate_desired_enum(
                    &d.with,
                    "state",
                    &["present", "absent"],
                    ctx,
                    &format!("{} state must be present or absent", kind),
                )?;
            }
            crate::accounts::validate_account_literals(
                kind,
                &d.with,
                ctx,
                d.sensitive || field_sensitive("name"),
            )?;
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

fn require_static_string_field(
    with: &BTreeMap<String, Value>,
    key: &str,
    ctx: &str,
    sensitive: bool,
) -> Result<()> {
    match with.get(key) {
        Some(Value::Str(s)) => {
            if s.is_empty() {
                return Err(SinterError::schema(format!(
                    "{}: {} must not be empty",
                    ctx, key
                )));
            }
            require_static_identifier_string(s, key, ctx, sensitive)
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

/// Validate a resolved package name. Names are passed verbatim as argv to
/// the platform package manager. Exact argv means no shell injection is
/// possible, but a name that begins with '-' is still option injection and
/// rpm treats '*', '?', and '[' as glob metacharacters. The accepted charset
/// is a conservative superset of real Debian/RPM package names. When the
/// resource (or the name itself) is sensitive the rejected value is never
/// echoed into diagnostics.
fn validate_package_name(name: &str, ctx: &str, sensitive: bool) -> Result<()> {
    let valid = name
        .chars()
        .next()
        .map(|c| c.is_ascii_alphanumeric())
        .unwrap_or(false)
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~'));
    if !valid {
        return Err(SinterError::schema(if sensitive {
            format!("{}: invalid package name (value redacted)", ctx)
        } else {
            format!("{}: invalid package name {:?}", ctx, name)
        }));
    }
    Ok(())
}

/// `state` of file, directory, link and template: omitted or null means
/// present; an interpolated value is checked against the same domain when
/// the resource runs.
fn validate_path_state(with: &BTreeMap<String, Value>, kind: &str, ctx: &str) -> Result<()> {
    match with.get("state") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Str(s))
            if crate::expressions::has_interpolation(s) || s == "present" || s == "absent" =>
        {
            Ok(())
        }
        Some(_) => Err(SinterError::schema(format!(
            "{}: {} state must be present or absent",
            ctx, kind
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
    sensitive: bool,
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
            require_static_identifier_string(s, key, ctx, sensitive)
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
fn require_static_identifier_string(s: &str, key: &str, ctx: &str, sensitive: bool) -> Result<()> {
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
            if sensitive {
                SinterError::schema(format!(
                    "{}: {} has invalid interpolation (value redacted): {}",
                    ctx,
                    key,
                    e.category()
                ))
            } else {
                SinterError::schema(format!("{}: {} has invalid interpolation: {}", ctx, key, e))
            }
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

/// Conservative sensitivity check for diagnostics: true when the value
/// structurally references a sensitive variable OR its raw text names one
/// (`vars.<name>`). The textual fallback covers interpolations that fail to
/// parse — their token contents still name a sensitive source and must not
/// be echoed into diagnostics.
fn value_may_be_sensitive(v: &Value, sensitive_vars: &BTreeSet<String>) -> bool {
    match v {
        Value::Str(s) => {
            sensitive_vars
                .iter()
                .any(|n| s.contains(&format!("vars.{n}")))
                || value_references_sensitive_var(v, sensitive_vars)
        }
        Value::List(items) => items
            .iter()
            .any(|i| value_may_be_sensitive(i, sensitive_vars)),
        Value::Map(m) => m
            .values()
            .any(|i| value_may_be_sensitive(i, sensitive_vars)),
        _ => false,
    }
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
        // `{ secret: <path> }`: only the shape is checked here; the reference
        // itself is resolved when the model is frozen.
        Some(Value::Map(_)) => crate::secret_source::content_shape(&with["content"])
            .map(|_| ())
            .map_err(|what| SinterError::schema(format!("{}: {}", ctx, what))),
        Some(_) => Err(SinterError::schema(format!(
            "{}: content must be a string or {{ secret: <path> }}",
            ctx
        ))),
    }
}

/// Apply the recipe-wide default `env` to a resource's `with`.
///
/// Only `package` and `command` resources run an external process Sinter gives
/// an environment to, so only they inherit it (DESIGN §27.1). A name the
/// resource sets explicitly overrides the recipe default; the default is never
/// merged into an unrelated resource type, and never passed to a service,
/// package query, or connection step. The merged map is an ordinary `env`
/// value, so interpolation and sensitivity behave exactly as if the resource
/// had written it.
fn merge_recipe_env(
    type_: &str,
    with: &BTreeMap<String, Value>,
    recipe: &Value,
) -> BTreeMap<String, Value> {
    if type_ != "package" && type_ != "command" {
        return with.clone();
    }
    let Some(defaults) = recipe.as_map() else {
        return with.clone();
    };
    if defaults.is_empty() {
        return with.clone();
    }
    let mut merged: BTreeMap<String, Value> = defaults.clone();
    if let Some(Value::Map(own)) = with.get("env") {
        for (k, v) in own {
            merged.insert(k.clone(), v.clone());
        }
    }
    let mut out = with.clone();
    out.insert("env".to_string(), Value::Map(merged));
    out
}

fn freeze(state: LoadState, entry: &Path, overrides: &VarOverrides) -> Result<Model> {
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
    // The scope of a structure-only probe (see [`Tolerance`]); built for no
    // other freeze.
    let probe_vars: BTreeMap<String, EvalVal> = if overrides.structure_only {
        state
            .vars
            .iter()
            .map(|v| {
                let val = if v.sensitive {
                    EvalVal::known_sensitive(v.value.clone())
                } else {
                    EvalVal::known(neutral_value(&v.value))
                };
                (v.name.clone(), val)
            })
            .collect()
    } else {
        BTreeMap::new()
    };

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
    let mut account_name_owner: BTreeMap<(String, String), String> = BTreeMap::new();
    // Recipe-wide default environment, applied to `package`/`command`
    // resources as a base their own `env` overrides (DESIGN §27.1).
    let recipe_env = state.recipe_env.clone().unwrap_or(Value::Null);

    // Fields referencing an overridden variable, per frozen resource (the
    // other side of an ownership conflict). Empty without a variables file.
    let mut peer_refs: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for r in &state.resources {
        let refs = override_refs(&r.with, overrides);
        let mut stage = Stage::Unattributed;
        // Every early return of this resource's checks leaves the closure and
        // passes the one boundary below (DESIGN §19.5).
        #[allow(clippy::redundant_closure_call)]
        let checked: Result<FrozenResource> = (|| {
            // Dependency / notify reference validation.
            staged(&mut stage, Stage::ValueFree, || {
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
                Ok(())
            })?;

            let item_eval = r.loop_item.as_ref().map(|v| EvalVal::known(v.clone()));
            let scope = Scope {
                vars: Some(&static_vars),
                facts: None,
                registers: None,
                item: item_eval.as_ref(),
                result: None,
                template: None,
            };
            let tol = Tolerance {
                on: overrides.structure_only,
                refs: &refs,
                probe_vars: &probe_vars,
                item: item_eval.as_ref(),
                with: &r.with,
                ctx: &r.id,
            };

            // Validate `when` parses and gather register references. Sensitive
            // conditions/resources keep token contents out of diagnostics. Only
            // the written text is checked here; no value is evaluated.
            staged(&mut stage, Stage::ValueFree, || {
                let mut expr_register_refs: BTreeSet<String> = BTreeSet::new();
                let mut scratch_names = BTreeSet::new();
                if let Some(w) = &r.when {
                    let when_sensitive = r.sensitive
                        || value_may_be_sensitive(&Value::Str(w.clone()), &sensitive_var_names);
                    let expr = parse_expr(w).map_err(|e| {
                        if when_sensitive {
                            SinterError::schema(format!(
                                "{}: invalid when expression (value redacted): {}",
                                r.id,
                                e.category()
                            ))
                        } else {
                            SinterError::schema(format!("{}: invalid when expression: {}", r.id, e))
                        }
                    })?;
                    collect_register_refs(&expr, &mut expr_register_refs, &mut scratch_names);
                }
                // Gather register references from interpolated `with` values.
                for v in r.with.values() {
                    collect_value_register_refs(
                        v,
                        &mut expr_register_refs,
                        r.sensitive,
                        &sensitive_var_names,
                    )?;
                }
                for reg in &expr_register_refs {
                    let producer = register_producers.get(reg).ok_or_else(|| {
                        SinterError::schema(format!(
                            "{}: references unknown register {}",
                            r.id, reg
                        ))
                    })?;
                    if !r.depends_on.contains(producer) {
                        return Err(SinterError::schema(format!(
                            "{}: register {} must be listed directly in depends_on",
                            r.id, reg
                        )));
                    }
                }
                Ok(())
            })?;

            let mut fr = FrozenResource {
                id: r.id.clone(),
                type_: r.type_.clone(),
                with: merge_recipe_env(&r.type_, &r.with, &recipe_env),
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
                account_name: None,
                controller_source: None,
                secret: None,
                register: r
                    .with
                    .get("register")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            };

            let resource_ctx = r.id.clone();
            // Whether diagnostics about a `with` field must be redacted for this
            // resource (explicit sensitivity or a reference to a sensitive
            // variable — including unparseable text that still names one).
            let field_sensitive = |key: &str| {
                r.sensitive
                    || r.with
                        .get(key)
                        .is_some_and(|v| value_may_be_sensitive(v, &sensitive_var_names))
            };
            match r.type_.as_str() {
                "file" => {
                    staged(&mut stage, Stage::ValueFree, || {
                        validate_with_fields(&r.with, FILE_FIELDS, &resource_ctx)?;
                        if let Some(v) = r.with.get("validate") {
                            validate_validate_spec(v, &resource_ctx)?;
                        }
                        Ok(())
                    })?;
                    let path = staged_field(&mut stage, &tol, "path", || {
                        let path = static_string(
                            &r.with,
                            "path",
                            &scope,
                            &resource_ctx,
                            true,
                            field_sensitive("path"),
                        )?;
                        validate_path(&path).map_err(|e| {
                            SinterError::schema(format!("{}: {}", resource_ctx, e.message))
                        })?;
                        Ok(path)
                    })?;
                    fr.path = path;
                    validate_file_common(
                        &r.with,
                        &scope,
                        &resource_ctx,
                        &mut fr,
                        &sensitive_var_names,
                        &mut stage,
                        &tol,
                    )?;
                    // `content: { secret: <path> }`: resolve and confine the
                    // reference (a static literal). Nothing is decrypted while
                    // loading.
                    if let Some(content) = r.with.get("content") {
                        if let Ok(crate::secret_source::ContentShape::Secret(reference)) =
                            crate::secret_source::content_shape(content)
                        {
                            fr.secret = Some(staged(&mut stage, Stage::ValueFree, || {
                                crate::secret_source::resolve_reference_with(
                                    state.refs,
                                    &r.origin,
                                    reference,
                                    &resource_ctx,
                                    r.sensitive,
                                )
                            })?);
                        }
                    }
                }
                "directory" => {
                    staged(&mut stage, Stage::ValueFree, || {
                        validate_with_fields(&r.with, DIR_FIELDS, &resource_ctx)
                    })?;
                    let path = staged_field(&mut stage, &tol, "path", || {
                        let path = static_string(
                            &r.with,
                            "path",
                            &scope,
                            &resource_ctx,
                            true,
                            field_sensitive("path"),
                        )?;
                        validate_path(&path).map_err(|e| {
                            SinterError::schema(format!("{}: {}", resource_ctx, e.message))
                        })?;
                        Ok(path)
                    })?;
                    fr.path = path;
                }
                "link" => {
                    staged(&mut stage, Stage::ValueFree, || {
                        validate_with_fields(&r.with, LINK_FIELDS, &resource_ctx)
                    })?;
                    let path = staged_field(&mut stage, &tol, "path", || {
                        let path = static_string(
                            &r.with,
                            "path",
                            &scope,
                            &resource_ctx,
                            true,
                            field_sensitive("path"),
                        )?;
                        validate_path(&path).map_err(|e| {
                            SinterError::schema(format!("{}: {}", resource_ctx, e.message))
                        })?;
                        Ok(path)
                    })?;
                    fr.path = path;
                }
                "template" => {
                    staged(&mut stage, Stage::ValueFree, || {
                        if r.with.contains_key("content") {
                            return Err(SinterError::schema(format!(
                                "{}: template does not support content; use source",
                                resource_ctx
                            )));
                        }
                        validate_with_fields(&r.with, TEMPLATE_FIELDS, &resource_ctx)?;
                        if let Some(v) = r.with.get("validate") {
                            validate_validate_spec(v, &resource_ctx)?;
                        }
                        Ok(())
                    })?;
                    let path = staged_field(&mut stage, &tol, "path", || {
                        let path = static_string(
                            &r.with,
                            "path",
                            &scope,
                            &resource_ctx,
                            true,
                            field_sensitive("path"),
                        )?;
                        validate_path(&path).map_err(|e| {
                            SinterError::schema(format!("{}: {}", resource_ctx, e.message))
                        })?;
                        Ok(path)
                    })?;
                    fr.path = path;
                    let controller_source = staged_field(&mut stage, &tol, "source", || {
                        let source = static_string(
                            &r.with,
                            "source",
                            &scope,
                            &resource_ctx,
                            true,
                            field_sensitive("source"),
                        )?;
                        let source_sensitive = r.sensitive
                            || value_references_sensitive_var(
                                &r.with["source"],
                                &sensitive_var_names,
                            );
                        resolve_source(&r.origin, &source).map_err(|e| {
                            if source_sensitive {
                                SinterError::schema(format!(
                                    "{}: source validation failed (value redacted)",
                                    resource_ctx
                                ))
                            } else {
                                e
                            }
                        })
                    })?;
                    fr.controller_source = controller_source;
                    validate_file_common(
                        &r.with,
                        &scope,
                        &resource_ctx,
                        &mut fr,
                        &sensitive_var_names,
                        &mut stage,
                        &tol,
                    )?;
                }
                "command" => {
                    staged(&mut stage, Stage::ValueFree, || {
                        validate_with_fields(&r.with, COMMAND_FIELDS, &resource_ctx)
                    })?;
                    let program = staged_field(&mut stage, &tol, "program", || {
                        let program = static_string(
                            &r.with,
                            "program",
                            &scope,
                            &resource_ctx,
                            true,
                            field_sensitive("program"),
                        )?;
                        if !program.starts_with('/') {
                            return Err(SinterError::schema(format!(
                                "{}: program must be an absolute path",
                                resource_ctx
                            )));
                        }
                        Ok(program)
                    })?;
                    fr.program = program;
                    if let Some(v) = r.with.get("creates") {
                        if !v.is_null() {
                            let s = staged_field(&mut stage, &tol, "creates", || {
                                let s = static_string(
                                    &r.with,
                                    "creates",
                                    &scope,
                                    &resource_ctx,
                                    true,
                                    field_sensitive("creates"),
                                )?;
                                validate_path(&s).map_err(|e| {
                                    SinterError::schema(format!(
                                        "{}: creates: {}",
                                        resource_ctx, e.message
                                    ))
                                })?;
                                Ok(s)
                            })?;
                            fr.creates = s;
                        }
                    }
                    if let Some(v) = r.with.get("removes") {
                        if !v.is_null() {
                            let s = staged_field(&mut stage, &tol, "removes", || {
                                let s = static_string(
                                    &r.with,
                                    "removes",
                                    &scope,
                                    &resource_ctx,
                                    true,
                                    field_sensitive("removes"),
                                )?;
                                validate_path(&s).map_err(|e| {
                                    SinterError::schema(format!(
                                        "{}: removes: {}",
                                        resource_ctx, e.message
                                    ))
                                })?;
                                Ok(s)
                            })?;
                            fr.removes = s;
                        }
                    }
                    validate_command_fields(
                        &r.with,
                        &scope,
                        &resource_ctx,
                        &mut fr,
                        &sensitive_var_names,
                        &mut stage,
                        &tol,
                    )?;
                }
                "package" => {
                    staged(&mut stage, Stage::ValueFree, || {
                        validate_with_fields(&r.with, PACKAGE_FIELDS, &resource_ctx)?;
                        if let Some(v) = r.with.get("env") {
                            validate_env_map(v, &resource_ctx)?;
                        }
                        Ok(())
                    })?;
                    let name_sensitive = field_sensitive("name");
                    let name = staged_field(&mut stage, &tol, "name", || {
                        let name = static_string(
                            &r.with,
                            "name",
                            &scope,
                            &resource_ctx,
                            true,
                            name_sensitive,
                        )
                        .map_err(|e| {
                            if name_sensitive {
                                SinterError::schema(format!(
                            "{}: package name is not a statically-known string (value redacted)",
                            resource_ctx
                        ))
                            } else {
                                e
                            }
                        })?;
                        validate_package_name(&name, &resource_ctx, name_sensitive)?;
                        Ok(name)
                    })?;
                    fr.package_name = name;
                    staged(&mut stage, Stage::ValueFree, || {
                        validate_desired_enum(
                            &r.with,
                            "state",
                            &["present", "absent"],
                            &resource_ctx,
                            "package state is required and must be present or absent",
                        )
                    })?;
                }
                "service" => {
                    staged(&mut stage, Stage::ValueFree, || {
                        validate_with_fields(&r.with, SERVICE_FIELDS, &resource_ctx)
                    })?;
                    let name = staged_field(&mut stage, &tol, "name", || {
                        static_string(
                            &r.with,
                            "name",
                            &scope,
                            &resource_ctx,
                            true,
                            field_sensitive("name"),
                        )
                    })?;
                    fr.service_name = name;
                    staged(&mut stage, Stage::ValueFree, || {
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
                            if e.as_bool().is_none()
                                && !matches!(e, Value::Str(s) if crate::expressions::has_interpolation(s))
                            {
                                return Err(SinterError::schema(format!(
                                    "{}: service enabled must be a boolean",
                                    resource_ctx
                                )));
                            }
                        }
                        Ok(())
                    })?;
                }
                "postgresql_role" => {
                    staged(&mut stage, Stage::ValueFree, || {
                        validate_with_fields(&r.with, crate::pgrole::PGROLE_FIELDS, &resource_ctx)
                    })?;
                    let name_sensitive = field_sensitive("name");
                    let name = staged_field(&mut stage, &tol, "name", || {
                        let name = static_string(
                            &r.with,
                            "name",
                            &scope,
                            &resource_ctx,
                            true,
                            name_sensitive,
                        )?;
                        if !crate::pgrole::valid_role_name(&name) {
                            return Err(SinterError::schema(format!(
                                "{}: postgresql_role name {} is not a valid role name",
                                resource_ctx,
                                if name_sensitive {
                                    "(value redacted)".to_string()
                                } else {
                                    format!("{:?}", name)
                                }
                            )));
                        }
                        Ok(name)
                    })?;
                    staged(&mut stage, Stage::ValueFree, || {
                        crate::pgrole::validate_literals(&r.with, &resource_ctx)
                    })?;
                    // One resource per role of one server (port, when literal).
                    let port = r
                        .with
                        .get("port")
                        .and_then(|v| v.as_int())
                        .map(|p| p.to_string())
                        // An omitted port is the server default, 5432.
                        .unwrap_or_else(|| "5432".to_string());
                    if let Some(name) = &name {
                        if let Some(owner) = account_name_owner.insert(
                            ("postgresql_role".to_string(), format!("{}@{}", name, port)),
                            r.id.clone(),
                        ) {
                            // May depend on a variable: left unjudged, the
                            // other checks go on.
                            if !ownership_may_depend_on_values(&tol, &peer_refs, "name", &owner) {
                                stage = Stage::Ownership {
                                    field: "name",
                                    peer: owner.clone(),
                                };
                                return Err(SinterError::schema(format!(
                                    "conflicting ownership of PostgreSQL role {} by resources {} and {}",
                                    if name_sensitive {
                                        "(value redacted)"
                                    } else {
                                        name.as_str()
                                    },
                                    owner,
                                    r.id
                                )));
                            }
                        }
                    }
                    // `password_verifier: { secret: <path> }`: resolve and confine
                    // the reference. Nothing is decrypted while loading.
                    if let Some(pv) = r.with.get("password_verifier") {
                        if let Ok(crate::secret_source::ContentShape::Secret(reference)) =
                            crate::secret_source::content_shape(pv)
                        {
                            fr.secret = Some(staged(&mut stage, Stage::ValueFree, || {
                                crate::secret_source::resolve_reference_with(
                                    state.refs,
                                    &r.origin,
                                    reference,
                                    &resource_ctx,
                                    r.sensitive || name_sensitive,
                                )
                            })?);
                        }
                    }
                }
                "group" | "user" => {
                    let kind = r.type_.as_str();
                    staged(&mut stage, Stage::ValueFree, || {
                        validate_with_fields(
                            &r.with,
                            if kind == "group" {
                                GROUP_FIELDS
                            } else {
                                USER_FIELDS
                            },
                            &resource_ctx,
                        )
                    })?;
                    let name_sensitive = field_sensitive("name");
                    let name = staged_field(&mut stage, &tol, "name", || {
                        let name = static_string(
                            &r.with,
                            "name",
                            &scope,
                            &resource_ctx,
                            true,
                            name_sensitive,
                        )?;
                        if !crate::accounts::valid_account_name(&name) {
                            return Err(SinterError::schema(format!(
                                "{}: {} name {} is not a valid account name",
                                resource_ctx,
                                kind,
                                if name_sensitive {
                                    "(value redacted)".to_string()
                                } else {
                                    format!("{:?}", name)
                                }
                            )));
                        }
                        Ok(name)
                    })?;
                    if let Some(name) = &name {
                        if let Some(owner) = account_name_owner
                            .insert((kind.to_string(), name.clone()), r.id.clone())
                        {
                            // May depend on a variable: left unjudged, the
                            // other checks go on.
                            if !ownership_may_depend_on_values(&tol, &peer_refs, "name", &owner) {
                                stage = Stage::Ownership {
                                    field: "name",
                                    peer: owner.clone(),
                                };
                                return Err(SinterError::schema(format!(
                                    "conflicting ownership of {} {} by resources {} and {}",
                                    kind,
                                    if name_sensitive {
                                        "(value redacted)"
                                    } else {
                                        name.as_str()
                                    },
                                    owner,
                                    r.id
                                )));
                            }
                        }
                    }
                    fr.account_name = name;
                    staged(&mut stage, Stage::ValueFree, || {
                        if r.with.contains_key("state") {
                            validate_desired_enum(
                                &r.with,
                                "state",
                                &["present", "absent"],
                                &resource_ctx,
                                &format!("{} state must be present or absent", kind),
                            )?;
                        }
                        crate::accounts::validate_account_literals(
                            kind,
                            &r.with,
                            &resource_ctx,
                            r.sensitive || name_sensitive,
                        )
                    })?;
                    // `password_hash: { secret: <path> }`: resolve and confine the
                    // reference. Nothing is decrypted while loading.
                    if let Some(ph) = r.with.get("password_hash") {
                        if let Ok(crate::secret_source::ContentShape::Secret(reference)) =
                            crate::secret_source::content_shape(ph)
                        {
                            fr.secret = Some(staged(&mut stage, Stage::ValueFree, || {
                                crate::secret_source::resolve_reference_with(
                                    state.refs,
                                    &r.origin,
                                    reference,
                                    &resource_ctx,
                                    r.sensitive || name_sensitive,
                                )
                            })?);
                        }
                    }
                }
                other => {
                    stage = Stage::ValueFree;
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
                        // May depend on a variable: left unjudged, the other
                        // checks go on.
                        if !ownership_may_depend_on_values(&tol, &peer_refs, "path", &prev) {
                            stage = Stage::Ownership {
                                field: "path",
                                peer: prev.clone(),
                            };
                            return Err(SinterError::schema(format!(
                                "conflicting ownership of path {} by resources {} and {}",
                                p, prev, r.id
                            )));
                        }
                    }
                }
            }

            // Conservative static sensitivity used for early diagnostics. Computed
            // BEFORE template body validation so body-derived values are redacted
            // whenever sensitivity is explicit OR inherited from a sensitive
            // variable in a `with` field or in the `when` condition (DESIGN §31).
            // Iterate the FROZEN `with` (which already carries the merged
            // recipe-wide `env`), not the raw one: a default environment derived
            // from a sensitive variable must make the resource sensitive for early
            // diagnostics too.
            let mut derived_from_with = r.sensitive;
            for v in fr.with.values() {
                if value_references_sensitive_var(v, &sensitive_var_names) {
                    derived_from_with = true;
                }
            }
            // A `when` condition that references a sensitive variable makes the
            // whole resource's diagnostics sensitive: the raw expression tokens
            // must never surface, including from later runtime evaluation of the
            // condition itself.
            if let Some(w) = &r.when {
                if value_may_be_sensitive(&Value::Str(w.clone()), &sensitive_var_names) {
                    derived_from_with = true;
                }
            }
            let template_sensitive = r.sensitive || derived_from_with;

            // Template bodies can reference registers; those references require the
            // same direct-dependency validation as `with`/`when` interpolations.
            // Its messages name the template file, whose path is the `source`.
            stage = Stage::Field("source");
            if fr.type_ == "template" {
                if let Some(src) = &fr.controller_source {
                    let body = std::fs::read_to_string(src).map_err(|e| {
                        if template_sensitive {
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
                    if let Some(tag) = crate::expressions::unsupported_template_tag(&body) {
                        return Err(SinterError::schema(if template_sensitive {
                            format!("{}: template: {}", resource_ctx, tag.describe())
                        } else {
                            format!(
                                "{}: template {}: {}",
                                resource_ctx,
                                src.display(),
                                tag.describe()
                            )
                        }));
                    }
                    let mut body_regs: BTreeSet<String> = BTreeSet::new();
                    for tok in extract_interpolation_exprs(&body) {
                        let expr = parse_expr(&tok).map_err(|e| {
                            // DESIGN §31: body-derived fragments (including numeric
                            // literals) are sensitive when the resource is sensitive
                            // explicitly or through derived sensitivity.
                            if template_sensitive {
                                SinterError::schema(format!(
                                    "{}: invalid template interpolation (value redacted): {}",
                                    resource_ctx,
                                    e.category()
                                ))
                            } else {
                                SinterError::schema(format!(
                                    "{}: invalid template interpolation: {}",
                                    resource_ctx, e
                                ))
                            }
                        })?;
                        let mut names = BTreeSet::new();
                        collect_register_refs(&expr, &mut body_regs, &mut names);
                    }
                    for reg in &body_regs {
                        let producer = register_producers.get(reg).ok_or_else(|| {
                            if template_sensitive {
                                SinterError::schema(format!(
                                    "{}: template references unknown register (value redacted)",
                                    resource_ctx
                                ))
                            } else {
                                SinterError::schema(format!(
                                    "{}: template references unknown register {}",
                                    resource_ctx, reg
                                ))
                            }
                        })?;
                        if !r.depends_on.contains(producer) {
                            return Err(if template_sensitive {
                                SinterError::schema(format!(
                                "{}: template register must be listed directly in depends_on (value redacted)",
                                resource_ctx
                            ))
                            } else {
                                SinterError::schema(format!(
                                "{}: template register {} must be listed directly in depends_on",
                                resource_ctx, reg
                            ))
                            });
                        }
                    }
                }
            }

            // Full conservative static sensitivity: explicit flag, any sensitive
            // variable referenced by interpolated fields, or a sensitive variable in
            // a template body.
            let mut derived = derived_from_with;
            // A resource that holds a secret is sensitive whatever it declares.
            if fr.secret.is_some() {
                derived = true;
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
            Ok(fr)
        })();
        match checked {
            Ok(fr) => frozen.push(fr),
            Err(e) if overrides.is_empty() => return Err(e),
            Err(e) => {
                let original = e.message.clone();
                let e = withhold_override_values(r, &stage, &refs, &peer_refs, overrides, e);
                // A structure check does not judge what a variable holds: a
                // failure the boundary withheld is left out, any other stays.
                if !(overrides.structure_only && e.message != original) {
                    return Err(e);
                }
            }
        }
        peer_refs.insert(r.id.clone(), refs);
    }

    // Static loop input must be statically known: already guaranteed by IR being
    // literal values (facts/registers cannot form loop input).
    let _ = entry;

    // Dependency graph must be acyclic. Detect it during static validation.
    if overrides.structure_only {
        // A resource whose check was left out at the boundary above has no
        // frozen form: walk the declared graph instead (the same ids and
        // edges).
        let declared: Vec<(&str, &[String])> = state
            .resources
            .iter()
            .map(|r| (r.id.as_str(), r.depends_on.as_slice()))
            .collect();
        detect_dependency_cycle(&declared)?;
    } else {
        let edges: Vec<(&str, &[String])> = frozen
            .iter()
            .map(|r| (r.id.as_str(), r.depends_on.as_slice()))
            .collect();
        detect_dependency_cycle(&edges)?;
    }

    // R-3: `template.vars` values are passed to the template as written; a
    // `{{ ... }}` inside one is not evaluated and would be rendered literally.
    let mut warnings = Vec::new();
    for fr in &frozen {
        if fr.type_ != "template" {
            continue;
        }
        if let Some(Value::Map(m)) = fr.with.get("vars") {
            for (k, v) in m {
                if value_has_interpolation(v) {
                    warnings.push(format!(
                        "{}: template vars value {} contains {{{{ ... }}}}; template vars are not \
                         interpolated and the text would be rendered literally — reference \
                         vars.* or facts.* in the template body instead",
                        fr.id,
                        if fr.sensitive || fr.derived_sensitive {
                            "(name redacted)".to_string()
                        } else {
                            format!("{:?}", k)
                        }
                    ));
                }
            }
        }
    }

    Ok(Model {
        vars,
        resources: frozen,
        handlers: state.handlers,
        handler_index,
        register_producers,
        backups: state.backups.into_iter().map(|(p, _)| p).collect(),
        targets: state.targets,
        warnings,
    })
}

/// Whether a value (or any string nested in it) carries `{{ ... }}`.
fn value_has_interpolation(v: &Value) -> bool {
    match v {
        Value::Str(s) => crate::expressions::has_interpolation(s),
        Value::List(items) => items.iter().any(value_has_interpolation),
        Value::Map(m) => m.values().any(value_has_interpolation),
        _ => false,
    }
}

fn detect_dependency_cycle(resources: &[(&str, &[String])]) -> Result<()> {
    let index: BTreeMap<&str, usize> = resources
        .iter()
        .enumerate()
        .map(|(i, (id, _))| (*id, i))
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
        resources: &[(&str, &[String])],
        index: &BTreeMap<&str, usize>,
        marks: &mut Vec<Mark>,
    ) -> Result<()> {
        marks[i] = Mark::Gray;
        for d in resources[i].1 {
            let di = *index.get(d.as_str()).ok_or_else(|| {
                SinterError::schema(format!("{}: unknown dependency {}", resources[i].0, d))
            })?;
            match marks[di] {
                Mark::Gray => {
                    return Err(SinterError::schema(format!(
                        "dependency cycle detected involving {}",
                        resources[di].0
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

fn collect_value_register_refs(
    v: &Value,
    out: &mut BTreeSet<String>,
    decl_sensitive: bool,
    sensitive_vars: &BTreeSet<String>,
) -> Result<()> {
    match v {
        Value::Str(s) => {
            if crate::expressions::has_interpolation(s) {
                // Parse tokens to find registers. When the value is sensitive
                // (sensitive resource or derived from a sensitive variable)
                // the token contents may carry secrets; parser errors are
                // reduced to their safe category instead of echoing input.
                let sensitive = decl_sensitive || value_may_be_sensitive(v, sensitive_vars);
                for tok in extract_interpolation_exprs(s) {
                    let expr = parse_expr(&tok).map_err(|e| {
                        if sensitive {
                            SinterError::schema(format!(
                                "invalid interpolation expression (value redacted): {}",
                                e.category()
                            ))
                        } else {
                            SinterError::schema(format!("invalid interpolation expression: {}", e))
                        }
                    })?;
                    let mut names = BTreeSet::new();
                    collect_register_refs(&expr, out, &mut names);
                }
            }
        }
        Value::List(items) => {
            for i in items {
                collect_value_register_refs(i, out, decl_sensitive, sensitive_vars)?;
            }
        }
        Value::Map(m) => {
            for i in m.values() {
                collect_value_register_refs(i, out, decl_sensitive, sensitive_vars)?;
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
    sensitive_vars: &BTreeSet<String>,
    stage: &mut Stage,
    tol: &Tolerance,
) -> Result<()> {
    // Literal checks only: the written mode/owner/group text is checked, no
    // variable value is evaluated.
    staged(stage, Stage::ValueFree, || {
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
        Ok(())
    })?;
    // Validate that `source` is static when present.
    if with.get("source").is_some() {
        let sens = fr.sensitive || value_may_be_sensitive(&with["source"], sensitive_vars);
        staged_field(stage, tol, "source", || {
            static_string(with, "source", scope, ctx, true, sens)
        })?;
    }
    Ok(())
}

fn validate_command_fields(
    with: &BTreeMap<String, Value>,
    scope: &Scope,
    ctx: &str,
    fr: &mut FrozenResource,
    sensitive_vars: &BTreeSet<String>,
    stage: &mut Stage,
    tol: &Tolerance,
) -> Result<()> {
    // Literal checks only: the written args, numbers and changed_when text.
    staged(stage, Stage::ValueFree, || {
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
                        // A changed_when expression is sensitive when the resource
                        // is sensitive or the expression references (or textually
                        // names) a sensitive variable: its tokens must never reach
                        // diagnostics on any parse/validation path.
                        let cw_sensitive = fr.sensitive
                            || value_may_be_sensitive(&Value::Str(s.to_string()), sensitive_vars);
                        let expr = parse_expr(s).map_err(|e| {
                            if cw_sensitive {
                                SinterError::schema(format!(
                                    "{}: invalid changed_when (value redacted): {}",
                                    ctx,
                                    e.category()
                                ))
                            } else {
                                SinterError::schema(format!("{}: invalid changed_when: {}", ctx, e))
                            }
                        })?;
                        validate_changed_when(&expr, ctx, cw_sensitive)?;
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
        // Written presence, not the frozen values: a structure-only check may
        // have left one of them unjudged.
        let written = |k: &str| with.get(k).is_some_and(|v| !v.is_null());
        if written("creates") && written("removes") {
            return Err(SinterError::schema(format!(
                "{}: creates and removes are mutually exclusive",
                ctx
            )));
        }
        Ok(())
    })?;
    // Validate cwd statically if present (must be an absolute path, no facts
    // permitted for the identifier, no sensitive).
    if let Some(v) = with.get("cwd") {
        if !v.is_null() {
            let sens = fr.sensitive || value_may_be_sensitive(v, sensitive_vars);
            staged_field(stage, tol, "cwd", || {
                let s = static_string(with, "cwd", scope, ctx, true, sens)?;
                validate_path(&s)
                    .map_err(|e| SinterError::schema(format!("{}: cwd: {}", ctx, e.message)))
            })?;
        }
    }
    // env: keys must be strings, reserved names rejected.
    staged(stage, Stage::ValueFree, || {
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
    })
}

pub(crate) const RESERVED_ENV: &[&str] = &["PATH", "LANG", "LC_ALL", "HOME"];

fn validate_env_map(value: &Value, ctx: &str) -> Result<()> {
    match value {
        Value::Null => Ok(()),
        Value::Map(m) => {
            for (key, val) in m {
                let mut chars = key.chars();
                let valid = chars
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
                if !valid {
                    return Err(SinterError::schema(format!(
                        "{}: invalid environment variable name {:?}",
                        ctx, key
                    )));
                }
                if RESERVED_ENV.contains(&key.as_str()) {
                    return Err(SinterError::schema(format!(
                        "{}: env name {} is reserved by the command baseline",
                        ctx, key
                    )));
                }
                if !matches!(val, Value::Str(_)) {
                    return Err(SinterError::schema(format!(
                        "{}: env values must be strings",
                        ctx
                    )));
                }
            }
            Ok(())
        }
        _ => Err(SinterError::schema(format!(
            "{}: env must be a map of strings",
            ctx
        ))),
    }
}

/// Allowed keys of a `file`/`template` `validate` map.
const VALIDATE_FIELDS: &[&str] = &["program", "args", "timeout_seconds"];

/// Validate the optional `validate` map of a `file`/`template` resource. It
/// names a command run against the *staged* file before it is published
/// (DESIGN §24.4). The shape is checked here; the command itself is only
/// resolved and run at apply time.
fn validate_validate_spec(value: &Value, ctx: &str) -> Result<()> {
    match value {
        Value::Null => Ok(()),
        Value::Map(m) => {
            for k in m.keys() {
                if !VALIDATE_FIELDS.contains(&k.as_str()) {
                    return Err(SinterError::schema(format!(
                        "{}: validate has no field {}",
                        ctx, k
                    )));
                }
            }
            match m.get("program") {
                Some(Value::Str(p)) => {
                    if p.is_empty() {
                        return Err(SinterError::schema(format!(
                            "{}: validate.program must not be empty",
                            ctx
                        )));
                    }
                    if !crate::expressions::has_interpolation(p) && !p.starts_with('/') {
                        return Err(SinterError::schema(format!(
                            "{}: validate.program must be an absolute path",
                            ctx
                        )));
                    }
                }
                _ => {
                    return Err(SinterError::schema(format!(
                        "{}: validate.program is required and must be a string",
                        ctx
                    )))
                }
            }
            if let Some(v) = m.get("args") {
                match v {
                    Value::Null => {}
                    Value::List(items) => {
                        for i in items {
                            match i {
                                // A NUL here is the lowered `{{ staged }}`
                                // placeholder: a recipe NUL was already
                                // rejected by `lower_validate_placeholders`.
                                Value::Str(_) => {}
                                _ => {
                                    return Err(SinterError::schema(format!(
                                        "{}: validate.args must be a list of strings",
                                        ctx
                                    )))
                                }
                            }
                        }
                    }
                    _ => {
                        return Err(SinterError::schema(format!(
                            "{}: validate.args must be a list of strings",
                            ctx
                        )))
                    }
                }
            }
            if let Some(v) = m.get("timeout_seconds") {
                if !matches!(v, Value::Null) {
                    match v.as_int() {
                        Some(n) if (1..=86400).contains(&n) => {}
                        _ => {
                            return Err(SinterError::schema(format!(
                                "{}: validate.timeout_seconds must be an integer in 1..86400",
                                ctx
                            )))
                        }
                    }
                }
            }
            Ok(())
        }
        _ => Err(SinterError::schema(format!(
            "{}: validate must be a map with program/args/timeout_seconds",
            ctx
        ))),
    }
}

fn validate_changed_when(e: &Expr, ctx: &str, sensitive: bool) -> Result<()> {
    let mut regs = BTreeSet::new();
    let mut names = BTreeSet::new();
    collect_register_refs(e, &mut regs, &mut names);
    if !regs.is_empty() {
        return Err(SinterError::schema(format!(
            "{}: changed_when may not reference registers",
            ctx
        )));
    }
    validate_changed_when_fields(e, ctx, sensitive)
}

fn validate_changed_when_fields(e: &Expr, ctx: &str, sensitive: bool) -> Result<()> {
    match e {
        Expr::Or(a, b) | Expr::And(a, b) | Expr::Cmp(a, _, b) => {
            validate_changed_when_fields(a, ctx, sensitive)?;
            validate_changed_when_fields(b, ctx, sensitive)
        }
        Expr::Not(a) => validate_changed_when_fields(a, ctx, sensitive),
        Expr::ResultField(name) => match name.as_str() {
            "executed" | "exit_code" | "stdout" | "stderr" | "stdout_complete"
            | "stderr_complete" => Ok(()),
            // The offending field name is expression content: redact it when
            // the expression is sensitive instead of echoing the token.
            other => Err(SinterError::schema(if sensitive {
                format!(
                    "{}: changed_when may not read an unknown result field (value redacted)",
                    ctx
                )
            } else {
                format!("{}: changed_when may not read result.{}", ctx, other)
            })),
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
    sensitive: bool,
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
        if sensitive {
            SinterError::schema(format!(
                "{}: {} must be a statically-known string (value redacted): {}",
                ctx,
                key,
                e.category()
            ))
        } else {
            SinterError::schema(format!(
                "{}: {} must be a statically-known string ({}); facts and registers may not form identifiers",
                ctx, key, e
            ))
        }
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
    "path", "state", "content", "source", "owner", "group", "mode", "validate",
];
pub const DIR_FIELDS: &[&str] = &["path", "state", "owner", "group", "mode"];
pub const LINK_FIELDS: &[&str] = &["path", "target", "state"];
pub const TEMPLATE_FIELDS: &[&str] = &[
    "path", "state", "source", "owner", "group", "mode", "vars", "validate",
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
pub const PACKAGE_FIELDS: &[&str] = &["name", "state", "env"];
pub const SERVICE_FIELDS: &[&str] = &["name", "state", "enabled"];
pub const GROUP_FIELDS: &[&str] = &["name", "state", "gid", "system"];
pub const USER_FIELDS: &[&str] = &[
    "name",
    "state",
    "uid",
    "group",
    "groups",
    "shell",
    "home",
    "create_home",
    "system",
    "password_hash",
];

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

// ---------------------------------------------------------------------------
// WP-VARS (DESIGN §19.5): prepare / freeze_with and value-free diagnostics.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod vars_tests {
    use super::*;

    /// A fictitious value that must never reach a diagnostic.
    const CANARY: &str = "SINTER_VARS_CANARY_DO_NOT_PRINT_20261019";

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    fn s(v: &str) -> Value {
        Value::Str(v.to_string())
    }

    /// Overrides, all from one layer.
    fn ov(pairs: &[(&str, Value)], layer: &str) -> VarOverrides {
        let mut o = VarOverrides::default();
        for (n, v) in pairs {
            o.insert(n, v.clone(), layer);
        }
        o
    }

    fn dbg(r: &Result<Model>) -> String {
        match r {
            Ok(m) => format!("OK {m:?}"),
            Err(e) => format!("ERR {:?} {}", e.kind, e.message),
        }
    }

    fn files_under(root: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(root) else {
            return;
        };
        let mut v: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
        v.sort();
        for p in v {
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "node_modules") {
                    continue;
                }
                files_under(&p, out);
            } else if matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("yaml" | "yml" | "toml")
            ) {
                out.push(p);
            }
        }
    }

    /// Every shipped recipe and fixture: freezing a copy without overrides
    /// equals the established path, errors included.
    #[test]
    fn freeze_with_no_overrides_equals_load_model_on_every_shipped_file() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for d in ["examples", "tests/fixtures", "docs-site/src", "release"] {
            files_under(&root.join(d), &mut files);
        }
        let mut compared = 0;
        for f in &files {
            let established = dbg(&load_model(f));
            match prepare(f) {
                Ok(p) => {
                    assert_eq!(
                        dbg(&p.freeze_with(&VarOverrides::default())),
                        established,
                        "{}",
                        f.display()
                    );
                    assert_eq!(dbg(&p.freeze_default()), established, "{}", f.display());
                    compared += 1;
                }
                Err(e) => assert_eq!(format!("ERR {:?} {}", e.kind, e.message), established),
            }
        }
        assert!(compared > 30, "compared {compared}");
        eprintln!(
            "WP-VARS: {} files, {compared} prepared and compared",
            files.len()
        );
    }

    const SITE: &str = "version: 1\ntargets: { groups: [web] }\nvars:\n  site_root: { value: \"CHANGE_ME\" }\n  port: { value: 80 }\nresources:\n  - id: index\n    type: file\n    with: { path: \"{{ vars.site_root }}/index.html\", content: \"listen {{ vars.port }}\\n\" }\n";

    /// `check_structure` never refuses a recipe that freezes with its own
    /// values (it is a subset of the same checks), on every shipped file.
    #[test]
    fn check_structure_accepts_every_recipe_that_freezes() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for d in ["examples", "tests/fixtures", "docs-site/src", "release"] {
            files_under(&root.join(d), &mut files);
        }
        let mut checked = 0;
        for f in &files {
            if load_model(f).is_ok() {
                let p = prepare(f).unwrap();
                p.check_structure()
                    .unwrap_or_else(|e| panic!("{}: {}", f.display(), e.message));
                checked += 1;
            }
        }
        assert!(checked > 15, "checked {checked}");
    }

    /// A recipe that freezes with its own values passes the structure check
    /// whatever its string variables hold: nothing a variable decides is
    /// judged, on every shipped file.
    #[test]
    fn check_structure_accepts_a_valid_recipe_whatever_its_string_variables_hold() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for d in ["examples", "tests/fixtures", "docs-site/src", "release"] {
            files_under(&root.join(d), &mut files);
        }
        let (mut checked, mut changed) = (0, 0);
        for f in &files {
            if load_model(f).is_err() {
                continue;
            }
            for held in [
                "CHANGE_ME",
                "",
                "rel/path",
                "has space",
                "A!",
                "/",
                "\u{0}x",
            ] {
                let mut p = prepare(f).unwrap();
                let mut any = false;
                for v in p.state.vars.iter_mut().filter(|v| !v.sensitive) {
                    if matches!(v.value, Value::Str(_)) {
                        v.value = Value::Str(held.to_string());
                        any = true;
                    }
                }
                p.check_structure()
                    .unwrap_or_else(|e| panic!("{} with {held:?}: {}", f.display(), e.message));
                checked += 1;
                changed += usize::from(any);
            }
        }
        assert!(
            checked > 100 && changed >= 14,
            "checked {checked}, changed {changed}"
        );
        eprintln!("D-15: {checked} structure checks, {changed} with string variables changed");
    }

    #[test]
    fn check_structure_judges_structure_and_not_a_variables_value() {
        let d = tempfile::tempdir().unwrap();
        // The placeholder default fails freezing, not the structure check.
        let p = write(d.path(), "site.yaml", SITE);
        assert!(load_model(&p).is_err());
        prepare(&p).unwrap().check_structure().unwrap();
        // Structure errors fail it, with or without a variable next to them.
        let head = "version: 1\nvars:\n  root: { value: CHANGE_ME }\nresources:\n";
        for (what, resources) in [
            ("unknown type", "  - { id: d, type: nosuch, with: { path: \"{{ vars.root }}/x\" } }\n"),
            ("unknown field", "  - { id: d, type: file, with: { path: \"{{ vars.root }}/x\", nosuch: 1 } }\n"),
            ("duplicate id", "  - { id: d, type: file, with: { path: /x, content: y } }\n  - { id: d, type: file, with: { path: /y, content: y } }\n"),
            ("unknown dependency", "  - { id: d, type: file, depends_on: [zz], with: { path: \"{{ vars.root }}/x\", content: y } }\n"),
            ("unknown handler", "  - { id: d, type: file, notify: [zz], with: { path: \"{{ vars.root }}/x\", content: y } }\n"),
            ("cycle", "  - { id: a, type: file, depends_on: [b], with: { path: \"{{ vars.root }}/x\", content: y } }\n  - { id: b, type: file, depends_on: [a], with: { path: \"{{ vars.root }}/y\", content: y } }\n"),
            ("literal relative path", "  - { id: d, type: file, with: { path: rel/x, content: y } }\n"),
            ("undeclared variable", "  - { id: d, type: file, with: { path: \"{{ vars.nope }}/x\", content: y } }\n"),
        ] {
            let p = write(d.path(), "r.yaml", &format!("{head}{resources}"));
            let e = prepare(&p)
                .and_then(|p| p.check_structure())
                .expect_err(what);
            assert_eq!(e.kind, crate::error::ErrorKind::Schema, "{what}");
            assert!(!e.message.contains("withheld"), "{what}: {}", e.message);
        }
        // A recipe with no variable has nothing to leave out: it must freeze.
        let p = write(
            d.path(),
            "novars.yaml",
            "version: 1\nresources:\n  - { id: d, type: file, with: { path: rel/x, content: y } }\n",
        );
        assert!(prepare(&p).unwrap().check_structure().is_err());
    }

    /// A sensitive variable is never registered as a value to leave out: a
    /// failure on a field built from one is kept, and its value is redacted.
    #[test]
    fn check_structure_keeps_a_failure_on_a_sensitive_variables_field() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "r.yaml",
            "version: 1\nvars:\n  tok: { value: relsecretvalue, sensitive: true }\nresources:\n  - { id: d, type: file, with: { path: \"{{ vars.tok }}/x\", content: y } }\n",
        );
        let e = prepare(&p).unwrap().check_structure().expect_err("kept");
        assert!(!e.message.contains("relsecretvalue"), "{}", e.message);
    }

    /// A recipe with the placeholder variable `root` (no usable default), a
    /// sensitive `tok` and an integer `n`, given resources, structure-checked.
    fn structure_of(dir: &Path, resources: &str) -> Result<()> {
        structure_holding(dir, "CHANGE_ME", resources)
    }

    /// [`structure_of`] with `root` holding `held` (a YAML scalar).
    fn structure_holding(dir: &Path, held: &str, resources: &str) -> Result<()> {
        let head = format!(
            "version: 1\nvars:\n  root: {{ value: {held} }}\n  n: {{ value: 7 }}\n  flag: {{ value: false }}\n  flag2: {{ value: true }}\n  lst: {{ value: [a] }}\n  tok: {{ value: {CANARY}, sensitive: true }}\nresources:\n"
        );
        let p = write(dir, "r.yaml", &format!("{head}{resources}"));
        prepare(&p).and_then(|p| p.check_structure())
    }

    /// The checks that follow a field a variable decides still run: a field
    /// the check cannot judge (the placeholder fails it) is left out and
    /// nothing else is.
    #[test]
    fn check_structure_goes_on_past_a_field_a_variable_decides() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "t.j2", "x\n");
        write(d.path(), "bad.j2", "{% if a %}x{% endif %}\n");
        let root = "\"{{ vars.root }}/x\"";
        for (what, resources, want) in [
            // Fails whatever the variables hold, in the same field.
            ("undeclared variable", "  - { id: a, type: file, with: { path: \"{{ vars.root }}/{{ vars.nope }}\", content: y } }\n".to_string(), "undefined variable"),
            ("sensitive value", "  - { id: a, type: file, with: { path: \"{{ vars.root }}/{{ vars.tok }}\", content: y } }\n".to_string(), "sensitive values"),
            ("other type", format!("  - {{ id: a, type: file, with: {{ path: {root}, source: \"{{{{ vars.n }}}}\" }} }}\n"), "must be a string"),
            // A later check of the same resource, per kind of resource.
            ("file owner", format!("  - {{ id: a, type: file, with: {{ path: {root}, owner: \"\", content: y }} }}\n"), "invalid owner"),
            ("file group", format!("  - {{ id: a, type: file, with: {{ path: {root}, group: \"\", content: y }} }}\n"), "invalid group"),
            ("file content and source", format!("  - {{ id: a, type: file, with: {{ path: {root}, content: y, source: s }} }}\n"), "mutually exclusive"),
            ("file secret", format!("  - {{ id: a, type: file, with: {{ path: {root}, content: {{ secret: ../b.age }} }} }}\n"), "secret reference"),
            ("template mode", format!("  - {{ id: a, type: template, with: {{ path: {root}, source: \"{{{{ vars.root }}}}/t\", mode: \"99\" }} }}\n"), "mode"),
            ("template literal source", format!("  - {{ id: a, type: template, with: {{ path: {root}, source: nosuch.j2 }} }}\n"), "not found"),
            ("template body", format!("  - {{ id: a, type: template, with: {{ path: {root}, source: bad.j2 }} }}\n"), "{% ... %}"),
            ("command removes", format!("  - {{ id: a, type: command, with: {{ program: /bin/true, creates: {root}, removes: /r }} }}\n"), "mutually exclusive"),
            ("command cwd", format!("  - {{ id: a, type: command, with: {{ program: /bin/true, removes: {root}, cwd: rel }} }}\n"), "cwd"),
            ("account secret", "  - { id: a, type: user, with: { name: \"{{ vars.root }}\", password_hash: { secret: ../b.age } } }\n".to_string(), "secret reference"),
            ("group state", "  - { id: a, type: group, with: { name: \"{{ vars.root }}\", state: sideways } }\n".to_string(), "state"),
            ("role secret", "  - { id: a, type: postgresql_role, with: { name: \"{{ vars.root }}\", password_verifier: { secret: ../b.age } } }\n".to_string(), "secret reference"),
            // Ownership that the failing resource still holds.
            ("path owner", "  - { id: a, type: template, with: { path: /etc/same, source: \"{{ vars.root }}/t\" } }\n  - { id: b, type: file, with: { path: /etc/same, content: y } }\n".to_string(), "conflicting ownership of path"),
            // Another resource after the failing one.
            ("next resource", format!("  - {{ id: a, type: file, with: {{ path: {root}, content: y }} }}\n  - {{ id: b, type: file, with: {{ path: /y, owner: \"\", content: y }} }}\n"), "invalid owner"),
        ] {
            let e = structure_of(d.path(), &resources)
                .expect_err(&format!("{what}: not refused"));
            assert_eq!(e.kind, crate::error::ErrorKind::Schema, "{what}");
            assert!(!e.message.contains("withheld"), "{what}: {}", e.message);
            assert!(e.message.contains(want), "{what}: {}", e.message);
            assert!(!e.message.contains(CANARY), "{what}: {}", e.message);
        }
    }

    /// What a variable may decide stays undecided, in every kind of resource,
    /// and so does a conflict between things named by a variable.
    #[test]
    fn check_structure_leaves_what_a_variable_decides_undecided() {
        let d = tempfile::tempdir().unwrap();
        let root = "\"{{ vars.root }}/x\"";
        let name = "\"{{ vars.root }}\"";
        for (what, resources) in [
            ("file", format!("  - {{ id: a, type: file, with: {{ path: {root}, content: y }} }}\n")),
            ("directory", format!("  - {{ id: a, type: directory, with: {{ path: {root} }} }}\n")),
            ("link", format!("  - {{ id: a, type: link, with: {{ path: {root}, target: /t }} }}\n")),
            ("template", format!("  - {{ id: a, type: template, with: {{ path: {root}, source: \"{{{{ vars.root }}}}/t.j2\" }} }}\n")),
            ("command", format!("  - {{ id: a, type: command, with: {{ program: /bin/true, creates: {root}, cwd: {root} }} }}\n")),
            ("package", "  - { id: a, type: package, with: { name: \"{{ vars.root }} x\", state: present } }\n".to_string()),
            ("service", format!("  - {{ id: a, type: service, with: {{ name: {name}, state: running }} }}\n")),
            ("user", format!("  - {{ id: a, type: user, with: {{ name: {name} }} }}\n")),
            ("group", format!("  - {{ id: a, type: group, with: {{ name: {name} }} }}\n")),
            ("role", format!("  - {{ id: a, type: postgresql_role, with: {{ name: {name} }} }}\n")),
            ("path owned twice", format!("  - {{ id: a, type: file, with: {{ path: {root}, content: y }} }}\n  - {{ id: b, type: file, with: {{ path: {root}, content: y }} }}\n")),
            ("account owned twice", format!("  - {{ id: a, type: user, with: {{ name: {name} }} }}\n  - {{ id: b, type: user, with: {{ name: {name} }} }}\n")),
            ("role owned twice", format!("  - {{ id: a, type: postgresql_role, with: {{ name: {name} }} }}\n  - {{ id: b, type: postgresql_role, with: {{ name: {name} }} }}\n")),
        ] {
            for held in [
                "CHANGE_ME",
                "\"\"",
                "rel/path",
                "\"has space\"",
                "\"A!\"",
                "\"/\"",
                "/srv",
            ] {
                structure_holding(d.path(), held, &resources)
                    .unwrap_or_else(|e| panic!("{what} with {held}: {}", e.message));
            }
        }
        // The same conflicts are refused where the names are literal.
        for (what, resources) in [
            ("path", "  - { id: a, type: file, with: { path: /x, content: y } }\n  - { id: b, type: file, with: { path: /x, content: y } }\n"),
            ("user", "  - { id: a, type: user, with: { name: dup } }\n  - { id: b, type: user, with: { name: dup } }\n"),
            ("role", "  - { id: a, type: postgresql_role, with: { name: dup } }\n  - { id: b, type: postgresql_role, with: { name: dup } }\n"),
        ] {
            let e = structure_of(d.path(), resources).expect_err(what);
            assert!(e.message.contains("conflicting ownership"), "{what}: {}", e.message);
        }
    }

    /// What fails whatever the variables hold is refused at every field that
    /// is checked on its own: leaving the field out would hide it.
    #[test]
    fn check_structure_keeps_what_fails_whatever_a_variable_holds_at_every_field() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "t.j2", "x\n");
        let u = "\"{{ vars.root }}/{{ vars.nope }}\"";
        let sole_list = "\"{{ vars.lst }}\"";
        for (what, field, resources) in [
            (
                "file path",
                u,
                "  - { id: a, type: file, with: { path: FIELD, content: y } }\n",
            ),
            (
                "file source",
                u,
                "  - { id: a, type: file, with: { path: /x, source: FIELD } }\n",
            ),
            (
                "directory path",
                u,
                "  - { id: a, type: directory, with: { path: FIELD } }\n",
            ),
            (
                "link path",
                u,
                "  - { id: a, type: link, with: { path: FIELD, target: /t } }\n",
            ),
            (
                "template path",
                u,
                "  - { id: a, type: template, with: { path: FIELD, source: t.j2 } }\n",
            ),
            (
                "template source",
                u,
                "  - { id: a, type: template, with: { path: /x, source: FIELD } }\n",
            ),
            (
                "command program",
                "\"/{{ vars.root }}/{{ vars.nope }}\"",
                "  - { id: a, type: command, with: { program: FIELD } }\n",
            ),
            (
                "command creates",
                u,
                "  - { id: a, type: command, with: { program: /bin/true, creates: FIELD } }\n",
            ),
            (
                "command removes",
                u,
                "  - { id: a, type: command, with: { program: /bin/true, removes: FIELD } }\n",
            ),
            (
                "command cwd",
                u,
                "  - { id: a, type: command, with: { program: /bin/true, cwd: FIELD } }\n",
            ),
            (
                "package name",
                u,
                "  - { id: a, type: package, with: { name: FIELD, state: present } }\n",
            ),
            (
                "service name",
                u,
                "  - { id: a, type: service, with: { name: FIELD, state: running } }\n",
            ),
            (
                "user name",
                u,
                "  - { id: a, type: user, with: { name: FIELD } }\n",
            ),
            (
                "group name",
                u,
                "  - { id: a, type: group, with: { name: FIELD } }\n",
            ),
            (
                "role name",
                u,
                "  - { id: a, type: postgresql_role, with: { name: FIELD } }\n",
            ),
            // A variable of another type, used as the whole value.
            (
                "file path (list)",
                sole_list,
                "  - { id: a, type: file, with: { path: FIELD, content: y } }\n",
            ),
            (
                "template source (list)",
                sole_list,
                "  - { id: a, type: template, with: { path: /x, source: FIELD } }\n",
            ),
            (
                "command creates (list)",
                sole_list,
                "  - { id: a, type: command, with: { program: /bin/true, creates: FIELD } }\n",
            ),
            (
                "package name (list)",
                sole_list,
                "  - { id: a, type: package, with: { name: FIELD, state: present } }\n",
            ),
            (
                "user name (list)",
                sole_list,
                "  - { id: a, type: user, with: { name: FIELD } }\n",
            ),
            // The loop item takes part in the same field.
            (
                "loop item",
                u,
                "  - { id: a, type: file, loop: [x, y], with: { path: FIELD, content: y } }\n",
            ),
        ] {
            let resources = resources.replace("FIELD", field);
            let e = structure_of(d.path(), &resources).expect_err(&format!("{what}: not refused"));
            assert!(!e.message.contains("withheld"), "{what}: {}", e.message);
            assert!(!e.message.contains(CANARY), "{what}: {}", e.message);
        }
    }

    /// A failure that depends on the value of a variable is left undecided,
    /// whatever the type of the variable and the way the field is built.
    #[test]
    fn check_structure_leaves_undecided_what_a_value_a_boolean_or_an_item_decides() {
        let d = tempfile::tempdir().unwrap();
        let file = |path: &str| {
            format!("  - {{ id: a, type: file, with: {{ path: \"{path}\", content: y }} }}\n")
        };
        // `||` and `&&` evaluate their right side only for some values.
        for (what, resources) in [
            ("or, right side only when false", file("/a/{{ vars.flag || vars.root }}")),
            ("or, right side only when false (true)", file("{{ vars.root }}/{{ vars.flag2 || vars.root }}")),
            ("and, right side only when true", file("/a/{{ vars.flag2 && vars.root }}")),
            ("item and a variable", "  - { id: a, type: file, loop: [x, y], with: { path: \"{{ vars.root }}/{{ item }}\", content: y } }\n".to_string()),
        ] {
            structure_of(d.path(), &resources).unwrap_or_else(|e| panic!("{what}: {}", e.message));
        }
        // A NUL in a default is a value, not a structure.
        structure_holding(d.path(), "\"a\\u0000b\"", &file("{{ vars.root }}/x"))
            .unwrap_or_else(|e| panic!("nul: {}", e.message));
        // What fails for every value of the booleans is refused (an integer is
        // never an operand of `||` or `&&`).
        let e = structure_of(d.path(), &file("/a/{{ vars.n || vars.flag }}")).expect_err("or int");
        assert!(!e.message.contains("withheld"), "{}", e.message);
        let e =
            structure_of(d.path(), &file("/a/{{ vars.n && vars.flag2 }}")).expect_err("and int");
        assert!(!e.message.contains("withheld"), "{}", e.message);
        // Used as the whole value, `flag2 && root` is a boolean for every value.
        let e = structure_of(
            d.path(),
            "  - { id: a, type: user, with: { name: \"{{ vars.flag2 && vars.root }}\" } }\n",
        )
        .expect_err("and, whole value");
        assert!(!e.message.contains("withheld"), "{}", e.message);
    }

    /// A field that names more booleans than are tried is left undecided.
    #[test]
    fn check_structure_leaves_a_field_naming_many_booleans_undecided() {
        let d = tempfile::tempdir().unwrap();
        let names: Vec<String> = (1..=MAX_PROBED_BOOLS + 1)
            .map(|i| format!("b{i}"))
            .collect();
        let decl: String = names
            .iter()
            .map(|n| format!("  {n}: {{ value: false }}\n"))
            .collect();
        let used: String = names
            .iter()
            .map(|n| format!("{{{{ vars.{n} }}}}"))
            .collect();
        let p = write(
            d.path(),
            "r.yaml",
            &format!(
                "version: 1\nvars:\n  root: {{ value: CHANGE_ME }}\n{decl}resources:\n  - {{ id: a, type: file, with: {{ path: \"{{{{ vars.root }}}}/{used}\", content: y }} }}\n"
            ),
        );
        prepare(&p).unwrap().check_structure().unwrap();
    }

    /// A conflict a variable takes part in is left undecided, on whichever
    /// side the variable is, and the resource's later checks still run.
    #[test]
    fn check_structure_leaves_a_conflict_a_variable_decides_and_goes_on() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "bad.j2", "{% if a %}x{% endif %}\n");
        // `root` holds a usable value here: a and b collide with it, and with
        // no other value they would not.
        for (what, held, resources) in [
            ("variable, then literal", "/srv", "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", content: y } }\n  - { id: b, type: file, with: { path: /srv/x, content: y } }\n"),
            ("literal, then variable", "/srv", "  - { id: a, type: file, with: { path: /srv/x, content: y } }\n  - { id: b, type: file, with: { path: \"{{ vars.root }}/x\", content: y } }\n"),
            ("account, variable then literal", "dup", "  - { id: a, type: user, with: { name: \"{{ vars.root }}\" } }\n  - { id: b, type: user, with: { name: dup } }\n"),
            ("account, literal then variable", "dup", "  - { id: a, type: user, with: { name: dup } }\n  - { id: b, type: user, with: { name: \"{{ vars.root }}\" } }\n"),
            ("role, variable then literal", "dup", "  - { id: a, type: postgresql_role, with: { name: \"{{ vars.root }}\" } }\n  - { id: b, type: postgresql_role, with: { name: dup } }\n"),
        ] {
            structure_holding(d.path(), held, resources)
                .unwrap_or_else(|e| panic!("{what}: {}", e.message));
        }
        for (what, held, resources, want) in [
            ("template body after a path conflict", "/srv", "  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", content: y } }\n  - { id: b, type: template, with: { path: \"{{ vars.root }}/x\", source: bad.j2 } }\n", "{% ... %}"),
            ("template body after a path conflict, literal first", "/srv", "  - { id: a, type: file, with: { path: /srv/x, content: y } }\n  - { id: b, type: template, with: { path: \"{{ vars.root }}/x\", source: bad.j2 } }\n", "{% ... %}"),
            ("secret after an account conflict, literal first", "dup", "  - { id: a, type: user, with: { name: dup } }\n  - { id: b, type: user, with: { name: \"{{ vars.root }}\", password_hash: { secret: ../b.age } } }\n", "secret reference"),
            ("secret after a role conflict, literal first", "dup", "  - { id: a, type: postgresql_role, with: { name: dup } }\n  - { id: b, type: postgresql_role, with: { name: \"{{ vars.root }}\", password_verifier: { secret: ../b.age } } }\n", "secret reference"),
            ("secret after an account conflict", "dup", "  - { id: a, type: user, with: { name: \"{{ vars.root }}\" } }\n  - { id: b, type: user, with: { name: dup, password_hash: { secret: ../b.age } } }\n", "secret reference"),
            ("secret after a role conflict", "dup", "  - { id: a, type: postgresql_role, with: { name: \"{{ vars.root }}\" } }\n  - { id: b, type: postgresql_role, with: { name: dup, password_verifier: { secret: ../b.age } } }\n", "secret reference"),
        ] {
            let e = structure_holding(d.path(), held, resources).expect_err(what);
            assert!(e.message.contains(want), "{what}: {}", e.message);
        }
    }

    /// A freeze that runs a recipe is the freeze it was: the same field that
    /// the structure check leaves undecided fails there, and fails first.
    #[test]
    fn freezing_still_fails_on_the_first_failing_check() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "r.yaml",
            "version: 1\nvars:\n  root: { value: CHANGE_ME }\nresources:\n  - { id: a, type: file, with: { path: \"{{ vars.root }}/x\", owner: \"\", content: y } }\n",
        );
        let e = load_model(&p).unwrap_err();
        assert!(e.message.contains("path must be absolute"), "{}", e.message);
        let e = prepare(&p)
            .unwrap()
            .freeze_with(&ov(&[("root", s("/srv"))], "hosts.web01"))
            .unwrap_err();
        assert!(e.message.contains("invalid owner"), "{}", e.message);
        // A field an override decides fails the freeze that runs it: it is
        // never left out there.
        let e = prepare(&p)
            .unwrap()
            .freeze_with(&ov(&[("root", s("rel"))], "hosts.web01"))
            .unwrap_err();
        assert!(e.message.contains("withheld"), "{}", e.message);
        assert!(!e.message.contains("invalid owner"), "{}", e.message);
    }

    #[test]
    fn a_failing_default_is_never_frozen_when_overridden() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "site.yaml", SITE);
        assert!(load_model(&p)
            .unwrap_err()
            .message
            .contains("path must be absolute"));
        let m = prepare(&p)
            .unwrap()
            .freeze_with(&ov(&[("site_root", s("/srv/a"))], "hosts.web01"))
            .unwrap();
        assert_eq!(m.resources[0].path.as_deref(), Some("/srv/a/index.html"));
        assert_eq!(m.vars["site_root"].value, s("/srv/a"));
        assert_eq!(m.vars["port"].value, Value::Int(80));
    }

    #[test]
    fn one_prepared_recipe_many_hosts_without_mixing() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "site.yaml", SITE);
        let pr = prepare(&p).unwrap();
        let a = ov(
            &[("site_root", s("/srv/a")), ("port", Value::Int(8081))],
            "hosts.a",
        );
        let a1 = pr.freeze_with(&a).unwrap();
        let b = pr
            .freeze_with(&ov(&[("site_root", s("/srv/b"))], "hosts.b"))
            .unwrap();
        let a2 = pr.freeze_with(&a).unwrap();
        assert_eq!(b.resources[0].path.as_deref(), Some("/srv/b/index.html"));
        assert_eq!(b.vars["port"].value, Value::Int(80));
        assert_eq!(a1.vars["port"].value, Value::Int(8081));
        assert_eq!(format!("{a1:?}"), format!("{a2:?}"));
        assert_ne!(format!("{a1:?}"), format!("{b:?}"));
        // The prepared recipe keeps its defaults.
        let defaults: BTreeMap<&str, &Value> = pr.declared().map(|(n, v, _)| (n, v)).collect();
        assert_eq!(defaults["site_root"], &s("CHANGE_ME"));
        assert_eq!(defaults["port"], &Value::Int(80));
        drop(a1);
        assert_eq!(a2.resources[0].path.as_deref(), Some("/srv/a/index.html"));
    }

    #[test]
    fn concurrent_freezes_of_one_prepared_recipe_stay_separate() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "site.yaml", SITE);
        let pr = prepare(&p).unwrap();
        let hosts: Vec<String> = (0..16).map(|i| format!("h{i:02}")).collect();
        let models: Vec<(String, Model)> = std::thread::scope(|sc| {
            let handles: Vec<_> = hosts
                .iter()
                .map(|h| {
                    let pr = &pr;
                    sc.spawn(move || {
                        let o = ov(
                            &[
                                ("site_root", s(&format!("/srv/{h}"))),
                                ("port", Value::Int(h[1..].parse::<i64>().unwrap() + 9000)),
                            ],
                            &format!("hosts.{h}"),
                        );
                        (h.clone(), pr.freeze_with(&o).unwrap())
                    })
                })
                .collect();
            handles.into_iter().map(|j| j.join().unwrap()).collect()
        });
        for (h, m) in &models {
            assert_eq!(
                m.resources[0].path.as_deref(),
                Some(format!("/srv/{h}/index.html").as_str())
            );
            assert_eq!(
                m.vars["port"].value,
                Value::Int(h[1..].parse::<i64>().unwrap() + 9000)
            );
        }
    }

    #[test]
    fn override_rules_name_types_never_values() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "r.yaml",
            "version: 1\nvars:\n  a: { value: \"x\" }\n  n: { value: 1 }\n  tok: { value: \"t\", sensitive: true }\nresources: []\n",
        );
        let pr = prepare(&p).unwrap();
        for (o, want) in [
            (ov(&[("nope", s(CANARY))], "vars"), "is not declared"),
            (
                ov(&[("tok", s(CANARY))], "vars"),
                "is sensitive and cannot be overridden",
            ),
            (
                ov(&[("a", Value::List(vec![s(CANARY)]))], "vars"),
                "must be string, not list",
            ),
            (
                ov(&[("n", Value::Float(1.5))], "vars"),
                "must be integer, not float",
            ),
        ] {
            let e = pr.freeze_with(&o).unwrap_err();
            assert!(e.message.contains(want), "{}", e.message);
            assert!(!e.message.contains(CANARY), "{}", e.message);
        }
    }

    /// The error of `body` frozen with `overrides` from `hosts.web01`.
    fn override_error(dir: &Path, body: &str, overrides: &[(&str, Value)]) -> SinterError {
        let p = write(dir, "r.yaml", body);
        prepare(&p)
            .unwrap()
            .freeze_with(&ov(overrides, "hosts.web01"))
            .unwrap_err()
    }

    fn assert_withheld(e: &SinterError, id: &str, check: &str, var: &str) {
        let m = &e.message;
        assert!(!m.contains(CANARY), "LEAK: {m}");
        assert!(m.starts_with(&format!("{id}: ")), "{m}");
        assert!(m.contains(check), "want {check:?}: {m}");
        assert!(m.contains(&format!("{var} (hosts.web01)")), "{m}");
        assert!(m.ends_with("the value is withheld"), "{m}");
        let json = serde_json::json!({ "error": { "kind": "schema", "message": m } }).to_string();
        assert!(!json.contains(CANARY));
        assert!(!crate::diff::sanitize_line(m).contains(CANARY));
    }

    /// The same failure with the canary as the recipe's own default prints
    /// it (established behavior, unchanged): proves each case reaches a
    /// message that would carry the value.
    fn established_prints_value(dir: &Path, body: &str) {
        let p = write(dir, "base.yaml", body);
        let e = load_model(&p).unwrap_err();
        assert!(e.message.contains(CANARY), "{}", e.message);
    }

    fn one_var(name: &str, default: &str, resources: &str) -> String {
        format!("version: 1\nvars:\n  {name}: {{ value: \"{default}\" }}\nresources:\n{resources}")
    }

    #[test]
    fn invalid_paths_of_every_path_resource_are_withheld() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "t.tmpl", "x\n");
        for (id, ty, extra) in [
            ("f", "file", "content: x"),
            ("dir", "directory", "state: present"),
            ("ln", "link", "target: /etc/hosts"),
            ("tpl", "template", "source: t.tmpl"),
        ] {
            let res = format!(
                "  - id: {id}\n    type: {ty}\n    with: {{ path: \"{{{{ vars.root }}}}/x\", {extra} }}\n"
            );
            established_prints_value(d.path(), &one_var("root", CANARY, &res));
            let e = override_error(
                d.path(),
                &one_var("root", "/ok", &res),
                &[("root", s(CANARY))],
            );
            assert_withheld(&e, id, "field path", "root");
        }
    }

    #[test]
    fn command_fields_are_withheld() {
        let d = tempfile::tempdir().unwrap();
        for field in ["creates", "removes", "cwd"] {
            let res = format!(
                "  - id: cmd\n    type: command\n    with: {{ program: /bin/true, {field}: \"{{{{ vars.c }}}}\" }}\n"
            );
            established_prints_value(d.path(), &one_var("c", CANARY, &res));
            let e = override_error(d.path(), &one_var("c", "/ok", &res), &[("c", s(CANARY))]);
            assert_withheld(&e, "cmd", &format!("field {field}"), "c");
        }
        // program: written text must start with "/" (a value-free declaration
        // check, message kept); a value of the wrong shape is attributed.
        let res = "  - id: cmd\n    type: command\n    with: { program: \"{{ vars.c }}\" }\n";
        let p = write(d.path(), "r.yaml", &one_var("c", "/bin/true", res));
        let established = load_model(&p).unwrap_err().message;
        assert_eq!(established, "cmd: program must be an absolute path");
        let e = override_error(
            d.path(),
            &one_var("c", "/bin/true", res),
            &[("c", s(CANARY))],
        );
        assert_eq!(e.message, established);
        let res = "  - id: cmd\n    type: command\n    with: { program: \"/opt/{{ vars.c }}\" }\n";
        let body = "version: 1\nvars:\n  c: { value: [a] }\nresources:\n".to_string() + res;
        let e = override_error(d.path(), &body, &[("c", Value::List(vec![s(CANARY)]))]);
        assert_withheld(&e, "cmd", "field program", "c");
    }

    #[test]
    fn names_of_packages_accounts_and_roles_are_withheld() {
        let d = tempfile::tempdir().unwrap();
        let bad = format!("bad name {CANARY}");
        for (id, res) in [
            ("pkg", "  - id: pkg\n    type: package\n    with: { name: \"{{ vars.n }}\", state: present }\n"),
            ("u", "  - id: u\n    type: user\n    with: { name: \"{{ vars.n }}\" }\n"),
            ("g", "  - id: g\n    type: group\n    with: { name: \"{{ vars.n }}\" }\n"),
            ("role", "  - id: role\n    type: postgresql_role\n    with: { name: \"{{ vars.n }}\" }\n"),
        ] {
            established_prints_value(d.path(), &one_var("n", &bad, res));
            let e = override_error(d.path(), &one_var("n", "ok", res), &[("n", s(&bad))]);
            assert_withheld(&e, id, "field name", "n");
        }
        // A service name cannot fail on a string; a wrong shape still is
        // attributed (the evaluator names only types).
        let res = "  - id: svc\n    type: service\n    with: { name: \"{{ vars.n }}\", state: running }\n";
        let body = "version: 1\nvars:\n  n: { value: [a] }\nresources:\n".to_string() + res;
        let e = override_error(d.path(), &body, &[("n", Value::List(vec![s(CANARY)]))]);
        assert_withheld(&e, "svc", "field name", "n");
    }

    #[test]
    fn ownership_conflicts_are_withheld_on_either_side() {
        let d = tempfile::tempdir().unwrap();
        let leak = format!("/srv/{CANARY}");
        // Both sides from the file.
        let two = "version: 1\nvars:\n  a: { value: \"/srv/x\" }\n  b: { value: \"/srv/y\" }\nresources:\n  - id: ra\n    type: file\n    with: { path: \"{{ vars.a }}\", content: a }\n  - id: rb\n    type: file\n    with: { path: \"{{ vars.b }}\", content: b }\n";
        established_prints_value(
            d.path(),
            &two.replace("/srv/x", &leak).replace("/srv/y", &leak),
        );
        let e = override_error(d.path(), two, &[("a", s(&leak)), ("b", s(&leak))]);
        assert_withheld(&e, "rb", "conflicts with resource ra", "b");
        assert!(e.message.contains("a (hosts.web01)"), "{}", e.message);
        // Only the other side from the file: the literal equals its value.
        let peer = format!("version: 1\nvars:\n  a: {{ value: \"/srv/x\" }}\nresources:\n  - id: ra\n    type: file\n    with: {{ path: \"{{{{ vars.a }}}}\", content: a }}\n  - id: rb\n    type: file\n    with: {{ path: \"{leak}\", content: b }}\n");
        let e = override_error(d.path(), &peer, &[("a", s(&leak))]);
        assert!(!e.message.contains(CANARY), "{}", e.message);
        assert!(e
            .message
            .contains("ownership of field path (conflicts with resource ra)"));
        // Accounts and roles.
        for (ty, extra) in [("user", ""), ("group", ""), ("postgresql_role", "")] {
            let body = format!("version: 1\nvars:\n  a: {{ value: x }}\n  b: {{ value: y }}\nresources:\n  - id: one\n    type: {ty}\n    with: {{ name: \"{{{{ vars.a }}}}\"{extra} }}\n  - id: two\n    type: {ty}\n    with: {{ name: \"{{{{ vars.b }}}}\"{extra} }}\n");
            let name = format!("n{}", &CANARY.to_ascii_lowercase()[..20]);
            let e = override_error(d.path(), &body, &[("a", s(&name)), ("b", s(&name))]);
            assert!(!e.message.contains(&name), "{ty}: {}", e.message);
            assert!(
                e.message
                    .contains("ownership of field name (conflicts with resource one)"),
                "{ty}: {}",
                e.message
            );
        }
    }

    #[test]
    fn template_sources_are_withheld() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "ok.tmpl", "x\n");
        let res = "  - id: conf\n    type: template\n    with: { path: /etc/x.conf, source: \"{{ vars.t }}\" }\n";
        // Missing source.
        established_prints_value(d.path(), &one_var("t", &format!("{CANARY}.tmpl"), res));
        let e = override_error(
            d.path(),
            &one_var("t", "ok.tmpl", res),
            &[("t", s(&format!("{CANARY}.tmpl")))],
        );
        assert_withheld(&e, "conf", "field source", "t");
        // A source that exists but cannot be read as a template (a directory).
        std::fs::create_dir(d.path().join(format!("{CANARY}.d"))).unwrap();
        established_prints_value(d.path(), &one_var("t", &format!("{CANARY}.d"), res));
        let e = override_error(
            d.path(),
            &one_var("t", "ok.tmpl", res),
            &[("t", s(&format!("{CANARY}.d")))],
        );
        assert_withheld(&e, "conf", "field source", "t");
        // An unsupported tag in a body the file selects names the file.
        write(d.path(), &format!("{CANARY}.tmpl"), "{% if x %}\n");
        let e = override_error(
            d.path(),
            &one_var("t", "ok.tmpl", res),
            &[("t", s(&format!("{CANARY}.tmpl")))],
        );
        assert_withheld(&e, "conf", "field source", "t");
        // file.source: only its shape is checked while loading.
        let res =
            "  - id: f\n    type: file\n    with: { path: /etc/f, source: \"{{ vars.t }}\" }\n";
        let body = "version: 1\nvars:\n  t: { value: [a] }\nresources:\n".to_string() + res;
        let e = override_error(d.path(), &body, &[("t", Value::List(vec![s(CANARY)]))]);
        assert_withheld(&e, "f", "field source", "t");
    }

    #[test]
    fn evaluation_failures_carry_no_value_with_or_without_the_boundary() {
        let d = tempfile::tempdir().unwrap();
        let body = "version: 1\nvars:\n  l: { value: [\"a\"] }\nresources:\n  - id: f\n    type: file\n    with: { path: \"/x/{{ vars.l }}\", content: x }\n";
        let e = override_error(d.path(), body, &[("l", Value::List(vec![s(CANARY)]))]);
        assert_withheld(&e, "f", "field path", "l");
        let p = write(
            d.path(),
            "r.yaml",
            &body.replace("[\"a\"]", &format!("[\"{CANARY}\"]")),
        );
        assert!(!load_model(&p).unwrap_err().message.contains(CANARY));
    }

    #[test]
    fn value_free_checks_keep_their_message_on_a_resource_that_uses_the_file() {
        let d = tempfile::tempdir().unwrap();
        for (body, want) in [
            // Unknown field.
            ("version: 1\nvars:\n  r: { value: /ok }\nresources:\n  - id: f\n    type: file\n    with: { path: \"{{ vars.r }}\", content: x, colour: red }\n", "unknown field"),
            // Unknown dependency.
            ("version: 1\nvars:\n  r: { value: /ok }\nresources:\n  - id: f\n    type: file\n    depends_on: [nope]\n    with: { path: \"{{ vars.r }}\", content: x }\n", "depends_on references unknown"),
            // Invalid enumeration.
            ("version: 1\nvars:\n  n: { value: jq }\nresources:\n  - id: p\n    type: package\n    with: { name: \"{{ vars.n }}\", state: sideways }\n", "package state"),
            // Invalid literal mode.
            ("version: 1\nvars:\n  r: { value: /ok }\nresources:\n  - id: f\n    type: file\n    with: { path: \"{{ vars.r }}\", content: x, mode: \"999\" }\n", "mode"),
        ] {
            let p = write(d.path(), "r.yaml", body);
            let established = load_model(&p).unwrap_err().message;
            assert!(established.contains(want), "{established}");
            let name = if body.contains("vars.n") { "n" } else { "r" };
            let value = if name == "n" { s("curl") } else { s("/srv/other") };
            let e = prepare(&p)
                .unwrap()
                .freeze_with(&ov(&[(name, value)], "hosts.web01"))
                .unwrap_err();
            assert_eq!(e.message, established);
        }
    }

    #[test]
    fn checks_on_fields_without_file_values_keep_their_message() {
        let d = tempfile::tempdir().unwrap();
        let body = "version: 1\nvars:\n  port: { value: 80 }\nresources:\n  - id: f\n    type: file\n    with: { path: relative/path, content: \"{{ vars.port }}\" }\n";
        let p = write(d.path(), "r.yaml", body);
        let established = load_model(&p).unwrap_err().message;
        let e = prepare(&p)
            .unwrap()
            .freeze_with(&ov(&[("port", Value::Int(9))], "groups.web"))
            .unwrap_err();
        assert_eq!(e.message, established);
    }

    #[test]
    fn an_unattributed_failure_withholds_when_the_resource_uses_the_file() {
        let r = RawResource {
            id: "f".into(),
            type_: "file".into(),
            with: BTreeMap::from([
                ("path".to_string(), s("{{ vars.root }}/x")),
                ("content".to_string(), s("plain")),
            ]),
            when: None,
            depends_on: vec![],
            notify: vec![],
            sensitive: false,
            origin: "r.yaml".into(),
            loop_index: None,
            loop_item: None,
            register_refs: BTreeSet::new(),
        };
        let o = ov(&[("root", s(CANARY))], "hosts.web01");
        let refs = override_refs(&r.with, &o);
        let original = || SinterError::schema(format!("f: something about {CANARY}"));
        let e = withhold_override_values(
            &r,
            &Stage::Unattributed,
            &refs,
            &BTreeMap::new(),
            &o,
            original(),
        );
        assert_withheld(&e, "f", "check not attributed to one field", "root");
        // Value-free keeps; a field without file values keeps.
        let e = withhold_override_values(
            &r,
            &Stage::ValueFree,
            &refs,
            &BTreeMap::new(),
            &o,
            original(),
        );
        assert!(e.message.contains("something about"));
        let e = withhold_override_values(
            &r,
            &Stage::Field("content"),
            &refs,
            &BTreeMap::new(),
            &o,
            original(),
        );
        assert!(e.message.contains("something about"));
    }

    #[test]
    fn a_check_that_succeeds_returns_the_stage_to_unattributed() {
        let mut stage = Stage::Unattributed;
        staged(&mut stage, Stage::ValueFree, || Ok(())).unwrap();
        assert!(matches!(stage, Stage::Unattributed));
        let _ = staged(&mut stage, Stage::Field("path"), || -> Result<()> {
            Err(SinterError::schema("x"))
        });
        assert!(matches!(stage, Stage::Field("path")));
    }

    #[test]
    fn diagnostics_differ_per_layer_and_carry_no_value() {
        let d = tempfile::tempdir().unwrap();
        let body = "version: 1\nvars:\n  root: { value: /ok }\nresources:\n  - id: index\n    type: file\n    with: { path: \"{{ vars.root }}/i\", content: x }\n";
        let p = write(d.path(), "r.yaml", body);
        let pr = prepare(&p).unwrap();
        let mut agg: BTreeMap<String, Vec<&str>> = BTreeMap::new();
        for host in ["web01", "web02", "web03"] {
            let e = pr
                .freeze_with(&ov(
                    &[("root", s(&format!("{CANARY}-{host}")))],
                    &format!("hosts.{host}"),
                ))
                .unwrap_err();
            agg.entry(e.message).or_default().push(host);
        }
        assert_eq!(agg.len(), 3);
        assert!(!serde_json::to_string(&agg).unwrap().contains(CANARY));
        // Same layer, different values: one message.
        let mut agg: BTreeSet<String> = BTreeSet::new();
        for v in ["a", "b"] {
            agg.insert(
                pr.freeze_with(&ov(&[("root", s(&format!("{CANARY}{v}")))], "vars"))
                    .unwrap_err()
                    .message,
            );
        }
        assert_eq!(agg.len(), 1);
    }

    #[test]
    fn overridden_values_never_change_sensitivity() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "site.yaml", SITE);
        let pr = prepare(&p).unwrap();
        let m = pr
            .freeze_with(&ov(&[("site_root", s("/srv/a"))], "hosts.web01"))
            .unwrap();
        assert!(!m.resources[0].sensitive);
        assert!(!m.resources[0].derived_sensitive);
        assert!(!m.vars["site_root"].sensitive);
        // A resource that is sensitive through another variable stays so.
        let body = "version: 1\nvars:\n  root: { value: /srv }\n  tok: { value: t, sensitive: true }\nresources:\n  - id: f\n    type: file\n    with: { path: \"{{ vars.root }}/f\", content: \"{{ vars.tok }}\" }\n";
        let p = write(d.path(), "s.yaml", body);
        let pr = prepare(&p).unwrap();
        let base = pr.clone().freeze_default().unwrap();
        let m = pr
            .freeze_with(&ov(&[("root", s("/srv/b"))], "vars"))
            .unwrap();
        assert!(base.resources[0].derived_sensitive && m.resources[0].derived_sensitive);
        assert!(m.vars["tok"].sensitive);
    }

    #[test]
    fn include_declared_variables_are_overridden_by_name() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "part.yaml",
            "version: 1\nvars:\n  inner: { value: /srv/default }\nresources:\n  - id: f\n    type: file\n    with: { path: \"{{ vars.inner }}/f\", content: x }\n",
        );
        let p = write(
            d.path(),
            "main.yaml",
            "version: 1\ninclude:\n  - part.yaml\nvars:\n  outer: { value: 1 }\nresources: []\n",
        );
        let pr = prepare(&p).unwrap();
        let names: BTreeSet<&str> = pr.declared().map(|(n, _, _)| n).collect();
        assert_eq!(names, BTreeSet::from(["inner", "outer"]));
        let m = pr
            .freeze_with(&ov(&[("inner", s("/srv/h1"))], "hosts.h1"))
            .unwrap();
        assert_eq!(m.resources[0].path.as_deref(), Some("/srv/h1/f"));
    }

    #[test]
    fn secret_references_are_untouched_by_overrides() {
        let d = tempfile::tempdir().unwrap();
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/secrets/go-recipient.age");
        std::fs::copy(&fixture, d.path().join("secret.age")).unwrap();
        let p = write(
            d.path(),
            "r.yaml",
            "version: 1\nvars:\n  root: { value: /srv }\nresources:\n  - id: f\n    type: file\n    with: { path: \"{{ vars.root }}/f\", content: { secret: secret.age } }\n",
        );
        let pr = prepare(&p).unwrap();
        let base = pr.clone().freeze_default().unwrap();
        let m = pr
            .freeze_with(&ov(&[("root", s("/srv/h1"))], "hosts.h1"))
            .unwrap();
        assert_eq!(m.resources[0].path.as_deref(), Some("/srv/h1/f"));
        assert_eq!(
            format!("{:?}", m.resources[0].secret),
            format!("{:?}", base.resources[0].secret)
        );
        assert!(m.resources[0].secret.is_some() && m.resources[0].derived_sensitive);
        // A reference is a static literal: a variable can never select it.
        let p = write(
            d.path(),
            "dyn.yaml",
            "version: 1\nvars:\n  ref: { value: secret.age }\nresources:\n  - id: f\n    type: file\n    with: { path: /etc/f, content: { secret: \"{{ vars.ref }}\" } }\n",
        );
        let established = load_model(&p).unwrap_err().message;
        let e = prepare(&p)
            .map(|pr| pr.freeze_with(&ov(&[("ref", s(CANARY))], "vars")))
            .and_then(|r| r.map(|_| ()))
            .unwrap_err();
        assert_eq!(e.message, established);
        assert!(!e.message.contains(CANARY));
    }
}
