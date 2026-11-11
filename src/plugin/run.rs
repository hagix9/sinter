//! Plugin resource types in plan, apply and audit (DESIGN §38.10, §38.11).
//!
//! Plan and audit run prechecks and observe operations only, through the
//! observe channel, which needs no permit. Apply observes first, runs a
//! facet's mutate operation only when its observed state differs from the
//! wanted one (through the mutate channel, with the permit), observes that
//! facet again, and stops on the first failure. An unknown completion after
//! a mutation is Indeterminate and is never retried.

use super::exec::{
    classify_mutation, classify_observation, MutateCall, Mutated, ObserveCall, Observed,
};
use super::verify::{ResourceType, VerifiedCatalog, VerifiedOp, VerifiedPlugin, Want};
use super::PluginSet;
use crate::engine::{Engine, Mode};
use crate::error::{Result, SinterError};
use crate::expressions::EvalVal;
use crate::model::FrozenResource;
use crate::result::{Change, Diff, DiffBody, Disposition, Execution, ResourceResult, Verification};
use std::collections::BTreeMap;
use std::sync::Arc;

/// One facet as observed now.
#[derive(Debug, Clone)]
pub(crate) struct FacetState {
    pub name: String,
    pub observed: String,
    pub want: String,
    observe_op: String,
    ensure_op: Option<String>,
}

/// Everything plan, apply and audit need after observing a resource.
pub(crate) struct Observation {
    set: Arc<PluginSet>,
    values: BTreeMap<String, String>,
    pub sensitive: bool,
    pub facets: Vec<FacetState>,
    /// `plugin firewalld@0.1.0 (catalog firewalld@0.1.0)`, for messages.
    pub origin: String,
    /// The machine-readable provenance results carry (DESIGN §38.11):
    /// `plugin=<id>@<ver> plugin_sha256=<hex> catalog=<id>@<ver>
    /// catalog_sha256=<hex> registry=first-party`.
    pub provenance: String,
    /// Operation ids run so far, in order.
    pub ops_run: Vec<String>,
}

fn withheld(sensitive: bool, msg: String) -> String {
    if sensitive {
        "plugin operation failed (details withheld: the resource is sensitive)".to_string()
    } else {
        msg
    }
}

/// The plugin, its catalog and the type that provide `type_`.
fn resolve<'a>(
    set: &'a PluginSet,
    res: &FrozenResource,
) -> Result<(&'a VerifiedPlugin, &'a VerifiedCatalog, &'a ResourceType)> {
    let unknown =
        || SinterError::schema(format!("{}: unknown resource type {}", res.id, res.type_));
    let (plugin, rtype) = set.resource_type(&res.type_).ok_or_else(unknown)?;
    let catalog = set.catalog(plugin.catalog()).ok_or_else(unknown)?;
    Ok((plugin, catalog, rtype))
}

fn op<'a>(catalog: &'a VerifiedCatalog, id: &str) -> Result<&'a VerifiedOp> {
    catalog.op(id).ok_or_else(|| {
        SinterError::apply(format!(
            "internal error: plugin operation {} is not in the verified catalog",
            id
        ))
    })
}

impl Engine {
    /// Observe one operation through the observe channel. The error text
    /// never carries standard error, standard output or a value.
    fn plugin_observe_op(
        &mut self,
        op: &VerifiedOp,
        values: &BTreeMap<String, String>,
        sensitive: bool,
    ) -> std::result::Result<String, String> {
        let call = ObserveCall::new(op, values, sensitive).map_err(|e| e.message)?;
        match self.fs.plugin_observe(&call) {
            Ok(out) => match classify_observation(op, values, &out) {
                Observed::State(s) => Ok(s),
                Observed::Error(m) => Err(m),
            },
            Err(e) => Err(format!(
                "observation {} could not be run: {}",
                call.op_id(),
                e.message
            )),
        }
    }

    /// Evaluate the resource's values, run its prechecks and observe every
    /// facet. Shared by plan, apply and audit; it never mutates.
    pub(crate) fn plugin_observe_resource(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<Observation> {
        let set = self.model.plugins.clone().ok_or_else(|| {
            SinterError::schema(format!("{}: unknown resource type {}", res.id, res.type_))
        })?;
        let (plugin, catalog, rtype) = resolve(&set, res)?;
        let origin = format!(
            "plugin {}@{} (catalog {}@{})",
            plugin.id(),
            plugin.version(),
            catalog.id(),
            catalog.version()
        );
        let provenance = format!(
            "plugin={}@{} plugin_sha256={} catalog={}@{} catalog_sha256={} registry=first-party",
            plugin.id(),
            plugin.version(),
            plugin.sha256(),
            catalog.id(),
            catalog.version(),
            catalog.sha256()
        );
        let evaluated = self.eval_with(res, item)?;
        let mut sensitive = res.sensitive || res.derived_sensitive;
        let mut values = BTreeMap::new();
        for field in rtype.fields().keys() {
            match crate::resources::ev_str(&evaluated, field)? {
                Some((v, s)) => {
                    sensitive |= s;
                    values.insert(field.clone(), v);
                }
                None => {
                    return Err(SinterError::apply(format!(
                        "{}: with.{} is required",
                        res.id, field
                    )))
                }
            }
        }
        rtype
            .check_values(&values)
            .map_err(|e| SinterError::apply(format!("{}: {}", res.id, e.message)))?;
        let mut ops_run = Vec::new();
        for (op_id, expect) in rtype.prechecks() {
            let o = op(catalog, op_id)?;
            ops_run.push(op_id.clone());
            match self.plugin_observe_op(o, &values, sensitive) {
                Ok(state) if &state == expect => {}
                Ok(state) => {
                    return Err(SinterError::apply(withheld(
                        sensitive,
                        format!(
                            "{}: precondition {} is {}, expected {} ({})",
                            res.id, op_id, state, expect, origin
                        ),
                    )))
                }
                Err(m) => {
                    return Err(SinterError::apply(withheld(
                        sensitive,
                        format!("{}: {} ({})", res.id, m, origin),
                    )))
                }
            }
        }
        let mut facets = Vec::new();
        for f in rtype.facets() {
            let want = match f.want() {
                Want::State(s) => s.clone(),
                Want::Field(field) => values.get(field).cloned().unwrap_or_default(),
            };
            let o = op(catalog, f.observe_op())?;
            ops_run.push(f.observe_op().to_string());
            let observed = self.plugin_observe_op(o, &values, sensitive).map_err(|m| {
                SinterError::apply(withheld(
                    sensitive,
                    format!("{}: facet {}: {} ({})", res.id, f.name(), m, origin),
                ))
            })?;
            facets.push(FacetState {
                name: f.name().to_string(),
                ensure_op: f.ensure_op(&want).map(str::to_string),
                observe_op: f.observe_op().to_string(),
                observed,
                want,
            });
        }
        Ok(Observation {
            set,
            values,
            sensitive,
            facets,
            origin,
            provenance,
            ops_run,
        })
    }

    /// `dispatch_resource` for a plugin type (plan and apply).
    pub(crate) fn run_plugin(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        // C1: the run-level gate refused this already; checked again here,
        // before anything about this resource is observed or changed.
        if let Some(set) = self.model.plugins.clone() {
            let missing = unallowed_mutations(&set, res);
            if !missing.is_empty() {
                return Err(SinterError::schema(format!(
                    "{}: resource type {} could need mutate operations the trust file does not allow: {}",
                    res.id,
                    res.type_,
                    missing.join(", ")
                )));
            }
        }
        let mut obs = self.plugin_observe_resource(res, item)?;
        let sensitive = obs.sensitive;
        let pending: Vec<FacetState> = obs
            .facets
            .iter()
            .filter(|f| f.observed != f.want)
            .cloned()
            .collect();
        let summary = |facets: &[FacetState], observed: bool| {
            facets
                .iter()
                .map(|f| {
                    format!(
                        "{}={}",
                        f.name,
                        if observed { &f.observed } else { &f.want }
                    )
                })
                .collect::<Vec<_>>()
                .join(" ")
        };
        if pending.is_empty() {
            let mut r = result(
                res,
                sensitive,
                Execution::Succeeded,
                Change::None,
                Verification::Verified,
            );
            r.reason = Some("plugin resource already matches the desired state".into());
            r.notes.push(format!(
                "{} observed={} verified=yes",
                obs.provenance,
                obs.ops_run.join(",")
            ));
            return Ok(r);
        }
        if self.opts.mode == Mode::Plan {
            let mut r = result(
                res,
                sensitive,
                Execution::Succeeded,
                Change::Changed,
                Verification::NotPerformed,
            );
            r.diff = Some(Diff {
                body: if sensitive {
                    DiffBody::Redacted
                } else {
                    DiffBody::Summary {
                        current: summary(&obs.facets, true),
                        desired: summary(&obs.facets, false),
                    }
                },
            });
            let would: Vec<String> = pending.iter().filter_map(|f| f.ensure_op.clone()).collect();
            r.notes.push(format!(
                "{} observed={} would_run={}",
                obs.provenance,
                obs.ops_run.join(","),
                would.join(",")
            ));
            return Ok(r);
        }

        // Apply.
        let permit = self.fs.mutation_permit()?;
        let set = obs.set.clone();
        let (_, catalog, _) = resolve(&set, res)?;
        let mut changed_any = false;
        let mut done = Vec::new();
        let mark = |e: SinterError, changed_any: bool, dispatched: bool| {
            if changed_any {
                e.changed()
            } else if dispatched {
                e.possible()
            } else {
                e
            }
        };
        for f in &pending {
            let Some(ensure) = &f.ensure_op else {
                return Err(mark(
                    SinterError::apply(format!(
                        "{}: facet {} has no operation for its wanted state",
                        res.id, f.name
                    )),
                    changed_any,
                    false,
                ));
            };
            let mop = op(catalog, ensure)?;
            let call = MutateCall::new(mop, &obs.values, sensitive)
                .map_err(|e| mark(e, changed_any, false))?;
            obs.ops_run.push(ensure.clone());
            let outcome = match self.fs.plugin_mutate(&permit, &call) {
                Ok(out) => classify_mutation(mop, &out),
                // A transport failure is treated as dispatched: Sinter never
                // claims that nothing changed when it cannot know.
                Err(e) => Mutated::Unknown(format!(
                    "operation {} could not be completed: {} (not retried)",
                    call.op_id(),
                    e.message
                )),
            };
            match outcome {
                Mutated::Ok => {}
                Mutated::Failed(m) => {
                    return Err(mark(
                        SinterError::apply(withheld(
                            sensitive,
                            format!("{}: {} ({})", res.id, m, obs.origin),
                        )),
                        changed_any,
                        true,
                    ))
                }
                Mutated::Unknown(m) => {
                    return Err(mark(
                        SinterError::indeterminate(withheld(
                            sensitive,
                            format!("{}: {} ({})", res.id, m, obs.origin),
                        )),
                        changed_any,
                        true,
                    ))
                }
            }
            // Observe the facet again: success means the wanted state.
            let oop = op(catalog, &f.observe_op)?;
            obs.ops_run.push(f.observe_op.clone());
            match self.plugin_observe_op(oop, &obs.values, sensitive) {
                Ok(state) if state == f.want => {
                    changed_any = true;
                    done.push(f.name.clone());
                }
                Ok(state) => {
                    return Err(mark(
                        SinterError::apply(withheld(
                            sensitive,
                            format!(
                                "{}: after {} facet {} is {}, not {} ({})",
                                res.id, ensure, f.name, state, f.want, obs.origin
                            ),
                        )),
                        changed_any,
                        true,
                    ))
                }
                Err(m) => {
                    return Err(mark(
                        SinterError::indeterminate(withheld(
                            sensitive,
                            format!(
                                "{}: {} reported success but facet {} could not be observed again: {} ({})",
                                res.id, ensure, f.name, m, obs.origin
                            ),
                        )),
                        changed_any,
                        true,
                    ))
                }
            }
        }
        let mut r = result(
            res,
            sensitive,
            Execution::Succeeded,
            Change::Changed,
            Verification::Verified,
        );
        r.notes.push(format!(
            "{} ran={} verified={}",
            obs.provenance,
            obs.ops_run.join(","),
            done.join(",")
        ));
        Ok(r)
    }
}

fn result(
    res: &FrozenResource,
    sensitive: bool,
    execution: Execution,
    change: Change,
    verification: Verification,
) -> ResourceResult {
    ResourceResult {
        id: res.id.clone(),
        type_: res.type_.clone(),
        origin: res.origin.clone(),
        execution,
        change,
        verification,
        disposition: Disposition::Normal,
        reason: None,
        unknown: false,
        sensitive,
        diff: None,
        notes: Vec::new(),
        handler_notifications: Vec::new(),
        loop_index: res.loop_index,
    }
}

/// The mutate operations a plugin resource could need that the trust file
/// does not allow (C1, DESIGN §38.4), sorted and without repetition. Static:
/// for each facet, the ensure operation of every state the resource may want.
/// A wanted state that is a literal enum value names one operation; a value
/// with `{{ }}`, or a missing one, counts as every value of the field. A type
/// no enabled plugin provides needs nothing here (it is refused elsewhere).
pub(crate) fn unallowed_mutations(set: &PluginSet, res: &FrozenResource) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    let Ok((_, catalog, rtype)) = resolve(set, res) else {
        return Vec::new();
    };
    for f in rtype.facets() {
        let wanted: Vec<String> = match f.want() {
            Want::State(s) => vec![s.clone()],
            Want::Field(field) => match res.with.get(field) {
                Some(crate::value::Value::Str(v)) if !crate::expressions::has_interpolation(v) => {
                    vec![v.clone()]
                }
                _ => match rtype.fields().get(field) {
                    Some(super::verify::FieldKind::Enum(values)) => values.clone(),
                    _ => Vec::new(),
                },
            },
        };
        for state in &wanted {
            // Verification guarantees an ensure operation for every value a
            // facet can want; one that is somehow missing counts as needed and
            // not allowed, so the resource is refused rather than run.
            match f.ensure_op(state) {
                Some(id) => {
                    if !catalog.op(id).is_some_and(|o| o.is_enabled()) {
                        out.insert(id.to_string());
                    }
                }
                None => {
                    // Names the facet, never the value (DESIGN §38.9).
                    out.insert(format!("(no operation for a state of facet {})", f.name()));
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Refuse, before any target is contacted, a model that plan or apply could
/// not finish because a plugin resource could need a mutate operation the
/// trust file does not allow (C1, DESIGN §38.4, §38.11). Every resource is
/// checked, whatever it will observe, so a run never stops part-way with
/// some changes made for want of a permission. Exit 2. audit does not call
/// this: it never runs a mutate operation.
pub fn require_allowed_mutations(model: &crate::model::Model) -> Result<()> {
    let Some(set) = model.plugins.as_deref() else {
        return Ok(());
    };
    for res in &model.resources {
        if !is_plugin_type(&res.type_) {
            continue;
        }
        let missing = unallowed_mutations(set, res);
        if !missing.is_empty() {
            return Err(SinterError::schema(format!(
                "{}: resource type {} could need mutate operations the trust file does not allow: {}; plan and apply refuse it before contacting any target (allow them under allowed_mutate, or use audit, which runs observe operations only)",
                res.id,
                res.type_,
                missing.join(", ")
            )));
        }
    }
    Ok(())
}

/// Whether a frozen type name is a plugin type (`<plugin>.<name>`). Built-in
/// type names never contain a dot (DESIGN §38.6).
pub(crate) fn is_plugin_type(type_: &str) -> bool {
    type_.contains('.')
}
