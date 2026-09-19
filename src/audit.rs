//! Sinter Audit: a read-only Configuration Audit.
//!
//! Audit determines whether safely observable current configuration satisfies
//! the desired configuration expressed by an existing Sinter recipe. It shares
//! resource *semantics* with Plan/Apply through a neutral observation and
//! comparison boundary, but it never inherits repair-oriented behavior and it
//! never mutates the target.
//!
//! Safety is enforced structurally, not by convention:
//!
//! * Audit drives a [`TargetFs`](crate::targetfs::TargetFs) constructed in
//!   read-only mode. No code on the Audit path constructs a
//!   [`MutationPermit`](crate::targetfs::MutationPermit) — the token has a
//!   private constructor and is not `Clone`/`Copy`, so within this control
//!   flow there is no way to name a value of the type — and every mutation
//!   method plus the raw execution channel additionally requires a borrowed
//!   permit, which a read-only target never yields: `TargetFs::mutation_permit`
//!   returns `Err` at runtime and every mutation channel fails closed.
//! * Audit never runs the [`Engine`]'s Plan/Apply dispatch; it uses its own
//!   observation-only control strategy so dependency drift never stops an
//!   independently safe observation, and `Mode` is never consulted to mean
//!   "anything other than Plan implies Apply".
//! * `command` resources are never executed; they are always
//!   [`AuditResourceStatus::NotAuditable`]. Handlers are never queued or run.
//!
//! Incomplete, truncated, malformed, or ambiguous evidence never produces
//! `Compliant`: every required observation either establishes the actual
//! state well enough to compare it, or the result is `Error`. Known
//! non-compliance is `Drift`; an observation that could not determine the
//! state is `Error`.

use crate::engine::Engine;
use crate::error::{Result, SinterError};
use crate::executor::CommandRecord;
use crate::model::FrozenResource;
use std::collections::BTreeMap;

/// The compliance outcome of auditing a single resource.
///
/// This is deliberately independent of the Plan/Apply `ResourceResult`: Plan
/// answers "what would repair do", whereas Audit answers "does the safely
/// observable current state satisfy the desired state".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditResourceStatus {
    /// Observed state satisfies the desired state.
    Compliant,
    /// Observation established that the desired state is not satisfied.
    Drift,
    /// The resource cannot be audited without performing an action Audit never
    /// performs (e.g. executing a `command` resource), or a required value
    /// cannot be produced without such an action.
    NotAuditable,
    /// The resource's `when` condition evaluated to false, so it is out of
    /// scope for this Audit run.
    NotApplicable,
    /// A required observation could not be completed (e.g. content could not
    /// be read or hashed, a query failed), or an expression/evaluation error
    /// occurred. Distinct from `Drift`: an observation failure is never
    /// reported as drift.
    Error,
}

impl AuditResourceStatus {
    pub fn label(self) -> &'static str {
        match self {
            AuditResourceStatus::Compliant => "PASS",
            AuditResourceStatus::Drift => "DRIFT",
            AuditResourceStatus::NotAuditable => "NOT_AUDITABLE",
            AuditResourceStatus::NotApplicable => "NOT_APPLICABLE",
            AuditResourceStatus::Error => "ERROR",
        }
    }
}

/// A single drift facet for a resource. Raw expected/actual values are only
/// ever retained for non-sensitive resources; for sensitive resources the
/// detail is redacted at construction (RA-06), never merely at render time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditDriftDetail {
    /// The dimension that differs: e.g. "type", "content", "mode", "owner",
    /// "group", "target", "state", "enabled", "package".
    pub dimension: String,
    /// Human-readable observed value, or a redacted placeholder.
    pub observed: String,
    /// Human-readable desired value, or a redacted placeholder.
    pub desired: String,
}

impl AuditDriftDetail {
    /// Build a detail, redacting both sides when the resource is sensitive.
    fn new(dimension: &str, observed: String, desired: String, sensitive: bool) -> Self {
        if sensitive {
            AuditDriftDetail {
                dimension: dimension.to_string(),
                observed: "[redacted]".to_string(),
                desired: "[redacted]".to_string(),
            }
        } else {
            AuditDriftDetail {
                dimension: dimension.to_string(),
                observed,
                desired,
            }
        }
    }
}

/// The audit outcome for one resource. Renderer-, CLI-, and
/// transport-independent. For a sensitive resource no raw secret expected or
/// actual value is retained anywhere in this structure.
#[derive(Debug, Clone)]
pub struct AuditResourceResult {
    pub id: String,
    pub type_: String,
    pub origin: String,
    pub status: AuditResourceStatus,
    /// True when this resource is (or derives from) sensitive input. When set,
    /// `details` contain only redacted placeholders and `reason` never carries
    /// a secret.
    pub sensitive: bool,
    /// Drift facets for `Drift`; empty otherwise. Redacted when `sensitive`.
    pub details: Vec<AuditDriftDetail>,
    /// Optional explanatory text. Never carries a secret for sensitive
    /// resources.
    pub reason: Option<String>,
    pub loop_index: Option<usize>,
}

impl AuditResourceResult {
    fn base(res: &FrozenResource, status: AuditResourceStatus, sensitive: bool) -> Self {
        AuditResourceResult {
            id: res.id.clone(),
            type_: res.type_.clone(),
            origin: res.origin.clone(),
            status,
            sensitive,
            details: Vec::new(),
            reason: None,
            loop_index: res.loop_index,
        }
    }

    /// Render the one-line human form, e.g. `DRIFT motd [file]`. Sensitive
    /// resources render `details: redacted` instead of any value.
    pub fn render_line(&self) -> String {
        let mut line = format!("{} {} [{}]", self.status.label(), self.id, self.type_);
        if self.sensitive && self.status == AuditResourceStatus::Drift {
            line.push_str("\n    details: redacted");
        }
        line
    }
}

/// Deterministic summary derived from per-resource results.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditSummary {
    pub total: usize,
    pub compliant: usize,
    pub drifted: usize,
    pub not_auditable: usize,
    pub not_applicable: usize,
    pub errors: usize,
}

impl AuditSummary {
    pub fn from_results(results: &[AuditResourceResult]) -> Self {
        let mut s = AuditSummary {
            total: results.len(),
            ..Default::default()
        };
        for r in results {
            match r.status {
                AuditResourceStatus::Compliant => s.compliant += 1,
                AuditResourceStatus::Drift => s.drifted += 1,
                AuditResourceStatus::NotAuditable => s.not_auditable += 1,
                AuditResourceStatus::NotApplicable => s.not_applicable += 1,
                AuditResourceStatus::Error => s.errors += 1,
            }
        }
        s
    }

    /// True when the audit completed with no auditable drift and no errors.
    /// `NotAuditable` and `NotApplicable` alone do not constitute drift.
    pub fn no_drift(&self) -> bool {
        self.drifted == 0 && self.errors == 0
    }
}

/// An Audit report. The JSON form is built explicitly by the output layer
/// (no `Serialize` is derived here), so this structure stays free to evolve.
#[derive(Debug, Clone)]
pub struct AuditReport {
    pub resources: Vec<AuditResourceResult>,
    pub summary: AuditSummary,
    /// Full log of the raw commands dispatched (instrumentation), used by
    /// tests to prove every dispatched command is an observation.
    pub commands: Vec<CommandRecord>,
}

impl AuditReport {
    /// Deterministic human renderer backing `sinter audit --format text`.
    /// Sensitive resources never print raw values.
    pub fn render_text(&self) -> String {
        let mut out = String::from("== Sinter AUDIT ==\n");
        for r in &self.resources {
            out.push_str(&r.render_line());
            out.push('\n');
            if !r.sensitive {
                for d in &r.details {
                    out.push_str(&format!(
                        "    {}: observed={} desired={}\n",
                        d.dimension, d.observed, d.desired
                    ));
                }
            }
            if let Some(reason) = &r.reason {
                out.push_str(&format!("    reason: {}\n", reason));
            }
        }
        let s = &self.summary;
        out.push_str(&format!(
            "summary: {} total, {} compliant, {} drifted, {} not_auditable, {} not_applicable, {} errors\n",
            s.total, s.compliant, s.drifted, s.not_auditable, s.not_applicable, s.errors
        ));
        out.push_str(&format!("status: {}\n", self.aggregate_label()));
        out
    }

    /// Aggregate label describing the audit outcome:
    /// `no_drift` (no drift and no errors), `drift` (drift, no errors), or
    /// `indeterminate` (at least one observation error — a verdict computed
    /// from failed observations is untrustworthy, so errors dominate drift).
    pub fn aggregate_label(&self) -> &'static str {
        if self.summary.errors > 0 {
            "indeterminate"
        } else if self.summary.drifted > 0 {
            "drift"
        } else {
            "no_drift"
        }
    }

    /// CLI exit code for this audit outcome. `0` means the audit completed
    /// with no detected drift and no observation errors — NOT_AUDITABLE and
    /// NOT_APPLICABLE resources do not affect it and stay visible in output.
    /// `7` means drift with a fully determined result; `6`
    /// ([`ErrorKind::Indeterminate`](crate::error::ErrorKind)) means at least
    /// one observation error, which always dominates drift.
    pub fn exit_code(&self) -> u8 {
        if self.summary.errors > 0 {
            crate::error::ErrorKind::Indeterminate.exit_code() as u8
        } else if self.summary.drifted > 0 {
            7
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 1B: structurally read-only Audit runner
// ---------------------------------------------------------------------------

use crate::expressions::EvalVal;
use crate::resources::{ev_bool, ev_str, sha256_hex, PackageState};
use crate::targetfs::ObjKind;
use crate::value::Value;

/// Run a read-only Configuration Audit over the model held by `engine`.
///
/// The engine's `TargetFs` must be in read-only mode (Plan/Audit construction)
/// so no mutation permit can be produced; every observation below uses only
/// the observation API surface. The Audit runner has its own control strategy
/// (RA-05): it visits resources in deterministic dependency/execution order —
/// dependencies are visited before resources that depend on them — never
/// applies Apply's fail-fast/dependency gating, and collects as much safely
/// observable drift as possible in one run.
pub fn run_audit(mut engine: Engine) -> Result<AuditReport> {
    // Fail closed: Audit must never run on a mutation-enabled TargetFs. If a
    // caller built the engine with Apply authority, a MutationPermit would be
    // obtainable here — refuse before any observation runs (RA-01/RA-02).
    if engine.fs.mutation_permit().is_ok() {
        return Err(SinterError::plan(
            "audit requires a read-only target: mutation authority is present",
        ));
    }
    // Every declared register is represented as Unknown — the same shape Plan
    // uses for a command it did not run — so `registers.x.*` expressions
    // evaluate to Unknown rather than "undefined register" errors. Audit then
    // classifies those consumers truthfully as NOT_AUDITABLE (§10 register).
    for res in &engine.model.resources {
        if let Some(reg) = &res.register {
            engine.registers.insert(reg.clone(), EvalVal::unknown());
        }
    }
    let mut results: Vec<AuditResourceResult> = Vec::new();
    // Dependency order is preserved for report ordering (§10) — the model is
    // already validated acyclic — but no dependency gates an observation:
    // every resource is visited independently (RA-05).
    let order = crate::engine::execution_order(&engine.model)?;
    for &ridx in &order {
        let res = engine.model.resources[ridx].clone();
        results.push(audit_resource(&mut engine, &res));
    }
    let summary = AuditSummary::from_results(&results);
    let commands = engine.fs.log();
    Ok(AuditReport {
        resources: results,
        summary,
        commands,
    })
}

/// Audit one resource. Never panics on a recipe/observation problem; every
/// failure is folded into a typed `Error`/`NotAuditable` result so one bad
/// resource does not abort the whole audit.
fn audit_resource(engine: &mut Engine, res: &FrozenResource) -> AuditResourceResult {
    let sensitive = res.sensitive || res.derived_sensitive;
    let item = res.loop_item.as_ref().map(|v| EvalVal::known(v.clone()));

    // `when` control flow (§7). Reuse the existing expression semantics via
    // Engine::eval_condition; do not build a second evaluator.
    match engine.eval_condition(res, item.as_ref()) {
        Ok(Some(false)) => {
            let mut r =
                AuditResourceResult::base(res, AuditResourceStatus::NotApplicable, sensitive);
            r.reason = Some("condition evaluated to false".to_string());
            return r;
        }
        Ok(None) => {
            // Unknown in audit almost always means a required register value is
            // unavailable because its producing command was not executed.
            let mut r =
                AuditResourceResult::base(res, AuditResourceStatus::NotAuditable, sensitive);
            r.reason =
                Some("when condition is unknown without executing a command register".to_string());
            return r;
        }
        Ok(Some(true)) => {}
        Err(e) => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some(redact_reason(sensitive, &e.message));
            return r;
        }
    }

    match res.type_.as_str() {
        "command" => {
            // Hard boundary (§6): a command resource is never executed. Guards
            // are not used to prove compliance; the resource is simply not
            // auditable. No program is dispatched.
            let mut r =
                AuditResourceResult::base(res, AuditResourceStatus::NotAuditable, sensitive);
            r.reason = Some("command resources are not executed during audit".to_string());
            r
        }
        "file" => audit_file(engine, res, item.as_ref(), sensitive),
        "template" => audit_template(engine, res, item.as_ref(), sensitive),
        "directory" => audit_directory(engine, res, item.as_ref(), sensitive),
        "link" => audit_link(engine, res, item.as_ref(), sensitive),
        "package" => audit_package(engine, res, item.as_ref(), sensitive),
        "service" => audit_service(engine, res, item.as_ref(), sensitive),
        other => {
            let mut r =
                AuditResourceResult::base(res, AuditResourceStatus::NotAuditable, sensitive);
            r.reason = Some(format!("resource type {} is not auditable", other));
            r
        }
    }
}

/// Redact a free-form reason string for sensitive resources. Observation
/// helpers already redact sensitive operands, so this is a conservative
/// defense-in-depth measure (RA-06).
fn redact_reason(sensitive: bool, msg: &str) -> String {
    if sensitive {
        "observation failed (details redacted)".to_string()
    } else {
        msg.to_string()
    }
}

/// Shared outcome of a filesystem metadata comparison (owner/group/mode).
fn compare_metadata(
    stat: &crate::targetfs::Stat,
    meta: &crate::resources::MetaSpec,
    sensitive: bool,
    details: &mut Vec<AuditDriftDetail>,
) {
    if meta.manage_owner {
        if let Some(uid) = meta.owner_uid {
            if stat.uid != uid {
                details.push(AuditDriftDetail::new(
                    "owner",
                    stat.uid.to_string(),
                    uid.to_string(),
                    sensitive,
                ));
            }
        }
    }
    if meta.manage_group {
        if let Some(gid) = meta.group_gid {
            if stat.gid != gid {
                details.push(AuditDriftDetail::new(
                    "group",
                    stat.gid.to_string(),
                    gid.to_string(),
                    sensitive,
                ));
            }
        }
    }
    if meta.manage_mode {
        if let Some(m) = meta.mode {
            if (stat.mode & 0o7777) != m {
                details.push(AuditDriftDetail::new(
                    "mode",
                    crate::paths::mode_to_string(stat.mode & 0o7777),
                    crate::paths::mode_to_string(m),
                    sensitive,
                ));
            }
        }
    }
}

/// Fold a `Result<T>` observation into either a value or an `Error` result,
/// preserving the drift-vs-error distinction (RA-04): a failed observation is
/// an `Error`, never drift. The `Err` variant is boxed to keep the (hot, Ok)
/// path small: it carries a full result struct only on failure.
fn obs_or_error<T>(
    res: &FrozenResource,
    sensitive: bool,
    r: Result<T>,
) -> std::result::Result<T, Box<AuditResourceResult>> {
    match r {
        Ok(v) => Ok(v),
        Err(e) => {
            // A required runtime value that is Unknown almost always means a
            // command `register` was intentionally not executed; the resource
            // is not auditable rather than erroneous (§10 register).
            let status = if e.kind == crate::error::ErrorKind::Unknown {
                AuditResourceStatus::NotAuditable
            } else {
                AuditResourceStatus::Error
            };
            let mut out = AuditResourceResult::base(res, status, sensitive);
            out.reason = Some(redact_reason(sensitive, &e.message));
            Err(Box::new(out))
        }
    }
}

/// Audit a `file` resource (and, via `audit_template`, the desired-state side
/// of a `template`). `desired` is the resolved desired content: `Some(bytes)`
/// when the recipe pins content, `None` when existing content is preserved.
fn audit_file_impl(
    engine: &mut Engine,
    res: &FrozenResource,
    item: Option<&EvalVal>,
    sensitive: bool,
    desired_override: Option<Option<Vec<u8>>>,
) -> AuditResourceResult {
    let path = match res.path.clone() {
        Some(p) => p,
        None => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some("file resource missing path".to_string());
            return r;
        }
    };
    let vals = match obs_or_error(res, sensitive, engine.eval_with(res, item)) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let state = match obs_or_error(res, sensitive, ev_str(&vals, "state")) {
        Ok(s) => s.map(|(s, _)| s).unwrap_or_else(|| "present".to_string()),
        Err(r) => return *r,
    };
    if state != "present" && state != "absent" {
        let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
        r.reason = Some("file state must be present or absent".to_string());
        return r;
    }
    let stat = match obs_or_error(res, sensitive, engine.fs.inspect(&path)) {
        Ok(s) => s,
        Err(r) => return *r,
    };

    if state == "absent" {
        return match stat.kind {
            ObjKind::Absent => {
                let mut r =
                    AuditResourceResult::base(res, AuditResourceStatus::Compliant, sensitive);
                r.reason = Some("path is absent as desired".to_string());
                r
            }
            other => {
                let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
                r.details.push(AuditDriftDetail::new(
                    "state",
                    other.describe().to_string(),
                    "absent".to_string(),
                    sensitive,
                ));
                r
            }
        };
    }

    // present
    match stat.kind {
        ObjKind::Absent => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
            r.details.push(AuditDriftDetail::new(
                "state",
                "absent".to_string(),
                "file".to_string(),
                sensitive,
            ));
            return r;
        }
        ObjKind::File => (),
        other => {
            // Wrong type: this is DRIFT, not a repair-feasibility error (RA-03).
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
            r.details.push(AuditDriftDetail::new(
                "type",
                other.describe().to_string(),
                "file".to_string(),
                sensitive,
            ));
            return r;
        }
    }

    // Resolve desired content.
    let desired: Option<Vec<u8>> = match desired_override {
        Some(d) => d,
        None => match obs_or_error(res, sensitive, engine.resolve_content(res, &vals)) {
            Ok(c) => c.bytes,
            Err(r) => return *r,
        },
    };

    let mut details: Vec<AuditDriftDetail> = Vec::new();

    // Content comparison. Unspecified content means existing content is
    // preserved, so arbitrary existing content is not drift (§5).
    if let Some(bytes) = &desired {
        let desired_sha = sha256_hex(bytes);
        // RA-04: distinguish "could not observe the hash" (Error) from
        // "observed hash differs" (Drift). TargetFs::sha256 collapses a
        // non-zero exit into None; treat that as an observation failure here,
        // not as a mismatch.
        match obs_or_error(res, sensitive, engine.fs.sha256(&path)) {
            Ok(Some(remote)) => {
                if remote != desired_sha {
                    details.push(AuditDriftDetail::new(
                        "content",
                        "sha256 differs".to_string(),
                        "sha256 matches desired".to_string(),
                        true, // never echo hashes; content may be large/secret-adjacent
                    ));
                }
            }
            Ok(None) => {
                let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
                r.reason = Some(if sensitive {
                    "could not read or hash content (path redacted)".to_string()
                } else {
                    format!("could not read or hash content of {}", path)
                });
                return r;
            }
            Err(r) => return *r,
        }
    }

    let meta = match obs_or_error(
        res,
        sensitive,
        engine.file_meta(res, &vals, ObjKind::File, sensitive),
    ) {
        Ok(m) => m,
        Err(r) => return *r,
    };
    compare_metadata(&stat, &meta, sensitive, &mut details);

    finish_drift(res, sensitive, details, "file matches desired state")
}

fn finish_drift(
    res: &FrozenResource,
    sensitive: bool,
    details: Vec<AuditDriftDetail>,
    compliant_reason: &str,
) -> AuditResourceResult {
    if details.is_empty() {
        let mut r = AuditResourceResult::base(res, AuditResourceStatus::Compliant, sensitive);
        r.reason = Some(compliant_reason.to_string());
        r
    } else {
        let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
        r.details = details;
        r
    }
}

fn audit_file(
    engine: &mut Engine,
    res: &FrozenResource,
    item: Option<&EvalVal>,
    sensitive: bool,
) -> AuditResourceResult {
    audit_file_impl(engine, res, item, sensitive, None)
}

/// Audit a `template`: render the desired bytes on the controller with the
/// exact current template/interpolation semantics, then run the neutral file
/// comparison. Application behavior represented by the template is never
/// executed.
fn audit_template(
    engine: &mut Engine,
    res: &FrozenResource,
    item: Option<&EvalVal>,
    sensitive: bool,
) -> AuditResourceResult {
    let source = match res.controller_source.clone() {
        Some(s) => s,
        None => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some("template missing source".to_string());
            return r;
        }
    };
    let template_text = match std::fs::read_to_string(&source) {
        Ok(t) => t,
        Err(e) => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some(if sensitive {
                "cannot read template (redacted)".to_string()
            } else {
                format!("cannot read template {}: {}", source.display(), e)
            });
            return r;
        }
    };
    // Template-local vars are literal and NOT interpolated (DESIGN §26.4).
    let mut tvals: BTreeMap<String, EvalVal> = BTreeMap::new();
    if let Some(Value::Map(m)) = res.with.get("vars") {
        for (k, v) in m {
            tvals.insert(k.clone(), EvalVal::known(v.clone()));
        }
    }
    let scope = engine.scope(item, None, Some(&tvals));
    let rendered = match crate::expressions::eval_interpolated(&template_text, &scope) {
        Ok(v) => match v.val {
            Some(Value::Str(s)) => s,
            Some(other) => other.canonical_scalar_string().unwrap_or_default(),
            None => {
                // The template depends on a value that is Unknown. Audit
                // never executes a `command` resource, so a register it
                // references is unavailable by design — this is the same
                // distinction used for `when` and for `with` values (§10
                // register): the template is NOT_AUDITABLE, not erroneous.
                // A genuine expression/render/type error takes the `Err`
                // branch below and remains ERROR.
                let mut r =
                    AuditResourceResult::base(res, AuditResourceStatus::NotAuditable, sensitive);
                r.reason = Some(
                    "template depends on a register value that is unavailable \
                     because audit does not execute commands"
                        .to_string(),
                );
                return r;
            }
        },
        Err(e) => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some(if sensitive {
                format!(
                    "template rendering error (value redacted): {}",
                    e.category()
                )
            } else {
                format!("template rendering error: {}", e)
            });
            return r;
        }
    };
    audit_file_impl(
        engine,
        res,
        item,
        sensitive,
        Some(Some(rendered.into_bytes())),
    )
}

fn audit_directory(
    engine: &mut Engine,
    res: &FrozenResource,
    item: Option<&EvalVal>,
    sensitive: bool,
) -> AuditResourceResult {
    let path = match res.path.clone() {
        Some(p) => p,
        None => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some("directory resource missing path".to_string());
            return r;
        }
    };
    let vals = match obs_or_error(res, sensitive, engine.eval_with(res, item)) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let state = match obs_or_error(res, sensitive, ev_str(&vals, "state")) {
        Ok(s) => s.map(|(s, _)| s).unwrap_or_else(|| "present".to_string()),
        Err(r) => return *r,
    };
    if state != "present" && state != "absent" {
        let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
        r.reason = Some("directory state must be present or absent".to_string());
        return r;
    }
    let stat = match obs_or_error(res, sensitive, engine.fs.inspect(&path)) {
        Ok(s) => s,
        Err(r) => return *r,
    };

    if state == "absent" {
        return match stat.kind {
            ObjKind::Absent => {
                let mut r =
                    AuditResourceResult::base(res, AuditResourceStatus::Compliant, sensitive);
                r.reason = Some("path is absent as desired".to_string());
                r
            }
            other => {
                let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
                r.details.push(AuditDriftDetail::new(
                    "state",
                    other.describe().to_string(),
                    "absent".to_string(),
                    sensitive,
                ));
                r
            }
        };
    }

    match stat.kind {
        ObjKind::Absent => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
            r.details.push(AuditDriftDetail::new(
                "state",
                "absent".to_string(),
                "directory".to_string(),
                sensitive,
            ));
            return r;
        }
        ObjKind::Dir => {}
        other => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
            r.details.push(AuditDriftDetail::new(
                "type",
                other.describe().to_string(),
                "directory".to_string(),
                sensitive,
            ));
            return r;
        }
    }

    let meta = match obs_or_error(res, sensitive, engine.dir_meta(res, &vals, ObjKind::Dir)) {
        Ok(m) => m,
        Err(r) => return *r,
    };
    let mut details = Vec::new();
    compare_metadata(&stat, &meta, sensitive, &mut details);
    finish_drift(res, sensitive, details, "directory matches desired state")
}

fn audit_link(
    engine: &mut Engine,
    res: &FrozenResource,
    item: Option<&EvalVal>,
    sensitive: bool,
) -> AuditResourceResult {
    let path = match res.path.clone() {
        Some(p) => p,
        None => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some("link resource missing path".to_string());
            return r;
        }
    };
    let vals = match obs_or_error(res, sensitive, engine.eval_with(res, item)) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let state = match obs_or_error(res, sensitive, ev_str(&vals, "state")) {
        Ok(s) => s.map(|(s, _)| s).unwrap_or_else(|| "present".to_string()),
        Err(r) => return *r,
    };
    let target = match obs_or_error(res, sensitive, ev_str(&vals, "target")) {
        Ok(t) => t,
        Err(r) => return *r,
    };
    let stat = match obs_or_error(res, sensitive, engine.fs.inspect(&path)) {
        Ok(s) => s,
        Err(r) => return *r,
    };

    if state == "absent" {
        return match stat.kind {
            ObjKind::Absent => {
                let mut r =
                    AuditResourceResult::base(res, AuditResourceStatus::Compliant, sensitive);
                r.reason = Some("path is absent as desired".to_string());
                r
            }
            other => {
                let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
                r.details.push(AuditDriftDetail::new(
                    "state",
                    other.describe().to_string(),
                    "absent".to_string(),
                    sensitive,
                ));
                r
            }
        };
    }

    let (target_val, target_sens) = match target {
        Some(t) => t,
        None => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some("link target is required when present".to_string());
            return r;
        }
    };
    let link_sensitive = sensitive || target_sens;

    match stat.kind {
        ObjKind::Absent => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, link_sensitive);
            r.details.push(AuditDriftDetail::new(
                "state",
                "absent".to_string(),
                format!("symlink -> {}", target_val),
                link_sensitive,
            ));
            r
        }
        ObjKind::Symlink => {
            // Read the link's target string only. A dangling link whose target
            // string matches is compliant with the link resource itself; the
            // target object's existence is not implicitly audited (§5).
            let cur = match obs_or_error(res, link_sensitive, engine.fs.readlink(&path)) {
                Ok(c) => c,
                Err(r) => return *r,
            };
            if cur == target_val {
                let mut r =
                    AuditResourceResult::base(res, AuditResourceStatus::Compliant, link_sensitive);
                r.reason = Some("symlink points to desired target".to_string());
                r
            } else {
                let mut r =
                    AuditResourceResult::base(res, AuditResourceStatus::Drift, link_sensitive);
                r.details.push(AuditDriftDetail::new(
                    "target",
                    cur,
                    target_val,
                    link_sensitive,
                ));
                r
            }
        }
        other => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, link_sensitive);
            r.details.push(AuditDriftDetail::new(
                "type",
                other.describe().to_string(),
                "symlink".to_string(),
                link_sensitive,
            ));
            r
        }
    }
}

fn audit_package(
    engine: &mut Engine,
    res: &FrozenResource,
    item: Option<&EvalVal>,
    sensitive: bool,
) -> AuditResourceResult {
    let name = match res.package_name.clone() {
        Some(n) => n,
        None => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some("package resource missing name".to_string());
            return r;
        }
    };
    let vals = match obs_or_error(res, sensitive, engine.eval_with(res, item)) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let state = match obs_or_error(res, sensitive, ev_str(&vals, "state")) {
        Ok(s) => s.map(|(s, _)| s),
        Err(r) => return *r,
    };
    let state = match state {
        Some(s) => s,
        None => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some("package state is required".to_string());
            return r;
        }
    };
    if state != "present" && state != "absent" {
        let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
        r.reason = Some("package state must resolve to present or absent".to_string());
        return r;
    }
    // env is a mutation-only field (it feeds the package manager at
    // install/remove time); it is not a desired-state audit dimension (§5).
    let backend = match engine.fs.pkg_backend {
        Some(b) => b,
        None => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some("package resources require a supported target platform".to_string());
            return r;
        }
    };
    let observed = match obs_or_error(
        res,
        sensitive,
        engine.observe_package_sensitive(backend, &name, sensitive),
    ) {
        Ok(o) => o,
        Err(r) => return *r,
    };
    let want_installed = state == "present";
    let is_installed = matches!(observed, PackageState::Installed);
    if want_installed == is_installed {
        let mut r = AuditResourceResult::base(res, AuditResourceStatus::Compliant, sensitive);
        r.reason = Some("package already in desired state".to_string());
        r
    } else {
        let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
        r.details.push(AuditDriftDetail::new(
            "package",
            if is_installed { "installed" } else { "absent" }.to_string(),
            if want_installed {
                "installed"
            } else {
                "absent"
            }
            .to_string(),
            sensitive,
        ));
        r
    }
}

fn audit_service(
    engine: &mut Engine,
    res: &FrozenResource,
    item: Option<&EvalVal>,
    sensitive: bool,
) -> AuditResourceResult {
    let name = match res.service_name.clone() {
        Some(n) => n,
        None => {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some("service resource missing name".to_string());
            return r;
        }
    };
    let vals = match obs_or_error(res, sensitive, engine.eval_with(res, item)) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let want_state = match obs_or_error(res, sensitive, ev_str(&vals, "state")) {
        Ok(s) => s.map(|(s, _)| s),
        Err(r) => return *r,
    };
    let want_enabled = match obs_or_error(res, sensitive, ev_bool(&vals, "enabled")) {
        Ok(b) => b,
        Err(r) => return *r,
    };
    if let Some(state) = &want_state {
        if state != "running" && state != "stopped" {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Error, sensitive);
            r.reason = Some("service state must resolve to running or stopped".to_string());
            return r;
        }
    }
    let obs = match obs_or_error(
        res,
        sensitive,
        engine.observe_service_sensitive(&name, sensitive),
    ) {
        Ok(o) => o,
        Err(r) => return *r,
    };

    let unit_disp = || {
        if sensitive {
            "[redacted]".to_string()
        } else {
            name.clone()
        }
    };

    // Missing/static/masked units are compliance facts, not repair-feasibility
    // errors (RA-03). A declared state/enablement that cannot hold is DRIFT.
    if obs.load_state == "not-found" {
        let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
        r.details.push(AuditDriftDetail::new(
            "state",
            format!("unit {} not found", unit_disp()),
            "present".to_string(),
            true, // unit_disp already encodes sensitivity; keep conservative
        ));
        r.reason = Some("service unit was not found".to_string());
        return r;
    }
    if want_state.as_deref() == Some("running") && obs.unit_file_state == "masked" {
        let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
        r.details.push(AuditDriftDetail::new(
            "state",
            format!("unit {} is masked", unit_disp()),
            "running".to_string(),
            true,
        ));
        r.reason = Some("service is masked and cannot be running".to_string());
        return r;
    }
    if obs.unit_file_state == "static" {
        if let Some(want) = want_enabled {
            let mut r = AuditResourceResult::base(res, AuditResourceStatus::Drift, sensitive);
            r.details.push(AuditDriftDetail::new(
                "enabled",
                format!("unit {} is static", unit_disp()),
                format!("enabled={}", want),
                true,
            ));
            r.reason = Some("service is static and cannot be enabled/disabled".to_string());
            return r;
        }
    }

    let mut details: Vec<AuditDriftDetail> = Vec::new();
    if let Some(want) = &want_state {
        let running = obs.active_state == "active";
        let failed = obs.active_state == "failed";
        let matches = if want == "running" {
            running && !failed
        } else {
            obs.active_state == "inactive" && !failed
        };
        if !matches {
            details.push(AuditDriftDetail::new(
                "state",
                obs.active_state.clone(),
                want.clone(),
                sensitive,
            ));
        }
    }
    if let Some(want) = want_enabled {
        let enabled = obs.unit_file_state == "enabled";
        if enabled != want {
            details.push(AuditDriftDetail::new(
                "enabled",
                obs.unit_file_state.clone(),
                want.to_string(),
                sensitive,
            ));
        }
    }
    finish_drift(res, sensitive, details, "service matches desired state")
}
