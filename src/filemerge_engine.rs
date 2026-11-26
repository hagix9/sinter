//! Plan, apply and audit of `file_merge`.
//!
//! The file is observed through the `file` resource's parent gate
//! ([`Engine::partial_observe`]), the edit is computed by the pure
//! [`crate::filemerge`] module, and the result is published through the
//! `file` resource's own path ([`Engine::partial_publish`]): the same parent
//! checks, staging, atomic replacement, identity re-check, metadata rules and
//! verification. Nothing here writes on its own.

use std::collections::BTreeMap;

use crate::audit::{AuditDriftDetail, AuditResourceResult, AuditResourceStatus};
use crate::engine::{Engine, Mode};
use crate::error::{ErrorKind, Result, SinterError};
use crate::expressions::EvalVal;
use crate::filemerge::{apply_edit, Edit, MergeSpec, MergeState};
use crate::model::FrozenResource;
use crate::paths::mode_to_string;
use crate::result::{DiffBody, ResourceResult};
use crate::targetfs::{ObjKind, Observed, Stat};
use crate::value::Value;

/// The fully checked spec of an evaluated `file_merge`. An unknown value
/// stops the resource as for every other type.
fn evaluated_spec(res: &FrozenResource, vals: &BTreeMap<String, EvalVal>) -> Result<MergeSpec> {
    let mut plain: BTreeMap<String, Value> = BTreeMap::new();
    for (k, v) in vals {
        match &v.val {
            Some(x) => {
                plain.insert(k.clone(), x.clone());
            }
            None => {
                return Err(SinterError::unknown(format!(
                    "with.{} could not be evaluated (unknown)",
                    k
                )))
            }
        }
    }
    MergeSpec::check(&plain, &res.id, false)?.ok_or_else(|| {
        SinterError::apply(format!(
            "{}: file_merge fields are not fully evaluated",
            res.id
        ))
    })
}

/// A resource is sensitive when it says so, when a field references a
/// sensitive variable, or when an evaluated field carries a sensitive value.
fn effective_sensitivity(res: &FrozenResource, vals: &BTreeMap<String, EvalVal>) -> bool {
    res.sensitive || res.derived_sensitive || vals.values().any(|v| v.sensitive)
}

fn missing_path(res: &FrozenResource) -> SinterError {
    SinterError::schema(format!("{}: file_merge resource missing path", res.id))
}

impl Engine {
    pub(crate) fn run_file_merge(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let path = res.path.clone().ok_or_else(|| missing_path(res))?;
        let vals = self.eval_with(res, item)?;
        let sensitive = effective_sensitivity(res, &vals);
        if sensitive {
            // What the filesystem layer refuses from here on names no path
            // or uid either (the dispatcher resets this).
            self.fs.set_redact(true);
        }
        let spec = evaluated_spec(res, &vals)?;
        let (stat, current) = self.partial_observe(res, &path)?;

        if current.is_none() && spec.state == MergeState::Present && !spec.create {
            // The file may be created by an earlier resource of this run;
            // plan cannot know, and guesses nothing.
            if self.opts.mode == Mode::Plan {
                if let Some(why) = self.planned.affecting(&path) {
                    return Err(SinterError::unknown(format!(
                        "{} does not exist now and create is false; deferred to apply ({})",
                        path, why
                    )));
                }
            }
            return Err(SinterError::apply(format!(
                "{}: {} does not exist and create is false; set create: true to let file_merge create it, or create the file first",
                res.id, path
            )));
        }

        let outcome = apply_edit(current.as_deref(), &spec)
            .map_err(|e| SinterError::apply(format!("{}: {}: {}", res.id, path, e)))?;
        // Several removed lines: the diff names them and none of the
        // unmanaged lines between them.
        let removed_lines = match (&spec.edit, spec.state, &current, &outcome.new_content) {
            (Edit::Line { line }, MergeState::Absent, Some(cur), Some(_)) => Some((
                line.clone(),
                String::from_utf8_lossy(cur)
                    .split('\n')
                    .filter(|l| l == line)
                    .count(),
            )),
            _ => None,
        };
        let mut r = self.partial_publish(
            res,
            &path,
            stat,
            current.as_deref(),
            &vals,
            outcome.new_content,
            sensitive,
        )?;
        if let (Some((line, count)), Some(diff)) = (removed_lines, r.diff.as_mut()) {
            if matches!(diff.body, DiffBody::Text { .. }) {
                diff.body = DiffBody::Text {
                    removed: vec![crate::diff::sanitize_line(&line); count],
                    added: Vec::new(),
                };
            }
        }
        Ok(r)
    }
}

fn audit_result(
    res: &FrozenResource,
    status: AuditResourceStatus,
    sensitive: bool,
    reason: Option<String>,
) -> AuditResourceResult {
    AuditResourceResult {
        id: res.id.clone(),
        type_: res.type_.clone(),
        origin: res.origin.clone(),
        status,
        sensitive,
        details: Vec::new(),
        reason,
        loop_index: res.loop_index,
    }
}

/// A drift detail, redacted at construction for a sensitive resource.
fn detail(dimension: &str, observed: String, desired: String, sensitive: bool) -> AuditDriftDetail {
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

/// A failed step of the audit: an unknown value means the resource is not
/// auditable; everything else is an error, never drift and never absence.
fn audit_failure(res: &FrozenResource, sensitive: bool, e: &SinterError) -> AuditResourceResult {
    let status = if e.kind == ErrorKind::Unknown {
        AuditResourceStatus::NotAuditable
    } else {
        AuditResourceStatus::Error
    };
    let reason = if sensitive {
        "observation failed (details redacted)".to_string()
    } else {
        e.message.clone()
    };
    audit_result(res, status, sensitive, Some(reason))
}

/// The `lstat` of the file the audit just read, through the same gate, for
/// the metadata comparison.
fn audit_stat(engine: &mut Engine, path: &str) -> Result<Stat> {
    match engine.fs.observed_stat(path)? {
        Observed::Value(st) if st.kind == ObjKind::File => Ok(st),
        Observed::Value(_) | Observed::ParentAbsent | Observed::Gone => Err(SinterError::apply(
            format!("{} changed while it was observed", path),
        )),
        Observed::Refused(e) => Err(SinterError::apply(format!(
            "{} was not observed: Sinter's parent path check refuses it ({})",
            path, e.message
        ))),
    }
}

/// Audit a `file_merge`: only the managed part and the declared metadata are
/// judged; every other byte of the file is never drift. Reads only.
pub(crate) fn audit_file_merge(
    engine: &mut Engine,
    res: &FrozenResource,
    item: Option<&EvalVal>,
    sensitive: bool,
) -> AuditResourceResult {
    let Some(path) = res.path.clone() else {
        return audit_failure(res, sensitive, &missing_path(res));
    };
    let vals = match engine.eval_with(res, item) {
        Ok(v) => v,
        Err(e) => return audit_failure(res, sensitive, &e),
    };
    let sensitive = sensitive || effective_sensitivity(res, &vals);
    let spec = match evaluated_spec(res, &vals) {
        Ok(s) => s,
        Err(e) => return audit_failure(res, sensitive, &e),
    };
    let current = match crate::audit::audit_partial_read(engine, &path) {
        Ok(c) => c,
        Err(e) => return audit_failure(res, sensitive, &e),
    };
    let Some(current) = current else {
        return match spec.state {
            MergeState::Absent => audit_result(
                res,
                AuditResourceStatus::Compliant,
                sensitive,
                Some("the file is absent, so the managed part is absent".to_string()),
            ),
            MergeState::Present => {
                let mut r = audit_result(res, AuditResourceStatus::Drift, sensitive, None);
                r.details.push(detail(
                    "state",
                    "absent".to_string(),
                    "present".to_string(),
                    sensitive,
                ));
                r
            }
        };
    };
    let outcome = match apply_edit(Some(&current), &spec) {
        Ok(o) => o,
        Err(e) => {
            let e = SinterError::apply(format!("{}: {}", path, e));
            return audit_failure(res, sensitive, &e);
        }
    };
    let mut details: Vec<AuditDriftDetail> = Vec::new();
    if let Some(d) = outcome.drift {
        details.push(detail(d.dimension, d.observed, d.desired, sensitive));
    }

    // Declared metadata only: an undeclared dimension is never compared.
    if ["owner", "group", "mode"]
        .iter()
        .any(|k| !matches!(vals.get(*k).map(|v| &v.val), None | Some(Some(Value::Null))))
    {
        let stat = match audit_stat(engine, &path) {
            Ok(s) => s,
            Err(e) => return audit_failure(res, sensitive, &e),
        };
        let meta = match engine.file_meta(res, &vals, ObjKind::File, sensitive) {
            Ok(m) => m,
            Err(e) => return audit_failure(res, sensitive, &e),
        };
        if let (true, Some(uid)) = (meta.manage_owner, meta.owner_uid) {
            if stat.uid != uid {
                details.push(detail(
                    "owner",
                    stat.uid.to_string(),
                    uid.to_string(),
                    sensitive,
                ));
            }
        }
        if let (true, Some(gid)) = (meta.manage_group, meta.group_gid) {
            if stat.gid != gid {
                details.push(detail(
                    "group",
                    stat.gid.to_string(),
                    gid.to_string(),
                    sensitive,
                ));
            }
        }
        if let (true, Some(mode)) = (meta.manage_mode, meta.mode) {
            if (stat.mode & 0o7777) != mode {
                details.push(detail(
                    "mode",
                    mode_to_string(stat.mode & 0o7777),
                    mode_to_string(mode),
                    sensitive,
                ));
            }
        }
    }

    if details.is_empty() {
        audit_result(
            res,
            AuditResourceStatus::Compliant,
            sensitive,
            Some("the managed part matches the desired state".to_string()),
        )
    } else {
        let mut r = audit_result(res, AuditResourceStatus::Drift, sensitive, None);
        r.details = details;
        r
    }
}
