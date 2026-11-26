//! Plan, apply and audit of `dnf_repository`.
//!
//! The repository file is observed with the partial-edit helpers (the `file`
//! resource's parent gate, no symlink followed, bounded size), the decision
//! is made by the pure [`crate::dnf_repository`] code, and a change is
//! published through the `file` resource's own publication path. No DNF
//! command is run: the only other target reads are the `lstat` and
//! `readlink` of `/usr/bin/dnf` that tell DNF 4 from DNF 5 (the check
//! shared with `dnf_module`, [`crate::dnfgen`]).

use std::collections::BTreeMap;

use crate::dnf_repository::{self as repo, Drift, RepoSpec};
use crate::engine::{Engine, Mode};
use crate::error::{Result, SinterError};
use crate::expressions::EvalVal;
use crate::inifile;
use crate::model::FrozenResource;
use crate::resources::{unchanged_result, PARTIAL_EDIT_MAX_BYTES};
use crate::result::{Change, ResourceResult};
use crate::targetfs::ObjKind;
use crate::value::Value;

/// What audit learned about a `dnf_repository`.
pub(crate) struct RepoAudit {
    pub(crate) drift: Vec<Drift>,
    /// A declared value is sensitive at run time, or the file holds
    /// credentials: no value may be shown.
    pub(crate) sensitive: bool,
    pub(crate) note: Option<String>,
}

/// The fully checked spec of an evaluated `dnf_repository`.
fn evaluated_spec(res: &FrozenResource, vals: &BTreeMap<String, EvalVal>) -> Result<RepoSpec> {
    let plain = crate::timer_engine::plain_values(vals)?;
    let spec = RepoSpec::check(&plain, &res.id, false)?.ok_or_else(|| {
        SinterError::apply(format!(
            "{}: dnf_repository fields are not fully evaluated",
            res.id
        ))
    })?;
    // The file was fixed when the recipe was loaded (ownership conflicts are
    // judged on it); an evaluation that names another one is not followed.
    if res.path.as_deref() != Some(spec.file.as_str()) {
        return Err(SinterError::apply(format!(
            "{}: the repository file differs from the one resolved when the recipe was loaded",
            res.id
        )));
    }
    Ok(spec)
}

/// A refusal as the resource's error. Refusals built by this type name
/// rules, line numbers, the repository id and the file path only; for a
/// resource declared `sensitive: true` even those are withheld.
fn refused(res: &FrozenResource, why: &str) -> String {
    if res.sensitive {
        format!(
            "{}: dnf_repository was refused (details withheld: the resource is sensitive)",
            res.id
        )
    } else {
        format!("{}: {}", res.id, why)
    }
}

fn any_sensitive(res: &FrozenResource, vals: &BTreeMap<String, EvalVal>) -> bool {
    res.sensitive || res.derived_sensitive || vals.values().any(|v| v.sensitive)
}

impl Engine {
    pub(crate) fn run_dnf_repository(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let vals = self.eval_with(res, item)?;
        let declared_sensitive = any_sensitive(res, &vals);
        let spec = evaluated_spec(res, &vals)?;
        self.require_dnf4(&res.id, "dnf_repository")?;
        let (stat, bytes) = self.partial_observe(res, &spec.file)?;
        let decision = match &bytes {
            None => repo::decide(&spec, None),
            Some(b) => inifile::check_text(b, PARTIAL_EDIT_MAX_BYTES)
                .map_err(|e| format!("{} is not read: {}", spec.file, e.0))
                .and_then(|text| repo::decide(&spec, Some(text))),
        };
        let decision = match decision {
            Ok(d) => d,
            Err(why) => {
                // Plan sees the file as it is now. When an earlier planned
                // change can alter it (a package that installs the file, or
                // another repository in it), apply decides.
                if self.opts.mode == Mode::Plan {
                    if let Some(earlier) = self.planned.affecting(&spec.file) {
                        return Err(SinterError::unknown(if res.sensitive {
                            format!("deferred to apply ({})", earlier)
                        } else {
                            format!("deferred to apply: {} ({})", why, earlier)
                        }));
                    }
                }
                return Err(SinterError::apply(refused(res, &why)));
            }
        };
        let sensitive = declared_sensitive || decision.credentials;
        let Some(new_content) = decision.new_content else {
            let mut r = unchanged_result(
                res,
                if spec.absent {
                    "repository is not defined in the file"
                } else {
                    "repository already matches the declared keys"
                },
            );
            r.sensitive = r.sensitive || sensitive;
            r.notes.extend(decision.notes);
            return Ok(r);
        };
        // A new file is root's, world-readable like every repository file;
        // an existing file keeps its owner, group and mode.
        let mut meta: BTreeMap<String, EvalVal> = BTreeMap::new();
        if stat.kind == ObjKind::Absent {
            for (k, v) in [("owner", "root"), ("group", "root"), ("mode", "0644")] {
                meta.insert(k.to_string(), EvalVal::known(Value::Str(v.to_string())));
            }
        }
        let mut r = self.partial_publish(
            res,
            &spec.file,
            stat,
            &meta,
            Some(new_content.into_bytes()),
            sensitive,
        )?;
        r.notes.extend(decision.notes);
        if self.opts.mode == Mode::Plan
            && r.change == Change::Changed
            && !self.fs.runs_as_root()
            && !r.notes.iter().any(|n| n.starts_with("needs root"))
        {
            r.notes.push(format!(
                "needs root: changing a dnf_repository requires root privilege; the target user is uid {} and --sudo was not given, so apply will fail unless the connection is root or --sudo is used",
                self.fs.target_uid()
            ));
        }
        Ok(r)
    }

    /// The read-only observation and comparison for audit. Every refusal
    /// (unsupported host, symlink, oversized or unreadable file, a file that
    /// cannot be read with certainty) is an error, never drift.
    pub(crate) fn dnf_repo_audit(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<RepoAudit> {
        let vals = self.eval_with(res, item)?;
        let declared_sensitive = any_sensitive(res, &vals);
        let spec = evaluated_spec(res, &vals)?;
        self.require_dnf4(&res.id, "dnf_repository")?;
        let bytes = crate::audit::audit_partial_read(self, &spec.file)?;
        let decision = match &bytes {
            None => repo::audit(&spec, None),
            Some(b) => inifile::check_text(b, PARTIAL_EDIT_MAX_BYTES)
                .map_err(|e| format!("{} is not read: {}", spec.file, e.0))
                .and_then(|text| repo::audit(&spec, Some(text))),
        }
        .map_err(|why| SinterError::apply(refused(res, &why)))?;
        Ok(RepoAudit {
            drift: decision.drift,
            sensitive: declared_sensitive || decision.credentials,
            note: decision.notes.into_iter().next(),
        })
    }
}
