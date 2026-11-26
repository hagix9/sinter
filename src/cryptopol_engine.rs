//! Plan, apply and audit of `crypto_policy`.
//!
//! Observation is `update-crypto-policies --show` (read-only, fixed argv);
//! only a clean exit with exactly one policy line is a state. The change is
//! `update-crypto-policies --set <POLICY>`; its exit code never decides
//! success: the policy is observed again and must equal the declared one.
//! Nothing here restarts a service or reboots.

use std::collections::BTreeMap;

use crate::cryptopol::{Policy, PolicySpec, SERVICES_NOTE, TIMEOUT_SECS, TOOL};
use crate::engine::{Engine, Mode};
use crate::error::{Result, SinterError};
use crate::executor::{Completion, ExecRequest};
use crate::expressions::EvalVal;
use crate::model::FrozenResource;
use crate::resources::{baseline_env, changed_result_sensitive, unchanged_result};
use crate::result::{Change, Diff, DiffBody, Execution, ResourceResult, Verification};
use crate::targetfs::ObjKind;
use crate::value::Value;

/// The first non-empty line of the tool's standard error, printable ASCII
/// and capped, for a failure reason.
fn stderr_excerpt(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    line.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(160)
        .collect()
}

impl Engine {
    fn crypto_policy_evaluate(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<PolicySpec> {
        let vals = self.eval_with(res, item)?;
        let mut plain: BTreeMap<String, Value> = BTreeMap::new();
        for (k, v) in &vals {
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
        PolicySpec::from_values(&plain, &res.id, sensitive)
    }

    /// The system-wide policy the host reports. Read-only. A missing tool is
    /// "not supported on this host"; any answer other than a clean exit with
    /// one policy line is an error, never a state.
    fn crypto_policy_observe(&mut self, res: &FrozenResource, audit: bool) -> Result<Policy> {
        if !self.fs.executable_present(TOOL, false)? {
            // Plan: an earlier planned change (for example the package that
            // ships the tool) may bring it; apply decides then.
            if self.opts.mode == Mode::Plan && !audit {
                if let Some(why) = self.planned.affecting(TOOL) {
                    return Err(SinterError::unknown(format!(
                        "deferred/unknown until apply: update-crypto-policies was not found now ({})",
                        why
                    )));
                }
            }
            return Err(SinterError::apply(format!(
                "{}: crypto_policy is not supported on this host (update-crypto-policies was not found)",
                res.id
            )));
        }
        let out = self.fs.update_crypto_policies_show()?;
        match &out.completion {
            Completion::Exited(0) => {}
            Completion::Exited(code) => {
                return Err(SinterError::apply(format!(
                    "{}: the current crypto policy could not be observed: update-crypto-policies --show exited {}",
                    res.id, code
                )))
            }
            Completion::Signaled(s) => {
                return Err(SinterError::apply(format!(
                    "{}: the current crypto policy could not be observed: update-crypto-policies --show was terminated by signal {}",
                    res.id, s
                )))
            }
            Completion::Indeterminate { .. } => {
                return Err(SinterError::indeterminate(format!(
                    "{}: the current crypto policy could not be observed: update-crypto-policies --show did not complete",
                    res.id
                )))
            }
        }
        if out.stdout_truncated || out.stderr_truncated {
            return Err(SinterError::apply(format!(
                "{}: the current crypto policy could not be observed: the output of update-crypto-policies --show was truncated",
                res.id
            )));
        }
        crate::cryptopol::parse_show(&out.stdout).map_err(|why| {
            SinterError::apply(format!(
                "{}: the current crypto policy could not be observed: the output of update-crypto-policies --show is not one policy line ({})",
                res.id, why
            ))
        })
    }

    /// Every policy and subpolicy definition the declared policy needs must
    /// exist as a regular file in the vendor or the local tree, so an
    /// unknown policy is refused before the tool is run. In plan, a
    /// definition an earlier planned change may still create is a note
    /// instead (apply checks again before it runs the tool).
    fn crypto_policy_definitions(
        &mut self,
        res: &FrozenResource,
        spec: &PolicySpec,
    ) -> Result<Vec<String>> {
        let mut notes = Vec::new();
        for (what, candidates) in spec.definition_files() {
            let mut found = false;
            for path in &candidates {
                match self.observe_stat(res, path)?.kind {
                    ObjKind::File => {
                        found = true;
                        break;
                    }
                    ObjKind::Absent => {}
                    other => {
                        return Err(SinterError::apply(format!(
                            "{}: {} exists as {}; a policy definition must be a regular file",
                            res.id,
                            path,
                            other.describe()
                        )))
                    }
                }
            }
            if !found && self.opts.mode == Mode::Plan {
                if let Some(why) = candidates.iter().find_map(|p| self.planned.affecting(p)) {
                    notes.push(format!(
                        "the {} is not defined on this host now; checked again at apply ({})",
                        what, why
                    ));
                    continue;
                }
            }
            if !found {
                return Err(SinterError::apply(format!(
                    "{}: the {} is not defined on this host (looked for {})",
                    res.id,
                    what,
                    candidates.join(" and ")
                )));
            }
        }
        Ok(notes)
    }

    /// Audit: observe and compare, nothing else. Returns the drift
    /// dimensions (at most `policy`).
    pub(crate) fn crypto_policy_audit(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<Vec<(String, String, String)>> {
        let spec = self.crypto_policy_evaluate(res, item, sensitive)?;
        let current = self.crypto_policy_observe(res, true)?;
        Ok(if current == spec.policy {
            Vec::new()
        } else {
            vec![("policy".to_string(), current.text(), spec.policy.text())]
        })
    }

    pub(crate) fn run_crypto_policy(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let sensitive = res.sensitive || res.derived_sensitive;
        let spec = self.crypto_policy_evaluate(res, item, sensitive)?;
        // A sensitive resource names neither the policy nor what was read.
        let hide = |e: SinterError| -> SinterError {
            if sensitive {
                let mut out = e;
                out.message = format!(
                    "{}: the crypto_policy could not be handled (details withheld for a sensitive resource)",
                    res.id
                );
                out
            } else {
                e
            }
        };
        // The first observation is information only: nothing was sent that
        // could change the host, so it is a failure, never "indeterminate".
        let current = self.crypto_policy_observe(res, false).map_err(|e| {
            hide(if e.kind == crate::error::ErrorKind::Indeterminate {
                SinterError::apply(e.message)
            } else {
                e
            })
        })?;
        if current == spec.policy {
            return Ok(unchanged_result(res, "crypto policy already applied"));
        }
        if let Some(why) = spec.change_refusal(&current) {
            return Err(hide(SinterError::apply(format!("{}: {}", res.id, why))));
        }
        let definition_notes = self.crypto_policy_definitions(res, &spec).map_err(hide)?;
        let diff = Diff {
            body: if sensitive {
                DiffBody::Redacted
            } else {
                DiffBody::Summary {
                    current: current.text(),
                    desired: spec.policy.text(),
                }
            },
        };

        if self.opts.mode == Mode::Plan {
            let mut r = changed_result_sensitive(res, sensitive);
            r.diff = Some(diff);
            r.notes.push(SERVICES_NOTE.to_string());
            if !sensitive {
                r.notes.extend(definition_notes);
            }
            return Ok(r);
        }

        if !self.fs.runs_as_root() {
            return Err(SinterError::apply(format!(
                "{}: crypto_policy needs root: connect as root or use --sudo",
                res.id
            )));
        }
        // The decision above rests on `current`. Look once more right before
        // the change: if someone else changed the policy meanwhile, the
        // weakening rules were judged against a policy that is gone.
        let again = self.crypto_policy_observe(res, false).map_err(|e| {
            hide(if e.kind == crate::error::ErrorKind::Indeterminate {
                SinterError::apply(e.message)
            } else {
                e
            })
        })?;
        if again != current {
            return Err(hide(SinterError::apply(format!(
                "{}: the crypto policy changed while this resource was being handled (it was {}, it is now {}); nothing was changed, run again",
                res.id,
                current.text(),
                again.text()
            ))));
        }
        let permit = self.fs.mutation_permit()?;
        let mut req = ExecRequest::new(TOOL);
        req.args = spec.change_args();
        req.env = baseline_env(self.fs.home_env());
        req.sensitive = sensitive;
        req.timeout_secs = TIMEOUT_SECS;
        let out = self.fs.exec(&permit, &req).map_err(|e| {
            SinterError::apply(format!(
                "{}: update-crypto-policies --set failed to dispatch: {}",
                res.id,
                if sensitive {
                    "(details withheld)"
                } else {
                    e.message.as_str()
                }
            ))
        })?;

        let mut r = changed_result_sensitive(res, sensitive);
        r.diff = Some(diff);
        r.notes.push(SERVICES_NOTE.to_string());
        match &out.completion {
            // The tool may still be running: nothing else is sent for this
            // resource, and nothing is claimed about the policy.
            Completion::Indeterminate { reason, .. } => {
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "update-crypto-policies --set did not complete ({}); the policy may or may not have been applied",
                    reason
                ));
                return Ok(r);
            }
            Completion::Signaled(s) => {
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "update-crypto-policies --set was terminated by signal {}; the policy may or may not have been applied",
                    s
                ));
                return Ok(r);
            }
            Completion::Exited(code) if *code != 0 => {
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                let detail = stderr_excerpt(&out.stderr);
                r.reason = Some(format!(
                    "update-crypto-policies --set failed with exit code {}{}; the policy may or may not have been applied",
                    code,
                    if sensitive || detail.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", detail)
                    }
                ));
                return Ok(r);
            }
            Completion::Exited(_) => {}
        }

        // Exit 0 is only the tool's claim. The policy it reports decides.
        match self.crypto_policy_observe(res, false) {
            Ok(after) if after == spec.policy => {
                r.change = Change::Changed;
                r.verification = Verification::Verified;
            }
            Ok(after) => {
                r.execution = Execution::Failed;
                r.change = if after == current {
                    Change::Possible
                } else {
                    Change::Changed
                };
                r.verification = Verification::Failed;
                r.reason = Some(if sensitive {
                    "update-crypto-policies reported success but the applied policy is not the declared one".to_string()
                } else {
                    format!(
                        "update-crypto-policies reported success but the applied policy is {} (declared: {})",
                        after.text(),
                        spec.policy.text()
                    )
                });
            }
            Err(e) => {
                let indeterminate = e.kind == crate::error::ErrorKind::Indeterminate;
                r.execution = if indeterminate {
                    Execution::Indeterminate
                } else {
                    Execution::Failed
                };
                r.change = Change::Possible;
                r.verification = if indeterminate {
                    Verification::Unknown
                } else {
                    Verification::Failed
                };
                r.reason = Some(format!(
                    "update-crypto-policies reported success but the policy could not be observed again, so it may or may not have been applied: {}",
                    if sensitive {
                        "(details withheld)"
                    } else {
                        e.message.as_str()
                    }
                ));
            }
        }
        Ok(r)
    }
}
