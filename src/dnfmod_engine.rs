//! Plan, apply and audit of `dnf_module`.
//!
//! Observation is DNF 4's own state file, read without following a symlink
//! and parsed by the closed parser of [`crate::dnfmod`]. The change is one
//! fixed `dnf -y module enable|disable|reset` argv. Its exit code never
//! decides success: after an exit of zero the state file is read again and
//! must show the declared state.

use std::collections::BTreeMap;

use crate::dnfmod::{Desired, ModuleSpec, Observed, DNF, TIMEOUT_SECS};
use crate::engine::{Engine, Mode};
use crate::error::{Result, SinterError};
use crate::executor::{Completion, ExecRequest};
use crate::expressions::EvalVal;
use crate::model::FrozenResource;
use crate::resources::{baseline_env, changed_result_sensitive, ev_env, unchanged_result};
use crate::result::{Change, Diff, DiffBody, Execution, ResourceResult, Verification};
use crate::value::Value;

/// The evaluated declaration and the environment of the change.
struct Evaluated {
    spec: ModuleSpec,
    env: BTreeMap<String, String>,
    sensitive: bool,
}

/// The `with` values without `env` (a map the spec does not read); an
/// unknown value stops the resource as for every other type.
fn spec_values(vals: &BTreeMap<String, EvalVal>) -> Result<BTreeMap<String, Value>> {
    let mut out = BTreeMap::new();
    for (k, v) in vals {
        if k == "env" {
            continue;
        }
        match &v.val {
            Some(x) => {
                out.insert(k.clone(), x.clone());
            }
            None => {
                return Err(SinterError::unknown(format!(
                    "with.{} could not be evaluated (unknown)",
                    k
                )))
            }
        }
    }
    Ok(out)
}

impl Engine {
    fn dnf_module_evaluate(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<Evaluated> {
        let vals = self.eval_with(res, item)?;
        let (env, env_sensitive) = ev_env(&vals, "env")?;
        let spec = ModuleSpec::from_values(&spec_values(&vals)?, &res.id)?;
        Ok(Evaluated {
            spec,
            env,
            sensitive: res.sensitive || res.derived_sensitive || env_sensitive,
        })
    }

    /// Read the module's state file (never following a symlink) and parse
    /// it. A file that is not fully understood is an error, never a state.
    fn dnf_module_observe(
        &mut self,
        res: &FrozenResource,
        spec: &ModuleSpec,
        audit: bool,
    ) -> Result<Observed> {
        let path = spec.state_path();
        let content = if audit {
            crate::audit::audit_partial_read(self, &path)
                .map_err(|e| SinterError::apply(format!("{}: {}", res.id, e.message)))?
        } else {
            self.partial_observe(res, &path)?.1
        };
        match content {
            None => Ok(Observed::absent()),
            Some(bytes) => crate::dnfmod::parse_state_file(&spec.name, &bytes).map_err(|why| {
                SinterError::apply(format!(
                    "{}: the DNF module state file {} is not in the form Sinter reads ({}); the module state is not guessed",
                    res.id, path, why
                ))
            }),
        }
    }

    /// Audit: the same platform check, observation and comparison as plan,
    /// and nothing else. Returns the drift dimensions.
    pub(crate) fn dnf_module_audit(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<Vec<(String, String, String)>> {
        let ev = self.dnf_module_evaluate(res, item)?;
        self.require_dnf4(&res.id, "dnf_module")?;
        let obs = self.dnf_module_observe(res, &ev.spec, true)?;
        Ok(ev.spec.drift(&obs))
    }

    pub(crate) fn run_dnf_module(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let ev = self.dnf_module_evaluate(res, item)?;
        let sensitive = ev.sensitive;
        let spec = &ev.spec;
        // A sensitive resource names neither the module nor what was read.
        let hide = |e: SinterError| -> SinterError {
            if sensitive {
                let mut out = e;
                out.message = format!(
                    "{}: the dnf_module could not be handled (details withheld for a sensitive resource)",
                    res.id
                );
                out
            } else {
                e
            }
        };
        self.require_dnf4(&res.id, "dnf_module").map_err(hide)?;
        let obs = self.dnf_module_observe(res, spec, false).map_err(hide)?;
        if spec.drift(&obs).is_empty() {
            return Ok(unchanged_result(res, "module already in desired state"));
        }
        if let Some(why) = spec.refusal(&obs) {
            return Err(hide(SinterError::apply(format!("{}: {}", res.id, why))));
        }
        let diff = Diff {
            body: if sensitive {
                DiffBody::Redacted
            } else {
                DiffBody::Summary {
                    current: obs.text(),
                    desired: spec.desired_text(),
                }
            },
        };

        if self.opts.mode == Mode::Plan {
            let mut r = changed_result_sensitive(res, sensitive);
            r.diff = Some(diff);
            if let Desired::Enabled(stream) = &spec.desired {
                r.notes.push(if sensitive {
                    "plan does not read repository metadata: whether the module stream exists in the enabled repositories is checked by dnf at apply".to_string()
                } else {
                    format!(
                        "plan does not read repository metadata: whether {}:{} exists in the enabled repositories is checked by dnf at apply",
                        spec.name, stream
                    )
                });
            }
            return Ok(r);
        }

        if !self.fs.runs_as_root() {
            return Err(SinterError::apply(format!(
                "{}: dnf_module needs root: connect as root or use --sudo",
                res.id
            )));
        }
        // The decision above rests on `obs`. Read the state once more right
        // before the change: if someone else changed the module meanwhile,
        // the refusals were judged against a state that is gone.
        let again = self.dnf_module_observe(res, spec, false).map_err(hide)?;
        if again != obs {
            return Err(hide(SinterError::apply(format!(
                "{}: the state of module {} changed while this resource was being handled (it was {}, it is now {}); nothing was changed, run again",
                res.id,
                spec.name,
                obs.text(),
                again.text()
            ))));
        }
        let permit = self.fs.mutation_permit()?;
        let mut req = ExecRequest::new(DNF);
        req.args = spec.change_args();
        req.env = baseline_env(self.fs.home_env());
        req.env.extend(ev.env.clone());
        req.sensitive = sensitive;
        req.timeout_secs = TIMEOUT_SECS;
        let verb = req.args[2].clone();
        let shown = if sensitive {
            "[redacted]".to_string()
        } else {
            req.args[3].clone()
        };
        let out = self.fs.exec(&permit, &req).map_err(|e| {
            SinterError::apply(format!(
                "{}: {} module {} {} failed to dispatch: {}",
                res.id,
                DNF,
                verb,
                shown,
                if sensitive {
                    "(details withheld)"
                } else {
                    e.message.as_str()
                }
            ))
        })?;

        let mut r = changed_result_sensitive(res, sensitive);
        r.diff = Some(diff);
        match &out.completion {
            // The remote dnf may still be running: nothing else is sent to
            // the target for this resource, and nothing is claimed.
            Completion::Indeterminate { reason, .. } => {
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "dnf module {} did not complete ({}); the module state may or may not have changed",
                    verb, reason
                ));
                return Ok(r);
            }
            Completion::Signaled(s) => {
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "dnf module {} was terminated by signal {}; the module state may or may not have changed",
                    verb, s
                ));
                return Ok(r);
            }
            Completion::Exited(code) if *code != 0 => {
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                // dnf's output can carry repository URLs with credentials;
                // like a failed package change, it is withheld.
                let hint = if sensitive {
                    String::new()
                } else {
                    format!(
                        " ({} bytes of dnf output withheld; run `dnf module list {}` on the target to see the streams its repositories offer)",
                        out.stdout.len() + out.stderr.len(),
                        spec.name
                    )
                };
                r.reason = Some(format!(
                    "{} module {} {} failed with exit code {}{}",
                    DNF, verb, shown, code, hint
                ));
                return Ok(r);
            }
            Completion::Exited(_) => {}
        }

        // Exit 0 is only dnf's claim. The state file decides.
        match self.dnf_module_observe(res, spec, false) {
            Ok(after) if spec.drift(&after).is_empty() => {
                r.change = Change::Changed;
                r.verification = Verification::Verified;
            }
            Ok(after) => {
                r.execution = Execution::Failed;
                // An unchanged state file does not prove dnf changed nothing
                // else, so "no change" is not claimed.
                r.change = if after == obs {
                    Change::Possible
                } else {
                    Change::Changed
                };
                r.verification = Verification::Failed;
                r.reason = Some(if sensitive {
                    "dnf reported success but the module state is not the declared one".to_string()
                } else {
                    format!(
                        "dnf reported success but the module state is {} (declared: {})",
                        after.text(),
                        spec.desired_text()
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
                    "dnf reported success but the module state could not be read again: {}",
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
