//! Plan, apply and audit of `sysctl`.
//!
//! The persistent setting is one whole file of Sinter's own and goes through
//! the `file` resource code unchanged (atomic write, parent checks, diff).
//! The running value is observed with `sysctl -n -- <name>` (read-only,
//! fixed argv) and changed with `sysctl -w -- <name>=<value>`; the exit code
//! of the change never decides success: the value is observed again and
//! must equal the declared one.
//!
//! Order in apply: the running value is observed first (so an unknown
//! parameter is refused before anything is written), then the file is
//! written, then the running value is changed.

use crate::engine::{Engine, Mode};
use crate::error::{ErrorKind, MutationState, Result, SinterError};
use crate::executor::{Completion, ExecRequest};
use crate::expressions::EvalVal;
use crate::model::FrozenResource;
use crate::resources::{baseline_env, changed_result_sensitive, unchanged_result};
use crate::result::{Change, Diff, DiffBody, Execution, ResourceResult, Verification};
use crate::sysctl::{SysctlSpec, ABSENT_NOTE, BOOT_NOTE, NOT_RUNNING_NOTE, TIMEOUT_SECS, TOOL};
use crate::timer_engine::{merge, plain_values};

/// The first non-empty line of a tool's standard error, printable ASCII and
/// capped, for a failure reason.
pub(crate) fn stderr_excerpt(stderr: &[u8]) -> String {
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

/// A value for a message: printable ASCII, capped.
pub(crate) fn shown(value: &str) -> String {
    let mut out: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(200)
        .collect();
    if value.chars().count() > 200 {
        out.push_str("...");
    }
    format!("{:?}", out)
}

/// An observation that could not complete before anything was sent that
/// changes the host is a plain failure, never "indeterminate".
fn before_any_change(e: SinterError) -> SinterError {
    if e.kind == ErrorKind::Indeterminate {
        SinterError::apply(e.message)
    } else {
        e
    }
}

impl Engine {
    fn sysctl_evaluate(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<SysctlSpec> {
        let vals = self.eval_with(res, item)?;
        SysctlSpec::from_values(&plain_values(&vals)?, &res.id, sensitive)
    }

    /// The running value of one kernel parameter, normalized. Read-only. A
    /// missing tool is "not supported on this host"; a non-zero exit is an
    /// unknown parameter; anything but a clean exit with exactly one line
    /// and nothing on standard error is an error. Never "absent", never a
    /// state.
    fn sysctl_observe(
        &mut self,
        res: &FrozenResource,
        name: &str,
        sensitive: bool,
        audit: bool,
    ) -> Result<String> {
        if !self.fs.executable_present(TOOL, false)? {
            // Plan: an earlier planned change (for example the package that
            // ships the tool) may bring it; apply decides then.
            if self.opts.mode == Mode::Plan && !audit {
                if let Some(why) = self.planned.affecting(TOOL) {
                    return Err(SinterError::unknown(format!(
                        "deferred/unknown until apply: {} was not found now ({})",
                        TOOL, why
                    )));
                }
            }
            return Err(SinterError::apply(format!(
                "{}: sysctl cannot manage the running value on this host ({} was not found)",
                res.id, TOOL
            )));
        }
        let out = self.fs.sysctl_read(name, sensitive)?;
        let what = format!("{}: the running value of {}", res.id, name);
        match &out.completion {
            Completion::Exited(0) => {}
            Completion::Exited(code) => {
                let detail = stderr_excerpt(&out.stderr);
                return Err(SinterError::apply(format!(
                    "{}: unknown kernel parameter {}: sysctl -n exited {}{} (the running kernel does not have it, or this account cannot read it); nothing was changed",
                    res.id,
                    name,
                    code,
                    if detail.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", detail)
                    }
                )));
            }
            Completion::Signaled(s) => {
                return Err(SinterError::apply(format!(
                    "{} could not be observed: sysctl -n was terminated by signal {}",
                    what, s
                )))
            }
            Completion::Indeterminate { .. } => {
                return Err(SinterError::indeterminate(format!(
                    "{} could not be observed: sysctl -n did not complete",
                    what
                )))
            }
        }
        if out.stdout_truncated || out.stderr_truncated {
            return Err(SinterError::apply(format!(
                "{} could not be observed: the output of sysctl -n was truncated",
                what
            )));
        }
        if !out.stderr.is_empty() {
            return Err(SinterError::apply(format!(
                "{} could not be observed: sysctl -n exited 0 but wrote to standard error{}",
                what,
                if sensitive {
                    String::new()
                } else {
                    format!(" ({})", stderr_excerpt(&out.stderr))
                }
            )));
        }
        crate::sysctl::parse_value(&out.stdout).map_err(|why| {
            SinterError::apply(format!(
                "{} could not be observed: the output of sysctl -n is not one value line ({})",
                what, why
            ))
        })
    }

    /// Audit, the part that is not the file: the spec, the synthetic file
    /// resource to audit when the persistent setting is managed, and the
    /// drift of the running value (`observed`, `desired`) when that is
    /// managed and differs. Read-only.
    #[allow(clippy::type_complexity)]
    pub(crate) fn sysctl_audit(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<(Option<FrozenResource>, Option<(String, String)>)> {
        let spec = self.sysctl_evaluate(res, item, sensitive)?;
        let file = spec.persist.then(|| spec.file_part(res));
        let mut runtime = None;
        if spec.runtime {
            let current = self.sysctl_observe(res, &spec.name, sensitive, true)?;
            if current != spec.value {
                runtime = Some((current, spec.value.clone()));
            }
        }
        Ok((file, runtime))
    }

    pub(crate) fn run_sysctl(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let sensitive = res.sensitive || res.derived_sensitive;
        let spec = self.sysctl_evaluate(res, item, sensitive)?;
        let apply = self.opts.mode == Mode::Apply;
        let file = spec.file_part(res);

        if spec.absent {
            let mut r = merge(res, vec![self.run_file(&file, None)?]);
            if r.change != Change::None {
                r.notes.push(ABSENT_NOTE.to_string());
            }
            return Ok(r);
        }

        // Read-only, and first: a parameter the running kernel does not have
        // is refused before the file is written.
        let current = if spec.runtime {
            Some(
                self.sysctl_observe(res, &spec.name, sensitive, false)
                    .map_err(before_any_change)?,
            )
        } else {
            None
        };
        let differs = current.as_ref().is_some_and(|c| *c != spec.value);
        if apply && differs && !self.fs.runs_as_root() {
            return Err(SinterError::apply(format!(
                "{}: sysctl needs root to change a kernel parameter: connect as root or use --sudo; nothing was changed",
                res.id
            )));
        }

        let mut parts: Vec<ResourceResult> = Vec::new();
        let mut file_changed = false;
        let mut file_planned = false;
        if spec.persist {
            let fr = self.run_file(&file, None)?;
            // The file's parent walk may have switched to the account that
            // owns the directory; the tool runs as the invocation itself.
            self.fs.clear_identity();
            file_changed = apply && fr.change == Change::Changed;
            file_planned = fr.change != Change::None;
            let failed = matches!(fr.execution, Execution::Failed | Execution::Indeterminate);
            parts.push(fr);
            if failed {
                // The file is not as declared: the running value is left
                // alone, so the two do not drift apart silently.
                let mut r = merge(res, parts);
                r.notes.push(
                    "the running value was not changed because the persistent file could not be written"
                        .to_string(),
                );
                return Ok(r);
            }
        }

        if let Some(current) = &current {
            let part = if !differs {
                unchanged_result(res, "running value already as declared")
            } else {
                self.sysctl_set(res, &spec, current, sensitive, file_changed)?
            };
            parts.push(part);
        }

        let mut r = merge(res, parts);
        if file_planned {
            r.notes.push(BOOT_NOTE.to_string());
            if !spec.runtime {
                r.notes.push(NOT_RUNNING_NOTE.to_string());
            }
        }
        Ok(r)
    }

    /// The running-value part when it differs: what plan reports, and in
    /// apply the change with its verification. `file_changed`: the
    /// persistent file was already changed by this resource, so an error
    /// here reports that change as certain.
    fn sysctl_set(
        &mut self,
        res: &FrozenResource,
        spec: &SysctlSpec,
        current: &str,
        sensitive: bool,
        file_changed: bool,
    ) -> Result<ResourceResult> {
        let mut r = changed_result_sensitive(res, sensitive);
        r.diff = Some(Diff {
            body: if sensitive {
                DiffBody::Redacted
            } else {
                DiffBody::Summary {
                    current: current.to_string(),
                    desired: spec.value.clone(),
                }
            },
        });
        if !sensitive {
            r.notes.push(format!(
                "running value of {}: {} -> {}",
                spec.name,
                shown(current),
                shown(&spec.value)
            ));
        }
        if self.opts.mode == Mode::Plan {
            return Ok(r);
        }

        let after_change = |mut e: SinterError| {
            if file_changed {
                e.mutation = MutationState::Changed;
            }
            e
        };
        let permit = self.fs.mutation_permit().map_err(after_change)?;
        let mut req = ExecRequest::new(TOOL);
        req.args = spec.write_args();
        req.env = baseline_env(self.fs.home_env());
        req.sensitive = sensitive;
        req.timeout_secs = TIMEOUT_SECS;
        let out = self.fs.exec(&permit, &req).map_err(|e| {
            after_change(SinterError::apply(format!(
                "{}: sysctl -w failed to dispatch: {}",
                res.id,
                if sensitive {
                    "(details withheld)"
                } else {
                    e.message.as_str()
                }
            )))
        })?;

        match &out.completion {
            // The tool may still be running: nothing else is sent for this
            // resource, and nothing is claimed about the value.
            Completion::Indeterminate { reason, .. } => {
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "sysctl -w did not complete ({}); the running value may or may not have been changed",
                    reason
                ));
                return Ok(r);
            }
            Completion::Signaled(s) => {
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "sysctl -w was terminated by signal {}; the running value may or may not have been changed",
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
                    "sysctl -w failed with exit code {}{}; the running value may or may not have been changed",
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

        // Exit 0 is only the tool's claim. The value the kernel reports
        // decides.
        match self.sysctl_observe(res, &spec.name, sensitive, false) {
            Ok(after) if after == spec.value => {
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
                    "sysctl -w reported success but the running value is not the declared one"
                        .to_string()
                } else {
                    format!(
                        "sysctl -w reported success but the running value of {} is {} (declared: {}); a parameter the kernel rounds, clamps or keeps read-only must be declared as the kernel reports it",
                        spec.name,
                        shown(&after),
                        shown(&spec.value)
                    )
                });
            }
            Err(e) => {
                let indeterminate = e.kind == ErrorKind::Indeterminate;
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
                    "sysctl -w reported success but the running value could not be observed again, so it may or may not have been changed: {}",
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
