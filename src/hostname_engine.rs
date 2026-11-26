//! Plan, apply and audit of `hostname`.
//!
//! Observation is `hostnamectl --static` and `hostnamectl --transient`
//! (read-only, fixed argv). The change is `hostnamectl set-hostname <name>`;
//! its exit code never decides success: the static name is observed again
//! and must equal the declared one. The transient name is reported, never
//! managed. Nothing here restarts a service or edits `/etc/hosts`.

use crate::engine::{Engine, Mode};
use crate::error::{ErrorKind, Result, SinterError};
use crate::executor::{Completion, ExecRequest};
use crate::expressions::EvalVal;
use crate::hostname::{Which, PROGRAMS_NOTE, TIMEOUT_SECS, TOOL};
use crate::model::FrozenResource;
use crate::resources::{baseline_env, changed_result_sensitive, unchanged_result};
use crate::result::{Change, Diff, DiffBody, Execution, ResourceResult, Verification};
use crate::sysctl_engine::{shown, stderr_excerpt};
use crate::timer_engine::plain_values;

/// A name for a message: `(not set)` when empty.
fn display(name: &str) -> String {
    if name.is_empty() {
        "(not set)".to_string()
    } else {
        shown(name)
    }
}

/// The note about a transient name that is not the declared one.
fn transient_note(transient: &str, declared: &str) -> String {
    format!(
        "the transient (running) host name is {}, not {}: another source such as DHCP sets it; Sinter manages the static name only",
        display(transient),
        shown(declared)
    )
}

impl Engine {
    fn hostname_evaluate(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<String> {
        let vals = self.eval_with(res, item)?;
        crate::hostname::name_from_values(&plain_values(&vals)?, &res.id, sensitive)
    }

    /// Whether `hostnamectl` exists. A missing tool is "not supported on
    /// this host".
    fn hostname_tool(&mut self, res: &FrozenResource, audit: bool) -> Result<()> {
        if self.fs.executable_present(TOOL, false)? {
            return Ok(());
        }
        // Plan: an earlier planned change may bring the tool; apply decides
        // then.
        if self.opts.mode == Mode::Plan && !audit {
            if let Some(why) = self.planned.affecting(TOOL) {
                return Err(SinterError::unknown(format!(
                    "deferred/unknown until apply: hostnamectl was not found now ({})",
                    why
                )));
            }
        }
        Err(SinterError::apply(format!(
            "{}: hostname is not supported on this host (hostnamectl was not found)",
            res.id
        )))
    }

    /// One name the host reports. Read-only. Only a clean exit with at most
    /// one line is a name (empty: not set); everything else is an error,
    /// never a state.
    fn hostname_observe(&mut self, res: &FrozenResource, which: Which) -> Result<String> {
        let out = self.fs.hostnamectl_show(which)?;
        let what = format!(
            "{}: the {} host name could not be observed: hostnamectl {}",
            res.id,
            if which == Which::Static {
                "static"
            } else {
                "transient"
            },
            which.flag()
        );
        match &out.completion {
            Completion::Exited(0) => {}
            Completion::Exited(code) => {
                let detail = stderr_excerpt(&out.stderr);
                return Err(SinterError::apply(format!(
                    "{} exited {}{}",
                    what,
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
                    "{} was terminated by signal {}",
                    what, s
                )))
            }
            Completion::Indeterminate { .. } => {
                return Err(SinterError::indeterminate(format!(
                    "{} did not complete",
                    what
                )))
            }
        }
        if out.stdout_truncated || out.stderr_truncated {
            return Err(SinterError::apply(format!(
                "{}: its output was truncated",
                what
            )));
        }
        crate::hostname::parse_name(&out.stdout).map_err(|why| {
            SinterError::apply(format!("{}: its output is not one name ({})", what, why))
        })
    }

    /// Audit: observe and compare, nothing else. Returns the drift of the
    /// static name (`observed`, `desired`) when it differs, and a note when
    /// the transient name is not the declared one.
    #[allow(clippy::type_complexity)]
    pub(crate) fn hostname_audit(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<(Option<(String, String)>, Option<String>)> {
        let name = self.hostname_evaluate(res, item, sensitive)?;
        self.hostname_tool(res, true)?;
        let current = self.hostname_observe(res, Which::Static)?;
        let transient = self.hostname_observe(res, Which::Transient)?;
        let drift = (current != name).then(|| {
            (
                if current.is_empty() {
                    "(not set)".to_string()
                } else {
                    current.clone()
                },
                name.clone(),
            )
        });
        let note = (transient != name && !sensitive).then(|| transient_note(&transient, &name));
        Ok((drift, note))
    }

    pub(crate) fn run_hostname(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let sensitive = res.sensitive || res.derived_sensitive;
        let name = self.hostname_evaluate(res, item, sensitive)?;
        // A sensitive resource names neither the name nor what was read.
        let hide = |e: SinterError| -> SinterError {
            if sensitive && e.kind != ErrorKind::Unknown {
                let mut out = e;
                out.message = format!(
                    "{}: the hostname could not be handled (details withheld for a sensitive resource)",
                    res.id
                );
                out
            } else {
                e
            }
        };
        // The first observations are information only: nothing was sent
        // that could change the host, so a failure is never "indeterminate".
        let before = |e: SinterError| -> SinterError {
            hide(if e.kind == ErrorKind::Indeterminate {
                SinterError::apply(e.message)
            } else {
                e
            })
        };
        self.hostname_tool(res, false).map_err(hide)?;
        let current = self.hostname_observe(res, Which::Static).map_err(before)?;
        let transient = self
            .hostname_observe(res, Which::Transient)
            .map_err(before)?;
        if current == name {
            let mut r = unchanged_result(res, "static host name already set");
            if transient != name && !sensitive {
                r.notes.push(transient_note(&transient, &name));
            }
            return Ok(r);
        }
        let diff = Diff {
            body: if sensitive {
                DiffBody::Redacted
            } else {
                DiffBody::Summary {
                    current: if current.is_empty() {
                        "(not set)".to_string()
                    } else {
                        current.clone()
                    },
                    desired: name.clone(),
                }
            },
        };
        let mut r = changed_result_sensitive(res, sensitive);
        r.diff = Some(diff);
        r.notes.push(PROGRAMS_NOTE.to_string());
        if self.opts.mode == Mode::Plan {
            return Ok(r);
        }

        if !self.fs.runs_as_root() {
            return Err(SinterError::apply(format!(
                "{}: hostname needs root: connect as root or use --sudo",
                res.id
            )));
        }
        let permit = self.fs.mutation_permit()?;
        let mut req = ExecRequest::new(TOOL);
        req.args = crate::hostname::set_args(&name);
        req.env = baseline_env(self.fs.home_env());
        req.sensitive = sensitive;
        req.timeout_secs = TIMEOUT_SECS;
        let out = self.fs.exec(&permit, &req).map_err(|e| {
            SinterError::apply(format!(
                "{}: hostnamectl set-hostname failed to dispatch: {}",
                res.id,
                if sensitive {
                    "(details withheld)"
                } else {
                    e.message.as_str()
                }
            ))
        })?;

        match &out.completion {
            // The tool may still be running: nothing else is sent for this
            // resource, and nothing is claimed about the name.
            Completion::Indeterminate { reason, .. } => {
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "hostnamectl set-hostname did not complete ({}); the host name may or may not have been changed",
                    reason
                ));
                return Ok(r);
            }
            Completion::Signaled(s) => {
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "hostnamectl set-hostname was terminated by signal {}; the host name may or may not have been changed",
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
                    "hostnamectl set-hostname failed with exit code {}{}; the host name may or may not have been changed",
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

        // Exit 0 is only the tool's claim. The static name it reports
        // decides.
        match self.hostname_observe(res, Which::Static) {
            Ok(after) if after == name => {
                r.change = Change::Changed;
                r.verification = Verification::Verified;
                // The transient name is reported, not managed: whatever it
                // is, the change above stands.
                if !sensitive {
                    match self.hostname_observe(res, Which::Transient) {
                        Ok(t) if t == name => {}
                        Ok(t) => r.notes.push(transient_note(&t, &name)),
                        Err(_) => r.notes.push(
                            "the transient (running) host name could not be observed after the change; it is not managed and was not verified"
                                .to_string(),
                        ),
                    }
                }
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
                    "hostnamectl reported success but the static host name is not the declared one"
                        .to_string()
                } else {
                    format!(
                        "hostnamectl reported success but the static host name is {} (declared: {})",
                        display(&after),
                        shown(&name)
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
                    "hostnamectl reported success but the static host name could not be observed again, so it may or may not have been changed: {}",
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
