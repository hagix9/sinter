//! Engine helpers shared by the OS base-setting types that change one
//! setting through the OS's own tool and observe it again (`timezone`,
//! `locale`, `kernel_module`): the presence check of the tool, the dispatch
//! of the fixed-argv change and the classification of its completion.
//!
//! Nothing here decides success: a clean exit only lets the caller observe
//! again, and the observation decides.

use crate::engine::{Engine, Mode};
use crate::error::{ErrorKind, MutationState, Result, SinterError};
use crate::executor::{Completion, ExecRequest};
use crate::model::FrozenResource;
use crate::resources::baseline_env;
use crate::result::{Change, Execution, ResourceResult, Verification};

/// The first non-empty line of a tool's standard error, printable ASCII and
/// capped, for a failure reason.
pub(crate) fn stderr_excerpt(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    printable(line, 160)
}

/// `s` with every character that is not printable ASCII replaced by `?`,
/// at most `max` characters.
fn printable(s: &str, max: usize) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(max)
        .collect()
}

/// A value for a message: printable ASCII, capped, quoted.
pub(crate) fn shown(value: &str) -> String {
    let mut out = printable(value, 200);
    if value.chars().count() > 200 {
        out.push_str("...");
    }
    format!("{:?}", out)
}

/// An observation that could not complete before anything was sent that
/// changes the host is a plain failure, never "indeterminate".
pub(crate) fn before_any_change(e: SinterError) -> SinterError {
    if e.kind == ErrorKind::Indeterminate {
        SinterError::apply(e.message)
    } else {
        e
    }
}

/// Record on `r` that the observation after a change that exited 0 failed:
/// the change may or may not have been made.
pub(crate) fn reobservation_failed(
    r: &mut ResourceResult,
    e: &SinterError,
    what: &str,
    subject: &str,
    sensitive: bool,
) {
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
        "{} reported success but {} could not be observed again, so it may or may not have been changed: {}",
        what,
        subject,
        if sensitive {
            "(details withheld)"
        } else {
            e.message.as_str()
        }
    ));
}

impl Engine {
    /// Whether the tool `tool` of type `type_` exists. A missing tool is
    /// "`type_` is not supported on this host"; in plan only, when an
    /// earlier planned change may bring it, the resource is deferred to
    /// apply.
    pub(crate) fn osbase_tool(
        &mut self,
        res: &FrozenResource,
        tool: &str,
        type_: &str,
        audit: bool,
    ) -> Result<()> {
        if self.fs.executable_present(tool, false)? {
            return Ok(());
        }
        let short = tool.rsplit('/').next().unwrap_or(tool);
        if self.opts.mode == Mode::Plan && !audit {
            if let Some(why) = self.planned.affecting(tool) {
                return Err(SinterError::unknown(format!(
                    "deferred/unknown until apply: {} was not found now ({})",
                    short, why
                )));
            }
        }
        Err(SinterError::apply(format!(
            "{}: {} is not supported on this host ({} was not found)",
            res.id, type_, tool
        )))
    }

    /// Dispatch the change `tool args` with a mutation permit (fixed
    /// absolute program, fixed argv, no shell, baseline environment) and
    /// classify its completion into `r`. Returns `true` when it exited 0
    /// (the caller then observes again), `false` when `r` now carries an
    /// indeterminate or failed outcome. `what` names the command in
    /// reasons (`timedatectl set-timezone`), `subject` what it changes (`the
    /// time zone`). `changed_before`: this resource already changed the
    /// host, so a dispatch error carries the mutation state `changed`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn osbase_exec(
        &mut self,
        res: &FrozenResource,
        r: &mut ResourceResult,
        tool: &str,
        args: Vec<String>,
        timeout_secs: u64,
        sensitive: bool,
        what: &str,
        subject: &str,
        changed_before: bool,
    ) -> Result<bool> {
        let after_change = |mut e: SinterError| {
            if changed_before {
                e.mutation = MutationState::Changed;
            }
            e
        };
        let permit = self.fs.mutation_permit().map_err(after_change)?;
        let mut req = ExecRequest::new(tool);
        req.args = args;
        req.env = baseline_env(self.fs.home_env());
        req.sensitive = sensitive;
        req.timeout_secs = timeout_secs;
        let out = self.fs.exec(&permit, &req).map_err(|e| {
            after_change(SinterError::apply(format!(
                "{}: {} failed to dispatch: {}",
                res.id,
                what,
                if sensitive {
                    "(details withheld)"
                } else {
                    e.message.as_str()
                }
            )))
        })?;
        match &out.completion {
            // The tool may still be running: nothing else is sent for this
            // resource, and nothing is claimed about the setting.
            Completion::Indeterminate { reason, .. } => {
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "{} did not complete ({}); {} may or may not have been changed",
                    what, reason, subject
                ));
                Ok(false)
            }
            Completion::Signaled(s) => {
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "{} was terminated by signal {}; {} may or may not have been changed",
                    what, s, subject
                ));
                Ok(false)
            }
            Completion::Exited(code) if *code != 0 => {
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                let detail = stderr_excerpt(&out.stderr);
                r.reason = Some(format!(
                    "{} failed with exit code {}{}; {} may or may not have been changed",
                    what,
                    code,
                    if sensitive || detail.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", detail)
                    },
                    subject
                ));
                Ok(false)
            }
            Completion::Exited(_) => Ok(true),
        }
    }
}
