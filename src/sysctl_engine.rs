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
//!
//! With the persistent file managed, the boot-time configuration is read
//! with `systemd-analyze cat-config sysctl.d` (read-only, fixed argv): a
//! file applied after Sinter's own that sets the same key is named in a
//! note, and audit compares the value that order gives (dimension `boot`).
//! `sysctl --system` is never run. A selected TuneD profile is a note.

use crate::engine::{Engine, Mode};
use crate::error::{ErrorKind, MutationState, Result, SinterError};
use crate::executor::{Completion, ExecRequest};
use crate::expressions::EvalVal;
use crate::model::FrozenResource;
use crate::resources::{baseline_env, changed_result_sensitive, unchanged_result};
use crate::result::{Change, Diff, DiffBody, Execution, ResourceResult, Verification};
use crate::sysctl::{
    BootView, SysctlSpec, ABSENT_NOTE, ANALYZE, BOOT_NOTE, NOT_RUNNING_NOTE, TIMEOUT_SECS, TOOL,
    TUNED_NOTE, TUNED_STATE,
};
use crate::timer_engine::{merge, plain_values};

/// What the observation of the boot-time configuration found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootObs {
    /// `systemd-analyze cat-config sysctl.d` answered in the accepted form.
    Seen(BootView),
    /// It could not be used; why. Nothing is guessed.
    NotExamined(String),
}

/// The note of a result when the boot-time order could not be examined.
fn not_examined_note(why: &str) -> String {
    format!(
        "other sysctl configuration files were not examined ({}); {}",
        why, BOOT_NOTE
    )
}

/// What a value is for a note: shown, or withheld for a sensitive resource.
fn value_or_withheld(value: &str, sensitive: bool) -> String {
    if sensitive {
        "(value withheld)".to_string()
    } else {
        shown(value)
    }
}

/// The notes of a `present` resource with the persistent file, from the
/// boot-time configuration. Values are withheld for a sensitive resource.
fn present_notes(spec: &SysctlSpec, v: &BootView, sensitive: bool) -> Vec<String> {
    let mut notes = Vec::new();
    let name = &spec.name;
    if let Some(path) = &v.undecided_later {
        notes.push(format!(
            "{} is applied after Sinter's file and has a line that mentions {} but is not a setting Sinter can read; which value {} has at boot cannot be decided",
            path, name, name
        ));
    }
    if let Some((path, value)) = v.later.last() {
        let others: Vec<&str> = v.later[..v.later.len() - 1]
            .iter()
            .map(|(p, _)| p.as_str())
            .collect();
        let also = if others.is_empty() {
            String::new()
        } else {
            format!(" (it is also set later by {})", others.join(", "))
        };
        notes.push(if *value == spec.value {
            format!(
                "{} also sets {} and is applied after Sinter's file: at boot its value wins; it is the declared value{}",
                path, name, also
            )
        } else if sensitive {
            format!(
                "{} also sets {} and is applied after Sinter's file: at boot its value wins, so after a reboot the value will be that file's value, not the declared one; remove that setting or declare the value there{}",
                path, name, also
            )
        } else {
            format!(
                "{} also sets {} and is applied after Sinter's file: at boot its value wins, so after a reboot the value will be {}, not the declared {}; remove that setting or declare the value there{}",
                path,
                name,
                shown(value),
                shown(&spec.value),
                also
            )
        });
    }
    for (path, pattern, value) in &v.later_patterns {
        let what = if *value == spec.value {
            "it gives the declared value".to_string()
        } else if sensitive {
            "its value differs from the declared one".to_string()
        } else {
            format!("it gives {}", shown(value))
        };
        notes.push(format!(
            "{} sets the pattern {}, which matches {}, and is applied after Sinter's file; {}; Sinter does not decide whether the pattern or an explicit setting wins at boot",
            path, pattern, name, what
        ));
    }
    notes
}

/// The notes of an `absent` resource: which file still sets the key at
/// boot once Sinter's file is removed.
fn absent_notes(spec: &SysctlSpec, v: &BootView, sensitive: bool) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(path) = &v.undecided_any {
        notes.push(format!(
            "{} has a line that mentions {} but is not a setting Sinter can read; what {} is at boot without Sinter's file cannot be decided",
            path, spec.name, spec.name
        ));
    }
    notes.push(match &v.without_own {
        Some((path, value)) => format!(
            "without Sinter's file, {} still sets {} at boot (to {})",
            path,
            spec.name,
            value_or_withheld(value, sensitive)
        ),
        None => format!(
            "without Sinter's file, no other boot-time file sets {} (the kernel default applies at boot)",
            spec.name
        ),
    });
    notes
}

/// What audit found for a `sysctl`, besides the file.
#[derive(Debug, Clone)]
pub(crate) struct SysctlAudit {
    /// The synthetic file resource, when the persistent file is managed.
    pub file: Option<FrozenResource>,
    /// The running value `(observed, desired)` when it differs.
    pub runtime: Option<(String, String)>,
    /// The boot-time value `(observed, desired)` when it differs.
    pub boot: Option<(String, String)>,
    /// Notes for the reason, in every outcome.
    pub notes: Vec<String>,
    /// The reason of a compliant result.
    pub compliant: String,
}

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

    /// The boot-time configuration in the order systemd-sysctl applies it,
    /// as seen for `name`. Read-only: `test -x` and
    /// `systemd-analyze cat-config sysctl.d` (never `sysctl --system`). A
    /// missing tool, a failed or interrupted run, a non-empty standard
    /// error, a truncated capture or output not in the accepted form is
    /// "not examined", never a guess.
    pub(crate) fn sysctl_boot_observe(&mut self, name: &str) -> BootObs {
        // The tool runs as the invocation itself, never as a tree account.
        self.fs.clear_identity();
        match self.fs.executable_present(ANALYZE, false) {
            Ok(true) => {}
            Ok(false) => return BootObs::NotExamined(format!("{} was not found", ANALYZE)),
            Err(_) => {
                return BootObs::NotExamined(format!(
                    "whether {} is present could not be determined",
                    ANALYZE
                ))
            }
        }
        let what = "systemd-analyze cat-config sysctl.d";
        let out = match self.fs.systemd_analyze_cat_config_sysctl() {
            Ok(o) => o,
            Err(_) => return BootObs::NotExamined(format!("{} could not be run", what)),
        };
        let why = match &out.completion {
            Completion::Exited(0) if out.stdout_truncated || out.stderr_truncated => {
                Some(format!("the output of {} was truncated", what))
            }
            Completion::Exited(0) if !out.stderr.is_empty() => {
                Some(format!("{} wrote to standard error", what))
            }
            Completion::Exited(0) => None,
            Completion::Exited(code) => Some(format!("{} exited {}", what, code)),
            Completion::Signaled(s) => Some(format!("{} was terminated by signal {}", what, s)),
            Completion::Indeterminate { .. } => Some(format!("{} did not complete", what)),
        };
        if let Some(why) = why {
            return BootObs::NotExamined(why);
        }
        match crate::sysctl::parse_cat_config(&out.stdout) {
            Ok(cfg) => BootObs::Seen(BootView::of(&cfg, name)),
            Err(e) => BootObs::NotExamined(format!(
                "the output of {} is not in the expected form: {}",
                what, e
            )),
        }
    }

    /// [`TUNED_NOTE`] when TuneD's state file names a profile. Read-only;
    /// any problem reading it is simply no note.
    fn sysctl_tuned_note(&mut self, res: &FrozenResource, audit: bool) -> Option<String> {
        let bytes = if audit {
            crate::audit::audit_partial_read(self, TUNED_STATE)
                .ok()
                .flatten()
        } else {
            self.partial_observe(res, TUNED_STATE)
                .ok()
                .and_then(|(_, c)| c)
        };
        self.fs.clear_identity();
        bytes
            .filter(|b| b.iter().any(|c| !c.is_ascii_whitespace()))
            .map(|_| TUNED_NOTE.to_string())
    }

    /// Audit, the part that is not the file: the synthetic file resource to
    /// audit when the persistent setting is managed, the drift of the
    /// running value when that is managed and differs, and the drift of the
    /// boot-time value (dimension `boot`) when the persistent setting is
    /// managed and the boot-time configuration gives another value.
    /// Read-only.
    pub(crate) fn sysctl_audit(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<SysctlAudit> {
        let spec = self.sysctl_evaluate(res, item, sensitive)?;
        let file = spec.persist.then(|| spec.file_part(res));
        let mut runtime = None;
        if spec.runtime {
            let current = self.sysctl_observe(res, &spec.name, sensitive, true)?;
            if current != spec.value {
                runtime = Some((current, spec.value.clone()));
            }
        }
        let mut boot = None;
        let mut notes = Vec::new();
        let mut compliant = "matches the declared state; whether another file overrides the value at boot is not evaluated".to_string();
        if spec.absent {
            match self.sysctl_boot_observe(&spec.name) {
                BootObs::Seen(v) => notes.extend(absent_notes(&spec, &v, sensitive)),
                BootObs::NotExamined(why) => notes.push(not_examined_note(&why)),
            }
            compliant = "matches the declared state".to_string();
        } else if spec.persist {
            match self.sysctl_boot_observe(&spec.name) {
                BootObs::Seen(v) => {
                    notes.extend(present_notes(&spec, &v, sensitive));
                    let pattern_differs = v.later_patterns.iter().any(|(_, _, x)| *x != spec.value);
                    if v.undecided_later.is_some() || pattern_differs {
                        notes.push(
                            "boot: not examined (the boot-time value cannot be decided from the configuration files)"
                                .to_string(),
                        );
                    } else {
                        match &v.effective {
                            Some((_, value)) if *value == spec.value => {
                                compliant = "matches the declared state; the boot-time configuration files give the declared value (the value after a reboot itself is not verified)".to_string();
                            }
                            Some((path, value)) => {
                                boot = Some((
                                    format!("{} (from {})", value, path),
                                    spec.value.clone(),
                                ));
                            }
                            None => {
                                boot = Some((
                                    "not set by any boot-time configuration file".to_string(),
                                    spec.value.clone(),
                                ));
                            }
                        }
                    }
                }
                BootObs::NotExamined(why) => {
                    notes.push(format!("boot: not examined; {}", not_examined_note(&why)))
                }
            }
        }
        if let Some(n) = self.sysctl_tuned_note(res, true) {
            notes.push(n);
        }
        Ok(SysctlAudit {
            file,
            runtime,
            boot,
            notes,
            compliant,
        })
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
            let changes = r.change != Change::None;
            if changes {
                r.notes.push(ABSENT_NOTE.to_string());
            }
            match self.sysctl_boot_observe(&spec.name) {
                BootObs::Seen(v) => r.notes.extend(absent_notes(&spec, &v, sensitive)),
                BootObs::NotExamined(why) if changes => r.notes.push(not_examined_note(&why)),
                BootObs::NotExamined(_) => {}
            }
            if let Some(n) = self.sysctl_tuned_note(res, false) {
                r.notes.push(n);
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
        if spec.persist {
            // Read-only, after the change: the order of the boot-time files
            // with Sinter's file in its place. Never `sysctl --system`.
            match self.sysctl_boot_observe(&spec.name) {
                BootObs::Seen(v) => {
                    let notes = present_notes(&spec, &v, sensitive);
                    if notes.is_empty() && file_planned {
                        r.notes.push(format!(
                            "no boot-time configuration file applied after Sinter's file sets {} (the value after a reboot itself is not verified)",
                            spec.name
                        ));
                    }
                    r.notes.extend(notes);
                }
                BootObs::NotExamined(why) if file_planned => {
                    r.notes.push(not_examined_note(&why));
                }
                BootObs::NotExamined(_) => {}
            }
        }
        if file_planned && !spec.runtime {
            r.notes.push(NOT_RUNNING_NOTE.to_string());
        }
        if let Some(n) = self.sysctl_tuned_note(res, false) {
            r.notes.push(n);
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
