//! Plan, apply and audit of `tuned`.
//!
//! The selected profile is read from TuneD's own state file
//! (`/etc/tuned/active_profile`), the service with the observation the
//! `service` resource uses, a profile's existence with `lstat`. The only
//! commands are `tuned-adm recommend` (when `recommended: true`),
//! `tuned-adm verify` (when `verify: true`; never in plan) and the change,
//! `tuned-adm profile <name>` or `tuned-adm off`. The exit code of the
//! change never decides success: the state file is read again and must hold
//! the declared selection. Selecting a profile and the profile being applied
//! are reported separately. Nothing here installs TuneD or starts, restarts
//! or enables its service.

use std::collections::BTreeMap;

use crate::engine::{Engine, Mode};
use crate::error::{ErrorKind, Result, SinterError};
use crate::executor::{Completion, ExecRequest, Output};
use crate::expressions::EvalVal;
use crate::model::FrozenResource;
use crate::resources::{baseline_env, changed_result_sensitive, unchanged_result};
use crate::result::{Change, Diff, DiffBody, Execution, ResourceResult, Verification};
use crate::targetfs::ObjKind;
use crate::tuned::{
    change_args, change_text, profile_files, Intent, TunedSpec, ACTIVE_PROFILE, PROFILE_DIRS,
    SERVICE, SETTINGS_NOTE, TIMEOUT_SECS, TOOL, VERIFY_PLAN_NOTE,
};
use crate::value::Value;

/// What `tuned.service` is observed as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Daemon {
    /// The unit is active: TuneD applies the selected profile.
    Active,
    /// The unit exists and is not active (its `ActiveState`).
    NotActive(String),
    /// systemd knows no such unit.
    UnitNotFound,
}

impl Daemon {
    /// Why nothing is changed in this state.
    fn refusal(&self) -> String {
        match self {
            Daemon::Active => String::new(),
            Daemon::NotActive(state) => format!(
                "TuneD is installed but its service is not running ({} is {}); start it with a service resource (Sinter does not start it)",
                SERVICE, state
            ),
            Daemon::UnitNotFound => format!(
                "tuned-adm is installed but the unit {} was not found, so TuneD cannot apply a profile; install the tuned package with a package resource and start the service with a service resource (Sinter does neither here)",
                SERVICE
            ),
        }
    }

    /// The state in a few words, for notes and audit.
    fn describe(&self) -> String {
        match self {
            Daemon::Active => format!("{} is active", SERVICE),
            Daemon::NotActive(state) => format!("{} is not active ({})", SERVICE, state),
            Daemon::UnitNotFound => format!("the unit {} was not found", SERVICE),
        }
    }
}

/// What an audit of a `tuned` found.
pub(crate) struct TunedAudit {
    /// Drift as (dimension, observed, desired).
    pub(crate) drift: Vec<(String, String, String)>,
    /// What a compliant result says.
    pub(crate) compliant: String,
}

/// The first non-empty line of a tool's standard error, printable ASCII and
/// capped, for a failure reason.
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

/// An observation that did not complete sent nothing that could change the
/// host: it is a failure, never "indeterminate".
fn observation_failure(e: SinterError) -> SinterError {
    if e.kind == ErrorKind::Indeterminate {
        SinterError::apply(e.message)
    } else {
        e
    }
}

fn shown(selection: &Option<String>) -> String {
    match selection {
        Some(name) => name.clone(),
        None => "(no profile selected)".to_string(),
    }
}

impl Engine {
    fn tuned_evaluate(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<TunedSpec> {
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
        TunedSpec::from_values(&plain, &res.id, sensitive)
    }

    /// TuneD is installed when its tool is. A host without it is refused,
    /// except in plan when an earlier planned change (the package that ships
    /// it) may still bring it: apply decides then.
    fn tuned_tool(&mut self, res: &FrozenResource, audit: bool) -> Result<()> {
        if self.fs.executable_present(TOOL, false)? {
            return Ok(());
        }
        if self.opts.mode == Mode::Plan && !audit {
            if let Some(why) = self.planned.affecting(TOOL) {
                return Err(SinterError::unknown(format!(
                    "deferred/unknown until apply: tuned-adm was not found now ({})",
                    why
                )));
            }
        }
        Err(SinterError::apply(format!(
            "{}: tuned is not supported on this host (tuned-adm was not found); install it with a package resource",
            res.id
        )))
    }

    fn tuned_selection_of(
        res: &FrozenResource,
        content: Option<Vec<u8>>,
    ) -> Result<Option<String>> {
        match content {
            None => Ok(None),
            Some(bytes) => crate::tuned::parse_active_profile(&bytes).map_err(|why| {
                SinterError::apply(format!(
                    "{}: the selected profile could not be observed: {} is not in the accepted form ({})",
                    res.id, ACTIVE_PROFILE, why
                ))
            }),
        }
    }

    /// The profile TuneD's state file names (`None`: none). Read-only; an
    /// absent file is "no profile selected", a file in any other form than
    /// one profile name is an error.
    fn tuned_selection(&mut self, res: &FrozenResource) -> Result<Option<String>> {
        let (_, content) = self.partial_observe(res, ACTIVE_PROFILE)?;
        Self::tuned_selection_of(res, content)
    }

    /// `tuned.service` as the `service` resource observes a unit.
    fn tuned_daemon(&mut self) -> Result<Daemon> {
        let obs = self
            .observe_service_sensitive(SERVICE, false)
            .map_err(observation_failure)?;
        Ok(if obs.load_state == "not-found" {
            Daemon::UnitNotFound
        } else if obs.active_state == "active" {
            Daemon::Active
        } else {
            Daemon::NotActive(obs.active_state)
        })
    }

    /// A clean exit of one read-only `tuned-adm` call, or why it is not one.
    /// `accept` lists the exit codes that are answers.
    fn tuned_answer(verb: &str, out: &Output, accept: &[i32]) -> std::result::Result<i32, String> {
        let what = format!("tuned-adm {}", verb);
        let code = match &out.completion {
            Completion::Exited(code) if accept.contains(code) => *code,
            Completion::Exited(code) => {
                let detail = stderr_excerpt(&out.stderr);
                return Err(format!(
                    "{} exited {}{}",
                    what,
                    code,
                    if detail.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", detail)
                    }
                ));
            }
            Completion::Signaled(s) => {
                return Err(format!("{} was terminated by signal {}", what, s))
            }
            Completion::Indeterminate { .. } => return Err(format!("{} did not complete", what)),
        };
        if out.stdout_truncated || out.stderr_truncated {
            return Err(format!("the output of {} was truncated", what));
        }
        Ok(code)
    }

    /// The profile TuneD recommends for this host. Read-only. Only a clean
    /// exit with exactly one profile name is an answer.
    fn tuned_recommend(&mut self, res: &FrozenResource) -> Result<String> {
        let out = self.fs.tuned_adm_recommend()?;
        Self::tuned_answer("recommend", &out, &[0])
            .and_then(|_| {
                crate::tuned::parse_recommend(&out.stdout).map_err(|why| {
                    format!(
                        "the output of tuned-adm recommend is not one profile name ({})",
                        why
                    )
                })
            })
            .map_err(|why| {
                SinterError::apply(format!(
                    "{}: the recommended profile could not be observed: {}",
                    res.id, why
                ))
            })
    }

    /// Whether TuneD reports the selected profile as applied
    /// (`tuned-adm verify`: 0 applied, 1 not applied; any other exit, a
    /// signal, a timeout or a truncated capture is no answer). Never called
    /// in plan: whether the call is free of side effects is not measured.
    fn tuned_verify(&mut self, res: &FrozenResource) -> Result<bool> {
        let out = self.fs.tuned_adm_verify()?;
        Self::tuned_answer("verify", &out, &[0, 1])
            .map(|code| code == 0)
            .map_err(|why| {
                SinterError::apply(format!(
                    "{}: whether the profile is applied could not be observed: {}",
                    res.id, why
                ))
            })
    }

    /// Whether `name` is a profile: `<dir>/<name>/tuned.conf` is a regular
    /// file in one of the four profile directories. Read-only.
    fn tuned_profile_exists(&mut self, res: &FrozenResource, name: &str) -> Result<bool> {
        for path in profile_files(name) {
            match self.observe_stat(res, &path)?.kind {
                ObjKind::File => return Ok(true),
                ObjKind::Absent => {}
                other => {
                    return Err(SinterError::apply(format!(
                        "{}: {} exists as {}; a profile definition must be a regular file",
                        res.id,
                        path,
                        other.describe()
                    )))
                }
            }
        }
        Ok(false)
    }

    /// The profile the declaration asks for (`None`: none). `recommended`
    /// asks TuneD.
    fn tuned_desired(&mut self, res: &FrozenResource, spec: &TunedSpec) -> Result<Option<String>> {
        Ok(match &spec.intent {
            Intent::Profile(name) => Some(name.clone()),
            Intent::Off => None,
            Intent::Recommended => Some(self.tuned_recommend(res)?),
        })
    }

    /// Audit: observe and compare, nothing else. Dimensions: `profile` (the
    /// selection), `service` (a profile is declared and the service is not
    /// active, so it is not applied) and, with `verify: true`, `applied`.
    pub(crate) fn tuned_audit(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<TunedAudit> {
        let spec = self.tuned_evaluate(res, item, sensitive)?;
        self.tuned_tool(res, true)?;
        let content = crate::audit::audit_partial_read(self, ACTIVE_PROFILE)?;
        let selected = Self::tuned_selection_of(res, content)?;
        let daemon = self.tuned_daemon()?;
        let desired = self.tuned_desired(res, &spec)?;
        let mut drift = Vec::new();
        if selected != desired {
            drift.push(("profile".to_string(), shown(&selected), shown(&desired)));
        }
        if desired.is_some() && daemon != Daemon::Active {
            drift.push((
                "service".to_string(),
                format!("{}: the selected profile is not applied", daemon.describe()),
                format!("{} is active", SERVICE),
            ));
        }
        // `tuned-adm verify` judges the profile TuneD has selected, and
        // needs the running service: it is asked only when both are as
        // declared (otherwise the differences above already say so).
        let mut compliant = match &desired {
            Some(_) => "the selected profile matches and tuned.service is active; whether the profile's settings are applied is not checked (verify is not set)",
            None => "no profile is selected",
        }
        .to_string();
        if spec.verify && drift.is_empty() {
            if self.tuned_verify(res)? {
                compliant = "the selected profile matches, tuned.service is active and tuned-adm verify reports the profile as applied".to_string();
            } else {
                drift.push((
                    "applied".to_string(),
                    "tuned-adm verify reports that the system differs from the selected profile (exit 1)".to_string(),
                    "the selected profile is applied".to_string(),
                ));
            }
        }
        Ok(TunedAudit { drift, compliant })
    }

    pub(crate) fn run_tuned(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let sensitive = res.sensitive || res.derived_sensitive;
        let spec = self.tuned_evaluate(res, item, sensitive)?;
        let id = res.id.clone();
        self.tuned_run(res, &spec, sensitive).map_err(|e| {
            // A sensitive resource names neither the profile nor what was
            // read. A deferral carries no value and stays as it is.
            if sensitive && e.kind != ErrorKind::Unknown {
                let mut out = e;
                out.message = format!(
                    "{}: the tuned profile could not be handled (details withheld for a sensitive resource)",
                    id
                );
                out
            } else {
                e
            }
        })
    }

    fn tuned_run(
        &mut self,
        res: &FrozenResource,
        spec: &TunedSpec,
        sensitive: bool,
    ) -> Result<ResourceResult> {
        let plan = self.opts.mode == Mode::Plan;
        self.tuned_tool(res, false)?;
        let selected = self.tuned_selection(res)?;
        let daemon = self.tuned_daemon()?;
        let desired = self.tuned_desired(res, spec)?;

        if selected == desired {
            // Nothing is sent, whatever the service does. The selection and
            // the tuning are two things: say so when only one holds.
            let mut r = unchanged_result(
                res,
                if desired.is_some() {
                    "profile already selected"
                } else {
                    "no profile is selected"
                },
            );
            r.sensitive = sensitive;
            if desired.is_some() && daemon != Daemon::Active {
                r.notes.push(format!(
                    "{}: the profile is selected but not applied while the service is stopped; start it with a service resource (Sinter does not start it)",
                    daemon.describe()
                ));
            }
            if spec.verify {
                r.notes.push(
                    "verify: tuned-adm verify is not run for an unchanged selection in plan or apply; audit runs it"
                        .to_string(),
                );
            }
            return Ok(r);
        }

        // A change is needed. Everything that would stop it is found before
        // anything is sent.
        let mut notes: Vec<String> = Vec::new();
        if let Some(name) = &desired {
            if !self.tuned_profile_exists(res, name)? {
                let later = if plan {
                    profile_files(name)
                        .iter()
                        .find_map(|p| self.planned.affecting(p))
                } else {
                    None
                };
                match later {
                    Some(why) => notes.push(format!(
                        "the profile {} is not defined on this host now; checked again at apply ({})",
                        name, why
                    )),
                    None => {
                        return Err(SinterError::apply(format!(
                            "{}: the profile {} is not defined on this host (no {}/tuned.conf in {})",
                            res.id,
                            name,
                            name,
                            PROFILE_DIRS.join(", ")
                        )))
                    }
                }
            }
        }
        if daemon != Daemon::Active {
            // Plan: an earlier planned change (a service resource that
            // starts TuneD, a package) may bring the service up.
            match self.planned.opaque.clone().filter(|_| plan) {
                Some(earlier) => notes.push(format!(
                    "{} now; checked again at apply ({} runs earlier and may start it): nothing is changed unless the service is active then",
                    daemon.describe(),
                    earlier
                )),
                None => {
                    return Err(SinterError::apply(format!(
                        "{}: {}",
                        res.id,
                        daemon.refusal()
                    )))
                }
            }
        }
        let diff = Diff {
            body: if sensitive {
                DiffBody::Redacted
            } else {
                DiffBody::Summary {
                    current: shown(&selected),
                    desired: shown(&desired),
                }
            },
        };
        let mut r = changed_result_sensitive(res, sensitive);
        r.diff = Some(diff);
        if desired.is_some() {
            r.notes.push(SETTINGS_NOTE.to_string());
        }

        if plan {
            if spec.verify {
                r.notes.push(VERIFY_PLAN_NOTE.to_string());
            }
            if !sensitive {
                r.notes.extend(notes);
            }
            return Ok(r);
        }

        if !self.fs.runs_as_root() {
            return Err(SinterError::apply(format!(
                "{}: tuned needs root: connect as root or use --sudo",
                res.id
            )));
        }
        // The decision above rests on `selected`. Look once more right
        // before the change: if someone else selected a profile meanwhile,
        // nothing is sent.
        let again = self.tuned_selection(res)?;
        if again != selected {
            return Err(SinterError::apply(format!(
                "{}: the selected profile changed while this resource was being handled (it was {}, it is now {}); nothing was changed, run again",
                res.id,
                shown(&selected),
                shown(&again)
            )));
        }
        let verb = change_text(desired.as_deref());
        let permit = self.fs.mutation_permit()?;
        let mut req = ExecRequest::new(TOOL);
        req.args = change_args(desired.as_deref());
        req.env = baseline_env(self.fs.home_env());
        req.sensitive = sensitive;
        req.timeout_secs = TIMEOUT_SECS;
        let out = self.fs.exec(&permit, &req).map_err(|e| {
            SinterError::apply(format!(
                "{}: {} failed to dispatch: {}",
                res.id, verb, e.message
            ))
        })?;

        const MAYBE: &str = "the profile selection may or may not have been changed";
        match &out.completion {
            // The tool may still be running: nothing else is sent for this
            // resource, and nothing is claimed about the selection.
            Completion::Indeterminate { reason, .. } => {
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!("{} did not complete ({}); {}", verb, reason, MAYBE));
                return Ok(r);
            }
            Completion::Signaled(s) => {
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "{} was terminated by signal {}; {}",
                    verb, s, MAYBE
                ));
                return Ok(r);
            }
            Completion::Exited(code) if *code != 0 => {
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                let detail = stderr_excerpt(&out.stderr);
                r.reason = Some(format!(
                    "{} failed with exit code {}{}; {}",
                    verb,
                    code,
                    if sensitive || detail.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", detail)
                    },
                    MAYBE
                ));
                return Ok(r);
            }
            Completion::Exited(_) => {}
        }

        // Exit 0 is only the tool's claim. TuneD's state file decides.
        match self.tuned_selection(res) {
            Ok(after) if after == desired => {
                r.change = Change::Changed;
                r.verification = Verification::Verified;
            }
            Ok(after) => {
                r.execution = Execution::Failed;
                r.change = if after == selected {
                    Change::Possible
                } else {
                    Change::Changed
                };
                r.verification = Verification::Failed;
                r.reason = Some(if sensitive {
                    format!(
                        "{} reported success but the selected profile is not the declared one",
                        verb
                    )
                } else {
                    format!(
                        "{} reported success but {} names {} (declared: {})",
                        verb,
                        ACTIVE_PROFILE,
                        shown(&after),
                        shown(&desired)
                    )
                });
                return Ok(r);
            }
            Err(e) => {
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Failed;
                r.reason = Some(format!(
                    "{} reported success but the selected profile could not be observed again, so it may or may not have been changed: {}",
                    verb,
                    if sensitive {
                        "(details withheld)"
                    } else {
                        e.message.as_str()
                    }
                ));
                return Ok(r);
            }
        }

        // The selection changed. Whether the tuning is applied is a second
        // question, asked only on request.
        if spec.verify && desired.is_some() {
            match self.tuned_verify(res) {
                Ok(true) => r.notes.push(
                    "verify: tuned-adm verify reports the selected profile as applied".to_string(),
                ),
                Ok(false) => {
                    r.execution = Execution::Failed;
                    r.verification = Verification::Failed;
                    r.reason = Some(
                        "the profile was selected, but tuned-adm verify reports that the system differs from it (exit 1): the selection changed, the tuning did not verify"
                            .to_string(),
                    );
                }
                Err(e) => {
                    r.execution = Execution::Failed;
                    r.verification = Verification::Unknown;
                    r.reason = Some(format!(
                        "the profile was selected, but whether it is applied is not known: {}",
                        if sensitive {
                            "(details withheld)"
                        } else {
                            e.message.as_str()
                        }
                    ));
                }
            }
        }
        Ok(r)
    }
}
