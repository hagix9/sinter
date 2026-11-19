//! Plan and apply of `systemd_timer` (DESIGN §42).
//!
//! The timer-specific checks come first and change nothing: the unit's own
//! state (masked), where its definition comes from (another fragment, drop-
//! ins) and every `OnCalendar` expression checked by the target's systemd.
//! Then the unit file goes through the `file` resource code and the
//! activation through the `service` resource code, unchanged, so a timer
//! decides, writes, reloads, enables and verifies exactly as those two do.

use std::collections::BTreeMap;

use crate::engine::{unknown_result, Engine, Mode};
use crate::error::{MutationState, Result, SinterError};
use crate::executor::Completion;
use crate::expressions::EvalVal;
use crate::manager::ManagerReloadPhase;
use crate::model::FrozenResource;
use crate::result::{Change, Execution, ResourceResult, Verification};
use crate::timer::{refusal, timer_unit, TimerSpec, TimerState};
use crate::value::Value;

/// Evaluated `with` values as plain values; an unknown value stops the
/// resource as for every other type.
pub(crate) fn plain_values(vals: &BTreeMap<String, EvalVal>) -> Result<BTreeMap<String, Value>> {
    let mut out = BTreeMap::new();
    for (k, v) in vals {
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

/// The fully checked spec of an evaluated timer.
pub(crate) fn evaluated_spec(
    res: &FrozenResource,
    vals: &BTreeMap<String, EvalVal>,
) -> Result<TimerSpec> {
    let plain = plain_values(vals)?;
    TimerSpec::check(&plain, &res.id, false)?.ok_or_else(|| {
        SinterError::apply(format!(
            "{}: systemd_timer fields are not fully evaluated",
            res.id
        ))
    })
}

/// Combine the unit-file part and the activation part into the timer's one
/// result: the more severe execution and verification, any change, every
/// reason and note, the unit-file diff first.
pub(crate) fn merge(res: &FrozenResource, parts: Vec<ResourceResult>) -> ResourceResult {
    let sensitive = res.sensitive || res.derived_sensitive;
    let mut r = ResourceResult {
        id: res.id.clone(),
        type_: res.type_.clone(),
        origin: res.origin.clone(),
        execution: Execution::NotRun,
        change: Change::None,
        verification: Verification::NotPerformed,
        disposition: crate::result::Disposition::Normal,
        reason: None,
        unknown: false,
        sensitive,
        diff: None,
        notes: Vec::new(),
        handler_notifications: Vec::new(),
        loop_index: res.loop_index,
    };
    let mut reasons: Vec<String> = Vec::new();
    let mut verified_all = !parts.is_empty();
    for p in parts {
        r.execution = match (r.execution, p.execution) {
            (Execution::Indeterminate, _) | (_, Execution::Indeterminate) => {
                Execution::Indeterminate
            }
            (Execution::Failed, _) | (_, Execution::Failed) => Execution::Failed,
            (Execution::Succeeded, _) | (_, Execution::Succeeded) => Execution::Succeeded,
            _ => Execution::NotRun,
        };
        r.change = match (r.change, p.change) {
            (Change::Changed, _) | (_, Change::Changed) => Change::Changed,
            (Change::Possible, _) | (_, Change::Possible) => Change::Possible,
            _ => Change::None,
        };
        r.verification = match (r.verification, p.verification) {
            (Verification::Failed, _) | (_, Verification::Failed) => Verification::Failed,
            (Verification::Unknown, _) | (_, Verification::Unknown) => Verification::Unknown,
            (a, _) => a,
        };
        if !matches!(
            p.verification,
            Verification::Verified | Verification::NotApplicable
        ) {
            verified_all = false;
        }
        r.unknown |= p.unknown;
        r.sensitive |= p.sensitive;
        if r.diff.is_none() {
            r.diff = p.diff;
        }
        r.notes.extend(p.notes);
        if let Some(reason) = p.reason {
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
    }
    if verified_all && !matches!(r.verification, Verification::Failed | Verification::Unknown) {
        r.verification = Verification::Verified;
    }
    if !reasons.is_empty() {
        r.reason = Some(reasons.join("; "));
    }
    r
}

/// A failure of the timer after the unit file may already have changed:
/// the error keeps that change (a mutation is never hidden).
fn after_change(mut e: SinterError, file_changed: bool) -> SinterError {
    if file_changed && e.mutation == MutationState::None {
        e.mutation = MutationState::Changed;
    }
    e
}

impl Engine {
    /// The checks that change nothing and must pass before a timer is
    /// touched (DESIGN §42.3–§42.5). Returns the timer unit's LoadState.
    pub(crate) fn timer_prechecks(
        &mut self,
        res: &FrozenResource,
        spec: &TimerSpec,
        sensitive: bool,
    ) -> Result<String> {
        let unit = timer_unit(&spec.name);
        let obs = if self.opts.mode == Mode::Apply {
            // Synchronize the manager first (pending unit input of earlier
            // resources), as a service does, and decide from what follows.
            self.manager_sync(
                ManagerReloadPhase::Resource,
                Some(&res.id),
                &[(unit.clone(), sensitive)],
            )
            .map(|mut v| v.remove(0))
            .map_err(|mut e| {
                e.mutation = MutationState::None;
                e
            })?
        } else {
            self.observe_service_sensitive(&unit, sensitive)?
        };
        let files = self.observe_timer_unit_files(&unit, sensitive)?;
        if let Some(why) = refusal(&spec.name, &files, &obs.unit_file_state) {
            return Err(SinterError::apply(format!("{}: {}", res.id, why)));
        }
        for (i, expr) in spec.on_calendar.iter().enumerate() {
            self.check_calendar(res, i, expr, sensitive)?;
        }
        Ok(obs.load_state)
    }

    fn observe_timer_unit_files(
        &mut self,
        unit: &str,
        sensitive: bool,
    ) -> Result<crate::timer::UnitFiles> {
        let shown = if sensitive { "[redacted]" } else { unit };
        let out = self
            .fs
            .systemctl_show_unit_files_sensitive(unit, sensitive)?;
        match &out.completion {
            Completion::Indeterminate { .. } => {
                return Err(SinterError::indeterminate(format!(
                    "unit file observation for {} did not complete",
                    shown
                )))
            }
            Completion::Signaled(s) => {
                return Err(SinterError::apply(format!(
                    "unit file observation for {} terminated by signal {}",
                    shown, s
                )))
            }
            Completion::Exited(_) => {}
        }
        if !out.is_success() || out.stdout_truncated {
            return Err(SinterError::apply(format!(
                "unit file observation for {} failed: systemctl exited {:?}",
                shown,
                out.exit_code()
            )));
        }
        let text = std::str::from_utf8(&out.stdout).map_err(|_| {
            SinterError::apply(format!(
                "unit file observation for {} is not valid UTF-8",
                shown
            ))
        })?;
        crate::timer::parse_unit_files(text).map_err(|why| {
            SinterError::apply(format!("unit file observation for {}: {}", shown, why))
        })
    }

    fn check_calendar(
        &mut self,
        res: &FrozenResource,
        index: usize,
        expr: &str,
        sensitive: bool,
    ) -> Result<()> {
        let out = self.fs.systemd_analyze_calendar(expr, sensitive)?;
        let shown = if sensitive {
            format!("on_calendar entry {} (value redacted)", index + 1)
        } else {
            format!("on_calendar entry {} ({:?})", index + 1, expr)
        };
        match &out.completion {
            Completion::Exited(0) => Ok(()),
            Completion::Exited(127) => Err(SinterError::apply(format!(
                "{}: systemd-analyze is not available on the target, so {} cannot be checked; it is not accepted unchecked",
                res.id, shown
            ))),
            Completion::Exited(code) => Err(SinterError::apply(format!(
                "{}: {} is not a valid calendar expression for the target's systemd (systemd-analyze exited {})",
                res.id, shown, code
            ))),
            Completion::Signaled(s) => Err(SinterError::apply(format!(
                "{}: checking {} was terminated by signal {}",
                res.id, shown, s
            ))),
            Completion::Indeterminate { .. } => Err(SinterError::indeterminate(format!(
                "{}: checking {} did not complete",
                res.id, shown
            ))),
        }
    }

    pub(crate) fn run_systemd_timer(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let sensitive = res.sensitive || res.derived_sensitive;
        let vals = self.eval_with(res, item)?;
        let spec = evaluated_spec(res, &vals)?;
        let apply = self.opts.mode == Mode::Apply;

        // Plan cannot judge a unit whose manager input earlier resources
        // change: the manager's answer is meaningless until apply reloads.
        if !apply && !self.manager.pending.is_empty() {
            let mut r = unknown_result(res);
            r.reason = Some(
                "deferred/unknown until manager synchronization at apply: managed systemd input changes are planned"
                    .into(),
            );
            return Ok(r);
        }
        let load_state = self.timer_prechecks(res, &spec, sensitive)?;
        let file = spec.file_part(res);
        let service = spec.service_part(res);

        if spec.state == Some(TimerState::Absent) {
            let mut parts = Vec::new();
            let mut service_changed = false;
            if load_state != "not-found" {
                if let Some(svc) = &service {
                    let r = self.run_service(svc, None)?;
                    service_changed = r.change != Change::None;
                    let failed =
                        r.execution != Execution::Succeeded && r.execution != Execution::NotRun;
                    parts.push(r);
                    if failed {
                        return Ok(merge(res, parts));
                    }
                }
            }
            let fr = self
                .run_file(&file, None)
                .map_err(|e| after_change(e, service_changed))?;
            let file_changed = fr.change == Change::Changed;
            let file_failed =
                fr.execution == Execution::Failed || fr.execution == Execution::Indeterminate;
            parts.push(fr);
            if apply && !file_failed && (file_changed || load_state != "not-found") {
                // Reload now (the removed unit file is pending manager input)
                // and require that the unit is gone.
                let unit = timer_unit(&spec.name);
                let after = self
                    .manager_sync(
                        ManagerReloadPhase::Resource,
                        Some(&res.id),
                        &[(unit, sensitive)],
                    )
                    .map(|mut v| v.remove(0))
                    .map_err(|e| after_change(e, file_changed || service_changed))?;
                if after.load_state != "not-found" {
                    let mut r = merge(res, parts);
                    r.execution = Execution::Failed;
                    r.verification = Verification::Failed;
                    r.reason = Some(format!(
                        "timer verification failed: the unit is still {} after removal",
                        after.load_state
                    ));
                    return Ok(r);
                }
            }
            return Ok(merge(res, parts));
        }

        let fr = self.run_file(&file, None)?;
        let file_changed = fr.change == Change::Changed;
        if matches!(fr.execution, Execution::Failed | Execution::Indeterminate) {
            return Ok(merge(res, vec![fr]));
        }
        let mut parts = vec![fr];
        if spec.needs_trigger_unit() {
            let target = spec.triggered_unit();
            if apply {
                let unit = timer_unit(&spec.name);
                let obs = self
                    .manager_sync(
                        ManagerReloadPhase::Resource,
                        Some(&res.id),
                        &[(unit, sensitive), (target.clone(), sensitive)],
                    )
                    .map_err(|e| after_change(e, file_changed))?;
                if obs.get(1).map(|o| o.load_state.as_str()) == Some("not-found") {
                    let mut r = merge(res, parts);
                    r.execution = Execution::Failed;
                    r.verification = Verification::Failed;
                    r.reason = Some(format!(
                        "the unit {} that the timer activates does not exist; the timer was not enabled or started",
                        if sensitive { "[redacted]" } else { target.as_str() }
                    ));
                    return Ok(r);
                }
            } else if self.manager.pending.is_empty() {
                let obs = self.observe_service_sensitive(&target, sensitive)?;
                if obs.load_state == "not-found" {
                    let mut r = unknown_result(res);
                    r.reason = Some(format!(
                        "the unit {} that the timer activates does not exist now; apply refuses to enable or start the timer unless it exists then",
                        if sensitive { "[redacted]" } else { target.as_str() }
                    ));
                    parts.push(r);
                }
            }
        }
        if let Some(svc) = &service {
            let sr = self
                .run_service(svc, None)
                .map_err(|e| after_change(e, file_changed))?;
            parts.push(sr);
        }
        Ok(merge(res, parts))
    }
}
