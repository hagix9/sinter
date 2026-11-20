//! Plan, apply and the NetworkManager checkpoint of `nm_connection`
//! (DESIGN §45).
//!
//! Order at the resource's turn: precheck (NetworkManager running, `nmcli`
//! present), observation (the profile list, the active profiles, the one
//! profile with the name, bound to its UUID), the comparison, the
//! connection-risk check (§45.6, the §43.3 table) and only then a change.
//! Every change uses the observed UUID, so a profile renamed or replaced
//! between observation and change is never the one changed; the profile is
//! observed again afterwards and every declared field verified.
//!
//! A change that `affects` the management path runs, with an approval, only
//! inside a checkpoint (§45.7). The checkpoint can restore NetworkManager's
//! configuration while NetworkManager keeps running; it does not cover a
//! NetworkManager restart, a reboot or anything outside NetworkManager, and
//! Sinter never states that recovery is guaranteed.

use std::collections::BTreeSet;
use std::time::Instant;

use serde_json::json;

use crate::engine::{Engine, Mode};
use crate::error::{Result, SinterError};
use crate::executor::{Completion, Output};
use crate::expressions::EvalVal;
use crate::model::FrozenResource;
use crate::nm::{self, NmSpec, Observed, Steps};
use crate::result::{Change, Diff, DiffBody, Disposition, Execution, ResourceResult, Verification};
use crate::risk::engine::NmRiskInput;
use crate::risk::rules::NmChange;
use crate::targetfs::MutationPermit;

fn result(
    res: &FrozenResource,
    sensitive: bool,
    execution: Execution,
    change: Change,
    verification: Verification,
) -> ResourceResult {
    ResourceResult {
        id: res.id.clone(),
        type_: res.type_.clone(),
        origin: res.origin.clone(),
        execution,
        change,
        verification,
        disposition: Disposition::Normal,
        reason: None,
        unknown: false,
        sensitive,
        diff: None,
        notes: Vec::new(),
        handler_notifications: Vec::new(),
        loop_index: res.loop_index,
    }
}

fn withheld(sensitive: bool, msg: String) -> String {
    if sensitive {
        "nm_connection operation failed (details withheld: the resource is sensitive)".into()
    } else {
        msg
    }
}

/// The text of a successful command, or why there is none.
fn stdout_ok(o: &Output) -> std::result::Result<String, String> {
    match o.completion {
        Completion::Exited(0) if !o.stdout_truncated => {
            String::from_utf8(o.stdout.clone()).map_err(|_| "output is not UTF-8".to_string())
        }
        Completion::Exited(0) => Err("output was truncated".into()),
        Completion::Exited(c) => Err(format!(
            "exit {}: {}",
            c,
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        _ => Err("the command did not complete".into()),
    }
}

/// The note shown when an active profile changes without `active`.
const NOT_REACTIVATED: &str = "the profile is active and active is not declared: the change is saved but not applied to the running device until NetworkManager activates the profile again (for example at boot)";

/// Outcome of a change that dispatched commands.
enum Failure {
    /// Definitely failed; `changed` says whether an earlier step changed.
    Failed(String, bool),
    /// The outcome is unknown.
    Unknown(String),
}

impl Engine {
    /// The checked spec of an evaluated `nm_connection`.
    pub(crate) fn nm_spec(&self, res: &FrozenResource, item: Option<&EvalVal>) -> Result<NmSpec> {
        let vals = self.eval_with(res, item)?;
        let plain = crate::timer_engine::plain_values(&vals)?;
        NmSpec::check(&plain, &res.id, false)?.ok_or_else(|| {
            SinterError::apply(format!(
                "{}: nm_connection fields are not fully evaluated",
                res.id
            ))
        })
    }

    /// §45.3 precheck: NetworkManager is running and `nmcli` exists. Sinter
    /// never installs or starts NetworkManager.
    pub(crate) fn nm_precheck(&mut self, res: &FrozenResource, sensitive: bool) -> Result<()> {
        let svc = self.observe_service_sensitive(nm::NM_SERVICE, sensitive)?;
        if svc.active_state != "active" {
            return Err(SinterError::apply(format!(
                "{}: NetworkManager is not running ({} is {}); Sinter does not install or start it",
                res.id,
                nm::NM_SERVICE,
                if svc.load_state == "not-found" {
                    "not installed".to_string()
                } else {
                    svc.active_state.clone()
                }
            )));
        }
        if !self.fs.executable_present(nm::NMCLI, sensitive)? {
            return Err(SinterError::apply(format!(
                "{}: {} is missing on the target",
                res.id,
                nm::NMCLI
            )));
        }
        Ok(())
    }

    fn nm_query(
        &mut self,
        args: &[String],
        sensitive: bool,
    ) -> std::result::Result<String, String> {
        let o = self
            .fs
            .nm_read(nm::NMCLI, args, sensitive)
            .map_err(|e| e.message)?;
        stdout_ok(&o)
    }

    /// Observe the declared profile (§45.3): the profile list (exactly one
    /// profile may have the name), the active profiles and the profile's
    /// settings read by its UUID. Anything Sinter cannot read exactly is an
    /// error, never drift.
    pub(crate) fn nm_observe(
        &mut self,
        res: &FrozenResource,
        spec: &NmSpec,
        sensitive: bool,
    ) -> Result<Observed> {
        let fail = |what: &str, why: String| {
            SinterError::apply(withheld(
                sensitive,
                format!(
                    "{}: NetworkManager {} could not be read: {}",
                    res.id, what, why
                ),
            ))
        };
        let list = self
            .nm_query(&nm::list_argv(), sensitive)
            .and_then(|t| nm::parse_list(&t))
            .map_err(|w| fail("profile list", w))?;
        let matches: Vec<&nm::ListEntry> = list.iter().filter(|e| e.name == spec.name).collect();
        if matches.len() > 1 {
            return Err(SinterError::apply(withheld(
                sensitive,
                format!(
                    "{}: {} NetworkManager profiles have the name {:?}; Sinter does not choose one",
                    res.id,
                    matches.len(),
                    spec.name
                ),
            )));
        }
        let active = self
            .nm_query(&nm::active_argv(), sensitive)
            .and_then(|t| nm::parse_active(&t))
            .map_err(|w| fail("active profiles", w))?;
        let Some(entry) = matches.first() else {
            return Ok(Observed {
                profile: None,
                active_on: None,
            });
        };
        let profile = self
            .nm_query(&nm::profile_argv(&entry.uuid), sensitive)
            .and_then(|t| nm::parse_profile(&t))
            .map_err(|w| fail("profile", w))?;
        if profile.uuid != entry.uuid || profile.id != spec.name {
            return Err(SinterError::apply(withheld(
                sensitive,
                format!(
                    "{}: the profile changed while it was observed (name or UUID differs)",
                    res.id
                ),
            )));
        }
        let mine: Vec<&nm::ActiveEntry> =
            active.iter().filter(|a| a.uuid == profile.uuid).collect();
        let active_on = match mine.as_slice() {
            [] => None,
            [a] if a.state == "activated" && !a.device.is_empty() => Some(a.device.clone()),
            [a] if a.state == "deactivated" => None,
            [a] => {
                return Err(SinterError::apply(withheld(
                    sensitive,
                    format!(
                        "{}: the profile is {} (in transition); its state cannot be judged",
                        res.id, a.state
                    ),
                )))
            }
            _ => {
                return Err(fail(
                    "active profiles",
                    "the profile is active more than once".into(),
                ))
            }
        };
        Ok(Observed {
            profile: Some(profile),
            active_on,
        })
    }

    /// Observation and comparison (plan, apply and audit share them).
    pub(crate) fn nm_compare(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<(NmSpec, Observed, Steps)> {
        let sensitive = res.sensitive || res.derived_sensitive;
        let spec = self.nm_spec(res, item)?;
        self.nm_precheck(res, sensitive)?;
        let obs = self.nm_observe(res, &spec, sensitive)?;
        let st = nm::steps(&spec, &obs)
            .map_err(|w| SinterError::apply(withheld(sensitive, format!("{}: {}", res.id, w))))?;
        Ok((spec, obs, st))
    }

    /// What the connection-risk rule needs to know about the change.
    fn nm_risk_input(spec: &NmSpec, obs: &Observed, st: &Steps) -> NmRiskInput {
        let a = nm::after(spec, obs);
        let removes = st.delete;
        // NetworkManager may activate a changed, inactive profile that
        // autoconnects by itself (and a created one): counted as an
        // activation, so its addressing and gateway are judged.
        let changed = st.create || !st.settings.is_empty();
        let activates =
            st.up || st.create || (changed && !removes && a.autoconnect && obs.active_on.is_none());
        let p = obs.profile.as_ref();
        let method_changed = |fam: &str| {
            st.settings
                .iter()
                .any(|(k, _)| k == &format!("{}.method", fam))
        };
        let auto4 = a.method4 == "auto";
        let auto6 = matches!(a.method6.as_str(), "auto" | "dhcp");
        let dhcp = !removes
            && ((auto4 && (activates || method_changed("ipv4")))
                || (auto6 && (activates || method_changed("ipv6"))));
        let gw_changed = st
            .settings
            .iter()
            .any(|(k, v)| k.ends_with(".gateway") && !v.is_empty());
        let addr_changed = st.settings.iter().any(|(k, _)| k.ends_with(".addresses"));
        let mut addresses = Vec::new();
        if removes || st.down {
            if let Some(p) = p {
                addresses.extend(p.ipv4.addresses.iter().cloned());
                addresses.extend(p.ipv6.addresses.iter().cloned());
            }
        } else if activates || addr_changed {
            addresses = a.addresses.clone();
        }
        let mut devices = BTreeSet::new();
        devices.extend(a.ifname_before.clone());
        devices.extend(a.ifname_after.clone());
        devices.extend(obs.active_on.clone());
        NmRiskInput {
            desired: nm::desired_summary(spec),
            observed: nm::observed_summary(obs),
            steps: st.labels(),
            device_types: None,
            change: NmChange {
                ifname: if removes {
                    None
                } else {
                    a.ifname_after.clone()
                },
                ifname_before: a.ifname_before.clone(),
                active_on: Some(obs.active_on.iter().cloned().collect()),
                autoconnect: !removes && a.autoconnect,
                deactivates_or_removes: st.down || st.delete,
                dhcp,
                sets_gateway: !removes && (gw_changed || (activates && a.gateway)),
                addresses,
                routing_readable: true,
                activates: activates && !removes,
                port: p.is_some_and(|p| !p.master.is_empty()),
                lower_unknown: None,
            },
            takes_effect_now: st.up || ((st.down || st.delete) && obs.active_on.is_some()),
            devices,
        }
    }

    /// `dispatch_resource` for `nm_connection` (plan and apply).
    pub(crate) fn run_nm_connection(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let sensitive = res.sensitive || res.derived_sensitive;
        let (spec, obs, st) = self.nm_compare(res, item)?;
        let mut input = Self::nm_risk_input(&spec, &obs, &st);
        if !st.is_empty() {
            input.device_types = self
                .nm_query(&nm::devices_argv(), sensitive)
                .and_then(|t| nm::parse_devices(&t))
                .ok();
        }
        let verdict = self.risk_check_nm(res, input)?;
        let mut notes: Vec<String> = Vec::new();
        let changes_profile = st.create || !st.settings.is_empty();
        if changes_profile && spec.active.is_none() && obs.active_on.is_some() {
            notes.push(NOT_REACTIVATED.to_string());
        }
        if st.is_empty() {
            let mut r = result(
                res,
                sensitive,
                Execution::Succeeded,
                Change::None,
                Verification::Verified,
            );
            r.reason = Some("NetworkManager profile already matches the declared fields".into());
            r.notes.extend(verdict.note);
            return Ok(r);
        }
        let labels = st.labels();
        if self.opts.mode == Mode::Plan {
            let mut r = result(
                res,
                sensitive,
                Execution::Succeeded,
                Change::Changed,
                Verification::NotPerformed,
            );
            r.diff = Some(Diff {
                body: if sensitive {
                    DiffBody::Redacted
                } else {
                    DiffBody::Summary {
                        current: st
                            .drift
                            .iter()
                            .map(|(f, o, _)| format!("{}={}", f, o))
                            .collect::<Vec<_>>()
                            .join(" "),
                        desired: st
                            .drift
                            .iter()
                            .map(|(f, _, d)| format!("{}={}", f, d))
                            .collect::<Vec<_>>()
                            .join(" "),
                    }
                },
            });
            if !sensitive {
                r.notes.push(format!("would_run={}", labels.join(";")));
            }
            r.notes.extend(notes);
            r.notes.extend(verdict.note);
            return Ok(r);
        }
        let permit = self.fs.mutation_permit()?;
        let outcome = match &verdict.checkpoint {
            Some(devs) => self.nm_guarded(res, &spec, &obs, &st, devs, &permit, sensitive),
            None => self
                .nm_execute(&spec, &obs, &st, &permit, sensitive)
                .map_err(|f| self.nm_failure(res, f, sensitive))
                .and_then(|_| self.nm_verify(res, &spec, &obs, sensitive)),
        };
        outcome?;
        let mut r = result(
            res,
            sensitive,
            Execution::Succeeded,
            Change::Changed,
            Verification::Verified,
        );
        if !sensitive {
            r.notes.push(format!("ran={}", labels.join(";")));
        }
        r.notes.extend(notes);
        r.notes.extend(verdict.note);
        if verdict.checkpoint.is_some() {
            r.notes.push(
                "checkpoint: created, change applied, new connection verified, checkpoint destroyed"
                    .into(),
            );
        }
        Ok(r)
    }

    fn nm_failure(&self, res: &FrozenResource, f: Failure, sensitive: bool) -> SinterError {
        match f {
            Failure::Failed(m, changed) => {
                let e = SinterError::apply(withheld(sensitive, format!("{}: {}", res.id, m)));
                if changed {
                    e.changed()
                } else {
                    e.possible()
                }
            }
            Failure::Unknown(m) => {
                SinterError::indeterminate(withheld(sensitive, format!("{}: {}", res.id, m)))
                    .possible()
            }
        }
    }

    fn nm_run(
        &mut self,
        permit: &MutationPermit,
        program: &str,
        args: &[String],
        sensitive: bool,
        changed: bool,
    ) -> std::result::Result<String, Failure> {
        let what = args.get(1).cloned().unwrap_or_default();
        match self.fs.nm_change(permit, program, args, sensitive) {
            Ok(o) => match o.completion {
                Completion::Exited(0) => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
                Completion::Exited(c) => Err(Failure::Failed(
                    format!(
                        "nmcli connection {} failed (exit {}): {}",
                        what,
                        c,
                        String::from_utf8_lossy(&o.stderr).trim()
                    ),
                    changed,
                )),
                _ => Err(Failure::Unknown(format!(
                    "nmcli connection {} did not complete (not retried)",
                    what
                ))),
            },
            Err(e) => Err(Failure::Unknown(format!(
                "nmcli connection {} could not be completed: {} (not retried)",
                what, e.message
            ))),
        }
    }

    /// Run the steps (§45.4), by UUID. A created profile's UUID is read back
    /// from the profile list (exactly one profile with the name).
    fn nm_execute(
        &mut self,
        spec: &NmSpec,
        obs: &Observed,
        st: &Steps,
        permit: &MutationPermit,
        sensitive: bool,
    ) -> std::result::Result<(), Failure> {
        let mut changed = false;
        let mut uuid = obs.profile.as_ref().map(|p| p.uuid.clone());
        if st.create {
            self.nm_run(
                permit,
                nm::NMCLI,
                &nm::add_argv(spec, &st.settings),
                sensitive,
                changed,
            )?;
            changed = true;
            let list = self
                .nm_query(&nm::list_argv(), sensitive)
                .and_then(|t| nm::parse_list(&t))
                .map_err(|w| {
                    Failure::Unknown(format!(
                        "the profile list could not be read after creating the profile: {}",
                        w
                    ))
                })?;
            let mine: Vec<&nm::ListEntry> = list.iter().filter(|e| e.name == spec.name).collect();
            match mine.as_slice() {
                [e] => uuid = Some(e.uuid.clone()),
                _ => {
                    return Err(Failure::Unknown(format!(
                        "after creating the profile {} profiles have its name",
                        mine.len()
                    )))
                }
            }
        } else if !st.settings.is_empty() {
            let u = uuid.clone().unwrap_or_default();
            self.nm_run(
                permit,
                nm::NMCLI,
                &nm::modify_argv(&u, &st.settings),
                sensitive,
                changed,
            )?;
            changed = true;
        }
        let u = uuid.unwrap_or_default();
        if st.up {
            self.nm_run(
                permit,
                nm::NMCLI,
                &nm::uuid_argv("up", &u),
                sensitive,
                changed,
            )?;
            changed = true;
        }
        if st.down {
            self.nm_run(
                permit,
                nm::NMCLI,
                &nm::uuid_argv("down", &u),
                sensitive,
                changed,
            )?;
            changed = true;
        }
        if st.delete {
            self.nm_run(
                permit,
                nm::NMCLI,
                &nm::uuid_argv("delete", &u),
                sensitive,
                changed,
            )?;
        }
        Ok(())
    }

    /// Observe again and verify every declared field (§45.4). A modified
    /// profile must still have its UUID.
    fn nm_verify(
        &mut self,
        res: &FrozenResource,
        spec: &NmSpec,
        before: &Observed,
        sensitive: bool,
    ) -> Result<()> {
        let now = self.nm_observe(res, spec, sensitive).map_err(|e| {
            SinterError::indeterminate(format!("{} (after the change)", e.message)).changed()
        })?;
        if let (Some(b), Some(n)) = (&before.profile, &now.profile) {
            if b.uuid != n.uuid {
                return Err(SinterError::apply(withheld(
                    sensitive,
                    format!("{}: after the change the profile has another UUID", res.id),
                ))
                .changed());
            }
        }
        let left = nm::steps(spec, &now).map_err(|w| {
            SinterError::apply(withheld(sensitive, format!("{}: {}", res.id, w))).changed()
        })?;
        if !left.is_empty() {
            return Err(SinterError::apply(withheld(
                sensitive,
                format!(
                    "{}: after the change the profile does not match: {}",
                    res.id,
                    left.drift
                        .iter()
                        .map(|(f, o, d)| format!("{} is {:?}, not {:?}", f, o, d))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ))
            .changed());
        }
        Ok(())
    }

    /// Observe after a rollback; a profile in transition is read again a
    /// few times (two seconds apart).
    fn nm_observe_settled(
        &mut self,
        res: &FrozenResource,
        spec: &NmSpec,
        sensitive: bool,
    ) -> Option<Observed> {
        for i in 0..3 {
            match self.nm_observe(res, spec, sensitive) {
                Ok(o) => return Some(o),
                Err(_) if i < 2 => self.fs.wait_secs(2),
                Err(_) => {}
            }
        }
        None
    }

    fn busctl_read(
        &mut self,
        args: &[String],
        sensitive: bool,
    ) -> std::result::Result<String, String> {
        let o = self
            .fs
            .nm_read(nm::BUSCTL, args, sensitive)
            .map_err(|e| e.message)?;
        stdout_ok(&o)
    }

    /// Whether the checkpoint API can be used here (§45.7 step 1): busctl
    /// present, the three methods offered with the expected signatures, and
    /// the checkpoint permission granted without authentication. Returns
    /// the D-Bus object paths of the devices.
    fn nm_checkpoint_available(
        &mut self,
        devices: &[String],
        sensitive: bool,
    ) -> std::result::Result<Vec<String>, String> {
        if !self
            .fs
            .executable_present(nm::BUSCTL, sensitive)
            .map_err(|e| e.message)?
        {
            return Err(format!("{} is missing", nm::BUSCTL));
        }
        let intro = self.busctl_read(&nm::introspect_argv(), sensitive)?;
        if !nm::introspection_has_checkpoints(&intro) {
            return Err("NetworkManager does not offer the checkpoint methods".into());
        }
        let perms = self
            .busctl_read(&nm::call_argv("GetPermissions", &[]), sensitive)
            .and_then(|t| nm::parse_permissions(&t))?;
        match perms
            .get("org.freedesktop.NetworkManager.checkpoint-rollback")
            .map(|s| s.as_str())
        {
            Some("yes") => {}
            other => {
                return Err(format!(
                    "the checkpoint permission is {} (needs yes)",
                    other.unwrap_or("not reported")
                ))
            }
        }
        let mut paths = Vec::new();
        for d in devices {
            let p = self
                .busctl_read(
                    &nm::call_argv("GetDeviceByIpIface", &["s".into(), d.clone()]),
                    sensitive,
                )
                .and_then(|t| nm::parse_object_reply(&t, nm::valid_device_path))
                .map_err(|w| format!("the device {} is not known to NetworkManager: {}", d, w))?;
            paths.push(p);
        }
        Ok(paths)
    }

    /// The guarded procedure (§45.7): checkpoint, change, new connection,
    /// then destroy (keep) or roll back and verify.
    #[allow(clippy::too_many_arguments)]
    fn nm_guarded(
        &mut self,
        res: &FrozenResource,
        spec: &NmSpec,
        before: &Observed,
        st: &Steps,
        devices: &[String],
        permit: &MutationPermit,
        sensitive: bool,
    ) -> Result<()> {
        let t = spec.checkpoint_timeout;
        let refuse = |this: &mut Engine, why: String| {
            this.risk_mark_refused(&res.id, &why);
            SinterError::apply(withheld(
                sensitive,
                format!(
                    "{}: connection-risk control: the change affects the management connection and needs a NetworkManager checkpoint, but {}; nothing was changed",
                    res.id, why
                ),
            ))
        };
        let paths = match self.nm_checkpoint_available(devices, sensitive) {
            Ok(p) => p,
            Err(why) => return Err(refuse(self, why)),
        };
        let base = json!({"resource": res.id, "devices": devices, "timeout": t});
        if let Err(e) = self.risk_ledger("checkpoint-intent", base.clone()) {
            return Err(refuse(
                self,
                format!("the ledger could not be written ({})", e.message),
            ));
        }
        let started = Instant::now();
        let created = self.fs.nm_change(
            permit,
            nm::BUSCTL,
            &nm::checkpoint_create_argv(&paths, t),
            sensitive,
        );
        let cp = match created {
            Ok(o) => match o.completion {
                Completion::Exited(0) => {
                    match nm::parse_object_reply(
                        &String::from_utf8_lossy(&o.stdout),
                        nm::valid_checkpoint_path,
                    ) {
                        Ok(p) => p,
                        Err(w) => {
                            let _ = self.risk_ledger("checkpoint-unconfirmed", base.clone());
                            return Err(refuse(self, format!("the checkpoint reply could not be read ({}); an unconfirmed checkpoint rolls back by itself at its timeout", w)));
                        }
                    }
                }
                Completion::Exited(c) => {
                    let _ = self.risk_ledger("checkpoint-refused", base.clone());
                    return Err(refuse(
                        self,
                        format!(
                            "creating the checkpoint was refused (exit {}: {})",
                            c,
                            String::from_utf8_lossy(&o.stderr).trim()
                        ),
                    ));
                }
                _ => {
                    let _ = self.risk_ledger("checkpoint-unconfirmed", base.clone());
                    return Err(refuse(self, "creating the checkpoint did not complete; an unconfirmed checkpoint rolls back by itself at its timeout".into()));
                }
            },
            Err(e) => {
                let _ = self.risk_ledger("checkpoint-unconfirmed", base.clone());
                return Err(refuse(
                    self,
                    format!("creating the checkpoint failed ({})", e.message),
                ));
            }
        };
        let mut rec = base.clone();
        rec["checkpoint"] = json!(cp);
        if let Err(e) = self.risk_ledger("checkpoint-created", rec.clone()) {
            // Nothing changed yet: remove the checkpoint and stop.
            let _ = self.fs.nm_change(
                permit,
                nm::BUSCTL,
                &nm::call_argv("CheckpointDestroy", &["o".into(), cp.clone()]),
                sensitive,
            );
            return Err(refuse(
                self,
                format!("the ledger could not be written ({})", e.message),
            ));
        }
        let changed = self.nm_execute(spec, before, st, permit, sensitive);
        // A first command that failed changed nothing for certain: a
        // verified rollback is then reported as possible, not changed.
        let mutated = !matches!(&changed, Err(Failure::Failed(_, false)));
        let reached = changed.is_ok() && self.fs.probe_new_connection();
        let in_time = started.elapsed().as_secs() + 5 < u64::from(t);
        if reached && in_time {
            let destroyed = self.fs.nm_change(
                permit,
                nm::BUSCTL,
                &nm::call_argv("CheckpointDestroy", &["o".into(), cp.clone()]),
                sensitive,
            );
            if matches!(&destroyed, Ok(o) if o.completion == Completion::Exited(0)) {
                let _ = self.risk_ledger("checkpoint-destroyed", rec.clone());
                return self.nm_verify(res, spec, before, sensitive);
            }
            let _ = self.risk_ledger("checkpoint-destroy-failed", rec.clone());
            return self.nm_wait_and_verify(
                res,
                spec,
                before,
                &rec,
                sensitive,
                "the change worked but the checkpoint could not be destroyed, so NetworkManager rolls it back at the timeout",
                true,
            );
        }
        let why = match &changed {
            Err(Failure::Failed(m, _)) | Err(Failure::Unknown(m)) => {
                format!("the change failed ({})", m)
            }
            Ok(()) if !reached => "a new connection failed after the change".to_string(),
            Ok(()) => {
                "the change and the new connection took longer than the checkpoint timeout allows"
                    .to_string()
            }
        };
        if self.fs.original_alive() {
            let rolled = self.fs.nm_change(
                permit,
                nm::BUSCTL,
                &nm::call_argv("CheckpointRollback", &["o".into(), cp.clone()]),
                sensitive,
            );
            let ok = match &rolled {
                Ok(o) if o.completion == Completion::Exited(0) => {
                    nm::rollback_ok(&String::from_utf8_lossy(&o.stdout), &paths)
                }
                _ => false,
            };
            if ok {
                let _ = self.risk_ledger("checkpoint-rolled-back", rec.clone());
                return match self.nm_observe_settled(res, spec, sensitive) {
                    Some(now) if nm::same_state(before, &now) => {
                        let _ = self.risk_ledger("rollback-verified", rec.clone());
                        let e = SinterError::apply(withheld(
                            sensitive,
                            format!(
                                "{}: {}; the checkpoint was rolled back and the previous profile and active state were verified",
                                res.id, why
                            ),
                        ));
                        Err(if mutated { e.changed() } else { e.possible() })
                    }
                    _ => {
                        let _ = self.risk_ledger("rollback-unverified", rec.clone());
                        Err(SinterError::indeterminate(withheld(
                            sensitive,
                            format!(
                                "{}: {}; the checkpoint rollback ran but the previous state could not be verified (recovery is not guaranteed)",
                                res.id, why
                            ),
                        ))
                        .possible())
                    }
                };
            }
            let _ = self.risk_ledger("checkpoint-rollback-failed", rec.clone());
            return self.nm_wait_and_verify(
                res,
                spec,
                before,
                &rec,
                sensitive,
                &format!(
                    "{}; the explicit rollback failed, so NetworkManager rolls back at the timeout",
                    why
                ),
                mutated,
            );
        }
        self.nm_wait_and_verify(
            res,
            spec,
            before,
            &rec,
            sensitive,
            &format!("{}; the original connection does not answer, so NetworkManager rolls back at the timeout", why),
            mutated,
        )
    }

    /// Wait the checkpoint timeout plus 15 seconds, reconnect and verify
    /// that the previous state is back (§45.7).
    #[allow(clippy::too_many_arguments)]
    fn nm_wait_and_verify(
        &mut self,
        res: &FrozenResource,
        spec: &NmSpec,
        before: &Observed,
        rec: &serde_json::Value,
        sensitive: bool,
        why: &str,
        mutated: bool,
    ) -> Result<()> {
        let _ = self.risk_ledger("checkpoint-waiting", rec.clone());
        self.fs.wait_secs(u64::from(spec.checkpoint_timeout) + 15);
        let alive = self.fs.original_alive() || self.fs.reconnect();
        if alive {
            if let Some(now) = self.nm_observe_settled(res, spec, sensitive) {
                if nm::same_state(before, &now) {
                    let _ = self.risk_ledger("rollback-verified", rec.clone());
                    let e = SinterError::apply(withheld(
                        sensitive,
                        format!(
                            "{}: {}; after the timeout the previous profile and active state were verified",
                            res.id, why
                        ),
                    ));
                    return Err(if mutated { e.changed() } else { e.possible() });
                }
            }
        }
        let _ = self.risk_ledger("rollback-unverified", rec.clone());
        Err(SinterError::indeterminate(withheld(
            sensitive,
            format!(
                "{}: {}; the previous state could not be verified after the timeout{} (recovery is not guaranteed; an out-of-band console may be needed)",
                res.id,
                why,
                if alive { "" } else { " (no connection)" }
            ),
        ))
        .possible())
    }
}
