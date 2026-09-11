use crate::engine::{command_register_map, unknown_result, Engine, Mode};
use crate::error::{MutationState, Result, SinterError};
use crate::executor::{Completion, ExecRequest, Output};
use crate::expressions::{eval_boolean, eval_value_interpolated, parse_expr, EvalVal, Scope};
use crate::model::FrozenResource;
use crate::paths::{mode_to_string, parent_and_name, parse_mode};
use crate::result::Diff;
use crate::result::*;
use crate::targetfs::{ObjKind, Stat, Xattrs};
use crate::value::Value;
use std::collections::BTreeMap;

/// Metadata desired for a filesystem object.
#[derive(Debug, Clone)]
struct MetaSpec {
    owner_uid: Option<u32>,
    group_gid: Option<u32>,
    mode: Option<u32>,
    /// Whether each dimension is explicitly managed (from the recipe).
    manage_owner: bool,
    manage_group: bool,
    manage_mode: bool,
}

fn ev_str(m: &BTreeMap<String, EvalVal>, key: &str) -> Result<Option<(String, bool)>> {
    match m.get(key) {
        None => Ok(None),
        Some(v) => match &v.val {
            None => Err(SinterError::apply(format!(
                "with.{} could not be evaluated (unknown)",
                key
            ))),
            Some(Value::Null) => Ok(None),
            Some(Value::Str(s)) => Ok(Some((s.clone(), v.sensitive))),
            Some(other) => Err(SinterError::apply(format!(
                "with.{} must be a string, got {}",
                key,
                other.type_name()
            ))),
        },
    }
}

fn ev_bool(m: &BTreeMap<String, EvalVal>, key: &str) -> Result<Option<bool>> {
    match m.get(key) {
        None => Ok(None),
        Some(v) => match &v.val {
            None => Err(SinterError::unknown(format!(
                "with.{} could not be evaluated (unknown)",
                key
            ))),
            Some(Value::Null) => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(other) => Err(SinterError::apply(format!(
                "with.{} must be a boolean, got {}",
                key,
                other.type_name()
            ))),
        },
    }
}

fn ev_int(m: &BTreeMap<String, EvalVal>, key: &str) -> Result<Option<i64>> {
    match m.get(key) {
        None => Ok(None),
        Some(v) => match &v.val {
            None => Err(SinterError::unknown(format!(
                "with.{} could not be evaluated (unknown)",
                key
            ))),
            Some(Value::Null) => Ok(None),
            Some(Value::Int(i)) => Ok(Some(*i)),
            Some(other) => Err(SinterError::apply(format!(
                "with.{} must be an integer, got {}",
                key,
                other.type_name()
            ))),
        },
    }
}

fn ev_list_str(m: &BTreeMap<String, EvalVal>, key: &str) -> Result<Option<(Vec<String>, bool)>> {
    match m.get(key) {
        None => Ok(None),
        Some(v) => match &v.val {
            None => Err(SinterError::unknown(format!(
                "with.{} could not be evaluated (unknown)",
                key
            ))),
            Some(Value::List(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for (i, item) in items.iter().enumerate() {
                    match item {
                        Value::Str(s) => {
                            if s.contains('\0') {
                                return Err(SinterError::schema(format!(
                                    "{}.args[{}] may not contain NUL",
                                    key, i
                                )));
                            }
                            out.push(s.clone());
                        }
                        other => {
                            return Err(SinterError::apply(format!(
                                "with.{}[{}] must be a string, got {}",
                                key,
                                i,
                                other.type_name()
                            )))
                        }
                    }
                }
                Ok(Some((out, v.sensitive)))
            }
            Some(Value::Null) => Ok(None),
            Some(other) => Err(SinterError::apply(format!(
                "with.{} must be a list, got {}",
                key,
                other.type_name()
            ))),
        },
    }
}

fn derived_sensitivity(base: bool, vals: &BTreeMap<String, EvalVal>) -> bool {
    base || vals.values().any(|v| v.sensitive)
}

/// Redact a diagnostic that would otherwise embed a sensitive raw value.
fn redact_msg(id: &str, what: &str, detail: &str) -> SinterError {
    SinterError::apply(format!("{}: {} (value redacted): {}", id, what, detail))
}

impl Engine {
    // -----------------------------------------------------------------------
    // file
    // -----------------------------------------------------------------------
    pub(crate) fn run_file(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let path = res.path.clone().ok_or_else(|| {
            SinterError::schema(format!("{}: file resource missing path", res.id))
        })?;
        let vals = self.eval_with(res, item)?;
        let state = ev_str(&vals, "state")?
            .map(|(s, _)| s)
            .unwrap_or_else(|| "present".to_string());
        if state != "present" && state != "absent" {
            return Err(SinterError::schema(format!(
                "{}: file state must be present or absent",
                res.id
            )));
        }

        let stat = self.fs.inspect(&path)?;
        if state == "absent" {
            return self.file_absent(res, &path, stat);
        }

        let content = self.resolve_content(res, &vals)?;
        let content_sensitive = content.sensitive || res.sensitive;
        let effective_content_sensitive = res.sensitive || content_sensitive;
        let meta = self.file_meta(res, &vals, stat.kind, effective_content_sensitive)?;
        self.file_present(
            res,
            &path,
            stat,
            content.bytes,
            effective_content_sensitive,
            meta,
        )
    }

    fn file_absent(
        &mut self,
        res: &FrozenResource,
        path: &str,
        stat: Stat,
    ) -> Result<ResourceResult> {
        match stat.kind {
            ObjKind::Absent => Ok(unchanged_result(res, "path is already absent")),
            ObjKind::File => {
                if self.opts.mode == Mode::Plan {
                    let mut r = changed_result(res);
                    r.diff = Some(Diff {
                        body: DiffBody::Summary {
                            current: "file".into(),
                            desired: "absent".into(),
                        },
                    });
                    return Ok(r);
                }
                self.fs.check_trusted_parents(path)?;
                self.fs.reject_final_symlink(path)?;
                let re = self.fs.inspect(path)?;
                if re.kind != ObjKind::File {
                    return Err(SinterError::apply(format!(
                        "{}: target drift detected before removal of {}",
                        res.id, path
                    )));
                }
                self.fs.remove_file(path)?;
                self.verify_absent(res, path)
            }
            other => Err(SinterError::apply(format!(
                "{}: cannot remove {} of type {}",
                res.id,
                path,
                other.describe()
            ))),
        }
    }

    fn verify_absent(&mut self, res: &FrozenResource, path: &str) -> Result<ResourceResult> {
        let st = match self.fs.inspect(path) {
            Ok(st) => st,
            Err(e) => {
                // The removal already succeeded. A later observation failure
                // must never erase the known mutation.
                let mut r = changed_result(res);
                r.change = Change::Changed;
                if e.kind == crate::error::ErrorKind::Indeterminate {
                    r.execution = Execution::Indeterminate;
                    r.verification = Verification::Unknown;
                } else {
                    r.execution = Execution::Failed;
                    r.verification = Verification::Failed;
                }
                r.reason = Some(format!(
                    "removal of {} succeeded but re-observation failed: {}",
                    path, e.message
                ));
                return Ok(r);
            }
        };
        if st.kind == ObjKind::Absent {
            let mut r = changed_result(res);
            r.verification = Verification::Verified;
            Ok(r)
        } else {
            let mut r = changed_result(res);
            r.verification = Verification::Failed;
            r.execution = Execution::Failed;
            r.reason = Some(format!("path {} still exists after removal", path));
            Ok(r)
        }
    }

    fn resolve_content(
        &mut self,
        res: &FrozenResource,
        vals: &BTreeMap<String, EvalVal>,
    ) -> Result<ContentSpec> {
        let content = ev_str(vals, "content")?;
        let source = ev_str(vals, "source")?;
        match (content, source) {
            (Some((c, sens)), None) => Ok(ContentSpec {
                bytes: Some(c.into_bytes()),
                sensitive: sens,
            }),
            (None, Some((s, sens))) => {
                let sensitive = sens || res.sensitive || res.derived_sensitive;
                let resolved = if std::path::Path::new(&s).is_absolute() {
                    std::path::PathBuf::from(&s)
                } else {
                    crate::model::resolve_source_pub(&res.origin, &s).map_err(|e| {
                        if sensitive {
                            redact_msg(&res.id, "cannot resolve source", "not found or unreadable")
                        } else {
                            e
                        }
                    })?
                };
                let bytes = std::fs::read(&resolved).map_err(|e| {
                    if sensitive {
                        redact_msg(&res.id, "cannot read source", &format!("{}", e.kind()))
                    } else {
                        SinterError::apply(format!(
                            "{}: cannot read source {}: {}",
                            res.id,
                            resolved.display(),
                            e
                        ))
                    }
                })?;
                Ok(ContentSpec {
                    bytes: Some(bytes),
                    sensitive: false,
                })
            }
            (None, None) => Ok(ContentSpec {
                bytes: None,
                sensitive: false,
            }),
            (Some(_), Some(_)) => Err(SinterError::schema(format!(
                "{}: content and source are mutually exclusive",
                res.id
            ))),
        }
    }

    fn file_meta(
        &mut self,
        res: &FrozenResource,
        vals: &BTreeMap<String, EvalVal>,
        existing: ObjKind,
        content_sensitive: bool,
    ) -> Result<MetaSpec> {
        let owner = ev_str(vals, "owner")?;
        let group = ev_str(vals, "group")?;
        let mode = match vals.get("mode") {
            None => None,
            Some(v) => match &v.val {
                None => {
                    return Err(SinterError::unknown(format!(
                        "{}: mode could not be evaluated (unknown)",
                        res.id
                    )))
                }
                Some(Value::Null) => None,
                Some(Value::Str(s)) => Some(
                    parse_mode(s)
                        .map_err(|e| SinterError::schema(format!("{}: {}", res.id, e.message)))?,
                ),
                Some(other) => {
                    return Err(SinterError::schema(format!(
                        "{}: mode must be a string, got {}",
                        res.id,
                        other.type_name()
                    )))
                }
            },
        };
        let is_existing = existing != ObjKind::Absent;
        let manage_owner = owner.is_some();
        let manage_group = group.is_some();
        let manage_mode = mode.is_some();
        let meta_sensitive = content_sensitive || res.sensitive || res.derived_sensitive;

        let owner_uid = if let Some((spec, sens)) = &owner {
            let sensitive = *sens || meta_sensitive;
            Some(self.fs.resolve_uid(spec).map_err(|e| {
                if sensitive {
                    redact_msg(&res.id, "unknown user", "resolution failed")
                } else {
                    e
                }
            })?)
        } else if is_existing {
            None // preserve
        } else {
            Some(self.fs.target_uid)
        };

        let group_gid = if let Some((spec, sens)) = &group {
            let sensitive = *sens || meta_sensitive;
            Some(self.fs.resolve_gid(spec).map_err(|e| {
                if sensitive {
                    redact_msg(&res.id, "unknown group", "resolution failed")
                } else {
                    e
                }
            })?)
        } else if is_existing {
            None // preserve
        } else if let Some(uid) = owner_uid {
            if uid == self.fs.target_uid {
                Some(self.fs.target_gid)
            } else {
                Some(self.fs.primary_gid_of_uid(uid).map_err(|e| {
                    if meta_sensitive {
                        redact_msg(&res.id, "unknown primary group", "resolution failed")
                    } else {
                        e
                    }
                })?)
            }
        } else {
            Some(self.fs.target_gid)
        };

        let mode_final = if let Some(m) = mode {
            Some(m)
        } else if is_existing {
            None // preserve
        } else if content_sensitive {
            Some(0o600)
        } else {
            Some(0o644)
        };

        Ok(MetaSpec {
            owner_uid,
            group_gid,
            mode: mode_final,
            manage_owner,
            manage_group,
            manage_mode,
        })
    }

    fn file_present(
        &mut self,
        res: &FrozenResource,
        path: &str,
        stat: Stat,
        desired_content: Option<Vec<u8>>,
        sensitive: bool,
        meta: MetaSpec,
    ) -> Result<ResourceResult> {
        // Determine whether the object type is acceptable.
        match stat.kind {
            ObjKind::Absent | ObjKind::File => {}
            ObjKind::Symlink => {
                return Err(SinterError::apply(format!(
                    "{}: {} is a symlink; refusing to follow it",
                    res.id, path
                )))
            }
            other => {
                return Err(SinterError::apply(format!(
                    "{}: {} exists as {}; refusing to replace",
                    res.id,
                    path,
                    other.describe()
                )))
            }
        }

        // Resolve the effective desired bytes.
        let effective: Option<Vec<u8>> = match &desired_content {
            Some(c) => Some(c.clone()),
            None => {
                if stat.kind == ObjKind::Absent {
                    Some(Vec::new())
                } else {
                    None // preserve existing content
                }
            }
        };

        // Compute current vs desired content change. Comparison uses remote
        // sha256 so arbitrarily large files can be compared without pulling
        // their full contents onto the controller.
        let desired_sha = effective.as_ref().map(|b| sha256_hex(b));
        let content_changed = match (&effective, stat.kind) {
            (Some(_), ObjKind::Absent) => true,
            (Some(_), ObjKind::File) => {
                let remote = self.fs.sha256(path)?;
                remote.as_deref() != desired_sha.as_deref()
            }
            (None, _) => false,
            _ => false,
        };

        // Compute metadata change.
        let mut meta_changed = false;
        if let Some(uid) = meta.owner_uid {
            if meta.manage_owner && stat.uid != uid {
                meta_changed = true;
            }
        }
        if let Some(gid) = meta.group_gid {
            if meta.manage_group && stat.gid != gid {
                meta_changed = true;
            }
        }
        if let Some(m) = meta.mode {
            if meta.manage_mode && (stat.mode & 0o7777) != m {
                meta_changed = true;
            }
        }

        let need_mutation = content_changed || meta_changed || stat.kind == ObjKind::Absent;

        if self.opts.mode == Mode::Plan {
            if !need_mutation {
                return Ok(unchanged_result(res, "file already matches desired state"));
            }
            let mut r = changed_result_sensitive(res, sensitive);
            if content_changed {
                let desired = effective.clone().unwrap_or_default();
                // Only fetch current bytes when a text diff is actually
                // possible: non-sensitive and within the diff size bound.
                let within = desired.len() <= crate::diff::MAX_DIFF_LINE_BYTES
                    && stat.size as usize <= crate::diff::MAX_DIFF_LINE_BYTES;
                let cur_bytes = if stat.kind == ObjKind::File && !sensitive && within {
                    Some(self.fs.read_file(path)?)
                } else {
                    None
                };
                if sensitive {
                    r.diff = Some(Diff {
                        body: DiffBody::Redacted,
                    });
                    r.notes.push("content diff redacted (sensitive)".into());
                } else if cur_bytes.is_some() {
                    r.diff = Some(crate::diff::content_diff(
                        cur_bytes.as_deref(),
                        &desired,
                        false,
                    ));
                } else {
                    let current = if stat.kind == ObjKind::File {
                        format!("{} bytes", stat.size)
                    } else {
                        "absent".to_string()
                    };
                    r.diff = Some(Diff {
                        body: DiffBody::Summary {
                            current,
                            desired: crate::diff::format_bytes(Some(&desired)),
                        },
                    });
                }
            } else {
                // Metadata change: report the actual current and desired values.
                let current = format!(
                    "mode={} owner={} group={}",
                    mode_to_string(stat.mode),
                    stat.uid,
                    stat.gid
                );
                let desired = format!(
                    "mode={} owner={} group={}",
                    mode_to_string(meta.mode.unwrap_or(stat.mode)),
                    meta.owner_uid.unwrap_or(stat.uid),
                    meta.group_gid.unwrap_or(stat.gid)
                );
                r.diff = Some(Diff {
                    body: DiffBody::Summary { current, desired },
                });
            }
            let _ = &desired_sha;
            return Ok(r);
        }

        // Apply mode.
        if !need_mutation {
            return Ok(unchanged_result(res, "file already matches desired state"));
        }

        self.fs.check_trusted_parents(path)?;
        self.fs.reject_final_symlink(path)?;

        // Capture current object for metadata preservation and xattr checks.
        let (existing_uid, existing_gid, existing_mode) = if stat.kind == ObjKind::File {
            (stat.uid, stat.gid, stat.mode)
        } else {
            (self.fs.target_uid, self.fs.target_gid, 0o644)
        };

        // Determine which metadata to enforce.
        let enforce_uid = meta.owner_uid.unwrap_or(existing_uid);
        let enforce_gid = meta.group_gid.unwrap_or(existing_gid);
        let enforce_mode = meta.mode.unwrap_or(existing_mode);

        if content_changed || stat.kind == ObjKind::Absent {
            // Capture security metadata from the existing file.
            let xattrs: Xattrs = if stat.kind == ObjKind::File {
                if self.fs.fault() == Some("uninspectable_metadata") {
                    Xattrs {
                        attrs: BTreeMap::new(),
                        inspected: false,
                    }
                } else {
                    self.fs.xattrs(path)?
                }
            } else {
                Xattrs {
                    attrs: BTreeMap::new(),
                    inspected: true,
                }
            };
            if let Some(bad) = xattrs.unsafe_attr() {
                return Err(SinterError::apply(format!(
                    "{}: refusing content replacement of {} because it carries {} that cannot be safely preserved",
                    res.id, path, bad
                )));
            }
            if !xattrs.inspected {
                return Err(SinterError::apply(format!(
                    "{}: cannot inspect security metadata of {}; refusing content replacement",
                    res.id, path
                )));
            }
            let bytes = effective.clone().unwrap_or_default();
            let outcome = self.publish_file(
                res,
                path,
                &bytes,
                enforce_uid,
                enforce_gid,
                enforce_mode,
                &xattrs,
                stat,
            )?;

            match outcome {
                PublishOutcome::Indeterminate(reason) => {
                    let mut r = changed_result_sensitive(res, sensitive);
                    r.execution = Execution::Indeterminate;
                    r.change = Change::Possible;
                    r.verification = Verification::Unknown;
                    r.reason = Some(reason);
                    Ok(r)
                }
                PublishOutcome::FailedBeforePublish(reason) => {
                    let mut r = changed_result_sensitive(res, sensitive);
                    r.execution = Execution::Failed;
                    r.change = Change::None;
                    r.verification = Verification::NotPerformed;
                    r.reason = Some(reason);
                    Ok(r)
                }
                PublishOutcome::FailedAfterPublish(reason) => {
                    let mut r = changed_result_sensitive(res, sensitive);
                    r.execution = Execution::Failed;
                    r.change = Change::Changed;
                    r.verification = Verification::Failed;
                    r.reason = Some(reason);
                    Ok(r)
                }
                PublishOutcome::Published => {
                    // Re-observe and verify. Publication already happened, so a
                    // failure to re-observe must NOT be reported as change:none:
                    // the mutation is known to have occurred.
                    let mut r = changed_result_sensitive(res, sensitive);
                    r.change = Change::Changed;
                    match self.verify_file(
                        res,
                        path,
                        Some(&bytes),
                        enforce_uid,
                        enforce_gid,
                        enforce_mode,
                        sensitive,
                    ) {
                        Ok(v) => {
                            if v.verification == Verification::Failed {
                                r.execution = Execution::Failed;
                                r.verification = Verification::Failed;
                                r.reason = v.reason;
                            } else {
                                r.verification = v.verification;
                                r.reason = None;
                            }
                        }
                        Err(e) if e.kind == crate::error::ErrorKind::Indeterminate => {
                            // Publication is a known mutation; verification is
                            // unknown. Change stays Changed.
                            r.execution = Execution::Indeterminate;
                            r.verification = Verification::Unknown;
                            r.reason = Some(format!(
                                "publication succeeded but re-observation was indeterminate: {}",
                                e.message
                            ));
                        }
                        Err(e) => {
                            r.execution = Execution::Failed;
                            r.verification = Verification::Unknown;
                            r.reason = Some(format!(
                                "publication succeeded but re-observation failed: {}",
                                e.message
                            ));
                        }
                    }
                    Ok(r)
                }
            }
        } else {
            // Metadata-only change. Ownership is applied before mode so set-ID
            // bits are not transiently held while owned by the wrong principal.
            // Every successful step is recorded so a later failure can never be
            // reported as change:none.
            let mut mutated = false;
            let mut failure: Option<String> = None;

            if stat.uid != enforce_uid || stat.gid != enforce_gid {
                match self.fs.chown(path, enforce_uid, enforce_gid) {
                    Ok(()) => mutated = true,
                    Err(e) => failure = Some(e.message),
                }
            }
            if failure.is_none() && (stat.mode & 0o7777) != enforce_mode {
                match self.fs.chmod(path, enforce_mode) {
                    Ok(()) => mutated = true,
                    Err(e) => failure = Some(e.message),
                }
            }

            if let Some(reason) = failure {
                let mut r = changed_result_sensitive(res, sensitive);
                r.execution = Execution::Failed;
                r.change = if mutated {
                    Change::Changed
                } else {
                    Change::None
                };
                r.verification = Verification::NotPerformed;
                r.reason = Some(format!(
                    "metadata update failed after {}: {}",
                    if mutated {
                        "a partial mutation"
                    } else {
                        "no mutation"
                    },
                    reason
                ));
                return Ok(r);
            }

            // Controlled injection: force a failure between a successful chown
            // and the chmod step, producing a genuine partial mutation.
            if self.fs.fault() == Some("fail_chmod_after_chown") && mutated {
                let mut r = changed_result_sensitive(res, sensitive);
                r.execution = Execution::Failed;
                r.change = Change::Changed;
                r.verification = Verification::NotPerformed;
                r.reason = Some("injected failure after chown, before chmod".into());
                return Ok(r);
            }

            let v = match self.verify_file(
                res,
                path,
                None,
                enforce_uid,
                enforce_gid,
                enforce_mode,
                sensitive,
            ) {
                Ok(v) => v,
                Err(e) => {
                    // Metadata mutation already completed. Verification failure
                    // must not erase the known change.
                    let mut r = changed_result_sensitive(res, sensitive);
                    r.change = Change::Changed;
                    if e.kind == crate::error::ErrorKind::Indeterminate {
                        r.execution = Execution::Indeterminate;
                        r.verification = Verification::Unknown;
                    } else {
                        r.execution = Execution::Failed;
                        r.verification = Verification::Failed;
                    }
                    r.reason = Some(format!(
                        "metadata mutation succeeded but re-observation failed: {}",
                        e.message
                    ));
                    return Ok(r);
                }
            };
            let mut r = changed_result_sensitive(res, sensitive);
            r.verification = v.verification;
            if v.verification == Verification::Failed {
                r.execution = Execution::Failed;
                r.change = if mutated {
                    Change::Changed
                } else {
                    Change::None
                };
                r.reason = v.reason;
            } else if mutated {
                r.change = Change::Changed;
            }
            Ok(r)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_file(
        &mut self,
        res: &FrozenResource,
        path: &str,
        bytes: &[u8],
        uid: u32,
        gid: u32,
        mode: u32,
        xattrs: &Xattrs,
        observed: Stat,
    ) -> Result<PublishOutcome> {
        let (dir, _name) = parent_and_name(path);
        // Revalidate the protected parent and final path before writing any
        // staging bytes, and confirm the final object still matches what was
        // observed so that publication identity is established.
        self.fs.check_trusted_parents(path)?;
        let cur = self.fs.inspect(path)?;
        if cur.kind == ObjKind::Symlink {
            return Ok(PublishOutcome::FailedBeforePublish(format!(
                "{}: final path {} became a symlink before publication; refusing",
                res.id, path
            )));
        }
        if !same_object_identity(&observed, &cur) {
            return Ok(PublishOutcome::FailedBeforePublish(format!(
                "{}: target drift detected at {} before publication; refusing",
                res.id, path
            )));
        }
        if !self.fs.same_filesystem(&dir, path)? {
            return Ok(PublishOutcome::FailedBeforePublish(format!(
                "{}: atomic same-filesystem publication unavailable for {}",
                res.id, path
            )));
        }

        // Staging lives in a fresh, private 0700 directory with a
        // non-predictable name, so it can never be pre-created or replaced by a
        // non-privileged user between creation and publication.
        let stage_dir = self.fs.make_staging_dir(&dir)?;
        let staging = format!("{}/payload", stage_dir);

        let prepare: Result<()> = (|| -> Result<()> {
            self.fs.write_bytes(&staging, bytes)?;
            self.fs.set_metadata(&staging, mode, uid, gid)?;
            for (name, value) in xattrs.user_attrs() {
                self.fs.set_xattr(name, value, &staging)?;
            }
            Ok(())
        })();

        if let Err(e) = prepare {
            // Nothing has been published; staging cleanup failure must not mask
            // the primary error but is reported alongside it.
            let cleanup_ok = self.cleanup_stage_dir(&stage_dir);
            return Ok(PublishOutcome::FailedBeforePublish(format!(
                "{}: staging preparation failed: {} (staging cleanup {})",
                res.id,
                e.message,
                if cleanup_ok { "succeeded" } else { "failed" }
            )));
        }

        // Controlled failure-injection point (required by DESIGN §34.5).
        if self.fs.fault() == Some("before_publish") {
            let cleanup_ok = self.cleanup_stage_dir(&stage_dir);
            return Ok(PublishOutcome::FailedBeforePublish(format!(
                "{}: injected failure before publication (staging cleanup {})",
                res.id,
                if cleanup_ok { "succeeded" } else { "failed" }
            )));
        }

        // Controlled injection: the rename was dispatched but its completion is
        // unknown. This must be reported as indeterminate/possible, not as a
        // plain failure with change:none.
        if self.fs.fault() == Some("indeterminate_publish") {
            return Ok(PublishOutcome::Indeterminate(format!(
                "{}: injected indeterminate publication result",
                res.id
            )));
        }

        // Revalidate once more immediately before the atomic rename.
        self.fs.check_trusted_parents(path)?;
        let pre = self.fs.inspect(path)?;
        if pre.kind == ObjKind::Symlink || !same_object_identity(&observed, &pre) {
            let _ = self.cleanup_stage_dir(&stage_dir);
            return Ok(PublishOutcome::FailedBeforePublish(format!(
                "{}: target drift detected at {} immediately before publication; refusing",
                res.id, path
            )));
        }

        match self.fs.rename(&staging, path) {
            Ok(()) => {}
            Err(e) => {
                // Classify publication completion BEFORE any cleanup. An
                // indeterminate rename must not trigger cleanup that could
                // destroy evidence or rewrite the publication fact.
                if e.kind == crate::error::ErrorKind::Indeterminate {
                    return Ok(PublishOutcome::Indeterminate(format!(
                        "{}: publication completion is unknown: {}",
                        res.id, e.message
                    )));
                }
                let cleanup_ok = self.cleanup_stage_dir(&stage_dir);
                // A definite rename failure left the destination unchanged
                // (the atomic replace did not take effect).
                return Ok(PublishOutcome::FailedBeforePublish(format!(
                    "{}: publication rename failed before publication: {} (staging cleanup {})",
                    res.id,
                    e.message,
                    if cleanup_ok { "succeeded" } else { "failed" }
                )));
            }
        }

        // The staging directory is now empty; remove it. Failure to clean the
        // empty directory is reported but must not change the published result.
        let cleanup_ok = self.cleanup_stage_dir(&stage_dir);
        if !cleanup_ok {
            return Ok(PublishOutcome::FailedAfterPublish(format!(
                "{}: published successfully but staging directory {} could not be removed",
                res.id, stage_dir
            )));
        }

        if self.fs.fault() == Some("after_publish") {
            return Ok(PublishOutcome::FailedAfterPublish(
                "injected verification failure after publication".into(),
            ));
        }

        Ok(PublishOutcome::Published)
    }

    fn cleanup_stage_dir(&mut self, stage_dir: &str) -> bool {
        if self.fs.fault() == Some("cleanup_stage") {
            return false;
        }
        // Remove the staging payload if present, then the directory.
        let payload = format!("{}/payload", stage_dir);
        match self.fs.inspect(&payload) {
            Ok(stat) if stat.kind == ObjKind::Absent => {}
            Ok(_) => {
                if self.fs.remove_file(&payload).is_err() {
                    return false;
                }
            }
            Err(_) => return false,
        }
        self.fs.rmdir(stage_dir).is_ok()
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_file(
        &mut self,
        res: &FrozenResource,
        path: &str,
        desired: Option<&[u8]>,
        uid: u32,
        gid: u32,
        mode: u32,
        _sensitive: bool,
    ) -> Result<ResourceResult> {
        if self.fs.fault() == Some("reobserve_fail") {
            return Err(SinterError::apply(
                "injected re-observation failure after publication",
            ));
        }
        let st = self.fs.inspect(path)?;
        if st.kind != ObjKind::File {
            let mut r = changed_result(res);
            r.verification = Verification::Failed;
            r.reason = Some(format!("{} is not a regular file after publication", path));
            return Ok(r);
        }
        if let Some(want) = desired {
            // Verify content with a remote digest so empty files and large files
            // are both checked correctly without a full transfer.
            let want_sha = sha256_hex(want);
            let got_sha = self.fs.sha256(path)?;
            if got_sha.as_deref() != Some(want_sha.as_str()) {
                let mut r = changed_result(res);
                r.verification = Verification::Failed;
                r.reason = Some("published content does not match desired content".into());
                return Ok(r);
            }
        }
        if st.uid != uid || st.gid != gid || (st.mode & 0o7777) != mode {
            let mut r = changed_result(res);
            r.verification = Verification::Failed;
            r.reason = Some(format!(
                "metadata mismatch after publication: got uid={} gid={} mode={}, wanted uid={} gid={} mode={}",
                st.uid,
                st.gid,
                mode_to_string(st.mode),
                uid,
                gid,
                mode_to_string(mode)
            ));
            return Ok(r);
        }
        let mut r = changed_result(res);
        r.verification = Verification::Verified;
        Ok(r)
    }

    // -----------------------------------------------------------------------
    // directory
    // -----------------------------------------------------------------------
    pub(crate) fn run_directory(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let path = res
            .path
            .clone()
            .ok_or_else(|| SinterError::schema(format!("{}: directory missing path", res.id)))?;
        let vals = self.eval_with(res, item)?;
        let state = ev_str(&vals, "state")?
            .map(|(s, _)| s)
            .unwrap_or_else(|| "present".to_string());
        if state != "present" && state != "absent" {
            return Err(SinterError::schema(format!(
                "{}: directory state must be present or absent",
                res.id
            )));
        }
        let stat = self.fs.inspect(&path)?;

        if state == "absent" {
            return match stat.kind {
                ObjKind::Absent => Ok(unchanged_result(res, "directory is already absent")),
                ObjKind::Dir => {
                    if self.opts.mode == Mode::Plan {
                        let mut r = changed_result(res);
                        r.diff = Some(Diff {
                            body: DiffBody::Summary {
                                current: "directory".into(),
                                desired: "absent".into(),
                            },
                        });
                        return Ok(r);
                    }
                    self.fs.check_trusted_parents(&path)?;
                    let re = self.fs.inspect(&path)?;
                    if re.kind != ObjKind::Dir {
                        return Err(SinterError::apply(format!(
                            "{}: target drift detected before removal of {}",
                            res.id, path
                        )));
                    }
                    // Only empty directories may be removed.
                    match self.fs.rmdir(&path) {
                        Ok(()) => self.verify_absent(res, &path),
                        Err(e) => {
                            let mut r = changed_result(res);
                            r.execution = if e.kind == crate::error::ErrorKind::Indeterminate {
                                Execution::Indeterminate
                            } else {
                                Execution::Failed
                            };
                            r.change = match e.mutation {
                                MutationState::None => Change::None,
                                MutationState::Changed => Change::Changed,
                                MutationState::Possible => Change::Possible,
                            };
                            r.reason = Some(format!(
                                "directory {} is not empty or could not be removed: {}",
                                path, e.message
                            ));
                            Ok(r)
                        }
                    }
                }
                other => Err(SinterError::apply(format!(
                    "{}: cannot remove {} of type {}",
                    res.id,
                    path,
                    other.describe()
                ))),
            };
        }

        // present
        match stat.kind {
            ObjKind::Absent => {
                let meta = self.dir_meta(res, &vals, ObjKind::Absent)?;
                if self.opts.mode == Mode::Plan {
                    let mut r = changed_result(res);
                    r.diff = Some(Diff {
                        body: DiffBody::Summary {
                            current: "absent".into(),
                            desired: "directory".into(),
                        },
                    });
                    return Ok(r);
                }
                self.fs.check_trusted_parents(&path)?;
                if let Err(e) = self.fs.mkdir(&path) {
                    let mut r = changed_result(res);
                    r.execution = if e.kind == crate::error::ErrorKind::Indeterminate {
                        Execution::Indeterminate
                    } else {
                        Execution::Failed
                    };
                    r.change = if e.kind == crate::error::ErrorKind::Indeterminate {
                        Change::Possible
                    } else {
                        Change::None
                    };
                    r.verification = if r.execution == Execution::Indeterminate {
                        Verification::Unknown
                    } else {
                        Verification::NotPerformed
                    };
                    r.reason = Some(e.message);
                    return Ok(r);
                }
                let mode = meta.mode.unwrap_or(0o755);
                let uid = meta.owner_uid.unwrap_or(self.fs.target_uid);
                let gid = meta.group_gid.unwrap_or(self.fs.target_gid);
                if let Err(e) = self.fs.set_metadata(&path, mode, uid, gid) {
                    let mut r = changed_result(res);
                    r.execution = if e.kind == crate::error::ErrorKind::Indeterminate {
                        Execution::Indeterminate
                    } else {
                        Execution::Failed
                    };
                    r.change = if e.kind == crate::error::ErrorKind::Indeterminate {
                        Change::Possible
                    } else {
                        Change::Changed
                    };
                    r.verification = if r.execution == Execution::Indeterminate {
                        Verification::Unknown
                    } else {
                        Verification::NotPerformed
                    };
                    r.reason = Some(e.message);
                    return Ok(r);
                }
                match self.verify_directory(res, &path, uid, gid, mode) {
                    Ok(result) => Ok(result),
                    Err(e) => Ok(post_mutation_failure(res, e)),
                }
            }
            ObjKind::Dir => {
                let meta = self.dir_meta(res, &vals, ObjKind::Dir)?;
                let uid = meta.owner_uid.unwrap_or(stat.uid);
                let gid = meta.group_gid.unwrap_or(stat.gid);
                let mode = meta.mode.unwrap_or(stat.mode & 0o7777);
                let changed = (meta.manage_owner && stat.uid != uid)
                    || (meta.manage_group && stat.gid != gid)
                    || (meta.manage_mode && (stat.mode & 0o7777) != mode);
                if !changed {
                    return Ok(unchanged_result(
                        res,
                        "directory already matches desired state",
                    ));
                }
                if self.opts.mode == Mode::Plan {
                    let mut r = changed_result(res);
                    r.diff = Some(Diff {
                        body: DiffBody::Summary {
                            current: format!(
                                "mode={} owner={} group={}",
                                mode_to_string(stat.mode),
                                stat.uid,
                                stat.gid
                            ),
                            desired: format!(
                                "mode={} owner={} group={}",
                                mode_to_string(mode),
                                uid,
                                gid
                            ),
                        },
                    });
                    return Ok(r);
                }
                self.fs.check_trusted_parents(&path)?;
                let mut mutated = false;
                if let Err(e) = self.fs.chown(&path, uid, gid) {
                    return Ok(metadata_failure(res, e, mutated));
                }
                mutated = true;
                if let Err(e) = self.fs.chmod(&path, mode) {
                    return Ok(metadata_failure(res, e, mutated));
                }
                match self.verify_directory(res, &path, uid, gid, mode) {
                    Ok(result) => Ok(result),
                    Err(e) => Ok(post_mutation_failure(res, e)),
                }
            }
            other => Err(SinterError::apply(format!(
                "{}: {} exists as {}; refusing to manage as directory",
                res.id,
                path,
                other.describe()
            ))),
        }
    }

    fn dir_meta(
        &mut self,
        res: &FrozenResource,
        vals: &BTreeMap<String, EvalVal>,
        existing: ObjKind,
    ) -> Result<MetaSpec> {
        let owner = ev_str(vals, "owner")?;
        let group = ev_str(vals, "group")?;
        let mode = match vals.get("mode") {
            None => None,
            Some(v) => match &v.val {
                None => {
                    return Err(SinterError::apply(format!(
                        "{}: mode could not be evaluated",
                        res.id
                    )))
                }
                Some(Value::Null) => None,
                Some(Value::Str(s)) => {
                    Some(parse_mode(s).map_err(|e| SinterError::schema(e.message))?)
                }
                Some(other) => {
                    return Err(SinterError::schema(format!(
                        "{}: mode must be a string, got {}",
                        res.id,
                        other.type_name()
                    )))
                }
            },
        };
        let is_existing = existing != ObjKind::Absent;
        let owner_uid = if let Some((spec, _)) = &owner {
            Some(self.fs.resolve_uid(spec)?)
        } else if is_existing {
            None
        } else {
            Some(self.fs.target_uid)
        };
        let group_gid = if let Some((spec, _)) = &group {
            Some(self.fs.resolve_gid(spec)?)
        } else if is_existing {
            None
        } else if let Some(uid) = owner_uid {
            if uid == self.fs.target_uid {
                Some(self.fs.target_gid)
            } else {
                Some(self.fs.primary_gid_of_uid(uid)?)
            }
        } else {
            Some(self.fs.target_gid)
        };
        let mode_final = if mode.is_some() {
            mode
        } else if is_existing {
            None
        } else {
            Some(0o755)
        };
        Ok(MetaSpec {
            owner_uid,
            group_gid,
            mode: mode_final,
            manage_owner: owner.is_some(),
            manage_group: group.is_some(),
            manage_mode: mode.is_some(),
        })
    }

    fn verify_directory(
        &mut self,
        res: &FrozenResource,
        path: &str,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> Result<ResourceResult> {
        let st = self.fs.inspect(path)?;
        if st.kind != ObjKind::Dir {
            let mut r = changed_result(res);
            r.verification = Verification::Failed;
            r.reason = Some(format!("{} is not a directory after mutation", path));
            return Ok(r);
        }
        if st.uid != uid || st.gid != gid || (st.mode & 0o7777) != mode {
            let mut r = changed_result(res);
            r.verification = Verification::Failed;
            r.reason = Some(format!(
                "directory metadata mismatch after mutation: got uid={} gid={} mode={}",
                st.uid,
                st.gid,
                mode_to_string(st.mode)
            ));
            return Ok(r);
        }
        let mut r = changed_result(res);
        r.verification = Verification::Verified;
        Ok(r)
    }

    // -----------------------------------------------------------------------
    // link
    // -----------------------------------------------------------------------
    pub(crate) fn run_link(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let path = res
            .path
            .clone()
            .ok_or_else(|| SinterError::schema(format!("{}: link missing path", res.id)))?;
        let vals = self.eval_with(res, item)?;
        let state = ev_str(&vals, "state")?
            .map(|(s, _)| s)
            .unwrap_or_else(|| "present".to_string());
        let target = ev_str(&vals, "target")?;
        let stat = self.fs.inspect(&path)?;

        if state == "absent" {
            return match stat.kind {
                ObjKind::Absent => Ok(unchanged_result(res, "link is already absent")),
                ObjKind::Symlink => {
                    if self.opts.mode == Mode::Plan {
                        let cur = self.fs.readlink(&path)?;
                        let mut r = changed_result(res);
                        r.diff = Some(Diff {
                            body: DiffBody::Summary {
                                current: format!("symlink -> {}", cur),
                                desired: "absent".to_string(),
                            },
                        });
                        return Ok(r);
                    }
                    self.fs.check_trusted_parents(&path)?;
                    self.fs.remove_symlink(&path)?;
                    self.verify_absent(res, &path)
                }
                other => Err(SinterError::apply(format!(
                    "{}: {} is {}; refusing to remove as link",
                    res.id,
                    path,
                    other.describe()
                ))),
            };
        }

        let (target_val, target_sens) = target.ok_or_else(|| {
            SinterError::schema(format!("{}: link target is required when present", res.id))
        })?;
        if target_val.contains('\0') {
            return Err(SinterError::schema(format!(
                "{}: link target may not contain NUL",
                res.id
            )));
        }
        // DESIGN §31: derived/desired values from sensitive inputs stay sensitive.
        let link_sensitive = target_sens || res.sensitive || res.derived_sensitive;

        match stat.kind {
            ObjKind::Absent => {
                if self.opts.mode == Mode::Plan {
                    let mut r = changed_result_sensitive(res, link_sensitive);
                    let desired = if link_sensitive {
                        "symlink -> [redacted]".to_string()
                    } else {
                        format!("symlink -> {}", target_val)
                    };
                    r.diff = Some(Diff {
                        body: DiffBody::Summary {
                            current: "absent".to_string(),
                            desired,
                        },
                    });
                    return Ok(r);
                }
                self.fs.check_trusted_parents(&path)?;
                self.fs.symlink(&target_val, &path)?;
                match self.verify_link(res, &path, &target_val) {
                    Ok(result) => Ok(result),
                    Err(e) => Ok(post_mutation_failure(res, e)),
                }
            }
            ObjKind::Symlink => {
                let cur = self.fs.readlink(&path)?;
                if cur == target_val {
                    return Ok(unchanged_result(
                        res,
                        "symlink already points to desired target",
                    ));
                }
                if self.opts.mode == Mode::Plan {
                    let mut r = changed_result_sensitive(res, link_sensitive);
                    let desired = if link_sensitive {
                        "symlink -> [redacted]".to_string()
                    } else {
                        format!("symlink -> {}", target_val)
                    };
                    let current = if link_sensitive {
                        // Current target is not the secret, but keep presentation
                        // conservative when the desired side is sensitive.
                        format!("symlink -> {}", cur)
                    } else {
                        format!("symlink -> {}", cur)
                    };
                    r.diff = Some(Diff {
                        body: DiffBody::Summary { current, desired },
                    });
                    return Ok(r);
                }
                self.fs.check_trusted_parents(&path)?;
                self.fs.symlink_replace(&target_val, &path, &stat)?;
                match self.verify_link(res, &path, &target_val) {
                    Ok(result) => Ok(result),
                    Err(e) => Ok(post_mutation_failure(res, e)),
                }
            }
            other => Err(SinterError::apply(format!(
                "{}: {} is {}; refusing to replace as symlink",
                res.id,
                path,
                other.describe()
            ))),
        }
    }

    fn verify_link(
        &mut self,
        res: &FrozenResource,
        path: &str,
        target: &str,
    ) -> Result<ResourceResult> {
        let st = self.fs.inspect(path)?;
        if st.kind != ObjKind::Symlink {
            let mut r = changed_result(res);
            r.verification = Verification::Failed;
            r.reason = Some(format!("{} is not a symlink after mutation", path));
            return Ok(r);
        }
        let cur = self.fs.readlink(path)?;
        if cur != target {
            let mut r = changed_result(res);
            r.verification = Verification::Failed;
            r.reason = Some(format!("symlink target mismatch: got {:?}", cur));
            return Ok(r);
        }
        let mut r = changed_result(res);
        r.verification = Verification::Verified;
        Ok(r)
    }

    // -----------------------------------------------------------------------
    // template
    // -----------------------------------------------------------------------
    pub(crate) fn run_template(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let path = res
            .path
            .clone()
            .ok_or_else(|| SinterError::schema(format!("{}: template missing path", res.id)))?;
        let vals = self.eval_with(res, item)?;
        let state = ev_str(&vals, "state")?
            .map(|(s, _)| s)
            .unwrap_or_else(|| "present".to_string());
        if state == "absent" {
            // Delegate to file_absent semantics.
            let stat = self.fs.inspect(&path)?;
            return self.file_absent(res, &path, stat);
        }

        let source = res
            .controller_source
            .clone()
            .ok_or_else(|| SinterError::schema(format!("{}: template missing source", res.id)))?;
        let template_text = std::fs::read_to_string(&source).map_err(|e| {
            SinterError::apply(format!(
                "{}: cannot read template {}: {}",
                res.id,
                source.display(),
                e
            ))
        })?;

        // Template-local vars. Per DESIGN §26.4 these are literal values exposed
        // under template.<name>; they are NOT interpolated and do not shadow any
        // other namespace.
        let mut tvals: BTreeMap<String, EvalVal> = BTreeMap::new();
        if let Some(Value::Map(m)) = res.with.get("vars") {
            for (k, v) in m {
                tvals.insert(k.clone(), EvalVal::known(v.clone()));
            }
        }
        let rendered = {
            let scope = self.scope(item, None, Some(&tvals));
            match crate::expressions::eval_interpolated(&template_text, &scope) {
                Ok(v) => match v.val {
                    Some(Value::Str(s)) => (s, v.sensitive),
                    Some(other) => (
                        other.canonical_scalar_string().unwrap_or_default(),
                        v.sensitive,
                    ),
                    None => {
                        return Err(SinterError::apply(format!(
                            "{}: template rendering produced Unknown",
                            res.id
                        )))
                    }
                },
                Err(e) => {
                    return Err(SinterError::apply(format!(
                        "{}: template rendering error: {}",
                        res.id, e
                    )))
                }
            }
        };

        let stat = self.fs.inspect(&path)?;
        let sensitive = res.sensitive || rendered.1;
        let meta = self.file_meta(res, &vals, stat.kind, sensitive)?;
        self.file_present(
            res,
            &path,
            stat,
            Some(rendered.0.into_bytes()),
            sensitive,
            meta,
        )
    }

    // -----------------------------------------------------------------------
    // command
    // -----------------------------------------------------------------------
    pub(crate) fn run_command(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let program = res
            .program
            .clone()
            .ok_or_else(|| SinterError::schema(format!("{}: command missing program", res.id)))?;
        let vals = self.eval_with(res, item)?;
        let (args, args_sens) = ev_list_str(&vals, "args")?.unwrap_or((Vec::new(), false));
        let (cwd, cwd_sens) = match ev_str(&vals, "cwd")? {
            Some(v) => (Some(v.0), v.1),
            None => (None, false),
        };
        let env = match vals.get("env") {
            None => (BTreeMap::new(), false),
            Some(v) => match &v.val {
                Some(Value::Map(m)) => {
                    let mut out = BTreeMap::new();
                    for (k, val) in m {
                        match val {
                            Value::Str(s) => {
                                if s.contains('\0') || k.contains('\0') {
                                    return Err(SinterError::schema(format!(
                                        "{}: command env may not contain NUL",
                                        res.id
                                    )));
                                }
                                out.insert(k.clone(), s.clone());
                            }
                            _ => {
                                return Err(SinterError::apply(format!(
                                    "{}: command env values must be strings",
                                    res.id
                                )))
                            }
                        }
                    }
                    (out, v.sensitive)
                }
                _ => {
                    return Err(SinterError::apply(format!(
                        "{}: command env must be a map",
                        res.id
                    )))
                }
            },
        };

        let timeout = ev_int(&vals, "timeout_seconds")?.unwrap_or(300) as u64;
        let success_codes: Vec<i32> = match vals.get("success_codes") {
            None => vec![0],
            Some(v) => match &v.val {
                Some(Value::List(items)) => items
                    .iter()
                    .filter_map(|i| i.as_int().map(|n| n as i32))
                    .collect(),
                _ => vec![0],
            },
        };

        let command_sensitive = derived_sensitivity(res.sensitive, &vals); // whole-command rule

        // Guards.
        if let Some(creates) = &res.creates {
            let st = self.fs.inspect(creates)?;
            match st.kind {
                ObjKind::Absent => {}
                _ => {
                    return self.guard_satisfied(res, "creates guard path is present");
                }
            }
        } else if let Some(removes) = &res.removes {
            let st = self.fs.inspect(removes)?;
            if st.kind == ObjKind::Absent {
                return self.guard_satisfied(res, "removes guard path is absent");
            }
        }

        if self.opts.mode == Mode::Plan {
            // Plan never executes a command resource.
            if let Some(reg) = &res.register {
                self.registers.insert(reg.clone(), EvalVal::unknown());
            }
            let mut r = unknown_result(res);
            r.sensitive = command_sensitive;
            r.reason = Some("command not executed during plan".into());
            r.verification = Verification::NotApplicable;
            return Ok(r);
        }

        // Apply: actually execute.
        let mut req = ExecRequest::new(&program);
        req.args = args.clone();
        req.cwd = cwd.clone();
        req.env = env.0.clone();
        req.timeout_secs = timeout;
        // DESIGN §31.3/31.4: if any evaluated command input is sensitive the
        // whole command is sensitive, including internal audit records.
        req.sensitive = command_sensitive;
        // Add the fixed baseline environment.
        req.env.insert(
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        );
        req.env.insert("LANG".to_string(), "C.UTF-8".to_string());
        req.env.insert("LC_ALL".to_string(), "C.UTF-8".to_string());
        req.env.insert("HOME".to_string(), self.fs.home_env());

        let out = self.fs.exec(&req)?;
        let _ = (args_sens, cwd_sens);
        let _ = cwd_sens;
        match out.completion {
            Completion::Indeterminate { ref reason, .. } => {
                if let Some(reg) = &res.register {
                    let map = command_register_map(
                        true,
                        Some(&out.completion),
                        Some(&out),
                        None,
                        "indeterminate",
                    );
                    self.registers
                        .insert(reg.clone(), register_eval(map, command_sensitive));
                }
                let mut r = changed_result(res);
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::NotApplicable;
                r.sensitive = command_sensitive;
                r.reason = Some(reason.clone());
                Ok(r)
            }
            Completion::Signaled(sig) => {
                let map =
                    command_register_map(true, Some(&out.completion), Some(&out), None, "failed");
                if let Some(reg) = &res.register {
                    self.registers
                        .insert(reg.clone(), register_eval(map, command_sensitive));
                }
                let mut r = changed_result(res);
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::NotApplicable;
                r.sensitive = command_sensitive;
                r.reason = Some(format!("command terminated by signal {}", sig));
                Ok(r)
            }
            Completion::Exited(code) => {
                let success = success_codes.contains(&code);
                if !success {
                    let map = command_register_map(
                        true,
                        Some(&out.completion),
                        Some(&out),
                        None,
                        "failed",
                    );
                    if let Some(reg) = &res.register {
                        self.registers
                            .insert(reg.clone(), register_eval(map, command_sensitive));
                    }
                    let mut r = changed_result(res);
                    r.execution = Execution::Failed;
                    r.change = Change::Possible;
                    r.verification = Verification::NotApplicable;
                    r.sensitive = command_sensitive;
                    r.reason = Some(format!(
                        "command exit code {} is not in success_codes",
                        code
                    ));
                    return Ok(r);
                }

                // Evaluate changed_when.
                let (changed, changed_err) =
                    self.eval_changed_when(res, &out, command_sensitive)?;
                if let Some(err) = changed_err {
                    let map = command_register_map(
                        true,
                        Some(&out.completion),
                        Some(&out),
                        None,
                        "failed",
                    );
                    if let Some(reg) = &res.register {
                        self.registers
                            .insert(reg.clone(), register_eval(map, command_sensitive));
                    }
                    let mut r = changed_result(res);
                    r.execution = Execution::Failed;
                    r.change = Change::Possible;
                    r.verification = Verification::NotApplicable;
                    r.sensitive = command_sensitive;
                    r.reason = Some(format!("changed_when evaluation failed: {}", err));
                    return Ok(r);
                }

                if let Some(reg) = &res.register {
                    let map = command_register_map(
                        true,
                        Some(&out.completion),
                        Some(&out),
                        changed,
                        "succeeded",
                    );
                    self.registers
                        .insert(reg.clone(), register_eval(map, command_sensitive));
                }
                let mut r = changed_result(res);
                r.execution = Execution::Succeeded;
                r.change = if changed == Some(true) {
                    Change::Changed
                } else {
                    Change::None
                };
                r.verification = Verification::NotApplicable;
                r.sensitive = command_sensitive;
                if let Some(reg) = &res.register {
                    r.notes.push(format!("registered {}", reg));
                }
                Ok(r)
            }
        }
    }

    fn eval_changed_when(
        &self,
        res: &FrozenResource,
        out: &Output,
        sensitive: bool,
    ) -> Result<(Option<bool>, Option<String>)> {
        let cw = match res.with.get("changed_when") {
            None => return Ok((Some(true), None)),
            Some(Value::Null) => return Ok((Some(true), None)),
            Some(Value::Str(s)) => s.clone(),
            Some(_) => {
                return Err(SinterError::schema(format!(
                    "{}: changed_when must be a string",
                    res.id
                )))
            }
        };
        let expr = parse_expr(&cw)
            .map_err(|e| SinterError::schema(format!("{}: invalid changed_when: {}", res.id, e)))?;
        let mut fields: BTreeMap<String, EvalVal> = BTreeMap::new();
        fields.insert("executed".to_string(), EvalVal::known(Value::Bool(true)));
        fields.insert(
            "exit_code".to_string(),
            EvalVal::known(match out.completion {
                Completion::Exited(c) => Value::Int(c as i64),
                _ => Value::Null,
            }),
        );
        let sel = |bytes: &[u8], trunc: bool| -> (Value, bool) {
            if trunc {
                (Value::Null, false)
            } else {
                match std::str::from_utf8(bytes) {
                    Ok(s) => (Value::Str(s.to_string()), true),
                    Err(_) => (Value::Null, false),
                }
            }
        };
        let (so, sc) = sel(&out.stdout, out.stdout_truncated);
        let (se, ec) = sel(&out.stderr, out.stderr_truncated);
        fields.insert(
            "stdout".to_string(),
            if sensitive {
                EvalVal::known_sensitive(so)
            } else {
                EvalVal::known(so)
            },
        );
        fields.insert(
            "stderr".to_string(),
            if sensitive {
                EvalVal::known_sensitive(se)
            } else {
                EvalVal::known(se)
            },
        );
        fields.insert(
            "stdout_complete".to_string(),
            EvalVal::known(Value::Bool(sc)),
        );
        fields.insert(
            "stderr_complete".to_string(),
            EvalVal::known(Value::Bool(ec)),
        );
        let scope = Scope {
            vars: Some(&self.vars),
            facts: Some(&self.facts),
            registers: Some(&self.registers),
            item: None,
            result: Some(&fields),
            template: None,
        };
        match eval_boolean(&expr, &scope) {
            Ok(v) => match v.val {
                Some(Value::Bool(b)) => Ok((Some(b), None)),
                _ => Ok((None, Some("changed_when produced Unknown".into()))),
            },
            Err(e) => Ok((None, Some(e.to_string()))),
        }
    }

    fn guard_satisfied(&mut self, res: &FrozenResource, reason: &str) -> Result<ResourceResult> {
        if let Some(reg) = &res.register {
            let mut map = BTreeMap::new();
            map.insert("executed".to_string(), Value::Bool(false));
            map.insert("exit_code".to_string(), Value::Null);
            map.insert("stdout".to_string(), Value::Null);
            map.insert("stderr".to_string(), Value::Null);
            map.insert("stdout_complete".to_string(), Value::Bool(true));
            map.insert("stderr_complete".to_string(), Value::Bool(true));
            map.insert("changed".to_string(), Value::Bool(false));
            map.insert("execution".to_string(), Value::Str("succeeded".into()));
            self.registers
                .insert(reg.clone(), register_eval(map, res.sensitive));
        }
        let mut r = changed_result(res);
        r.execution = Execution::Succeeded;
        r.change = Change::None;
        r.verification = Verification::NotApplicable;
        r.disposition = Disposition::GuardSatisfied;
        r.reason = Some(reason.to_string());
        Ok(r)
    }

    // -----------------------------------------------------------------------
    // package
    // -----------------------------------------------------------------------
    pub(crate) fn run_package(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let name = res
            .package_name
            .clone()
            .ok_or_else(|| SinterError::schema(format!("{}: package missing name", res.id)))?;
        let vals = self.eval_with(res, item)?;
        let state = ev_str(&vals, "state")?
            .map(|(s, _)| s)
            .ok_or_else(|| SinterError::schema(format!("{}: package state is required", res.id)))?;
        if state != "present" && state != "absent" {
            return Err(SinterError::apply(format!(
                "{}: package state must resolve to present or absent",
                res.id
            )));
        }
        let observed = self.observe_package(&name)?;
        let want_installed = state == "present";
        let is_installed = matches!(observed, PackageState::Installed);

        if want_installed == is_installed {
            return Ok(unchanged_result(res, "package already in desired state"));
        }

        if self.opts.mode == Mode::Plan {
            let mut r = changed_result(res);
            r.diff = Some(Diff {
                body: DiffBody::Summary {
                    current: if is_installed { "installed" } else { "absent" }.into(),
                    desired: if want_installed {
                        "installed"
                    } else {
                        "absent"
                    }
                    .into(),
                },
            });
            return Ok(r);
        }

        let mut req = ExecRequest::new("/usr/bin/apt-get");
        req.env = baseline_env(self.fs.home_env());
        if want_installed {
            req.args = vec!["-y".to_string(), "install".to_string(), name.clone()];
        } else {
            req.args = vec!["-y".to_string(), "remove".to_string(), name.clone()];
        }
        req.timeout_secs = 300;
        let out = self.fs.exec(&req)?;
        match out.completion {
            Completion::Indeterminate { reason, .. } => {
                let mut r = changed_result(res);
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!("apt operation did not complete: {}", reason));
                return Ok(r);
            }
            Completion::Signaled(s) => {
                let mut r = changed_result(res);
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!("apt operation terminated by signal {}", s));
                return Ok(r);
            }
            Completion::Exited(code) => {
                if code != 0 {
                    let mut r = changed_result(res);
                    r.execution = Execution::Failed;
                    r.change = Change::Possible;
                    r.verification = Verification::Unknown;
                    r.reason = Some(format!(
                        "apt-get {} {} failed with exit code {}: {}",
                        if want_installed { "install" } else { "remove" },
                        name,
                        code,
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                    return Ok(r);
                }
            }
        }

        // Re-observe and verify. A successful apt dispatch is retained even if
        // the post-mutation observation fails.
        let after = match self.observe_package(&name) {
            Ok(after) => after,
            Err(e) => {
                let mut r = changed_result(res);
                r.execution = if e.kind == crate::error::ErrorKind::Indeterminate {
                    Execution::Indeterminate
                } else {
                    Execution::Failed
                };
                r.change = if e.kind == crate::error::ErrorKind::Indeterminate {
                    Change::Possible
                } else {
                    Change::Changed
                };
                r.verification = if r.execution == Execution::Indeterminate {
                    Verification::Unknown
                } else {
                    Verification::Failed
                };
                r.reason = Some(format!(
                    "package mutation succeeded but re-observation failed: {}",
                    e.message
                ));
                return Ok(r);
            }
        };
        let verified = matches!(after, PackageState::Installed) == want_installed;
        let mut r = changed_result(res);
        r.change = Change::Changed;
        if verified {
            r.verification = Verification::Verified;
        } else {
            r.execution = Execution::Failed;
            r.verification = Verification::Failed;
            r.reason = Some("package state did not reach desired state after mutation".into());
        }
        Ok(r)
    }

    fn observe_package(&mut self, name: &str) -> Result<PackageState> {
        // argv-only: the package name never becomes shell syntax. dpkg-query
        // prints the status on stdout and uses its exit status to signal
        // absence, so we must distinguish exit 1 (confirmed absent) from any
        // other failure (inspection failed).
        if self.fs.fault() == Some("dpkg_observe_fail") {
            return Err(SinterError::apply(format!(
                "package observation failed for {}: injected dpkg-query failure",
                name
            )));
        }
        let out = self.fs.dpkg_query(name)?;
        match out.completion {
            Completion::Exited(0) => {
                let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
                classify_dpkg_status(&status)
            }
            Completion::Exited(1) => {
                // Confirmed absent: dpkg-query found no matching package.
                Ok(PackageState::Absent)
            }
            Completion::Exited(c) => Err(SinterError::apply(format!(
                "package observation failed for {}: dpkg-query exited {} ({})",
                name,
                c,
                String::from_utf8_lossy(&out.stderr).trim()
            ))),
            Completion::Signaled(s) => Err(SinterError::apply(format!(
                "package observation for {} terminated by signal {}",
                name, s
            ))),
            Completion::Indeterminate { reason, .. } => Err(SinterError::indeterminate(format!(
                "package observation for {} did not complete: {}",
                name, reason
            ))),
        }
    }

    // -----------------------------------------------------------------------
    // service
    // -----------------------------------------------------------------------
    pub(crate) fn run_service(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let name = res
            .service_name
            .clone()
            .ok_or_else(|| SinterError::schema(format!("{}: service missing name", res.id)))?;
        let vals = self.eval_with(res, item)?;
        let want_state = ev_str(&vals, "state")?.map(|(s, _)| s);
        let want_enabled = ev_bool(&vals, "enabled")?;
        if let Some(state) = &want_state {
            if state != "running" && state != "stopped" {
                return Err(SinterError::apply(format!(
                    "{}: service state must resolve to running or stopped",
                    res.id
                )));
            }
        }
        let obs = self.observe_service(&name)?;

        if obs.load_state == "not-found" {
            if self.opts.mode == Mode::Plan && self.service_has_present_package_dep(res)? {
                let mut r = unknown_result(res);
                r.reason = Some("deferred/unknown until dependency apply".into());
                r.verification = Verification::NotPerformed;
                return Ok(r);
            }
            return Err(if self.opts.mode == Mode::Plan {
                SinterError::plan(format!("{}: service unit {} was not found", res.id, name))
            } else {
                SinterError::apply(format!("{}: service unit {} was not found", res.id, name))
            });
        }

        if want_state.as_deref() == Some("running") && obs.unit_file_state == "masked" {
            return Err(SinterError::apply(format!(
                "{}: service {} is masked and cannot be started",
                res.id, name
            )));
        }
        if want_enabled.is_some() && obs.unit_file_state == "static" {
            return Err(SinterError::apply(format!(
                "{}: service {} is static and cannot be enabled/disabled",
                res.id, name
            )));
        }

        // Determine required mutations.
        let state_needs = want_state.as_deref().map(|want| {
            let running = obs.active_state == "active";
            let failed = obs.active_state == "failed";
            let matches = if want == "running" {
                running && !failed
            } else {
                // stopped means inactive and not failed
                obs.active_state == "inactive" && !failed
            };
            !matches
        });
        let enabled_needs = match want_enabled {
            None => false,
            Some(want) => (obs.unit_file_state == "enabled") != want,
        };

        if state_needs != Some(true) && !enabled_needs {
            return Ok(unchanged_result(
                res,
                "service already matches desired state",
            ));
        }

        if self.opts.mode == Mode::Plan {
            let mut r = changed_result(res);
            r.diff = Some(Diff {
                body: DiffBody::Summary {
                    current: format!(
                        "active={} enabled={}",
                        obs.active_state, obs.unit_file_state
                    ),
                    desired: format!(
                        "state={} enabled={}",
                        want_state.clone().unwrap_or_else(|| "unmanaged".into()),
                        want_enabled
                            .map(|b| b.to_string())
                            .unwrap_or_else(|| "unmanaged".into())
                    ),
                },
            });
            return Ok(r);
        }

        // Apply ordering table. Keep mutation history local to this resource so
        // a later step cannot erase an earlier successful mutation.
        let runit = |e: &mut Self, args: &[&str]| -> Result<()> {
            let mut req = ExecRequest::new("/usr/bin/systemctl");
            req.args = args.iter().map(|s| s.to_string()).collect();
            req.env = baseline_env(e.fs.home_env());
            let out = e.fs.exec(&req)?;
            match out.completion {
                Completion::Exited(0) => Ok(()),
                Completion::Exited(c) => Err(SinterError::apply(format!(
                    "systemctl {} failed with exit code {}: {}",
                    args.join(" "),
                    c,
                    String::from_utf8_lossy(&out.stderr).trim()
                ))),
                Completion::Signaled(s) => Err(SinterError::apply(format!(
                    "systemctl {} terminated by signal {}",
                    args.join(" "),
                    s
                ))),
                Completion::Indeterminate { reason, .. } => Err(SinterError::indeterminate(reason)),
            }
        };

        let desired_state = want_state.as_deref().unwrap_or("");
        let desired_enabled = want_enabled;
        let mut mutated = false;
        // Ordering:
        //  running/true  -> enable if needed then start if needed
        //  running/false -> disable if needed then start if needed
        //  stopped/true  -> stop if needed then enable if needed
        //  stopped/false -> stop if needed then disable if needed
        match (desired_state, desired_enabled) {
            ("running", Some(en)) => {
                if enabled_needs {
                    if let Err(e) = runit(self, &[if en { "enable" } else { "disable" }, &name]) {
                        return Ok(service_step_failure(res, e, mutated));
                    }
                    mutated = true;
                }
                if state_needs == Some(true) {
                    if let Err(e) = runit(self, &["start", &name]) {
                        return Ok(service_step_failure(res, e, mutated));
                    }
                    mutated = true;
                }
            }
            ("stopped", Some(en)) => {
                if state_needs == Some(true) {
                    if let Err(e) = self.stop_and_reset(&name) {
                        return Ok(service_step_failure(res, e, mutated));
                    }
                    mutated = true;
                }
                if enabled_needs {
                    if let Err(e) = runit(self, &[if en { "enable" } else { "disable" }, &name]) {
                        return Ok(service_step_failure(res, e, mutated));
                    }
                    mutated = true;
                }
            }
            ("running", None) => {
                if state_needs == Some(true) {
                    if let Err(e) = runit(self, &["start", &name]) {
                        return Ok(service_step_failure(res, e, mutated));
                    }
                    mutated = true;
                }
            }
            ("stopped", None) => {
                if state_needs == Some(true) {
                    if let Err(e) = self.stop_and_reset(&name) {
                        return Ok(service_step_failure(res, e, mutated));
                    }
                    mutated = true;
                }
            }
            ("", Some(en)) => {
                if enabled_needs {
                    if let Err(e) = runit(self, &[if en { "enable" } else { "disable" }, &name]) {
                        return Ok(service_step_failure(res, e, mutated));
                    }
                    mutated = true;
                }
            }
            ("", None) => {}
            _ => {}
        }

        // Controlled injection: successful service mutation followed by a
        // re-observation failure. Mutation truth must be preserved.
        if self.fs.fault() == Some("service_reobserve_fail") {
            return Ok(service_step_failure(
                res,
                SinterError::apply("injected service re-observation failure after mutation"),
                mutated,
            ));
        }

        // Re-observe and verify every requested dimension.
        let after = match self.observe_service(&name) {
            Ok(after) => after,
            Err(e) => return Ok(service_step_failure(res, e, mutated)),
        };
        let mut ok = true;
        let mut detail = String::new();
        if let Some(want) = &want_state {
            if want == "running" {
                if after.active_state != "active" {
                    ok = false;
                    detail = format!("service is {}", after.active_state);
                }
            } else if want == "stopped"
                && (after.active_state != "inactive" || after.active_state == "failed")
            {
                ok = false;
                detail = format!("service is {}", after.active_state);
            }
        }
        if let Some(want) = want_enabled {
            if (after.unit_file_state == "enabled") != want {
                ok = false;
                detail = format!("service enabled state is {}", after.unit_file_state);
            }
        }
        let mut r = changed_result(res);
        r.change = Change::Changed;
        if ok {
            r.verification = Verification::Verified;
        } else {
            r.execution = Execution::Failed;
            r.verification = Verification::Failed;
            r.reason = Some(format!("service verification failed: {}", detail));
        }
        Ok(r)
    }

    fn stop_and_reset(&mut self, name: &str) -> Result<()> {
        let mut req = ExecRequest::new("/usr/bin/systemctl");
        req.args = vec!["stop".to_string(), name.to_string()];
        req.env = baseline_env(self.fs.home_env());
        let out = self.fs.exec(&req)?;
        match out.completion {
            Completion::Exited(0) => {}
            Completion::Exited(_) | Completion::Signaled(_) => {
                return Err(SinterError::apply(format!(
                    "systemctl stop {} failed",
                    name
                )));
            }
            Completion::Indeterminate { reason, .. } => {
                // Stop completion unknown: mutation may have occurred.
                return Err(SinterError::indeterminate(format!(
                    "systemctl stop {} did not complete: {}",
                    name, reason
                )));
            }
        }
        // Clear a failed state so that "stopped" is clean, not failed.
        let mut req = ExecRequest::new("/usr/bin/systemctl");
        req.args = vec!["reset-failed".to_string(), name.to_string()];
        req.env = baseline_env(self.fs.home_env());
        let reset = self.fs.exec(&req)?;
        match reset.completion {
            Completion::Exited(0) => Ok(()),
            Completion::Indeterminate { reason, .. } => {
                // Stop already succeeded (mutation known). Reset completion is
                // unknown; preserve indeterminate with known mutation.
                Err(SinterError::indeterminate(format!(
                    "systemctl reset-failed {} did not complete after stop: {}",
                    name, reason
                ))
                .changed())
            }
            _ => {
                Err(SinterError::apply(format!("systemctl reset-failed {} failed", name)).changed())
            }
        }
    }

    fn observe_service(&mut self, name: &str) -> Result<ServiceObs> {
        let out = self.fs.systemctl_show(name)?;
        let text = String::from_utf8_lossy(&out.stdout);
        match out.completion {
            Completion::Indeterminate { reason, .. } => {
                return Err(SinterError::indeterminate(format!(
                    "service observation for {} did not complete: {}",
                    name, reason
                )));
            }
            Completion::Signaled(s) => {
                return Err(SinterError::apply(format!(
                    "service observation for {} terminated by signal {}",
                    name, s
                )));
            }
            Completion::Exited(_) => {}
        }
        if !out.is_success() {
            // systemctl returns non-zero for an unknown unit but still prints
            // LoadState=not-found; a non-zero with no recognizable output is an
            // observation failure.
            return Err(SinterError::apply(format!(
                "service observation failed for {}: systemctl exited {:?} ({})",
                name,
                out.exit_code(),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        if out.stdout_truncated || out.stderr_truncated {
            return Err(SinterError::indeterminate(format!(
                "service observation for {} was truncated or incomplete",
                name
            )));
        }
        let mut load_state = String::new();
        let mut active_state = String::new();
        let mut unit_file_state = String::new();
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=') {
                match k {
                    "LoadState" => load_state = v.to_string(),
                    "ActiveState" => active_state = v.to_string(),
                    "UnitFileState" => unit_file_state = v.to_string(),
                    _ => {}
                }
            }
        }
        if load_state.is_empty()
            || active_state.is_empty()
            || (unit_file_state.is_empty() && load_state != "not-found")
        {
            return Err(SinterError::apply(format!(
                "service observation for {} was incomplete",
                name
            )));
        }
        Ok(ServiceObs {
            load_state,
            active_state,
            unit_file_state,
        })
    }

    fn service_has_present_package_dep(&self, res: &FrozenResource) -> Result<bool> {
        for dep in &res.depends_on {
            if let Some(d) = self.model.resources.iter().find(|r| &r.id == dep) {
                if d.type_ == "package" {
                    if let Some(value) = d.with.get("state") {
                        // Evaluate the producer in its own loop-item context.
                        // Re-evaluating without that context loses `item` and
                        // can invent a plan error for a valid defer.
                        let item = d.loop_item.as_ref().map(|v| EvalVal::known(v.clone()));
                        let evaluated =
                            eval_value_interpolated(value, &self.scope(item.as_ref(), None, None))
                                .map_err(|e| {
                                    SinterError::plan(format!(
                                        "{}: could not evaluate package dependency state: {}",
                                        res.id, e
                                    ))
                                })?;
                        if matches!(evaluated.val, Some(Value::Str(s)) if s == "present") {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    // -----------------------------------------------------------------------
    // handlers
    // -----------------------------------------------------------------------
    pub(crate) fn handler_service(
        &mut self,
        h: &crate::model::FrozenHandler,
        action: &str,
    ) -> Result<HandlerOutcomeState> {
        let name = &h.service;
        let obs = match self.observe_service(name) {
            Ok(obs) => obs,
            Err(e) => {
                // Observation failure is a handler outcome, not an outer report
                // abort. Preserve indeterminate when observation is unknown.
                return Ok(if e.kind == crate::error::ErrorKind::Indeterminate {
                    HandlerOutcomeState::Indeterminate
                } else {
                    HandlerOutcomeState::Failed
                });
            }
        };
        if obs.load_state == "not-found" {
            return Ok(HandlerOutcomeState::Failed);
        }
        if obs.unit_file_state == "masked" {
            return Ok(HandlerOutcomeState::Failed);
        }
        // Controlled injection for the handler-indeterminate aggregate contract.
        if self.fs.fault() == Some("handler_indeterminate") {
            return Ok(HandlerOutcomeState::Indeterminate);
        }
        // Controlled injection for an outer handler error after prior report
        // state exists (resources already processed, handlers pending).
        if self.fs.fault() == Some("handler_outer_error") {
            return Err(SinterError::apply("injected handler outer error"));
        }
        let mut req = ExecRequest::new("/usr/bin/systemctl");
        req.args = vec![action.to_string(), name.to_string()];
        req.env = baseline_env(self.fs.home_env());
        let out = self.fs.exec(&req)?;
        match out.completion {
            Completion::Indeterminate { .. } => Ok(HandlerOutcomeState::Indeterminate),
            Completion::Signaled(_) => Ok(HandlerOutcomeState::Failed),
            Completion::Exited(code) => {
                if code != 0 {
                    return Ok(HandlerOutcomeState::Failed);
                }
                // Verification.
                let after = match self.observe_service(name) {
                    Ok(after) => after,
                    Err(e) => {
                        return Ok(if e.kind == crate::error::ErrorKind::Indeterminate {
                            HandlerOutcomeState::Indeterminate
                        } else {
                            HandlerOutcomeState::Failed
                        })
                    }
                };
                match action {
                    "restart" => {
                        if after.active_state == "active" {
                            Ok(HandlerOutcomeState::Succeeded)
                        } else {
                            Ok(HandlerOutcomeState::Failed)
                        }
                    }
                    "reload" => {
                        if after.active_state == "active" {
                            Ok(HandlerOutcomeState::Succeeded)
                        } else {
                            Ok(HandlerOutcomeState::Failed)
                        }
                    }
                    _ => Ok(HandlerOutcomeState::Failed),
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ContentSpec {
    bytes: Option<Vec<u8>>,
    sensitive: bool,
}

/// The outcome of a file publication attempt, preserving whether a mutation
/// definitely occurred, definitely did not, or is unknown.
enum PublishOutcome {
    /// The destination was atomically replaced and verified prerequisites held.
    Published,
    /// Published successfully, but a non-fatal cleanup/note condition applies.
    /// Nothing was published; the destination is unchanged.
    FailedBeforePublish(String),
    /// Publication was attempted/dispatched but failed afterwards; the
    /// destination may have changed.
    FailedAfterPublish(String),
    /// Completion of the mutation cannot be established.
    Indeterminate(String),
}

/// Whether the currently observed object is the same object as previously
/// observed, using device/inode/type identity for existing objects and
/// absent-vs-present for new ones.
fn same_object_identity(prev: &Stat, cur: &Stat) -> bool {
    if prev.kind != cur.kind {
        return false;
    }
    match prev.kind {
        ObjKind::Absent => true,
        ObjKind::Symlink => prev.ino == cur.ino && prev.dev == cur.dev,
        _ => {
            prev.ino == cur.ino
                && prev.dev == cur.dev
                && prev.kind == cur.kind
                && prev.mode == cur.mode
                && prev.uid == cur.uid
                && prev.gid == cur.gid
                && prev.size == cur.size
                && prev.mtime == cur.mtime
                && prev.ctime == cur.ctime
        }
    }
}

fn service_step_failure(res: &FrozenResource, e: SinterError, mutated: bool) -> ResourceResult {
    let mut r = changed_result(res);
    let indeterminate = e.kind == crate::error::ErrorKind::Indeterminate;
    r.execution = if indeterminate {
        Execution::Indeterminate
    } else {
        Execution::Failed
    };
    // Once a mutation is known to have occurred, later uncertainty must not
    // erase that fact. Possible is only for "may have mutated".
    r.change = if mutated || e.mutation == MutationState::Changed {
        Change::Changed
    } else if indeterminate || e.mutation == MutationState::Possible {
        Change::Possible
    } else {
        Change::None
    };
    r.verification = if indeterminate {
        Verification::Unknown
    } else {
        Verification::NotPerformed
    };
    r.reason = Some(e.message);
    r
}

fn metadata_failure(res: &FrozenResource, e: SinterError, mutated: bool) -> ResourceResult {
    let mut r = changed_result(res);
    r.execution = if e.kind == crate::error::ErrorKind::Indeterminate {
        Execution::Indeterminate
    } else {
        Execution::Failed
    };
    r.change = match e.mutation {
        MutationState::Changed => Change::Changed,
        MutationState::Possible => Change::Possible,
        MutationState::None if mutated => Change::Changed,
        MutationState::None => Change::None,
    };
    r.verification = if r.execution == Execution::Indeterminate {
        Verification::Unknown
    } else {
        Verification::NotPerformed
    };
    r.reason = Some(e.message);
    r
}

fn post_mutation_failure(res: &FrozenResource, e: SinterError) -> ResourceResult {
    let mut r = changed_result(res);
    let indeterminate = e.kind == crate::error::ErrorKind::Indeterminate;
    r.execution = if indeterminate {
        Execution::Indeterminate
    } else {
        Execution::Failed
    };
    // This helper is only used after a mutation that definitely completed.
    // Later uncertainty must not erase that fact.
    r.change = Change::Changed;
    r.verification = if indeterminate {
        Verification::Unknown
    } else {
        Verification::NotPerformed
    };
    r.reason = Some(e.message);
    r
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageState {
    Installed,
    Absent,
}

struct ServiceObs {
    load_state: String,
    active_state: String,
    unit_file_state: String,
}

fn unchanged_result(res: &FrozenResource, reason: &str) -> ResourceResult {
    ResourceResult {
        id: res.id.clone(),
        type_: res.type_.clone(),
        origin: res.origin.clone(),
        execution: Execution::Succeeded,
        change: Change::None,
        verification: Verification::Verified,
        disposition: Disposition::Normal,
        reason: Some(reason.to_string()),
        unknown: false,
        sensitive: res.sensitive,
        diff: None,
        notes: Vec::new(),
        handler_notifications: Vec::new(),
        loop_index: res.loop_index,
    }
}

fn changed_result(res: &FrozenResource) -> ResourceResult {
    changed_result_sensitive(res, res.sensitive)
}

/// Build a changed result carrying the effective (possibly derived) sensitivity
/// so presentation paths can redact diff content and diagnostics.
fn changed_result_sensitive(res: &FrozenResource, sensitive: bool) -> ResourceResult {
    ResourceResult {
        id: res.id.clone(),
        type_: res.type_.clone(),
        origin: res.origin.clone(),
        execution: Execution::Succeeded,
        change: Change::Changed,
        verification: Verification::NotPerformed,
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

fn register_eval(map: BTreeMap<String, Value>, sensitive: bool) -> EvalVal {
    if sensitive {
        EvalVal::known_sensitive(Value::Map(map))
    } else {
        EvalVal::known(Value::Map(map))
    }
}

pub(crate) fn baseline_env(home: String) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    env.insert("LANG".to_string(), "C.UTF-8".to_string());
    env.insert("LC_ALL".to_string(), "C.UTF-8".to_string());
    env.insert("HOME".to_string(), home);
    env
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Classify a dpkg-query status string into a clean package state. Any broken,
/// half-configured, or otherwise non-clean state is an error (DESIGN §27).
pub fn classify_dpkg_status(status: &str) -> Result<PackageState> {
    let s = status.trim();
    if s.is_empty() {
        return Ok(PackageState::Absent);
    }
    match s {
        "install ok installed" => Ok(PackageState::Installed),
        "deinstall ok config-files"
        | "deinstall ok not-installed"
        | "purge ok not-installed"
        | "purge ok config-files" => Ok(PackageState::Absent),
        other => Err(SinterError::apply(format!(
            "package is in an unsupported or non-clean state: {}",
            other
        ))),
    }
}

#[cfg(test)]
mod package_tests {
    use super::*;

    #[test]
    fn clean_states() {
        assert_eq!(
            classify_dpkg_status("install ok installed").unwrap(),
            PackageState::Installed
        );
        assert_eq!(classify_dpkg_status("").unwrap(), PackageState::Absent);
        assert_eq!(
            classify_dpkg_status("deinstall ok config-files").unwrap(),
            PackageState::Absent
        );
    }

    #[test]
    fn inconsistent_states_error() {
        for s in [
            "install ok half-configured",
            "install ok unpacked",
            "install ok half-installed",
            "install ok triggers-awaited",
            "install reinstreq half-installed",
            "install reinstreq half-configured",
            "unknown ok not-installed",
        ] {
            assert!(
                classify_dpkg_status(s).is_err(),
                "state {:?} must be rejected",
                s
            );
        }
    }
}
