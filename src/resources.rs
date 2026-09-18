use crate::engine::{command_register_map, unknown_result, Engine, Mode};
use crate::error::{MutationState, Result, SinterError};
use crate::executor::{Completion, ExecRequest, Output};
use crate::expressions::{eval_boolean, eval_value_interpolated, parse_expr, EvalVal, Scope};
use crate::model::FrozenResource;
use crate::paths::{mode_to_string, parent_and_name, parse_mode};
use crate::platform::PackageBackend;
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

fn ev_env(m: &BTreeMap<String, EvalVal>, key: &str) -> Result<(BTreeMap<String, String>, bool)> {
    let Some(v) = m.get(key) else {
        return Ok((BTreeMap::new(), false));
    };
    let Some(value) = &v.val else {
        return Err(SinterError::unknown(format!(
            "with.{} could not be evaluated (unknown)",
            key
        )));
    };
    if matches!(value, Value::Null) {
        return Ok((BTreeMap::new(), v.sensitive));
    }
    let Value::Map(entries) = value else {
        return Err(SinterError::apply(format!("with.{} must be a map", key)));
    };
    let mut out = BTreeMap::new();
    for (name, value) in entries {
        let Value::Str(value) = value else {
            return Err(SinterError::apply(format!(
                "with.{} values must be strings",
                key
            )));
        };
        if value.contains('\0') || name.contains('\0') {
            return Err(SinterError::schema(format!(
                "with.{} may not contain NUL",
                key
            )));
        }
        out.insert(name.clone(), value.clone());
    }
    Ok((out, v.sensitive))
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
            Some(
                self.fs
                    .resolve_uid_sensitive(spec, sensitive)
                    .map_err(|e| {
                        if sensitive {
                            redact_msg(&res.id, "unknown user", "resolution failed")
                        } else {
                            e
                        }
                    })?,
            )
        } else if is_existing {
            None // preserve
        } else {
            Some(self.fs.target_uid)
        };

        let group_gid = if let Some((spec, sens)) = &group {
            let sensitive = *sens || meta_sensitive;
            Some(
                self.fs
                    .resolve_gid_sensitive(spec, sensitive)
                    .map_err(|e| {
                        if sensitive {
                            redact_msg(&res.id, "unknown group", "resolution failed")
                        } else {
                            e
                        }
                    })?,
            )
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
                    "{}: cannot inspect security metadata of {}; refusing content replacement{}",
                    res.id,
                    path,
                    self.fs.xattr_inspection_unavailable().unwrap_or_default()
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
            // reported as change:none. Typed error state is preserved.
            let mut mutated = false;
            let mut failure: Option<SinterError> = None;

            if stat.uid != enforce_uid || stat.gid != enforce_gid {
                match self.fs.chown(path, enforce_uid, enforce_gid) {
                    Ok(()) => mutated = true,
                    Err(e) => failure = Some(e),
                }
            }
            if failure.is_none() && (stat.mode & 0o7777) != enforce_mode {
                match self.fs.chmod(path, enforce_mode) {
                    Ok(()) => mutated = true,
                    Err(e) => failure = Some(e),
                }
            }

            if let Some(e) = failure {
                return Ok(metadata_failure(res, e, mutated));
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
            for (name, value) in xattrs.preserved_attrs() {
                self.fs.set_xattr(name, value, &staging)?;
            }
            Ok(())
        })();

        if let Err(e) = prepare {
            // Destination was never published. Staging cleanup is permitted for
            // unpublished staging, but typed uncertainty must be preserved:
            // Indeterminate preparation is not a definite ordinary failure.
            if e.kind == crate::error::ErrorKind::Indeterminate {
                return Ok(PublishOutcome::Indeterminate(format!(
                    "{}: staging preparation completion is unknown: {}",
                    res.id, e.message
                )));
            }
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
                    // If the rename is already known to have mutated (typed
                    // mutation state), publication occurred: report after-publish.
                    if e.mutation == MutationState::Changed {
                        return Ok(PublishOutcome::FailedAfterPublish(format!(
                            "{}: publication completed but completion was abnormal: {}",
                            res.id, e.message
                        )));
                    }
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
                    // mkdir already succeeded. Later metadata uncertainty must
                    // not erase the known directory creation.
                    return Ok(metadata_failure(res, e, true));
                }
                match self.verify_directory(res, &path, uid, gid, mode) {
                    Ok(v) => {
                        // A required verification mismatch is a failed resource
                        // (DESIGN §17/§30). Mutation already occurred.
                        if v.verification == Verification::Failed {
                            let mut r = v;
                            r.execution = Execution::Failed;
                            Ok(r)
                        } else {
                            Ok(v)
                        }
                    }
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
                    Ok(v) => {
                        // A required verification mismatch is a failed resource
                        // (DESIGN §17/§30). Mutation already occurred.
                        if v.verification == Verification::Failed {
                            let mut r = v;
                            r.execution = Execution::Failed;
                            Ok(r)
                        } else {
                            Ok(v)
                        }
                    }
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
        let meta_sensitive = res.sensitive || res.derived_sensitive;
        let owner_uid = if let Some((spec, sens)) = &owner {
            let sensitive = *sens || meta_sensitive;
            Some(
                self.fs
                    .resolve_uid_sensitive(spec, sensitive)
                    .map_err(|e| {
                        if sensitive {
                            redact_msg(&res.id, "unknown user", "resolution failed")
                        } else {
                            e
                        }
                    })?,
            )
        } else if is_existing {
            None
        } else {
            Some(self.fs.target_uid)
        };
        let group_gid = if let Some((spec, sens)) = &group {
            let sensitive = *sens || meta_sensitive;
            Some(
                self.fs
                    .resolve_gid_sensitive(spec, sensitive)
                    .map_err(|e| {
                        if sensitive {
                            redact_msg(&res.id, "unknown group", "resolution failed")
                        } else {
                            e
                        }
                    })?,
            )
        } else if is_existing {
            None
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
                match self.verify_link(res, &path, &target_val, link_sensitive) {
                    Ok(v) => {
                        // Required verification mismatch is a failed resource
                        // (DESIGN §17/§30). Mutation already occurred.
                        if v.verification == Verification::Failed {
                            let mut r = v;
                            r.execution = Execution::Failed;
                            Ok(r)
                        } else {
                            Ok(v)
                        }
                    }
                    Err(e) => Ok(post_mutation_failure_sensitive(res, e, link_sensitive)),
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
                match self.verify_link(res, &path, &target_val, link_sensitive) {
                    Ok(v) => {
                        // Required verification mismatch is a failed resource
                        // (DESIGN §17/§30). Mutation already occurred.
                        if v.verification == Verification::Failed {
                            let mut r = v;
                            r.execution = Execution::Failed;
                            Ok(r)
                        } else {
                            Ok(v)
                        }
                    }
                    Err(e) => Ok(post_mutation_failure_sensitive(res, e, link_sensitive)),
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
        sensitive: bool,
    ) -> Result<ResourceResult> {
        // Deterministic verification-failure injection (same class as
        // file `reobserve_fail`) used to prove the public result path.
        if self.fs.fault() == Some("link_verify_fail") {
            let mut r = changed_result_sensitive(res, sensitive);
            r.verification = Verification::Failed;
            r.reason = Some("injected link verification failure after mutation".into());
            return Ok(r);
        }
        let st = self.fs.inspect(path)?;
        if st.kind != ObjKind::Symlink {
            let mut r = changed_result_sensitive(res, sensitive);
            r.verification = Verification::Failed;
            r.reason = Some(format!("{} is not a symlink after mutation", path));
            return Ok(r);
        }
        let cur = self.fs.readlink(path)?;
        if cur != target {
            let mut r = changed_result_sensitive(res, sensitive);
            r.verification = Verification::Failed;
            // Never echo a sensitive desired target in the mismatch reason.
            r.reason = Some(if sensitive {
                "symlink target mismatch after mutation".to_string()
            } else {
                format!("symlink target mismatch: got {:?}", cur)
            });
            return Ok(r);
        }
        let mut r = changed_result_sensitive(res, sensitive);
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
        let template_sensitive = res.sensitive || res.derived_sensitive;
        let template_text = std::fs::read_to_string(&source).map_err(|e| {
            if template_sensitive {
                redact_msg(&res.id, "cannot read template", &format!("{}", e.kind()))
            } else {
                SinterError::apply(format!(
                    "{}: cannot read template {}: {}",
                    res.id,
                    source.display(),
                    e
                ))
            }
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
                    // DESIGN §31: fragments from a sensitive template body must
                    // not appear raw in diagnostics.
                    if res.sensitive || res.derived_sensitive {
                        return Err(SinterError::apply(format!(
                            "{}: template rendering error (value redacted): {}",
                            res.id,
                            e.category()
                        )));
                    }
                    return Err(SinterError::apply(format!(
                        "{}: template rendering error: {}",
                        res.id, e
                    )));
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
        let expr = parse_expr(&cw).map_err(|e| {
            if sensitive {
                SinterError::schema(format!(
                    "{}: invalid changed_when (value redacted): {}",
                    res.id,
                    e.category()
                ))
            } else {
                SinterError::schema(format!("{}: invalid changed_when: {}", res.id, e))
            }
        })?;
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
            Err(e) => Ok((
                None,
                Some(if sensitive {
                    format!("expression error (value redacted): {}", e.category())
                } else {
                    e.to_string()
                }),
            )),
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
        let (package_env, env_sensitive) = ev_env(&vals, "env")?;
        let state = ev_str(&vals, "state")?
            .map(|(s, _)| s)
            .ok_or_else(|| SinterError::schema(format!("{}: package state is required", res.id)))?;
        if state != "present" && state != "absent" {
            return Err(SinterError::apply(format!(
                "{}: package state must resolve to present or absent",
                res.id
            )));
        }
        let sensitive = res.sensitive || res.derived_sensitive || env_sensitive;
        // The backend was selected from detected /etc/os-release identity at
        // capability detection (DESIGN §8 phase F, §27). A package resource
        // with no supported backend is a capability error, not a guess.
        let backend = self.fs.pkg_backend.ok_or_else(|| {
            SinterError::apply(format!(
                "{}: package resources require a supported target platform",
                res.id
            ))
        })?;
        let observed = match self.observe_package_sensitive(backend, &name, sensitive) {
            Ok(s) => s,
            Err(e) => {
                // Initial observation is information uncertainty. No mutating
                // command has been dispatched, so Change must stay None.
                return Err(if e.kind == crate::error::ErrorKind::Indeterminate {
                    SinterError::apply(e.message)
                } else {
                    e
                });
            }
        };
        let want_installed = state == "present";
        let is_installed = matches!(observed, PackageState::Installed);

        if want_installed == is_installed {
            return Ok(unchanged_result(res, "package already in desired state"));
        }

        if self.opts.mode == Mode::Plan {
            let mut r = changed_result_sensitive(res, sensitive);
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

        // DESIGN §27: a dnf install mutation runs cache-only (`-C`) against
        // a private snapshot of the metadata cache whose completeness —
        // repodata, mirror lists, and every required package payload — is
        // proven inside the snapshot immediately beforehand. The mutation
        // process itself can never fetch repository metadata; payloads are
        // prefetched into the snapshot (payload downloads are allowed).
        // A probe exit code is never used as proof: completeness is
        // established against the snapshot the mutation actually uses.
        // Failure to prove completeness fails closed before any mutation.
        let mut snapshot_dir: Option<String> = None;
        if backend == PackageBackend::Dnf && want_installed {
            match self.dnf_metadata_snapshot(&name, sensitive, &package_env)? {
                DnfSnapshot::Ready(p) => snapshot_dir = Some(p),
                DnfSnapshot::Blocked(detail, indeterminate) => {
                    let mut r = changed_result_sensitive(res, sensitive);
                    r.change = Change::None;
                    r.verification = Verification::NotPerformed;
                    r.execution = if indeterminate {
                        Execution::Indeterminate
                    } else {
                        Execution::Failed
                    };
                    r.reason = Some(format!(
                        "{} repository metadata not locally complete; refusing to fetch metadata ({})",
                        backend.label(),
                        detail
                    ));
                    return Ok(r);
                }
            }
        }

        let mut req = ExecRequest::new(backend.manager_program());
        req.env = baseline_env(self.fs.home_env());
        req.env.extend(package_env);
        req.sensitive = sensitive;
        req.args = backend.mutate_args(want_installed, &name, snapshot_dir.as_deref());
        req.timeout_secs = 300;
        let action = if want_installed { "install" } else { "remove" };
        let pkg_disp = if sensitive {
            "[redacted]"
        } else {
            name.as_str()
        };
        // R2-05: a dispatch failure before the mutation's start can be
        // established leaves the snapshot behind. The cleanup outcome is
        // attached to the propagated error so it is never discarded by a
        // bare `?` — but the mutation itself never ran, so there is no
        // mutation truth to preserve.
        let out = if self.fs.fault() == Some("package_mutation_dispatch_fail") {
            Err(SinterError::apply(format!(
                "injected {} {} dispatch failure",
                backend.label(),
                action
            )))
        } else {
            self.fs.exec(&req)
        };
        // R2-02: the mutation completion state must be classified BEFORE any
        // further command is sent to the target. When the mutation's
        // completion cannot be established the remote process may still be
        // running, and dispatching anything else to this target afterwards —
        // snapshot cleanup, re-observation, retry, or a diagnostic command —
        // is forbidden. The result keeps the existing
        // Indeterminate/Possible truthfulness contract.
        let mutation_indeterminate = match &out {
            Ok(o) => matches!(o.completion, Completion::Indeterminate { .. }),
            // A pre-dispatch failure ran no command at all; the snapshot may
            // still exist and must be cleaned up (R2-05).
            Err(_) => false,
        };
        let cleanup_failure = if mutation_indeterminate {
            // R2-02: do not touch the target again. The private snapshot is
            // deliberately left in place.
            None
        } else if let Some(snap) = &snapshot_dir {
            self.dnf_snapshot_cleanup(snap)
        } else {
            None
        };
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                let mut reason = format!(
                    "{} {} {} failed to dispatch: {}",
                    backend.manager_program(),
                    action,
                    pkg_disp,
                    e.message
                );
                if let Some(msg) = &cleanup_failure {
                    reason.push_str(&format!("; private snapshot cleanup failed: {}", msg));
                }
                return Err(SinterError::apply(reason));
            }
        };
        match out.completion {
            Completion::Indeterminate { reason, .. } => {
                let mut r = changed_result_sensitive(res, sensitive);
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "{} operation did not complete: {}",
                    backend.label(),
                    reason
                ));
                return Ok(r);
            }
            Completion::Signaled(s) => {
                let mut r = changed_result_sensitive(res, sensitive);
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "{} operation terminated by signal {}",
                    backend.label(),
                    s
                ));
                Self::note_snapshot_cleanup_failure(&mut r, &cleanup_failure);
                return Ok(r);
            }
            Completion::Exited(code) => {
                if code != 0 {
                    let mut r = changed_result_sensitive(res, sensitive);
                    r.execution = Execution::Failed;
                    r.change = Change::Possible;
                    r.verification = Verification::Unknown;
                    // Package-manager stderr can echo the package name; never
                    // include it for a sensitive resource (DESIGN §31).
                    let stderr_note = if sensitive {
                        String::new()
                    } else {
                        format!(": {}", String::from_utf8_lossy(&out.stderr).trim())
                    };
                    r.reason = Some(format!(
                        "{} {} {} failed with exit code {}{}",
                        backend.manager_program(),
                        action,
                        pkg_disp,
                        code,
                        stderr_note
                    ));
                    Self::note_snapshot_cleanup_failure(&mut r, &cleanup_failure);
                    return Ok(r);
                }
            }
        }

        // Re-observe and verify. A successful package-manager dispatch is
        // retained even if the post-mutation observation fails. The mutation
        // is already known: later uncertainty must never weaken Changed to
        // Possible/None.
        if self.fs.fault() == Some("package_reobserve_indeterminate") {
            let mut r = changed_result_sensitive(res, sensitive);
            r.change = Change::Changed;
            r.execution = Execution::Indeterminate;
            r.verification = Verification::Unknown;
            r.reason = Some("injected package re-observation indeterminate after mutation".into());
            Self::note_snapshot_cleanup_failure(&mut r, &cleanup_failure);
            return Ok(r);
        }
        if self.fs.fault() == Some("package_reobserve_fail") {
            let mut r = changed_result_sensitive(res, sensitive);
            r.change = Change::Changed;
            r.execution = Execution::Failed;
            r.verification = Verification::Failed;
            r.reason = Some("injected package re-observation failure after mutation".into());
            Self::note_snapshot_cleanup_failure(&mut r, &cleanup_failure);
            return Ok(r);
        }
        let after = match self.observe_package_sensitive(backend, &name, sensitive) {
            Ok(after) => after,
            Err(e) => {
                let mut r = changed_result_sensitive(res, sensitive);
                r.change = Change::Changed;
                r.execution = if e.kind == crate::error::ErrorKind::Indeterminate {
                    Execution::Indeterminate
                } else {
                    Execution::Failed
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
                Self::note_snapshot_cleanup_failure(&mut r, &cleanup_failure);
                return Ok(r);
            }
        };
        let verified = matches!(after, PackageState::Installed) == want_installed;
        let mut r = changed_result_sensitive(res, sensitive);
        r.change = Change::Changed;
        if verified {
            r.verification = Verification::Verified;
        } else {
            r.execution = Execution::Failed;
            r.verification = Verification::Failed;
            r.reason = Some("package state did not reach desired state after mutation".into());
        }
        Self::note_snapshot_cleanup_failure(&mut r, &cleanup_failure);
        Ok(r)
    }

    /// Surface a private-snapshot cleanup failure on a result whose mutation
    /// already definitively completed. The mutation truth (Changed) and any
    /// verification already established are preserved exactly — a leftover
    /// private snapshot is a real post-mutation defect, so the resource is
    /// not reported as cleanly successful, but the defect must never weaken
    /// what already happened (R2-05).
    fn note_snapshot_cleanup_failure(r: &mut ResourceResult, cleanup_failure: &Option<String>) {
        let Some(msg) = cleanup_failure else {
            return;
        };
        let detail = format!("; private snapshot cleanup failed: {}", msg);
        match &mut r.reason {
            Some(reason) => reason.push_str(&detail),
            None => r.reason = Some(format!("private snapshot cleanup failed: {}", msg)),
        }
        if r.execution == Execution::Succeeded {
            r.execution = Execution::Failed;
        }
    }

    /// Enforce the private snapshot root to 0700 and prove the mode and
    /// ownership by reading them back (snapshot-permission hardening). This
    /// runs before the metadata cache is copied into the root so the privacy
    /// guarantee covers the copy itself, not just the moment after it.
    fn enforce_snapshot_permissions(&mut self, snap: &str) -> Result<DnfSnapshot> {
        let mut req = ExecRequest::new("/usr/bin/chmod");
        req.args = vec!["700".to_string(), snap.to_string()];
        req.env = baseline_env(self.fs.home_env());
        match self
            .snap_exec(
                snap,
                &req,
                "snapshot permission enforcement",
                "snapshot_chmod_dispatch_fail",
            )?
            .completion
        {
            Completion::Exited(0) => {}
            Completion::Indeterminate { reason, .. } => {
                return self.dnf_snapshot_blocked(
                    snap,
                    format!(
                        "snapshot permission enforcement did not complete: {}",
                        reason
                    ),
                    true,
                );
            }
            _ => {
                return self.dnf_snapshot_blocked(
                    snap,
                    "cannot enforce the private snapshot directory permissions".to_string(),
                    false,
                );
            }
        }
        self.verify_snapshot_permissions(snap, "before the metadata cache copy")
    }

    /// Read the private snapshot root's mode and owner back and require 0700
    /// owned by the effective execution identity. A snapshot whose
    /// permissions or owner cannot be established is not usable and fails
    /// closed. `when` names the point in the snapshot lifetime for the
    /// failure reason.
    fn verify_snapshot_permissions(&mut self, snap: &str, when: &str) -> Result<DnfSnapshot> {
        let mut req = ExecRequest::new("/usr/bin/stat");
        req.args = vec![
            "-c".to_string(),
            "%a %u".to_string(),
            "--".to_string(),
            snap.to_string(),
        ];
        req.env = baseline_env(self.fs.home_env());
        let perm_out = self.snap_exec(
            snap,
            &req,
            "snapshot permission verification",
            "snapshot_stat_dispatch_fail",
        )?;
        match perm_out.completion {
            Completion::Exited(0) => {
                let text = String::from_utf8_lossy(&perm_out.stdout);
                let mut fields = text.split_whitespace();
                let (mode, uid) = (fields.next(), fields.next());
                match (mode, uid) {
                    (Some("700"), Some(uid_str)) => match uid_str.parse::<u32>() {
                        Ok(owner) if owner == self.fs.target_uid() => {}
                        Ok(owner) => {
                            return self.dnf_snapshot_blocked(
                                snap,
                                format!(
                                    "private snapshot directory is owned by uid {}, expected {}",
                                    owner,
                                    self.fs.target_uid()
                                ),
                                false,
                            );
                        }
                        Err(_) => {
                            return self.dnf_snapshot_blocked(
                                snap,
                                "cannot determine the private snapshot directory owner".to_string(),
                                false,
                            );
                        }
                    },
                    _ => {
                        return self.dnf_snapshot_blocked(
                            snap,
                            "private snapshot directory is not 0700".to_string(),
                            false,
                        );
                    }
                }
            }
            Completion::Indeterminate { reason, .. } => {
                return self.dnf_snapshot_blocked(
                    snap,
                    format!(
                        "snapshot permission verification did not complete ({}): {}",
                        when, reason
                    ),
                    true,
                );
            }
            _ => {
                return self.dnf_snapshot_blocked(
                    snap,
                    format!(
                        "cannot verify the private snapshot directory permissions ({})",
                        when
                    ),
                    false,
                );
            }
        }
        Ok(DnfSnapshot::Ready(snap.to_string()))
    }

    /// The live DNF metadata cache Sinter snapshots with `cp -a`.
    const LIVE_CACHE_ROOT: &'static str = "/var/cache/dnf";

    /// Copy the live DNF metadata cache into the private snapshot root
    /// (R4-A04). Only the *children* of the live cache root are copied.
    /// `cp -a <root>/. <dst>/` copies the source root's own metadata onto the
    /// destination as well, so a 0755 live cache root widens the private 0700
    /// snapshot root *while secret content is being placed into it* — the
    /// privacy invariant must hold for the whole copy, not only after it.
    /// Copying each child of the root into the existing snapshot directory
    /// creates new entries only and never makes the root itself a copy
    /// target, so the mode and ownership enforced before the copy hold
    /// throughout it.
    ///
    /// The children are enumerated with `find` — not a shell glob, which
    /// would miss dotfile entries and re-interpret names — and every path is
    /// a discrete argv element, so a cache entry name can never alter the
    /// command structure.
    fn copy_dnf_cache_into_snapshot(&mut self, snap: &str) -> Result<DnfSnapshot> {
        // Enumerate the live cache root's own entries, hidden ones included.
        // `-print0` keeps names with spaces or newlines discrete.
        let mut req = ExecRequest::new("/usr/bin/find");
        req.args = vec![
            Self::LIVE_CACHE_ROOT.to_string(),
            "-mindepth".to_string(),
            "1".to_string(),
            "-maxdepth".to_string(),
            "1".to_string(),
            "-print0".to_string(),
        ];
        req.env = baseline_env(self.fs.home_env());
        let list_out = self.snap_exec(
            snap,
            &req,
            "metadata cache enumeration",
            "dnf_snapshot_dispatch_fail",
        )?;
        let children: Vec<String> = match list_out.completion {
            Completion::Exited(0) => {
                // The enumeration answer is only interpretable when the whole
                // capture completed and find wrote nothing but the listing: a
                // truncated stdout could cut an entry mid-path and unexpected
                // stderr means find reported something this model does not
                // cover (R4-F01).
                if list_out.stdout_truncated || list_out.stderr_truncated {
                    return self.dnf_snapshot_blocked(
                        snap,
                        "metadata cache enumeration output was incomplete".to_string(),
                        false,
                    );
                }
                if !list_out.stderr.is_empty() {
                    return self.dnf_snapshot_blocked(
                        snap,
                        "metadata cache enumeration produced unexpected stderr".to_string(),
                        false,
                    );
                }
                // Raw bytes: untrusted entry names must never be lossily
                // re-encoded into a different string before use (R4-F01).
                match parse_cache_children(&list_out.stdout) {
                    Ok(c) => c,
                    Err(reason) => {
                        return self.dnf_snapshot_blocked(
                            snap,
                            format!("metadata cache enumeration is uninterpretable: {}", reason),
                            false,
                        );
                    }
                }
            }
            Completion::Indeterminate { reason, .. } => {
                return self.dnf_snapshot_blocked(
                    snap,
                    format!("metadata cache enumeration did not complete: {}", reason),
                    true,
                );
            }
            _ => {
                return self.dnf_snapshot_blocked(
                    snap,
                    "cannot enumerate the metadata cache".to_string(),
                    false,
                );
            }
        };
        // Each child is copied into the existing snapshot root: `-a` keeps
        // each child's own metadata, and the root's metadata is never
        // rewritten because the root is neither the source nor the
        // destination of any copy.
        for child in &children {
            let mut req = ExecRequest::new("/usr/bin/cp");
            req.args = vec![
                "-a".to_string(),
                "--".to_string(),
                child.clone(),
                format!("{}/", snap),
            ];
            req.env = baseline_env(self.fs.home_env());
            match self
                .snap_exec(
                    snap,
                    &req,
                    "metadata cache copy",
                    "dnf_snapshot_dispatch_fail",
                )?
                .completion
            {
                Completion::Exited(0) => {}
                Completion::Indeterminate { reason, .. } => {
                    return self.dnf_snapshot_blocked(
                        snap,
                        format!("metadata snapshot copy did not complete: {}", reason),
                        true,
                    );
                }
                _ => {
                    return self.dnf_snapshot_blocked(
                        snap,
                        "cannot snapshot the metadata cache".to_string(),
                        false,
                    );
                }
            }
        }
        Ok(DnfSnapshot::Ready(snap.to_string()))
    }

    /// Prepare a private snapshot of the dnf metadata cache and prove that
    /// it is locally complete for the install — every enabled repository's
    /// repodata usable offline, the resolved mirror list for repos that
    /// resolve via mirrors, and every package payload the transaction
    /// needs prefetched into the snapshot's package dirs. Only then may
    /// the `dnf -C install` mutation run, scoped to the snapshot: it has
    /// no path to remote repository metadata at all (DESIGN §27).
    ///
    /// This is deliberately not a "probe then trust" design: the checks
    /// run against the same private cachedir the mutation uses, so a
    /// disappearing or changing system cache cannot invalidate the proof.
    /// Any gap — missing repodata, a missing mirror list, an unparseable
    /// repository list, an unresolvable payload — blocks the mutation.
    fn dnf_metadata_snapshot(
        &mut self,
        name: &str,
        sensitive: bool,
        package_env: &BTreeMap<String, String>,
    ) -> Result<DnfSnapshot> {
        let name_disp = if sensitive { "[redacted]" } else { name };
        // 1. Private snapshot directory.
        let mut req = ExecRequest::new("/usr/bin/mktemp");
        req.args = vec!["-d".to_string(), "/var/tmp/sinter-dnf.XXXXXXXX".to_string()];
        req.env = baseline_env(self.fs.home_env());
        let out = self.fs.exec(&req)?;
        // The snapshot path is helper output: it is only interpretable when the
        // whole capture completed and mktemp wrote nothing but the path, and
        // the path must be proven to be Sinter's own private snapshot
        // namespace before any operation targets it (R4-F01). Until it is
        // validated it is an unverified value: no chmod, stat, copy or cleanup
        // command may use it.
        let snap = match out.completion {
            Completion::Exited(0) => {
                if out.stdout_truncated || out.stderr_truncated {
                    return Ok(DnfSnapshot::Blocked(
                        "metadata snapshot directory output was incomplete".to_string(),
                        false,
                    ));
                }
                if !out.stderr.is_empty() {
                    return Ok(DnfSnapshot::Blocked(
                        "metadata snapshot directory creation produced unexpected stderr"
                            .to_string(),
                        false,
                    ));
                }
                match validate_snapshot_path(&out.stdout) {
                    Ok(p) => p,
                    // An unverified path must never become a target — not even
                    // a cleanup target (R2-05): the directory cannot be proven
                    // to be one Sinter created.
                    Err(reason) => {
                        return Ok(DnfSnapshot::Blocked(
                            format!(
                                "metadata snapshot directory is not in the expected private namespace: {}",
                                reason
                            ),
                            false,
                        ));
                    }
                }
            }
            Completion::Indeterminate { reason, .. } => {
                return Ok(DnfSnapshot::Blocked(
                    format!("metadata snapshot creation did not complete: {}", reason),
                    true,
                ));
            }
            _ => {
                return Ok(DnfSnapshot::Blocked(
                    "cannot create metadata snapshot directory".to_string(),
                    false,
                ));
            }
        };
        // 2. Enforce the private snapshot root to 0700 and prove mode and
        //    ownership by reading them back BEFORE any content is copied
        //    into it. The privacy guarantee then covers the copy itself
        //    rather than only the moment after it: `cp -a` copies the
        //    source *contents* into an existing directory and does not
        //    change the root's own mode, which the post-copy verification
        //    in step 3 proves independently.
        if let blocked @ DnfSnapshot::Blocked(..) = self.enforce_snapshot_permissions(&snap)? {
            return Ok(blocked);
        }
        // 3. Copy the metadata cache into the snapshot. From here on every
        //    check — and the mutation — uses this private copy, never the
        //    live system cache. Only the children of the live cache root are
        //    copied, so the private root's own 0700 metadata is never a copy
        //    target and the privacy invariant holds *during* the copy
        //    (R4-A04); the post-copy verification below still proves it
        //    independently.
        if let blocked @ DnfSnapshot::Blocked(..) = self.copy_dnf_cache_into_snapshot(&snap)? {
            return Ok(blocked);
        }
        // 3b. Re-verify the root after the copy: a snapshot whose
        //     permissions (or owner) cannot be established is not usable and
        //     fails closed, so the 0700 guarantee holds across the whole
        //     snapshot lifetime.
        if let blocked @ DnfSnapshot::Blocked(..) =
            self.verify_snapshot_permissions(&snap, "after the metadata cache copy")?
        {
            return Ok(blocked);
        }
        // 3. Prove every enabled repository's repodata loads from the
        //    snapshot alone. `-C` makes this check itself incapable of
        //    fetching; `*.skip_if_unavailable=0` turns any unusable
        //    repository into an error instead of a silent skip.
        let mut req = ExecRequest::new("/usr/bin/dnf");
        req.args = PackageBackend::dnf_snapshot_check_args(&snap, name);
        req.env = baseline_env(self.fs.home_env());
        req.sensitive = sensitive;
        req.timeout_secs = 120;
        let check_out = self.snap_exec(&snap, &req, "metadata completeness check", "")?;
        match check_out.completion {
            Completion::Exited(0) => {
                // R2-03: a clean check must also be a complete one. Exit 0
                // with unexpected stderr or a truncated capture cannot prove
                // the snapshot usable.
                if let Err(e) = self.dnf_output_guard(
                    &check_out,
                    "metadata completeness check",
                    &[DnfStderr::MetadataExpiration],
                ) {
                    return self.dnf_snapshot_blocked(&snap, e.message, false);
                }
            }
            Completion::Indeterminate { reason, .. } => {
                return self.dnf_snapshot_blocked(
                    &snap,
                    format!("metadata completeness check did not complete: {}", reason),
                    true,
                );
            }
            Completion::Signaled(s) => {
                return self.dnf_snapshot_blocked(
                    &snap,
                    format!("metadata completeness check terminated by signal {}", s),
                    false,
                );
            }
            Completion::Exited(c) => {
                return self.dnf_snapshot_blocked(
                    &snap,
                    format!(
                        "snapshot repodata unusable for {} (check exited {})",
                        name_disp, c
                    ),
                    false,
                );
            }
        }
        // 4. Enumerate enabled repositories and which resolve via a mirror
        //    list — a repo whose repodata exists but whose mirror list is
        //    missing would re-resolve over the network during the install.
        let mut req = ExecRequest::new("/usr/bin/dnf");
        req.args = PackageBackend::dnf_repolist_args();
        req.env = baseline_env(self.fs.home_env());
        req.timeout_secs = 120;
        let repos_out = self.snap_exec(&snap, &req, "repository enumeration", "")?;
        let repos = match repos_out.completion {
            Completion::Exited(0) => {
                // R2-03: reject truncated or stderr-bearing output before
                // trusting a parse of the repository list. The guard failure
                // routes through the blocked path like every other snapshot
                // defect: a bare `?` would leak the private snapshot (R2-05)
                // and bypass the metadata-contract result.
                if let Err(e) = self.dnf_output_guard(
                    &repos_out,
                    "repository enumeration",
                    &[DnfStderr::MetadataExpiration],
                ) {
                    return self.dnf_snapshot_blocked(&snap, e.message, false);
                }
                match parse_dnf_enabled_repos(&String::from_utf8_lossy(&repos_out.stdout)) {
                    Some(r) => r,
                    None => {
                        return self.dnf_snapshot_blocked(
                            &snap,
                            "cannot establish the enabled repository set".to_string(),
                            false,
                        );
                    }
                }
            }
            Completion::Indeterminate { reason, .. } => {
                return self.dnf_snapshot_blocked(
                    &snap,
                    format!("repository enumeration did not complete: {}", reason),
                    true,
                );
            }
            _ => {
                return self.dnf_snapshot_blocked(
                    &snap,
                    "cannot enumerate enabled repositories".to_string(),
                    false,
                );
            }
        };
        // 5. List the snapshot's per-repository cache dirs and mirror lists
        //    in one pass — used for both the mirror-list check below and
        //    payload placement afterwards.
        let mut req = ExecRequest::new("/usr/bin/find");
        req.args = vec![
            snap.clone(),
            "-mindepth".to_string(),
            "1".to_string(),
            "-maxdepth".to_string(),
            "2".to_string(),
        ];
        req.env = baseline_env(self.fs.home_env());
        let listing = match self.snap_exec(&snap, &req, "snapshot cache listing", "")? {
            Output {
                completion: Completion::Exited(0),
                stdout,
                ..
            } => String::from_utf8_lossy(&stdout).into_owned(),
            Output {
                completion: Completion::Indeterminate { reason, .. },
                ..
            } => {
                return self.dnf_snapshot_blocked(
                    &snap,
                    format!("snapshot cache listing did not complete: {}", reason),
                    true,
                );
            }
            _ => {
                return self.dnf_snapshot_blocked(
                    &snap,
                    "cannot list the metadata snapshot".to_string(),
                    false,
                );
            }
        };
        // For every mirror-resolving enabled repository the snapshot must
        // hold the resolved mirror list — payload URLs are composed from
        // it entirely offline. The mirror list must be in the repository's
        // own cache directory, proved by identity rather than by a name
        // prefix (R4-A03).
        for repoid in repos
            .iter()
            .filter(|(_, mirrors)| *mirrors)
            .map(|(id, _)| id)
        {
            if !listing_has_mirrorlist(&listing, &snap, repoid) {
                return self.dnf_snapshot_blocked(
                    &snap,
                    format!("repository {} mirror list missing from snapshot", repoid),
                    false,
                );
            }
        }
        // 6. Resolve the exact payload set from the snapshot alone. The
        //    `--assumeno` dry run performs full dependency resolution
        //    against cached metadata and aborts before any mutation or
        //    download — its transaction table is what the install needs.
        let mut req = ExecRequest::new("/usr/bin/dnf");
        req.args = PackageBackend::dnf_dry_run_args(&snap, name);
        req.env = baseline_env(self.fs.home_env());
        req.sensitive = sensitive;
        req.timeout_secs = 120;
        let dry_out = self.snap_exec(&snap, &req, "install set resolution", "")?;
        let rows = match dry_out.completion {
            // Exit 1 = "Operation aborted." after a successful resolution;
            // exit 0 = nothing to do. Anything else is a resolution error.
            // The stderr contract follows the exit status (R5-F04): the
            // CliError line is only ever expected after an aborted
            // resolution — on an exit-0 stderr it contradicts the completion
            // and is unexpected like any other line.
            Completion::Exited(0) | Completion::Exited(1) => {
                let expected = match dry_out.completion {
                    Completion::Exited(1) => &[DnfStderr::OperationAborted][..],
                    _ => &[][..],
                };
                // R2-03: the transaction table must be complete and clean
                // before it can be trusted as the exact payload set.
                if let Err(e) = self.dnf_output_guard(&dry_out, "install set resolution", expected)
                {
                    return self.dnf_snapshot_blocked(&snap, e.message, false);
                }
                match parse_dnf_install_set(&String::from_utf8_lossy(&dry_out.stdout)) {
                    Some(r) => r,
                    None => {
                        return self.dnf_snapshot_blocked(
                            &snap,
                            "cannot establish the install transaction set".to_string(),
                            false,
                        );
                    }
                }
            }
            Completion::Indeterminate { reason, .. } => {
                return self.dnf_snapshot_blocked(
                    &snap,
                    format!("install set resolution did not complete: {}", reason),
                    true,
                );
            }
            _ => {
                return self.dnf_snapshot_blocked(
                    &snap,
                    format!("cannot resolve the install transaction for {}", name_disp),
                    false,
                );
            }
        };
        if !rows.is_empty() {
            match self.dnf_prefetch_payloads(
                &snap,
                &listing,
                &rows,
                sensitive,
                name_disp,
                package_env,
            )? {
                DnfSnapshot::Ready(_) => {}
                blocked => return Ok(blocked),
            }
        }
        Ok(DnfSnapshot::Ready(snap))
    }

    /// Prefetch every payload the install transaction needs into the
    /// snapshot's per-repository package cache, so the subsequent
    /// `dnf -C install` is provably incapable of touching the network
    /// (DESIGN §27: payload downloads allowed, metadata downloads never).
    /// URLs are resolved from the snapshot's own cached metadata and
    /// mirror lists — no metadata is ever fetched to compute them.
    fn dnf_prefetch_payloads(
        &mut self,
        snap: &str,
        listing: &str,
        rows: &[DnfInstallRow],
        sensitive: bool,
        name_disp: &str,
        package_env: &BTreeMap<String, String>,
    ) -> Result<DnfSnapshot> {
        let blocked = |s: &mut Self, reason: String, indeterminate: bool| -> Result<DnfSnapshot> {
            let mut reason = reason;
            if let Some(msg) = s.dnf_snapshot_cleanup(snap) {
                reason.push_str(&format!("; private snapshot cleanup failed: {}", msg));
            }
            Ok(DnfSnapshot::Blocked(reason, indeterminate))
        };
        // Resolve payload URLs from cached metadata alone (`-C`): one
        // repoquery for every package in the transaction set.
        let names: Vec<String> = {
            let mut v: Vec<String> = rows.iter().map(|r| r.name.clone()).collect();
            v.sort();
            v.dedup();
            v
        };
        let mut req = ExecRequest::new("/usr/bin/dnf");
        req.args = PackageBackend::dnf_payload_location_args(snap, &names);
        req.env = baseline_env(self.fs.home_env());
        req.sensitive = sensitive;
        req.timeout_secs = 120;
        let loc_out = self.snap_exec(snap, &req, "payload location resolution", "")?;
        let urls: Vec<String> = match loc_out.completion {
            Completion::Exited(0) => {
                // R2-03: payload locations are only trustworthy when the
                // whole answer was captured and no stderr was produced.
                if let Err(e) = self.dnf_output_guard(
                    &loc_out,
                    "payload location resolution",
                    &[DnfStderr::MetadataExpiration],
                ) {
                    return blocked(self, e.message, false);
                }
                let mut urls: Vec<String> = Vec::new();
                for l in String::from_utf8_lossy(&loc_out.stdout).lines() {
                    let l = l.trim();
                    if l.is_empty() {
                        continue;
                    }
                    // R2-03-C: each location must be a URL the downloader can
                    // actually fetch; anything else is unrecognized structure.
                    if let Err(reason) = validate_payload_url(l) {
                        return blocked(self, format!("{} for {}", reason, name_disp), false);
                    }
                    urls.push(l.to_string());
                }
                urls
            }
            Completion::Indeterminate { reason, .. } => {
                return blocked(
                    self,
                    format!("payload location resolution did not complete: {}", reason),
                    true,
                )
            }
            _ => {
                return blocked(
                    self,
                    format!("cannot resolve payload locations for {}", name_disp),
                    false,
                )
            }
        };
        // A non-interactive payload fetcher on the target. curl is
        // near-universal on RHEL-family systems; wget is the fallback.
        // A dispatch failure here runs after the snapshot exists, so it goes
        // through the same cleanup policy as every other preparation step
        // (R2-05): a bare `?` would leak the private snapshot.
        let fetcher = match self.dnf_fetch_tool(snap)? {
            Ok(f) => f,
            Err(reason) => return blocked(self, reason, true),
        };
        let fetcher = match fetcher {
            Some(f) => f,
            None => {
                return blocked(
                    self,
                    "no payload fetch tool (curl/wget) available".to_string(),
                    false,
                )
            }
        };
        for row in rows {
            // rpm payload file names are <name>-<version-release>.<arch>.rpm
            // with no epoch component; match the resolved URL by basename.
            let want = format!("{}-{}.{}.rpm", row.name, row.verrel, row.arch);
            // R2-04: the transaction row must map to exactly one payload
            // location. Multiple URLs sharing a basename cannot be told
            // apart, so the mapping is ambiguous and must fail closed
            // instead of picking the first candidate.
            let candidates: Vec<&String> = urls
                .iter()
                .filter(|u| u.rsplit('/').next() == Some(want.as_str()))
                .collect();
            let url = match candidates.len() {
                0 => {
                    return blocked(
                        self,
                        format!("no cached payload location for {}", name_disp),
                        false,
                    )
                }
                1 => candidates[0].clone(),
                n => {
                    return blocked(
                        self,
                        format!(
                            "payload location for {} is not unique ({} candidate URLs)",
                            name_disp, n
                        ),
                        false,
                    )
                }
            };
            // The repository's cache dir inside the snapshot. It must be
            // provably and uniquely resolvable (R2-04, R4-A03): the directory
            // name must prove it belongs to this transaction's repository —
            // not merely share an id prefix with it — and only one such
            // directory may exist.
            let prefix = format!("{}/", snap);
            let dirs: Vec<&str> = listing
                .lines()
                .filter_map(|l| {
                    let name = l.strip_prefix(&prefix)?;
                    is_repo_cache_dir(&row.repoid, name).then_some(name)
                })
                .collect();
            let repodir = match dirs.len() {
                0 => {
                    return blocked(
                        self,
                        format!("repository {} cache dir missing from snapshot", row.repoid),
                        false,
                    )
                }
                1 => format!("{}/{}", snap, dirs[0]),
                n => {
                    return blocked(
                        self,
                        format!(
                            "repository {} cache dir is not unique ({} candidate directories)",
                            row.repoid, n
                        ),
                        false,
                    )
                }
            };
            let pkgdir = format!("{}/packages", repodir);
            let mut req = ExecRequest::new("/usr/bin/mkdir");
            req.args = vec!["-p".to_string(), pkgdir.clone()];
            req.env = baseline_env(self.fs.home_env());
            match self
                .snap_exec(
                    snap,
                    &req,
                    "payload directory creation",
                    "payload_mkdir_fail",
                )?
                .completion
            {
                Completion::Exited(0) => {}
                Completion::Indeterminate { reason, .. } => {
                    return blocked(
                        self,
                        format!("payload directory creation did not complete: {}", reason),
                        true,
                    );
                }
                _ => {
                    return blocked(
                        self,
                        format!("cannot create payload directory in {}", repodir),
                        false,
                    )
                }
            }
            let dest = format!("{}/{}", pkgdir, want);
            let mut req = ExecRequest::new(fetcher.path());
            req.args = fetcher
                .payload_args(&dest, &url)
                .iter()
                .map(|s| s.to_string())
                .collect();
            req.env = baseline_env(self.fs.home_env());
            req.env.extend(package_env.clone());
            req.sensitive = sensitive;
            req.timeout_secs = 300;
            match self
                .snap_exec(snap, &req, "payload download", "payload_download_fail")?
                .completion
            {
                Completion::Exited(0) => {}
                Completion::Indeterminate { reason, .. } => {
                    return blocked(
                        self,
                        format!("payload fetch did not complete: {}", reason),
                        true,
                    );
                }
                _ => {
                    return blocked(
                        self,
                        format!("payload fetch failed for {}", name_disp),
                        false,
                    )
                }
            }
        }
        Ok(DnfSnapshot::Ready(snap.to_string()))
    }

    /// Pick a non-interactive payload fetch tool on the target. `Err` is
    /// an indeterminate outcome (the capability probe could not complete).
    /// The probe is a snapshot-preparation command: a dispatch failure is
    /// routed through the cleanup policy so the private snapshot is never
    /// leaked by a bare `?` (R2-05).
    fn dnf_fetch_tool(
        &mut self,
        snap: &str,
    ) -> Result<std::result::Result<Option<DnfFetchTool>, String>> {
        for (path, tool) in [
            ("/usr/bin/curl", DnfFetchTool::Curl),
            ("/usr/bin/wget", DnfFetchTool::Wget),
        ] {
            let mut req = ExecRequest::new("/usr/bin/test");
            req.args = vec!["-x".to_string(), path.to_string()];
            req.env = baseline_env(self.fs.home_env());
            match self
                .snap_exec(
                    snap,
                    &req,
                    "payload fetch tool detection",
                    "payload_fetch_tool_fail",
                )?
                .completion
            {
                Completion::Exited(0) => return Ok(Ok(Some(tool))),
                Completion::Exited(_) => {}
                Completion::Indeterminate { reason, .. } => {
                    return Ok(Err(format!(
                        "payload fetch tool probe did not complete: {}",
                        reason
                    )));
                }
                Completion::Signaled(_) => {
                    return Ok(Ok(None));
                }
            }
        }
        Ok(Ok(None))
    }

    /// Run one snapshot-preparation command. A transport-level dispatch
    /// failure (`Err`) leaves the private snapshot directory behind, so it is
    /// cleaned up here and the failure is propagated with the cleanup outcome
    /// attached — a bare `?` would leak the snapshot (R2-05).
    ///
    /// `fault` names the resource-layer fault this call models a dispatch
    /// failure for, so tests can target a specific preparation step; an empty
    /// name disables injection for that call.
    fn snap_exec(
        &mut self,
        snap: &str,
        req: &ExecRequest,
        what: &str,
        fault: &str,
    ) -> Result<Output> {
        let out = if !fault.is_empty() && self.fs.fault() == Some(fault) {
            Err(SinterError::apply(format!(
                "injected {} dispatch failure",
                what
            )))
        } else {
            self.fs.exec(req)
        };
        match out {
            Ok(o) => Ok(o),
            Err(e) => {
                let mut reason = format!("{} failed to dispatch: {}", what, e.message);
                if let Some(msg) = self.dnf_snapshot_cleanup(snap) {
                    reason.push_str(&format!("; private snapshot cleanup failed: {}", msg));
                }
                Err(SinterError::apply(reason))
            }
        }
    }

    /// Guard the interpretation of any dnf diagnostic output (R2-03). A result
    /// is only interpretable when the whole capture completed and dnf wrote
    /// nothing to stderr: truncated stdout/stderr means the table could be cut
    /// mid-structure, and unexpected stderr means dnf reported something this
    /// parser does not model. Both fail closed rather than guessing.
    /// Guard one dnf command's captured output before it is trusted: a
    /// truncated capture is never a complete answer, and stderr is matched
    /// line-by-line against the command's own allowlist of native benign
    /// lines (R5-F04). Real dnf 4 emits informational diagnostics on stderr
    /// for some subcommands — `Last metadata expiration check:` for
    /// `repoquery`/`repolist` (whose CLI redirects INFO to stderr) and
    /// `Operation aborted.` for `--assumeno` (a `CliError` logged at ERROR).
    /// Anything else on stderr — an unknown line, an extra line, a repeated
    /// benign line, non-UTF-8 bytes — fails closed exactly as before. stderr
    /// is never ignored wholesale.
    fn dnf_output_guard(&self, out: &Output, what: &str, benign: &[DnfStderr]) -> Result<()> {
        if out.stdout_truncated {
            return Err(SinterError::apply(format!(
                "{} output was incomplete (stdout truncated)",
                what
            )));
        }
        if out.stderr_truncated {
            return Err(SinterError::apply(format!(
                "{} output was incomplete (stderr truncated)",
                what
            )));
        }
        if out.stderr.is_empty() {
            return Ok(());
        }
        let unexpected = || {
            SinterError::apply(format!(
                "{} produced unexpected stderr ({} bytes)",
                what,
                out.stderr.len()
            ))
        };
        // A byte stream that is not UTF-8 cannot be matched against the
        // expected lines and is not a native informational message.
        let Ok(text) = std::str::from_utf8(&out.stderr) else {
            return Err(unexpected());
        };
        // Each native benign line may appear at most once: dnf emits each
        // exactly once, so a repeat is not native output.
        let mut seen = vec![false; benign.len()];
        for line in text.lines() {
            match benign.iter().position(|k| k.matches(line)) {
                Some(i) if !seen[i] => seen[i] = true,
                _ => return Err(unexpected()),
            }
        }
        Ok(())
    }

    fn dnf_snapshot_blocked(
        &mut self,
        snap: &str,
        reason: String,
        indeterminate: bool,
    ) -> Result<DnfSnapshot> {
        let mut reason = reason;
        if let Some(msg) = self.dnf_snapshot_cleanup(snap) {
            // The blocking reason is preserved; the cleanup failure is
            // appended so it is never swallowed (R2-05).
            reason.push_str(&format!("; private snapshot cleanup failed: {}", msg));
        }
        Ok(DnfSnapshot::Blocked(reason, indeterminate))
    }

    /// Best-effort removal of a private metadata snapshot directory. Returns
    /// `Some(reason)` when the removal could not be proven successful — a
    /// non-zero exit, a signal, an indeterminate completion, or a transport
    /// failure all count. Callers must surface the failure instead of
    /// discarding it (R2-05).
    fn dnf_snapshot_cleanup(&mut self, snap: &str) -> Option<String> {
        // The path must first be proven to be Sinter's own private snapshot
        // namespace. An unverified value is never used as a removal target —
        // not even when cleanup is the intent (R4-F01, R2-05).
        if !is_valid_snapshot_path(snap) {
            return Some("snapshot path is outside the expected private namespace".to_string());
        }
        let mut req = ExecRequest::new("/usr/bin/rm");
        req.args = vec!["-rf".to_string(), snap.to_string()];
        req.env = baseline_env(self.fs.home_env());
        match self.fs.exec(&req) {
            Ok(out) => match out.completion {
                Completion::Exited(0) => None,
                Completion::Exited(c) => Some(format!("rm -rf exited {}", c)),
                Completion::Signaled(s) => Some(format!("rm -rf terminated by signal {}", s)),
                Completion::Indeterminate { reason, .. } => Some(reason),
            },
            Err(e) => Some(e.message),
        }
    }

    fn observe_package_sensitive(
        &mut self,
        backend: crate::platform::PackageBackend,
        name: &str,
        sensitive: bool,
    ) -> Result<PackageState> {
        // argv-only: the package name never becomes shell syntax. Each backend
        // distinguishes a confirmed "absent" query answer from any other
        // failure (inspection failed); nothing uninspectable is treated as
        // absent (DESIGN §27).
        let name_disp = if sensitive { "[redacted]" } else { name };
        if self.fs.fault() == Some("dpkg_observe_fail") {
            return Err(SinterError::apply(format!(
                "package observation failed for {}: injected query failure",
                name_disp
            )));
        }
        if self.fs.fault() == Some("dpkg_observe_indeterminate") {
            return Err(SinterError::indeterminate(format!(
                "package observation for {}: injected indeterminate query completion",
                name_disp
            )));
        }
        let out = self.fs.package_query_sensitive(name, sensitive)?;
        backend.classify_observation(&out, name, name_disp, sensitive)
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
        let sensitive = res.sensitive || res.derived_sensitive;
        let obs = match self.observe_service_sensitive(&name, sensitive) {
            Ok(obs) => obs,
            Err(e) => {
                // Initial observation is information uncertainty. No mutating
                // command has been dispatched, so Change must stay None.
                return Err(if e.kind == crate::error::ErrorKind::Indeterminate {
                    SinterError::apply(e.message)
                } else {
                    e
                });
            }
        };

        if obs.load_state == "not-found" {
            if self.opts.mode == Mode::Plan && self.service_has_present_package_dep(res)? {
                let mut r = unknown_result(res);
                r.reason = Some("deferred/unknown until dependency apply".into());
                r.verification = Verification::NotPerformed;
                return Ok(r);
            }
            let unit_disp = if sensitive {
                "[redacted]"
            } else {
                name.as_str()
            };
            return Err(if self.opts.mode == Mode::Plan {
                SinterError::plan(format!(
                    "{}: service unit {} was not found",
                    res.id, unit_disp
                ))
            } else {
                SinterError::apply(format!(
                    "{}: service unit {} was not found",
                    res.id, unit_disp
                ))
            });
        }

        if want_state.as_deref() == Some("running") && obs.unit_file_state == "masked" {
            let unit_disp = if sensitive {
                "[redacted]"
            } else {
                name.as_str()
            };
            return Err(SinterError::apply(format!(
                "{}: service {} is masked and cannot be started",
                res.id, unit_disp
            )));
        }
        if want_enabled.is_some() && obs.unit_file_state == "static" {
            let unit_disp = if sensitive {
                "[redacted]"
            } else {
                name.as_str()
            };
            return Err(SinterError::apply(format!(
                "{}: service {} is static and cannot be enabled/disabled",
                res.id, unit_disp
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
        // systemctl start/stop/enable/disable can change unit state even when
        // the command exits nonzero (e.g. start transitions inactive -> failed).
        let runit = |e: &mut Self, args: &[&str]| -> Result<()> {
            let mut req = ExecRequest::new("/usr/bin/systemctl");
            req.args = args.iter().map(|s| s.to_string()).collect();
            req.env = baseline_env(e.fs.home_env());
            req.sensitive = sensitive;
            let out = e.fs.exec(&req)?;
            let action = if sensitive {
                "[redacted]".to_string()
            } else {
                args.join(" ")
            };
            match out.completion {
                Completion::Exited(0) => Ok(()),
                Completion::Exited(c) => {
                    // Nonzero does not prove the unit state was untouched.
                    Err(SinterError::apply(format!(
                        "systemctl {} failed with exit code {}: {}",
                        action,
                        c,
                        String::from_utf8_lossy(&out.stderr).trim()
                    ))
                    .possible())
                }
                Completion::Signaled(s) => Err(SinterError::indeterminate(format!(
                    "systemctl {} terminated by signal {}",
                    action, s
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
                        return Ok(service_step_failure(res, e, mutated, sensitive));
                    }
                    mutated = true;
                }
                if state_needs == Some(true) {
                    if let Err(e) = runit(self, &["start", &name]) {
                        return Ok(service_step_failure(res, e, mutated, sensitive));
                    }
                    mutated = true;
                }
            }
            ("stopped", Some(en)) => {
                if state_needs == Some(true) {
                    if let Err(e) = self.stop_and_reset(&name, sensitive) {
                        return Ok(service_step_failure(res, e, mutated, sensitive));
                    }
                    mutated = true;
                }
                if enabled_needs {
                    if let Err(e) = runit(self, &[if en { "enable" } else { "disable" }, &name]) {
                        return Ok(service_step_failure(res, e, mutated, sensitive));
                    }
                    mutated = true;
                }
            }
            ("running", None) => {
                if state_needs == Some(true) {
                    if let Err(e) = runit(self, &["start", &name]) {
                        return Ok(service_step_failure(res, e, mutated, sensitive));
                    }
                    mutated = true;
                }
            }
            ("stopped", None) => {
                if state_needs == Some(true) {
                    if let Err(e) = self.stop_and_reset(&name, sensitive) {
                        return Ok(service_step_failure(res, e, mutated, sensitive));
                    }
                    mutated = true;
                }
            }
            ("", Some(en)) => {
                if enabled_needs {
                    if let Err(e) = runit(self, &[if en { "enable" } else { "disable" }, &name]) {
                        return Ok(service_step_failure(res, e, mutated, sensitive));
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
                sensitive,
            ));
        }

        // Re-observe and verify every requested dimension.
        let after = match self.observe_service_sensitive(&name, sensitive) {
            Ok(after) => after,
            Err(e) => return Ok(service_step_failure(res, e, mutated, sensitive)),
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
        let mut r = changed_result_sensitive(res, sensitive);
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

    fn stop_and_reset(&mut self, name: &str, sensitive: bool) -> Result<()> {
        let mut req = ExecRequest::new("/usr/bin/systemctl");
        req.args = vec!["stop".to_string(), name.to_string()];
        req.env = baseline_env(self.fs.home_env());
        req.sensitive = sensitive;
        let out = self.fs.exec(&req)?;
        let unit_disp = if sensitive { "[redacted]" } else { name };
        match out.completion {
            Completion::Exited(0) => {}
            Completion::Exited(_) | Completion::Signaled(_) => {
                // stop nonzero/signal may still have changed unit state.
                return Err(
                    SinterError::apply(format!("systemctl stop {} failed", unit_disp)).possible(),
                );
            }
            Completion::Indeterminate { reason, .. } => {
                return Err(SinterError::indeterminate(format!(
                    "systemctl stop {} did not complete: {}",
                    unit_disp, reason
                )));
            }
        }
        // Stop succeeded: the unit was mutated. Every later failure path must
        // preserve that known change (DESIGN §15/§30).
        if self.fs.fault() == Some("reset_failed_api_err") {
            // Simulate executor/API failure before a CommandResult exists.
            return Err(SinterError::apply(format!(
                "reset-failed execution API failed after successful stop of {}",
                unit_disp
            ))
            .changed());
        }
        // Clear a failed state so that "stopped" is clean, not failed.
        let mut req = ExecRequest::new("/usr/bin/systemctl");
        req.args = vec!["reset-failed".to_string(), name.to_string()];
        req.env = baseline_env(self.fs.home_env());
        req.sensitive = sensitive;
        let reset = match self.fs.exec(&req) {
            Ok(out) => out,
            Err(e) => {
                // API-level failure before CommandResult: stop already mutated.
                return Err(e.changed());
            }
        };
        match reset.completion {
            Completion::Exited(0) => Ok(()),
            Completion::Indeterminate { reason, .. } => Err(SinterError::indeterminate(format!(
                "systemctl reset-failed {} did not complete after stop: {}",
                unit_disp, reason
            ))
            .changed()),
            _ => Err(
                SinterError::apply(format!("systemctl reset-failed {} failed", unit_disp))
                    .changed(),
            ),
        }
    }

    fn observe_service_sensitive(&mut self, name: &str, sensitive: bool) -> Result<ServiceObs> {
        let out = self.fs.systemctl_show_sensitive(name, sensitive)?;
        let text = String::from_utf8_lossy(&out.stdout);
        match out.completion {
            Completion::Indeterminate { reason, .. } => {
                return Err(SinterError::indeterminate(format!(
                    "service observation for {} did not complete: {}",
                    if sensitive { "[redacted]" } else { name },
                    reason
                )));
            }
            Completion::Signaled(s) => {
                return Err(SinterError::apply(format!(
                    "service observation for {} terminated by signal {}",
                    if sensitive { "[redacted]" } else { name },
                    s
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
                if sensitive { "[redacted]" } else { name },
                out.exit_code(),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        if out.stdout_truncated || out.stderr_truncated {
            // Incomplete capture before any mutating command: this is an
            // information failure, not mutation uncertainty. Change stays None
            // when nothing was dispatched.
            return Err(SinterError::apply(format!(
                "service observation for {} was truncated or incomplete",
                if sensitive { "[redacted]" } else { name }
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
                if sensitive { "[redacted]" } else { name }
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
                        // The producer resource or the consumer may be
                        // sensitive; keep expression contents out of errors.
                        let dep_sensitive = d.sensitive || res.sensitive || res.derived_sensitive;
                        let evaluated =
                            eval_value_interpolated(value, &self.scope(item.as_ref(), None, None))
                                .map_err(|e| {
                                    if dep_sensitive {
                                        SinterError::plan(format!(
                                            "{}: could not evaluate package dependency state (value redacted): {}",
                                            res.id,
                                            e.category()
                                        ))
                                    } else {
                                        SinterError::plan(format!(
                                            "{}: could not evaluate package dependency state: {}",
                                            res.id, e
                                        ))
                                    }
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
        let sensitive = h.sensitive;
        let obs = match self.observe_service_sensitive(name, sensitive) {
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
        req.sensitive = sensitive;
        let out = self.fs.exec(&req)?;
        match out.completion {
            Completion::Indeterminate { .. } => Ok(HandlerOutcomeState::Indeterminate),
            Completion::Signaled(_) => Ok(HandlerOutcomeState::Failed),
            Completion::Exited(code) => {
                if code != 0 {
                    return Ok(HandlerOutcomeState::Failed);
                }
                // Verification.
                let after = match self.observe_service_sensitive(name, sensitive) {
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

/// Outcome of preparing the private dnf metadata snapshot for an install.
enum DnfSnapshot {
    /// Verified snapshot cachedir path; the install may run against it.
    Ready(String),
    /// Completeness could not be proven — the mutation must fail closed.
    /// (reason, indeterminate)
    Blocked(String, bool),
}

/// A benign stderr line one dnf subcommand is known to print on a normal,
/// successful run (R5-F04). The contract is per-command and each kind is
/// matched by an exact grammar — never a prefix — so a line that merely
/// resembles the expected one still fails closed.
#[derive(Clone, Copy)]
enum DnfStderr {
    /// `Last metadata expiration check: <age> ago on <date>.` — logged at
    /// INFO when the sack is loaded from cache (dnf/base.py `fill_sack`).
    /// `repoquery` and `repolist` redirect INFO to stderr, so this line is
    /// expected there for those commands (at most once).
    MetadataExpiration,
    /// `Operation aborted.` — an `--assumeno` install resolves the
    /// transaction, prints the table, then aborts the prompt by raising
    /// `CliError`, which `main` logs at ERROR level → stderr (at most once).
    /// Expected only for the `install --assumeno` resolution step.
    OperationAborted,
}

impl DnfStderr {
    fn matches(&self, line: &str) -> bool {
        match self {
            Self::MetadataExpiration => is_metadata_expiration_line(line),
            Self::OperationAborted => line == "Operation aborted.",
        }
    }
}

/// Parse `dnf repolist -v` output into `(repo id, resolves-via-mirrorlist)`
/// pairs. Every `Repo-id` line begins a block for an enabled repository
/// (`repolist` lists enabled repos only); a `Repo-mirrors` field inside a
/// block means the repo resolves through a mirror list whose cached copy
/// the snapshot must contain.
///
/// The grammar is strict but native-compatible (R4-F03/R4-F04): it accepts
/// exactly what `dnf repolist -v` prints (dnf 4.14 `RepoListCommand.run`) and
/// rejects everything else. Native output is a sequence of blocks, one per
/// enabled repository, separated by blank lines, ending with a
/// `Total packages: <count>` footer. Each block opens with `Repo-id`, always
/// shows `Repo-name`, and shows any of the other fields dnf prints
/// conditionally. `Repo-status` is *optional*: dnf only prints it for
/// `--all`/explicit-repo invocations, never for the plain `repolist -v` this
/// tool runs, so requiring it would reject valid upstream output (R4-F04).
///
/// Fail closed (R2-03, R4-A01, R4-F03): a recognized field must have the exact
/// `Repo-<name> : <value>` shape dnf prints, must be a field dnf actually
/// prints (an arbitrary `Repo-*` line is unrecognized structure, not a
/// tolerated extra), and each field must appear exactly once in its block. A
/// prefix match with a malformed separator (e.g. `Repo-idNOT_A_FIELD:
/// baseos`), an empty value, a duplicated field, a duplicated repository
/// identity, a duplicated block, an orphan field outside any block, a
/// malformed footer, or any line that is not a recognized field, the
/// structural `Updated` line, a blank separator or the footer yields `None`:
/// a partially understood repository set can never prove the snapshot is
/// complete, so it is never guessed from. One malformed block among several
/// valid ones rejects the whole output — the repository set cannot be proven,
/// so only some of it may never be trusted.
///
/// Block boundaries are explicit (R4-F03): a blank line *closes* the current
/// block; it never clears the seen fields while keeping the block open. A
/// field that appears after the closing blank has no enclosing block and is
/// malformed. A block is a complete enabled-repository record only when it
/// showed its identity (`Repo-id`) and its name (`Repo-name`) — both are
/// printed unconditionally by dnf, so a block without them is incomplete
/// output (R2-03-A). A `Repo-status` other than `enabled` contradicts
/// `repolist` semantics and is rejected.
fn parse_dnf_enabled_repos(text: &str) -> Option<Vec<(String, bool)>> {
    let mut out: Vec<(String, bool)> = Vec::new();
    // Repository identities already seen: `repolist` lists each repository
    // once, so a repeated identity is not an interpretable repository set.
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    // The block lifecycle. `open` means a `Repo-id` opened a block that has
    // not yet been closed by a blank separator, a new block, or the footer.
    let mut open = false;
    let mut have_name = false;
    let mut block_fields: Vec<&str> = Vec::new();
    // Completed blocks seen, so the native footer is only accepted after at
    // least one real repository block.
    let mut complete = 0usize;
    let mut footer_seen = false;
    // Preamble lines dnf prints before the first block — each at most once
    // (R5-F04). The set keeps a preamble line from repeating or reappearing
    // in preamble position after itself.
    let mut preamble_fields: Vec<&str> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if footer_seen {
            // Only blank lines may follow the native footer.
            if !t.is_empty() {
                return None;
            }
            continue;
        }
        if t.is_empty() {
            // A blank separator closes the block: an incomplete one is not a
            // repository record. It never keeps the block open with cleared
            // field state (R4-F03).
            if open {
                if !have_name {
                    return None;
                }
                complete += 1;
                open = false;
                have_name = false;
                block_fields.clear();
            }
            continue;
        }
        // Native preamble (R5-F04): before the first `Repo-id` opens a
        // block, `repolist -v` prints `Loaded plugins:`, `DNF version:` and
        // `cachedir:` lines — each matched by its own grammar and accepted
        // at most once, in any order. Once a repository id has been seen a
        // preamble-shaped line is unrecognized structure (the checks below
        // reject it), so a preamble field inside or after a block still
        // fails closed.
        if seen_ids.is_empty() {
            if let Some(kind) = repolist_preamble_line(t) {
                if !repo_field_once(&mut preamble_fields, kind) {
                    return None;
                }
                continue;
            }
        }
        // The native footer ends the repository list and is matched exactly.
        if parse_repolist_footer(t).is_some() {
            // dnf prints it directly after the last block's fields, with no
            // blank separator, so a block may still be open here. Either way
            // at least one complete block must exist, and a block still open
            // at the footer must itself be complete.
            if open && !have_name {
                return None;
            }
            if complete == 0 && !open {
                return None;
            }
            footer_seen = true;
            continue;
        }
        if let Some(id) = repo_field_value(t, "Repo-id") {
            // A new block opens; the previous one must have been complete.
            if open {
                if !have_name {
                    return None;
                }
                complete += 1;
            }
            // A duplicate repository identity is not a repository set dnf
            // prints, whatever the other fields say.
            if !seen_ids.insert(id.to_string()) {
                return None;
            }
            out.push((id.to_string(), false));
            open = true;
            have_name = false;
            block_fields.clear();
            repo_field_once(&mut block_fields, "Repo-id");
        } else if t.starts_with("Repo-id") {
            // A prefix match that is not a well-formed Repo-id field
            // (e.g. `Repo-idNOT_A_FIELD: baseos`) is unrecognized structure.
            return None;
        } else if let Some(name) = repo_field_name(t, "Repo-name") {
            // The repository name dnf prints unconditionally; a block without
            // it is incomplete.
            if !open || !repo_field_once(&mut block_fields, name) {
                return None;
            }
            have_name = true;
        } else if t.starts_with("Repo-name") {
            return None;
        } else if let Some(status) = repo_field_value(t, "Repo-status") {
            // Optional in native output: dnf prints it only for invocations
            // this tool never runs. When present it must say `enabled`, since
            // `repolist` lists enabled repositories only. A status with no
            // enclosing block is an orphan field (R4-F03).
            if !open || status != "enabled" {
                return None;
            }
            // A repeated status is malformed output even when it agrees; a
            // contradictory one was rejected by the check above.
            if !repo_field_once(&mut block_fields, "Repo-status") {
                return None;
            }
        } else if t.starts_with("Repo-status") {
            return None;
        } else if repo_field_value(t, "Repo-mirrors").is_some() {
            // A repo that resolves through a mirror list.
            if !open || !repo_field_once(&mut block_fields, "Repo-mirrors") {
                return None;
            }
            let last = out.last_mut()?;
            last.1 = true;
        } else if t.starts_with("Repo-mirrors") {
            return None;
        } else if let Some((name, _value)) = split_repo_field(t) {
            // Another field dnf prints. It must be a recognized one — an
            // arbitrary `Repo-*` line is not structure this parser models —
            // and it must sit inside an open block and appear once there.
            if !open || !is_known_repolist_field(name) || !repo_field_once(&mut block_fields, name)
            {
                return None;
            }
        } else if is_repolist_updated_line(t) {
            // The indented `Updated` timestamp dnf prints under
            // `Repo-metalink` for an enabled repository. It is structural, not
            // a `Repo-` field, and appears once in its block.
            if !open || !repo_field_once(&mut block_fields, "Updated") {
                return None;
            }
        } else if t.starts_with("Repo-") {
            // A `Repo-` line without the `name : value` shape dnf prints.
            return None;
        } else {
            // Unrecognized line structure.
            return None;
        }
    }
    // The final block must be complete too: output that stops after a bare
    // `Repo-id` is incomplete, not an enabled-repository record.
    if open && !have_name {
        return None;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// The fields dnf 4 prints in a `repolist -v` block, from
/// `dnf/cli/commands/repolist.py::RepoListCommand.run`. `Repo-id` and
/// `Repo-name` are unconditional; the rest are conditional on loaded metadata
/// and repository configuration. An unknown `Repo-*` field is not a field
/// this parser may silently accept (R4-F03).
const KNOWN_REPOLIST_FIELDS: &[&str] = &[
    "Repo-id",
    "Repo-name",
    "Repo-status",
    "Repo-revision",
    "Repo-tags",
    "Repo-distro-tags",
    "Repo-updated",
    "Repo-pkgs",
    "Repo-available-pkgs",
    "Repo-size",
    "Repo-metalink",
    "Repo-mirrors",
    "Repo-baseurl",
    "Repo-expire",
    "Repo-exclude",
    "Repo-include",
    "Repo-excluded",
    "Repo-filename",
];

/// Whether a field name is one dnf prints in a `repolist -v` block.
fn is_known_repolist_field(name: &str) -> bool {
    KNOWN_REPOLIST_FIELDS.contains(&name)
}

/// The native `dnf repolist -v` footer: exactly `Total packages: <count>`
/// (dnf 4 `print(_('Total packages: {}').format(...))`), where the count is a
/// plain decimal number — dnf formats it with `%d`, so no sign, grouping or
/// leading zero. Anything else is unrecognized trailing structure.
fn parse_repolist_footer(t: &str) -> Option<usize> {
    let rest = t.strip_prefix("Total packages:")?;
    let rest = rest.trim();
    if rest.is_empty() {
        return None;
    }
    // Canonical decimal only: no leading zero (a `0` count alone is fine).
    if rest.len() > 1 && rest.starts_with('0') {
        return None;
    }
    if !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rest.parse::<usize>().ok()
}

/// A preamble line `dnf -C repolist -v` prints before the first repository
/// block (R5-F04): `Loaded plugins: <names>` when plugins are enabled, and
/// the `-v` debug lines `DNF version: <ver>` and `cachedir: <path>`
/// (`dnf/cli/cli.py::_log_essentials`). Each is matched by its own grammar —
/// an arbitrary banner or a field-shaped line that merely resembles one is
/// not a preamble and yields `None`.
fn repolist_preamble_line(t: &str) -> Option<&'static str> {
    if let Some(rest) = t.strip_prefix("Loaded plugins:") {
        return is_dnf_plugin_list(rest.trim()).then_some("Loaded plugins");
    }
    if let Some(rest) = t.strip_prefix("DNF version:") {
        return is_dnf_version(rest.trim()).then_some("DNF version");
    }
    if let Some(rest) = t.strip_prefix("cachedir:") {
        return is_dnf_cachedir(rest.trim()).then_some("cachedir");
    }
    None
}

/// The `Loaded plugins:` list: plugin names joined by `, `, each a Python
/// attribute name (`[A-Za-z0-9_-]+` — e.g. `config-manager`,
/// `generate_completion_cache`).
fn is_dnf_plugin_list(t: &str) -> bool {
    !t.is_empty()
        && t.split(", ").all(|n| {
            !n.is_empty()
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

/// The `DNF version:` value: `dnf.const.VERSION`, a dotted number such as
/// `4.14.0`.
fn is_dnf_version(t: &str) -> bool {
    !t.is_empty()
        && t.split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The `cachedir:` value: an absolute path naming the metadata cache root.
/// Restricted to the printable path alphabet dnf/installroot paths use; a
/// path carrying whitespace or control bytes is not this line.
fn is_dnf_cachedir(t: &str) -> bool {
    t.len() > 1
        && t.starts_with('/')
        && t.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'+' | b'=' | b'@')
        })
}

/// The informational line dnf logs at INFO after loading repository
/// metadata: `Last metadata expiration check: <age> ago on <date>.`
/// (dnf/base.py `fill_sack`: `_("Last metadata expiration check: %s ago on
/// %s.")` with a `datetime.timedelta` age and a `strftime("%c")` date). The
/// grammar is exactly what dnf renders under the C locale this tool forces —
/// anything merely resembling the line is not it.
fn is_metadata_expiration_line(t: &str) -> bool {
    let Some(rest) = t.strip_prefix("Last metadata expiration check: ") else {
        return false;
    };
    let Some((age, date)) = rest.split_once(" ago on ") else {
        return false;
    };
    is_dnf_timedelta_age(age) && is_dnf_ctime_date(date)
}

/// A `str(datetime.timedelta)` age: `H:MM:SS`, or `<N> day[s], H:MM:SS`.
/// A negative timedelta always carries a day count (`-1 day, 23:59:59`),
/// so a leading `-` is only valid in the day form.
fn is_dnf_timedelta_age(t: &str) -> bool {
    let f: Vec<&str> = t.split_whitespace().collect();
    match f.len() {
        1 => is_dnf_hms(f[0], false),
        3 => {
            let days = f[0].strip_prefix('-').unwrap_or(f[0]);
            !days.is_empty()
                && days.bytes().all(|b| b.is_ascii_digit())
                && (f[1] == "day," || f[1] == "days,")
                && is_dnf_hms(f[2], false)
        }
        _ => false,
    }
}

/// Whether `s` is exactly `w` decimal digits whose value is under `max`.
fn is_bounded_digits(s: &str, w: usize, max: u32) -> bool {
    s.len() == w && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u32>().is_ok_and(|v| v < max)
}

/// An `H:MM:SS` duration (`padded=false`: the hour is not zero-padded and
/// not bounded — timedelta renders `26:00:00` for a day-plus overflow only
/// via the day form) or a strict `HH:MM:SS` clock time (`padded=true`:
/// exactly two digits, hour < 24). Minutes and seconds are two digits < 60
/// in both forms.
fn is_dnf_hms(t: &str, padded: bool) -> bool {
    let f: Vec<&str> = t.split(':').collect();
    f.len() == 3
        && (if padded {
            is_bounded_digits(f[0], 2, 24)
        } else {
            !f[0].is_empty() && f[0].bytes().all(|b| b.is_ascii_digit())
        })
        && is_bounded_digits(f[1], 2, 60)
        && is_bounded_digits(f[2], 2, 60)
}

/// A `strftime("%c")` date under the C locale plus the message's literal
/// trailing dot: `Www Mmm D[D] HH:MM:SS YYYY.` — the day is `%e`
/// (space-padded, so it splits to one or two digits), weekday and month are
/// the C-locale abbreviations, the clock is strict `%H:%M:%S`, the year four
/// digits.
fn is_dnf_ctime_date(t: &str) -> bool {
    let Some(t) = t.strip_suffix('.') else {
        return false;
    };
    const DAYS: &[&str] = &["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: &[&str] = &[
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let f: Vec<&str> = t.split_whitespace().collect();
    f.len() == 5
        && DAYS.contains(&f[0])
        && MONTHS.contains(&f[1])
        && (1..=2).contains(&f[2].len())
        && f[2].bytes().all(|b| b.is_ascii_digit())
        && is_dnf_hms(f[3], true)
        && f[4].len() == 4
        && f[4].bytes().all(|b| b.is_ascii_digit())
}

/// The indented `Updated` line dnf prints under `Repo-metalink` for an enabled
/// repository (`fmtKeyValFill(_("  Updated          : "), ...)`). Matched
/// exactly, not by prefix: the label is `Updated`, padded to the column, then
/// ` : ` and a non-empty timestamp.
fn is_repolist_updated_line(t: &str) -> bool {
    let Some(rest) = t.strip_prefix("Updated") else {
        return false;
    };
    let rest = rest.trim_start();
    rest.starts_with(':') && !rest[1..].trim().is_empty()
}

/// Split a well-formed `Repo-<name> ... : <value>` line into its field name
/// and value (R2-03, R4-A01). dnf prints each field name left-justified in a
/// fixed-width column followed by ` : ` and the value. A line that is not
/// exactly that shape — a field name run into other characters
/// (`Repo-idNOT_A_FIELD: baseos`), an empty value, or a missing separator —
/// is not a field dnf prints and yields `None`.
fn split_repo_field(t: &str) -> Option<(&str, &str)> {
    let (name, value) = t.split_once(':')?;
    let name = name.trim();
    if !name.starts_with("Repo-") || name.len() <= "Repo-".len() {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some((name, value))
}

/// Extract the value of a `Repo-<field> ... : <value>` line. The field name
/// must match exactly: a prefix that runs into other characters
/// (`Repo-idNOT_A_FIELD: baseos`) is not the field it resembles.
fn repo_field_value<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let (name, value) = split_repo_field(line)?;
    if name == field {
        Some(value)
    } else {
        None
    }
}

/// The field name of a `Repo-<field> ... : <value>` line when it matches
/// `field` exactly. Used for fields whose presence (not value) is what the
/// block lifecycle tracks.
fn repo_field_name<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    split_repo_field(line).and_then(|(name, _)| (name == field).then_some(name))
}

/// Record a field name seen once in the current repository block, rejecting a
/// repeat: dnf prints every field exactly once, so a duplicated field is
/// malformed output even when the two values agree.
fn repo_field_once<'a>(block_fields: &mut Vec<&'a str>, name: &'a str) -> bool {
    if block_fields.contains(&name) {
        return false;
    }
    block_fields.push(name);
    true
}

/// Interpret a `find <root> -mindepth 1 -maxdepth 1 -print0` answer as raw
/// NUL-framed bytes and prove every entry is exactly one direct child of
/// the live cache root (R4-F01). The answer is never treated as text until
/// its framing and structure are established:
///
///   * the capture is complete (the caller rejects truncation/stderr), and
///     a non-empty answer must be NUL-terminated — `find -print0` ends
///     every entry with a NUL, so a missing trailing one is truncated
///     framing, not a final entry;
///   * every entry is valid UTF-8 — invalid bytes must not be lossily
///     converted into a different path (`String::from_utf8_lossy` would
///     silently rename an entry);
///   * there is no empty entry (a doubled NUL) and no duplicate entry —
///     `find` prints each path exactly once;
///   * every entry is `<root>/<one-child>`: absolute, under the cache root,
///     a single non-empty path component, and not `.`/`..`.
///
/// Only then does an entry become a `cp` argv element. Because every entry
/// is provably a direct child, the copy can never leave the cache root,
/// and because the entries stay discrete argv elements, a name with a
/// space, a newline, or a leading `-` cannot alter the command structure.
fn parse_cache_children(stdout: &[u8]) -> std::result::Result<Vec<String>, &'static str> {
    if stdout.is_empty() {
        return Ok(Vec::new());
    }
    // Invalid UTF-8 must not be lossily re-encoded into another path.
    if std::str::from_utf8(stdout).is_err() {
        return Err("an entry is not valid UTF-8");
    }
    // NUL framing: a non-empty answer must end with a NUL.
    if stdout.last() != Some(&0) {
        return Err("the listing is not NUL-terminated");
    }
    let parts: Vec<&[u8]> = stdout.split(|b| *b == 0).collect();
    // The trailing NUL yields one final empty element; drop it. Any other
    // empty element is a doubled NUL, which `find` never prints.
    let parts = if parts.last() == Some(&&[][..]) {
        &parts[..parts.len() - 1]
    } else {
        &parts[..]
    };
    let mut children: Vec<String> = Vec::new();
    for entry in parts {
        if entry.is_empty() {
            return Err("the listing contains an empty entry");
        }
        // Prove the entry is one direct child of the cache root before it
        // is used as a copy source.
        cache_direct_child(entry)?;
        let s = std::str::from_utf8(entry)
            .expect("validated above")
            .to_string();
        if children.contains(&s) {
            return Err("the listing contains a duplicate entry");
        }
        children.push(s);
    }
    Ok(children)
}

/// Prove a `find -print0` entry is exactly one direct child of the live DNF
/// metadata cache root (R4-F01): the entry must be absolute, must start with
/// the cache root followed by a path separator, and what follows must be a
/// single non-empty path component that is not `.` or `..`. Anything else —
/// an absolute path outside the root, a relative path, the root itself, a
/// `/.` form, a `..` traversal, or a nested descendant — proves nothing about
/// the cache layout and is rejected.
fn cache_direct_child(entry: &[u8]) -> std::result::Result<(), &'static str> {
    let root = b"/var/cache/dnf";
    let Some(rest) = entry.strip_prefix(root) else {
        return Err("an entry is outside the metadata cache root");
    };
    let Some(child) = rest.strip_prefix(b"/") else {
        // The entry is the cache root itself.
        return Err("an entry is the metadata cache root, not a child");
    };
    if child.is_empty() {
        return Err("an entry is the metadata cache root, not a child");
    }
    if child == b"." || child == b".." {
        return Err("an entry is a dot entry, not a cache child");
    }
    // A direct child has no further path component. This also rejects a
    // nested descendant and any `/.`-style traversal inside the name.
    if child.contains(&b'/') {
        return Err("an entry is not a direct child of the cache root");
    }
    Ok(())
}

/// Prove a `mktemp -d /var/tmp/sinter-dnf.XXXXXXXX` answer is exactly one
/// absolute path inside Sinter's own private snapshot namespace (R4-F01). The
/// helper output is captured whole first, then framed, then validated:
///
///   * the capture is complete (the caller rejects truncation/stderr) and is
///     valid UTF-8 — no lossy re-encoding of an untrusted value;
///   * it is exactly one line (an optional trailing newline aside) — an extra
///     line is not a path mktemp prints;
///   * the path is `/var/tmp/sinter-dnf.<suffix>`, where the suffix is a
///     single path component of exactly the eight replacement characters the
///     requested template asks for (`[A-Za-z0-9]`), and not `.` or `..`.
///
/// Only a proven path may be the target of a chmod, stat, copy or cleanup
/// operation. The returned reason is a constant: an untrusted path is never
/// echoed back out (R2-01).
fn validate_snapshot_path(stdout: &[u8]) -> std::result::Result<String, &'static str> {
    let s = std::str::from_utf8(stdout).map_err(|_| "the output is not valid UTF-8")?;
    let line = s.strip_suffix('\n').unwrap_or(s);
    if line.is_empty() {
        return Err("the snapshot directory path is empty");
    }
    if line.contains('\n') {
        return Err("the snapshot helper produced more than one line");
    }
    if line.contains('\0') {
        return Err("the snapshot directory path contains a NUL");
    }
    if !is_valid_snapshot_path(line) {
        return Err("the path is not in the expected private snapshot namespace");
    }
    Ok(line.to_string())
}

/// Whether a path is a member of Sinter's private snapshot namespace:
/// `/var/tmp/sinter-dnf.` followed by exactly eight mktemp replacement
/// characters as a single path component. The namespace is the one the
/// `mktemp` template requests, so anything else — `/tmp/outside`,
/// `../outside`, `/`, `.`, `..`, an unexpected prefix, a traversal-like form,
/// or a suffix of the wrong shape — is not a directory Sinter created and may
/// never be operated on.
fn is_valid_snapshot_path(path: &str) -> bool {
    let Some(suffix) = path.strip_prefix("/var/tmp/sinter-dnf.") else {
        return false;
    };
    // Exactly the eight replacement characters the template requests; a single
    // path component with no separator, no NUL and no dot-entry form.
    suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Whether a snapshot cache directory name is exactly the directory DNF
/// keeps for repository `repoid` (R4-A03, R4-F05). libdnf names a repository's
/// metadata cache `<repo-id>-<hash>`; the hash is the first eight bytes of a
/// SHA-256 digest rendered as hexadecimal — exactly sixteen characters
/// (libdnf 0.69 `Repo::Impl::getHash()`: `USE_CHECKSUM_BYTES = 8` and
/// `solv_bin2hex`). A repository id may itself contain '-' but the hash never
/// does, so the identity a directory name proves is exactly the text before
/// its *last* '-' — provided the text after it is that native hash. That
/// boundary is unambiguous, so a directory either proves it belongs to
/// `repoid` or proves it does not: `baseos-extra-<hash>` proves repository
/// `baseos-extra`, never `baseos`. A hash of any other length, an empty one,
/// or a non-hexadecimal one proves no repository mapping at all.
fn is_repo_cache_dir(repoid: &str, name: &str) -> bool {
    let Some((id, hash)) = name.rsplit_once('-') else {
        return false;
    };
    // The exact native hash format: 16 lowercase/uppercase hex characters.
    !id.is_empty()
        && hash.len() == 16
        && hash.bytes().all(|b| b.is_ascii_hexdigit())
        && id == repoid
}

/// Whether a transaction-derived package name is a valid operand for a dnf
/// package query (R4-F05). rpm package names are `[A-Za-z0-9._+-]+`; a value
/// that starts with `-` is an option, not a package, and a value containing a
/// path separator, whitespace or a control character is not a package
/// identifier either. The value reaches a dnf argv element, so the target
/// CLI's own operand semantics — not just shell quoting — must hold.
fn valid_package_name(t: &str) -> bool {
    !t.is_empty()
        && !t.starts_with('-')
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// Whether a transaction-derived architecture is one an rpm payload file name
/// carries: `[A-Za-z0-9_]+` (e.g. `x86_64`, `aarch64`, `noarch`).
fn valid_package_arch(t: &str) -> bool {
    !t.is_empty() && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Whether a transaction-derived version-release string is safe to embed in a
/// payload file name: rpm version-release text over `[A-Za-z0-9._+-]`, never
/// starting with `-` and never containing a path separator or control byte.
fn valid_version_release(t: &str) -> bool {
    !t.is_empty()
        && !t.starts_with('-')
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// Whether a transaction-derived repository id is a value libdnf accepts as a
/// repository id *and* a safe path component (R4-F05). libdnf's
/// `REPOID_CHARS` is ASCII letters, digits, `-`, `_`, `.` and `:`, so a repo
/// id from a transaction table must be within that set; the empty string and
/// the dot entries are never repository ids. This is what lets a repo id be
/// used to recognize — never to construct — a cache directory: a value with a
/// path separator, a traversal form, a control byte or an option-like leading
/// dash proves no repository at all.
fn valid_repo_id(t: &str) -> bool {
    !t.is_empty()
        && t != "."
        && t != ".."
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// Whether the snapshot listing shows the cached mirror list for repository
/// `repoid` (R4-A03). The line must be exactly `<snap>/<repoid>-<hash>/
/// mirrorlist`, where the directory name proves it belongs to `repoid` — a
/// directory that merely shares an id prefix is not this repository's.
fn listing_has_mirrorlist(listing: &str, snap: &str, repoid: &str) -> bool {
    let prefix = format!("{}/", snap);
    listing.lines().any(|l| {
        let Some(rest) = l.strip_prefix(&prefix) else {
            return false;
        };
        let Some(dirname) = rest.strip_suffix("/mirrorlist") else {
            return false;
        };
        is_repo_cache_dir(repoid, dirname)
    })
}

/// Classify a resolved payload location as the one URL this tool actually and
/// safely fetches (R2-03-C, R4-A02, R4-F02). The location is handed to a
/// non-interactive downloader as one argv element, and the downloader must
/// retrieve exactly the resource the validated string names — so the value is
/// not merely a syntactically valid URL, but one whose resource identity is
/// unambiguous:
///
///   * scheme `http` or `https`, a well-formed authority (optional userinfo,
///     registered name or IPv4/IPv6 literal, optional in-range port), and an
///     absolute path — relative paths, scheme-less strings, unsupported
///     schemes, host-less URLs, malformed authorities, malformed IPv6 literals
///     and invalid ports are all rejected;
///   * **no query and no fragment** (Phase 1): a `?` or `#` anywhere would
///     make the resource identity depend on downloader behavior this tool
///     cannot prove, so both are rejected outright instead of normalized;
///   * **no percent-encoding** (Phase 1): every `%` would have to be
///     interpreted to know which resource it names (an encoded slash, dot or
///     basename changes the identity), and a malformed one (`%`, `%A`, `%GG`)
///     is not a location at all. RPM payload names never need encoding, so
///     rejecting `%` outright keeps the identity byte-exact;
///   * the path has no `.`/`..` segment, and its final segment is a
///     well-formed RPM payload name — the exact resource the transaction
///     row expects, matched by basename without ambiguity. An empty
///     segment (a doubled `/`) is *not* rejected: native
///     `repoquery --location` output legitimately contains it because the
///     mirror baseurl ends in `/` and dnf joins the package path with
///     another `/` (e.g. the real Rocky 9 mirror
///     `.../pub/rocky//9.8/BaseOS/...`, R5-F04). A doubled separator is
///     requested byte-for-byte by the downloader and still resolves to one
///     resource — unlike a dot segment, nothing reinterprets it.
///
/// The value is never echoed in the returned reason: location text is
/// repository data (R2-01).
fn validate_payload_url(url: &str) -> std::result::Result<(), &'static str> {
    if url.is_empty() {
        return Err("empty payload location");
    }
    // Whitespace or a control character anywhere in a URL can only come from
    // a malformed or hostile repository record. This is checked before any
    // parsing because a URL parser may silently discard such characters
    // instead of rejecting the URL, which would make the value ambiguous.
    if url
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("payload location contains whitespace");
    }
    // The Phase 1 accepted character set: unreserved characters,
    // sub-delimiters and the structural delimiters a URL authority/path needs.
    // Query and fragment separators and the percent sigil are absent on
    // purpose — see the function docs.
    if !url.chars().all(is_payload_url_char) {
        return Err("payload location is not a URL");
    }
    let (scheme, rest) = url
        .split_once("://")
        .ok_or("payload location is not a URL")?;
    if scheme.is_empty() {
        return Err("payload location is not a URL");
    }
    if scheme != "http" && scheme != "https" {
        return Err("payload location uses an unsupported scheme");
    }
    // The authority component ends at the first '/' — a query or fragment
    // separator cannot appear, so only '/' ends it here.
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err("payload location has no host");
    }
    // `userinfo@host:port`; only the last '@' can separate them.
    let host_port = match authority.rsplit_once('@') {
        Some((userinfo, host)) => {
            if userinfo.is_empty() || !userinfo.chars().all(is_url_userinfo_char) {
                return Err("payload location has a malformed authority");
            }
            host
        }
        None => authority,
    };
    // The port, if any, and the host it belongs to. A bracketed host is an
    // IPv6 literal; any other host is a registered name (which also covers
    // IPv4 literals). The two forms are never mixed.
    let port: Option<&str> = if let Some(inner) = host_port.strip_prefix('[') {
        let Some(end) = inner.find(']') else {
            return Err("payload location has a malformed host");
        };
        let (ipv6, tail) = (&inner[..end], &inner[end + 1..]);
        if !is_ipv6_address(ipv6) {
            return Err("payload location has a malformed host");
        }
        match tail.strip_prefix(':') {
            Some(p) => Some(p),
            None if tail.is_empty() => None,
            None => return Err("payload location has a malformed host"),
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port)) => {
                if host.is_empty() || !host.chars().all(is_url_reg_name_char) {
                    return Err("payload location has a malformed host");
                }
                Some(port)
            }
            None => {
                // An empty host (`user@/path`) names no host at all.
                if host_port.is_empty() || !host_port.chars().all(is_url_reg_name_char) {
                    return Err("payload location has a malformed host");
                }
                None
            }
        }
    };
    // A port is a plain decimal number in the valid TCP port range.
    if let Some(port) = port {
        let in_range = |n: u32| (1..=65535).contains(&n);
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || !port.parse::<u32>().map(in_range).unwrap_or(false)
        {
            return Err("payload location has a malformed port");
        }
    }
    // There must be an absolute path to fetch from: a URL that ends at the
    // authority names no resource.
    let path = path
        .strip_prefix('/')
        .ok_or("payload location has no path")?;
    // Glob and bracket characters would let the downloader reinterpret the
    // path (curl URL glob expansion of `[1-2]` or `{a,b}`); they are only
    // meaningful inside an IPv6 authority, which the authority parsing above
    // already consumed. Disabling globbing in the downloader plus rejecting
    // the syntax here is the one-validated-URL-one-request contract (R4-F02).
    if path.bytes().any(|b| matches!(b, b'[' | b']' | b'{' | b'}')) {
        return Err("payload location uses URL glob syntax");
    }
    // Dot segments are rejected: URL normalization would reinterpret them
    // and the resource the downloader actually receives could differ from
    // the path as written. An empty segment (a doubled `/`) is *not* a dot
    // segment and is not normalized away by the downloader — curl requests
    // the path literally — and native `repoquery --location` output
    // produces it whenever the mirror baseurl ends in `/` (the real Rocky
    // mirrors do: `.../pub/rocky//9.8/...`, R5-F04).
    for seg in path.split('/') {
        if seg == "." || seg == ".." {
            return Err("payload location has a dot path segment");
        }
    }
    // The final path segment names the payload: an RPM file. Because no
    // percent-encoding is accepted, this comparison is byte-exact against the
    // payload name the transaction row expects, which is what proves the
    // downloader fetches the intended resource.
    if !is_rpm_payload_name(path.rsplit('/').next().unwrap_or("")) {
        return Err("payload location has no payload name");
    }
    Ok(())
}

/// Whether a character may appear in a payload URL this tool fetches (Phase 1
/// subset of RFC 3986): unreserved characters, sub-delimiters and the
/// structural delimiters. Query/fragment separators (`?`, `#`) and the
/// percent sigil are deliberately excluded — resource identity must stay
/// byte-exact (R4-F02).
fn is_payload_url_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.'
                | '_'
                | '~'
                | '!'
                | '$'
                | '&'
                | '\''
                | '('
                | ')'
                | '*'
                | '+'
                | ','
                | ';'
                | '='
                | ':'
                | '/'
                | '['
                | ']'
                | '@'
        )
}

/// Whether a path segment is a well-formed RPM payload file name: a non-empty
/// stem over the characters rpm package names, versions and architectures use,
/// followed by `.rpm`. A leading `-` is not a file name any repository prints
/// and would be indistinguishable from a downloader option, so it is rejected.
fn is_rpm_payload_name(seg: &str) -> bool {
    let Some(stem) = seg.strip_suffix(".rpm") else {
        return false;
    };
    !stem.is_empty()
        && !seg.starts_with('-')
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// Whether a character may appear in the userinfo component of a URL
/// (RFC 3986): unreserved characters, sub-delimiters, percent-encodings and
/// the colon that separates a user from a password.
fn is_url_userinfo_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.' | '_' | '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';'
        )
        || matches!(c, ':' | '%')
}

/// Whether a character may appear in a registered host name (RFC 3986):
/// unreserved characters, sub-delimiters and percent-encodings. IPv4 literals
/// are covered by this set as well.
fn is_url_reg_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.'
                | '_'
                | '~'
                | '!'
                | '$'
                | '&'
                | '\''
                | '('
                | ')'
                | '*'
                | '+'
                | ','
                | ';'
                | '='
        )
        || c == '%'
}

/// Whether a text is a valid IPv6 address (RFC 4291): up to eight groups of
/// one to four hexadecimal digits separated by ':', at most one '::'
/// compression, optionally ending in an embedded IPv4 address (which occupies
/// the final two groups). Anything else — too many groups, a group wider than
/// four digits, a second compression, a stray empty group, an embedded IPv4
/// anywhere but last — is not an address and fails closed.
fn is_ipv6_address(t: &str) -> bool {
    if t.is_empty() || t.matches("::").count() > 1 {
        return false;
    }
    match t.split_once("::") {
        Some((left, right)) => {
            matches!(
                (ipv6_half_groups(left, false), ipv6_half_groups(right, true)),
                (Some(l), Some(r)) if l + r <= 7
            )
        }
        None => ipv6_half_groups(t, true) == Some(8),
    }
}

/// The number of groups in one half of an IPv6 text. An empty half holds zero
/// groups. `ipv4_last` allows the final group of the half to be an embedded
/// IPv4 address, which counts as two groups; it is only valid there.
fn ipv6_half_groups(half: &str, ipv4_last: bool) -> Option<usize> {
    if half.is_empty() {
        return Some(0);
    }
    let parts: Vec<&str> = half.split(':').collect();
    let mut groups = 0;
    for (i, part) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        if part.is_empty() {
            return None;
        }
        if last && ipv4_last && is_ipv4_address(part) {
            groups += 2;
        } else if part.len() <= 4 && part.bytes().all(|b| b.is_ascii_hexdigit()) {
            groups += 1;
        } else {
            return None;
        }
    }
    Some(groups)
}

/// Whether a text is a valid IPv4 address: four decimal octets, each at most
/// 255.
fn is_ipv4_address(t: &str) -> bool {
    let parts: Vec<&str> = t.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
        })
}

/// One package payload the install transaction will need, parsed from a
/// `dnf -C install --assumeno` transaction table.
#[derive(Debug)]
struct DnfInstallRow {
    name: String,
    /// version-release as displayed, with any leading `epoch:` stripped —
    /// rpm payload file names never carry the epoch.
    verrel: String,
    arch: String,
    repoid: String,
}

/// Recognized dnf transaction-table sections. Rows only ever appear under
/// one of these headers. A section outside this set is unknown structure and
/// fails closed rather than risk a mis-parsed or silently skipped payload
/// row (R2-03).
const DNF_TABLE_SECTIONS: &[&str] = &[
    "Installing:",
    "Installing dependencies:",
    "Installing weak dependencies:",
    "Reinstalling:",
    "Upgrading:",
    "Upgrading dependencies:",
    "Downgrading:",
    "Removing:",
    "Removing dependencies:",
    // Old versions cleaned up by an upgrade/downgrade; not counted in the
    // Transaction Summary verbs.
    "Cleanup:",
];

/// The Transaction Summary verb a table section's rows are counted by.
fn dnf_section_verb(section: &str) -> Option<&'static str> {
    match section {
        "Installing:" | "Installing dependencies:" | "Installing weak dependencies:" => {
            Some("Install")
        }
        "Reinstalling:" => Some("Reinstall"),
        "Upgrading:" | "Upgrading dependencies:" => Some("Upgrade"),
        "Downgrading:" => Some("Downgrade"),
        "Removing:" | "Removing dependencies:" => Some("Remove"),
        // Cleanup rows accompany an upgrade/downgrade and are not counted.
        "Cleanup:" => None,
        _ => None,
    }
}

fn is_divider(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c == '=')
}

/// A `replacing` sub-line dnf appends to a transaction row when the new
/// package obsoletes an installed one: `     replacing  <name>.<arch>
/// <evr>` (dnf 4 `output.py`: `'     ' + _('replacing') + '  %s%s.%s %s'`).
/// The named package is being removed by the transaction, not downloaded,
/// so the line is only recognized — its fields are never consumed — but it
/// must still have the exact native shape.
fn is_dnf_replacing_line(t: &str) -> bool {
    let Some(rest) = t.strip_prefix("replacing") else {
        return false;
    };
    let f: Vec<&str> = rest.split_whitespace().collect();
    if f.len() != 2 {
        return false;
    }
    // `<name>.<arch> <evr>`
    let Some((n, a)) = f[0].rsplit_once('.') else {
        return false;
    };
    valid_package_name(n)
        && valid_package_arch(a)
        && !f[1].is_empty()
        && f[1].bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-' | b':' | b'~')
        })
}

/// Parse one transaction-table row:
/// `<name> <arch> <ver-rel> <repoid> <size> [unit]`. Every field is a value
/// derived from dnf diagnostic output, so each is domain-validated before it
/// can reach a command or a path (R4-F05): the name must be a valid package
/// operand, the arch and version-release ones a payload file name can carry,
/// and the repository id one that can recognize a cache directory. The size
/// uses the same grammar as the summary's size lines (R4-F03), so a value
/// like `1..2` is not a size dnf prints.
fn parse_dnf_row(t: &str) -> Option<DnfInstallRow> {
    let f: Vec<&str> = t.split_whitespace().collect();
    if f.len() < 5 || f.len() > 6 {
        return None;
    }
    if !valid_package_name(f[0]) || !valid_package_arch(f[1]) {
        return None;
    }
    // rpm payload file names never carry the epoch the table may print, so the
    // epoch is stripped before the version-release is validated as a payload
    // file name component. A colon that is not a leading epoch is not a
    // version-release dnf prints and is rejected by the validation below.
    let verrel = match f[2].split_once(':') {
        Some((ep, rest)) if !ep.is_empty() && ep.chars().all(|c| c.is_ascii_digit()) => rest,
        _ => f[2],
    };
    if !valid_version_release(verrel) {
        return None;
    }
    if !valid_repo_id(f[3]) {
        return None;
    }
    // The size grammar dnf prints everywhere it prints a size, so a row and a
    // summary line can never disagree about what a size is.
    let size_ok = is_dnf_size_number(f[4]);
    let unit_ok = f.len() == 5 || is_dnf_size_unit(f[5]);
    if !size_ok || !unit_ok {
        return None;
    }
    Some(DnfInstallRow {
        name: f[0].to_string(),
        verrel: verrel.to_string(),
        arch: f[1].to_string(),
        repoid: f[3].to_string(),
    })
}

/// Parse a Transaction Summary count line: exactly `<Verb> <N> Package[s]`
/// (R4-A01, R4-F03). The verb must be one dnf prints, the count a canonical
/// plain decimal number — dnf formats it with `%d`, so a sign, a space, a
/// grouping separator or a leading zero (`01`) is not a count dnf prints —
/// and the noun must agree with the count — dnf prints the singular `Package`
/// only for a count of one. Any extra token is unrecognized structure and
/// fails closed.
fn parse_dnf_summary_line(t: &str) -> Option<(&'static str, usize)> {
    let f: Vec<&str> = t.split_whitespace().collect();
    if f.len() != 3 {
        return None;
    }
    let verb = match f[0] {
        "Install" => "Install",
        "Reinstall" => "Reinstall",
        "Upgrade" => "Upgrade",
        "Downgrade" => "Downgrade",
        "Remove" => "Remove",
        _ => return None,
    };
    // A canonical decimal number: digits only, and no leading zero unless the
    // count is exactly zero.
    if f[1].is_empty()
        || !f[1].bytes().all(|b| b.is_ascii_digit())
        || (f[1].len() > 1 && f[1].starts_with('0'))
    {
        return None;
    }
    let count = f[1].parse::<usize>().ok()?;
    // The noun must agree with the count: dnf prints `Package` only for one.
    let noun = if count == 1 { "Package" } else { "Packages" };
    if f[2] != noun {
        return None;
    }
    Some((verb, count))
}

/// A dnf size value: `<number> [<unit>]`, where the number is a plain decimal
/// (a single optional decimal point) and the unit one dnf prints.
fn is_dnf_size_value(t: &str) -> bool {
    let f: Vec<&str> = t.split_whitespace().collect();
    match f.len() {
        1 => is_dnf_size_number(f[0]),
        2 => is_dnf_size_number(f[0]) && is_dnf_size_unit(f[1]),
        _ => false,
    }
}

fn is_dnf_size_number(t: &str) -> bool {
    !t.is_empty()
        && t.matches('.').count() <= 1
        && t.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && t.bytes().any(|b| b.is_ascii_digit())
}

fn is_dnf_size_unit(t: &str) -> bool {
    matches!(
        t,
        "B" | "k"
            | "M"
            | "G"
            | "T"
            | "P"
            | "E"
            | "kB"
            | "MB"
            | "GB"
            | "TB"
            | "KiB"
            | "MiB"
            | "GiB"
            | "TiB"
    )
}

/// A line dnf prints after the Transaction Summary counts (R4-A01). Each is
/// matched against its exact grammar; a line that merely resembles one —
/// `Totally malformed` starting like `Total` — is unrecognized structure and
/// fails closed instead of being tolerated as a prefix.
fn is_known_trailing_line(t: &str) -> bool {
    // `Operation aborted.` is *not* a stdout line: the `--assumeno` abort is
    // a `CliError` dnf logs at ERROR → stderr (R5-F04). Its expected stream
    // is the command's stderr contract, not this table.
    for prefix in [
        "Total download size:",
        "Total size:",
        "Disk usage:",
        "Installed size:",
    ] {
        if let Some(rest) = t.strip_prefix(prefix) {
            return is_dnf_size_value(rest.trim());
        }
    }
    is_metadata_expiration_line(t)
}

/// A line dnf prints before the transaction table (R4-F03). Anything dnf
/// writes ahead of the column header is a preamble, and only the lines dnf
/// actually prints there are recognized: an error banner or a diagnostic
/// (e.g. `ERROR rpm database unavailable`) makes the whole table
/// uninterpretable, so it is not tolerated as ignored noise.
fn is_known_preamble_line(t: &str) -> bool {
    if t == "Dependencies resolved." {
        return true;
    }
    is_metadata_expiration_line(t)
}

/// The transaction-table column header dnf prints, matched as an exact
/// token sequence: a header that merely starts with `Package` and contains
/// the column words (`PackageEVIL Arch Version Repository Size`) is not the
/// header dnf prints (R4-F03). The arch and repository labels are
/// width-dependent in dnf 4 (`select_short_long` in `output.py`): a wide
/// table prints `Architecture`/`Repository`, a narrow one `Arch`/`Repo` —
/// both are native (R5-F04).
fn is_transaction_header(t: &str) -> bool {
    let f: Vec<&str> = t.split_whitespace().collect();
    f.len() == 5
        && f[0] == "Package"
        && (f[1] == "Arch" || f[1] == "Architecture")
        && f[2] == "Version"
        && (f[3] == "Repo" || f[3] == "Repository")
        && f[4] == "Size"
}

/// Parse a `dnf install --assumeno` transaction table into the exact
/// payload set (DESIGN §27). Fail closed (`None`) on anything that is not a
/// recognized, complete table — never a partial guess.
///
/// A complete answer is exactly one of:
///   - `Nothing to do.` as the sole content — dnf reports that no
///     transaction is needed, so the payload set is provably empty; or
///   - a full table: an optional preamble of lines dnf prints, a column
///     header (`Package Arch Version Repository Size`) with the exact token
///     sequence dnf uses, a `=` divider, one or more rows grouped
///     exclusively under recognized section headers, then a
///     `Transaction Summary` section with its own divider whose per-verb
///     package counts must equal the rows parsed for that verb. Format drift
///     fails closed.
fn parse_dnf_install_set(text: &str) -> Option<Vec<DnfInstallRow>> {
    let lines: Vec<&str> = text.lines().collect();
    // `Nothing to do.` is a complete answer only when it is the sole
    // content — anything else around it is unrecognized structure.
    let non_blank: Vec<&str> = lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    if non_blank.first() == Some(&"Nothing to do.") {
        if non_blank.len() == 1 {
            return Some(Vec::new());
        }
        return None;
    }
    // Everything before the column header is a preamble: only lines dnf
    // prints there may appear — a status line, a divider, or a metadata
    // expiration notice — so an unknown banner ahead of the table rejects it
    // instead of being skipped (R4-F03).
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim();
        if t.is_empty() || is_divider(t) || is_transaction_header(t) {
            if is_transaction_header(t) {
                break;
            }
            i += 1;
            continue;
        }
        if !is_known_preamble_line(t) {
            return None;
        }
        i += 1;
    }
    let header_idx = i;
    // The header must be terminated by a divider row.
    if !is_divider(lines.get(header_idx + 1)?.trim()) {
        return None;
    }
    let mut rows: Vec<(&'static str, DnfInstallRow)> = Vec::new();
    let mut counts: Vec<(&'static str, usize)> = Vec::new();
    let mut current_section: Option<&'static str> = None;
    let mut seen_summary = false;
    let mut summary_divider = false;
    let mut i = header_idx + 2;
    while i < lines.len() {
        let t = lines[i].trim();
        i += 1;
        if t.is_empty() {
            continue;
        }
        if !seen_summary {
            if t == "Transaction Summary" {
                seen_summary = true;
                continue;
            }
            if is_divider(t) {
                continue;
            }
            if let Some(section) = DNF_TABLE_SECTIONS.iter().copied().find(|s| *s == t) {
                current_section = Some(section);
                continue;
            }
            // `     replacing  <name>.<arch> <evr>` is appended under a row
            // when the transaction obsoletes an installed package
            // (`output.py` `_add_line` obsoletes). It names a package being
            // replaced — not a payload to fetch — so it is validated and
            // skipped, never pushed into the transaction rows.
            if is_dnf_replacing_line(t) {
                current_section?;
                continue;
            }
            // A payload row must sit under a recognized section header.
            let section = current_section?;
            let row = parse_dnf_row(t)?;
            rows.push((section, row));
        } else if !summary_divider {
            // The summary must be introduced by a divider.
            if !is_divider(t) {
                return None;
            }
            summary_divider = true;
        } else if let Some((verb, n)) = parse_dnf_summary_line(t) {
            // Each summary verb appears exactly once: a repeated verb is
            // malformed output, whatever the two counts say.
            if counts.iter().any(|(v, _)| *v == verb) {
                return None;
            }
            counts.push((verb, n));
        } else if is_divider(t) {
            continue;
        } else if is_known_trailing_line(t) {
            // A known line dnf prints after the counts, matched exactly.
            continue;
        } else {
            // Unrecognized trailing structure.
            return None;
        }
    }
    if !seen_summary || !summary_divider || counts.is_empty() || rows.is_empty() {
        // A summary with no rows is inconsistent: a real empty transaction
        // prints `Nothing to do.` instead (R2-03).
        return None;
    }
    // Cross-check the summary counts against the parsed rows, in both
    // directions (R2-03-B). Counting only what the summary happens to list
    // would let a body whose `Upgrading:` rows are missing from the summary
    // pass as a consistent transaction.
    let mut cleanup_rows = false;
    let mut body_counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for (section, _) in &rows {
        if *section == "Cleanup:" {
            cleanup_rows = true;
        }
        if let Some(verb) = dnf_section_verb(section) {
            *body_counts.entry(verb).or_insert(0) += 1;
        }
    }
    // Every summary line must agree with the rows counted for its verb.
    for (verb, count) in &counts {
        let matching = body_counts.get(verb).copied().unwrap_or(0);
        if matching != *count {
            return None;
        }
    }
    // And the summary must account for every counted action the body
    // performed: a verb with rows but no matching summary line is a
    // missing count, not a zero this parser may assume.
    for (verb, count) in &body_counts {
        if !counts.iter().any(|(v, c)| v == verb && c == count) {
            return None;
        }
    }
    // Cleanup rows are old versions removed during an upgrade/downgrade and
    // are not counted by a summary verb; they may only appear alongside one.
    if cleanup_rows
        && !body_counts.contains_key("Upgrade")
        && !body_counts.contains_key("Downgrade")
    {
        return None;
    }
    Some(rows.into_iter().map(|(_, r)| r).collect())
}

/// Non-interactive payload fetch tool used to place resolved payloads
/// into the snapshot package cache.
#[derive(Debug, Clone, Copy)]
enum DnfFetchTool {
    Curl,
    Wget,
}

impl DnfFetchTool {
    fn payload_args<'a>(&'a self, dest: &'a str, url: &'a str) -> Vec<&'a str> {
        match self {
            // -f: fail on HTTP errors; -sS: quiet but report errors;
            // -L: follow mirror redirects; -g: disable URL glob expansion so
            // one validated URL is exactly one intended request — a `[1-2]`
            // or `{a,b}` in a URL must never fan out into several requests
            // whose resource identity this tool did not validate (R4-F02).
            DnfFetchTool::Curl => vec!["-g", "-fsSL", "-o", dest, url],
            // wget has no URL glob expansion; the URL is a single operand.
            DnfFetchTool::Wget => vec!["-q", "-O", dest, url],
        }
    }
    fn path(&self) -> &'static str {
        match self {
            DnfFetchTool::Curl => "/usr/bin/curl",
            DnfFetchTool::Wget => "/usr/bin/wget",
        }
    }
}

impl std::fmt::Display for DnfFetchTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.path())
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

fn service_step_failure(
    res: &FrozenResource,
    e: SinterError,
    mutated: bool,
    sensitive: bool,
) -> ResourceResult {
    let mut r = changed_result_sensitive(res, sensitive || res.sensitive || res.derived_sensitive);
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
    // Strongest known mutation truth wins. A prior successful step must not be
    // weakened to Possible by a later Indeterminate error.
    r.change = if mutated || e.mutation == MutationState::Changed {
        Change::Changed
    } else if e.mutation == MutationState::Possible {
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
    r
}

fn post_mutation_failure(res: &FrozenResource, e: SinterError) -> ResourceResult {
    post_mutation_failure_sensitive(res, e, res.sensitive || res.derived_sensitive)
}

fn post_mutation_failure_sensitive(
    res: &FrozenResource,
    e: SinterError,
    sensitive: bool,
) -> ResourceResult {
    let mut r = changed_result_sensitive(res, sensitive);
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

    fn table(body: &str) -> String {
        table_summary(body, "Install  1 Package")
    }

    /// Build a transaction table with an explicit Transaction Summary line.
    fn table_summary(body: &str, summary: &str) -> String {
        format!(
            "Dependencies resolved.\n\
             ================================================================================\n \
             Package                Arch        Version                Repository      Size\n\
             ================================================================================\n\
             {}\
             Transaction Summary\n\
             ================================================================================\n\
             {}\n",
            body, summary
        )
    }

    #[test]
    fn dnf_install_set_parses_exact_rows() {
        let out = table_summary(
            "Installing:\n \
             httpd                  x86_64      2.4.62-13.el9_8.6      appstream       46 k\n\
             Installing dependencies:\n \
             apr                    x86_64      1.7.0-12.el9_3         appstream      122 k\n \
             mailcap                noarch      2.1.49-5.el9.0.2       baseos          32 k\n\n",
            "Install  3 Packages",
        );
        let rows = parse_dnf_install_set(&out).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].name, "httpd");
        assert_eq!(rows[0].arch, "x86_64");
        assert_eq!(rows[0].verrel, "2.4.62-13.el9_8.6");
        assert_eq!(rows[0].repoid, "appstream");
        assert_eq!(rows[2].repoid, "baseos");
    }

    #[test]
    fn dnf_install_set_strips_epoch_for_basename() {
        // rpm payload file names never carry the epoch; the table shows it.
        let out = table_summary(
            "Installing:\n \
             coreutils              x86_64      1:8.32-38.el9          baseos         1.1 M\n",
            "Install  1 Package",
        );
        let rows = parse_dnf_install_set(&out).unwrap();
        assert_eq!(rows[0].verrel, "8.32-38.el9");
    }

    #[test]
    fn dnf_install_set_nothing_to_do_is_an_empty_set() {
        // `Nothing to do.` is a complete, unambiguous answer: the payload set
        // is provably empty (R2-03: code, comment, and test agree).
        let rows = parse_dnf_install_set("Nothing to do.\n").unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn dnf_install_set_rejects_malformed_and_incomplete() {
        // No transaction summary at all — truncated output must not parse.
        assert!(parse_dnf_install_set("Installing:\n httpd x86_64 1-1 appstream 1 k\n").is_none());
        // A non-row line inside the table fails closed.
        assert!(parse_dnf_install_set(&table("Installing:\n garbage line here\n")).is_none());
        // A row with a non-numeric size fails closed.
        assert!(parse_dnf_install_set(&table_summary(
            "Installing:\n httpd x86_64 1-1 appstream huge\n",
            "Install  1 Package"
        ))
        .is_none());
        // A table header with a Transaction Summary but no package rows is
        // inconsistent — a real empty transaction prints "Nothing to do."
        assert!(parse_dnf_install_set(&table_summary("", "Install  0 Packages")).is_none());
        // A header that is not followed by a divider fails closed.
        assert!(parse_dnf_install_set(
            "Package Arch Version Repository Size\nhttpd x86_64 1-1 appstream 1 k\n"
        )
        .is_none());
        // An unknown transaction section is unrecognized structure.
        assert!(
            parse_dnf_install_set(&table("Bogus:\n httpd x86_64 1-1 appstream 1 k\n")).is_none()
        );
        // A row outside any section header fails closed.
        assert!(parse_dnf_install_set(&table_summary(
            "httpd x86_64 1-1 appstream 1 k\n",
            "Install  1 Package"
        ))
        .is_none());
        // `Nothing to do.` buried in other output is not a sole answer.
        assert!(parse_dnf_install_set("Nothing to do.\nextra noise\n").is_none());
        // Transaction Summary counts must match the parsed rows.
        assert!(parse_dnf_install_set(&table_summary(
            "Installing:\n httpd x86_64 1-1 appstream 1 k\n",
            "Install  2 Packages"
        ))
        .is_none());
        // A Transaction Summary without its divider fails closed.
        assert!(
            parse_dnf_install_set(
                "Dependencies resolved.\n\
                 ================================================================================\n \
                 Package                Arch        Version                Repository      Size\n\
                 ================================================================================\n\
                 Installing:\n \
                 httpd                  x86_64      1-1                    appstream       1 k\n\
                 Transaction Summary\n\
                 Install  1 Package\n"
            )
            .is_none()
        );
    }

    #[test]
    fn dnf_enabled_repos_parses_strictly() {
        let text = "Repo-id            : baseos\nRepo-name          : BaseOS\nRepo-status        : enabled\nRepo-mirrors       : https://mirrors.example/?repo=baseos\n\nRepo-id            : appstream\nRepo-name          : AppStream\nRepo-status        : enabled\n\n";
        let repos = parse_dnf_enabled_repos(text).unwrap();
        assert_eq!(repos.len(), 2);
        assert_eq!(repos[0], ("baseos".to_string(), true));
        assert_eq!(repos[1], ("appstream".to_string(), false));
    }

    #[test]
    fn dnf_enabled_repos_rejects_malformed_fields() {
        // A Repo-id prefix match with a malformed separator (R2-03
        // reproduction) must not be accepted as a repository id.
        assert!(parse_dnf_enabled_repos("Repo-idNOT_A_FIELD: baseos\n").is_none());
        // An empty value is not a repository id.
        assert!(parse_dnf_enabled_repos("Repo-id            : \n").is_none());
        // A Repo- field with no separator is unrecognized structure.
        assert!(parse_dnf_enabled_repos("Repo-namegarbage\n").is_none());
        // A non-Repo- line is unrecognized structure.
        assert!(parse_dnf_enabled_repos("Repo-id : baseos\nsome other line\n").is_none());
        // A mirror field with no enclosing block is malformed.
        assert!(parse_dnf_enabled_repos("Repo-mirrors : https://x\n").is_none());
        // No repos at all cannot establish completeness.
        assert!(parse_dnf_enabled_repos("").is_none());
    }

    #[test]
    fn dnf_enabled_repos_rejects_incomplete_blocks() {
        // R2-03-A: seeing a repo id alone proves nothing about the repository
        // — the block must be a complete record dnf prints, which always
        // shows the repository name as well.
        assert!(parse_dnf_enabled_repos("Repo-id            : baseos\n").is_none());
        // A block whose name line is missing at the blank separator.
        assert!(parse_dnf_enabled_repos(
            "Repo-id            : baseos\n\nRepo-name          : BaseOS\n"
        )
        .is_none());
        // A name field with no enclosing block is an orphan (R4-F03).
        assert!(parse_dnf_enabled_repos("Repo-name          : BaseOS\n").is_none());
        // A status that is not `enabled` contradicts `repolist` semantics.
        assert!(parse_dnf_enabled_repos(
            "Repo-id            : baseos\nRepo-name          : BaseOS\nRepo-status        : disabled\n"
        )
        .is_none());
        // A status field with no enclosing block is malformed.
        assert!(parse_dnf_enabled_repos("Repo-status        : enabled\n").is_none());
        // A complete single block parses — `Repo-status` is optional in
        // native `repolist -v` output (R4-F04).
        let repos = parse_dnf_enabled_repos(
            "Repo-id            : baseos\nRepo-name          : BaseOS\nRepo-status        : enabled\n",
        )
        .unwrap();
        assert_eq!(repos, vec![("baseos".to_string(), false)]);
        // The native upstream shape — no `Repo-status`, other dnf fields, and
        // the `Total packages:` footer — is accepted (R4-F04).
        assert!(parse_dnf_enabled_repos(
            "Repo-id            : baseos\nRepo-name          : Rocky Linux 9 - BaseOS\nRepo-baseurl       : https://mirror.example/baseos\nRepo-expire        : Never (last: unknown)\nRepo-filename      : /etc/yum.repos.d/rocky.repo\nTotal packages: 0\n"
        )
        .is_some());
    }

    #[test]
    fn dnf_install_set_summary_must_account_for_the_body() {
        // R2-03-B: the body performs an Upgrade the summary never reports;
        // reading only the summary lines would miss it.
        assert!(parse_dnf_install_set(&table_summary(
            "Installing:\n httpd x86_64 1-1 appstream 1 k\nUpgrading:\n foo x86_64 2-1 appstream 1 k\n",
            "Install  1 Package"
        ))
        .is_none());
        // A summary verb with no body rows is inconsistent in the other
        // direction as well.
        assert!(parse_dnf_install_set(&table_summary(
            "Installing:\n httpd x86_64 1-1 appstream 1 k\n",
            "Install  1 Package\nUpgrade  1 Package"
        ))
        .is_none());
        // A consistent multi-action table parses, and every section under a
        // shared verb is counted together.
        let rows = parse_dnf_install_set(&table_summary(
            "Installing:\n httpd x86_64 1-1 appstream 1 k\nInstalling dependencies:\n apr x86_64 1-1 appstream 1 k\nUpgrading:\n foo x86_64 2-1 appstream 1 k\n",
            "Install  2 Packages\nUpgrade  1 Package"
        ))
        .unwrap();
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn payload_location_must_be_a_fetchable_url() {
        // R2-03-C: basename agreement is not enough — the value must be an
        // absolute http(s) URL the downloader can actually fetch.
        assert!(validate_payload_url("not-a-url/nano-1.0-1.el9.x86_64.rpm").is_err());
        assert!(validate_payload_url("/local/path/nano-1.0-1.el9.x86_64.rpm").is_err());
        assert!(validate_payload_url("file:///nano-1.0-1.el9.x86_64.rpm").is_err());
        // A host-less absolute URL (`https:///path` names no host).
        assert!(validate_payload_url("https:///nano-1.0-1.el9.x86_64.rpm").is_err());
        // A URL with no path after the host.
        assert!(validate_payload_url("https://mirror.example").is_err());
        assert!(validate_payload_url("https://mirror /x.rpm").is_err());
        assert!(validate_payload_url("").is_err());
        assert!(validate_payload_url("HTTPS://mirror.example/x.rpm").is_err());
        // A well-formed absolute URL is accepted — a single-label host is a
        // legitimate LAN mirror name.
        assert!(validate_payload_url(
            "https://mirror.example/baseos/Packages/nano-1.0-1.el9.x86_64.rpm"
        )
        .is_ok());
        assert!(validate_payload_url("http://mirror.example/x.rpm").is_ok());
        assert!(validate_payload_url("https://lan-mirror/x.rpm").is_ok());
    }

    /// R4-F02: the validated string and the resource the downloader fetches
    /// must be the same thing. Query and fragment separators, URL glob
    /// syntax, and percent-encoding all make the resource identity ambiguous
    /// or multipart, so Phase 1 rejects them outright.
    #[test]
    fn payload_url_resource_identity_is_unambiguous() {
        // A fragment changes nothing about what is fetched, but it is not a
        // resource this tool can prove it requested.
        assert!(validate_payload_url(
            "https://mirror.example/repodata/repomd.xml#/nano-1.0-1.el9.x86_64.rpm"
        )
        .is_err());
        // A query likewise — and one whose value re-parses as a path.
        assert!(validate_payload_url(
            "https://mirror.example/not-rpm?download=/nano-1.0-1.el9.x86_64.rpm"
        )
        .is_err());
        // curl URL glob syntax: `[1-2]` would fan out into two requests.
        assert!(validate_payload_url("https://mirror.example/[1-2]/nano.rpm").is_err());
        assert!(validate_payload_url("https://mirror.example/{a,b}/nano.rpm").is_err());
        // Malformed percent encoding is never a location.
        assert!(validate_payload_url("https://mirror.example/%/nano.rpm").is_err());
        assert!(validate_payload_url("https://mirror.example/%A/nano.rpm").is_err());
        assert!(validate_payload_url("https://mirror.example/%GG/nano.rpm").is_err());
        // Any percent encoding at all is rejected in Phase 1: an encoded slash
        // or dot would make the resource identity depend on interpretation.
        assert!(validate_payload_url("https://mirror.example/a%2fb/nano.rpm").is_err());
        assert!(validate_payload_url("https://mirror.example/a%2eb/nano.rpm").is_err());
        assert!(validate_payload_url("https://mirror.example/%2e/nano.rpm").is_err());
        assert!(validate_payload_url("https://m/%41/nano.rpm").is_err());
        // A path that does not name an RPM payload.
        assert!(validate_payload_url("https://mirror.example/baseos/Packages/").is_err());
        assert!(validate_payload_url("https://mirror.example/baseos/Packages/notrpm").is_err());
        assert!(validate_payload_url("https://mirror.example/baseos/Packages/.rpm").is_err());
        // Dot-segments are not a normalized path.
        assert!(validate_payload_url("https://mirror.example/./x.rpm").is_err());
        assert!(validate_payload_url("https://mirror.example/../x.rpm").is_err());
        // A doubled separator is native `repoquery --location` output — the
        // mirror baseurl ends in `/` and the package path joins with another
        // (the real Rocky 9 mirror serves `.../pub/rocky//9.8/...`, R5-F04).
        // It is requested byte-for-byte and the basename still pins the
        // payload identity.
        assert!(validate_payload_url("https://mirror.example//x.rpm").is_ok());
        assert!(validate_payload_url(
            "https://mirror.example/pub/rocky//9.8/BaseOS/x86_64/os/Packages/n/nano-5.6.1-7.el9.x86_64.rpm"
        )
        .is_ok());
        // A URL that would be an option to the downloader.
        assert!(validate_payload_url("-g/x.rpm").is_err());
        // Positive: the shapes real mirrors use, including an explicit port,
        // an IPv4 literal and an IPv6 literal.
        assert!(validate_payload_url(
            "https://mirror.example:8443/baseos/Packages/nano-1.0-1.el9.x86_64.rpm"
        )
        .is_ok());
        assert!(
            validate_payload_url("http://192.0.2.1/baseos/Packages/nano-1.0-1.el9.x86_64.rpm")
                .is_ok()
        );
        assert!(validate_payload_url(
            "https://[2001:db8::1]/baseos/Packages/nano-1.0-1.el9.x86_64.rpm"
        )
        .is_ok());
        assert!(validate_payload_url(
            "https://[2001:db8::1]:8080/baseos/Packages/nano-1.0-1.el9.x86_64.rpm"
        )
        .is_ok());
        // A package name with a `+` needs no encoding.
        assert!(validate_payload_url(
            "https://mirror.example/baseos/Packages/libstdc++-11.2.1-1.el9.x86_64.rpm"
        )
        .is_ok());
    }

    /// R4-F01: the `find -print0` answer is raw bytes whose framing and path
    /// domain must be proven before any entry reaches a copy argv.
    #[test]
    fn cache_children_framing_and_domain() {
        // The native answer: one NUL-terminated entry per direct child.
        let ok = format!(
            "{}\0{}\0",
            "/var/cache/dnf/baseos-cafebabecafebabe", "/var/cache/dnf/appstream-deadbeefdeadbeef"
        );
        let children = parse_cache_children(ok.as_bytes()).expect("native listing parses");
        assert_eq!(
            children,
            vec![
                "/var/cache/dnf/baseos-cafebabecafebabe",
                "/var/cache/dnf/appstream-deadbeefdeadbeef"
            ]
        );
        // An empty cache root yields no children.
        assert!(parse_cache_children(b"").unwrap().is_empty());
        // Legal but unusual child names stay discrete entries.
        let odd = [
            "/var/cache/dnf/.hidden",
            "/var/cache/dnf/name with spaces",
            "/var/cache/dnf/name\nwith newline",
            "/var/cache/dnf/-leading-dash",
            "/var/cache/dnf/underscore_child",
        ]
        .join("\0")
            + "\0";
        let odd_children = parse_cache_children(odd.as_bytes()).expect("odd names parse");
        assert_eq!(odd_children.len(), 5);
        // Missing trailing NUL is truncated framing.
        assert!(parse_cache_children(b"/var/cache/dnf/baseos-abcdef0123456789").is_err());
        // An empty (doubled-NUL) entry.
        assert!(parse_cache_children(b"/var/cache/dnf/a\0\0/var/cache/dnf/b\0").is_err());
        // A duplicate entry.
        let dup = "/var/cache/dnf/a\0/var/cache/dnf/a\0";
        assert!(parse_cache_children(dup.as_bytes()).is_err());
        // Invalid UTF-8 must not be lossily re-encoded into another path.
        let bad_utf8 = b"/var/cache/dnf/\xff\0";
        assert!(parse_cache_children(bad_utf8).is_err());
        // Entries outside the cache root or not a direct child.
        assert!(parse_cache_children(b"/etc/passwd\0").is_err());
        assert!(parse_cache_children(b"../../etc\0").is_err());
        assert!(parse_cache_children(b"/var/cache/dnf/../../etc\0").is_err());
        assert!(parse_cache_children(b"/var/cache/dnf/.\0").is_err());
        assert!(parse_cache_children(b"/var/cache/dnf/..\0").is_err());
        assert!(parse_cache_children(b"/var/cache/dnf\0").is_err());
        assert!(parse_cache_children(b"/var/cache/dnf/sub/nested\0").is_err());
        // A sibling root that merely shares the prefix.
        assert!(parse_cache_children(b"/var/cache/dnf-evil/x\0").is_err());
    }

    /// R4-F01: the snapshot helper's path is validated before any operation
    /// targets it, and an unverified value is never a cleanup target.
    #[test]
    fn snapshot_path_namespace_is_validated() {
        // The value mktemp prints for the requested template.
        assert_eq!(
            validate_snapshot_path(b"/var/tmp/sinter-dnf.fakesnap\n").unwrap(),
            "/var/tmp/sinter-dnf.fakesnap"
        );
        assert_eq!(
            validate_snapshot_path(b"/var/tmp/sinter-dnf.Ab3xK9pQ").unwrap(),
            "/var/tmp/sinter-dnf.Ab3xK9pQ"
        );
        // Outside the private namespace.
        assert!(validate_snapshot_path(b"/tmp/outside\n").is_err());
        assert!(validate_snapshot_path(b"../outside\n").is_err());
        assert!(validate_snapshot_path(b"/\n").is_err());
        assert!(validate_snapshot_path(b".\n").is_err());
        assert!(validate_snapshot_path(b"..\n").is_err());
        assert!(validate_snapshot_path(b"/var/tmp/sinter-dnf.\n").is_err());
        // A suffix of the wrong shape.
        assert!(validate_snapshot_path(b"/var/tmp/sinter-dnf.short\n").is_err());
        assert!(validate_snapshot_path(b"/var/tmp/sinter-dnf.too-long\n").is_err());
        assert!(validate_snapshot_path(b"/var/tmp/sinter-dnf.dots-..\n").is_err());
        assert!(validate_snapshot_path(b"/var/tmp/sinter-dnf.with/slash\n").is_err());
        assert!(validate_snapshot_path(b"/var/tmp/other.fakesnap\n").is_err());
        // Extra output, malformed bytes, truncation of the value itself.
        assert!(validate_snapshot_path(b"/var/tmp/sinter-dnf.fakesnap\nextra\n").is_err());
        assert!(validate_snapshot_path(b"\0").is_err());
        assert!(validate_snapshot_path(b"\xff\n").is_err());
        assert!(validate_snapshot_path(b"").is_err());
    }

    /// R4-F05: a transaction-derived identifier is domain-validated before it
    /// can reach a command or a path.
    #[test]
    fn transaction_identifiers_are_domain_validated() {
        // Package names: real names pass, option-like and path-like fail.
        assert!(valid_package_name("nano"));
        assert!(valid_package_name("python3-pip"));
        assert!(valid_package_name("libstdc++"));
        assert!(valid_package_name("perl-Foo.Bar"));
        assert!(!valid_package_name("--refresh"));
        assert!(!valid_package_name("-x"));
        assert!(!valid_package_name("../x"));
        assert!(!valid_package_name("a/b"));
        assert!(!valid_package_name("a\nb"));
        assert!(!valid_package_name(""));
        // Architectures.
        assert!(valid_package_arch("x86_64"));
        assert!(valid_package_arch("noarch"));
        assert!(valid_package_arch("aarch64"));
        assert!(!valid_package_arch("x86_64.rpm"));
        assert!(!valid_package_arch("-x"));
        // Version-release, including an epoch-stripped value.
        assert!(valid_version_release("1.0-1.el9"));
        assert!(valid_version_release("2.4.62-13.el9_8.6"));
        assert!(!valid_version_release("-1.el9"));
        assert!(!valid_version_release("a/b"));
        // Repository ids: the libdnf REPOID_CHARS domain, minus the dot
        // entries, so a repo id is always a safe path component.
        assert!(valid_repo_id("baseos"));
        assert!(valid_repo_id("appstream"));
        assert!(valid_repo_id("my-repo"));
        assert!(valid_repo_id("my_repo"));
        assert!(valid_repo_id("my.repo"));
        assert!(!valid_repo_id("../escape"));
        assert!(!valid_repo_id("."));
        assert!(!valid_repo_id(".."));
        assert!(!valid_repo_id("/absolute"));
        assert!(!valid_repo_id("a/b"));
        assert!(!valid_repo_id("a\\b"));
        assert!(!valid_repo_id("a\nb"));
        assert!(!valid_repo_id(""));
    }

    /// R4-F05: the cache directory hash is the exact native libdnf format —
    /// the first eight bytes of a SHA-256 digest as sixteen hex characters.
    #[test]
    fn cache_dir_hash_is_the_native_format() {
        assert!(is_repo_cache_dir("baseos", "baseos-cafebabecafebabe"));
        assert!(is_repo_cache_dir(
            "baseos-extra",
            "baseos-extra-abcdef0123456789"
        ));
        // A repo id that itself contains '-' still resolves by identity.
        assert!(is_repo_cache_dir("my-repo", "my-repo-0123456789abcdef"));
        // A directory that proves a different repository.
        assert!(!is_repo_cache_dir(
            "baseos",
            "baseos-extra-abcdef0123456789"
        ));
        // A hash of the wrong length or shape proves nothing.
        assert!(!is_repo_cache_dir("baseos", "baseos-cafebabef00d"));
        assert!(!is_repo_cache_dir("baseos", "baseos-cafebabecafebabe00"));
        assert!(!is_repo_cache_dir("baseos", "baseos-xyzzyxyzzyxyzzy"));
        assert!(!is_repo_cache_dir("baseos", "baseos-"));
        assert!(!is_repo_cache_dir("baseos", "baseos"));
        assert!(!is_repo_cache_dir("baseos", "-cafebabecafebabe"));
    }

    /// R4-F04: the native `Total packages:` footer is matched exactly.
    #[test]
    fn repolist_footer_grammar_is_exact() {
        assert_eq!(parse_repolist_footer("Total packages: 0"), Some(0));
        assert_eq!(parse_repolist_footer("Total packages: 1"), Some(1));
        assert_eq!(parse_repolist_footer("Total packages: 1234"), Some(1234));
        assert!(parse_repolist_footer("Total packages: 01").is_none());
        assert!(parse_repolist_footer("Total packages: -1").is_none());
        assert!(parse_repolist_footer("Total packages: 1,234").is_none());
        assert!(parse_repolist_footer("Total packages: abc").is_none());
        assert!(parse_repolist_footer("Total packages:").is_none());
        assert!(parse_repolist_footer("Total packages: 1 extra").is_none());
        assert!(parse_repolist_footer("Totally packages: 1").is_none());
        assert!(parse_repolist_footer("Total packages 1").is_none());
    }

    /// R4-F03: a transaction-table header is the exact token sequence dnf
    /// prints, and a preamble only carries lines dnf prints.
    #[test]
    fn transaction_header_and_preamble_are_exact() {
        assert!(is_transaction_header(
            " Package                Arch        Version                Repository      Size"
        ));
        assert!(is_transaction_header(
            "Package Arch Version Repository Size"
        ));
        // The wide layout native dnf prints when the columns allow the long
        // labels (real Rocky 9.8 capture, R5-F04).
        assert!(is_transaction_header(
            " Package        Architecture     Version                 Repository        Size"
        ));
        // A header whose first token merely starts with `Package`.
        assert!(!is_transaction_header(
            "PackageEVIL Arch Version Repository Size"
        ));
        assert!(!is_transaction_header(
            "Package Arch Version Repository Size Extra"
        ));
        assert!(!is_transaction_header("Package Arch Version Repository"));
        assert!(is_known_preamble_line("Dependencies resolved."));
        assert!(is_known_preamble_line(
            "Last metadata expiration check: 0:12:34 ago on Tue Sep 16 04:00:00 2026."
        ));
        // An error banner is not a preamble dnf prints before the table.
        assert!(!is_known_preamble_line("ERROR rpm database unavailable"));
        assert!(!is_known_preamble_line("some other noise"));
    }

    /// R5-F04: the `Last metadata expiration check:` line is matched by the
    /// exact grammar dnf renders under the C locale — `timedelta ago on
    /// strftime("%c")` plus the message's trailing dot. Anything merely
    /// resembling it is not the native line.
    #[test]
    fn metadata_expiration_line_grammar_is_exact() {
        // The real Rocky 9.8 / dnf 4.14.0 capture.
        assert!(is_metadata_expiration_line(
            "Last metadata expiration check: 1:35:13 ago on Wed Sep 16 10:28:01 2026."
        ));
        // A space-padded day (%e) and a day-count timedelta are native too.
        assert!(is_metadata_expiration_line(
            "Last metadata expiration check: 2 days, 3:04:05 ago on Tue Sep  1 05:55:47 2026."
        ));
        // The line alone, or with a different tail, is not the message.
        assert!(!is_metadata_expiration_line(
            "Last metadata expiration check:"
        ));
        assert!(!is_metadata_expiration_line(
            "Last metadata expiration check: 0:30:00 ago"
        ));
        assert!(!is_metadata_expiration_line(
            "Last metadata expiration check: soon ago on Wed Sep 16 10:28:01 2026."
        ));
        assert!(!is_metadata_expiration_line(
            "Last metadata expiration check: 0:30:00 ago on yesterday."
        ));
        // A malformed clock is not a %c date.
        assert!(!is_metadata_expiration_line(
            "Last metadata expiration check: 0:30:00 ago on Wed Sep 16 25:28:01 2026."
        ));
        // Missing trailing dot — not the message dnf prints.
        assert!(!is_metadata_expiration_line(
            "Last metadata expiration check: 0:30:00 ago on Wed Sep 16 10:28:01 2026"
        ));
        // Trailing content after the native line.
        assert!(!is_metadata_expiration_line(
            "Last metadata expiration check: 0:30:00 ago on Wed Sep 16 10:28:01 2026. extra"
        ));
    }

    /// R5-F04: the `repolist -v` preamble accepts exactly the three lines
    /// native dnf prints before the first block, each by its own grammar.
    #[test]
    fn repolist_preamble_grammar_is_exact() {
        // The real Rocky 9.8 capture.
        assert_eq!(
            repolist_preamble_line(
                "Loaded plugins: builddep, changelog, config-manager, copr, debug, \
                 debuginfo-install, download, generate_completion_cache, groups-manager, \
                 needs-restarting, playground, repoclosure, repodiff, repograph, \
                 repomanage, reposync, system-upgrade"
            ),
            Some("Loaded plugins")
        );
        assert_eq!(
            repolist_preamble_line("DNF version: 4.14.0"),
            Some("DNF version")
        );
        assert_eq!(
            repolist_preamble_line("cachedir: /var/cache/dnf"),
            Some("cachedir")
        );
        // Malformed or unknown preambles are not native lines.
        assert_eq!(repolist_preamble_line("Loaded plugins:"), None);
        assert_eq!(repolist_preamble_line("DNF version:"), None);
        assert_eq!(repolist_preamble_line("DNF version: 4.x"), None);
        assert_eq!(repolist_preamble_line("cachedir: relative/path"), None);
        assert_eq!(repolist_preamble_line("Banner: hello"), None);
        assert_eq!(repolist_preamble_line("Loaded pluginz: x"), None);
    }

    /// R4-F03: the repolist block lifecycle — a blank closes a block, so a
    /// field after it is an orphan, and an unknown `Repo-*` is not tolerated.
    #[test]
    fn repolist_block_boundary_is_explicit() {
        // Native upstream output without Repo-status and with the footer.
        assert!(parse_dnf_enabled_repos(
            "Repo-id            : baseos\nRepo-name          : Rocky Linux 9 - BaseOS\nRepo-baseurl       : https://mirror.example/baseos\nRepo-expire        : Never (last: unknown)\nRepo-filename      : /etc/yum.repos.d/rocky.repo\nTotal packages: 0\n"
        )
        .is_some());
        // Multiple repos, native style: blank-separated blocks with a single
        // footer dnf prints after the last one.
        assert!(parse_dnf_enabled_repos(
            "Repo-id            : baseos\nRepo-name          : BaseOS\nRepo-mirrors       : https://m/?repo=baseos\n\nRepo-id            : appstream\nRepo-name          : AppStream\nRepo-mirrors       : https://m/?repo=appstream\nTotal packages: 1\n"
        )
        .is_some());
        // An orphan status field after a closed block (R4-F03 reproduction).
        assert!(parse_dnf_enabled_repos(
            "Repo-id            : baseos\nRepo-name          : BaseOS\n\nRepo-status        : enabled\n"
        )
        .is_none());
        // An arbitrary Repo- field is not structure dnf prints.
        assert!(parse_dnf_enabled_repos(
            "Repo-id            : baseos\nRepo-name          : BaseOS\nRepo-nonsense      : x\n"
        )
        .is_none());
        // Garbage after the footer.
        assert!(parse_dnf_enabled_repos(
            "Repo-id            : baseos\nRepo-name          : BaseOS\nTotal packages: 0\ngarbage\n"
        )
        .is_none());
        // A malformed footer.
        assert!(parse_dnf_enabled_repos(
            "Repo-id            : baseos\nRepo-name          : BaseOS\nTotal packages: none\n"
        )
        .is_none());
        // A footer with no repository block at all.
        assert!(parse_dnf_enabled_repos("Total packages: 0\n").is_none());
    }

    /// Rocky Linux 10 ships dnf 4.20.0 and rpm 4.19. Native `repolist -v`
    /// output (captured on a real Rocky 10.2 target under Sinter's pinned
    /// C.UTF-8 locale) uses the same field grammar as dnf 4.14, with two
    /// newer fields this parser already knows: `Repo-distro-tags` and
    /// `Repo-available-pkgs`. A mirror-resolving repo carries `Repo-mirrors`
    /// and a `Repo-baseurl` whose value ends in `(32 more)` (the mirror list
    /// has more than one entry) and contains a doubled separator — native
    /// upstream output, not a defect.
    const ROCKY10_REPOLIST: &str = "\
Loaded plugins: builddep, changelog, config-manager, copr, debuginfo-install, download, generate_completion_cache, groups-manager, needs-restarting, playground, repoclosure, repodiff, repograph, repomanage, reposync, system-upgrade\n\
DNF version: 4.20.0\n\
cachedir: /var/cache/dnf\n\
Repo-id            : appstream\n\
Repo-name          : Rocky Linux 10 - AppStream\n\
Repo-revision      : 10.2\n\
Repo-distro-tags      : [cpe:/o:rocky:rocky:10.2]:  ,  , ., 0, 1, 2, L, R, c, i, k, n, o, u, x, y\n\
Repo-updated       : Thu Sep 17 07:46:26 2026\n\
Repo-pkgs          : 6773\n\
Repo-available-pkgs: 6773\n\
Repo-size          : 19 G\n\
Repo-mirrors       : https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=AppStream-10\n\
Repo-baseurl       : https://rocky-linux-asia-northeast1.production.gcp.mirrors.ctrliq.cloud/pub/rocky//10.2/AppStream/x86_64/os/ (32 more)\n\
Repo-expire        : 21600 second(s) (last: Thu Sep 17 20:41:17 2026)\n\
Repo-filename      : /etc/yum.repos.d/rocky.repo\n\
\n\
Repo-id            : baseos\n\
Repo-name          : Rocky Linux 10 - BaseOS\n\
Repo-revision      : 10.2\n\
Repo-distro-tags      : [cpe:/o:rocky:rocky:10.2]:  ,  , ., 0, 1, 2, L, R, c, i, k, n, o, u, x, y\n\
Repo-updated       : Thu Sep 17 07:49:34 2026\n\
Repo-pkgs          : 2311\n\
Repo-available-pkgs: 2311\n\
Repo-size          : 13 G\n\
Repo-mirrors       : https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=BaseOS-10\n\
Repo-baseurl       : https://rocky-linux-asia-northeast1.production.gcp.mirrors.ctrliq.cloud/pub/rocky//10.2/BaseOS/x86_64/os/ (32 more)\n\
Repo-expire        : 21600 second(s) (last: Thu Sep 17 20:41:17 2026)\n\
Repo-filename      : /etc/yum.repos.d/rocky.repo\n\
\n\
Repo-id            : extras\n\
Repo-name          : Rocky Linux 10 - Extras\n\
Repo-revision      : 10.2\n\
Repo-updated       : Tue Sep  1 07:41:40 2026\n\
Repo-pkgs          : 23\n\
Repo-available-pkgs: 23\n\
Repo-size          : 66 M\n\
Repo-mirrors       : https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=extras-10\n\
Repo-baseurl       : https://rocky-linux-asia-northeast1.production.gcp.mirrors.ctrliq.cloud/pub/rocky//10.2/extras/x86_64/os/ (32 more)\n\
Repo-expire        : 21600 second(s) (last: Thu Sep 17 20:41:18 2026)\n\
Repo-filename      : /etc/yum.repos.d/rocky-extras.repo\n\
Total packages: 9107\n";

    #[test]
    fn rocky10_dnf420_repolist_parses_with_mirror_flags() {
        let repos = parse_dnf_enabled_repos(ROCKY10_REPOLIST)
            .expect("real Rocky 10 / dnf 4.20.0 repolist -v output must parse");
        assert_eq!(
            repos,
            vec![
                ("appstream".to_string(), true),
                ("baseos".to_string(), true),
                ("extras".to_string(), true),
            ]
        );
    }

    #[test]
    fn rocky10_dnf420_repolist_footer_is_ungrouped_under_pinned_locale() {
        // dnf 4.20 groups the footer count with a comma in some locales
        // (`Total packages: 10,900`), but Sinter pins LANG/LC_ALL to C.UTF-8
        // for every dnf command, where it prints a plain decimal. The strict
        // grammar therefore accepts the real pinned-locale form and rejects
        // any grouped variant without loosening: a count this parser cannot
        // prove decimal cannot prove the repository set is complete.
        assert!(parse_repolist_footer("Total packages: 9107").is_some());
        assert!(parse_repolist_footer("Total packages: 10,900").is_none());
        // The full Rocky 10 stream with a grouped footer is rejected whole.
        let grouped = ROCKY10_REPOLIST.replace("Total packages: 9107", "Total packages: 9,107");
        assert!(parse_dnf_enabled_repos(&grouped).is_none());
    }

    #[test]
    fn rocky10_dnf420_install_table_parses() {
        // Real cache-only `dnf install --assumeno tree` on Rocky 10.2: the
        // INFO metadata-age line lands on stdout (dnf 4.20 routes it there
        // for install), `Operation aborted.` alone on stderr, exit 1 — the
        // exact contract the stderr allowlist models for dnf 4.14.
        let out = "Last metadata expiration check: 0:44:34 ago on Thu Sep 17 20:41:18 2026.\n\
Dependencies resolved.\n\
================================================================================\n\
 Package        Architecture     Version                 Repository        Size\n\
================================================================================\n\
Installing:\n\
 tree           x86_64           2.1.0-8.el10            baseos            56 k\n\
\n\
Transaction Summary\n\
================================================================================\n\
Install  1 Package\n\
\n\
Total download size: 56 k\n\
Installed size: 108 k\n";
        let rows = parse_dnf_install_set(out).expect("real Rocky 10 transaction table must parse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "tree");
        assert_eq!(rows[0].verrel, "2.1.0-8.el10");
        assert_eq!(rows[0].arch, "x86_64");
        assert_eq!(rows[0].repoid, "baseos");
    }

    #[test]
    fn rocky10_payload_location_doubled_separator_is_native() {
        // Real `repoquery --location tree` on Rocky 10.2: the resolved
        // mirror baseurl ends in `/`, so the joined path carries `//` —
        // native output (already covered for Rocky 9 by R5-F04), and the
        // el10 payload name validates.
        let url = "https://rocky-linux-asia-northeast1.production.gcp.mirrors.ctrliq.cloud/pub/rocky//10.2/BaseOS/x86_64/os/Packages/t/tree-2.1.0-8.el10.x86_64.rpm";
        assert!(validate_payload_url(url).is_ok());
    }

    #[test]
    fn rocky10_metadata_expiration_line_is_native() {
        // dnf 4.20 emits the same INFO line; under the pinned C locale the
        // date is `Www Mmm D D HH:MM:SS YYYY` with a space-padded day.
        assert!(is_metadata_expiration_line(
            "Last metadata expiration check: 0:44:34 ago on Thu Sep 17 20:41:18 2026."
        ));
        assert!(is_metadata_expiration_line(
            "Last metadata expiration check: 1 day, 2:03:04 ago on Tue Sep  1 07:41:40 2026."
        ));
        // A locale-rendered date is not the C-locale form this tool forces.
        assert!(!is_metadata_expiration_line(
            "Last metadata expiration check: 0:44:34 ago on Thu Sep 17 08:41:18 PM UTC."
        ));
    }
}
