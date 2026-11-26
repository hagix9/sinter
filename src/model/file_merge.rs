//! Load-time checks of `file_merge` (the shape of a declaration, its static
//! fields, and the conflicts between resources of one recipe).
//!
//! A `file_merge` manages a part of a file, so it is not an exclusive owner
//! of its path: several may share one path as long as each manages another
//! part. A resource that manages the whole path (`file`, `template`,
//! `directory`, `link`, `systemd_timer`) contradicts every `file_merge` of
//! that path.

use super::{
    require_optional_mode, require_optional_static_string, require_static_string_field, staged,
    staged_field, static_string, validate_path, validate_with_fields, value_may_be_sensitive,
    value_references_sensitive_var, Declaration, FrozenResource, RawResource, Stage, Tolerance,
};
use crate::error::{Result, SinterError};
use crate::expressions::Scope;
use crate::filemerge::{
    static_identity, valid_key, valid_marker, Identity, MergeSpec, COMMENT_PREFIXES, FIELDS,
    MERGES, SEPARATORS, STATIC_FIELDS,
};
use crate::value::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The resource types that manage a whole path.
/// (`dnf_repository` manages a section of its file with its own rules; a
/// `file_merge` beside it would bypass them, so it counts as the owner.)
const WHOLE_PATH_TYPES: &[&str] = &[
    "file",
    "template",
    "directory",
    "link",
    "systemd_timer",
    "sysctl",
    "dnf_repository",
];

/// Refuse a `file_merge` on DNF's and RPM's configuration: the repository
/// files (also `/etc/distro.repos.d`), the main configuration, everything
/// under `/etc/dnf/` and `/etc/yum/` (module state, variables, plugin
/// configuration), RPM's macros (`/etc/rpm`, which can change signature
/// verification) and the signing keys (`/etc/pki/rpm-gpg`). A partial edit there
/// could switch off package signature checking with one line, which no
/// native resource may do. The path is absolute and has no `.`, `..` or
/// repeated separator (`validate_path`), so the comparison is on text.
pub(crate) fn check_not_dnf_configuration(path: &str, ctx: &str) -> Result<()> {
    const TREES: [&str; 6] = [
        "/etc/yum.repos.d",
        "/etc/distro.repos.d",
        "/etc/dnf",
        "/etc/yum",
        "/etc/rpm",
        "/etc/pki/rpm-gpg",
    ];
    let inside = |tree: &str| {
        path.strip_prefix(tree)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    };
    if path == "/etc/yum.conf" || TREES.iter().any(|t| inside(t)) {
        return Err(SinterError::schema(format!(
            "{}: file_merge does not edit DNF configuration ({}): repositories and DNF configuration are managed with dnf_repository and dnf_module (or a whole file resource), which keep package signature checking",
            ctx, path
        )));
    }
    Ok(())
}

const META_FIELDS: [&str; 3] = ["owner", "group", "mode"];

/// Declaration-level shape check: unknown fields, wrong types and bad
/// literal values. A field that carries `{{ ... }}` is judged when its value
/// is known.
pub(super) fn check_shape(d: &Declaration, sensitive_var_names: &BTreeSet<String>) -> Result<()> {
    let ctx = &d.id;
    let field_sensitive = |key: &str| {
        d.sensitive
            || d.with
                .get(key)
                .is_some_and(|v| value_may_be_sensitive(v, sensitive_var_names))
    };
    validate_with_fields(&d.with, FIELDS, ctx)?;
    require_static_string_field(&d.with, "path", ctx, field_sensitive("path"))?;
    require_static_string_field(&d.with, "merge", ctx, field_sensitive("merge"))?;
    for key in STATIC_FIELDS {
        require_optional_static_string(&d.with, key, ctx, field_sensitive(key))?;
    }
    require_optional_mode(
        &d.with,
        ctx,
        d.sensitive
            || d.with
                .get("mode")
                .is_some_and(|v| value_references_sensitive_var(v, sensitive_var_names)),
    )?;
    check_owner_group(&d.with, ctx)?;
    MergeSpec::check(&d.with, ctx, true).map(|_| ())
}

fn check_owner_group(with: &BTreeMap<String, Value>, ctx: &str) -> Result<()> {
    for key in ["owner", "group"] {
        match with.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::Str(s)) if !s.is_empty() && !crate::value::has_nul(s) => {}
            Some(_) => {
                return Err(SinterError::schema(format!("{}: invalid {}", ctx, key)));
            }
        }
    }
    Ok(())
}

/// Resolve the static fields of one `file_merge` and check the declaration
/// with them. Returns nothing: the engine evaluates and checks the fields
/// again when the resource runs.
pub(super) fn freeze_fields(
    r: &RawResource,
    scope: &Scope,
    ctx: &str,
    fr: &mut FrozenResource,
    sensitive_vars: &BTreeSet<String>,
    stage: &mut Stage,
    tol: &Tolerance,
) -> Result<()> {
    let field_sensitive = |key: &str| {
        r.sensitive
            || r.with
                .get(key)
                .is_some_and(|v| value_may_be_sensitive(v, sensitive_vars))
    };
    staged(stage, Stage::ValueFree, || {
        validate_with_fields(&r.with, FIELDS, ctx)?;
        if let Some(Value::Str(s)) = r.with.get("mode") {
            crate::paths::parse_mode(s).map_err(|e| {
                if r.sensitive {
                    SinterError::schema(format!("{}: invalid mode", ctx))
                } else {
                    SinterError::schema(format!("{}: {}", ctx, e.message))
                }
            })?;
        }
        check_owner_group(&r.with, ctx)
    })?;
    fr.path = staged_field(stage, tol, "path", || {
        let path = static_string(&r.with, "path", scope, ctx, true, field_sensitive("path"))?;
        validate_path(&path).map_err(|e| SinterError::schema(format!("{}: {}", ctx, e.message)))?;
        check_not_dnf_configuration(&path, ctx)?;
        Ok(path)
    })?;
    let Some(resolved) = resolved_static_fields(r, scope, ctx, sensitive_vars, stage, tol)? else {
        return Ok(());
    };
    // A structure-only check holds the recipe's defaults: which fields apply
    // is not its to judge when a variable decides a static field.
    if tol.on && STATIC_FIELDS.iter().any(|k| tol.refs.contains_key(*k)) {
        return Ok(());
    }
    // Unattributed: the check reads the resolved static fields, so its
    // message is withheld whenever the resource references a variable of a
    // variables file.
    MergeSpec::check(&resolved, ctx, true).map(|_| ())
}

/// The check of one resolved static field on its own.
fn check_static_value(key: &str, value: &str, ctx: &str) -> Result<()> {
    let ok = match key {
        "merge" => MERGES.contains(&value),
        "marker" => valid_marker(value),
        "comment_prefix" => COMMENT_PREFIXES.contains(&value),
        "key" => valid_key(value),
        "separator" => SEPARATORS.contains(&value),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(SinterError::schema(format!(
            "{}: file_merge {} is not valid: {}",
            ctx,
            key,
            match key {
                "merge" => "it must be line, block or key_value",
                "marker" => "it must be 1 to 64 characters of [A-Za-z0-9_.-]",
                "comment_prefix" => "it must be one of \"#\", \";\", \"//\", \"--\"",
                "key" => "it must be 1 to 128 characters of [A-Za-z0-9_.-]",
                _ => "it must be one of \"=\", \" = \", \":\", \": \", \" \"",
            }
        )))
    }
}

/// `with` with every static field replaced by its resolved value, or `None`
/// when a structure-only check leaves one of them unjudged.
fn resolved_static_fields(
    r: &RawResource,
    scope: &Scope,
    ctx: &str,
    sensitive_vars: &BTreeSet<String>,
    stage: &mut Stage,
    tol: &Tolerance,
) -> Result<Option<BTreeMap<String, Value>>> {
    let mut resolved = r.with.clone();
    for key in STATIC_FIELDS {
        match r.with.get(*key) {
            None => continue,
            Some(Value::Null) => {
                resolved.remove(*key);
                continue;
            }
            Some(_) => {}
        }
        let sensitive = r.sensitive
            || r.with
                .get(*key)
                .is_some_and(|v| value_may_be_sensitive(v, sensitive_vars));
        match staged_field(stage, tol, key, || {
            let v = static_string(&r.with, key, scope, ctx, true, sensitive)?;
            check_static_value(key, &v, ctx)?;
            Ok(v)
        })? {
            Some(v) => {
                resolved.insert((*key).to_string(), Value::Str(v));
            }
            None => return Ok(None),
        }
    }
    Ok(Some(resolved))
}

struct MergeOwner {
    id: String,
    identity: Option<Identity>,
    /// Declared `owner`, `group`, `mode` when statically known.
    meta: [Option<String>; 3],
}

/// The `file_merge` resources frozen so far, by path.
#[derive(Default)]
pub(super) struct MergeOwners {
    by_path: BTreeMap<String, Vec<MergeOwner>>,
}

impl MergeOwners {
    /// The first `file_merge` frozen so far on `path` (for the paths a
    /// native type owns besides its `path`, `super::owned`).
    pub(super) fn first_on(&self, path: &str) -> Option<&str> {
        self.by_path
            .get(path)
            .and_then(|v| v.first())
            .map(|o| o.id.as_str())
    }
}

/// A field's value when it is known without evaluating anything that is not
/// static (and is not sensitive).
fn static_value(with: &BTreeMap<String, Value>, key: &str, scope: &Scope) -> Option<String> {
    match with.get(key) {
        None | Some(Value::Null) => None,
        Some(_) => static_string(with, key, scope, "", true, true).ok(),
    }
}

/// Refuse a conflict with resource `peer` that `fields` (of either side)
/// decide. A structure-only check leaves it unjudged when a variable takes
/// part; otherwise the failure is attributed to the first of `fields` that
/// references a variable, so that a value of a variables file is withheld.
fn conflict(
    stage: &mut Stage,
    tol: &Tolerance,
    peer_refs: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
    fields: &[&'static str],
    peer: &str,
    message: String,
) -> Result<()> {
    let by_variable = fields.iter().copied().find(|f| {
        tol.refs.contains_key(*f) || peer_refs.get(peer).is_some_and(|m| m.contains_key(*f))
    });
    if tol.on && by_variable.is_some() {
        return Ok(());
    }
    *stage = Stage::Ownership {
        field: by_variable.unwrap_or(fields[0]),
        peer: peer.to_string(),
    };
    Err(SinterError::schema(message))
}

/// Conflicts of one recipe around `file_merge`, checked as each resource is
/// frozen (after the whole-path ownership check has recorded `r`):
///
/// - a whole-path resource and a `file_merge` on one path;
/// - two `file_merge` of one path with the same identity (the same exact
///   line, block marker or key); a `line` that is not statically known is
///   not compared;
/// - two `file_merge` of one path that declare different `owner`, `group`
///   or `mode`.
#[allow(clippy::too_many_arguments)]
pub(super) fn check_ownership(
    owners: &mut MergeOwners,
    path_owner: &BTreeMap<String, String>,
    r: &RawResource,
    fr: &FrozenResource,
    scope: &Scope,
    stage: &mut Stage,
    tol: &Tolerance,
    peer_refs: &BTreeMap<String, BTreeMap<String, BTreeSet<String>>>,
) -> Result<()> {
    let Some(path) = &fr.path else {
        return Ok(());
    };
    if WHOLE_PATH_TYPES.contains(&r.type_.as_str()) {
        if let Some(peer) = owners.by_path.get(path).and_then(|v| v.first()) {
            return conflict(
                stage,
                tol,
                peer_refs,
                &["path"],
                &peer.id,
                format!(
                    "conflicting management of path {}: {} ({}) manages {} and {} (file_merge) manages a part of it",
                    path,
                    r.id,
                    r.type_,
                    if r.type_ == "dnf_repository" {
                        "a repository of that file"
                    } else {
                        "the whole path"
                    },
                    peer.id
                ),
            );
        }
        return Ok(());
    }
    if r.type_ != "file_merge" {
        return Ok(());
    }
    if let Some(peer) = path_owner.get(path) {
        return conflict(
            stage,
            tol,
            peer_refs,
            &["path"],
            peer,
            format!(
                "conflicting management of path {}: {} manages the whole path and {} (file_merge) manages a part of it",
                path, peer, r.id
            ),
        );
    }

    // The identity, from the resolved static fields; `line` only when it is
    // statically known and not sensitive.
    let mut resolved = r.with.clone();
    for key in STATIC_FIELDS.iter().chain(["line"].iter()) {
        match static_value(&r.with, key, scope) {
            Some(v) => {
                resolved.insert((*key).to_string(), Value::Str(v));
            }
            None => {
                resolved.remove(*key);
            }
        }
    }
    let mine = MergeOwner {
        id: r.id.clone(),
        identity: static_identity(&resolved),
        meta: META_FIELDS.map(|k| static_value(&r.with, k, scope)),
    };
    for peer in owners.by_path.get(path).into_iter().flatten() {
        if let (Some(a), Some(b)) = (&mine.identity, &peer.identity) {
            if a == b {
                let what = match a {
                    Identity::Line(_) => "the same line".to_string(),
                    Identity::Block(m) => format!("the same block marker {}", m),
                    Identity::Key(k) => format!("the same key {}", k),
                };
                conflict(
                    stage,
                    tol,
                    peer_refs,
                    &[a.field(), "merge", "path"],
                    &peer.id,
                    format!(
                        "conflicting file_merge resources {} and {} manage {} of path {}",
                        peer.id, r.id, what, path
                    ),
                )?;
            }
        }
        for (i, field) in META_FIELDS.into_iter().enumerate() {
            if let (Some(a), Some(b)) = (&mine.meta[i], &peer.meta[i]) {
                if a != b {
                    conflict(
                        stage,
                        tol,
                        peer_refs,
                        &[field, "path"],
                        &peer.id,
                        format!(
                            "conflicting file_merge resources {} and {} declare different {} for path {}",
                            peer.id, r.id, field, path
                        ),
                    )?;
                }
            }
        }
    }
    owners.by_path.entry(path.clone()).or_default().push(mine);
    Ok(())
}
