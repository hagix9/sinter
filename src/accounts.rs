//! Local `group` and `user` resources.
//!
//! Scope (reviewed contract, POST_V1.1.1_FOLLOWUP_RESEARCH.md §C.5 narrowed by
//! the resource-type gap analysis §6.4):
//!
//! * local accounts only: every observation uses `getent -s files`, and an
//!   account that only another identity source (LDAP, SSSD, ...) provides is
//!   an error, never a create (a `useradd` would shadow it);
//! * only the dimensions a recipe names are managed; everything else is left
//!   alone;
//! * an existing account is never renumbered (uid/gid mismatch is refused),
//!   renamed, or have its home directory moved;
//! * supplementary membership is additive and never removes;
//! * `absent` is `userdel`/`groupdel` without `-r`/`-f`; the home directory
//!   and mail spool are kept;
//! * every command is a fixed executable with explicit argv, never a shell,
//!   and every mutation goes through the engine's mutation permit;
//! * `password_hash` (a secret reference, never a literal) is set with
//!   `chpasswd -e` reading `name:hash` on standard input, compared in memory
//!   against `getent -s files shadow`, requires `--sudo`, and is never shown.

use crate::engine::{unknown_result, Engine, Mode};
use crate::error::{ErrorKind, Result, SinterError};
use crate::executor::{Completion, ExecRequest, Output};
use crate::expressions::EvalVal;
use crate::model::FrozenResource;
use crate::resources::{ev_bool, ev_int, ev_list_str, ev_str};
use crate::result::*;
use crate::targetfs::TargetFs;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const CHPASSWD: &str = "/usr/sbin/chpasswd";
const GROUPADD: &str = "/usr/sbin/groupadd";
const GROUPDEL: &str = "/usr/sbin/groupdel";
const USERADD: &str = "/usr/sbin/useradd";
const USERMOD: &str = "/usr/sbin/usermod";
const USERDEL: &str = "/usr/sbin/userdel";

/// Largest id the kernel accepts for an account (`(uid_t)-1` is reserved).
const MAX_ID: i64 = 4_294_967_294;

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

/// A portable local account/group name: `[a-z_][a-z0-9_-]*`, at most 32
/// bytes. Stricter than shadow-utils on purpose: a name can never be numeric,
/// begin with `-` (an option), or contain `:` `,` whitespace or a control
/// character that would corrupt a passwd/group record or an argv list.
pub(crate) fn valid_account_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 32 {
        return false;
    }
    if !(b[0].is_ascii_lowercase() || b[0] == b'_') {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// An absolute path usable as a passwd home or shell field: a valid Sinter
/// path that is not `/`, and contains none of the characters that would end
/// or corrupt a colon-separated record (`:`, newline, any control character).
pub(crate) fn valid_account_path(s: &str) -> bool {
    if s == "/" || crate::paths::validate_path(s).is_err() {
        return false;
    }
    !s.chars().any(|c| c == ':' || c == ',' || c.is_control())
}

/// Validate the literal, statically-known parts of an account `with` map.
/// Interpolated values are validated again after evaluation at run time.
pub(crate) fn validate_account_literals(
    kind: &str,
    with: &BTreeMap<String, crate::value::Value>,
    ctx: &str,
    redact: bool,
) -> std::result::Result<(), SinterError> {
    use crate::value::Value;
    let shown = |v: &str| {
        if redact {
            "(value redacted)".to_string()
        } else {
            format!("{:?}", v)
        }
    };
    let literal = |v: &Value| -> Option<String> {
        match v {
            Value::Str(s) if !crate::expressions::has_interpolation(s) => Some(s.clone()),
            _ => None,
        }
    };
    for key in ["gid", "uid"] {
        if let Some(v) = with.get(key) {
            match v {
                Value::Int(i) if (1..=MAX_ID).contains(i) => {}
                Value::Int(_) => {
                    return Err(SinterError::schema(format!(
                        "{}: {} must be between 1 and {}",
                        ctx, key, MAX_ID
                    )))
                }
                Value::Str(s) if crate::expressions::has_interpolation(s) => {}
                Value::Null => {}
                _ => {
                    return Err(SinterError::schema(format!(
                        "{}: {} must be an integer",
                        ctx, key
                    )))
                }
            }
        }
    }
    for key in ["system", "create_home"] {
        if let Some(v) = with.get(key) {
            match v {
                Value::Bool(_) | Value::Null => {}
                Value::Str(s) if crate::expressions::has_interpolation(s) => {}
                _ => {
                    return Err(SinterError::schema(format!(
                        "{}: {} must be a boolean",
                        ctx, key
                    )))
                }
            }
        }
    }
    if kind == "user" {
        if let Some(v) = with.get("password_hash") {
            // Only a secret reference: a hash is secret material and is never
            // written in a recipe, and there is no plaintext `password`.
            match crate::secret_source::content_shape(v) {
                Ok(crate::secret_source::ContentShape::Secret(_)) => {}
                _ => {
                    return Err(SinterError::schema(format!(
                        "{}: password_hash must be {{ secret: <path> }} (a hash is secret and is \
                         never written in a recipe)",
                        ctx
                    )))
                }
            }
            if matches!(with.get("state"), Some(Value::Str(s)) if s == "absent") {
                return Err(SinterError::schema(format!(
                    "{}: password_hash cannot be combined with state: absent",
                    ctx
                )));
            }
        }
        if let Some(v) = with.get("group") {
            if !matches!(v, Value::Null) {
                match v {
                    Value::Str(_) => {
                        if let Some(s) = literal(v) {
                            if !valid_account_name(&s) {
                                return Err(SinterError::schema(format!(
                                    "{}: group must be a valid group name, got {}",
                                    ctx,
                                    shown(&s)
                                )));
                            }
                        }
                    }
                    _ => {
                        return Err(SinterError::schema(format!(
                            "{}: group must be a group name string",
                            ctx
                        )))
                    }
                }
            }
        }
        for key in ["shell", "home"] {
            match with.get(key) {
                None | Some(Value::Null) => {}
                Some(v @ Value::Str(_)) => {
                    if let Some(s) = literal(v) {
                        if !valid_account_path(&s) {
                            return Err(SinterError::schema(format!(
                                "{}: {} must be an absolute path without ':' ',' or control characters, got {}",
                                ctx,
                                key,
                                shown(&s)
                            )));
                        }
                    }
                }
                Some(_) => {
                    return Err(SinterError::schema(format!(
                        "{}: {} must be an absolute path string",
                        ctx, key
                    )))
                }
            }
        }
        match with.get("groups") {
            None | Some(Value::Null) => {}
            Some(Value::List(items)) => {
                let mut seen = Vec::new();
                for it in items {
                    match it {
                        Value::Str(s) => {
                            if let Some(s) = literal(it) {
                                if !valid_account_name(&s) {
                                    return Err(SinterError::schema(format!(
                                        "{}: groups entry must be a valid group name, got {}",
                                        ctx,
                                        shown(&s)
                                    )));
                                }
                                if seen.contains(&s) {
                                    return Err(SinterError::schema(format!(
                                        "{}: groups lists {} more than once",
                                        ctx,
                                        shown(&s)
                                    )));
                                }
                                seen.push(s);
                            } else {
                                let _ = s;
                            }
                        }
                        _ => {
                            return Err(SinterError::schema(format!(
                                "{}: groups entries must be group name strings",
                                ctx
                            )))
                        }
                    }
                }
                if let Some(Value::Str(p)) = with.get("group") {
                    if seen.contains(p) {
                        return Err(SinterError::schema(format!(
                            "{}: the primary group {} must not also be listed in groups",
                            ctx,
                            shown(p)
                        )));
                    }
                }
            }
            Some(Value::Str(s)) if crate::expressions::has_interpolation(s) => {}
            Some(_) => {
                return Err(SinterError::schema(format!(
                    "{}: groups must be a list of group names",
                    ctx
                )))
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// desired state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct GroupDesired {
    pub name: String,
    pub present: bool,
    pub gid: Option<u32>,
    pub system: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct UserDesired {
    pub name: String,
    pub present: bool,
    pub uid: Option<u32>,
    pub group: Option<String>,
    pub groups: Vec<String>,
    pub shell: Option<String>,
    pub home: Option<String>,
    pub create_home: bool,
    pub system: bool,
}

fn desired_state(vals: &BTreeMap<String, EvalVal>, id: &str, kind: &str) -> Result<bool> {
    match ev_str(vals, "state")?.map(|(s, _)| s).as_deref() {
        None | Some("present") => Ok(true),
        Some("absent") => Ok(false),
        Some(_) => Err(SinterError::apply(format!(
            "{}: {} state must resolve to present or absent",
            id, kind
        ))),
    }
}

fn desired_id(vals: &BTreeMap<String, EvalVal>, id: &str, key: &str) -> Result<Option<u32>> {
    match ev_int(vals, key)? {
        None => Ok(None),
        Some(i) if (1..=MAX_ID).contains(&i) => Ok(Some(i as u32)),
        Some(_) => Err(SinterError::apply(format!(
            "{}: {} must be between 1 and {}",
            id, key, MAX_ID
        ))),
    }
}

fn desired_name(v: &str, id: &str, what: &str, sensitive: bool) -> Result<String> {
    if valid_account_name(v) {
        Ok(v.to_string())
    } else if sensitive {
        Err(SinterError::apply(format!(
            "{}: {} is not a valid account name (value redacted)",
            id, what
        )))
    } else {
        Err(SinterError::apply(format!(
            "{}: {} {:?} is not a valid account name",
            id, what, v
        )))
    }
}

fn desired_path(
    vals: &BTreeMap<String, EvalVal>,
    id: &str,
    key: &str,
    sensitive: bool,
) -> Result<Option<String>> {
    match ev_str(vals, key)? {
        None => Ok(None),
        Some((p, _)) if valid_account_path(&p) => Ok(Some(p)),
        Some(_) if sensitive => Err(SinterError::apply(format!(
            "{}: {} is not a valid absolute path (value redacted)",
            id, key
        ))),
        Some((p, _)) => Err(SinterError::apply(format!(
            "{}: {} {:?} is not a valid absolute path (no ':' ',' or control characters)",
            id, key, p
        ))),
    }
}

pub(crate) fn group_desired(
    res: &FrozenResource,
    vals: &BTreeMap<String, EvalVal>,
    sensitive: bool,
) -> Result<GroupDesired> {
    let name = res
        .account_name
        .clone()
        .ok_or_else(|| SinterError::schema(format!("{}: group missing name", res.id)))?;
    let name = desired_name(&name, &res.id, "group name", sensitive)?;
    Ok(GroupDesired {
        name,
        present: desired_state(vals, &res.id, "group")?,
        gid: desired_id(vals, &res.id, "gid")?,
        system: ev_bool(vals, "system")?.unwrap_or(false),
    })
}

pub(crate) fn user_desired(
    res: &FrozenResource,
    vals: &BTreeMap<String, EvalVal>,
    sensitive: bool,
) -> Result<UserDesired> {
    let name = res
        .account_name
        .clone()
        .ok_or_else(|| SinterError::schema(format!("{}: user missing name", res.id)))?;
    let name = desired_name(&name, &res.id, "user name", sensitive)?;
    let group = match ev_str(vals, "group")? {
        None => None,
        Some((g, _)) => Some(desired_name(&g, &res.id, "primary group", sensitive)?),
    };
    let mut groups: Vec<String> = Vec::new();
    if let Some((list, _)) = ev_list_str(vals, "groups")? {
        for g in list {
            let g = desired_name(&g, &res.id, "supplementary group", sensitive)?;
            if groups.contains(&g) {
                return Err(SinterError::apply(format!(
                    "{}: groups lists a group more than once",
                    res.id
                )));
            }
            groups.push(g);
        }
    }
    if let Some(p) = &group {
        if groups.contains(p) {
            return Err(SinterError::apply(format!(
                "{}: the primary group must not also be listed in groups",
                res.id
            )));
        }
    }
    Ok(UserDesired {
        name,
        present: desired_state(vals, &res.id, "user")?,
        uid: desired_id(vals, &res.id, "uid")?,
        group,
        groups,
        shell: desired_path(vals, &res.id, "shell", sensitive)?,
        home: desired_path(vals, &res.id, "home", sensitive)?,
        create_home: ev_bool(vals, "create_home")?.unwrap_or(false),
        system: ev_bool(vals, "system")?.unwrap_or(false),
    })
}

/// The declared password hash of a user (secret material).
#[derive(Clone)]
pub(crate) struct PasswordSpec {
    pub hash: Zeroizing<String>,
}

impl std::fmt::Debug for PasswordSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordSpec([redacted])")
    }
}

// ---------------------------------------------------------------------------
// observation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupRec {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UserRec {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Lookup<T> {
    /// No local record, and no other identity source answers either.
    Absent,
    /// A record in the local database.
    Local(T),
    /// Not in the local database, but another identity source (NSS) has it.
    NssOnly,
}

/// A decimal id: ASCII digits only (`"+5"` is not an id).
fn parse_id(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn parse_group_line(line: &str) -> Option<GroupRec> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() != 4 || f[0].is_empty() {
        return None;
    }
    Some(GroupRec {
        name: f[0].to_string(),
        gid: parse_id(f[2])?,
        members: f[3]
            .split(',')
            .filter(|m| !m.is_empty())
            .map(String::from)
            .collect(),
    })
}

fn parse_user_line(line: &str) -> Option<UserRec> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() != 7 || f[0].is_empty() {
        return None;
    }
    Some(UserRec {
        name: f[0].to_string(),
        uid: parse_id(f[2])?,
        gid: parse_id(f[3])?,
        home: f[5].to_string(),
        shell: f[6].to_string(),
    })
}

fn shown(key: &str, sensitive: bool) -> &str {
    if sensitive {
        "[redacted]"
    } else {
        key
    }
}

/// One strict record from a `getent` capture: complete, valid UTF-8, no
/// diagnostic, exactly one newline-terminated line.
fn single_record<'a>(out: &'a Output, what: &str) -> Result<&'a str> {
    if out.stdout_truncated || out.stderr_truncated {
        return Err(SinterError::apply(format!(
            "account lookup for {} captured truncated output: the result is incomplete",
            what
        )));
    }
    if !out.stderr.is_empty() {
        return Err(SinterError::apply(format!(
            "account lookup for {} returned an unexpected diagnostic",
            what
        )));
    }
    let text = std::str::from_utf8(&out.stdout).map_err(|_| {
        SinterError::apply(format!(
            "account lookup for {} captured invalid UTF-8 output",
            what
        ))
    })?;
    let line = text.strip_suffix('\n').ok_or_else(|| {
        SinterError::apply(format!(
            "account lookup for {} returned an unterminated record",
            what
        ))
    })?;
    if line.is_empty() || line.contains('\n') || line.contains('\r') {
        return Err(SinterError::apply(format!(
            "account lookup for {} did not return exactly one record",
            what
        )));
    }
    Ok(line)
}

fn lookup_failure(what: &str, out: &Output) -> SinterError {
    match &out.completion {
        Completion::Indeterminate { reason, .. } => SinterError::indeterminate(format!(
            "account lookup for {} did not complete: {}",
            what, reason
        )),
        Completion::Signaled(s) => SinterError::apply(format!(
            "account lookup for {} terminated by signal {}",
            what, s
        )),
        Completion::Exited(c) => SinterError::apply(format!(
            "account lookup for {} failed unexpectedly (exit {})",
            what, c
        )),
    }
}

/// Look one record up: local database first (`getent -s files`), then, only
/// when the local database has no such record, the NSS-wide answer to tell a
/// true absence from an externally provided account. Exit status 2 is
/// getent's only "key not found"; every other failure is an observation
/// error, never an absence.
fn lookup<T>(
    fs: &mut TargetFs,
    database: &str,
    key: &str,
    sensitive: bool,
    parse: fn(&str) -> Option<T>,
    key_matches: impl Fn(&T) -> bool,
) -> Result<Lookup<T>> {
    let what = shown(key, sensitive);
    let out = fs.account_getent(true, database, Some(key), sensitive)?;
    match out.completion {
        Completion::Exited(0) => {
            let line = single_record(&out, what)?;
            let rec = parse(line).ok_or_else(|| {
                SinterError::apply(format!(
                    "account lookup for {} returned a malformed record",
                    what
                ))
            })?;
            if !key_matches(&rec) {
                return Err(SinterError::apply(format!(
                    "account lookup for {} returned a different account",
                    what
                )));
            }
            Ok(Lookup::Local(rec))
        }
        Completion::Exited(2) => {
            let nss = fs.account_getent(false, database, Some(key), sensitive)?;
            match nss.completion {
                Completion::Exited(0) => Ok(Lookup::NssOnly),
                Completion::Exited(2) => Ok(Lookup::Absent),
                _ => Err(lookup_failure(what, &nss)),
            }
        }
        _ => Err(lookup_failure(what, &out)),
    }
}

pub(crate) fn lookup_group(
    fs: &mut TargetFs,
    name: &str,
    sensitive: bool,
) -> Result<Lookup<GroupRec>> {
    lookup(
        fs,
        "group",
        name,
        sensitive,
        parse_group_line,
        |r: &GroupRec| r.name == name,
    )
}

pub(crate) fn lookup_group_gid(
    fs: &mut TargetFs,
    gid: u32,
    sensitive: bool,
) -> Result<Lookup<GroupRec>> {
    lookup(
        fs,
        "group",
        &gid.to_string(),
        sensitive,
        parse_group_line,
        move |r: &GroupRec| r.gid == gid,
    )
}

pub(crate) fn lookup_user(
    fs: &mut TargetFs,
    name: &str,
    sensitive: bool,
) -> Result<Lookup<UserRec>> {
    lookup(
        fs,
        "passwd",
        name,
        sensitive,
        parse_user_line,
        |r: &UserRec| r.name == name,
    )
}

pub(crate) fn lookup_user_uid(
    fs: &mut TargetFs,
    uid: u32,
    sensitive: bool,
) -> Result<Lookup<UserRec>> {
    lookup(
        fs,
        "passwd",
        &uid.to_string(),
        sensitive,
        parse_user_line,
        move |r: &UserRec| r.uid == uid,
    )
}

/// Every local user, from `getent -s files passwd`.
fn local_users(fs: &mut TargetFs, sensitive: bool) -> Result<Vec<UserRec>> {
    let out = fs.account_getent(true, "passwd", None, sensitive)?;
    match out.completion {
        Completion::Exited(0) => {}
        _ => return Err(lookup_failure("the local user list", &out)),
    }
    if out.stdout_truncated || out.stderr_truncated || !out.stderr.is_empty() {
        return Err(SinterError::apply(
            "account enumeration was incomplete or returned a diagnostic",
        ));
    }
    let text = std::str::from_utf8(&out.stdout)
        .map_err(|_| SinterError::apply("account enumeration captured invalid UTF-8 output"))?;
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| SinterError::apply("account enumeration returned an unterminated record"))?;
    let mut users = Vec::new();
    for line in body.split('\n') {
        users.push(parse_user_line(line).ok_or_else(|| {
            SinterError::apply("account enumeration returned a malformed passwd record")
        })?);
    }
    if users.is_empty() {
        return Err(SinterError::apply(
            "account enumeration returned no local users",
        ));
    }
    Ok(users)
}

// ---------------------------------------------------------------------------
// comparison (pure)
// ---------------------------------------------------------------------------

/// One drifting dimension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dim {
    pub dimension: &'static str,
    pub observed: String,
    pub desired: String,
}

fn dim(dimension: &'static str, observed: impl Into<String>, desired: impl Into<String>) -> Dim {
    Dim {
        dimension,
        observed: observed.into(),
        desired: desired.into(),
    }
}

#[derive(Debug, Default)]
pub(crate) struct Compare {
    pub dims: Vec<Dim>,
    /// Changes the contract refuses to make (renumbering).
    pub refusals: Vec<String>,
    /// Groups the desired state names that do not exist locally.
    pub missing_groups: Vec<String>,
}

pub(crate) fn compare_group(d: &GroupDesired, o: &Lookup<GroupRec>) -> Result<Compare> {
    let mut c = Compare::default();
    match (o, d.present) {
        (Lookup::NssOnly, _) => return Err(nss_only_error("group")),
        (Lookup::Absent, true) => c.dims.push(dim("state", "absent", "present")),
        (Lookup::Absent, false) => {}
        (Lookup::Local(_), false) => c.dims.push(dim("state", "present", "absent")),
        (Lookup::Local(g), true) => {
            if let Some(gid) = d.gid {
                if gid != g.gid {
                    c.dims.push(dim("gid", g.gid.to_string(), gid.to_string()));
                    c.refusals.push(format!(
                        "the group has gid {} but gid {} is declared; an existing group is never renumbered",
                        g.gid, gid
                    ));
                }
            }
        }
    }
    Ok(c)
}

fn nss_only_error(what: &str) -> SinterError {
    SinterError::apply(format!(
        "the {} resolves through a non-local identity source (NSS) but is not in the local database; \
         refusing to manage it",
        what
    ))
}

pub(crate) struct UserObservation {
    pub user: Lookup<UserRec>,
    /// The declared primary group, when one is declared.
    pub primary: Option<Lookup<GroupRec>>,
    pub supplementary: Vec<(String, Lookup<GroupRec>)>,
}

pub(crate) fn compare_user(d: &UserDesired, o: &UserObservation) -> Result<Compare> {
    let mut c = Compare::default();
    if matches!(o.user, Lookup::NssOnly) {
        return Err(nss_only_error("user"));
    }
    if let Some(Lookup::NssOnly) = o.primary {
        return Err(nss_only_error("primary group"));
    }
    if o.supplementary.iter().any(|(_, l)| *l == Lookup::NssOnly) {
        return Err(nss_only_error("supplementary group"));
    }
    if d.present {
        if let (Some(name), Some(Lookup::Absent)) = (&d.group, &o.primary) {
            c.missing_groups.push(name.clone());
        }
        for (name, l) in &o.supplementary {
            if *l == Lookup::Absent {
                c.missing_groups.push(name.clone());
            }
        }
    }
    match (&o.user, d.present) {
        (Lookup::NssOnly, _) => {}
        (Lookup::Absent, true) => c.dims.push(dim("state", "absent", "present")),
        (Lookup::Absent, false) => {}
        (Lookup::Local(_), false) => c.dims.push(dim("state", "present", "absent")),
        (Lookup::Local(u), true) => {
            if let Some(uid) = d.uid {
                if uid != u.uid {
                    c.dims.push(dim("uid", u.uid.to_string(), uid.to_string()));
                    c.refusals.push(format!(
                        "the user has uid {} but uid {} is declared; an existing user is never renumbered",
                        u.uid, uid
                    ));
                }
            }
            if let (Some(name), Some(p)) = (&d.group, &o.primary) {
                match p {
                    Lookup::Local(g) => {
                        if g.gid != u.gid {
                            c.dims.push(dim(
                                "group",
                                format!("gid {}", u.gid),
                                format!("{} (gid {})", name, g.gid),
                            ));
                        }
                    }
                    _ => c.dims.push(dim(
                        "group",
                        format!("gid {}", u.gid),
                        format!("{} (does not exist)", name),
                    )),
                }
            }
            if let Some(shell) = &d.shell {
                if *shell != u.shell {
                    c.dims.push(dim("shell", u.shell.clone(), shell.clone()));
                }
            }
            if let Some(home) = &d.home {
                if *home != u.home {
                    c.dims.push(dim("home", u.home.clone(), home.clone()));
                }
            }
            let missing = missing_memberships(d, o, &u.name);
            let nonexistent: Vec<&String> = o
                .supplementary
                .iter()
                .filter(|(_, l)| *l == Lookup::Absent)
                .map(|(n, _)| n)
                .collect();
            if !missing.is_empty() || !nonexistent.is_empty() {
                let have: Vec<String> = d
                    .groups
                    .iter()
                    .filter(|g| !missing.contains(g) && !nonexistent.contains(g))
                    .cloned()
                    .collect();
                let mut observed = if have.is_empty() {
                    "none of the declared groups".to_string()
                } else {
                    have.join(",")
                };
                if !nonexistent.is_empty() {
                    observed.push_str(&format!(
                        " (nonexistent: {})",
                        nonexistent
                            .iter()
                            .map(|g| g.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    ));
                }
                c.dims.push(dim("groups", observed, d.groups.join(",")));
            }
        }
    }
    Ok(c)
}

/// Declared supplementary groups the user is not (yet) a member of, among
/// groups that exist.
pub(crate) fn missing_memberships(d: &UserDesired, o: &UserObservation, user: &str) -> Vec<String> {
    o.supplementary
        .iter()
        .filter_map(|(name, l)| match l {
            Lookup::Local(g) if !g.members.iter().any(|m| m == user) => Some(name.clone()),
            _ => None,
        })
        .filter(|n| d.groups.contains(n))
        .collect()
}

fn describe_group(d: &GroupDesired) -> String {
    if !d.present {
        return "absent".to_string();
    }
    let mut s = String::from("present");
    if let Some(g) = d.gid {
        s.push_str(&format!(" gid={}", g));
    }
    s
}

fn describe_user(d: &UserDesired) -> String {
    if !d.present {
        return "absent".to_string();
    }
    let mut s = String::from("present");
    if let Some(v) = d.uid {
        s.push_str(&format!(" uid={}", v));
    }
    if let Some(v) = &d.group {
        s.push_str(&format!(" group={}", v));
    }
    if !d.groups.is_empty() {
        s.push_str(&format!(" groups={}", d.groups.join(",")));
    }
    if let Some(v) = &d.shell {
        s.push_str(&format!(" shell={}", v));
    }
    if let Some(v) = &d.home {
        s.push_str(&format!(" home={}", v));
    }
    s
}

fn describe_dims(dims: &[Dim]) -> (String, String) {
    (
        dims.iter()
            .map(|d| format!("{}={}", d.dimension, d.observed))
            .collect::<Vec<_>>()
            .join(" "),
        dims.iter()
            .map(|d| format!("{}={}", d.dimension, d.desired))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

// ---------------------------------------------------------------------------
// argv (pure)
// ---------------------------------------------------------------------------

pub(crate) fn groupadd_args(d: &GroupDesired) -> Vec<String> {
    let mut a = Vec::new();
    if d.system {
        a.push("--system".to_string());
    }
    if let Some(g) = d.gid {
        a.push("-g".to_string());
        a.push(g.to_string());
    }
    a.push(d.name.clone());
    a
}

pub(crate) fn useradd_args(d: &UserDesired) -> Vec<String> {
    let mut a = Vec::new();
    if d.system {
        a.push("--system".to_string());
    }
    if let Some(u) = d.uid {
        a.push("-u".to_string());
        a.push(u.to_string());
    }
    if let Some(g) = &d.group {
        a.push("-g".to_string());
        a.push(g.clone());
    }
    if !d.groups.is_empty() {
        a.push("-G".to_string());
        a.push(d.groups.join(","));
    }
    if let Some(s) = &d.shell {
        a.push("-s".to_string());
        a.push(s.clone());
    }
    if let Some(h) = &d.home {
        a.push("-d".to_string());
        a.push(h.clone());
    }
    // Explicit either way: the distro default (login.defs CREATE_HOME)
    // differs between Debian and Red Hat families.
    a.push(if d.create_home { "-m" } else { "-M" }.to_string());
    a.push(d.name.clone());
    a
}

pub(crate) fn usermod_args(d: &UserDesired, o: &UserObservation, current: &UserRec) -> Vec<String> {
    let mut a = Vec::new();
    if let (Some(g), Some(Lookup::Local(rec))) = (&d.group, &o.primary) {
        if rec.gid != current.gid {
            a.push("-g".to_string());
            a.push(g.clone());
        }
    }
    if let Some(s) = &d.shell {
        if *s != current.shell {
            a.push("-s".to_string());
            a.push(s.clone());
        }
    }
    if let Some(h) = &d.home {
        // Record only: no `-m`, so nothing is moved.
        if *h != current.home {
            a.push("-d".to_string());
            a.push(h.clone());
        }
    }
    let missing = missing_memberships(d, o, &current.name);
    if !missing.is_empty() {
        a.push("-a".to_string());
        a.push("-G".to_string());
        a.push(missing.join(","));
    }
    a.push(current.name.clone());
    a
}

// ---------------------------------------------------------------------------
// engine integration
// ---------------------------------------------------------------------------

impl Engine {
    fn account_err(&self, msg: String) -> SinterError {
        if self.opts.mode == Mode::Plan {
            SinterError::plan(msg)
        } else {
            SinterError::apply(msg)
        }
    }

    /// The identity of the session that runs Sinter (as opposed to the
    /// effective identity `--sudo` switches to). Never deleted.
    fn login_identity(&self) -> (Option<u32>, Option<String>) {
        if let Some(f) = &self.opts.fake_target {
            return (Some(f.uid), None);
        }
        match &self.opts.target.ssh {
            Some(s) => (None, Some(s.user.clone())),
            None => (Some(unsafe { libc::getuid() }), None),
        }
    }

    fn protected_user(&self, u: &UserRec) -> Option<&'static str> {
        let (login_uid, login_name) = self.login_identity();
        if u.uid == 0 || u.name == "root" {
            Some("it is root")
        } else if u.uid == self.fs.target_uid() {
            Some("it is the account this run executes as")
        } else if login_uid == Some(u.uid) || login_name.as_deref() == Some(u.name.as_str()) {
            Some("it is the account running or connecting this session")
        } else {
            None
        }
    }

    /// Names of the direct `depends_on` resources of type `type_` that
    /// evaluate to `present` and declare an account name. Only explicit,
    /// direct dependencies count: nothing is inferred.
    pub(crate) fn account_producers(
        &self,
        res: &FrozenResource,
        type_: &str,
    ) -> Result<Vec<String>> {
        let mut found = Vec::new();
        for dep in &res.depends_on {
            let Some(d) = self.model.resources.iter().find(|r| &r.id == dep) else {
                continue;
            };
            if d.type_ != type_ {
                continue;
            }
            let Some(name) = &d.account_name else {
                continue;
            };
            let present = match d.with.get("state") {
                None | Some(crate::value::Value::Null) => true,
                Some(v) => {
                    let item = d.loop_item.as_ref().map(|v| EvalVal::known(v.clone()));
                    let dep_sensitive = d.sensitive || res.sensitive || res.derived_sensitive;
                    let ev = crate::expressions::eval_value_interpolated(
                        v,
                        &self.scope(item.as_ref(), None, None),
                    )
                    .map_err(|e| {
                        if dep_sensitive {
                            SinterError::plan(format!(
                                "{}: could not evaluate account dependency state (value redacted): {}",
                                res.id,
                                e.category()
                            ))
                        } else {
                            SinterError::plan(format!(
                                "{}: could not evaluate account dependency state: {}",
                                res.id, e
                            ))
                        }
                    })?;
                    matches!(ev.val, Some(crate::value::Value::Str(s)) if s == "present")
                }
            };
            if present {
                found.push(name.clone());
            }
        }
        Ok(found)
    }

    /// Plan only: a file-like resource whose `owner`/`group` names an account
    /// that an explicit direct dependency creates cannot be resolved yet.
    /// Returns the Unknown (deferred) error in that case.
    pub(crate) fn defer_owner_for_dependency(
        &mut self,
        res: &FrozenResource,
        type_: &str,
        spec: &str,
        failed: &SinterError,
    ) -> Result<Option<SinterError>> {
        if self.opts.mode != Mode::Plan || failed.kind == ErrorKind::Indeterminate {
            return Ok(None);
        }
        if self
            .account_producers(res, type_)?
            .iter()
            .any(|n| n == spec)
        {
            let sensitive = res.sensitive || res.derived_sensitive;
            // Defer only on a confirmed absence: any other lookup problem
            // stays the plan error it is.
            let absent = if type_ == "user" {
                lookup_user(&mut self.fs, spec, sensitive).map(|l| l == Lookup::Absent)
            } else {
                lookup_group(&mut self.fs, spec, sensitive).map(|l| l == Lookup::Absent)
            };
            if !matches!(absent, Ok(true)) {
                return Ok(None);
            }
            return Ok(Some(SinterError::unknown(format!(
                "{} {} is created by a dependency; deferred until dependency apply",
                type_,
                shown(spec, sensitive)
            ))));
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // group
    // -----------------------------------------------------------------------

    pub(crate) fn run_group(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let vals = self.eval_with(res, item)?;
        let sensitive = res.sensitive || res.derived_sensitive;
        let d = group_desired(res, &vals, sensitive)?;
        let obs = lookup_group(&mut self.fs, &d.name, sensitive)?;
        let c = compare_group(&d, &obs)?;
        if c.dims.is_empty() {
            return Ok(unchanged_account(
                res,
                "group already matches desired state",
            ));
        }
        if let Some(r) = c.refusals.first() {
            return Err(self.account_err(format!(
                "{}: refusing to change group {}: {}",
                res.id,
                shown(&d.name, sensitive),
                refusal_text(r, sensitive)
            )));
        }
        self.check_group_change(res, &d, &obs, sensitive)?;
        if self.opts.mode == Mode::Plan {
            return Ok(planned_account(res, sensitive, &c.dims, describe_group(&d)));
        }
        let (program, args) = match (&obs, d.present) {
            (Lookup::Absent, true) => (GROUPADD, groupadd_args(&d)),
            (_, false) => (GROUPDEL, vec![d.name.clone()]),
            _ => unreachable!("a changing present group that exists is refused above"),
        };
        if let Err(r) = self.account_exec(res, sensitive, program, args, None) {
            return Ok(*r);
        }
        let mut r = changed_account(res, sensitive);
        match lookup_group(&mut self.fs, &d.name, sensitive)
            .and_then(|after| compare_group(&d, &after))
        {
            Ok(after) if after.dims.is_empty() && after.refusals.is_empty() => {
                r.verification = Verification::Verified;
            }
            Ok(_) => {
                r.execution = Execution::Failed;
                r.verification = Verification::Failed;
                r.reason = Some("group did not reach the desired state after the mutation".into());
            }
            Err(e) => reobserve_failed(&mut r, &e),
        }
        if !d.present && r.verification == Verification::Verified {
            r.notes
                .push("group deleted; files owned by its gid are not touched".to_string());
        }
        Ok(r)
    }

    /// Pre-mutation checks shared by plan and apply.
    fn check_group_change(
        &mut self,
        res: &FrozenResource,
        d: &GroupDesired,
        obs: &Lookup<GroupRec>,
        sensitive: bool,
    ) -> Result<()> {
        match (obs, d.present) {
            (Lookup::Absent, true) => {
                if let Some(gid) = d.gid {
                    if lookup_group_gid(&mut self.fs, gid, sensitive)? != Lookup::Absent {
                        return Err(self.account_err(format!(
                            "{}: refusing to create group {}: gid {} is already in use",
                            res.id,
                            shown(&d.name, sensitive),
                            if sensitive {
                                "[redacted]".to_string()
                            } else {
                                gid.to_string()
                            }
                        )));
                    }
                }
            }
            (Lookup::Local(g), false) => {
                if g.gid == 0 || d.name == "root" {
                    return Err(
                        self.account_err(format!("{}: refusing to delete the root group", res.id))
                    );
                }
                if g.gid == self.fs.target_gid() {
                    return Err(self.account_err(format!(
                        "{}: refusing to delete the group this run executes as",
                        res.id
                    )));
                }
                let users: Vec<String> = local_users(&mut self.fs, sensitive)?
                    .into_iter()
                    .filter(|u| u.gid == g.gid)
                    .map(|u| u.name)
                    .collect();
                if !users.is_empty() {
                    return Err(self.account_err(format!(
                        "{}: refusing to delete group {}: it is the primary group of {}",
                        res.id,
                        shown(&d.name, sensitive),
                        if sensitive {
                            "[redacted]".to_string()
                        } else {
                            users.join(", ")
                        }
                    )));
                }
            }
            _ => {}
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // user
    // -----------------------------------------------------------------------

    pub(crate) fn observe_user(
        &mut self,
        d: &UserDesired,
        sensitive: bool,
    ) -> Result<UserObservation> {
        let user = lookup_user(&mut self.fs, &d.name, sensitive)?;
        let (primary, supplementary) = if d.present {
            let primary = match &d.group {
                Some(g) => Some(lookup_group(&mut self.fs, g, sensitive)?),
                None => None,
            };
            let mut supp = Vec::new();
            for g in &d.groups {
                supp.push((g.clone(), lookup_group(&mut self.fs, g, sensitive)?));
            }
            (primary, supp)
        } else {
            (None, Vec::new())
        };
        Ok(UserObservation {
            user,
            primary,
            supplementary,
        })
    }

    /// The desired user, with its password hash opened from the secret named
    /// by `password_hash` (if any). Everything that can fail does so before
    /// anything is observed or changed: no `--sudo`, an absent user, an
    /// unavailable key, a secret that is not an accepted hash, or yescrypt on
    /// an EL9 target.
    pub(crate) fn desired_user(
        &mut self,
        res: &FrozenResource,
        vals: &BTreeMap<String, EvalVal>,
        sensitive: bool,
    ) -> Result<(UserDesired, Option<PasswordSpec>)> {
        let d = user_desired(res, vals, sensitive)?;
        if res.secret.is_none() {
            return Ok((d, None));
        }
        if !d.present {
            return Err(self.account_err(format!(
                "{}: password_hash cannot be combined with state: absent",
                res.id
            )));
        }
        if !self.opts.sudo {
            return Err(self.account_err(format!(
                "{}: password_hash needs --sudo: the password database is readable and writable \
                 only by root",
                res.id
            )));
        }
        let secret = self.open_resource_secret(res)?;
        let (kind, hash) = crate::passwd_hash::parse_secret(secret.expose()).map_err(|_| {
            redact_text(&res.id, "password_hash", crate::passwd_hash::Rejected::TEXT)
        })?;
        drop(secret);
        if kind == crate::passwd_hash::Format::Yescrypt && self.is_el9() {
            return Err(self.account_err(format!(
                "{}: yescrypt ($y$) hashes are not supported on this platform (RHEL-family 9); \
                 use a $6$ hash",
                res.id
            )));
        }
        Ok((d, Some(PasswordSpec { hash })))
    }

    /// RHEL-family major version 9 (Rocky, Alma, RHEL): shadow-utils and
    /// libxcrypt there are built without yescrypt (Red Hat bz 2151145).
    fn is_el9(&self) -> bool {
        self.facts.os_family == "redhat" && self.facts.os_version.split('.').next() == Some("9")
    }

    /// The stored password field of a local user: `getent -s files shadow`
    /// under sudo, in memory only. A failed or denied read is an error, never
    /// "no change".
    fn observe_password(&mut self, name: &str, sensitive: bool) -> Result<Zeroizing<String>> {
        let what = shown(name, sensitive);
        let mut out = self
            .fs
            .account_getent(true, "shadow", Some(name), sensitive)?;
        let field = match out.completion {
            Completion::Exited(0) => {
                single_record(&out, "the password database").and_then(|line| {
                    let mut f = line.split(':');
                    match (f.next(), f.next()) {
                        (Some(n), Some(h)) if n == name => Ok(Zeroizing::new(h.to_string())),
                        _ => Err(SinterError::apply(format!(
                            "the password database returned a malformed record for {}",
                            what
                        ))),
                    }
                })
            }
            // The passwd entry is local, so a missing or unreadable shadow
            // record is something this resource cannot manage.
            Completion::Exited(2) => Err(SinterError::apply(format!(
                "the password database has no readable record for local user {}",
                what
            ))),
            _ => Err(lookup_failure("the password database", &out)),
        };
        zeroize::Zeroize::zeroize(&mut out.stdout);
        field
    }

    /// Add the `password_hash` dimension to `c`. The observed and desired
    /// values are never put into it.
    fn password_compare(
        &mut self,
        d: &UserDesired,
        o: &UserObservation,
        pw: &Option<PasswordSpec>,
        sensitive: bool,
        c: &mut Compare,
    ) -> Result<()> {
        let (Some(pw), Lookup::Local(_), true) = (pw, &o.user, d.present) else {
            return Ok(());
        };
        let field = self.observe_password(&d.name, sensitive)?;
        match crate::passwd_hash::relate(&field, &pw.hash) {
            crate::passwd_hash::Relation::Same => {}
            crate::passwd_hash::Relation::Differs => {
                c.dims
                    .push(dim("password_hash", "(redacted)", "(redacted)"));
            }
            crate::passwd_hash::Relation::DiffersLocked => {
                c.dims
                    .push(dim("password_hash", "(redacted)", "(redacted)"));
                c.refusals.push(LOCKED_REFUSAL.to_string());
            }
        }
        Ok(())
    }

    /// [`Self::password_compare`] for callers that own the comparison.
    pub(crate) fn compare_password(
        &mut self,
        d: &UserDesired,
        o: &UserObservation,
        pw: &Option<PasswordSpec>,
        sensitive: bool,
        mut c: Compare,
    ) -> Result<Compare> {
        self.password_compare(d, o, pw, sensitive, &mut c)?;
        Ok(c)
    }

    pub(crate) fn run_user(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let vals = self.eval_with(res, item)?;
        let sensitive = res.sensitive || res.derived_sensitive;
        let (d, pw) = self.desired_user(res, &vals, sensitive)?;
        let obs = self.observe_user(&d, sensitive)?;
        let mut c = compare_user(&d, &obs)?;
        self.password_compare(&d, &obs, &pw, sensitive, &mut c)?;
        if let Some(r) = c.refusals.first() {
            return Err(self.account_err(format!(
                "{}: refusing to change user {}: {}",
                res.id,
                shown(&d.name, sensitive),
                refusal_text(r, sensitive)
            )));
        }
        if !c.missing_groups.is_empty() {
            let producers = self.account_producers(res, "group")?;
            let uncovered: Vec<&String> = c
                .missing_groups
                .iter()
                .filter(|g| !producers.contains(g))
                .collect();
            if self.opts.mode == Mode::Plan && uncovered.is_empty() {
                // Every missing group is created by an explicit dependency:
                // the outcome cannot be known before that dependency applies.
                let mut r = unknown_result(res);
                r.reason = Some("deferred/unknown until dependency apply: a declared group is created by a dependency".into());
                r.verification = Verification::NotPerformed;
                return Ok(r);
            }
            return Err(self.account_err(format!(
                "{}: group {} does not exist; declare a group resource and list it in depends_on",
                res.id,
                if sensitive {
                    "[redacted]".to_string()
                } else {
                    uncovered
                        .first()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| c.missing_groups[0].clone())
                }
            )));
        }
        if c.dims.is_empty() {
            return Ok(unchanged_account(res, "user already matches desired state"));
        }
        let created = matches!(obs.user, Lookup::Absent);
        let primary_gid_before = match &obs.user {
            Lookup::Local(u) => Some(u.gid),
            _ => None,
        };
        let deleting = matches!(obs.user, Lookup::Local(_)) && !d.present;
        if created && d.group.is_none() {
            // Without `group`, useradd creates a same-named private group and
            // fails when one already exists. Say so before anything runs,
            // for a group that exists now or that a dependency creates.
            let same_name_dependency = self.account_producers(res, "group")?.contains(&d.name);
            let exists = lookup_group(&mut self.fs, &d.name, sensitive)? != Lookup::Absent;
            if exists || same_name_dependency {
                return Err(self.account_err(format!(
                    "{}: refusing to create user {} without a primary group: a group of the same name exists; \
                     declare group: to use it",
                    res.id,
                    shown(&d.name, sensitive)
                )));
            }
        }
        if created {
            if let Some(uid) = d.uid {
                if lookup_user_uid(&mut self.fs, uid, sensitive)? != Lookup::Absent {
                    return Err(self.account_err(format!(
                        "{}: refusing to create user {}: uid {} is already in use",
                        res.id,
                        shown(&d.name, sensitive),
                        if sensitive {
                            "[redacted]".to_string()
                        } else {
                            uid.to_string()
                        }
                    )));
                }
            }
        }
        if let (true, Lookup::Local(u)) = (deleting, &obs.user) {
            if let Some(why) = self.protected_user(u) {
                return Err(self.account_err(format!(
                    "{}: refusing to delete user {}: {}",
                    res.id,
                    shown(&d.name, sensitive),
                    why
                )));
            }
        }
        if self.opts.mode == Mode::Plan {
            let mut r = planned_account(res, sensitive, &c.dims, describe_user(&d));
            if deleting {
                r.notes
                    .push("home directory and mail spool are kept".to_string());
            }
            return Ok(r);
        }

        // Records needed to report the side effects of userdel.
        let private_group = match (deleting, primary_gid_before) {
            (true, Some(gid)) => match lookup_group_gid(&mut self.fs, gid, sensitive) {
                Ok(Lookup::Local(g)) if g.name == d.name => Some(g.name),
                _ => None,
            },
            _ => None,
        };
        let uid_before = match &obs.user {
            Lookup::Local(u) => Some(u.uid),
            _ => None,
        };

        // Account attributes first (useradd/usermod/userdel), then the
        // password. A password-only drift runs chpasswd alone.
        let base_dims = c.dims.iter().any(|x| x.dimension != "password_hash");
        let set_password = d.present
            && pw.is_some()
            && (created || c.dims.iter().any(|x| x.dimension == "password_hash"));
        if base_dims {
            let (program, args) = match (&obs.user, d.present) {
                (Lookup::Absent, true) => (USERADD, useradd_args(&d)),
                (Lookup::Local(u), true) => (USERMOD, usermod_args(&d, &obs, u)),
                (Lookup::Local(_), false) => (USERDEL, vec![d.name.clone()]),
                _ => unreachable!("an absent user that should be absent has no drift"),
            };
            if let Err(r) = self.account_exec(res, sensitive, program, args, None) {
                return Ok(*r);
            }
        }
        if let (true, Some(pw)) = (set_password, &pw) {
            let input = crate::passwd_hash::chpasswd_input(&d.name, &pw.hash);
            if let Err(mut r) =
                self.account_exec(res, true, CHPASSWD, vec!["-e".to_string()], Some(input))
            {
                if base_dims {
                    // The account was already created or changed: say so, and
                    // that the password is what is missing. A re-run converges.
                    r.change = Change::Changed;
                    r.reason = Some(
                        "the account was changed but its password could not be set; \
                         run again to finish"
                            .to_string(),
                    );
                } else {
                    r.reason = Some("the password could not be set".to_string());
                }
                return Ok(*r);
            }
        }
        let mut r = changed_account(res, sensitive);
        let after = self.observe_user(&d, sensitive).and_then(|after| {
            let mut c = compare_user(&d, &after)?;
            self.password_compare(&d, &after, &pw, sensitive, &mut c)?;
            Ok(c)
        });
        match after {
            Ok(after)
                if after.dims.is_empty()
                    && after.refusals.is_empty()
                    && after.missing_groups.is_empty() =>
            {
                r.verification = Verification::Verified;
            }
            Ok(_) => {
                r.execution = Execution::Failed;
                r.verification = Verification::Failed;
                r.reason = Some("user did not reach the desired state after the mutation".into());
            }
            Err(e) => reobserve_failed(&mut r, &e),
        }
        if created && d.group.is_none() && r.verification == Verification::Verified {
            if let Ok(Lookup::Local(_)) = lookup_group(&mut self.fs, &d.name, sensitive) {
                r.notes.push(if sensitive {
                    "useradd created the user's private group (distribution default)".to_string()
                } else {
                    format!(
                        "useradd created the private group {} (distribution default; declare group: to choose)",
                        d.name
                    )
                });
            }
        }
        if deleting && r.verification == Verification::Verified {
            r.notes
                .push("home directory and mail spool were kept".to_string());
            if let Some(uid) = uid_before {
                r.notes.push(if sensitive {
                    "files owned by the removed uid remain; none were searched for or changed"
                        .to_string()
                } else {
                    format!(
                        "files owned by uid {} remain; none were searched for or changed",
                        uid
                    )
                });
            }
            if let Some(g) = private_group {
                if let Ok(Lookup::Absent) = lookup_group(&mut self.fs, &g, sensitive) {
                    r.notes.push(if sensitive {
                        "userdel also removed the user's private group (USERGROUPS_ENAB)"
                            .to_string()
                    } else {
                        format!(
                            "userdel also removed the user's private group {} (USERGROUPS_ENAB)",
                            g
                        )
                    });
                }
            }
        }
        Ok(r)
    }

    /// Dispatch one account-management command. `Err` carries the finished
    /// resource result for a command that failed or did not complete; a
    /// dispatch failure before the command started is an ordinary error.
    fn account_exec(
        &mut self,
        res: &FrozenResource,
        sensitive: bool,
        program: &str,
        args: Vec<String>,
        stdin: Option<Zeroizing<Vec<u8>>>,
    ) -> std::result::Result<(), Box<ResourceResult>> {
        let permit = self.fs.mutation_permit().map_err(|e| {
            let mut r = changed_account(res, sensitive);
            r.change = Change::None;
            r.execution = Execution::Failed;
            r.reason = Some(e.message);
            Box::new(r)
        })?;
        let mut req = ExecRequest::new(program);
        req.args = args;
        req.env = crate::resources::baseline_env(self.fs.home_env());
        req.sensitive = sensitive;
        req.timeout_secs = 60;
        // Standard input may carry a password hash: it is zeroized when the
        // request is dropped and never recorded.
        req.stdin = stdin.as_ref().map(|b| b.to_vec());
        let verb = program.rsplit('/').next().unwrap_or(program);
        let out = match self.fs.exec(&permit, &req) {
            Ok(o) => o,
            Err(e) => {
                // The failure may have come after the command started (for
                // example while waiting for it), so no change is not proven.
                let mut r = changed_account(res, sensitive);
                r.change = Change::Possible;
                r.execution = if e.kind == ErrorKind::Indeterminate {
                    Execution::Indeterminate
                } else {
                    Execution::Failed
                };
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "{} did not complete cleanly: {}",
                    verb,
                    if sensitive { "[redacted]" } else { &e.message }
                ));
                return Err(Box::new(r));
            }
        };
        match out.completion {
            Completion::Exited(0) => Ok(()),
            Completion::Exited(code) => {
                let mut r = changed_account(res, sensitive);
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(if sensitive {
                    format!("{} failed with exit code {}", verb, code)
                } else {
                    format!(
                        "{} failed with exit code {}: {}",
                        verb,
                        code,
                        String::from_utf8_lossy(&out.stderr).trim()
                    )
                });
                Err(Box::new(r))
            }
            Completion::Signaled(s) => {
                let mut r = changed_account(res, sensitive);
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!("{} terminated by signal {}", verb, s));
                Err(Box::new(r))
            }
            Completion::Indeterminate { reason, .. } => {
                let mut r = changed_account(res, sensitive);
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!("{} did not complete: {}", verb, reason));
                Err(Box::new(r))
            }
        }
    }
}

fn unchanged_account(res: &FrozenResource, reason: &str) -> ResourceResult {
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

fn changed_account(res: &FrozenResource, sensitive: bool) -> ResourceResult {
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

/// The refusal for a locked account whose password hash differs (fixed text,
/// safe to show for a sensitive resource).
const LOCKED_REFUSAL: &str = "the account is locked with a different password hash; setting \
     the declared hash would unlock it, and this resource has no lock field";

/// A refusal reason, without the ids when the resource is sensitive.
fn refusal_text(r: &str, sensitive: bool) -> &str {
    if sensitive && r != LOCKED_REFUSAL {
        "an existing account is never renumbered"
    } else {
        r
    }
}

fn planned_account(
    res: &FrozenResource,
    sensitive: bool,
    dims: &[Dim],
    desired: String,
) -> ResourceResult {
    let mut r = changed_account(res, sensitive);
    if sensitive {
        // No renderer or transport may show account attributes.
        r.diff = Some(Diff {
            body: DiffBody::Redacted,
        });
        return r;
    }
    let (current, dim_desired) = describe_dims(dims);
    let is_state = dims.iter().any(|d| d.dimension == "state");
    r.diff = Some(Diff {
        body: DiffBody::Summary {
            current: if is_state {
                dims.iter()
                    .find(|d| d.dimension == "state")
                    .map(|d| d.observed.clone())
                    .unwrap_or_default()
            } else {
                current
            },
            desired: if is_state { desired } else { dim_desired },
        },
    });
    r
}

fn redact_text(id: &str, what: &str, detail: &str) -> SinterError {
    SinterError::apply(format!("{}: {} (value redacted): {}", id, what, detail))
}

/// The mutation is known to have succeeded; only the verification failed.
fn reobserve_failed(r: &mut ResourceResult, e: &SinterError) {
    r.change = Change::Changed;
    r.execution = if e.kind == ErrorKind::Indeterminate {
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
        "the mutation succeeded but re-observation failed: {}",
        e.message
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["app", "_svc", "a-b_c9", "x", "a".repeat(32).as_str()] {
            assert!(valid_account_name(ok), "{}", ok);
        }
        for bad in [
            "",
            "App",
            "9app",
            "-app",
            "a:b",
            "a,b",
            "a b",
            "a\nb",
            "a.b",
            "a$",
            "root!",
            "a".repeat(33).as_str(),
            "1000",
            "é",
        ] {
            assert!(!valid_account_name(bad), "{:?}", bad);
        }
    }

    #[test]
    fn paths() {
        assert!(valid_account_path("/usr/sbin/nologin"));
        assert!(valid_account_path("/var/lib/app"));
        for bad in [
            "", "/", "rel/x", "/a:b", "/a,b", "/a\nb", "/a/../b", "/a/", "/a//b",
        ] {
            assert!(!valid_account_path(bad), "{:?}", bad);
        }
    }

    #[test]
    fn group_line() {
        let g = parse_group_line("app:x:990:alice,bob").unwrap();
        assert_eq!((g.gid, g.members.len()), (990, 2));
        assert!(parse_group_line("app:x:990").is_none());
        assert!(parse_group_line("app:x:nope:").is_none());
        assert!(parse_group_line(":x:1:").is_none());
        assert!(parse_group_line("app:x:1::extra").is_none());
    }

    #[test]
    fn user_line() {
        let u = parse_user_line("app:x:990:990::/var/lib/app:/usr/sbin/nologin").unwrap();
        assert_eq!(
            (u.uid, u.gid, u.shell.as_str()),
            (990, 990, "/usr/sbin/nologin")
        );
        assert!(parse_user_line("app:x:990:990::/var/lib/app").is_none());
        assert!(parse_user_line("app:x:a:990::/h:/s").is_none());
    }

    fn ud(name: &str) -> UserDesired {
        UserDesired {
            name: name.into(),
            present: true,
            uid: None,
            group: None,
            groups: vec![],
            shell: None,
            home: None,
            create_home: false,
            system: false,
        }
    }

    #[test]
    fn useradd_argv_is_explicit() {
        let mut d = ud("app");
        assert_eq!(useradd_args(&d), ["-M", "app"]);
        d.system = true;
        d.uid = Some(990);
        d.group = Some("app".into());
        d.groups = vec!["a".into(), "b".into()];
        d.shell = Some("/usr/sbin/nologin".into());
        d.home = Some("/var/lib/app".into());
        d.create_home = true;
        assert_eq!(
            useradd_args(&d),
            [
                "--system",
                "-u",
                "990",
                "-g",
                "app",
                "-G",
                "a,b",
                "-s",
                "/usr/sbin/nologin",
                "-d",
                "/var/lib/app",
                "-m",
                "app"
            ]
        );
    }

    #[test]
    fn usermod_never_moves_home_or_removes_groups() {
        let mut d = ud("app");
        d.home = Some("/srv/app".into());
        d.groups = vec!["extra".into()];
        let u = UserRec {
            name: "app".into(),
            uid: 990,
            gid: 990,
            home: "/var/lib/app".into(),
            shell: "/bin/sh".into(),
        };
        let o = UserObservation {
            user: Lookup::Local(u.clone()),
            primary: None,
            supplementary: vec![(
                "extra".into(),
                Lookup::Local(GroupRec {
                    name: "extra".into(),
                    gid: 5,
                    members: vec![],
                }),
            )],
        };
        let a = usermod_args(&d, &o, &u);
        assert_eq!(a, ["-d", "/srv/app", "-a", "-G", "extra", "app"]);
        assert!(!a.iter().any(|x| x == "-m" || x == "-r" || x == "-f"));
    }

    #[test]
    fn compare_refuses_renumbering() {
        let mut d = ud("app");
        d.uid = Some(991);
        let u = UserRec {
            name: "app".into(),
            uid: 990,
            gid: 990,
            home: "/h".into(),
            shell: "/s".into(),
        };
        let o = UserObservation {
            user: Lookup::Local(u),
            primary: None,
            supplementary: vec![],
        };
        let c = compare_user(&d, &o).unwrap();
        assert_eq!(c.refusals.len(), 1);
        assert_eq!(c.dims[0].dimension, "uid");
    }

    #[test]
    fn nss_only_is_an_error_not_a_create() {
        let d = ud("app");
        let o = UserObservation {
            user: Lookup::NssOnly,
            primary: None,
            supplementary: vec![],
        };
        assert!(compare_user(&d, &o).is_err());
        let g = GroupDesired {
            name: "app".into(),
            present: true,
            gid: None,
            system: false,
        };
        assert!(compare_group(&g, &Lookup::NssOnly).is_err());
    }
}
