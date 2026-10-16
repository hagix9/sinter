//! `postgresql_role`: one role of a local PostgreSQL server (S151-29, P2-05).
//!
//! Contract:
//!
//! * the role is reached through the server's local socket as the operating
//!   system account that owns the cluster (`os_user`, default `postgres`),
//!   with `psql` started through `setpriv` (peer authentication; no password
//!   is ever used to connect). This needs root on the target;
//! * only the attributes a recipe declares are managed (`login`, `superuser`,
//!   `createdb`, `createrole`, `inherit`, `replication`, `bypassrls`,
//!   `connection_limit`, `password_verifier`); everything else is left alone,
//!   and a new role gets PostgreSQL's own defaults for what is not declared
//!   (`NOSUPERUSER`, `NOLOGIN`, ...). Nothing is ever granted implicitly;
//! * `state: absent` is `DROP ROLE` without `CASCADE`: PostgreSQL refuses to
//!   drop a role that still owns objects or holds privileges, and that refusal
//!   is the result. A role is only dropped when a recipe declares it absent;
//! * the role Sinter connects as (`os_user`) is never dropped and never has
//!   `superuser` or `login` removed: that would cut off Sinter's own access;
//! * the password is a **SCRAM-SHA-256 verifier** read from an encrypted
//!   secret (`password_verifier: { secret: <path> }`). Sinter never sees,
//!   accepts or sends a plaintext password, and refuses an `md5` hash or a
//!   plaintext-looking value. PostgreSQL 10 and later store a SCRAM verifier
//!   exactly as given, whatever `password_encryption` says;
//! * the verifier is secret material: it travels only on `psql`'s standard
//!   input, never in argv, an environment variable, a temporary file, plan,
//!   audit, a reason or a log record. The observed verifier is compared in
//!   memory (constant time) and zeroized;
//! * the server must not log the statement that carries it. Before any
//!   change, the session sets `log_min_messages`, `log_min_error_statement`
//!   and `log_statement` (and the duration/sampling/debug logging, statistics
//!   and `pgaudit` settings that could record statement text) to their
//!   silent values, then reads them back with `current_setting`. Only when
//!   every one is verified does psql's `\if` let the change run; otherwise
//!   nothing carrying the verifier is sent and the resource fails;
//! * observation is one read-only `SELECT` on `pg_authid` passed in argv (it
//!   names only the role). Role names are restricted to
//!   `[a-z_][a-z0-9_]{0,62}` (no `pg_` prefix) and verifiers to the SCRAM
//!   alphabet, so neither can contain a quote: the generated SQL can never be
//!   anything but the statements Sinter writes (no SQL injection).

use crate::engine::{unknown_result, Engine, Mode};
use crate::error::{ErrorKind, Result, SinterError};
use crate::executor::{Completion, ExecRequest, Output};
use crate::expressions::EvalVal;
use crate::model::FrozenResource;
use crate::resources::{ev_bool, ev_int, ev_str};
use crate::result::*;
use crate::value::Value;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The fields of a `postgresql_role` resource.
pub const PGROLE_FIELDS: &[&str] = &[
    "name",
    "state",
    "login",
    "superuser",
    "createdb",
    "createrole",
    "inherit",
    "replication",
    "bypassrls",
    "connection_limit",
    "password_verifier",
    "os_user",
    "psql",
    "port",
    "database",
];

const DEFAULT_OS_USER: &str = "postgres";
const DEFAULT_PSQL: &str = "/usr/bin/psql";
const DEFAULT_DATABASE: &str = "postgres";
const SETPRIV: &str = "/usr/bin/setpriv";

/// The first column of the observation query: proves the row is the answer
/// to this query, not some other output.
const OBS_TAG: &str = "sinter-pgrole-1";
/// What psql prints after the change ran and committed.
const APPLIED_MARK: &str = "sinter-pgrole-applied";
/// What psql prints when the log suppression could not be verified (nothing
/// carrying the verifier was sent).
const UNQUIET_MARK: &str = "sinter-pgrole-unquiet";

/// Oldest server this resource supports (PostgreSQL 10: SCRAM verifiers,
/// `current_setting(name, missing_ok)`, psql `\if`).
const MIN_SERVER_VERSION: u32 = 100_000;

/// Fixed text for any rejected secret (never contains the value).
pub(crate) const VERIFIER_REJECTED: &str = "the secret is not an accepted SCRAM-SHA-256 \
     verifier (one SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey> value, at least \
     4096 iterations, optionally followed by a single newline); plaintext passwords and md5 \
     hashes are not accepted";

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

/// A role name Sinter manages: `[a-z_][a-z0-9_]{0,62}`, not `pg_*` (reserved
/// by PostgreSQL). Lowercase only, so the quoted identifier equals the name
/// PostgreSQL folds an unquoted one to; it can never contain a quote.
pub fn valid_role_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
        && !s.starts_with("pg_")
}

/// The `psql` binaries Sinter runs, as the cluster owner, during plan, apply
/// and audit: the distribution's `/usr/bin/psql` or a PGDG
/// `/usr/pgsql-<major>/bin/psql` (both root-owned package paths). A recipe
/// (or an MCP manifest) can never choose another executable to run while
/// observing.
pub fn allowed_psql(p: &str) -> bool {
    if p == DEFAULT_PSQL {
        return true;
    }
    let Some(major) = p
        .strip_prefix("/usr/pgsql-")
        .and_then(|r| r.strip_suffix("/bin/psql"))
    else {
        return false;
    };
    !major.is_empty()
        && major.len() <= 3
        && !major.starts_with('0')
        && major.bytes().all(|b| b.is_ascii_digit())
}

/// A database name to connect to: same alphabet as a role name.
fn valid_database_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

fn b64(s: &str) -> bool {
    !s.is_empty()
        && s.len().is_multiple_of(4)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        && !s.trim_end_matches('=').contains('=')
        && s.len() - s.trim_end_matches('=').len() <= 2
}

/// Whether `v` is exactly one SCRAM-SHA-256 verifier as PostgreSQL stores it:
/// `SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>`, iterations 4096 or
/// more, every key 32 bytes (44 base64 characters).
pub(crate) fn valid_scram_verifier(v: &str) -> bool {
    let Some(rest) = v.strip_prefix("SCRAM-SHA-256$") else {
        return false;
    };
    let Some((iter_salt, keys)) = rest.split_once('$') else {
        return false;
    };
    let Some((iter, salt)) = iter_salt.split_once(':') else {
        return false;
    };
    let Some((stored, server)) = keys.split_once(':') else {
        return false;
    };
    let iter_ok = !iter.is_empty()
        && iter.len() <= 10
        && !iter.starts_with('0')
        && iter.bytes().all(|b| b.is_ascii_digit())
        && iter
            .parse::<u64>()
            .is_ok_and(|n| (4096..=2_147_483_647).contains(&n));
    // A 32-byte key is exactly 44 base64 characters ending in a single `=`.
    // Anything else PostgreSQL does not parse as a verifier and would store
    // as a *plaintext* password (hashing the verifier text itself).
    let key32 = |k: &str| k.len() == 44 && b64(k) && k.ends_with('=') && !k.ends_with("==");
    iter_ok && b64(salt) && salt.len() <= 256 && key32(stored) && key32(server)
}

/// Read a verifier from decrypted secret bytes: UTF-8, at most one trailing
/// newline removed, the rest exactly one verifier.
pub(crate) fn parse_verifier_secret(bytes: &[u8]) -> std::result::Result<Zeroizing<String>, ()> {
    if bytes.len() > 512 {
        return Err(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if !valid_scram_verifier(text) {
        return Err(());
    }
    Ok(Zeroizing::new(text.to_string()))
}

fn literal(v: &Value) -> Option<&str> {
    match v {
        Value::Str(s) if !crate::expressions::has_interpolation(s) => Some(s),
        _ => None,
    }
}

fn interpolated(v: &Value) -> bool {
    matches!(v, Value::Str(s) if crate::expressions::has_interpolation(s))
}

/// Load-time checks of the literal fields of a `postgresql_role` (the name
/// itself is checked by the caller, which also knows its sensitivity).
pub(crate) fn validate_literals(with: &BTreeMap<String, Value>, ctx: &str) -> Result<()> {
    let schema = |m: String| SinterError::schema(format!("{}: {}", ctx, m));
    if let Some(v) = with.get("state") {
        let ok = interpolated(v) || matches!(literal(v), Some("present") | Some("absent"));
        if !ok {
            return Err(schema(
                "postgresql_role state must be present or absent".into(),
            ));
        }
    }
    for key in [
        "login",
        "superuser",
        "createdb",
        "createrole",
        "inherit",
        "replication",
        "bypassrls",
    ] {
        if let Some(v) = with.get(key) {
            if v.as_bool().is_none() && !interpolated(v) {
                return Err(schema(format!("{} must be a boolean", key)));
            }
        }
    }
    if let Some(v) = with.get("connection_limit") {
        match v.as_int() {
            Some(n) if (-1..=i32::MAX as i64).contains(&n) => {}
            None if interpolated(v) => {}
            _ => {
                return Err(schema(
                    "connection_limit must be an integer of -1 (no limit) or more".into(),
                ))
            }
        }
    }
    if let Some(v) = with.get("password_verifier") {
        match crate::secret_source::content_shape(v) {
            Ok(crate::secret_source::ContentShape::Secret(_)) => {}
            _ => {
                return Err(schema(
                    "password_verifier must be { secret: <path> } (a verifier is secret and is \
                     never written in a recipe)"
                        .into(),
                ))
            }
        }
        if matches!(with.get("state"), Some(Value::Str(s)) if s == "absent") {
            return Err(schema(
                "password_verifier cannot be combined with state: absent".into(),
            ));
        }
    }
    if let Some(v) = with.get("os_user") {
        match literal(v) {
            Some(s) if crate::accounts::valid_account_name(s) => {}
            None if interpolated(v) => {}
            _ => return Err(schema("os_user must be a valid account name".into())),
        }
    }
    if let Some(v) = with.get("psql") {
        match literal(v) {
            Some(s) if allowed_psql(s) => {}
            None if interpolated(v) => {}
            _ => {
                return Err(schema(
                    "psql must be /usr/bin/psql or /usr/pgsql-<major>/bin/psql".into(),
                ))
            }
        }
    }
    if let Some(v) = with.get("port") {
        match v.as_int() {
            Some(n) if (1..=65535).contains(&n) => {}
            None if interpolated(v) => {}
            _ => return Err(schema("port must be an integer in 1..65535".into())),
        }
    }
    if let Some(v) = with.get("database") {
        match literal(v) {
            Some(s) if valid_database_name(s) => {}
            None if interpolated(v) => {}
            _ => {
                return Err(schema(
                    "database must be a name of lowercase letters, digits and _".into(),
                ))
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// desired / observed
// ---------------------------------------------------------------------------

/// The boolean role attributes, in observation-column order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attr {
    Login,
    Superuser,
    CreateDb,
    CreateRole,
    Inherit,
    Replication,
    BypassRls,
}

const ATTRS: [Attr; 7] = [
    Attr::Login,
    Attr::Superuser,
    Attr::CreateDb,
    Attr::CreateRole,
    Attr::Inherit,
    Attr::Replication,
    Attr::BypassRls,
];

impl Attr {
    fn field(self) -> &'static str {
        match self {
            Attr::Login => "login",
            Attr::Superuser => "superuser",
            Attr::CreateDb => "createdb",
            Attr::CreateRole => "createrole",
            Attr::Inherit => "inherit",
            Attr::Replication => "replication",
            Attr::BypassRls => "bypassrls",
        }
    }
    fn column(self) -> &'static str {
        match self {
            Attr::Login => "rolcanlogin",
            Attr::Superuser => "rolsuper",
            Attr::CreateDb => "rolcreatedb",
            Attr::CreateRole => "rolcreaterole",
            Attr::Inherit => "rolinherit",
            Attr::Replication => "rolreplication",
            Attr::BypassRls => "rolbypassrls",
        }
    }
    fn keyword(self, on: bool) -> &'static str {
        match (self, on) {
            (Attr::Login, true) => "LOGIN",
            (Attr::Login, false) => "NOLOGIN",
            (Attr::Superuser, true) => "SUPERUSER",
            (Attr::Superuser, false) => "NOSUPERUSER",
            (Attr::CreateDb, true) => "CREATEDB",
            (Attr::CreateDb, false) => "NOCREATEDB",
            (Attr::CreateRole, true) => "CREATEROLE",
            (Attr::CreateRole, false) => "NOCREATEROLE",
            (Attr::Inherit, true) => "INHERIT",
            (Attr::Inherit, false) => "NOINHERIT",
            (Attr::Replication, true) => "REPLICATION",
            (Attr::Replication, false) => "NOREPLICATION",
            (Attr::BypassRls, true) => "BYPASSRLS",
            (Attr::BypassRls, false) => "NOBYPASSRLS",
        }
    }
    fn index(self) -> usize {
        ATTRS.iter().position(|a| *a == self).unwrap_or(0)
    }
}

pub(crate) struct RoleDesired {
    pub name: String,
    pub present: bool,
    pub attrs: Vec<(Attr, bool)>,
    pub conn_limit: Option<i64>,
    pub os_user: String,
    pub psql: String,
    pub port: Option<i64>,
    pub database: String,
}

pub(crate) fn role_desired(
    res: &FrozenResource,
    vals: &BTreeMap<String, EvalVal>,
) -> Result<RoleDesired> {
    let name = ev_str(vals, "name")?
        .map(|(s, _)| s)
        .ok_or_else(|| SinterError::schema(format!("{}: postgresql_role needs a name", res.id)))?;
    if !valid_role_name(&name) {
        return Err(SinterError::apply(format!(
            "{}: postgresql_role name is not a valid role name",
            res.id
        )));
    }
    let present = match ev_str(vals, "state")?.map(|(s, _)| s).as_deref() {
        None | Some("present") => true,
        Some("absent") => false,
        Some(_) => {
            return Err(SinterError::apply(format!(
                "{}: postgresql_role state must resolve to present or absent",
                res.id
            )))
        }
    };
    let mut attrs = Vec::new();
    for a in ATTRS {
        if let Some(b) = ev_bool(vals, a.field())? {
            attrs.push((a, b));
        }
    }
    let conn_limit = ev_int(vals, "connection_limit")?;
    if let Some(n) = conn_limit {
        if !(-1..=i32::MAX as i64).contains(&n) {
            return Err(SinterError::apply(format!(
                "{}: connection_limit must be -1 or more",
                res.id
            )));
        }
    }
    let os_user = ev_str(vals, "os_user")?
        .map(|(s, _)| s)
        .unwrap_or_else(|| DEFAULT_OS_USER.to_string());
    if !crate::accounts::valid_account_name(&os_user) {
        return Err(SinterError::apply(format!(
            "{}: os_user must be a valid account name",
            res.id
        )));
    }
    let psql = ev_str(vals, "psql")?
        .map(|(s, _)| s)
        .unwrap_or_else(|| DEFAULT_PSQL.to_string());
    if !allowed_psql(&psql) {
        return Err(SinterError::apply(format!(
            "{}: psql must be /usr/bin/psql or /usr/pgsql-<major>/bin/psql",
            res.id
        )));
    }
    let port = ev_int(vals, "port")?;
    if let Some(p) = port {
        if !(1..=65535).contains(&p) {
            return Err(SinterError::apply(format!(
                "{}: port must be in 1..65535",
                res.id
            )));
        }
    }
    let database = ev_str(vals, "database")?
        .map(|(s, _)| s)
        .unwrap_or_else(|| DEFAULT_DATABASE.to_string());
    if !valid_database_name(&database) {
        return Err(SinterError::apply(format!(
            "{}: database is not a valid name",
            res.id
        )));
    }
    if !present && (!attrs.is_empty() || conn_limit.is_some() || res.secret.is_some()) {
        return Err(SinterError::apply(format!(
            "{}: an absent postgresql_role cannot declare attributes or a password",
            res.id
        )));
    }
    Ok(RoleDesired {
        name,
        present,
        attrs,
        conn_limit,
        os_user,
        psql,
        port,
        database,
    })
}

/// One observed role (or its absence) and the server it lives on.
pub(crate) struct RoleObserved {
    pub server_version: u32,
    pub role: Option<RoleRow>,
}

pub(crate) struct RoleRow {
    pub attrs: [bool; 7],
    pub conn_limit: i64,
    /// The stored password field — only read when a verifier is declared.
    pub verifier: Option<Zeroizing<String>>,
}

/// The read-only observation query: one row always (a LEFT JOIN on a
/// one-row relation), so "no such role" is a positive answer and an empty
/// capture is a failure. It names only the role.
fn observation_query(name: &str, with_verifier: bool) -> String {
    let cols: Vec<String> = ATTRS.iter().map(|a| format!("r.{}", a.column())).collect();
    format!(
        "SELECT '{tag}', current_setting('server_version_num'), r.rolname IS NOT NULL, {cols}, \
         r.rolconnlimit, r.rolpassword IS NOT NULL{pw} FROM (SELECT 1) AS one LEFT JOIN \
         pg_catalog.pg_authid AS r ON r.rolname = '{name}'",
        tag = OBS_TAG,
        cols = cols.join(", "),
        pw = if with_verifier {
            ", coalesce(r.rolpassword, '')"
        } else {
            ""
        },
        name = name
    )
}

fn parse_bool(t: &str) -> Option<bool> {
    match t {
        "t" => Some(true),
        "f" => Some(false),
        _ => None,
    }
}

/// Parse the observation answer (`psql -A -t -F '|'`): exactly one line of
/// exactly the expected fields. Anything else is not this query's answer.
pub(crate) fn parse_observation(stdout: &[u8], with_verifier: bool) -> Option<RoleObserved> {
    let text = std::str::from_utf8(stdout).ok()?;
    let text = text.strip_suffix('\n')?;
    if text.contains('\n') {
        return None;
    }
    let f: Vec<&str> = text.split('|').collect();
    let want = if with_verifier { 13 } else { 12 };
    if f.len() != want || f[0] != OBS_TAG {
        return None;
    }
    if f[1].is_empty() || f[1].len() > 9 || !f[1].bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let server_version: u32 = f[1].parse().ok()?;
    let exists = parse_bool(f[2])?;
    if !exists {
        // Every role column of a missing role is NULL (printed empty), except
        // `rolpassword IS NOT NULL`, which is false — not NULL — for the NULL
        // row of the outer join (measured on PostgreSQL 10).
        if f[3..11].iter().any(|c| !c.is_empty()) || f[11] != "f" {
            return None;
        }
        if with_verifier && !f[12].is_empty() {
            return None;
        }
        return Some(RoleObserved {
            server_version,
            role: None,
        });
    }
    let mut attrs = [false; 7];
    for (i, a) in attrs.iter_mut().enumerate() {
        *a = parse_bool(f[3 + i])?;
    }
    let cl = f[10];
    let conn_limit: i64 = if cl == "-1" {
        -1
    } else if !cl.is_empty() && cl.bytes().all(|b| b.is_ascii_digit()) && cl.len() <= 10 {
        cl.parse().ok()?
    } else {
        return None;
    };
    let has_password = parse_bool(f[11])?;
    let verifier = if with_verifier {
        let v = f[12];
        if has_password == v.is_empty() {
            return None;
        }
        Some(Zeroizing::new(v.to_string()))
    } else {
        None
    };
    Some(RoleObserved {
        server_version,
        role: Some(RoleRow {
            attrs,
            conn_limit,
            verifier,
        }),
    })
}

/// Constant-time equality of two secrets.
fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// One differing dimension. Values are attribute booleans / limits only —
/// a password dimension never carries a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoleDim {
    pub dimension: &'static str,
    pub observed: String,
    pub desired: String,
}

pub(crate) fn compare_role(
    d: &RoleDesired,
    o: &RoleObserved,
    verifier: Option<&Zeroizing<String>>,
) -> Vec<RoleDim> {
    let dim = |dimension, observed: &str, desired: &str| RoleDim {
        dimension,
        observed: observed.to_string(),
        desired: desired.to_string(),
    };
    let mut dims = Vec::new();
    match (&o.role, d.present) {
        (None, true) => dims.push(dim("state", "absent", "present")),
        (None, false) => {}
        (Some(_), false) => dims.push(dim("state", "present", "absent")),
        (Some(r), true) => {
            for (a, want) in &d.attrs {
                let have = r.attrs[a.index()];
                if have != *want {
                    dims.push(dim(a.field(), &have.to_string(), &want.to_string()));
                }
            }
            if let Some(n) = d.conn_limit {
                if n != r.conn_limit {
                    dims.push(dim(
                        "connection_limit",
                        &r.conn_limit.to_string(),
                        &n.to_string(),
                    ));
                }
            }
            if let Some(v) = verifier {
                let same = r.verifier.as_ref().is_some_and(|s| secret_eq(s, v));
                if !same {
                    dims.push(dim("password_verifier", "(redacted)", "(redacted)"));
                }
            }
        }
    }
    dims
}

/// A change that would cut off Sinter's own access to the server.
fn self_lockout(d: &RoleDesired) -> Option<&'static str> {
    if d.name != d.os_user {
        return None;
    }
    if !d.present {
        return Some("it is the role Sinter connects as (os_user); it is never dropped");
    }
    for (a, on) in &d.attrs {
        if !on && matches!(a, Attr::Superuser | Attr::Login) {
            return Some(
                "it is the role Sinter connects as (os_user); its superuser and login \
                 attributes are never removed",
            );
        }
    }
    None
}

/// The change statements (inside the verified-quiet session). `verifier` is
/// already validated (SCRAM alphabet, no quote).
fn change_statements(
    d: &RoleDesired,
    o: &RoleObserved,
    dims: &[RoleDim],
    verifier: Option<&Zeroizing<String>>,
) -> Zeroizing<String> {
    let q = format!("\"{}\"", d.name);
    // Reserved up front: growing the buffer after the verifier is in it would
    // free an unzeroized copy.
    let mut sql = Zeroizing::new(String::with_capacity(
        512 + verifier.map(|v| v.len()).unwrap_or(0),
    ));
    match (&o.role, d.present) {
        (_, false) => sql.push_str(&format!("DROP ROLE {};\n", q)),
        (None, true) => {
            let mut opts: Vec<String> = d
                .attrs
                .iter()
                .map(|(a, on)| a.keyword(*on).to_string())
                .collect();
            if let Some(n) = d.conn_limit {
                opts.push(format!("CONNECTION LIMIT {}", n));
            }
            sql.push_str(&format!("CREATE ROLE {}", q));
            if !opts.is_empty() || verifier.is_some() {
                sql.push_str(" WITH");
            }
            for o in &opts {
                sql.push(' ');
                sql.push_str(o);
            }
            if let Some(v) = verifier {
                sql.push_str(" PASSWORD '");
                sql.push_str(v);
                sql.push('\'');
            }
            sql.push_str(";\n");
        }
        (Some(_), true) => {
            let mut opts: Vec<String> = Vec::new();
            for (a, on) in &d.attrs {
                if dims.iter().any(|x| x.dimension == a.field()) {
                    opts.push(a.keyword(*on).to_string());
                }
            }
            if let Some(n) = d.conn_limit {
                if dims.iter().any(|x| x.dimension == "connection_limit") {
                    opts.push(format!("CONNECTION LIMIT {}", n));
                }
            }
            if !opts.is_empty() {
                sql.push_str(&format!("ALTER ROLE {} WITH {};\n", q, opts.join(" ")));
            }
            if let Some(v) = verifier {
                if dims.iter().any(|x| x.dimension == "password_verifier") {
                    sql.push_str(&format!("ALTER ROLE {} PASSWORD '", q));
                    sql.push_str(v);
                    sql.push_str("';\n");
                }
            }
        }
    }
    sql
}

/// The whole psql script: silence and verify server-side statement logging,
/// then — only when verified — run the change in one transaction.
pub(crate) fn change_script(statements: &str) -> Zeroizing<String> {
    // Reserved up front so the buffer holding the statements never regrows.
    let mut s = Zeroizing::new(String::with_capacity(4096 + statements.len()));
    s.push_str(
        "\\set ON_ERROR_STOP on\n\
         \\set QUIET on\n\
         \\set VERBOSITY terse\n\
         \\set SHOW_CONTEXT never\n\
         SET client_min_messages = 'warning';\n\
         SET log_min_messages = 'panic';\n\
         SET log_min_error_statement = 'panic';\n\
         SET log_statement = 'none';\n\
         SET log_min_duration_statement = -1;\n\
         SET log_duration = off;\n\
         SET debug_print_parse = off;\n\
         SET debug_print_rewritten = off;\n\
         SET debug_print_plan = off;\n\
         SET track_activities = off;\n\
         SET pg_stat_statements.track = 'none';\n\
         SET pg_stat_statements.track_utility = off;\n\
         SET pgaudit.log = 'none';\n\
         SELECT current_setting('server_version_num')::int >= 120000 AS sinter_pg12 \\gset\n\
         \\if :sinter_pg12\n\
         SET log_transaction_sample_rate = 0;\n\
         \\endif\n\
         SELECT current_setting('server_version_num')::int >= 130000 AS sinter_pg13 \\gset\n\
         \\if :sinter_pg13\n\
         SET log_min_duration_sample = -1;\n\
         SET log_statement_sample_rate = 0;\n\
         \\endif\n\
         SELECT current_setting('log_min_messages') = 'panic'\n  \
         AND current_setting('log_min_error_statement') = 'panic'\n  \
         AND current_setting('log_statement') = 'none'\n  \
         AND current_setting('log_min_duration_statement') = '-1'\n  \
         AND current_setting('log_duration') = 'off'\n  \
         AND current_setting('debug_print_parse') = 'off'\n  \
         AND current_setting('debug_print_rewritten') = 'off'\n  \
         AND current_setting('debug_print_plan') = 'off'\n  \
         AND current_setting('track_activities') = 'off'\n  \
         AND current_setting('pg_stat_statements.track', true) = 'none'\n  \
         AND current_setting('pg_stat_statements.track_utility', true) = 'off'\n  \
         AND current_setting('pgaudit.log', true) = 'none'\n  \
         AND coalesce(current_setting('log_transaction_sample_rate', true), '0') = '0'\n  \
         AND coalesce(current_setting('log_min_duration_sample', true), '-1') = '-1'\n  \
         AND coalesce(current_setting('log_statement_sample_rate', true), '0') = '0'\n  \
         AS sinter_quiet \\gset\n\
         \\if :sinter_quiet\n\
         BEGIN;\n",
    );
    s.push_str(statements);
    s.push_str("COMMIT;\n");
    s.push_str(&format!("\\echo {}\n", APPLIED_MARK));
    s.push_str("\\else\n");
    s.push_str(&format!("\\echo {}\n", UNQUIET_MARK));
    s.push_str("\\endif\n");
    s
}

// ---------------------------------------------------------------------------
// engine
// ---------------------------------------------------------------------------

fn shown(name: &str, sensitive: bool) -> &str {
    if sensitive {
        "[redacted]"
    } else {
        name
    }
}

fn base_result(res: &FrozenResource, sensitive: bool) -> ResourceResult {
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

fn unchanged(res: &FrozenResource, sensitive: bool) -> ResourceResult {
    let mut r = base_result(res, sensitive);
    r.change = Change::None;
    r.verification = Verification::Verified;
    r.reason = Some("role already matches desired state".to_string());
    r
}

impl Engine {
    fn pgrole_err(&self, msg: String) -> SinterError {
        if self.opts.mode == Mode::Plan {
            SinterError::plan(msg)
        } else {
            SinterError::apply(msg)
        }
    }

    /// The declared verifier, opened from the resource's secret. Fails with
    /// fixed text before anything is observed.
    pub(crate) fn pgrole_verifier(
        &mut self,
        res: &FrozenResource,
    ) -> Result<Option<Zeroizing<String>>> {
        if res.secret.is_none() {
            return Ok(None);
        }
        let secret = self.open_resource_secret(res)?;
        let v = parse_verifier_secret(secret.expose()).map_err(|_| {
            SinterError::apply(format!(
                "{}: password_verifier: {}",
                res.id, VERIFIER_REJECTED
            ))
        })?;
        drop(secret);
        Ok(Some(v))
    }

    /// uid/gid of the cluster owner, from the local account database.
    fn pgrole_os_identity(&mut self, d: &RoleDesired, sensitive: bool) -> Result<(u32, u32)> {
        let uid = self.fs.resolve_uid_sensitive(&d.os_user, sensitive)?;
        let gid = self.fs.primary_gid_of_uid_sensitive(uid, sensitive)?;
        if uid == 0 {
            return Err(SinterError::apply(
                "os_user resolves to root; psql must run as the account that owns the cluster"
                    .to_string(),
            ));
        }
        Ok((uid, gid))
    }

    fn pgrole_psql_args(d: &RoleDesired) -> Vec<String> {
        let mut a = vec![
            "-X".to_string(),
            "-q".to_string(),
            "-A".to_string(),
            "-t".to_string(),
            "-F".to_string(),
            "|".to_string(),
            "-v".to_string(),
            "ON_ERROR_STOP=1".to_string(),
        ];
        if let Some(p) = d.port {
            a.push("-p".to_string());
            a.push(p.to_string());
        }
        a.push("-d".to_string());
        a.push(d.database.clone());
        a
    }

    fn pgrole_request(
        &self,
        uid: u32,
        gid: u32,
        d: &RoleDesired,
        tail: Vec<String>,
    ) -> ExecRequest {
        let mut args = vec![
            "--reuid".to_string(),
            uid.to_string(),
            "--regid".to_string(),
            gid.to_string(),
            "--init-groups".to_string(),
            "--no-new-privs".to_string(),
            "--".to_string(),
            d.psql.clone(),
        ];
        args.extend(Self::pgrole_psql_args(d));
        args.extend(tail);
        let mut req = ExecRequest::new(SETPRIV);
        req.args = args;
        req.cwd = Some("/".to_string());
        req.env = crate::resources::baseline_env("/".to_string());
        req.env
            .insert("PGCONNECT_TIMEOUT".to_string(), "10".to_string());
        req.timeout_secs = 120;
        req
    }

    /// Observe the role (read-only). The answer may carry the stored
    /// verifier; it is parsed and the capture zeroized.
    pub(crate) fn pgrole_observe(
        &mut self,
        d: &RoleDesired,
        with_verifier: bool,
        sensitive: bool,
    ) -> Result<RoleObserved> {
        if !self.fs.runs_as_root() {
            return Err(self.pgrole_err(
                "postgresql_role needs root: connect as root or use --sudo (psql runs as the \
                 cluster owner through setpriv)"
                    .to_string(),
            ));
        }
        let (uid, gid) = self.pgrole_os_identity(d, sensitive)?;
        let mut req = self.pgrole_request(
            uid,
            gid,
            d,
            vec!["-c".to_string(), observation_query(&d.name, with_verifier)],
        );
        // The answer may hold the verifier; the request is marked sensitive
        // so no record keeps its command line either.
        req.sensitive = sensitive || with_verifier;
        let mut out: Output = self.fs.observe_postgresql(&req)?;
        let parsed = match out.completion {
            Completion::Exited(0) if !out.stdout_truncated => {
                parse_observation(&out.stdout, with_verifier)
            }
            _ => None,
        };
        zeroize::Zeroize::zeroize(&mut out.stdout);
        let completion = out.completion.clone();
        match parsed {
            Some(o) if o.server_version >= MIN_SERVER_VERSION => Ok(o),
            Some(_) => Err(SinterError::apply(
                "the PostgreSQL server is older than 10; postgresql_role needs 10 or later"
                    .to_string(),
            )),
            None => {
                let what = match completion {
                    Completion::Exited(0) => {
                        "returned an answer that is not the role query's".to_string()
                    }
                    Completion::Exited(c) => format!(
                        "exited {} (psql missing, the server not running, or os_user not \
                         allowed to connect)",
                        c
                    ),
                    Completion::Signaled(s) => format!("was terminated by signal {}", s),
                    Completion::Indeterminate { .. } => "did not complete".to_string(),
                };
                let mut e = SinterError::apply(format!(
                    "cannot observe PostgreSQL role {}: psql {} (output withheld)",
                    shown(&d.name, sensitive),
                    what
                ));
                if matches!(completion, Completion::Indeterminate { .. }) {
                    e.kind = ErrorKind::Indeterminate;
                }
                Err(e)
            }
        }
    }

    pub(crate) fn run_postgresql_role(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let vals = self.eval_with(res, item)?;
        let sensitive = res.sensitive || res.derived_sensitive;
        let d = role_desired(res, &vals)?;
        if let Some(why) = self_lockout(&d) {
            return Err(self.pgrole_err(format!(
                "{}: refusing to change PostgreSQL role {}: {}",
                res.id,
                shown(&d.name, sensitive),
                why
            )));
        }
        let verifier = self.pgrole_verifier(res)?;
        let obs = match self.pgrole_observe(&d, verifier.is_some(), sensitive) {
            Ok(o) => o,
            // Plan on a host whose server an earlier resource still has to
            // install or start: the role cannot be observed yet, which is an
            // Unknown, not an error. Apply never guesses.
            Err(e) if self.opts.mode == Mode::Plan && self.planned.opaque.is_some() => {
                let mut r = unknown_result(res);
                r.reason = Some(format!(
                    "the role cannot be observed before earlier planned changes ({}) are \
                     applied: {}",
                    self.planned.opaque.clone().unwrap_or_default(),
                    e.message
                ));
                return Ok(r);
            }
            Err(e) => return Err(e),
        };
        let dims = compare_role(&d, &obs, verifier.as_ref());
        if dims.is_empty() {
            return Ok(unchanged(res, sensitive));
        }
        if self.opts.mode == Mode::Plan {
            let mut r = base_result(res, sensitive);
            r.diff = Some(Diff {
                body: if sensitive {
                    DiffBody::Redacted
                } else {
                    let (cur, want): (Vec<String>, Vec<String>) = dims
                        .iter()
                        .map(|x| {
                            (
                                format!("{}={}", x.dimension, x.observed),
                                format!("{}={}", x.dimension, x.desired),
                            )
                        })
                        .unzip();
                    DiffBody::Summary {
                        current: cur.join(", "),
                        desired: want.join(", "),
                    }
                },
            });
            return Ok(r);
        }
        let statements = change_statements(&d, &obs, &dims, verifier.as_ref());
        let script = change_script(&statements);
        drop(statements);
        let (uid, gid) = self.pgrole_os_identity(&d, sensitive)?;
        let mut req = self.pgrole_request(uid, gid, &d, vec!["-f".to_string(), "-".to_string()]);
        req.sensitive = true;
        req.stdin = Some(script.as_bytes().to_vec());
        drop(script);
        let permit = self.fs.mutation_permit()?;
        let out = self.fs.exec(&permit, &req);
        drop(req);
        let mut r = base_result(res, sensitive);
        let out = match out {
            Ok(o) => o,
            Err(e) => {
                r.change = Change::Possible;
                r.execution = Execution::Failed;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "the role change could not be confirmed as run: {}",
                    if sensitive {
                        "(details withheld)".to_string()
                    } else {
                        e.message
                    }
                ));
                return Ok(r);
            }
        };
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let applied = matches!(out.completion, Completion::Exited(0))
            && stdout == format!("{}\n", APPLIED_MARK);
        let unquiet = matches!(out.completion, Completion::Exited(0))
            && stdout == format!("{}\n", UNQUIET_MARK);
        if unquiet {
            r.change = Change::None;
            r.execution = Execution::Failed;
            r.reason = Some(
                "the PostgreSQL session could not be verified to keep statements out of the \
                 server log (log_statement, log_min_error_statement, log_min_messages, \
                 statistics or audit settings did not take effect); the role change was not \
                 sent"
                    .to_string(),
            );
            return Ok(r);
        }
        if !applied {
            // The change ran in one transaction. Whether it committed is
            // decided by observing again: unchanged managed dimensions prove
            // no change.
            let what = match &out.completion {
                Completion::Exited(c) => format!("psql exited {}", c),
                Completion::Signaled(s) => format!("psql was terminated by signal {}", s),
                Completion::Indeterminate { .. } => "psql did not complete".to_string(),
            };
            r.execution = Execution::Failed;
            r.verification = Verification::Unknown;
            r.change = Change::Possible;
            // Only a definite psql exit (a statement error rolls the
            // transaction back) is settled by observing again; a signal or an
            // unknown completion may have interrupted a COMMIT in flight.
            if matches!(out.completion, Completion::Exited(_)) {
                if let Ok(after) = self.pgrole_observe(&d, verifier.is_some(), sensitive) {
                    if compare_role(&d, &after, verifier.as_ref()) == dims {
                        r.change = Change::None;
                    }
                }
            } else if matches!(out.completion, Completion::Indeterminate { .. }) {
                r.execution = Execution::Indeterminate;
            }
            r.reason = Some(format!(
                "PostgreSQL refused or did not finish the role change ({}; psql output \
                 withheld because the statement carries secret material)",
                what
            ));
            return Ok(r);
        }
        if !out.stderr.is_empty() {
            r.notes.push(format!(
                "psql printed {} bytes of diagnostics (withheld)",
                out.stderr.len()
            ));
        }
        match self.pgrole_observe(&d, verifier.is_some(), sensitive) {
            Ok(after) if compare_role(&d, &after, verifier.as_ref()).is_empty() => {
                r.verification = Verification::Verified;
            }
            Ok(_) => {
                r.execution = Execution::Failed;
                r.verification = Verification::Failed;
                r.reason =
                    Some("the role did not reach the desired state after the change".to_string());
            }
            Err(e) => {
                r.execution = if e.kind == ErrorKind::Indeterminate {
                    Execution::Indeterminate
                } else {
                    Execution::Failed
                };
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "the role change succeeded but re-observation failed: {}",
                    e.message
                ));
            }
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "SCRAM-SHA-256$4096:c2FsdHNhbHRzYWx0c2FsdA==$\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:\
                     BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

    #[test]
    fn role_names() {
        for ok in [
            "app",
            "_x",
            "app_1",
            "a234567890123456789012345678901234567890123456789012345678901",
        ] {
            assert!(valid_role_name(ok), "{ok}");
        }
        for bad in [
            "",
            "App",
            "1app",
            "app-x",
            "app x",
            "app\"",
            "app'",
            "pg_monitor",
            "ap;p",
            "a2345678901234567890123456789012345678901234567890123456789012345",
        ] {
            assert!(!valid_role_name(bad), "{bad}");
        }
    }

    #[test]
    fn only_package_psql_binaries_are_run() {
        for ok in [
            "/usr/bin/psql",
            "/usr/pgsql-17/bin/psql",
            "/usr/pgsql-9/bin/psql",
            "/usr/pgsql-100/bin/psql",
        ] {
            assert!(allowed_psql(ok), "{ok}");
        }
        for bad in [
            "/tmp/x/psql",
            "/usr/local/bin/psql",
            "psql",
            "/usr/pgsql-/bin/psql",
            "/usr/pgsql-17x/bin/psql",
            "/usr/pgsql-017/bin/psql",
            "/usr/pgsql-17/../../tmp/bin/psql",
            "/usr/pgsql-1000/bin/psql",
            "/usr/bin/psql2",
            "/opt/pg/bin/psql16",
        ] {
            assert!(!allowed_psql(bad), "{bad}");
        }
    }

    #[test]
    fn scram_verifiers() {
        assert!(valid_scram_verifier(V));
        for bad in [
            "",
            "pencil",
            "md5d3ef0a4f6b55e2b3eb5c1c4c1b0a0f9e",
            &V.replace("4096", "1000"),
            &V.replace("4096", "04096"),
            &V.replace("SCRAM-SHA-256", "SCRAM-SHA-1"),
            &format!("{V}'"),
            &format!("{V} "),
            &V.replace("c2FsdHNhbHRzYWx0c2FsdA==", "c2Fsd'Nh"),
            &V.replace(":BBBB", ":BBB"),
            &V.replace("$AAAA", "$AAA="),
            // 44 characters but not 32 bytes: no `=`, or `==`
            &V.replace("A=:", "AA:"),
            &V.replace("B=", "BB"),
            &V.replace("AA=:", "A==:"),
        ] {
            assert!(!valid_scram_verifier(bad), "{bad}");
        }
        assert!(parse_verifier_secret(format!("{V}\n").as_bytes()).is_ok());
        assert!(parse_verifier_secret(format!("{V}\n\n").as_bytes()).is_err());
        assert!(parse_verifier_secret(b"hunter2\n").is_err());
    }

    /// The columns after the tag and version for a missing role: `f`, eight
    /// empty role columns, then the `rolpassword IS NOT NULL` value (and an
    /// empty password column when the verifier is read).
    fn absent_cols(has_pw: &str, with_verifier: bool) -> String {
        let mut v = vec!["f"];
        v.extend([""; 8]);
        v.push(has_pw);
        if with_verifier {
            v.push("");
        }
        v.join("|")
    }

    #[test]
    fn observation_parses_exactly() {
        let absent = format!("{OBS_TAG}|170011|{}\n", absent_cols("f", false));
        let o = parse_observation(absent.as_bytes(), false).unwrap();
        assert!(o.role.is_none());
        assert_eq!(o.server_version, 170011);
        // The verifier variant of a missing role: an empty password column.
        let absent_v = format!("{OBS_TAG}|100023|{}\n", absent_cols("f", true));
        assert!(parse_observation(absent_v.as_bytes(), true)
            .unwrap()
            .role
            .is_none());
        let absent_v_bad = format!("{OBS_TAG}|100023|{}x\n", absent_cols("f", true));
        assert!(parse_observation(absent_v_bad.as_bytes(), true).is_none());
        let present = format!("{OBS_TAG}|100023|t|t|f|f|f|t|f|f|-1|t\n");
        let o = parse_observation(present.as_bytes(), false).unwrap();
        let r = o.role.unwrap();
        assert!(r.attrs[0] && !r.attrs[1] && r.attrs[4]);
        assert_eq!(r.conn_limit, -1);
        let with_v = format!("{OBS_TAG}|160015|t|t|f|f|f|t|f|f|5|t|{V}\n");
        let o = parse_observation(with_v.as_bytes(), true).unwrap();
        assert_eq!(o.role.unwrap().verifier.unwrap().as_str(), V);
        for bad in [
            String::new(),
            format!("{OBS_TAG}|170011|{}", absent_cols("f", false)),
            format!("{OBS_TAG}|170011|{}\nextra\n", absent_cols("f", false)),
            format!("other|170011|{}\n", absent_cols("f", false)),
            // the NULL row's password test must read false, not empty / true
            format!("{OBS_TAG}|170011|{}\n", absent_cols("", false)),
            format!("{OBS_TAG}|170011|{}\n", absent_cols("t", false)),
            format!("{OBS_TAG}|17x|f||||||||||\n"),
            format!("{OBS_TAG}|170011|f|t|{}|f\n", [""; 7].join("|")),
            format!("{OBS_TAG}|170011|t|t|f|f|f|t|f|f|-2|t\n"),
            format!("{OBS_TAG}|170011|t|t|f|f|f|t|f|yes|-1|t\n"),
            format!("{OBS_TAG}|170011|t|t|f|f|f|t|f|f|-1|t|x|y\n"),
        ] {
            assert!(
                parse_observation(bad.as_bytes(), false).is_none(),
                "{bad:?}"
            );
        }
        // has_password must agree with the verifier column.
        let lie = format!("{OBS_TAG}|160015|t|t|f|f|f|t|f|f|5|f|{V}\n");
        assert!(parse_observation(lie.as_bytes(), true).is_none());
    }

    fn desired(name: &str, present: bool, attrs: Vec<(Attr, bool)>) -> RoleDesired {
        RoleDesired {
            name: name.into(),
            present,
            attrs,
            conn_limit: None,
            os_user: "postgres".into(),
            psql: DEFAULT_PSQL.into(),
            port: None,
            database: "postgres".into(),
        }
    }

    #[test]
    fn only_declared_attributes_are_compared_and_changed() {
        let d = desired("app", true, vec![(Attr::Login, true)]);
        let o = RoleObserved {
            server_version: 170000,
            role: Some(RoleRow {
                attrs: [false, true, false, false, true, false, false],
                conn_limit: -1,
                verifier: None,
            }),
        };
        let dims = compare_role(&d, &o, None);
        assert_eq!(
            dims.len(),
            1,
            "superuser is not declared, so it is not touched"
        );
        let sql = change_statements(&d, &o, &dims, None);
        assert_eq!(sql.as_str(), "ALTER ROLE \"app\" WITH LOGIN;\n");
    }

    #[test]
    fn create_uses_only_declared_attributes_and_the_verifier() {
        let mut d = desired("app", true, vec![(Attr::Login, true)]);
        d.conn_limit = Some(10);
        let o = RoleObserved {
            server_version: 100000,
            role: None,
        };
        let v = Zeroizing::new(V.to_string());
        let dims = compare_role(&d, &o, Some(&v));
        let sql = change_statements(&d, &o, &dims, Some(&v));
        assert_eq!(
            sql.as_str(),
            format!("CREATE ROLE \"app\" WITH LOGIN CONNECTION LIMIT 10 PASSWORD '{V}';\n")
        );
        assert!(!sql.contains("SUPERUSER"));
    }

    #[test]
    fn verifier_drift_is_detected_without_values() {
        let d = desired("app", true, vec![]);
        let o = RoleObserved {
            server_version: 130000,
            role: Some(RoleRow {
                attrs: [true, false, false, false, true, false, false],
                conn_limit: -1,
                verifier: Some(Zeroizing::new("md5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into())),
            }),
        };
        let v = Zeroizing::new(V.to_string());
        let dims = compare_role(&d, &o, Some(&v));
        assert_eq!(dims.len(), 1);
        assert_eq!(dims[0].dimension, "password_verifier");
        assert!(!dims[0].observed.contains("md5") && !dims[0].desired.contains("SCRAM"));
        let sql = change_statements(&d, &o, &dims, Some(&v));
        assert_eq!(
            sql.as_str(),
            format!("ALTER ROLE \"app\" PASSWORD '{V}';\n")
        );
        // Same verifier: no drift.
        let same = RoleObserved {
            server_version: 130000,
            role: Some(RoleRow {
                attrs: [true, false, false, false, true, false, false],
                conn_limit: -1,
                verifier: Some(Zeroizing::new(V.to_string())),
            }),
        };
        assert!(compare_role(&d, &same, Some(&v)).is_empty());
    }

    #[test]
    fn the_connecting_role_is_never_locked_out() {
        assert!(self_lockout(&desired("postgres", false, vec![])).is_some());
        assert!(self_lockout(&desired("postgres", true, vec![(Attr::Superuser, false)])).is_some());
        assert!(self_lockout(&desired("postgres", true, vec![(Attr::Login, false)])).is_some());
        assert!(self_lockout(&desired("postgres", true, vec![(Attr::CreateDb, false)])).is_none());
        assert!(self_lockout(&desired("app", false, vec![])).is_none());
    }

    #[test]
    fn the_script_verifies_quiet_logging_before_the_change() {
        let s = change_script("ALTER ROLE \"app\" PASSWORD 'X';\n");
        let quiet = s.find("AS sinter_quiet").unwrap();
        let gate = s.find("\\if :sinter_quiet").unwrap();
        let change = s.find("ALTER ROLE").unwrap();
        assert!(quiet < gate && gate < change);
        for setting in [
            "SET log_min_messages = 'panic';",
            "SET log_min_error_statement = 'panic';",
            "SET log_statement = 'none';",
            "SET log_min_duration_statement = -1;",
            "SET pg_stat_statements.track_utility = off;",
            "SET pgaudit.log = 'none';",
            "SET track_activities = off;",
        ] {
            let at = s.find(setting).unwrap_or_else(|| panic!("{setting}"));
            assert!(at < quiet, "{setting} must precede the check");
        }
        // The change is inside the gate, the unquiet mark in its else branch.
        let els = s.find("\\else").unwrap();
        assert!(change < els);
        assert!(s[els..].contains(UNQUIET_MARK));
        assert!(!s[els..].contains("ALTER ROLE"));
    }
}
