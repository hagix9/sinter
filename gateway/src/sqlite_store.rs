//! P3 — durable identity persistence: `SqliteStore` implementing the P2
//! `IdentityStore` contract against an embedded SQLite database.
//!
//! DEPENDENCY MODEL (RFC §10/§14): rusqlite with the `bundled` feature —
//! SQLite C source is compiled into the gateway binary at build time.
//! There is no external SQLite runtime, OS package, or CLI dependency, and
//! this dependency exists only in the `sinter-gateway` crate — never in
//! `sinter`, `sinter mcp`, `sinter-bridge`, or any customer-side component.
//!
//! DURABLE / MEMORY-ONLY BOUNDARY (RFC §10):
//!   durable:    controller identity + binding, credential verifier, status,
//!               registration-token verifier + expiry + consumption, audit
//!               metadata (no payloads)
//!   memory only: MCP requests, work queues, inflight, deadlines, sessions,
//!               tool args/results — none of it ever reaches this file.
//!
//! CONFIG: WAL + synchronous=FULL + busy_timeout — the identity workload is
//! tiny (registration/rotation/revocation are rare, human-scale events), so a
//! single `Mutex<Connection>` serializes everything and transactions give
//! crash-atomicity. busy_timeout bounds transient contention; WAL is the
//! standard embedded default. No cargo-culted pool.
//!
//! SCHEMA INIT / FAIL-CLOSED OPEN:
//!   - path does not exist (or is a zero-length file): create + initialize —
//!     a fresh environment must be able to bootstrap itself (no sqlite3 CLI).
//!   - path exists and is non-empty: schema version and required tables are
//!     verified. Mismatch/corruption/open failure → Err. We NEVER silently
//!     recreate an expected database — that could erase revocations.
//!
//! SECRETS: only SHA-256 verifier hex strings are ever bound as SQL
//! parameters. Plaintext `reg_`/`ctrlk_` values never enter this module.
//! Audit rows carry identity metadata only — never payloads or secrets.

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::id::{AccountId, ControllerId};
use crate::store::*;

/// Current schema version. Future migrations bump this and upgrade in place;
/// an unknown/newer version fails closed on open.
const SCHEMA_VERSION: &str = "1";

/// RFC §10: spent registration tokens are retained 24 h, then purgeable.
const SPENT_TOKEN_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- registration token verifiers: plaintext reg_ never persisted.
CREATE TABLE IF NOT EXISTS registration_tokens (
    verifier         TEXT PRIMARY KEY,            -- sha256 hex of token
    account_id       TEXT NOT NULL,               -- token is account-bound
    created_unix_ms  INTEGER NOT NULL,
    expires_unix_ms  INTEGER NOT NULL,            -- explicit unix ms; no tz
    consumed_unix_ms INTEGER                      -- NULL = unconsumed
);
-- controllers: one row per identity; exactly one live cred_verifier at a time.
CREATE TABLE IF NOT EXISTS controllers (
    controller_id   TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL,
    cred_verifier   TEXT NOT NULL UNIQUE,         -- sha256 hex of bearer
    status          TEXT NOT NULL CHECK (status IN ('active','revoked')),
    created_unix_ms INTEGER NOT NULL,
    rotated_unix_ms INTEGER,
    revoked_unix_ms INTEGER
);
-- v1 invariant at the storage layer: one ACTIVE controller per account.
-- A partial unique index fails closed even if application checks race.
CREATE UNIQUE INDEX IF NOT EXISTS controllers_one_active_per_account
    ON controllers(account_id) WHERE status = 'active';
-- audit: metadata only — request/identity events, NEVER payloads or secrets.
CREATE TABLE IF NOT EXISTS audit_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_unix_ms    INTEGER NOT NULL,
    kind          TEXT NOT NULL,
    account_id    TEXT,
    controller_id TEXT
);
";

fn status_str(s: ControllerStatus) -> &'static str {
    match s {
        ControllerStatus::Active => "active",
        ControllerStatus::Revoked => "revoked",
    }
}

fn parse_status(s: &str) -> ControllerStatus {
    match s {
        "revoked" => ControllerStatus::Revoked,
        _ => ControllerStatus::Active,
    }
}

fn to_store_err(e: rusqlite::Error) -> StoreError {
    // rusqlite errors never echo bound parameters — safe to keep the text
    // for internal diagnostics. Verifiers are the only sensitive-ish params
    // and rusqlite does not include them in error strings.
    StoreError::Internal(format!("sqlite: {e}"))
}

/// One audit row written inside the same transaction as the operation it
/// describes. Metadata only.
fn audit(
    conn: &Connection,
    ts: u64,
    kind: &str,
    account: Option<&str>,
    controller: Option<&str>,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO audit_events (ts_unix_ms, kind, account_id, controller_id)
         VALUES (?1, ?2, ?3, ?4)",
        params![ts as i64, kind, account, controller],
    )
    .map_err(to_store_err)?;
    Ok(())
}

fn row_to_controller(r: &rusqlite::Row<'_>) -> rusqlite::Result<ControllerRecord> {
    Ok(ControllerRecord {
        controller_id: ControllerId::new(r.get::<_, String>(0)?),
        account_id: AccountId::new(r.get::<_, String>(1)?),
        cred_verifier: Verifier(r.get::<_, String>(2)?),
        status: parse_status(&r.get::<_, String>(3)?),
        created_unix_ms: r.get::<_, i64>(4)? as u64,
        rotated_unix_ms: r.get::<_, Option<i64>>(5)?.map(|v| v as u64),
        revoked_unix_ms: r.get::<_, Option<i64>>(6)?.map(|v| v as u64),
    })
}

const CONTROLLER_COLS: &str = "controller_id, account_id, cred_verifier, status, created_unix_ms, \
     rotated_unix_ms, revoked_unix_ms";

/// Durable identity store. Clone-able via `Arc` by callers; internally a
/// single connection under one mutex — correct for the tiny identity
/// workload and it makes every trait method trivially serialized.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for SqliteStore {
    /// Deliberately minimal — never dump connection internals or row content.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SqliteStore(..)")
    }
}

impl SqliteStore {
    /// Open or initialize the identity database. Fail-closed:
    /// an existing but unreadable/corrupt/foreign-schema file is an error,
    /// never a silent wipe.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let preexisting = match fs::metadata(path) {
            Ok(m) => m.len() > 0,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(StoreError::Internal(format!("stat db: {e}"))),
        };
        let conn =
            Connection::open(path).map_err(|e| StoreError::Internal(format!("open db: {e}")))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .and_then(|_| conn.pragma_update(None, "synchronous", "FULL"))
            .and_then(|_| conn.pragma_update(None, "busy_timeout", 5000_i64))
            .map_err(to_store_err)?;

        if preexisting {
            Self::verify_schema(&conn)?;
        } else {
            conn.execute_batch(SCHEMA).map_err(to_store_err)?;
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
                params![SCHEMA_VERSION],
            )
            .map_err(to_store_err)?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Existing database: verify it is OUR schema at a supported version.
    /// Anything else fails closed — we do not guess or wipe.
    fn verify_schema(conn: &Connection) -> Result<(), StoreError> {
        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| {
                StoreError::Internal(
                    "existing database has no sinter-gateway schema version".into(),
                )
            })?;
        if version != SCHEMA_VERSION {
            return Err(StoreError::Internal(format!(
                "unsupported identity schema version {version:?} (supported: {SCHEMA_VERSION:?})"
            )));
        }
        for table in ["registration_tokens", "controllers", "audit_events"] {
            let n: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![table],
                    |r| r.get(0),
                )
                .map_err(to_store_err)?;
            if n != 1 {
                return Err(StoreError::Internal(format!(
                    "existing database missing required table {table:?}"
                )));
            }
        }
        Ok(())
    }

    /// Audit rows for inspection/ops (metadata only — no secrets by construction).
    pub fn audit_rows(&self) -> Vec<(u64, String, Option<String>, Option<String>)> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare(
                "SELECT ts_unix_ms, kind, account_id, controller_id \
                 FROM audit_events ORDER BY id",
            )
            .unwrap();
        st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
    }

    /// Flush WAL content into the main database file (checkpoint). Useful for
    /// backups and for byte-level inspection of the persisted state.
    pub fn checkpoint(&self) -> Result<(), StoreError> {
        self.conn
            .lock()
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .map_err(to_store_err)
    }

    /// Path-independent constructor for tests and ephemeral environments.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(to_store_err)?;
        conn.execute_batch(SCHEMA).map_err(to_store_err)?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION],
        )
        .map_err(to_store_err)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl IdentityStore for SqliteStore {
    fn put_registration_token(&self, rec: RegistrationTokenRecord) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction().map_err(to_store_err)?;
        tx.execute(
            "INSERT INTO registration_tokens
             (verifier, account_id, created_unix_ms, expires_unix_ms, consumed_unix_ms)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![
                rec.verifier.0,
                rec.account_id.as_str(),
                rec.created_unix_ms as i64,
                rec.expires_unix_ms as i64
            ],
        )
        .map_err(to_store_err)?;
        audit(
            &tx,
            rec.created_unix_ms,
            "registration_token_issued",
            Some(rec.account_id.as_str()),
            None,
        )?;
        tx.commit().map_err(to_store_err)
    }

    /// ATOMIC: presence + unconsumed + unexpired checked and consumed marked
    /// inside one IMMEDIATE transaction — same contract as MemoryStore.
    fn take_registration_token(
        &self,
        verifier: &Verifier,
        now_unix_ms: u64,
    ) -> Result<TokenTake, StoreError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction().map_err(to_store_err)?;
        let row = tx
            .query_row(
                "SELECT account_id, expires_unix_ms, created_unix_ms, consumed_unix_ms
                 FROM registration_tokens WHERE verifier = ?1",
                params![verifier.0],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(to_store_err)?;
        let Some((account, expires, created, consumed)) = row else {
            return Ok(TokenTake::Missing); // tx drops → rollback, no write
        };
        if consumed.is_some() {
            return Ok(TokenTake::AlreadyConsumed);
        }
        if now_unix_ms >= expires as u64 {
            return Ok(TokenTake::Expired);
        }
        tx.execute(
            "UPDATE registration_tokens SET consumed_unix_ms = ?1 WHERE verifier = ?2",
            params![now_unix_ms as i64, verifier.0],
        )
        .map_err(to_store_err)?;
        audit(
            &tx,
            now_unix_ms,
            "registration_token_consumed",
            Some(account.as_str()),
            None,
        )?;
        tx.commit().map_err(to_store_err)?;
        Ok(TokenTake::Consumed(RegistrationTokenRecord {
            verifier: verifier.clone(),
            account_id: AccountId::new(account),
            expires_unix_ms: expires as u64,
            created_unix_ms: created as u64,
        }))
    }

    /// ATOMIC: the partial unique index `controllers_one_active_per_account`
    /// makes a second ACTIVE controller per account impossible even if the
    /// application check raced — constraint violation maps to
    /// AccountHasActiveController.
    fn insert_controller(&self, rec: ControllerRecord) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction().map_err(to_store_err)?;
        let res = tx.execute(
            "INSERT INTO controllers
             (controller_id, account_id, cred_verifier, status, created_unix_ms)
             VALUES (?1, ?2, ?3, 'active', ?4)",
            params![
                rec.controller_id.as_str(),
                rec.account_id.as_str(),
                rec.cred_verifier.0,
                rec.created_unix_ms as i64
            ],
        );
        match res {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(StoreError::AccountHasActiveController)
            }
            Err(e) => return Err(to_store_err(e)),
        }
        audit(
            &tx,
            rec.created_unix_ms,
            "controller_registered",
            Some(rec.account_id.as_str()),
            Some(rec.controller_id.as_str()),
        )?;
        tx.commit().map_err(to_store_err)
    }

    fn controller_by_verifier(&self, verifier: &Verifier) -> Option<ControllerRecord> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            &format!("SELECT {CONTROLLER_COLS} FROM controllers WHERE cred_verifier = ?1"),
            params![verifier.0],
            row_to_controller,
        )
        .optional()
        .unwrap_or(None)
    }

    fn controller(&self, id: &ControllerId) -> Option<ControllerRecord> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            &format!("SELECT {CONTROLLER_COLS} FROM controllers WHERE controller_id = ?1"),
            params![id.as_str()],
            row_to_controller,
        )
        .optional()
        .unwrap_or(None)
    }

    /// ATOMIC rotation: read status+verifier, verify expected, swap verifier —
    /// one IMMEDIATE transaction. The P2 race defect (two racers both
    /// swapping) cannot reappear: the expected-verifier check runs inside the
    /// transaction, so the second racer's read observes the rotated verifier
    /// and fails StaleCredential.
    fn rotate_credential(
        &self,
        id: &ControllerId,
        expected: &Verifier,
        new_verifier: Verifier,
        now_unix_ms: u64,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction().map_err(to_store_err)?;
        let row = tx
            .query_row(
                "SELECT status, cred_verifier, account_id FROM controllers
                 WHERE controller_id = ?1",
                params![id.as_str()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(to_store_err)?;
        let Some((status, cur_verifier, account)) = row else {
            return Err(StoreError::UnknownController);
        };
        if status != "active" {
            return Err(StoreError::ControllerNotActive);
        }
        if cur_verifier != expected.0 {
            return Err(StoreError::StaleCredential);
        }
        tx.execute(
            "UPDATE controllers SET cred_verifier = ?1, rotated_unix_ms = ?2
             WHERE controller_id = ?3",
            params![new_verifier.0, now_unix_ms as i64, id.as_str()],
        )
        .map_err(to_store_err)?;
        audit(
            &tx,
            now_unix_ms,
            "credential_rotated",
            Some(account.as_str()),
            Some(id.as_str()),
        )?;
        tx.commit().map_err(to_store_err)
    }

    /// ATOMIC + terminal: Revoked→Active rejected inside the transaction.
    fn set_status(
        &self,
        id: &ControllerId,
        status: ControllerStatus,
        now_unix_ms: u64,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction().map_err(to_store_err)?;
        let row = tx
            .query_row(
                "SELECT status, account_id FROM controllers WHERE controller_id = ?1",
                params![id.as_str()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(to_store_err)?;
        let Some((cur, account)) = row else {
            return Err(StoreError::UnknownController);
        };
        if cur == "revoked" && status == ControllerStatus::Active {
            return Err(StoreError::ControllerNotActive); // terminal
        }
        if cur == status_str(status) {
            return Ok(()); // idempotent no-op (tx rolls back — nothing written)
        }
        tx.execute(
            "UPDATE controllers SET status = ?1, revoked_unix_ms = ?2
             WHERE controller_id = ?3",
            params![
                status_str(status),
                (status == ControllerStatus::Revoked).then_some(now_unix_ms as i64),
                id.as_str()
            ],
        )
        .map_err(to_store_err)?;
        audit(
            &tx,
            now_unix_ms,
            match status {
                ControllerStatus::Revoked => "controller_revoked",
                ControllerStatus::Active => "controller_activated",
            },
            Some(account.as_str()),
            Some(id.as_str()),
        )?;
        tx.commit().map_err(to_store_err)
    }

    fn purge_spent_tokens(&self, now_unix_ms: u64) -> Result<u64, StoreError> {
        let conn = self.conn.lock().unwrap();
        let n = conn
            .execute(
                "DELETE FROM registration_tokens
                 WHERE consumed_unix_ms IS NOT NULL
                   AND ?1 - consumed_unix_ms >= ?2",
                params![now_unix_ms as i64, SPENT_TOKEN_RETENTION_MS as i64],
            )
            .map_err(to_store_err)?;
        Ok(n as u64)
    }

    fn readyz(&self) -> Result<(), StoreError> {
        self.conn
            .lock()
            .unwrap()
            .query_row("SELECT 1", [], |_| Ok(()))
            .map_err(to_store_err)
    }
}

// `.optional()` lives on a trait in rusqlite 0.40
use rusqlite::OptionalExtension;
