//! P3 — durable SQLite identity store: parity with MemoryStore, restart
//! persistence, memory-only work boundary, secret-free persisted bytes,
//! schema fail-closed behavior, retention purge, and audit rows.

use sha2::{Digest, Sha256};
use sinter_gateway::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn tmpdb(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sinter-gw-p3-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(format!("{name}.db"))
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", self.0.display()));
        }
    }
}

fn sqlite_auth(
    clk: &TestClock,
) -> (
    Arc<SqliteStore>,
    ControllerAuth<SqliteStore, TestClock>,
    GatewayCore<TestClock>,
) {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let core = GatewayCore::with_clock(clk.clone());
    let auth = ControllerAuth::new(store.clone(), clk.clone());
    (store, auth, core)
}

/// Run the same lifecycle against MemoryStore and SqliteStore — the trait
/// contract must not diverge between implementations.
fn lifecycle_parity<S: IdentityStore>(store: Arc<S>, clk: TestClock) {
    let core = GatewayCore::with_clock(clk.clone());
    let auth = ControllerAuth::new(store, clk.clone());

    // register
    let t = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let (p, cred) = auth.register(&core, t.expose()).unwrap();
    // single-use
    assert_eq!(
        auth.register(&core, t.expose()).unwrap_err().code,
        "consumed_registration_token"
    );
    // authenticate
    assert_eq!(auth.authenticate(cred.expose()).unwrap(), p);
    // second active controller fails
    let t2 = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    assert_eq!(
        auth.register(&core, t2.expose()).unwrap_err().code,
        "account_has_controller"
    );
    // rotation
    let c2 = auth.rotate(cred.expose()).unwrap();
    assert_eq!(
        auth.authenticate(cred.expose()).unwrap_err().code,
        "invalid_credential"
    );
    assert_eq!(auth.authenticate(c2.expose()).unwrap(), p);
    // expiry
    let t3 = auth
        .issue_registration_token(&AccountId::new("acc_b"))
        .unwrap();
    clk.advance(Duration::from_millis(auth::REGISTRATION_TOKEN_TTL_MS));
    assert_eq!(
        auth.register(&core, t3.expose()).unwrap_err().code,
        "expired_registration_token"
    );
    // revocation
    auth.revoke(c2.expose()).unwrap();
    assert_eq!(
        auth.authenticate(c2.expose()).unwrap_err().code,
        "revoked_controller"
    );
    // re-registration → new identity
    let t4 = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let (p2, _c3) = auth.register(&core, t4.expose()).unwrap();
    assert_ne!(p.controller_id(), p2.controller_id());
}

#[test]
fn sqlite_parity_with_memory_store() {
    lifecycle_parity(Arc::new(MemoryStore::default()), TestClock::new());
    lifecycle_parity(
        Arc::new(SqliteStore::open_in_memory().unwrap()),
        TestClock::new(),
    );
}

// ---------- restart semantics (the central P3 gate) ----------

#[test]
fn identity_survives_restart_work_does_not() {
    let path = tmpdb("restart");
    let _g = Cleanup(path.clone());
    let clk = TestClock::new();
    let token_plain;
    let cred_plain;
    let rotated_plain;
    let ctl_id;
    let account = AccountId::new("acc_a");

    // First process lifetime: register, rotate, queue live work.
    {
        let store = Arc::new(SqliteStore::open(&path).unwrap());
        let core = GatewayCore::with_clock(clk.clone());
        let auth = ControllerAuth::new(store.clone(), clk.clone());
        let t = auth.issue_registration_token(&account).unwrap();
        token_plain = t.expose().to_string();
        let (p, c) = auth.register(&core, t.expose()).unwrap();
        ctl_id = p.controller_id().clone();
        cred_plain = c.expose().to_string();
        rotated_plain = auth.rotate(c.expose()).unwrap().expose().to_string();

        // Live P1 work: submitted + queued, never responded.
        let (rid, _rx) = core
            .submit(
                p.account_id(),
                serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
                None,
            )
            .unwrap();
        assert!(core.poll(p.controller_id()).unwrap().is_some());
        let _ = rid;
        // Drop everything — process "restart".
    }

    // Second lifetime: same DB file, fresh everything.
    {
        let store = Arc::new(SqliteStore::open(&path).unwrap());
        let core = GatewayCore::with_clock(clk.clone());
        let auth = ControllerAuth::new(store.clone(), clk.clone());

        // Durable: rotated credential authenticates to the SAME identity.
        let p = auth.authenticate(&rotated_plain).unwrap();
        assert_eq!(p.controller_id(), &ctl_id);
        assert_eq!(p.account_id().as_str(), "acc_a");
        // Re-bind into the fresh work core (the P4 reconnect path).
        auth.bind(&core, &p).unwrap();
        // Old credential remains invalid across restart.
        assert_eq!(
            auth.authenticate(&cred_plain).unwrap_err().code,
            "invalid_credential"
        );
        // Consumed token remains consumed.
        assert_eq!(
            auth.register(&core, &token_plain).unwrap_err().code,
            "consumed_registration_token"
        );
        // Account binding survived: re-register attempt fails (still active).
        let t2 = auth.issue_registration_token(&account).unwrap();
        assert_eq!(
            auth.register(&core, t2.expose()).unwrap_err().code,
            "account_has_controller"
        );

        // NOT durable: the P1 work queue is empty — no request was persisted.
        assert!(
            core.poll(&ctl_id).unwrap().is_none(),
            "active work must not survive restart"
        );
        // And a live poll on a fresh core can still deliver NEW work.
        let (rid, rx) = core
            .submit(
                p.account_id(),
                serde_json::json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
                None,
            )
            .unwrap();
        let w = core.poll(&ctl_id).unwrap().unwrap();
        assert_eq!(w.request_id, rid.as_str());
        core.respond(&ctl_id, &rid, Outcome::Mcp(serde_json::json!({"ok":1})))
            .unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());
    }
}

#[test]
fn revoked_and_expired_state_survives_restart() {
    let path = tmpdb("revoked");
    let _g = Cleanup(path.clone());
    let clk = TestClock::new();
    let dead_cred;
    let expired_token;
    {
        let store = Arc::new(SqliteStore::open(&path).unwrap());
        let core = GatewayCore::with_clock(clk.clone());
        let auth = ControllerAuth::new(store.clone(), clk.clone());
        let t = auth
            .issue_registration_token(&AccountId::new("acc_a"))
            .unwrap();
        let (_p, c) = auth.register(&core, t.expose()).unwrap();
        auth.revoke(c.expose()).unwrap();
        dead_cred = c.expose().to_string();
        let t2 = auth
            .issue_registration_token(&AccountId::new("acc_b"))
            .unwrap();
        expired_token = t2.expose().to_string();
        clk.advance(Duration::from_millis(auth::REGISTRATION_TOKEN_TTL_MS));
    }
    {
        let store = Arc::new(SqliteStore::open(&path).unwrap());
        let core = GatewayCore::with_clock(clk.clone());
        let auth = ControllerAuth::new(store.clone(), clk.clone());
        assert_eq!(
            auth.authenticate(&dead_cred).unwrap_err().code,
            "revoked_controller"
        );
        assert_eq!(
            auth.register(&core, &expired_token).unwrap_err().code,
            "expired_registration_token"
        );
        // Re-registration for the revoked account yields a NEW identity.
        let t3 = auth
            .issue_registration_token(&AccountId::new("acc_a"))
            .unwrap();
        let (p3, _c) = auth.register(&core, t3.expose()).unwrap();
        assert!(p3.controller_id().as_str().starts_with("ctl_"));
    }
}

// ---------- schema / fail-closed open ----------

#[test]
fn init_is_idempotent_and_reopen_verifies_schema() {
    let path = tmpdb("init");
    let _g = Cleanup(path.clone());
    let _a = SqliteStore::open(&path).unwrap();
    let _b = SqliteStore::open(&path).unwrap(); // reopen verifies, no error
}

#[test]
fn corrupt_db_fails_closed_no_silent_recreate() {
    let path = tmpdb("corrupt");
    let _g = Cleanup(path.clone());
    std::fs::write(&path, b"this is not a sqlite database at all").unwrap();
    assert!(SqliteStore::open(&path).is_err());
}

#[test]
fn foreign_schema_fails_closed() {
    let path = tmpdb("foreign");
    let _g = Cleanup(path.clone());
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE something_else (x INTEGER);")
            .unwrap();
    }
    assert!(SqliteStore::open(&path).is_err());
}

#[test]
fn wrong_schema_version_fails_closed() {
    let path = tmpdb("version");
    let _g = Cleanup(path.clone());
    {
        let _s = SqliteStore::open(&path).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE meta SET value = '999' WHERE key = 'schema_version'",
            [],
        )
        .unwrap();
    }
    assert!(SqliteStore::open(&path).is_err());
}

// ---------- secret persistence audit ----------

#[test]
fn plaintext_secrets_absent_from_database_file_and_rows() {
    let path = tmpdb("secrets");
    let _g = Cleanup(path.clone());
    let clk = TestClock::new();
    let (token_s, cred_s, cred2_s);
    {
        let store = Arc::new(SqliteStore::open(&path).unwrap());
        let core = GatewayCore::with_clock(clk.clone());
        let auth = ControllerAuth::new(store.clone(), clk.clone());
        let t = auth
            .issue_registration_token(&AccountId::new("acc_a"))
            .unwrap();
        token_s = t.expose().to_string();
        let (_p, c) = auth.register(&core, t.expose()).unwrap();
        cred_s = c.expose().to_string();
        let c2 = auth.rotate(c.expose()).unwrap();
        cred2_s = c2.expose().to_string();
        auth.revoke(c2.expose()).unwrap();
        // Explicit checkpoint so WAL content is in the main db file too.
        store.checkpoint().unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    let hay = String::from_utf8_lossy(&bytes);
    for secret in [&token_s, &cred_s, &cred2_s] {
        assert!(
            !hay.contains(secret.as_str()),
            "plaintext secret in db file"
        );
        assert!(!hay.contains(&secret[5..]), "secret body in db file");
    }
    // Also query every text column of every table — belt and suspenders.
    let conn = rusqlite::Connection::open(&path).unwrap();
    for table in ["registration_tokens", "controllers", "audit_events", "meta"] {
        let mut st = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
        let mut rows = st.query([]).unwrap();
        while let Some(r) = rows.next().unwrap() {
            for i in 0..r.as_ref().column_count() {
                if let Ok(s) = r.get::<_, String>(i) {
                    for secret in [&token_s, &cred_s, &cred2_s] {
                        assert!(!s.contains(secret.as_str()), "plaintext in {table}");
                    }
                }
            }
        }
    }
    // SHA-256 of a marker secret IS what we persist — confirm verifier form.
    use sha2::{Digest, Sha256};
    let v = hex::encode(Sha256::digest(cred2_s.as_bytes()));
    assert!(hay.contains(&v), "expected persisted verifier missing");
}

// ---------- retention & audit ----------

#[test]
fn spent_token_purge_honors_24h_retention() {
    let clk = TestClock::new();
    let (store, auth, core) = sqlite_auth(&clk);
    let t = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let _ = auth.register(&core, t.expose()).unwrap();
    // Freshly spent: not purged.
    assert_eq!(store.purge_spent_tokens(clk.unix_ms()).unwrap(), 0);
    // After 24h: purged.
    clk.advance(Duration::from_millis(24 * 60 * 60 * 1000));
    assert_eq!(store.purge_spent_tokens(clk.unix_ms()).unwrap(), 1);
}

#[test]
fn audit_rows_contain_metadata_no_secrets() {
    let clk = TestClock::new();
    let (store, auth, core) = sqlite_auth(&clk);
    let t = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let token_s = t.expose().to_string();
    let (p, c) = auth.register(&core, t.expose()).unwrap();
    let c2 = auth.rotate(c.expose()).unwrap();
    auth.revoke(c2.expose()).unwrap();
    let rows = store.audit_rows();
    let kinds: Vec<&str> = rows.iter().map(|r| r.1.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "registration_token_issued",
            "registration_token_consumed",
            "controller_registered",
            "credential_rotated",
            "controller_revoked"
        ]
    );
    let dump = format!("{rows:?}");
    assert!(dump.contains(p.controller_id().as_str())); // identity metadata present
    for s in [token_s.as_str(), c.expose(), c2.expose()] {
        assert!(!dump.contains(s));
    }
}

#[test]
fn sqlite_error_paths_never_echo_secret_material() {
    // Corrupt DB error must not include path tricks or secret-ish content.
    let path = tmpdb("errpath");
    let _g = Cleanup(path.clone());
    std::fs::write(&path, b"junk").unwrap();
    let e = SqliteStore::open(&path).unwrap_err();
    let msg = format!("{e:?}");
    assert!(!msg.contains("reg_") && !msg.contains("ctrlk_"));

    // Constraint violation on duplicate controller id must not echo the
    // presented verifier in the surfaced StoreError text.
    let clk = TestClock::new();
    let (store, auth, core) = sqlite_auth(&clk);
    let t = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let (_p, c) = auth.register(&core, t.expose()).unwrap();
    let rec = store
        .controller_by_verifier(&Verifier(hex::encode(Sha256::digest(c.expose()))))
        .unwrap();
    let dupe = ControllerRecord {
        controller_id: rec.controller_id.clone(),
        account_id: AccountId::new("acc_b"),
        cred_verifier: rec.cred_verifier.clone(),
        status: ControllerStatus::Active,
        created_unix_ms: 0,
        rotated_unix_ms: None,
        revoked_unix_ms: None,
    };
    if let Err(e) = store.insert_controller(dupe) {
        let msg = format!("{e:?}");
        assert!(!msg.contains(&rec.cred_verifier.0), "error echoes verifier");
    }
    // Errors must not contain the presented bearer either.
    let bad =
        auth.authenticate("ctrlk_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let msg = format!("{}", bad.unwrap_err());
    assert!(!msg.contains("0123456789abcdef"));
}
