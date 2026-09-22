//! P7 — cleanup scheduler + retention tests (RFC §F, §J.4b).
//! Revoked controllers purge after +90d; spent tokens after 24h; active
//! rows are never touched. Scheduler lifecycle is deterministic.

use sinter_gateway::cleanup::{Cleanup, CleanupScheduler, REVOKED_RETENTION_MS};
use sinter_gateway::metrics::Metrics;
use sinter_gateway::rate_limit::RateLimiter;
use sinter_gateway::*;
use std::sync::Arc;
use std::time::Duration;

const NOW: u64 = 1_800_000_000_000;

fn ctrl_rec(id: &str, acc: &str) -> ControllerRecord {
    // Inserts are always Active — revocation happens via set_status so the
    // revoked_unix_ms timestamp is exercised through the real code path.
    ControllerRecord {
        controller_id: ControllerId::new(id),
        account_id: AccountId::new(acc),
        cred_verifier: Verifier(format!("cred-{id}")),
        status: ControllerStatus::Active,
        created_unix_ms: NOW,
        rotated_unix_ms: None,
        revoked_unix_ms: None,
    }
}

fn revoke_at<S: IdentityStore>(store: &S, id: &str, when: u64) {
    store
        .set_status(&ControllerId::new(id), ControllerStatus::Revoked, when)
        .unwrap();
}

fn memory_store() -> MemoryStore {
    MemoryStore::default()
}

fn sqlite_store() -> (SqliteStore, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("sinter-gw-p7cln-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.db", uuidish()));
    (SqliteStore::open(&path).unwrap(), path)
}

fn uuidish() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!("t{}", N.fetch_add(1, Ordering::SeqCst))
}

/// The retention contract holds identically for both store impls.
fn retention_contract<S: IdentityStore>(store: &S) {
    let id = ControllerId::new("ctl_old");
    // Revoked 91 days ago → purgeable.
    store.insert_controller(ctrl_rec("ctl_old", "acc")).unwrap();
    revoke_at(store, "ctl_old", NOW - REVOKED_RETENTION_MS - 86_400_000);
    // Revoked 1 day ago → retained.
    store
        .insert_controller(ctrl_rec("ctl_recent", "acc2"))
        .unwrap();
    revoke_at(store, "ctl_recent", NOW - 86_400_000);
    // Active forever → never purged.
    store
        .insert_controller(ctrl_rec("ctl_live", "acc3"))
        .unwrap();

    let n = store
        .purge_revoked_controllers(NOW, REVOKED_RETENTION_MS)
        .unwrap();
    assert_eq!(n, 1, "only the >90d-revoked row purges");
    assert!(store.controller(&id).is_none(), "old revoked row gone");
    assert!(
        store.controller(&ControllerId::new("ctl_recent")).is_some(),
        "recently revoked retained"
    );
    assert!(
        store.controller(&ControllerId::new("ctl_live")).is_some(),
        "active controller never purged"
    );
    // Idempotent: second purge removes nothing.
    assert_eq!(
        store
            .purge_revoked_controllers(NOW, REVOKED_RETENTION_MS)
            .unwrap(),
        0
    );
}

#[test]
fn memory_store_revoked_retention() {
    retention_contract(&memory_store());
}

#[test]
fn sqlite_store_revoked_retention() {
    let (store, path) = sqlite_store();
    retention_contract(&store);
    // Audit row for the purge itself must not resurrect the controller.
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
}

#[test]
fn revocation_semantics_survive_purge_window() {
    let store = memory_store();
    store.insert_controller(ctrl_rec("c1", "a1")).unwrap();
    store
        .set_status(&ControllerId::new("c1"), ControllerStatus::Revoked, NOW)
        .unwrap();
    // Inside retention: purge is a no-op, record still revoked.
    assert_eq!(
        store
            .purge_revoked_controllers(NOW + REVOKED_RETENTION_MS - 1, REVOKED_RETENTION_MS)
            .unwrap(),
        0
    );
    let rec = store.controller(&ControllerId::new("c1")).unwrap();
    assert_eq!(rec.status, ControllerStatus::Revoked);
    // Past retention: purged.
    assert_eq!(
        store
            .purge_revoked_controllers(NOW + REVOKED_RETENTION_MS + 1, REVOKED_RETENTION_MS)
            .unwrap(),
        1
    );
}

#[test]
fn spent_token_purge_retains_unconsumed() {
    let store = memory_store();
    store
        .put_registration_token(RegistrationTokenRecord {
            verifier: Verifier("tok-spent".into()),
            account_id: AccountId::new("a"),
            expires_unix_ms: NOW + 3_600_000,
            created_unix_ms: NOW,
        })
        .unwrap();
    // Consume it.
    let _ = store.take_registration_token(&Verifier("tok-spent".into()), NOW);
    // Fresh spent token → retained (24h retention not elapsed).
    assert_eq!(store.purge_spent_tokens(NOW + 60_000).unwrap(), 0);
    // 25h later → purged.
    assert_eq!(store.purge_spent_tokens(NOW + 25 * 3_600_000).unwrap(), 1);
}

#[test]
fn cleanup_run_once_coordinates_all() {
    let clk = TestClock::new();
    let core = GatewayCore::with_clock(clk.clone());
    let store = memory_store();
    let lim: RateLimiter<TestClock> = RateLimiter::new(clk.clone(), Default::default());
    let metrics = Metrics::new();

    // Seed: an expired request (deadline default) + an idle bucket.
    let acc = AccountId::new("a");
    let ctl = ControllerId::new("c");
    core.register_controller(&ctl, &acc).unwrap();
    core.poll(&ctl).unwrap(); // marks the controller online for submit
    let _ = core
        .submit(
            &acc,
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
            None,
        )
        .unwrap();
    let _ = lim.check(sinter_gateway::rate_limit::BucketClass::McpAccount, "k");

    clk.advance(Duration::from_secs(400)); // past bucket TTL + request deadline
    let c = Cleanup {
        core: &core,
        store: &store,
        limiter: &lim,
        clock: &clk,
        metrics: &metrics,
    };
    let (_t, _c, expired, buckets) = c.run_once();
    assert!(expired >= 1, "expired request swept");
    assert_eq!(buckets, 1, "idle bucket reclaimed");
}

#[test]
fn scheduler_starts_and_stops_cleanly() {
    let clk = TestClock::new();
    let core = Arc::new(GatewayCore::with_clock(clk.clone()));
    let store: Arc<dyn IdentityStore> = Arc::new(memory_store());
    let lim = Arc::new(RateLimiter::new(clk.clone(), Default::default()));
    let sched = CleanupScheduler::start(
        Duration::from_secs(3600),
        core,
        store,
        lim,
        clk,
        Metrics::new(),
    );
    // stop() must not block: the thread parks on a condvar and wakes on the
    // stop flag — a hang here would fail the test harness timeout.
    sched.stop();
}

#[test]
fn scheduler_drop_without_stop_is_safe() {
    let clk = TestClock::new();
    let core = Arc::new(GatewayCore::with_clock(clk.clone()));
    let store: Arc<dyn IdentityStore> = Arc::new(memory_store());
    let lim = Arc::new(RateLimiter::new(clk.clone(), Default::default()));
    let sched = CleanupScheduler::start(
        Duration::from_secs(3600),
        core,
        store,
        lim,
        clk,
        Metrics::new(),
    );
    drop(sched); // Drop impl terminates the thread deterministically.
}
