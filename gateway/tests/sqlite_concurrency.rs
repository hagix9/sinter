//! P3 concurrency — the P2 race gates re-run against the durable SQLite
//! store. Transactions + the partial unique index must preserve every P2
//! atomicity guarantee across the SQL boundary.

use sinter_gateway::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

fn setup() -> (
    Arc<GatewayCore<TestClock>>,
    Arc<ControllerAuth<SqliteStore, TestClock>>,
) {
    let clk = TestClock::new();
    let core = Arc::new(GatewayCore::with_clock(clk.clone()));
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let auth = Arc::new(ControllerAuth::new(store, clk));
    (core, auth)
}

fn registered(
    auth: &ControllerAuth<SqliteStore, TestClock>,
    core: &GatewayCore<TestClock>,
    acc: &str,
) -> String {
    let t = auth.issue_registration_token(&AccountId::new(acc)).unwrap();
    let (_p, c) = auth.register(core, t.expose()).unwrap();
    c.expose().to_string()
}

#[test]
fn sqlite_single_use_token_16_consumers_exactly_one_wins() {
    let (core, auth) = setup();
    let token = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap()
        .expose()
        .to_string();

    let wins = Arc::new(AtomicUsize::new(0));
    let fails = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(16));
    let mut hs = Vec::new();
    for _ in 0..16 {
        let (auth, core, token) = (auth.clone(), core.clone(), token.clone());
        let (wins, fails, barrier) = (wins.clone(), fails.clone(), barrier.clone());
        hs.push(std::thread::spawn(move || {
            barrier.wait();
            match auth.register(&core, &token) {
                Ok(_) => wins.fetch_add(1, Ordering::SeqCst),
                Err(e)
                    if e.code == "consumed_registration_token"
                        || e.code == "account_has_controller" =>
                {
                    fails.fetch_add(1, Ordering::SeqCst)
                }
                Err(e) => panic!("unexpected: {e}"),
            };
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(wins.load(Ordering::SeqCst), 1);
    assert_eq!(fails.load(Ordering::SeqCst), 15);
}

#[test]
fn sqlite_concurrent_rotations_one_winner() {
    let (core, auth) = setup();
    let cred = registered(&auth, &core, "acc_a");
    let barrier = Arc::new(Barrier::new(8));
    let mut hs = Vec::new();
    for _ in 0..8 {
        let (auth, cred, barrier) = (auth.clone(), cred.clone(), barrier.clone());
        hs.push(std::thread::spawn(move || {
            barrier.wait();
            auth.rotate(&cred).ok().map(|c| c.expose().to_string())
        }));
    }
    let winners: Vec<String> = hs.into_iter().filter_map(|h| h.join().unwrap()).collect();
    assert_eq!(winners.len(), 1, "exactly one rotation may win");
    assert_eq!(
        auth.authenticate(&cred).unwrap_err().code,
        "invalid_credential"
    );
    assert!(auth.authenticate(&winners[0]).is_ok());
}

#[test]
fn sqlite_duplicate_registration_one_active_controller() {
    let (core, auth) = setup();
    let acc = AccountId::new("acc_a");
    let tokens: Vec<String> = (0..4)
        .map(|_| {
            auth.issue_registration_token(&acc)
                .unwrap()
                .expose()
                .to_string()
        })
        .collect();
    let wins = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(tokens.len()));
    let mut hs = Vec::new();
    for t in tokens {
        let (auth, core, wins, barrier) =
            (auth.clone(), core.clone(), wins.clone(), barrier.clone());
        hs.push(std::thread::spawn(move || {
            barrier.wait();
            if auth.register(&core, &t).is_ok() {
                wins.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(wins.load(Ordering::SeqCst), 1);
}

#[test]
fn sqlite_auth_vs_revoke_linearizes() {
    let (core, auth) = setup();
    let cred = registered(&auth, &core, "acc_a");
    let stop = Arc::new(AtomicUsize::new(0));
    let post_revoke_wins = Arc::new(AtomicUsize::new(0));
    let revoked = Arc::new(AtomicUsize::new(0));
    let (a2, c2, s2, w2, r2) = (
        auth.clone(),
        cred.clone(),
        stop.clone(),
        post_revoke_wins.clone(),
        revoked.clone(),
    );
    let reader = std::thread::spawn(move || {
        while s2.load(Ordering::SeqCst) == 0 {
            if a2.authenticate(&c2).is_ok() && r2.load(Ordering::SeqCst) != 0 {
                w2.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    auth.revoke(&cred).unwrap();
    revoked.store(1, Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_millis(5));
    stop.store(1, Ordering::SeqCst);
    reader.join().unwrap();
    assert_eq!(post_revoke_wins.load(Ordering::SeqCst), 0);
    assert_eq!(
        auth.authenticate(&cred).unwrap_err().code,
        "revoked_controller"
    );
}
