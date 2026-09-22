//! P2 concurrency tests — the mandatory race gates: single-use tokens,
//! rotation atomicity, auth-vs-rotation, revocation linearization, and
//! duplicate registration under contention.

use sinter_gateway::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

fn setup() -> (
    GatewayCore<TestClock>,
    Arc<MemoryStore>,
    Arc<ControllerAuth<MemoryStore, TestClock>>,
) {
    let clk = TestClock::new();
    let core = GatewayCore::with_clock(clk.clone());
    let store = Arc::new(MemoryStore::default());
    let auth = Arc::new(ControllerAuth::new(store.clone(), clk));
    (core, store, auth)
}

#[test]
fn single_use_token_16_concurrent_consumers_exactly_one_wins() {
    let (core, _s, auth) = setup();
    let core = Arc::new(core);
    let token = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let presented = token.expose().to_string();

    let wins = Arc::new(AtomicUsize::new(0));
    let consumed = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(16));
    let mut hs = Vec::new();
    for _ in 0..16 {
        let (auth, core, presented) = (auth.clone(), core.clone(), presented.clone());
        let (wins, consumed, barrier) = (wins.clone(), consumed.clone(), barrier.clone());
        hs.push(std::thread::spawn(move || {
            barrier.wait(); // maximize simultaneity
            match auth.register(&core, &presented) {
                Ok(_) => wins.fetch_add(1, Ordering::SeqCst),
                Err(e)
                    if e.code == "consumed_registration_token"
                        || e.code == "account_has_controller" =>
                {
                    consumed.fetch_add(1, Ordering::SeqCst)
                }
                Err(e) => panic!("unexpected error: {e}"),
            };
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(
        wins.load(Ordering::SeqCst),
        1,
        "exactly one registration may succeed"
    );
    assert_eq!(
        wins.load(Ordering::SeqCst) + consumed.load(Ordering::SeqCst),
        16
    );
}

#[test]
fn concurrent_rotations_leave_exactly_one_valid_credential() {
    let (core, _s, auth) = setup();
    let core = Arc::new(core);
    let token = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let (_p, cred) = auth.register(&core, token.expose()).unwrap();
    let presented = cred.expose().to_string();

    // N racers all rotate from the same starting credential: at most one can
    // win the first rotate; winners rotate again — final state must be
    // exactly one valid credential chain tip.
    let successes = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(8));
    let results: Vec<std::thread::JoinHandle<Option<String>>> = (0..8)
        .map(|_| {
            let (auth, presented, successes, barrier) = (
                auth.clone(),
                presented.clone(),
                successes.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                barrier.wait();
                auth.rotate(&presented).ok().map(|c| {
                    successes.fetch_add(1, Ordering::SeqCst);
                    c.expose().to_string()
                })
            })
        })
        .collect();
    let new_creds: Vec<String> = results
        .into_iter()
        .filter_map(|h| h.join().unwrap())
        .collect();
    assert_eq!(successes.load(Ordering::SeqCst), new_creds.len());
    // Exactly one first-generation rotation succeeded.
    assert_eq!(new_creds.len(), 1);
    // Old credential is dead; the sole new one works.
    assert_eq!(
        auth.authenticate(&presented).unwrap_err().code,
        "invalid_credential"
    );
    assert!(auth.authenticate(&new_creds[0]).is_ok());
}

#[test]
fn auth_vs_rotation_linearizes_cleanly() {
    let (core, _s, auth) = setup();
    let core = Arc::new(core);
    let token = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let (_p, cred) = auth.register(&core, token.expose()).unwrap();
    let presented = cred.expose().to_string();

    let stop = Arc::new(AtomicUsize::new(0));
    let auth_ok = Arc::new(AtomicUsize::new(0));
    let auth_fail = Arc::new(AtomicUsize::new(0));
    let a2 = auth.clone();
    let p2 = presented.clone();
    let (stop2, ok2, fail2) = (stop.clone(), auth_ok.clone(), auth_fail.clone());
    let reader = std::thread::spawn(move || {
        while stop2.load(Ordering::SeqCst) == 0 {
            if a2.authenticate(&p2).is_ok() {
                ok2.fetch_add(1, Ordering::SeqCst);
            } else {
                fail2.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    let new_cred = auth.rotate(&presented).unwrap();
    stop.store(1, Ordering::SeqCst);
    reader.join().unwrap();

    // Post-rotation: old cred must ALWAYS fail — no valid-after-rotation reads.
    for _ in 0..100 {
        assert_eq!(
            auth.authenticate(&presented).unwrap_err().code,
            "invalid_credential"
        );
    }
    assert!(auth.authenticate(new_cred.expose()).is_ok());
}

#[test]
fn concurrent_revoke_and_authenticate_has_clean_linearization() {
    let (core, _s, auth) = setup();
    let core = Arc::new(core);
    let token = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let (_p, cred) = auth.register(&core, token.expose()).unwrap();
    let presented = cred.expose().to_string();

    let stop = Arc::new(AtomicUsize::new(0));
    let post_revoke_successes = Arc::new(AtomicUsize::new(0));
    let revoked = Arc::new(AtomicUsize::new(0));

    let a2 = auth.clone();
    let p2 = presented.clone();
    let (stop2, wins2, rev2) = (stop.clone(), post_revoke_successes.clone(), revoked.clone());
    let reader = std::thread::spawn(move || {
        while stop2.load(Ordering::SeqCst) == 0 {
            if a2.authenticate(&p2).is_ok() && rev2.load(Ordering::SeqCst) != 0 {
                wins2.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    auth.revoke(&presented).unwrap();
    revoked.store(1, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(5));
    stop.store(1, Ordering::SeqCst);
    reader.join().unwrap();

    // After revocation completed, zero successful authentications observed.
    assert_eq!(post_revoke_successes.load(Ordering::SeqCst), 0);
    assert_eq!(
        auth.authenticate(&presented).unwrap_err().code,
        "revoked_controller"
    );
}

#[test]
fn concurrent_duplicate_registration_preserves_one_controller_per_account() {
    let (core, _s, auth) = setup();
    let core = Arc::new(core);
    let acc = AccountId::new("acc_a");
    // Two different valid tokens, same account — only one may win.
    let t1 = auth
        .issue_registration_token(&acc)
        .unwrap()
        .expose()
        .to_string();
    let t2 = auth
        .issue_registration_token(&acc)
        .unwrap()
        .expose()
        .to_string();

    let wins = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(2));
    let mut hs = Vec::new();
    for t in [t1, t2] {
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
    assert_eq!(
        wins.load(Ordering::SeqCst),
        1,
        "one account — one controller"
    );
    assert!(core.account_controller(&acc).is_some());
}
