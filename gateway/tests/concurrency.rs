//! Concurrency tests: the single-lock core must never double-complete,
//! deadlock, or corrupt state under parallel submit/poll/respond/cancel.

use serde_json::json;
use sinter_gateway::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn concurrent_full_lifecycle_no_double_completion() {
    let c = Arc::new(GatewayCore::new());
    let acc = AccountId::new("acc_a");
    let ctl = ControllerId::new("ctl_a");
    c.register_controller(&ctl, &acc).unwrap();

    let completed = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    // Producer: submit 32 requests.
    for _ in 0..32 {
        let c = c.clone();
        let acc = acc.clone();
        let completed = completed.clone();
        handles.push(std::thread::spawn(move || {
            // Queue cap is 8 — submissions contend for admission; retry
            // backpressure (a correct rejection), bounded.
            for _ in 0..500 {
                match c.submit(&acc, json!({"jsonrpc":"2.0","id":1,"method":"ping"}), None) {
                    Ok((_rid, rx)) => {
                        if let Ok(Outcome::Mcp(_)) = rx.recv_timeout(Duration::from_secs(30)) {
                            completed.fetch_add(1, Ordering::SeqCst);
                        }
                        return;
                    }
                    Err(e) if e.code == "backend_unavailable" => std::thread::yield_now(),
                    Err(_) => return,
                }
            }
        }));
    }
    // Consumer: single controller polls and responds.
    {
        let c = c.clone();
        let ctl = ctl.clone();
        let accepted = accepted.clone();
        handles.push(std::thread::spawn(move || {
            let mut n = 0;
            while n < 20_000 && accepted.load(Ordering::SeqCst) < 32 {
                if let Ok(Some(w)) = c.poll(&ctl) {
                    if c.respond(
                        &ctl,
                        &RequestId::from_wire(w.request_id),
                        Outcome::Mcp(json!({"ok":1})),
                    )
                    .is_ok()
                    {
                        accepted.fetch_add(1, Ordering::SeqCst);
                    }
                }
                n += 1;
                std::thread::yield_now();
            }
        }));
    }
    for h in handles {
        h.join().expect("no deadlock/panic");
    }
    assert_eq!(completed.load(Ordering::SeqCst), 32);
    assert_eq!(accepted.load(Ordering::SeqCst), 32);
}

#[test]
fn concurrent_responders_exactly_one_wins() {
    let c = Arc::new(GatewayCore::new());
    let acc = AccountId::new("acc_a");
    let ctl = ControllerId::new("ctl_a");
    c.register_controller(&ctl, &acc).unwrap();
    let (rid, rx) = c
        .submit(&acc, json!({"jsonrpc":"2.0","id":1,"method":"ping"}), None)
        .unwrap();
    c.poll(&ctl).unwrap();

    let wins = Arc::new(AtomicUsize::new(0));
    let mut hs = Vec::new();
    for _ in 0..16 {
        let c = c.clone();
        let ctl = ctl.clone();
        let rid = rid.clone();
        let wins = wins.clone();
        hs.push(std::thread::spawn(move || {
            if c.respond(&ctl, &rid, Outcome::Mcp(json!({"ok":1}))).is_ok() {
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
        "exactly one response completes"
    );
    assert!(rx.recv_timeout(Duration::from_secs(2)).is_ok());
    assert!(rx.try_recv().is_err(), "no second completion possible");
}

#[test]
fn concurrent_cancel_and_respond_one_terminal_outcome() {
    for _ in 0..50 {
        let c = Arc::new(GatewayCore::new());
        let acc = AccountId::new("acc_a");
        let ctl = ControllerId::new("ctl_a");
        c.register_controller(&ctl, &acc).unwrap();
        let (rid, rx) = c
            .submit(&acc, json!({"jsonrpc":"2.0","id":1,"method":"ping"}), None)
            .unwrap();
        c.poll(&ctl).unwrap();

        let c2 = c.clone();
        let rid2 = rid.clone();
        let ctl2 = ctl.clone();
        let t = std::thread::spawn(move || c2.respond(&ctl2, &rid2, Outcome::Mcp(json!({"ok":1}))));
        let cancel_res = c.cancel(&acc, &rid);
        let respond_res = t.join().unwrap();

        // Exactly one of cancel/respond won; both paths are loud, none silent.
        let outcomes = [cancel_res.is_ok(), respond_res.is_ok()];
        assert!(outcomes.iter().filter(|x| **x).count() <= 1);
        // The waiter always received a definitive terminal outcome.
        let _ = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            c.request_state(&rid),
            Some(ReqState::Cancelled) | Some(ReqState::Responded)
        ));
    }
}

#[test]
fn concurrent_polls_never_duplicate_delivery() {
    let c = Arc::new(GatewayCore::new());
    let acc = AccountId::new("acc_a");
    let ctl = ControllerId::new("ctl_a");
    c.register_controller(&ctl, &acc).unwrap();
    let (_rid, _rx) = c
        .submit(&acc, json!({"jsonrpc":"2.0","id":1,"method":"ping"}), None)
        .unwrap();

    let got = Arc::new(AtomicUsize::new(0));
    let mut hs = Vec::new();
    for _ in 0..8 {
        let c = c.clone();
        let ctl = ctl.clone();
        let got = got.clone();
        hs.push(std::thread::spawn(move || {
            if let Ok(Some(_)) = c.poll(&ctl) {
                got.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(got.load(Ordering::SeqCst), 1, "delivered exactly once");
}
