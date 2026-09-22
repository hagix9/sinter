//! Lifecycle tests: happy path, all transitions, expiry, cancellation, duplication.

use serde_json::{json, Value};
use sinter_gateway::*;
use std::sync::mpsc::Receiver;
use std::time::Duration;

fn core() -> (GatewayCore<TestClock>, TestClock) {
    let clk = TestClock::new();
    (GatewayCore::with_clock(clk.clone()), clk)
}

const ACC: &str = "acc_a";
const CTL: &str = "ctl_a";

fn setup() -> (GatewayCore<TestClock>, TestClock, AccountId, ControllerId) {
    let (c, h) = core();
    let acc = AccountId::new(ACC);
    let ctl = ControllerId::new(CTL);
    c.register_controller(&ctl, &acc).unwrap();
    (c, h, acc, ctl)
}

fn frame() -> Value {
    json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"sinter_get_version","arguments":{}}})
}

fn submit(c: &GatewayCore<TestClock>, acc: &AccountId) -> (RequestId, Receiver<Outcome>) {
    c.submit(acc, frame(), Some(10_000)).unwrap()
}

#[test]
fn happy_path_full_cycle() {
    let (c, _h, acc, ctl) = setup();
    let (rid, rx) = submit(&c, &acc);
    assert_eq!(c.request_state(&rid), Some(ReqState::Queued));

    let w = c.poll(&ctl).unwrap().expect("work item");
    assert_eq!(w.request_id, rid.as_str());
    assert_eq!(w.mcp, frame());
    assert_eq!(c.request_state(&rid), Some(ReqState::Delivered));

    let resp = json!({"jsonrpc":"2.0","id":7,"result":{"ok":true}});
    c.respond(&ctl, &rid, Outcome::Mcp(resp.clone())).unwrap();
    assert_eq!(c.request_state(&rid), Some(ReqState::Responded));
    match rx.recv_timeout(Duration::from_secs(2)).unwrap() {
        Outcome::Mcp(v) => assert_eq!(v, resp),
        Outcome::Transport(e) => panic!("unexpected transport error: {e}"),
    }
}

#[test]
fn transition_table_explicit() {
    use ReqState::*;
    let legal = [
        (Created, Queued),
        (Created, Cancelled),
        (Queued, Delivered),
        (Queued, Expired),
        (Queued, Cancelled),
        (Delivered, Responded),
        (Delivered, Expired),
        (Delivered, Cancelled),
    ];
    for (a, b) in legal {
        assert!(state::can_transition(a, b), "{a:?}->{b:?} must be legal");
    }
    let illegal = [
        (Responded, Delivered),
        (Responded, Responded),
        (Expired, Responded),
        (Cancelled, Responded),
        (Expired, Queued),
        (Cancelled, Queued),
        (Delivered, Queued),
        (Queued, Responded), // cannot respond before delivery
        (Created, Responded),
        (Created, Delivered),
    ];
    for (a, b) in illegal {
        assert!(
            !state::can_transition(a, b),
            "{a:?}->{b:?} must be forbidden"
        );
    }
    assert!(Responded.is_terminal() && Expired.is_terminal() && Cancelled.is_terminal());
}

#[test]
fn delivered_item_is_never_redelivered() {
    let (c, _h, acc, ctl) = setup();
    let (rid, _rx) = submit(&c, &acc);
    assert!(c.poll(&ctl).unwrap().is_some());
    // Same poll slot consumed; a second poll cannot return it.
    assert!(c.poll(&ctl).unwrap().is_none());
    assert_eq!(c.request_state(&rid), Some(ReqState::Delivered));
}

#[test]
fn duplicate_response_is_rejected_and_not_recompleted() {
    let (c, _h, acc, ctl) = setup();
    let (rid, rx) = submit(&c, &acc);
    c.poll(&ctl).unwrap();
    c.respond(&ctl, &rid, Outcome::Mcp(json!({"r":1}))).unwrap();

    let e = c
        .respond(&ctl, &rid, Outcome::Mcp(json!({"r":2})))
        .unwrap_err();
    assert_eq!(e.code, "duplicate_response");
    // Exactly one completion was ever produced.
    let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(rx.try_recv().is_err());
}

#[test]
fn respond_before_delivery_rejected() {
    let (c, _h, acc, ctl) = setup();
    let (rid, _rx) = submit(&c, &acc);
    let e = c.respond(&ctl, &rid, Outcome::Mcp(json!({}))).unwrap_err();
    assert_eq!(e.code, "invalid_lifecycle_state");
}

#[test]
fn response_before_deadline_succeeds() {
    let (c, h, acc, ctl) = setup();
    let (rid, rx) = submit(&c, &acc);
    c.poll(&ctl).unwrap();
    h.advance(Duration::from_millis(9_999)); // deadline 10_000
    c.respond(&ctl, &rid, Outcome::Mcp(json!({"ok":1})))
        .unwrap();
    assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());
}

#[test]
fn response_exactly_at_deadline_is_expired() {
    // Boundary semantics: expiry when now >= deadline (respond must arrive
    // strictly before). Conservative — a late frame never sneaks in.
    let (c, h, acc, ctl) = setup();
    let (rid, rx) = submit(&c, &acc);
    c.poll(&ctl).unwrap();
    h.advance(Duration::from_millis(10_000));
    let e = c.respond(&ctl, &rid, Outcome::Mcp(json!({}))).unwrap_err();
    assert_eq!(e.code, "deadline_exceeded");
    assert_eq!(c.request_state(&rid), Some(ReqState::Expired));
    // Caller was failed loudly, not left hanging.
    match rx.recv_timeout(Duration::from_secs(1)).unwrap() {
        Outcome::Transport(t) => assert_eq!(t.code, "deadline_exceeded"),
        Outcome::Mcp(_) => panic!("expired request must not produce mcp result"),
    }
}

#[test]
fn late_response_after_expiry_gets_expired_not_duplicate() {
    let (c, h, acc, ctl) = setup();
    let (rid, _rx) = submit(&c, &acc);
    c.poll(&ctl).unwrap();
    h.advance(Duration::from_millis(11_000));
    let _ = c.respond(&ctl, &rid, Outcome::Mcp(json!({})));
    let e = c.respond(&ctl, &rid, Outcome::Mcp(json!({}))).unwrap_err();
    assert_eq!(e.code, "expired_request");
}

#[test]
fn expired_queued_work_is_never_delivered() {
    let (c, h, acc, ctl) = setup();
    let (rid, _rx) = submit(&c, &acc);
    h.advance(Duration::from_millis(11_000));
    assert!(
        c.poll(&ctl).unwrap().is_none(),
        "dead work must not deliver"
    );
    assert_eq!(c.request_state(&rid), Some(ReqState::Expired));
}

#[test]
fn sweep_expires_open_requests() {
    let (c, h, acc, ctl) = setup();
    let (rid, _rx) = submit(&c, &acc);
    c.poll(&ctl).unwrap();
    h.advance(Duration::from_millis(11_000));
    assert_eq!(c.sweep_expired(), 1);
    assert_eq!(c.request_state(&rid), Some(ReqState::Expired));
}

#[test]
fn cancel_is_terminal_and_blocks_late_response() {
    let (c, _h, acc, ctl) = setup();
    let (rid, rx) = submit(&c, &acc);
    c.poll(&ctl).unwrap();
    c.cancel(&acc, &rid).unwrap();
    assert_eq!(c.request_state(&rid), Some(ReqState::Cancelled));

    let e = c
        .respond(&ctl, &rid, Outcome::Mcp(json!({"ok":1})))
        .unwrap_err();
    assert_eq!(e.code, "cancelled_request");
    // The completion channel carried the cancellation, not a result.
    match rx.recv_timeout(Duration::from_secs(1)).unwrap() {
        Outcome::Transport(t) => assert_eq!(t.code, "cancelled_request"),
        Outcome::Mcp(_) => panic!("cancelled request must not complete"),
    }
}

#[test]
fn cancel_queued_request() {
    let (c, _h, acc, ctl) = setup();
    let (rid, _rx) = submit(&c, &acc);
    c.cancel(&acc, &rid).unwrap();
    assert!(c.poll(&ctl).unwrap().is_none());
    assert_eq!(c.request_state(&rid), Some(ReqState::Cancelled));
}

#[test]
fn cancel_vs_expiry_first_terminal_wins() {
    let (c, h, acc, ctl) = setup();
    let (rid, _rx) = submit(&c, &acc);
    c.poll(&ctl).unwrap();
    c.cancel(&acc, &rid).unwrap();
    h.advance(Duration::from_millis(11_000));
    assert_eq!(
        c.sweep_expired(),
        0,
        "already terminal — cannot be re-expired"
    );
    let e = c.respond(&ctl, &rid, Outcome::Mcp(json!({}))).unwrap_err();
    assert_eq!(e.code, "cancelled_request");
}

#[test]
fn submit_fails_when_controller_offline() {
    let (c, h, acc, ctl) = setup();
    h.advance(Duration::from_millis(OFFLINE_AFTER_MS + 1));
    let e = c.submit(&acc, frame(), None).unwrap_err();
    assert_eq!(e.code, "controller_offline");
    let _ = ctl;
}

#[test]
fn submit_fails_when_no_controller_registered() {
    let (c, _h) = core();
    let e = c
        .submit(&AccountId::new("acc_x"), frame(), None)
        .unwrap_err();
    assert_eq!(e.code, "controller_offline");
}

#[test]
fn queue_capacity_is_enforced() {
    let (c, _h, acc, _ctl) = setup();
    for _ in 0..QUEUE_CAP_PER_CONTROLLER {
        c.submit(&acc, frame(), None).unwrap();
    }
    let e = c.submit(&acc, frame(), None).unwrap_err();
    assert_eq!(e.code, "backend_unavailable");
}

#[test]
fn inflight_capacity_is_enforced() {
    let (c, _h, acc, ctl) = setup();
    for _ in 0..MAX_INFLIGHT_PER_ACCOUNT {
        let (_r, _rx) = c.submit(&acc, frame(), None).unwrap();
        c.poll(&ctl).unwrap(); // drain queue so inflight (not queue) is the limit hit
    }
    let e = c.submit(&acc, frame(), None).unwrap_err();
    assert_eq!(e.code, "backend_unavailable");
}
