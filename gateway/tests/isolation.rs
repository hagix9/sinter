//! Ownership/isolation tests: a valid request_id alone never grants access.

use serde_json::{json, Value};
use sinter_gateway::*;

fn setup_two_tenants() -> (
    GatewayCore<TestClock>,
    AccountId,
    ControllerId,
    AccountId,
    ControllerId,
) {
    let c = GatewayCore::with_clock(TestClock::new());
    let (acc_a, ctl_a) = (AccountId::new("acc_a"), ControllerId::new("ctl_a"));
    let (acc_b, ctl_b) = (AccountId::new("acc_b"), ControllerId::new("ctl_b"));
    c.register_controller(&ctl_a, &acc_a).unwrap();
    c.register_controller(&ctl_b, &acc_b).unwrap();
    (c, acc_a, ctl_a, acc_b, ctl_b)
}

fn frame() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"ping"})
}

#[test]
fn controller_cannot_answer_another_controllers_request() {
    let (c, acc_a, ctl_a, _acc_b, ctl_b) = setup_two_tenants();
    let (rid, rx) = c.submit(&acc_a, frame(), None).unwrap();
    c.poll(&ctl_a).unwrap();

    // B's controller holds a *valid* credential and the real request_id — still refused.
    let e = c
        .respond(&ctl_b, &rid, Outcome::Mcp(json!({"injected":true})))
        .unwrap_err();
    assert_eq!(e.code, "wrong_controller");
    assert!(
        rx.try_recv().is_err(),
        "injected response must not complete"
    );

    // The rightful controller still completes normally.
    c.respond(&ctl_a, &rid, Outcome::Mcp(json!({"ok":1})))
        .unwrap();
    assert!(rx.recv_timeout(std::time::Duration::from_secs(1)).is_ok());
}

#[test]
fn work_enqueued_for_account_a_is_invisible_to_controller_b() {
    let (c, acc_a, ctl_a, _acc_b, ctl_b) = setup_two_tenants();
    c.submit(&acc_a, frame(), None).unwrap();
    // B polls its own queue — A's work is not there. No cross-tenant visibility.
    assert!(c.poll(&ctl_b).unwrap().is_none());
    assert!(c.poll(&ctl_a).unwrap().is_some());
}

#[test]
fn unknown_request_id_is_rejected() {
    let (c, _a, ctl_a, _b, _cb) = setup_two_tenants();
    let ghost = RequestId::generate();
    let e = c
        .respond(&ctl_a, &ghost, Outcome::Mcp(json!({})))
        .unwrap_err();
    assert_eq!(e.code, "unknown_request");
}

#[test]
fn unregistered_controller_identity_fails_closed() {
    let (c, acc_a, ctl_a, _b, _cb) = setup_two_tenants();
    let (rid, _rx) = c.submit(&acc_a, frame(), None).unwrap();
    c.poll(&ctl_a).unwrap();
    // A controller id the gateway has never registered.
    let ghost = ControllerId::new("ctl_ghost");
    let e = c
        .respond(&ghost, &rid, Outcome::Mcp(json!({})))
        .unwrap_err();
    assert_eq!(e.code, "wrong_controller");
    let e = c.poll(&ghost).unwrap_err();
    assert_eq!(e.code, "wrong_controller");
}

#[test]
fn controller_cannot_be_rebound_to_another_account() {
    let c = GatewayCore::with_clock(TestClock::new());
    let (acc_a, acc_b) = (AccountId::new("acc_a"), AccountId::new("acc_b"));
    let ctl = ControllerId::new("ctl_shared");
    c.register_controller(&ctl, &acc_a).unwrap();
    let e = c.register_controller(&ctl, &acc_b).unwrap_err();
    assert_eq!(e.code, "wrong_account");
}

#[test]
fn one_active_controller_per_account_enforced() {
    let c = GatewayCore::with_clock(TestClock::new());
    let acc = AccountId::new("acc_a");
    c.register_controller(&ControllerId::new("ctl_1"), &acc)
        .unwrap();
    let e = c
        .register_controller(&ControllerId::new("ctl_2"), &acc)
        .unwrap_err();
    assert_eq!(e.code, "wrong_account");
}

#[test]
fn stolen_request_id_without_delivery_is_useless() {
    // Even on the OWNING controller, a request that was never delivered to it
    // (still queued) cannot be answered — ownership AND state must hold.
    let (c, acc_a, ctl_a, _b, _cb) = setup_two_tenants();
    let (rid, _rx) = c.submit(&acc_a, frame(), None).unwrap();
    let e = c
        .respond(&ctl_a, &rid, Outcome::Mcp(json!({})))
        .unwrap_err();
    assert_eq!(e.code, "invalid_lifecycle_state");
}
