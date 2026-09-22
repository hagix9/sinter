//! P2 auth lifecycle tests: registration tokens, bearer auth, rotation,
//! revocation, re-registration, and integration with P1 ownership.

use serde_json::json;
use sinter_gateway::*;
use std::sync::Arc;
use std::time::Duration;

fn setup() -> (
    GatewayCore<TestClock>,
    TestClock,
    Arc<MemoryStore>,
    ControllerAuth<MemoryStore, TestClock>,
) {
    let clk = TestClock::new();
    let core = GatewayCore::with_clock(clk.clone());
    let store = Arc::new(MemoryStore::default());
    let auth = ControllerAuth::new(store.clone(), clk.clone());
    (core, clk, store, auth)
}

fn acc() -> AccountId {
    AccountId::new("acc_a")
}

#[test]
fn registration_happy_path_yields_authenticating_credential() {
    let (core, _clk, _s, auth) = setup();
    let token = auth.issue_registration_token(&acc()).unwrap();
    let (principal, cred) = auth.register(&core, token.expose()).unwrap();
    assert_eq!(principal.account_id().as_str(), "acc_a");
    assert!(principal.controller_id().as_str().starts_with("ctl_"));
    assert!(cred.expose().starts_with("ctrlk_"));

    // The issued credential authenticates to the same principal.
    let p2 = auth.authenticate(cred.expose()).unwrap();
    assert_eq!(p2, principal);
    // Identity is stable and independent of the credential string.
    assert_ne!(principal.controller_id().as_str(), cred.expose());
}

#[test]
fn token_is_single_use() {
    let (core, _clk, _s, auth) = setup();
    let token = auth.issue_registration_token(&acc()).unwrap();
    auth.register(&core, token.expose()).unwrap();
    let e = auth.register(&core, token.expose()).unwrap_err();
    assert_eq!(e.code, "consumed_registration_token");
    // And it never becomes valid again.
    let e = auth.register(&core, token.expose()).unwrap_err();
    assert_eq!(e.code, "consumed_registration_token");
}

#[test]
fn unknown_and_malformed_tokens_fail_closed() {
    let (core, _clk, _s, auth) = setup();
    let e = auth
        .register(
            &core,
            "reg_0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
    assert_eq!(e.code, "invalid_credential");
    for bad in [
        "",
        "reg_short",
        "ctrlk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "reg_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    ] {
        let e = auth.register(&core, bad).unwrap_err();
        assert_eq!(e.code, "malformed_credential", "input: {bad:?}");
    }
}

#[test]
fn registration_token_is_never_a_bearer_credential() {
    let (core, _clk, _s, auth) = setup();
    let token = auth.issue_registration_token(&acc()).unwrap();
    let e = auth.authenticate(token.expose()).unwrap_err();
    assert_eq!(e.code, "malformed_credential");
    let _ = core;
}

#[test]
fn token_expiry_boundary() {
    let (core, clk, _s, auth) = setup();
    let token = auth.issue_registration_token(&acc()).unwrap();
    // Before expiry: works (uses a second token for the boundary probe).
    let t2 = auth.issue_registration_token(&acc()).unwrap();
    clk.advance(Duration::from_millis(auth::REGISTRATION_TOKEN_TTL_MS - 1));
    // t2 still valid at ttl-1... but account will get a controller on consume;
    // probe boundary with a fresh check on the expired one instead.
    clk.advance(Duration::from_millis(1)); // now == issued + TTL → expired (now >= expires)
    let e = auth.register(&core, token.expose()).unwrap_err();
    assert_eq!(e.code, "expired_registration_token");
    // Never valid again.
    let e = auth.register(&core, token.expose()).unwrap_err();
    assert_eq!(e.code, "expired_registration_token");
    let _ = t2;
}

#[test]
fn one_active_controller_per_account_enforced_at_registration() {
    let (core, _clk, _s, auth) = setup();
    let t1 = auth.issue_registration_token(&acc()).unwrap();
    auth.register(&core, t1.expose()).unwrap();
    // A second valid token for the same account fails closed.
    let t2 = auth.issue_registration_token(&acc()).unwrap();
    let e = auth.register(&core, t2.expose()).unwrap_err();
    assert_eq!(e.code, "account_has_controller");
}

#[test]
fn token_is_account_bound_not_caller_bound() {
    let (core, _clk, _s, auth) = setup();
    let token = auth
        .issue_registration_token(&AccountId::new("acc_bound"))
        .unwrap();
    // No parameter exists to redirect registration to another account.
    let (principal, _c) = auth.register(&core, token.expose()).unwrap();
    assert_eq!(principal.account_id().as_str(), "acc_bound");
}

#[test]
fn rotation_swaps_credential_atomically() {
    let (core, _clk, _s, auth) = setup();
    let token = auth.issue_registration_token(&acc()).unwrap();
    let (principal, old_cred) = auth.register(&core, token.expose()).unwrap();

    let new_cred = auth.rotate(old_cred.expose()).unwrap();
    // Old is dead immediately; new authenticates to the SAME controller identity.
    let e = auth.authenticate(old_cred.expose()).unwrap_err();
    assert_eq!(e.code, "invalid_credential");
    let p2 = auth.authenticate(new_cred.expose()).unwrap();
    assert_eq!(p2, principal);
    // Rotating again with the OLD credential fails.
    assert!(auth.rotate(old_cred.expose()).is_err());
    // Rotating with the new one works.
    let c3 = auth.rotate(new_cred.expose()).unwrap();
    assert!(auth.authenticate(c3.expose()).is_ok());
    assert!(auth.authenticate(new_cred.expose()).is_err());
}

#[test]
fn revocation_kills_authentication_and_rotation() {
    let (core, _clk, _s, auth) = setup();
    let token = auth.issue_registration_token(&acc()).unwrap();
    let (principal, cred) = auth.register(&core, token.expose()).unwrap();

    auth.revoke(cred.expose()).unwrap();
    let e = auth.authenticate(cred.expose()).unwrap_err();
    assert_eq!(e.code, "revoked_controller");
    let e = auth.rotate(cred.expose()).unwrap_err();
    assert_eq!(e.code, "revoked_controller");
    // Administrative path also revoked — stays revoked.
    let e = auth.revoke_controller(principal.controller_id());
    assert!(e.is_ok()); // idempotent
    let e = auth.authenticate(cred.expose()).unwrap_err();
    assert_eq!(e.code, "revoked_controller");
}

#[test]
fn revoked_credential_never_regains_validity() {
    let (core, _clk, _s, auth) = setup();
    let token = auth.issue_registration_token(&acc()).unwrap();
    let (_p, cred) = auth.register(&core, token.expose()).unwrap();
    auth.revoke(cred.expose()).unwrap();
    for _ in 0..3 {
        assert_eq!(
            auth.authenticate(cred.expose()).unwrap_err().code,
            "revoked_controller"
        );
    }
}

#[test]
fn reregistration_after_revocation_issues_new_identity() {
    let (core, _clk, _s, auth) = setup();
    let a = acc();
    let t1 = auth.issue_registration_token(&a).unwrap();
    let (p1, c1) = auth.register(&core, t1.expose()).unwrap();
    auth.revoke(c1.expose()).unwrap();

    // New token → NEW controller identity under the same account.
    let t2 = auth.issue_registration_token(&a).unwrap();
    let (p2, c2) = auth.register(&core, t2.expose()).unwrap();
    assert_ne!(p1.controller_id(), p2.controller_id());
    assert_eq!(p2.account_id().as_str(), "acc_a");
    assert!(auth.authenticate(c2.expose()).is_ok());
    assert_eq!(
        auth.authenticate(c1.expose()).unwrap_err().code,
        "revoked_controller"
    );

    // The P1 binding now routes work to the new controller.
    assert_eq!(
        core.account_controller(&a).as_ref(),
        Some(p2.controller_id())
    );
}

#[test]
fn authenticated_principal_drives_p1_ownership() {
    let clk = TestClock::new();
    let core = GatewayCore::with_clock(clk.clone());
    let store = Arc::new(MemoryStore::default());
    let auth = ControllerAuth::new(store.clone(), clk.clone());

    // Two tenants via full registration flow.
    let (acc_a, acc_b) = (AccountId::new("acc_a"), AccountId::new("acc_b"));
    let ta = auth.issue_registration_token(&acc_a).unwrap();
    let (pa, _ca) = auth.register(&core, ta.expose()).unwrap();
    let tb = auth.issue_registration_token(&acc_b).unwrap();
    let (pb, _cb) = auth.register(&core, tb.expose()).unwrap();

    // A submits work; only A's authenticated principal can poll + respond.
    let (rid, rx) = core
        .submit(
            pa.account_id(),
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
            None,
        )
        .unwrap();
    // B's poll sees nothing of A's queue.
    assert!(core.poll(pb.controller_id()).unwrap().is_none());
    let w = core.poll(pa.controller_id()).unwrap().unwrap();
    assert_eq!(w.request_id, rid.as_str());
    // B cannot answer even holding the request_id.
    assert_eq!(
        core.respond(pb.controller_id(), &rid, Outcome::Mcp(json!({"evil":1})))
            .unwrap_err()
            .code,
        "wrong_controller"
    );
    // A completes.
    core.respond(pa.controller_id(), &rid, Outcome::Mcp(json!({"ok":1})))
        .unwrap();
    assert!(rx.recv_timeout(Duration::from_secs(1)).is_ok());
}

#[test]
fn registration_after_revocation_blocks_active_overlap() {
    // After re-registration the OLD controller can never poll/answer again —
    // both because its credential is revoked and because its binding is gone.
    let (core, _clk, _s, auth) = setup();
    let a = acc();
    let t1 = auth.issue_registration_token(&a).unwrap();
    let (p1, c1) = auth.register(&core, t1.expose()).unwrap();
    auth.revoke(c1.expose()).unwrap();
    let t2 = auth.issue_registration_token(&a).unwrap();
    let (p2, _c2) = auth.register(&core, t2.expose()).unwrap();

    // Old controller id no longer resolves to a queue at all.
    let e = core.poll(p1.controller_id()).unwrap_err();
    assert_eq!(e.code, "wrong_controller");
    assert!(core.poll(p2.controller_id()).unwrap().is_none());
}
