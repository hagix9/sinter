//! Secret-lifecycle & exposure tests (RFC §13, I-7): plaintext exists only at
//! issue time; verifiers are what persists; formatting/logging never leaks.

use sinter_gateway::*;
use std::sync::Arc;

fn setup() -> (
    GatewayCore<TestClock>,
    Arc<MemoryStore>,
    ControllerAuth<MemoryStore, TestClock>,
) {
    let clk = TestClock::new();
    let core = GatewayCore::with_clock(clk.clone());
    let store = Arc::new(MemoryStore::default());
    let auth = ControllerAuth::new(store.clone(), clk);
    (core, store, auth)
}

#[test]
fn secret_debug_and_formatting_are_redacted() {
    let token = RegistrationToken::generate();
    let cred = ControllerCredential::generate();
    assert_eq!(format!("{token:?}"), "RegistrationToken(REDACTED)");
    assert_eq!(format!("{cred:?}"), "ControllerCredential(REDACTED)");
    // No Display impl and no Serialize impl exist — `format!("{token}")` and
    // `serde_json::to_string(&cred)` are compile errors, not test cases.
}

#[test]
fn plaintext_is_never_stored_only_verifiers() {
    let (core, store, auth) = setup();
    let token = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let (_p, cred) = auth.register(&core, token.expose()).unwrap();
    let new_cred = auth.rotate(cred.expose()).unwrap();

    // Inspect every persisted record: none may contain any plaintext secret.
    let dump = format!("{store:?}");
    for secret in [token.expose(), cred.expose(), new_cred.expose()] {
        assert!(!dump.contains(secret), "plaintext secret persisted");
        // And no structurally-secret-looking 64-char run of the plaintext is stored raw.
        assert!(!dump.contains(&secret[5..]));
    }
}

#[test]
fn errors_do_not_echo_presented_secrets() {
    let (core, _s, auth) = setup();
    let marker = "reg_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let e = auth.register(&core, marker).unwrap_err();
    assert!(
        !format!("{e}").contains("eeee"),
        "error echoes secret material"
    );
    assert!(!e.message.contains(marker));

    let token = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let (_p, cred) = auth.register(&core, token.expose()).unwrap();
    let marker_cred = cred.expose().to_string();
    auth.revoke(&marker_cred).unwrap();
    let e = auth.authenticate(&marker_cred).unwrap_err();
    assert!(!e.message.contains(&marker_cred), "error leaks credential");
}
