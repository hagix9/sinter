//! P2/P3 secret-marker logging test. Isolated in its own test binary:
//! `tracing` callsite interest is cached process-globally, so sharing a binary
//! with tests that hit the same `info!` callsites under no subscriber could
//! starve this test's scoped subscriber (flaky empty capture).

use sinter_gateway::*;
use std::io::Write;
use std::sync::{Arc, Mutex};

fn setup() -> (
    GatewayCore<TestClock>,
    ControllerAuth<MemoryStore, TestClock>,
) {
    let clk = TestClock::new();
    let core = GatewayCore::with_clock(clk.clone());
    let store = Arc::new(MemoryStore::default());
    let auth = ControllerAuth::new(store, clk);
    (core, auth)
}

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn p2_logging_paths_never_emit_secrets() {
    let cap = Capture(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(cap.clone())
        .with_ansi(false)
        .finish();
    let (mut token_s, mut cred_s, mut cred2_s) = (String::new(), String::new(), String::new());
    tracing::subscriber::with_default(subscriber, || {
        let (core, auth) = setup();
        let token = auth
            .issue_registration_token(&AccountId::new("acc_a"))
            .unwrap();
        token_s = token.expose().to_string();
        let (_p, cred) = auth.register(&core, token.expose()).unwrap();
        cred_s = cred.expose().to_string();
        let c2 = auth.rotate(cred.expose()).unwrap();
        cred2_s = c2.expose().to_string();
        auth.revoke(c2.expose()).unwrap();
        // Also exercise failure paths that could log input.
        let _ = auth
            .authenticate("ctrlk_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let _ = auth.register(&core, token.expose());
    });
    let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.is_empty());
    for s in [&token_s, &cred_s, &cred2_s] {
        assert!(!logs.contains(s.as_str()), "secret in logs: {s}");
    }
    // Identity metadata IS present (logs are functional, not empty).
    assert!(logs.contains("ctl_") || logs.contains("registered"));
}
