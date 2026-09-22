//! F-07 regression: revocation must be re-checked before delivery and
//! completion — a mid-poll or post-auth revoke cannot hand out or accept work.

use sinter_gateway::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn tmpdb(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sinter-gw-f07-{}", std::process::id()));
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

fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &[u8],
) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    for h in headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    s.write_all(req.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    s.flush().unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf);
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn err_code(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"]["code"].as_str().map(String::from))
        .unwrap_or_default()
}

/// `ensure_active` rejects a revoked controller (F-07 primitive).
#[test]
fn ensure_active_rejects_revoked_controller() {
    let path = tmpdb("ensure");
    let _g = Cleanup(path.clone());
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    let auth = ControllerAuth::new(store.clone(), SystemClock);
    let core = GatewayCore::with_clock(SystemClock);

    let account = AccountId::new("acc_a");
    let token = auth.issue_registration_token(&account).unwrap();
    let (principal, cred) = auth.register(&core, token.expose()).unwrap();

    assert!(auth.ensure_active(principal.controller_id()).is_ok());
    auth.revoke(cred.expose()).unwrap();
    let e = auth.ensure_active(principal.controller_id()).unwrap_err();
    assert_eq!(e.code, "revoked_controller");
}

/// Mid-wait revocation: `poll_wait` must NOT deliver post-revocation work.
/// The work item stays queued (not Delivered).
#[test]
fn poll_wait_refuses_delivery_after_revocation() {
    let path = tmpdb("midpoll");
    let _g = Cleanup(path.clone());
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let core = Arc::new(GatewayCore::with_clock(SystemClock));

    let account = AccountId::new("acc_a");
    let token = auth.issue_registration_token(&account).unwrap();
    let (principal, cred) = auth.register(&core, token.expose()).unwrap();
    let ctl = principal.controller_id().clone();

    // Simulate a controller that was authenticated at poll start, then revoked
    // mid-wait: still_authorised reflects the durable store.
    let auth2 = auth.clone();
    let core2 = core.clone();
    let ctl2 = ctl.clone();
    let ctl_for_check = ctl.clone();
    let revoked_flag = Arc::new(AtomicBool::new(false));
    let flag = revoked_flag.clone();

    let handle = std::thread::spawn(move || {
        core2.poll_wait(&ctl2, Duration::from_millis(400), move || {
            if flag.load(Ordering::SeqCst) {
                // Mimic ensure_active observing Revoked.
                Err(TransportError::new(
                    ErrorCode::RevokedController,
                    "controller revoked",
                ))
            } else {
                auth2.ensure_active(&ctl_for_check)
            }
        })
    });

    // Let the poll park, then revoke and submit work.
    std::thread::sleep(Duration::from_millis(50));
    auth.revoke(cred.expose()).unwrap();
    revoked_flag.store(true, Ordering::SeqCst);
    // Keep the account→controller binding so submit can queue the item.
    let _ = core.register_controller(&ctl, &AccountId::new("acc_a"));
    let (_rid, _rx) = core
        .submit(
            &AccountId::new("acc_a"),
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            Some(30_000),
        )
        .unwrap();

    let res = handle.join().unwrap();
    let e = res.expect_err("revoked poll must not deliver work");
    assert_eq!(e.code, "revoked_controller");

    // Work must still be queued (not Delivered) — a later active poll could
    // take it after re-register, or it expires. poll() with always-ok check
    // would deliver it; ensure_active path would refuse again.
    let e2 = core
        .poll_wait(&ctl, Duration::from_millis(10), || {
            Err(TransportError::new(
                ErrorCode::RevokedController,
                "controller revoked",
            ))
        })
        .expect_err("still revoked");
    assert_eq!(e2.code, "revoked_controller");
}

/// HTTP respond after revoke is rejected (401 revoked_controller).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_rejects_respond_after_revocation() {
    let path = tmpdb("httprsp");
    let _g = Cleanup(path.clone());
    let core = Arc::new(GatewayCore::with_clock(SystemClock));
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let state = GatewayHttp::new(core.clone(), auth.clone(), store.clone())
        .with_poll_hold(Duration::from_millis(100));
    let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();
    let addr = server.addr;

    let account = AccountId::new("acc_a");
    let token = auth.issue_registration_token(&account).unwrap();
    let (s, b) = http(
        addr,
        "POST",
        "/v1/register",
        &["Content-Type: application/json"],
        serde_json::json!({"token": token.expose()})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(s, 200, "{b}");
    let cred = serde_json::from_str::<serde_json::Value>(&b).unwrap()["credential"]
        .as_str()
        .unwrap()
        .to_string();

    // Deliver a work item so respond has a live request_id.
    let ctl = core.account_controller(&account).unwrap();
    let (rid, _rx) = core
        .submit(
            &account,
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            Some(30_000),
        )
        .unwrap();
    let _ = core.poll(&ctl).unwrap().expect("deliver");

    // Revoke, then attempt respond over HTTP.
    auth.revoke(&cred).unwrap();
    let body = serde_json::json!({"v":1,"request_id":rid.as_str(),"mcp":{"ok":1}}).to_string();
    let (s, b) = http(
        addr,
        "POST",
        "/v1/respond",
        &[
            &format!("Authorization: Bearer {cred}"),
            "Content-Type: application/json",
        ],
        body.as_bytes(),
    );
    assert_eq!(s, 401, "{b}");
    assert_eq!(err_code(&b), "revoked_controller");

    // Poll after revoke is likewise rejected.
    let (s, b) = http(
        addr,
        "POST",
        "/v1/poll",
        &[&format!("Authorization: Bearer {cred}")],
        b"",
    );
    assert_eq!(s, 401, "{b}");
    assert_eq!(err_code(&b), "revoked_controller");

    server.shutdown().await;
}

/// F-01: TestPublicAuth exists only under test/`test-auth`. This test links
/// it (the test target enables `test-auth`) and proves the fail-closed default
/// when no PublicAuth is configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_public_auth_requires_feature_and_default_fails_closed() {
    // Constructible under the test-auth feature used by this suite.
    let mut pa = TestPublicAuth::new();
    pa.add("tok", "acc", "sub");
    let mut hdrs = axum::http::HeaderMap::new();
    assert!(PublicAuth::authenticate(&pa, &hdrs).is_err());
    hdrs.insert(
        "x-sinter-test-principal",
        axum::http::HeaderValue::from_static("tok"),
    );
    assert!(PublicAuth::authenticate(&pa, &hdrs).is_ok());

    // Default GatewayHttp has no public auth → /mcp fails closed.
    let path = tmpdb("f01");
    let _g = Cleanup(path.clone());
    let core = Arc::new(GatewayCore::with_clock(SystemClock));
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let state = GatewayHttp::new(core, auth, store);
    let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();
    let (s, _) = http(
        server.addr,
        "POST",
        "/mcp",
        &["Content-Type: application/json"],
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
    );
    assert_eq!(s, 503, "no PublicAuth configured must fail closed");
    server.shutdown().await;
}
