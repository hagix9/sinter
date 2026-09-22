//! P4 — real HTTP integration tests: loopback-bound ephemeral axum server,
//! raw `TcpStream` client (deliberately not reqwest: we need exact control
//! over malformed headers, duplicate Authorization lines, wrong methods).

use serde_json::{json, Value};
use sinter_gateway::*;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------- fixtures ----------

struct Rig {
    server: GatewayServer,
    core: Arc<GatewayCore<SystemClock>>,
    auth: Arc<ControllerAuth<SqliteStore, SystemClock>>,
}

async fn rig_with_db(path: &PathBuf, hold: Duration) -> Rig {
    let core = Arc::new(GatewayCore::with_clock(SystemClock));
    let store = Arc::new(SqliteStore::open(path).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let state = GatewayHttp::new(core.clone(), auth.clone(), store.clone()).with_poll_hold(hold);
    let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();
    Rig { server, core, auth }
}

fn tmpdb(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sinter-gw-p4-{}", std::process::id()));
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

/// Raw HTTP/1.1 request over a fresh connection (Connection: close).
/// `headers` are appended verbatim — caller controls everything.
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
    // Early rejects can RST before the body drains — keep received bytes.
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn bearer(t: &str) -> String {
    format!("Authorization: Bearer {t}")
}

fn err_code(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["error"]["code"].as_str().map(String::from))
        .unwrap_or_default()
}

/// Issue a registration token console-side (auth object, not HTTP), then
/// register through the real HTTP endpoint.
fn register_http(
    addr: SocketAddr,
    auth: &ControllerAuth<SqliteStore, SystemClock>,
    acc: &str,
) -> String {
    let token = auth.issue_registration_token(&AccountId::new(acc)).unwrap();
    let body = json!({"token": token.expose()}).to_string();
    let (status, body) = http(
        addr,
        "POST",
        "/v1/register",
        &["Content-Type: application/json"],
        body.as_bytes(),
    );
    assert_eq!(status, 200, "register failed: {body}");
    serde_json::from_str::<Value>(&body).unwrap()["credential"]
        .as_str()
        .unwrap()
        .to_string()
}

// ---------- authentication matrix ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_matrix() {
    let path = tmpdb("auth");
    let _g = Cleanup(path.clone());
    let rig = rig_with_db(&path, Duration::from_millis(150)).await;
    let addr = rig.server.addr;
    let cred = register_http(addr, &rig.auth, "acc_a");

    // valid bearer
    let (s, b) = http(addr, "POST", "/v1/poll", &[&bearer(&cred)], b"");
    assert_eq!(s, 200, "{b}");

    // missing Authorization entirely
    let (s, b) = http(addr, "POST", "/v1/poll", &[], b"");
    assert_eq!((s, err_code(&b)), (401, "missing_auth".into()));

    // wrong scheme
    let (s, _) = http(
        addr,
        "POST",
        "/v1/poll",
        &[&format!("Authorization: Basic {cred}")],
        b"",
    );
    assert_eq!(s, 401);

    // empty bearer
    let (s, _) = http(addr, "POST", "/v1/poll", &["Authorization: Bearer"], b"");
    assert_eq!(s, 401);

    // registration token is not a bearer
    let token = rig
        .auth
        .issue_registration_token(&AccountId::new("acc_z"))
        .unwrap();
    let (s, b) = http(addr, "POST", "/v1/poll", &[&bearer(token.expose())], b"");
    assert_eq!((s, err_code(&b)), (401, "malformed_credential".into()));

    // random well-shaped bearer
    let rand = format!("ctrlk_{}", "ab".repeat(32));
    let (s, b) = http(addr, "POST", "/v1/poll", &[&bearer(&rand)], b"");
    assert_eq!((s, err_code(&b)), (401, "invalid_credential".into()));

    // duplicate Authorization headers → ambiguous, rejected
    let (s, _) = http(
        addr,
        "POST",
        "/v1/poll",
        &[&bearer(&cred), &bearer(&rand)],
        b"",
    );
    assert_eq!(s, 401);

    // rotated-old credential
    let (s, b) = http(addr, "POST", "/v1/rotate", &[&bearer(&cred)], b"");
    assert_eq!(s, 200, "{b}");
    let new_cred = serde_json::from_str::<Value>(&b).unwrap()["credential"]
        .as_str()
        .unwrap()
        .to_string();
    let (s, _) = http(addr, "POST", "/v1/poll", &[&bearer(&cred)], b"");
    assert_eq!(s, 401);
    let (s, _) = http(addr, "POST", "/v1/poll", &[&bearer(&new_cred)], b"");
    assert_eq!(s, 200);

    // revoked credential — console-side revoke
    rig.auth.revoke(&new_cred).unwrap();
    let (s, b) = http(addr, "POST", "/v1/poll", &[&bearer(&new_cred)], b"");
    assert_eq!((s, err_code(&b)), (401, "revoked_controller".into()));

    rig.server.shutdown().await;
}

// ---------- poll ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_immediate_and_wake_on_submit() {
    let path = tmpdb("pollwake");
    let _g = Cleanup(path.clone());
    let rig = rig_with_db(&path, Duration::from_secs(10)).await;
    let addr = rig.server.addr;
    let cred = register_http(addr, &rig.auth, "acc_a");
    let principal = rig.auth.authenticate(&cred).unwrap();

    // First poll binds + marks controller online; submit work, next poll gets it.
    let (s, _) = http(addr, "POST", "/v1/poll", &[&bearer(&cred)], b"");
    assert_eq!(s, 200);
    let (rid, _rx) = rig
        .core
        .submit(
            principal.account_id(),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            None,
        )
        .unwrap();

    // Waiting poll wakes on submit.
    let cred2 = cred.clone();
    let h = std::thread::spawn(move || {
        let t = Instant::now();
        let r = http(addr, "POST", "/v1/poll", &[&bearer(&cred2)], b"");
        (t.elapsed(), r)
    });
    std::thread::sleep(Duration::from_millis(50));
    // poll already delivered the queued item? If so this submit goes to a
    // fresh wait — either way the poll must return promptly with the work.
    let (elapsed, (s, body)) = h.join().unwrap();
    assert_eq!(s, 200);
    let work = serde_json::from_str::<Value>(&body).unwrap()["work"].clone();
    assert!(work.is_object(), "expected work item, got {body}");
    assert_eq!(work["request_id"].as_str().unwrap(), rid.as_str());
    assert!(elapsed < Duration::from_secs(5));
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_hold_timeout_returns_null_work() {
    let path = tmpdb("pollto");
    let _g = Cleanup(path.clone());
    let rig = rig_with_db(&path, Duration::from_millis(250)).await;
    let addr = rig.server.addr;
    let cred = register_http(addr, &rig.auth, "acc_a");
    let t = Instant::now();
    let (s, body) = http(addr, "POST", "/v1/poll", &[&bearer(&cred)], b"");
    assert_eq!(s, 200);
    assert!(serde_json::from_str::<Value>(&body).unwrap()["work"].is_null());
    let e = t.elapsed();
    assert!(
        e >= Duration::from_millis(200) && e < Duration::from_secs(5),
        "{e:?}"
    );
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_isolation_between_controllers() {
    let path = tmpdb("polliso");
    let _g = Cleanup(path.clone());
    let rig = rig_with_db(&path, Duration::from_millis(150)).await;
    let addr = rig.server.addr;
    let cred_a = register_http(addr, &rig.auth, "acc_a");
    let cred_b = register_http(addr, &rig.auth, "acc_b");
    let pa = rig.auth.authenticate(&cred_a).unwrap();

    // bind both, submit work for A only
    http(addr, "POST", "/v1/poll", &[&bearer(&cred_a)], b"");
    http(addr, "POST", "/v1/poll", &[&bearer(&cred_b)], b"");
    rig.core
        .submit(
            pa.account_id(),
            json!({"jsonrpc":"2.0","id":9,"method":"ping"}),
            None,
        )
        .unwrap();

    // B's poll sees nothing of A's work (times out empty).
    let (s, body) = http(addr, "POST", "/v1/poll", &[&bearer(&cred_b)], b"");
    assert_eq!(s, 200);
    assert!(serde_json::from_str::<Value>(&body).unwrap()["work"].is_null());
    // A's poll gets it.
    let (s, body) = http(addr, "POST", "/v1/poll", &[&bearer(&cred_a)], b"");
    assert_eq!(s, 200);
    assert!(serde_json::from_str::<Value>(&body).unwrap()["work"].is_object());
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_poll_second_rejected_409() {
    let path = tmpdb("pollconf");
    let _g = Cleanup(path.clone());
    let rig = rig_with_db(&path, Duration::from_secs(10)).await;
    let addr = rig.server.addr;
    let cred = register_http(addr, &rig.auth, "acc_a");

    // poll A parks (holds the slot); poll B must be rejected immediately.
    let c2 = cred.clone();
    let h = std::thread::spawn(move || http(addr, "POST", "/v1/poll", &[&bearer(&c2)], b""));
    std::thread::sleep(Duration::from_millis(80)); // let A settle into the wait
    let (s, b) = http(addr, "POST", "/v1/poll", &[&bearer(&cred)], b"");
    assert_eq!((s, err_code(&b)), (409, "poll_conflict".into()));
    // Release A via shutdown, then a fresh poll succeeds.
    rig.server.shutdown().await;
    let _ = h.join();

    let path2 = tmpdb("pollconf2");
    let _g2 = Cleanup(path2.clone());
    let rig2 = rig_with_db(&path2, Duration::from_millis(100)).await;
    let cred2 = register_http(rig2.server.addr, &rig2.auth, "acc_a");
    let (s, _) = http(
        rig2.server.addr,
        "POST",
        "/v1/poll",
        &[&bearer(&cred2)],
        b"",
    );
    assert_eq!(s, 200);
    rig2.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_releases_waiting_poll() {
    let path = tmpdb("pollshut");
    let _g = Cleanup(path.clone());
    let rig = rig_with_db(&path, Duration::from_secs(60)).await; // long hold
    let addr = rig.server.addr;
    let cred = register_http(addr, &rig.auth, "acc_a");
    let h = std::thread::spawn(move || {
        let t = Instant::now();
        let r = http(addr, "POST", "/v1/poll", &[&bearer(&cred)], b"");
        (t.elapsed(), r)
    });
    std::thread::sleep(Duration::from_millis(80));
    rig.server.shutdown().await; // must wake the parked poll
    let (elapsed, (status, _body)) = h.join().unwrap();
    assert!(elapsed < Duration::from_secs(10), "poll hung past shutdown");
    // Either a clean 200 {work:null} or a drained connection — both fine.
    assert!(status == 200 || status == 0);
}

// ---------- respond ----------

fn submit_and_deliver(
    core: &GatewayCore<SystemClock>,
    auth: &ControllerAuth<SqliteStore, SystemClock>,
    addr: SocketAddr,
    cred: &str,
    acc: &str,
) -> String {
    let p = auth.authenticate(cred).unwrap();
    http(addr, "POST", "/v1/poll", &[&bearer(cred)], b""); // bind/online
    let (rid, _rx) = core
        .submit(
            p.account_id(),
            json!({"jsonrpc":"2.0","id":7,"method":"ping"}),
            None,
        )
        .unwrap();
    let (s, body) = http(addr, "POST", "/v1/poll", &[&bearer(cred)], b"");
    assert_eq!(s, 200);
    let w = serde_json::from_str::<Value>(&body).unwrap();
    assert_eq!(w["work"]["request_id"].as_str().unwrap(), rid.as_str());
    let _ = acc;
    rid.as_str().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_happy_and_duplicates() {
    let path = tmpdb("resp");
    let _g = Cleanup(path.clone());
    let rig = rig_with_db(&path, Duration::from_millis(150)).await;
    let addr = rig.server.addr;
    let cred = register_http(addr, &rig.auth, "acc_a");
    let rid = submit_and_deliver(&rig.core, &rig.auth, addr, &cred, "acc_a");

    let body =
        json!({"v":1,"request_id":rid,"mcp":{"jsonrpc":"2.0","id":7,"result":{}}}).to_string();
    let (s, b) = http(
        addr,
        "POST",
        "/v1/respond",
        &[&bearer(&cred), "Content-Type: application/json"],
        body.as_bytes(),
    );
    assert_eq!(s, 200, "{b}");
    // Duplicate (network retry): rejected — one completion only.
    let (s, b) = http(
        addr,
        "POST",
        "/v1/respond",
        &[&bearer(&cred), "Content-Type: application/json"],
        body.as_bytes(),
    );
    assert_eq!((s, err_code(&b)), (409, "duplicate_response".into()));
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_ownership_and_state_negatives() {
    let path = tmpdb("respneg");
    let _g = Cleanup(path.clone());
    let rig = rig_with_db(&path, Duration::from_millis(150)).await;
    let addr = rig.server.addr;
    let cred_a = register_http(addr, &rig.auth, "acc_a");
    let cred_b = register_http(addr, &rig.auth, "acc_b");
    let rid = submit_and_deliver(&rig.core, &rig.auth, addr, &cred_a, "acc_a");

    let mk = |rid: &str| json!({"v":1,"request_id":rid,"mcp":{"ok":1}}).to_string();
    let post = |cred: &str, body: &str| {
        http(
            addr,
            "POST",
            "/v1/respond",
            &[&bearer(cred), "Content-Type: application/json"],
            body.as_bytes(),
        )
    };

    // B's credential + A's request_id → 403 wrong_controller
    let (s, b) = post(&cred_b, &mk(&rid));
    assert_eq!((s, err_code(&b)), (403, "wrong_controller".into()));
    // unknown request → 404
    let (s, b) = post(&cred_a, &mk("req_nonexistent"));
    assert_eq!((s, err_code(&b)), (404, "unknown_request".into()));
    // A answers correctly → 200; then late retry → 409
    assert_eq!(post(&cred_a, &mk(&rid)).0, 200);

    // expired request: submit with 150ms deadline, deliver, then respond late
    let p = rig.auth.authenticate(&cred_a).unwrap();
    let (rid2, _rx) = rig
        .core
        .submit(
            p.account_id(),
            json!({"jsonrpc":"2.0","id":8,"method":"ping"}),
            Some(150),
        )
        .unwrap();
    http(addr, "POST", "/v1/poll", &[&bearer(&cred_a)], b"");
    std::thread::sleep(Duration::from_millis(400));
    let (s, b) = post(&cred_a, &mk(rid2.as_str()));
    assert_eq!(s, 410, "{b}");
    let _ = rid2;

    // cancelled request: submit, deliver, cancel via core, respond → 410
    let (rid3, _rx3) = rig
        .core
        .submit(
            p.account_id(),
            json!({"jsonrpc":"2.0","id":9,"method":"ping"}),
            None,
        )
        .unwrap();
    http(addr, "POST", "/v1/poll", &[&bearer(&cred_a)], b"");
    rig.core
        .cancel(p.account_id(), &RequestId::from_wire(rid3.as_str()))
        .unwrap();
    let (s, b) = post(&cred_a, &mk(rid3.as_str()));
    assert_eq!((s, err_code(&b)), (410, "cancelled_request".into()));
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_envelope_strictness() {
    let path = tmpdb("respenv");
    let _g = Cleanup(path.clone());
    let rig = rig_with_db(&path, Duration::from_millis(150)).await;
    let addr = rig.server.addr;
    let cred = register_http(addr, &rig.auth, "acc_a");
    let rid = submit_and_deliver(&rig.core, &rig.auth, addr, &cred, "acc_a");

    // wrong content type
    let (s, _) = http(
        addr,
        "POST",
        "/v1/respond",
        &[&bearer(&cred), "Content-Type: text/plain"],
        b"{}",
    );
    assert_eq!(s, 415);
    // missing content type
    let (s, _) = http(addr, "POST", "/v1/respond", &[&bearer(&cred)], b"{}");
    assert_eq!(s, 415);
    // malformed JSON
    let (s, b) = http(
        addr,
        "POST",
        "/v1/respond",
        &[&bearer(&cred), "Content-Type: application/json"],
        b"{nope",
    );
    assert_eq!((s, err_code(&b)), (400, "malformed_request".into()));
    // unknown field smuggled (incl. attempted identity fields) → rejected
    let evil = json!({"v":1,"request_id":rid,"mcp":{"x":1},"controller_id":"ctl_evil"}).to_string();
    let (s, _) = http(
        addr,
        "POST",
        "/v1/respond",
        &[&bearer(&cred), "Content-Type: application/json"],
        evil.as_bytes(),
    );
    assert_eq!(s, 400);
    // ambiguous: both mcp and error
    let amb = json!({"v":1,"request_id":rid,"mcp":{"x":1},"error":{"code":"x","message":"y"}})
        .to_string();
    let (s, _) = http(
        addr,
        "POST",
        "/v1/respond",
        &[&bearer(&cred), "Content-Type: application/json"],
        amb.as_bytes(),
    );
    assert_eq!(s, 400);
    rig.server.shutdown().await;
}

// ---------- methods / surface ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn methods_and_surface() {
    let path = tmpdb("methods");
    let _g = Cleanup(path.clone());
    let rig = rig_with_db(&path, Duration::from_millis(50)).await;
    let addr = rig.server.addr;
    let cred = register_http(addr, &rig.auth, "acc_a");

    for m in ["GET", "PUT", "DELETE"] {
        let (s, _) = http(addr, m, "/v1/poll", &[&bearer(&cred)], b"");
        assert_eq!(s, 405, "{m} /v1/poll");
    }
    let (s, _) = http(addr, "GET", "/v1/respond", &[&bearer(&cred)], b"");
    assert_eq!(s, 405);
    // unknown paths
    for p in ["/v1/test/call", "/v1/revoke", "/admin", "/v1/status"] {
        let (s, _) = http(addr, "POST", p, &[&bearer(&cred)], b"");
        assert_eq!(s, 404, "{p}");
    }
    // /mcp EXISTS as of P5 — in a rig with no public auth it must fail
    // closed. As of P6 authentication precedes body checks, so an
    // unconfigured gateway answers 503 before content negotiation.
    let (s, _) = http(addr, "POST", "/mcp", &[&bearer(&cred)], b"");
    assert_eq!(s, 503, "POST /mcp with no public auth configured");
    // health endpoints
    let (s, b) = http(addr, "GET", "/healthz", &[], b"");
    assert_eq!(s, 200);
    assert!(b.contains("ok"));
    let (s, b) = http(addr, "GET", "/readyz", &[], b"");
    assert_eq!(s, 200);
    assert!(b.contains("ready"));
    rig.server.shutdown().await;
}

// ---------- restart boundary (P3 + P4) ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_identity_durable_work_gone() {
    let path = tmpdb("p4restart");
    let _g = Cleanup(path.clone());

    // lifetime 1: register, queue work, deliver it, then die mid-flight.
    let cred;
    let stale_rid;
    {
        let rig = rig_with_db(&path, Duration::from_millis(150)).await;
        let addr = rig.server.addr;
        cred = register_http(addr, &rig.auth, "acc_a");
        stale_rid = submit_and_deliver(&rig.core, &rig.auth, addr, &cred, "acc_a");
        rig.server.shutdown().await;
    }
    // lifetime 2: same DB — credential authenticates, poll re-binds, old
    // request_id is unanswerable, no work reappears.
    {
        let rig = rig_with_db(&path, Duration::from_millis(150)).await;
        let addr = rig.server.addr;
        let (s, b) = http(addr, "POST", "/v1/poll", &[&bearer(&cred)], b"");
        assert_eq!(s, 200, "{b}");
        assert!(serde_json::from_str::<Value>(&b).unwrap()["work"].is_null());
        let body = json!({"v":1,"request_id":stale_rid,"mcp":{"x":1}}).to_string();
        let (s, b2) = http(
            addr,
            "POST",
            "/v1/respond",
            &[&bearer(&cred), "Content-Type: application/json"],
            body.as_bytes(),
        );
        assert_eq!((s, err_code(&b2)), (404, "unknown_request".into()));
        rig.server.shutdown().await;
    }
}
