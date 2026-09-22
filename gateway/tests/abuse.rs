//! P7 — abuse tests (RFC §N): rate-limit boundaries over real HTTP,
//! cross-account isolation, forwarded-header immunity, invalid-auth
//! flood self-limiting, uniform 429 contract, F-03 foreign cancel.

use serde_json::{json, Value};
use sinter_gateway::rate_limit::{RateLimiter, RateLimits};
use sinter_gateway::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

// ---------- infra (mirrors tests/mcp_http.rs conventions) ----------

struct Rig {
    server: GatewayServer,
    auth: Arc<ControllerAuth<SqliteStore, SystemClock>>,
}

fn tmpdb(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sinter-gw-p7-{}", std::process::id()));
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

const TOKEN_A: &str = "testpub-aaa";
const TOKEN_B: &str = "testpub-bbb";
const ORIGIN: &str = "https://chatgpt.com";

/// Near-zero rates: bursts are code constants, refill is negligible for
/// the test duration — limits trip deterministically without sleeps.
fn tight_limits() -> RateLimits {
    RateLimits {
        enabled: true,
        mcp_rps: 0.001,
        mcp_burst: 4,
        mcp_global_rps: 1000.0,
        poll_rps: 0.001,
        respond_rps: 1000.0,
        register_per_min: 0.06,
        rotate_per_min: 0.06,
        authfail_per_min: 6.0,
    }
}

async fn rig(path: &PathBuf, limits: RateLimits) -> Rig {
    let core = Arc::new(GatewayCore::with_clock(SystemClock));
    let store = Arc::new(SqliteStore::open(path).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let mut pa = TestPublicAuth::new();
    pa.add(TOKEN_A, "acc_a", "subject-a@example.com");
    pa.add(TOKEN_B, "acc_b", "subject-b@example.com");
    let state = GatewayHttp::new(core.clone(), auth.clone(), store)
        .with_poll_hold(Duration::from_millis(120))
        .with_mcp_deadline(Duration::from_secs(5))
        .with_public_auth(Arc::new(pa), [ORIGIN.to_string()].into_iter().collect())
        .with_limiter(Arc::new(RateLimiter::new(SystemClock, limits)));
    let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();
    Rig { server, auth }
}

fn http_full(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &[u8],
) -> (u16, HashMap<String, String>, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    for h in headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let _ = s.write_all(req.as_bytes());
    let _ = s.write_all(body);
    let _ = s.flush();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    let hdrs: HashMap<String, String> = head
        .lines()
        .skip(1)
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
        })
        .collect();
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, hdrs, body)
}

fn bearer(t: &str) -> String {
    format!("Authorization: Bearer {t}")
}

fn mcp_headers(token: &str, sid: Option<&str>, extra: &[&str]) -> Vec<String> {
    let mut h = vec![
        format!("X-Sinter-Test-Principal: {token}"),
        format!("Origin: {ORIGIN}"),
        "Content-Type: application/json".to_string(),
    ];
    if let Some(s) = sid {
        h.push(format!("MCP-Session-Id: {s}"));
        h.push("MCP-Protocol-Version: 2025-03-26".to_string());
    }
    for e in extra {
        h.push(e.to_string());
    }
    h
}

fn mcp_post(
    addr: SocketAddr,
    token: &str,
    sid: Option<&str>,
    frame: &Value,
    extra: &[&str],
) -> (u16, HashMap<String, String>, String) {
    let h = mcp_headers(token, sid, extra);
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    http_full(addr, "POST", "/mcp", &hs, frame.to_string().as_bytes())
}

fn init_session(addr: SocketAddr, token: &str) -> String {
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}});
    let (s, hdrs, body) = mcp_post(addr, token, None, &init, &[]);
    assert_eq!(s, 200, "{body}");
    hdrs["mcp-session-id"].clone()
}

fn register(
    addr: SocketAddr,
    auth: &ControllerAuth<SqliteStore, SystemClock>,
    acc: &str,
) -> String {
    let token = auth.issue_registration_token(&AccountId::new(acc)).unwrap();
    let body = json!({"token": token.expose()}).to_string();
    let (s, _h, b) = http_full(
        addr,
        "POST",
        "/v1/register",
        &["Content-Type: application/json"],
        body.as_bytes(),
    );
    assert_eq!(s, 200, "{b}");
    serde_json::from_str::<Value>(&b).unwrap()["credential"]
        .as_str()
        .unwrap()
        .to_string()
}

fn assert_429(status: u16, hdrs: &HashMap<String, String>, body: &str) {
    assert_eq!(status, 429, "{body}");
    assert!(hdrs.contains_key("retry-after"), "Retry-After required");
    assert!(
        hdrs["retry-after"].parse::<u64>().unwrap() >= 1,
        "Retry-After must be >= 1s"
    );
    let v: Value = serde_json::from_str(body).unwrap();
    assert_eq!(v["error"]["code"], "rate_limited", "uniform body");
    assert_eq!(v["error"]["message"], "rate limit exceeded");
}

// ---------- tests ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_account_burst_then_429() {
    let path = tmpdb("burst");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, tight_limits()).await;
    let addr = rig.server.addr;

    // burst=4: init + 3 pings admitted; 5th → 429.
    let sid = init_session(addr, TOKEN_A);
    for i in 0..3 {
        let (s, _h, b) = mcp_post(
            addr,
            TOKEN_A,
            Some(&sid),
            &json!({"jsonrpc":"2.0","id":i,"method":"ping"}),
            &[],
        );
        assert_eq!(s, 200, "req {i}: {b}");
    }
    let (s, h, b) = mcp_post(
        addr,
        TOKEN_A,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":99,"method":"ping"}),
        &[],
    );
    assert_429(s, &h, &b);
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_account_isolation() {
    let path = tmpdb("xacct");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, tight_limits()).await;
    let addr = rig.server.addr;

    // Exhaust acc_a's bucket.
    let sid_a = init_session(addr, TOKEN_A);
    for i in 0..3 {
        mcp_post(
            addr,
            TOKEN_A,
            Some(&sid_a),
            &json!({"jsonrpc":"2.0","id":i,"method":"ping"}),
            &[],
        );
    }
    let (s, _h, b) = mcp_post(
        addr,
        TOKEN_A,
        Some(&sid_a),
        &json!({"jsonrpc":"2.0","id":9,"method":"ping"}),
        &[],
    );
    assert_eq!(s, 429, "{b}");

    // acc_b untouched.
    let sid_b = init_session(addr, TOKEN_B);
    let (s, _h, b) = mcp_post(
        addr,
        TOKEN_B,
        Some(&sid_b),
        &json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
        &[],
    );
    assert_eq!(s, 200, "{b}");
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poll_rate_limited() {
    let path = tmpdb("poll");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, tight_limits()).await;
    let addr = rig.server.addr;
    let cred = register(addr, &rig.auth, "acc_a");
    let b = bearer(&cred);

    // POLL_BURST=5: first 5 admitted (each waits poll_hold=120ms), 6th → 429.
    for i in 0..5 {
        let (s, _h, body) = http_full(addr, "POST", "/v1/poll", &[&b], b"");
        assert_eq!(s, 200, "poll {i}: {body}");
    }
    let (s, h, body) = http_full(addr, "POST", "/v1/poll", &[&b], b"");
    assert_429(s, &h, &body);
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_per_ip_rate_limited() {
    let path = tmpdb("reg");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, tight_limits()).await;
    let addr = rig.server.addr;

    // REGISTER_BURST=10: bad tokens → 401 ×10, then 429 — before auth even runs.
    for i in 0..10 {
        let (s, _h, b) = http_full(
            addr,
            "POST",
            "/v1/register",
            &["Content-Type: application/json"],
            json!({"token": "bogus"}).to_string().as_bytes(),
        );
        assert_eq!(s, 401, "register {i}: {b}");
    }
    let (s, h, b) = http_full(
        addr,
        "POST",
        "/v1/register",
        &["Content-Type: application/json"],
        json!({"token": "bogus"}).to_string().as_bytes(),
    );
    assert_429(s, &h, &b);
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwarded_headers_cannot_reset_ip_bucket() {
    let path = tmpdb("xff");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, tight_limits()).await;
    let addr = rig.server.addr;

    // Burn the RegisterIp bucket while varying forwarding headers — the
    // socket IP is the only key, so spoofed headers cannot mint fresh
    // buckets.
    let spoofs = [
        "X-Forwarded-For: 1.2.3.4",
        "X-Forwarded-For: 9.9.9.9",
        "X-Real-IP: 8.8.8.8",
        "Forwarded: for=203.0.113.66;proto=https",
        "X-Forwarded-For: 127.0.0.1",
    ];
    let mut limited_at = None;
    for i in 0..12 {
        let extra = spoofs[i % spoofs.len()];
        let (s, h, b) = http_full(
            addr,
            "POST",
            "/v1/register",
            &["Content-Type: application/json", extra],
            json!({"token": "bogus"}).to_string().as_bytes(),
        );
        if s == 429 {
            assert_429(s, &h, &b);
            limited_at = Some(i);
            break;
        }
    }
    assert_eq!(
        limited_at,
        Some(10),
        "bucket must be keyed on socket IP, immune to forwarded headers"
    );
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotate_rate_limited() {
    let path = tmpdb("rot");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, tight_limits()).await;
    let addr = rig.server.addr;
    let mut cred = register(addr, &rig.auth, "acc_a");

    // ROTATE_BURST=20 → 20 rotations OK, 21st → 429. Each rotation
    // invalidates the old credential — chain the fresh one.
    for i in 0..20 {
        let b = bearer(&cred);
        let (s, _h, body) = http_full(addr, "POST", "/v1/rotate", &[&b], b"");
        assert_eq!(s, 200, "rotate {i}: {body}");
        cred = serde_json::from_str::<Value>(&body).unwrap()["credential"]
            .as_str()
            .unwrap()
            .to_string();
    }
    let b = bearer(&cred);
    let (s, h, body) = http_full(addr, "POST", "/v1/rotate", &[&b], b"");
    assert_429(s, &h, &body);
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_auth_flood_self_limits() {
    let path = tmpdb("authfail");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, tight_limits()).await;
    let addr = rig.server.addr;

    // AUTHFAIL_BURST=60, rate 6/min → 60×401 then 429 (not 401).
    let bad = bearer("garbage-credential");
    let mut saw = (0, 0);
    for i in 0..70 {
        let (s, h, b) = http_full(addr, "POST", "/v1/poll", &[&bad], b"");
        if s == 429 {
            assert_429(s, &h, &b);
            saw = (i, 429);
            break;
        }
        assert_eq!(s, 401, "bad auth {i} must be 401 until the cap: {b}");
    }
    assert_eq!(saw, (60, 429), "invalid-auth bucket must cap at burst 60");
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limit_body_is_uniform_across_routes() {
    let path = tmpdb("uniform");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, tight_limits()).await;
    let addr = rig.server.addr;

    // Force a /mcp 429 and a /v1/poll 429; bodies must be identical —
    // no route, identity, or bucket detail may leak.
    let cred = register(addr, &rig.auth, "acc_a");
    let b = bearer(&cred);
    for _ in 0..5 {
        http_full(addr, "POST", "/v1/poll", &[&b], b"");
    }
    let (_, _, poll_body) = http_full(addr, "POST", "/v1/poll", &[&b], b"");

    let sid = init_session(addr, TOKEN_A);
    for i in 0..3 {
        mcp_post(
            addr,
            TOKEN_A,
            Some(&sid),
            &json!({"jsonrpc":"2.0","id":i,"method":"ping"}),
            &[],
        );
    }
    let (s, _h, mcp_body) = mcp_post(
        addr,
        TOKEN_A,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":9,"method":"ping"}),
        &[],
    );
    assert_eq!(s, 429);
    assert_eq!(poll_body, mcp_body, "429 body must be uniform");
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_body_is_413_not_429() {
    let path = tmpdb("big");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, tight_limits()).await;
    let addr = rig.server.addr;
    // 5 MiB of body on /mcp with a valid principal → 413 (cap), never 429.
    let sid = init_session(addr, TOKEN_A);
    let big = vec![b'x'; 5 << 20];
    let h = mcp_headers(TOKEN_A, Some(&sid), &[]);
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    let (s, _h, _b) = http_full(addr, "POST", "/mcp", &hs, &big);
    assert_eq!(s, 413, "oversized body must be 413");
    rig.server.shutdown().await;
}

#[test]
fn f03_foreign_account_cannot_cancel() {
    // Core-level F-03: a RequestId alone never authorizes cancellation.
    let c = GatewayCore::new();
    let acc_a = AccountId::new("acc_a");
    let acc_b = AccountId::new("acc_b");
    let ctl = ControllerId::new("ctl_a");
    c.register_controller(&ctl, &acc_a).unwrap();
    c.poll(&ctl).unwrap(); // online
    let (rid, rx) = c
        .submit(
            &acc_a,
            json!({"jsonrpc":"2.0","id":7,"method":"ping"}),
            None,
        )
        .unwrap();

    // acc_b presents acc_a's rid — must be refused and leave state untouched.
    let e = c.cancel(&acc_b, &rid).unwrap_err();
    assert_eq!(e.code, "wrong_account");
    assert_eq!(c.request_state(&rid), Some(ReqState::Queued));

    // Owner cancel works; late respond then fails loudly.
    c.cancel(&acc_a, &rid).unwrap();
    assert_eq!(c.request_state(&rid), Some(ReqState::Cancelled));
    let e = c
        .respond(&ctl, &rid, Outcome::Mcp(json!({"ok":1})))
        .unwrap_err();
    assert_eq!(e.code, "cancelled_request");
    match rx.recv_timeout(Duration::from_secs(1)).unwrap() {
        Outcome::Transport(t) => assert_eq!(t.code, "cancelled_request"),
        Outcome::Mcp(_) => panic!("cancelled request must not complete"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f03_foreign_cancel_notification_noop_over_http() {
    // HTTP-level: acc_b's notifications/cancelled naming acc_a's in-flight
    // request id must be a no-op; the request completes normally.
    let path = tmpdb("f03");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, RateLimits::default()).await;
    let addr = rig.server.addr;
    let cred = register(addr, &rig.auth, "acc_a");
    let b = bearer(&cred);

    // Bind + mark online.
    http_full(addr, "POST", "/v1/poll", &[&b], b"");

    let sid_a = init_session(addr, TOKEN_A);
    let sid_b = init_session(addr, TOKEN_B);

    // acc_a starts a tools/call in a thread — it blocks until respond.
    let (tx, rx) = std::sync::mpsc::channel();
    let addr2 = addr;
    let sid_a2 = sid_a.clone();
    let call = json!({"jsonrpc":"2.0","id":42,"method":"tools/call",
        "params":{"name":"sinter_get_version","arguments":{}}});
    let t = std::thread::spawn(move || {
        let r = mcp_post(addr2, TOKEN_A, Some(&sid_a2), &call, &[]);
        tx.send(r).unwrap();
    });

    // Poll until the work is delivered — deterministic rendezvous: the
    // request exists iff the controller receives it.
    let mut work = None;
    for _ in 0..50 {
        let (s, _h, body) = http_full(addr, "POST", "/v1/poll", &[&b], b"");
        assert_eq!(s, 200, "{body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        if let Some(w) = v.get("work").filter(|w| w.is_object()) {
            work = Some(w.clone());
            break;
        }
    }
    let work = work.expect("request must be delivered");
    let rid = work["request_id"].as_str().unwrap().to_string();

    // acc_b attempts to cancel acc_a's request by its public JSON-RPC id.
    let (s, _h, b2) = mcp_post(
        addr,
        TOKEN_B,
        Some(&sid_b),
        &json!({"jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":42,"reason":"malicious"}}),
        &[],
    );
    assert_eq!(s, 202, "{b2}");

    // acc_b also cannot cancel the internal request_id directly via any
    // public surface — verified at core level above.

    // Controller responds normally → acc_a's call completes with 200.
    let rb = json!({"v":1,"request_id":rid,"mcp":{
        "jsonrpc":"2.0","id":42,"result":{"ok":true}}});
    let (s, _h, b2) = http_full(
        addr,
        "POST",
        "/v1/respond",
        &[&b, "Content-Type: application/json"],
        rb.to_string().as_bytes(),
    );
    assert_eq!(s, 200, "{b2}");

    let (s, _h, body) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(s, 200, "foreign cancel must not kill the request: {body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["result"]["ok"], true);
    t.join().unwrap();
    rig.server.shutdown().await;
}

/// F-08 verification (P7 verify-only): a panic inside poll_wait's locked
/// region (e.g. the still_authorised store callback) poisons the core
/// mutex — the process fails STOP, never silently delivering work through
/// a dead auth path. The future RAII redesign remains out of P7 scope.
#[test]
fn f08_poll_panic_is_fail_stop_not_silent() {
    let c = GatewayCore::new();
    let acc = AccountId::new("a");
    let ctl = ControllerId::new("c");
    c.register_controller(&ctl, &acc).unwrap();
    c.poll(&ctl).unwrap(); // online
                           // Queue work so the still_authorised re-check actually runs.
    c.submit(
        &acc,
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
        None,
    )
    .unwrap();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        c.poll_wait(
            &ctl,
            Duration::from_millis(10),
            || -> Result<(), TransportError> { panic!("simulated store panic") },
        )
    }));
    assert!(res.is_err(), "panic must propagate");
    // Poisoned mutex → every core op panics. Fail-stop: a revoked-controller
    // check that cannot run can never pass silently.
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.poll(&ctl))).is_err(),
        "poisoned core must panic, not serve"
    );
}
