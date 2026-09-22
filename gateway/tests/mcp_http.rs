//! P5 — public /mcp ingress integration tests over real loopback HTTP.
//! Includes a `sinter-bridge`-shaped controller loop driving a REAL
//! `sinter mcp` child over stdio (the production path end-to-end).

use serde_json::{json, Value};
use sinter_gateway::edge::PROFILE_TOOL;
use sinter_gateway::*;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ---------- infra ----------

struct Rig {
    server: GatewayServer,
    core: Arc<GatewayCore<SystemClock>>,
    auth: Arc<ControllerAuth<SqliteStore, SystemClock>>,
}

fn tmpdb(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sinter-gw-p5-{}", std::process::id()));
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

const TEST_TOKEN_A: &str = "testpub-aaa";
const TEST_TOKEN_B: &str = "testpub-bbb";
const ORIGIN: &str = "https://chatgpt.com";

async fn rig(path: &PathBuf, with_auth: bool) -> Rig {
    let core = Arc::new(GatewayCore::with_clock(SystemClock));
    let store = Arc::new(SqliteStore::open(path).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let mut state = GatewayHttp::new(core.clone(), auth.clone(), store.clone())
        .with_poll_hold(Duration::from_millis(150));
    if with_auth {
        let mut pa = TestPublicAuth::new();
        pa.add(TEST_TOKEN_A, "acc_a", "subject-a@example.com");
        pa.add(TEST_TOKEN_B, "acc_b", "subject-b@example.com");
        state = state.with_public_auth(Arc::new(pa), [ORIGIN.to_string()].into_iter().collect());
    }
    let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();
    Rig { server, core, auth }
}

/// Full HTTP response: status, headers, body.
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
    // Best-effort writes: hyper may reject malformed headers and close the
    // socket before draining the body (ECONNRESET on write is expected for
    // those cases — the response is still readable).
    let _ = s.write_all(req.as_bytes());
    let _ = s.write_all(body);
    let _ = s.flush();
    // Early-reject responses (400 before body is drained) arrive followed
    // by a TCP RST — read_to_end then errors but keeps buffered bytes.
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

fn pubhdrs(sid: Option<&str>) -> Vec<String> {
    let mut h = vec![
        format!("X-Sinter-Test-Principal: {TEST_TOKEN_A}"),
        format!("Origin: {ORIGIN}"),
        "Content-Type: application/json".to_string(),
    ];
    if let Some(s) = sid {
        h.push(format!("MCP-Session-Id: {s}"));
        h.push("MCP-Protocol-Version: 2025-03-26".to_string());
    }
    h
}

fn mcp_post(
    addr: SocketAddr,
    sid: Option<&str>,
    frame: &Value,
) -> (u16, HashMap<String, String>, String) {
    let h: Vec<String> = pubhdrs(sid);
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    http_full(addr, "POST", "/mcp", &hs, frame.to_string().as_bytes())
}

/// initialize → session id.
fn init_session(addr: SocketAddr) -> String {
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}});
    let (s, hdrs, body) = mcp_post(addr, None, &init);
    assert_eq!(s, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["result"]["serverInfo"]["name"], "sinter-gateway");
    assert_eq!(v["result"]["capabilities"]["tools"]["listChanged"], false);
    let sid = hdrs["mcp-session-id"].clone();
    assert!(sid.starts_with("sess_"));
    // notifications/initialized → 202, no body
    let (s, _h, b) = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert_eq!((s, b.as_str()), (202, ""));
    sid
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

/// Bridge-shaped controller loop: poll → run frame through real `sinter mcp`
/// (or a stub) → respond. Stop via flag.
struct Bridge {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

struct SinterChild {
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    _proc: Child,
}

impl SinterChild {
    fn spawn() -> Option<Self> {
        let bin = std::env::var("SINTER_BIN").unwrap_or_else(|_| {
            "/Volumes/VGX1000 SSD/Codex/Projects/Sinter/target/debug/sinter".into()
        });
        let mut p = Command::new(&bin)
            .args(["mcp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        Some(Self {
            stdin: p.stdin.take().unwrap(),
            stdout: BufReader::new(p.stdout.take().unwrap()),
            _proc: p,
        })
    }
    fn call(&mut self, frame: &Value) -> Value {
        writeln!(self.stdin, "{frame}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

/// Start a bridge loop. `use_real_sinter` = production path through real
/// `sinter mcp`; false = stub that echoes a canned response (still exercises
/// the full HTTP envelope path).
fn start_bridge(addr: SocketAddr, cred: String, use_real_sinter: bool) -> Bridge {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let join = std::thread::spawn(move || {
        let mut child = if use_real_sinter {
            SinterChild::spawn()
        } else {
            None
        };
        let bearer = format!("Authorization: Bearer {cred}");
        while !stop2.load(Ordering::SeqCst) {
            let (s, _h, body) = http_full(addr, "POST", "/v1/poll", &[&bearer], b"");
            if s != 200 {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            let v: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(work) = v.get("work").cloned().filter(|w| w.is_object()) else {
                continue;
            };
            let rid = work["request_id"].as_str().unwrap().to_string();
            let frame = &work["mcp"];
            let resp = if let Some(c) = child.as_mut() {
                c.call(frame)
            } else {
                json!({"jsonrpc":"2.0","id":frame["id"],"result":{"ok":true}})
            };
            let rb = json!({"v":1,"request_id":rid,"mcp":resp}).to_string();
            let (s2, _h, b2) = http_full(
                addr,
                "POST",
                "/v1/respond",
                &[&bearer, "Content-Type: application/json"],
                rb.as_bytes(),
            );
            if s2 != 200 {
                eprintln!("bridge respond failed: {s2} {b2}");
            }
        }
    });
    Bridge {
        stop,
        join: Some(join),
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

// ---------- tests ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_to_end_real_sinter_mcp() {
    let path = tmpdb("e2e");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    let addr = rig.server.addr;
    let cred = register(addr, &rig.auth, "acc_a");
    let bridge = start_bridge(addr, cred, true); // real sinter mcp

    let sid = init_session(addr);

    // tools/list forwarded through bridge → real sinter → 8 tools + profile.
    let (s, _h, b) = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":77,"method":"tools/list"}),
    );
    assert_eq!(s, 200, "{b}");
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["id"], 77);
    let tools = v["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(tools.len(), 9, "{names:?}");
    assert!(names.contains(&"sinter_get_version"));
    assert!(names.contains(&"sinter_audit_host"));
    assert_eq!(names.iter().filter(|n| **n == PROFILE_TOOL).count(), 1);
    let profile = tools.iter().find(|t| t["name"] == PROFILE_TOOL).unwrap();
    assert_eq!(profile["_meta"]["openai/profile"], true);
    assert_eq!(profile["annotations"]["readOnlyHint"], true);

    // tools/call forwarded verbatim — caller id preserved (weird string).
    let (s, _h, b) = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":"weird-id-42",
        "method":"tools/call","params":{"name":"sinter_get_version","arguments":{}}}),
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["id"], "weird-id-42");
    assert_eq!(v["result"]["isError"], false);

    // profile tool resolved at the edge — never reaches the controller.
    let (s, _h, b) = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":9,
        "method":"tools/call","params":{"name":PROFILE_TOOL,"arguments":{}}}),
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["result"]["structuredContent"]["id"], "acc_a");
    assert_eq!(v["result"]["isError"], false);

    drop(bridge);
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_fails_closed_without_public_auth() {
    let path = tmpdb("noauth");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, false).await; // no public auth configured
                                       // No Origin header (origin check passes trivially); request must reach
                                       // the auth layer and fail closed — there is no anonymous path.
    let (s, _h, b) = http_full(
        rig.server.addr,
        "POST",
        "/mcp",
        &[
            "Content-Type: application/json",
            "X-Sinter-Test-Principal: testpub-aaa",
        ],
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(s, 503, "{b}");
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_auth_and_session_isolation() {
    let path = tmpdb("sesiso");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    let addr = rig.server.addr;
    let sid_a = init_session(addr);

    // account B principal gets its own session
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
    let h_b = [
        format!("X-Sinter-Test-Principal: {TEST_TOKEN_B}"),
        "Content-Type: application/json".to_string(),
    ];
    let hs: Vec<&str> = h_b.iter().map(String::as_str).collect();
    let (s, hdrs, _b) = http_full(addr, "POST", "/mcp", &hs, init.to_string().as_bytes());
    assert_eq!(s, 200);
    let sid_b = hdrs["mcp-session-id"].clone();

    // no credential at all → 401
    let (s, _h, _b) = http_full(
        addr,
        "POST",
        "/mcp",
        &["Content-Type: application/json"],
        init.to_string().as_bytes(),
    );
    assert_eq!(s, 401);
    // bad credential → 401
    let (s, _h, _b) = http_full(
        addr,
        "POST",
        "/mcp",
        &[
            "Content-Type: application/json",
            "X-Sinter-Test-Principal: wrong",
        ],
        init.to_string().as_bytes(),
    );
    assert_eq!(s, 401);

    // A's session + B's auth → 403 session mismatch
    let h = [
        format!("X-Sinter-Test-Principal: {TEST_TOKEN_B}"),
        "Content-Type: application/json".to_string(),
        format!("MCP-Session-Id: {sid_a}"),
    ];
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    let (s, _h2, b) = http_full(
        addr,
        "POST",
        "/mcp",
        &hs,
        json!({"jsonrpc":"2.0","id":2,"method":"ping"})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(s, 403, "{b}");

    // missing session on post-init call → 401 missing_auth
    let (s, _h, _b) = mcp_post(addr, None, &json!({"jsonrpc":"2.0","id":3,"method":"ping"}));
    assert_eq!(s, 401);

    // B cannot DELETE A's session → 403
    let (s, _h, _b) = http_full(addr, "DELETE", "/mcp", &hs, b"");
    assert_eq!(s, 403);

    // A deletes own → 200; reuse fails; second delete → deterministic 4xx
    let (s, _h, _b) = http_full(
        addr,
        "DELETE",
        "/mcp",
        &[
            &format!("X-Sinter-Test-Principal: {TEST_TOKEN_A}"),
            &format!("MCP-Session-Id: {sid_a}"),
        ],
        b"",
    );
    assert_eq!(s, 200);
    let (s, _h, _b) = http_full(
        addr,
        "DELETE",
        "/mcp",
        &[
            &format!("X-Sinter-Test-Principal: {TEST_TOKEN_A}"),
            &format!("MCP-Session-Id: {sid_a}"),
        ],
        b"",
    );
    assert_eq!(s, 404); // unknown_or_expired session → deterministic 404
    let (s, _h, _b) = mcp_post(
        addr,
        Some(&sid_a),
        &json!({"jsonrpc":"2.0","id":4,"method":"ping"}),
    );
    assert_eq!(s, 404);

    let _ = sid_b;
    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_version_origin_method_matrix() {
    let path = tmpdb("matrix");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    let addr = rig.server.addr;
    let sid = init_session(addr);

    let ping = json!({"jsonrpc":"2.0","id":5,"method":"ping"}).to_string();

    // valid version header → 200
    let h = pubhdrs(Some(&sid));
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    assert_eq!(http_full(addr, "POST", "/mcp", &hs, ping.as_bytes()).0, 200);
    // missing version header → allowed (assume 2025-03-26)
    let h: Vec<String> = pubhdrs(Some(&sid))
        .into_iter()
        .filter(|x| !x.starts_with("MCP-Protocol"))
        .collect();
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    assert_eq!(http_full(addr, "POST", "/mcp", &hs, ping.as_bytes()).0, 200);
    // unsupported version → 400
    let mut h = pubhdrs(Some(&sid));
    h.retain(|x| !x.starts_with("MCP-Protocol"));
    h.push("MCP-Protocol-Version: 1999-01-01".into());
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    assert_eq!(http_full(addr, "POST", "/mcp", &hs, ping.as_bytes()).0, 400);
    // duplicate version headers → 400
    let mut h = pubhdrs(Some(&sid));
    h.push("MCP-Protocol-Version: 2025-06-18".into());
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    assert_eq!(http_full(addr, "POST", "/mcp", &hs, ping.as_bytes()).0, 400);

    // Origin: allowed ok; wrong → 403; missing → ok; duplicate → 400
    let (s, _h, _b) = http_full(
        addr,
        "POST",
        "/mcp",
        &[
            &format!("X-Sinter-Test-Principal: {TEST_TOKEN_A}"),
            "Content-Type: application/json",
            &format!("MCP-Session-Id: {sid}"),
            "Origin: https://evil.example",
        ],
        ping.as_bytes(),
    );
    assert_eq!(s, 403);
    let h: Vec<String> = pubhdrs(Some(&sid))
        .into_iter()
        .filter(|x| !x.starts_with("Origin"))
        .collect();
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    assert_eq!(http_full(addr, "POST", "/mcp", &hs, ping.as_bytes()).0, 200); // absent ok
    let mut h = pubhdrs(Some(&sid));
    h.push("Origin: https://other.example".into());
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    assert_eq!(http_full(addr, "POST", "/mcp", &hs, ping.as_bytes()).0, 400); // duplicate

    // GET → 405; PUT → 405
    let (s, _h, _b) = http_full(
        addr,
        "GET",
        "/mcp",
        &pubhdrs(Some(&sid))
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        b"",
    );
    assert_eq!(s, 405);

    // content-type: missing → 415; wrong → 415; malformed JSON → 400
    let h = [
        format!("X-Sinter-Test-Principal: {TEST_TOKEN_A}"),
        format!("MCP-Session-Id: {sid}"),
    ];
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    assert_eq!(http_full(addr, "POST", "/mcp", &hs, ping.as_bytes()).0, 415);
    let h = [
        format!("X-Sinter-Test-Principal: {TEST_TOKEN_A}"),
        format!("MCP-Session-Id: {sid}"),
        "Content-Type: text/plain".into(),
    ];
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    assert_eq!(http_full(addr, "POST", "/mcp", &hs, ping.as_bytes()).0, 415);
    let (s, _h, b) = http_full(
        addr,
        "POST",
        "/mcp",
        &[
            &format!("X-Sinter-Test-Principal: {TEST_TOKEN_A}"),
            "Content-Type: application/json",
            &format!("MCP-Session-Id: {sid}"),
        ],
        b"{broken",
    );
    assert_eq!(s, 400, "{b}");

    // batch → -32600 (Streamable HTTP is single-message; deliberate reject)
    let (s, _h, b) = mcp_post(
        addr,
        Some(&sid),
        &json!([{"jsonrpc":"2.0","id":1,"method":"ping"}]),
    );
    assert_eq!(s, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&b).unwrap()["error"]["code"],
        -32600
    );

    // unknown method → -32601, and it never reaches the controller queue
    let (s, _h, b) = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":6,"method":"evil/exec"}),
    );
    assert_eq!(s, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&b).unwrap()["error"]["code"],
        -32601
    );

    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn caller_disconnect_cancels_owned_work() {
    let path = tmpdb("disconnect");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    let addr = rig.server.addr;
    let cred = register(addr, &rig.auth, "acc_a");
    // controller that polls and HOLDS work (never responds in time)
    let bearer = format!("Authorization: Bearer {cred}");
    let cred2 = cred.clone();
    let sid = init_session(addr);

    // Raw socket: start tools/call, read nothing, close.
    let mut sock = TcpStream::connect(addr).unwrap();
    let call = json!({"jsonrpc":"2.0","id":10,"method":"tools/call",
        "params":{"name":"sinter_get_version","arguments":{}}})
    .to_string();
    let auth_hdr = format!("X-Sinter-Test-Principal: {TEST_TOKEN_A}");
    let sid_hdr = format!("MCP-Session-Id: {sid}");
    let req = format!("POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n{auth_hdr}\r\n{sid_hdr}\r\nContent-Length: {}\r\n\r\n{}",
        call.len(), call);
    sock.write_all(req.as_bytes()).unwrap();
    sock.flush().unwrap();

    // controller picks up the work
    std::thread::sleep(Duration::from_millis(50));
    let (s, _h, body) = http_full(addr, "POST", "/v1/poll", &[&bearer], b"");
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&body).unwrap();
    let rid = v["work"]["request_id"].as_str().unwrap().to_string();

    // caller disconnects
    drop(sock);
    std::thread::sleep(Duration::from_millis(150));

    // request must be cancelled — late respond is rejected
    let rb = json!({"v":1,"request_id":rid,"mcp":{"x":1}}).to_string();
    let (s, _h, b) = http_full(
        addr,
        "POST",
        "/v1/respond",
        &[
            &format!("Authorization: Bearer {cred2}"),
            "Content-Type: application/json",
        ],
        rb.as_bytes(),
    );
    assert_eq!(
        (s, err_code_of(&b)),
        (410, "cancelled_request".into()),
        "{b}"
    );

    rig.server.shutdown().await;
}

fn err_code_of(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["error"]["code"].as_str().map(String::from))
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_delete_cancels_live_request() {
    let path = tmpdb("sesdel");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    let addr = rig.server.addr;
    let cred = register(addr, &rig.auth, "acc_a");
    let sid = init_session(addr);

    // submit a tools/call; deliver it to controller; then DELETE the session
    // while the call is in flight → live work cancelled.
    let call = json!({"jsonrpc":"2.0","id":11,"method":"tools/call",
        "params":{"name":"sinter_get_version","arguments":{}}});
    let sid2 = sid.clone();
    let h = std::thread::spawn(move || mcp_post(addr, Some(&sid2), &call));
    std::thread::sleep(Duration::from_millis(80));
    let (s, _h, body) = http_full(
        addr,
        "POST",
        "/v1/poll",
        &[&format!("Authorization: Bearer {cred}")],
        b"",
    );
    let v: Value = serde_json::from_str(&body).unwrap();
    let rid = v["work"]["request_id"].as_str().unwrap().to_string();
    assert_eq!(s, 200);

    let (s, _h, _b) = http_full(
        addr,
        "DELETE",
        "/mcp",
        &[
            &format!("X-Sinter-Test-Principal: {TEST_TOKEN_A}"),
            &format!("MCP-Session-Id: {sid}"),
        ],
        b"",
    );
    assert_eq!(s, 200);
    let _ = h.join();

    // late respond → request gone
    let rb = json!({"v":1,"request_id":rid,"mcp":{"x":1}}).to_string();
    let (s, _h, b) = http_full(
        addr,
        "POST",
        "/v1/respond",
        &[
            &format!("Authorization: Bearer {cred}"),
            "Content-Type: application/json",
        ],
        rb.as_bytes(),
    );
    assert_eq!(s, 410, "{b}");

    rig.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_controller_fails_loudly() {
    let path = tmpdb("offline");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    // Short public deadline — registered controller is "online" after bind
    // but never polls, so the request must fail at the deadline, not hang.
    rig.server.shutdown().await;
    let core = rig.core.clone();
    let auth = rig.auth.clone();
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    let mut pa = TestPublicAuth::new();
    pa.add(TEST_TOKEN_A, "acc_a", "subject-a@example.com");
    let state = GatewayHttp::new(core.clone(), auth.clone(), store)
        .with_poll_hold(Duration::from_millis(150))
        .with_mcp_deadline(Duration::from_millis(400))
        .with_public_auth(Arc::new(pa), [ORIGIN.to_string()].into_iter().collect());
    let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();
    let addr = server.addr;

    // Case 1: registered but never polls → work queues → deadline_exceeded.
    let _cred = register(addr, &auth, "acc_a");
    let sid = init_session(addr);
    let (s, _h, b) = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":20,
        "method":"tools/call","params":{"name":"sinter_get_version","arguments":{}}}),
    );
    assert_eq!(s, 200, "{b}");
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["error"]["code"], -32000);
    assert_eq!(v["error"]["data"]["code"], "deadline_exceeded", "{b}");

    // Case 2: account with NO controller at all → immediate controller_offline.
    // Reuse acc_b principal (registered in rig's auth map? no — rebuild).
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_sessions_gone_identity_survives() {
    let path = tmpdb("p5restart");
    let _g = Cleanup(path.clone());
    let sid;
    let cred;
    {
        let rig = rig(&path, true).await;
        cred = register(rig.server.addr, &rig.auth, "acc_a");
        sid = init_session(rig.server.addr);
        rig.server.shutdown().await;
    }
    {
        let rig = rig(&path, true).await;
        // session is memory-only → stale sid fails
        let (s, _h, _b) = mcp_post(
            rig.server.addr,
            Some(&sid),
            &json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
        );
        assert_eq!(s, 404); // session was memory-only; stale sid is gone
                            // controller identity survived → poll works after re-bind
        let (s, _h, _b) = http_full(
            rig.server.addr,
            "POST",
            "/v1/poll",
            &[&format!("Authorization: Bearer {cred}")],
            b"",
        );
        assert_eq!(s, 200);
        rig.server.shutdown().await;
    }
}

/// Caller-supplied identity must never route work: params, arguments, and
/// JSON-RPC fields naming foreign accounts/controllers are ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn caller_supplied_identity_never_routes() {
    let path = tmpdb("spoof");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    let addr = rig.server.addr;
    let cred_a = register(addr, &rig.auth, "acc_a");
    let _cred_b = register(addr, &rig.auth, "acc_b");
    let bridge_a = start_bridge(addr, cred_a.clone(), false);
    let sid = init_session(addr); // acc_a session

    // tools/call that names acc_b / another controller in params — spoofing
    // fields are opaque args to the gateway; routing comes from the principal.
    let (s, _h, b) = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":31,
        "method":"tools/call","params":{"name":"sinter_get_version",
            "arguments":{"account_id":"acc_b","controller_id":"ctrl_evil","target":"other"}}}),
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["id"], 31);
    assert!(v.get("result").is_some(), "{b}");

    // profile tool: caller asks for acc_b's profile — gets acc_a's.
    let (s, _h, b) = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":32,
        "method":"tools/call","params":{"name":PROFILE_TOOL,
            "arguments":{"account_id":"acc_b"}}}),
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["result"]["structuredContent"]["id"], "acc_a");

    drop(bridge_a);
    rig.server.shutdown().await;
}

/// An account with NO registered controller: forwarded calls get an
/// immediate JSON-RPC -32000 controller_offline (no wait, no queue).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_controller_at_all() {
    let path = tmpdb("noctl");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    let addr = rig.server.addr;
    let sid = init_session(addr); // acc_a never registers a controller
    let (s, _h, b) = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":40,
        "method":"tools/call","params":{"name":"sinter_get_version","arguments":{}}}),
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["id"], 40);
    assert_eq!(v["error"]["code"], -32000);
    assert_eq!(v["error"]["data"]["code"], "controller_offline", "{b}");
    rig.server.shutdown().await;
}

/// Edge-rejected methods must never appear as controller work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_methods_never_reach_controller() {
    let path = tmpdb("tunnel");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    let addr = rig.server.addr;
    let cred = register(addr, &rig.auth, "acc_a");
    let sid = init_session(addr);

    for m in [
        "evil/exec",
        "resources/read",
        "prompts/get",
        "tools/call/../../etc",
    ] {
        let (s, _h, b) = mcp_post(
            addr,
            Some(&sid),
            &json!({"jsonrpc":"2.0","id":1,"method":m}),
        );
        assert_eq!(s, 200, "{m}");
        assert_eq!(
            serde_json::from_str::<Value>(&b).unwrap()["error"]["code"],
            -32601,
            "{m}"
        );
    }
    // ping and profile are edge-owned — must not queue work either.
    let _ = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
    );
    let _ = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":3,
        "method":"tools/call","params":{"name":PROFILE_TOOL,"arguments":{}}}),
    );
    let _ = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );

    // The controller's next poll must see NO queued work (all edge-handled).
    let (s, _h, b) = http_full(
        addr,
        "POST",
        "/v1/poll",
        &[&format!("Authorization: Bearer {cred}")],
        b"",
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&b).unwrap();
    assert!(
        v["work"].is_null(),
        "edge traffic leaked to controller: {b}"
    );

    rig.server.shutdown().await;
}

/// Two accounts, two controllers: work routed strictly by the authenticated
/// principal's account — A's calls appear only on A's poll, B's on B's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_account_work_isolation() {
    let path = tmpdb("xiso");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    let addr = rig.server.addr;
    let cred_a = register(addr, &rig.auth, "acc_a");
    let cred_b = register(addr, &rig.auth, "acc_b");

    // acc_a session
    let sid_a = init_session(addr);
    // acc_b session
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
    let h_b = [
        format!("X-Sinter-Test-Principal: {TEST_TOKEN_B}"),
        "Content-Type: application/json".to_string(),
    ];
    let hs: Vec<&str> = h_b.iter().map(String::as_str).collect();
    let (s, hdrs, _b) = http_full(addr, "POST", "/mcp", &hs, init.to_string().as_bytes());
    assert_eq!(s, 200);
    let sid_b = hdrs["mcp-session-id"].clone();

    // acc_a submits a call (stub bridge answers); acc_b polls and must see
    // only ITS work — never A's. Submit A's call, poll as B first.
    let sid_a2 = sid_a.clone();
    let call_a = std::thread::spawn(move || {
        mcp_post(
            addr,
            Some(&sid_a2),
            &json!({"jsonrpc":"2.0","id":"a-req","method":"tools/call",
            "params":{"name":"sinter_get_version","arguments":{}}}),
        )
    });
    std::thread::sleep(Duration::from_millis(80));

    // B's poll must return null (A's work belongs to A's controller).
    let (s, _h, b) = http_full(
        addr,
        "POST",
        "/v1/poll",
        &[&format!("Authorization: Bearer {cred_b}")],
        b"",
    );
    assert_eq!(s, 200);
    assert!(
        serde_json::from_str::<Value>(&b).unwrap()["work"].is_null(),
        "{b}"
    );

    // A's controller picks up A's work and answers it.
    let (s, _h, b) = http_full(
        addr,
        "POST",
        "/v1/poll",
        &[&format!("Authorization: Bearer {cred_a}")],
        b"",
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&b).unwrap();
    let rid = v["work"]["request_id"].as_str().unwrap().to_string();
    assert_eq!(v["work"]["mcp"]["id"], "a-req");
    let rb = json!({"v":1,"request_id":rid,"mcp":{"jsonrpc":"2.0","id":"a-req","result":{"ok":1}}})
        .to_string();
    let (s, _h, _b) = http_full(
        addr,
        "POST",
        "/v1/respond",
        &[
            &format!("Authorization: Bearer {cred_a}"),
            "Content-Type: application/json",
        ],
        rb.as_bytes(),
    );
    assert_eq!(s, 200);
    let (s, _h, b) = call_a.join().unwrap();
    assert_eq!(s, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&b).unwrap()["result"]["ok"],
        1
    );

    let _ = sid_b;
    rig.server.shutdown().await;
}

/// Concurrent calls on one account + across accounts: every caller gets its
/// own response, ids round-trip, nothing double-completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn concurrent_mcp_calls() {
    let path = tmpdb("conc");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    let addr = rig.server.addr;
    let cred = register(addr, &rig.auth, "acc_a");
    let bridge = start_bridge(addr, cred, false);
    let sid = init_session(addr);

    let mut handles = Vec::new();
    for i in 0..8 {
        let sid = sid.clone();
        handles.push(std::thread::spawn(move || {
            let id = format!("conc-{i}");
            let (s, _h, b) = mcp_post(
                addr,
                Some(&sid),
                &json!({"jsonrpc":"2.0","id":id,
                "method":"tools/call","params":{"name":"sinter_get_version","arguments":{}}}),
            );
            assert_eq!(s, 200, "{b}");
            let v: Value = serde_json::from_str(&b).unwrap();
            assert_eq!(v["id"], id);
            assert!(v.get("result").is_some(), "{b}");
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    drop(bridge);
    rig.server.shutdown().await;
}

/// `notifications/cancelled` cancels live work by public JSON-RPC id
/// (RFC §8) — a later controller respond is rejected, the notification
/// itself is 202'd, and unknown ids are a no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_notification_cancels_live_work() {
    let path = tmpdb("notifcancel");
    let _g = Cleanup(path.clone());
    let rig = rig(&path, true).await;
    let addr = rig.server.addr;
    let cred = register(addr, &rig.auth, "acc_a");
    let sid = init_session(addr);

    // fire a forwarded call in the background; controller picks it up
    let sid2 = sid.clone();
    let call = std::thread::spawn(move || {
        mcp_post(
            addr,
            Some(&sid2),
            &json!({"jsonrpc":"2.0","id":"cancel-me",
            "method":"tools/call","params":{"name":"sinter_get_version","arguments":{}}}),
        )
    });
    std::thread::sleep(Duration::from_millis(80));
    let (s, _h, b) = http_full(
        addr,
        "POST",
        "/v1/poll",
        &[&format!("Authorization: Bearer {cred}")],
        b"",
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&b).unwrap();
    let rid = v["work"]["request_id"].as_str().unwrap().to_string();

    // cancelled notification → 202, no body
    let (s, _h, b) = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"cancel-me"}}),
    );
    assert_eq!((s, b.as_str()), (202, ""));

    // the waiting caller gets a JSON-RPC error (request is terminal)
    let (s, _h, b) = call.join().unwrap();
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["error"]["code"], -32000, "{b}");
    assert_eq!(v["error"]["data"]["code"], "cancelled_request", "{b}");

    // late controller respond → rejected
    let rb = json!({"v":1,"request_id":rid,"mcp":{"x":1}}).to_string();
    let (s, _h, b) = http_full(
        addr,
        "POST",
        "/v1/respond",
        &[
            &format!("Authorization: Bearer {cred}"),
            "Content-Type: application/json",
        ],
        rb.as_bytes(),
    );
    assert_eq!(s, 410, "{b}");

    // unknown id → still 202, harmless
    let (s, _h, _b) = mcp_post(
        addr,
        Some(&sid),
        &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"nope"}}),
    );
    assert_eq!(s, 202);

    rig.server.shutdown().await;
}
