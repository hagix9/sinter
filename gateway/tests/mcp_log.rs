//! P5 secret-marker test through the public /mcp path: the test-principal
//! token, MCP payload content (tool arguments), and controller bearer must
//! never appear in tracing output — on success OR failure paths. Isolated
//! binary (tracing callsite interest is process-global).

use serde_json::{json, Value};
use sinter_gateway::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

fn http_full(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &[u8],
) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
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
    s.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    (
        status,
        text.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_path_never_logs_secrets_or_payloads() {
    let cap = Capture(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(cap.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let cap2 = cap.clone();

    const PRINCIPAL_TOKEN: &str = "testpub-PRINCIPALMARKER-7f3a9c";
    const TOOL_ARG_MARKER: &str = "ssh-key-marker-DO-NOT-LOG-91be";
    const MANIFEST_MARKER: &str = "manifest-marker-DO-NOT-LOG-44de";

    let dir = std::env::temp_dir().join(format!("sinter-gw-p5log-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("log.db");
    let core = Arc::new(GatewayCore::new());
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let mut pa = TestPublicAuth::new();
    pa.add(PRINCIPAL_TOKEN, "acc_a", "subject-a@example.com");
    let state = GatewayHttp::new(core.clone(), auth.clone(), store)
        .with_poll_hold(Duration::from_millis(80))
        .with_public_auth(
            Arc::new(pa),
            ["https://chatgpt.com".to_string()].into_iter().collect(),
        );
    let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();
    let addr = server.addr;

    let base: [String; 3] = [
        format!("X-Sinter-Test-Principal: {PRINCIPAL_TOKEN}"),
        "Content-Type: application/json".to_string(),
        "Origin: https://chatgpt.com".to_string(),
    ];
    let base_refs: Vec<&str> = base.iter().map(String::as_str).collect();

    // initialize (success — uses the principal token)
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string();
    let (s, _b) = http_full(addr, "POST", "/mcp", &base_refs, init.as_bytes());
    assert_eq!(s, 200);

    // auth failure with a *different* marker principal token
    let (s, _b) = http_full(
        addr,
        "POST",
        "/mcp",
        &[
            "Content-Type: application/json",
            "X-Sinter-Test-Principal: testpub-BADMARKER-ccee",
        ],
        init.as_bytes(),
    );
    assert_eq!(s, 401);

    // malformed JSON carrying marker bytes
    let (s, _b) = http_full(
        addr,
        "POST",
        "/mcp",
        &base_refs,
        format!("{{broken {TOOL_ARG_MARKER}").as_bytes(),
    );
    assert_eq!(s, 400);

    // oversized body carrying marker bytes (>1MiB cap)
    let big = vec![b'x'; (1 << 20) + (8 << 10)];
    let (s, _b) = http_full(addr, "POST", "/mcp", &base_refs, &big);
    assert_eq!(s, 413);

    // origin rejection path
    let (s, _b) = http_full(
        addr,
        "POST",
        "/mcp",
        &[
            &format!("X-Sinter-Test-Principal: {PRINCIPAL_TOKEN}"),
            "Content-Type: application/json",
            "Origin: https://evil-marker-origin.example",
        ],
        init.as_bytes(),
    );
    assert_eq!(s, 403);

    // register a controller, forward a tools/call whose ARGUMENTS carry
    // markers — arguments flow to the controller but must never be logged.
    let token = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let reg = json!({"token": token.expose()}).to_string();
    let (s, b) = http_full(
        addr,
        "POST",
        "/v1/register",
        &["Content-Type: application/json"],
        reg.as_bytes(),
    );
    assert_eq!(s, 200);
    let cred = serde_json::from_str::<Value>(&b).unwrap()["credential"]
        .as_str()
        .unwrap()
        .to_string();

    // fresh session for the call
    let (s, _hdr_body) = http_full(addr, "POST", "/mcp", &base_refs, init.as_bytes());
    assert_eq!(s, 200);
    // pull the session id off the wire
    let mut sock = TcpStream::connect(addr).unwrap();
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{}\r\nContent-Length: {}\r\n\r\n{}",
        base.as_slice().join("\r\n"),
        init.len(),
        init
    );
    sock.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let sid = text
        .lines()
        .find(|l| l.to_lowercase().starts_with("mcp-session-id:"))
        .unwrap()
        .split(':')
        .nth(1)
        .unwrap()
        .trim()
        .to_string();

    // forwarded call with marker arguments — delivered to controller, blocked
    // briefly on a poll so the full path logs, then answered.
    let call = json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
        "params":{"name":"sinter_audit_host","arguments":{"target":TOOL_ARG_MARKER,
            "manifest":MANIFEST_MARKER}}})
    .to_string();
    let sid2 = sid.clone();
    let base2: Vec<String> = base.to_vec();
    let h = std::thread::spawn(move || {
        let mut hs = base2;
        hs.push(format!("MCP-Session-Id: {sid2}"));
        let r: Vec<&str> = hs.iter().map(String::as_str).collect();
        http_full(addr, "POST", "/mcp", &r, call.as_bytes())
    });
    std::thread::sleep(Duration::from_millis(80));
    let (s, b) = http_full(
        addr,
        "POST",
        "/v1/poll",
        &[&format!("Authorization: Bearer {cred}")],
        b"",
    );
    assert_eq!(s, 200);
    let v: Value = serde_json::from_str(&b).unwrap();
    let rid = v["work"]["request_id"].as_str().unwrap().to_string();
    // respond with a marker-laden result — must not be logged either
    let rb = json!({"v":1,"request_id":rid,
        "mcp":{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":MANIFEST_MARKER}]}}}).to_string();
    let (s, _b) = http_full(
        addr,
        "POST",
        "/v1/respond",
        &[
            &format!("Authorization: Bearer {cred}"),
            "Content-Type: application/json",
        ],
        rb.as_bytes(),
    );
    assert_eq!(s, 200);
    let _ = h.join();

    // DELETE the session (success path)
    let (s, _b) = http_full(
        addr,
        "DELETE",
        "/mcp",
        &[
            &format!("X-Sinter-Test-Principal: {PRINCIPAL_TOKEN}"),
            &format!("MCP-Session-Id: {sid}"),
        ],
        b"",
    );
    assert_eq!(s, 200);

    server.shutdown().await;
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }

    let logs = String::from_utf8(cap2.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.is_empty(), "expected some transport logs");
    for marker in [
        PRINCIPAL_TOKEN,
        "testpub-BADMARKER-ccee",
        TOOL_ARG_MARKER,
        MANIFEST_MARKER,
        &cred,
        token.expose(),
        "evil-marker-origin.example",
    ] {
        assert!(!logs.contains(marker), "marker in /mcp-path logs: {marker}");
    }
}
