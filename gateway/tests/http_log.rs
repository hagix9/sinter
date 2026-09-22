//! P4 secret-marker test through REAL HTTP paths — registration token,
//! bearer credential, and rotated credential must never appear in tracing
//! output, including on failure paths. Isolated in its own test binary
//! (tracing callsite interest is process-global; see tests/log_capture.rs).

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

fn http(addr: std::net::SocketAddr, path: &str, headers: &[&str], body: &[u8]) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    let mut req = format!("POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
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
    (
        status,
        text.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_paths_never_log_secrets() {
    let cap = Capture(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(cap.clone())
        .with_ansi(false)
        .finish();

    // Global subscriber: handler logs run on tokio worker threads, so a
    // thread-scoped default would capture nothing. This binary holds exactly
    // one test — global default is safe here.
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let mut secrets: Vec<String> = Vec::new();
    let cap2 = cap.clone();
    let secrets_out = {
        let dir = std::env::temp_dir().join(format!("sinter-gw-p4log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.db");
        let core = Arc::new(GatewayCore::new());
        let store = Arc::new(SqliteStore::open(&path).unwrap());
        let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
        let state = GatewayHttp::new(core.clone(), auth.clone(), store)
            .with_poll_hold(Duration::from_millis(80));
        let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();
        let addr = server.addr;

        let token = auth
            .issue_registration_token(&AccountId::new("acc_a"))
            .unwrap();
        let token_s = token.expose().to_string();

        // register (success)
        let body = json!({"token": token_s}).to_string();
        let (s, b) = http(
            addr,
            "/v1/register",
            &["Content-Type: application/json"],
            body.as_bytes(),
        );
        assert_eq!(s, 200);
        let cred = serde_json::from_str::<Value>(&b).unwrap()["credential"]
            .as_str()
            .unwrap()
            .to_string();

        // register again with the SAME token (consumed failure path)
        let _ = http(
            addr,
            "/v1/register",
            &["Content-Type: application/json"],
            body.as_bytes(),
        );
        // bearer auth failures: malformed + invalid marker creds
        let bad = format!("ctrlk_{}", "cd".repeat(32));
        let _ = http(
            addr,
            "/v1/poll",
            &[&format!("Authorization: Bearer {bad}")],
            b"",
        );
        // rotate (success) then poll with rotated-old + revoked paths
        let (s, b) = http(
            addr,
            "/v1/rotate",
            &[&format!("Authorization: Bearer {cred}")],
            b"",
        );
        assert_eq!(s, 200);
        let cred2 = serde_json::from_str::<Value>(&b).unwrap()["credential"]
            .as_str()
            .unwrap()
            .to_string();
        let _ = http(
            addr,
            "/v1/poll",
            &[&format!("Authorization: Bearer {cred}")],
            b"",
        );
        // respond failure (unknown request) with real cred
        let rb = json!({"v":1,"request_id":"req_nope","mcp":{"x":1}}).to_string();
        let _ = http(
            addr,
            "/v1/respond",
            &[
                &format!("Authorization: Bearer {cred2}"),
                "Content-Type: application/json",
            ],
            rb.as_bytes(),
        );

        server.shutdown().await;
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
        (token_s, cred, cred2, bad)
    };
    let (token_s, cred, cred2, bad) = secrets_out;
    secrets.extend([token_s, cred, cred2, bad]);
    let logs = String::from_utf8(cap2.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.is_empty(), "expected some transport logs");
    for s in &secrets {
        assert!(!logs.contains(s.as_str()), "secret in HTTP-path logs: {s}");
    }
}
