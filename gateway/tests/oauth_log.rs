//! P6 secret-marker test through the OAuth public path: the bearer access
//! token, its signature segment, the `sub` claim, controller credentials
//! and MCP payloads must never appear in tracing output — on success OR
//! failure paths. Isolated binary (tracing callsite interest is
//! process-global).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sinter_gateway::oauth::{HttpJwksSource, OAuthConfig};
use sinter_gateway::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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
    let _ = s.read_to_end(&mut buf);
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

/// Loopback AS serving a fixed JWKS — enough to make tokens validate.
struct MiniAs {
    addr: std::net::SocketAddr,
    priv_pem: String,
    stop: Arc<AtomicBool>,
}
impl MiniAs {
    fn start() -> Self {
        let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let pubkey = RsaPublicKey::from(&key);
        let priv_pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let doc = json!({"keys":[{
            "kty":"RSA","kid":"k1","use":"sig","alg":"RS256",
            "n": URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be()),
        }]})
        .to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (d2, s2) = (Arc::new(RwLock::new(doc)), stop.clone());
        std::thread::spawn(move || loop {
            if s2.load(Ordering::SeqCst) {
                return;
            }
            match listener.accept() {
                Ok((mut conn, _)) => {
                    let mut br = BufReader::new(conn.try_clone().unwrap());
                    let mut line = String::new();
                    loop {
                        line.clear();
                        if br.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                            break;
                        }
                    }
                    let body = d2.read().unwrap().clone();
                    let _ = conn.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    );
                    let _ = conn.write_all(body.as_bytes());
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        });
        Self {
            addr,
            priv_pem,
            stop,
        }
    }
    fn mint(&self, sub: &str, account: &str, exp_off: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = json!({
            "iss": format!("http://{}", self.addr),
            "aud": format!("http://{}", self.addr),
            "sub": sub,
            "sinter_account": account,
            "exp": now + exp_off,
            "iat": now,
        });
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("k1".into());
        encode(
            &h,
            &claims,
            &EncodingKey::from_rsa_pem(self.priv_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }
}
impl Drop for MiniAs {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_path_never_logs_tokens_or_claims() {
    let cap = Capture(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(cap.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let cap2 = cap.clone();

    const SUB_MARKER: &str = "sub-OAUTHMARKER-8f2c1d";
    const TOOL_MARKER: &str = "oauth-tool-arg-DO-NOT-LOG-77ab";

    let as_ = MiniAs::start();
    let dir = std::env::temp_dir().join(format!("sinter-gw-p6log-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("log.db");
    let core = Arc::new(GatewayCore::new());
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let mut cfg = OAuthConfig::new(
        format!("http://{}", as_.addr),
        format!("http://{}", as_.addr),
        format!("http://{}", as_.addr),
        format!("http://{}/jwks", as_.addr),
    );
    cfg.jwks_min_refresh = Duration::from_millis(10);
    let state = GatewayHttp::new(core.clone(), auth.clone(), store)
        .with_poll_hold(Duration::from_millis(80))
        .with_oauth(
            cfg,
            Box::new(HttpJwksSource::new().unwrap()),
            ["https://chatgpt.com".to_string()].into_iter().collect(),
        )
        .unwrap();
    let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();
    let addr = server.addr;

    let token = as_.mint(SUB_MARKER, "acc_a", 3600);
    let sig_segment = token.rsplit('.').next().unwrap().to_string();
    let authz = format!("Authorization: Bearer {token}");
    let base = [
        authz.as_str(),
        "Content-Type: application/json",
        "Origin: https://chatgpt.com",
        "MCP-Protocol-Version: 2025-03-26",
    ];

    // initialize (success — the bearer flows through validation)
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string();
    let (s, _b) = http_full(addr, "POST", "/mcp", &base, init.as_bytes());
    assert_eq!(s, 200);

    // invalid bearer carrying marker-shaped bytes → 401, never logged
    let bad = format!("Authorization: Bearer badtoken.{SUB_MARKER}.sig");
    let (s, _b) = http_full(
        addr,
        "POST",
        "/mcp",
        &[&bad, "Content-Type: application/json"],
        init.as_bytes(),
    );
    assert_eq!(s, 401);

    // expired token → 401 (token must not be logged)
    let expired = as_.mint(SUB_MARKER, "acc_a", -3600);
    let (s, _b) = http_full(
        addr,
        "POST",
        "/mcp",
        &[
            &format!("Authorization: Bearer {expired}"),
            "Content-Type: application/json",
        ],
        init.as_bytes(),
    );
    assert_eq!(s, 401);

    // register a controller; forward a marker-arg tools/call
    let reg_tok = auth
        .issue_registration_token(&AccountId::new("acc_a"))
        .unwrap();
    let reg = json!({"token": reg_tok.expose()}).to_string();
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

    // fresh session
    let (s, _b) = http_full(addr, "POST", "/mcp", &base, init.as_bytes());
    assert_eq!(s, 200);
    let mut sock = TcpStream::connect(addr).unwrap();
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{}\r\nContent-Length: {}\r\n\r\n{}",
        base.join("\r\n"),
        init.len(),
        init
    );
    sock.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf);
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

    let call = json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
        "params":{"name":"sinter_audit_host","arguments":{"target":TOOL_MARKER}}})
    .to_string();
    let sid2 = sid.clone();
    let authz2 = authz.clone();
    let h = std::thread::spawn(move || {
        let hs = [
            authz2.as_str(),
            "Content-Type: application/json",
            "Origin: https://chatgpt.com",
            "MCP-Protocol-Version: 2025-03-26",
            &format!("MCP-Session-Id: {sid2}"),
        ];
        http_full(addr, "POST", "/mcp", &hs, call.as_bytes())
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
    let rb = json!({"v":1,"request_id":rid,
        "mcp":{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":TOOL_MARKER}]}}})
    .to_string();
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

    server.shutdown().await;
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }

    let logs = String::from_utf8(cap2.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.is_empty(), "expected some transport logs");
    for marker in [
        token.as_str(),       // full bearer token
        sig_segment.as_str(), // signature segment alone
        SUB_MARKER,           // the sub claim value
        TOOL_MARKER,          // MCP payload content
        &cred,                // controller credential
        reg_tok.expose(),     // registration token
        &expired,             // rejected token
        "badtoken",           // malformed-bearer bytes
    ] {
        assert!(!logs.contains(marker), "marker in logs: {marker}");
    }
}
