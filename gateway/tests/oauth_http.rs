//! P6 — production OAuth public authentication over real loopback HTTP.
//! A loopback "test authorization server" (RSA keypair + JWKS endpoint)
//! mints tokens; the Gateway validates through the real `HttpJwksSource`
//! fetcher — loopback HTTP is the one permitted non-HTTPS exception and is
//! exercised as production code, not mocked away.
//!
//! The test AS lives only in this test binary: nothing here is linked into
//! or reachable from a production Gateway build.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sinter_gateway::edge::PROFILE_TOOL;
use sinter_gateway::oauth::{trusted_uri, HttpJwksSource, OAuthConfig};
use sinter_gateway::*;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------- infra ----------

struct Rig {
    server: GatewayServer,
    auth: Arc<ControllerAuth<SqliteStore, SystemClock>>,
}

fn tmpdb(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sinter-gw-p6-{}", std::process::id()));
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

const ORIGIN: &str = "https://chatgpt.com";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------- test authorization server ----------

/// Minimal loopback AS: one RSA keypair, a JWKS document served over HTTP.
/// The document body is swappable to model key rotation and malformed
/// keysets. Fetches are counted to prove cache/throttle behavior.
struct TestAs {
    addr: SocketAddr,
    priv_pem: String,
    kid: String,
    doc: Arc<RwLock<Vec<u8>>>,
    fetches: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl TestAs {
    fn start() -> Self {
        let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let pubkey = RsaPublicKey::from(&key);
        let priv_pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let kid = "k1".to_string();
        let doc = Arc::new(RwLock::new(
            json!({"keys":[jwk_for(&pubkey, "k1")]})
                .to_string()
                .into_bytes(),
        ));
        let fetches = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let (d2, f2, s2) = (doc.clone(), fetches.clone(), stop.clone());
        std::thread::spawn(move || loop {
            if s2.load(Ordering::SeqCst) {
                return;
            }
            match listener.accept() {
                Ok((mut conn, _)) => {
                    conn.set_nonblocking(false).unwrap();
                    f2.fetch_add(1, Ordering::SeqCst);
                    // Consume request headers, then answer with the doc.
                    let mut br = BufReader::new(conn.try_clone().unwrap());
                    let mut line = String::new();
                    loop {
                        line.clear();
                        if br.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                            break;
                        }
                    }
                    let body = d2.read().unwrap().clone();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = conn.write_all(resp.as_bytes());
                    let _ = conn.write_all(&body);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        });
        Self {
            addr,
            priv_pem,
            kid,
            doc,
            fetches,
            stop,
        }
    }

    fn issuer(&self) -> String {
        format!("http://{}", self.addr)
    }
    fn jwks_uri(&self) -> String {
        format!("http://{}/jwks.json", self.addr)
    }

    fn set_doc(&self, doc: Value) {
        *self.doc.write().unwrap() = doc.to_string().into_bytes();
    }
    fn set_doc_raw(&self, raw: &[u8]) {
        *self.doc.write().unwrap() = raw.to_vec();
    }

    /// Mint an RS256 token with this AS's key. Claims are caller-provided
    /// so tests control every field (iss/aud/sub/exp/iat/account).
    fn mint(&self, claims: &Value) -> String {
        self.mint_with(claims, &self.kid, &self.priv_pem)
    }

    fn mint_with(&self, claims: &Value, kid: &str, pem: &str) -> String {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some(kid.to_string());
        encode(
            &h,
            claims,
            &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn claims(&self, aud: &str, sub: &str, account: Option<&str>, exp_off: i64) -> Value {
        let mut c = json!({
            "iss": self.issuer(),
            "aud": aud,
            "sub": sub,
            "exp": (now() as i64 + exp_off),
            "iat": now(),
        });
        if let Some(a) = account {
            c["sinter_account"] = json!(a);
        }
        c
    }
}

impl Drop for TestAs {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn jwk_for(pubkey: &RsaPublicKey, kid: &str) -> Value {
    json!({
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be()),
    })
}

/// Hand-built unsigned token (alg=none or arbitrary header/payload).
fn unsigned_token(header: Value, claims: &Value) -> String {
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

// ---------- gateway rig ----------

async fn rig_oauth(path: &PathBuf, as_: &TestAs) -> Rig {
    rig_oauth_cfg(path, default_cfg(as_)).await
}

fn default_cfg(as_: &TestAs) -> OAuthConfig {
    let mut cfg = OAuthConfig::new(
        as_.issuer(),
        // RFC 8707: the audience is the protected-resource URL itself.
        as_.issuer(),
        as_.issuer(),
        as_.jwks_uri(),
    );
    cfg.jwks_min_refresh = Duration::from_millis(10);
    cfg.jwks_ttl = Duration::from_secs(3600);
    cfg
}

async fn rig_oauth_cfg(path: &PathBuf, cfg: OAuthConfig) -> Rig {
    let core = Arc::new(GatewayCore::with_clock(SystemClock));
    let store = Arc::new(SqliteStore::open(path).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let state = GatewayHttp::new(core.clone(), auth.clone(), store.clone())
        .with_poll_hold(Duration::from_millis(150))
        .with_oauth(
            cfg,
            Box::new(HttpJwksSource::new().unwrap()),
            [ORIGIN.to_string()].into_iter().collect(),
        )
        .unwrap();
    let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();
    let _ = core;
    Rig { server, auth }
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

/// /mcp POST with an OAuth Bearer credential.
fn mcp_post_bearer(
    addr: SocketAddr,
    token: &str,
    sid: Option<&str>,
    frame: &Value,
) -> (u16, HashMap<String, String>, String) {
    let mut h = vec![
        format!("Authorization: Bearer {token}"),
        format!("Origin: {ORIGIN}"),
        "Content-Type: application/json".to_string(),
        "MCP-Protocol-Version: 2025-03-26".to_string(),
    ];
    if let Some(s) = sid {
        h.push(format!("MCP-Session-Id: {s}"));
    }
    let hs: Vec<&str> = h.iter().map(String::as_str).collect();
    http_full(addr, "POST", "/mcp", &hs, frame.to_string().as_bytes())
}

fn init_frame() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}})
}

/// initialize → session id (asserts the full happy path).
fn init_session(addr: SocketAddr, token: &str) -> String {
    let (s, hdrs, body) = mcp_post_bearer(addr, token, None, &init_frame());
    assert_eq!(s, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["result"]["serverInfo"]["name"], "sinter-gateway");
    let sid = hdrs["mcp-session-id"].clone();
    assert!(sid.starts_with("sess_"));
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

fn bearer(t: &str) -> String {
    format!("Authorization: Bearer {t}")
}

// ---------- real sinter bridge ----------

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

struct Bridge {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Bridge loop: poll → optionally run through real `sinter mcp` → respond.
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

// ---------- tests ----------

/// §7/§8 strict credential parsing + JWT validation matrix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_credential_matrix() {
    let path = tmpdb("matrix");
    let _g = Cleanup(path.clone());
    let as_ = TestAs::start();
    let aud = format!("http://{}", as_.addr);
    let rig = rig_oauth(&path, &as_).await;
    let addr = rig.server.addr;

    let frame = init_frame().to_string();
    let post = |hdrs: &[&str]| http_full(addr, "POST", "/mcp", hdrs, frame.as_bytes());
    let base = [
        format!("Origin: {ORIGIN}"),
        "Content-Type: application/json".to_string(),
        "MCP-Protocol-Version: 2025-03-26".to_string(),
    ];
    let with = |extra: &[&str]| {
        let mut h: Vec<String> = base.to_vec();
        h.extend(extra.iter().map(|s| s.to_string()));
        h
    };

    // missing → 401 + challenge with resource_metadata
    let hs = with(&[]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, h, b) = post(&hs2);
    assert_eq!(s, 401, "{b}");
    assert!(h["www-authenticate"].starts_with("Bearer "));
    assert!(h["www-authenticate"].contains("resource_metadata="));
    assert!(
        !h["www-authenticate"].contains("error="),
        "missing creds carry no error"
    );

    // duplicate Authorization → 401 malformed
    let t = as_.mint(&as_.claims(&aud, "subj", Some("acc_a"), 3600));
    let hs = with(&[&bearer(&t), &bearer(&t)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, h, _) = post(&hs2);
    assert_eq!(s, 401);
    assert!(h["www-authenticate"].contains("invalid_request"));

    // malformed scheme / empty / whitespace-ambiguous bearers.
    // (HTTP strips leading/trailing OWS from field values before the app
    // sees them — interior whitespace is what reaches the parser.)
    for auth in [
        "Basic Zm9vOmJhcg==".to_string(),
        "Bearer".to_string(),
        "Bearer ".to_string(),
        format!("Bearer  {t}"),   // double space
        "Bearer a b".to_string(), // interior space
        "Token xyz".to_string(),
    ] {
        let hs = with(&[&format!("Authorization: {auth}")]);
        let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
        let (s, h, b) = post(&hs2);
        assert_eq!(s, 401, "{auth:?} → {s} {b}");
        assert!(
            h["www-authenticate"].contains("invalid_request"),
            "{auth:?}"
        );
    }

    // oversized Authorization header → malformed
    let big = format!("Bearer {}", "x".repeat(9000));
    let hs = with(&[&format!("Authorization: {big}")]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, _, _) = post(&hs2);
    assert_eq!(s, 401);

    // random bearer / malformed token → invalid_token
    for bad_tok in ["not-a-jwt", "a.b.c", &"y".repeat(200)] {
        let hs = with(&[&bearer(bad_tok)]);
        let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
        let (s, h, b) = post(&hs2);
        assert_eq!(s, 401, "{bad_tok:?} → {s} {b}");
        assert!(h["www-authenticate"].contains("invalid_token"));
    }

    // alg=none hand-crafted → invalid (header parsed, algorithm rejected)
    let none_tok = unsigned_token(
        json!({"alg":"none","typ":"JWT"}),
        &as_.claims(&aud, "subj", Some("acc_a"), 3600),
    );
    let hs = with(&[&bearer(&none_tok)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, _, b) = post(&hs2);
    assert_eq!(s, 401, "{b}");

    // HS256 (symmetric, disallowed family) → invalid
    let mut hh = Header::new(Algorithm::HS256);
    hh.kid = Some("k1".into());
    let hs_tok = encode(
        &hh,
        &as_.claims(&aud, "subj", Some("acc_a"), 3600),
        &EncodingKey::from_secret(b"shared"),
    )
    .unwrap();
    let hs = with(&[&bearer(&hs_tok)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, _, b) = post(&hs2);
    assert_eq!(s, 401, "{b}");

    // expired (beyond leeway) → invalid
    let expired = as_.mint(&as_.claims(&aud, "subj", Some("acc_a"), -3600));
    let hs = with(&[&bearer(&expired)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, h, b) = post(&hs2);
    assert_eq!(s, 401, "{b}");
    assert!(h["www-authenticate"].contains("invalid_token"));

    // wrong issuer → invalid
    let mut c = as_.claims(&aud, "subj", Some("acc_a"), 3600);
    c["iss"] = json!("https://evil.example.com");
    let wrong_iss = as_.mint(&c);
    let hs = with(&[&bearer(&wrong_iss)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, _, b) = post(&hs2);
    assert_eq!(s, 401, "{b}");

    // wrong audience → invalid
    let mut c = as_.claims(&aud, "subj", Some("acc_a"), 3600);
    c["aud"] = json!("https://other-resource.example.com");
    let wrong_aud = as_.mint(&c);
    let hs = with(&[&bearer(&wrong_aud)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, _, b) = post(&hs2);
    assert_eq!(s, 401, "{b}");

    // bad signature (different key) → invalid
    let other = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
    let other_pem = other.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let bad_sig = as_.mint_with(
        &as_.claims(&aud, "subj", Some("acc_a"), 3600),
        "k1",
        &other_pem,
    );
    let hs = with(&[&bearer(&bad_sig)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, _, b) = post(&hs2);
    assert_eq!(s, 401, "{b}");

    // unknown kid → invalid (after bounded refresh attempt)
    let unknown_kid = as_.mint_with(
        &as_.claims(&aud, "subj", Some("acc_a"), 3600),
        "kZZ",
        &as_.priv_pem,
    );
    let hs = with(&[&bearer(&unknown_kid)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, _, b) = post(&hs2);
    assert_eq!(s, 401, "{b}");

    // no kid in header → invalid
    let mut h2 = Header::new(Algorithm::RS256);
    h2.kid = None;
    let no_kid = encode(
        &h2,
        &as_.claims(&aud, "subj", Some("acc_a"), 3600),
        &EncodingKey::from_rsa_pem(as_.priv_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let hs = with(&[&bearer(&no_kid)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, _, b) = post(&hs2);
    assert_eq!(s, 401, "{b}");

    // future iat → invalid
    let mut c = as_.claims(&aud, "subj", Some("acc_a"), 3600);
    c["iat"] = json!(now() + 3600);
    let future_iat = as_.mint(&c);
    let hs = with(&[&bearer(&future_iat)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, _, b) = post(&hs2);
    assert_eq!(s, 401, "{b}");

    // missing sub → invalid
    let mut c = as_.claims(&aud, "", Some("acc_a"), 3600);
    c.as_object_mut().unwrap().remove("sub");
    let no_sub = as_.mint(&c);
    let hs = with(&[&bearer(&no_sub)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, _, b) = post(&hs2);
    assert_eq!(s, 401, "{b}");

    // missing account claim → authenticated but unbound → 403
    let unbound = as_.mint(&as_.claims(&aud, "subj", None, 3600));
    let hs = with(&[&bearer(&unbound)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, h, b) = post(&hs2);
    assert_eq!(s, 403, "{b}");
    assert!(h["www-authenticate"].contains("insufficient_scope"));

    // valid → 200 initialize
    let good = as_.mint(&as_.claims(&aud, "subj-a", Some("acc_a"), 3600));
    let hs = with(&[&bearer(&good)]);
    let hs2: Vec<&str> = hs.iter().map(String::as_str).collect();
    let (s, _, b) = post(&hs2);
    assert_eq!(s, 200, "{b}");
    rig.server.shutdown().await;
}

/// F-11 regression: `iat` is optional, but a *present* iat must be a
/// NumericDate. Every malformed representation must fail authentication
/// rather than silently degrade to "absent" — signed with the real key so
/// rejection is attributable to the claim itself, over the real HTTP +
/// JWKS path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_iat_malformed_rejected() {
    let path = tmpdb("iatmal");
    let _g = Cleanup(path.clone());
    let as_ = TestAs::start();
    let aud = format!("http://{}", as_.addr);
    let rig = rig_oauth(&path, &as_).await;
    let addr = rig.server.addr;

    let status_for = |iat: Option<Value>| -> (u16, String) {
        let mut c = as_.claims(&aud, "subj", Some("acc_a"), 3600);
        match iat {
            Some(v) => c["iat"] = v,
            None => {
                c.as_object_mut().unwrap().remove("iat");
            }
        }
        let t = as_.mint(&c);
        let (s, _h, b) = mcp_post_bearer(addr, &t, None, &init_frame());
        (s, b)
    };

    // Malformed representations → 401, never silently accepted.
    for (name, v) in [
        ("string", json!("tomorrow")),
        ("numeric string", json!("1720000000")),
        ("negative", json!(-1)),
        ("float", json!(1.5)),
        ("integer-valued float", json!(1e9)),
        ("null", Value::Null),
        ("object", json!({})),
        ("array", json!([])),
    ] {
        let (s, b) = status_for(Some(v));
        assert_eq!(s, 401, "iat {name} must be rejected: {b}");
    }

    // Valid representations → existing policy preserved.
    for (name, v) in [
        ("now", json!(now())),
        ("past", json!(now() - 3600)),
        ("epoch", json!(0)),
        ("within future leeway", json!(now() + 59)),
    ] {
        let (s, b) = status_for(Some(v));
        assert_eq!(s, 200, "iat {name} must stay accepted: {b}");
    }
    let (s, b) = status_for(Some(json!(now() + 3600)));
    assert_eq!(s, 401, "future iat beyond leeway must stay rejected: {b}");

    // Absent → existing optional-claim policy preserved.
    let (s, b) = status_for(None);
    assert_eq!(s, 200, "absent iat must stay accepted: {b}");

    rig.server.shutdown().await;
}

/// §39 session + profile flow through the real auth path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_session_and_profile() {
    let path = tmpdb("sess");
    let _g = Cleanup(path.clone());
    let as_ = TestAs::start();
    let aud = format!("http://{}", as_.addr);
    let rig = rig_oauth(&path, &as_).await;
    let addr = rig.server.addr;

    let mut c = as_.claims(&aud, "subj-alice", Some("acc_a"), 3600);
    c["name"] = json!("Alice A");
    c["email"] = json!("alice@example.com");
    let tok = as_.mint(&c);
    let sid = init_session(addr, &tok);

    // ping → edge answer
    let (s, _h, b) = mcp_post_bearer(
        addr,
        &tok,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
    );
    assert_eq!(s, 200, "{b}");
    assert_eq!(
        serde_json::from_str::<Value>(&b).unwrap()["result"],
        json!({})
    );

    // profile tool → built from the validated principal's claims
    let (s, _h, b) = mcp_post_bearer(
        addr,
        &tok,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":PROFILE_TOOL,"arguments":{}}}),
    );
    assert_eq!(s, 200, "{b}");
    let v: Value = serde_json::from_str(&b).unwrap();
    let prof = &v["result"]["structuredContent"];
    assert_eq!(prof["id"], "acc_a");
    assert_eq!(prof["name"], "Alice A");
    assert_eq!(prof["email"], "alice@example.com");
    // Never leaks token material.
    assert!(!b.contains(&tok));

    // unknown method → -32601, never reaches a controller
    let (s, _h, b) = mcp_post_bearer(
        addr,
        &tok,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":4,"method":"resources/read"}),
    );
    assert_eq!(s, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&b).unwrap()["error"]["code"],
        -32601
    );

    // DELETE with same token → 200; repeat → 404; session reuse → 404
    let (s, _h, _b) = http_full(
        addr,
        "DELETE",
        "/mcp",
        &[
            &bearer(&tok),
            &format!("Origin: {ORIGIN}"),
            &format!("MCP-Session-Id: {sid}"),
        ],
        b"",
    );
    assert_eq!(s, 200);
    let (s, _h, _b) = http_full(
        addr,
        "DELETE",
        "/mcp",
        &[
            &bearer(&tok),
            &format!("Origin: {ORIGIN}"),
            &format!("MCP-Session-Id: {sid}"),
        ],
        b"",
    );
    assert_eq!(s, 404);
    let (s, _h, b) = mcp_post_bearer(
        addr,
        &tok,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":5,"method":"ping"}),
    );
    assert_eq!(s, 404, "{b}");
    rig.server.shutdown().await;
}

/// §19 cross-account isolation through the real auth boundary.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_cross_account_isolation() {
    let path = tmpdb("iso");
    let _g = Cleanup(path.clone());
    let as_ = TestAs::start();
    let aud = format!("http://{}", as_.addr);
    let rig = rig_oauth(&path, &as_).await;
    let addr = rig.server.addr;

    let cred_a = register(addr, &rig.auth, "acc_a");
    let cred_b = register(addr, &rig.auth, "acc_b");
    let tok_a = as_.mint(&as_.claims(&aud, "subj-a", Some("acc_a"), 3600));
    let tok_b = as_.mint(&as_.claims(&aud, "subj-b", Some("acc_b"), 3600));

    let sid_a = init_session(addr, &tok_a);
    let sid_b = init_session(addr, &tok_b);

    // A token + A session → ok
    let (s, _h, b) = mcp_post_bearer(
        addr,
        &tok_a,
        Some(&sid_a),
        &json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    );
    assert_eq!(s, 200, "{b}");

    // A token + B session → rejected
    let (s, _h, _) = mcp_post_bearer(
        addr,
        &tok_a,
        Some(&sid_b),
        &json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    );
    assert_eq!(s, 403);
    // B token + A session → rejected
    let (s, _h, _) = mcp_post_bearer(
        addr,
        &tok_b,
        Some(&sid_a),
        &json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    );
    assert_eq!(s, 403);

    // A token cannot DELETE B's session
    let (s, _h, _b) = http_full(
        addr,
        "DELETE",
        "/mcp",
        &[
            &bearer(&tok_a),
            &format!("Origin: {ORIGIN}"),
            &format!("MCP-Session-Id: {sid_b}"),
        ],
        b"",
    );
    assert_eq!(s, 403);
    let _ = sid_b;

    // A's work never reaches B's controller: submit a forwarded call for A,
    // then poll as B — B must see nothing; A's poll sees it.
    let (s, _h, b) = mcp_post_bearer(
        addr,
        &tok_a,
        Some(&sid_a),
        &json!({"jsonrpc":"2.0","id":42,"method":"tools/call",
            "params":{"name":"sinter_get_version","arguments":{}}}),
    );
    // The call may complete only via A's controller; B's poll gets nothing.
    let _ = (s, b);
    let (s, _h, b) = http_full(addr, "POST", "/v1/poll", &[&bearer(&cred_b)], b"");
    assert_eq!(s, 200, "{b}");
    assert!(
        serde_json::from_str::<Value>(&b).unwrap()["work"].is_null(),
        "{b}"
    );
    let (s, _h, b) = http_full(addr, "POST", "/v1/poll", &[&bearer(&cred_a)], b"");
    assert_eq!(s, 200, "{b}");
    let work = serde_json::from_str::<Value>(&b).unwrap();
    if let Some(w) = work.get("work").filter(|w| w.is_object()) {
        let rid = w["request_id"].as_str().unwrap().to_string();
        let rb = json!({"v":1,"request_id":rid,
            "mcp":{"jsonrpc":"2.0","id":42,"result":{"ok":true}}})
        .to_string();
        http_full(
            addr,
            "POST",
            "/v1/respond",
            &[&bearer(&cred_a), "Content-Type: application/json"],
            rb.as_bytes(),
        );
    }

    // §30 — secret/persistence boundary: raw SQLite bytes must never
    // contain OAuth material (access tokens, subject ids, claim values).
    // The identity ledger holds controller records only.
    let bytes = std::fs::read(&path).unwrap();
    let blob = String::from_utf8_lossy(&bytes);
    for secret in [&tok_a, &tok_b] {
        assert!(!blob.contains(secret.as_str()), "access token persisted");
        // JWT segments individually (header/payload/signature).
        for seg in secret.split('.') {
            assert!(!blob.contains(seg), "jwt segment persisted");
        }
    }
    assert!(
        !blob.contains("subj-a") && !blob.contains("subj-b"),
        "subject persisted"
    );
    rig.server.shutdown().await;
}

/// §21 — an expired token cannot ride a live session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_expired_token_does_not_ride_session() {
    let path = tmpdb("expiry");
    let _g = Cleanup(path.clone());
    let as_ = TestAs::start();
    let aud = format!("http://{}", as_.addr);
    let rig = rig_oauth(&path, &as_).await;
    let addr = rig.server.addr;

    let tok = as_.mint(&as_.claims(&aud, "subj-a", Some("acc_a"), 3600));
    let sid = init_session(addr, &tok);

    // Session exists, but the presented token is expired → 401.
    let expired = as_.mint(&as_.claims(&aud, "subj-a", Some("acc_a"), -3600));
    let (s, _h, b) = mcp_post_bearer(
        addr,
        &expired,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
    );
    assert_eq!(s, 401, "{b}");

    // Session-id alone is not a credential: no Authorization → 401.
    let (s, _h, b) = http_full(
        addr,
        "POST",
        "/mcp",
        &[
            &format!("Origin: {ORIGIN}"),
            "Content-Type: application/json",
            &format!("MCP-Session-Id: {sid}"),
            "MCP-Protocol-Version: 2025-03-26",
        ],
        json!({"jsonrpc":"2.0","id":2,"method":"ping"})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(s, 401, "{b}");
    rig.server.shutdown().await;
}

/// §11 — RFC 9728 protected-resource metadata exact contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oauth_protected_resource_metadata() {
    let path = tmpdb("prm");
    let _g = Cleanup(path.clone());
    let as_ = TestAs::start();
    let rig = rig_oauth(&path, &as_).await;
    let addr = rig.server.addr;

    for p in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let (s, _h, b) = http_full(addr, "GET", p, &[], b"");
        assert_eq!(s, 200, "{p} {b}");
        let v: Value = serde_json::from_str(&b).unwrap();
        assert_eq!(v["resource"], json!(as_.issuer()));
        assert_eq!(v["authorization_servers"], json!([as_.issuer()]));
        assert_eq!(v["bearer_methods_supported"], json!(["header"]));
        // No internal topology: no controller/host names beyond the resource.
        assert!(v.get("controllers").is_none() && v.get("jwks_uri").is_none());
    }

    // A gateway without OAuth serves no metadata document.
    let core = Arc::new(GatewayCore::with_clock(SystemClock));
    let store = Arc::new(SqliteStore::open(tmpdb("prm-none")).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let plain = GatewayHttp::new(core, auth, store);
    let srv = GatewayServer::start(plain, "127.0.0.1:0").await.unwrap();
    let (s, _h, _b) = http_full(
        srv.addr,
        "GET",
        "/.well-known/oauth-protected-resource",
        &[],
        b"",
    );
    assert_eq!(s, 404);
    srv.shutdown().await;
    rig.server.shutdown().await;
}

/// §15/§16 — JWKS rotation, malformed keysets, bounded refresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_jwks_rotation_and_malformed() {
    let path = tmpdb("jwks");
    let _g = Cleanup(path.clone());
    let as_ = TestAs::start();
    let aud = format!("http://{}", as_.addr);
    let rig = rig_oauth(&path, &as_).await;
    let addr = rig.server.addr;
    let tok_k1 = as_.mint(&as_.claims(&aud, "s", Some("acc_a"), 3600));

    // Baseline works.
    init_session(addr, &tok_k1);
    let fetches_after_first = as_.fetches.load(Ordering::SeqCst);
    assert!(fetches_after_first >= 1);

    // Rotate: new keypair under kid k2; the AS now serves only k2.
    let key2 = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
    let pub2 = RsaPublicKey::from(&key2);
    let pem2 = key2.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    as_.set_doc(json!({"keys":[jwk_for(&pub2, "k2")]}));

    // Unknown kid k2 → bounded refresh → now valid.
    let tok_k2 = as_.mint_with(&as_.claims(&aud, "s", Some("acc_a"), 3600), "k2", &pem2);
    let sid2 = init_session(addr, &tok_k2);
    assert!(sid2.starts_with("sess_"));

    // Old key no longer trusted → k1 tokens fail.
    let (s, _h, b) = mcp_post_bearer(addr, &tok_k1, None, &init_frame());
    assert_eq!(s, 401, "{b}");

    // Malformed JWKS → fail closed on a fresh validator.
    let path2 = tmpdb("jwks-bad");
    let _g2 = Cleanup(path2.clone());
    let as_bad = TestAs::start();
    as_bad.set_doc_raw(b"{not json");
    let mut cfg = default_cfg(&as_bad);
    cfg.jwks_min_refresh = Duration::from_millis(5);
    let rig2 = rig_oauth_cfg(&path2, cfg).await;
    let tok =
        as_bad.mint(&as_bad.claims(&format!("http://{}", as_bad.addr), "s", Some("acc_a"), 3600));
    let (s, _h, b) = mcp_post_bearer(rig2.server.addr, &tok, None, &init_frame());
    assert_eq!(s, 401, "{b}");
    rig2.server.shutdown().await;
    rig.server.shutdown().await;
}

/// §14 — SSRF trust policy + startup config validation.
#[test]
fn oauth_uri_trust_policy() {
    // HTTPS anywhere
    assert!(trusted_uri("https://as.example.com/jwks.json"));
    // loopback HTTP literals only
    assert!(trusted_uri("http://127.0.0.1:8080/jwks"));
    assert!(trusted_uri("http://[::1]:9/jwks"));
    // rejected: non-loopback http, hostnames over http, private ranges,
    // metadata endpoints, other schemes, userinfo
    for u in [
        "http://as.example.com/jwks",         // hostname over http
        "http://169.254.169.254/latest/meta", // cloud metadata
        "http://10.0.0.1/jwks",               // RFC1918
        "http://192.168.1.1/jwks",
        "http://localhost/jwks", // hostname, not literal
        "file:///etc/passwd",
        "ftp://x/jwks",
        "https://user:pw@as.example.com/j", // userinfo
        "gopher://127.0.0.1/",
        "not a url",
    ] {
        assert!(!trusted_uri(u), "{u}");
    }

    // Config validation is fail-closed.
    let as_ = TestAs::start();
    let good = default_cfg(&as_);
    assert!(good.validate().is_ok());
    let mut bad = good.clone();
    bad.jwks_uri = "http://169.254.169.254/latest/meta-data".into();
    assert!(bad.validate().is_err());
    let mut bad2 = good.clone();
    bad2.issuer = "file:///etc/passwd".into();
    assert!(bad2.validate().is_err());
    let mut bad3 = good;
    bad3.audience = String::new();
    assert!(bad3.validate().is_err());
}

/// Public OAuth credentials must never authorize controller routes, and
/// controller credentials must never authorize /mcp — the auth domains
/// stay disjoint (§50 questions 9/10).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_auth_domains_disjoint() {
    let path = tmpdb("domains");
    let _g = Cleanup(path.clone());
    let as_ = TestAs::start();
    let aud = format!("http://{}", as_.addr);
    let rig = rig_oauth(&path, &as_).await;
    let addr = rig.server.addr;

    let cred = register(addr, &rig.auth, "acc_a");
    let tok = as_.mint(&as_.claims(&aud, "s", Some("acc_a"), 3600));

    // OAuth bearer on /v1/* → not a controller credential → 401.
    for p in ["/v1/poll", "/v1/respond"] {
        let (s, _h, b) = http_full(
            addr,
            "POST",
            p,
            &[&bearer(&tok), "Content-Type: application/json"],
            b"{}",
        );
        assert_eq!(s, 401, "{p} {b}");
    }
    // Controller credential on /mcp → not a JWT → 401.
    let (s, _h, b) = mcp_post_bearer(addr, &cred, None, &init_frame());
    assert_eq!(s, 401, "{b}");
    rig.server.shutdown().await;
}

/// §23/§39 — F-07 regression through OAuth auth: revoked controller cannot
/// receive queued work or deliver responses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_controller_revocation_revalidation() {
    let path = tmpdb("revoke");
    let _g = Cleanup(path.clone());
    let as_ = TestAs::start();
    let aud = format!("http://{}", as_.addr);
    // custom rig to shorten the /mcp deadline for the revoked path
    let core = Arc::new(GatewayCore::with_clock(SystemClock));
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    let rig_auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let cfg = default_cfg(&as_);
    let state = GatewayHttp::new(core.clone(), rig_auth.clone(), store.clone())
        .with_poll_hold(Duration::from_millis(150))
        .with_mcp_deadline(Duration::from_millis(800))
        .with_oauth(
            cfg,
            Box::new(HttpJwksSource::new().unwrap()),
            [ORIGIN.to_string()].into_iter().collect(),
        )
        .unwrap();
    let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();
    let addr = server.addr;
    let cred = register(addr, &rig_auth, "acc_a");

    let tok = as_.mint(&as_.claims(&aud, "s", Some("acc_a"), 3600));
    let sid = init_session(addr, &tok);

    // Submit a forwarded call (no poller yet — it queues).
    let tok2 = tok.clone();
    let sid2 = sid.clone();
    let jh = std::thread::spawn(move || {
        mcp_post_bearer(
            addr,
            &tok2,
            Some(&sid2),
            &json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
                "params":{"name":"sinter_get_version","arguments":{}}}),
        )
    });

    // Revoke BEFORE the controller ever polls. The poll must be rejected
    // (durable revalidation before delivery) and the caller must get a
    // JSON-RPC error — never a hang-to-success.
    rig_auth.revoke(&cred).unwrap();
    let (s, _h, b) = http_full(addr, "POST", "/v1/poll", &[&bearer(&cred)], b"");
    assert_eq!(s, 401, "{b}");
    let (s, _h, b) = jh.join().unwrap();
    assert_eq!(s, 200);
    assert!(
        serde_json::from_str::<Value>(&b).unwrap()["error"].is_object(),
        "{b}"
    );
    server.shutdown().await;
}

/// §40 — full production path through real `sinter mcp`, OAuth-authed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oauth_e2e_real_sinter() {
    let path = tmpdb("e2e");
    let _g = Cleanup(path.clone());
    let as_ = TestAs::start();
    let aud = format!("http://{}", as_.addr);
    let rig = rig_oauth(&path, &as_).await;
    let addr = rig.server.addr;
    let cred = register(addr, &rig.auth, "acc_a");
    let _bridge = start_bridge(addr, cred, true);

    let tok = as_.mint(&as_.claims(&aud, "subj-a", Some("acc_a"), 3600));
    let sid = init_session(addr, &tok);

    // tools/list → real sinter's 8 tools + injected profile tool
    let (s, _h, b) = mcp_post_bearer(
        addr,
        &tok,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":10,"method":"tools/list"}),
    );
    assert_eq!(s, 200, "{b}");
    let v: Value = serde_json::from_str(&b).unwrap();
    let tools = v["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("{v}"));
    assert_eq!(tools.len(), 9, "{v}");
    assert_eq!(
        tools.iter().filter(|t| t["name"] == PROFILE_TOOL).count(),
        1
    );

    // tools/call → real sinter_get_version, caller id preserved
    let (s, _h, b) = mcp_post_bearer(
        addr,
        &tok,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":"call-1","method":"tools/call",
            "params":{"name":"sinter_get_version","arguments":{}}}),
    );
    assert_eq!(s, 200, "{b}");
    let v: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(v["id"], "call-1");
    assert!(v["result"].is_object(), "{v}");
    rig.server.shutdown().await;
}

/// Concurrency smoke: parallel OAuth-authed sessions and calls.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn oauth_concurrent_sessions() {
    let path = tmpdb("conc");
    let _g = Cleanup(path.clone());
    let as_ = TestAs::start();
    let aud = format!("http://{}", as_.addr);
    let rig = rig_oauth(&path, &as_).await;
    let addr = rig.server.addr;
    let cred = register(addr, &rig.auth, "acc_a");
    let _bridge = start_bridge(addr, cred, false);

    let mut handles = Vec::new();
    for i in 0..6 {
        let tok = as_.mint(&as_.claims(&aud, &format!("s{i}"), Some("acc_a"), 3600));
        handles.push(std::thread::spawn(move || {
            let sid = init_session(addr, &tok);
            let (s, _h, b) = mcp_post_bearer(
                addr,
                &tok,
                Some(&sid),
                &json!({"jsonrpc":"2.0","id":i,"method":"tools/call",
                    "params":{"name":"sinter_get_version","arguments":{}}}),
            );
            assert_eq!(s, 200, "{b}");
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    rig.server.shutdown().await;
}
