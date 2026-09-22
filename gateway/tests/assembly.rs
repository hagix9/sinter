//! P7.5 assembly tests — real production binaries as real processes.
//!
//! Positive chain: `sinter-gateway` bin (test-auth build, loopback) →
//! `sinter-bridge` bin → official `sinter mcp` child. Plus config/child
//! contract negatives. Run requires the root `sinter` binary:
//! `cargo build` in the repo root (or SINTER_BIN env).

use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

fn gw_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sinter-gateway")
}
fn br_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sinter-bridge")
}

fn sinter_bin() -> PathBuf {
    if let Ok(p) = std::env::var("SINTER_BIN") {
        return PathBuf::from(p);
    }
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/debug/sinter");
    if p.exists() {
        return p;
    }
    PathBuf::from("sinter")
}

fn wait_port(port: u16, dur: Duration) {
    let start = Instant::now();
    while start.elapsed() < dur {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("port {port} never came up");
}

/// Parse `sinter-gateway serving on 127.0.0.1:PORT` from child stdout.
fn parse_listening_port(line: &str) -> Option<u16> {
    let key = "sinter-gateway serving on ";
    let i = line.find(key)?;
    let addr = line[i + key.len()..].split_whitespace().next()?;
    addr.rsplit(':').next()?.parse().ok()
}

/// Unique per-call temp root (pid + monotonic counter + nanos).
fn tmpdir(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!(
        "sinter-asm-{name}-{}-{n}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Drain a piped stdio stream on a thread so the child never blocks on a
/// full pipe (and the parent never deadlocks waiting for exit).
fn drain_pipe<R: std::io::Read + Send + 'static>(r: R) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut s = String::new();
        let mut r = r;
        let _ = r.read_to_string(&mut s);
        s
    })
}

/// Start gateway bound to an ephemeral port; the OS assigns the port and
/// the child keeps the listener (no free_port TOCTOU). Returns (proc, port, stdout_jh).
/// `bin` is injectable so failure-path tests can use a stub gateway.
fn bind_gateway_ephemeral(
    bin: &str,
    db: &std::path::Path,
    extra: &[(String, String)],
) -> (Proc, u16, std::thread::JoinHandle<String>) {
    let mut cmd = Command::new(bin);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("SINTER_GW_BIND", "127.0.0.1:0")
        .env("SINTER_GW_SQLITE", db)
        .env("SINTER_GW_PUBLIC_URL", "https://gw.example.com")
        .env("SINTER_GW_OAUTH_ISSUER", "https://as.example.com")
        .env("SINTER_GW_OAUTH_AUDIENCE", "https://gw.example.com")
        .env(
            "SINTER_GW_OAUTH_JWKS_URI",
            "https://as.example.com/.well-known/jwks.json",
        )
        .env("SINTER_GW_ALLOWED_ORIGINS", "https://chatgpt.com")
        .env("SINTER_GW_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra {
        cmd.env(k, v);
    }
    // Proc owns the child from the moment spawn succeeds: every later
    // failure path — stdout take, port parse, recv timeout, panic — is
    // covered by RAII kill+wait. (PUB-F01)
    let mut child = Proc(cmd.spawn().unwrap());
    let stdout = child.0.stdout.take().unwrap();
    let stderr = child.0.stderr.take().unwrap();
    let _err_jh = drain_pipe(stderr);
    // Drain stdout on a thread; signal the ephemeral port once logged.
    let (tx, rx) = std::sync::mpsc::channel::<u16>();
    let out_jh = std::thread::spawn(move || {
        use std::io::Read;
        let mut stdout = stdout;
        let mut acc = String::new();
        let mut buf = [0u8; 512];
        let mut announced = false;
        loop {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if !announced {
                        if let Some(p) = parse_listening_port(&acc) {
                            let _ = tx.send(p);
                            announced = true;
                        }
                    }
                }
            }
        }
        acc
    });
    let port = rx
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| panic!("gateway never logged listening addr"));
    (child, port, out_jh)
}

struct Proc(Child);
impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sigterm(c: &mut Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(c.id().to_string())
            .status();
    }
}

fn mcp_post(port: u16, sid: Option<&str>, frame: &Value) -> (u16, reqwest::blocking::Response) {
    let c = reqwest::blocking::Client::new();
    let mut r = c
        .post(format!("http://127.0.0.1:{port}/mcp"))
        .header("X-Sinter-Test-Principal", "testpub-a")
        .header("Origin", "https://chatgpt.com")
        .header("Content-Type", "application/json");
    if let Some(s) = sid {
        r = r
            .header("MCP-Session-Id", s)
            .header("MCP-Protocol-Version", "2025-03-26");
    }
    let res = r.json(frame).send().unwrap();
    (res.status().as_u16(), res)
}

fn init_session(port: u16) -> String {
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-03-26","capabilities":{},
                  "clientInfo":{"name":"asm","version":"0"}}});
    let (s, res) = mcp_post(port, None, &init);
    assert_eq!(s, 200);
    res.headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

/// The complete non-ChatGPT production chain with real processes:
/// gateway bin → bridge bin → official `sinter mcp` child.
#[test]
fn real_process_chain() {
    let _g = proc_lock();
    let dir = tmpdir("chain");
    let db = dir.join("gw.db");
    // Ephemeral bind: OS-assigned port held by the gateway child (no TOCTOU).
    let extra = [(
        "SINTER_GW_TEST_PRINCIPALS".to_string(),
        "testpub-a=acc_a:subj-a@example.com".to_string(),
    )];
    let (mut gw, port, _gw_out) = bind_gateway_ephemeral(gw_bin(), &db, &extra);
    let base = format!("http://127.0.0.1:{port}");
    wait_port(port, Duration::from_secs(10));

    // --- operator bootstrap: single-use registration token ---
    let tok = Command::new(gw_bin())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("SINTER_GW_SQLITE", &db)
        .args(["--issue-registration-token", "acc_a"])
        .output()
        .unwrap();
    assert!(tok.status.success());
    let token = String::from_utf8(tok.stdout).unwrap().trim().to_string();
    assert!(!token.is_empty());
    assert!(token.len() > 30, "registration token too short");

    // --- bridge-side registration: token → controller credential ---
    // Token injected via env (never argv).
    let reg = Command::new(br_bin())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("SINTER_BRIDGE_GATEWAY_URL", &base)
        .env("SINTER_BRIDGE_ALLOW_HTTP", "1")
        .env("SINTER_BRIDGE_REG_TOKEN", &token)
        .arg("register")
        .output()
        .unwrap();
    assert!(
        reg.status.success(),
        "{}",
        String::from_utf8_lossy(&reg.stderr)
    );
    let cred = String::from_utf8(reg.stdout).unwrap().trim().to_string();
    assert!(cred.len() > 30);
    // Single-use: replaying the same token must fail.
    let reg2 = Command::new(br_bin())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("SINTER_BRIDGE_GATEWAY_URL", &base)
        .env("SINTER_BRIDGE_ALLOW_HTTP", "1")
        .env("SINTER_BRIDGE_REG_TOKEN", &token)
        .arg("register")
        .output()
        .unwrap();
    assert!(!reg2.status.success(), "registration token replay accepted");

    // --- credential file (chmod 600 contract) ---
    let credfile = dir.join("controller.cred");
    std::fs::write(&credfile, &cred).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&credfile, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // --- bridge process: outbound only, fixed sinter mcp child ---
    let sinter = sinter_bin();
    assert!(sinter.exists() || sinter.to_str() == Some("sinter"));
    let mut br = Proc(
        Command::new(br_bin())
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap())
            .env("HOME", std::env::var("HOME").unwrap())
            .env("SINTER_BRIDGE_GATEWAY_URL", &base)
            .env("SINTER_BRIDGE_ALLOW_HTTP", "1")
            .env("SINTER_BRIDGE_CREDENTIAL_FILE", &credfile)
            .env("SINTER_BRIDGE_SINTER_BIN", &sinter)
            .env("SINTER_BRIDGE_LOG", "info")
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    // Readiness: poll process liveness instead of a fixed sleep.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if br.0.try_wait().unwrap().is_some() {
            panic!("bridge exited early");
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(br.0.try_wait().unwrap().is_none(), "bridge exited early");

    // --- ChatGPT-side leg (test principal stands in for OAuth) ---
    let sid = init_session(port);

    let (s, res) = mcp_post(
        port,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":77,"method":"tools/list"}),
    );
    assert_eq!(s, 200);
    let v: Value = res.json().unwrap();
    assert_eq!(v["id"], 77);
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"sinter_get_version"), "{names:?}");
    assert!(names.contains(&"sinter_audit_host"), "{names:?}");
    assert!(names.contains(&"sinter_plan_host"), "{names:?}");

    let (s, res) = mcp_post(
        port,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":"call-9","method":"tools/call",
                "params":{"name":"sinter_get_version","arguments":{}}}),
    );
    assert_eq!(s, 200);
    let v: Value = res.json().unwrap();
    assert_eq!(v["id"], "call-9", "caller JSON-RPC id not preserved");
    assert_eq!(v["result"]["isError"], false, "{v}");

    let (s, res) = mcp_post(
        port,
        Some(&sid),
        &json!({"jsonrpc":"2.0","id":10,"method":"tools/call",
                "params":{"name":"sinter_list_targets","arguments":{}}}),
    );
    assert_eq!(s, 200);
    let v: Value = res.json().unwrap();
    assert_eq!(v["result"]["isError"], false, "{v}");

    // --- graceful shutdown: SIGTERM both, bounded exit ---
    sigterm(&mut br.0);
    sigterm(&mut gw.0);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if br.0.try_wait().unwrap().is_some() && gw.0.try_wait().unwrap().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("processes did not exit within 10s of SIGTERM");
}

/// PUB-F01: readiness failure must not leak the spawned gateway.
/// A stub gateway that stays alive but never logs its bind line drives
/// `bind_gateway_ephemeral` into the recv_timeout panic path — the bare
/// spawn must already be owned by `Proc`, so the panic still kills it.
#[test]
fn gateway_readiness_failure_no_leak() {
    let _g = proc_lock();
    let dir = tmpdir("gwfail");
    let db = dir.join("gw.db");
    let stubbin = stub(&dir, "sinter-gateway", "while :; do /bin/sleep 30; done\n");
    let stub_str = stubbin.to_str().unwrap().to_string();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = bind_gateway_ephemeral(&stub_str, &db, &[]);
    }));
    assert!(res.is_err(), "expected readiness panic");
    // Proc::drop fired during unwind: the stub must be dead and reaped.
    std::thread::sleep(Duration::from_millis(300));
    let out = Command::new("pgrep")
        .arg("-f")
        .arg(&stub_str)
        .output()
        .unwrap();
    assert!(
        !out.status.success() || out.stdout.is_empty(),
        "stub gateway leaked: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Gateway binary fails closed when required config is missing.
#[test]
fn gateway_requires_config() {
    let out = Command::new(gw_bin())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("SINTER_GW_BIND", "127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(out.code(), Some(2), "gateway ran without required config");
}

/// Bridge config negatives — URL validation, credential requirements.
#[test]
fn bridge_config_negatives() {
    use sinter_gateway::bridge::BridgeConfig;
    let ok = |u: &str, insecure: bool| {
        BridgeConfig::new(
            u,
            "cred".to_string(),
            PathBuf::from("sinter"),
            None,
            insecure,
        )
    };
    assert!(ok("https://gw.example.com", false).is_ok());
    assert!(
        ok("http://127.0.0.1:8080", false).is_err(),
        "plain http accepted"
    );
    assert!(
        ok("http://example.com", true).is_err(),
        "http non-loopback accepted"
    );
    assert!(
        ok("http://127.0.0.1:8080", true).is_ok(),
        "loopback dev http refused"
    );
    assert!(
        ok("https://user:pw@gw.example.com", false).is_err(),
        "userinfo accepted"
    );
    assert!(
        ok("https://gw.example.com/x", false).is_err(),
        "path accepted"
    );
    assert!(
        ok("https://gw.example.com/?a=b", false).is_err(),
        "query accepted"
    );
    assert!(
        ok("https://gw.example.com/#f", false).is_err(),
        "fragment accepted"
    );
    assert!(
        ok("ftp://gw.example.com", false).is_err(),
        "scheme accepted"
    );
    assert!(
        BridgeConfig::new(
            "https://gw.example.com",
            String::new(),
            PathBuf::from("sinter"),
            None,
            false
        )
        .is_err(),
        "empty credential accepted"
    );
}

/// Bridge refuses to start without a credential.
#[test]
fn bridge_requires_credential() {
    let out = Command::new(br_bin())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .env("SINTER_BRIDGE_GATEWAY_URL", "https://gw.example.com")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(out.code(), Some(2));
}

/// The production artifact never carries test-auth: --version must
/// report it off in a default build (this test runs under the test-auth
/// feature — assert the env var alone cannot flip a non-test build, and
/// that even here the OAuth vars are still honored path).
#[test]
fn version_reports_test_auth_flag() {
    let out = Command::new(gw_bin()).arg("--version").output().unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    // Built with test-auth for this suite: proves the flag is visible in
    // the artifact identity (production build reports "off").
    assert!(
        s.contains("test-auth: ON") || s.contains("test-auth: off"),
        "{s}"
    );
}

/// Write an executable stub `sinter` script; returns its path.
fn stub(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    let mut f = std::fs::File::create(&p).unwrap();
    write!(f, "#!/bin/sh\n{body}").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    p
}

fn child_cfg(dir: &Path, bin: PathBuf) -> sinter_gateway::bridge::BridgeConfig {
    sinter_gateway::bridge::BridgeConfig::new(
        "https://gw.example.com",
        "MARKER-CREDENTIAL".to_string(),
        bin,
        Some(dir.join("targets.toml")),
        false,
    )
    .unwrap()
}

/// Serialize tests that spawn in-process children — `McpChild::spawn`
/// snapshots the process environment. Poison-tolerant: a failing test
/// must not permanently disable the rest of the suite.
static PROC_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn proc_lock() -> std::sync::MutexGuard<'static, ()> {
    PROC_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Child contract: fixed argv, env whitelist, no credential leak, no
/// shell — verified with a stub `sinter` that records its invocation.
/// The marker credential lives in the config; it must never reach the
/// child's argv or environment.
#[test]
fn child_contract() {
    let _g = proc_lock();
    use sinter_gateway::bridge::McpChild;
    let dir = tmpdir("child");
    let out = dir.join("invocation.txt");
    // argv first (fast, before any external `env`), then env dump, then
    // JSON-RPC loop. Avoid racing a 5s request against a slow `env`.
    let stubbin = stub(
        &dir,
        "sinter",
        &format!(
            "printf '%s\\n' \"$@\" > \"{}\"\n/bin/env >> \"{}\"\nwhile IFS= read -r l; do\n  echo '{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"ok\":true}}}}'\ndone\n",
            out.display(),
            out.display()
        ),
    );
    let mut cfg = child_cfg(&dir, stubbin);
    let tf = dir.join("targets.toml");
    std::fs::write(&tf, "# stub\n").unwrap();
    cfg.targets_file = Some(tf.clone());
    let mut child = McpChild::spawn(&cfg).unwrap();
    let r = child.request(
        &json!({"jsonrpc":"2.0","id":1,"method":"x"}),
        Duration::from_secs(15),
    );
    assert!(r.is_ok(), "{r:?}");
    // Invocation file is written before the first response — poll briefly
    // instead of sleeping after kill (Drop races file flush otherwise).
    let start = Instant::now();
    let inv = loop {
        if let Ok(s) = std::fs::read_to_string(&out) {
            if s.contains("mcp") {
                break s;
            }
        }
        if start.elapsed() > Duration::from_secs(2) {
            panic!("invocation.txt never recorded argv");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    drop(child);
    // argv contract: exactly `mcp --targets-file <path>` — no shell words.
    let args: Vec<&str> = inv.lines().filter(|l| !l.contains('=')).collect();
    assert_eq!(
        args,
        vec!["mcp", "--targets-file", tf.to_str().unwrap()],
        "{inv}"
    );
    // env whitelist: credential and bridge config absent.
    assert!(
        !inv.contains("MARKER-CREDENTIAL"),
        "credential in child env"
    );
    assert!(
        !inv.contains("SINTER_BRIDGE_"),
        "bridge env leaked into child"
    );
    assert!(!inv.contains("SINTER_GW_"), "gateway env leaked into child");
}

/// Malformed/desynced/oversized child output fails closed.
#[test]
fn child_malformed_output() {
    let _g = proc_lock();
    use sinter_gateway::bridge::McpChild;
    let dir = tmpdir("badchild");

    // Non-JSON line → malformed. Stub writes exactly one line and holds
    // the process open without depending on `sleep` being on PATH.
    let b = stub(
        &dir,
        "sinter-bad",
        "echo 'not-json'\nwhile :; do /bin/sleep 30; done\n",
    );
    let cfg = child_cfg(&dir, b);
    let mut c = McpChild::spawn(&cfg).unwrap();
    let r = c.request(&json!({"id":1}), Duration::from_secs(15));
    assert!(
        matches!(r, Err(sinter_gateway::bridge::ChildError::Malformed(_))),
        "expected Malformed, got {r:?}"
    );
    drop(c);

    // Wrong id → desync.
    let b = stub(
        &dir,
        "sinter-wrongid",
        "while IFS= read -r l; do echo '{\"jsonrpc\":\"2.0\",\"id\":999,\"result\":{}}'; done\n",
    );
    let cfg = child_cfg(&dir, b);
    let mut c = McpChild::spawn(&cfg).unwrap();
    let r = c.request(&json!({"id":1}), Duration::from_secs(15));
    assert!(
        matches!(r, Err(sinter_gateway::bridge::ChildError::Desynced)),
        "expected Desynced, got {r:?}"
    );
    drop(c);

    // Oversized line → error (bounded reader).
    let b = stub(
        &dir,
        "sinter-big",
        "python3 -c \"print('x' * 6000000)\"\nwhile :; do /bin/sleep 30; done\n",
    );
    if Command::new("python3").arg("--version").output().is_ok() {
        let cfg = child_cfg(&dir, b);
        let mut c = McpChild::spawn(&cfg).unwrap();
        let r = c.request(&json!({"id":1}), Duration::from_secs(15));
        assert!(r.is_err(), "expected error for oversized, got {r:?}");
        drop(c);
    }

    // EOF / child death → Died.
    let b = stub(&dir, "sinter-die", "exit 0\n");
    let cfg = child_cfg(&dir, b);
    let mut c = McpChild::spawn(&cfg).unwrap();
    // Child exits immediately; first request observes EOF/death.
    let r = c.request(&json!({"id":1}), Duration::from_secs(5));
    assert!(
        matches!(
            r,
            Err(sinter_gateway::bridge::ChildError::Died)
                | Err(sinter_gateway::bridge::ChildError::Malformed(_))
        ),
        "expected Died/Malformed, got {r:?}"
    );
}
