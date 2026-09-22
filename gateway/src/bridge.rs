//! P7.5 — production bridge core (`sinter-bridge`).
//!
//! Controller-side component: outbound HTTPS only. Long-polls the Gateway
//! `/v1/poll` with the controller credential, forwards each opaque MCP
//! frame to the fixed `sinter mcp` child over stdio, and posts the child's
//! response to `/v1/respond`. All work is memory-only — nothing is queued
//! durably, nothing is replayed after restart.
//!
//! Security contract (hard rules):
//! * The child executable and argv are fixed local configuration — never
//!   derived from Gateway data.
//! * No shell is ever invoked.
//! * The controller credential never reaches argv, the child's
//!   environment, the child's stdio, or logs.
//! * Redirects are disabled — the credential can never be forwarded to a
//!   different origin.
//! * Plain-HTTP Gateway URLs are rejected unless explicitly opted into
//!   AND the host is loopback (non-production local use only).

use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tracing::{debug, info, warn};

use crate::proto::{
    ErrorCode, PollResponse, RespondRequest, TransportError, WorkItem, MAX_MCP_RESPONSE_BYTES,
    MAX_POLL_WAIT_MS,
};

/// How long poll responses may take: server hold + network slack.
const POLL_HTTP_TIMEOUT_MS: u64 = MAX_POLL_WAIT_MS + 15_000;
/// Timeout for register/respond-sized requests.
const REQUEST_TIMEOUT_MS: u64 = 15_000;
/// Base backoff on transient poll failure.
const BACKOFF_BASE_MS: u64 = 1_000;
/// Backoff ceiling on transient failure.
const BACKOFF_MAX_MS: u64 = 60_000;
/// Cadence for persistent authentication failure (401/403). Kept slow —
/// a revoked/invalid credential is not a retryable transient error, but a
/// rotated/restored credential may succeed later without restart.
const AUTH_BACKOFF_MS: u64 = 300_000;
/// Max stdout line the child may emit (4 MiB protocol cap + slack).
const MAX_CHILD_LINE: usize = MAX_MCP_RESPONSE_BYTES + (64 << 10);
/// Child restart attempts inside a 5-minute window before the bridge
/// exits — the service manager then owns the decision.
const MAX_CHILD_RESTARTS: u32 = 5;
/// Spacing between automatic child restarts.
const CHILD_RESTART_DELAY_MS: u64 = 1_000;
/// Child response wait ceiling — bound even if a work deadline is absent.
const CHILD_WAIT_MAX_MS: u64 = 300_000;

/// Environment the child is allowed to see. Whitelisted, never inherited
/// wholesale: bridge/Gateway secrets (SINTER_BRIDGE_*, controller
/// credential) cannot leak into `sinter mcp`. SSH_AUTH_SOCK is required
/// for agent-based Sinter SSH auth; HOME/PATH for its key/config lookup.
const CHILD_ENV_ALLOW: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "TZ",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "SINTER_LOG",
];

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Validated bridge configuration. Construct via [`BridgeConfig::new`];
/// invalid values fail closed before any network or child activity.
#[derive(Clone)]
pub struct BridgeConfig {
    /// Gateway base URL, e.g. `https://gw.example.com`. No userinfo, no
    /// query, no fragment; path must be empty/`/`.
    pub gateway_url: url::Url,
    /// Controller credential — secret. Never logged or Debug-printed.
    credential: String,
    /// Resolved path/name of the `sinter` executable.
    pub sinter_bin: PathBuf,
    /// Optional local targets file passed to the child as
    /// `--targets-file`. Purely local trusted configuration.
    pub targets_file: Option<PathBuf>,
    /// Per-request HTTP timeout for non-poll calls.
    pub request_timeout: Duration,
    /// Overall poll request timeout (server hold + slack).
    pub poll_timeout: Duration,
    /// Backoff ceiling for transient errors.
    pub max_backoff: Duration,
}

impl BridgeConfig {
    pub fn new(
        gateway_url: &str,
        credential: String,
        sinter_bin: PathBuf,
        targets_file: Option<PathBuf>,
        allow_insecure_http: bool,
    ) -> Result<Self, String> {
        let url = url::Url::parse(gateway_url).map_err(|e| format!("gateway url: {e}"))?;
        match url.scheme() {
            "https" => {}
            "http" => {
                let loopback = match url.host() {
                    Some(url::Host::Domain(d)) => d == "localhost",
                    Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
                    Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
                    None => false,
                };
                if !(allow_insecure_http && loopback) {
                    return Err("gateway url must be https:// (plain http is only allowed \
                         for loopback with SINTER_BRIDGE_ALLOW_HTTP=1)"
                        .to_string());
                }
            }
            s => return Err(format!("unsupported gateway url scheme: {s}")),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("gateway url must not contain userinfo".to_string());
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err("gateway url must not contain query or fragment".to_string());
        }
        if !url.path().trim_end_matches('/').is_empty() {
            return Err("gateway url must not contain a path".to_string());
        }
        if credential.is_empty() {
            return Err("controller credential is empty".to_string());
        }
        Ok(Self {
            gateway_url: url,
            credential,
            sinter_bin,
            targets_file,
            request_timeout: Duration::from_millis(REQUEST_TIMEOUT_MS),
            poll_timeout: Duration::from_millis(POLL_HTTP_TIMEOUT_MS),
            max_backoff: Duration::from_millis(BACKOFF_MAX_MS),
        })
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}{}",
            self.gateway_url.as_str().trim_end_matches('/'),
            path
        )
    }
}

/// One `sinter mcp` child: fixed executable, fixed argv, stdio pipes.
/// stdout frames are produced by a bounded reader thread; stderr is
/// inherited (child diagnostics stay local to the bridge process).
pub struct McpChild {
    child: Child,
    stdin: std::process::ChildStdin,
    lines: mpsc::Receiver<Result<String, String>>,
}

impl McpChild {
    pub fn spawn(cfg: &BridgeConfig) -> Result<Self, String> {
        let mut cmd = Command::new(&cfg.sinter_bin);
        cmd.arg("mcp");
        if let Some(f) = &cfg.targets_file {
            cmd.arg("--targets-file").arg(f);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env_clear();
        for (k, v) in std::env::vars_os() {
            if let Some(k) = k.to_str() {
                if CHILD_ENV_ALLOW.contains(&k) {
                    cmd.env(k, v);
                }
            }
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", cfg.sinter_bin.display()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "child stdin unavailable".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "child stdout unavailable".to_string())?;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            loop {
                let mut buf = Vec::with_capacity(4096);
                let res = bounded_line(&mut r, &mut buf, MAX_CHILD_LINE);
                let msg = match res {
                    Ok(0) => break, // EOF — child closed stdout
                    Ok(_) => String::from_utf8(buf)
                        .map_err(|_| "child emitted non-UTF8 frame".to_string()),
                    Err(e) => Err(e.to_string()),
                };
                if tx.send(msg).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines: rx,
        })
    }

    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Kill the child without waiting for graceful exit. Used on desync,
    /// oversized output, and shutdown.
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Execute one JSON-RPC frame. Returns the child's verbatim response
    /// frame, or an error if the child failed/desynced/timed out.
    pub fn request(&mut self, frame: &Value, deadline: Duration) -> Result<Value, ChildError> {
        if !self.alive() {
            return Err(ChildError::Died);
        }
        let sent_id = frame.get("id").cloned();
        let line = serde_json::to_string(frame)
            .map_err(|e| ChildError::Malformed(format!("serialize: {e}")))?;
        if self
            .stdin
            .write_all(line.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .is_err()
        {
            return Err(ChildError::Died);
        }
        match self.lines.recv_timeout(deadline) {
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ChildError::Deadline),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ChildError::Died),
            Ok(Err(e)) => Err(ChildError::Malformed(e)),
            Ok(Ok(text)) => {
                if text.len() > MAX_MCP_RESPONSE_BYTES {
                    return Err(ChildError::Oversized);
                }
                let v: Value = serde_json::from_str(&text)
                    .map_err(|e| ChildError::Malformed(format!("json: {e}")))?;
                if !v.is_object() || v.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                    return Err(ChildError::Malformed("not a JSON-RPC response".into()));
                }
                // id discipline: a matching id is a normal response; a
                // null id is sinter-mcp's own parse-error reply to our
                // frame — still ours, forward it. Any other id means the
                // stream desynced.
                let rid = v.get("id").cloned().unwrap_or(Value::Null);
                match sent_id {
                    Some(id) if id == rid => Ok(v),
                    _ if rid.is_null() => Ok(v),
                    _ => Err(ChildError::Desynced),
                }
            }
        }
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        self.kill();
    }
}

/// `Ok(n)` bytes read (0 = EOF), `Err` on io error or cap exceeded.
fn bounded_line(r: &mut impl BufRead, buf: &mut Vec<u8>, cap: usize) -> std::io::Result<usize> {
    let mut total = 0usize;
    loop {
        let avail = r.fill_buf()?;
        if avail.is_empty() {
            return Ok(total);
        }
        let take = avail
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(avail.len());
        if total + take > cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "child frame exceeds size cap",
            ));
        }
        let ended = avail[take - 1] == b'\n';
        buf.extend_from_slice(&avail[..take]);
        r.consume(take);
        total += take;
        if ended {
            return Ok(total);
        }
    }
}

#[derive(Debug)]
pub enum ChildError {
    Died,
    Deadline,
    Oversized,
    Malformed(String),
    Desynced,
}

impl ChildError {
    fn into_transport(self) -> TransportError {
        match self {
            ChildError::Died => {
                TransportError::new(ErrorCode::BackendTerminated, "mcp child terminated")
            }
            ChildError::Deadline => {
                TransportError::new(ErrorCode::DeadlineExceeded, "mcp child deadline")
            }
            ChildError::Oversized => {
                TransportError::new(ErrorCode::OversizedResponse, "mcp child oversized")
            }
            ChildError::Desynced => {
                TransportError::new(ErrorCode::BackendUnavailable, "mcp child desynced")
            }
            ChildError::Malformed(m) => {
                TransportError::new(ErrorCode::BackendUnavailable, format!("mcp child: {m}"))
            }
        }
    }
}

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        // Never follow redirects: the Authorization credential must
        // only ever reach the configured Gateway origin.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("http client: {e}"))
}

/// Run the bridge until `shutdown` fires. Serial work loop — at most one
/// MCP request in flight, matching the one-work-per-poll contract.
/// Returns Err on fatal child-spawn failure; exits process code 3 if the
/// child restart budget is exhausted (service manager owns the decision).
pub async fn run(
    cfg: BridgeConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let client = http_client()?;
    let mut child: Option<McpChild> = Some(McpChild::spawn(&cfg)?);
    let mut restarts = 0u32;
    let mut restart_window: Option<Instant> = None;
    let mut backoff = Duration::from_millis(BACKOFF_BASE_MS);
    info!("bridge polling {}", cfg.gateway_url);

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            res = poll_once(&client, &cfg) => {
                match res {
                    Ok(r) if r.status().is_success() => {
                        backoff = Duration::from_millis(BACKOFF_BASE_MS);
                        match r.json::<PollResponse>().await {
                            Ok(PollResponse { work: Some(w) }) => {
                                debug!("work received");
                                child = execute(&client, &cfg, child, w, &mut shutdown).await;
                                if child.is_none()
                                    && !respawn(
                                        &cfg, &mut child, &mut restarts,
                                        &mut restart_window, &mut shutdown,
                                    ).await
                                {
                                    warn!("mcp child restart budget exhausted — exiting");
                                    return Err("child restart budget exhausted".into());
                                }
                            }
                            Ok(_) => {} // hold timed out, no work — normal
                            Err(_) => warn!("malformed poll body"),
                        }
                    }
                    Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED
                        || r.status() == reqwest::StatusCode::FORBIDDEN =>
                    {
                        warn!("controller authentication failed — retrying every {}s",
                            AUTH_BACKOFF_MS / 1000);
                        if !sleep_or_shutdown(AUTH_BACKOFF_MS, &mut shutdown).await {
                            break;
                        }
                    }
                    Ok(r) => {
                        warn!("poll HTTP {}", r.status());
                        if !sleep_or_shutdown(backoff.as_millis() as u64, &mut shutdown).await {
                            break;
                        }
                        backoff = jitter(backoff, cfg.max_backoff);
                    }
                    Err(e) => {
                        warn!("poll failed: {}", err_kind(&e));
                        if !sleep_or_shutdown(backoff.as_millis() as u64, &mut shutdown).await {
                            break;
                        }
                        backoff = jitter(backoff, cfg.max_backoff);
                    }
                }
            }
        }
    }
    info!("bridge shutdown");
    Ok(())
}

async fn poll_once(
    client: &reqwest::Client,
    cfg: &BridgeConfig,
) -> reqwest::Result<reqwest::Response> {
    client
        .post(cfg.endpoint("/v1/poll"))
        .bearer_auth(&cfg.credential)
        .timeout(cfg.poll_timeout)
        .send()
        .await
}

/// Bounded child respawn. Returns false once the restart budget inside
/// the 5-minute window is exhausted — `run` then exits so the service
/// manager owns the decision.
async fn respawn(
    cfg: &BridgeConfig,
    child: &mut Option<McpChild>,
    restarts: &mut u32,
    window: &mut Option<Instant>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    if window.is_some_and(|t| t.elapsed() > Duration::from_secs(300)) {
        *restarts = 0;
        *window = None;
    }
    if window.is_none() {
        *window = Some(Instant::now());
    }
    if *restarts >= MAX_CHILD_RESTARTS {
        return false;
    }
    *restarts += 1;
    tokio::select! {
        _ = shutdown.changed() => return true,
        _ = tokio::time::sleep(Duration::from_millis(CHILD_RESTART_DELAY_MS)) => {}
    }
    match McpChild::spawn(cfg) {
        Ok(c) => {
            warn!("mcp child restarted (attempt {restarts})");
            *child = Some(c);
        }
        Err(e) => warn!("mcp child respawn failed: {e}"),
    }
    true
}

/// Run one work item through the child and post the outcome. Child I/O
/// runs on a blocking thread so the async loop stays responsive to
/// shutdown. Returns the child (taken ownership to satisfy 'static), or
/// None if the child died/must be restarted.
async fn execute(
    client: &reqwest::Client,
    cfg: &BridgeConfig,
    mut child: Option<McpChild>,
    work: WorkItem,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Option<McpChild> {
    let rid = work.request_id.clone();
    if child.is_none() {
        // No healthy child — report transport failure rather than
        // silently dropping the work.
        deliver(
            client,
            cfg,
            rid,
            Err(ChildError::Malformed("no mcp child".into())),
        )
        .await;
        return None;
    }
    let now = unix_ms();
    if work.deadline_unix_ms <= now {
        deliver(client, cfg, rid, Err(ChildError::Deadline)).await;
        return child;
    }
    let remaining = Duration::from_millis(work.deadline_unix_ms - now)
        .min(Duration::from_millis(CHILD_WAIT_MAX_MS));
    let frame = work.mcp.clone();
    let mut c = child.take().unwrap_or_else(|| unreachable!());
    let task = tokio::task::spawn_blocking(move || {
        let r = c.request(&frame, remaining);
        (c, r)
    });
    let (returned, result) = match tokio::select! {
        r = task => r,
        _ = shutdown.changed() => {
            // The detached blocking task keeps the child until its frame
            // completes or the reader hits the deadline; its Drop kills
            // it. No outcome is delivered — the Gateway deadline applies.
            return None;
        }
    } {
        Ok((c, r)) => (Some(c), r),
        Err(_) => (None, Err(ChildError::Died)),
    };
    let restart = matches!(
        result,
        Err(ChildError::Died | ChildError::Desynced | ChildError::Oversized)
    );
    deliver(client, cfg, rid, result).await;
    if restart {
        None
    } else {
        returned
    }
}

async fn deliver(
    client: &reqwest::Client,
    cfg: &BridgeConfig,
    rid: String,
    outcome: Result<Value, ChildError>,
) {
    let body = match outcome {
        Ok(mcp) => RespondRequest {
            v: 1,
            request_id: rid,
            mcp: Some(mcp),
            error: None,
        },
        Err(e) => RespondRequest {
            v: 1,
            request_id: rid,
            mcp: None,
            error: Some(e.into_transport()),
        },
    };
    match client
        .post(cfg.endpoint("/v1/respond"))
        .bearer_auth(&cfg.credential)
        .json(&body)
        .timeout(cfg.request_timeout)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => debug!("work delivered"),
        Ok(r) => warn!("respond rejected: HTTP {}", r.status()),
        Err(e) => warn!("respond failed: {}", err_kind(&e)),
    }
}

async fn sleep_or_shutdown(ms: u64, shutdown: &mut tokio::sync::watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = shutdown.changed() => false,
        _ = tokio::time::sleep(Duration::from_millis(ms)) => true,
    }
}

/// Next backoff: ~2x with ±25% jitter, capped.
fn jitter(cur: Duration, max: Duration) -> Duration {
    let mut b = [0u8; 8];
    let _ = getrandom::fill(&mut b);
    let j = (u64::from_le_bytes(b) % 501) as i64 - 250; // -250..=250 per-mille
    let base = cur.as_millis() as u64 * 2;
    let jittered = (base as i64 + (base as i64 * j / 1000)).max(250) as u64;
    Duration::from_millis(jittered.min(max.as_millis() as u64))
}

/// Short error categorization — never includes the URL with userinfo or
/// the credential (reqwest error strings may embed the request URL).
fn err_kind(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect failed"
    } else if e.is_request() {
        "request build failed"
    } else if e.is_body() || e.is_decode() {
        "response body error"
    } else {
        "http error"
    }
}

/// Exchange a single-use registration token for a controller credential.
/// Used by `sinter-bridge register`; the credential is returned to the
/// caller once — callers must persist it in the credential file.
pub async fn register_controller(
    gateway_url: &str,
    token: &str,
    allow_insecure_http: bool,
) -> Result<String, String> {
    let cfg = BridgeConfig::new(
        gateway_url,
        "unused".to_string(),
        PathBuf::from("sinter"),
        None,
        allow_insecure_http,
    )?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(REQUEST_TIMEOUT_MS))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let r = client
        .post(cfg.endpoint("/v1/register"))
        .json(&crate::proto::RegisterRequest {
            token: token.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("register request failed: {}", err_kind(&e)))?;
    if !r.status().is_success() {
        return Err(format!("register rejected: HTTP {}", r.status()));
    }
    let body: crate::proto::RegisterResponse = r
        .json()
        .await
        .map_err(|e| format!("register response: {e}"))?;
    Ok(body.credential)
}
