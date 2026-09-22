//! P7 — telemetry tests (RFC §L): bounded cardinality, fixed labels,
//! render shape, gauge RAII, optional loopback /metrics endpoint.

use sinter_gateway::metrics::{AuthFailReason, Metrics, SqlOp};
use sinter_gateway::rate_limit::BucketClass;
use sinter_gateway::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

#[test]
fn render_contains_ratified_metrics_only() {
    let m = Metrics::new();
    m.observe_http(Some("/mcp"), "POST", 200, 0.012);
    m.observe_http(Some("/v1/poll"), "POST", 429, 0.001);
    m.rate_limited(BucketClass::McpAccount);
    m.concurrency_limited();
    m.auth_failure(AuthFailReason::Invalid);
    m.jwks_refresh(true);
    m.jwks_refresh(false);
    m.sqlite_error(SqlOp::TokenTake);
    m.deadline_exceeded(2);
    m.set_controller_active_polls(3);
    m.set_work_queued(7);
    m.set_controller_online(1);

    let out = m.render();
    for name in [
        "http_requests_total",
        "http_request_duration_seconds",
        "rate_limited_total",
        "auth_failures_total",
        "jwks_refresh_total",
        "sqlite_errors_total",
        "mcp_active_requests",
        "controller_active_polls",
        "work_queued",
        "controller_online",
        "deadline_exceeded_total",
    ] {
        assert!(out.contains(name), "missing {name}");
    }
    assert!(out.contains("rate_limited_total{bucket_class=\"mcp_account\"} 1"));
    assert!(out.contains("rate_limited_total{bucket_class=\"concurrency\"} 1"));
    assert!(out.contains("auth_failures_total{reason_class=\"invalid\"} 1"));
    assert!(out.contains("jwks_refresh_total{result=\"ok\"} 1"));
    assert!(out.contains("sqlite_errors_total{op=\"token_take\"} 1"));
    assert!(out.contains("deadline_exceeded_total 2"));
    assert!(out.contains("controller_active_polls 3"));
}

#[test]
fn attacker_input_cannot_grow_cardinality() {
    let m = Metrics::new();
    // Attacker-controlled strings as "route"/"method" collapse to fixed sets.
    for i in 0..10_000 {
        m.observe_http(
            Some(&format!("/evil/{i}")),
            &format!("METHOD{i}"),
            200 + (i % 400) as u16,
            0.001,
        );
    }
    // Every bogus route → "other"; every bogus method → "other".
    // 4xx/5xx classes still bucket normally — total cells ≤ ROUTES×4×4.
    assert!(m.cardinality() <= 160 + 64 + 8 + 5 + 8 + 2);
    let out = m.render();
    assert!(!out.contains("/evil/"), "attacker label leaked");
    assert!(!out.contains("METHOD0"), "attacker method leaked");
}

#[test]
fn gauge_guard_raii() {
    let m = Metrics::new();
    {
        let _g = m.mcp_active();
        assert!(m.render().contains("mcp_active_requests 1"));
        {
            let _g2 = m.mcp_active();
            assert!(m.render().contains("mcp_active_requests 2"));
        }
        assert!(m.render().contains("mcp_active_requests 1"));
    }
    assert!(m.render().contains("mcp_active_requests 0"));
}

#[test]
fn no_payload_or_identity_strings_in_render() {
    let m = Metrics::new();
    m.observe_http(Some("/mcp"), "POST", 200, 0.1);
    m.auth_failure(AuthFailReason::Malformed);
    let out = m.render();
    for forbidden in [
        "Bearer",
        "acc_",
        "subject",
        "request_id",
        "controller_id",
        "token",
        "ssh",
    ] {
        assert!(
            !out.contains(forbidden),
            "render leaked forbidden token {forbidden:?}"
        );
    }
}

/// Loopback /metrics endpoint: enabled via config → serves counters;
/// the main router never exposes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_endpoint_loopback_only_when_enabled() {
    let dir = std::env::temp_dir().join(format!("sinter-gw-p7met-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("m.db");
    let core = Arc::new(GatewayCore::with_clock(SystemClock));
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let cfg = sinter_gateway::config::GwConfig {
        metrics_enabled: true,
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    };
    let state = GatewayHttp::new(core.clone(), auth, store).with_config(&cfg);
    let server = GatewayServer::start(state, "127.0.0.1:0").await.unwrap();

    // Main listener must NOT expose /metrics.
    let mut s = TcpStream::connect(server.addr).unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.starts_with("HTTP/1.1 404"),
        "main router must not expose metrics: {text}"
    );

    // The metrics listener IS up on its own loopback bind and serves the
    // counters ( gauges refreshed from core at render time ).
    let maddr = server.metrics_addr.expect("metrics listener bound");
    let mut s = TcpStream::connect(maddr).unwrap();
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(text.starts_with("HTTP/1.1 200"), "metrics endpoint: {text}");
    assert!(text.contains("http_requests_total"), "{text}");
    assert!(text.contains("work_queued"), "{text}");
    server.shutdown().await;
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
}

/// F-13: the loopback-only metrics invariant is enforced at the bind
/// site, not just in `GwConfig::from_vars` — a programmatically built
/// config with a public bind must fail closed at server start.
#[tokio::test]
async fn programmatic_non_loopback_metrics_bind_refused() {
    use sinter_gateway::config::GwConfig;
    let dir = std::env::temp_dir().join(format!("sinter-f13-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("m.db");
    let core = Arc::new(GatewayCore::with_clock(SystemClock));
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let mut cfg = GwConfig::from_vars(|_| None).unwrap();
    cfg.metrics_enabled = true;
    cfg.metrics_bind = "0.0.0.0:0".parse().unwrap(); // bypasses from_vars
    let st = GatewayHttp::new(core, auth, store).with_config(&cfg);
    let r = GatewayServer::start(st, "127.0.0.1:0").await;
    assert!(r.is_err(), "non-loopback metrics bind must fail closed");
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
}

/// F-17: `sqlite_errors_total{op}` must count real store-operation
/// failures — wired automatically at `GatewayHttp::new`.
#[test]
fn sqlite_errors_total_counts_store_failures() {
    let dir = std::env::temp_dir().join(format!("sinter-f17-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("m.db");
    let store = Arc::new(SqliteStore::open(&path).unwrap());
    let core = Arc::new(GatewayCore::with_clock(SystemClock));
    let auth = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let st = GatewayHttp::new(core, auth, store.clone());
    // Sabotage the schema on a second connection — the next store op fails.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DROP TABLE controllers", []).unwrap();
    }
    let r = store.controller(&ControllerId::new("gone"));
    assert!(r.is_none(), "failed read must not fabricate a record");
    let out = st.metrics().render();
    assert!(
        out.contains("sqlite_errors_total"),
        "store failure must be counted: {out}"
    );
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
}
