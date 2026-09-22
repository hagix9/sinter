//! P7 — configuration contract tests (RFC §M). Every invalid value must
//! fail closed; absent values must produce the ratified safe defaults.

use sinter_gateway::config::GwConfig;
use std::collections::HashMap;

fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let m: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |k| m.get(k).cloned()
}

#[test]
fn empty_env_yields_ratified_defaults() {
    let c = GwConfig::from_vars(|_| None).unwrap();
    assert!(c.rate.enabled);
    assert_eq!(c.rate.mcp_rps, 30.0);
    assert_eq!(c.rate.mcp_burst, 60);
    assert_eq!(c.rate.mcp_global_rps, 300.0);
    assert_eq!(c.rate.poll_rps, 2.0);
    assert_eq!(c.rate.respond_rps, 20.0);
    assert_eq!(c.rate.register_per_min, 5.0);
    assert_eq!(c.rate.rotate_per_min, 10.0);
    assert_eq!(c.rate.authfail_per_min, 30.0);
    assert!(!c.metrics_enabled, "metrics default off");
    assert_eq!(c.metrics_bind.to_string(), "127.0.0.1:9091");
    assert_eq!(c.cleanup_interval.as_secs(), 3600);
}

#[test]
fn valid_values_apply() {
    let c = GwConfig::from_vars(vars(&[
        ("SINTER_GW_RATE_MCP_RPS", "10"),
        ("SINTER_GW_RATE_MCP_BURST", "5"),
        ("SINTER_GW_RATE_POLL_RPS", "0.5"),
        ("SINTER_GW_RATE_ENABLED", "false"),
        ("SINTER_GW_METRICS_ENABLED", "true"),
        ("SINTER_GW_METRICS_BIND", "127.0.0.1:9999"),
        ("SINTER_GW_CLEANUP_INTERVAL_SECS", "120"),
    ]))
    .unwrap();
    assert_eq!(c.rate.mcp_rps, 10.0);
    assert_eq!(c.rate.mcp_burst, 5);
    assert_eq!(c.rate.poll_rps, 0.5);
    assert!(!c.rate.enabled);
    assert!(c.metrics_enabled);
    assert_eq!(c.metrics_bind.to_string(), "127.0.0.1:9999");
    assert_eq!(c.cleanup_interval.as_secs(), 120);
}

#[test]
fn malformed_values_fail_closed() {
    for (k, v) in [
        ("SINTER_GW_RATE_MCP_RPS", "fast"),
        ("SINTER_GW_RATE_MCP_RPS", "NaN"),
        ("SINTER_GW_RATE_MCP_RPS", "inf"),
        ("SINTER_GW_RATE_MCP_BURST", "lots"),
        ("SINTER_GW_RATE_MCP_BURST", "-1"),
        ("SINTER_GW_RATE_ENABLED", "yes"),
        ("SINTER_GW_RATE_ENABLED", "1"),
        ("SINTER_GW_METRICS_ENABLED", "on"),
        ("SINTER_GW_METRICS_BIND", "not-an-addr"),
        ("SINTER_GW_CLEANUP_INTERVAL_SECS", "hourly"),
        ("SINTER_GW_RATE_POLL_RPS", ""),
    ] {
        // Empty string is treated as absent (Ok); everything else → Err.
        let r = GwConfig::from_vars(vars(&[(k, v)]));
        if v.is_empty() {
            assert!(r.is_ok(), "{k}=empty should be treated as absent");
        } else {
            assert!(r.is_err(), "{k}={v:?} must fail closed");
        }
    }
}

#[test]
fn out_of_range_values_fail_closed() {
    for (k, v) in [
        ("SINTER_GW_RATE_MCP_RPS", "0"),    // below min 1.0
        ("SINTER_GW_RATE_MCP_RPS", "1001"), // above max 1000
        ("SINTER_GW_RATE_MCP_RPS", "-5"),
        ("SINTER_GW_RATE_POLL_RPS", "0.05"), // below min 0.1
        ("SINTER_GW_RATE_POLL_RPS", "101"),  // above max 100
        ("SINTER_GW_RATE_REGISTER_PER_MIN", "0"),
        ("SINTER_GW_RATE_MCP_BURST", "0"),
        ("SINTER_GW_RATE_MCP_BURST", "10001"),
        ("SINTER_GW_CLEANUP_INTERVAL_SECS", "59"), // below min 60
        ("SINTER_GW_CLEANUP_INTERVAL_SECS", "86401"), // above max
        ("SINTER_GW_RATE_AUTHFAIL_PER_MIN", "0.5"),
    ] {
        assert!(
            GwConfig::from_vars(vars(&[(k, v)])).is_err(),
            "{k}={v} must fail closed"
        );
    }
}

#[test]
fn boundary_values_accepted() {
    let c = GwConfig::from_vars(vars(&[
        ("SINTER_GW_RATE_MCP_RPS", "1"),
        ("SINTER_GW_RATE_POLL_RPS", "0.1"),
        ("SINTER_GW_RATE_MCP_BURST", "1"),
        ("SINTER_GW_CLEANUP_INTERVAL_SECS", "60"),
    ]))
    .unwrap();
    assert_eq!(c.rate.mcp_rps, 1.0);
    let c = GwConfig::from_vars(vars(&[
        ("SINTER_GW_RATE_MCP_RPS", "1000"),
        ("SINTER_GW_RATE_POLL_RPS", "100"),
        ("SINTER_GW_RATE_MCP_BURST", "10000"),
        ("SINTER_GW_CLEANUP_INTERVAL_SECS", "86400"),
    ]))
    .unwrap();
    assert_eq!(c.rate.mcp_burst, 10000);
}

#[test]
fn non_loopback_metrics_bind_refused() {
    for bind in [
        "0.0.0.0:9091",
        "10.0.0.5:9091",
        "203.0.113.1:9091",
        "[::]:9091",
    ] {
        assert!(
            GwConfig::from_vars(vars(&[("SINTER_GW_METRICS_BIND", bind)])).is_err(),
            "{bind} must be refused — unauthenticated endpoint"
        );
    }
    // IPv6 loopback is fine.
    assert!(GwConfig::from_vars(vars(&[("SINTER_GW_METRICS_BIND", "[::1]:9091")])).is_ok());
}

#[test]
fn trusted_proxy_must_stay_empty_in_v1() {
    assert!(GwConfig::from_vars(vars(&[("SINTER_GW_TRUSTED_PROXY", "")])).is_ok());
    for v in ["10.0.0.1", "true", "any"] {
        assert!(
            GwConfig::from_vars(vars(&[("SINTER_GW_TRUSTED_PROXY", v)])).is_err(),
            "SINTER_GW_TRUSTED_PROXY={v:?} must fail closed (no proxy mode in v1)"
        );
    }
}
