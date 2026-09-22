//! P7 — token-bucket unit tests over `RateLimiter<TestClock>`.
//! Fully deterministic: time advances only via `TestClock::advance`.

use sinter_gateway::rate_limit::{
    BucketClass, ConcurrencyGate, RateLimiter, RateLimits, MAX_BUCKET_KEYS,
};
use sinter_gateway::TestClock;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn cfg() -> RateLimits {
    RateLimits {
        enabled: true,
        mcp_rps: 30.0,
        mcp_burst: 60,
        mcp_global_rps: 300.0,
        poll_rps: 2.0,
        respond_rps: 20.0,
        register_per_min: 5.0,
        rotate_per_min: 10.0,
        authfail_per_min: 30.0,
    }
}

#[test]
fn burst_then_limited_then_retry_after() {
    let clk = TestClock::new();
    let lim = RateLimiter::new(clk.clone(), cfg());
    // mcp burst = 60: first 60 admitted, 61st limited.
    for i in 0..60 {
        assert!(
            lim.check(BucketClass::McpAccount, "acct").is_ok(),
            "req {i}"
        );
    }
    let e = lim.check(BucketClass::McpAccount, "acct").unwrap_err();
    assert!(e.retry_after_secs >= 1);
}

#[test]
fn retry_after_matches_bucket_deficit() {
    let clk = TestClock::new();
    let mut c = cfg();
    c.mcp_rps = 2.0; // 2 tokens/s
    c.mcp_burst = 2;
    let lim = RateLimiter::new(clk.clone(), c);
    assert!(lim.check(BucketClass::McpAccount, "a").is_ok());
    assert!(lim.check(BucketClass::McpAccount, "a").is_ok());
    // Bucket empty → next token in ~0.5 s → Retry-After 1 (ceil).
    let e = lim.check(BucketClass::McpAccount, "a").unwrap_err();
    assert_eq!(e.retry_after_secs, 1);
    // After 0.5 s of refill the bucket has ~1 token → admitted.
    clk.advance(Duration::from_millis(500));
    assert!(lim.check(BucketClass::McpAccount, "a").is_ok());
}

#[test]
fn sustained_rate_stays_limited_without_refill() {
    let clk = TestClock::new();
    let mut c = cfg();
    c.poll_rps = 2.0;
    let lim = RateLimiter::new(clk.clone(), c);
    // poll burst = 5 (code constant); requests 6..10 all fail instantly.
    for _ in 0..5 {
        assert!(lim.check(BucketClass::PollController, "ctl").is_ok());
    }
    for _ in 0..10 {
        assert!(lim.check(BucketClass::PollController, "ctl").is_err());
    }
}

#[test]
fn cross_key_isolation() {
    let clk = TestClock::new();
    let mut c = cfg();
    c.mcp_burst = 2;
    let lim = RateLimiter::new(clk.clone(), c);
    assert!(lim.check(BucketClass::McpAccount, "a").is_ok());
    assert!(lim.check(BucketClass::McpAccount, "a").is_ok());
    assert!(lim.check(BucketClass::McpAccount, "a").is_err());
    // Account B has a fresh bucket.
    assert!(lim.check(BucketClass::McpAccount, "b").is_ok());
}

#[test]
fn cross_class_isolation() {
    let clk = TestClock::new();
    let mut c = cfg();
    c.mcp_burst = 1;
    let lim = RateLimiter::new(clk.clone(), c);
    assert!(lim.check(BucketClass::McpAccount, "a").is_ok());
    assert!(lim.check(BucketClass::McpAccount, "a").is_err());
    // Other classes untouched.
    assert!(lim.check(BucketClass::PollController, "a").is_ok());
    assert!(lim.check(BucketClass::McpGlobal, "gateway").is_ok());
}

#[test]
fn ip_keys_use_canonical_form() {
    let clk = TestClock::new();
    let mut c = cfg();
    c.register_per_min = 0.06; // ~0.001/s — effectively burst-only
    let lim = RateLimiter::new(clk.clone(), c);
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    for _ in 0..10 {
        assert!(lim.check_ip(BucketClass::RegisterIp, ip).is_ok());
    }
    assert!(lim.check_ip(BucketClass::RegisterIp, ip).is_err());
    // Different IP → independent bucket.
    let ip2 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
    assert!(lim.check_ip(BucketClass::RegisterIp, ip2).is_ok());
}

#[test]
fn sweep_reclaims_only_idle_buckets() {
    let clk = TestClock::new();
    let lim = RateLimiter::new(clk.clone(), cfg());
    let _ = lim.check(BucketClass::McpAccount, "old");
    let _ = lim.check(BucketClass::McpAccount, "old2");
    assert_eq!(lim.key_count(), 2);
    clk.advance(Duration::from_secs(400)); // > BUCKET_IDLE_TTL (300s)
    let removed = lim.sweep();
    assert_eq!(removed, 2, "idle buckets reclaimed");
    assert_eq!(lim.key_count(), 0);
    // A fresh bucket survives the next sweep; the opportunistic in-check
    // sweep does not confuse it for idle state.
    let _ = lim.check(BucketClass::McpAccount, "fresh");
    assert_eq!(lim.key_count(), 1);
    assert_eq!(lim.sweep(), 0, "fresh bucket untouched");
}

#[test]
fn saturated_map_fails_closed() {
    let clk = TestClock::new();
    let lim = RateLimiter::new(clk.clone(), cfg());
    // Fill the map to the hard cap with active (recently-touched) buckets.
    for i in 0..MAX_BUCKET_KEYS {
        lim.check(BucketClass::McpAccount, &format!("k{i}"))
            .unwrap();
    }
    assert_eq!(lim.key_count(), MAX_BUCKET_KEYS);
    // A brand-new key is refused rather than evicting live state or
    // growing memory — fail closed, bounded.
    assert!(lim.check(BucketClass::McpAccount, "one-more").is_err());
    assert_eq!(lim.key_count(), MAX_BUCKET_KEYS);
}

#[test]
fn disabled_limiter_admits_everything() {
    let clk = TestClock::new();
    let mut c = cfg();
    c.enabled = false;
    let lim = RateLimiter::new(clk.clone(), c);
    for _ in 0..1000 {
        assert!(lim.check(BucketClass::McpAccount, "a").is_ok());
    }
}

#[test]
fn concurrency_gate_caps_and_recovers() {
    let gate = ConcurrencyGate::new(2);
    let g1 = gate.acquire().unwrap();
    let g2 = gate.acquire().unwrap();
    assert!(gate.acquire().is_none(), "cap reached");
    drop(g1);
    assert!(gate.acquire().is_some(), "slot freed on drop");
    drop(g2);
    assert_eq!(gate.in_flight(), 0);
}

#[test]
fn concurrency_gate_clones_share_state() {
    let gate = ConcurrencyGate::new(1);
    let clone = gate.clone();
    let _g = gate.acquire().unwrap();
    assert!(clone.acquire().is_none(), "clone sees same counter");
    drop(_g);
    assert!(clone.acquire().is_some());
}

#[test]
fn refill_capped_at_burst() {
    let clk = TestClock::new();
    let mut c = cfg();
    c.mcp_rps = 1000.0;
    c.mcp_burst = 5;
    let lim = RateLimiter::new(clk.clone(), c);
    clk.advance(Duration::from_secs(3600)); // idle for an hour
                                            // Bucket caps at burst=5, not at rate×elapsed.
    for _ in 0..5 {
        assert!(lim.check(BucketClass::McpAccount, "a").is_ok());
    }
    assert!(lim.check(BucketClass::McpAccount, "a").is_err());
}

/// F-14: `RateLimits` fields are public — a programmatically-constructed
/// config can bypass `GwConfig` validation. Non-finite / non-positive
/// rates and sub-token bursts must fail closed, never admit.
#[test]
fn invalid_rate_params_fail_closed() {
    let clk = TestClock::new();
    for (r, b) in [
        (f64::NAN, 5u32),
        (f64::INFINITY, 5),
        (0.0, 5),
        (-1.0, 5),
        (1.0, 0), // burst < 1 token can never admit
    ] {
        let mut c = cfg();
        c.mcp_rps = r;
        c.mcp_burst = b;
        let lim = RateLimiter::new(clk.clone(), c);
        for i in 0..10 {
            assert!(
                lim.check(BucketClass::McpAccount, "k").is_err(),
                "rate={r} burst={b} req {i} must be denied"
            );
        }
    }
}
