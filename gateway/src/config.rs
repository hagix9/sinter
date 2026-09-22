//! P7 — configuration contract (RFC §M).
//!
//! Env vars applied at process start; changing a value requires a restart —
//! that IS the rollback lever (RFC §O: configuration revert + restart, no
//! code rollback, no dynamic control plane).
//!
//! Every value fails closed: a malformed or out-of-range setting refuses to
//! build a config rather than silently weakening protection. Only the
//! documented clamps/defaults apply when a variable is absent.
//!
//! `SINTER_GW_TRUSTED_PROXY` must stay empty in v1 — there is no trusted
//! proxy mode, so a non-empty value is a startup error, not a silent ignore.

use std::net::SocketAddr;
use std::time::Duration;

use crate::proto::{ErrorCode, TransportError};
use crate::rate_limit::RateLimits;

fn cfg_err(msg: impl Into<String>) -> TransportError {
    TransportError::new(ErrorCode::MalformedCredential, msg.into())
}

/// Full P7 runtime configuration (RFC §M table).
#[derive(Debug, Clone)]
pub struct GwConfig {
    pub rate: RateLimits,
    /// `SINTER_GW_METRICS_ENABLED` — optional `/metrics` admin endpoint.
    pub metrics_enabled: bool,
    /// `SINTER_GW_METRICS_BIND` — loopback only (unauthenticated endpoint).
    pub metrics_bind: SocketAddr,
    /// `SINTER_GW_CLEANUP_INTERVAL_SECS` — identity GC period.
    pub cleanup_interval: Duration,
}

impl Default for GwConfig {
    fn default() -> Self {
        Self {
            rate: RateLimits::default(),
            metrics_enabled: false,
            metrics_bind: "127.0.0.1:9091".parse().unwrap(),
            cleanup_interval: Duration::from_secs(3600),
        }
    }
}

/// Read one variable through the injected getter. `Err` = malformed config.
fn var<F: Fn(&str) -> Option<String>>(
    get: &F,
    name: &str,
) -> Result<Option<String>, TransportError> {
    match get(name) {
        Some(v) if v.is_empty() => Ok(None),
        Some(v) => Ok(Some(v)),
        None => Ok(None),
    }
}

fn parse_f64<F>(
    get: &F,
    name: &str,
    min: f64,
    max: f64,
    dst: &mut f64,
) -> Result<(), TransportError>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(raw) = var(get, name)? {
        let v: f64 = raw
            .parse()
            .map_err(|_| cfg_err(format!("{name}: malformed number {raw:?}")))?;
        if !v.is_finite() || v < min || v > max {
            return Err(cfg_err(format!(
                "{name}: {raw:?} out of range [{min}, {max}]"
            )));
        }
        *dst = v;
    }
    Ok(())
}

fn parse_u64<F>(
    get: &F,
    name: &str,
    min: u64,
    max: u64,
    dst: &mut u64,
) -> Result<(), TransportError>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(raw) = var(get, name)? {
        let v: u64 = raw
            .parse()
            .map_err(|_| cfg_err(format!("{name}: malformed integer {raw:?}")))?;
        if v < min || v > max {
            return Err(cfg_err(format!(
                "{name}: {raw:?} out of range [{min}, {max}]"
            )));
        }
        *dst = v;
    }
    Ok(())
}

fn parse_bool<F>(get: &F, name: &str, dst: &mut bool) -> Result<(), TransportError>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(raw) = var(get, name)? {
        *dst = match raw.as_str() {
            "true" => true,
            "false" => false,
            _ => {
                return Err(cfg_err(format!(
                    "{name}: expected 'true' or 'false', got {raw:?}"
                )))
            }
        };
    }
    Ok(())
}

impl GwConfig {
    /// Load from process environment — fail closed on any invalid value.
    pub fn from_env() -> Result<Self, TransportError> {
        Self::from_vars(|k| std::env::var(k).ok())
    }

    /// Load through an injected getter — deterministic config tests.
    /// Any malformed/out-of-range value is an error (refuse start).
    pub fn from_vars<F>(get: F) -> Result<Self, TransportError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut cfg = GwConfig::default();
        let r = &mut cfg.rate;

        parse_bool(&get, "SINTER_GW_RATE_ENABLED", &mut r.enabled)?;
        parse_f64(&get, "SINTER_GW_RATE_MCP_RPS", 1.0, 1000.0, &mut r.mcp_rps)?;
        {
            let mut burst = u64::from(r.mcp_burst);
            parse_u64(&get, "SINTER_GW_RATE_MCP_BURST", 1, 10_000, &mut burst)?;
            r.mcp_burst = burst as u32;
        }
        parse_f64(
            &get,
            "SINTER_GW_RATE_MCP_GLOBAL_RPS",
            1.0,
            10_000.0,
            &mut r.mcp_global_rps,
        )?;
        parse_f64(&get, "SINTER_GW_RATE_POLL_RPS", 0.1, 100.0, &mut r.poll_rps)?;
        parse_f64(
            &get,
            "SINTER_GW_RATE_RESPOND_RPS",
            1.0,
            1000.0,
            &mut r.respond_rps,
        )?;
        parse_f64(
            &get,
            "SINTER_GW_RATE_REGISTER_PER_MIN",
            0.1,
            100.0,
            &mut r.register_per_min,
        )?;
        parse_f64(
            &get,
            "SINTER_GW_RATE_ROTATE_PER_MIN",
            0.1,
            100.0,
            &mut r.rotate_per_min,
        )?;
        parse_f64(
            &get,
            "SINTER_GW_RATE_AUTHFAIL_PER_MIN",
            1.0,
            10_000.0,
            &mut r.authfail_per_min,
        )?;

        parse_bool(&get, "SINTER_GW_METRICS_ENABLED", &mut cfg.metrics_enabled)?;
        if let Some(raw) = var(&get, "SINTER_GW_METRICS_BIND")? {
            let addr: SocketAddr = raw.parse().map_err(|_| {
                cfg_err(format!("SINTER_GW_METRICS_BIND: malformed address {raw:?}"))
            })?;
            // Unauthenticated endpoint: loopback only (RFC §L exposure model).
            if !addr.ip().is_loopback() {
                return Err(cfg_err(format!(
                    "SINTER_GW_METRICS_BIND: {raw:?} is not loopback"
                )));
            }
            cfg.metrics_bind = addr;
        }

        {
            let mut secs = cfg.cleanup_interval.as_secs();
            parse_u64(
                &get,
                "SINTER_GW_CLEANUP_INTERVAL_SECS",
                60,
                86_400,
                &mut secs,
            )?;
            cfg.cleanup_interval = Duration::from_secs(secs);
        }

        // RFC §M: v1 has no trusted proxy — a non-empty value means the
        // operator believes forwarded headers are honored. They are not;
        // refusing to start beats silently ignoring the stated intent.
        if let Some(raw) = var(&get, "SINTER_GW_TRUSTED_PROXY")? {
            return Err(cfg_err(format!(
                "SINTER_GW_TRUSTED_PROXY: {raw:?} unsupported in v1 (no trusted proxy mode)"
            )));
        }

        Ok(cfg)
    }
}
