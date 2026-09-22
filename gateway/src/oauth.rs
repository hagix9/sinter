//! P6 — production public authentication.
//!
//! The Gateway is an OAuth **resource server** (accepted RFC §17: "AS
//! integration + RS validation"). A managed OAuth 2.1 authorization server,
//! chosen at deployment (Q-1), issues JWT access tokens for this resource.
//! The Gateway:
//!
//!   * validates `iss`/`aud`/`exp`/`nbf`/`iat` + signature via the AS JWKS,
//!   * maps claims to `PublicPrincipal` (stable `sub` + configured account
//!     claim — never caller-supplied routing fields),
//!   * serves RFC 9728 protected-resource metadata,
//!   * emits RFC 6750 `WWW-Authenticate` challenges.
//!
//! It never hosts authorization-server functions: no authorization codes,
//! no PKCE verification, no client registration (CIMD/DCR belong to the AS),
//! no token issuance, no refresh handling.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::{header::AUTHORIZATION, HeaderMap};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::{json, Value};

use crate::id::AccountId;
use crate::mcp::{PublicAuth, PublicAuthError, PublicPrincipal};
use crate::proto::{ErrorCode, TransportError};

// ---------- bounds (RFC §34/§36) ----------

/// Maximum Authorization header size accepted for parsing.
pub const MAX_AUTHZ_HEADER: usize = 8 * 1024;
/// Maximum JWT `kid` length.
pub const MAX_KID_LEN: usize = 128;
/// Maximum JWKS document body.
pub const MAX_JWKS_BYTES: usize = 256 * 1024;
/// Maximum keys per JWKS document.
pub const MAX_JWKS_KEYS: usize = 64;
/// Default JWKS cache lifetime before a forced refresh attempt.
pub const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(3600);
/// Minimum spacing between refresh attempts triggered by unknown `kid`
/// (bounds outbound-request amplification by forged tokens).
pub const DEFAULT_JWKS_MIN_REFRESH: Duration = Duration::from_secs(60);
/// Clock-skew allowance for exp/nbf/iat comparisons.
const LEEWAY_SECS: u64 = 60;
/// Only these signature algorithms are accepted; `none` and HS* are not.
const ALLOWED_ALGS: [Algorithm; 2] = [Algorithm::RS256, Algorithm::ES256];

/// Allowed signature algorithms as wire strings (for tests/reporting).
pub const ALLOWED_ALG_NAMES: [&str; 2] = ["RS256", "ES256"];

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------- configuration ----------

/// Production OAuth resource-server configuration. All URLs are validated
/// at startup; a bad value prevents `with_oauth` from succeeding rather
/// than silently weakening authentication.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Trusted issuer — must exactly equal token `iss`.
    pub issuer: String,
    /// Expected `aud` — the RFC 8707 resource indicator for this Gateway.
    pub audience: String,
    /// Public Gateway URL advertised as the RFC 9728 `resource` and used as
    /// the `realm` in challenges. External, not internal.
    pub resource_url: String,
    /// JWKS document URI, pinned by configuration — never taken from the
    /// token (`jku`/`x5u` are ignored entirely).
    pub jwks_uri: String,
    /// Claim carrying the stable account binding (default `sinter_account`).
    pub account_claim: String,
    /// Forced JWKS refresh interval.
    pub jwks_ttl: Duration,
    /// Minimum spacing between unknown-`kid` refresh attempts.
    pub jwks_min_refresh: Duration,
}

impl OAuthConfig {
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        resource_url: impl Into<String>,
        jwks_uri: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            resource_url: resource_url.into(),
            jwks_uri: jwks_uri.into(),
            account_claim: "sinter_account".to_string(),
            jwks_ttl: DEFAULT_JWKS_TTL,
            jwks_min_refresh: DEFAULT_JWKS_MIN_REFRESH,
        }
    }

    /// Fail-closed startup validation of security-critical configuration.
    pub fn validate(&self) -> Result<(), TransportError> {
        let bad_cfg = |m: &str| TransportError::new(ErrorCode::MalformedCredential, m);
        if self.issuer.is_empty() || self.issuer.len() > 512 || !trusted_uri(&self.issuer) {
            return Err(bad_cfg("oauth issuer must be a trusted https URL"));
        }
        if self.audience.is_empty() || self.audience.len() > 512 {
            return Err(bad_cfg("oauth audience must be a non-empty value"));
        }
        if self.resource_url.is_empty()
            || self.resource_url.len() > 512
            || !trusted_uri(&self.resource_url)
        {
            return Err(bad_cfg("oauth resource_url must be a trusted https URL"));
        }
        if !trusted_uri(&self.jwks_uri) {
            return Err(bad_cfg("oauth jwks_uri must be a trusted https URL"));
        }
        if self.account_claim.is_empty() || self.account_claim.len() > 64 {
            return Err(bad_cfg(
                "oauth account_claim must be a non-empty claim name",
            ));
        }
        if self.jwks_ttl.is_zero() || self.jwks_min_refresh.is_zero() {
            return Err(bad_cfg("oauth jwks refresh intervals must be non-zero"));
        }
        Ok(())
    }
}

/// URL trust boundary for issuer/resource/JWKS endpoints: HTTPS anywhere,
/// or plain HTTP only to loopback IP literals (local test/dev AS). Host
/// *names* are never accepted over HTTP — DNS results are not pinned at
/// validation time. No userinfo, no embedded query, no non-http(s) scheme;
/// this is not a generic fetch surface (RFC §14).
pub fn trusted_uri(raw: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(raw) else {
        return false;
    };
    if !u.username().is_empty() || u.password().is_some() || u.query().is_some() {
        return false;
    }
    match u.scheme() {
        "https" => u.has_host(),
        "http" => match u.host() {
            Some(url::Host::Ipv4(a)) => a.is_loopback(),
            Some(url::Host::Ipv6(a)) => a.is_loopback(),
            _ => false,
        },
        _ => false,
    }
}

// ---------- JWKS source ----------

/// Fetcher abstraction so tests can substitute deterministic sources; the
/// production path uses `HttpJwksSource`.
pub trait JwksSource: Send + Sync {
    /// Return the JWKS document bytes for `uri` (already validated by
    /// `OAuthConfig`). Errors are treated as authentication-unavailable,
    /// never as authentication-bypass.
    fn fetch(&self, uri: &str) -> Result<Vec<u8>, String>;
}

/// Production JWKS fetcher: one narrowly configured client — HTTPS only
/// (loopback HTTP permitted for dev/test AS), no redirects, bounded
/// connect/total timeouts, bounded body, no cookies, no proxy credentials.
///
/// The reqwest blocking client is built lazily on first `fetch`: its
/// constructor internally waits on a temporary runtime, which is only
/// legal on a blocking executor slot — exactly where `fetch` runs.
pub struct HttpJwksSource {
    client: Mutex<Option<reqwest::blocking::Client>>,
}

impl HttpJwksSource {
    pub fn new() -> Result<Self, TransportError> {
        Ok(Self {
            client: Mutex::new(None),
        })
    }

    fn client(&self) -> Result<reqwest::blocking::Client, String> {
        let mut guard = self.client.lock().unwrap();
        if guard.is_none() {
            let c = reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(5))
                .build()
                .map_err(|e| e.to_string())?;
            *guard = Some(c);
        }
        Ok(guard.as_ref().unwrap().clone())
    }
}

impl Drop for HttpJwksSource {
    fn drop(&mut self) {
        // The blocking client owns an internal runtime thread; keep its
        // teardown off any async worker.
        if let Some(c) = self.client.get_mut().unwrap().take() {
            std::thread::spawn(move || drop(c));
        }
    }
}

impl JwksSource for HttpJwksSource {
    fn fetch(&self, uri: &str) -> Result<Vec<u8>, String> {
        if !trusted_uri(uri) {
            return Err("jwks uri rejected by trust policy".into());
        }
        let resp = self.client()?.get(uri).send().map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("jwks http status {}", resp.status().as_u16()));
        }
        // Stream with a hard cap rather than buffering an unbounded body.
        let mut buf = Vec::new();
        resp.take(MAX_JWKS_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        if buf.len() > MAX_JWKS_BYTES {
            return Err("jwks document too large".into());
        }
        Ok(buf)
    }
}

// ---------- JWKS parsing ----------

/// `Option<JwkKey>` per `kid`: `None` marks an ambiguous or unusable key —
/// tokens referencing it are rejected, never resolved arbitrarily.
type KeyMap = HashMap<String, Option<JwkKey>>;

struct JwkKey {
    alg: Algorithm,
    key: DecodingKey,
}

fn alg_allowed(name: &str) -> bool {
    ALLOWED_ALG_NAMES.contains(&name)
}

/// Convert one JWK to a `JwkKey`, or None when unusable for this RS.
fn jwk_to_key(jwk: &Value) -> Option<JwkKey> {
    if let Some(u) = jwk.get("use").and_then(Value::as_str) {
        if u != "sig" {
            return None;
        }
    }
    let kty = jwk.get("kty")?.as_str()?;
    if let Some(a) = jwk.get("alg").and_then(Value::as_str) {
        if !alg_allowed(a) {
            return None; // keys pinned to disallowed algorithms are dropped
        }
    }
    match kty {
        "RSA" => Some(JwkKey {
            alg: Algorithm::RS256,
            key: DecodingKey::from_rsa_components(jwk.get("n")?.as_str()?, jwk.get("e")?.as_str()?)
                .ok()?,
        }),
        "EC" if jwk.get("crv").and_then(Value::as_str) == Some("P-256") => Some(JwkKey {
            alg: Algorithm::ES256,
            key: DecodingKey::from_ec_components(jwk.get("x")?.as_str()?, jwk.get("y")?.as_str()?)
                .ok()?,
        }),
        _ => None,
    }
}

fn parse_jwks(body: &[u8]) -> Result<KeyMap, String> {
    let doc: Value = serde_json::from_slice(body).map_err(|_| "jwks not json".to_string())?;
    let keys = doc
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| "jwks missing keys array".to_string())?;
    if keys.len() > MAX_JWKS_KEYS {
        return Err("jwks too many keys".into());
    }
    let mut map = KeyMap::new();
    let mut seen = HashSet::new();
    for jwk in keys {
        let Some(kid) = jwk.get("kid").and_then(Value::as_str) else {
            continue; // kid-less keys can never be selected (tokens require kid)
        };
        if kid.is_empty() || kid.len() > MAX_KID_LEN || !seen.insert(kid.to_string()) {
            // A second entry under the same kid makes the kid ambiguous.
            map.insert(kid.to_string(), None);
            continue;
        }
        map.insert(kid.to_string(), jwk_to_key(jwk));
    }
    Ok(map)
}

// ---------- validator ----------

struct JwksState {
    keys: KeyMap,
    /// Last fetch *attempt* — throttles unknown-kid retries and stale
    /// refreshes independently of success.
    last_attempt: Option<Instant>,
    /// Set when the last fetch attempt succeeded.
    keys_fresh: bool,
}

/// Production `PublicAuth`: strict Bearer extraction + JWT validation +
/// bounded JWKS caching. Performs blocking network IO on cache miss —
/// callers must run it on a blocking executor slot.
pub struct OAuthValidator {
    cfg: OAuthConfig,
    source: Box<dyn JwksSource>,
    jwks: Mutex<JwksState>,
}

impl OAuthValidator {
    pub fn new(cfg: OAuthConfig, source: Box<dyn JwksSource>) -> Result<Self, TransportError> {
        cfg.validate()?;
        Ok(Self {
            cfg,
            source,
            jwks: Mutex::new(JwksState {
                keys: KeyMap::new(),
                last_attempt: None,
                keys_fresh: false,
            }),
        })
    }

    /// RFC 9728 protected-resource metadata — exact document served at
    /// `/.well-known/oauth-protected-resource`. Internal hostnames,
    /// controller state and store topology never appear.
    pub fn protected_resource_metadata(&self) -> Value {
        json!({
            "resource": self.cfg.resource_url,
            "authorization_servers": [self.cfg.issuer],
            "bearer_methods_supported": ["header"],
        })
    }

    /// Attempt one fetch+parse; updates `last_attempt` either way (attempt
    /// spacing is what bounds amplification, not success).
    fn refresh_locked(&self, st: &mut JwksState) -> bool {
        st.last_attempt = Some(Instant::now());
        match self
            .source
            .fetch(&self.cfg.jwks_uri)
            .and_then(|body| parse_jwks(&body))
        {
            Ok(keys) => {
                st.keys = keys;
                st.keys_fresh = true;
                true
            }
            Err(e) => {
                tracing::warn!(reason = %e, "jwks refresh failed");
                false
            }
        }
    }

    fn decode_token(&self, token: &str) -> Result<PublicPrincipal, PublicAuthError> {
        let header = decode_header(token).map_err(|_| PublicAuthError::Invalid)?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(PublicAuthError::Invalid);
        }
        let kid = header.kid.as_deref().unwrap_or("");
        if kid.is_empty() || kid.len() > MAX_KID_LEN {
            return Err(PublicAuthError::Invalid);
        }

        let mut st = self.jwks.lock().unwrap();
        let stale = st
            .last_attempt
            .map(|t| t.elapsed() >= self.cfg.jwks_ttl)
            .unwrap_or(true);
        let unknown_kid_retry = !st.keys.contains_key(kid)
            && st
                .last_attempt
                .map(|t| t.elapsed() >= self.cfg.jwks_min_refresh)
                .unwrap_or(true);
        if stale || unknown_kid_retry {
            let ok = self.refresh_locked(&mut st);
            if stale && !ok {
                // Forced-refresh window with a failed fetch: fail closed
                // rather than authenticate on expired trust.
                return Err(PublicAuthError::Invalid);
            }
        }
        let Some(Some(jwk)) = st.keys.get(kid) else {
            return Err(PublicAuthError::Invalid);
        };
        if jwk.alg != header.alg {
            return Err(PublicAuthError::Invalid); // key/alg family mismatch
        }

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.cfg.issuer.as_str()]);
        validation.set_audience(&[self.cfg.audience.as_str()]);
        validation.required_spec_claims = ["exp", "iss", "aud", "sub"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = LEEWAY_SECS;
        let data =
            decode::<Value>(token, &jwk.key, &validation).map_err(|_| PublicAuthError::Invalid)?;
        let claims = data.claims;

        // iat is optional but, when present, must be a NumericDate — a
        // non-negative integer — that is not in the future. A present but
        // malformed iat (string, negative, float, null, object, array) must
        // fail closed, not silently degrade to "absent" (F-11).
        if let Some(v) = claims.get("iat") {
            let Some(iat) = v.as_u64() else {
                return Err(PublicAuthError::Invalid);
            };
            if iat > now_secs() + LEEWAY_SECS {
                return Err(PublicAuthError::Invalid);
            }
        }
        let sub = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(PublicAuthError::Invalid)?;
        let account = claims
            .get(&self.cfg.account_claim)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(PublicAuthError::Unbound)?;
        let name = claims.get("name").and_then(Value::as_str);
        let email = claims.get("email").and_then(Value::as_str);
        Ok(PublicPrincipal::new(
            AccountId::new(account),
            sub.to_string(),
            name.map(str::to_string),
            email.map(str::to_string),
        ))
    }
}

impl PublicAuth for OAuthValidator {
    fn authenticate(&self, headers: &HeaderMap) -> Result<PublicPrincipal, PublicAuthError> {
        // Exactly one Authorization header; duplicates are ambiguous.
        let count = headers.get_all(AUTHORIZATION).iter().count();
        if count == 0 {
            return Err(PublicAuthError::Missing);
        }
        if count > 1 {
            return Err(PublicAuthError::Malformed);
        }
        let raw = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(PublicAuthError::Malformed)?;
        if raw.len() > MAX_AUTHZ_HEADER {
            return Err(PublicAuthError::Malformed);
        }
        let (scheme, token) = raw.split_once(' ').ok_or(PublicAuthError::Malformed)?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(PublicAuthError::Malformed);
        }
        // No trimming/normalizing: the token must be exactly one non-empty
        // segment. Whitespace ambiguity is malformed, never normalized.
        if token.is_empty() || token != token.trim() || token.contains(' ') {
            return Err(PublicAuthError::Malformed);
        }
        self.decode_token(token)
    }

    fn www_authenticate(&self, err: &PublicAuthError) -> Option<String> {
        let prm = format!(
            "{}/.well-known/oauth-protected-resource",
            self.cfg.resource_url.trim_end_matches('/')
        );
        let base = format!(
            "Bearer realm=\"{}\", resource_metadata=\"{prm}\"",
            self.cfg.resource_url
        );
        Some(match err {
            PublicAuthError::Missing => base,
            PublicAuthError::Malformed => format!("{base}, error=\"invalid_request\""),
            PublicAuthError::Invalid => format!("{base}, error=\"invalid_token\""),
            PublicAuthError::Unbound => format!("{base}, error=\"insufficient_scope\""),
        })
    }
}
