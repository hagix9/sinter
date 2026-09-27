//! The invalid-credential diagnostic log line carries only a fixed
//! `reason_class` — never the token, its segments, or any claim value.
//! Isolated binary (tracing callsite interest is process-global).

use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;
use sinter_gateway::oauth::{JwksSource, OAuthConfig, OAuthValidator};
use sinter_gateway::PublicAuth;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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

struct StaticJwks(Vec<u8>);
impl JwksSource for StaticJwks {
    fn fetch(&self, _uri: &str) -> Result<Vec<u8>, String> {
        Ok(self.0.clone())
    }
}

#[test]
fn invalid_credential_log_has_reason_class_and_no_secrets() {
    const ISS: &str = "https://as.example.com";
    const AUD: &str = "https://gw.example.com";
    let key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
    let pubk = RsaPublicKey::from(&key);
    let jwks = json!({"keys": [{"kty": "RSA", "kid": "k1",
        "n": URL_SAFE_NO_PAD.encode(pubk.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(pubk.e().to_bytes_be())}]});
    let cfg = OAuthConfig::new(ISS, AUD, AUD, "https://as.example.com/jwks");
    let v = OAuthValidator::new(cfg, Box::new(StaticJwks(jwks.to_string().into_bytes()))).unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let sub = "SUBJECT-MARKER-5f1c";
    let acct = "ACCOUNT-MARKER-9a2e";
    let email = "EMAIL-MARKER@example.com";
    let claims = json!({"iss": ISS, "aud": "https://wrong-aud.example.com", "sub": sub,
        "sinter_account": acct, "email": email, "exp": now + 600});
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some("k1".into());
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let token = encode(
        &h,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap();

    let buf = Arc::new(Mutex::new(Vec::new()));
    let sub_ = tracing_subscriber::fmt()
        .with_writer(Capture(buf.clone()))
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::with_default(sub_, || {
        let mut hm = HeaderMap::new();
        hm.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        assert!(v.authenticate(&hm).is_err());
    });
    let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();

    assert!(out.contains("reason_class=\"audience_mismatch\""), "{out}");
    assert!(out.contains("code=\"invalid_credential\""), "{out}");
    for seg in token.split('.') {
        assert!(!out.contains(seg), "token segment leaked");
    }
    for marker in [sub, acct, email, "wrong-aud", "k1\"", "RS256"] {
        assert!(!out.contains(marker), "leaked {marker}");
    }
}
