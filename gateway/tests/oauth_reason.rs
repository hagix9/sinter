//! Internal validation-failure classification. Every invalid-credential
//! class must still surface publicly as `PublicAuthError::Invalid`
//! (401 invalid_credential); a missing account binding must stay
//! `PublicAuthError::Unbound` (403 account_unbound).

use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderValue};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sinter_gateway::mcp::PublicAuthError;
use sinter_gateway::oauth::{
    InvalidReason, JwksSource, OAuthConfig, OAuthValidator, TokenRejection,
};
use sinter_gateway::PublicAuth;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const ISS: &str = "https://as.example.com";
const AUD: &str = "https://gw.example.com";
const KID: &str = "k1";

struct StaticJwks(Vec<u8>);
impl JwksSource for StaticJwks {
    fn fetch(&self, _uri: &str) -> Result<Vec<u8>, String> {
        Ok(self.0.clone())
    }
}
struct FailingJwks;
impl JwksSource for FailingJwks {
    fn fetch(&self, _uri: &str) -> Result<Vec<u8>, String> {
        Err("down".into())
    }
}

fn keys() -> &'static (String, String, Value) {
    static K: OnceLock<(String, String, Value)> = OnceLock::new();
    K.get_or_init(|| {
        let gen = || RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let (good, other) = (gen(), gen());
        let pem = |k: &RsaPrivateKey| k.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let pubk = RsaPublicKey::from(&good);
        let jwk = json!({"keys": [{
            "kty": "RSA", "use": "sig", "kid": KID,
            "n": URL_SAFE_NO_PAD.encode(pubk.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(pubk.e().to_bytes_be()),
        }]});
        (pem(&good), pem(&other), jwk)
    })
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn validator_with(src: Box<dyn JwksSource>) -> OAuthValidator {
    let cfg = OAuthConfig::new(ISS, AUD, AUD, "https://as.example.com/jwks");
    OAuthValidator::new(cfg, src).unwrap()
}
fn validator() -> OAuthValidator {
    validator_with(Box::new(StaticJwks(keys().2.to_string().into_bytes())))
}

fn claims() -> Value {
    json!({"iss": ISS, "aud": AUD, "sub": "user-1", "sinter_account": "acct-1",
           "exp": now() + 600, "iat": now()})
}
fn mint_pem(c: &Value, kid: Option<&str>, pem: &str) -> String {
    let mut h = Header::new(Algorithm::RS256);
    h.kid = kid.map(str::to_string);
    encode(&h, c, &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap()).unwrap()
}
fn mint(c: &Value) -> String {
    mint_pem(c, Some(KID), &keys().0)
}
fn unsigned(header: Value, c: &Value) -> String {
    let e = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
    format!("{}.{}.c2ln", e(&header), e(c))
}
fn with(f: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Value {
    let mut c = claims();
    f(c.as_object_mut().unwrap());
    c
}

fn public(v: &OAuthValidator, token: &str) -> Result<(), PublicAuthError> {
    let mut h = HeaderMap::new();
    h.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    v.authenticate(&h).map(|_| ())
}

/// Assert both the internal class and the unchanged public mapping.
fn expect_invalid(token: &str, reason: InvalidReason) {
    let v = validator();
    assert_eq!(
        v.evaluate_token(token).err(),
        Some(TokenRejection::Invalid(reason))
    );
    assert_eq!(public(&v, token).err(), Some(PublicAuthError::Invalid));
}

#[test]
fn malformed_token() {
    expect_invalid("not-a-jwt", InvalidReason::MalformedToken);
    // Parsable header, garbage payload segment.
    let h = URL_SAFE_NO_PAD.encode(json!({"alg":"RS256","kid":KID}).to_string());
    let tok = format!("{h}.%%%.{}", mint(&claims()).rsplit('.').next().unwrap());
    let r = validator().evaluate_token(&tok).err();
    assert!(matches!(
        r,
        Some(TokenRejection::Invalid(
            InvalidReason::MalformedToken | InvalidReason::SignatureInvalid
        ))
    ));
}

#[test]
fn unsupported_alg() {
    for alg in ["ES384", "HS256", "PS256"] {
        expect_invalid(
            &unsigned(json!({"alg": alg, "kid": KID}), &claims()),
            InvalidReason::UnsupportedAlg,
        );
    }
    // alg=none is not a jsonwebtoken Algorithm → header unparsable.
    expect_invalid(
        &unsigned(json!({"alg": "none", "kid": KID}), &claims()),
        InvalidReason::MalformedToken,
    );
}

#[test]
fn kid_classes() {
    expect_invalid(
        &mint_pem(&claims(), None, &keys().0),
        InvalidReason::KidInvalid,
    );
    expect_invalid(
        &mint_pem(&claims(), Some("nope"), &keys().0),
        InvalidReason::UnknownKid,
    );
    expect_invalid(
        &unsigned(json!({"alg": "ES256", "kid": KID}), &claims()),
        InvalidReason::KeyAlgMismatch,
    );
}

#[test]
fn signature_invalid() {
    expect_invalid(
        &mint_pem(&claims(), Some(KID), &keys().1),
        InvalidReason::SignatureInvalid,
    );
}

#[test]
fn jwks_unavailable() {
    let v = validator_with(Box::new(FailingJwks));
    let t = mint(&claims());
    assert_eq!(
        v.evaluate_token(&t).err(),
        Some(TokenRejection::Invalid(InvalidReason::JwksUnavailable))
    );
    assert_eq!(public(&v, &t).err(), Some(PublicAuthError::Invalid));
}

#[test]
fn claim_classes() {
    expect_invalid(
        &mint(&with(|c| {
            c.insert("iss".into(), json!("https://evil.example.com"));
        })),
        InvalidReason::IssuerMismatch,
    );
    expect_invalid(
        &mint(&with(|c| {
            c.insert("aud".into(), json!("https://other.example.com"));
        })),
        InvalidReason::AudienceMismatch,
    );
    expect_invalid(
        &mint(&with(|c| {
            c.insert("exp".into(), json!(now() - 3600));
        })),
        InvalidReason::Expired,
    );
    expect_invalid(
        &mint(&with(|c| {
            c.insert("nbf".into(), json!(now() + 3600));
        })),
        InvalidReason::NotYetValid,
    );
    for claim in ["exp", "aud", "iss", "sub"] {
        expect_invalid(
            &mint(&with(|c| {
                c.remove(claim);
            })),
            InvalidReason::MissingRequiredClaim,
        );
    }
    expect_invalid(
        &mint(&with(|c| {
            c.insert("iat".into(), json!(now() + 3600));
        })),
        InvalidReason::IatInvalid,
    );
    expect_invalid(
        &mint(&with(|c| {
            c.insert("iat".into(), json!("yesterday"));
        })),
        InvalidReason::IatInvalid,
    );
    expect_invalid(
        &mint(&with(|c| {
            c.insert("sub".into(), json!(""));
        })),
        InvalidReason::SubInvalid,
    );
}

#[test]
fn missing_account_stays_unbound() {
    let v = validator();
    for tok in [
        mint(&with(|c| {
            c.remove("sinter_account");
        })),
        mint(&with(|c| {
            c.insert("sinter_account".into(), json!(""));
        })),
    ] {
        assert_eq!(v.evaluate_token(&tok).err(), Some(TokenRejection::Unbound));
        assert_eq!(public(&v, &tok).err(), Some(PublicAuthError::Unbound));
    }
}

#[test]
fn valid_token_accepted() {
    let v = validator();
    let t = mint(&claims());
    assert!(v.evaluate_token(&t).is_ok());
    assert!(public(&v, &t).is_ok());
}

#[test]
fn reason_strings_are_fixed_snake_case() {
    use InvalidReason::*;
    for r in [
        MalformedToken,
        UnsupportedAlg,
        KidInvalid,
        JwksUnavailable,
        UnknownKid,
        KeyAlgMismatch,
        SignatureInvalid,
        IssuerMismatch,
        AudienceMismatch,
        Expired,
        NotYetValid,
        MissingRequiredClaim,
        IatInvalid,
        SubInvalid,
        OtherValidationFailure,
    ] {
        assert!(r
            .as_str()
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}
