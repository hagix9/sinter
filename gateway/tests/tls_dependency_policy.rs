//! TLS dependency regression guards for the v1.7.0 advisory remediation.
//!
//! RUSTSEC-2026-0381 and RUSTSEC-2026-0382 are one CVE (CVE-2026-111943).
//! The bundled Mozilla root set still contained `emSign ECC Root CA - G3`,
//! which could anchor certificate paths through emSign intermediates whose
//! private keys are publicly known. `webpki-roots` 1.0.10 removes that root
//! and `rustls-webpki` 0.103.16 rejects the distrusted intermediate SPKIs;
//! the gateway reaches both crates through `reqwest`'s `rustls-tls` feature
//! (`rustls-tls` = `rustls-tls-webpki-roots`).
//!
//! These tests fail if either fixed version is downgraded, if the removed
//! root comes back, or if a production TLS client starts disabling
//! certificate or hostname verification. They do not replace the upstream
//! verifier tests; they guard the inputs Sinter pins and the code it ships.

use webpki_roots::TLS_SERVER_ROOTS;

/// Common name of the root removed by webpki-roots 1.0.10.
const DISTRUSTED_ROOT_CN: &str = "emSign ECC Root CA - G3";

#[test]
fn bundled_trust_store_excludes_the_distrusted_emsign_root() {
    assert!(
        !TLS_SERVER_ROOTS.is_empty(),
        "the bundled trust store must not be empty"
    );
    let needle = DISTRUSTED_ROOT_CN.as_bytes();
    let present: Vec<String> = TLS_SERVER_ROOTS
        .iter()
        .filter(|anchor| {
            let subject: &[u8] = anchor.subject.as_ref();
            subject.windows(needle.len()).any(|w| w == needle)
        })
        .map(|anchor| String::from_utf8_lossy(anchor.subject.as_ref()).into_owned())
        .collect();
    assert!(
        present.is_empty(),
        "distrusted root {DISTRUSTED_ROOT_CN} is back in the bundled trust store: {present:?}"
    );
}

#[test]
fn gateway_lockfile_pins_the_fixed_tls_versions() {
    // RUSTSEC-2026-0382: rustls-webpki must be at least 0.103.16 (or the
    // 0.104 line from 0.104.0-alpha.8, which this workspace does not use).
    let webpki = lockfile_version("rustls-webpki");
    assert!(
        !affected_0104_alpha(&webpki) && version_at_least(&webpki, (0, 103, 16)),
        "rustls-webpki {webpki} is below the fixed 0.103.16, or is an affected 0.104.0 alpha"
    );
    // RUSTSEC-2026-0381: webpki-roots must be at least 1.0.10.
    let roots = lockfile_version("webpki-roots");
    assert!(
        version_at_least(&roots, (1, 0, 10)),
        "webpki-roots {roots} is below the fixed 1.0.10"
    );
}

#[test]
fn production_tls_clients_keep_default_verification() {
    // The gateway's outbound HTTPS clients (bridge -> gateway, OAuth JWKS
    // fetch) must keep the default rustls verification. Any of these tokens
    // would turn certificate or hostname checking off, or pin a different
    // root set, and must be a reviewed change, never a quiet edit.
    const FORBIDDEN: &[&str] = &[
        "danger_accept_invalid_certs",
        "danger_accept_invalid_hostnames",
        ".dangerous()",
        "tls_built_in_root_certs(false)",
        "add_root_certificate",
    ];
    for (name, src) in [
        ("src/bridge.rs", include_str!("../src/bridge.rs")),
        ("src/oauth.rs", include_str!("../src/oauth.rs")),
    ] {
        for token in FORBIDDEN {
            assert!(
                !src.contains(token),
                "{name} contains {token}: production TLS verification was weakened"
            );
        }
    }
}

#[test]
fn version_floor_rejects_the_affected_0104_alphas() {
    // RUSTSEC-2026-0382 fixes 0.104.0-alpha.8; 0.104.0-alpha.1 through
    // -alpha.7 are affected. A plain `>= 0.103.16` floor would accept them
    // because 0.104.0 sorts above 0.103.16, so the floor is paired with the
    // explicit alpha check.
    for affected in ["0.104.0-alpha.1", "0.104.0-alpha.7"] {
        assert!(affected_0104_alpha(affected), "{affected} must be rejected");
        assert!(
            !(!affected_0104_alpha(affected) && version_at_least(affected, (0, 103, 16))),
            "{affected} must not pass the fixed-version floor"
        );
    }
    assert!(!affected_0104_alpha("0.104.0-alpha.8"));
    assert!(version_at_least("0.104.0-alpha.8", (0, 103, 16)));
    assert!(version_at_least("0.103.16", (0, 103, 16)));
    assert!(!version_at_least("0.103.15", (0, 103, 16)));
}

/// True for the 0.104.0 alphas the advisory marks as affected (alpha.1 to
/// alpha.7). Malformed suffixes fail closed.
fn affected_0104_alpha(version: &str) -> bool {
    match version.strip_prefix("0.104.0-alpha.") {
        Some(n) => n.parse::<u64>().map(|n| n < 8).unwrap_or(true),
        None => false,
    }
}

/// Reads the version of `name` from the gateway lockfile this test is built
/// with (`gateway/Cargo.lock`).
fn lockfile_version(name: &str) -> String {
    let lock = include_str!("../Cargo.lock");
    let mut lines = lock.lines();
    let header = format!("name = \"{name}\"");
    while let Some(line) = lines.next() {
        if line == header {
            let version = lines
                .next()
                .unwrap_or_else(|| panic!("no version line after {name}"));
            return version
                .strip_prefix("version = \"")
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or_else(|| panic!("malformed version line for {name}: {version}"))
                .to_string();
        }
    }
    panic!("{name} not found in gateway/Cargo.lock");
}

/// Minimal `major.minor.patch` comparison. A pre-release of the same core
/// version sorts below the release, which is what we want for a floor.
fn version_at_least(actual: &str, min: (u64, u64, u64)) -> bool {
    let (core, pre) = match actual.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (actual, None),
    };
    let mut parts = core.split('.');
    let parsed = (
        parts.next().and_then(|v| v.parse().ok()),
        parts.next().and_then(|v| v.parse().ok()),
        parts.next().and_then(|v| v.parse().ok()),
    );
    let (Some(major), Some(minor), Some(patch)) = parsed else {
        return false;
    };
    let have = (major, minor, patch);
    if pre.is_some() {
        have > min
    } else {
        have >= min
    }
}
