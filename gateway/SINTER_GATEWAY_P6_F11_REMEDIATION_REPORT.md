# Sinter Gateway P6 — F-11 Limited Remediation + Final Revalidation

**Scope:** remediation of F-11 only. F-12 intentionally untouched. No commits, no push, no P7.

**Verdict:** `SINTER GATEWAY P6 F-11 REMEDIATION: PASS` — see §22.

---

## A. Starting identity

| Item | Value |
|---|---|
| Base HEAD | `469aaafa85a8658bff31ede6325981b4018db2c5` (unchanged) |
| Worktree at start | identical to post-audit state (see §O); P6 uncommitted, `D opencode.json` user-owned and preserved |
| P6 baseline | Gateway 130/0, Sinter 484/0, fmt/clippy clean |
| Audit verdict | `SINTER GATEWAY P6 SECURITY AUDIT: PASS` — `~/sinter-public-plugin-gateway/SINTER_GATEWAY_P6_OAUTH_SECURITY_AUDIT.md` |

## B. F-11 reproduction (pre-fix)

Source before remediation (`gateway/src/oauth.rs`, `decode_token`):

```rust
// iat is optional but, when present, must not be in the future.
if let Some(iat) = claims.get("iat").and_then(Value::as_u64) {
    if iat > now_secs() + LEEWAY_SECS {
        return Err(PublicAuthError::Invalid);
    }
}
```

Independent audit evidence (external harness, real HTTP + real RSA JWKS AS, valid signature/iss/aud/exp):

- `iat: "tomorrow"` → **200** (accepted)
- `iat: -5` → **200** (accepted)

## C. Root cause

`claims.get("iat").and_then(Value::as_u64)` collapses two distinct states into `None`:

1. `iat` absent → `get` returns `None`.
2. `iat` present but not representable as `u64` (string, negative, float, null, object, array, > u64::MAX) → `as_u64` returns `None`.

The `if let Some(...)` therefore skipped validation for malformed present values — a silent downgrade of a present-but-invalid claim to "absent", contradicting the documented "iat validated" property. No signature/claim bypass existed (exp/nbf/iss/aud/sub/account all still enforced), which is why the audit classified it LOW.

## D. Minimal remediation

**One production block changed** — `gateway/src/oauth.rs`, `decode_token`, the `iat` check only:

```rust
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
```

- Absent `iat` → unchanged (optional per existing P6 policy — not made mandatory).
- Present + non-negative integer → existing future-check unchanged (same `LEEWAY_SECS`, same wall clock).
- Present + any other representation → `PublicAuthError::Invalid` → 401 + `invalid_token` challenge. No claim values are logged or reflected — the existing categorical error contract is reused.

NumericDate semantics: `as_u64` is the same numeric gate the rest of the validator and `jsonwebtoken` itself apply to `exp`/`nbf`. Consequences, verified: `0` and positive integers accepted; negatives, floats (including integer-valued `1e9` and scientific-notation forms serde_json parses as `f64`), numeric strings like `"1720000000"`, `null`, objects, arrays, and integers exceeding `u64` range are all rejected. No string-to-number coercion was added — `"1720000000"` does not silently become numeric.

Nothing else in `decode_token` was touched: algorithm allowlist, `kid` selection, signature verification, iss/aud/exp/nbf validation, account binding, and the JWKS machinery are byte-identical.

## E. Focused tests

New test `oauth_iat_malformed_rejected` in `gateway/tests/oauth_http.rs` — real HTTP path, real `HttpJwksSource`, real loopback AS, valid RS256 signature/iss/aud/exp so rejection is attributable solely to `iat`:

| `iat` value | Expected | Actual |
|---|---|---|
| `"tomorrow"` (string) | 401 | 401 |
| `"1720000000"` (numeric string) | 401 | 401 |
| `-1` (negative) | 401 | 401 |
| `1.5` (float) | 401 | 401 |
| `1e9` (integer-valued float / sci-notation) | 401 | 401 |
| `null` | 401 | 401 |
| `{}` (object) | 401 | 401 |
| `[]` (array) | 401 | 401 |
| `now` | 200 | 200 |
| `now − 3600` | 200 | 200 |
| `0` (epoch) | 200 | 200 |
| `now + 59` (within leeway) | 200 | 200 |
| `now + 3600` (future) | 401 | 401 |
| absent | 200 (existing policy) | 200 |

Result: `test oauth_iat_malformed_rejected ... ok` (5.15 s).

## F. Real HTTP reproduction (independent)

The external audit harness at `/tmp/sinter-p6-audit` was updated to expect rejection and re-run end-to-end (signed JWTs, real JWKS fetch over loopback HTTP, real gateway):

```
PASS iat malformed → 401: iat string                  401
PASS iat malformed → 401: iat numeric string          401
PASS iat malformed → 401: iat negative                401
PASS iat malformed → 401: iat float                   401
PASS iat malformed → 401: iat integer-valued float    401
PASS iat malformed → 401: iat null                    401
PASS iat malformed → 401: iat object                  401
PASS iat malformed → 401: iat array                   401
PASS iat absent → existing policy (accept)            200
PASS iat boundary iat=now-3600                        200
PASS iat boundary iat=now+59 (within leeway)          200
PASS iat boundary iat=now+120 (future)                401
```

Full adversarial suite post-remediation: **127 checks / 127 passed / 0 failed** (120 original + 7 new iat cases).

## G. F-01 regression — CLOSED

- `cfg` boundary untouched (`#[cfg(any(test, feature = "test-auth"))]`, opt-in feature only).
- Artifact-level re-proof: `cargo build` (default) → `strings libsinter_gateway-*.rlib | grep -c "x-sinter-test-principal"` = **0**. (`--features test-auth` build contains it, as designed.)

## H. F-07 regression — CLOSED

- `cargo test --all-features --test revocation_recheck` → **4/4 pass**: `poll_wait_refuses_delivery_after_revocation`, `http_rejects_respond_after_revocation`, `ensure_active_rejects_revoked_controller`, `test_public_auth_requires_feature_and_default_fails_closed`.
- OAuth-path revocation coverage inside `oauth_http.rs` unchanged and passing.
- The `iat` change is inside public-token claim validation only — controller lifecycle code paths are untouched.

## I. F-12 preservation

**F-12 remains OPEN / INFO and was not modified.** JWKS cache locking, fetch architecture, timeouts, and refresh throttling are byte-identical to the audited state.

## J. Full Gateway regression

`cargo test --all-targets --all-features` → **131 passed / 0 failed** (baseline 130 + 1 new F-11 test).

## K. Sinter regression

`cargo test` at repo root → **484 passed / 0 failed**. Sinter HEAD unchanged (`469aaaf`), Sinter source untouched, `opencode.json` deletion preserved.

## L. Quality gates

| Gate | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS |
| `cargo test --all-targets --all-features` | 131/0 |
| `oauth_http` + `oauth_log` repeated ×3 | 13/13 each run — deterministic, no flakes |
| external adversarial harness | 127/0 |

## M. Final diff scope

Tracked-file diff stat is **byte-identical to the audited P6 baseline** (12 files, 1375 insertions / 178 deletions, `D opencode.json` included). The remediation exists only inside the two untracked P6 files:

- `gateway/src/oauth.rs` — the `iat` block: 6 lines → 12 lines. No signature, issuer, audience, exp, nbf, JWKS, SSRF, routing, session, controller-auth, or store code changed.
- `gateway/tests/oauth_http.rs` — new `oauth_iat_malformed_rejected` test only.

No unrelated production behavior changed.

## N. Finding ledger

| ID | Status | Evidence |
|---|---|---|
| F-01 | **CLOSED** | §G — 0-occurrence default rlib, cfg boundary untouched |
| F-03 | non-blocking (carried) | unchanged |
| F-06 | non-blocking (carried) | unchanged |
| F-07 | **CLOSED** | §H — 4/4 revocation tests incl. OAuth path |
| F-08 | non-blocking (carried) | unchanged |
| F-09 | INFO | unchanged |
| F-10 | INFO | unchanged |
| F-11 | **CLOSED** | §D–F — malformed present `iat` fails closed; absent/valid semantics preserved |
| F-12 | INFO (open by design) | §I — untouched |

## O. Final worktree

```
 M gateway/Cargo.lock
 M gateway/Cargo.toml
 M gateway/src/edge.rs
 M gateway/src/http.rs
 M gateway/src/lib.rs
 M gateway/src/mcp.rs
 M gateway/src/proto.rs
 M gateway/tests/http.rs
 M gateway/tests/mcp_contract.rs
 M gateway/tests/mcp_http.rs
 M gateway/tests/revocation_recheck.rs
 D opencode.json
?? gateway/SINTER_GATEWAY_P1_P5_GATE_REEVALUATION_REPORT.md
?? gateway/SINTER_GATEWAY_P6_IMPLEMENTATION_REPORT.md
?? gateway/src/oauth.rs
?? gateway/tests/oauth_http.rs
?? gateway/tests/oauth_log.rs
```

No `git add`, commit, push, reset, restore, checkout, stash, or clean was performed.

## 22. Verdict

- malformed present `iat` fails closed — proven via unit test and real-HTTP reproduction (8 representations)
- absent `iat` retains existing optional-claim policy — proven
- valid `iat` retains existing behavior incl. leeway boundaries — proven
- F-01 CLOSED (artifact-level), F-07 CLOSED (regression suite), F-12 untouched
- Gateway 131/0, Sinter 484/0, fmt/clippy clean, OAuth suites stable ×3
- remediation confined to the `iat` check + one test — no scope expansion

**SINTER GATEWAY P6 F-11 REMEDIATION: PASS**
