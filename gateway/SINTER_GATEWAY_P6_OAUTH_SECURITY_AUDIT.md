# Sinter Gateway P6 — OAuth / Public Identity Independent Security Audit

**Audit type:** independent adversarial review — audit-only. No source, test, or report file was modified; no commits; no remediation performed.

**Verdict:** `SINTER GATEWAY P6 SECURITY AUDIT: PASS` — see §X.

---

## A. Audit identity

| Item | Value |
|---|---|
| Base HEAD | `469aaafa85a8658bff31ede6325981b4018db2c5` (verified via `git rev-parse HEAD`) |
| P6 diff | uncommitted worktree: `src/oauth.rs` (new, 488 lines), `src/http.rs`, `src/mcp.rs`, `src/edge.rs`, `src/proto.rs`, `src/lib.rs`, `Cargo.toml`/`Cargo.lock`; tests `tests/oauth_http.rs`, `tests/oauth_log.rs` (new) + updates to `tests/http.rs`, `mcp_contract.rs`, `mcp_http.rs`, `revocation_recheck.rs` |
| Pre-existing user-owned change | `D opencode.json` — left untouched throughout |
| Reported baseline | Gateway 130/0, Sinter 484/0 |
| Audit-measured baseline | **Gateway 130 passed / 0 failed** (`cargo test --all-targets --all-features`, full run); `cargo fmt --check` clean; `cargo clippy --all-targets --all-features -- -D warnings` clean |
| Independent adversarial harness | `/tmp/sinter-p6-audit` (outside repo): real HTTP against the compiled gateway, real `HttpJwksSource`, real loopback JWKS/AS with RSA-2048 signing. **120 checks: 120 passed / 0 failed.** |

## B. Scope

Audited: the P6 OAuth resource-server implementation and every P1–P5 invariant it could disturb — authentication boundary, JWT cryptography, issuer/audience/time validation, account + cross-account isolation, credential-domain separation, session/auth continuity, JWKS fetch/cache/SSRF, PRM discovery, MCP edge/tunnel surface, durable controller revalidation, secret logging/persistence, restart/concurrency, new dependencies.

Not audited: the authorization server itself (delegated by design — Q-1), TLS termination (front of this layer per RFC §13), the ChatGPT client, Sinter's internal tool semantics beyond the MCP contract boundary, and non-security code quality.

Method: security model reconstructed from source first (`oauth.rs`, `http.rs`, `mcp.rs`, `edge.rs`, `proto.rs`), standards checked against current authoritative documents, *then* existing tests/reports consulted. All attacks were re-derived independently through an external harness — not the repo's test suite.

## C. Standards verification

Retrieval date: 2026-09-22.

| Source | Requirement | P6 behavior | Verdict |
|---|---|---|---|
| MCP Authorization spec (2025-06-18, 2025-11-25), modelcontextprotocol.io | Resource server MUST implement RFC 9728 Protected Resource Metadata | `GET /.well-known/oauth-protected-resource{,/mcp}` serves exact doc; 404 when OAuth unconfigured | MATCH |
| Same | PRM MUST include `authorization_servers` | `{"resource","authorization_servers":[iss],"bearer_methods_supported":["header"]}` — verified byte-exact | MATCH |
| Same + RFC 9728 | Discovery via `WWW-Authenticate` `resource_metadata` parameter or well-known | Both implemented; 401 challenge carries `Bearer realm=…, resource_metadata=…` (verified on wire) | MATCH |
| RFC 6750 | Bearer challenge grammar, error codes (`invalid_request`, `invalid_token`, `insufficient_scope`) | Distinct mapping: Missing→bare challenge, Malformed→`invalid_request`, Invalid→`invalid_token`, Unbound→403 `insufficient_scope` | MATCH |
| RFC 7519 / OAuth 2.1 | JWT signature, `iss`/`aud`/`exp`/`nbf` validation; `alg=none` rejection | All enforced (see §F/G). `iat` non-numeric tolerated — see F-11 | MATCH (with F-11 note) |
| OpenAI connector docs (current) | `_meta["openai/profile"]` profile tool resolved from validated identity | `sinter_get_profile` injected into `tools/list`, answered locally from `PublicPrincipal`, conflict fail-closed | MATCH |
| CIMD / DCR status | Client↔AS concerns (ChatGPT↔managed IdP) | Correctly absent from the resource server; no registration endpoint exists | N/A (correctly out of scope) |
| PKCE / authorization-code flow | Owned by AS + client, not the RS | Not implemented — correctly; no fake callback/state handling | N/A (correctly out of scope) |

No current-requirement delta materially changes the accepted RFC architecture. The RFC's Q-1 conclusion (vendor-agnostic RS contract: PRM + challenge + JWT validation) holds.

## D. Trust model (reconstructed from source)

```
Internet
  │  untrusted: entire HTTP request (headers, body, method)
  ▼
axum/hyper HTTP parser          — header merging, OWS strip, 400 on malformed
  │
  ▼  POST /mcp only
check_origin()                  — untrusted Origin vs configured allowlist;
                                  absent→allow, multiple→400, unlisted→403
  ▼
public_principal()              — spawn_blocking → OAuthValidator::authenticate
  │    ├─ exactly ONE Authorization header (count>1 → Malformed)
  │    ├─ `Bearer <tok>`: scheme case-insensitive, single segment,
  │    │  no trim/normalize, ≤8KiB; else Malformed
  │    └─ decode_token (see below)     failure → 401/403 + WWW-Authenticate
  ▼                                   [auth occurs BEFORE body parse]
PublicPrincipal {account_id, subject_id, name?, email?}
  │    account_id ← claims[cfg.account_claim] (as_str, non-empty, else Unbound→403)
  │    subject_id ← claims["sub"] (as_str, non-empty, else Invalid→401)
  ▼
check_protocol_version()        — MCP-Protocol-Version vs edge allowlist
  ▼
json_body(cap 1MiB+4KiB)        — bounded stream, application/json only
  ▼
SessionManager                  — durable? NO — memory-only.
  │    with_session: account && subject && TTL(8h) must all match
  ▼
edge::handle_frame              — initialize/ping/notifications/profile/unknown → EDGE
  │                               tools/list, tools/call → FORWARD (verbatim frame)
  ▼
GatewayCore.submit(account…)    — account from principal, never caller data
  ▼
controller work queue → /v1/poll (ControllerAuth domain — separate bearer)
```

Key properties verified in source:

- Identity is **never** reconstructed from untrusted data post-authentication: `PublicPrincipal` fields are private, constructed only by `pub(crate) fn new` inside auth implementations; `forward()` uses `principal.account_id()`, not any request field.
- Session id is routing context only — every request re-authenticates (`mcp_post` always calls `public_principal` first).
- Controller path (`/v1/*`) uses `ControllerAuth` (SHA-256-hashed opaque `ctrlk_` credentials against the durable store) — a disjoint type from `PublicAuth`.
- `/v1/poll` re-checks `ensure_active` inside `poll_wait` at delivery; `/v1/respond` re-checks `ensure_active` after body parse (F-07).
- Failure modes: auth failure → 401/403; unconfigured auth → 503 (fail closed); JWKS stale+fetch-failure → Invalid (fail closed); edge-unknown method → -32601 (never forwarded).

## E. Authentication bypass analysis (incl. F-01)

Attempts — all rejected or inert:

| Probe | Result |
|---|---|
| No `Authorization` → `POST /mcp` initialize | 401 + `WWW-Authenticate` |
| `X-Sinter-Test-Principal` header on no-auth gateway | 503 fail-closed (header inert) |
| Same header on OAuth gateway | 401 (header not consulted) |
| Session-id-only request (no Authorization) | 401 |
| `Bearer` with tab separator / trailing content / empty token | 401 |
| Duplicate `Authorization` headers | 401 |
| Oversized `Authorization` (>8 KiB) | 401 |
| Env-var / debug / alternate-router search of `mcp.rs`, `http.rs`, `lib.rs` | no bypass path found; `public_auth: Option` is `None`→503, `Some(OAuthValidator)` only |

**F-01 independent verification:**

- Source: `TestPublicAuth` is `#[cfg(any(test, feature = "test-auth"))]`; `test-auth` is opt-in, not in default features, nothing enables it.
- Artifact: `cargo build` (default) → `strings libsinter_gateway-*.rlib | grep -c x-sinter-test-principal` = **0**. `cargo build --features test-auth` → **1**. The header string is structurally absent from the production/default compiled artifact.

**F-01: CLOSED — independently re-confirmed.**

## F. JWT cryptographic audit

Performed against the real `HttpJwksSource` + loopback AS (RS256, RSA-2048):

| Attack | Expected | Actual |
|---|---|---|
| `alg=none` | reject | 401 |
| HS256 signed with RSA *public* key material (confusion) | reject | 401 |
| RS384 / ES384 / unknown alg / missing alg | reject | 401 |
| `kid` missing / empty / unknown / >128 chars | reject | 401 |
| Duplicate `kid` in JWKS | ambiguous→reject | 401 |
| Tampered payload post-signing | reject | 401 |
| Truncated token / random signature | reject | 401 |
| Token signed by a different RSA key | reject | 401 |
| `jku`/`x5u` in token header pointing at attacker URI | ignored — verify via pinned `jwks_uri` | 200 (valid sig) — source never consulted |
| EC key with `crv≠P-256`, RSA key marked `use=enc`, JWK `alg=HS256` | unusable | rejected/dropped (source: `jwk_to_key` returns None) |
| Key/alg family mismatch (RSA key + ES256 token) | reject | 401 (`jwk.alg != header.alg` check) |

Source review confirms the algorithm whitelist (`RS256`/`ES256` only) is applied to the *token header* before key selection, and the JWKS `alg`/`use`/`kty`/`crv` fields are independently screened. `decode()` (jsonwebtoken) verifies the signature before claim validation — no claim is trusted pre-verification. **No JWT verification bypass found.**

## G. Issuer / audience / time audit

Issuer (`iss` exact-match via `Validation::set_issuer`):

- wrong iss, lookalike iss, trailing-slash iss, uppercase iss, path-appended iss → all **401**; correct iss → 200.

Audience (`aud` exact-match via `set_audience`):

- wrong/missing/numeric aud, aud array without ours, lookalike prefix, trailing-slash, uppercase → all **401**; aud array *containing* ours → 200 (correct per spec — `aud` is a set).

Time claims (offset-minted, no sleeps):

- `exp`: now+3600/now+61/now+59 → 200; now−59 (inside 60 s leeway) → 200; now−120/now−3600 → **401**. Boundary behavior matches documented `LEEWAY_SECS=60`.
- `nbf`: past → 200; now+59 (within leeway) → 200; now+120 → **401**.
- `iat`: past/now+59 → 200; now+120 → **401**; **string `iat` → 200; negative `iat` → 200** — see F-11.
- missing `exp`/`iss`/`aud`/`sub` → 401 (`required_spec_claims`); `sub` numeric/empty → 401.

A token valid for another issuer or another audience cannot authorize Sinter Gateway — verified, not assumed.

## H. Account and cross-account isolation

- Missing/empty/numeric/array `sinter_account` → **403 `account_unbound`** + `insufficient_scope` challenge. No default/first/fallback account path exists in source (`ok_or(PublicAuthError::Unbound)`).
- Ghost-account check: a valid token binding to an account with no controller → `initialize` succeeds (authentication is identity, not authorization to a registered controller) but `tools/call` → JSON-RPC error `controller_offline` — no work routed.
- Cross-account matrix: A-token+B-session → 403; B-token+A-session → 403; A DELETE B session → 403; same-account/different-subject + session → 403 (`with_session`/`delete`/`cancel_live` all check account ∧ subject ∧ TTL).
- Concurrency: 8 parallel cross-account uses → all 403; 8 parallel same-account session creates → all succeed independently.

## I. Credential-domain separation

| Credential | Target | Result |
|---|---|---|
| controller `ctrlk_…` bearer | `POST /mcp` | 401 (fails JWT decode — invalid) |
| OAuth JWT | `POST /v1/poll` | 401 (fails `ctrlk_` parse — malformed) |
| OAuth JWT | `POST /v1/respond` | 401 |
| registration token | `POST /mcp` | 401 |

Domains are disjoint at the type level (`PublicAuth` vs `ControllerAuth`) — no shared parser can cross-accept. Registration tokens are consumed once (`consumed_registration_token` on replay).

## J. Session/auth continuity

- Valid session + expired token → 401; valid session + invalid token → 401; valid session + *other* account's valid token → 403.
- Session is `sess_`+128-bit CSPRNG, memory-only (`SessionManager` has no store), TTL 8 h, caps 64/account + 10 k global with lazy sweep.
- Restart: fresh `SessionManager` → old session id → 404 `unknown_request`; stale work cannot revive (verified by restarting the server mid-test).

## K. SSRF / JWKS / outbound HTTP

`trusted_uri` semantics (verified against source + live policy table):

- `https://` any host (JWKS URI is *operator config*, not attacker input — `jku`/`x5u` never consulted).
- `http://` only loopback **IP literals** — hostnames over HTTP rejected (no DNS → no rebinding window for HTTP).
- WHATWG canonicalization is consistent between validation and connection (same `url` crate used by reqwest): `http://2130706433/` and `http://0x7f000001/` parse to `127.0.0.1` → allowed, and the *connection target is genuinely loopback* — not a bypass.
- `::ffff:127.0.0.1` (v4-mapped v6) → rejected (Rust `Ipv6Addr::is_loopback` is `::1`-only — conservative, errs safe).
- `0.0.0.0`, 10/8, 172.16/12, 192.168/16, 169.254.169.254, `file:`, `ftp:`, `gopher:`, userinfo, query strings → all rejected.
- Redirects disabled (`Policy::none`): JWKS endpoint returning 302→private → fetch error → fail closed (verified live: 401).
- Body streamed with 256 KiB hard cap; >64-key docs rejected; malformed JSON rejected; duplicate `kid` poisons the entry.
- Unknown-`kid` amplification bound: 16 parallel distinct-unknown-kid requests → **4 JWKS fetches** (mutex serialization + `min_refresh` throttle).
- Stale-cache + fetch-failure → fail closed (401), verified.

Residual notes (not findings): (a) HTTPS to private IPs is allowed by policy — correct, since the URI is operator-trusted config and TLS binds the hostname; (b) reqwest honors proxy env vars by default — standard operator trust, documented for operators; (c) JWKS mutex is held across the network fetch — worst-case auth stall bounded by the 5 s timeout (see F-12).

## L. PRM / discovery audit

- `GET /.well-known/oauth-protected-resource` and `…/mcp` → 200 `application/json`, exact doc `{resource, authorization_servers, bearer_methods_supported}` — 3 keys, no extras.
- Doc is built once from config (`with_oauth`) — no request reflection; `Host: attacker.example`, `X-Forwarded-Host`, `Forwarded`, `X-Forwarded-Proto` → doc unchanged (verified).
- No internal hostname, controller identity, path, or store detail in the doc or in `WWW-Authenticate`.
- Public access (no auth) — correct, discovery requires it. 404 when OAuth unconfigured — verified.

## M. MCP edge / tunnel audit

- Edge handles: `initialize`, `ping`, `notifications/*` (202, never forwarded), `notifications/cancelled` (→ Cancel), `tools/call name==sinter_get_profile` (→ local profile from principal), unknown methods (→ -32601), batches (→ -32600), non-`"2.0"` (→ -32600).
- Verified live: unknown method → -32601 **and** controller poll returns `{work:null}` — edge-rejected traffic never enters the work queue.
- Forwarded set is exactly `tools/list` + `tools/call` (non-profile names) verbatim — tool-name authority stays with sinter; callers cannot inject methods, argv, env, SSH targets, or paths beyond the existing sinter MCP tool contract. **Not a generic tunnel.**
- Profile injection is keyed on the *request* method (`tools/list`), fail-closed on name conflict; profile content comes from the principal only.

## N. Durable controller revalidation (F-07)

- `poll`: `authenticate` → `bind` → `poll_wait(…, || auth.ensure_active(ctl))` — revocation checked at every delivery point.
- `respond`: `authenticate` → body → `ensure_active` → `core.respond` — checked post-parse.
- OAuth-path regression: issued work request in-flight → `revoke` → controller poll → **401 `revoked_controller`**; caller received JSON-RPC error (`deadline_exceeded`), never a post-revocation result.
- Race ×20 (revoke landing at random offsets around poll): every outcome 200-with-`work:null` or 401 — no post-revocation delivery, no hang, no panic.

**F-07: CLOSED — independently re-confirmed through the OAuth path.**

## O. Secret / log / persistence audit

- Marker-secret test (`tests/oauth_log.rs`) passes; independently: no JWT, token segment, `sub`, `ctrlk_` credential, or registration token appears in SQLite raw bytes after a full exercised run.
- `err_response` sanitizes `store_failure` to "internal error"; bearer values are never logged or reflected; `tracing` calls carry codes/ids only.
- Persistence boundary holds: durable = identity/security lifecycle; memory-only = sessions, live work, payloads, results.

## P. Restart / concurrency

- Restart: controller identity survives (SqliteStore), OAuth config is config (by design), sessions/work die, stale session → 404.
- Concurrency results in §K/§H/§N: bounded JWKS amplification under flood, deterministic cross-account rejection, clean revoke/poll races, no deadlock or unbounded wait observed.

## Q. Dependency review

| Dep | Version | Role | Assessment |
|---|---|---|---|
| `jsonwebtoken` | 9.3.1 | JWT decode/verify | Current major; explicit `Validation` (alg pinned per-token-header-checked, required claims, leeway); no unsafe defaults relied on |
| `reqwest` | 0.12.28 | JWKS fetch only | `default-features=false` + `blocking` + `rustls-tls` — no cookies/gzip/proxy-auth extras; redirects disabled; timeouts set |
| `url` | 2.x | `trusted_uri` parsing | WHATWG-consistent with reqwest's own parser — no validation/connection TOCTOU |
| `base64`, `rsa`, `pkcs8` | dev-only | test AS | not in production artifact |

`cargo audit` not installed in the environment — advisory check not run (environment limitation, noted). No duplicate JWT implementations, no OAuth framework bloat, no unnecessary crypto.

## R. Attack matrix

| Attack | Expected | Actual | Evidence | Verdict |
|---|---|---|---|---|
| no Authorization | reject | 401+challenge | harness | PASS |
| test auth in production | unreachable | header inert; 0 rlib occurrences | strings check | PASS |
| alg=none | reject | 401 | harness | PASS |
| HS256 confusion | reject | 401 | harness | PASS |
| wrong/tampered/truncated signature | reject | 401 | harness | PASS |
| wrong issuer (incl. lookalike/case/path) | reject | 401 | harness | PASS |
| wrong audience (incl. prefix/suffix/case/type) | reject | 401 | harness | PASS |
| expired token | reject | 401 | harness | PASS |
| future nbf | reject | 401 | harness | PASS |
| missing/unbound account | 403 | 403 `account_unbound` | harness | PASS |
| A token + B session | reject | 403 | harness | PASS |
| controller bearer → /mcp | reject | 401 | harness | PASS |
| OAuth token → /v1/poll, /v1/respond | reject | 401 | harness | PASS |
| registration token → /mcp | reject | 401 | harness | PASS |
| attacker jku/x5u | ignored | ignored (valid sig → 200 via pinned JWKS) | harness | PASS |
| private/link-local/metadata JWKS URI | reject | rejected (policy table) | harness+source | PASS |
| redirect-to-private JWKS | reject | 401 (redirects disabled) | harness | PASS |
| oversized / >64-key / duplicate-kid / malformed JWKS | reject | 401 fail-closed | harness | PASS |
| host-header poisoning of PRM/challenge | not trusted | doc static from config | harness | PASS |
| unknown MCP method | edge reject | -32601, never queued (poll→null) | harness | PASS |
| edge method reaches controller | no | no | harness | PASS |
| revoked controller delivery | reject | 401 pre-delivery | harness+race×20 | PASS |
| revoked controller respond | reject | `ensure_active` post-parse | source+repo tests | PASS |
| secret markers in logs | absent | absent | repo log test | PASS |
| secret markers in SQLite | absent | absent (raw-bytes scan) | harness | PASS |
| stale session after restart | reject | 404 | harness | PASS |
| session as bearer | reject | 401 | harness | PASS |
| unauth large body / bad CT / bad JSON | auth first | 401 before parse | harness | PASS |
| unknown-kid flood amplification | bounded | 4 fetches / 16 reqs | harness | PASS |
| numeric-IPv4 JWKS URI spellings | safe | canonicalize to loopback; conn target loopback | harness+source | PASS |

## S. Existing finding re-evaluation

| ID | Verdict | Evidence |
|---|---|---|
| F-01 test auth in production | **CLOSED** | source cfg + 0-occurrence default rlib + inert header probes (§E) |
| F-03 `core.cancel` public surface | **OPEN — carried forward, non-blocking** | unchanged; public paths enforce ownership before any cancel reaches it |
| F-06 duplicate JSON-RPC id tracking | **OPEN — carried forward, non-blocking** | unchanged; `public_key` canonicalization keeps `7`/`"7"` distinct |
| F-07 durable revocation recheck | **CLOSED** | re-proven through OAuth path + 20-run race (§N) |
| F-08 panic-safe active-poll slot | **OPEN — carried forward, non-blocking** | unchanged |
| F-09 `iat` future check uses wall clock | **INFO — confirmed** | offset-minted boundary tests show correct ±60 s leeway behavior |
| F-10 revocation window = token lifetime | **INFO — confirmed** | offline JWT validation; window bounded by AS-issued `exp`, enforced by Gateway; documented |

## T. New findings

### F-11 — non-numeric `iat` silently ignored — **LOW**

- **Component:** `gateway/src/oauth.rs` `decode_token` (lines 416–421).
- **Precondition:** AS issues a JWT whose `iat` is a string, negative integer, or float.
- **Observation:** `claims.get("iat").and_then(Value::as_u64)` returns `None` for non-u64 values, so malformed `iat` is treated as *absent* rather than rejected. Verified live: `iat:"string"` → 200, `iat:-5` → 200.
- **Impact:** none on the security boundary — signature, `exp`, `nbf`, `iss`, `aud`, `sub`, and account binding are all still enforced; `iat` is only used to reject future-dated tokens. This is a spec-strictness gap (RFC 7519 `iat` is a NumericDate) and a slight overstatement in the implementation report's "iat validated" claim — not an authentication bypass.
- **Recommendation direction:** treat `iat` present-but-non-NumericDate as `Invalid` (reject), matching the strictness applied to `sub` and the account claim. Low priority.

### F-12 — JWKS mutex held across network fetch — **INFO**

- **Component:** `oauth.rs` `decode_token`/`refresh_locked` — `self.jwks` lock is held for the duration of a blocking fetch.
- **Impact:** a slow JWKS endpoint stalls all concurrent authentication up to the 5 s client timeout per refresh; refresh cadence is throttled (TTL + `min_refresh`), so worst-case periodic stall, not amplification. Bounded and fail-closed — acceptable for the RFC threat model; noted for awareness.

## U. Test evidence

- Repo suite (independent re-run): `cargo test --all-targets --all-features` → **130 passed / 0 failed**; `cargo fmt --check` clean; `cargo clippy --all-targets --all-features -- -D warnings` clean.
- External adversarial harness (`/tmp/sinter-p6-audit`, real HTTP + real `HttpJwksSource` + real RSA JWKS AS): **120 checks — 120 passed / 0 failed**, covering §6–§33 of the audit spec: auth bypass, alg confusion, kid/key-selection, signature forgery, issuer/audience/time boundaries, account binding, cross-account matrix, session-as-auth, credential-domain crossover, auth-before-body, duplicate/malformed headers, PRM contract + host-header immunity, edge/tunnel bounds, JWKS bounds/SSRF/redirects, persistence scan, restart, and concurrency.
- Two earlier harness FAILs were diagnosed as harness bugs (empty Origin allowlist masking auth results; `bearer()` helper emitting a header-less line → hyper 400), corrected, and re-run — no implementation defect behind any of them.

## V. Security questions

1. Can an unauthenticated caller reach MCP execution? **NO** — every `/mcp` verb authenticates first; 401/403/503 verified.
2. Can test authentication be reached in the production/default build? **NO** — `cfg` gated; 0 `x-sinter-test-principal` occurrences in the default rlib; header inert.
3. Can a forged JWT be accepted? **NO** — alg confusion, tamper, truncation, wrong-key, random-sig all → 401.
4. Can an attacker select the verification key source? **NO** — `jku`/`x5u` never consulted; JWKS URI pinned by config and re-validated per fetch.
5. Can a token for another issuer be accepted? **NO** — exact-match `iss`; lookalike/case/path variants → 401.
6. Can a token for another audience/resource be accepted? **NO** — exact-match `aud` membership; lookalikes → 401.
7. Can account A use account B's MCP session? **NO** — account ∧ subject ∧ TTL check on every session op; 403 verified incl. concurrency.
8. Can account A route work to account B's controller? **NO** — `forward` submits under `principal.account_id()`; ghost-account work → `controller_offline`, never routed.
9. Can an MCP session replace OAuth authentication? **NO** — session-id alone → 401; expired/invalid token + live session → 401.
10. Can a controller credential authenticate to `/mcp`? **NO** — `ctrlk_` fails JWT decode → 401.
11. Can a public OAuth credential authenticate to `/v1/poll` or `/v1/respond`? **NO** — JWT fails controller-credential parse → 401.
12. Can OAuth/JWKS metadata fetching reach a protected local/private address? **NO** — attacker has no URL control; configured URIs are trust-validated (private/link-local/userinfo/non-http(s) rejected; HTTP only to loopback literals; redirects disabled). Residual: operator-configured HTTPS may legitimately target private IPs.
13. Can Host/Forwarded headers poison OAuth/PRM metadata? **NO** — metadata/challenges are built from static config; verified unchanged under hostile headers.
14. Can an unknown MCP method become arbitrary controller work? **NO** — -32601 at the edge; controller poll returns `work:null`.
15. Can OAuth cause MCP payloads/results to become durable? **NO** — sessions/work memory-only; raw-bytes SQLite scan clean.
16. Can OAuth/public secrets enter logs? **NO** — marker test passes; bearer values never logged/reflected.
17. Can OAuth/public secrets enter SQLite unexpectedly? **NO** — tokens, segments, subs absent from raw database bytes.
18. Can a revoked controller receive new work after durable revocation? **NO** — `ensure_active` at delivery; 401 verified + race×20.
19. Can a revoked controller submit a response after durable revocation? **NO** — post-parse `ensure_active` → rejection.
20. Can Gateway restart revive a stale MCP session/work item? **NO** — memory-only manager; stale session → 404.

## W. Worktree preservation

Final `git status --short` (identical to initial capture — the audit modified nothing in-repo):

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

All audit artifacts live at `/tmp/sinter-p6-audit` (outside the repo). `opencode.json` deletion untouched. No `git add/commit/checkout/restore/reset/stash/clean` performed.

## X. Final verdict

Against the PASS rules: no unresolved CRITICAL or HIGH; F-01 and F-07 remain CLOSED under independent re-verification (including compiled-artifact inspection and OAuth-path revocation races); no production auth bypass; no JWT verification bypass; issuer/audience boundaries exact; account isolation and credential-domain separation hold; no practical protected-network SSRF (JWKS source is operator-pinned, redirects disabled, numeric-IPv4 spellings canonicalize safely); the MCP edge cannot become an arbitrary tunnel; the persistence/secret boundary holds; P1–P5 invariants remain intact.

New findings are F-11 (LOW — lenient non-numeric `iat` handling; strictness gap only, no bypass) and F-12 (INFO — bounded JWKS fetch stall). Neither fails the audit criteria.

**SINTER GATEWAY P6 SECURITY AUDIT: PASS**
