# SINTER GATEWAY P6 IMPLEMENTATION REPORT

Phase: **P6 — production OAuth public authentication / public identity**

Scope guard honored: P6 replaces *only* the public identity source. No changes
to `GatewayCore`, controller registration/auth, `/v1/poll`, `/v1/respond`,
SQLite identity boundaries, P5 session model, edge/forward/reject
classification, `sinter mcp`, or Sinter.

---

## A. Starting identity

| Item | Value |
|---|---|
| Gateway HEAD | `469aaafa85a8658bff31ede6325981b4018db2c5` |
| Sinter HEAD | `66ca3d778918e0d81500b9ba041d268ae90a9104` |
| Baseline Gateway tests | 118 / 0 |
| Baseline Sinter tests | 484 / 0 |
| Accepted gate state | F-01 CLOSED, F-07 CLOSED, no open HIGH/CRITICAL |
| Pre-existing worktree | ` D opencode.json` (user-owned, untouched) + `?? gateway/SINTER_GATEWAY_P1_P5_GATE_REEVALUATION_REPORT.md` |

## B. P6 requirements resolution

### Implementation matrix (RFC §17 vs current platform contract)

| Requirement | P6 | Reason |
|---|---|---|
| Public OAuth authentication (bearer JWT validation) | **yes** | RFC §17 RS role; MCP authorization spec requires OAuth 2.1 resource server |
| RFC 9728 Protected Resource Metadata | **yes** | MCP spec: resource servers MUST serve PRM with `authorization_servers` |
| `WWW-Authenticate` challenges | **yes** | RFC 6750 + MCP spec (SEP-985: SHOULD); needed for AS discovery |
| Authorization Server Metadata | **no** | owned by the managed AS; duplicating it in Gateway = half-AS (rejected) |
| CIMD | **no** | client↔AS concern (ChatGPT↔managed AS); Gateway never sees it |
| DCR | **no** | same — AS-side client registration |
| PKCE S256 | **no** | authorization-code flow lives at the AS; Gateway is RS-only |
| RFC 9207 `iss` | **yes** | `iss` claim exact-match against configured trusted issuer |
| Refresh tokens | **no** | never reach a resource server |
| managed mTLS | **no** | transport deployment concern (P7+) |
| connector IP allowlist | **no** | deployment/edge concern |

### Q-1 resolution

**Q-1 (managed-AS vendor CIMD support) — resolved as a deployment-time vendor
requirement, not a Gateway implementation dependency.**

Current authoritative evidence (retrieved this session):

- OpenAI Apps SDK docs: ChatGPT prefers **CIMD** (client_id metadata document),
  falls back to **DCR**; authorization_code flow with PKCE at the AS.
- MCP authorization spec (2025-06-18 / 2025-11-25 drafts): resource servers
  MUST implement RFC 9728 PRM and MUST validate tokens per RFC 9068-class
  bearer semantics; clients discover the AS via `authorization_servers` or
  `WWW-Authenticate` `resource_metadata`.
- Community evidence: ChatGPT probes `/.well-known/oauth-protected-resource`
  on the MCP host and AS-metadata documents on the AS host — a compliant
  404 on the former with a working PRM is the expected discovery path.

**Implementation consequence:** the Gateway ships the complete *resource-server*
contract — PRM document + `WWW-Authenticate` + JWT validation — and is
vendor-agnostic. Any AS that (a) issues JWT access tokens for a configured
audience, (b) publishes JWKS, (c) supports CIMD or DCR for ChatGPT onboarding,
satisfies deployment. Vendor selection (WorkOS / Keycloak / Auth0 / Stytch etc.)
is an operational decision outside P6 code. No stop condition triggered.

## C. Authentication architecture

```text
HTTP request
    │  Authorization: Bearer <jwt>
    ▼
check_origin (P5, unchanged)
    ▼
PublicAuth::authenticate            ← P6 boundary (spawn_blocking slot)
    │  strict Bearer parsing → decode_header (alg allowlist, kid required)
    │  → bounded JWKS cache (refresh on stale/unknown-kid)
    │  → signature + iss + aud + exp + nbf + iat + required claims
    │  → account claim → PublicPrincipal
    ▼
AuthenticatedPublicPrincipal        (private fields; only auth can mint)
    ▼
[P5 MCP edge — unchanged]  →  [P1–P4 — unchanged]
```

`PublicAuth::authenticate` now returns `Result<PublicPrincipal,
PublicAuthError>` where `PublicAuthError ∈ {Missing, Malformed, Invalid,
Unbound}`. The trait gained `www_authenticate(&err)` (default `None`) so the
HTTP layer can emit the RFC 6750 challenge without knowing OAuth internals.
P5 business logic sees only `PublicPrincipal`.

Ordering change in `/mcp` POST: **authentication now precedes body parsing**
(origin → auth → protocol-version → body). An unauthenticated request receives
no service beyond the challenge. `/v1/respond` was likewise reordered to
authenticate before body parsing (P4 hardening; both orders were safe, this
one is cleaner).

## D. OAuth/MCP discovery

Implemented, served only when OAuth is configured:

| Route | Behavior |
|---|---|
| `GET /.well-known/oauth-protected-resource` | RFC 9728 document |
| `GET /.well-known/oauth-protected-resource/mcp` | same document (resource-path-suffixed form) |

Exact document:

```json
{
  "resource": "<configured public gateway URL>",
  "authorization_servers": ["<configured trusted issuer>"],
  "bearer_methods_supported": ["header"]
}
```

No controller info, internal hostnames, key ids, or store topology appear.
A gateway built without OAuth returns 404 on both routes (contract test).
No AS-metadata endpoint is served — the Gateway is not an authorization
server and does not pretend to be one.

## E. Token validation

`OAuthValidator` (`src/oauth.rs`):

- **Scheme**: `Bearer` (case-insensitive per RFC 7235), exactly one
  `Authorization` header (duplicates → malformed), token is a single
  non-empty segment; interior whitespace → malformed; header cap 8 KiB.
- **Header**: `alg` must be RS256 or ES256 (`alg=none`, HS*, all others →
  invalid); `kid` required, ≤128 chars.
- **Signature**: verified via `jsonwebtoken` against the JWKS key selected
  by `kid` — pinned to the configured `jwks_uri`; `jku`/`x5u` token fields
  are ignored entirely.
- **Claims** (`jsonwebtoken::Validation`):
  `exp`, `iss`, `aud`, `sub` required; `exp`/`nbf` enforced with 60 s leeway;
  `iat`, when present, must not be in the future; `iss` exact-match to
  configured issuer (RFC 9207 mix-up protection); `aud` exact-match to
  configured resource indicator.
- **Principal**: `sub` → `subject_id`; configured account claim (default
  `sinter_account`) → `account_id`. Missing/empty account claim →
  `Unbound` (403), never a default/fallback account. Optional `name`/`email`
  claims surface only through the profile tool.
- **Validation internals never cross the wire** — every failure maps to a
  generic category; JWKS fetch failures log a category only.

## F. Public principal / account binding

```text
trusted issuer (iss, exact) + signature over claims
        │
        ▼
sub (stable AS-issued subject)      sinter_account (stable account claim)
        │                                   │
        └───────── PublicPrincipal ─────────┘
              account_id  subject_id  (name?, email?)
```

`account_id` is accepted **only** from the validated token claim — never from
body, query, arbitrary headers, session ids, controller credentials, or tool
arguments (isolation test proves A-token can neither use B-session nor reach
B-controller). `PublicPrincipal` fields are private; the only constructor is
`pub(crate)` and called only by `PublicAuth` implementations.

**Unbound ≠ anonymous**: a perfectly valid token without the account claim
gets `403 account_unbound` — authenticated, but bound to no account, so it
can do nothing.

## G. CIMD / DCR decision

**Deliberately not implemented** — both are client↔AS registration
mechanisms. Per current OpenAI docs ChatGPT drives CIMD (preferred) or DCR
against the *authorization server*; the resource server's only obligations are
PRM + challenges + token validation, all implemented. Implementing CIMD/DCR
inside the Gateway would create a half-AS, which the task explicitly forbids.

## H. PKCE / issuer protections

- **PKCE**: not implemented — the Gateway performs no authorization-code
  flow (no `/authorize`, no token endpoint, no callbacks). PKCE S256 is the
  AS's obligation in the ChatGPT↔AS flow. Writing fake PKCE logic into the
  RS would be security theater.
- **Issuer binding**: `iss` is an exact string match against the configured
  issuer (never inferred from token or callback parameters). Wrong-issuer and
  evil-issuer tokens → 401 `invalid_token` (test matrix).

## I. SSRF / outbound HTTP

`HttpJwksSource` is the only new outbound surface:

- URL policy (`trusted_uri`): **HTTPS anywhere; HTTP only to loopback IP
  literals** (test/dev AS). Hostnames over HTTP are rejected even when they
  resolve loopback — DNS is not pinned at validation time, closing the
  rebinding hole for non-literal hosts. No userinfo, no embedded query, no
  non-http(s) scheme. `file://`, `gopher://`, RFC1918/link-local/metadata
  endpoints (`169.254.169.254`), `localhost` over HTTP — all rejected.
- Client: `reqwest::blocking` with `rustls`, **redirects disabled**,
  connect timeout 3 s, total timeout 5 s, streamed body capped at 256 KiB,
  no cookie jar, no credential forwarding.
- JWKS is fetched only from the **configured** `jwks_uri` — never from
  token-supplied `jku`/`x5u`.
- Refresh amplification bound: unknown-`kid` retries are spaced by
  `jwks_min_refresh` (default 60 s); forged tokens cannot force unbounded
  outbound requests.
- Lazy client construction on first fetch (blocking context required by
  reqwest's blocking client); teardown deferred off async workers.

## J. Session / auth continuity

- Every `/mcp` request re-authenticates. Session ids remain routing context,
  not credentials: valid token + missing session → `missing_auth`; session +
  no token → 401; expired token + valid session → 401 (test).
- Sessions still bind (account, subject) — a token whose `sub`/account
  differs from the session's is rejected (403).
- **Revocation**: JWT validation is offline — there is no instantaneous
  token revocation. Effective revocation window = access-token lifetime
  (issuer-configured; short-lived tokens recommended) — documented
  limitation, exactly as the RFC model provides. Session DELETE remains the
  immediate caller-side kill switch.
- MCP sessions are memory-only; active work is memory-only; restart wipes
  both (P5 semantics unchanged).

## K. MCP regression

Edge/forward/reject unchanged: `initialize`, `ping`, `notifications/*`,
profile tool → EDGE; `tools/list`, `tools/call` → FORWARD; batches,
malformed, unknown methods → rejected. All P5 `mcp_contract` + `mcp_http`
tests pass unmodified except: `handle_frame` lost the now-unneeded `account`
param (the `tools/call` profile arm yields `EdgeAction::Profile(id)`, and
the MCP layer builds the result from the principal — wire shape still owned
by `edge::profile_result`), and the pre-P6 surface test expected 415 where
auth-first ordering now answers 503 on a no-auth gateway.

## L. Controller revalidation regression (F-07)

`oauth_controller_revocation_revalidation`: OAuth-authed caller submits
`tools/call`; controller revoked *before* its first poll; poll → 401
`revoked_controller` (durable revalidation before delivery); the public
caller receives a structured JSON-RPC error — never a false success.
F-07 remains CLOSED through the production auth path.

## M. Test-auth exclusion (F-01)

`TestPublicAuth` remains `#[cfg(any(test, feature = "test-auth"))]` — absent
from default builds. Evidence: default `cargo build` rlib contains **zero**
occurrences of the `x-sinter-test-principal` header string; the type name
appears only inside rustdoc metadata, never as code. `GatewayHttp::new` still
defaults to `public_auth: None` → `/mcp` answers 503 fail-closed. A
production deployment uses `with_oauth`, which *requires* a validated
`OAuthConfig` — no anonymous path exists.

## N. Secret / persistence audit

- Marker test (`tests/oauth_log.rs`): DEBUG-level tracing capture across
  success + failure paths — full bearer token, signature segment, `sub`
  value, expired token, malformed-bearer bytes, MCP payload markers,
  registration token and controller credential — **none appear in logs**.
- Raw SQLite scan (`oauth_cross_account_isolation`): database bytes searched
  for both access tokens, every JWT segment, and subject ids — **nothing
  persisted**. The ledger stores controller records only; no OAuth tables or
  columns were added (nothing durable was needed — RFC §29 honored).

## O. Full E2E

`oauth_e2e_real_sinter` (real loopback HTTP, real `sinter mcp` over stdio):

```text
Bearer-authed initialize → /mcp → session
tools/list  → forward → /v1/poll → bridge → sinter mcp → /v1/respond → caller
            (8 real tools + injected profile tool)
tools/call sinter_get_version → same chain → verbatim caller id + result
```

Plus `oauth_session_and_profile` (edge methods + profile claims) and
`oauth_concurrent_sessions` (6 parallel authed sessions + calls). Safe,
non-mutating tools only — no target hosts involved; zero mutation by
construction.

## P. Tests

| Binary | Tests | Content |
|---|---|---|
| `oauth_http.rs` | **11** | credential matrix (~30 cases), session+profile, cross-account isolation + SQLite scan, expiry-mid-session, PRM contract, JWKS rotation/malformed, URI/SSRF policy, auth-domain disjointness, F-07 revocation regression, real-sinter e2e, concurrency |
| `oauth_log.rs` | **1** | OAuth-path secret-marker test |
| existing suite | 118 | unchanged; only mechanical updates — `handle_frame` signature, `authenticate` → `Result`, profile `EdgeAction::Profile` assertion, `/mcp` 503-before-415 ordering, tolerant-read in a shared helper |
| **Total** | **130 / 0** | |

## Q. Quality gates

| Gate | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test --all-targets --all-features` | **130 / 0**, repeated runs |
| Sinter regression `cargo test --all-targets` | **484 / 0** |
| F-01 rlib check | `x-sinter-test-principal` = 0 occurrences in default build |

## R. Dependency review

| Dep | Version | Purpose | Notes |
|---|---|---|---|
| `jsonwebtoken` | 9.3.1 | JWT decode/verify (alg allowlist, iss/aud/exp/nbf, required claims) | mature, no crypto hand-rolled |
| `reqwest` | 0.12.28 | JWKS fetch only (`blocking` + `rustls-tls`, no defaults) | no cookies/proxy-creds; redirects off |
| `url` | 2.x | URI trust parsing (already transitive via reqwest) | scheme/host/userinfo validation |
| `rsa` (dev) | 0.9 | test-AS keygen + PEM | test binaries only |
| `pkcs8` (dev) | 0.10 | PEM encode for test keys | test only |
| `base64` (dev) | 0.22 | JWK/thumbprint encoding in tests | test only |

No dependency reaches Sinter; the gateway crate is the only consumer.

## S. Security invariant mapping (I-1 … I-11)

| Inv | Status | Evidence |
|---|---|---|
| I-1 auth fail-closed | ✅ stronger | auth now precedes body parse; no anonymous/default principal |
| I-2 no caller-supplied routing identity | ✅ | account only from validated claim; spoofing impossible (no claim → 403) |
| I-3 sessions are context not credentials | ✅ | expired-token-on-valid-session → 401; every request re-auths |
| I-4 controller auth separate | ✅ | OAuth bearer on /v1 → 401; controller cred on /mcp → 401 (disjoint domains test) |
| I-5 work ownership | ✅ | P1 semantics unchanged; F-07 regression re-proven through OAuth |
| I-6 edge contract | ✅ | routing table unchanged; unknown methods never forwarded |
| I-7 no unsolicited traffic | ✅ | GET /mcp → 405; no SSE |
| I-8 bounded inputs | ✅ | + Authorization ≤8KiB, kid ≤128, JWKS ≤256KiB/64 keys |
| I-9 memory-only sessions/work | ✅ | unchanged; SQLite scan shows no token persistence |
| I-10 secret hygiene | ✅ | marker test: tokens/claims/creds/payloads absent from logs |
| I-11 Sinter unchanged | ✅ | 484/0, no Sinter diff, real `sinter mcp` e2e passes |

## T. Finding ledger

| ID | Severity | Status |
|---|---|---|
| F-01 test auth in production | — | **CLOSED** (re-proven: 0 header-string occurrences in default rlib) |
| F-03 `core.cancel` public surface | MEDIUM | carried forward — public paths enforce ownership; internal hardening still open for P7 |
| F-06 duplicate JSON-RPC id tracking | LOW | carried forward — unchanged |
| F-07 controller revocation recheck | — | **CLOSED** (regression re-proven through OAuth path) |
| F-08 panic-safe active-poll slot | LOW | carried forward — unchanged |
| F-09 `iat` future check uses wall clock | INFO | new — acceptable; leeway 60 s bounds skew; no testable-clock requirement met via offset minting |
| F-10 revocation window = token lifetime | INFO | new — offline JWT validation means no instantaneous revocation; documented per §22 |

No new CRITICAL/HIGH.

## U. Files changed

Modified: `gateway/src/edge.rs` (Profile action, pub `profile_result`, dropped
unused `account` param), `gateway/src/http.rs` (auth-first ordering, auth
error mapping + `WWW-Authenticate`, `with_oauth`, PRM routes, respond auth
reorder), `gateway/src/mcp.rs` (principal enrichment, `PublicAuthError`,
trait signature, Profile arm), `gateway/src/proto.rs` (`account_unbound`),
`gateway/src/lib.rs` (`pub mod oauth`), `gateway/Cargo.toml` + `Cargo.lock`
(new deps), `gateway/tests/{http,mcp_contract,mcp_http,revocation_recheck}.rs`
(ordering/variant/Result-signature updates).

New: `gateway/src/oauth.rs`, `gateway/tests/oauth_http.rs`,
`gateway/tests/oauth_log.rs`.

Unchanged: all Sinter source, `sinter mcp`, tool definitions, prototype tree,
RFC docs, `opencode.json` (user-owned deletion preserved), all controller
routes.

## V. P7 readiness

P6 is ready for a dedicated **P6 OAUTH / PUBLIC IDENTITY SECURITY AUDIT** —
not performed here. Open items carried to P7 scope: F-03, F-06, F-08,
rate limiting, telemetry, abuse testing.

## Required security summary

| Question | Answer | Evidence |
|---|---|---|
| Can an unauthenticated public caller reach MCP? | **No** — every /mcp request re-authenticates; no-auth gateway → 503; no credential → 401 | `oauth_credential_matrix`, P5 fail-closed tests |
| Can test-auth exist in the production binary? | **No** — `cfg(test/feature)` gated; 0 occurrences of the header string in the default rlib | rlib scan, `with_oauth` is the only prod path |
| Can caller A impersonate account B? | **No** — account comes only from the validated claim; A-token + B-session → 403; A can't reach B's controller | `oauth_cross_account_isolation` |
| Can a session ID replace OAuth? | **No** — session + no/expired token → 401 | `oauth_expired_token_does_not_ride_session` |
| Can issuer X's token pass as issuer Y? | **No** — `iss` exact-match; wrong-iss → 401 | credential matrix |
| Can a token for another audience pass? | **No** — `aud` exact-match → 401 | credential matrix |
| Can an attacker choose the JWKS source? | **No** — `jwks_uri` is configured; `jku`/`x5u` ignored | design + `oauth_jwks_rotation_and_malformed` |
| Can metadata fetching reach private/local addresses? | **No** — HTTPS-only except loopback IP literals; no redirects; metadata/RFC1918 rejected | `oauth_uri_trust_policy` |
| Can public OAuth creds authorize /v1/poll or /v1/respond? | **No** → 401 | `oauth_auth_domains_disjoint` |
| Can controller creds authorize /mcp? | **No** → 401 | same test |
| Can OAuth change Sinter tool semantics? | **No** — frames forwarded verbatim; Sinter is sole tool authority | e2e + edge contract tests |
| Can OAuth make active MCP work durable? | **No** — work/sessions memory-only; nothing persisted | §N raw-scan + P5 restart tests |

---

SINTER GATEWAY P6: PASS
