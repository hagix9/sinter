# Sinter Gateway F-01 / F-07 Remediation Report

**Date:** 2026-09-22  
**Baseline audit:** `SINTER_GATEWAY_P1_P5_INTEGRATED_AUDIT_REPORT.md` (NO-GO)  
**Scope:** close P6-blocking findings F-01 and F-07 only

---

## F-01 — TestPublicAuth production containment (HIGH)

**Root cause:** `TestPublicAuth` was production-compiled (`pub`, no `#[cfg]`),
re-exported from `lib.rs`, and attachable via `GatewayHttp::with_public_auth`.
A production `main()` could enable `X-Sinter-Test-Principal` header auth.

**Fix:**
- `TestPublicAuth` and its `PublicAuth` impl are now behind
  `#[cfg(any(test, feature = "test-auth"))]`.
- `lib.rs` re-export is gated the same way.
- Cargo feature `test-auth` is **opt-in** (not in `default`).
- Integration tests that need it (`mcp_http`, `mcp_log`) declare
  `required-features = ["test-auth"]`.
- Quality gates run with `--all-features`, so the suite still exercises it.

**Evidence:**
- Production consumer (`sinter-gateway` without `test-auth`) fails to compile
  on `sinter_gateway::TestPublicAuth` — rustc: *item was gated here*.
- `cargo check --lib` (no features) succeeds; type is absent from the API.
- Regression: `tests/revocation_recheck.rs::test_public_auth_requires_feature_and_default_fails_closed`
  - constructs `TestPublicAuth` under the feature
  - proves default `GatewayHttp` (no `PublicAuth`) fails closed with **503** on `/mcp`

**Verdict:** CLOSED

---

## F-07 — Revocation re-check (mid-poll / respond gap) (MEDIUM, P6 blocker)

**Root cause:**
1. HTTP `poll` authenticated once, then blocked in `poll_wait`. A revoke during
   the wait did not stop delivery of post-revocation work.
2. `core.respond` / `poll_locked` never re-checked controller status after the
   initial authenticate.

**Fix:**
- `ControllerAuth::ensure_active(controller_id)` re-reads store status and
  returns `revoked_controller` / `unknown_controller`.
- `GatewayCore::poll_wait` takes `still_authorised: impl FnMut() -> Result<(), TransportError>`
  and invokes it **immediately before** marking work `Delivered`. On failure the
  item is pushed back on the queue and the poll returns that error (not the work).
- HTTP `poll` wires `ensure_active` into `poll_wait`.
- HTTP `respond` calls `ensure_active` again after body parse (TOCTOU close).

**Evidence (regression tests in `tests/revocation_recheck.rs`):**
| Test | Proves |
|---|---|
| `ensure_active_rejects_revoked_controller` | store re-check returns `revoked_controller` |
| `poll_wait_refuses_delivery_after_revocation` | mid-wait revoke → no delivery; work stays queued |
| `http_rejects_respond_after_revocation` | HTTP respond + poll after revoke → 401 `revoked_controller` |
| `test_public_auth_requires_feature_and_default_fails_closed` | F-01 fail-closed default |

**Verdict:** CLOSED

---

## Non-blocking findings (unchanged)

| ID | Severity | Status |
|---|---|---|
| F-03 `core.cancel` lacks ownership | MEDIUM | open (defense-in-depth; not P6 blocker) |
| F-06 duplicate JSON-RPC id overwrite | LOW | open |
| F-08 `active_polls` not RAII | LOW | open |

---

## Quality gates

| Gate | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS |
| `cargo test --all-targets --all-features` | PASS — 118 tests, 0 fail |
| Production build without `test-auth` | PASS — `TestPublicAuth` not linkable |
| Sinter repo (HEAD `66ca3d7`) | untouched |

---

## Files changed (Gateway only)

- `Cargo.toml` — `test-auth` feature; `required-features` on `mcp_http`/`mcp_log`; `axum` dev-dep
- `src/lib.rs` — gated `TestPublicAuth` re-export
- `src/mcp.rs` — gated `TestPublicAuth`
- `src/auth.rs` — `ensure_active`
- `src/core.rs` — `poll_wait`/`poll_locked` authorization re-check
- `src/http.rs` — poll/respond wire `ensure_active`
- `tests/revocation_recheck.rs` — new regression suite

---

## P6 readiness

```
READY FOR P6 GATE RE-EVALUATION
```

F-01 and F-07 are closed with runtime regression evidence. F-03/F-06/F-08 remain
non-blocking. A follow-up integrated re-audit can flip the P1–P5 gate to GO.
