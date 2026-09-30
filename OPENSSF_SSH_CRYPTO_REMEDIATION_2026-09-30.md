# SSH cryptographic defaults: remediation evidence (2026-09-30)

- **Implementer status:** REMEDIATED, pending independent verification.
- **Scope:** source-tree remediation of the SSH finding in `OPENSSF_BEST_PRACTICES_GAP_ASSESSMENT_2026-09-30.md` (recorded unchanged, SHA-256 `8176c56fd39593ca32d5d49ee9778a3c1b44db846cb9a300f30917b3e1628eb1`).
- **Release state:** the published **v1.1.1 is unchanged** and still has the old behaviour. No release, OpenSSF registration or online answer was made.

## Original blocker

The assessment found the only Passing MUST blockers to be `crypto_working` and `crypto_keylength`, plus the SHOULD `crypto_weaknesses`. The cause was that Sinter set only the SSH **host-key** preference; key exchange, ciphers and MACs were left to the bundled libssh2's defaults.

## SSH contract before the fix (re-verified, not taken from the assessment)

| Item | Finding |
|---|---|
| SSH library | `ssh2` 0.9.6 → `libssh2-sys` 0.3.3 (bundled libssh2 1.11.1_DEV), linked against the system OpenSSL 3 |
| Session setup | `src/executor.rs` `SshExecutor::connect`: `Session::new`, `set_tcp_stream`, host-key preference, timeout, `handshake`, `verify_host_key`, authentication |
| Host key | reorders the whole libssh2-supported list (known types first). Left the default order untouched when nothing was known. `ssh-rsa` (SHA-1 signature) and certificate types were still offered |
| KEX / cipher / MAC | **not configured**, so libssh2 defaults applied |
| Compression | the build supports only `none`; not a factor |

Supported by the linked libssh2 (`Session::supported_algs`, measured):
- **KEX:** curve25519-sha256(+@libssh.org), ecdh-sha2-nistp256/384/521, dh-gex-sha256, dh-group16/18-sha512, dh-group14-sha256, **dh-group14-sha1, dh-group1-sha1, dh-gex-sha1**, `ext-info-c`, `kex-strict-c-v00@openssh.com`.
- **Host key:** ecdsa-sha2-*, ssh-ed25519, rsa-sha2-512/256, **ssh-rsa**, plus `-cert-v01` variants.
- **Ciphers:** chacha20-poly1305, aes256/128-gcm, aes256/192/128-ctr, **aes256/192/128-cbc, rijndael-cbc, blowfish-cbc, arcfour128, arcfour, cast128-cbc, 3des-cbc**.
- **MACs:** hmac-sha2-256/512(+etm), **hmac-sha1(+etm, -96), hmac-md5(-96), hmac-ripemd160(+@openssh.com)**.

**The weak fallback was reachable.** It was measured with the existing throwaway-`sshd` lab (`tests/ssh_keys.rs`, OpenSSH 10.3p1, loopback, unprivileged), with the server restricted to exactly one legacy algorithm, against the **unmodified** executor:

| Server offers only | Before the fix |
|---|---|
| kex `diffie-hellman-group1-sha1` (1024-bit) | **session established** |
| kex `diffie-hellman-group14-sha1` | **session established** |
| kex `diffie-hellman-group-exchange-sha1` | **session established** |
| cipher `3des-cbc` | **session established** |
| cipher `aes256-cbc` | **session established** |
| MAC `hmac-md5` (with `aes128-ctr`) | **session established** |
| MAC `hmac-sha1` (with `aes128-ctr`) | **session established** |
| host key `ssh-rsa` (SHA-1 signature) | **session established** |

RC4, Blowfish and CAST could not be exercised: OpenSSH 10.3 no longer implements them.

## Policy after the fix (`src/executor.rs`)

Every negotiated category gets a positive allowlist, installed with `Session::method_pref` before the handshake:

| Category | Allowed (in preference order) |
|---|---|
| KEX | curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521, diffie-hellman-group-exchange-sha256, diffie-hellman-group16-sha512, diffie-hellman-group18-sha512, diffie-hellman-group14-sha256 |
| Host key | ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-ed25519, rsa-sha2-512, rsa-sha2-256 (key types already in known_hosts are moved first) |
| Cipher (both directions) | chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com, aes256-ctr, aes192-ctr, aes128-ctr |
| MAC (both directions) | hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com, hmac-sha2-256, hmac-sha2-512 |

Design notes:
- **KEX extensions.** libssh2 1.11 prepends `ext-info-c,kex-strict-c-v00@openssh.com` to any KEX preference (`libssh2_session_method_pref`, verified in the pinned source). So the Terrapin countermeasure (strict KEX) and `ext-info-c` stay enabled; `ext-info-c` is needed for RSA user-key authentication with rsa-sha2.
- **Group exchange.** The pinned libssh2 requests at least 2048-bit groups (`LIBSSH2_DH_GEX_MINGROUP 2048`).
- **SHA-1, per category.**
  - KEX `*-sha1` is excluded: a SHA-1 exchange hash, and `group1` is 1024-bit.
  - The `ssh-rsa` host-key signature is excluded because it is SHA-1. RSA host keys still work through rsa-sha2-512/256.
  - `hmac-sha1` is excluded. HMAC-SHA1 is not known to be broken, but it is SHA-1-based and not needed: every supported target offers HMAC-SHA2 or AEAD ciphers.
- **Certificates.** Host-certificate types are not offered: known_hosts verification (no `@cert-authority` support) cannot validate them.
- **Fail-closed.** Any `method_pref` error aborts the connection with `cannot apply the SSH <category> algorithm policy: …`. There is no fallback to libssh2 defaults.
- **Silent drops.** libssh2 silently drops unknown names, so a unit test requires every allowlisted name to be supported by the linked build.
- **No override.** No user-facing option, environment variable or configuration re-enables legacy algorithms.
- **Unchanged:** host-key *verification* (`verify_host_key`, `@revoked`, portless and alias rules), authentication, timeouts, network behaviour and logging.

## Tests

**Unit tests** (`src/executor.rs`). Per-commit CI only builds them (`cargo test --no-run`, Option C); they run with `cargo test` locally and in the release gate:
- `known_types_are_preferred_within_the_allowlist`: RSA → rsa-sha2-*, never `ssh-rsa`; the allowlist order when nothing or an unsupported type is known.
- `ssh_policy_lists_are_well_formed`: non-empty, no duplicates, no separators in names.
- `ssh_policy_matches_the_linked_libssh2`: every allowed name is supported; every supported name that is not allowed is a known legacy exclusion. This catches both silent drops and modern algorithms lost by accident.
- `ssh_policy_excludes_legacy_and_keeps_modern_algorithms`
- `ssh_policy_installs_on_a_session`: formatting accepted by libssh2.
- `ssh_policy_failure_is_an_error`: fail-closed.

**Negotiation tests** (`tests/ssh_keys.rs`, opt-in `SINTER_TEST_LOCAL_SSHD=1`). The v1.1.1 gate harness set this variable (its gate log shows `SINTER_TEST_LOCAL_SSHD=1` and `Running tests/ssh_keys.rs`); RELEASE.md itself does not require it:
- `server_offering_only_legacy_algorithms_is_refused`: all 8 cases above.
- `server_offering_only_modern_algorithms_is_accepted`: curve25519 + chacha20-poly1305; dh-group14-sha256 + aes128-ctr + hmac-sha2-256; an RSA host key via rsa-sha2-512.

**After the fix** (same lab, macOS host, OpenSSH 10.3p1):
- all 8 legacy-only servers were **refused at the handshake**, before authentication: `Unable to exchange encryption keys`;
- all 3 modern-only servers were accepted;
- the 6 pre-existing tests still pass (key formats including RSA user keys, agent, mismatch, unknown host, portless, `@revoked`, hashed entries, HostKeyAlias).

**Validation** (macOS, cargo 1.98.1):

| Command | Result |
|---|---|
| `cargo fmt --check` | pass |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | pass |
| `cargo test --locked --all-targets --all-features` | 24 harnesses, 620 passed, 0 failed (Linux-only suites compile to zero on macOS) |
| `SINTER_TEST_LOCAL_SSHD=1 cargo test --locked --test ssh_keys` | 8 passed |
| `cargo test --locked --all-targets --all-features --no-run` | 24 executables |
| `python3 -m unittest discover -s release/tests` | pass |
| `cargo fmt --manifest-path gateway/Cargo.toml --check` | pass |
| `git diff --check` | clean |

## Interoperability

- The supported targets (README §Supported platforms) are Ubuntu 24.04/26.04 and Rocky/RHEL/AlmaLinux 9/10.
- Their OpenSSH servers are 8.7 or later. In their default configurations these offer, from each allowed category, at least curve25519 or ECDH, AES-GCM/CTR and HMAC-SHA2, and Ed25519, ECDSA or rsa-sha2 host keys. This comes from the OpenSSH versions shipped on those platforms and **was not measured here**.
- **Ubuntu and Rocky real-target runs: UNVERIFIED.** No VM was started: the acceptance fleet is stopped, and starting it needs authorization.
- They are verified by the **release gate** (RELEASE.md step 4's root `cargo test` on Linux x86_64; the negotiation tests run there when the gate harness sets `SINTER_TEST_LOCAL_SSHD=1`, as the v1.1.1 harness did) and by the **8-target acceptance** (steps 7–9, real SSH to every supported platform).

## OpenSSF Passing mapping (no registration)

| Criterion | Previous state | Post-remediation | Evidence | Release dependency |
|---|---|---|---|---|
| `crypto_working` (MUST) | PARTIAL: MD5, RC4, CBC and 3DES fallbacks enabled by default | **SOURCE REMEDIATED** | allowlists; legacy-only servers refused (negotiation tests) | **RELEASE PENDING**: v1.1.1 unchanged |
| `crypto_keylength` (MUST) | PARTIAL: 1024-bit DH offered, no way to disable | **SOURCE REMEDIATED**: 1024-bit and SHA-1 KEX are never offered; group exchange needs at least 2048 bits | same | **RELEASE PENDING** |
| `crypto_weaknesses` (SHOULD) | NOT SATISFIED: SHA-1 and SSH CBC offered | **SOURCE REMEDIATED** | same | **RELEASE PENDING** |

**Readiness:**
- source tree: remediated;
- next release: pending, and it must pass the release gate and 8-target acceptance;
- published v1.1.1: unchanged;
- registration: **WAIT**.

**Independent closure: NO.**

## Remaining

- An independent audit of this hardening before the next release.
- Release-time interoperability evidence on real Ubuntu and Rocky/RHEL/Alma targets (release gate + acceptance). Make sure the next gate run sets `SINTER_TEST_LOCAL_SSHD=1` so the negotiation tests execute on Linux.
- At release: README security properties (EN/JA) and a docs-site troubleshooting entry for `Unable to exchange encryption keys`. These are not updated now, because README and the docs site describe the released v1.1.1.
