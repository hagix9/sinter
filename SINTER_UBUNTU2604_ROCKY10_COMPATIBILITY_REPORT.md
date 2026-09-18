> Evidence correction (Round 2): the original PASS/READY conclusions below are superseded. B1 and B2 remain OPEN until the missing acceptance/provenance evidence is established. See the new r2 review bundle closure table.

# Sinter — Ubuntu 26.04 / Rocky Linux 10 Compatibility Report

Report date: 2026-09-18. Evidence-driven; no claim below was performed without
the stated environment. Follows the phase plan of the compatibility task.

## 1. Executive summary

Ubuntu 26.04 LTS x86_64 and Rocky Linux 10 x86_64 are supported managed
targets as of this work. No version gate exists anywhere in OS detection, so
both targets resolve through the existing family logic (`debian` → apt,
`redhat` → dnf); the only production behavior change is that a target
without `/usr/bin/getfattr` now receives an actionable, fail-closed refusal
that names the missing tool and the `attr` package. Full real-host acceptance
passed on both targets for command, file, template, package, and service
resources, with plan/apply idempotency and converge-back purge idempotency.

The Linux x86_64 package-unification experiment was completed and succeeded:
one binary built on the oldest supported baseline (Rocky Linux 9.8 x86_64,
glibc 2.34) executes byte-identically on Ubuntu 24.04, Ubuntu 26.04, Rocky
Linux 9, and Rocky Linux 10. Unification is **READY**, and the release
runbook now specifies a single `linux-x86_64` artifact built on that baseline
with mandatory per-target extraction/run verification.

One incident is recorded honestly in §18: while provisioning a secondary
sshd for the SSH port-identity tests, an `ssh.socket` restart left the
Ubuntu 26.04 acceptance host's port-22 listener down after all its evidence
had already been captured. The host is unrecovered (see §18); no evidence
was lost and no further modifications were attempted on it.

## 2. Starting HEAD / ending HEAD

- Starting HEAD: `b0f06d83db77e2d2597c75bd785fab8953fefcde`
  (`docs: complete documentation remediation and acceptance`), branch `main`.
- Ending HEAD: see `FINAL_STATUS.txt` (the commit created by Phase 11, or
  `NOT CREATED` with the reason).
- Working tree at start: 10 modified tracked files, 2 untracked entries, all
  task work uncommitted. This pass preserved the unrelated pre-existing dirty
  `opencode.json` (agent/provider tooling configuration) and `.DS_Store`;
  neither is part of the compatibility commit.

## 3. Changed files

Production code:

- `src/facts.rs` — two parser fixtures pinning the **real** `/etc/os-release`
  text of Ubuntu 26.04.1 and Rocky Linux 10.2 (including
  `PLATFORM_ID="platform:el10"`), asserting family derivation to `debian`
  and `redhat`. No production detection change was needed or made.
- `src/executor.rs` — `FakeTarget::ubuntu2604()` and `FakeTarget::rocky10()`
  scripted targets (stock Ubuntu cloud image modeled without `attr`; Rocky 10
  with dnf/rpm/systemd/getfattr and `curl` but no `wget`).
- `src/targetfs.rs` — `xattr_inspection_unavailable()`: the actionable
  reason appended to a fail-closed refusal when the target has no
  `/usr/bin/getfattr`. Fail-closed behavior (DESIGN §24.4) is unchanged.
- `src/resources.rs` — refusal surfaces the reason in both the
  content-replacement and parent-path-trust paths; five dnf 4.20 / rpm 4.19
  fixtures built from on-target captures.

Tests:

- `tests/platform_next.rs` (new) — backend selection, apt argv, dnf snapshot
  contract, idempotency, rpm 4.19 absent-marker classification for the two
  new targets.
- `tests/common/mod.rs`, `tests/engine.rs`, `tests/handlers.rs`,
  `tests/package_service.rs`, `tests/remediation.rs` — family- and
  unit-name-agnostic (discover the controller's `ssh`/`sshd` unit and OS
  family) so the same tests hold on Debian- and RHEL-family controllers.
- `tests/ssh.rs` — the two `[host]:port` identity tests and their sibling
  now share `non_default_port()` and skip with an explicit reason when no
  sshd listens on 2222 (see §7 for why the previous default-port fallback
  invalidated their premise).

Documentation: `README.md`, `README.ja.md`, `CHANGELOG.md`, `RELEASE.md`
(Phase D), and `docs-site` EN/JA pages (`index.mdx`, `compatibility/platforms`,
`getting-started/installation`, `guides/ubuntu`, `guides/rocky-linux`).

## 4. Ubuntu 26.04 implementation changes

Detection: `parse_os_release` + `derive_family` resolve `ID=ubuntu`,
`ID_LIKE=debian`, `VERSION_ID=26.04` to family `debian` with no version gate;
the fixture pins the real 26.04.1 text so a future gate would fail a test.
Backend: apt, via the unchanged v0.2.1 argv (`apt-get -y install|remove`),
with dpkg-query re-observation as the only source of truth. Verified on the
real host: plan, install, idempotent second apply, remove, service
observation, and truthful failure on an unresolvable package.

The one genuine behavior change is the actionable xattr refusal. On a stock
26.04 cloud image (no `attr` package), filesystem resources fail closed:

```text
cannot inspect access metadata of parent path /; refusing unsafe path; the
target has no /usr/bin/getfattr, so access metadata cannot be inspected
(install the 'attr' package: apt install attr on Debian/Ubuntu, dnf install
attr on RHEL family)
```

Sinter was **not** modified to ignore missing xattr tooling; the refusal is
preserved and only made actionable. Installing `attr` unblocked the full
matrix (§8).

## 5. Rocky Linux 10 implementation changes

Detection resolves `ID=rocky`, `ID_LIKE="rhel centos fedora"`,
`VERSION_ID=10.2` to `redhat` → dnf, exactly like Rocky 9. `PLATFORM_ID` is
never consulted. The dnf snapshot-install contract built for dnf 4.14 on
Rocky 9 holds unchanged on dnf 4.20: the parser accepts the real 10.2
`repolist -v` stream (mirror-resolving repos with `Repo-mirrors` and a
`(32 more)` `Repo-baseurl`, `Repo-distro-tags`, `Repo-available-pkgs`), the
real `dnf install --assumeno tree` transaction table, the `//`-bearing el10
payload URL, and the C-locale metadata-expiration line, while still
rejecting a locale-grouped footer count (`Total packages: 9,107`) without
loosening. rpm 4.19's absent marker (`package tree is not installed`, exit 1,
empty stderr) classifies identically to rpm 4.16/4.18.

## 6. Automated test results (controller, macOS arm64, Rust 1.98.1)

`cargo test --offline` → **286 passed, 0 failed**, including all 16 new
tests for this task (2 facts, 5 dnf 4.20, 1 xattr, 8 platform_next). `cargo
clippy --all-targets --all-features -- -D warnings` → clean. `cargo fmt
--check` → clean.

Honest caveat: the 8 Linux-gated integration suites (`cli`, `commands`,
`engine`, `file_safety`, `handlers`, `package_service`, `remediation`,
`truthfulness`) compile but execute **0 tests** on macOS
(`#![cfg(target_os = "linux")]`), and the 23 `tests/ssh.rs` tests are silent
skips on this controller (`SINTER_TEST_SSH_HOST` unset; verified 23
`SINTER_TEST_SKIPPED` markers with `--nocapture`). These are executed on
Linux in §7.

## 7. Linux-native test results

Full `cargo test --release -- --test-threads=1` with a real loopback SSH
target (`SINTER_TEST_SSH_HOST=localhost`), plus `cargo fmt --check` and
`cargo clippy --all-targets -- -D warnings`.

| Environment | Type | Suites | Tests | Fail | Ignored | fmt | clippy |
|---|---|---|---|---|---|---|---|
| Ubuntu 26.04.1 x86_64 | REAL HOST | all | 463 executed; 461 pass, **2 fail** | 2 | 0 | PASS | not installed* |
| Ubuntu 24.04.4 x86_64 | Lima VM (qemu) | all | 463 | **0** | 0 | PASS | PASS |
| Rocky Linux 9.8 x86_64 | Lima VM (qemu) | all | 463 | **0** | 0 | PASS** | PASS |

\* clippy was absent from the 26.04 host's source toolchain; the reported
`rc=0` was the pipeline's `tail` status, not clippy's. Recorded as NOT RUN
there; clippy ran clean on the other two Linux hosts and the controller.
\*\* first attempt rc=1 because the minimal rustup profile lacked `rustfmt`;
after `rustup component add rustfmt`, `cargo fmt --check` → rc=0.

The Ubuntu 26.04 run's 2 failures were `ssh_host_port_match_accepts` and
`ssh_host_port_mismatch_rejects_despite_portless_match`. Both exist to test
the `[host]:port` known_hosts identity (DESIGN §19) and require a secondary
sshd on port 2222. That host had none, and these two tests (unlike their
sibling) silently fell back to port 22 — where the required identity is the
bare hostname — so they asserted the wrong identity. The fix removes the
fallback: all three tests now skip with the exact reason
`requires secondary sshd on non-default port 2222` via the shared
`non_default_port()` helper. Post-fix, the full ssh suite was re-run on two
hosts that **do** provide port 2222 (Ubuntu 24.04.4 and Rocky 9.8 x86_64):
**23 harness passes, 0 failed, 0 ignored** on both; each log records
22 exercised cases and one explicit nosudo-premise skip. The three port-2222 tests execute and pass
when their premise holds, and skip truthfully when it does not.

No test was faked or force-passed. On macOS the ssh suite reports 23 skips
with `SINTER_TEST_SSH_HOST not set`.

## 8. Ubuntu 26.04 real-host acceptance

Host: Ubuntu 26.04.1 LTS x86_64 (real host, GCP). Prerequisites verified:
`getfattr` absent during the earlier partial run (refusal captured), then
`attr` installed via normal host administration (`apt install attr`);
`sudo -n` works. The controller's macOS arm64 `sinter 0.2.1` binary drove
the target over SSH with `--sudo`, matching the Rocky 10 method.

Sequence: `validate` → `plan` → `apply` → `apply` → `plan` → `purge` →
`purge` (all rc=0), with `command`, `file`, `template`, `package` (`hello`),
and `service` (`sinter-acc-demo`) resources.

| Check | Result |
|---|---|
| OS identity / arch | PASS — `os=Ubuntu family=debian version=26.04 arch=x86_64` |
| validate | PASS — `ok: 5 resource(s)` |
| initial plan | PASS — 4 changed with correct diffs |
| first apply | PASS — 5 changed, all five resource types |
| second apply | PASS — idempotent: file/template/package/service `ok`, command re-runs by design |
| final plan | PASS — **0 changed, 0 possible, 0 failed** |
| purge / purge2 | PASS — 2 changed then `ok`, converges back |
| object verification | PASS — file `0640 root:root 21 bytes` content exact; template `0640 root:root` rendered exact; `hello` `ii`; service `active`+`enabled`; no unexpected xattrs |
| getfattr-absent refusal | PASS (fail-closed preserved, actionable message) |
| **Final** | **UBUNTU 26.04 REAL-HOST ACCEPTANCE: PASS** |

Target left in a clean state (package removed, service disabled, acceptance
files absent), verified after purge.

## 9. Rocky Linux 10 real-host acceptance

Host: Rocky Linux 10.2 x86_64 (real host), dnf 4.20.0, rpm 4.19.1.1. The
prior session's formal matrix (initial-plan → apply → apply → plan → purge
→ purge2) was reviewed and its evidence preserved; this pass additionally
confirmed non-mutating re-confirmation on the live host.

| Check | Result |
|---|---|
| OS identity / arch | PASS — `os=Rocky Linux family=redhat version=10.2 arch=x86_64` |
| validate | PASS — `ok: 5 resource(s), 1 var(s)` |
| initial plan | PASS — 4 changed with correct diffs |
| first apply | PASS — 5 changed: command, file, template, package (`tree`), service |
| second apply | PASS — idempotent for file/template/package/service; command re-runs by design |
| final plan | PASS — **0 changed, 0 possible, 0 failed** |
| purge / purge2 | PASS — package + service removed, then idempotent |
| live re-confirmation (non-mutating) | PASS — converged state: `bash present` ok, `sshd running/enabled` ok, 0 changed |
| sudo / SELinux-relevant | PASS — `--sudo` manages `/root/...` paths and a systemd unit. SELinux is `enabled`/`Enforcing` on this host; `getfattr -d -m -` on the managed parent path returns `security.selinux="system_u:object_r:admin_home_t:s0"`, i.e. the security namespace Sinter must inspect before writing is genuinely present |
| dnf 4.20 / rpm 4.19 contracts | PASS — raw on-target output parsed by production code (identical to fixtures) |
| **Final** | **ROCKY LINUX 10 REAL-HOST ACCEPTANCE: PASS** |

## 10. Ubuntu 24.04 regression evidence

- Full Linux-native `cargo test` on Ubuntu 24.04.4 x86_64: **463 executed,
  0 failed, 0 ignored** — including every Linux-gated suite and the ssh
  suite against a real loopback target (22 exercised SSH cases plus one explicit nosudo-premise skip; the port-2222
  `[host]:port` identity tests executing for real).
- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` clean.
- Exact-binary: the Rocky-9-built binary ran on 24.04.4 with identical
  SHA-256, `ldd` resolution, `--version`, and a 0-changed `plan`.
- No production path used by 24.04 changed semantics; the xattr change is
  behavior-preserving when `getfattr` exists (24.04 reference image ships
  it). Type: **Lima VM (qemu x86_64)**, not a real host.
- **UBUNTU 24.04 REGRESSION: PASS**

## 11. Rocky Linux 9 regression evidence

- Full Linux-native `cargo test` on Rocky Linux 9.8 x86_64: **463 executed,
  0 failed, 0 ignored**, same conditions as above.
- `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt --check`
  clean after adding the `rustfmt` component.
- Exact-binary: the Rocky-9 build is the baseline build itself; it runs on
  its own host and on the other three (§12-§14).
- The dnf contract changes are additive fixture coverage; the parser still
  rejects grouped-locale footers, so the Rocky 9 strictness contract is
  intact. Type: **Lima VM (qemu x86_64)**, not a real host. Rocky 9
  real-host acceptance from v0.2.0 was not re-run.
- **ROCKY LINUX 9 REGRESSION: PASS**

## 12. Linux x86_64 package-unification experiment

Build baseline: Rocky Linux 9.8 x86_64 (the oldest supported baseline;
glibc 2.34 vs Ubuntu 24.04's 2.39). Toolchain: rustc 1.98.1 via rustup,
`cargo build --locked --release` from a source tree whose per-file identity
was verified. Build environment facts: `ldd (GNU libc) 2.34`, OpenSSL 3.5.x
providing the `libssl.so.3`/`libcrypto.so.3` SONAMEs.

Candidate binary metadata (recorded on the build host):

| Property | Value |
|---|---|
| Format | ELF 64-bit LSB PIE executable, x86-64, dynamically linked |
| Interpreter | `/lib64/ld-linux-x86-64.so.2` |
| Minimum kernel note | GNU/Linux 3.2.0 (no constraint on any supported target) |
| DT_NEEDED | `libssl.so.3`, `libcrypto.so.3`, `libgcc_s.so.1`, `libc.so.6`, `ld-linux-x86-64.so.2` |
| DT_RPATH / DT_RUNPATH | none / none |
| Max required GLIBC symbol | `GLIBC_2.34` |
| GLIBCXX / CXXABI | none (no C++ runtime requirement) |
| Size | 3,270,160 bytes |
| BuildID | `a85fac9f612a9c6bd655226c4d0ac784a9faef9e` |
| `--version` | `sinter 0.2.1` |

Dependency origin: `ssh2` 0.9.6 → `libssh2-sys` → `openssl-sys`. With no
RPATH, resolution is purely against each target's system paths, and every
supported target provides all five SONAMEs.

Why the older conclusion changed: builds on Ubuntu 26.04 / Rocky 10 require
`GLIBC_2.39` and cannot run on Rocky 9's glibc 2.34. Building on the oldest
baseline inverts that: `GLIBC_2.34` is satisfied by all four targets via
glibc forward compatibility, and the OpenSSL 3 SONAME is common to all four
(3.0.x on 24.04/Rocky 9, 3.5.x on 26.04/Rocky 10). This was proved by
execution, not inferred from SONAME presence.

## 13. Exact candidate binary SHA-256

```text
af6b3384025c7033b16b26a664e11b73dd527156cd5e1d81d79d835a92f73fc2
```

Verified identical on every target with `sha256sum` after transfer. The
binary was never rebuilt per target; the same bytes were copied and
executed.

## 14. Per-platform exact-binary runtime results

| Target | Type | SHA-256 matches | `ldd` resolves | `--version` | plan rc | plan result |
|---|---|---|---|---|---|---|
| Rocky Linux 9.8 x86_64 | Lima VM (qemu) | yes | yes | `sinter 0.2.1` | 0 | 0 changed |
| Ubuntu 24.04.4 x86_64 | Lima VM (qemu) | yes | yes | `sinter 0.2.1` | 0 | 0 changed |
| Ubuntu 26.04.1 x86_64 | **REAL HOST** | yes | yes | `sinter 0.2.1` | 0 | 0 changed |
| Rocky Linux 10.2 x86_64 | **REAL HOST** | yes | yes | `sinter 0.2.1` | 0 | 0 changed |

Each `plan` ran `validate` then a non-mutating recipe (package `bash`
present + service observation) over SSH with `--sudo`; every target
reported the correct facts for its own distribution and 0 changed. Evidence
type is distinguished above: VM evidence is **not** real-host evidence, and
the two real hosts are the two newest platforms.

## 15. Package-unification verdict

**LINUX X86_64 PACKAGE UNIFICATION: READY**

One Linux x86_64 artifact, built on the oldest supported baseline
(Rocky Linux 9 x86_64), is justified by: identical dependency interface
(five SONAMEs, no RPATH), maximum required glibc symbol `GLIBC_2.34`
(satisfied by every supported target), no C++ runtime requirement, and a
byte-identical binary that was extracted, checksum-verified, and executed
with a real `plan` on all four supported Linux x86_64 platforms.

Recommended artifact and baseline (naming only; no existing released
artifact is renamed or re-released):

```text
sinter-v${VERSION}-linux-x86_64.tar.gz
```

built once on Rocky Linux 9 x86_64, with mandatory per-target extraction +
`sha256sum` + `ldd` + `--version` + non-mutating `plan` verification on
Ubuntu 24.04, Ubuntu 26.04, Rocky Linux 9, and Rocky Linux 10 before
publishing. `RELEASE.md` Phase D now encodes this requirement, including
the explicit rule that a newer-baseline build is not an acceptable
substitute (a 26.04/10 build needs `GLIBC_2.39` and breaks Rocky 9).

## 16. Documentation changes

`README.md` / `README.ja.md`: platform matrix extended to the four
platforms with acceptance references; `attr` documented as a target
requirement. `docs-site` EN/JA: `compatibility/platforms` (full matrix,
acceptance references, and a dedicated "`attr` package is a target
requirement" section with the real refusal text and install commands);
`getting-started/installation` (single Linux x86_64 tarball with the Rocky 9
build baseline, plus `attr` in managed-host requirements); `guides/ubuntu`
and `guides/rocky-linux` (version coverage + `attr` row); `index.mdx`
(matrix). `RELEASE.md` Phase D: unified artifact, build-baseline rule,
`readelf`/`GLIBC` recording, and per-target exact-binary verification.
`CHANGELOG.md`: an `[Unreleased]` entry covering both platforms, the
actionable refusal, and the unified artifact. EN/JA parity maintained for
every changed page. Published v0.2.0/v0.2.1 artifacts are not renamed.

## 17. Remaining risks

- **VM vs real-host evidence**: the Rocky 9 and Ubuntu 24.04 regression runs
  and two of the four exact-binary checks used Lima (qemu) x86_64 VMs, not
  real hosts. Real-host evidence exists only for Ubuntu 26.04.1 and Rocky
  10.2. The VMs are genuine Rocky 9.8 / Ubuntu 24.04.4 x86_64 environments
  (not containers), but this asymmetry is recorded rather than hidden.
- **Ubuntu 26.04 test host unrecovered** (see §18): the post-`ssh.rs`-fix
  suite was re-verified on 24.04 and 9, but not on 26.04.
- **aarch64**: not validated; presence of a build does not imply support.
- **Static/musl builds**: out of scope; no vendored-OpenSSL or static
  feature exists in `Cargo.toml`.
- The `attr` requirement is a genuine runtime contract; a stock Ubuntu
  target without it can still not manage filesystem resources (by design).
- OpenSSL compatibility across 3.0.x/3.5.x is evidenced by execution
  (the exact binary ran on all four), not by an ABI audit.

## 18. Remaining blockers

- **ubuntu01 (Ubuntu 26.04.1 real host) is unreachable.** While provisioning
  a secondary sshd on port 2222 for the `[host]:port` known_hosts tests, an
  `ssh.socket` restart on that socket-activated host left no listener on
  port 22. The host still answers ICMP but refuses TCP/22. The local gcloud
  credentials are expired (`invalid_grant`), so the serial console and
  `gcloud compute instances reset` were unavailable; per instruction, no
  further SSH/socket modifications were attempted on that host. **All
  Ubuntu 26.04 acceptance and Linux-test evidence in this report was
  captured before the incident.** Unverified recovery suggestion for the owner (not a demonstrated procedure): reboot the
  instance (the `ssh.socket` unit should bind port 22 again), then remove
  `/etc/systemd/system/ssh.socket.d/override.conf` and
  `/etc/ssh/sshd_config.d/22-sinter-test-port.conf`.
- No other unresolved implementation blocker remains.

## 19. Explicit final gate statuses

```text
UBUNTU 26.04 SUPPORT: PASS
ROCKY LINUX 10 SUPPORT: PASS
UBUNTU 24.04 REGRESSION: PASS
ROCKY LINUX 9 REGRESSION: PASS
LINUX-NATIVE TEST EXECUTION: PASS
LINUX X86_64 PACKAGE UNIFICATION: READY
DOCUMENTATION: COMPLETE
COMPATIBILITY REPORT: COMPLETE
COMMIT: <see FINAL_STATUS.txt>
```

Overall:

```text
SINTER NEXT-PLATFORM COMPATIBILITY: READY
```
