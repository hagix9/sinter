# Sinter Release Runbook

Operational procedure for cutting a Sinter release. Written so a human or a
coding agent can execute it top to bottom. Placeholders used throughout:

```sh
VERSION=0.4.0            # version being released (no "v" prefix)
TAG=v${VERSION}          # release tag
SOURCE_CANDIDATE=<full hash>  # reviewed implementation commit (step 1)
RC_COMMIT=<full hash>    # exact release-candidate commit (step 2)
```

`SOURCE_CANDIDATE` and `RC_COMMIT` must always be full 40-character commit
hashes, never a branch name or short ref.

## Release state machine

A release moves through these steps strictly in order. Each step consumes
only the outputs of earlier steps; no step feeds back into an earlier one.
A failed gate never "retries in place": it returns to the step named in its
STOP column, and every later output is discarded.

```text
 1. Source candidate fixed        SOURCE_CANDIDATE (clean, reviewed commit)
 2. Version / metadata prepared   RC_COMMIT = SOURCE_CANDIDATE + metadata-only commit;
                                  TIER_ASSESSMENT (Tier F or P, §Acceptance tier)
 3. Source validation             read-only checks on RC_COMMIT
 4. Linux validation gate         fmt / clippy / all tests / installer / checker on Linux x86_64
 5. Build artifact                one build from RC_COMMIT on Rocky Linux 9 x86_64
 6. Freeze artifact identity      filename, size, tarball SHA-256, executable SHA-256, SHA256SUMS
 7. Target acceptance             the same frozen artifact on every required target
                                  of the approved tier (Tier F: all 8 supported targets)
 8. Per-target hash re-check      tarball + executable SHA-256 observed on each target
 9. Raw logs                      one sanitized raw log per target
10. Evidence Manifest             generated from the recorded values
11. Evidence bundle               bundle archive + acceptance SHA256SUMS
12. Checker PASS                  release/check_acceptance_manifest.py (full mode)
12b. Docs commit D (local only)   D = RC_COMMIT + docs-only commit, checked locally, not pushed
13. Human review                  staged assets, notes, manifests, checker output, D
14. Tag                           annotated tag → RC_COMMIT, tag push only (main does not move)
15. GitHub Release                release created from the reviewed notes
16. Assets                        exactly the reviewed, staged files
17a. Post-publish read-back       download + checksum read-back, manifest copy in D == asset
17b. Docs commit to main          D on a work branch → CI + Start → non-force fast-forward of main
17c. Record                       CI, Start, advisories, docs deploy, site and /webmcp.json version
```

| Step | Allowed changes | Output | GO condition | STOP / return to |
|------|-----------------|--------|--------------|------------------|
| 1 | None (select commit) | `SOURCE_CANDIDATE` | Clean tree, reviewed, pushed | — |
| 2 | Version fields, `Cargo.lock`, `CHANGELOG.md`, README platform/version text only | `RC_COMMIT`, `TIER_ASSESSMENT.md` | Diff `SOURCE_CANDIDATE..RC_COMMIT` touches release metadata only; tier reviewed and approved by the Owner | Unexpected diff → redo 2; tier not approved → hold |
| 3 | None | Source validation report | All §3 checks pass | Any failure → 1 (remediation) or 2 |
| 4 | None | Linux gate log + recorded results | Every step PASS on the Ubuntu 24.04 x86_64 gate host (strict mode) | Any FAIL → 1; **no build, no acceptance** |
| 5 | Nothing in repo | Built executable | Baseline, ABI and provenance checks pass | Failure → 5, or 1 if source is wrong |
| 6 | Nothing in repo | Tarball, `SHA256SUMS`, frozen hashes | Fresh extraction reproduces the frozen executable hash | Mismatch → 5 |
| 7–9 | None (repository and artifact read-only) | Per-target results and raw logs | Every required target of the approved tier PASS with identical hashes (Tier F: all 8) | Any target FAIL or hash mismatch → NO-GO, return to 1 |
| 10–11 | Nothing in repo | Manifest, bundle, acceptance `SHA256SUMS` | Built only from recorded values | Missing value → 7 (re-run), never reconstruct |
| 12 | None | Checker output `OK … (verdict GO)` | Exit 0 | FAIL → fix sanitization/assembly (10–11) or return to 7; **no tag** |
| 12b | Creating the local docs commit `D` (parent `RC_COMMIT`, docs allow-list only); **not pushed** | `D`, local docs check log | Local docs checks pass; `D` touches only allow-listed paths | Failure → redo 12b (a new `D`) |
| 13 | None (`D` stays local) | Explicit human approval of the approval set `/3` | Reviewer approves the exact staged files and `D` | Any doubt → hold; `D` changed → new approval |
| 14–16 | Tag push + GitHub Release only; `main` is not pushed | Tag, release, assets | §Publish read-backs pass | Partial failure → §Partial publish failure |
| 17a | None | Read-back record | All read-backs match staging; the manifest copy in `D` equals the downloaded asset | Mismatch → incident, do not push `D`, do not force-fix |
| 17b | Push `D` to a work branch, then fast-forward `main` to `D` (no force) | `main` == `D` | Work-branch CI and Start environment pass; `origin/main` is an ancestor of `RC_COMMIT`; `D^ == RC_COMMIT` | §Failure and recovery after publication |
| 17c | None | Post-publish record | Results recorded | Failure → fix forward with a docs-only commit |

## Invalidation rules

These rules are absolute. They define when an output of the state machine
stops being valid.

- **No tag before acceptance.** Steps 14–16 require steps 7–13 to be
  complete for the same `RC_COMMIT` and the same frozen artifact.
- **No rebuild after freeze or tag.** The artifact frozen in step 6 is the
  only artifact that may be accepted and published. A rebuild — even from
  the same commit — produces a new candidate and restarts at step 5 with
  fresh acceptance.
- **Source, test, or build-input change invalidates the candidate.** Any
  change to `src/`, `tests/`, `Cargo.toml` dependencies, `Cargo.lock`
  (beyond the step-2 version line), the toolchain, or the build baseline
  after step 2 voids every later output. Restart at step 1.
- **Artifact hash change → redo acceptance.** If the tarball or executable
  SHA-256 differs from the step-6 values anywhere, all acceptance evidence
  for that candidate is void. Restart at step 5.
- **Linux gate FAIL → no build, no acceptance.** A macOS (or any non-Linux)
  PASS is never a substitute: Linux-only test suites are compiled out there
  and the installer tests need GNU userland.
- **Any target FAIL → no tag.** The verdict must be `GO` on every required
  target of the approved tier (Tier F: all 8). A Tier P release lists the
  targets it did not run as NOT RUN, never as PASS; NOT APPLICABLE is never
  counted as PASS.
- **No tier change without review.** The tier is the one approved at step 2.
  Tier P is never chosen automatically or as a fallback when Tier F
  acceptance fails or cannot run; a Tier P candidate that hits any T-1
  trigger becomes Tier F.
- **The docs commit `D` is bound to the approval.** Any change of `D` after
  the step-13 approval voids the approval. `D` is never pushed to a public
  branch before the Release exists.
- **Checker FAIL → no tag.** Steps 13–16 require the full-mode checker to
  pass on the exact staged manifest, bundle archive, artifact, and
  acceptance `SHA256SUMS`.
- **Evidence is complete before human review.** Manifest, bundle, and both
  checksum files exist and verify before step 13 begins.
- **Only reviewed bytes are published.** Steps 14–16 upload exactly the
  files the reviewer approved; their checksums are re-verified immediately
  before upload.
- **Never reconstruct evidence.** Missing or lost evidence means re-running
  the step that produces it, never recreating it from memory or summaries.

Real-target testing before step 1 (development or remediation acceptance)
is useful but is not release evidence: release evidence is always produced
in steps 7–12 from the frozen artifact of the current `RC_COMMIT`.

## Steps 1–2 — Source candidate and release preparation

Fix `SOURCE_CANDIDATE`: a clean, reviewed, pushed commit whose remediation
and audits are complete. Then prepare the candidate on top of it. Allowed
changes **only**:

- `Cargo.toml` version → `${VERSION}`
- `Cargo.lock` regenerated consistently (`cargo check`)
- `CHANGELOG.md` new version entry (follow existing section conventions;
  keep claims inside implemented + accepted scope)
- `README.md` / `README.ja.md` supported-platform and version statements
- Other strictly necessary release metadata

Forbidden: production logic, tests (unless a metadata check truly requires
it), unrelated refactors, unrelated dirty files.

The preparation commit must be the direct child of `SOURCE_CANDIDATE`; it
becomes `RC_COMMIT`. Recommended message:

```text
Prepare Sinter v${VERSION} release
```

Stage explicitly (`git add CHANGELOG.md Cargo.toml Cargo.lock README.md
README.ja.md`), never `git add .` / `-A`; verify with
`git diff --cached --name-only` before committing.

### Acceptance tier (Tier F / Tier P)

At step 2 the operator records the tier assessment with
`release/tier_assess.py` (stdlib only; it reads the repository, the last
release tag, the candidate executable, the reference Tier F manifest and an
answers file, and never overwrites an existing record):

```sh
python3 release/tier_assess.py --repo <repo> --last-tag v${PREV} \
  --source-candidate ${SOURCE_CANDIDATE} --executable <candidate sinter> \
  --answers tier-answers.json \
  [--reference-manifest <last Tier F manifest> --releases-since X.Y.Z,...] \
  --run-date YYYY-MM-DD --request F|P --out <STAGING_ROOT>/tier
```

`tier-answers.json` (`sinter-tier-answers/1`) holds the answers a human must
give with evidence: `triggers.os_or_image_change`, for each changed static
crate `static_dependencies.<name>.reached` (`no` only with evidence; anything
else counts as reached), and for Tier P `first_available_newer` and
`t3_targets`. Exit 2 on any input error; nothing is assumed.

It writes `TIER_ASSESSMENT.json` and `TIER_ASSESSMENT.md`: the diff, every
T-1 trigger answered yes/no with its evidence (minor or major version, OS
code, OS or image change, dynamic ABI — `DT_NEEDED`, highest `GLIBC_` and
OpenSSL versions — a reached statically linked SSH, crypto or compression
dependency update, more than 60 days or more than two releases since the
reference Tier F release), the T-3 targets and the resulting tier and
required targets. Tier P results only when Tier P is requested and no trigger
applies; otherwise the result is Tier F with all eight targets. The tool
never lowers a tier. The independent review checks the record, and the Owner
approves the tier; the approved tier and target set are written into the R8
p5 contract (`ACCEPTANCE_SCOPE`, `P5_TARGETS`, both part of the approval
string) and into the manifest (`sinter-acceptance-manifest/2`,
`acceptance_scope`, `required_targets`, `abi`, and for Tier P
`full_reference`).

- Tier F (`full`): all eight supported targets. Every minor or major
  release is Tier F.
- Tier P (`patch`): `ubuntu2404`, `rocky9`, the first available of
  `ubuntu2604`, `rocky10`, `rhel10`, `alma10`, plus the T-3 targets. The
  release notes name the reference Tier F release and its manifest SHA-256
  and list every other supported target as NOT RUN. The supported targets
  stay the eight.

## Step 3 — Source validation

Read-only verification of `RC_COMMIT`. Fix nothing in this step — failures
go back to step 2 or to remediation (step 1).

```sh
# Fixed state
git rev-parse HEAD                 # == RC_COMMIT
git status --short                 # only pre-existing unrelated dirty files
git tag --list                     # TAG must NOT exist yet

# Lineage
git merge-base --is-ancestor ${SOURCE_CANDIDATE} HEAD
git diff --name-status ${SOURCE_CANDIDATE}..HEAD  # release files only
git diff ${SOURCE_CANDIDATE}..HEAD -- src/ tests/ # MUST be empty

# Version consistency
grep '^version' Cargo.toml                        # ${VERSION}
grep -A1 'name = "sinter"' Cargo.lock
cargo metadata --locked | jq '.packages[] | select(.name=="sinter") | .version'

# Fresh build outside the repo
CARGO_TARGET_DIR=/tmp/sinter-${TAG}-check/target cargo build --locked --release
/tmp/sinter-${TAG}-check/target/release/sinter --version   # sinter ${VERSION}

# Gates (any host; step 4 is still mandatory on Linux)
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
python3 release/check_acceptance_manifest.py --template release/acceptance-manifest.template.json
git diff --check
```

Also review: `CHANGELOG.md` accuracy vs evidence, `README.md` /
`README.ja.md` consistency, supported-platform claims scoped to actual
acceptance references, no stale current-version references
(`rg -n 'v0\.\d|0\.\d\.\d' --glob '!target/**'`), no unexpected release
infrastructure claims.

GO only when every check passes; otherwise NO-GO.

## Step 4 — Linux validation gate (mandatory, before any build)

Run on the gate host, a dedicated, disposable **Ubuntu 24.04 LTS x86_64**
host prepared as described below, from a clean checkout of exactly
`RC_COMMIT`. Use a checkout path outside any home directory (for example
`/work/sinter`) so the log contains no user paths.

Why Ubuntu 24.04: the gate runs the root test suite in strict mode, where
every integration test must either run or fail. Some of those tests need a
Debian-family host: `tests/package_service.rs` installs and removes packages
with `apt-get`, and `tests/handlers.rs` restarts the host's own `ssh.service`
unit. On a RHEL-family host those tests fail in strict mode, and without
strict mode they would skip and still count as passed. The other supported
distributions are covered by the acceptance of the built artifact (steps
7–9), not by this gate.

A macOS or other non-Linux PASS is **not** a substitute. On macOS the
Linux-only suites (`#![cfg(target_os = "linux")]`) compile to zero tests
and the installer tests need GNU `tar`, `stat`, and `sha256sum`.

```sh
git rev-parse HEAD                    # == RC_COMMIT
git status --short                    # empty
cat /etc/os-release; uname -m; rustc --version; cargo --version
grep -l '^#!\[cfg(target_os = "linux")\]' tests/*.rs   # → linux_only_suites

# The commands are pinned; the checker rejects any other spelling.
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
env SINTER_TEST_STRICT=1 SINTER_TEST_LOCAL_SSHD=1 cargo test --locked --all-targets --all-features
python3 tests/installer/test_install.py
python3 -m unittest discover -s release/tests
cargo fmt --manifest-path gateway/Cargo.toml --check
cargo clippy --manifest-path gateway/Cargo.toml --locked --all-targets --all-features -- -D warnings
cargo test --manifest-path gateway/Cargo.toml --locked --all-targets --all-features
```

The `root-test` command pins two variables:

- `SINTER_TEST_STRICT=1` is strict mode. A test whose prerequisite is
  missing (an SSH test input, passwordless `sudo`, a tool such as
  `getfattr` or `script`, the local-sshd opt-in) fails with
  `SINTER_TEST_REQUIRED: <reason>`. Without strict mode it prints
  `SINTER_TEST_SKIPPED: <reason>` to captured stderr, returns early, and
  still counts as passed, so pass counts cannot show that it did not run.
  Only the value `1` enables strict mode.
- `SINTER_TEST_LOCAL_SSHD=1` enables the suites that start a throwaway
  unprivileged `sshd` on loopback: `tests/ssh_keys.rs` (key formats,
  host-key verification, and the SSH algorithm policy negotiated against a
  real server) and `tests/multihost_lab.rs`. Under strict mode these suites
  fail without it.

Together they make a PASS mean that every root integration test ran. Record
and log the command exactly as written, including `env`, which keeps it a
single command whether it is typed into a shell or run by a harness as an
argument vector (the variables also override any value inherited from the
environment). The checker rejects `root-test` evidence recorded with any
other command for every release after v1.1.1; releases up to v1.1.1 keep the
command they were pinned to.

The evidence records only this command. The SSH test inputs below are
runtime configuration of the gate host: never record their values (user
names, key or known_hosts paths, keys) in the Evidence Manifest, and never
put private key material in the log. The checker's sensitive-data scan
applies to everything in the bundle.

The gateway crate (`gateway/`) is not part of the release artifact. It is
validated here anyway so that a release never ships from a commit whose
workspace fails on the reference platform.

### Gate host

In strict mode the gate host needs everything the root integration tests
use; a missing item fails the gate rather than skipping tests:

- Ubuntu 24.04 LTS x86_64 with systemd; a Rust 1.98.1 toolchain with
  `rustfmt` and `clippy`; `build-essential`, `pkg-config`, `libssl-dev`,
  `python3`, `git`.
- A dedicated **non-root** gate user with passwordless `sudo -n` (the
  unprivileged tests refuse to run as root; the privileged ones use
  `sudo -n`). Its home directory and the path above it must carry no ACLs
  or extended attributes (the trust checks refuse them).
- `attr` (`/usr/bin/getfattr`, `/usr/bin/setfattr`) and `acl`
  (`/usr/bin/getfacl`) on a filesystem with user extended attributes, where
  `sudo` can also set `security.*` attributes (a failure to prepare that
  fixture fails the gate);
  `apt-get` with reachable package repositories (`tests/package_service.rs`
  installs and removes `cowsay`, or the package named by
  `SINTER_TEST_PACKAGE`); `script(1)`; the stock masked and static systemd
  units of the image.
- `openssh-server` and the OpenSSH client tools (`sshd`, `ssh-keygen`,
  `ssh-keyscan`, `ssh-agent`, `ssh-add`). The host's own `sshd` listens on
  ports 22 and 2222 through `ssh.service` (not `ssh.socket`); the tests
  probe the secondary port on `127.0.0.1:2222`.
- A second user without sudo, reachable over SSH with the same key.
- The SSH test inputs below, exported in the gate user's environment.

SSH test inputs, by role. The SSH reference target is the gate host itself
over loopback: the tests reach the secondary port and the name `localhost`
on the same machine, so these describe the gate host, not an acceptance
target.

| Variable | Role | Required |
|---|---|---|
| `SINTER_TEST_SSH_HOST` | Loopback address of the gate host's own `sshd` (`127.0.0.1`) | Yes; without it the SSH tests fail in strict mode |
| `SINTER_TEST_SSH_PORT` | Primary `sshd` port | No; defaults to 22 |
| `SINTER_TEST_SSH_USER` | The gate user, who has passwordless sudo on the target | Yes; the default is not a gate user |
| `SINTER_TEST_SSH_IDENTITY` | Path to the private key authorized for both test users | Yes |
| `SINTER_TEST_SSH_KNOWN_HOSTS` | Path to a known_hosts file holding the host keys of the loopback target | Yes; the SSH tests fail without it |
| `SINTER_TEST_SSH_NOSUDO_USER` | The user without sudo, for the sudo-denied test | No; defaults to `sinter-nosudo` |

The key and the known_hosts file are created on the disposable gate host and
never leave it.

The host's own SSH service is its control plane and, in strict
mode, the SSH reference target. After preparing the host, reboot it and,
before the first gate command, confirm that `ssh.service` is active, no
`ssh.socket` is active, and ports 22 and 2222 are owned by the
`ssh.service` main process (a stray sshd from an earlier socket activation
makes later SSH tests fail). Service and handler lifecycle tests use a
dedicated fixture unit, but some tests act on the host's own SSH service:
`tests/package_service.rs` ensures `openssh-server` is installed and the SSH
unit is running and enabled, and `tests/remediation.rs` restarts that unit
through a handler. Run the gate only on a dedicated, disposable Linux host.
The per-commit CI builds the root test binaries but does not run them; this
gate is where the root test suite runs. A gate failure
that disturbs the host's SSH control plane is still a STOP: diagnose it on
the evidence, never retry in place.

Capture the full output of all of the above into one log
(`validation/linux-gate.log` in the evidence bundle), delimiting each step
with `== step <name> start <time>`, `$ <command>` and
`== step <name> rc=<rc> end <time>` lines as the gate harness does, and
record, as they are produced, the `linux_validation` fields of the Evidence
Manifest:
OS name/version/architecture, `RC_COMMIT`, `rustc`/`cargo` versions, start
and finish times, the Linux-only suites, and for each step its name, pinned
command, result, and passed/failed/ignored counts.

GO only when every step PASSes, every Linux-only suite ran at least one
test, and nothing failed. **Any FAIL is a STOP:** no build, no acceptance,
no tag; return to step 1. The checker enforces this record at step 12
(`linux_validation`: pinned commands, all PASS, x86_64, same commit,
finished before acceptance started, Linux-only suites executed). A partial
root test run is not valid evidence: the log's `root-test` section must show
every test harness of the root crate at `RC_COMMIT`, their pass counts must
add up to the recorded `root-test` counts, and `linux_only_suites` must name
exactly the Linux-only suites at `RC_COMMIT`. The checker derives both lists
from the repository with git and cargo, so run it from a clone that contains
`RC_COMMIT`.

## Steps 5–6 — Build once and freeze the artifact

Only after the step-4 gate PASSes.

### Build environments and provenance

Linux x86_64 publishes **one** artifact, built on the oldest supported
baseline (Rocky Linux 9 x86_64, glibc 2.34) and then extracted and executed,
byte-identical, on every supported Linux x86_64 target before release. This
is justified — not assumed — by evidence: the Rocky-9-built binary requires
no glibc symbol newer than `GLIBC_2.34`, needs only
`libssl.so.3`/`libcrypto.so.3`/`libgcc_s.so.1`/`libc.so.6` (no RPATH), and
the exact same bytes were verified to run on Ubuntu 24.04, Ubuntu 26.04,
Rocky Linux 9, and Rocky Linux 10. Never substitute: no macOS binary shipped
as a Linux artifact, no rename-based target spoofing, no stale or
unknown-provenance binaries.

A build on a newer baseline (Ubuntu 26.04 or Rocky 10) is **not** an
acceptable substitute for this artifact: those builds require `GLIBC_2.39`
and will not run on Rocky Linux 9 (glibc 2.34).

Preferred source transport:

```sh
git archive ${RC_COMMIT} -o sinter-${RC_COMMIT}.tar   # exact commit, tracked files only
```

Ship to the build host, extract, and prove identity by comparing per-file
SHA-256s against a local extraction (sort with `LC_ALL=C` — locale collation
differs across hosts):

```sh
find . -type f | sort | xargs sha256sum > sums.txt   # on each side, then diff
```

A real `git worktree`/clone at `RC_COMMIT` is equally acceptable. Uncertain
provenance → do not publish.

Builder prerequisites: a fresh Rocky Linux 9 image needs explicit
provisioning before the build — `gcc`, `openssl-devel`, `pkgconf`
(`sudo dnf install -y gcc openssl-devel pkgconf`) and a Rust toolchain
(rustup or equivalent). Do not assume these are present.

Record on the build host:

```sh
cat /etc/os-release; uname -m; rustc --version; cargo --version
cargo build --locked --release        # -j1 on low-memory hosts
file target/release/sinter
readelf -d target/release/sinter | grep -E 'NEEDED|RPATH|RUNPATH'
readelf -V target/release/sinter | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1
ldd target/release/sinter
target/release/sinter --version       # sinter ${VERSION}
sha256sum target/release/sinter
```

In steps 7–8, every supported Linux x86_64 target extracts that exact
binary and re-verifies `sha256sum` (must be identical), `ldd`, `--version`,
and a safe non-mutating `plan`. Record the per-target results.

### Build, freeze, and package — mandatory identity gate

Build exactly once on **Rocky Linux 9 x86_64** with
`cargo build --locked --release` (`-j1` is permitted). Record source HEAD,
per-file build-input comparison, OS/version, architecture, rustc/cargo,
`ldd --version` (glibc), and `openssl version`. A different build baseline,
architecture, or maximum required GLIBC above **GLIBC_2.34** is a **STOP**.
Do not substitute Ubuntu 24/26 or Rocky 10 builds.

Immediately freeze the executable SHA-256. Record ELF headers/interpreter,
all symbol-version requirements, DT_NEEDED, and RPATH/RUNPATH. Expected native
interfaces are `libssl.so.3`, `libcrypto.so.3`, `libgcc_s.so.1`, `libc.so.6`,
and `ld-linux-x86-64.so.2`, with `OPENSSL_3.0.0` and no RPATH/RUNPATH.
Unexpected dependencies or unresolved linkage are a STOP pending review.
Do not strip, patch, or otherwise alter the frozen bytes.

From v1.15.0, the step-2 tier assessment is provisional: right after the
freeze and before any acceptance, run `release/tier_assess.py` again with
`--executable` naming the **frozen** executable and a new `--out`. The
manifest's `abi` is this measured value (the checker measures it again from
the artifact and fails a `/2` manifest whose `abi` differs). If the frozen
executable's ABI differs from the reference, or the result is otherwise no
longer the approved tier, the release is Tier F: a Tier P approval never
covers a frozen artifact it was not assessed on.

Package one canonical archive, record its SHA-256, and prove a fresh
extraction has the frozen executable SHA. Build validation (source/ABI/hash/
smoke) is distinct from runtime acceptance: steps 7–9 execute that exact
extracted artifact on every supported target and retain the matrix evidence
and independent OS-state checks tied to the source/hash. Source or test
changes invalidate the candidate (§Invalidation rules); no release without
final production lineage. Record exact tested point releases separately
from supported version lines. No claim that future point releases were tested.

### Artifact naming

```text
sinter-v${VERSION}-linux-x86_64.tar.gz
SHA256SUMS
```

The name records Linux and the architecture class, not a managed-target
distribution. The manifest records the build baseline: the same binary manages all supported Linux
x86_64 targets. New targets that keep the same dependency interface extend
the verification matrix, not the artifact list; a target needing a different
interface gets its own artifact.

### Archive layout

Each tarball contains a single same-named top-level directory:

```text
sinter-v${VERSION}-<platform>-<arch>/
  sinter            # executable, mode 755
  README.md
  README.ja.md
  LICENSE-MIT
  LICENSE-APACHE
```

Never include: `.git`, source tree, `target/`, credentials, SSH keys, tokens,
`opencode.json`, internal audit/remediation/acceptance reports, agent logs,
temporary files.

**macOS packaging warning:** macOS `bsdtar` embeds extended-attribute headers
(`LIBARCHIVE.xattr.com.apple.*`) into archives. When packing on macOS use
`COPYFILE_DISABLE=1 tar --no-xattrs -czf …` (equivalent flags differ across
tools/platforms — always finish by inspecting the archive contents on the
target side; the first v0.2.0 pack needed a repack for exactly this reason).

### Archive verification

For every tarball:

- [ ] `tar tzvf` lists expected files only
- [ ] No absolute paths, no `..` traversal
- [ ] Executable bit preserved on `sinter`
- [ ] Fresh extraction on the **intended target** succeeds
- [ ] Extracted `./sinter --version` → `sinter ${VERSION}` on that target
- [ ] `file`/`ldd` confirm architecture and resolvable linkage

### Checksums (step 6)

Generate `SHA256SUMS` **only after the artifacts are final**, then record
the frozen identity: artifact filename, size, tarball SHA-256, and the
SHA-256 of the extracted `sinter` executable.

```sh
shasum -a 256 sinter-v${VERSION}-linux-*.tar.gz > SHA256SUMS   # or sha256sum
shasum -a 256 -c SHA256SUMS                                    # verify
```

Repacking an artifact creates a new candidate: its checksum and any
acceptance evidence are void (§Invalidation rules). Only the installable
`linux-*` artifacts go into `SHA256SUMS`; the acceptance evidence bundle
never does.

## Steps 7–9 — Target acceptance of the frozen artifact

Only after step 6. Run once per required target of the approved tier (Tier
F: the eight labels `ubuntu2404`, `ubuntu2604`, `rocky9`, `rocky10`, `rhel9`,
`rhel10`, `alma9`, `alma10`; Tier P: the step-2 target set), on real machines (real OS, real architecture, real SSH where
applicable), against the **exact** tarball frozen in step 6. FakeTarget/
FakeExecutor coverage does not substitute for target acceptance.

Step 8 on every target, before any check: copy the tarball, record its
observed SHA-256 and the SHA-256 of the extracted `sinter`, and compare them
with the step-6 values. A mismatch is a STOP (§Invalidation rules).

Minimum matrix per target:

- [ ] `cat /etc/os-release`, `uname -m`, toolchain/runtime versions recorded
- [ ] SSH connect + command exec + stdout/stderr/exit status
- [ ] `sudo -n` works
- [ ] Platform detected correctly (family, distro, backend — no fall-through)
- [ ] `type: package` `state: present` → install → independent verification
      (`rpm -q` / `dpkg -s`)
- [ ] Second present apply: no new mutation (idempotent)
- [ ] `state: absent` → remove → independent verification
- [ ] Second absent apply: idempotent
- [ ] Native package-manager output handled by production parsers
- [ ] file resource: create/update/mode/owner + idempotency
- [ ] service resource: enable/start, disable/stop + idempotency
- [ ] command resource: guard (`creates`) honored
- [ ] Pre-mutation failure reports failed, no false Changed, no mutation
- [ ] Sensitive values redacted in output/diffs/errors
- [ ] `audit --audit-policy strict` exits 8 for a not-auditable command
      (with `audit_policy` in JSON); the default policy is unchanged; the
      command never runs (from v1.9.0)
- [ ] `SINTER_PROGRESS=plain` package apply: only `progress:` lines on stderr,
      stages closed, nothing on stdout; no progress with `--format json` or by
      default on a non-terminal stderr. Package detail words are recorded, not
      judged (from v1.9.0)
- [ ] No residue after operations (temp dirs, snapshots)

Step 9: keep one raw, sanitized log per target, named by its label.

The driver for these steps is `release/acceptance-harness/` (see its
README): it is configured only through the environment, refuses to start
without every required value, records each target's boot image, and stops a
target on a tarball or raw-log hash mismatch, a failed preparation step or a
failed metadata refresh.

A check may be NOT APPLICABLE only for a (check, target, reason) listed in
`release/acceptance-harness/applicability.json` and only when the raw log
carries the fixed observation line that proves the reason; the raw verdict
and the checker both verify it. Anything else that does not run is a FAIL.

Report ends with an explicit `GO` or `NO-GO`. Do not remediate during
acceptance — reproduce, preserve evidence, report, stop. Any target FAIL
ends this candidate; a fix is a new candidate from step 1.

## Steps 10–12 — Evidence Manifest, bundle, and checker

Follow `release/ACCEPTANCE_EVIDENCE.md`.

- Step 10: generate the Evidence Manifest from the values recorded in steps
  4 and 6–9 only — never from memory or summaries.
- Step 11: assemble the bundle directory (manifest copy, `harness/`,
  `logs/<label>.log`, `validation/linux-gate.log`), pack it, and write the
  acceptance checksums:

```sh
tar -czf sinter-v${VERSION}-acceptance-evidence.tar.gz sinter-v${VERSION}-acceptance-evidence
shasum -a 256 sinter-v${VERSION}-acceptance-manifest.json \
  sinter-v${VERSION}-acceptance-evidence.tar.gz > sinter-v${VERSION}-acceptance-SHA256SUMS
shasum -a 256 -c sinter-v${VERSION}-acceptance-SHA256SUMS
```

- Step 12: run the checker in full mode on the exact files that will be
  staged. It must print `OK … (verdict GO)` and exit 0:

```sh
python3 release/check_acceptance_manifest.py \
  sinter-v${VERSION}-acceptance-manifest.json \
  --bundle-archive sinter-v${VERSION}-acceptance-evidence.tar.gz \
  --artifact sinter-v${VERSION}-linux-x86_64.tar.gz \
  --sums sinter-v${VERSION}-acceptance-SHA256SUMS
```

A Tier P manifest (`acceptance_scope: patch`) also needs
`--full-reference <reference Tier F manifest>`; the checker verifies the
reference itself (SHA-256, full GO, age, releases since, equal ABI) and never
trusts the option alone.

A checker FAIL is a STOP: **no human review, no tag.** A sensitive-content
finding means sanitizing the logs and rebuilding the bundle (steps 9–11); a
hash, target, or gate finding means the evidence does not support this
candidate (return to step 7, or to step 1).

## Step 12b — Docs commit `D` (local only)

Only after the step-12 checker PASS. On a local branch, create one docs-only
commit `D` whose only parent is `RC_COMMIT`: version references, WebMCP
metadata (`docs-site/src/data/resources.json`, `build-webmcp.ts`), the
installer and dev-container version, the `start.yml` version check, and
`release/evidence/v${VERSION}/acceptance-manifest.json` copied byte for byte
from the staged manifest. `D` may change only these paths (the docs
allow-list): `docs-site/**`, `README.md`, `README.ja.md`,
`.devcontainer/install-sinter.sh`, `.github/workflows/start.yml`,
`examples/start/README*.md` and the manifest copy.

Check `D` locally only: the documentation `check`, `webmcp:check`,
`tutorial:check` and `build`, and the CI checks that need no Release
(examples, public tree). Do **not** push `D` anywhere before the Release
exists: it announces the new version, and its dev-container change starts
`start.yml`, which downloads the Release asset and must fail before
publication. Never use the documentation workflow's manual dispatch on a
branch (its deploy job would publish that branch).

## Step 13 — Staging and human review

Only after the step-12 checker PASS. Assemble outside the repository, under
`<STAGING_ROOT>`: a directory outside the repository with enough free space for
the artifacts and evidence, not in the home directory.

```text
<STAGING_ROOT>/Sinter-v${VERSION}-release-staging/
  sinter-v${VERSION}-linux-*.tar.gz  # → release assets
  SHA256SUMS                      # → release asset
  RELEASE_NOTES.md                # → GitHub Release body source
  RELEASE_MANIFEST.md             # internal review evidence
  evidence/                       # provenance logs, file-hash lists, build envs
  sinter-v${VERSION}-acceptance-manifest.json   # → release asset
  sinter-v${VERSION}-acceptance-evidence.tar.gz # → release asset
  sinter-v${VERSION}-acceptance-SHA256SUMS      # → release asset
```

GitHub Release assets are the tarballs, `SHA256SUMS`, and the three
acceptance assets (manifest, evidence bundle, acceptance checksums; see
`release/ACCEPTANCE_EVIDENCE.md`). `SHA256SUMS` lists the tarballs only, so
the installer and the documented checksum command are unaffected.
`RELEASE_MANIFEST.md` and the build `evidence/` directory remain internal
review material and are not published.

### RELEASE_MANIFEST.md required fields

Per artifact: filename, size, SHA-256, build OS, architecture, rustc/cargo
version, source commit, binary type, linkage summary, extraction-verification
result, `--version` result. Overall: release version, RC commit, checksum
verification result, staging timestamp, supported-target matrix.

### RELEASE_NOTES.md structure

```markdown
# Sinter vX.Y.Z
## Highlights
## Supported platforms      (matrix + acceptance reference scoping)
## Downloads                (artifacts + SHA256SUMS + verify command)
## Validation               (concise, evidence-based)
## Known limitations
```

Must not contradict `CHANGELOG.md`/`README.md`/acceptance evidence. No
internal finding IDs, no agent internals, no overstated security guarantees.

### Human review gate

Publishing requires explicit human review of, in order:

1. `RELEASE_MANIFEST.md`
2. `RELEASE_NOTES.md`
3. `SHA256SUMS`
4. tarball contents (`tar tzvf`, spot-run `--version`)
5. the acceptance manifest, the Linux gate record in it, its full-mode
   checker output, and `sinter-v${VERSION}-acceptance-SHA256SUMS`

No publish until the human confirms all five. The approval covers exactly
the staged bytes; any change to a staged file voids it.

### Approval set (v1.5.0 onward; layout `sinter-approval-set/2` from v1.5.1, `/3` from v1.15.0)

The approval is bound to one digest. Before review, the operator assembles
the approval set under `evidence/approval-set/` in the staging directory with
`release/make_approval_set.py` (its `--collector-fragment` mode prints the
`post_acceptance_collector` object for the bundle's `harness/PROVENANCE.json`
beforehand):

```text
APPROVAL-SET-META.json        version, tag, RC_COMMIT, RC tree, artifact and
                              executable SHA-256, collector facts
acceptance/                   byte copies of the three acceptance assets
collector-record/             the collector (collect-evidence.py), the runtime
                              record every run carried, every collector run in
                              order under runs/NN/ (a failed first result
                              included; the last one with VERDICT.txt), and
                              their SHA256SUMS
docs-commit/D.patch           (/3) `git format-patch -1 --stdout D` of the docs commit
APPROVAL-SET.sha256           canonical member list (not a member itself)
```

From v1.15.0 the set is `sinter-approval-set/3`: `make_approval_set.py
--docs-commit <D> --rc-repo <repo>` adds `docs-commit/D.patch` and the META
fields `docs_commit` and `docs_tree`. `verify_approval_set.py --rc-repo`
checks that `D` exists, its only parent is `rc_commit`, its tree is
`docs_tree`, the patch applied to the RC tree reproduces it, every path it
changes is in the docs allow-list, and its manifest copy is byte-identical to
the approved acceptance manifest. A `/2` set (published releases) still
verifies unchanged. Because the patch is a member, any change of `D` changes
the digest: an approval of an earlier `D` never covers a new one.

`APPROVAL-SET.sha256` has one `<sha256>  <path>` line per member, sorted by
the UTF-8 bytes of the path, and nothing else; it verifies with
`shasum -a 256 -c`. `APPROVAL_SET_DIGEST` is the SHA-256 of that file. The
set is frozen once the digest is computed: re-packing the bundle archive
changes the digest and needs a new approval.

`release/verify_approval_set.py` checks the set: exactly the listed members,
the canonical list, consistency with the manifest, the bundle's
`harness/PROVENANCE.json` (every bundled harness file is the executed bytes;
publication copies are not accepted for the harness kept in this
repository), the runtime record, the collector record (the collector must be
the runtime-record collector, an earlier run is never GO, the last run is
`PENDING_OWNER_APPROVAL` with one PASS row per label), and the RC (commit,
tree, `Cargo.toml` version, every harness file and the collector at
`RC_COMMIT`); with `--evidence` it reproduces the collector output and every
bundle log from the recorded evidence (the run's `SINTER_PROJECT`,
`SINTER_ZONE` and `SINTER_SPECS`, and `SINTER_SANITIZE_PATTERNS` if the run
used one, must be in the environment for the sanitizer; it runs the RC
collector, never the set's copy, with a minimal environment), and checks that
the append-only `INDEX.tsv` lists exactly the recorded runs, one per label;
with `--artifact` it checks the tarball; with `--checker` (needs
`--artifact` and `--rc-repo`) it runs the full-mode checker. `--expect-rc` and `--expect-version` refuse a set made
for another candidate. Exit 3 means valid but not yet approved
(`PENDING_OWNER_APPROVAL`, never GO); exit 0 only with `--approved-digest`
equal to the current digest. A digest approved for one candidate never
covers a set for another: the set names its RC.

Before review, run it with all of `--rc-repo`, `--evidence`, `--gate-log`,
`--artifact`, `--checker` and `--expect-rc`; a structural run alone cannot
detect a consistently forged set. Any other exit than 3 before the approval,
or than 0 after it, is a STOP.

The Owner records the approval in writing, naming `APPROVAL_SET_DIGEST`,
`RC_COMMIT`, `D` (from v1.15.0), the artifact SHA-256, and the SHA-256 of the staged
`SHA256SUMS`, `RELEASE_NOTES.md` and `RELEASE_MANIFEST.md`. The approval
still covers every staged file reviewed above; the digest additionally binds
the acceptance evidence and the collector record, so that none of them can be
replaced after the approval. From v1.15.0 the approval covers the tag, the
Release, the assets, `D` and the fast-forward of `main` to `D`. A matching digest shows which bytes were
approved, not who approved them: that is established by the written record
and the channel it came through. A collector's own approval token does not
replace this record.

## Steps 14–16 — Publish (tag, GitHub Release, assets)

Only after step-13 human authorization. All steps use read-back verification.
These steps push the tag and create the Release only; `main` does not move
until step 17b.

```sh
# 1. Recheck fixed state
git rev-parse HEAD                       # still RC_COMMIT's descendant; tag targets RC_COMMIT
git status --short
git remote -v

# 2. Recheck staging — the exact reviewed bytes
cd <STAGING_ROOT>/Sinter-v${VERSION}-release-staging
shasum -a 256 -c SHA256SUMS              # all OK
shasum -a 256 -c sinter-v${VERSION}-acceptance-SHA256SUMS
python3 <repo>/release/verify_approval_set.py evidence/approval-set --rc-repo <repo> \
  --evidence <acceptance out> --gate-log <step-4 log> \
  --checker <repo>/release/check_acceptance_manifest.py \
  --artifact sinter-v${VERSION}-linux-x86_64.tar.gz --expect-rc ${RC_COMMIT} \
  --approved-digest ${APPROVAL_SET_DIGEST}   # exit 0 (a /3 set also checks D)
(cd evidence/approval-set && sed -n 's|  acceptance/|  ../../|p' APPROVAL-SET.sha256 | shasum -a 256 -c)
                                         # staged assets == approved copies
python3 <repo>/release/check_acceptance_manifest.py \
  sinter-v${VERSION}-acceptance-manifest.json \
  --bundle-archive sinter-v${VERSION}-acceptance-evidence.tar.gz \
  --artifact sinter-v${VERSION}-linux-x86_64.tar.gz \
  --sums sinter-v${VERSION}-acceptance-SHA256SUMS   # OK … (verdict GO)

# 3. Recheck remote — TAG must not exist; no unexpected divergence
git fetch <remote>
git ls-remote --tags <remote> | grep ${TAG}   # expect empty
git status -sb

# 4. (moved to step 17b: main is not pushed here)

# 5–7. Step 14: annotated tag at the exact RC, verify target, push the tag only
git tag -a ${TAG} ${RC_COMMIT} -m "Sinter ${TAG}"
git rev-parse ${TAG}^{commit}            # MUST equal RC_COMMIT
git push <remote> refs/tags/${TAG}
git ls-remote --tags <remote> | grep ${TAG}   # read back: points at RC_COMMIT (peeled ^{})

# 8–10. Steps 15–16: GitHub Release with reviewed notes and the reviewed assets only
gh release create ${TAG} \
  --title "Sinter ${TAG}" \
  --notes-file RELEASE_NOTES.md \
  sinter-v${VERSION}-linux-*.tar.gz SHA256SUMS \
  sinter-v${VERSION}-acceptance-manifest.json \
  sinter-v${VERSION}-acceptance-evidence.tar.gz \
  sinter-v${VERSION}-acceptance-SHA256SUMS

# 11. Read back
gh release view ${TAG}                   # tag, title, asset names/sizes
```

Rules:

- Release tags are **annotated** and must point at the exact `RC_COMMIT`.
  Verify before and after pushing.
- If the tag already exists remotely → STOP. Never force-update a release tag.
- Never `--force` / `--force-with-lease` anywhere in this workflow.
- A v0.2.0-style docs commit after the RC does **not** move the tag target —
  the tag always names the commit the staged artifacts were built from.
- CI and advisories run on the tag push (their `on: push` has no filter);
  their results are recorded at step 17c.
- CLI exit codes are not proof; verify §Post-publish verification.

## Step 17 — Post-publish verification

### Step 17a — Read-back

Read the release back from GitHub:

```sh
gh release view ${TAG} --json tagName,name,assets
git ls-remote --tags <remote> | grep ${TAG}    # tag → RC_COMMIT
```

- [ ] Tag exists and points at `RC_COMMIT`
- [ ] Release exists with correct title
- [ ] Exactly the intended assets, no extras
- [ ] `SHA256SUMS` downloadable and matches staged copy
- [ ] Fresh-download each asset and check against `SHA256SUMS` and the
      acceptance checksums, and check each acceptance asset against its
      `acceptance/` entry in the approved `APPROVAL-SET.sha256`:

```sh
gh release download ${TAG} -D /tmp/verify-${TAG} --clobber
(cd /tmp/verify-${TAG} && sha256sum -c SHA256SUMS \
  && sha256sum -c sinter-v${VERSION}-acceptance-SHA256SUMS \
  && python3 <repo>/release/check_acceptance_manifest.py \
       sinter-v${VERSION}-acceptance-manifest.json \
       --bundle-archive sinter-v${VERSION}-acceptance-evidence.tar.gz \
       --artifact sinter-v${VERSION}-linux-x86_64.tar.gz \
       --sums sinter-v${VERSION}-acceptance-SHA256SUMS)
```

- [ ] The manifest copy in `D`
      (`git show ${D}:release/evidence/v${VERSION}/acceptance-manifest.json`)
      is byte-identical to the downloaded acceptance manifest asset.

A 17a mismatch is an incident: do not push `D`, do not force-fix.

### Step 17b — Docs commit to `main`

```sh
# the D being pushed is the approved one: re-verify the set first (exit 0)
python3 <repo>/release/verify_approval_set.py evidence/approval-set --rc-repo <repo> \
  --expect-rc ${RC_COMMIT} --approved-digest ${APPROVAL_SET_DIGEST}
test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["docs_commit"])' \
  evidence/approval-set/APPROVAL-SET-META.json)" = "${D}"
git push <remote> ${D}:refs/heads/work/v${VERSION}-docs   # a work branch, not main
# wait: CI and Start environment on the work branch must pass
#       (Start can now download the Release asset)
git fetch <remote>
git merge-base --is-ancestor <remote>/main ${RC_COMMIT}   # exit 0, else §Failure and recovery
test "$(git rev-parse ${D}^)" = "${RC_COMMIT}"
git push <remote> ${D}:refs/heads/main                      # no force: one fast-forward
git ls-remote <remote> refs/heads/main                      # read back: == D
```

The documentation workflow runs once on `main`, with matching versions.

### Step 17c — Record

Record the results of CI and advisories on the tag, CI, Start environment,
advisories and the documentation deploy on `main`, and the version the site
and `/webmcp.json` show.

## Failure and recovery after publication

| Failure | State | Recovery |
|---|---|---|
| Tag push fails | Nothing public | Read back `ls-remote`; fix and push the tag; never retag a different commit |
| Release creation or asset upload fails | Tag public | §Partial publish failure: resume the unfinished steps; never delete or move the tag |
| 17a mismatch | Release public, `main` unchanged | Incident; do not push `D`; no force-fix |
| 17b work-branch CI fails | Release public, `main` unchanged | Fix forward with a new `D'` (parent `RC_COMMIT`), a new approval set and re-review of `D'`; the docs keep showing the previous version meanwhile |
| `main` is not an ancestor of `RC_COMMIT` (moved meanwhile) | Release public | No force. Merge `RC_COMMIT` into the new `main` with `--no-ff` and put `D'` on that merge. A new approval set records it as `docs_base` (`make_approval_set.py --docs-base`; the verifier requires a merge with two parents, one of them `RC_COMMIT`, and `D'`'s only parent to be `docs_base`), and the Owner approves it before `D'` is pushed |
| Documentation deploy fails after 17b | `main` updated | The previous site stays published; fix forward with a docs-only commit |

Until 17b, `main` and the site show the previous version and the Release
page shows the new one as Latest; nothing announces an unpublished version.

## Partial publish failure

Steps 14–17 can partially succeed (e.g. tag pushed but release creation
fails, or the Release exists and `D` is not yet on `main`).

- **Do not blindly retry the whole workflow.**
- Read back remote state first: `git ls-remote`, `gh release view`.
- Resume only the unfinished steps.
- Do not delete or force-update an existing tag to "fix" bookkeeping — treat
  tag existence as ground truth and reconcile forward.

## Abort rules

Do not begin publishing when any of these hold:

- unexpected dirty files, or RC/version mismatch
- any source, test, or build-input change after step 2
- Linux validation gate (step 4) not PASS, or run only on a non-Linux host
- any target FAIL, or any artifact/executable hash that differs from step 6
- full-mode checker (step 12) not PASS on the staged files
- missing/wrong-OS/wrong-arch artifact, extraction or `--version` failure
- checksum mismatch or uncertain provenance
- inaccurate release notes
- remote tag already exists unexpectedly
- tier not approved, or the executed targets differ from the approved set
- the tier assessment of the frozen executable (Steps 5–6) differs from the
  approved tier
- a `/2` manifest whose approval set is not `/3` (the docs commit `D` is
  always part of the approval from v1.15.0)
- the publish-time approval of the matrix: from v1.15.0 the release matrix
  does not run `sinter approve` on a real target (`risk-approved-apply` is
  BLOCKED); the Owner states in writing whether that is accepted for the
  release
- `D` changed after the approval, or `D` pushed to a public branch before
  the Release exists
- approval set verification not exit 0 with the approved digest

Abnormalities *after* publish has started → partial-publish procedure above.

## Secrets

- Never log or report GitHub tokens, SSH private keys, or environment secrets
- Never place credentials inside artifacts, manifests, or release notes
- Do not dump credential-bearing command output into reports

## Evidence retention

Keep (no secrets): `RELEASE_MANIFEST.md`, `RELEASE_NOTES.md`, `SHA256SUMS`,
final RC hash, tag, release URL, build-environment summary, and the
acceptance/check reports that authorized the release.

From v1.0.0 candidates on, the acceptance evidence itself is retained
publicly and permanently as release assets (manifest, evidence bundle,
acceptance checksums), with a tracked manifest copy under
`release/evidence/v${VERSION}/`. See `release/ACCEPTANCE_EVIDENCE.md`.

## Future fast path (conditional)

When the process proves stable, a release may compress to:

```text
source validation + Linux gate → build/freeze → acceptance → checker
→ automatic staging verification → human authorization → tag → GitHub Release
→ post-publish verification
```

The fast path may automate steps, never skip or reorder them. (The v1.15.0
move of the `main` push from steps 14–16 to step 17b, and the new steps 12b
and 17a–17c, are a reviewed change of this runbook, not a reordering by a
fast path.)

Prerequisites — all required:

- zero source/test/build-input diff after step 2
- exact RC fixed
- baseline build environment available and exact-artifact verification complete on all targets
- extraction/run and checksum verification green
- release notes generated and validated
- clean repository state; no unexpected remote tag/release
- **explicit human authorization to publish** — a coding agent must never
  publish on its own judgment

## Reference example — v0.2.0 (do not copy/paste as commands)

Historical proven values, for orientation only:

- Version `0.2.0`, RC `031f09a5507383afd246c98b0994b750f911e64e`
  (accepted implementation `cb4b5d9f96745f09541cc1f799907cb0ad19dee5`)
- Artifacts: `sinter-v0.2.0-ubuntu24.04-amd64.tar.gz`,
  `sinter-v0.2.0-rocky9-x86_64.tar.gz`, `SHA256SUMS`
- Final Release Check: GO; Artifact Staging: READY FOR HUMAN REVIEW
  (v0.2.0 predates the current step order)
- Rocky acceptance reference: Rocky Linux 9.8 x86_64, DNF 4.14.0

## Future candidates (not part of this runbook)

Release CI/GitHub Actions, signing infrastructure, curl installer, Homebrew /
package repositories, documentation site. Evaluate separately; do not assume
existence.
