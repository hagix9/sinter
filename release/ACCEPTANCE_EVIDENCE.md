# Acceptance evidence retention (v1.0.0 candidates onward)

This document defines how release acceptance evidence (`RELEASE.md` steps 4 and 6–12) is captured, published, and kept verifiable. It applies to every release candidate from v1.0.0 on.

The goal is that an independent auditor, without access to any maintainer machine, can confirm:
- which source commit the artifact was built from;
- that the mandatory Linux validation gate passed on that commit before acceptance;
- which exact artifact was accepted;
- on which operating systems it was accepted;
- how many checks ran, and with what result.

Releases up to and including v0.5.1 predate this contract. Their acceptance record is the summary in each GitHub Release and in `README.md`. Their raw logs were not published and are **not** reconstructed.

## What is published

Every release that claims target acceptance publishes three additional GitHub Release assets next to the artifact and `SHA256SUMS`.

| Asset | Contents |
|---|---|
| `sinter-v${VERSION}-acceptance-manifest.json` | The Evidence Manifest (schema below). |
| `sinter-v${VERSION}-acceptance-evidence.tar.gz` | The raw evidence bundle (layout below). |
| `sinter-v${VERSION}-acceptance-SHA256SUMS` | SHA-256 of the two files above. |

`SHA256SUMS` keeps listing only the installable artifacts, so the installer and the documented `sha256sum -c SHA256SUMS` check are unchanged.

After publication, a copy of the manifest is committed to `release/evidence/v${VERSION}/acceptance-manifest.json`. That copy must be byte-identical to the published asset. It keeps the record discoverable from the repository even without the release page.

**Published evidence is immutable.**
- Never delete, replace, or re-upload an evidence asset.
- If an error is found later, publish a separate `sinter-v${VERSION}-acceptance-erratum.md` asset that explains it. Do not edit the original.

## Evidence bundle layout

```text
sinter-v${VERSION}-acceptance-evidence/
  acceptance-manifest.json      # byte-identical to the published manifest asset
  harness/                      # the exact acceptance harness files that ran
  logs/<target-label>.log       # one raw, sanitized log per target
  validation/linux-gate.log     # full output of the step-4 Linux validation gate
```

The harness files are included verbatim and hashed in the manifest. The run can then be tied to the exact harness code even though the harness lives outside this repository.

The bundle must be exactly this set, nothing more:
- Only regular files and directories. No symlinks, hardlinks, devices, FIFOs, sockets, or setuid/setgid files.
- Every path is relative, normalized, and stays inside the bundle: no absolute paths, drive letters, backslashes, `.` or `..` components, or characters outside `A-Z a-z 0-9 . _ / -`.
- Every file is referenced by the manifest (harness files, target logs, Linux gate log) or is the manifest copy. An unreferenced file — including a hidden one such as `.env` — is an error.
- No two paths may be equal ignoring case, and no path may be both a file and a directory.
- The archive has a single top-level directory named after the bundle, and is created with:

```sh
tar -czf sinter-v${VERSION}-acceptance-evidence.tar.gz sinter-v${VERSION}-acceptance-evidence
```

## Evidence Manifest

The manifest is a JSON object with schema id `sinter-acceptance-manifest/1`. `release/acceptance-manifest.template.json` shows every field with placeholders.

Top-level fields:

| Field | Meaning |
|---|---|
| `schema` | `"sinter-acceptance-manifest/1"` |
| `candidate.version` | Candidate version (`X.Y.Z`) |
| `candidate.tag` | Release tag (`vX.Y.Z`) |
| `candidate.source_commit` | 40-hex commit the artifact was built from (the RC commit) |
| `candidate.artifact` | `filename`, `sha256`, `size_bytes` of the release tarball |
| `candidate.executable_sha256` | SHA-256 of the frozen `sinter` executable inside the tarball |
| `candidate.build` | `baseline` (build OS/arch), `rustc`, `cargo`, `max_glibc` |
| `harness.name` | Harness name |
| `harness.version` | Harness version or commit |
| `harness.files` | List of `{path, sha256}` for the harness files in the bundle |
| `harness.runner` | The command or runner used, with placeholders for target labels (no hostnames or IPs) |
| `harness.operator` | Role of the person or agent who ran it (not a personal name) |
| `run.started_at`, `run.finished_at` | RFC 3339 UTC timestamps of the whole run |
| `linux_validation` | The step-4 Linux validation gate record (fields below) |
| `targets` | One entry per target (fields below) |
| `totals` | Sums over all targets: `targets`, `total`, `passed`, `failed`, `skipped` |
| `verdict` | `"GO"` or `"NO-GO"` |
| `evidence_bundle` | File name of the evidence bundle asset |
| `sanitization.allowed_literals` | Optional. Exact literals a reviewer cleared as false positives (see below) |

Fields of `linux_validation`:

| Field | Meaning |
|---|---|
| `os_name`, `os_version`, `arch` | The gate host. `arch` must be `x86_64`; a non-Linux host is never a substitute. |
| `source_commit` | Must equal `candidate.source_commit` |
| `rustc`, `cargo` | Toolchain versions on the gate host |
| `started_at`, `finished_at` | RFC 3339 UTC; the gate must finish before `run.started_at` |
| `linux_only_suites` | The `tests/<name>.rs` suites gated by `#![cfg(target_os = "linux")]` |
| `steps` | One `{name, command, result, passed, failed, ignored}` per required step: `root-fmt`, `root-clippy`, `root-test`, `installer-test`, `checker-test`, `gateway-fmt`, `gateway-clippy`, `gateway-test`. Commands are pinned (see `RELEASE.md` step 4). `root-test` is `env SINTER_TEST_LOCAL_SSHD=1 cargo test --locked --all-targets --all-features`; evidence for v1.1.1 and earlier was pinned without `env SINTER_TEST_LOCAL_SSHD=1` and is checked against that command. |
| `verdict` | `"PASS"` |
| `log` | `{path, sha256}` of `validation/linux-gate.log` |

Fields for each entry in `targets`:

| Field | Meaning |
|---|---|
| `label` | One of the eight supported-target labels: `ubuntu2404`, `ubuntu2604`, `rocky9`, `rocky10`, `rhel9`, `rhel10`, `alma9`, `alma10` (never a hostname) |
| `os_name`, `os_version`, `arch` | Values from the target's `/etc/os-release` and `uname -m`, e.g. `Rocky Linux`, `9.8`, `x86_64`. They must match the label's distribution and major version; `arch` must be `x86_64`. |
| `image` | Public image identity (vendor image family and version). Never a project, instance, or account ID. |
| `started_at`, `finished_at` | RFC 3339 UTC |
| `artifact_sha256` | SHA-256 of the tarball as observed **on the target**. It must equal `candidate.artifact.sha256`. |
| `executable_sha256` | SHA-256 of the extracted `sinter` as observed on the target. It must equal `candidate.executable_sha256`. |
| `version_output` | `sinter --version` output on the target. It must equal `sinter ${VERSION}`. |
| `checks` | `total`, `passed`, `failed`, `skipped`, with `passed + failed + skipped = total` |
| `verdict` | `"PASS"` when `failed = 0` and `total > 0`; otherwise `"FAIL"` |
| `log` | `{path, sha256}` of the raw log inside the bundle; `path` must be `logs/<label>.log` |

**Consistency rules** (enforced by `release/check_acceptance_manifest.py`):
- Every target observed the same artifact and executable hashes as the candidate.
- All eight supported targets are present exactly once; labels are unique.
- Per-target counts add up, and a target is `PASS` only with `failed = 0` and `total > 0`.
- `totals` equals the sum over all targets.
- `verdict` is `GO` only when every target is `PASS`. A `NO-GO` manifest never passes the checker, because it cannot support a release.
- Timestamps are ordered: Linux gate before the run, each target inside the run.
- The Linux gate record has every required step with its pinned command, all `PASS` with no failures, test steps with at least one passed test, and each Linux-only suite shows executed tests in `validation/linux-gate.log`.
- The log's `root-test` section (from `== step root-test start` to `== step root-test rc=0 end`, starting with the pinned command) shows every test harness of the root crate at `candidate.source_commit`, each passing; their pass and ignore counts add up to the recorded `root-test` counts; and `linux_only_suites` names exactly the Linux-only suites at that commit. Both lists come from the repository (git and cargo), not from the manifest, so a partial run cannot be recorded as the full suite.
- Every referenced file exists in the bundle as a regular file and matches its SHA-256; the bundle's `acceptance-manifest.json` is byte-identical to the manifest being checked.
- The artifact given to the checker has the recorded name, size, and SHA-256, and its `sinter-v${VERSION}-linux-x86_64/sinter` has the recorded executable SHA-256.
- With `--sums`, the acceptance checksum file lists exactly the manifest and bundle assets, with matching hashes.

## How raw logs are tied to the claim

The chain of hashes runs as follows:

1. Release `SHA256SUMS` → artifact.
2. The manifest records that artifact hash, and the observed hash on each target.
3. The manifest records each log's hash.
4. `sinter-v${VERSION}-acceptance-SHA256SUMS` covers the manifest and the bundle.
5. The tag points at `candidate.source_commit`.

An auditor downloads the three acceptance assets and the artifact, verifies both checksum files, and runs the checker in full mode. The bundle archive is inspected in memory; nothing is extracted:

```sh
python3 release/check_acceptance_manifest.py \
  sinter-v${VERSION}-acceptance-manifest.json \
  --bundle-archive sinter-v${VERSION}-acceptance-evidence.tar.gz \
  --artifact sinter-v${VERSION}-linux-x86_64.tar.gz \
  --sums sinter-v${VERSION}-acceptance-SHA256SUMS
```

`--bundle <dir>` checks an already extracted bundle directory instead of the archive, with the same rules. The checker needs `git`, `cargo` and a clone of the repository that contains `candidate.source_commit`: by default the checkout it runs from, otherwise `--repo <dir>`. Exit 0 means valid and `GO`; exit 1 prints one `FAIL` line per problem; exit 2 is a usage error.

The checker's own threat-model tests run with `python3 -m unittest discover -s release/tests` (offline, synthetic fixtures only; they need `git` and `cargo`).

## Sensitive-data exclusion

The manifest and the bundle are public. Before staging, sanitize the logs.

They must **not** contain:
- secrets, passwords, tokens, API keys, client secrets, private keys, SSH identity material, `Authorization` or `Cookie` values, or JWTs;
- IP addresses (IPv4 or IPv6, public or private), hostnames, FQDNs, or internal DNS names;
- cloud project, instance, account, or subscription IDs;
- user names, home-directory paths (`/home/…`, `/Users/…`, `C:\Users\…`), or other machine-specific paths (`/Volumes/…`, `/private/…`, `/var/folders/…`, UNC paths).

Refer to targets only by their `label`, and run the gate and harness from paths outside home directories.

The checker scans the manifest, every bundle file, and the bundle paths. It reports the file, line, and category of each finding, never the value. Every file must be UTF-8 text. A finding is a STOP: fix the sanitization and rebuild the bundle. Do not edit a published asset.

Values that are never findings: loopback and unspecified addresses, the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`, the reserved names `example.com`/`.org`/`.net`, `*.example`, `*.test`, `*.invalid`, `localhost`, public project and distribution domains (`github.com`, `sinter.fulltrust.co.jp`, `rust-lang.org`, `crates.io`, the supported distributions' vendor domains), public image projects in `projects/<name>` paths, default system accounts (`root`, `nobody`, `sinter`, and the image default users), target labels, and redaction markers such as `[redacted]` or `<redacted>`.

`sanitization.allowed_literals` lets a reviewer clear a specific false positive, such as a four-part package version that looks like an IPv4 address. Rules:
- Each entry is one exact literal (3–253 characters of `A-Z a-z 0-9 . _ : -`).
- It clears only IP address, hostname, username, cloud resource ID, and environment-specific path findings.
- Private keys, access tokens, JWTs, email addresses, internal DNS names, home-directory paths, and credential values can never be cleared, with one exception: a credential value that contains `synthetic`. The harness uses such a declared synthetic value to prove redaction.
- The list is public and part of the human review.

## Procedure

The numbers refer to the `RELEASE.md` state machine.

1. **Step 4, Linux gate** — on supported Linux x86_64, at `RC_COMMIT`, run the pinned gate commands. Keep the full output as `validation/linux-gate.log` and record the `linux_validation` fields. Any FAIL stops the release before a build.
2. **Step 6, freeze** — record the artifact name, size, and SHA-256, and the executable SHA-256.
3. **Steps 7–9, acceptance** — run the harness against that frozen, extracted artifact on all eight targets. Re-check both hashes on each target first. Capture one raw, sanitized log per target and record the fields above as they are produced.
4. **Steps 10–11, assemble** — generate the manifest from the recorded values only, never from memory or estimates. Build the bundle directory and archive, and write `sinter-v${VERSION}-acceptance-SHA256SUMS`.
5. **Step 12, validate** — run the full-mode checker (above) on the exact files to be staged. It must print `OK … (verdict GO)`.
6. **Step 13, human review** — stage the three acceptance assets with the artifact. The reviewer checks the manifest, its Linux gate record, the checker output, and `RELEASE_MANIFEST.md`.
7. **Steps 14–16, publish** — upload the three acceptance assets with the artifact and `SHA256SUMS`.
8. **Step 17, post-publish** — download the acceptance assets, verify `sinter-v${VERSION}-acceptance-SHA256SUMS`, and re-run the full-mode checker on the downloads. Then commit the manifest copy to `release/evidence/v${VERSION}/` in a docs-only commit.
