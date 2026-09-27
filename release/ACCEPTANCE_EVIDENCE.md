# Acceptance evidence retention (v1.0.0 candidates onward)

This document defines how Phase A target-acceptance evidence (see `RELEASE.md`) is captured, published, and kept verifiable. It applies to every release candidate from v1.0.0 on.

The goal is that an independent auditor, without access to any maintainer machine, can confirm:
- which source commit the artifact was built from;
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
  acceptance-manifest.json      # identical to the published manifest asset
  harness/                      # the exact acceptance harness files that ran
  logs/<target-label>.log       # one raw, sanitized log per target
```

The harness files are included verbatim and hashed in the manifest. The run can then be tied to the exact harness code even though the harness lives outside this repository.

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
| `candidate.build` | `baseline` (build OS/arch), `rustc`, `max_glibc` |
| `harness.name` | Harness name |
| `harness.version` | Harness version or commit |
| `harness.files` | List of `{path, sha256}` for the harness files in the bundle |
| `harness.runner` | The command or runner used, with placeholders for target labels (no hostnames or IPs) |
| `harness.operator` | Role of the person or agent who ran it (not a personal name) |
| `run.started_at`, `run.finished_at` | RFC 3339 UTC timestamps of the whole run |
| `targets` | One entry per target (fields below) |
| `totals` | Sums over all targets: `targets`, `total`, `passed`, `failed`, `skipped` |
| `verdict` | `"GO"` or `"NO-GO"` |
| `evidence_bundle` | File name of the evidence bundle asset |

Fields for each entry in `targets`:

| Field | Meaning |
|---|---|
| `label` | Stable, non-identifying label, e.g. `rocky9` (never a hostname) |
| `os_name`, `os_version`, `arch` | Values from the target's `/etc/os-release` and `uname -m`, e.g. `Rocky Linux`, `9.8`, `x86_64` |
| `image` | Public image identity (vendor image family and version). Never a project, instance, or account ID. |
| `started_at`, `finished_at` | RFC 3339 UTC |
| `artifact_sha256` | SHA-256 of the tarball as observed **on the target**. It must equal `candidate.artifact.sha256`. |
| `executable_sha256` | SHA-256 of the extracted `sinter` as observed on the target. It must equal `candidate.executable_sha256`. |
| `version_output` | `sinter --version` output on the target. It must equal `sinter ${VERSION}`. |
| `checks` | `total`, `passed`, `failed`, `skipped`, with `passed + failed + skipped = total` |
| `verdict` | `"PASS"` when `failed = 0` and `total > 0`; otherwise `"FAIL"` |
| `log` | `{path, sha256}` of the raw log inside the bundle |

**Consistency rules** (enforced by `release/check_acceptance_manifest.py`):
- Every target observed the same artifact and executable hashes as the candidate.
- Per-target counts add up.
- `totals` equals the sum over all targets.
- `verdict` is `GO` only when every target is `PASS`.
- Target labels are unique.

## How raw logs are tied to the claim

The chain of hashes runs as follows:

1. Release `SHA256SUMS` → artifact.
2. The manifest records that artifact hash, and the observed hash on each target.
3. The manifest records each log's hash.
4. `sinter-v${VERSION}-acceptance-SHA256SUMS` covers the manifest and the bundle.
5. The tag points at `candidate.source_commit`.

An auditor downloads the three acceptance assets and the artifact, verifies both checksum files, extracts the bundle, and runs:

```sh
python3 release/check_acceptance_manifest.py \
  sinter-v${VERSION}-acceptance-manifest.json --bundle <extracted-bundle-dir>
```

## Sensitive-data exclusion

The manifest and the bundle are public. Before staging, sanitize the logs.

They must **not** contain:
- secrets, passwords, tokens, private keys, or SSH identity material;
- IP addresses (public or private), hostnames, or internal DNS names;
- cloud project, instance, or account IDs, or user names and home-directory paths.

Refer to targets only by their `label`. The checker rejects documents and logs that match known sensitive patterns. A match is a STOP: fix the sanitization and rebuild the bundle. Do not edit a published asset.

## Procedure

1. **Phase A** — run the harness against the frozen, extracted release artifact on every supported target. Capture one raw log per target and record the fields above as they are produced.
2. **Assemble** — build the bundle. Generate the manifest from the recorded values; never from memory or estimates.
3. **Validate** — run `python3 release/check_acceptance_manifest.py <manifest> --bundle <bundle-dir>`. It must pass.
4. **Phase D and Human Review** — put the three acceptance assets into the staging directory. The reviewer checks the manifest together with `RELEASE_MANIFEST.md`.
5. **Publish** — upload the three acceptance assets with the artifact and `SHA256SUMS`.
6. **Post-publish** — download the acceptance assets, verify `sinter-v${VERSION}-acceptance-SHA256SUMS`, then commit the manifest copy to `release/evidence/v${VERSION}/` in a docs-only commit.
