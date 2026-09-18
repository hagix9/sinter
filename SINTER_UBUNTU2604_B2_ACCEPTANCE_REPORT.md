> Current provenance: this historical acceptance used production baseline `237547124e5ea675bfa1295f487ffa871a77f306`, candidate `af6b3384025c7033b16b26a664e11b73dd527156cd5e1d81d79d835a92f73fc2`, fresh GCP host `ubuntu02-b2`. Documentation-only finalization does not rerun or replace this evidence.

# Sinter — Ubuntu 26.04 B2 Fresh Acceptance Report

Report date: 2026-09-18 (UTC). B2-only pass. Evidence-driven; every claim below is
backed by the raw capture in `evidence/ubuntu02-b2-acceptance-raw.json`.

## 1. Purpose

Close the open acceptance item:

- **B2 / Ubuntu 26.04.x x86_64 fresh real-host acceptance — OPEN → CLOSED**

B1 (Rocky Linux 10.2) was previously closed and was **not** reopened, re-run, or
re-examined. No Rocky host was touched. No package-unification analysis was
redone. This pass did not rebuild the candidate, modify production Rust, tests,
documentation, or `opencode.json`, and made no commit, push, tag, release, or
deploy.

## 2. Production HEAD

```
237547124e5ea675bfa1295f487ffa871a77f306
```

Verified with `git rev-parse HEAD`. Matches the expected production HEAD exactly.
Working tree left exactly as found (only the pre-existing unrelated doc/`opencode.json`
working-tree modifications; see `git-status.txt` — nothing was staged or committed).

## 3. Candidate SHA-256

```
af6b3384025c7033b16b26a664e11b73dd527156cd5e1d81d79d835a92f73fc2
```

The existing candidate was reused and **not rebuilt**. The on-host recompute
immediately before the matrix, and again after `chmod`, both returned this exact
value (`sha256sum`, 3270160 bytes, ELF 64-bit x86-64 PIE, glibc-2.34-baseline
linkage, executes on glibc 2.43). See `candidate-sha256.txt` and raw event
`candidate`.

## 4. Host identity

| Field | Value |
|---|---|
| Alias | `Ubuntu2604-fresh-real-host` (evidence sanitized as `<ubuntu02-b2-host>`) |
| hostname SHA-256 | `51b7997364747f486c211218db54255bbe04a0886af0f4e77a42f9e67c5f48bf` |
| OS | Ubuntu 26.04.1 LTS (Resolute Raccoon), `VERSION_ID=26.04`, `ID=ubuntu`, `ID_LIKE=debian` |
| Architecture | `x86_64` |
| Kernel | `7.0.0-1011-gcp #11-Ubuntu SMP PREEMPT` |
| glibc | 2.43 |
| Tooling | apt 3.2.0, dpkg 1.23.7, systemd 259, getfattr/setfattr 2.5.2 |
| Privilege | `sudo -n true` → `uid=0(root)` |
| Type | real cloud VM (GCP Compute Engine, e2-small, RUNNING) |

See `host-identity.txt`.

## 5. Existing or newly provisioned host

**Newly provisioned.** The pre-existing `ubuntu01` was diagnosed first: it is
`RUNNING` in the cloud inventory but refuses TCP/22 (`ssh: connect to host
ubuntu01 port 22: Connection refused`) — the continuing effect of the earlier
`ssh.socket` incident recorded in the R3 report (§18). Consistent with the
safety rules of this pass, its SSH was **not** restarted or reconfigured, no
`ssh.socket` configuration was modified, and no additional SSH listener was
created for any test premise. A fresh Ubuntu 26.04.1 x86_64 VM was provisioned
instead. No Google account credentials, IAM permissions, project configuration,
or unrelated cloud resources were modified.

## 6. Why this qualifies as a fresh acceptance run

The host was created minutes before the run, had never executed any Sinter
acceptance before, and had no pre-existing Sinter fixtures, units, or the test
package. The test package (`tree`) was confirmed absent by an independent
`dpkg-query` before any Sinter invocation, `/root` had no Sinter fixtures, and
no Sinter systemd unit existed. The exact candidate was then executed natively
on this host for the first time, with the SHA verified on-host immediately prior.

## 7. Host preparation

The fresh Ubuntu 26.04.1 host used here initially lacked the `attr` package, so
`getfattr`/`setfattr` were absent. Per the established runtime contract this is
explicit, allowed host preparation:

```
before: un  attr  <none>            (dpkg: package not installed; getfattr/setfattr absent)
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y attr
after:  ii  attr  1:2.5.2-4ubuntu0.1 amd64  ;  getfattr 2.5.2
```

This prerequisite step installed `attr`; the matrix separately installed and
removed its temporary `tree` package and managed a dedicated temporary service.
No primary SSH service was reconfigured. The
noted actionable Sinter refusal for a target lacking `/usr/bin/getfattr` was
**not** bypassed or weakened — the tooling was installed, matching how the R3
matrix unblocked the same cases.

## 8. Exact candidate verification

On the host, immediately before and after the matrix:

```
sha256sum /tmp/sinter-candidate
af6b3384025c7033b16b26a664e11b73dd527156cd5e1d81d79d835a92f73fc2  /tmp/sinter-candidate
file:  ELF 64-bit LSB pie executable, x86-64, dynamically linked, /lib64/ld-linux-x86-64.so.2
--version: sinter 0.2.1
```

The binary linked against the Rocky-9 glibc-2.34 baseline ran natively on
Ubuntu 26.04's glibc 2.43 with no compatibility issue (package-unification
premise holds; no rebuild performed).

## 9. Acceptance cases and results

All 19 semantic checks PASS. Runner exit 0. Full raw evidence:
`evidence/ubuntu02-b2-acceptance-raw.json`.

| Case | Sinter result | Independent OS-state verification | Result |
|---|---|---|---|
| Package plan non-mutation | plan exit 0 | `dpkg-query` absence re-observed after plan | PASS |
| Package install | apply exit 0, `tree 2.3.1-1 amd64 install ok installed` | `dpkg-query -W`, `dpkg -V` (exit 0), `dpkg -L`, `tree --version` | PASS |
| Package idempotency | second apply: "package already in desired state" | same dpkg state | PASS |
| File mutation/state | apply exit 0, mode `0640`, owner/group `0/0` | `stat -c "%a %u %g"` = `640 0 0`; content hash = sha256("sinter-b2-final\n") | PASS |
| Metadata (xattr) preservation | replacement succeeded | `user.sinter_b2=preserved` (base64) identical before/after | PASS |
| File idempotency | second apply: "file already matches desired state" | identical stat/hash | PASS |
| Command guard | first apply creates marker | second apply suppressed; `%i %Y %Z` (inode/mtime/ctime) unchanged after 1s time separation | PASS |
| Pre-mutation refusal | **apply exit 5**, `execution=failed`, `change=none`, `verification=not_performed`, reason names the symlink | protected bytes + `stat` byte-identical before/after | PASS |
| Sensitive-output redaction | apply exit 5, output shows `<redacted>` | freshly generated fake canary absent from complete stdout+stderr across validate text/JSON, plan JSON, apply text/JSON (verbose) | PASS |
| Service mutation | apply exit 0 (start+enable) | `systemctl is-active`=active, `is-enabled`=enabled, MainPID present | PASS |
| Service idempotency | second apply: "service already matches desired state" | same systemctl state | PASS |
| Service teardown | apply exit 0 (stop+disable) | `ActiveState=inactive`, `UnitFileState=disabled` | PASS |
| Package removal | apply exit 0 | `dpkg-query` → exit 1 "no packages found matching tree" | PASS |
| Removal idempotency | second apply: "package already in desired state" | same absence | PASS |
| Privilege / sudo boundary | n/a | `sudo -n -- /usr/bin/id` → `uid=0(root)` | PASS |
| Final safe plan | plan exit 0 | n/a | PASS |

Sinter's facts on this host resolved to `os_name=Ubuntu, os_family=debian,
os_version=26.04, arch=x86_64` — no version gate, exactly as designed.

### Exit-code premise (collector correctness)

The R3 collector defect (expecting apply-failure exit 1/2) was **not** repeated.
The corrected premise was used throughout: a Sinter apply refusal/failure exits
**5**. The two intentional negative rows returned exactly exit 5 with
`status: apply_failed`, which is correct product behavior and is recorded as a
PASS, not a failure.

## 10. Independent OS-state verification

Every mutation and non-mutation was re-observed with normal OS tools rather than
inferred from Sinter output: `dpkg-query`, `dpkg -V`, `dpkg -L`, `stat`,
`sha256sum`, `getfattr`, `systemctl is-active/is-enabled/show`, and direct
absence tests. Before/after captures for the refusal case prove the protected
file was byte-for-byte unchanged.

## 11. Idempotency

Convergence was demonstrated by executing each resource twice and confirming the
second run reported "already in desired state" **and** that independent OS state
was unchanged: package (install, remove), file, service, and command guard. For
the guard, inode/mtime/ctime were compared across a deliberate 1-second time
separation so suppression is independently provable, not merely asserted.

## 12. Cleanup

Bounded cleanup ran and was independently verified:

- test package `tree`: removed; `dpkg-query` confirms absence
- `/root/sinter-b2-ubuntu` fixture tree: removed; `/root` clean
- temporary sleep unit: stopped, disabled, removed, `daemon-reload`; no Sinter unit remains
- second cleanup run: exit 0 (cleanup itself idempotent)
- final independent sweep: no Sinter-managed acceptance fixtures or resources
  remain under `/var/tmp`, `/root`, or `/etc/systemd/system`. Under `/tmp` the
  captured sweep still listed collector/evidence infrastructure files
  (`sinter-b2-ubuntu-raw.json`, `sinter-b2-ubuntu-raw.stderr`,
  `sinter-b2-ubuntu-runner.py`, and the transferred candidate copy
  `sinter-candidate`). These are acceptance infrastructure — collector, raw
  evidence, runner, and candidate copy — **not** failed Sinter-managed
  resources, and their presence at capture time is not evidence of a cleanup
  failure of the managed-resource acceptance contract. This raw capture does
  not independently establish later removal of collector/candidate files;
  no such removal is asserted by this finalization. The original evidence
  is preserved exactly, including the recorded infrastructure files.

The intentionally-installed `attr` host-preparation package is retained, as
recorded in §7; the test package and managed fixtures are independently absent.

## 13. Sensitive-output verification

A fresh fake canary (`SINTER_B2_FAKE_SECRET_<random>`) was generated in the
collector and emitted by a `sensitive: true` command resource to both stdout and
stderr. The complete stdout+stderr of validate (text/JSON), plan (JSON, verbose),
and apply (text/JSON, verbose) was searched exactly for the canary value: **zero
occurrences**; the failure surfaced as `<redacted>`. Only the canary's SHA-256
and its prefix are recorded in evidence (`9b0f4ba58b28bb86c6ad4b8a884a2578c733590eb9596f838cfb2c0f86742d00`);
the canary-bearing recipe is intentionally excluded from the bundle.

## 14. Failures, retries, and collector issues

Two collector (test-harness) defects in my own runner were found and fixed before
the successful run. **Neither was a Sinter product defect**, and neither was
converted into a PASS or a skip:

1. **dpkg-query marker channel.** My runner first asserted the absent marker in
   `stdout`. On Debian/Ubuntu, `dpkg-query` writes "no packages found matching
   tree" to **stderr** (exit 1) — unlike `rpm`, which writes to stdout. The
   product had not even executed at that point. Corrected to match the channel.
2. **`sensitive` field placement.** My runner first placed `sensitive` inside
   `with`. Sinter's strict `validate` correctly **rejected** this with exit 2
   ("unknown field with.sensitive") — correct fail-closed product behavior that
   caught my malformed recipe. Fixed to the resource-level placement used by the
   R3 contract.

Each failed attempt stopped immediately, cleaned up, and left the host clean
before the next run; the successful run is the one whose evidence is included.

## 15. B2 verdict

**B2: CLOSED**

All closure conditions are met: Ubuntu 26.04.x, x86_64, qualifying real/cloud VM,
fresh acceptance run, exact candidate SHA verified on host, required acceptance
cases completed, independent OS-state verification completed, idempotency
completed, required cleanup completed, sensitive-output verification completed,
no unexplained Sinter product failure, and no evidence-integrity problem.

## 16. Remaining blockers

None for B2.

Notes (not blockers, no action taken within this pass's scope):

- The pre-existing `ubuntu01` still refuses TCP/22 from the earlier `ssh.socket`
  incident. It was deliberately left untouched per the safety rules. If its
  recovery is desired, that is a separate, explicitly-scoped action outside B2.
- The freshly provisioned evidence VM was left `RUNNING` so its state remains
  available for independent re-verification; it can be deleted when review is
  complete.
- Pre-existing unrelated working-tree modifications (docs, `opencode.json`,
  `.DS_Store`) were preserved exactly as found and not committed.
