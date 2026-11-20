# Release acceptance harness

The scripts that run RELEASE.md steps 7–9 (target acceptance of the frozen
artifact) on real cloud machines. They are a minimal, fail-closed driver, not
a provisioning system: the target instances must already exist, and nothing
here creates, deletes or modifies them beyond start/stop and an optional
temporary external IP that is removed again.

## Configuration

Everything environment- or release-specific comes from the environment;
nothing is hardcoded and nothing has a default. Copy `harness.env.example`
to a place **outside the repository**, fill it in and load it with
`set -a; . <file>; set +a`. A missing or malformed value (including an
instance name or label that is not a plain name) stops the run with exit 64
before any cloud call.

| Variable | Meaning |
|----------|---------|
| `SINTER_PROJECT`, `SINTER_ZONE` | cloud project and zone of the targets |
| `SINTER_SPECS` | one `<instance>:<label>:<need_ip>:<make_cache>` per line |
| `SINTER_ARTIFACT` | the frozen tarball `sinter-v<version>-linux-x86_64.tar.gz` |
| `SINTER_RC_COMMIT` | full 40-hex release-candidate commit |
| `SINTER_EXP_ART`, `SINTER_EXP_EXE` | step-6 tarball / executable SHA-256 |
| `SINTER_EXP_VER` | expected `sinter --version` line |
| `SINTER_SANITIZE_PATTERNS` | optional: a local, untracked `<regex><TAB><replacement>` file with extra identifiers to mask in published logs |
| `SINTER_ACCEPTANCE_SCOPE`, `SINTER_P5_TARGETS` | collector only (from v1.15.0): the approved tier, `full` (default) or `patch`, and the comma-separated target set. `full` needs exactly the eight labels; `patch` needs `ubuntu2404`, `rocky9` and one of `ubuntu2604`, `rocky10`, `rhel10`, `alma10`. Anything else stops with exit 64 |

`GCLOUD` may name a different `gcloud` executable (the tests use a fake one).

## Flow

`run-all.sh <out>` runs `run-target.sh` once per spec, sequentially and
fail-fast (no retry). For one target, `run-target.sh`:

1. verifies the local tarball against `SINTER_EXP_ART` (refuses to start on a
   mismatch);
2. records the boot disk's source image and image id (`source_image`,
   `source_image_id` in `run.json`); no provenance → `ERROR`;
3. starts the instance, uploads the harness and the tarball, and re-checks
   the tarball hash on the target;
4. runs `target-prep.sh` after removing any earlier `/tmp/prep.rc`; it stops
   the automatic-update timers and waits (at most `SINTER_PREP_QUIET_SECONDS`,
   default 900; the call itself is bounded by `SINTER_PREP_TIMEOUT`, default
   1200) for any package manager already running; a stale, missing or non-zero
   result → `ERROR`;
5. optionally refreshes dnf metadata; a non-zero `dnf makecache` → `ERROR`;
6. runs the frozen `acceptance-target.sh` in a private per-run directory,
   hashes the raw log on the target, fetches it, and stops with
   `RAW_SHA_MISMATCH` unless the fetched copy has the same SHA-256;
7. derives the verdict with `raw-verdict.py`, cleans up only its own per-run
   directory, and stops the instance on every path.

Every run writes `runs/<run-id>/` (`driver.log`, `run.json`, `result`, the
raw log and a `scripts/` copy with its SHA-256 sums) and appends to
`INDEX.tsv`; a used run directory is never reused. `collect-evidence.py`
gathers the PASS runs; GO requires a verified PASS for every label of the
approved target set (Tier F: all eight; the set comes only from
`SINTER_ACCEPTANCE_SCOPE` and `SINTER_P5_TARGETS`, never from the runs found)
and an Owner approval signed with `approve.py`. `sanitize.py <label> <raw> <out>` writes the publishable log: it
masks the project, the zone and the instance names from `SINTER_SPECS` as
literals, plus generic hosts, users, paths and addresses, and writes nothing
if any of the run's identifiers would remain.

## Checks

`acceptance-target.sh` defines the checks; `derive-expected-checks.sh`
writes their ids to `expected-check-ids.txt` (60 from v1.12.0, 76 from
v1.15.0). Each prints one `== check <id> ok|FAIL` line, or
`== check <id> NOT_APPLICABLE <reason>` (below). From v1.12.0 two sections cover the plugin
commands (`plugin-checks`: list, verify, install, remove and the partial mutate
permission, against a plugin root inside the run's private directory, never the
default root, and without running `firewall-cmd`) and `recipe_vars`
(`recipe-vars-checks`: a project in the run's directory writing files under the
acceptance state directory, removed again). Applying firewalld rules on a real
firewalld is not part of this matrix.

From v1.15.0 the `v1150-checks` section adds `timer-create`,
`timer-idempotent`, `timer-running`, `timer-absent`, `timer-calendar-invalid`,
`service-timer-name` (a disposable `sinter-acc-timer` unit), `risk-static-refusal`
(a network-affecting apply without approval is refused before any connection),
`nm-profile-crud` (an inactive NetworkManager profile bound to a non-existent
interface, applied over the loopback SSH management path, verified with
`nmcli` and removed), and `discover-readonly` / `discover-roundtrip` (planted
files with a synthetic credential under `/etc/sinter-acc-disc`; the package
database and `/etc` digests are unchanged, the credential never appears, and an
audit of the generated recipe reports no drift). Everything is removed again.

From v1.15.0 P7-R1 the `fw03-checks` section runs firewalld 0.3.0 on
disposable objects (zone `sintacc`, dummy interface `sintacc0`, RFC 5737
networks) over SSH to 127.0.0.1 with the declared loopback management path:
`fw03-zone`, `fw03-interface`, `fw03-source`, `fw03-reload`,
`risk-approved-apply` (approval request, `sinter approve` on a
pseudo-terminal, apply; approve refuses a pipe, a wrong digest and an altered
request; apply refuses no approval, another change and reuse) and
`fw03-no-residue`. `target-prep.sh` installs and starts firewalld where it is
missing; unless the zone of the default-route interface allows ssh or 22/tcp
and a new loopback SSH session works, it puts firewalld back as it was and
stops. The zone configuration of the VM's management path (and of every other
zone) is observed after every change; at the end of the checks the section
removes what it created and compares the firewall with its state before (a
harness killed in the middle leaves them on the disposable VM). It never
removes a zone, zone file or interface that existed before it started. A missing prerequisite
(firewalld not running, firewalld 0.3.0 not in the sinter under test) fails
all six checks; they are never SKIP or NOT APPLICABLE. They pass only after
firewalld 0.3.0 is registered and the reload rule on a loopback path is
measured (`docs/design/v1.15.0-release-and-acceptance.md` §3.2).

NOT APPLICABLE: `applicability.json` lists the only allowed
(check, reason, targets) entries; in v1.15.0 `nm-profile-crud` with
`NM_NOT_INSTALLED` on `ubuntu2404` and `ubuntu2604`. The check first prints
exactly one `== observe nm-presence nmcli=<present|absent>
service=<active|inactive|not-found>` line; only `nmcli=absent` with a listed
entry yields NOT APPLICABLE. An installed but stopped NetworkManager runs the
check (and fails it). The end line adds `not_applicable=<n>`. `raw-verdict.py`
(given the table and the label) and the manifest checker both verify the
table and the observation line; a NOT_APPLICABLE line without them is a FAIL.

Tests: `python3 -m unittest discover -s release/tests`
(`test_acceptance_harness.py` drives these scripts against a fake `gcloud`;
`test_acceptance_v1150.py` covers the v1.15.0 raw verdict, NOT APPLICABLE,
the target set and the new check section statically;
`test_acceptance_fw03_checks.py` runs the firewalld section against a fake
`sinter`, `firewall-cmd`, `ip` and `ssh` with one defect at a time;
`test_acceptance_v190_checks.py` and `test_acceptance_v1120_checks.py` run the
check sections against a fake `sinter` with one defect at a time, and the
plugin section against a built binary when `SINTER_ACCEPTANCE_REAL_BIN` is set).
