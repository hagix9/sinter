#!/usr/bin/env python3
# ============================================================================
# Sinter release acceptance — evidence collector / GO gate (RELEASE.md
# steps 7-9). The RC commit and artifact SHA-256 come from SINTER_RC_COMMIT
# and SINTER_EXP_ART (required); GO always requires all eight release target
# labels (the matrix cannot be narrowed from the environment).
#
# F2: never trust run.json's own "PASS" string. Re-derive the truth from the
#     evidence bytes:
#       * raw.log present; SHA-256 recomputed == recorded
#       * raw.log re-verified with the same strict rule as the driver
#         (single end marker, expected check set, failed=0, skipped=0,
#          passed==expected, label match, fresh start)
#       * label is a known target; run_id not duplicated
#       * meta.rc_commit / meta.artifact_sha256 match the RC under test
#       * raw log OBSERVED_ARTIFACT_SHA (when present) matches the artifact
#       * executed-script copies exist and their SHA-256 matches SHA256SUMS
#       * all 8 labels present; ANY non-PASS run anywhere => NO-GO
#     missing / contradiction / tamper / duplicate / unknown => NO-GO.
#
# Owner approval: a bare self-declaration is not trusted. The approval must
# bind owner + RC + artifact + the EXACT evidence set (evidence_digest) + time,
# and be HMAC-signed with a key the Owner holds out of band. Without a valid
# signature and current digest the verdict is PENDING_OWNER_APPROVAL.
#
# Usage:
#   collect-evidence.py <out-dir> [--approval-key FILE] [--owner-approval FILE]
#                            [--expected-ids FILE] [--write-verdict]
# ============================================================================
import glob
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LABELS = ["ubuntu2404", "ubuntu2604", "rocky9", "rocky10",
                  "rhel9", "rhel10", "alma9", "alma10"]
SKEW_SECONDS = 300

def required_env():
    """RC commit and artifact SHA-256 of the release under test, from the
    environment only (no defaults: a missing or malformed value stops)."""
    rc = os.environ.get("SINTER_RC_COMMIT", "")
    art = os.environ.get("SINTER_EXP_ART", "")
    if not re.fullmatch(r"[0-9a-f]{40}", rc) or not re.fullmatch(r"[0-9a-f]{64}", art):
        sys.stderr.write("SINTER_RC_COMMIT (40 hex) and SINTER_EXP_ART (64 hex) are required\n")
        sys.exit(64)
    # The GO gate always requires the full release matrix; it cannot be
    # narrowed from the environment.
    return rc, art, list(DEFAULT_LABELS)


CANON_FIELDS = ["decision", "owner", "rc_commit", "artifact_sha256", "evidence_digest", "approved_at"]


def utc_epoch(iso):
    """Parse an ISO-8601 ...Z timestamp as UTC, independent of the host TZ.
    Returns None for anything unparsable (callers fail closed)."""
    if not iso:
        return None
    s = iso.strip()
    try:
        dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(dt.timestamp())


def raw_start_of(text):
    m = re.search(r"^== acceptance start (\S+)", text, re.M)
    return m.group(1) if m else None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(65536), b""):
            h.update(b)
    return h.hexdigest()


def parse_kv(path):
    out = {}
    for line in open(path, encoding="utf-8").read().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def canonical(fields):
    return "\n".join("%s=%s" % (k, fields.get(k, "")) for k in CANON_FIELDS)


def evidence_digest(accepted):
    """Deterministic digest over the accepted run set (sorted by label)."""
    lines = []
    for label in sorted(accepted):
        r = accepted[label]
        lines.append("%s\t%s\t%s\t%s" % (label, r.get("run_id", ""), r.get("verdict", ""), r.get("raw_log_sha256", "")))
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def verify_raw(run_dir, label, expected_ids, run_start):
    """Call the shared strict verifier; returns (verdict_token, detail)."""
    raw = os.path.join(run_dir, "raw.log")
    if not os.path.exists(raw) or os.path.getsize(raw) == 0:
        return "NO_RAW_LOG", ""
    try:
        p = subprocess.run([sys.executable, os.path.join(HERE, "raw-verdict.py"),
                            raw, expected_ids, run_start or "", "0"],
                           capture_output=True, text=True)
    except OSError as e:
        return "VERIFIER_ERROR", str(e)
    return p.stdout.strip(), p.stderr.strip()


def check_scripts(run_dir):
    d = os.path.join(run_dir, "scripts")
    sums = os.path.join(d, "SHA256SUMS")
    if not os.path.exists(sums):
        return ["scripts/SHA256SUMS missing"]
    problems = []
    have = set()
    for line in open(sums, encoding="utf-8"):
        m = re.match(r"^([0-9a-f]{64})\s+\*?(.+)$", line.strip())
        if not m:
            continue
        digest, name = m.group(1), os.path.basename(m.group(2))
        p = os.path.join(d, name)
        if not os.path.exists(p):
            problems.append("script %s listed but missing" % name); continue
        if sha256_file(p) != digest:
            problems.append("script %s sha mismatch" % name)
        have.add(name)
    if "acceptance-target.sh" not in have:
        problems.append("acceptance-target.sh not preserved")
    return problems


def main():
    args = sys.argv[1:]
    out = None
    approval_key = None
    approval = None
    expected_ids = os.path.join(HERE, "expected-check-ids.txt")
    write_verdict = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--approval-key":
            approval_key = args[i + 1]; i += 2
        elif a == "--owner-approval":
            approval = args[i + 1]; i += 2
        elif a == "--expected-ids":
            expected_ids = args[i + 1]; i += 2
        elif a == "--write-verdict":
            write_verdict = True; i += 1
        else:
            out = a; i += 1
    if not out:
        print("usage: collect-evidence.py <out-dir> [--approval-key FILE] [--owner-approval FILE]", file=sys.stderr)
        return 2
    global RC_COMMIT, EXP_ART, LABELS
    RC_COMMIT, EXP_ART, LABELS = required_env()

    runs = []
    seen_ids = set()
    for path in sorted(glob.glob(os.path.join(out, "runs", "*", "run.json"))):
        try:
            meta = json.load(open(path))
        except Exception as e:
            meta = {"run_id": os.path.basename(os.path.dirname(path)), "verdict": "UNREADABLE", "error": str(e)}
        meta["_dir"] = os.path.dirname(path)
        dup = meta.get("run_id") in seen_ids
        seen_ids.add(meta.get("run_id"))
        meta["_dup_id"] = dup
        runs.append(meta)

    lines = ["# Sinter %s acceptance — collected runs" % os.environ.get("SINTER_EXP_VER", "(version unset)"), ""]
    lines.append("label\trun_id\tverdict\tfile_verdict\tsha_ok\tscripts_ok\tacceptance_end")
    problems = []
    accepted = {}

    for r in runs:
        lb = r.get("label", "?")
        rd = r.get("_dir", "")
        file_verdict = "-"
        sha_ok = "-"
        scripts_ok = "-"
        if r["verdict"] == "PASS":
            # F2: re-derive from bytes
            raw = os.path.join(rd, "raw.log")
            if os.path.exists(raw):
                rec = r.get("raw_log_sha256", "")
                sha_ok = "yes" if (rec and sha256_file(raw) == rec) else "NO"
                if sha_ok == "NO":
                    problems.append("%s: raw.log sha mismatch (tampered or not recorded)" % lb)
                fv, _ = verify_raw(rd, lb, expected_ids, r.get("started_at"))
                file_verdict = fv
                if fv != "PASS":
                    problems.append("%s: raw re-verification = %s" % (lb, fv))
                # label correspondence inside the raw log
                try:
                    head = open(raw, encoding="utf-8", errors="replace").read()
                    if ("label=%s" % lb) not in head:
                        problems.append("%s: raw.log label does not match" % lb)
                    m = re.search(r"OBSERVED_ARTIFACT_SHA=(\S+)", head)
                    if m and m.group(1) != EXP_ART:
                        problems.append("%s: raw artifact sha %s != expected" % (lb, m.group(1)))
                    # A3/B2: RUN_ID <-> raw.log correspondence.
                    rid = r.get("run_id", "")
                    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$", rid or ""):
                        problems.append("%s: run_id is not of a valid form" % lb)
                    rwp = r.get("remote_raw_path", "")
                    if not rwp or rid not in rwp:
                        problems.append("%s: remote_raw_path does not bind the run_id" % lb)
                    # B2: the fetched bytes must equal the server-side hash
                    rmsha = r.get("remote_raw_sha256", "")
                    if not rmsha:
                        problems.append("%s: no server-side raw log sha recorded" % lb)
                    elif sha256_file(raw) != rmsha:
                        problems.append("%s: raw log differs from the recorded server-side sha" % lb)
                    # The boot image must have been recorded for this run.
                    if not r.get("source_image") or not re.fullmatch(r"[0-9]+", str(r.get("source_image_id", ""))):
                        problems.append("%s: boot image provenance not recorded" % lb)
                    # A3: raw start must fall inside this run's [started_at, finished_at]
                    rs = utc_epoch(raw_start_of(head))
                    se = utc_epoch(r.get("started_at", ""))
                    fe = utc_epoch(r.get("finished_at", ""))
                    if rs is None:
                        problems.append("%s: raw start unparsable" % lb)
                    else:
                        if se is not None and rs + SKEW_SECONDS < se:
                            problems.append("%s: raw start precedes run start" % lb)
                        if fe is not None and rs - SKEW_SECONDS > fe:
                            problems.append("%s: raw start after run finish (foreign run?)" % lb)
                except OSError:
                    problems.append("%s: cannot read raw.log" % lb)
            else:
                file_verdict = "NO_RAW_LOG"
                problems.append("%s: PASS but raw.log missing" % lb)
            sp = check_scripts(rd)
            scripts_ok = "yes" if not sp else "NO"
            for x in sp:
                problems.append("%s: %s" % (lb, x))
            if r.get("rc_commit") != RC_COMMIT:
                problems.append("%s: rc_commit mismatch" % lb)
            if r.get("artifact_sha256") != EXP_ART:
                problems.append("%s: artifact sha mismatch" % lb)
            if lb in accepted:
                problems.append("%s: duplicate PASS run" % lb)
            else:
                accepted[lb] = r
        else:
            problems.append("%s: run %s verdict=%s" % (lb, r.get("run_id"), r.get("verdict")))
        if lb not in LABELS:
            problems.append("%s: unknown target label" % lb)
        if r.get("_dup_id"):
            problems.append("%s: duplicate run_id %s" % (lb, r.get("run_id")))
        lines.append("\t".join(str(r.get(k, "")) for k in ("label", "run_id", "verdict")) +
                     "\t" + file_verdict + "\t" + sha_ok + "\t" + scripts_ok + "\t" + str(r.get("acceptance_end", "")))

    for lb in LABELS:
        if lb not in accepted:
            problems.append("%s: no accepted PASS evidence" % lb)

    # ---- Owner approval authenticity --------------------------------------
    approval_state = "no owner-approval file"
    approved = False
    if approval and os.path.exists(approval):
        af = parse_kv(approval)
        dig = evidence_digest(accepted)
        if af.get("decision") != "GO":
            approval_state = "approval decision is not GO"
        elif af.get("rc_commit") != RC_COMMIT:
            approval_state = "approval rc_commit does not match RC"
        elif af.get("artifact_sha256") != EXP_ART:
            approval_state = "approval artifact does not match frozen artifact"
        elif af.get("evidence_digest") != dig:
            approval_state = "approval evidence_digest does not match current evidence (stale or wrong evidence set)"
        elif not approval_key or not os.path.exists(approval_key):
            approval_state = "no approval key provided: cannot prove approval authenticity"
        else:
            key = open(approval_key, "rb").read()
            want = hmac.new(key, canonical(af).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(want, af.get("signature", "")):
                approval_state = "approval signature invalid"
            else:
                # A2: freshness in UTC only; host TZ must not change the verdict.
                ap = utc_epoch(af.get("approved_at", ""))
                newest = max([utc_epoch(r.get("finished_at", "")) or 0 for r in runs] + [0])
                now = int(time.time())
                if ap is None:
                    approval_state = "approval timestamp unparsable"
                elif ap + SKEW_SECONDS < newest:
                    approval_state = "approval predates the newest acceptance run (stale)"
                elif ap - SKEW_SECONDS > now:
                    approval_state = "approval timestamp is in the future"
                else:
                    approved = True
                    approval_state = "verified: owner=%s at %s" % (af.get("owner", "?"), af.get("approved_at"))

    all_pass = (len(runs) > 0 and not problems and all(lb in accepted for lb in LABELS))
    if not all_pass:
        verdict = "NO-GO"
    elif not approved:
        verdict = "PENDING_OWNER_APPROVAL"
    else:
        verdict = "GO"

    lines += ["", "problems:" + (" none" if not problems else "")]
    for p in problems:
        lines.append("  - " + p)
    lines.append("evidence_digest: " + evidence_digest(accepted))
    lines.append("owner approval: " + approval_state)
    lines.append("overall verdict: " + verdict)
    text = "\n".join(lines) + "\n"

    try:
        with open(os.path.join(out, "summary.txt"), "w") as fh:
            fh.write(text)
        if write_verdict:
            with open(os.path.join(out, "VERDICT.txt"), "w") as fh:
                fh.write(verdict + "\n")
    except OSError as e:
        print("SAVE_FAILURE: cannot write summary/VERDICT: %s" % e, file=sys.stderr)
        return 70
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
