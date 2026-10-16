#!/usr/bin/env python3
# ============================================================================
# Owner approval helper  --  HARNESS-FIX COPY
# Produces an HMAC-signed approval binding {owner, RC, artifact, exact evidence
# set, time}. The signing key is supplied out of band and is NEVER written here.
# A bare text "GO" is not a valid approval; collect-evidence-fixed.py verifies
# the signature, the evidence_digest and the timestamp.
#
# Usage:
#   approve-fixed.py <out-dir> --key FILE --owner NAME --out FILE [--decision GO]
# ============================================================================
import argparse
import glob
import hashlib
import hmac
import json
import os
import sys
import time

LABELS = ["ubuntu2404", "ubuntu2604", "rocky9", "rocky10",
          "rhel9", "rhel10", "alma9", "alma10"]
RC_COMMIT = "0fa75e47e82f2f9b0d74371fbdf4bd2ebea05e87"
EXP_ART = "8abe3a83db0a459f6df5f94435300cf50f6a8251f5189dc7fd58dbbf5ef9da71"
CANON_FIELDS = ["decision", "owner", "rc_commit", "artifact_sha256", "evidence_digest", "approved_at"]


def evidence_digest(accepted):
    lines = []
    for label in sorted(accepted):
        r = accepted[label]
        lines.append("%s\t%s\t%s\t%s" % (label, r.get("run_id", ""), r.get("verdict", ""), r.get("raw_log_sha256", "")))
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def canonical(fields):
    return "\n".join("%s=%s" % (k, fields.get(k, "")) for k in CANON_FIELDS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--key", required=True)
    ap.add_argument("--owner", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--decision", default="GO")
    a = ap.parse_args()

    accepted = {}
    for path in sorted(glob.glob(os.path.join(a.outdir, "runs", "*", "run.json"))):
        try:
            m = json.load(open(path))
        except Exception:
            continue
        if m.get("verdict") == "PASS" and m.get("label") in LABELS and m["label"] not in accepted:
            accepted[m["label"]] = m

    fields = {
        "decision": a.decision,
        "owner": a.owner,
        "rc_commit": RC_COMMIT,
        "artifact_sha256": EXP_ART,
        "evidence_digest": evidence_digest(accepted),
        "approved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    key = open(a.key, "rb").read()
    fields["signature"] = hmac.new(key, canonical(fields).encode(), hashlib.sha256).hexdigest()

    with open(a.out, "w") as fh:
        for k in CANON_FIELDS + ["signature"]:
            fh.write("%s: %s\n" % (k, fields[k]))
    print("wrote approval: %s (evidence_digest=%s)" % (a.out, fields["evidence_digest"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
