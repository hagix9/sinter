#!/usr/bin/env python3
# ============================================================================
# F1: strict verdict for one target raw acceptance log  --  HARNESS-FIX COPY
#
# PASS requires ALL of:
#   1. acceptance process exit code == 0
#   2. exactly one end marker `== acceptance end ...`
#   3. the end marker reports passed == expected count
#   4. failed == 0
#   5. skipped == 0
#   6. every expected check id appears exactly once as `== check <id> ok`
#   7. no `== check <id> FAIL` / `SKIP` line
#   8. the raw log exists and is non-empty
#   9. the raw log belongs to THIS run (acceptance start >= run start)
# Any anomaly, unparsable input, contradiction, id/clock mismatch => non-PASS.
#
# NOT APPLICABLE (v1.15.0, DESIGN §47.3): a `== check <id> NOT_APPLICABLE
# <reason>` line is accepted only when the applicability table lists (id,
# reason, label) and the log proves the reason with exactly one fixed
# observation line (`== observe nm-presence nmcli=absent service=<inactive|not-found>`
# for NM_NOT_INSTALLED). Such a check leaves the expected set; it is never counted
# as passed, and the end marker must carry `not_applicable=<n>`.
#
# Usage: raw-verdict.py <raw.log> <expected-ids.txt> <run_start_iso> <acc_rc>
#                       [<applicability.json> <label>]
# Prints the verdict token; exit 0 only for PASS.
# ============================================================================
import json
import os
import re
import sys

VERDICTS_NONPASS_EXIT = 1


def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None


OBSERVE_NM = re.compile(r"^== observe nm-presence nmcli=(present|absent) service=(active|inactive|not-found)$", re.M)
PROOFS = {"NM_NOT_INSTALLED": "nm"}


def load_table(path):
    """(check, reason) -> set of labels, or None when the table is unusable."""
    try:
        doc = json.loads(open(path, encoding="utf-8").read())
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("schema") != "sinter-acceptance-applicability/1":
        return None
    out = {}
    for e in doc.get("entries") or []:
        if not isinstance(e, dict):
            return None
        c, r, t = e.get("check"), e.get("reason"), e.get("targets")
        if not (isinstance(c, str) and isinstance(r, str) and isinstance(t, list)
                and r in PROOFS and all(isinstance(x, str) for x in t)):
            return None
        out[(c, r)] = set(t)
    return out


def proven(text, reason):
    """The log proves the reason with exactly one fixed observation line."""
    if PROOFS.get(reason) == "nm":
        obs = OBSERVE_NM.findall(text)
        all_lines = re.findall(r"^== observe nm-presence.*$", text, re.M)
        return (len(obs) == 1 and len(all_lines) == 1 and obs[0][0] == "absent"
                and obs[0][1] in ("inactive", "not-found"))
    return False


def main():
    if len(sys.argv) not in (5, 7):
        print("usage: raw-verdict.py <raw.log> <expected-ids.txt> <run_start_iso> <acc_rc> [<applicability.json> <label>]", file=sys.stderr)
        return 2
    raw_path, ids_path, run_start, acc_rc = sys.argv[1:5]
    table_path, label = (sys.argv[5], sys.argv[6]) if len(sys.argv) == 7 else (None, None)

    if acc_rc == "timeout":
        print("TIMEOUT"); return VERDICTS_NONPASS_EXIT

    text = read(raw_path)
    if not text or not text.strip():
        print("NO_RAW_LOG"); return VERDICTS_NONPASS_EXIT

    ids_text = read(ids_path)
    if not ids_text:
        print("ERROR_EXPECTED_IDS"); return VERDICTS_NONPASS_EXIT
    expected = [l.strip() for l in ids_text.splitlines() if l.strip()]
    expected_set = set(expected)

    # end marker: must exist exactly once
    ends = re.findall(r"^== acceptance end .*$", text, re.M)
    if len(ends) == 0:
        print("MARKER_MISSING"); return VERDICTS_NONPASS_EXIT
    if len(ends) > 1:
        print("MARKER_DUPLICATE"); return VERDICTS_NONPASS_EXIT
    m = re.match(r"^== acceptance end \S+ passed=(\d+) failed=(\d+) skipped=(\d+)(?: not_applicable=(\d+))?\s*$", ends[0])
    if not m:
        print("MARKER_MALFORMED"); return VERDICTS_NONPASS_EXIT
    passed, failed, skipped = int(m.group(1)), int(m.group(2)), int(m.group(3))
    na_count = int(m.group(4)) if m.group(4) is not None else None

    # freshness / run correspondence (item 9)
    starts = re.findall(r"^== acceptance start (\S+)", text, re.M)
    if len(starts) != 1:
        print("START_MARKER_BAD"); return VERDICTS_NONPASS_EXIT
    raw_start = starts[0]
    if run_start and raw_start < run_start:
        print("STALE_RAW_LOG"); return VERDICTS_NONPASS_EXIT

    ok_ids = re.findall(r"^== check (\S+) ok$", text, re.M)
    fail_ids = re.findall(r"^== check (\S+) FAIL$", text, re.M)
    skip_ids = re.findall(r"^== check (\S+) SKIP$", text, re.M)
    na = re.findall(r"^== check (\S+) NOT_APPLICABLE (\S+)$", text, re.M)
    other = [l for l in re.findall(r"^== check .*$", text, re.M)
             if not re.match(r"^== check \S+ (ok|FAIL|SKIP|NOT_APPLICABLE \S+)$", l)]
    if other:
        print("CHECK_LINE_MALFORMED"); return VERDICTS_NONPASS_EXIT

    # NOT APPLICABLE: listed in the table for this label and proven in the log.
    na_ids = [i for i, _ in na]
    if na:
        table = load_table(table_path) if table_path else None
        if table is None:
            print("NOT_APPLICABLE_WITHOUT_TABLE"); return VERDICTS_NONPASS_EXIT
        for cid, reason in na:
            if label not in table.get((cid, reason), set()):
                print("NOT_APPLICABLE_NOT_ALLOWED %s %s" % (cid, reason)); return VERDICTS_NONPASS_EXIT
            if not proven(text, reason):
                print("NOT_APPLICABLE_NOT_PROVEN %s %s" % (cid, reason)); return VERDICTS_NONPASS_EXIT
            if cid not in expected_set:
                print("NOT_APPLICABLE_UNKNOWN_CHECK %s" % cid); return VERDICTS_NONPASS_EXIT
        if len(na_ids) != len(set(na_ids)) or set(na_ids) & (set(ok_ids) | set(fail_ids) | set(skip_ids)):
            print("CHECK_DUPLICATE"); return VERDICTS_NONPASS_EXIT
    if (na_count or 0) != len(na):
        print("NOT_APPLICABLE_COUNT_MISMATCH"); return VERDICTS_NONPASS_EXIT
    expected = [e for e in expected if e not in set(na_ids)]
    expected_set = set(expected)

    if acc_rc != "0":
        print("FAIL"); return VERDICTS_NONPASS_EXIT
    if fail_ids or skip_ids:
        print("FAIL"); return VERDICTS_NONPASS_EXIT
    if failed != 0 or skipped != 0:
        print("COUNTS_NONZERO"); return VERDICTS_NONPASS_EXIT

    # duplicate ok ids
    if len(ok_ids) != len(set(ok_ids)):
        print("CHECK_DUPLICATE"); return VERDICTS_NONPASS_EXIT
    if set(ok_ids) != expected_set:
        missing = sorted(expected_set - set(ok_ids))
        extra = sorted(set(ok_ids) - expected_set)
        print("CHECK_SET_MISMATCH missing=%s extra=%s" % (missing, extra))
        return VERDICTS_NONPASS_EXIT
    if passed != len(expected) or len(ok_ids) != len(expected):
        print("CHECK_COUNT_MISMATCH passed=%d ok=%d expected=%d" % (passed, len(ok_ids), len(expected)))
        return VERDICTS_NONPASS_EXIT

    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
