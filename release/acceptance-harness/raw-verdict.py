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
# Usage: raw-verdict.py <raw.log> <expected-ids.txt> <run_start_iso> <acc_rc>
# Prints the verdict token; exit 0 only for PASS.
# ============================================================================
import os
import re
import sys

VERDICTS_NONPASS_EXIT = 1


def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None


def main():
    if len(sys.argv) != 5:
        print("usage: raw-verdict.py <raw.log> <expected-ids.txt> <run_start_iso> <acc_rc>", file=sys.stderr)
        return 2
    raw_path, ids_path, run_start, acc_rc = sys.argv[1:5]

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
    m = re.match(r"^== acceptance end \S+ passed=(\d+) failed=(\d+) skipped=(\d+)\s*$", ends[0])
    if not m:
        print("MARKER_MALFORMED"); return VERDICTS_NONPASS_EXIT
    passed, failed, skipped = int(m.group(1)), int(m.group(2)), int(m.group(3))

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
