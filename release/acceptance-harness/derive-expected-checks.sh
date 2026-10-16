#!/bin/bash
# ============================================================================
# Derive the expected acceptance check-id set from the OFFICIAL check harness
# (acceptance-target.sh). The expected check count is NOT hardcoded to any past
# report value; it is computed from the script that defines the checks.
#
# Usage: derive-expected-checks.sh [acceptance-target.sh] [out-file]
# ============================================================================
set -u
SRC=${1:-"$(cd "$(dirname "$0")" && pwd)/acceptance-target.sh"}
OUT=${2:-"$(cd "$(dirname "$0")" && pwd)/expected-check-ids.txt"}
# Every `check <id> ok|FAIL` call site names one check id. A check that has two
# call sites (ok / FAIL branch) still contributes one id.
grep -oE 'check [A-Za-z0-9_-]+ (ok|FAIL)' "$SRC" \
  | awk '{print $2}' | sort -u > "$OUT"
echo "wrote $(wc -l < "$OUT" | tr -d ' ') expected check ids to $OUT"
