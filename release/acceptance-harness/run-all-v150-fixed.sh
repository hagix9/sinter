#!/bin/bash
# ============================================================================
# Sinter Step 7-9 acceptance — sequential runner  --  HARNESS-FIX WORKING COPY
# (NOT an official acceptance artifact; do not publish. See reports/.)
#
# Differences from the original run-all-v150.sh:
#   * FAIL-FAST: on the first non-PASS target the loop stops; no further target
#     is run.
#   * NO automatic retry of a target (the original retried each target up to 3x).
#   * NO GO is recorded here at all. The best this runner can say is
#     ALL_TARGETS_PASS_PENDING_OWNER_APPROVAL; the GO gate is in
#     collect-evidence-fixed.py and needs an explicit Owner-approval file.
# ============================================================================
set -u
OUT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
RUN_TARGET="$HERE/run-target-v150-fixed.sh"
SPECS=${SINTER_SPECS:-"ubuntu24:ubuntu2404:no:no
ubuntu26:ubuntu2604:no:no
rocky98:rocky9:no:no
rocky102:rocky10:no:no
rhel9:rhel9:no:no
alma9:alma9:no:no
alma10:alma10:no:no
rhel10-r2:rhel10:yes:yes"}

mkdir -p "$OUT"
echo "===== run-all (fixed, fail-fast) start $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
STOPPED=0
for spec in $SPECS; do
  vm=${spec%%:*}; rest=${spec#*:}
  label=${rest%%:*}; rest=${rest#*:}
  need_ip=${rest%%:*}; rest=${rest#*:}
  make_cache=${rest%%:*}
  rid="${label}-$(date -u +%Y%m%dT%H%M%SZ)"
  echo "--- [$label] target ($vm, need_ip=$need_ip, make_cache=$make_cache) run_id=$rid"
  bash "$RUN_TARGET" "$vm" "$label" "$OUT" "$need_ip" "$make_cache" "$rid"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "### [$label] NOT PASS (rc=$rc) — STOPPING; no further targets are run"
    STOPPED=1
    break
  fi
  echo "### [$label] PASS"
done

if [ "$STOPPED" = 1 ]; then
  echo "overall: NO-GO (a target did not pass; fail-fast stopped the run)"
  echo "===== run-all (fixed) done $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
  exit 1
fi
echo "overall: ALL_TARGETS_PASS_PENDING_OWNER_APPROVAL"
echo "===== run-all (fixed) done $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
