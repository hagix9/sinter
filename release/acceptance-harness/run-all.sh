#!/bin/bash
# ============================================================================
# Sinter release acceptance — sequential runner (RELEASE.md steps 7-9).
#
# SINTER_SPECS lists the targets, one `<instance>:<label>:<need_ip>:<make_cache>`
# per line; it is required (instance names are environment-specific and are
# not kept in the repository). Every run-target.sh setting is required too.
#
#   * FAIL-FAST: on the first non-PASS target the loop stops; no further target
#     is run.
#   * NO automatic retry of a target (the original retried each target up to 3x).
#   * NO GO is recorded here at all. The best this runner can say is
#     ALL_TARGETS_PASS_PENDING_OWNER_APPROVAL; the GO gate is in
#     collect-evidence.py and needs an explicit Owner-approval file.
# ============================================================================
set -u
OUT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
RUN_TARGET="$HERE/run-target.sh"
SPECS=${SINTER_SPECS:-}
if [ -z "$SPECS" ]; then echo "MISSING REQUIRED CONFIGURATION: SINTER_SPECS (see harness.env.example)" >&2; exit 64; fi
for spec in $SPECS; do
  printf '%s' "$spec" | grep -qE '^[a-z0-9-]+:[a-z0-9]+:(yes|no):(yes|no)$' \
    || { echo "malformed SINTER_SPECS entry: $spec" >&2; exit 64; }
done

mkdir -p "$OUT"
echo "===== run-all (fail-fast) start $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
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
  echo "===== run-all done $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
  exit 1
fi
echo "overall: ALL_TARGETS_PASS_PENDING_OWNER_APPROVAL"
echo "===== run-all done $(date -u +%Y-%m-%dT%H:%M:%SZ) ====="
