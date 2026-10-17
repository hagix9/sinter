#!/bin/bash
# ============================================================================
# GO gate (release acceptance). Needs SINTER_RC_COMMIT and SINTER_EXP_ART.
# Records GO only when collect-evidence.py returns GO, which requires:
#   all 8 labels PASS with re-verified evidence, no non-PASS run anywhere, and
#   an Owner-approval file that is HMAC-verified against a key the Owner holds,
#   binds the RC + frozen artifact + the exact evidence_digest, and is current.
# Without a valid key/signature the verdict stays PENDING_OWNER_APPROVAL.
# ============================================================================
set -u
OUT=$1; shift
APPROVAL=""; KEY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --owner-approval) APPROVAL=$2; shift 2 ;;
    --approval-key) KEY=$2; shift 2 ;;
    *) shift ;;
  esac
done
COLLECT="$(cd "$(dirname "$0")" && pwd)/collect-evidence.py"
ARGS=("$OUT")
[ -n "$APPROVAL" ] && ARGS+=(--owner-approval "$APPROVAL")
[ -n "$KEY" ] && ARGS+=(--approval-key "$KEY")
python3 "$COLLECT" "${ARGS[@]}" --write-verdict || { echo "collector failed (save/parse) — refusing GO"; exit 70; }
V=$(cat "$OUT/VERDICT.txt" 2>/dev/null || echo "NO-GO")
echo "VERDICT=$V"
if [ "$V" != GO ]; then
  echo "refusing to record GO without a verified Owner approval (verdict=$V)"
  exit 1
fi
exit 0
