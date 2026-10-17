#!/bin/bash
# ============================================================================
# Sinter release acceptance — one-target driver (RELEASE.md steps 7-9).
#
# Configuration comes only from the environment; there are no defaults for
# anything environment- or release-specific, and a missing value stops the run
# before any cloud call (exit 64). See harness.env.example:
#   SINTER_PROJECT SINTER_ZONE           the GCP project/zone of the targets
#   SINTER_ARTIFACT                      local release tarball
#                                        (sinter-v<version>-linux-x86_64.tar.gz)
#   SINTER_RC_COMMIT                     the release-candidate commit
#   SINTER_EXP_ART SINTER_EXP_EXE        expected tarball / executable SHA-256
#   SINTER_EXP_VER                       expected `sinter --version` line
# The tarball is verified locally before upload and again on the target; the
# target's boot-disk image (sourceImage + sourceImageId) is recorded; a raw log
# whose SHA-256 differs from the one computed on the target, a stale or
# non-zero prep.rc, and a failed metadata refresh all stop the run (non-PASS).
# Nothing is retried by a loop above this driver.
#
# B1: every non-complete / non-save-ok / non-cleanup path exits NON-ZERO; only a
#     fully verified PASS exits 0. The EXIT trap forces non-zero when it records
#     an incomplete run, and cannot re-enter or double-run finalize/cleanup.
# B2: RUN_ID is validated (charset/length), unique, and the fetched raw log is
#     bound to it by an exclusive per-run remote directory plus a server-side
#     SHA-256 recorded before fetch; the collector re-verifies id/target/log.
# B3: the driver never deletes or replaces an existing remote directory. The
#     per-run directory is created exclusively (mkdir, no rm -rf); a pre-existing
#     RUN_ID area stops the run; the real /var/tmp/sinter-acceptance is left
#     untouched (a private mount namespace redirects the frozen script's writes).
# Frozen acceptance-target.sh is UNCHANGED. No GO here.
# ============================================================================
set -u

VM=$1; LABEL=$2; OUT=$3; NEED_IP=${4:-no}; MAKE_CACHE=${5:-no}
RUN_ID=${6:-${LABEL}-$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}}
mkdir -p "$OUT" || { echo "cannot create OUT=$OUT" >&2; exit 64; }

# ---- B2: strict RUN_ID validation -----------------------------------------
if ! printf '%s' "$RUN_ID" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'; then
  echo "INVALID RUN_ID (charset/length): $RUN_ID" >&2; exit 65
fi

# ---- required configuration (fail closed, before any cloud call) ----------
missing=""
for v in SINTER_PROJECT SINTER_ZONE SINTER_ARTIFACT SINTER_RC_COMMIT SINTER_EXP_ART SINTER_EXP_EXE SINTER_EXP_VER; do
  [ -n "${!v:-}" ] || missing="$missing $v"
done
if [ -n "$missing" ]; then echo "MISSING REQUIRED CONFIGURATION:$missing (see harness.env.example)" >&2; exit 64; fi
PROJ=$SINTER_PROJECT
ZONE=$SINTER_ZONE
GCLOUD=${GCLOUD:-gcloud}
HERE=$(cd "$(dirname "$0")" && pwd)
H=${SINTER_HARNESS_DIR:-$HERE}
ART=$SINTER_ARTIFACT
RC_COMMIT=$SINTER_RC_COMMIT
EXP_ART=$SINTER_EXP_ART
EXP_EXE=$SINTER_EXP_EXE
EXP_VER=$SINTER_EXP_VER
TARNAME=$(basename "$ART")
if ! printf '%s' "$TARNAME" | grep -qE '^sinter-v[0-9]+\.[0-9]+\.[0-9]+-linux-x86_64\.tar\.gz$'; then
  echo "SINTER_ARTIFACT is not a release tarball name: $TARNAME" >&2; exit 64
fi
for v in "$EXP_ART" "$EXP_EXE"; do
  printf '%s' "$v" | grep -qE '^[0-9a-f]{64}$' || { echo "expected SHA-256 values must be 64 lowercase hex digits" >&2; exit 64; }
done
printf '%s' "$RC_COMMIT" | grep -qE '^[0-9a-f]{40}$' || { echo "SINTER_RC_COMMIT must be a full 40-hex commit id" >&2; exit 64; }
printf '%s' "$EXP_VER" | grep -qE '^sinter [0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$' \
  || { echo "SINTER_EXP_VER must look like 'sinter X.Y.Z'" >&2; exit 64; }
# VM and LABEL are expanded inside remote shell commands: allow only plain names.
printf '%s' "$VM" | grep -qE '^[a-z][a-z0-9-]{0,62}$' || { echo "invalid instance name" >&2; exit 64; }
printf '%s' "$LABEL" | grep -qE '^[a-z0-9]{1,32}$' || { echo "invalid target label" >&2; exit 64; }
[ -f "$ART" ] || { echo "SINTER_ARTIFACT does not exist: $ART" >&2; exit 64; }
LOCAL_ART=$(shasum -a 256 "$ART" | cut -d' ' -f1)
if [ "$LOCAL_ART" != "$EXP_ART" ]; then
  echo "LOCAL ARTIFACT SHA-256 MISMATCH: $LOCAL_ART != SINTER_EXP_ART; refusing to start" >&2; exit 64
fi
EXPECTED_IDS="$H/expected-check-ids.txt"
RAW_VERDICT="$HERE/raw-verdict.py"
REMOTE_WORK="/var/tmp/sinter-acceptance-$RUN_ID"
WRAPPER=/tmp/run-acceptance-wrapper.sh

SSH_TMO=${SINTER_SSH_TIMEOUT:-120}
SCP_TMO=${SINTER_SCP_TIMEOUT:-240}
SSH_WAIT_TRIES=${SINTER_SSH_WAIT_TRIES:-60}
UP_TRIES=${SINTER_UPLOAD_TRIES:-5}
POLL_TRIES=${SINTER_ACCEPT_POLL_TRIES:-160}
POLL_INT=${SINTER_ACCEPT_POLL_INTERVAL:-15}

RUN_DIR="$OUT/runs/$RUN_ID"
if [ -e "$RUN_DIR" ] && [ -n "$(ls -A "$RUN_DIR" 2>/dev/null)" ]; then
  echo "REFUSING to reuse a non-empty run directory: $RUN_DIR" >&2; exit 65
fi
mkdir -p "$RUN_DIR" || { echo "cannot create run dir $RUN_DIR" >&2; exit 65; }
[ -w "$RUN_DIR" ] || { echo "run dir not writable: $RUN_DIR" >&2; exit 65; }

RESULT_FILE="$RUN_DIR/result"
SOURCE_IMAGE=""
SOURCE_IMAGE_ID=""
FAULT=${SINTER_TEST_FAULT_SAVE:-}
RAW_FETCHED=0
IP_ADDED=no
RUN_START=""
SAVE_FAILED=0
CLEANUP_DONE=0
CLEANUP_OK=0
FINALIZED=0
IN_FINALIZE=0
REMOTE_MKDIR=0
CLEANUP_NOTE=""

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
if ! : > "$RUN_DIR/driver.log"; then echo "cannot create driver.log" >&2; exit 70; fi
exec > "$RUN_DIR/driver.log" 2>&1

save_fail() { SAVE_FAILED=1; echo "SAVE_FAILURE: $1"; printf 'SAVE_FAILURE: %s\n' "$1" >> "$RUN_DIR/SAVE_FAILURE" 2>/dev/null || true; }
require_file() { [ -s "$1" ] || save_fail "missing/empty $2 ($1)"; }
atomic_write() {
  local dest="$1" tmp="$1.tmp.$$"
  if ! printf '%s\n' "$2" > "$tmp"; then save_fail "cannot write $dest"; rm -f "$tmp"; return 1; fi
  if ! mv "$tmp" "$dest"; then save_fail "cannot rename into $dest"; rm -f "$tmp"; return 1; fi
  require_file "$dest" "$dest"; return 0
}

tmo() { local t=$1; shift; perl -e 'alarm shift; exec @ARGV' "$t" "$@"; }
gssh()   { tmo "$SSH_TMO" "$GCLOUD" compute ssh "$VM" --project="$PROJ" --zone="$ZONE" --quiet --tunnel-through-iap --command "$1" </dev/null 2>/dev/null; }
gscp()   { tmo "$SCP_TMO" "$GCLOUD" compute scp --project="$PROJ" --zone="$ZONE" --quiet --tunnel-through-iap "$@"; }
gpush()  { tmo "$SCP_TMO" "$GCLOUD" compute ssh "$VM" --project="$PROJ" --zone="$ZONE" --quiet --tunnel-through-iap --command "cat > $2" < "$1" 2>/dev/null; }
gstatus(){ "$GCLOUD" compute instances describe "$VM" --project="$PROJ" --zone="$ZONE" --format="get(status)" 2>/dev/null; }

fetch_raw() {
  [ -n "$VM" ] || return 1
  if [ "$FAULT" = raw ]; then rm -f "$RUN_DIR/raw.log"; RAW_FETCHED=0; return 1; fi
  local rtmp="/tmp/raw-$RUN_ID.log"
  gssh "sudo cp '$REMOTE_WORK/raw.log' '$rtmp' 2>/dev/null; sudo chmod 644 '$rtmp' 2>/dev/null; true"
  rm -f "$RUN_DIR/raw.log"
  if gscp "$VM:$rtmp" "$RUN_DIR/raw.log" >/dev/null 2>&1 && [ -s "$RUN_DIR/raw.log" ]; then RAW_FETCHED=1; return 0; fi
  if gssh "sudo cat '$REMOTE_WORK/raw.log' 2>/dev/null" > "$RUN_DIR/raw.log" 2>/dev/null && [ -s "$RUN_DIR/raw.log" ]; then RAW_FETCHED=1; return 0; fi
  rm -f "$RUN_DIR/raw.log"; return 1
}

record_scripts() {
  [ "$FAULT" = scripts ] && { save_fail "injected scripts-copy failure"; return 1; }
  mkdir -p "$RUN_DIR/scripts" || { save_fail "cannot create scripts dir"; return 1; }
  local f b
  for f in "$HERE/run-target.sh" "$HERE/run-all.sh" \
           "$HERE/finalize-verdict.sh" "$HERE/collect-evidence.py" \
           "$HERE/raw-verdict.py" "$HERE/derive-expected-checks.sh" "$HERE/run-acceptance-wrapper.sh" \
           "$HERE/remote-cleanup.sh" \
           "$H/acceptance-target.sh" "$H/target-prep.sh" "$H/sanitize.py" "$EXPECTED_IDS"; do
    [ -f "$f" ] || continue
    b=$(basename "$f")
    cp "$f" "$RUN_DIR/scripts/$b" || { save_fail "cannot copy script $f"; return 1; }
    require_file "$RUN_DIR/scripts/$b" "script copy $b"
  done
  ( cd "$RUN_DIR/scripts" && shasum -a 256 ./* > SHA256SUMS ) || save_fail "cannot write scripts SHA256SUMS"
  require_file "$RUN_DIR/scripts/SHA256SUMS" "scripts SHA256SUMS"; cat "$RUN_DIR/scripts/SHA256SUMS"; [ "$SAVE_FAILED" = 0 ]
}

write_meta() { # write_meta <verdict> <acc_rc> <remote_sha> <remote_stat>
  [ "$FAULT" = run.json ] && { save_fail "injected run.json failure"; return 1; }
  local verdict="$1" acc_rc="$2" remote_sha="$3" remote_stat="$4" end_line raw_sha
  end_line=$(grep -E '^== acceptance end ' "$RUN_DIR/raw.log" 2>/dev/null | tail -1)
  if [ -s "$RUN_DIR/raw.log" ]; then raw_sha=$(shasum -a 256 "$RUN_DIR/raw.log" | cut -d' ' -f1); else raw_sha=""; fi
  local json
  if json=$(RUN_ID="$RUN_ID" SLABEL="$LABEL" SVM="$VM" SVERDICT="$verdict" SACC="$acc_rc" \
      SSTART="$RUN_START" SFINISH="$(ts)" SRAWSHA="$raw_sha" SEND="$end_line" \
      SRC="$RC_COMMIT" SART="$EXP_ART" SRWP="$REMOTE_WORK/raw.log" SCLEAN="$CLEANUP_OK" \
      SRMSHA="$remote_sha" SRMSTAT="$remote_stat" SIMAGE="$SOURCE_IMAGE" SIMAGEID="$SOURCE_IMAGE_ID" \
      python3 - <<'PY'
import json, os, sys
e = os.environ
print(json.dumps({
  "run_id": e["RUN_ID"], "label": e["SLABEL"], "vm": e["SVM"],
  "verdict": e["SVERDICT"], "acceptance_rc": e["SACC"],
  "started_at": e["SSTART"], "finished_at": e["SFINISH"],
  "raw_log_sha256": e["SRAWSHA"], "remote_raw_sha256": e["SRMSHA"],
  "remote_raw_stat": e["SRMSTAT"], "acceptance_end": e["SEND"],
  "rc_commit": e["SRC"], "artifact_sha256": e["SART"],
  "remote_raw_path": e["SRWP"], "cleanup_ok": e["SCLEAN"] == "1",
  "source_image": e["SIMAGE"], "source_image_id": e["SIMAGEID"],
}, indent=2))
PY
  ); then
    atomic_write "$RUN_DIR/run.json" "$json" || return 1
  else save_fail "cannot serialise run.json"; return 1; fi
  [ "$FAULT" = index ] && { save_fail "injected INDEX failure"; return 1; }
  local line; line=$(printf '%s\t%s\t%s\t%s\t%s\t%s' "$(ts)" "$RUN_ID" "$LABEL" "$verdict" "$acc_rc" "$raw_sha")
  printf '%s\n' "$line" >> "$OUT/INDEX.tsv" || { save_fail "cannot append INDEX.tsv"; return 1; }
  grep -qF "$line" "$OUT/INDEX.tsv" || { save_fail "INDEX.tsv append not confirmed"; return 1; }
  return 0
}

do_cleanup() {
  [ "$CLEANUP_DONE" = 1 ] && return
  CLEANUP_DONE=1
  local ok=1 st
  # B3/B3-C: validate the target and propagate the exit code of EACH removal.
  # Only our own per-run dir; never /var/tmp/sinter-acceptance or another run.
  if [ "$REMOTE_MKDIR" = 1 ]; then
    local allow=0; [ "$RAW_FETCHED" = 1 ] && allow=1
    local out rc state tmp_rc dir_rc exists
    out=$(gssh "sudo bash /tmp/remote-cleanup.sh '$REMOTE_WORK' '$RUN_ID' $allow"); rc=$?
    if [ "$rc" -ne 0 ] || [ -z "$out" ]; then
      ok=0; CLEANUP_NOTE="remote cleanup ssh failed (rc=$rc)"
    else
      state=$(printf '%s\n' "$out" | sed -n 's/^STATE=//p' | tail -1)
      tmp_rc=$(printf '%s\n' "$out" | sed -n 's/^TMP_RC=//p' | tail -1)
      dir_rc=$(printf '%s\n' "$out" | sed -n 's/^DIR_RC=//p' | tail -1)
      exists=$(printf '%s\n' "$out" | sed -n 's/^EXISTS=//p' | tail -1)
      echo "cleanup remote: STATE=$state TMP_RC=$tmp_rc DIR_RC=$dir_rc EXISTS=$exists allow=$allow"
      case "$state" in
        ABSENT) : ;;
        OKDIR)
          if [ "$allow" = 0 ]; then
            CLEANUP_NOTE="remote per-run dir kept (evidence not fetched)"; echo "WARN: $CLEANUP_NOTE"
          elif [ "$tmp_rc" != 0 ] || [ "$dir_rc" != 0 ] || [ "$exists" != no ]; then
            ok=0; CLEANUP_NOTE="remote cleanup failed (TMP_RC=$tmp_rc DIR_RC=$dir_rc EXISTS=$exists)"
          fi ;;
        SYMLINK|BADPATH|OTHERTYPE) ok=0; CLEANUP_NOTE="unsafe cleanup target STATE=$state; not deleted" ;;
        *) ok=0; CLEANUP_NOTE="unknown cleanup state '$state'" ;;
      esac
    fi
  fi
  "$GCLOUD" compute instances stop "$VM" --project="$PROJ" --zone="$ZONE" --quiet >/dev/null 2>&1 || ok=0
  st=$(gstatus); echo "stopped: $st"; [ "$st" = TERMINATED ] || ok=0
  if [ "${IP_ADDED:-no}" = yes ]; then
    if "$GCLOUD" compute instances delete-access-config "$VM" --project="$PROJ" --zone="$ZONE" --access-config-name=external-nat >/dev/null 2>&1; then
      echo "temporary external IP removed"
    else echo "WARN: IP removal failed"; ok=0; fi
  fi
  [ "$ok" = 1 ] && CLEANUP_OK=1 || { CLEANUP_OK=0; save_fail "cleanup did not fully succeed${CLEANUP_NOTE:+ ($CLEANUP_NOTE)}"; }
}

# ---- B1/A1: single finalizer; success only for a fully verified PASS --------
finalize() { # finalize <verdict> <acc_rc> [remote_sha] [remote_stat] <reason>
  [ "$FINALIZED" = 1 ] && { echo "finalize: already finalized"; return 1; }
  if [ "$IN_FINALIZE" = 1 ]; then
    echo "finalize: re-entry blocked; best-effort cleanup only"
    do_cleanup
    FINALIZED=1
    return 1
  fi
  IN_FINALIZE=1
  local verdict="$1" acc_rc="$2" rsha="${3:-}" rstat="${4:-}" reason="${5:-}"
  [ -n "$reason" ] && echo "finalize reason: $reason"
  [ "$RAW_FETCHED" != 1 ] && { fetch_raw || true; }
  do_cleanup
  if [ "$verdict" = PASS ] && [ "$CLEANUP_OK" != 1 ]; then verdict="CLEANUP_FAILED"; fi
  if [ "$FAULT" = result ]; then save_fail "injected result failure"; else atomic_write "$RESULT_FILE" "$verdict" || true; fi
  case "$verdict" in PASS|FAIL|TIMEOUT|NO_RAW_LOG|STALE_RAW_LOG|RAW_SHA_MISMATCH|INCOMPLETE|ERROR|CLEANUP_FAILED) : ;; *) verdict="ERROR" ;; esac
  write_meta "$verdict" "$acc_rc" "$rsha" "$rstat" || true
  if [ "$verdict" = PASS ] && [ "$SAVE_FAILED" = 0 ] && [ "$CLEANUP_OK" = 1 ] \
     && [ -s "$RUN_DIR/run.json" ] && [ -s "$RESULT_FILE" ]; then
    FINALIZED=1; IN_FINALIZE=0; echo "finalized OK verdict=PASS"; return 0
  fi
  FINALIZED=1; IN_FINALIZE=0
  echo "finalized NON-PASS verdict=$verdict save_failed=$SAVE_FAILED cleanup_ok=$CLEANUP_OK"; return 1
}

on_signal() { echo "signal received $(ts)" >&2; exit 130; }
on_exit() {
  local rc=$?
  # B1: if already finalized, preserve the explicit exit code.
  if [ "$FINALIZED" = 1 ]; then return "$rc"; fi
  echo "UNEXPECTED EXIT rc=$rc at $(ts): recording INCOMPLETE (raw_fetched=$RAW_FETCHED)"
  finalize "INCOMPLETE" "aborted" "" "" "trap rc=$rc" || true
  # B1: an incomplete/unfinalized run must NEVER exit 0.
  if [ "$rc" -eq 0 ]; then rc=1; fi
  exit "$rc"
}
trap on_exit EXIT
trap on_signal INT TERM

# ============================================================================
echo "### $VM ($LABEL) start $(ts) run_id=$RUN_ID rc_commit=$RC_COMMIT"
[ -s "$EXPECTED_IDS" ] || save_fail "expected check ids missing"
[ -f "$RAW_VERDICT" ] || save_fail "raw-verdict.py missing"
echo "expected_checks=$(wc -l < "$EXPECTED_IDS" | tr -d ' ')"
echo "== script provenance =="
record_scripts || true
echo "preflight_status=$(gstatus)"
echo "local_artifact_sha256=$LOCAL_ART"

# ---- image provenance: the boot disk's source image, recorded per run ------
BOOT_DISK=$("$GCLOUD" compute instances describe "$VM" --project="$PROJ" --zone="$ZONE" \
  --format="value(disks[0].source.basename())" 2>/dev/null)
if [ -n "$BOOT_DISK" ]; then
  SOURCE_IMAGE=$("$GCLOUD" compute disks describe "$BOOT_DISK" --project="$PROJ" --zone="$ZONE" \
    --format="value(sourceImage.basename())" 2>/dev/null)
  SOURCE_IMAGE_ID=$("$GCLOUD" compute disks describe "$BOOT_DISK" --project="$PROJ" --zone="$ZONE" \
    --format="value(sourceImageId)" 2>/dev/null)
fi
echo "source_image=$SOURCE_IMAGE source_image_id=$SOURCE_IMAGE_ID"
if [ -z "$SOURCE_IMAGE" ] || ! printf '%s' "$SOURCE_IMAGE_ID" | grep -qE '^[0-9]+$'; then
  finalize "ERROR" "image-provenance" "" "" "boot disk image provenance not recorded"; exit 14
fi

if [ "$NEED_IP" = yes ]; then
  HAS_AC=$("$GCLOUD" compute instances describe "$VM" --project="$PROJ" --zone="$ZONE" \
    --format="value(networkInterfaces[0].accessConfigs[0].type)" 2>/dev/null)
  if [ -z "$HAS_AC" ]; then
    echo "adding temporary external IP access-config (environment normalisation)"
    if "$GCLOUD" compute instances add-access-config "$VM" --project="$PROJ" --zone="$ZONE" --access-config-name=external-nat >/dev/null 2>&1; then
      IP_ADDED=yes
    else
      finalize "ERROR" "add-access-config" "" "" "temporary external IP could not be added"; exit 16
    fi
  else echo "access-config already present ($HAS_AC); not adding"; fi
fi

"$GCLOUD" compute instances start "$VM" --project="$PROJ" --zone="$ZONE" --quiet >/dev/null 2>&1 || true
echo "status_after_start=$(gstatus)"
READY=0
for i in $(seq 1 "$SSH_WAIT_TRIES"); do
  if [ "$(gssh 'echo SSH_READY')" = SSH_READY ]; then READY=1; echo "ssh ready after $((i*5))s"; break; fi
  sleep 5
done
if [ "$READY" != 1 ]; then echo "SSH NOT READY"; finalize "ERROR" "ssh-not-ready" "" "" "ssh-not-ready"; exit 3; fi
RUN_START=$(ts); echo "target_started_at=$RUN_START"

for f in target-prep.sh acceptance-target.sh run-acceptance-wrapper.sh remote-cleanup.sh; do
  ok=0; for i in $(seq 1 "$UP_TRIES"); do gscp "$H/$f" "$VM:/tmp/$f" >/dev/null 2>&1 && { ok=1; break; }; echo "upload $f attempt $i failed"; sleep 3; done
  [ "$ok" = 1 ] || { gpush "$H/$f" "/tmp/$f" && ok=1; }
  echo "harness $f uploaded=$ok"
  if [ "$ok" != 1 ]; then finalize "ERROR" "harness-upload" "" "" "harness-upload $f"; exit 6; fi
done
UP=0
for i in $(seq 1 "$UP_TRIES"); do
  if gscp "$ART" "$VM:/tmp/$TARNAME" >/dev/null 2>&1; then
    [ "$(gssh "sha256sum /tmp/$TARNAME | cut -d' ' -f1")" = "$EXP_ART" ] && { UP=1; break; }
  fi
  echo "artifact upload attempt $i failed"; sleep 3
done
if [ "$UP" != 1 ]; then
  gpush "$ART" "/tmp/$TARNAME" && [ "$(gssh "sha256sum /tmp/$TARNAME | cut -d' ' -f1")" = "$EXP_ART" ] && UP=1
fi
echo "artifact_on_target=$(gssh "sha256sum /tmp/$TARNAME | cut -d' ' -f1") upload_ok=$UP"
if [ "$UP" != 1 ]; then finalize "ERROR" "artifact-upload" "" "" "artifact-upload"; exit 6; fi

# A prep.rc left by an earlier run must never be read as this run's result.
gssh 'sudo rm -f /tmp/prep.rc; if [ -e /tmp/prep.rc ]; then echo stale; else sudo bash /tmp/target-prep.sh >/dev/null 2>&1; cat /tmp/prep.rc 2>/dev/null || echo missing; fi' > "$RUN_DIR/prep_rc.txt"
PREP_RC=$(cat "$RUN_DIR/prep_rc.txt" 2>/dev/null); echo "PREP_RC=$PREP_RC"
if [ "$PREP_RC" != 0 ]; then finalize "ERROR" "prep" "" "" "prep"; exit 7; fi

if [ "$MAKE_CACHE" = yes ]; then
  echo "warming dnf metadata cache (environment normalisation; metadata only)"
  MC=$(gssh 'sudo timeout 900 dnf -y makecache >/tmp/makecache.log 2>&1; echo "MAKECACHE_RC=$?"')
  echo "$MC"
  if [ "$MC" != "MAKECACHE_RC=0" ]; then finalize "ERROR" "makecache" "" "" "dnf makecache failed ($MC)"; exit 15; fi
fi

# ---- B2/B3: exclusive per-run dir + namespace capability (no rm of existing)
CAP=$(gssh 'sudo unshare -m true >/dev/null 2>&1 && echo UNSHARE_OK || echo UNSHARE_FAIL')
echo "unshare_capability=$CAP"
if [ "$CAP" != UNSHARE_OK ]; then finalize "ERROR" "no-mount-namespace" "" "" "unshare unavailable"; exit 11; fi

# official path: never delete/replace; only create if absent, refuse if not a real dir
OP=$(gssh 'if [ -L /var/tmp/sinter-acceptance ]; then echo SYMLINK; elif [ -d /var/tmp/sinter-acceptance ]; then echo DIR; elif [ -e /var/tmp/sinter-acceptance ]; then echo OTHER; else echo ABSENT; fi')
echo "official_path_state=$OP"
case "$OP" in
  SYMLINK|OTHER) finalize "ERROR" "official-path-unsafe" "" "" "official path is $OP"; exit 12 ;;
  ABSENT) gssh 'sudo mkdir -m 755 /var/tmp/sinter-acceptance && sudo chown sinter:sinter /var/tmp/sinter-acceptance && echo MKDIR_OK || echo MKDIR_FAIL' | grep -q MKDIR_OK \
            || { finalize "ERROR" "official-path-create" "" "" "cannot create official path"; exit 12; } ;;
esac

MKD=$(gssh "sudo mkdir -m 700 '$REMOTE_WORK' 2>/dev/null && sudo chown sinter:sinter '$REMOTE_WORK' && echo MKDIR_OK || echo MKDIR_EXISTS_OR_FAIL")
echo "remote_mkdir=$MKD"
if [ "$MKD" != MKDIR_OK ]; then finalize "ERROR" "run-dir-collision" "" "" "per-run dir exists or mkdir failed"; exit 13; fi
REMOTE_MKDIR=1
gssh "sudo -u sinter bash -c 'printf %s \"$RUN_ID\" > \"$REMOTE_WORK/run.marker\"' 2>/dev/null; true" >/dev/null 2>&1

BUSY=$(gssh 'sudo pgrep -af "[a]cceptance-target[.]sh" >/dev/null 2>&1 && echo BUSY || echo CLEAR')
if [ "$BUSY" != CLEAR ]; then finalize "ERROR" "stale-remote-process" "" "" "stale process"; exit 8; fi
gssh 'sudo rm -f /tmp/acceptance.rc 2>/dev/null; true' >/dev/null 2>&1
if [ "$(gssh 'test -f /tmp/acceptance.rc && echo PRESENT || echo CLEAR')" != CLEAR ]; then
  finalize "ERROR" "stale-acceptance-rc" "" "" "stale rc"; exit 9
fi

RUN_START=$(ts); echo "run_start=$RUN_START"
LAUNCH="sudo setsid bash $WRAPPER '$REMOTE_WORK' '$LABEL' '/tmp/$TARNAME' '$EXP_ART' '$EXP_EXE' '$EXP_VER' > /tmp/acceptance.nohup 2>&1 < /dev/null & echo launched"
LCHK=$(gssh "$LAUNCH"); echo "launch_response=$LCHK"
if [ "$LCHK" != launched ]; then finalize "ERROR" "launch" "" "" "launch not confirmed"; exit 10; fi
DONE=0
for i in $(seq 1 "$POLL_TRIES"); do
  if gssh 'test -f /tmp/acceptance.rc'; then DONE=1; break; fi
  sleep "$POLL_INT"
done
if [ "$DONE" = 1 ]; then ACC_RC=$(gssh 'cat /tmp/acceptance.rc 2>/dev/null'); else ACC_RC=timeout; fi
echo "acceptance_rc=$ACC_RC done=$DONE after $((i*POLL_INT))s"

# B2: capture the server-side hash + stat of the raw log BEFORE fetching
RMT_SHA=$(gssh "sudo sha256sum '$REMOTE_WORK/raw.log' 2>/dev/null | cut -d' ' -f1")
RMT_STAT=$(gssh "sudo stat -c '%s %Y %i' '$REMOTE_WORK/raw.log' 2>/dev/null")
echo "remote_raw_sha=$RMT_SHA remote_raw_stat=$RMT_STAT"
echo "target_finished_at=$(ts)"

fetch_raw && echo "raw_log_fetched=yes" || echo "raw_log_fetched=no"
if [ "$RAW_FETCHED" = 1 ]; then
  LOCAL_SHA=$(shasum -a 256 "$RUN_DIR/raw.log" | cut -d' ' -f1)
  # The fetched log must be byte-identical to the one hashed on the target;
  # otherwise it is not this run's evidence and the run stops (non-PASS).
  if [ -z "$RMT_SHA" ] || [ "$LOCAL_SHA" != "$RMT_SHA" ]; then
    echo "RAW SHA MISMATCH local=$LOCAL_SHA remote=${RMT_SHA:-unavailable}"
    finalize "RAW_SHA_MISMATCH" "$ACC_RC" "$RMT_SHA" "$RMT_STAT" "raw log hash mismatch"; exit 1
  fi
fi
VERDICT=$(python3 "$RAW_VERDICT" "$RUN_DIR/raw.log" "$EXPECTED_IDS" "$RUN_START" "$ACC_RC" 2>/dev/null || true)
[ -n "$VERDICT" ] || VERDICT="VERIFIER_ERROR"
echo "verdict=$VERDICT"

# TEST-ONLY: force an un-finalized exit 0 to exercise the EXIT trap (B1).
if [ "${SINTER_TEST_FORCE_EXIT0:-}" = 1 ]; then echo "TEST: forcing exit 0 before finalize"; exit 0; fi

if finalize "$VERDICT" "$ACC_RC" "$RMT_SHA" "$RMT_STAT" ""; then echo "### $VM done PASS"; exit 0; fi
echo "### $VM done $VERDICT"; exit 1
