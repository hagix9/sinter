#!/bin/bash
# ============================================================================
# Remote per-run cleanup  --  HARNESS-FIX COPY (B3-C)
# Validates the deletion target and reports the exit code of EACH removal so the
# driver can propagate failures (no trailing `true` masking a failure).
#
# args: $1=target per-run dir  $2=RUN_ID  $3=allow_delete (1|0)
# Output (exactly one line each):
#   STATE=OKDIR|ABSENT|SYMLINK|OTHERTYPE|BADPATH
#   TMP_RC=<rc|skip>
#   DIR_RC=<rc|skip>
#   EXISTS=yes|no
# Exit: 0 always (the driver parses STATE/rcs); SSH failure is detected by the
# driver from the transport, not from this exit code.
# ============================================================================
set -u
TARGET=$1; RID=$2; ALLOW=${3:-0}

# --- target validation: never delete anything that is not exactly our per-run dir
# Path structure is validated FIRST (before any existence test), so a
# non-existent path that is not ours is reported BADPATH, never ABSENT.
case "$TARGET" in
  /var/tmp/sinter-acceptance-"$RID") : ;;
  *) echo "STATE=BADPATH"; echo "TMP_RC=skip"; echo "DIR_RC=skip"; echo "EXISTS=no"; exit 0 ;;
esac
if [ -L "$TARGET" ]; then echo "STATE=SYMLINK"; echo "TMP_RC=skip"; echo "DIR_RC=skip"; echo "EXISTS=yes"; exit 0; fi
if [ -e "$TARGET" ] && [ ! -d "$TARGET" ]; then echo "STATE=OTHERTYPE"; echo "TMP_RC=skip"; echo "DIR_RC=skip"; echo "EXISTS=yes"; exit 0; fi
if [ ! -e "$TARGET" ]; then echo "STATE=ABSENT"; echo "TMP_RC=skip"; echo "DIR_RC=skip"; echo "EXISTS=no"; exit 0; fi
echo "STATE=OKDIR"

# --- deletion only when explicitly allowed (evidence preservation otherwise)
if [ "$ALLOW" != 1 ]; then echo "TMP_RC=skip"; echo "DIR_RC=skip"; echo "EXISTS=yes"; exit 0; fi

rm -f "/tmp/raw-$RID.log"; TMP_RC=$?
rm -rf "$TARGET"; DIR_RC=$?
if [ -e "$TARGET" ]; then EXISTS=yes; else EXISTS=no; fi
echo "TMP_RC=$TMP_RC"
echo "DIR_RC=$DIR_RC"
echo "EXISTS=$EXISTS"
exit 0
