#!/bin/bash
# ============================================================================
# Remote run wrapper  --  HARNESS-FIX COPY (B2/B3)
# Runs the FROZEN acceptance-target.sh UNCHANGED, but inside a private mount
# namespace where /var/tmp/sinter-acceptance is bind-mounted onto this run's
# exclusive per-run directory. The real /var/tmp/sinter-acceptance is never
# deleted or replaced, and the raw log lands in the run-specific directory by
# construction (no post-hoc move/edit of the log).
#
# args: $1=per-run work dir  $2=label  $3=tarball  $4=exp_art  $5=exp_exe  $6=exp_ver
# Run as root (mount needs CAP_SYS_ADMIN). Exit 41/42 signal setup failure.
# ============================================================================
set -u
WORK=$1; LABEL=$2; TARBALL=$3; EXP_ART=$4; EXP_EXE=$5; EXP_VER=$6
[ -d "$WORK" ] || exit 41
# private mount namespace: bind this run's dir over the frozen script's WORK path
exec unshare -m bash -c '
  mount --bind "$0" /var/tmp/sinter-acceptance || exit 42
  exec sudo -u sinter -H bash /tmp/acceptance-target.sh "$1" "$2" "$3" "$4" "$5"
' "$WORK" "$LABEL" "$TARBALL" "$EXP_ART" "$EXP_EXE" "$EXP_VER"
