#!/bin/bash
# assemble.sh OUTDIR -- builds the two INDEPENDENT scenario files (SA-3 and Multi-Arch):
#   common.sh + safe-lib.sh + shims.sh + captures.sh + <scenario body> + "__PAYLOAD__" + base64(tar.gz of that
#   scenario's synthetic packages + MANIFEST.sha256).  Each scenario carries only the packages of its own allowlist.
# Runs the lint first; refuses to assemble if it fails.  Prints the SHA-256 of each scenario file.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${1:?OUTDIR}"
BUILD="${ASSEMBLE_BUILD:-production}"      # production (default) | test: the only difference is the H_BUILD_KIND line
case "$BUILD" in production|test) ;; *) echo "assemble: ASSEMBLE_BUILD must be production or test" >&2; exit 2 ;; esac
"$HERE/lint-harness.sh" "$HERE"
mkdir -p "$OUTDIR"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/sinter-h-asm.XXXXXX")"
trap 'rm -f "$STAGE"/*.deb "$STAGE"/MANIFEST.sha256 "$STAGE"/payload.tgz "$STAGE"/list.txt 2>/dev/null; rmdir "$STAGE" 2>/dev/null; true' EXIT
# the recovery tool (F-1): one self-contained file, no payload
{ sed "s/@BUILD_KIND@/$BUILD/" "$HERE/lib/buildkind.sh"; cat "$HERE/lib/nscheck.sh" "$HERE/lib/safe-lib.sh" "$HERE/lib/shims.sh" "$HERE/recovery/body.sh"; } > "$OUTDIR/recover-synthetic.sh"
bash -n "$OUTDIR/recover-synthetic.sh"
# the explicit initialisation of the persistent state (R4-1): one self-contained file, no payload
{ sed "s/@BUILD_KIND@/$BUILD/" "$HERE/lib/buildkind.sh"; cat "$HERE/lib/nscheck.sh" "$HERE/lib/safe-lib.sh" "$HERE/lib/shims.sh" "$HERE/init/body.sh"; } > "$OUTDIR/init-state.sh"
bash -n "$OUTDIR/init-state.sh"
echo "$(shasum -a 256 "$OUTDIR/init-state.sh" | cut -d' ' -f1)  init-state.sh"
echo "$(shasum -a 256 "$OUTDIR/recover-synthetic.sh" | cut -d' ' -f1)  recover-synthetic.sh"
for kind in stageb1 stageb2 sa3 multiarch; do
    rm -f "$STAGE"/*.deb "$STAGE"/MANIFEST.sha256
    python3 -I "$HERE/build-debs.py" "$STAGE" "$kind" > "$STAGE/list.txt"
    ( cd "$STAGE" && if command -v sha256sum > /dev/null; then sha256sum ./*.deb; else shasum -a 256 ./*.deb; fi | sed 's# \./# #; s#  *# #' | awk '{print $1 "  " $2}' > MANIFEST.sha256 )
    ( cd "$STAGE" && COPYFILE_DISABLE=1 tar --no-xattrs -czf payload.tgz ./*.deb MANIFEST.sha256 )
    out="$OUTDIR/scenario-$kind.sh"
    { sed "s/@BUILD_KIND@/$BUILD/" "$HERE/lib/buildkind.sh"; cat "$HERE/lib/nscheck.sh" "$HERE/lib/common.sh" "$HERE/lib/safe-lib.sh" "$HERE/lib/shims.sh" "$HERE/lib/captures.sh" "$HERE/$kind/body.sh"
      echo "__PAYLOAD__"; base64 < "$STAGE/payload.tgz"; } > "$out"
    bash -n "$out"
    echo "$(shasum -a 256 "$out" | cut -d' ' -f1)  scenario-$kind.sh  ($(grep -c . "$STAGE/list.txt") packages)"
done
