#!/bin/bash
# Put the OpenStack RPM repository on the target host, where the Sinter recipes expect it
# (/opt/hagistack-repo by default; components/repo-local.yaml serves it over loopback HTTP).
#
# Method A — pre-built RPMs (verifies the download first):
#   tools/stage-rpm-repo.sh --archive openstack-rpm-rocky10.2-2026.1.tar.gz --sums SHA256SUMS --host TARGET
# Method B — RPMs built by builder.yaml on another host (streams /root/rpmbuild/RPMS builder -> target):
#   tools/stage-rpm-repo.sh --from-builder BUILDER --host TARGET
#
# Options: --user USER  --identity KEY  --port PORT  (ssh to both hosts)   --dest DIR (default /opt/hagistack-repo)
# Needs: ssh/tar/sha256sum (or shasum) here; sudo (or root) on the hosts. It changes nothing on the target but --dest.
# SHA-256 proves the archive matches the published list; it does not prove who published the list.
set -euo pipefail

DEST=/opt/hagistack-repo
ARCHIVE=; SUMS=; HOST=; BUILDER=; USER_=; IDENT=; PORT=
usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }
while [ $# -gt 0 ]; do
    case "$1" in
        --archive) ARCHIVE="$2"; shift 2 ;;
        --sums) SUMS="$2"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        --from-builder) BUILDER="$2"; shift 2 ;;
        --user) USER_="$2"; shift 2 ;;
        --identity) IDENT="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --dest) DEST="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done
[ -n "$HOST" ] || { echo "--host is required" >&2; usage; }
if [ -n "$ARCHIVE" ] && [ -n "$BUILDER" ]; then echo "use --archive (method A) or --from-builder (method B), not both" >&2; exit 2; fi
if [ -z "$ARCHIVE" ] && [ -z "$BUILDER" ]; then echo "give --archive or --from-builder" >&2; exit 2; fi
case "$DEST" in /*) ;; *) echo "--dest must be an absolute path" >&2; exit 2 ;; esac
case "$DEST" in *[!A-Za-z0-9_./-]*) echo "--dest may contain only letters, digits, _ . / -" >&2; exit 2 ;; esac

sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
SSH=(ssh -o BatchMode=yes)
[ -n "$IDENT" ] && SSH+=(-i "$IDENT")
[ -n "$PORT" ] && SSH+=(-p "$PORT")
target() { [ -n "$USER_" ] && echo "$USER_@$1" || echo "$1"; }
SUDO_REMOTE='if [ "$(id -u)" = 0 ]; then SUDO=; else SUDO=sudo; fi'

# ---- Method A: verify the archive, then the files inside it
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
if [ -n "$ARCHIVE" ]; then
    [ -f "$ARCHIVE" ] || { echo "no such archive: $ARCHIVE" >&2; exit 1; }
    [ -f "$SUMS" ] || { echo "--sums SHA256SUMS is required with --archive (the published list)" >&2; exit 2; }
    base="$(basename "$ARCHIVE")"
    want="$(awk -v f="$base" '{n=$2; sub(/^\*/,"",n); if (n==f) print $1}' "$SUMS" | head -1)"
    [ -n "$want" ] || { echo "$base is not listed in $SUMS" >&2; exit 1; }
    have="$(sha256_of "$ARCHIVE")"
    [ "$want" = "$have" ] || { echo "SHA-256 MISMATCH for $base: expected $want, got $have" >&2; exit 1; }
    echo "archive SHA-256 OK ($have)"
    tar -xzf "$ARCHIVE" -C "$TMP"
    top="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -1)"
    [ -d "$top/repo/repodata" ] && [ -f "$top/SHA256SUMS.repo" ] || { echo "unexpected archive layout (no repo/repodata or SHA256SUMS.repo)" >&2; exit 1; }
    if ! out="$(cd "$top/repo" && if command -v sha256sum >/dev/null 2>&1; then sha256sum -c ../SHA256SUMS.repo; else shasum -a 256 -c ../SHA256SUMS.repo; fi 2>&1)"; then
        printf '%s\n' "$out" | grep -v ': OK$' >&2 || true
        echo "a file inside the archive does not match SHA256SUMS.repo; nothing was copied" >&2; exit 1
    fi
    echo "all files inside the archive verified"
    echo "copying to $HOST:$DEST ..."
    tar -C "$top/repo" -cf - . | "${SSH[@]}" "$(target "$HOST")" "$SUDO_REMOTE; \$SUDO mkdir -p '$DEST' && \$SUDO rm -rf '$DEST/repodata' && \$SUDO tar --no-same-owner -C '$DEST' -xf -"
    # the list is read from stdin into a private temp file on the target (no predictable /tmp name)
    "${SSH[@]}" "$(target "$HOST")" "$SUDO_REMOTE; t=\$(mktemp) && cat > \"\$t\" && cd '$DEST' && if out=\$(\$SUDO sha256sum -c \"\$t\" 2>&1); then rm -f \"\$t\"; else printf '%s\\n' \"\$out\" | grep -v ': OK\$' >&2; rm -f \"\$t\"; echo 'verification on the target FAILED' >&2; exit 1; fi" < "$top/SHA256SUMS.repo"
    echo "verified on the target"
else
    # ---- Method B: stream the builder's repository
    echo "streaming $BUILDER:/root/rpmbuild/RPMS -> $HOST:$DEST ..."
    "${SSH[@]}" "$(target "$BUILDER")" "$SUDO_REMOTE; \$SUDO tar -C /root/rpmbuild/RPMS -cf - noarch repodata" \
      | "${SSH[@]}" "$(target "$HOST")" "$SUDO_REMOTE; \$SUDO mkdir -p '$DEST' && \$SUDO rm -rf '$DEST/repodata' && \$SUDO tar --no-same-owner -C '$DEST' -xf -"
fi
"${SSH[@]}" "$(target "$HOST")" "test -s '$DEST/repodata/repomd.xml' && n=\$(ls '$DEST'/noarch/*.rpm | wc -l) && echo \"repository in place: \$n RPMs, repodata present\" && [ \"\$n\" -gt 0 ]"
echo "done. Next: edit site.yaml, run tools/gen-secrets.sh, then sinter validate / plan / apply all-in-one.yaml"
