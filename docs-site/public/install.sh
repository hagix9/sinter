#!/bin/sh
# Install an official Sinter Linux x86_64 release. Never needs sudo by default.
set -eu
LC_ALL=C
export LC_ALL
fail() { printf 'sinter installer: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || fail 'only Linux is supported'
case $(uname -m) in x86_64|amd64) ;; *) fail 'only x86_64/amd64 is supported' ;; esac
for tool in curl sha256sum tar awk sort stat mktemp install cmp cut id mkdir chmod mv rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done
work=
staged=
cleanup() {
    [ -z "$staged" ] || rm -f -- "$staged"
    [ -z "$work" ] || rm -rf -- "$work"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
umask 077
work=$(mktemp -d) || fail 'cannot create temporary workspace'
fetch() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$1" -o "$2" || fail 'official release download failed'; }
version=${SINTER_VERSION:-}
if [ -z "$version" ]; then
    # GitHub's stable latest-release redirect excludes drafts/prereleases.
    url=$(curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' -o /dev/null -w '%{url_effective}' https://github.com/hagix9/sinter/releases/latest) || fail 'cannot resolve latest stable release'
    case $url in https://github.com/hagix9/sinter/releases/tag/v*) version=${url##*/} ;; *) fail 'unexpected latest-release URL' ;; esac
fi
version=${version#v}
printf '%s\n' "$version" | awk 'NR != 1 {bad=1} /^[0-9]+\.[0-9]+\.[0-9]+$/ {ok=1} END {exit (!ok || bad)}' || fail 'version must be X.Y.Z or vX.Y.Z'
name=sinter-v${version}-linux-x86_64
asset=$name.tar.gz
origin=https://github.com/hagix9/sinter/releases/download/v${version}
fetch "$origin/$asset" "$work/$asset"
fetch "$origin/SHA256SUMS" "$work/sums"
# Exactly one canonical entry; duplicates (even identical) and malformed hashes refuse.
awk -v name="$asset" '
$2 == name || $2 == "*" name {
    count++
    if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-fA-F]/) bad=1
    hash=$1
}
END { if (count != 1 || bad) exit 1; print hash "  " name }
' "$work/sums" > "$work/selected" || fail 'missing, duplicate or malformed checksum entry'
(cd "$work" && sha256sum -c selected) || fail 'archive checksum mismatch'
# GNU tar on supported Linux hosts: reject duplicate entries, links and other types.
tar -tzf "$work/$asset" > "$work/list" || fail 'invalid archive'
printf '%s\n' "$name/" "$name/sinter" "$name/README.md" "$name/README.ja.md" "$name/LICENSE-MIT" "$name/LICENSE-APACHE" | sort > "$work/expected"
sort "$work/list" > "$work/actual"
cmp -s "$work/expected" "$work/actual" || fail 'unexpected or unsafe archive paths'
tar -tvzf "$work/$asset" > "$work/types" || fail 'invalid archive headers'
awk 'NR==1 {if(substr($0,1,1)!="d") exit 1;next} {if(substr($0,1,1)!="-") exit 1} END {if(NR!=6) exit 1}' "$work/types" || fail 'archive contains links or nonregular files'
mkdir "$work/extracted"
tar --no-same-owner --no-same-permissions -xzf "$work/$asset" -C "$work/extracted" || fail 'archive extraction failed'
binary=$work/extracted/$name/sinter
[ -f "$binary" ] && [ ! -L "$binary" ] || fail 'missing regular executable'
chmod 755 "$binary"
[ "$("$binary" --version)" = "sinter $version" ] || fail 'downloaded binary version mismatch'
exe_hash=$(sha256sum "$binary"); exe_hash=${exe_hash%% *}
[ "${SINTER_INSTALL_DIR+x}" != x ] || [ -n "$SINTER_INSTALL_DIR" ] || fail 'install directory must not be empty'
dest=${SINTER_INSTALL_DIR:-${HOME:?HOME must be set}/.local/bin}
printf '%s\n' "$dest" | awk 'NR != 1 || /[[:cntrl:]]/ {bad=1} END {exit bad}' || fail 'control characters in install directory'
case $dest in /*) ;; *) fail 'install directory must be absolute' ;; esac
case $dest in /|*/|*//*|*/./*|*/../*|*/.|*/..) fail 'unsafe install directory' ;; esac
uid=$(id -u)
# Reject symlink/untrusted ancestors. A root-owned sticky /tmp is permissible.
trust_dir() {
    [ ! -L "$1" ] && [ -d "$1" ] || fail 'destination ancestor is not a real directory'
    owner=$(stat -c %u "$1"); mode=$(stat -c %a "$1")
    [ "$owner" = 0 ] || [ "$owner" = "$uid" ] || fail 'untrusted destination owner'
    bits=$((0$mode))
    if [ $((bits & 0022)) -ne 0 ]; then
        [ "$owner" = 0 ] && [ $((bits & 01000)) -ne 0 ] || fail 'destination ancestor is writable by others'
    fi
}
parent=/
rest=${dest#/}
trust_dir /
while [ -n "$rest" ]; do
    component=${rest%%/*}
    if [ "$component" = "$rest" ]; then rest=; else rest=${rest#*/}; fi
    parent=${parent%/}/$component
    if [ ! -e "$parent" ] && [ ! -L "$parent" ]; then mkdir "$parent" || fail 'cannot create install directory'; fi
    trust_dir "$parent"
done
[ -w "$dest" ] || fail 'install directory is not writable'
target=$dest/sinter
[ ! -L "$target" ] || fail 'existing sinter is a symlink'
if [ -e "$target" ]; then
    [ -f "$target" ] || fail 'existing sinter is not a regular file'
    [ "$(stat -c %u "$target")" = "$uid" ] || fail 'existing sinter is owned by another user'
fi
staged=$(mktemp "$dest/.sinter.XXXXXXXX") || fail 'cannot stage installation'
install -m 755 "$binary" "$staged" || fail 'cannot stage executable'
check=$(sha256sum "$staged"); [ "${check%% *}" = "$exe_hash" ] || fail 'staged executable identity mismatch'
mv -fT -- "$staged" "$target" || fail 'atomic installation failed'
staged=
check=$(sha256sum "$target"); [ "${check%% *}" = "$exe_hash" ] || fail 'installed executable identity mismatch'
[ "$("$target" --version)" = "sinter $version" ] || fail 'installed version mismatch'
printf 'Installed sinter %s at %s\nArchive SHA-256: ' "$version" "$target"
cut -d ' ' -f1 "$work/selected"
printf 'Executable SHA-256: %s\n' "$exe_hash"
case :${PATH:-}: in *:"$dest":*) ;; *) printf 'Add this directory to PATH: %s\n' "$dest" ;; esac
