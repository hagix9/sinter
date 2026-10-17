#!/bin/sh
# Generate the secret variable files the entry-point recipes include.
#   secrets/controller.yaml   all 14 secrets (controller and all-in-one)
#   secrets/compute.yaml      the 5 a compute node needs; the 9 others are empty
# Run it on the machine you run Sinter from. The files are mode 0600 and are NOT
# to be committed (see .gitignore). Existing files are never overwritten: delete
# them yourself to rotate (a re-run would otherwise change every password).
#
# Needs openssl. Every value is checked (32 characters of A-Za-z0-9) before anything
# is written; on any failure the script exits non-zero and leaves neither file.
# Both files are written in a private temporary directory inside secrets/ and then
# hard-linked into place, which never replaces an existing name. compute.yaml is
# placed first and controller.yaml last, so controller.yaml exists only when both are
# complete; a compute.yaml this run placed without its controller.yaml is taken back
# on exit. Only a kill that cannot be trapped (SIGKILL, power loss) can leave a lone
# compute.yaml, which the next run refuses and names, or the temporary directory
# secrets/.gen-secrets.* with generated values, which the next run reports (it is
# inside secrets/, mode 0700, and ignored by Git; delete it). No value is printed.
set -eu
dir="$(cd "$(dirname "$0")/.." && pwd)/secrets"
all_keys="mysql_root_pass keystone_db_pass glance_db_pass placement_db_pass neutron_db_pass nova_db_pass rabbit_pass admin_password glance_service_pass placement_service_pass neutron_service_pass nova_service_pass metadata_proxy_secret horizon_secret_key"
compute_keys="rabbit_pass nova_service_pass placement_service_pass neutron_service_pass metadata_proxy_secret"

die() { echo "gen-secrets: $*" >&2; exit 1; }

[ -L "$dir" ] && die "secrets/ is a symbolic link; not followed"
if [ -e "$dir/controller.yaml" ] || [ -L "$dir/controller.yaml" ]; then
    echo "secrets/controller.yaml exists; not overwritten" >&2; exit 1
fi
if [ -e "$dir/compute.yaml" ] || [ -L "$dir/compute.yaml" ]; then
    die "secrets/compute.yaml exists without secrets/controller.yaml (left by an interrupted run?); not overwritten: check it, delete it and run again"
fi
command -v openssl >/dev/null 2>&1 || die "openssl is required (install the openssl package); nothing was written"
for d in "$dir"/.gen-secrets.*; do
    [ -d "$d" ] && echo "gen-secrets: warning: secrets/${d##*/} is left from an interrupted run and may hold generated values; delete it" >&2
done

umask 077
mkdir -p "$dir"; chmod 0700 "$dir"
tmp="$(mktemp -d "$dir/.gen-secrets.XXXXXX")" || die "cannot create a temporary directory in secrets/"
cleanup() {
    # a compute.yaml this run placed (same inode as its temporary file) without its controller.yaml is taken back
    if ! [ "$dir/controller.yaml" -ef "$tmp/controller.yaml" ] && [ "$dir/compute.yaml" -ef "$tmp/compute.yaml" ]; then
        rm -f "$dir/compute.yaml"
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# one secret: exactly 32 characters of A-Za-z0-9, or a failure
gen() {
    raw="$(openssl rand -base64 192)" || return 1
    val="$(printf '%s' "$raw" | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-32)"
    case "$val" in *[!A-Za-z0-9]*) return 1 ;; esac
    [ "${#val}" -eq 32 ] || return 1
    printf '%s' "$val"
}

for k in $all_keys; do
    v="$(gen)" || die "could not generate a secret with openssl; nothing was written"
    eval "S_$k=\$v"
done

{ echo "# generated $(date -u +%FT%TZ) — never commit"; echo "version: 1"; echo "vars:"
  for k in $all_keys; do eval "v=\$S_$k"; printf '  %s:\n    value: "%s"\n    sensitive: true\n' "$k" "$v"; done
} > "$tmp/controller.yaml"
{ echo "# the credentials a compute node needs (hagistack: compute-secrets) — never commit"; echo "version: 1"; echo "vars:"
  for k in $all_keys; do
    case " $compute_keys " in *" $k "*) eval "v=\$S_$k" ;; *) v="" ;; esac
    printf '  %s:\n    value: "%s"\n    sensitive: true\n' "$k" "$v"
  done
} > "$tmp/compute.yaml"
chmod 0600 "$tmp/controller.yaml" "$tmp/compute.yaml"
# 3 header lines and 3 lines per key: a short write never gets placed
for f in controller.yaml compute.yaml; do
    [ "$(( $(wc -l < "$tmp/$f") ))" -eq 45 ] || die "secrets/$f was not written completely; nothing was written"
done

# place <name>: ln fails when the name exists (even as a dangling symlink), so nothing is replaced. If a
# directory (or a link to one) appeared under the name meanwhile, ln puts the link inside it: take it back.
place() {
    ln "$tmp/$1" "$dir/$1" 2>/dev/null || return 1
    if [ -L "$dir/$1" ] || ! [ "$dir/$1" -ef "$tmp/$1" ]; then
        if [ "$dir/$1/$1" -ef "$tmp/$1" ]; then rm -f "$dir/$1/$1"; fi
        return 1
    fi
}
place compute.yaml \
    || die "cannot place secrets/compute.yaml (it appeared meanwhile, or the file system has no hard links); nothing was written"
place controller.yaml \
    || die "cannot place secrets/controller.yaml (it appeared meanwhile, or the file system has no hard links); nothing was written"
echo "wrote $dir/controller.yaml and $dir/compute.yaml (mode 0600)"
