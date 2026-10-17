#!/bin/sh
# Generate the secret variable files the entry-point recipes include.
#   secrets/controller.yaml   all 14 secrets (controller and all-in-one)
#   secrets/compute.yaml      the 5 a compute node needs; the 9 others are empty
# Run it on the machine you run Sinter from. The files are mode 0600 and are NOT
# to be committed (see .gitignore). Existing files are never overwritten: delete
# them yourself to rotate (a re-run would otherwise change every password).
set -eu
dir="$(cd "$(dirname "$0")/.." && pwd)/secrets"
mkdir -p "$dir"; chmod 0700 "$dir"
gen() { openssl rand -base64 192 | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-32; }
all_keys="mysql_root_pass keystone_db_pass glance_db_pass placement_db_pass neutron_db_pass nova_db_pass rabbit_pass admin_password glance_service_pass placement_service_pass neutron_service_pass nova_service_pass metadata_proxy_secret horizon_secret_key"
compute_keys="rabbit_pass nova_service_pass placement_service_pass neutron_service_pass metadata_proxy_secret"
[ -e "$dir/controller.yaml" ] && { echo "secrets/controller.yaml exists; not overwritten" >&2; exit 1; }
umask 077
{ echo "# generated $(date -u +%FT%TZ) — never commit"; echo "version: 1"; echo "vars:"
  for k in $all_keys; do v="$(gen)"; eval "S_$k=\$v"; printf '  %s:\n    value: "%s"\n    sensitive: true\n' "$k" "$v"; done
} > "$dir/controller.yaml"
{ echo "# the credentials a compute node needs (hagistack: compute-secrets) — never commit"; echo "version: 1"; echo "vars:"
  for k in $all_keys; do
    case " $compute_keys " in *" $k "*) eval "v=\$S_$k" ;; *) v="" ;; esac
    printf '  %s:\n    value: "%s"\n    sensitive: true\n' "$k" "$v"
  done
} > "$dir/compute.yaml"
echo "wrote $dir/controller.yaml and $dir/compute.yaml (mode 0600)"
