#!/usr/bin/env bash
# sinter-openstack-ensure — the imperative steps of the OpenStack 2026.1 (Gazpacho)
# all-in-one build on Rocky Linux 10.2 that no Sinter resource type can express.
#
# Ported from hagistack (https://github.com/hagix9/hagistack, rocky10.2/hagistack).
# Each subcommand is one hagistack step, written as "ensure": it looks at the
# current state first, changes only what is missing, and prints exactly one
# word on its LAST stdout line — `changed` or `unchanged` — which the Sinter
# `command` resource reads through `changed_when`. Everything else goes to
# stderr. Credentials are read from root-only files that Sinter itself writes
# (secrets.env, admin-openrc). They are kept off command lines wherever the tool allows
# (SQL on stdin, OS_BOOTSTRAP_PASSWORD in the environment). The exceptions, as in hagistack, are
# `rabbitmqctl add_user` and `openstack user create --password`: those clients take the password
# as an argument. Output of the long-running tools is shown only after known secrets are masked.
#
# Run as root. Not a general tool: it knows this deployment's names.
set -euo pipefail

ETC="${SINTER_OS_ETC:-/etc/sinter-openstack}"
STATE="${SINTER_OS_STATE:-/var/lib/sinter-openstack}"
SECRETS="$ETC/secrets.env"
OPENRC="$ETC/admin-openrc"
HORIZON_SETTINGS="${SINTER_OS_HORIZON_SETTINGS:-/etc/openstack-dashboard/local_settings}"
REPO_DIR="${SINTER_OS_REPO_DIR:-/etc/yum.repos.d}"

log() { printf '    %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
changed()   { echo changed; exit 0; }
unchanged() { echo unchanged; exit 0; }

# Load the deployment's secrets into the environment (root-only file).
load_secrets() {
    [ -r "$SECRETS" ] || die "$SECRETS is not readable"
    set -a; . "$SECRETS"; set +a
}
load_openrc() {
    [ -r "$OPENRC" ] || die "$OPENRC is not readable"
    set -a; . "$OPENRC"; set +a
}
os() { openstack "$@"; }

wait_for() {  # wait_for <seconds> <what> <command...>
    local limit="$1" what="$2"; shift 2
    local waited=0
    while :; do
        if "$@" >/dev/null 2>&1; then
            [ "$waited" -gt 0 ] && log "$what ready after ${waited}s"
            return 0
        fi
        [ "$waited" -lt "$limit" ] || { log "$what not ready after ${limit}s"; return 1; }
        sleep 2; waited=$((waited + 2))
    done
}

mysql_root() { mariadb -uroot "$@"; }
table_count() { mysql_root -N -B -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$1'" 2>/dev/null || echo 0; }

# Run a command, keep its output, and on failure show the tail with every known secret masked.
redact() {
    local out v name mask='***'; out="$(cat)"
    for name in KEYSTONE_DB_PASS GLANCE_DB_PASS PLACEMENT_DB_PASS NEUTRON_DB_PASS NOVA_DB_PASS RABBIT_PASS \
                ADMIN_PASSWORD GLANCE_SERVICE_PASS PLACEMENT_SERVICE_PASS NEUTRON_SERVICE_PASS NOVA_SERVICE_PASS; do
        v="${!name:-}"; [ -n "$v" ] && out="${out//"$v"/$mask}"
    done
    printf '%s\n' "$out"
}
run_logged() {  # run_logged <what> <command...>
    local what="$1" out rc=0; shift
    out="$("$@" 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '%s\n' "$out" | tail -n 12 | redact | sed 's/^/    | /' >&2
        die "$what failed (exit $rc)"
    fi
}

# --------------------------------------------------------------------------
# readiness (bounded waits; the exit status is the verdict)
# --------------------------------------------------------------------------
cmd_wait_http() {      # wait-http <url> [seconds] [expected-http-code]
    local url="$1" secs="${2:-90}" want="${3:-}"
    probe() {
        if [ -n "$want" ]; then [ "$(curl -s -o /dev/null -m 10 -w '%{http_code}' "$url" 2>/dev/null)" = "$want" ]
        else curl -s -o /dev/null -m 10 "$url"; fi
    }
    wait_for "$secs" "$url" probe || die "$url does not answer${want:+ with $want}"
    unchanged
}
cmd_wait_placement() {  # wait-placement <url>: an authenticated GET /resource_providers
    load_openrc
    local url="$1"
    probe() {
        local t; t="$(os token issue -f value -c id 2>/dev/null)" || return 1
        curl -sf -H "X-Auth-Token: $t" -H "OpenStack-API-Version: placement 1.39" "$url/resource_providers" >/dev/null
    }
    wait_for 60 "an authenticated placement query" probe || die "the placement endpoint answers but an authenticated query failed"
    unchanged
}
cmd_wait_mariadb() { wait_for 60 MariaDB mysql_root -e 'SELECT 1' || die "MariaDB is not answering"; unchanged; }
cmd_wait_rabbit()  { wait_for 90 RabbitMQ rabbitmqctl status || die "RabbitMQ is not answering"; unchanged; }
cmd_wait_memcached() {  # wait-memcached <ip>
    local ip="$1"
    probe() { printf 'version\r\nquit\r\n' | timeout 5 bash -c "exec 3<>/dev/tcp/${ip}/11211; cat >&3; head -1 <&3" 2>/dev/null | grep -q VERSION; }
    wait_for 60 "memcached on $ip:11211" probe || die "memcached does not answer on $ip:11211"
    unchanged
}
cmd_wait_token() {     # an authenticated token, not a 200 on an open page
    load_openrc
    wait_for 60 "an authenticated token" os token issue || die "'openstack token issue' failed"
    unchanged
}
cmd_wait_ovs() { wait_for 60 "Open vSwitch" ovs-vsctl --timeout=10 show || die "ovs-vsctl does not answer"; unchanged; }
cmd_wait_ovn() { # wait-ovn  (northbound and southbound databases)
    wait_for 60 "OVN northbound" ovn-nbctl --timeout=10 show || die "ovn-nbctl does not answer"
    wait_for 60 "OVN southbound" ovn-sbctl --timeout=10 show || die "ovn-sbctl does not answer"
    unchanged
}
cmd_wait_api() {       # wait-api <what> <openstack args...>  (an authenticated call)
    load_openrc
    local what="$1"; shift
    wait_for 120 "$what" os "$@" || die "$what failed"
    unchanged
}
cmd_wait_compute_up() { # the hypervisor registered itself
    load_openrc
    probe() { os compute service list --service nova-compute -f value -c State 2>/dev/null | grep -q up; }
    wait_for 180 "nova-compute to register" probe || die "nova-compute never registered"
    unchanged
}
cmd_wait_ports() {      # wait-ports <host> <port>...   (compute node: can it reach the controller?)
    local host="$1"; shift; local p bad=0
    for p in "$@"; do
        if timeout 5 bash -c "exec 3<>/dev/tcp/${host}/${p}" 2>/dev/null; then log "tcp/$p reachable on $host"
        else log "tcp/$p NOT reachable on $host"; bad=1; fi
    done
    [ "$bad" -eq 0 ] || die "the controller is not reachable on every port this node needs"
    unchanged
}

# --------------------------------------------------------------------------
# host preparation
# --------------------------------------------------------------------------
cmd_crb() {             # EPEL needs CRB
    if dnf -q repolist --enabled 2>/dev/null | awk '{print $1}' | grep -qx crb; then unchanged; fi
    dnf config-manager --set-enabled crb >/dev/null 2>&1 || dnf config-manager --enable crb >/dev/null 2>&1 \
        || die "could not enable CRB"
    changed
}
cmd_check_repo() {      # check-repo <repo-id> <package>: the repository answers and offers the package
    local repo="$1" pkg="$2" v
    v="$(dnf -q repoquery --repo "$repo" --qf '%{version}' "$pkg" 2>/dev/null | tail -1)"
    [ -n "$v" ] || die "repository $repo does not offer $pkg (check the URL and that createrepo_c ran over it)"
    log "repository $repo answers: $pkg $v"
    unchanged
}
cmd_selinux_permissive() {   # the only verified SELinux mode (hagistack: permissive)
    command -v getenforce >/dev/null 2>&1 || unchanged
    local mode; mode="$(getenforce 2>/dev/null || echo Disabled)"
    case "$mode" in
        Disabled) log "SELinux is Disabled: reported, left alone (not the verified configuration)"; unchanged ;;
        Permissive) unchanged ;;
    esac
    setenforce 0 || die "setenforce 0 failed (SELinux is still $mode)"
    [ "$(getenforce)" = Permissive ] || die "setenforce 0 reported success but getenforce disagrees"
    changed
}
cmd_sebool_httpd() {    # every API vhost needs it
    command -v getsebool >/dev/null 2>&1 || unchanged
    getsebool httpd_can_network_connect 2>/dev/null | grep -q -- '--> on' && unchanged
    setsebool -P httpd_can_network_connect on || die "could not set httpd_can_network_connect"
    changed
}

# --------------------------------------------------------------------------
# MariaDB / RabbitMQ
# --------------------------------------------------------------------------
db_pass_var() {
    case "$1" in
        keystone) echo KEYSTONE_DB_PASS ;; glance) echo GLANCE_DB_PASS ;;
        placement) echo PLACEMENT_DB_PASS ;; neutron) echo NEUTRON_DB_PASS ;;
        nova|nova_api|nova_cell0) echo NOVA_DB_PASS ;; *) die "unknown database $1" ;;
    esac
}
db_user() { case "$1" in nova_api|nova_cell0) echo nova ;; *) echo "$1" ;; esac; }
cmd_db() {              # db <name>: database + user ('localhost' and '%') + grants
    local db="$1"; load_secrets
    local pv user pass did=0; pv="$(db_pass_var "$db")"; user="$(db_user "$db")"; pass="${!pv}"
    [ -n "$pass" ] || die "$pv is empty"
    if ! mysql_root -e "USE \`$db\`" >/dev/null 2>&1; then
        mysql_root -e "CREATE DATABASE \`$db\` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"
        did=1; log "database '$db' created"
    fi
    local host
    for host in localhost '%'; do
        if [ "$(mysql_root -N -B -e "SELECT COUNT(*) FROM mysql.user WHERE User='$user' AND Host='$host'")" = 0 ]; then
            printf '%s\n' "CREATE USER '$user'@'$host' IDENTIFIED BY '$pass'" | mysql_root; did=1
        fi
        mysql_root -e "GRANT ALL PRIVILEGES ON \`$db\`.* TO '$user'@'$host'"
    done
    mysql_root -e "FLUSH PRIVILEGES"
    [ "$did" = 1 ] && changed || unchanged
}
cmd_rabbit_user() {     # rabbit user 'openstack' (password left as it is when it exists)
    load_secrets; local did=0
    if ! rabbitmqctl list_users 2>/dev/null | awk '{print $1}' | grep -qx openstack; then
        rabbitmqctl add_user openstack "$RABBIT_PASS" >/dev/null; did=1; log "rabbit user 'openstack' created"
    fi
    if ! rabbitmqctl list_permissions 2>/dev/null | awk '$1=="openstack"{print $2$3$4}' | grep -qx '\.\*\.\*\.\*'; then
        rabbitmqctl set_permissions openstack ".*" ".*" ".*" >/dev/null; did=1
    fi
    [ "$did" = 1 ] && changed || unchanged
}

# --------------------------------------------------------------------------
# schema sync (counts tables before and after so that "changed" is true)
# --------------------------------------------------------------------------
cmd_sync() {            # sync keystone|glance|placement|neutron|nova
    load_secrets    # only so that failure output can be masked
    local svc="$1" before after
    case "$svc" in
        keystone)  before="$(table_count keystone)";  run_logged "keystone-manage db_sync" runuser -u keystone -- keystone-manage db_sync;  after="$(table_count keystone)" ;;
        glance)    before="$(table_count glance)";    run_logged "glance-manage db_sync" runuser -u glance -- glance-manage db_sync; after="$(table_count glance)" ;;
        placement) before="$(table_count placement)"; run_logged "placement-manage db sync" runuser -u placement -- placement-manage db sync; after="$(table_count placement)" ;;
        neutron)   before="$(table_count neutron)"
                   run_logged "neutron-db-manage upgrade head" runuser -u neutron -- neutron-db-manage \
                       --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini upgrade head
                   after="$(table_count neutron)" ;;
        nova)      before="$(( $(table_count nova_api) + $(table_count nova) + $(table_count nova_cell0) ))"
                   run_logged "nova-manage api_db sync" runuser -u nova -- nova-manage api_db sync
                   run_logged "nova-manage cell_v2 map_cell0" runuser -u nova -- nova-manage cell_v2 map_cell0
                   run_logged "nova-manage db sync" runuser -u nova -- nova-manage db sync
                   after="$(( $(table_count nova_api) + $(table_count nova) + $(table_count nova_cell0) ))" ;;
        *) die "unknown service $svc" ;;
    esac
    log "$svc schema: $before -> $after tables"
    [ "$before" = "$after" ] && unchanged || changed
}

# --------------------------------------------------------------------------
# Keystone
# --------------------------------------------------------------------------
cmd_keystone_keys() {   # keystone-keys fernet|credential
    case "$1" in
        # run_logged keeps the tool's output off stdout, which must be exactly "changed"/"unchanged" for
        # changed_when; on a failure it shows the tail of that output on stderr and stops.
        fernet)     [ -s /etc/keystone/fernet-keys/0 ] && unchanged
                    run_logged "keystone-manage fernet_setup" \
                        keystone-manage fernet_setup --keystone-user keystone --keystone-group keystone; changed ;;
        credential) [ -s /etc/keystone/credential-keys/0 ] && unchanged
                    run_logged "keystone-manage credential_setup" \
                        keystone-manage credential_setup --keystone-user keystone --keystone-group keystone; changed ;;
        *) die "unknown key kind $1" ;;
    esac
}
cmd_keystone_bootstrap() {   # keystone-bootstrap <controller-ip> <region>
    local ip="$1" region="$2"; load_secrets
    # bootstrap is idempotent in Keystone itself; "changed" means the admin could not yet authenticate
    if (set +e; . "$OPENRC" 2>/dev/null && OS_PASSWORD="$ADMIN_PASSWORD" os token issue >/dev/null 2>&1); then unchanged; fi
    OS_BOOTSTRAP_PASSWORD="$ADMIN_PASSWORD" keystone-manage bootstrap \
        --bootstrap-admin-url "http://${ip}:5000/v3/" --bootstrap-internal-url "http://${ip}:5000/v3/" \
        --bootstrap-public-url "http://${ip}:5000/v3/" --bootstrap-region-id "$region" >/dev/null \
        || die "keystone-manage bootstrap failed"
    changed
}
ks_pass_var() {
    case "$1" in
        glance) echo GLANCE_SERVICE_PASS ;; placement) echo PLACEMENT_SERVICE_PASS ;;
        neutron) echo NEUTRON_SERVICE_PASS ;; nova) echo NOVA_SERVICE_PASS ;; *) die "unknown service user $1" ;;
    esac
}
cmd_ks_project() { load_openrc; os project show "$1" >/dev/null 2>&1 && unchanged; os project create --domain default "$1" >/dev/null; changed; }
cmd_ks_user() {         # service user; an existing user's password is left unchanged
    load_secrets; load_openrc
    os user show "$1" >/dev/null 2>&1 && unchanged
    local pv; pv="$(ks_pass_var "$1")"
    # the client has no non-interactive channel other than --password (as in hagistack)
    os user create --domain default --password "${!pv}" "$1" >/dev/null
    changed
}
cmd_ks_role() {         # ks-role <user> <project> <role>
    load_openrc
    os role assignment list --user "$1" --project "$2" --role "$3" --names -f value 2>/dev/null | grep -q . && unchanged
    os role add --project "$2" --user "$1" "$3" >/dev/null; changed
}
cmd_ks_service() {      # ks-service <name> <type> <description>
    load_openrc
    os service show "$1" >/dev/null 2>&1 && unchanged
    os service create --name "$1" --description "$3" "$2" >/dev/null; changed
}
cmd_ks_endpoint() {     # ks-endpoint <service> <interface> <url> <region>
    load_openrc
    local line id cur
    line="$(os endpoint list --service "$1" --interface "$2" --region "$4" -f value -c ID -c URL 2>/dev/null | head -1)"
    if [ -n "$line" ]; then
        id="${line%% *}"; cur="${line#* }"
        [ "$cur" = "$3" ] && unchanged
        log "endpoint $1/$2 has URL $cur, wanted $3: updating"
        os endpoint set --url "$3" "$id" >/dev/null || die "could not update endpoint $1/$2"
        changed
    fi
    os endpoint create --region "$4" "$1" "$2" "$3" >/dev/null; changed
}

# --------------------------------------------------------------------------
# Nova cells
# --------------------------------------------------------------------------
cmd_nova_cell() {       # nova-cell create cell1 | nova-cell discover
    case "$1" in
        create) if runuser -u nova -- nova-manage cell_v2 list_cells 2>/dev/null | grep -qE "[| ]$2[ |]"; then unchanged; fi
                runuser -u nova -- nova-manage cell_v2 create_cell --name "$2" >/dev/null 2>&1 || die "cell_v2 create_cell failed"; changed ;;
        discover) # "Found N cell mappings." is printed on every run; only "unmapped computes" with N>0 means work was done
                  local out rc=0
                  load_secrets    # only so that failure output can be masked
                  out="$(runuser -u nova -- nova-manage cell_v2 discover_hosts --verbose 2>&1)" || rc=$?
                  [ "$rc" -eq 0 ] || { printf '%s\n' "$out" | tail -n 8 | redact | sed 's/^/    | /' >&2; die "nova-manage cell_v2 discover_hosts failed (exit $rc)"; }
                  if grep -qE 'Found [1-9][0-9]* unmapped computes' <<<"$out"; then changed; fi
                  unchanged ;;
        *) die "unknown nova-cell action $1" ;;
    esac
}

# --------------------------------------------------------------------------
# Open vSwitch / OVN
# --------------------------------------------------------------------------
cmd_ovs_set() {         # ovs-set <external-ids key> <value>
    local cur; cur="$(ovs-vsctl --if-exists get open . "external-ids:$1" 2>/dev/null | tr -d '"' || true)"
    [ "$cur" = "$2" ] && unchanged
    ovs-vsctl set open . "external-ids:$1=$2"; changed
}
cmd_ovs_bridge() { ovs-vsctl br-exists "$1" 2>/dev/null && unchanged; ovs-vsctl --may-exist add-br "$1"; changed; }
cmd_ovs_manager() {     # ovs-manager <target>   (loopback-only manager, for os_vif)
    ovs-vsctl --timeout=10 get-manager 2>/dev/null | grep -qx "$1" && unchanged
    ovs-vsctl --timeout=10 set-manager "$1"; changed
}
cmd_ovn_connection() {  # ovn-connection nb|sb <target>
    local tool="ovn-${1}ctl" cur
    # NB prints just the target; SB prints `read-write role="" ptcp:6642:<ip>` (found on a real host: comparing the
    # whole line made this report "changed" on every run), so compare the last field.
    cur="$($tool --timeout=10 get-connection 2>/dev/null | awk 'NF{print $NF}' | head -1 || true)"
    [ "$cur" = "$2" ] && unchanged
    $tool --timeout=10 set-connection "$2" >/dev/null 2>&1 || die "$tool set-connection $2 failed"; changed
}

# --------------------------------------------------------------------------
# initial resources (show-or-create by name)
# --------------------------------------------------------------------------
cmd_os_flavor() {       # os-flavor <name> <vcpus> <ram-mb> <disk-gb>
    load_openrc; os flavor show "$1" >/dev/null 2>&1 && unchanged
    os flavor create --vcpus "$2" --ram "$3" --disk "$4" "$1" >/dev/null; changed
}
cmd_os_image() {        # os-image <name> <url> <sha256>
    load_openrc
    local st
    st="$(os image show "$1" -f value -c status 2>/dev/null || true)"
    [ "$st" = active ] && unchanged
    case "$st" in
        "") ;;
        queued|killed|deleted)  # an upload that never completed: not usable, safe to replace
            log "image '$1' exists in state '$st'; deleting it to upload again"
            os image delete "$1" >/dev/null || die "could not delete the incomplete image '$1'" ;;
        *) die "image '$1' exists in state '$st' (not active); wait for it or remove it by hand" ;;
    esac
    mkdir -p "$STATE/images"; chmod 0755 "$STATE/images"
    local dest="$STATE/images/${2##*/}" have=""
    [ -f "$dest" ] && have="$(sha256sum "$dest" | cut -d' ' -f1)"
    if [ "$have" != "$3" ]; then
        curl -fsSL --retry 3 --retry-delay 2 -m 900 -o "$dest" "$2" || die "could not download $2"
        have="$(sha256sum "$dest" | cut -d' ' -f1)"
        [ "$have" = "$3" ] || die "downloaded image digest mismatch (expected $3, got $have); NOT uploaded"
    fi
    os image create --disk-format qcow2 --container-format bare --public \
        --property "sinter_sha256=$3" --file "$dest" "$1" >/dev/null
    changed
}
cmd_os_net_provider() { # os-net-provider <name> <physnet> <subnet> <cidr> <gateway> <start> <end>
    load_openrc; local did=0
    if ! os network show "$1" >/dev/null 2>&1; then
        os network create --share --external --provider-physical-network "$2" --provider-network-type flat "$1" >/dev/null; did=1
    fi
    # the subnet is checked on its own: a run that died between the two creates leaves a network without it
    if ! os subnet show "$3" >/dev/null 2>&1; then
        os subnet create --network "$1" --no-dhcp --allocation-pool "start=$6,end=$7" \
            --gateway "$5" --subnet-range "$4" "$3" >/dev/null; did=1
    fi
    [ "$did" = 1 ] && changed || unchanged
}
cmd_os_net_tenant() {   # os-net-tenant <name> <subnet> <cidr> <dns>
    load_openrc; local did=0
    if ! os network show "$1" >/dev/null 2>&1; then os network create "$1" >/dev/null; did=1; fi
    if ! os subnet show "$2" >/dev/null 2>&1; then
        os subnet create --network "$1" --dns-nameserver "$4" --subnet-range "$3" "$2" >/dev/null; did=1
    fi
    [ "$did" = 1 ] && changed || unchanged
}
cmd_os_router() {       # os-router <name> <tenant-subnet> <external-network>
    load_openrc; local did=0
    if ! os router show "$1" >/dev/null 2>&1; then os router create "$1" >/dev/null; did=1; fi
    local sid; sid="$(os subnet show "$2" -f value -c id 2>/dev/null)"
    if [ -n "$sid" ] && ! os port list --router "$1" -f json 2>/dev/null | python3 -c '
import json, sys
want = sys.argv[1]
try: ports = json.load(sys.stdin)
except Exception: raise SystemExit(1)
for port in ports:
    fixed = port.get("Fixed IP Addresses") or port.get("fixed_ips") or []
    if isinstance(fixed, dict): fixed = [fixed]
    for e in fixed:
        if isinstance(e, dict) and e.get("subnet_id") == want: raise SystemExit(0)
        if isinstance(e, str) and want in e: raise SystemExit(0)
raise SystemExit(1)' "$sid"; then
        os router add subnet "$1" "$2" >/dev/null || die "could not add subnet $2 to router $1"; did=1
    fi
    if [ "$(os router show "$1" -f value -c external_gateway_info 2>/dev/null | tr -d ' \n')" = "None" ] \
       || [ -z "$(os router show "$1" -f value -c external_gateway_info 2>/dev/null)" ]; then
        os router set --external-gateway "$3" "$1" >/dev/null || die "could not set the external gateway of router $1"; did=1
    fi
    [ "$did" = 1 ] && changed || unchanged
}
cmd_os_secgroup_rule() { # os-secgroup-rule ssh|icmp  (on the admin project's default group)
    load_openrc
    local proj sg out rc=0
    proj="$(os project show admin -f value -c id 2>/dev/null)" || die "no admin project"
    sg="$(os security group list --project "$proj" -f value -c ID -c Name 2>/dev/null | awk '$2=="default"{print $1; exit}')"
    [ -n "$sg" ] || die "could not resolve the admin project's default security group"
    case "$1" in
        ssh)  out="$(os security group rule create --proto tcp --dst-port 22 "$sg" 2>&1)" || rc=$? ;;
        icmp) out="$(os security group rule create --proto icmp "$sg" 2>&1)" || rc=$? ;;
        *) die "unknown rule $1" ;;
    esac
    if [ "$rc" -eq 0 ]; then changed; fi
    grep -qiE 'already exist|conflict|409' <<<"$out" && unchanged
    die "could not create the security group rule '$1': $(head -3 <<<"$out")"
}
cmd_os_keypair() {      # os-keypair <name>: the private key is kept in $ETC/<name> (0600)
    load_openrc; os keypair show "$1" >/dev/null 2>&1 && unchanged
    install -d -m 0700 "$ETC"
    ( umask 077; os keypair create "$1" > "$ETC/$1" ) || die "keypair create failed"
    chmod 0600 "$ETC/$1"; changed
}

# --------------------------------------------------------------------------
# Horizon (a marked block appended to the shipped local_settings)
# --------------------------------------------------------------------------
HZ_BEGIN="# >>> sinter-openstack begin — managed block, edit above this line"
HZ_END="# <<< sinter-openstack end"
cmd_horizon_settings() {   # horizon-settings <block-file>: install the block, cut anything after the marker
    local settings="$HORIZON_SETTINGS" blockfile="$1" cur="" tmp
    [ -f "$settings" ] || die "$settings does not exist; is openstack-dashboard installed?"
    [ -r "$blockfile" ] || die "$blockfile is not readable"
    if grep -qF "$HZ_BEGIN" "$settings"; then cur="$(awk -v m="$HZ_BEGIN" 'index($0,m)==1{f=1} f' "$settings")"; fi
    [ "$cur" = "$(cat "$blockfile")" ] && unchanged
    tmp="$(mktemp)"; chmod 0640 "$tmp"
    awk -v m="$HZ_BEGIN" 'index($0,m)==1{exit} {print}' "$settings" > "$tmp"
    cat "$blockfile" >> "$tmp"
    cat "$tmp" > "$settings"; rm -f "$tmp"
    chown root:apache "$settings"; chmod 0640 "$settings"
    changed
}
cmd_horizon_assets() {     # rebuild the offline manifest (needed whenever the settings change)
    local mark="$STATE/horizon-assets.stamp" settings="$HORIZON_SETTINGS"
    if [ -f "$mark" ] && [ "$mark" -nt "$settings" ]; then unchanged; fi
    log "regenerating static assets (collectstatic + compress); this takes a minute"
    /usr/share/openstack-dashboard/manage.py collectstatic --noinput --clear >/dev/null 2>&1 || die "collectstatic failed"
    /usr/share/openstack-dashboard/manage.py compress --force >/dev/null 2>&1 || die "compress failed"
    chown -R apache:apache /usr/share/openstack-dashboard/static 2>/dev/null || true
    mkdir -p "$STATE"; touch "$mark"
    # the running mod_wsgi processes hold the old settings; hagistack reloads httpd before it probes the login page
    systemctl try-reload-or-restart httpd >/dev/null 2>&1 || log "httpd could not be reloaded; the login page may still show the old settings"
    changed
}

sub="${1:-}"; [ -n "$sub" ] || die "usage: ensure <subcommand> [args...]"; shift || true
fn="cmd_${sub//-/_}"
declare -F "$fn" >/dev/null || die "unknown subcommand: $sub"
"$fn" "$@"
