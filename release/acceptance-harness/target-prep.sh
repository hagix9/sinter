#!/bin/bash
# Prepares one disposable acceptance target: the prerequisites RELEASE.md
# lists for a supported target (systemd, OpenSSH server, /bin/sh, attr) plus a
# dedicated non-root acceptance user with passwordless sudo -n and an SSH key
# pair for the loopback SSH check, and a running firewalld whose default zone
# allows ssh (v1.15.0 fw03 checks). Idempotent.
set -u
LOG=/tmp/target-prep.log
exec >> "$LOG" 2>&1
echo "== target prep start $(date -u +%Y-%m-%dT%H:%M:%SZ)"
. /etc/os-release
echo "os=$NAME $VERSION_ID $(uname -m)"

# Deterministic acceptance window: an unattended package transaction on the
# target would change the host and its package cache underneath the run, so the
# automatic update timers are stopped for the duration. This is host
# preparation only; it does not change the product under test.
for t in dnf-automatic.timer dnf-makecache.timer apt-daily.timer apt-daily-upgrade.timer; do
  if systemctl list-unit-files "$t" --no-legend 2>/dev/null | grep -q .; then
    systemctl disable --now "$t" >/dev/null 2>&1 && echo "stopped $t"
  fi
done
systemctl stop unattended-upgrades.service >/dev/null 2>&1
# A timer that fired before it was disabled leaves its service running (on a
# fresh RHEL-family VM, `dnf makecache --timer` about ten minutes after boot);
# a package check started meanwhile waits for the dnf lock. Such a run is
# never killed (an update stopped halfway can leave the host unbootable): wait
# until no package-manager service or process is left, three quiet checks in a
# row, for at most SINTER_PREP_QUIET_SECONDS (default 900). Otherwise stop
# without a prep.rc, which the driver records as a failed preparation.
busy() {
  local units n
  units=$(systemctl list-units --no-legend --state=activating,active,deactivating \
    'dnf-makecache.service' 'dnf-automatic*.service' 'apt-daily*.service' 'packagekit.service' 2>/dev/null | wc -l)
  n=$(ps -eo comm= | grep -cE '^(dnf|dnf-automatic|yum|apt|apt-get|dpkg|unattended-upgr|packagekitd)$')
  [ "$units" -gt 0 ] || [ "$n" -gt 0 ]
}
quiet=0; waited=0; limit=${SINTER_PREP_QUIET_SECONDS:-900}
while [ "$quiet" -lt 3 ]; do
  if busy; then quiet=0; else quiet=$((quiet + 1)); fi
  [ "$quiet" -ge 3 ] && break
  if [ "$waited" -ge "$limit" ]; then echo "STOP package manager still busy after ${waited}s"; exit 6; fi
  sleep 5; waited=$((waited + 5))
done
echo "package managers quiet (waited ${waited}s)"

# attr: /usr/bin/getfattr is a documented target prerequisite
if [ ! -x /usr/bin/getfattr ]; then
  echo "installing attr"
  case "$ID_LIKE $NAME" in
    *debian*|*ubuntu*|*Ubuntu*) apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq attr ;;
    *) dnf install -y -q attr ;;
  esac
fi
[ -x /usr/bin/getfattr ] && echo "getfattr OK" || { echo "STOP getfattr missing"; exit 3; }

command -v systemctl >/dev/null && echo "systemd OK" || { echo "STOP no systemd"; exit 3; }
[ -x /bin/sh ] && echo "/bin/sh OK" || { echo "STOP no /bin/sh"; exit 3; }
systemctl start sshd 2>/dev/null || systemctl start ssh 2>/dev/null
sleep 2
if ss -ltn 2>/dev/null | grep -q ':22 '; then echo "sshd listening OK"; else echo "STOP sshd not listening"; exit 3; fi

if ! id sinter >/dev/null 2>&1; then
  useradd -m -s /bin/bash sinter && echo "user sinter created"
else
  echo "user sinter exists"
fi
# Managed paths live under a root-owned tree so the product's trust-boundary
# check accepts them; the harness work area is separate and user-owned.
mkdir -p /opt/sinter-acceptance/state /opt/sinter-acceptance/ssh
chown root:root /opt/sinter-acceptance /opt/sinter-acceptance/state
chmod 755 /opt/sinter-acceptance /opt/sinter-acceptance/state
chown sinter:sinter /opt/sinter-acceptance/ssh
chmod 700 /opt/sinter-acceptance/ssh
mkdir -p /var/tmp/sinter-acceptance
chown sinter:sinter /var/tmp/sinter-acceptance
chmod 700 /var/tmp/sinter-acceptance
printf 'sinter ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/90-sinter-acceptance
chmod 440 /etc/sudoers.d/90-sinter-acceptance
echo "sudoers installed"

if [ ! -f /opt/sinter-acceptance/ssh/id_ed25519 ]; then
  sudo -u sinter ssh-keygen -q -t ed25519 -N '' -C acceptance -f /opt/sinter-acceptance/ssh/id_ed25519
  echo "keypair generated"
else
  echo "keypair exists"
fi
# The acceptance user's home comes from the account database (no fixed path).
SSHDIR="$(getent passwd sinter | cut -d: -f6)/.ssh"
install -d -m 700 -o sinter -g sinter "$SSHDIR"
touch "$SSHDIR/authorized_keys"
grep -q 'acceptance' "$SSHDIR/authorized_keys" 2>/dev/null || cat /opt/sinter-acceptance/ssh/id_ed25519.pub >> "$SSHDIR/authorized_keys"
chown sinter:sinter "$SSHDIR/authorized_keys"
chmod 600 "$SSHDIR/authorized_keys"
sudo -u sinter ssh-keyscan -H -p 22 127.0.0.1 2>/dev/null > /opt/sinter-acceptance/ssh/known_hosts.raw || true
grep -v '^#' /opt/sinter-acceptance/ssh/known_hosts.raw | grep -v '^$' > /opt/sinter-acceptance/ssh/known_hosts || true
chown sinter:sinter /opt/sinter-acceptance/ssh/known_hosts /opt/sinter-acceptance/ssh/id_ed25519.pub
chmod 600 /opt/sinter-acceptance/ssh/id_ed25519
echo "known_hosts lines: $(wc -l < /opt/sinter-acceptance/ssh/known_hosts)"
if sudo -u sinter ssh -i /opt/sinter-acceptance/ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 22 127.0.0.1 'echo LOOPBACK_SSH_OK' 2>&1 | grep -q LOOPBACK_SSH_OK; then
  echo "loopback ssh OK"
else
  echo "STOP loopback ssh failed"
  exit 4
fi
sudo -u sinter sudo -n true && echo "passwordless sudo OK" || { echo "STOP passwordless sudo failed"; exit 5; }
# BEGIN fw-prep
# firewalld (docs/design/v1.15.0-release-and-acceptance.md §3.1): the fw03
# checks need a running firewalld. It is installed and started here when it is
# missing (this VM is disposable). Starting it changes the filtering of the
# management connection, so the zone of the default-route interface (the zone
# the runner's connection uses; the default zone when the interface is in
# none) must allow the ssh service or 22/tcp, and a new loopback SSH session
# must work. Otherwise firewalld is put back as it was before (stopped and
# disabled when it was not active) and the preparation stops (exit 7). The
# state before is logged; nothing else is changed.
FW_PRE=$(command -v firewall-cmd >/dev/null 2>&1 && echo installed || echo missing)
FW_PREACT=$(systemctl is-active firewalld 2>/dev/null)
FW_PREEN=$(systemctl is-enabled firewalld 2>/dev/null)
UFW=$(command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 || echo "ufw absent")
echo "firewalld before: $FW_PRE active=$FW_PREACT enabled=$FW_PREEN ($UFW) dummy_links=$(ip -o link show type dummy 2>/dev/null | wc -l)"
fw_stop() { # fw_stop <reason>: firewalld back to the state before, then stop the preparation
  echo "STOP $1"
  if [ "$FW_PREACT" != active ]; then systemctl stop firewalld >/dev/null 2>&1; fi
  case "$FW_PREEN" in enabled) ;; *) systemctl disable firewalld >/dev/null 2>&1 ;; esac
  echo "firewalld restored: active=$(systemctl is-active firewalld 2>/dev/null) enabled=$(systemctl is-enabled firewalld 2>/dev/null)"
  exit 7; }
case "$UFW" in *"Status: active"*) echo "STOP ufw is active; firewalld would conflict with it"; exit 7 ;; esac
if [ "$FW_PRE" = missing ]; then
  case "$ID_LIKE $NAME" in
    *debian*|*ubuntu*|*Ubuntu*) apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq firewalld ;;
    *) dnf install -y -q firewalld ;;
  esac
fi
systemctl enable --now firewalld >/dev/null 2>&1
FW_STATE=$(firewall-cmd --state 2>&1)
FW_DEV=$(ip -o route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
FW_MZ=$(firewall-cmd --get-zone-of-interface="$FW_DEV" 2>/dev/null) || FW_MZ=$(firewall-cmd --get-default-zone 2>/dev/null)
FW_SSH=$(firewall-cmd --zone="$FW_MZ" --query-service=ssh 2>/dev/null)
FW_P22=$(firewall-cmd --zone="$FW_MZ" --query-port=22/tcp 2>/dev/null)
echo "firewalld after: state=$FW_STATE default_route_dev=$FW_DEV zone=$FW_MZ ssh_service=$FW_SSH port22=$FW_P22 version=$(firewall-cmd --version 2>/dev/null)"
[ "$FW_STATE" = running ] || fw_stop "firewalld is not running"
[ -n "$FW_DEV" ] && [ -n "$FW_MZ" ] || fw_stop "the default-route interface or its zone is unknown"
[ "$FW_SSH" = yes ] || [ "$FW_P22" = yes ] || fw_stop "zone $FW_MZ of $FW_DEV allows neither the ssh service nor 22/tcp"
if sudo -u sinter ssh -i /opt/sinter-acceptance/ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/opt/sinter-acceptance/ssh/known_hosts -p 22 127.0.0.1 'echo LOOPBACK_SSH_OK' 2>&1 | grep -q LOOPBACK_SSH_OK; then
  echo "loopback ssh after firewalld OK"
else
  fw_stop "loopback ssh failed after firewalld start"
fi
# END fw-prep
# the fw03 checks create a dummy interface; logged here, not required here
# (loading the dummy module may create dummy0 by itself: logged, so that the fw03 snapshot starts after it)
if ip link add sinterprep0 type dummy >/dev/null 2>&1; then ip link del sinterprep0; echo "dummy interface OK"; else echo "dummy interface unavailable"; fi
echo "dummy links after: $(ip -o link show type dummy 2>/dev/null | awk -F': ' '{print $2}' | tr '\n' ' ')"
df -h / | tail -1
echo "== target prep end $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo 0 > /tmp/prep.rc
