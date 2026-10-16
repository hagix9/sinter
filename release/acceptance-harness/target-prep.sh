#!/bin/bash
# Prepares one disposable acceptance target: the prerequisites RELEASE.md
# lists for a supported target (systemd, OpenSSH server, /bin/sh, attr) plus a
# dedicated non-root acceptance user with passwordless sudo -n and an SSH key
# pair for the loopback SSH check. Idempotent.
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
echo "pending package transactions: $(pgrep -c -f 'dnf|yum|apt-get' 2>/dev/null || echo 0)"

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
install -d -m 700 -o sinter -g sinter /home/sinter/.ssh
touch /home/sinter/.ssh/authorized_keys
grep -q 'acceptance' /home/sinter/.ssh/authorized_keys 2>/dev/null || cat /opt/sinter-acceptance/ssh/id_ed25519.pub >> /home/sinter/.ssh/authorized_keys
chown sinter:sinter /home/sinter/.ssh/authorized_keys
chmod 600 /home/sinter/.ssh/authorized_keys
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
df -h / | tail -1
echo "== target prep end $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo 0 > /tmp/prep.rc
