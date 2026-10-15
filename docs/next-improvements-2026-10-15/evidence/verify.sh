#!/bin/bash
# Sinter v1.5 DNF-metadata verification. Run as the sudo-capable login user.
LOG="$HOME/v15-verify.log"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1
SINTER=/usr/local/bin/sinter
PRE=/usr/local/bin/sinter-1.4.0
R="$HOME/v15"; rm -rf "$R"; mkdir -p "$R"

count_cache() { sudo -n bash -c 'find /var/cache/dnf -maxdepth 1 -mindepth 1 2>/dev/null | wc -l'; }
say() { echo "$@"; }

say "########## $(. /etc/os-release; echo "$PRETTY_NAME") ##########"
say "date: $(date -u +%FT%TZ)"
say "dnf: $(dnf --version 2>&1 | tail -1)   /usr/bin/dnf -> $(readlink -f /usr/bin/dnf 2>/dev/null)"
say "glibc: $(ldd --version 2>&1 | head -1)"
say "v1.5 binary  : $($SINTER --version 2>&1)"
if $PRE --version >/dev/null 2>&1; then
  say "v1.4.0 binary: $($PRE --version 2>&1)"
else
  say "v1.4.0 binary: NOT RUNNABLE on this host's glibc"
fi

cat > "$R/tree.yaml" <<'YAML'
version: 1
resources:
  - id: p
    type: package
    with:
      name: tree
      state: present
YAML
cat > "$R/zip.yaml" <<'YAML'
version: 1
resources:
  - id: p
    type: package
    with:
      name: zip
      state: present
YAML
cat > "$R/epel.yaml" <<'YAML'
version: 1
resources:
  - id: p
    type: package
    with:
      name: epel-release
      state: present
YAML
cat > "$R/epelpkg.yaml" <<'YAML'
version: 1
resources:
  - id: p
    type: package
    with:
      name: ncdu
      state: present
YAML
cat > "$R/dep.yaml" <<'YAML'
version: 1
resources:
  - id: grp
    type: group
    with:
      name: v15demo
      system: true
  - id: usr
    type: user
    depends_on: [grp]
    with:
      name: v15demo
      group: v15demo
      shell: /usr/sbin/nologin
      system: true
  - id: dir
    type: directory
    depends_on: [usr]
    with:
      path: /opt/v15demo
      owner: v15demo
      group: v15demo
      mode: "0750"
  - id: cfg
    type: file
    depends_on: [dir]
    with:
      path: /opt/v15demo/app.conf
      content: "managed by sinter\n"
      owner: v15demo
      group: v15demo
      mode: "0640"
YAML

say; say "===== S0 reset (make the run repeatable) ====="
sudo -n rm -f /etc/yum.repos.d/zzz-bogus.repo
sudo -n dnf remove -y tree zip ncdu epel-release >/dev/null 2>&1 || true
sudo -n dnf clean all >/dev/null 2>&1
sudo -n rpm -q tree zip ncdu epel-release 2>&1 | sed 's/^/  /'
say "  cachedir entries: $(count_cache)"

say; say "===== S1pre (v1.4.0, if runnable): dnf clean all, then apply package tree ====="
if $PRE --version >/dev/null 2>&1; then
  sudo -n dnf clean all >/dev/null 2>&1
  say "  cachedir entries after clean: $(count_cache)"
  $PRE apply "$R/tree.yaml" --sudo; say "  S1pre_RC=$?"
  say "  tree installed: $(sudo -n rpm -q tree 2>&1)"
  say "  cachedir entries after: $(count_cache)"
else
  say "  SKIPPED (v1.4.0 binary cannot run on this glibc)"
fi

say; say "===== S1 (v1.5): dnf clean all, then apply package tree ====="
sudo -n dnf clean all >/dev/null 2>&1
say "  cachedir entries after clean: $(count_cache)"
$SINTER apply "$R/tree.yaml" --sudo; say "  S1_RC=$?"
say "  tree installed: $(sudo -n rpm -q tree 2>&1)"
say "  cachedir entries after: $(count_cache)"

say; say "===== S1json (v1.5): dnf clean all, then apply --format json ====="
sudo -n dnf clean all >/dev/null 2>&1
$SINTER apply "$R/tree.yaml" --sudo --format json > "$HOME/s1.json" 2>&1; say "  S1json_RC=$?"
say "  json status line: $(grep -o '"status"[^,]*' "$HOME/s1.json" | head -1)"

say; say "===== S2 (v1.5): re-apply tree (idempotent) ====="
$SINTER apply "$R/tree.yaml" --sudo; say "  S2_RC=$?"

say; say "===== S3 (v1.5): plan tree after converged ====="
$SINTER plan "$R/tree.yaml" --sudo; say "  S3_RC=$?"

say; say "===== S4 (v1.5): audit tree ====="
$SINTER audit "$R/tree.yaml" --sudo; say "  S4_RC=$?"

say; say "===== S5a: apply epel-release (adds the EPEL repo) ====="
$SINTER apply "$R/epel.yaml" --sudo; say "  S5a_RC=$?"
say "  epel repo file(s): $(ls /etc/yum.repos.d/ | grep -i epel | tr '\n' ' ')"

say; say "===== S5b: apply ncdu from EPEL whose metadata was never fetched ====="
$SINTER apply "$R/epelpkg.yaml" --sudo; say "  S5b_RC=$?"
say "  ncdu installed: $(sudo -n rpm -q ncdu 2>&1)"

say; say "===== S6: a bogus enabled repo must fail closed (no install) ====="
sudo -n tee /etc/yum.repos.d/zzz-bogus.repo >/dev/null <<'REPO'
[bogus]
name=bogus
baseurl=http://127.0.0.1:1/does-not-exist/
enabled=1
gpgcheck=0
metadata_expire=never
REPO
sudo -n dnf clean metadata >/dev/null 2>&1
$SINTER apply "$R/zip.yaml" --sudo; say "  S6_RC=$?  (expect non-zero)"
say "  zip installed: $(sudo -n rpm -q zip 2>&1)  (expect not installed)"
sudo -n rm -f /etc/yum.repos.d/zzz-bogus.repo

say; say "===== S7: recovery - apply zip after removing the bogus repo ====="
$SINTER apply "$R/zip.yaml" --sudo; say "  S7_RC=$?"
say "  zip installed: $(sudo -n rpm -q zip 2>&1)"

say; say "===== S8: accounts/dirs dependency recipe (B/C regression) ====="
$SINTER apply "$R/dep.yaml" --sudo; say "  S8_RC=$?"
$SINTER apply "$R/dep.yaml" --sudo; say "  S8b_idempotent_RC=$?"
say "  app.conf: $(sudo -n stat -c '%U:%G %a' /opt/v15demo/app.conf 2>&1)"

say; say "===== S9: module probe (dnf module, for later design) ====="
if sudo -n dnf module list >/dev/null 2>&1; then
  say "  -- dnf module list --enabled --"
  sudo -n dnf module list --enabled 2>&1 | tail -15 | sed 's/^/  /'
  say "  -- raw 'dnf install --assumeno nodejs' transaction shape --"
  sudo -n dnf install --assumeno nodejs 2>&1 | tail -50 | sed 's/^/  /'
else
  say "  dnf module not available"
fi

say; say "===== summary ====="
sudo -n bash -c 'sed -n "s/^S\([0-9A-Za-z]*\)_RC=//p" '"$LOG"' | tr "\n" " "' 2>/dev/null || true
say "===== DONE $(date -u +%FT%TZ) ====="
