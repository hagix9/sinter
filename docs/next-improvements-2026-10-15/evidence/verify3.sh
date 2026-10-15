#!/bin/bash
# Sinter v1.5 N-1/N-2/N-4 + DNF-metadata regression verification.
# Run as the sudo-capable login user on a disposable Rocky VM.
LOG="$HOME/v15b-verify.log"
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1
SINTER=/usr/local/bin/sinter
PRE=/usr/local/bin/sinter-pre
R="$HOME/v15b"; rm -rf "$R"; mkdir -p "$R"

count_cache() { sudo -n bash -c 'find /var/cache/dnf -maxdepth 1 -mindepth 1 2>/dev/null | wc -l'; }
say() { echo "$@"; }

say "########## $(. /etc/os-release; echo "$PRETTY_NAME") ##########"
say "date   : $(date -u +%FT%TZ)"
say "dnf    : $(dnf --version 2>&1 | tail -1)"
say "glibc  : $(ldd --version 2>&1 | head -1)"
say "sinter : $($SINTER --version)"
PRE_OK=0
if $PRE --version >/dev/null 2>&1; then
  say "pre    : $($PRE --version)"
  PRE_OK=1
else
  say "pre    : NOT RUNNABLE"
fi
MAJOR=$(. /etc/os-release; echo "${VERSION_ID%%.*}")

cat > "$R/tree.yaml" <<'YAML'
version: 1
resources:
  - id: p
    type: package
    with:
      name: tree
      state: present
YAML
cat > "$R/sshd-ok.yaml" <<'YAML'
version: 1
resources:
  - id: sshd
    type: file
    with:
      path: /etc/ssh/sshd_config.d/60-sinter-demo.conf
      content: "PermitRootLogin no\nMaxAuthTries 4\n"
      owner: root
      group: root
      mode: "0600"
      validate:
        program: /usr/sbin/sshd
        args: ["-t", "-f"]
        timeout_seconds: 60
YAML
cat > "$R/sshd-bad.yaml" <<'YAML'
version: 1
resources:
  - id: sshd
    type: file
    with:
      path: /etc/ssh/sshd_config.d/60-sinter-demo.conf
      content: "PermitRootLogin no\nBadDirectiveN1 yes\n"
      owner: root
      group: root
      mode: "0600"
      validate:
        program: /usr/sbin/sshd
        args: ["-t", "-f"]
        timeout_seconds: 60
YAML
cat > "$R/env.yaml" <<'YAML'
version: 1
env:
  HTTP_PROXY: "http://proxy.example.com:3128"
  NO_PROXY: "localhost,.internal.example.com"
resources:
  - id: wr1
    type: command
    with:
      program: /bin/sh
      args: ["-c", "printf 'proxy=%s noproxy=%s\\n' \"$HTTP_PROXY\" \"$NO_PROXY\" > /root/v15b-env.txt"]
  - id: wr2
    type: command
    with:
      program: /bin/sh
      args: ["-c", "printf '%s\\n' \"$HTTP_PROXY\" > /root/v15b-env2.txt"]
      env:
        HTTP_PROXY: "http://override:1"
YAML
cat > "$R/nodejs.yaml" <<'YAML'
version: 1
resources:
  - id: p
    type: package
    with:
      name: nodejs
      state: present
YAML
cat > "$R/bogus.yaml" <<'YAML'
version: 1
resources:
  - id: p
    type: package
    with:
      name: no-such-package-xyzzy-42
      state: present
YAML

# reset to a repeatable baseline
say; say "===== reset ====="
sudo -n dnf remove -y tree zip nodejs ncdu epel-release >/dev/null 2>&1 || true
sudo -n dnf module reset -y nodejs >/dev/null 2>&1 || true
sudo -n rm -f /etc/ssh/sshd_config.d/60-sinter-demo.conf /root/v15b-env.txt /root/v15b-env2.txt
sudo -n mkdir -p /etc/ssh/sshd_config.d
sudo -n dnf clean all >/dev/null 2>&1
say "  cachedir entries: $(count_cache)"

### B: DNF metadata auto-acquisition regression
say; say "===== B: cold dnf cache, then apply package tree (v1.5) ====="
sudo -n dnf clean all >/dev/null 2>&1
say "  cachedir after clean: $(count_cache)"
$SINTER apply "$R/tree.yaml" --sudo; say "  B_RC=$?"
say "  tree: $(sudo -n rpm -q tree 2>&1)"
say "  cachedir after apply: $(count_cache)"

### C: N-1 pre-publication validation
say; say "===== C1: valid sshd drop-in with validate (must publish) ====="
$SINTER apply "$R/sshd-ok.yaml" --sudo; say "  C1_RC=$?"
say "  sshd -t: $(sudo -n sshd -t && echo OK || echo FAIL)"
BEFORE=$(sudo -n sha256sum /etc/ssh/sshd_config.d/60-sinter-demo.conf 2>/dev/null | cut -d' ' -f1)
say "  published sha256: $BEFORE"

say "===== C2: invalid sshd content with validate (must refuse, file unchanged) ====="
$SINTER apply "$R/sshd-bad.yaml" --sudo; say "  C2_RC=$? (expect nonzero)"
AFTER=$(sudo -n sha256sum /etc/ssh/sshd_config.d/60-sinter-demo.conf 2>/dev/null | cut -d' ' -f1)
say "  sha256 after: $AFTER"
if [ "$BEFORE" = "$AFTER" ]; then say "  C2_UNCHANGED=yes"; else say "  C2_UNCHANGED=NO"; fi
say "  file content:"; sudo -n cat /etc/ssh/sshd_config.d/60-sinter-demo.conf | sed 's/^/    /'

### D: N-4 recipe-wide env
say; say "===== D: recipe env reaches commands; resource env overrides ====="
$SINTER apply "$R/env.yaml" --sudo; say "  D_RC=$?"
say "  env.txt : $(sudo -n cat /root/v15b-env.txt 2>&1)"
say "  env2.txt: $(sudo -n cat /root/v15b-env2.txt 2>&1)"

### E: N-2 DNF module stream (Rocky 8 only)
if [ "$MAJOR" = "8" ]; then
  say; say "===== E: DNF module stream on Rocky $MAJOR ====="
  sudo -n dnf -y makecache >/dev/null 2>&1
  if [ "$PRE_OK" = "1" ]; then
    say "  --- E-pre: apply nodejs with the pre-fix binary (warm cache) ---"
    $PRE apply "$R/nodejs.yaml" --sudo; say "  Epre_RC=$?"
    say "  nodejs after pre: $(sudo -n rpm -q nodejs 2>&1)"
  fi
  say "  --- E-post: apply nodejs with v1.5 ---"
  $SINTER apply "$R/nodejs.yaml" --sudo; say "  Epost_RC=$?"
  say "  nodejs after post: $(sudo -n rpm -q nodejs 2>&1)"
  say "  enabled modules:"
  sudo -n dnf module list --enabled 2>&1 | grep -vE "^(Last metadata|Failed to set locale)" | sed 's/^/    /'
  say "  --- E-idempotent: re-apply ---"
  $SINTER apply "$R/nodejs.yaml" --sudo; say "  Eidem_RC=$?"
  say "  --- E-fail-closed: a non-existent package ---"
  $SINTER apply "$R/bogus.yaml" --sudo; say "  Ebogus_RC=$? (expect nonzero)"
else
  say; say "===== E: skipped (module stream test is Rocky 8 specific; this is $MAJOR) ====="
  say "  --- fail-closed check with a non-existent package ---"
  $SINTER apply "$R/bogus.yaml" --sudo; say "  Ebogus_RC=$? (expect nonzero)"
fi

say; say "===== DONE $(date -u +%FT%TZ) ====="
