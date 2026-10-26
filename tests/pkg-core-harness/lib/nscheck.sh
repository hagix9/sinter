#!/bin/bash
# nscheck.sh -- the gate every scenario passes BEFORE it touches a package: production-build environment guard and the
# verification, from REAL KERNEL STATE, that this shell lives in its own PRIVATE mount namespace (not init's).
#
# Why (independent audit F-2, 2026-10-24): the earlier `common.sh` skipped the namespace creation whenever the environment
# said H_NS_ENTERED=1 or H_TEST_MODE=1, and verified the namespace only when a wrapper was about to be mounted.  An
# environment variable is not a proof.  Now:
#   * H_NS_ENTERED is only a re-exec loop breaker.  It never skips a check.
#   * The namespace is verified from /proc (own ns id != init's ns id, every mount private) at the very start of the
#     scenario and again in h_init (before the baseline / any install) and again before a wrapper is mounted.
#   * A PRODUCTION build (the default; H_BUILD_KIND is a constant written by assemble.sh) aborts if the environment
#     carries any H_* variable other than the re-exec marker, resets PATH, and reads the kernel state only from the fixed
#     /proc paths.  The injection points the tests use (H_NS_SELF_LINK, H_NS_PID1_LINK, H_MOUNTINFO, H_SUDO_BIN, ...)
#     are honoured by a TEST build only, and a test build refuses to run without H_TEST_MODE=1.
# This file only DEFINES functions; common.sh runs them (so the unit tests can source it).  bash 3.2 / 5 compatible.

# production unless the build says "test" (fail-closed: a missing or unexpected value means production)
h_production() { [ "${H_BUILD_KIND:-production}" != test ]; }

h_gate_fail() { printf 'SCENARIO GATE FAILED: %s\n' "$*" >&2; }

h_env_guard() {  # production: no H_* variable may come from the environment (except the re-exec marker); test build: H_TEST_MODE=1
    local v bad=""
    if h_production; then
        for v in $(compgen -e); do
            case "$v" in H_NS_ENTERED) ;; H_*|BASH_ENV|ENV|SHELLOPTS|BASHOPTS|LD_PRELOAD|LD_LIBRARY_PATH|BASH_XTRACEFD|PROMPT_COMMAND) bad="$bad $v" ;; esac
        done
        if [ -n "$bad" ]; then h_gate_fail "the environment carries H_* variables [${bad# }]: a production run accepts none (names only are shown)"; return 1; fi
    else
        [ "${H_TEST_MODE:-0}" = 1 ] || { h_gate_fail "a test build runs only with H_TEST_MODE=1"; return 1; }
    fi
    return 0
}

h_ns_root_cmd() {  # run a command as root: directly if already root, otherwise through the non-interactive sudo
    if [ "$(id -u)" = 0 ]; then "$@"; return $?; fi
    if h_production; then /usr/bin/sudo -n "$@"; else "${H_SUDO_BIN:-sudo}" -n "$@"; fi
}

h_ns_require() {  # 0 only if this shell is in a mount namespace different from init's and EVERY mount is private
    local self_link pid1_link mi mine pid1 idre='^mnt:\[[0-9]+\]$'
    if h_production; then
        self_link=/proc/self/ns/mnt; pid1_link=/proc/1/ns/mnt; mi=/proc/self/mountinfo
    else
        self_link="${H_NS_SELF_LINK:-}"; pid1_link="${H_NS_PID1_LINK:-}"; mi="${H_MOUNTINFO:-}"
    fi
    [ -n "$self_link" ] && [ -n "$pid1_link" ] && [ -n "$mi" ] || { h_gate_fail "no kernel state sources"; return 1; }
    mine="$(readlink "$self_link" 2> /dev/null)"
    if [ -z "$mine" ]; then h_gate_fail "cannot read this shell's mount namespace id"; return 1; fi
    if h_production; then pid1="$(h_ns_root_cmd readlink "$pid1_link" 2> /dev/null)"; else pid1="$(readlink "$pid1_link" 2> /dev/null)"; fi
    if [ -z "$pid1" ]; then h_gate_fail "cannot read init's mount namespace id"; return 1; fi
    [[ "$mine" =~ $idre ]] && [[ "$pid1" =~ $idre ]] || { h_gate_fail "unexpected namespace id format"; return 1; }
    if [ "$mine" = "$pid1" ]; then h_gate_fail "this shell shares init's mount namespace [$mine]"; return 1; fi
    [ -r "$mi" ] || { h_gate_fail "cannot read the mount table"; return 1; }     # no `-s`: a procfs file reports size 0 on Linux; an empty table is still refused by the awk check below (NR == 0)
    # every mount line: optional fields (7th field up to the lone "-") must be empty = private; a "/" mount must exist
    if ! LC_ALL=C awk '
            { j = 0; for (k = 7; k <= NF; k++) if ($k == "-") { j = k; break }
              if (j == 0 || NF < 8) bad = 1
              for (k = 7; k < j; k++) if ($k ~ /^(shared|master|propagate_from|unbindable)/) bad = 1
              if ($5 == "/") root = 1 }
            END { exit (bad || !root || NR == 0) }' "$mi" 2> /dev/null; then
        h_gate_fail "the mount propagation is not private (or the mount table is unreadable/unparsable)"
        return 1
    fi
    H_NS_ID="$mine"; H_NS_HOST_ID="$pid1"
    return 0
}

h_gate_env() {  # environment guard + (production) fixed PATH: also the whole gate of the recovery tool, which needs no namespace
    h_env_guard || return 1
    if h_production; then PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; fi
    return 0
}

h_gate() {  # the early gate, run by common.sh before anything else: env guard -> (re-exec once) -> kernel verification
    local me sudo_bin unshare_bin env_bin
    h_gate_env || return 1
    if h_production; then
        sudo_bin=/usr/bin/sudo; unshare_bin=/usr/bin/unshare; env_bin=/usr/bin/env
    else
        sudo_bin="${H_SUDO_BIN:-sudo}"; unshare_bin="${H_UNSHARE_BIN:-unshare}"; env_bin="${H_ENV_BIN:-env}"
    fi
    if [ "${H_NS_ENTERED:-}" != 1 ]; then
        # not yet re-executed: enter a private mount namespace as root, then drop back to the login user.  A failing sudo or
        # unshare makes the exec chain fail: nothing of the scenario runs.
        me="$(id -un)" || { h_gate_fail "cannot determine the login user"; return 1; }
        exec "$sudo_bin" -n "$unshare_bin" --mount --propagation private -- "$sudo_bin" -n -u "$me" "$env_bin" H_NS_ENTERED=1 \
            HOME="$HOME" PATH="$PATH" ARTIFACT_PATH="${ARTIFACT_PATH:-}" RUN_ID="${RUN_ID:-}" WORKSPACE="${WORKSPACE:-}" "$BASH" "$0"
        h_gate_fail "cannot enter the private mount namespace"; return 1
    fi
    # re-executed (or the marker was set by someone else): the marker proves nothing, the kernel state decides
    h_ns_require
}
