#!/usr/bin/env bash
# Run hagistack's build-rpms.sh in two passes (builder.yaml).
#
# Pass 1 builds everything. build-rpms.sh publishes the repository only at the END of a run, so on a fresh
# builder the packages that need a library built earlier in the SAME run, at a version newer than RDO trunk
# offers, cannot find it yet and fail with unsatisfied build dependencies (found on the first real run:
# neutron, nova, horizon). Pass 2 builds just the packages that failed, now that pass 1 has published.
# A package that fails in pass 2 fails the run, except the names in $KNOWN_BAD (see below).
#
# KNOWN_BAD (default: requestsexceptions): its pinned signing key (0x01527a34..., the expired "Yoga Cycle"
# OpenStack Infra key) did not sign the 1.4.0 tarball (RSA key 421E6472811F9A81), so %prep's gpgverify fails.
# This is a hagistack input problem, not a Sinter one. The package is a plain Python library that Rocky/EPEL
# and RDO's deps tree provide (python3-requestsexceptions 1.4.0), so it is not needed from this repository.
set -uo pipefail
WORK="${WORK:-/var/lib/hagistack-build}"
NOCHECK="${NOCHECK:---nocheck}"
KNOWN_BAD="${KNOWN_BAD:-requestsexceptions}"
cd /opt/hagistack-src/rocky10.2 || exit 2
mkdir -p "$WORK"
./build-rpms.sh $NOCHECK 2>&1 | tee "$WORK/pass1.log"
rc1="${PIPESTATUS[0]}"
# build-rpms.sh exits non-zero when any package failed, and prints a "  FAIL <pkg>" line for each. A non-zero exit
# without such a line is a crash (killed, out of disk, manifest check failed), not a partial build.
if [ "$rc1" -ne 0 ] && ! grep -q '^  FAIL ' "$WORK/pass1.log"; then
    echo "build-rpms.sh exited $rc1 without reporting a failed package" >&2; exit 1
fi
failed="$(sed -n 's/^  FAIL \([^ ]*\) .*/\1/p' "$WORK/pass1.log" | grep -vxF -f <(printf '%s\n' $KNOWN_BAD) || true)"
if [ -n "$failed" ]; then
    echo "pass 2: rebuilding $failed" >&2
    # shellcheck disable=SC2086
    ./build-rpms.sh $NOCHECK $failed 2>&1 | tee "$WORK/pass2.log"
    [ "${PIPESTATUS[0]}" -eq 0 ] || { echo "pass 2 failed" >&2; exit 1; }
fi
# whatever is still FAIL in pass 1 must be a known-bad name
left="$(sed -n 's/^  FAIL \([^ ]*\) .*/\1/p' "$WORK/pass1.log" | grep -vxF -f <(printf '%s\n' $KNOWN_BAD) | grep -vxF -f <(printf '%s\n' $failed) || true)"
[ -z "$left" ] || { echo "unexpected failures: $left" >&2; exit 1; }
# the published repository must exist and contain the core packages before the run may be called complete
repo=/root/rpmbuild/RPMS
[ -s "$repo/repodata/repomd.xml" ] || { echo "no repository metadata under $repo" >&2; exit 1; }
for core in openstack-keystone openstack-glance openstack-placement-api openstack-neutron openstack-nova openstack-dashboard; do
    ls "$repo"/noarch/"$core"-[0-9]*.rpm >/dev/null 2>&1 || { echo "core package missing from the repository: $core" >&2; exit 1; }
done
touch "$WORK/build.ok"
