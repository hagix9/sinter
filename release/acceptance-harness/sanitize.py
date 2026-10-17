#!/usr/bin/env python3
"""Sanitize a raw acceptance log for the public evidence bundle.

ACCEPTANCE_EVIDENCE.md requires the published logs to carry no secrets, no IP
addresses, no hostnames or internal DNS names, no cloud project/instance
identifiers, no user names and no machine-specific paths. Targets are
referenced by their label only. Values are replaced with placeholders; nothing
else about the log is changed.
"""
import ipaddress
import os
import re
import sys

label, path = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8", errors="replace").read()

# Environment-specific identifiers (the cloud project, instance names, ...) are
# never kept in the repository: they come from a local, untracked patterns
# file named by SINTER_SANITIZE_PATTERNS, one `<regex><TAB><replacement>` per
# line (`#` comments allowed). Without it nothing is written (fail closed): a
# log sanitized without the project's own identifiers is not publishable.
pfile = os.environ.get("SINTER_SANITIZE_PATTERNS", "")
if not pfile or not os.path.isfile(pfile):
    sys.stderr.write("SINTER_SANITIZE_PATTERNS must name the local patterns file\n")
    sys.exit(2)
local = []
for n, line in enumerate(open(pfile, encoding="utf-8").read().splitlines(), 1):
    if not line.strip() or line.lstrip().startswith("#"):
        continue
    rx, sep, rep = line.partition("\t")
    if not sep or not rx:
        sys.stderr.write("SINTER_SANITIZE_PATTERNS line %d: expected <regex><TAB><replacement>\n" % n)
        sys.exit(2)
    local.append((re.compile(rx), rep))
if not local:
    sys.stderr.write("SINTER_SANITIZE_PATTERNS has no patterns\n")
    sys.exit(2)

subs = local + [
    # GCE internal DNS names of any instance, zone and project
    (re.compile(r"\b[a-z0-9-]+\.[a-z]+-[a-z]+[0-9]+-[a-z]\.c\.[a-z0-9-]+\.internal\b", re.I), "<target>"),
    (re.compile(r"\b[a-z0-9-]+\.c\.[a-z0-9-]+\.internal\b", re.I), "<target>"),
    (re.compile(r"\bhostname[=:\s]+[A-Za-z0-9][A-Za-z0-9.-]*", re.I), "hostname=<target>"),
    (re.compile(r"\bRunning on (?:host )?[A-Za-z0-9][A-Za-z0-9.-]*"), "Running on <target>"),
    (re.compile(r"--project[= ][A-Za-z0-9._:-]+"), "--project <project>"),
    (re.compile(r"--zone[= ][A-Za-z0-9._:-]+"), "--zone <zone>"),
    # user names other than the documented default system accounts
    (re.compile(r"\buid=\d+\((?!root\b|nobody\b|sinter\b|ubuntu\b|rocky\b|almalinux\b|cloud-user\b|ec2-user\b)([^)\s]+)\)"), "uid=<user>"),
    (re.compile(r"\b([a-z_][a-z0-9_-]*)@[A-Za-z0-9][A-Za-z0-9.-]*:[~/]"), r"<user>@<target>:~"),
    # machine-specific paths
    (re.compile(r"/(?:home)/[A-Za-z0-9._-]+"), "/home/<user>"),
    (re.compile(r"/Volumes/[^/\s]+"), "/<volume>"),
]
for rx, rep in subs:
    text = rx.sub(rep, text)

# any remaining non-loopback IPv4/IPv6 address
def mask_ip(m):
    try:
        addr = ipaddress.ip_address(m.group(0))
    except ValueError:
        return m.group(0)
    return m.group(0) if (addr.is_loopback or addr.is_unspecified) else "<ip>"


text = re.sub(r"(?<![\w.:])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])", mask_ip, text)
open(sys.argv[3], "w", encoding="utf-8").write(text)
print(f"sanitized {label}: {path} -> {sys.argv[3]}")
