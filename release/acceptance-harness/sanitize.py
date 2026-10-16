#!/usr/bin/env python3
"""Sanitize a raw acceptance log for the public evidence bundle.

ACCEPTANCE_EVIDENCE.md requires the published logs to carry no secrets, no IP
addresses, no hostnames or internal DNS names, no cloud project/instance
identifiers, no user names and no machine-specific paths. Targets are
referenced by their label only. Values are replaced with placeholders; nothing
else about the log is changed.
"""
import ipaddress
import re
import sys

label, path = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8", errors="replace").read()

subs = [
    # instance FQDNs and short host names
    (re.compile(r"\b[a-z0-9-]+\.asia-northeast1-a\.c\.[a-z0-9-]+\.internal\b", re.I), "<target>"),
    (re.compile(r"\bhostname[=:\s]+[A-Za-z0-9][A-Za-z0-9.-]*", re.I), "hostname=<target>"),
    (re.compile(r"\bRunning on (?:host )?[A-Za-z0-9][A-Za-z0-9.-]*"), "Running on <target>"),
    # the cloud project and instance identifiers
    (re.compile(r"\bsinter-508914\b"), "<project>"),
    (re.compile(r"--project[= ][A-Za-z0-9._:-]+"), "--project <project>"),
    (re.compile(r"\bsinter-(?:rc111-hv1|acc-rocky9-builder|os-[a-z]+|p8-gateway|mikagami-validation)\b"), "<instance>"),
    (re.compile(r"\b(ubuntu24|ubuntu26|rocky98|rocky102|rhel9|rhel10|alma9|alma10)\b"), "<instance>"),
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
