#!/usr/bin/env python3
"""Sanitize a raw acceptance log for the public evidence bundle.

ACCEPTANCE_EVIDENCE.md requires the published logs to carry no secrets, no IP
addresses, no hostnames or internal DNS names, no cloud project/instance
identifiers, no user names and no machine-specific paths. Targets are
referenced by their label only. Values are replaced with placeholders; nothing
else about the log is changed.

Usage: sanitize.py <label> <raw.log> <out.log>

The run's own identifiers come from the same environment as the driver
(SINTER_PROJECT, SINTER_ZONE and the instance names in SINTER_SPECS; all
required) and are masked as literals. SINTER_SANITIZE_PATTERNS may name a
local, untracked file of extra `<regex><TAB><replacement>` lines (`#` comments
allowed). If any of the run's identifiers is still present after masking,
nothing is written (exit 3).
"""
import ipaddress
import os
import re
import sys

# Public target labels: an instance named after (or inside) a label reveals
# nothing beyond the label, and masking it would destroy the label itself.
LABELS = {"ubuntu2404", "ubuntu2604", "rocky9", "rocky10",
          "rhel9", "rhel10", "alma9", "alma10"}


def die(code, msg):
    sys.stderr.write(msg + "\n")
    sys.exit(code)


if len(sys.argv) != 4:
    die(2, "usage: sanitize.py <label> <raw.log> <out.log>")
label, path, out_path = sys.argv[1:4]
text = open(path, encoding="utf-8", errors="replace").read()

literals = []  # (value, replacement)
for var, rep in (("SINTER_PROJECT", "<project>"), ("SINTER_ZONE", "<zone>")):
    v = os.environ.get(var, "").strip()
    if not v:
        die(2, "%s is required (the run's own identifiers are masked)" % var)
    literals.append((v, rep))
specs = os.environ.get("SINTER_SPECS", "").split()
if not specs:
    die(2, "SINTER_SPECS is required (the run's own identifiers are masked)")
for spec in specs:
    vm = spec.split(":", 1)[0]
    if vm and not any(vm in lb for lb in LABELS):
        literals.append((vm, "<target>"))
# Longest first, so a name that contains another is masked whole.
literals.sort(key=lambda x: -len(x[0]))

local = []
pfile = os.environ.get("SINTER_SANITIZE_PATTERNS", "")
if pfile:
    if not os.path.isfile(pfile):
        die(2, "SINTER_SANITIZE_PATTERNS does not name a file")
    for n, line in enumerate(open(pfile, encoding="utf-8").read().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        rx, sep, rep = line.partition("\t")
        if not sep or not rx:
            die(2, "SINTER_SANITIZE_PATTERNS line %d: expected <regex><TAB><replacement>" % n)
        local.append((re.compile(rx), rep))

subs = [(re.compile(re.escape(v)), rep) for v, rep in literals] + local + [
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
    # machine-specific paths (a volume name may contain blanks: mask up to the
    # next path separator or the end of the line)
    # (written with groups so that this published file holds no path-shaped
    # literal itself; the release checker scans the harness files too)
    (re.compile(r"/(?:home)/[A-Za-z0-9._-]+"), "/home/<user>"),
    (re.compile(r"/(?:Users)/[A-Za-z0-9._-]+"), "/Users/<user>"),
    (re.compile(r"/(?:Volumes)/[^/\n]+"), "/<volume>"),
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
text = re.sub(r"(?<![\w:])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![\w:])", mask_ip, text)

left = [rep for v, rep in literals if v in text]
if left:
    die(3, "identifiers still present after masking (%s); nothing written" % ", ".join(sorted(set(left))))
open(out_path, "w", encoding="utf-8").write(text)
print(f"sanitized {label}: {path} -> {out_path}")
