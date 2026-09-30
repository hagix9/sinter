#!/usr/bin/env python3
"""Validate a Sinter acceptance Evidence Manifest (sinter-acceptance-manifest/1).

Usage:
  check_acceptance_manifest.py MANIFEST.json
      (--bundle-archive BUNDLE.tar.gz | --bundle DIR)
      --artifact sinter-vX.Y.Z-linux-x86_64.tar.gz
      [--sums sinter-vX.Y.Z-acceptance-SHA256SUMS] [--repo DIR]
  check_acceptance_manifest.py --template release/acceptance-manifest.template.json

A real manifest passes only when all of the following hold (see
release/ACCEPTANCE_EVIDENCE.md):
  - the schema and every consistency rule, including the Linux validation
    gate, the required target set, and a GO verdict;
  - the gate log shows the full root test suite: every test harness that
    `cargo test --all-targets` runs at the candidate commit, with pass counts
    that add up to the recorded root-test counts, and linux_only_suites names
    exactly the Linux-only suites at that commit. Both lists are derived from
    the repository (--repo, default: this checkout) with git and cargo, never
    from the manifest;
  - the evidence bundle is safe and complete: only regular files, every path
    stays inside the bundle, no links or special files, the bundle holds
    exactly the manifest copy plus every referenced file, and every
    referenced file matches its SHA-256;
  - the artifact matches the recorded name, size, and hashes;
  - optionally, the acceptance SHA256SUMS covers the manifest and the bundle;
  - the manifest and every bundle file pass the sensitive-data scan.

The bundle archive is inspected in memory; nothing from it is extracted to
disk. Only the candidate commit's own tree is exported, to a temporary
directory, so that cargo can list its targets.
--template checks only the structure of the placeholder template.

Standard library only (plus the git and cargo executables).
Exit 0 = valid, 1 = invalid, 2 = usage error.
"""
import argparse
import datetime
import hashlib
import io
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zlib

SCHEMA = "sinter-acceptance-manifest/1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
RFC3339Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
LABEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
# Bundle paths: relative POSIX, conservative characters, no empty, "." or
# ".." components (checked separately).
PATH_CHARS = re.compile(r"^[A-Za-z0-9._/-]+$")

MANIFEST_IN_BUNDLE = "acceptance-manifest.json"
LINUX_GATE_LOG = "validation/linux-gate.log"
MAX_FILE_BYTES = 64 << 20
MAX_TOTAL_BYTES = 256 << 20
MAX_MEMBERS = 10000

# The supported platform set (README "Supported platforms"). Every release
# is accepted on exactly these targets; adding a platform is a reviewed
# change to this table.
REQUIRED_TARGETS = {
    "ubuntu2404": ("Ubuntu", "24.04"),
    "ubuntu2604": ("Ubuntu", "26.04"),
    "rocky9": ("Rocky Linux", "9"),
    "rocky10": ("Rocky Linux", "10"),
    "rhel9": ("Red Hat Enterprise Linux", "9"),
    "rhel10": ("Red Hat Enterprise Linux", "10"),
    "alma9": ("AlmaLinux", "9"),
    "alma10": ("AlmaLinux", "10"),
}

# The mandatory pre-acceptance Linux gate (RELEASE.md step 4). The exact
# command is pinned so a weaker substitute cannot be recorded as PASS.
LINUX_GATE_STEPS = {
    "root-fmt": ("cargo fmt --check", False),
    "root-clippy": ("cargo clippy --locked --all-targets --all-features -- -D warnings", False),
    # The throwaway local-sshd suites (tests/ssh_keys.rs, tests/multihost_lab.rs)
    # return early and still count as passed unless SINTER_TEST_LOCAL_SSHD=1, so
    # the variable is part of the pinned command. `env` keeps it one command
    # whether a shell or a harness running it as argv executes the line.
    "root-test": ("env SINTER_TEST_LOCAL_SSHD=1 cargo test --locked --all-targets --all-features", True),
    "installer-test": ("python3 tests/installer/test_install.py", True),
    "checker-test": ("python3 -m unittest discover -s release/tests", True),
    "gateway-fmt": ("cargo fmt --manifest-path gateway/Cargo.toml --check", False),
    "gateway-clippy": (
        "cargo clippy --manifest-path gateway/Cargo.toml --locked --all-targets --all-features -- -D warnings",
        False,
    ),
    "gateway-test": ("cargo test --manifest-path gateway/Cargo.toml --locked --all-targets --all-features", True),
}

# The root-test step must be evidenced for the whole suite. What that suite is
# comes from the repository at the candidate commit, not from the manifest:
# cargo's target list gives the test harnesses `cargo test --all-targets` runs,
# and a tests/*.rs file carrying this attribute is a Linux-only suite (the same
# rule as the grep in RELEASE.md step 4).
ROOT_TEST_STEP = "root-test"
# Releases up to v1.1.1 were accepted when root-test was pinned without the
# variable (their gate harness exported it instead). Their published evidence
# is checked against the command they were pinned to; every later version
# needs the current one.
LEGACY_ROOT_TEST = ((1, 1, 1), "cargo test --locked --all-targets --all-features")
LINUX_ONLY_ATTR = re.compile(r'(?m)^#!\[cfg\(target_os = "linux"\)\]')
LIB_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}
DEFAULT_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Invalid(Exception):
    """A clean, user-facing validation failure (never a traceback)."""


# ---------------------------------------------------------------------------
# Sensitive-data scan
# ---------------------------------------------------------------------------

# Reserved documentation names and public project/vendor domains. Anything
# else that looks like a hostname fails unless a reviewer adds the exact
# literal to sanitization.allowed_literals.
ALLOWED_DOMAINS = (
    "example.com", "example.org", "example.net", "example", "test", "invalid",
    "localhost", "localhost.localdomain",
    "github.com", "githubusercontent.com", "sinter.fulltrust.co.jp",
    "rust-lang.org", "crates.io",
    "rockylinux.org", "almalinux.org", "redhat.com", "fedoraproject.org",
    "ubuntu.com", "canonical.com", "debian.org",
)
PUBLIC_TLDS = (
    "com|net|org|io|dev|app|co|jp|cloud|ai|info|biz|us|uk|de|fr|cn|kr|ru|"
    "xyz|me|tech|site|online|gov|edu|eu|ca|au|nl|ch|se|no|fi|it|es|br|in|"
    "tw|hk|sg|nz"
)
INTERNAL_SUFFIXES = "internal|local|lan|intranet|corp|home|localdomain|priv|private|home\\.arpa"
ALLOWED_USERS = {"root", "nobody", "sinter", "ubuntu", "rocky", "almalinux", "cloud-user", "ec2-user"}
PUBLIC_IMAGE_PROJECTS = {
    "rocky-linux-cloud", "ubuntu-os-cloud", "rhel-cloud", "almalinux-cloud",
    "debian-cloud", "centos-cloud", "fedora-cloud", "cos-cloud",
}
REDACTION_MARKERS = {"[redacted]", "<redacted>", "redacted", "***", "****", "[filtered]"}
DOC_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
)]

# Categories whose findings a reviewer may clear with an exact literal in
# sanitization.allowed_literals (false positives such as a four-part
# package version). All other categories can never be allowlisted.
SUPPRESSIBLE = {
    "IPv4 address", "IPv6 address", "hostname", "username",
    "cloud resource ID", "environment-specific path",
}
# Credential-shaped findings may be cleared only for declared synthetic test
# fixtures (the harness must exercise redaction with a known value).
SYNTHETIC = re.compile(r"(?i)synthetic")

_V = r"[\"']?\s*[:=]\s*[\"']?"  # key/value separator, JSON or shell style
RULES = [
    # (category, regex, value group or 0, value filter)
    ("private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-|b3BlbnNzaC1rZXktdjE"), 0, None),
    ("access token", re.compile(
        r"\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
        r"\bAIza[0-9A-Za-z_-]{35}|\bxox[abprs]-[0-9A-Za-z-]{10,}|\bsk-[A-Za-z0-9_-]{20,}|"
        r"\bya29\.[0-9A-Za-z_-]{20,}|\bglpat-[0-9A-Za-z_-]{20,}|\"private_key_id\"\s*:|"
        r"\"type\"\s*:\s*\"service_account\""), 0, None),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"), 0, None),
    ("authorization header", re.compile(r"(?i)\b(?:proxy-)?authorization" + _V + r"([^\s\"',;]+)"), 1, "secret"),
    ("bearer/basic credential", re.compile(r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/-]{12,}=*)"), 1, "secret"),
    ("cookie", re.compile(r"(?i)\b(?:set-)?cookie" + _V + r"([^\s\"',;]+)"), 1, "secret"),
    ("credential", re.compile(
        r"(?i)\b[\w-]*(?:password|passphrase|secret|token|api[_-]?key|apikey|"
        r"access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|session[_-]?id)"
        + _V + r"([^\s\"',;]+)"), 1, "secret"),
    ("email address", re.compile(r"\b[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63})\b"), 1, "domain"),
    ("home directory path", re.compile(
        r"/(?:Users|home)/[A-Za-z0-9._-]+|\b[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+|/mnt/[a-z]/Users/"), 0, None),
    ("environment-specific path", re.compile(
        r"/Volumes/[^/\s]+|/private/(?:var|tmp)/|/var/folders/|\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+"), 0, None),
    ("internal DNS name", re.compile(
        r"(?<![A-Za-z0-9_.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:" + INTERNAL_SUFFIXES + r"))(?![A-Za-z0-9_-])", re.I), 1, "domain"),
    ("hostname", re.compile(
        r"(?<![A-Za-z0-9_.@-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:" + PUBLIC_TLDS + r"))(?![A-Za-z0-9_-]|\.[A-Za-z0-9])", re.I), 1, "domain"),
    ("hostname", re.compile(r"(?i)\b(?:host(?:name)?|fqdn|node(?:name)?|server)" + _V + r"([A-Za-z0-9][A-Za-z0-9.-]*)"), 1, "host"),
    ("hostname", re.compile(
        r"(?i)\b(?:host(?:name)?|server|node|ssh|(?:built|running|executed|connected)\s+(?:on|to|at))"
        r"\s+(?:[A-Za-z0-9_.-]+@)?([A-Za-z][A-Za-z0-9-]*)(?![\w.@])"), 1, "host-token"),
    ("hostname", re.compile(r"\bLinux ([A-Za-z0-9][A-Za-z0-9.-]*) \d+\.\d+\.\d+"), 1, "host"),
    ("username", re.compile(r"\b([a-z_][a-z0-9_-]*)@[A-Za-z0-9][A-Za-z0-9.-]*:[~/]"), 1, "user"),
    ("username", re.compile(r"(?i)\b(?:user(?:name)?|login|owner)" + _V + r"([A-Za-z_][A-Za-z0-9_.-]*)"), 1, "user"),
    ("username", re.compile(r"\b[ug]id=\d+\(([^)\s]+)\)"), 1, "user"),
    ("username", re.compile(r"--user[= ]([A-Za-z_][A-Za-z0-9_.-]*)"), 1, "user"),
    ("cloud resource ID", re.compile(
        r"(?i)\b(?:project(?:[_-]?(?:id|number))?|account(?:[_-]?id)?|instance(?:[_-]?id)?|"
        r"subscription(?:[_-]?id)?|tenant(?:[_-]?id)?|org(?:anization)?[_-]?id|billing[_-]?account)"
        + _V + r"([A-Za-z0-9][A-Za-z0-9_.:-]*)"), 1, None),
    ("cloud resource ID", re.compile(r"\bprojects/([a-z][a-z0-9-]{4,28}[a-z0-9])\b"), 1, "image-project"),
    ("cloud resource ID", re.compile(
        r"(?i)\bproject(?:[ _-]?id)?\s+([a-z][a-z0-9-]{4,28}[a-z0-9])(?![\w.])"), 1, "gcp-id"),
    ("cloud resource ID", re.compile(r"--project[= ]([A-Za-z0-9._:-]+)"), 1, None),
    ("cloud resource ID", re.compile(r"\barn:aws[\w-]*:[\w-]*:[\w-]*:\d{12}:"), 0, None),
    ("cloud resource ID", re.compile(r"\bi-(?:[0-9a-f]{17}|[0-9a-f]{8})\b"), 0, None),
    ("IPv4 address", re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w]|\.\d)"), 1, "ipv4"),
    ("IPv6 address", re.compile(r"(?<![\w:.])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![\w:])"), 1, "ipv6"),
]


def _domain_allowed(d):
    d = d.lower().rstrip(".")
    return any(d == a or d.endswith("." + a) for a in ALLOWED_DOMAINS)


def _ip_ignored(addr):
    return addr.is_loopback or addr.is_unspecified or any(addr in n for n in DOC_NETS)


def _is_finding(kind, value, labels):
    """Apply the value filter; True when the match is a real finding."""
    if kind is None:
        return True
    if kind == "secret":
        v = value.strip().lower()
        return not (
            v in REDACTION_MARKERS or v in ("", "true", "false", "null", "none")
            or v.startswith(("<", "$", "{{", "%"))
        )
    if kind == "domain":
        return not _domain_allowed(value)
    if kind == "host":
        v = value.lower().rstrip(".")
        return not (_domain_allowed(v) or v in labels)
    if kind == "user":
        return value not in ALLOWED_USERS
    if kind in ("host-token", "gcp-id"):
        # Whitespace-separated context: only identifier-shaped values
        # (with a digit or hyphen) count, so prose such as "host key" or
        # "project root" is not a finding.
        if not re.search(r"[0-9-]", value):
            return False
        if kind == "gcp-id":
            return value not in PUBLIC_IMAGE_PROJECTS
        v = value.lower()
        return not (_domain_allowed(v) or v in labels)
    if kind == "image-project":
        return value not in PUBLIC_IMAGE_PROJECTS
    if kind == "ipv4":
        try:
            return not _ip_ignored(ipaddress.IPv4Address(value))
        except ValueError:
            return False
    if kind == "ipv6":
        if value.count(":") < 2 or not any(c.isdigit() for c in value):
            return False
        try:
            return not _ip_ignored(ipaddress.IPv6Address(value))
        except ValueError:
            return False
    raise AssertionError(kind)


def scan(text, where, allowed, labels, errors):
    """Report sensitive content by category and line; never echo the value."""
    seen = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        for cat, rx, group, kind in RULES:
            for m in rx.finditer(line):
                value = m.group(group)
                if not _is_finding(kind, value, labels):
                    continue
                if value in allowed and (
                    cat in SUPPRESSIBLE or (kind == "secret" and SYNTHETIC.search(value))
                ):
                    continue
                key = (lineno, cat)
                if key not in seen:
                    seen.add(key)
                    errors.append(f"{where}:{lineno}: sensitive content ({cat})")


# ---------------------------------------------------------------------------
# Manifest structure and consistency
# ---------------------------------------------------------------------------

def req(obj, key, typ, where, errors):
    if not isinstance(obj, dict) or key not in obj:
        errors.append(f"{where}.{key}: missing")
        return None
    v = obj[key]
    if typ is int:
        ok = isinstance(v, int) and not isinstance(v, bool) and v >= 0
    else:
        ok = isinstance(v, typ)
    if not ok:
        errors.append(f"{where}.{key}: expected {typ.__name__}")
        return None
    return v


def match(v, rx, where, errors, template):
    if template or v is None:
        return
    if not rx.match(v):
        errors.append(f"{where}: invalid format")


def parse_time(v):
    if not isinstance(v, str) or not RFC3339Z.match(v):
        return None
    try:
        return datetime.datetime.strptime(v[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def ordered(a, b, what, errors):
    ta, tb = parse_time(a), parse_time(b)
    if ta and tb and ta > tb:
        errors.append(what)


def ref_path_error(p):
    """Why a manifest-referenced path is unsafe, or None."""
    if not p:
        return "empty path"
    if "\\" in p or "\x00" in p:
        return "backslash or NUL in path"
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        return "absolute path"
    parts = p.split("/")
    if any(c in ("", ".", "..") for c in parts):
        return "path is not normalized or leaves the bundle"
    if not PATH_CHARS.match(p):
        return "unsupported characters in path"
    return None


def check_ref(p, sha, where, errors, refs, prefix=None, exact=None):
    """Validate one bundle reference and record it with its expected SHA-256
    (duplicate or case-conflicting references are rejected)."""
    if p is None:
        return
    why = ref_path_error(p)
    if why:
        errors.append(f"{where}: {why}")
        return
    if exact is not None and p != exact:
        errors.append(f"{where}: must be {exact}")
        return
    if prefix is not None and not p.startswith(prefix):
        errors.append(f"{where}: must be under {prefix}")
        return
    if p == MANIFEST_IN_BUNDLE:
        errors.append(f"{where}: conflicts with the bundle manifest copy")
        return
    low = p.lower()
    if low in refs:
        errors.append(f"{where}: duplicate or conflicting path (also {refs[low][0]})")
        return
    refs[low] = (where, p, sha)


def check(doc, template, errors, refs):
    """Schema + consistency. Returns facts used by the bundle checks."""
    facts = {}
    if req(doc, "schema", str, "$", errors) != SCHEMA:
        errors.append("$.schema: must be " + SCHEMA)
    c = req(doc, "candidate", dict, "$", errors) or {}
    version = req(c, "version", str, "candidate", errors)
    match(version, SEMVER, "candidate.version", errors, template)
    if template or (version and not SEMVER.match(version)):
        version = None
    facts["version"] = version
    tag = req(c, "tag", str, "candidate", errors)
    if version and tag != f"v{version}":
        errors.append("candidate.tag: must be v<version>")
    commit = req(c, "source_commit", str, "candidate", errors)
    match(commit, HEX40, "candidate.source_commit", errors, template)
    art = req(c, "artifact", dict, "candidate", errors) or {}
    fname = req(art, "filename", str, "candidate.artifact", errors)
    art_sha = req(art, "sha256", str, "candidate.artifact", errors)
    match(art_sha, HEX64, "candidate.artifact.sha256", errors, template)
    size = req(art, "size_bytes", int, "candidate.artifact", errors)
    if version and fname != f"sinter-v{version}-linux-x86_64.tar.gz":
        errors.append("candidate.artifact.filename: does not match the release naming contract")
    if not template and size == 0:
        errors.append("candidate.artifact.size_bytes: must be positive")
    exe_sha = req(c, "executable_sha256", str, "candidate", errors)
    match(exe_sha, HEX64, "candidate.executable_sha256", errors, template)
    facts.update(artifact=(fname, art_sha, size), exe_sha=exe_sha)
    b = req(c, "build", dict, "candidate", errors) or {}
    for k in ("baseline", "rustc", "cargo", "max_glibc"):
        req(b, k, str, "candidate.build", errors)

    h = req(doc, "harness", dict, "$", errors) or {}
    for k in ("name", "version", "runner", "operator"):
        req(h, k, str, "harness", errors)
    files = req(h, "files", list, "harness", errors) or []
    if not files:
        errors.append("harness.files: must list the harness files")
    for i, f in enumerate(files):
        w = f"harness.files[{i}]"
        p = req(f, "path", str, w, errors)
        s = req(f, "sha256", str, w, errors)
        match(s, HEX64, f"{w}.sha256", errors, template)
        if not template:
            check_ref(p, s, w, errors, refs, prefix="harness/")

    r = req(doc, "run", dict, "$", errors) or {}
    run_start = req(r, "started_at", str, "run", errors)
    run_end = req(r, "finished_at", str, "run", errors)
    match(run_start, RFC3339Z, "run.started_at", errors, template)
    match(run_end, RFC3339Z, "run.finished_at", errors, template)
    if not template:
        ordered(run_start, run_end, "run: started_at is after finished_at", errors)

    lv = req(doc, "linux_validation", dict, "$", errors) or {}
    check_linux_gate(lv, commit, run_start, template, errors, refs, facts)

    targets = req(doc, "targets", list, "$", errors) or []
    if not targets:
        errors.append("targets: must not be empty")
    sums = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
    labels = set()
    all_pass = bool(targets)
    for i, t in enumerate(targets):
        w = f"targets[{i}]"
        label = req(t, "label", str, w, errors)
        match(label, LABEL, f"{w}.label", errors, template)
        if label in labels:
            errors.append(f"{w}.label: duplicate {label}")
        labels.add(label)
        os_name = req(t, "os_name", str, w, errors)
        os_version = req(t, "os_version", str, w, errors)
        arch = req(t, "arch", str, w, errors)
        for k in ("image", "version_output"):
            req(t, k, str, w, errors)
        t_start = req(t, "started_at", str, w, errors)
        t_end = req(t, "finished_at", str, w, errors)
        match(t_start, RFC3339Z, f"{w}.started_at", errors, template)
        match(t_end, RFC3339Z, f"{w}.finished_at", errors, template)
        a = req(t, "artifact_sha256", str, w, errors)
        e = req(t, "executable_sha256", str, w, errors)
        match(a, HEX64, f"{w}.artifact_sha256", errors, template)
        match(e, HEX64, f"{w}.executable_sha256", errors, template)
        if not template:
            if label in REQUIRED_TARGETS:
                want_name, want_ver = REQUIRED_TARGETS[label]
                if os_name != want_name or not (
                    os_version == want_ver or (os_version or "").startswith(want_ver + ".")
                ):
                    errors.append(f"{w}: os_name/os_version do not match target {label}")
            elif label is not None:
                errors.append(f"{w}.label: {label} is not a supported target")
            if arch != "x86_64":
                errors.append(f"{w}.arch: must be x86_64")
            ordered(t_start, t_end, f"{w}: started_at is after finished_at", errors)
            ordered(run_start, t_start, f"{w}: started before the run", errors)
            ordered(t_end, run_end, f"{w}: finished after the run", errors)
            if a != art_sha:
                errors.append(f"{w}: artifact_sha256 differs from the candidate artifact")
            if e != exe_sha:
                errors.append(f"{w}: executable_sha256 differs from the candidate executable")
            if version and t.get("version_output") != f"sinter {version}":
                errors.append(f"{w}.version_output: must be 'sinter {version}'")
        ch = req(t, "checks", dict, w, errors) or {}
        vals = {k: req(ch, k, int, f"{w}.checks", errors) for k in sums}
        if None not in vals.values():
            if not template and vals["passed"] + vals["failed"] + vals["skipped"] != vals["total"]:
                errors.append(f"{w}.checks: passed + failed + skipped != total")
            for k in sums:
                sums[k] += vals[k]
        verdict = req(t, "verdict", str, w, errors)
        if not template:
            expect = "PASS" if vals.get("failed") == 0 and (vals.get("total") or 0) > 0 else "FAIL"
            if verdict != expect:
                errors.append(f"{w}.verdict: must be {expect}")
            if verdict != "PASS":
                all_pass = False
        lg = req(t, "log", dict, w, errors) or {}
        lp = req(lg, "path", str, f"{w}.log", errors)
        ls = req(lg, "sha256", str, f"{w}.log", errors)
        match(ls, HEX64, f"{w}.log.sha256", errors, template)
        if not template and label and LABEL.match(label):
            check_ref(lp, ls, f"{w}.log", errors, refs, exact=f"logs/{label}.log")
    if not template:
        for label in sorted(set(REQUIRED_TARGETS) - labels):
            errors.append(f"targets: required target {label} is missing")
    facts["labels"] = labels

    tot = req(doc, "totals", dict, "$", errors) or {}
    tvals = {k: req(tot, k, int, "totals", errors) for k in ("targets", *sums)}
    verdict = req(doc, "verdict", str, "$", errors)
    if not template:
        if tvals.get("targets") != len(targets):
            errors.append("totals.targets: does not match the number of targets")
        for k in sums:
            if tvals.get(k) != sums[k]:
                errors.append(f"totals.{k}: does not equal the sum over targets")
        expect = "GO" if all_pass and sums["failed"] == 0 else "NO-GO"
        if verdict != expect:
            errors.append(f"$.verdict: must be {expect}")
        elif verdict != "GO":
            errors.append("$.verdict: NO-GO evidence cannot support a release")
    bundle_name = req(doc, "evidence_bundle", str, "$", errors)
    if version and bundle_name != f"sinter-v{version}-acceptance-evidence.tar.gz":
        errors.append("evidence_bundle: does not match the naming contract")
    facts["bundle_name"] = bundle_name

    san = doc.get("sanitization", {"allowed_literals": []})
    allowed = req(san, "allowed_literals", list, "sanitization", errors) if isinstance(san, dict) else None
    if not isinstance(san, dict):
        errors.append("sanitization: expected dict")
    facts["allowed"] = set()
    for i, lit in enumerate(allowed or []):
        if not isinstance(lit, str) or not re.match(r"^[A-Za-z0-9._:-]{3,253}$", lit):
            errors.append(f"sanitization.allowed_literals[{i}]: must be a plain literal of 3-253 characters")
        else:
            facts["allowed"].add(lit)
    return facts


def pinned_command(name, version):
    """The pinned command of gate step `name` for candidate `version`."""
    max_version, legacy = LEGACY_ROOT_TEST
    if name == ROOT_TEST_STEP and version and tuple(map(int, version.split("."))) <= max_version:
        return legacy
    return LINUX_GATE_STEPS[name][0]


def check_linux_gate(lv, commit, run_start, template, errors, refs, facts):
    w = "linux_validation"
    for k in ("os_name", "os_version", "rustc", "cargo"):
        req(lv, k, str, w, errors)
    arch = req(lv, "arch", str, w, errors)
    src = req(lv, "source_commit", str, w, errors)
    match(src, HEX40, f"{w}.source_commit", errors, template)
    start = req(lv, "started_at", str, w, errors)
    end = req(lv, "finished_at", str, w, errors)
    match(start, RFC3339Z, f"{w}.started_at", errors, template)
    match(end, RFC3339Z, f"{w}.finished_at", errors, template)
    suites = req(lv, "linux_only_suites", list, w, errors) or []
    steps = req(lv, "steps", list, w, errors) or []
    verdict = req(lv, "verdict", str, w, errors)
    lg = req(lv, "log", dict, w, errors) or {}
    lp = req(lg, "path", str, f"{w}.log", errors)
    ls = req(lg, "sha256", str, f"{w}.log", errors)
    match(ls, HEX64, f"{w}.log.sha256", errors, template)
    seen = {}
    for i, s in enumerate(steps):
        sw = f"{w}.steps[{i}]"
        name = req(s, "name", str, sw, errors)
        cmd = req(s, "command", str, sw, errors)
        result = req(s, "result", str, sw, errors)
        counts = {k: req(s, k, int, sw, errors) for k in ("passed", "failed", "ignored")}
        if template or name is None:
            continue
        if name in seen:
            errors.append(f"{sw}.name: duplicate step {name}")
            continue
        seen[name] = True
        if name not in LINUX_GATE_STEPS:
            errors.append(f"{sw}.name: unknown step {name}")
            continue
        want_cmd, is_test = pinned_command(name, facts.get("version")), LINUX_GATE_STEPS[name][1]
        if cmd != want_cmd:
            errors.append(f"{sw}.command: must be '{want_cmd}'")
        if result != "PASS":
            errors.append(f"{sw}.result: {name} must PASS before acceptance")
        if counts["failed"] not in (None, 0):
            errors.append(f"{sw}.failed: must be 0")
        if is_test and counts["passed"] == 0:
            errors.append(f"{sw}.passed: a test step must run tests")
        if name == ROOT_TEST_STEP:
            facts["root_test_counts"] = counts
    if template:
        return
    for name in LINUX_GATE_STEPS:
        if name not in seen:
            errors.append(f"{w}.steps: required step {name} is missing")
    if arch != "x86_64":
        errors.append(f"{w}.arch: must be x86_64 (macOS or other hosts are not a substitute)")
    if src != commit:
        errors.append(f"{w}.source_commit: must equal candidate.source_commit")
    if verdict != "PASS":
        errors.append(f"{w}.verdict: must be PASS (a failed Linux gate blocks acceptance)")
    ordered(start, end, f"{w}: started_at is after finished_at", errors)
    ordered(end, run_start, f"{w}: must finish before acceptance starts", errors)
    if not suites:
        errors.append(f"{w}.linux_only_suites: must list the Linux-only test suites")
    for i, s in enumerate(suites):
        if not isinstance(s, str) or not re.match(r"^tests/[a-z0-9_]+\.rs$", s):
            errors.append(f"{w}.linux_only_suites[{i}]: must be tests/<name>.rs")
    facts["linux_suites"] = [s for s in suites if isinstance(s, str)]
    facts["commit"] = commit
    check_ref(lp, ls, f"{w}.log", errors, refs, exact=LINUX_GATE_LOG)


def root_test_inventory(repo, commit):
    """Test harnesses and Linux-only suites of the root crate at `commit`.

    Returns (labels, linux_suites): labels as cargo prints them after
    "Running" ("unittests src/lib.rs", "tests/engine.rs"). Raises Invalid
    when the inventory cannot be established, so acceptance fails closed.
    """
    where = "linux_validation: root test inventory"
    try:
        tar = subprocess.run(
            ["git", "-C", repo, "archive", "--format=tar", commit],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        raise Invalid(f"{where}: cannot read commit {commit} from {repo} "
                      "(run the checker from a clone that contains the candidate commit)")
    with tempfile.TemporaryDirectory(prefix="sinter-root-inventory-") as tmp:
        with tarfile.open(fileobj=io.BytesIO(tar)) as tf:
            for m in tf.getmembers():
                norm = os.path.normpath(m.name)
                if (m.isdir() or m.isreg()) and not os.path.isabs(norm) and not norm.startswith(".."):
                    tf.extract(m, tmp)
        try:
            meta = json.loads(subprocess.run(
                ["cargo", "metadata", "--no-deps", "--offline", "--format-version", "1",
                 "--manifest-path", os.path.join(tmp, "Cargo.toml")],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            ).stdout)
        except (OSError, subprocess.CalledProcessError, ValueError):
            raise Invalid(f"{where}: cargo metadata failed at commit {commit}")
        root = os.path.realpath(tmp)
        pkgs = [p for p in meta.get("packages", [])
                if os.path.realpath(os.path.dirname(p.get("manifest_path", ""))) == root]
        if len(pkgs) != 1:
            raise Invalid(f"{where}: expected exactly one root package at commit {commit}")
        labels, linux = set(), set()
        for t in pkgs[0].get("targets", []):
            kinds = set(t.get("kind", []))
            if kinds == {"custom-build"}:
                continue
            rel = os.path.relpath(os.path.realpath(t["src_path"]), root).replace(os.sep, "/")
            if not t.get("test", True):
                raise Invalid(f"{where}: target {rel} sets test = false, which this checker does not handle")
            if kinds <= LIB_KINDS or kinds == {"bin"}:
                labels.add("unittests " + rel)
            elif kinds == {"test"}:
                labels.add(rel)
                with open(t["src_path"], encoding="utf-8", errors="replace") as f:
                    if LINUX_ONLY_ATTR.search(f.read()):
                        linux.add(rel)
            else:
                raise Invalid(f"{where}: target {rel} of kind {sorted(kinds)} is not handled by this checker")
        if not labels:
            raise Invalid(f"{where}: no test harness found at commit {commit}")
        return labels, linux


def check_linux_suite_inventory(facts, errors):
    """linux_only_suites must name exactly the Linux-only suites at the commit."""
    inv = facts.get("root_inventory")
    if inv is None:
        return
    w = "linux_validation.linux_only_suites"
    declared = set()
    for s in facts.get("linux_suites", []):
        if s in declared:
            errors.append(f"{w}: {s} is listed twice")
        declared.add(s)
    for s in sorted(inv[1] - declared):
        errors.append(f"{w}: missing {s}, a Linux-only suite at the candidate commit")
    for s in sorted(declared - inv[1]):
        errors.append(f"{w}: {s} is not a Linux-only suite at the candidate commit")


def check_root_test_log(text, facts, errors):
    """The root-test section of the gate log must show the full root suite."""
    inv = facts.get("root_inventory")
    if inv is None:
        return
    labels, linux = inv
    w = f"{LINUX_GATE_LOG}: root-test"
    starts = re.findall(r"(?m)^== step root-test start ", text)
    ends = re.findall(r"(?m)^== step root-test rc=", text)
    m = re.search(r"(?ms)^== step root-test start [^\n]*\n(.*?)^== step root-test rc=(\d+) end\b", text)
    if len(starts) != 1 or len(ends) != 1 or m is None:
        errors.append(f"{w}: the log must contain exactly one section from "
                      "'== step root-test start' to '== step root-test rc=N end'")
        return
    body, rc = m.group(1), m.group(2)
    first = next((ln for ln in body.splitlines() if ln.strip()), "")
    want = "$ " + pinned_command(ROOT_TEST_STEP, facts.get("version"))
    if first != want:
        errors.append(f"{w}: the section must start with '{want}'")
    if rc != "0":
        errors.append(f"{w}: the step exited with rc={rc}")
    heads = list(re.finditer(r"(?m)^\s+Running (\S+(?: \S+)?) \([^)\n]*\)[ \t]*$", body))
    ran, passed, ignored = {}, 0, 0
    for i, h in enumerate(heads):
        label = h.group(1)
        chunk = body[h.end():heads[i + 1].start() if i + 1 < len(heads) else len(body)]
        res = re.findall(r"(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", chunk)
        if label in ran:
            errors.append(f"{w}: {label} appears more than once")
            continue
        if len(res) != 1:
            errors.append(f"{w}: {label} must have exactly one test result line")
            continue
        status, p, f, ig = res[0][0], int(res[0][1]), int(res[0][2]), int(res[0][3])
        ran[label] = p
        if status != "ok" or f:
            errors.append(f"{w}: {label} did not pass")
        passed += p
        ignored += ig
    for label in sorted(labels - ran.keys()):
        errors.append(f"{w}: {label} did not run (the full root suite is required)")
    for label in sorted(ran.keys() - labels):
        errors.append(f"{w}: {label} is not a test harness of the candidate commit")
    for s in sorted(linux & ran.keys()):
        if ran[s] == 0:
            errors.append(f"{w}: Linux-only suite {s} ran no tests")
    counts = facts.get("root_test_counts") or {}
    if counts.get("passed") != passed:
        errors.append(f"{w}: recorded passed={counts.get('passed')} but the log shows {passed}")
    if counts.get("ignored") != ignored:
        errors.append(f"{w}: recorded ignored={counts.get('ignored')} but the log shows {ignored}")


# ---------------------------------------------------------------------------
# Bundle loading (directory or archive) — metadata first, nothing extracted
# ---------------------------------------------------------------------------

def load_bundle_dir(root):
    """Return {relpath: bytes} for a bundle directory, rejecting anything but
    plain regular files and directories that stay inside the root."""
    files, errors, total = {}, [], 0
    if os.path.islink(root):
        raise Invalid("--bundle: the bundle directory itself is a symlink")
    if not os.path.isdir(root):
        raise Invalid("--bundle: not a directory")
    real_root = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                errors.append(f"bundle:{rel}: symlink not allowed")
                continue
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                errors.append(f"bundle:{rel}: not a regular file (device, FIFO, or socket)")
                continue
            if st.st_nlink > 1:
                errors.append(f"bundle:{rel}: hardlink not allowed")
                continue
            real = os.path.realpath(full)
            if os.path.commonpath([real_root, real]) != real_root:
                errors.append(f"bundle:{rel}: resolves outside the bundle")
                continue
            why = ref_path_error(rel)
            if why:
                errors.append(f"bundle:{rel}: {why}")
                continue
            if st.st_size > MAX_FILE_BYTES:
                errors.append(f"bundle:{rel}: file too large")
                continue
            total += st.st_size
            if total > MAX_TOTAL_BYTES:
                raise Invalid("bundle: total size exceeds the limit")
            with open(full, "rb") as f:
                files[rel] = f.read()
        # Do not descend into symlinked directories (already rejected above).
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
    return files, errors


def load_bundle_archive(path, stem):
    """Validate every tar member's metadata, then read regular files into
    memory. Nothing is ever written to disk."""
    files, dirs, errors, total, seen = {}, set(), [], 0, {}
    try:
        tf = tarfile.open(path, mode="r:gz")
    except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
        raise Invalid(f"--bundle-archive: not a readable .tar.gz ({type(e).__name__})")
    with tf:
        try:
            members = tf.getmembers()
        except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
            raise Invalid(f"--bundle-archive: corrupt archive ({type(e).__name__})")
        if len(members) > MAX_MEMBERS:
            raise Invalid("--bundle-archive: too many members")
        ok = []
        for m in members:
            name = m.name
            shown = name if PATH_CHARS.match(name or "-") else "<unprintable member name>"
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or "\\" in name:
                errors.append(f"archive:{shown}: absolute member path")
                continue
            parts = name.split("/")
            if ".." in parts:
                errors.append(f"archive:{shown}: path traversal member")
                continue
            if m.issym() or m.islnk():
                errors.append(f"archive:{shown}: symlink/hardlink member not allowed")
                continue
            if not (m.isreg() or m.isdir()):
                errors.append(f"archive:{shown}: special file member not allowed (device, FIFO, or other)")
                continue
            if m.mode & (stat.S_ISUID | stat.S_ISGID):
                errors.append(f"archive:{shown}: setuid/setgid member not allowed")
                continue
            if parts[0] != stem:
                errors.append(f"archive:{shown}: outside the top-level directory {stem}/")
                continue
            rel = "/".join(parts[1:])
            if m.isdir():
                if rel:
                    why = ref_path_error(rel)
                    if why:
                        errors.append(f"archive:{shown}: {why}")
                    dirs.add(rel)
                continue
            why = ref_path_error(rel)
            if why:
                errors.append(f"archive:{shown}: {why}")
                continue
            low = rel.lower()
            if low in seen:
                errors.append(f"archive:{shown}: duplicate or conflicting member")
                continue
            seen[low] = rel
            if m.size > MAX_FILE_BYTES:
                errors.append(f"archive:{shown}: member too large")
                continue
            total += m.size
            if total > MAX_TOTAL_BYTES:
                raise Invalid("--bundle-archive: total size exceeds the limit")
            ok.append((rel, m))
        for rel in list(seen.values()):
            prefix = rel.split("/")
            for i in range(1, len(prefix)):
                if "/".join(prefix[:i]).lower() in seen:
                    errors.append(f"archive:{rel}: a parent path is also a file")
        if errors:
            return files, errors
        for rel, m in ok:
            try:
                fh = tf.extractfile(m)
                data = fh.read() if fh else None
            except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
                raise Invalid(f"--bundle-archive: corrupt member ({type(e).__name__})")
            if data is None or len(data) != m.size:
                errors.append(f"archive:{rel}: unreadable member")
                continue
            files[rel] = data
    for d in dirs:
        if d.lower() in seen:
            errors.append(f"archive:{d}: both a directory and a file")
    return files, errors


def check_bundle(files, manifest_raw, refs, facts, errors):
    if not files:
        errors.append("bundle: empty — it must contain the manifest copy and every referenced file")
        return
    lower = {}
    for p in files:
        if p.lower() in lower:
            errors.append(f"bundle:{p}: conflicts with {lower[p.lower()]} (case)")
        lower[p.lower()] = p
    if files.get(MANIFEST_IN_BUNDLE) is None:
        errors.append(f"bundle: {MANIFEST_IN_BUNDLE} is missing")
    elif files[MANIFEST_IN_BUNDLE] != manifest_raw:
        errors.append(f"bundle: {MANIFEST_IN_BUNDLE} is not byte-identical to the manifest (wrong bundle?)")
    dirs = set()
    for p in files:
        parts = p.split("/")
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))
    for where, p, want in refs.values():
        if p in dirs:
            errors.append(f"{where}: {p} is a directory, not a file")
        elif p not in files:
            errors.append(f"{where}: {p} missing from bundle")
        elif want is not None and hashlib.sha256(files[p]).hexdigest() != want:
            errors.append(f"{where}: {p} sha256 mismatch")
    expected = {MANIFEST_IN_BUNDLE} | {r[1] for r in refs.values()}
    for p in sorted(files):
        if p not in expected:
            errors.append(f"bundle:{p}: not referenced by the manifest (unlisted or hidden file)")
    gate = files.get(LINUX_GATE_LOG)
    if gate is not None:
        text = gate.decode("utf-8", "replace")
        if "test result: FAILED" in text:
            errors.append(f"{LINUX_GATE_LOG}: records a failed test run")
        # Each Linux-only suite must have actually executed tests on the gate
        # host. On a non-Linux host cargo still prints "Running tests/x.rs"
        # but the cfg-gated suite reports "0 passed", which is rejected.
        blocks = re.split(r"(?m)^\s*Running ", text)
        for s in facts.get("linux_suites", []):
            ran = False
            for b in blocks[1:]:
                if b.startswith(s + " ") or b.startswith(s + "\n"):
                    m = re.search(r"test result: ok\. (\d+) passed; 0 failed", b)
                    ran = bool(m and int(m.group(1)) > 0)
                    break
            if not ran:
                errors.append(f"{LINUX_GATE_LOG}: Linux-only suite {s} did not run tests on the gate host")
        check_root_test_log(text, facts, errors)


def check_artifact(path, facts, errors):
    fname, sha, size = facts["artifact"]
    version = facts["version"]
    if os.path.basename(path) != fname:
        errors.append("--artifact: file name differs from candidate.artifact.filename")
    st = os.stat(path)
    if st.st_size != size:
        errors.append("--artifact: size differs from candidate.artifact.size_bytes")
    if sha256_file(path) != sha:
        errors.append("--artifact: sha256 differs from candidate.artifact.sha256 (manifest and artifact do not match)")
        return
    exe = f"sinter-v{version}-linux-x86_64/sinter"
    try:
        with tarfile.open(path, mode="r:gz") as tf:
            hits = [m for m in tf.getmembers() if m.name == exe]
            if len(hits) != 1 or not hits[0].isreg():
                errors.append(f"--artifact: must contain exactly one regular file {exe}")
                return
            data = tf.extractfile(hits[0]).read()
    except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
        raise Invalid(f"--artifact: not a readable .tar.gz ({type(e).__name__})")
    if hashlib.sha256(data).hexdigest() != facts["exe_sha"]:
        errors.append("--artifact: executable sha256 differs from candidate.executable_sha256")


def check_sums(path, manifest_raw, archive, facts, errors):
    version = facts["version"]
    want = {
        f"sinter-v{version}-acceptance-manifest.json": hashlib.sha256(manifest_raw).hexdigest(),
        facts["bundle_name"]: sha256_file(archive),
    }
    got = {}
    with open(path, "rb") as f:
        raw = f.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Invalid("--sums: not UTF-8 text")
    for n, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)$", line)
        if not m:
            errors.append(f"--sums:{n}: malformed line")
            continue
        if m.group(2) in got:
            errors.append(f"--sums:{n}: duplicate entry")
        got[m.group(2)] = m.group(1)
    if set(got) != set(want):
        errors.append("--sums: must list exactly the manifest and evidence bundle assets")
    for name, h in want.items():
        if name in got and got[name] != h:
            errors.append(f"--sums: {name} checksum mismatch")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def decode_text(data, where, errors):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"{where}: not UTF-8 text")
        return None


def run(args):
    errors = []
    with open(args.manifest, "rb") as f:
        raw = f.read()
    text = decode_text(raw, os.path.basename(args.manifest), errors)
    if text is None:
        return errors
    try:
        doc = json.loads(text)
    except ValueError as e:
        return [f"{os.path.basename(args.manifest)}: not valid JSON ({e})"]
    if not isinstance(doc, dict):
        return ["$: top level must be an object"]
    refs = {}
    facts = check(doc, args.template, errors, refs)
    if args.template:
        return errors
    labels = facts.get("labels", set())
    allowed = facts.get("allowed", set())
    scan(text, os.path.basename(args.manifest), allowed, labels, errors)
    version = facts.get("version")
    if not version:
        return errors + ["candidate.version: required before the bundle can be checked"]
    if facts.get("commit") and HEX40.match(facts["commit"]):
        try:
            facts["root_inventory"] = root_test_inventory(args.repo, facts["commit"])
        except Invalid as e:
            errors.append(str(e))
        check_linux_suite_inventory(facts, errors)

    if args.bundle_archive:
        stem = (facts.get("bundle_name") or "")[: -len(".tar.gz")]
        if os.path.basename(args.bundle_archive) != facts.get("bundle_name"):
            errors.append("--bundle-archive: file name differs from evidence_bundle (wrong bundle?)")
        files, berrs = load_bundle_archive(args.bundle_archive, stem)
    else:
        files, berrs = load_bundle_dir(args.bundle)
    errors.extend(berrs)
    check_bundle(files, raw, refs, facts, errors)
    scan("\n".join(sorted(files)), "bundle paths", allowed, labels, errors)
    for p in sorted(files):
        t = decode_text(files[p], p, errors)
        if t is not None:
            scan(t, p, allowed, labels, errors)

    check_artifact(args.artifact, facts, errors)
    if args.sums:
        if not args.bundle_archive:
            errors.append("--sums: requires --bundle-archive")
        else:
            check_sums(args.sums, raw, args.bundle_archive, facts, errors)
    return errors


def main(argv):
    ap = argparse.ArgumentParser(
        description="Validate a Sinter acceptance Evidence Manifest and its bundle.",
    )
    ap.add_argument("manifest")
    ap.add_argument("--template", action="store_true", help="check only the template structure")
    ap.add_argument("--bundle", metavar="DIR", help="extracted evidence bundle directory")
    ap.add_argument("--bundle-archive", metavar="TAR_GZ", help="evidence bundle archive (inspected in memory)")
    ap.add_argument("--artifact", metavar="TAR_GZ", help="the release artifact the manifest describes")
    ap.add_argument("--sums", metavar="FILE", help="the acceptance SHA256SUMS asset")
    ap.add_argument("--repo", metavar="DIR", default=DEFAULT_REPO,
                    help="Sinter repository containing the candidate commit (default: this checkout)")
    args = ap.parse_args(argv)
    if not args.template:
        if bool(args.bundle) == bool(args.bundle_archive):
            ap.error("exactly one of --bundle or --bundle-archive is required")
        if not args.artifact:
            ap.error("--artifact is required")
    try:
        errors = run(args)
    except Invalid as e:
        errors = [str(e)]
    except OSError as e:
        errors = [f"cannot read input: {e.strerror or type(e).__name__}"]
    except (RecursionError, MemoryError, ValueError) as e:
        errors = [f"input rejected ({type(e).__name__})"]
    for e in errors:
        print(f"FAIL {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"OK {args.manifest}" + (" (template structure)" if args.template else " (verdict GO)"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
