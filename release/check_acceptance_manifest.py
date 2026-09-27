#!/usr/bin/env python3
"""Validate a Sinter acceptance Evidence Manifest (sinter-acceptance-manifest/1).

Usage:
  check_acceptance_manifest.py MANIFEST.json [--bundle DIR]
  check_acceptance_manifest.py --template release/acceptance-manifest.template.json

A real manifest must satisfy the schema, every consistency rule in
release/ACCEPTANCE_EVIDENCE.md, and the sensitive-data scan. With --bundle,
the harness files and per-target logs are verified by SHA-256 and every text
file in the bundle is scanned as well. --template checks only the structure
of the placeholder template shipped in the repository.

Standard library only. Exit 0 = valid, 1 = invalid.
"""
import hashlib
import json
import os
import re
import sys

SCHEMA = "sinter-acceptance-manifest/1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
RFC3339Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
LABEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")

# Content that must never appear in published evidence.
SENSITIVE = [
    ("IPv4 address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("email address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")),
    ("authorization header", re.compile(r"(?i)authorization:\s*\S+")),
    ("credential assignment", re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+")),
    ("home directory path", re.compile(r"(/Users/[^/\s]+|/home/[^/\s]+)")),
    ("internal DNS name", re.compile(r"\b[\w.-]+\.internal\b")),
]
# Version strings such as "9.8.0.1" are not addresses; allow only when the
# match is a plausible IPv4 address (every octet <= 255).
def _is_ipv4(s):
    return all(0 <= int(o) <= 255 for o in s.split("."))


def scan(text, where, errors):
    for name, rx in SENSITIVE:
        for m in rx.finditer(text):
            if name == "IPv4 address" and not _is_ipv4(m.group(0)):
                continue
            errors.append(f"{where}: sensitive content ({name})")
            break


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


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def check(doc, template, bundle, errors):
    if req(doc, "schema", str, "$", errors) != SCHEMA:
        errors.append("$.schema: must be " + SCHEMA)
    c = req(doc, "candidate", dict, "$", errors) or {}
    version = req(c, "version", str, "candidate", errors)
    match(version, SEMVER, "candidate.version", errors, template)
    tag = req(c, "tag", str, "candidate", errors)
    if not template and version and tag != f"v{version}":
        errors.append("candidate.tag: must be v<version>")
    match(req(c, "source_commit", str, "candidate", errors), HEX40, "candidate.source_commit", errors, template)
    art = req(c, "artifact", dict, "candidate", errors) or {}
    fname = req(art, "filename", str, "candidate.artifact", errors)
    art_sha = req(art, "sha256", str, "candidate.artifact", errors)
    match(art_sha, HEX64, "candidate.artifact.sha256", errors, template)
    req(art, "size_bytes", int, "candidate.artifact", errors)
    if not template and version and fname != f"sinter-v{version}-linux-x86_64.tar.gz":
        errors.append("candidate.artifact.filename: does not match the release naming contract")
    exe_sha = req(c, "executable_sha256", str, "candidate", errors)
    match(exe_sha, HEX64, "candidate.executable_sha256", errors, template)
    b = req(c, "build", dict, "candidate", errors) or {}
    for k in ("baseline", "rustc", "max_glibc"):
        req(b, k, str, "candidate.build", errors)

    h = req(doc, "harness", dict, "$", errors) or {}
    for k in ("name", "version", "runner", "operator"):
        req(h, k, str, "harness", errors)
    files = req(h, "files", list, "harness", errors) or []
    if not files:
        errors.append("harness.files: must list the harness files")
    for i, f in enumerate(files):
        p = req(f, "path", str, f"harness.files[{i}]", errors)
        s = req(f, "sha256", str, f"harness.files[{i}]", errors)
        match(s, HEX64, f"harness.files[{i}].sha256", errors, template)
        if bundle and p and s and not template:
            fp = os.path.join(bundle, p)
            if not os.path.isfile(fp):
                errors.append(f"harness.files[{i}]: {p} missing from bundle")
            elif sha256_file(fp) != s:
                errors.append(f"harness.files[{i}]: {p} sha256 mismatch")

    r = req(doc, "run", dict, "$", errors) or {}
    for k in ("started_at", "finished_at"):
        match(req(r, k, str, "run", errors), RFC3339Z, f"run.{k}", errors, template)

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
        for k in ("os_name", "os_version", "arch", "image", "version_output"):
            req(t, k, str, w, errors)
        for k in ("started_at", "finished_at"):
            match(req(t, k, str, w, errors), RFC3339Z, f"{w}.{k}", errors, template)
        a = req(t, "artifact_sha256", str, w, errors)
        e = req(t, "executable_sha256", str, w, errors)
        match(a, HEX64, f"{w}.artifact_sha256", errors, template)
        match(e, HEX64, f"{w}.executable_sha256", errors, template)
        if not template:
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
        if bundle and lp and ls and not template:
            fp = os.path.join(bundle, lp)
            if not os.path.isfile(fp):
                errors.append(f"{w}.log: {lp} missing from bundle")
            elif sha256_file(fp) != ls:
                errors.append(f"{w}.log: {lp} sha256 mismatch")

    tot = req(doc, "totals", dict, "$", errors) or {}
    tvals = {k: req(tot, k, int, "totals", errors) for k in ("targets", *sums)}
    if not template:
        if tvals.get("targets") != len(targets):
            errors.append("totals.targets: does not match the number of targets")
        for k in sums:
            if tvals.get(k) != sums[k]:
                errors.append(f"totals.{k}: does not equal the sum over targets")
        verdict = req(doc, "verdict", str, "$", errors)
        expect = "GO" if all_pass and sums["failed"] == 0 else "NO-GO"
        if verdict != expect:
            errors.append(f"$.verdict: must be {expect}")
    else:
        req(doc, "verdict", str, "$", errors)
    bundle_name = req(doc, "evidence_bundle", str, "$", errors)
    if not template and version and bundle_name != f"sinter-v{version}-acceptance-evidence.tar.gz":
        errors.append("evidence_bundle: does not match the naming contract")


def main(argv):
    template = "--template" in argv
    args = [a for a in argv if a != "--template"]
    bundle = None
    if "--bundle" in args:
        i = args.index("--bundle")
        bundle = args[i + 1] if i + 1 < len(args) else None
        del args[i : i + 2]
        if not bundle or not os.path.isdir(bundle):
            print("error: --bundle requires an existing directory", file=sys.stderr)
            return 1
    if len(args) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 1
    path = args[0]
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    errors = []
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"error: {path}: not valid JSON ({e})", file=sys.stderr)
        return 1
    if not isinstance(doc, dict):
        errors.append("$: top level must be an object")
    else:
        check(doc, template, bundle, errors)
    if not template:
        scan(raw, os.path.basename(path), errors)
        if bundle:
            for root, _, names in os.walk(bundle):
                for n in names:
                    fp = os.path.join(root, n)
                    try:
                        with open(fp, "r", encoding="utf-8") as f:
                            scan(f.read(), os.path.relpath(fp, bundle), errors)
                    except UnicodeDecodeError:
                        errors.append(f"{os.path.relpath(fp, bundle)}: not UTF-8 text")
    for e in errors:
        print(f"FAIL {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"OK {path}" + (" (template structure)" if template else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
