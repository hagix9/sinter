#!/usr/bin/env python3
"""Tier F / Tier P assessment of a release (RELEASE.md step 2, T-1 to T-5).

docs/design/v1.15.0-release-and-acceptance.md §1.1. The tool collects the
facts the tier depends on and applies the approved rules; the independent
review checks the result and the Owner approves the tier. It never chooses
Tier P by itself: the result is P only when P is requested and every condition
holds; otherwise it is F (never a silent downgrade of the acceptance).

Facts:
  - the diff of SOURCE_CANDIDATE against the last release tag (git), with
    every changed path matched against the OS-related code areas of T-1;
  - the release kind from the two Cargo.toml versions (a minor or major
    release is always Tier F);
  - the ABI of the frozen executable (DT_NEEDED, highest GLIBC_ and OPENSSL_
    version needs, read from the ELF file itself) compared with the reference
    Tier F manifest's `abi`;
  - every crate whose Cargo.lock version changed (listed for the review), and
    every statically linked SSH, crypto or compression crate or other *-sys
    crate among them, each needing an answer whether it is reached at run
    time (an unanswered or "unknown" answer counts as reached);
  - the reference Tier F GO manifest (schema /2, full scope): SHA-256, version,
    finished_at; the days and the releases published since (T-5);
  - the answers file: each T-1 trigger that needs a human answer (yes/no with
    evidence), the T-3 targets, and the first available newer generation.

Usage:
  tier_assess.py --repo DIR --last-tag vX.Y.Z --source-candidate SHA
                 --executable sinter --answers ANSWERS.json
                 [--reference-manifest REF.json --releases-since X.Y.Z,...]
                 --run-date YYYY-MM-DD --request F|P --out DIR

Writes DIR/TIER_ASSESSMENT.json and DIR/TIER_ASSESSMENT.md. Exit 0 with the
tier printed; 2 on a usage or input error (nothing is assumed).
Standard library only (plus git).
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

LABELS = ["ubuntu2404", "ubuntu2604", "rocky9", "rocky10", "rhel9", "rhel10", "alma9", "alma10"]
NEWER = ["ubuntu2604", "rocky10", "rhel10", "alma10"]
MAX_DAYS = 60
MAX_RELEASES = 2

# T-1: code whose change makes a release Tier F (platform detection, package
# and service handling and their parsing, SSH and its algorithm lists, sudo,
# the assembly of target commands). Matched against every changed path; a
# match cannot be answered away.
OS_CODE = [
    r"^src/platform\.rs$",
    r"^src/facts\.rs$",
    r"^src/resources\.rs$",
    r"^src/manager\.rs$",
    r"^src/targetfs\.rs$",
    r"^src/executor\.rs$",
    r"^src/sshconfig\.rs$",
    r"^src/accounts\.rs$",
    r"^src/package_progress\.rs$",
    r"^src/fakepkg\.rs$",
    r"^src/pgrole\.rs$",
    r"^src/timer\.rs$",
    r"^src/timer_engine\.rs$",
    r"^src/nm\.rs$",
    r"^src/nm_engine\.rs$",
    r"^src/discover\.rs$",
    r"^src/risk/",
    r"^src/plugin/",
    r"^plugins/",
    r"^build\.rs$",
    r"^\.cargo/",
]
# T-1: the supported OS or image set.
PLATFORM_DOCS = [r"^README\.md$", r"^docs-site/src/content/docs/[a-z]+/compatibility/platforms\.md$"]
# Statically linked SSH, crypto and compression crates.
STATIC_CRATES = {
    "ssh2", "libssh2-sys", "openssl", "openssl-sys", "openssl-src", "libz-sys", "zlib-rs",
    "flate2", "miniz_oxide", "age", "age-core", "aes", "aes-gcm", "chacha20", "chacha20poly1305",
    "curve25519-dalek", "x25519-dalek", "ed25519-dalek", "sha2", "hmac", "hkdf", "rsa",
    "ring", "rustls", "scrypt", "bcrypt-pbkdf", "zeroize",
}
ANSWERED_TRIGGERS = ("os_or_image_change",)


class Bad(Exception):
    pass


def git(repo, *args):
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                       env={"PATH": "/usr/bin:/bin:/usr/local/bin", "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0"})
    if p.returncode != 0:
        raise Bad(f"git {' '.join(args)} failed")
    return p.stdout


def cargo_version(text):
    m = re.search(r'(?m)^\[package\][^\[]*?^version = "(\d+)\.(\d+)\.(\d+)"', text)
    if not m:
        raise Bad("Cargo.toml has no package version")
    return tuple(int(x) for x in m.groups())


def package_name(text):
    m = re.search(r'(?m)^\[package\][^\[]*?^name = "([^"]+)"', text)
    if not m:
        raise Bad("Cargo.toml has no package name")
    return m.group(1)


def lock_versions(text):
    """name -> sorted list of versions in a Cargo.lock."""
    out = {}
    for block in text.split("[[package]]")[1:]:
        n = re.search(r'(?m)^name = "([^"]+)"', block)
        v = re.search(r'(?m)^version = "([^"]+)"', block)
        if n and v:
            out.setdefault(n.group(1), []).append(v.group(1))
    return {k: sorted(v) for k, v in out.items()}


def vtuple(s):
    return tuple(int(x) for x in re.findall(r"\d+", s))


def elf_abi(path):
    """DT_NEEDED and the highest GLIBC_/OPENSSL_ version needs of an ELF64
    little-endian executable, read from its section headers."""
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise Bad("the executable is not a 64-bit little-endian ELF file")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if shentsize != 64 or shnum == 0 or shoff + shnum * 64 > len(data):
        raise Bad("the ELF section headers are not readable")
    secs = []
    for i in range(shnum):
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
            "<IIQQQQIIQQ", data, shoff + i * 64)
        if off + size > len(data) and typ != 8:  # SHT_NOBITS has no file bytes
            raise Bad("an ELF section lies outside the file")
        secs.append((name, typ, off, size, link, info))

    def cstr(sec, off):
        base, size = secs[sec][2], secs[sec][3]
        if off >= size:
            raise Bad("an ELF string offset is outside its table")
        end = data.index(b"\0", base + off, base + size)
        return data[base + off:end].decode("ascii", "strict")

    needed, versions = [], []
    for name, typ, off, size, link, info in secs:
        if typ == 6:  # SHT_DYNAMIC
            for j in range(0, size, 16):
                tag, val = struct.unpack_from("<qQ", data, off + j)
                if tag == 0:
                    break
                if tag == 1:  # DT_NEEDED
                    needed.append(cstr(link, val))
        elif typ == 0x6FFFFFFE:  # SHT_GNU_verneed
            pos, n = off, info
            for _ in range(n):
                vn_version, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack_from("<HHIII", data, pos)
                apos = pos + vn_aux
                for _ in range(vn_cnt):
                    vna_hash, vna_flags, vna_other, vna_name, vna_next = struct.unpack_from("<IHHII", data, apos)
                    versions.append(cstr(link, vna_name))
                    if vna_next == 0:
                        break
                    apos += vna_next
                if vn_next == 0:
                    break
                pos += vn_next
    if not needed:
        raise Bad("the executable has no DT_NEEDED entry (not a dynamically linked executable?)")

    def top(prefix):
        vs = [v for v in versions if re.fullmatch(prefix + r"\d+(\.\d+)*[a-z]?", v)]
        return max(vs, key=vtuple) if vs else None
    return {"dt_needed": sorted(set(needed)), "max_glibc": top("GLIBC_") or "none",
            "max_openssl": top("OPENSSL_") or "none"}


def decide(facts, answers, request):
    """The tier and the reasons (T-1, T-2, T-3, T-5). Tier P only when
    requested and nothing requires F."""
    reasons = []
    if facts["release_kind"] in ("minor", "major"):
        reasons.append(f"T-1: a {facts['release_kind']} release")
    if facts["os_code_paths"]:
        reasons.append("T-1: OS-related code changed: " + ", ".join(facts["os_code_paths"]))
    for t in ANSWERED_TRIGGERS:
        a = (answers.get("triggers") or {}).get(t) or {}
        if a.get("answer") != "no" or not a.get("evidence"):
            reasons.append(f"T-1: {t} is not answered no with evidence")
    if facts["platform_doc_paths"]:
        reasons.append("T-1: the supported platform documentation changed: " + ", ".join(facts["platform_doc_paths"]))
    if facts["abi"] is None or facts["reference_abi"] is None:
        reasons.append("T-1: no ABI comparison with a reference Tier F manifest")
    elif facts["abi"] != facts["reference_abi"]:
        reasons.append("T-1: the ABI differs from the reference Tier F artifact")
    reach = answers.get("static_dependencies") or {}
    for name in facts["static_changes"]:
        a = reach.get(name) or {}
        if a.get("reached") != "no" or not a.get("evidence"):
            reasons.append(f"T-1: static dependency {name} changed and is (or may be) reached at run time")
    ref = facts["reference"]
    if ref is None:
        reasons.append("T-5: no reference Tier F GO manifest")
    else:
        if ref["days"] is None or ref["days"] < 0 or ref["days"] > MAX_DAYS:
            reasons.append(f"T-1/T-5: more than {MAX_DAYS} days since the reference Tier F GO (or not after it)")
        if len(facts["releases_since"]) > MAX_RELEASES:
            reasons.append(f"T-1/T-5: more than {MAX_RELEASES} releases since the reference Tier F GO")
    if request != "P":
        reasons.append("Tier P not requested")
    tier = "P" if not reasons else "F"
    if tier == "F":
        targets = list(LABELS)
    else:
        newer = answers.get("first_available_newer")
        if newer not in NEWER:
            raise Bad("answers.first_available_newer must be one of " + ", ".join(NEWER))
        t3 = answers.get("t3_targets") or []
        if not all(x in LABELS for x in t3):
            raise Bad("answers.t3_targets names an unknown target")
        want = {"ubuntu2404", "rocky9", newer, *t3}
        targets = [x for x in LABELS if x in want]
    return tier, reasons, targets


def main(argv):
    ap = argparse.ArgumentParser(description="Tier F / Tier P assessment (T-1 to T-5).")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--last-tag", required=True)
    ap.add_argument("--source-candidate", required=True)
    ap.add_argument("--executable", required=True)
    ap.add_argument("--answers", required=True)
    ap.add_argument("--reference-manifest")
    ap.add_argument("--releases-since", default="")
    ap.add_argument("--run-date", required=True)
    ap.add_argument("--request", required=True, choices=["F", "P"])
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    try:
        if not re.fullmatch(r"v\d+\.\d+\.\d+", a.last_tag) or not re.fullmatch(r"[0-9a-f]{40}", a.source_candidate):
            raise Bad("--last-tag must be vX.Y.Z and --source-candidate a full commit id")
        run_date = datetime.date.fromisoformat(a.run_date)
        answers = json.load(open(a.answers, encoding="utf-8"))
        if not isinstance(answers, dict) or answers.get("schema") != "sinter-tier-answers/1":
            raise Bad("--answers is not a sinter-tier-answers/1 document")
        tag_commit = git(a.repo, "rev-parse", a.last_tag + "^{commit}").strip()
        old_v = cargo_version(git(a.repo, "show", f"{tag_commit}:Cargo.toml"))
        new_v = cargo_version(git(a.repo, "show", f"{a.source_candidate}:Cargo.toml"))
        if new_v <= old_v:
            kind = "same"
        elif new_v[0] != old_v[0]:
            kind = "major"
        elif new_v[1] != old_v[1]:
            kind = "minor"
        else:
            kind = "patch"
        paths = [p for p in git(a.repo, "diff", "--name-only", tag_commit, a.source_candidate).splitlines() if p]
        os_paths = [p for p in paths if any(re.search(rx, p) for rx in OS_CODE)]
        doc_paths = [p for p in paths if any(re.search(rx, p) for rx in PLATFORM_DOCS)]
        old_lock = lock_versions(git(a.repo, "show", f"{tag_commit}:Cargo.lock"))
        new_lock = lock_versions(git(a.repo, "show", f"{a.source_candidate}:Cargo.lock"))
        root = package_name(git(a.repo, "show", f"{a.source_candidate}:Cargo.toml"))
        changed_crates = sorted(n for n in set(old_lock) | set(new_lock)
                                if n != root and old_lock.get(n) != new_lock.get(n))
        # T-1 names statically linked SSH, crypto and compression crates; any
        # other *-sys crate (native code) also needs a reachability answer.
        static_changes = [n for n in changed_crates if n in STATIC_CRATES or n.endswith("-sys")]
        abi = elf_abi(a.executable)
        ref = None
        ref_abi = None
        if a.reference_manifest:
            raw = open(a.reference_manifest, "rb").read()
            doc = json.loads(raw.decode("utf-8"))
            if doc.get("schema") != "sinter-acceptance-manifest/2" or doc.get("acceptance_scope") != "full" or doc.get("verdict") != "GO":
                raise Bad("--reference-manifest is not a full-scope /2 GO manifest")
            fin = doc["run"]["finished_at"]
            fin_date = datetime.date.fromisoformat(fin[:10])
            ref = {"version": doc["candidate"]["version"], "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                   "finished_at": fin, "days": (run_date - fin_date).days}
            ref_abi = doc.get("abi")
        since = [x for x in a.releases_since.split(",") if x]
        if not all(re.fullmatch(r"\d+\.\d+\.\d+", x) for x in since):
            raise Bad("--releases-since must list X.Y.Z versions")
        facts = {
            "last_tag": a.last_tag, "tag_commit": tag_commit, "source_candidate": a.source_candidate,
            "old_version": ".".join(map(str, old_v)), "new_version": ".".join(map(str, new_v)),
            "release_kind": kind, "changed_paths": len(paths), "os_code_paths": os_paths,
            "platform_doc_paths": doc_paths, "changed_crates": changed_crates,
            "static_changes": static_changes, "abi": abi,
            "reference_abi": ref_abi, "reference": ref, "releases_since": since,
            "executable_sha256": hashlib.sha256(open(a.executable, "rb").read()).hexdigest(),
        }
        if kind == "same":
            raise Bad("the source candidate does not raise the version")
        tier, reasons, targets = decide(facts, answers, a.request)
    except (Bad, OSError, ValueError, KeyError) as e:
        print(f"tier_assess: {e}", file=sys.stderr)
        return 2
    result = {"schema": "sinter-tier-assessment/1", "requested": a.request, "tier": tier,
              "acceptance_scope": "patch" if tier == "P" else "full", "required_targets": targets,
              "reasons_for_tier_f": reasons, "facts": facts, "answers": answers}
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "TIER_ASSESSMENT.json"), "x", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    md = [f"# Tier assessment: {facts['old_version']} -> {facts['new_version']}", "",
          f"- Requested: Tier {a.request}; result: **Tier {tier}** (scope {result['acceptance_scope']})",
          f"- Required targets: {', '.join(targets)}",
          f"- Diff {a.last_tag}..{a.source_candidate[:12]}: {len(paths)} paths; release kind {kind}",
          f"- ABI: {json.dumps(abi, sort_keys=True)}; reference: {json.dumps(ref_abi, sort_keys=True)}",
          f"- Reference Tier F: {json.dumps(ref, sort_keys=True)}; releases since: {since or 'none'}",
          f"- Crates changed in Cargo.lock: {changed_crates or 'none'}",
          f"- Static SSH/crypto/compression (and *-sys) crates changed: {static_changes or 'none'}", "",
          "## Reasons the release is Tier F", ""]
    md += [f"- {r}" for r in reasons] or ["- none"]
    md += ["", "Needs the independent review and the Owner's approval of the tier (T-4)."]
    with open(os.path.join(a.out, "TIER_ASSESSMENT.md"), "x", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print(f"tier {tier}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
