#!/usr/bin/env python3
"""Build and check the Sinter Skills-only plugin package for OpenAI submission.

The package is assembled from tracked sources only:
  - submission/openai/plugin.json          -> plugin.json
  - .agents/skills/sinter/**                -> skills/sinter/** (byte-identical copy)
  - .agents/skills/sinter/assets/*.png      -> assets/ (listing logo and composer icon)

Output (never inside the repository):
  <out>/sinter-openai-skills-<version>/     unpacked package root
  <out>/sinter-openai-skills-<version>.zip  deterministic ZIP, plugin.json at the archive root

The checks implement the rules published at
https://developers.openai.com/plugins/build/plugins and
https://developers.openai.com/plugins/deploy/submission-errors (Skills-only path).
They do not replace the portal's own validation and security scans.

Usage: python3 submission/openai/build_package.py [--out /tmp/sinter-openai-package]
Standard library only. Exit 0 = package built and all checks passed.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import zipfile

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SKILL_SRC = os.path.join(REPO, ".agents", "skills", "sinter")
MANIFEST_SRC = os.path.join(REPO, "submission", "openai", "plugin.json")
SCHEMA_URL = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
CATEGORIES = {"Productivity", "Creativity", "Developer Tools", "Business & Operations",
              "Data & Analytics", "Communication", "Education & Research", "Security",
              "Finance", "Healthcare", "Travel", "Entertainment", "Other"}
ZIP_TIME = (1980, 1, 1, 0, 0, 0)
FORBIDDEN_IN_SKILLS_ONLY = {"mcp.json", ".mcp.json", ".app.json"}


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def files_under(root):
    out = []
    for r, dirs, names in os.walk(root):
        dirs.sort()
        for n in sorted(names):
            out.append(os.path.relpath(os.path.join(r, n), root).replace(os.sep, "/"))
    return sorted(out)


def png_size(path):
    with open(path, "rb") as f:
        head = f.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n" or head[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", head[16:24])


def frontmatter(text):
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    if not m:
        return None, None
    fields = {}
    for line in m.group(1).splitlines():
        k, _, v = line.partition(":")
        if k and not k.startswith(" "):
            fields[k.strip()] = v.strip()
    return fields, m.group(2)


def simple_yaml_interface(text):
    """Read `interface:` string fields from agents/openai.yaml (quoted scalars only)."""
    fields, in_iface = {}, False
    for line in text.splitlines():
        if re.match(r"^interface:\s*$", line):
            in_iface = True
            continue
        if in_iface:
            m = re.match(r'^  ([a-z_]+): "(.*)"$', line)
            if m:
                fields[m.group(1)] = m.group(2)
            elif line and not line.startswith(" "):
                in_iface = False
    return fields


def one_line(s):
    return isinstance(s, str) and "\n" not in s and "\r" not in s and s.strip() == s and s != ""


class Checks:
    def __init__(self):
        self.results = []

    def add(self, name, ok, detail=""):
        self.results.append((name, bool(ok), detail))

    def report(self):
        for name, ok, detail in self.results:
            print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail else ""))
        failed = [r for r in self.results if not r[1]]
        print(f"\n{len(self.results) - len(failed)}/{len(self.results)} checks passed")
        return not failed


def check_manifest(c, m, root):
    allowed_top = {"$schema", "name", "version", "description", "author", "homepage",
                   "repository", "license", "keywords", "extensions"}
    c.add("manifest: only Agent Plugins 1.0.0 top-level keys", set(m) <= allowed_top, str(sorted(set(m) - allowed_top)))
    c.add("manifest: $schema is Agent Plugins 1.0.0", m.get("$schema") == SCHEMA_URL)
    name = m.get("name", "")
    c.add("manifest: name matches schema and portal rules",
          re.fullmatch(r"(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", name or "") is not None
          and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name) is not None and len(name) <= 64, name)
    c.add("manifest: version is semver <= 64 chars",
          re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", m.get("version", "")) is not None
          and len(m["version"]) <= 64, m.get("version"))
    c.add("manifest: description non-empty <= 1024", 0 < len(m.get("description", "")) <= 1024)
    a = m.get("author", {})
    c.add("manifest: author.name present <= 80 (final rule)", one_line(a.get("name")) and len(a["name"]) <= 80)
    c.add("manifest: author has only name/email/url", set(a) <= {"name", "email", "url"})
    ext = m.get("extensions", {})
    c.add("manifest: extensions only com.openai", set(ext) == {"com.openai"})
    oa = ext.get("com.openai", {})
    c.add("manifest: com.openai has interface only (no apps, no MCP)", set(oa) == {"interface"}, str(sorted(oa)))
    i = oa.get("interface", {})
    known = {"displayName", "shortDescription", "longDescription", "developerName", "category",
             "capabilities", "websiteURL", "privacyPolicyURL", "termsOfServiceURL", "defaultPrompt",
             "brandColor", "composerIcon", "logo", "screenshots"}
    c.add("interface: only documented keys", set(i) <= known, str(sorted(set(i) - known)))
    c.add("interface: no screenshots (Skills-only)", "screenshots" not in i)
    c.add("interface: displayName one line <= 30", one_line(i.get("displayName")) and len(i["displayName"]) <= 30)
    c.add("interface: shortDescription one line <= 30", one_line(i.get("shortDescription")) and len(i["shortDescription"]) <= 30,
          f"{len(i.get('shortDescription', ''))} chars")
    c.add("interface: longDescription non-empty <= 4000", 0 < len(i.get("longDescription", "")) <= 4000)
    c.add("interface: developerName one line <= 80 and equals author.name",
          one_line(i.get("developerName")) and len(i["developerName"]) <= 80 and i["developerName"] == a.get("name"))
    c.add("interface: category supported", i.get("category") in CATEGORIES, i.get("category"))
    caps = i.get("capabilities", [])
    c.add("interface: capabilities <= 20, each one line <= 120", len(caps) <= 20 and all(one_line(x) and len(x) <= 120 for x in caps))
    prompts = i.get("defaultPrompt", [])
    norm = [re.sub(r"\s+", " ", p).strip().lower() for p in prompts]
    c.add("interface: starter prompts <= 3, one line, <= 128, unique, no @mention",
          len(prompts) <= 3 and all(one_line(p) and len(p) <= 128 and "@" not in p for p in prompts) and len(set(norm)) == len(norm))
    for k in ("websiteURL", "privacyPolicyURL", "termsOfServiceURL"):
        if k in i:
            u = i[k]
            c.add(f"interface: {k} is HTTPS <= 1024", isinstance(u, str) and u.startswith("https://") and len(u) <= 1024 and "@" not in u.split("/")[2])
    for k in ("logo", "composerIcon"):
        p = i.get(k, "")
        full = os.path.normpath(os.path.join(root, p))
        size = png_size(full) if os.path.isfile(full) else None
        c.add(f"interface: {k} is a readable square PNG, 48..4096 px, <= 5 MiB",
              p.startswith("./") and os.path.isfile(full) and full.startswith(root + os.sep) and size is not None
              and size[0] == size[1] and 48 <= size[0] <= 4096 and os.path.getsize(full) <= 5 * 1024 * 1024,
              f"{p} {size}")


def check_skill(c, root, plugin_name):
    sk = os.path.join(root, "skills", "sinter")
    skills = [d for d in os.listdir(os.path.join(root, "skills")) if os.path.isdir(os.path.join(root, "skills", d))]
    c.add("skills: exactly one skill directory, not hidden", skills == ["sinter"], str(skills))
    text = open(os.path.join(sk, "SKILL.md"), "rb").read().decode("utf-8")
    fm, body = frontmatter(text)
    c.add("skill: SKILL.md has YAML front matter", fm is not None)
    c.add("skill: name and description present", fm and fm.get("name") == "sinter" and fm.get("description"))
    c.add("skill: description <= 1024", fm and len(fm.get("description", "")) <= 1024)
    c.add("skill: body non-empty", body is not None and body.strip() != "")
    c.add("skill: plugin:skill identity <= 64", len(f"{plugin_name}:{fm.get('name', '')}") <= 64)
    oy = simple_yaml_interface(open(os.path.join(sk, "agents", "openai.yaml"), encoding="utf-8").read())
    c.add("skill agent: display_name and short_description present", oy.get("display_name") and oy.get("short_description"))
    for k in ("icon_small", "icon_large"):
        if k in oy:
            p = oy[k]
            full = os.path.normpath(os.path.join(sk, p))
            c.add(f"skill agent: {k} is a relative path to an existing file",
                  not os.path.isabs(p) and os.path.isfile(full) and full.startswith(sk + os.sep), p)
    for rel in files_under(sk):
        if rel.endswith(".md"):
            t = open(os.path.join(sk, rel), encoding="utf-8").read()
            for link in re.findall(r"\]\(([^)]+)\)", t):
                if not link.startswith("http"):
                    target = os.path.normpath(os.path.join(sk, os.path.dirname(rel), link))
                    c.add(f"skill link resolves: {rel} -> {link}", os.path.exists(target) and target.startswith(sk + os.sep))


def check_hygiene(c, root):
    rels = files_under(root)
    c.add("hygiene: no hidden, temp, or OS files",
          not [r for r in rels if re.search(r"(^|/)\.|~$|\.(tmp|bak|orig|swp)$|__pycache__|Thumbs\.db", r)])
    c.add("hygiene: no MCP or app configuration (Skills-only)", not [r for r in rels if os.path.basename(r) in FORBIDDEN_IN_SKILLS_ONLY])
    c.add("hygiene: expected top level only", sorted({r.split("/")[0] for r in rels}) == ["assets", "plugin.json", "skills"],
          str(sorted({r.split("/")[0] for r in rels})))
    leaks = []
    for r in rels:
        if r.endswith((".md", ".json", ".yaml")):
            t = open(os.path.join(root, r), encoding="utf-8").read()
            for pat in (r"/Users/", r"/Volumes/", r"/home/[a-z]", r"/private/tmp",
                        r"ghp_|github_pat_|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|eyJ[A-Za-z0-9_-]{10,}\."):
                if re.search(pat, t):
                    leaks.append((r, pat))
    c.add("hygiene: no local absolute paths or secret-like strings", not leaks, str(leaks))


def check_zip(c, zpath, root):
    with zipfile.ZipFile(zpath) as z:
        infos = z.infolist()
        names = [i.filename for i in infos]
        c.add("zip: valid and readable", z.testzip() is None)
    c.add("zip: <= 100 MB compressed", os.path.getsize(zpath) <= 100 * 1000 * 1000, f"{os.path.getsize(zpath)} bytes")
    c.add("zip: <= 512 MiB uncompressed", sum(i.file_size for i in infos) <= 512 * 1024 * 1024)
    c.add("zip: <= 5000 entries", len(infos) <= 5000, str(len(infos)))
    bad = [n for n in names if not n or n != n.strip() or "\\" in n or n.startswith("/") or "" in n.rstrip("/").split("/")
           or ".." in n.split("/") or len(n.split("/")) > 20]
    c.add("zip: entry paths relative, '/'-separated, no empty or '..' segments, <= 20 segments", not bad, str(bad))
    c.add("zip: unique entries after case normalization", len({n.lower() for n in names}) == len(names))
    c.add("zip: plugin.json at archive root", "plugin.json" in names)
    c.add("zip: skills/sinter/SKILL.md present", "skills/sinter/SKILL.md" in names)
    c.add("zip: entries match the staged package exactly", sorted(names) == files_under(root))


def compare_skill(c, src, dst, label):
    a, b = files_under(src), files_under(dst)
    diffs = [r for r in sorted(set(a) | set(b)) if r not in a or r not in b or sha(os.path.join(src, r)) != sha(os.path.join(dst, r))]
    c.add(f"identity: {label} byte-identical to .agents/skills/sinter ({len(a)} files)", not diffs, str(diffs))
    return not diffs


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=os.path.join(tempfile.gettempdir(), "sinter-openai-package"))
    args = ap.parse_args()
    out = os.path.abspath(args.out)
    if out == REPO or out.startswith(REPO + os.sep):
        sys.exit("refusing to write build output inside the repository")
    manifest = json.load(open(MANIFEST_SRC, encoding="utf-8"))
    base = f"sinter-openai-skills-{manifest['version']}"
    root = os.path.join(out, base)
    zpath = os.path.join(out, base + ".zip")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    if os.path.exists(zpath):
        os.remove(zpath)

    shutil.copyfile(MANIFEST_SRC, os.path.join(root, "plugin.json"))
    for rel in files_under(SKILL_SRC):
        dst = os.path.join(root, "skills", "sinter", rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(os.path.join(SKILL_SRC, rel), dst)
    os.makedirs(os.path.join(root, "assets"))
    for n in ("sinter-icon.png", "sinter-logo.png"):
        shutil.copyfile(os.path.join(SKILL_SRC, "assets", n), os.path.join(root, "assets", n))

    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel in files_under(root):
            info = zipfile.ZipInfo(rel, date_time=ZIP_TIME)
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(os.path.join(root, rel), "rb") as f:
                z.writestr(info, f.read())

    c = Checks()
    check_zip(c, zpath, root)
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(zpath) as z:
            z.extractall(tmp)
        compare_skill(c, SKILL_SRC, os.path.join(tmp, "skills", "sinter"), "extracted ZIP skills/sinter")
        for n in ("sinter-icon.png", "sinter-logo.png"):
            c.add(f"identity: extracted assets/{n} matches the skill asset",
                  sha(os.path.join(tmp, "assets", n)) == sha(os.path.join(SKILL_SRC, "assets", n)))
        c.add("identity: extracted plugin.json matches submission/openai/plugin.json",
              sha(os.path.join(tmp, "plugin.json")) == sha(MANIFEST_SRC))
        check_manifest(c, json.load(open(os.path.join(tmp, "plugin.json"), encoding="utf-8")), tmp)
        check_skill(c, tmp, manifest["name"])
        check_hygiene(c, tmp)
    ok = c.report()
    print(f"\npackage: {root}\nzip:     {zpath}\nsha256:  {sha(zpath)}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
