"""Stand-in tests for the v1.16.0 acceptance checks (the v1160-checks section
of acceptance-target.sh; docs/design/v1.16.0-release-and-acceptance.md §2-§4).

The section between its BEGIN/END markers is extracted from the harness
exactly as written and run against a fake `sinter` that follows the documented
contract of each type (DESIGN §19.3, §49-§57, §60-§63) and fake host tools
(sysctl, hostnamectl, timedatectl, update-crypto-policies, tuned-adm, modprobe,
dnf, rpm, apt-cache, systemctl, systemd-analyze, getent, stat, ...) that share
one synthetic host: a directory standing for `/` (the section's V6ROOT line is
the only line replaced) and a JSON state. `sudo` is a shell function and
`sleep` a no-op. Each defect makes one fake break one rule, and the test
asserts that the check guarding it fails; the NOT_APPLICABLE cases are run with
and without their table entry and their proving observation, and
raw-verdict.py judges the resulting logs.

The real behaviour (every command's output on the eight images, PGDG over the
network, TuneD, the kernel's dummy module) is measured on real hosts only; these
tests show that the harness does not report PASS when the product breaks a
rule, that it records and puts back what it changes, and that it never removes
what it did not create. All data is synthetic.

With SINTER_ACCEPTANCE_REAL_BIN=<a built sinter>, every recipe the section
writes is also loaded by that binary (`sinter validate`, no target needed).

Run: python3 -m unittest discover -s release/tests
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
RELEASE = os.path.dirname(HERE)
REPO = os.path.dirname(RELEASE)
HARNESS = os.path.join(RELEASE, "acceptance-harness")
TARGET = os.path.join(HARNESS, "acceptance-target.sh")
RAW_VERDICT = os.path.join(HARNESS, "raw-verdict.py")
TABLE_PATH = os.path.join(HARNESS, "applicability.json")
IDS_PATH = os.path.join(HARNESS, "expected-check-ids.txt")
IDS = [l.strip() for l in open(IDS_PATH) if l.strip()]
TOOL_NAMES = ["sysctl", "hostnamectl", "timedatectl", "update-crypto-policies", "tuned-adm", "modprobe", "rpm", "dpkg-query",
              "apt-cache", "apt-get", "dnf", "systemctl", "systemd-analyze", "getent", "userdel", "groupdel", "ip", "chown",
              "timeout", "ssh", "sha256sum", "stat", "sudo", "locale"]

FAKE_SINTER = r'''#!/usr/bin/env python3
"""A stand-in for sinter that follows the documented contract of the v1.16.0
types (DESIGN §19.3, §49-§57, §60-§63) closely enough for the acceptance
checks; FAKE_DEFECT breaks one rule. The host is a directory (FAKE_ROOT) plus
a JSON state (FAKE_STATE: kernel values, names, packages, accounts, services,
owners)."""
import json, os, re, shutil, sys

FR = os.environ["FAKE_ROOT"]; SP = os.environ["FAKE_STATE"]
DEFECT = os.environ.get("FAKE_DEFECT", "")
A = sys.argv[1:]


def hp(p):
    return FR + p


def load_state():
    return json.load(open(SP))


def save_state(s):
    json.dump(s, open(SP, "w"), sort_keys=True)


# ---------------------------------------------------------------- YAML subset
def strip_comment(line):
    q = None
    for i, c in enumerate(line):
        if q:
            if c == "\\" and q == '"':
                continue
            if c == q:
                q = None
        elif c in "\"'":
            q = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def split_top(s):
    out, depth, q, cur = [], 0, None, ""
    for c in s:
        if q:
            cur += c
            if c == q:
                q = None
            continue
        if c in "\"'":
            q = c
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(cur.strip()); cur = ""; continue
        cur += c
    if cur.strip():
        out.append(cur.strip())
    return out


def scalar(s):
    s = s.strip()
    if s.startswith("[") and s.endswith("]"):
        return [scalar(x) for x in split_top(s[1:-1])]
    if s.startswith("{") and s.endswith("}"):
        d = {}
        for kv in split_top(s[1:-1]):
            k, _, v = kv.partition(":")
            d[k.strip()] = scalar(v)
        return d
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1].replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")
    if s.startswith("'") and s.endswith("'"):
        return s[1:-1]
    if s in ("true", "false"):
        return s == "true"
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return s


def yload(text):
    lines = []
    for raw in text.split("\n"):
        s = strip_comment(raw)
        if s.strip():
            lines.append([len(s) - len(s.lstrip(" ")), s.strip()])
    if not lines:
        return {}
    v, _ = block(lines, 0, lines[0][0])
    return v


def block(lines, i, ind):
    if lines[i][1].startswith("- ") or lines[i][1] == "-":
        out = []
        while i < len(lines) and lines[i][0] == ind and lines[i][1].startswith("-"):
            rest = lines[i][1][1:].strip()
            if re.match(r"^[A-Za-z_][\w.-]*:( |$)", rest):
                lines[i] = [ind + 2, rest]
                v, i = block(lines, i, ind + 2)
            else:
                v, i = scalar(rest), i + 1
            out.append(v)
        return out, i
    out = {}
    while i < len(lines) and lines[i][0] == ind and not lines[i][1].startswith("- "):
        k, _, rest = lines[i][1].partition(":")
        rest = rest.strip()
        if rest == "":
            if i + 1 < len(lines) and lines[i + 1][0] > ind:
                v, i = block(lines, i + 1, lines[i + 1][0])
            else:
                v, i = None, i + 1
        else:
            v, i = scalar(rest), i + 1
        out[k.strip()] = v
    return out, i


# ---------------------------------------------------------------- loading
class LoadError(Exception):
    pass


def facts():
    osr = {}
    for l in open(hp("/etc/os-release")):
        k, _, v = l.strip().partition("=")
        osr[k] = v.strip('"')
    fam = "redhat" if re.search(r"\b(rhel|fedora)\b", osr.get("ID", "") + " " + osr.get("ID_LIKE", "")) else "debian"
    return {"family": fam, "major": int(osr.get("VERSION_ID", "0").split(".")[0])}


def expand(path, label_prefix="", chain=()):
    """[(label, recipe path)], nested bundles count."""
    d = yload(open(path).read())
    if "recipes" not in d:
        return [(label_prefix + os.path.splitext(os.path.basename(path))[0], path)], 0
    out, nested = [], 0
    base = os.path.dirname(path)
    for e in d["recipes"]:
        p = os.path.join(base, e)
        if os.path.isdir(p):
            p = os.path.join(p, "bundle.yaml")
        sub = yload(open(p).read())
        if "recipes" in sub:
            name = sub.get("name") or os.path.basename(os.path.dirname(p))
            pref = "" if DEFECT == "nested-label" else label_prefix + name + "/"
            items, n = expand(p, pref)
            out += items; nested += 1 + n
        else:
            out.append((label_prefix + os.path.splitext(os.path.basename(p))[0], p))
    return out, nested


def check_recipe(path, doc):
    for r in doc.get("resources") or []:
        w = r.get("with") or {}
        if r["type"] == "dnf_repository" and w.get("gpgcheck") is False and DEFECT != "gpgcheck-false-ok":
            raise LoadError("%s: dnf_repository gpgcheck: Sinter never writes gpgcheck=0 or repo_gpgcheck=0" % r["id"])
        if r["type"] == "template" and DEFECT != "template-late":
            src = os.path.join(os.path.dirname(path), w["source"])
            for name in re.findall(r"\{\{\s*vars\.(\w+)\s*\}\}", open(src).read()):
                if name not in (doc.get("vars") or {}):
                    raise LoadError("resource %s: template %s references the undefined variable vars.%s" % (r["id"], src, name))


# ---------------------------------------------------------------- host
def owner(p):
    return load_state()["owners"].get(p, "root:root")


def set_owner(p, o, g):
    s = load_state(); s["owners"][p] = "%s:%s" % (o or "root", g or "root"); save_state(s)


def exists(p):
    return os.path.lexists(hp(p))


def mode(p):
    return os.lstat(hp(p)).st_mode & 0o7777


def writable_parent(p):
    d = os.path.dirname(p)
    if not os.path.isdir(hp(d)):
        return None
    m = os.stat(hp(d)).st_mode
    return d if (m & 0o022) and not (m & 0o1000) else None


def read(p):
    return open(hp(p)).read() if os.path.isfile(hp(p)) else None


def publish(p, content, md, own=("root", "root")):
    d = os.path.dirname(hp(p))
    stage = os.path.join(d, ".sinter-stage.ab12cd34")
    os.mkdir(stage)
    t = os.path.join(stage, "f")
    open(t, "w").write(content)
    os.chmod(t, md)
    os.rename(t, hp(p))
    if DEFECT != "stage-left":
        os.rmdir(stage)
    set_owner(p, *own)


class Fail(Exception):
    pass


class Unknown(Exception):
    pass


def carry_covers(carry, p):
    return carry["opaque"] or any(p == q or p.startswith(q + "/") for q in carry["paths"])


NOTES = [[]]   # the notes of the resource being handled (set per resource)


def parent_ok(p, carry, mode_):
    # DESIGN §29 / §49.1: a parent an earlier planned change creates defers
    # only the parent path check; the change itself is decided (a note, not
    # unknown). DEFECT nested-unknown restores the RC 2 harness's wrong model.
    d = os.path.dirname(p)
    if os.path.isdir(hp(d)):
        return True
    if mode_ == "plan" and DEFECT != "no-carry" and carry_covers(carry, d):
        if DEFECT == "nested-unknown":
            raise Unknown("its parent is created by an earlier change: %s" % carry_name(carry, d))
        NOTES[0].append("parent path check deferred to apply: parent directory %s does not exist (%s)" % (d, carry_name(carry, d)))
        return True
    raise Fail("parent directory %s does not exist" % d)


def carry_name(carry, p):
    for q, who in carry["paths"].items():
        if p == q or p.startswith(q + "/"):
            return who
    return carry["opaque"] or "an earlier change"


def account_ok(name, kind, carry, mode_):
    if name is None or name == "root":
        return True
    s = load_state()
    if name in s["users" if kind == "user" else "groups"]:
        return True
    if mode_ == "plan" and DEFECT != "no-carry" and name in carry["accounts"]:
        raise Unknown("account %s is created first by %s" % (name, carry["accounts"][name]))
    raise Fail("%s %s does not exist; declare it with creates_accounts, or a user/group resource" % (kind, name))


def platform_dnf4(rid, t):
    p = hp("/usr/bin/dnf")
    if not os.path.islink(p) and DEFECT == "refusal-other-text":
        raise Fail("%s: %s is not supported on this host: /usr/bin/dnf is not a symbolic link to a DNF 4 program, so the DNF generation cannot be told (only DNF 4 is supported)" % (rid, t))
    if not os.path.islink(p):
        raise Fail("%s: %s is not supported on this host (its package manager is not DNF)" % (rid, t))
    if "dnf5" in os.readlink(p):
        raise Fail("%s: %s is not supported on this host: it uses DNF 5, which this type does not support in this release" % (rid, t))


# ---------------------------------------------------------------- types
# each returns (current_ok, details) for audit/plan, and apply() mutates
def t_directory(r, w, mode_, carry, run):
    p = w["path"]; md = int(str(w.get("mode", "0755")), 8)
    wp = writable_parent(p)
    if wp:
        raise Fail("%s is in %s, a directory other accounts can write to (allowed by allow_writable_parents only for publishing a whole file or removing one): a directory is not supported there" % (p, wp))
    if exists(p):
        diffs = []
        if mode(p) != md:
            diffs.append(("mode", oct(mode(p)), oct(md)))
        want = "%s:%s" % (w.get("owner") or owner(p).split(":")[0], w.get("group") or owner(p).split(":")[1])
        if owner(p) != want and mode_ != "audit":
            account_ok(w.get("owner"), "user", carry, mode_); account_ok(w.get("group"), "group", carry, mode_)
        if owner(p) != want:
            diffs.append(("owner", owner(p), want))
        if not diffs:
            return []
        if run:
            os.chmod(hp(p), md); set_owner(p, w.get("owner"), w.get("group"))
        return diffs
    if mode_ == "audit":
        return [("state", "absent", "present")]
    missing = []
    d = os.path.dirname(p)
    while not os.path.isdir(hp(d)):
        missing.append(d); d = os.path.dirname(d)
    if missing and not w.get("parents"):
        parent_ok(p, carry, mode_)
    if missing and mode_ == "plan" and not w.get("parents") is True:
        pass
    account_ok(w.get("owner"), "user", carry, mode_); account_ok(w.get("group"), "group", carry, mode_)
    if run:
        for m in reversed(missing):
            os.mkdir(hp(m)); os.chmod(hp(m), 0o755); set_owner(m, "root", "root")
        if DEFECT == "parents-touch" and missing:
            os.chmod(hp(d), 0o755)
        os.mkdir(hp(p)); os.chmod(hp(p), md)
        o = "root" if DEFECT == "carry-owner" else w.get("owner")
        set_owner(p, o, w.get("group") if DEFECT != "carry-owner" else "root")
    for m in missing:
        carry["paths"][m] = carry["me"]
    return [("state", "absent", "present")]


def file_meta(p, w):
    d = []
    md = w.get("mode")
    if md is not None and mode(p) != int(str(md), 8):
        d.append(("mode", oct(mode(p)), str(md)))
    return d


def t_file(r, w, mode_, carry, run, content=None, ctx=None):
    p = w["path"]
    want = content if content is not None else w.get("content", "")
    st = w.get("state", "present")
    wp = writable_parent(p)
    notes = ctx["notes"]
    if wp:
        if wp not in ctx["awp"] or DEFECT == "writable-refuse":
            raise Fail("parent %s of %s is writable by other accounts" % (wp, p))
        notes.append("parent %s is writable by other accounts; allowed by allow_writable_parents" % wp)
    if st == "absent":
        if not exists(p):
            return []
        if run:
            os.remove(hp(p))
        return [("state", "present", "absent")]
    if mode_ != "audit":
        try:
            parent_ok(p, carry, mode_)
        except Unknown:
            carry["paths"][p] = carry["me"]
            raise
        account_ok(w.get("owner"), "user", carry, mode_)
    elif not os.path.isdir(hp(os.path.dirname(p))):
        return [("state", "absent", "present")]
    cur = read(p)
    if cur is None:
        if mode_ == "audit":
            return [("state", "absent", "present")]
        if run:
            publish(p, want, int(str(w.get("mode", "0644")), 8), (w.get("owner"), w.get("group")))
        carry["paths"][p] = carry["me"]
        return [("content", "", want)]
    diffs = []
    if cur != want:
        if wp and DEFECT != "planted-leak":
            ctx["diff"] = {"type": "summary", "current": "%d bytes, content differs (not shown)" % len(cur), "desired": "%d bytes" % len(want)}
        else:
            ctx["diff"] = {"type": "text", "removed": cur.splitlines(), "added": want.splitlines()}
        diffs.append(("content", "differs", "declared"))
    diffs += file_meta(p, w)
    if diffs and cur == want and wp and DEFECT != "writable-meta" and mode_ != "audit":
        raise Fail("%s is in %s, a directory other accounts can write to (allowed by allow_writable_parents only for publishing a whole file or removing one): a change of owner, group or mode alone is not supported there" % (p, wp))
    if diffs and run:
        publish(p, want, int(str(w.get("mode") or "%o" % mode(p)), 8), (w.get("owner"), w.get("group")))
    if diffs:
        carry["paths"][p] = carry["me"]
    return diffs


def render(src, doc):
    v = {k: (x.get("value") if isinstance(x, dict) else x) for k, x in (doc.get("vars") or {}).items()}
    return re.sub(r"\{\{\s*vars\.(\w+)\s*\}\}", lambda m: str(v[m.group(1)]), open(src).read())


def merge_edit(text, w, ctx):
    st = w.get("state", "present"); m = w["merge"]
    lines = text.split("\n")[:-1] if text else []
    if m == "line":
        ln = w["line"]
        if st == "present":
            if ln not in lines or DEFECT == "merge-dup":
                lines.append(ln)
        else:
            lines = [l for l in lines if l != ln]
    elif m == "block":
        b = "# BEGIN SINTER MANAGED BLOCK %s" % w["marker"]; e = "# END SINTER MANAGED BLOCK %s" % w["marker"]
        if b in lines:
            i, j = lines.index(b), lines.index(e)
            del lines[i:j + 1]
            if st == "present":
                lines[i:i] = [b] + w["content"].split("\n")[:-1] + [e]
        elif st == "present":
            lines += [b] + w["content"].split("\n")[:-1] + [e]
    else:
        k = w["key"]; idx = [i for i, l in enumerate(lines) if l.split("=", 1)[0] == k]
        if st == "present":
            if idx:
                lines[idx[0]] = "%s=%s" % (k, w["value"])
            else:
                lines.append("%s=%s" % (k, w["value"]))
        elif idx:
            del lines[idx[0]]
    return "\n".join(lines) + ("\n" if lines else "")


def t_file_merge(r, w, mode_, carry, run, ctx):
    p = w["path"]
    wp = writable_parent(p)
    if wp:
        if wp not in ctx["awp"]:
            raise Fail("parent %s is writable by other accounts" % wp)
        ctx["notes"].append("parent %s is writable by other accounts; allowed by allow_writable_parents" % wp)
    cur = read(p)
    if cur is None:
        return [] if w.get("state") == "absent" else [("state", "absent", "present")]
    if wp and w.get("mode") and (int(str(w["mode"]), 8) & 0o444 & ~mode(p)):
        raise Fail("%s: the file is in %s, a directory other accounts can write to, so the existing file may be one another account put there; file_merge keeps its content and does not make it readable by more accounts than the existing file: mode" % (r["id"], wp))
    new = merge_edit(cur, w, ctx)
    if new == cur:
        return []
    if run:
        publish(p, new, mode(p), tuple(owner(p).split(":")))
    return [(w["merge"], "differs", "declared")]


def read_ini_sections(p):
    secs, cur = {}, None
    for l in (read(p) or "").split("\n"):
        m = re.match(r"^\[(.+)\]$", l)
        if m:
            cur = m.group(1); secs[cur] = {}
        elif cur and "=" in l:
            k, _, v = l.partition("="); secs[cur][k.strip()] = v.strip()
    return secs


def t_dnf_repository(r, w, mode_, carry, run):
    platform_dnf4(r["id"], "dnf_repository")
    p = w.get("file") or "/etc/yum.repos.d/%s.repo" % w["name"]
    secs = read_ini_sections(p); n = w["name"]
    if w.get("state") == "absent":
        if n not in secs:
            return []
        if run:
            out, skip = [], False
            for l in read(p).split("\n"):
                if l == "[%s]" % n:
                    skip = True; continue
                if skip and l.startswith("["):
                    skip = False
                if not skip:
                    out.append(l)
            text = "\n".join(out).strip("\n")
            open(hp(p), "w").write(text + "\n" if text else "")
        return [("state", "present", "absent")]
    want = {}
    if "description" in w:
        want["name"] = w["description"]
    for k in ("baseurl", "mirrorlist", "metalink", "gpgkey"):
        if k in w:
            want[k] = w[k]
    want["enabled"] = "1" if w.get("enabled", True) and DEFECT != "repo-enabled" or DEFECT == "repo-enabled" else "0"
    want["gpgcheck"] = "1"
    if w.get("repo_gpgcheck"):
        want["repo_gpgcheck"] = "1"
    have = secs.get(n)
    if have is not None and all(have.get(k) == v for k, v in want.items()):
        return []
    if mode_ == "audit":
        return [("state", "absent", "present")]
    if run:
        body = "[%s]\n" % n + "".join("%s=%s\n" % (k, want[k]) for k in ("name", "baseurl", "mirrorlist", "metalink", "enabled", "gpgcheck", "repo_gpgcheck", "gpgkey") if k in want)
        old = read(p) or ""
        if have is None:
            open(hp(p), "w").write(old + ("\n" if old and not old.endswith("\n\n") else "") + body)
        else:
            raise Fail("fake: editing an existing section is not modelled")
        os.chmod(hp(p), 0o644)
    carry["paths"][p] = carry["me"]
    return [("state", "absent", "present")]


def module_state(name):
    t = read("/etc/dnf/modules.d/%s.module" % name)
    if t is None:
        return "", ""
    st = re.search(r"^state=(.*)$", t, re.M); sm = re.search(r"^stream=(.*)$", t, re.M)
    return (st.group(1) if st else ""), (sm.group(1) if sm else "")


def t_dnf_module(r, w, mode_, carry, run):
    platform_dnf4(r["id"], "dnf_module")
    n = w["name"]; st, sm = module_state(n); want = w["state"]
    ok = (want == "enabled" and st == "enabled" and sm == str(w.get("stream"))) or (want == "disabled" and st == "disabled") or (want == "reset" and st == "")
    if ok:
        return []
    if mode_ == "plan":
        carry["opaque"] = carry["opaque"] or carry["me"]
        return [("state", st or "default", want)]
    if mode_ == "audit":
        return [("state", st or "default", want)]
    if load_state().get("no_module_streams") and want == "enabled":
        raise Fail("%s: dnf exited 1 (no such module); run dnf module list %s on the target" % (r["id"], n))
    if DEFECT == "module-noverify" and want == "disabled":
        return [("state", st, want)]
    os.makedirs(hp("/etc/dnf/modules.d"), exist_ok=True)
    open(hp("/etc/dnf/modules.d/%s.module" % n), "w").write("[%s]\nname=%s\nstream=%s\nprofiles=\nstate=%s\n" % (
        n, n, w.get("stream", sm) if want == "enabled" else sm, "" if want == "reset" else want))
    return [("state", st or "default", want)]


def t_crypto_policy(r, w, mode_, carry, run):
    tool = hp("/usr/bin/update-crypto-policies")
    if not os.path.exists(tool) and DEFECT == "refusal-other-text":
        raise Fail("%s: crypto_policy is not supported on this host (its configuration is not readable)" % r["id"])
    if not os.path.exists(tool):
        raise Fail("%s: crypto_policy is not supported on this host (update-crypto-policies was not found)" % r["id"])
    s = load_state(); cur = s["crypto"]; want = w["policy"]
    if cur == want:
        return []
    if mode_ == "audit":
        return [("policy", cur, want)]
    for sub in want.split(":")[1:]:
        if not os.path.exists(hp("/usr/share/crypto-policies/policies/modules/%s.pmod" % sub)):
            raise Fail("%s: the module %s is not defined on this host (looked for /usr/share/crypto-policies/policies/modules/%s.pmod)" % (r["id"], sub, sub))
    if "NO-SHA1" in cur.split(":") and "NO-SHA1" not in want.split(":") and not w.get("allow_weaker") and DEFECT != "crypto-weaken":
        raise Fail("%s: the hardening subpolicy NO-SHA1 is applied on the host and missing from the declared policy; removing it weakens the policy, so it must be explicit (allow_weaker: true)" % r["id"])
    if run:
        s["crypto"] = want; save_state(s)
    return [("policy", cur, want)]


def boot_order(name, own):
    """[(path, value)] of the settings of name in the boot order (file name order)."""
    files = []
    for d in ("/usr/lib/sysctl.d", "/run/sysctl.d", "/etc/sysctl.d"):
        if os.path.isdir(hp(d)):
            files += [(f, d + "/" + f) for f in os.listdir(hp(d)) if f.endswith(".conf")]
    out = []
    for _, p in sorted(files):
        for l in (read(p) or "").split("\n"):
            k, _, v = l.partition("=")
            if k.strip() == name:
                out.append((p, v.strip()))
    return out


def t_sysctl(r, w, mode_, carry, run, ctx):
    n = w["name"]; f = "/etc/sysctl.d/90-sinter-%s.conf" % n
    if w.get("state") == "absent":
        if not exists(f):
            return []
        if run:
            os.remove(hp(f))
        ctx["notes"].append("the running value is not reset")
        return [("persistent", "present", "absent")]
    v = str(w["value"]); body = "# Managed by Sinter (sysctl). Local changes are replaced.\n%s = %s\n" % (n, v)
    s = load_state(); diffs = []
    if s["sysctl"].get(n) != v:
        diffs.append(("runtime", s["sysctl"].get(n), v))
    if read(f) != body:
        diffs.append(("persistent", "differs", "declared"))
    if mode_ == "audit" and DEFECT != "sysctl-noboot":
        eff = boot_order(n, f)
        if eff and eff[-1][1] != v:
            diffs.append(("boot", "%s (from %s)" % (eff[-1][1], eff[-1][0]), v))
    if diffs and run:
        open(hp(f), "w").write(body); os.chmod(hp(f), 0o644)
        s = load_state(); s["sysctl"][n] = v; save_state(s)
    return diffs


def t_hostname(r, w, mode_, carry, run):
    s = load_state(); n = w["name"]
    if s["hostname"]["static"] == n:
        return []
    if run:
        if DEFECT == "hostname-transient":
            s["hostname"]["transient"] = n
        else:
            s["hostname"]["static"] = s["hostname"]["transient"] = n
            open(hp("/etc/hostname"), "w").write(n + "\n")
        save_state(s)
    return [("static", s["hostname"]["static"], n)]


def t_timezone(r, w, mode_, carry, run):
    cur = os.readlink(hp("/etc/localtime")) if os.path.islink(hp("/etc/localtime")) else None
    if cur is None:
        raise Fail("/etc/localtime is a regular file (a copied zone file)")
    if cur.split("zoneinfo/", 1)[1] == w["name"]:
        return []
    if run:
        os.remove(hp("/etc/localtime"))
        if DEFECT == "tz-copy":
            shutil.copy(hp("/usr/share/zoneinfo/" + w["name"]), hp("/etc/localtime"))
        else:
            os.symlink("../usr/share/zoneinfo/" + w["name"], hp("/etc/localtime"))
    return [("timezone", cur, w["name"])]


def t_locale(r, w, mode_, carry, run):
    f = "/etc/default/locale" if facts()["family"] == "debian" else "/etc/locale.conf"
    link = None
    if os.path.islink(hp(f)):
        # DESIGN §61 (RC 3): only the Debian family's link to /etc/locale.conf
        # is followed; DEFECT locale-symlink-refused is RC 2's behaviour
        link = os.readlink(hp(f))
        if f != "/etc/default/locale" or link not in ("../locale.conf", "/etc/locale.conf") or DEFECT == "locale-symlink-refused":
            raise Fail("%s: the default locale could not be observed: %s is a symlink to another target" % (r["id"], f))
        if DEFECT == "locale-replace-link" and run:
            os.remove(hp(f))
        else:
            f = "/etc/locale.conf"
    t = read(f) or ""
    m = re.search(r"^LANG=\"?([^\"\n]*)\"?$", t, re.M)
    if m and m.group(1) == w["lang"]:
        return []
    if run:
        v = "C.utf8" if DEFECT == "locale-spelling" else w["lang"]
        lines = [l for l in t.split("\n") if l and not l.startswith("LANG=")]
        open(hp(f), "w").write("LANG=%s\n" % v + "".join(l + "\n" for l in lines))
        s = load_state(); s.setdefault("manager_env", {})["LANG"] = v; save_state(s)   # as systemd-localed does
    return [("LANG", m.group(1) if m else "(not set)", w["lang"])]


def t_kernel_module(r, w, mode_, carry, run):
    n = w["name"].replace("-", "_"); f = "/etc/modules-load.d/sinter-%s.conf" % n
    body = "# Managed by Sinter (kernel_module). Local changes are replaced.\n%s\n" % n
    if w.get("state") == "absent":
        if not exists(f):
            return []
        if run:
            os.remove(hp(f))
        return [("persistent", "present", "absent")]
    diffs = []
    if not os.path.isdir(hp("/sys/module/" + n)):
        if mode_ != "audit" and load_state().get("no_dummy"):
            raise Fail("%s: module %s is not available for the running kernel; nothing was changed" % (r["id"], n))
        diffs.append(("loaded", "not loaded", "loaded"))
    if read(f) != body:
        diffs.append(("persistent", "differs", "declared"))
    if diffs and run:
        open(hp(f), "w").write(body)
        if DEFECT != "kmod-noload":
            os.makedirs(hp("/sys/module/" + n), exist_ok=True)
    return diffs


def t_package(r, w, mode_, carry, run):
    s = load_state(); n = w["name"]; inst = n in s["packages"]
    if (w.get("state", "present") == "present") == inst:
        return []
    if mode_ == "plan":
        carry["opaque"] = carry["opaque"] or carry["me"]
        for a in (w.get("creates_accounts") or {}).get("users", []) + (w.get("creates_accounts") or {}).get("groups", []):
            carry["accounts"][a] = carry["me"]
        carry["install"] = carry["install"] or carry["me"]
    if run:
        if w.get("state", "present") == "present":
            s["packages"].append(n)
            if n == "tuned":
                os.makedirs(hp("/usr/sbin"), exist_ok=True); open(hp("/usr/sbin/tuned-adm"), "w").write("")
                os.makedirs(hp("/etc/tuned"), exist_ok=True)
                s["units"].append("tuned")
            if n == "postgresql17-server":
                s["packages"] += ["postgresql17", "postgresql17-libs"]
                for pool in ("users", "groups"):
                    if "postgres" not in s[pool]:
                        s[pool].append("postgres")
                s["units"].append("postgresql-17")
        else:
            s["packages"].remove(n)
        save_state(s)
    return [("state", "absent" if not inst else "present", w.get("state", "present"))]


def t_service(r, w, mode_, carry, run):
    s = load_state(); n = w["name"]
    if n not in s["units"]:
        if mode_ == "plan" and carry["install"] and DEFECT != "no-carry":
            raise Unknown("unit %s not found; %s is planned to be installed first" % (n, carry["install"]))
        raise Fail("unit %s.service not found" % n)
    sv = s["services"].setdefault(n, {"active": False, "enabled": False})
    want_a = w.get("state", "running") == "running"; want_e = w.get("enabled")
    diffs = []
    if sv["active"] != want_a:
        diffs.append(("state", sv["active"], want_a))
    if want_e is not None and sv["enabled"] != want_e:
        diffs.append(("enabled", sv["enabled"], want_e))
    if diffs and run and not (DEFECT == "tuned-nostart" and n == "tuned"):
        sv["active"] = want_a
        if want_e is not None:
            sv["enabled"] = want_e
        save_state(s)
    return diffs


def t_tuned(r, w, mode_, carry, run, ctx):
    if not os.path.exists(hp("/usr/sbin/tuned-adm")):
        if mode_ == "plan" and carry["opaque"]:
            raise Unknown("tuned-adm may be provided by %s" % carry["opaque"])
        raise Fail("%s: tuned is not supported on this host (tuned-adm was not found); install it with a package resource" % r["id"])
    cur = (read("/etc/tuned/active_profile") or "").strip()
    want = "" if w.get("state") == "off" else w["profile"]
    s = load_state()
    # the host's answer of tuned-adm verify (FAKE_STATE tuned_verify, default applied); DESIGN §57.5 / §57.6
    applied = s.get("tuned_verify", "applied") == "applied" or DEFECT == "tuned-verify-claims-applied"
    if cur == want:
        if mode_ == "audit" and want and w.get("verify") and DEFECT != "tuned-noverify":
            if not applied:
                return [("applied", "tuned-adm verify reports that the system differs from the selected profile (exit 1)", "the selected profile is applied")]
            ctx["reason"] = "the selected profile matches, tuned.service is active and tuned-adm verify reports the profile as applied"
        return []
    if mode_ == "audit":
        return [("profile", cur, want)]
    if mode_ == "plan":
        return [("profile", cur, want)]
    if not s["services"].get("tuned", {}).get("active"):
        raise Fail("TuneD is installed but its service is not running (tuned.service is inactive); start it with a service resource (Sinter does not start it)")
    if not (DEFECT == "tuned-off-noop" and not want):
        open(hp("/etc/tuned/active_profile"), "w").write(want + "\n" if want else "")
    if want and w.get("verify") and DEFECT != "tuned-noverify":
        if applied:
            ctx["notes"].append("verify: tuned-adm verify reports the selected profile as applied")
        elif DEFECT != "tuned-verify-no-fail":
            ctx["verify_failed"] = "the profile was selected, but tuned-adm verify reports that the system differs from it (exit 1): the selection changed, the tuning did not verify"
    return [("profile", cur, want)]


def t_user(r, w, mode_, carry, run):
    s = load_state(); n = w["name"]
    if n in s["users"]:
        return []
    if mode_ == "plan":
        carry["accounts"][n] = carry["me"]
    if w.get("group"):
        account_ok(w["group"], "group", carry, mode_)
    if run:
        s["users"].append(n); save_state(s)
    return [("state", "absent", "present")]


def t_group(r, w, mode_, carry, run):
    s = load_state(); n = w["name"]
    if n in s["groups"]:
        return []
    if mode_ == "plan":
        carry["accounts"][n] = carry["me"]
    if run:
        s["groups"].append(n); save_state(s)
    return [("state", "absent", "present")]


def t_command(r, w, mode_, carry, run):
    if mode_ == "audit":
        return "na"
    if exists(w["creates"]):
        return "guard"
    if mode_ == "plan":
        carry["opaque"] = carry["opaque"] or carry["me"]
        raise Unknown("the command may run")
    if run:
        os.makedirs(os.path.dirname(hp(w["creates"])), exist_ok=True)
        open(hp(w["creates"]), "w").write("17\n")
        set_owner(os.path.dirname(w["creates"]), "postgres", "postgres")
    return [("ran", "", "")]


# ---------------------------------------------------------------- one recipe
def when_ok(r):
    c = r.get("when")
    if c is None:
        return True
    m = re.fullmatch(r"facts\.os\.version_major < (\d+)", c.strip())
    return facts()["major"] < int(m.group(1))


def run_recipe(path, phase, label, carry, skip=()):
    doc = yload(open(path).read())
    check_recipe(path, doc)
    awp = doc.get("allow_writable_parents") or []
    resources, failed = [], False
    carry["me"] = None
    for r in doc.get("resources") or []:
        if r["id"] in skip:
            continue
        carry["me"] = "%s (recipe %s)" % (r["id"], label) if label else r["id"]
        w = r.get("with") or {}
        ctx = {"notes": [], "awp": awp, "diff": None, "reason": None}
        NOTES[0] = ctx["notes"]
        out = {"id": r["id"], "type": r["type"], "change": "none", "unknown": False, "execution": "not_run",
               "verification": "not_performed", "disposition": "normal", "reason": None, "notes": ctx["notes"], "diff": None,
               "status": "compliant", "details": []}
        if not when_ok(r):
            out["disposition"] = "skipped_by_condition"; out["status"] = "not_applicable"
            resources.append(out); continue
        if failed:
            out["disposition"] = "blocked_by_fail_fast"; resources.append(out); continue
        t = r["type"]; run = phase == "apply"
        try:
            if t in ("file", "template"):
                content = render(os.path.join(os.path.dirname(path), w["source"]), doc) if t == "template" else None
                diffs = t_file(r, w, phase, carry, run, content, ctx)
            elif t in ("file_merge", "sysctl", "tuned"):
                diffs = {"file_merge": t_file_merge, "sysctl": t_sysctl, "tuned": t_tuned}[t](r, w, phase, carry, run, ctx)
            else:
                diffs = globals()["t_" + t](r, w, phase, carry, run)
            if diffs == "guard":
                out["disposition"] = "guard_satisfied"; diffs = []
            elif diffs == "na":
                out["status"] = "not_auditable"; diffs = []
            if diffs:
                out["change"] = "changed"; out["status"] = "drift"
                out["details"] = [{"dimension": d[0], "observed": str(d[1]), "desired": str(d[2])} for d in diffs]
                if t in ("directory", "file", "template", "file_merge") and phase == "plan":
                    carry["paths"].setdefault(w.get("path", ""), carry["me"])
            if run:
                out["execution"] = "succeeded"; out["verification"] = "verified" if diffs else "not_performed"
            out["diff"] = ctx["diff"]
            if ctx["reason"]:
                out["reason"] = ctx["reason"]
            if t == "package" and diffs and DEFECT == "pg-noidem" and r["id"] == "pg_pkg" and phase == "apply":
                pass
            if ctx.get("verify_failed") and run:
                out["execution"] = "failed"; out["verification"] = "failed"; out["reason"] = ctx["verify_failed"]; failed = True
        except Unknown as e:
            out["unknown"] = True; out["change"] = "changed"; out["reason"] = "decided at apply: %s" % e
            carry["opaque"] = carry["opaque"] or (carry["me"] if t in ("command", "package") else carry["opaque"])
        except Fail as e:
            out["execution"] = "failed"; out["reason"] = str(e); out["status"] = "error"; failed = True
        if DEFECT == "pg-noidem" and phase == "apply" and r["id"] == "pg_hba" and out["change"] == "none":
            out["change"] = "changed"
        if DEFECT == "pg-audit-drift" and phase == "audit" and r["id"] == "pg_conf":
            out["status"] = "drift"
        if DEFECT == "fresh-audit-error" and phase == "audit" and out["status"] == "drift" and r["type"] == "file":
            out["status"] = "error"
        resources.append(out)
    if phase == "audit":
        sts = [x["status"] for x in resources]
        rc = 6 if "error" in sts else 7 if "drift" in sts else 0
        res = [{k: x[k] for k in ("id", "type", "status", "reason", "details")} for x in resources]
        return rc, {"mode": "audit", "status": "drift" if rc == 7 else "ok", "resources": res}
    rc = (4 if phase == "plan" else 5) if failed else 0
    res = [{k: x[k] for k in ("id", "type", "change", "unknown", "execution", "verification", "disposition", "reason", "notes", "diff")} for x in resources]
    d = {"mode": phase, "status": "success" if not failed else ("plan_error" if phase == "plan" else "apply_failed"), "resources": res}
    if doc.get("backup") and phase != "audit":
        d["backup"] = backup(doc, skip, phase)
    return rc, d


def backup(doc, skip, phase):
    b = doc["backup"]; ents = []
    for e in b["paths"]:
        p = e["path"] if isinstance(e, dict) else e
        need = [x for x in (e.get("resources") if isinstance(e, dict) else None) or [None] if x is None or x not in skip]
        if skip and not need and DEFECT != "backup-all":
            ents.append({"path": p, "status": "skipped", "reason": "SKIPPED_BY_USER"}); continue
        if phase == "apply" and exists(p):
            dst = hp(b["directory"] + "/run1" + p)
            os.makedirs(os.path.dirname(dst), exist_ok=True); shutil.copy(hp(p), dst)
            ents.append({"path": p, "status": "backed_up"})
        else:
            ents.append({"path": p, "status": "planned" if phase == "plan" else "absent"})
    return {"run_id": "run1", "entries": ents}


def new_carry():
    return {"paths": {}, "accounts": {}, "opaque": None, "install": None, "me": None}


def secrets_main():
    # DESIGN §65 stand-in: a synthetic "identity" (never a real age key) and a
    # reversible "encryption" good enough to prove the harness's checks.
    # Defects: keygen-mode (0644), keygen-leak (the key on stderr),
    # keygen-overwrite (an existing identity replaced), keygen-y-wrong.
    import base64, hashlib
    sub = A[1]; args = A[2:]
    def opt(f):
        return args[args.index(f) + 1] if f in args else None
    def pub_of(sec):
        return "age1" + hashlib.sha256(sec.encode()).hexdigest()[:40]
    if sub == "keygen" and "-y" not in args:
        out = opt("-o")
        if not out:
            sys.stderr.write("sinter: give the new identity file with -o\n"); return 2
        if os.path.lexists(out) and DEFECT != "keygen-overwrite":
            sys.stderr.write("sinter: %s already exists; an identity is never replaced\n" % out); return 2
        sec = "AGE-SECRET-KEY-1" + hashlib.sha256(os.urandom(16)).hexdigest().upper()
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644 if DEFECT == "keygen-mode" else 0o600)
        os.write(fd, ("# created: 2026-11-27T00:00:00Z\n# public key: %s\n%s\n" % (pub_of(sec), sec)).encode()); os.close(fd)
        if DEFECT == "keygen-mode":
            os.chmod(out, 0o644)
        sys.stderr.write("Public key: %s\n" % pub_of(sec))
        if DEFECT == "keygen-leak":
            sys.stderr.write("debug: %s\n" % sec)
        sys.stderr.write("sinter: created the private key %s (mode 600)\n" % out); return 0
    if sub == "keygen":
        secs = [l for l in open(opt("-y")).read().splitlines() if l.startswith("AGE-SECRET-KEY-1")]
        for x in secs:
            print(pub_of(x) + ("0" if DEFECT == "keygen-y-wrong" else ""))
        return 0 if secs else 1
    if sub == "encrypt":
        data = open(args[-1], "rb").read()
        open(opt("-o"), "w").write("age-encryption.org/v1\nTO %s\n%s\n" % (opt("-r"), base64.b64encode(data).decode())); return 0
    if sub == "decrypt":
        lines = open(args[-1]).read().splitlines()
        secs = [l for l in open(opt("-i")).read().splitlines() if l.startswith("AGE-SECRET-KEY-1")]
        if not any("TO " + pub_of(x) == lines[1] for x in secs):
            sys.stderr.write("sinter: no identity matches\n"); return 1
        sys.stdout.buffer.write(base64.b64decode(lines[2])); return 0
    return 99


def main():
    if A[0] == "secrets":
        return secrets_main()
    cmd, path = A[0], A[1]
    grab = os.environ.get("FAKE_GRAB")
    if grab:  # keep a copy of the recipe's directory for the real-binary test
        dst = os.path.join(grab, "r%03d" % len(os.listdir(grab)))
        shutil.copytree(os.path.dirname(os.path.abspath(path)), dst, ignore=shutil.ignore_patterns("*.json", "*.err", "*.out", "orig.*"))
        with open(os.path.join(grab, "list.txt"), "a") as f:
            f.write(os.path.join(dst, os.path.basename(path)) + "\n")
    skip = [A[i + 1] for i, x in enumerate(A) if x == "--skip-resource"]
    text = "--format" not in A
    try:
        items, nested = expand(path)
        if cmd == "validate":
            for label, p in items:
                d = yload(open(p).read()); check_recipe(p, d)
                for wd in d.get("allow_writable_parents") or []:
                    print("warning: allow_writable_parents lists %s: Sinter publishes and removes whole files in it although other accounts can write to it" % wd)
            if len(items) > 1 or nested:
                print("ok: bundle %s: %d recipe(s) from %d nested bundle(s)" % (yload(open(path).read()).get("name"), len(items), nested))
            else:
                print("ok: recipe %s" % path)
            return 0
        if cmd not in ("plan", "apply", "audit"):
            return 99
        for label, p in items:
            check_recipe(p, yload(open(p).read()))
    except LoadError as e:
        sys.stderr.write("sinter: %s\n" % e); return 2
    bundle = yload(open(path).read()).get("recipes") is not None
    carry = new_carry(); execs = []; overall = 0
    for label, p in items:
        if cmd != "plan" or not bundle:
            carry = new_carry() if cmd != "plan" else carry
        rc, d = run_recipe(p, cmd, label if bundle else None, carry, skip)
        execs.append({"recipe": label, "exit_code": rc, "status": d["status"], "result": d})
        overall = max(overall, rc)
        if cmd == "apply" and rc:
            break
    if DEFECT == "pg-apply-fail" and cmd == "apply" and any(l.startswith("postgresql-pgdg17") or l.endswith("07_service") for l, _ in items):
        overall = 5; execs[-1]["exit_code"] = 5
    if bundle:
        doc = {"mode": cmd, "exit_code": overall, "bundle": {"name": yload(open(path).read()).get("name"), "recipes": [{"recipe": l} for l, _ in items]}, "executions": execs}
    else:
        doc = execs[0]["result"]
    if text:
        for r in (doc.get("resources") or [x for e in doc.get("executions", []) for x in e["result"]["resources"]]):
            print("%s %s %s" % (r["id"], r.get("change") or r.get("status"), r.get("reason") or ""))
            dd = r.get("diff")
            if dd and dd.get("type") == "text":
                print("\n".join(dd["removed"] + dd["added"]))
            elif dd:
                print("%s -> %s" % (dd["current"], dd["desired"]))
    else:
        print(json.dumps(doc, indent=2))
    return overall


if __name__ == "__main__":
    sys.exit(main())
'''

FAKE_TOOLS = r'''#!/usr/bin/env python3
"""Stand-ins for the host tools the v1160-checks section calls itself (one
script, dispatched on the name it is called by). They read and write the same
FAKE_ROOT and FAKE_STATE as the fake sinter. FAKE_DEFECT=sysctl-sticky makes
`sysctl -w` (the harness's own restore) leave the value as it is."""
import json, os, re, stat, sys, time

FR = os.environ["FAKE_ROOT"]; SP = os.environ["FAKE_STATE"]
DEFECT = os.environ.get("FAKE_DEFECT", "")
me = os.path.basename(sys.argv[0]); a = sys.argv[1:]


def S():
    return json.load(open(SP))


def W(s):
    json.dump(s, open(SP, "w"), sort_keys=True)


def hp(p):
    return FR + p


def rd(p):
    return open(hp(p)).read() if os.path.isfile(hp(p)) else None


if me == "sysctl":
    s = S()
    if a[0] == "-n":
        v = s["sysctl"].get(a[-1])
        if v is None:
            sys.exit(255)
        print(v); sys.exit(0)
    kv = [x for x in a if "=" in x][0]
    k, _, v = kv.partition("=")
    if DEFECT != "sysctl-sticky":
        s["sysctl"][k] = v; W(s)
    sys.exit(0)

if me == "hostnamectl":
    s = S(); h = s["hostname"]
    if a and a[0] in ("--static", "--transient", "--pretty") and len(a) == 1:
        print(h[a[0][2:]]); sys.exit(0)
    if "set-hostname" in a:
        name = a[a.index("set-hostname") + 1]
        sel = [x[2:] for x in a if x in ("--static", "--transient", "--pretty")] or ["static", "transient"]
        for k in sel:
            h[k] = name
        if "static" in sel:
            open(hp("/etc/hostname"), "w").write(name + "\n" if name else "")
        W(s); sys.exit(0)
    sys.exit(99)

if me == "timedatectl":
    z = a[a.index("set-timezone") + 1]
    os.remove(hp("/etc/localtime")); os.symlink("../usr/share/zoneinfo/" + z, hp("/etc/localtime"))
    sys.exit(0)

if me == "update-crypto-policies":
    s = S()
    if a == ["--show"]:
        print(s["crypto"]); sys.exit(0)
    if a[0] == "--set":
        s["crypto"] = a[1]; W(s); sys.exit(0)
    sys.exit(99)

if me == "tuned-adm":
    if a[0] == "recommend":
        print("virtual-guest"); sys.exit(0)
    if a[0] == "verify":
        v = S().get("tuned_verify", "applied")
        sys.exit({"applied": 0, "not_applied": 1}.get(v, 3))
    if a[0] == "profile":
        open(hp("/etc/tuned/active_profile"), "w").write(a[1] + "\n")
    elif a[0] == "off":
        open(hp("/etc/tuned/active_profile"), "w").write("")
    sys.exit(0)

if me == "modprobe":
    if S().get("no_dummy"):
        sys.stderr.write("modprobe: FATAL: Module dummy not found in directory /lib/modules/6.0.0-fake\n"); sys.exit(1)
    if "-n" in a:
        print("insmod /lib/modules/6.0.0-fake/kernel/drivers/net/dummy.ko.xz numdummies=0"); sys.exit(0)
    os.makedirs(hp("/sys/module/dummy"), exist_ok=True); sys.exit(0)

if me == "rpm":
    s = S()
    if "-qa" in a:
        print("\n".join(sorted(s["packages"]))); sys.exit(0)
    if "gpg-pubkey" in a:
        print("PostgreSQL RPM Repository <synthetic@example.invalid> public key" if "postgresql17-server" in s["packages"] else "")
        sys.exit(0)
    sys.exit(0 if a[-1] in s["packages"] else 1)

if me == "dpkg-query":
    print("install ok installed" if "tuned" in S()["packages"] else "unknown ok not-installed", end="")
    sys.exit(0)

if me == "apt-cache":
    c = S().get("tuned_candidate", "2.21.0-1")
    print("tuned:\n  Installed: (none)\n  Candidate: %s\n" % c); sys.exit(0)

if me in ("apt-get", "dnf"):
    s = S(); q = [x for x in a if not x.startswith("-")]
    if q[:2] == ["module", "list"]:
        out = s.get("module_list")
        if out is None:
            sys.exit(0)
        sys.stdout.write(out); sys.exit(s.get("module_list_rc", 0))
    if q[:2] == ["module", "reset"]:
        f = hp("/etc/dnf/modules.d/%s.module" % q[2])
        if os.path.exists(f):
            t = re.sub(r"(?m)^state=.*$", "state=", open(f).read()); open(f, "w").write(t)
        sys.exit(0)
    if q[:1] == ["repolist"]:
        d = hp("/etc/yum.repos.d")
        for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            cur, en = None, {}
            for l in open(os.path.join(d, f)).read().split("\n"):
                m = re.match(r"^\[(.+)\]$", l)
                if m:
                    cur = m.group(1); en[cur] = True
                elif cur and l.startswith("enabled="):
                    en[cur] = l.endswith("1")
            for k, v in en.items():
                if ("--disabled" in a and not v) or ("--enabled" in a and v):
                    print("%s  some repository" % k)
        sys.exit(0)
    if q[:1] == ["list"]:
        sys.exit(0 if s.get("tuned_candidate", "x") != "(none)" else 1)
    if q[:1] == ["remove"]:
        for n in q[1:]:
            if n in s["packages"]:
                s["packages"].remove(n)
            if n == "tuned":
                for p in ("/usr/sbin/tuned-adm",):
                    if os.path.exists(hp(p)):
                        os.remove(hp(p))
                if "tuned" in s["units"]:
                    s["units"].remove("tuned")
        W(s); sys.exit(0)
    sys.exit(99)

if me == "systemctl":
    s = S(); verb = a[0]; unit = a[-1]
    env = s.setdefault("manager_env", {})
    if verb == "show-environment":
        print("PATH=/usr/bin"); [print("%s=%s" % kv) for kv in sorted(env.items())]; sys.exit(0)
    if verb == "set-environment":
        for kv in a[1:]:
            k, _, v = kv.partition("="); env[k] = v
        W(s); sys.exit(0)
    if verb == "unset-environment":
        for k in a[1:]:
            env.pop(k, None)
        W(s); sys.exit(0)
    sv = s["services"].setdefault(unit, {"active": False, "enabled": False})
    if verb == "is-active":
        print("active" if sv["active"] else ("inactive" if unit in s["units"] else "inactive")); sys.exit(0 if sv["active"] else 3)
    if verb == "is-enabled":
        if unit not in s["units"]:
            sys.exit(1)
        print("enabled" if sv["enabled"] else "disabled"); sys.exit(0 if sv["enabled"] else 1)
    if verb == "disable":
        sv["enabled"] = False
        if "--now" in a:
            sv["active"] = False
    elif verb == "enable":
        sv["enabled"] = True
    elif verb == "start":
        sv["active"] = True
    elif verb == "stop":
        sv["active"] = False
    W(s); sys.exit(0)

if me == "systemd-analyze":
    for d in ("/usr/lib/sysctl.d", "/etc/sysctl.d"):
        for f in sorted(os.listdir(hp(d))) if os.path.isdir(hp(d)) else []:
            print("\n# %s/%s" % (d, f)); print(open(hp(d + "/" + f)).read().rstrip("\n"))
    sys.exit(0)

if me == "getent":
    s = S(); kind, name = a
    if kind == "hosts":
        sys.exit(0 if name in s["hosts_resolvable"] or name in (rd("/etc/hosts") or "") else 2)
    pool = s["users"] if kind == "passwd" else s["groups"]
    if name in pool:
        print("%s:x:990:990::/:/usr/sbin/nologin" % name); sys.exit(0)
    sys.exit(2)

if me in ("userdel", "groupdel"):
    s = S(); pool = s["users" if me == "userdel" else "groups"]
    if a[-1] not in pool:
        sys.exit(6)
    pool.remove(a[-1]); W(s); sys.exit(0)

if me == "ip":
    sys.exit(0)

if me == "chown":
    s = S(); spec = a[0].split(":")
    names = {"0": "root"}
    for p in a[1:]:
        if p.startswith(FR):
            s["owners"][p[len(FR):]] = "%s:%s" % (names.get(spec[0], spec[0]), names.get(spec[1], spec[1]) if len(spec) > 1 else "root")
    W(s); sys.exit(0)

if me == "timeout":   # timeout [-k N] DURATION CMD...: the stand-ins never hang
    i = 0
    while a[i].startswith("-"):
        i += 2 if a[i] == "-k" else 1
    os.execvp(a[i + 1], a[i + 1:])

if me == "sudo":   # reached through timeout (the shell function covers direct calls)
    if a and a[0] == "-n":
        a = a[1:]
    os.execvp(a[0], a)

if me == "locale":
    print("C\nC.utf8\nPOSIX\nen_US.utf8"); sys.exit(0)

if me == "ssh":
    sys.exit(0)

if me == "sha256sum":
    import hashlib
    if "-c" in a:  # sha256sum -c --quiet: the list on stdin, names relative to the current directory
        bad = 0
        for l in sys.stdin.read().splitlines():
            h, _, n = l.partition("  ")
            try:
                bad += hashlib.sha256(open(n, "rb").read()).hexdigest() != h
            except OSError:
                bad += 1
        sys.exit(1 if bad else 0)
    fs = a or ["-"]
    for f in fs:
        b = sys.stdin.buffer.read() if f == "-" else open(f, "rb").read()
        print("%s  %s" % (hashlib.sha256(b).hexdigest(), f))
    sys.exit(0)

if me == "stat":
    # GNU stat: -c FORMAT [-L] [-f] PATH...; owners come from FAKE_STATE (the files are the test user's)
    fs = "-f" in a; deref = "-L" in a
    fmt = a[a.index("-c") + 1]; paths = [x for x in a[a.index("-c") + 2:] if x not in ("-L", "-f")]
    owners = S()["owners"]; rc = 0
    for p in paths:
        if fs:
            print(fmt.replace("%T", "apfs")); continue
        try:
            st = os.stat(p) if deref else os.lstat(p)
        except OSError:
            sys.stderr.write("stat: cannot statx '%s': No such file or directory\n" % p); rc = 1; continue
        o = owners.get(p[len(FR):] if p.startswith(FR) else p, "root:root").split(":")
        kind = "directory" if stat.S_ISDIR(st.st_mode) else "symbolic link" if stat.S_ISLNK(st.st_mode) else \
            "fifo" if stat.S_ISFIFO(st.st_mode) else "regular file" if st.st_size else "regular empty file"
        if kind == "regular empty file" and "%F" in fmt:
            kind = "regular empty file"
        rep = {"%F": kind, "%a": "%o" % (st.st_mode & 0o7777), "%u": "0" if o[0] == "root" else "990", "%g": "0" if o[1] == "root" else "990",
               "%U": o[0], "%G": o[1], "%s": str(st.st_size), "%d": str(st.st_dev), "%i": str(st.st_ino),
               "%y": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)) + ".%09d +0000" % (st.st_mtime_ns % 10**9),
               "%z": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime)) + ".%09d +0000" % (st.st_ctime_ns % 10**9),
               "%h": str(st.st_nlink)}
        print(re.sub(r"%[FaugUGsdiyzh]", lambda m: rep[m.group(0)], fmt))
    sys.exit(rc)

sys.stderr.write("fake tool %s: unsupported %r\n" % (me, a)); sys.exit(99)
'''


def section(name="v1160-checks"):
    text = open(TARGET, encoding="utf-8").read()
    m = re.search(r"^# BEGIN %s\n(.*?)^# END %s\n" % (name, name), text, re.S | re.M)
    assert m, name
    return m.group(1)


def na_allowed_source(table):
    """The harness's own na_allowed, reading the given table."""
    text = open(TARGET, encoding="utf-8").read()
    m = re.search(r"^na_allowed\(\) \{.*?^\}\n", text, re.S | re.M)
    assert m
    src = m.group(0)
    assert src.count('"$(dirname "$0")/applicability.json"') == 1
    return src.replace('"$(dirname "$0")/applicability.json"', "'%s'" % table)


OS_RELEASE = {
    "ubuntu2404": 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n',
    "ubuntu2604": 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="26.04"\n',
    "rocky9": 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.6"\n',
    "rocky10": 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="10.0"\n',
    "rhel9": 'NAME="Red Hat Enterprise Linux"\nID="rhel"\nID_LIKE="fedora"\nVERSION_ID="9.6"\n',
    "rhel10": 'NAME="Red Hat Enterprise Linux"\nID="rhel"\nID_LIKE="centos fedora"\nVERSION_ID="10.0"\n',
    "alma9": 'NAME="AlmaLinux"\nID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.6"\n',
    "alma10": 'NAME="AlmaLinux"\nID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="10.0"\n',
}
MODULE_LIST_EL9 = """Rocky Linux 9 - AppStream
Name       Stream    Profiles                                   Summary
maven      3.8       common [d]                                 Java project management and project comprehension tool
nodejs     18        common [d], development, minimal, s2i      Javascript runtime
nodejs     20        common [d], development, minimal, s2i      Javascript runtime
postgresql 15        client, server [d]                         PostgreSQL server and client module

Hint: [d]efault, [e]nabled, [x]disabled, [i]nstalled
"""


def world(label, root, **over):
    """A synthetic host of the label: files under root, and the state the fakes share."""
    rh = not label.startswith("ubuntu")
    major = int(re.search(r"(\d+)$", label).group(1)) if rh else 0
    dirs = ["/etc/sysctl.d", "/etc/modules-load.d", "/etc/pki/rpm-gpg", "/opt", "/var/lib", "/sys/module", "/usr/sbin",
            "/usr/bin", "/usr/lib/sysctl.d", "/usr/share/zoneinfo/Asia", "/usr/share/zoneinfo/Etc", "/etc/default"]
    if rh:
        dirs += ["/etc/yum.repos.d", "/etc/dnf/modules.d", "/usr/share/crypto-policies/policies/modules"]
    for d in dirs:
        os.makedirs(root + d, exist_ok=True)
    files = {"/etc/os-release": OS_RELEASE[label], "/etc/hostname": "fixture-vm\n", "/etc/hosts": "127.0.0.1 localhost\n",
             "/usr/share/zoneinfo/Asia/Tokyo": "TZif-fake-tokyo\n", "/usr/share/zoneinfo/Etc/UTC": "TZif-fake-utc\n",
             "/usr/lib/sysctl.d/50-default.conf": "kernel.sysrq = 16\n"}
    if rh:
        files["/etc/locale.conf"] = 'LANG="en_US.UTF-8"\n'
        if major == 9:
            files["/usr/share/crypto-policies/policies/modules/NO-SHA1.pmod"] = "# fake\n"
    else:
        files["/etc/default/locale"] = "LANG=C.UTF-8\n"
    tuned = over.pop("tuned_installed", rh)
    if tuned:
        files["/etc/tuned/active_profile"] = "virtual-guest\n"; files["/etc/tuned/profile_mode"] = "manual\n"
        files["/usr/sbin/tuned-adm"] = ""
    for p, b in files.items():
        os.makedirs(os.path.dirname(root + p), exist_ok=True)
        with open(root + p, "w") as f:
            f.write(b)
    if rh:
        os.symlink("dnf-3", root + "/usr/bin/dnf")
        tool = root + "/usr/bin/update-crypto-policies"
        os.symlink(os.path.join(over.pop("bin"), "update-crypto-policies"), tool)
    else:
        over.pop("bin")
    os.symlink("/usr/share/zoneinfo/Etc/UTC", root + "/etc/localtime")
    st = {"sysctl": {"vm.dirty_expire_centisecs": "3000"}, "hostname": {"static": "fixture-vm", "transient": "fixture-vm", "pretty": ""},
          "crypto": "DEFAULT", "packages": ["tuned"] if tuned else [], "units": ["tuned"] if tuned else [],
          "services": {"tuned": {"active": True, "enabled": True}} if tuned else {}, "users": ["root"], "groups": ["root"],
          "owners": {}, "hosts_resolvable": [], "tuned_candidate": "2.21.0-1",
          "module_list": MODULE_LIST_EL9 if major == 9 else None,
          "manager_env": {"LANG": "en_US.UTF-8" if rh else "C.UTF-8"}}
    if over.pop("hosts_no_newline", False):
        with open(root + "/etc/hosts", "w") as f:
            f.write("127.0.0.1 localhost")
    if over.pop("locale_link", False):   # Ubuntu 24.04 and later: /etc/default/locale -> ../locale.conf
        os.remove(root + "/etc/default/locale")
        with open(root + "/etc/locale.conf", "w") as f:
            f.write("LANG=C.UTF-8\n")
        os.symlink("../locale.conf", root + "/etc/default/locale")
    if over.pop("machine_info", False):
        with open(root + "/etc/machine-info", "w") as f:
            f.write('PRETTY_HOSTNAME="Fixture VM"\n')
    st.update(over)
    return st


def results(out):
    return (re.findall(r"^== check (\S+) ok$", out, re.M), re.findall(r"^== check (\S+) FAIL$", out, re.M),
            re.findall(r"^== check (\S+) NOT_APPLICABLE (\S+)$", out, re.M))


LABELS = ["ubuntu2404", "ubuntu2604", "rocky9", "rocky10", "rhel9", "rhel10", "alma9", "alma10"]


class Run:
    def __init__(self, ok, bad, na, out, state, root_left, prefixes=None):
        self.ok, self.bad, self.na, self.out, self.state, self.root_left = ok, bad, na, out, state, root_left
        self.prefixes = prefixes or {}


PG_EXAMPLE = os.path.join(REPO, "examples", "bundles", "postgresql-pgdg17")


def run_section(label, defect="", table=TABLE_PATH, keep=None, grab="", budget=None, **over):
    with tempfile.TemporaryDirectory(prefix="v1160-") as d:
        os.chmod(d, 0o700)
        b = os.path.join(d, "bin"); os.mkdir(b)
        with open(os.path.join(b, "sinter"), "w") as f:
            f.write(FAKE_SINTER)
        with open(os.path.join(b, "fake-tools"), "w") as f:
            f.write(FAKE_TOOLS)
        for n in ("sinter", "fake-tools"):
            os.chmod(os.path.join(b, n), 0o755)
        for n in TOOL_NAMES:
            os.symlink("fake-tools", os.path.join(b, n))
        root = os.path.join(d, "root"); os.mkdir(root)
        sp = os.path.join(d, "state.json")
        st = world(label, root, bin=b, **over)
        if keep:
            keep(root, st)
        json.dump(st, open(sp, "w"))
        s = os.path.join(d, "x"); os.mkdir(s)
        prelude = textwrap.dedent(f"""\
            set -u
            PASS=0; FAIL=0; NA=0
            check() {{ if [ "$2" = ok ]; then PASS=$((PASS+1)); echo "== check $1 ok"; echo "   $3";
              else FAIL=$((FAIL+1)); echo "== check $1 FAIL"; echo "   $3"; fi; }}
            not_applicable() {{ NA=$((NA+1)); echo "== check $1 NOT_APPLICABLE $2"; echo "   $3"; }}
            sudo() {{ [ "$1" = -n ] && shift; "$@"; }}
            sleep() {{ :; }}
            EXE="{b}/sinter"; S="{s}"; WORK="{d}"; LABEL={label}
            SSHUSER=sinter; SSHKEY="{d}/id_ed25519"
            """) + na_allowed_source(table)
        body = section()
        assert body.count('V6ROOT=""   #') == 1
        body = body.replace('V6ROOT=""   #', "V6ROOT='%s'   #" % root)
        if budget is not None:
            body = body.replace("V6_BUDGET=1200   #", "V6_BUDGET=%d   #" % budget)
        env = dict(os.environ, FAKE_ROOT=root, FAKE_STATE=sp, FAKE_DEFECT=defect, FAKE_GRAB=grab, PATH=b + os.pathsep + os.environ["PATH"])
        p = subprocess.run(["bash", "-c", prelude + body + '\necho "== section end passed=$PASS failed=$FAIL na=$NA"\n'],
                           capture_output=True, text=True, env=env, timeout=900, cwd=d)
        out = p.stdout + p.stderr
        assert p.returncode == 0, out
        ok, bad, na = results(p.stdout)
        left = sorted(x for x in os.listdir(root + "/opt")) + sorted(x for x in os.listdir(root + "/etc") if x.startswith("sinter-acc"))
        return Run(ok, bad, na, out, json.load(open(sp)), left, {root: "", d: "/var/tmp/sinter-acceptance"})


V116 = [l.strip() for l in open(IDS_PATH) if l.strip().startswith("v116-")]
PG = ["v116-pg-plan", "v116-pg-apply", "v116-pg-reapply", "v116-pg-audit"]
TUNED = ["v116-tuned-profile", "v116-tuned-verify", "v116-tuned-off"]


class PassAndNotApplicable(unittest.TestCase):
    """The documented behaviour passes every check; NOT_APPLICABLE only where the table and the observation agree."""

    def assertRun(self, r, na=()):
        self.assertEqual(r.bad, [], r.out)
        want_na = sorted(na)
        self.assertEqual(sorted(r.na), want_na, r.out)
        self.assertEqual(sorted(r.ok), sorted(set(V116) - {c for c, _ in na}), r.out)
        seen = r.ok + r.bad + [c for c, _ in r.na]
        for c in V116:
            self.assertEqual(seen.count(c), 1, c)
        self.assertEqual(r.root_left, [], r.out)

    def test_rocky9_runs_everything(self):
        r = run_section("rocky9")
        self.assertRun(r)
        # what the section changed is as it was
        self.assertEqual(r.state["sysctl"]["vm.dirty_expire_centisecs"], "3000")
        self.assertEqual(r.state["hostname"], {"static": "fixture-vm", "transient": "fixture-vm", "pretty": ""})
        self.assertEqual(r.state["crypto"], "DEFAULT")
        self.assertEqual(r.state["packages"], ["tuned"])
        self.assertNotIn("sinteracc", r.state["users"]); self.assertNotIn("postgres", r.state["users"])
        self.assertIn("== observe v116-crypto-ssh policy=DEFAULT:NO-SHA1 ", r.out)
        self.assertIn("V116_DNF_MODULE stream=18 state_before=default/absent", r.out)

    def test_ubuntu_refusals_and_pg_not_applicable(self):
        r = run_section("ubuntu2404", tuned_installed=False)
        self.assertRun(r, na=[(c, "NOT_DNF_HOST") for c in PG])
        self.assertIn("== observe v116-os family=debian major=24 dnf=absent", r.out)
        for tag in ("V116_DNF_REPO refusal plan=4:yes", "V116_DNF_MODULE refusal plan=4:yes", "V116_CRYPTO refusal plan=4:yes"):
            self.assertIn(tag, r.out)
        # tuned was installable: installed by the check, removed again
        self.assertEqual(r.state["packages"], [])
        self.assertIn("V116_LOCALE_BEFORE file=/etc/default/locale", r.out)

    def test_el10_module_streams_not_applicable(self):
        for label in ("rocky10", "rhel10", "alma10"):
            with self.subTest(label=label):
                r = run_section(label, no_module_streams=True)
                self.assertRun(r, na=[("v116-dnf-module", "NO_MODULE_STREAMS")])
                self.assertIn("== observe v116-dnf-modules modules_d=empty list=empty rows=0 source=cache", r.out)
                self.assertIn("V116_CRYPTO missing_module=4:yes:DEFAULT current=0:['none']:DEFAULT", r.out)
                self.assertRegex(r.out, r"V116_DNF_MODULE_EL10 plan=0 apply=5 ")

    def test_tuned_not_installable_on_ubuntu(self):
        r = run_section("ubuntu2604", tuned_installed=False, tuned_candidate="(none)")
        self.assertRun(r, na=[(c, "NOT_DNF_HOST") for c in PG] + [(c, "TUNED_NOT_AVAILABLE") for c in TUNED])

    def test_dummy_module_unavailable(self):
        r = run_section("alma9", no_dummy=True)
        self.assertRun(r, na=[("v116-kernel-module", "MODULE_UNAVAILABLE")])
        self.assertIn("== observe v116-kmod loaded=no modprobe_n_rc=1", r.out)

    def test_not_applicable_needs_the_table_entry(self):
        doc = json.loads(open(TABLE_PATH).read())
        for e in doc["entries"]:
            if e["reason"] in ("NO_MODULE_STREAMS", "NOT_DNF_HOST", "MODULE_UNAVAILABLE"):
                e["targets"] = [t for t in e["targets"] if t not in ("rocky10", "ubuntu2404")]
        with tempfile.TemporaryDirectory() as t:
            tp = os.path.join(t, "table.json"); json.dump(doc, open(tp, "w"))
            r = run_section("rocky10", table=tp, no_module_streams=True)
            self.assertEqual(r.na, [], r.out)
            self.assertEqual(r.bad, ["v116-dnf-module"], r.out)   # it runs: no nodejs stream to enable
            r = run_section("ubuntu2404", table=tp, tuned_installed=False, no_dummy=True)
            self.assertEqual(r.na, [], r.out)
            self.assertEqual(sorted(r.bad), sorted(PG + ["v116-kernel-module"]), r.out)

    def test_an_observation_that_does_not_prove_the_reason_runs_the_check(self):
        # a stream list on an EL 10 host: dnf_module runs (and passes with the fake)
        r = run_section("rocky10", module_list=MODULE_LIST_EL9)
        self.assertRun(r)
        # a non-empty modules.d with an empty list: not proven, the check runs and fails
        r = run_section("rocky10", no_module_streams=True,
                        keep=lambda root, st: open(root + "/etc/dnf/modules.d/other.module", "w").write("[other]\nstate=\n"))
        self.assertEqual(r.na, [], r.out); self.assertIn("v116-dnf-module", r.bad, r.out)
        # modprobe says the module exists although nothing is loaded: no NOT_APPLICABLE
        r = run_section("rocky9")
        self.assertIn("== observe v116-kmod loaded=no modprobe_n_rc=0", r.out)


class EachDefectFailsItsCheck(unittest.TestCase):
    CASES = {
        # defect: (label, checks that must fail)
        "fresh-audit-error": ("rocky9", ["v116-audit-fresh-drift"]),
        "nested-label": ("ubuntu2404", ["v116-bundle-nested"]),
        "no-carry": ("rocky9", ["v116-bundle-nested", "v116-bundle-carry", "v116-pg-plan"]),
        "carry-owner": ("ubuntu2404", ["v116-bundle-carry"]),
        "parents-touch": ("rocky9", ["v116-directory-parents"]),
        "template-late": ("ubuntu2404", ["v116-template-undefined-var"]),
        "backup-all": ("rocky9", ["v116-skip-resource-backup"]),
        "writable-refuse": ("rocky9", ["v116-writable-publish", "v116-writable-staging-cleanup"]),
        "stage-left": ("ubuntu2404", ["v116-writable-staging-cleanup"]),
        "writable-meta": ("rocky9", ["v116-writable-refusals"]),
        "planted-leak": ("ubuntu2404", ["v116-writable-planted"]),
        "merge-dup": ("rocky9", ["v116-file-merge"]),
        "gpgcheck-false-ok": ("ubuntu2404", ["v116-dnf-repository-gpgcheck-refused"]),
        "repo-enabled": ("rocky9", ["v116-dnf-repository"]),
        "module-noverify": ("rocky9", ["v116-dnf-module"]),
        "crypto-weaken": ("rocky9", ["v116-crypto-policy"]),
        "sysctl-noboot": ("ubuntu2404", ["v116-sysctl"]),
        "hostname-transient": ("rocky9", ["v116-hostname"]),
        "tz-copy": ("ubuntu2404", ["v116-timezone"]),
        "locale-spelling": ("rocky9", ["v116-locale"]),
        "kmod-noload": ("rocky9", ["v116-kernel-module"]),
        "tuned-nostart": ("ubuntu2404", ["v116-tuned-profile"]),
        "tuned-noverify": ("rocky9", ["v116-tuned-verify"]),
        "nested-unknown": ("ubuntu2404", ["v116-bundle-nested"]),
        "keygen-mode": ("rocky9", ["v116-secrets-keygen"]),
        "keygen-leak": ("ubuntu2404", ["v116-secrets-keygen"]),
        "keygen-overwrite": ("rocky9", ["v116-secrets-keygen"]),
        "keygen-y-wrong": ("ubuntu2404", ["v116-secrets-keygen"]),
        "tuned-off-noop": ("rocky9", ["v116-tuned-off"]),
        "pg-apply-fail": ("rocky9", ["v116-pg-apply"]),
        "pg-noidem": ("rocky10", ["v116-pg-reapply"]),
        "pg-audit-drift": ("rocky9", ["v116-pg-audit"]),
        "sysctl-sticky": ("rocky9", ["v116-no-residue"]),
        # M3 of audit G: another refusal sentence is not the documented refusal
        "refusal-other-text": ("ubuntu2404", ["v116-dnf-repository", "v116-dnf-module", "v116-crypto-policy"]),
    }

    def test_each_defect(self):
        covered = set()

        def one(item):
            defect, (label, ids) = item
            over = {"tuned_installed": False} if label == "ubuntu2404" else {}
            if label == "rocky10":
                over["no_module_streams"] = True
            return defect, ids, run_section(label, defect, **over)
        # each run has its own temporary host, state and PATH: they do not share anything
        with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 2)) as ex:
            runs = list(ex.map(one, self.CASES.items()))
        for defect, ids, r in runs:
            with self.subTest(defect=defect):
                for i in ids:
                    self.assertIn(i, r.bad, r.out)
                    self.assertNotIn(i, r.ok, r.out)
                covered.update(ids)
        # every new check has at least one defect that fails it
        self.assertEqual(sorted(set(V116) - covered), [])


class RC3Expectations(unittest.TestCase):
    """RC 3 (P-5 round 1 of RC 2 failed on ubuntu2404): the expectations that were wrong, both answers of tuned-adm verify."""

    def test_tuned_not_applied_is_accepted_only_with_the_failed_result_and_drift(self):
        r = run_section("rocky9", tuned_verify="not_applied")
        self.assertIn("v116-tuned-verify", r.ok, r.out)
        self.assertIn("after_apply=1 after_audit=1", r.out)
        self.assertEqual(r.bad, [], r.out)

    def test_tuned_not_applied_but_reported_applied_fails(self):
        r = run_section("rocky9", "tuned-verify-claims-applied", tuned_verify="not_applied")
        self.assertIn("v116-tuned-verify", r.bad, r.out)
        self.assertIn("DIAG tu5", r.out)

    def test_tuned_not_applied_but_apply_succeeds_fails(self):
        r = run_section("rocky9", "tuned-verify-no-fail", tuned_verify="not_applied")
        self.assertIn("v116-tuned-verify", r.bad, r.out)

    def test_tuned_verify_without_an_answer_fails(self):
        r = run_section("rocky9", tuned_verify="no_answer")
        self.assertIn("v116-tuned-verify", r.bad, r.out)

    def test_ubuntu_os_locale_link_is_followed_kept_and_restored(self):
        r = run_section("ubuntu2404", tuned_installed=False, locale_link=True)
        self.assertIn("v116-locale", r.ok, r.out)
        self.assertIn("v116-no-residue", r.ok, r.out)

    def test_ubuntu_locale_link_refused_or_replaced_fails(self):
        for defect in ("locale-symlink-refused", "locale-replace-link"):
            r = run_section("ubuntu2404", defect, tuned_installed=False, locale_link=True)
            self.assertIn("v116-locale", r.bad, defect + r.out)
            self.assertIn("DIAG lc", r.out, defect)

    def test_keygen_round_trip_and_its_defects(self):
        r = run_section("rocky9")
        self.assertIn("v116-secrets-keygen", r.ok, r.out)
        self.assertNotIn("AGE-SECRET-KEY-1", r.out)
        for defect in ("keygen-mode", "keygen-leak", "keygen-overwrite", "keygen-y-wrong"):
            r = run_section("rocky9", defect)
            self.assertIn("v116-secrets-keygen", r.bad, defect + r.out)
            self.assertNotIn("AGE-SECRET-KEY-1", r.out, defect)

    def test_nested_bundle_files_are_decided_changes_with_the_deferral_note(self):
        r = run_section("ubuntu2404", tuned_installed=False)
        self.assertIn("v116-bundle-nested", r.ok, r.out)
        self.assertIn("('nest_net', False), ('nest_top', False)", r.out)


class ExistingStateIsKept(unittest.TestCase):
    """Audit G mutants M1, M2 and the NON-BLOCKER restores: what existed before is as it was."""

    def test_an_existing_postgres_account_is_kept(self):
        r = run_section("rocky9", users=["root", "postgres"], groups=["root", "postgres"])
        self.assertEqual(r.bad, [], r.out)
        self.assertIn("postgres", r.state["users"]); self.assertIn("postgres", r.state["groups"])

    def test_a_postgres_group_alone_is_kept(self):
        r = run_section("rocky9", groups=["root", "postgres"])
        self.assertEqual(r.bad, [], r.out)
        self.assertNotIn("postgres", r.state["users"]); self.assertIn("postgres", r.state["groups"])

    def test_a_stopped_disabled_tuned_stays_stopped_and_disabled(self):
        def stop(root, st):
            st["services"]["tuned"] = {"active": False, "enabled": False}
        r = run_section("rocky9", keep=stop)
        self.assertEqual(r.bad, [], r.out)
        self.assertEqual(r.state["services"]["tuned"], {"active": False, "enabled": False})
        self.assertIn("V116_TUNED_RESTORE installed=yes service=inactive/disabled profile=virtual-guest", r.out)

    def test_manager_lang_machine_info_and_hosts_without_newline(self):
        r = run_section("rocky9", hosts_no_newline=True, machine_info=True)
        self.assertEqual(r.bad, [], r.out)
        self.assertEqual(r.state["manager_env"]["LANG"], "en_US.UTF-8")   # localectl had set C.UTF-8
        self.assertIn("== observe v116-locale-manager before=en_US.UTF-8 after_apply=C.UTF-8 readable=read", r.out)
        self.assertIn("manager_lang=same", r.out)

    def test_the_new_observations_are_logged(self):
        r = run_section("rocky9")
        for line in ("== observe v116-tuned-readonly recommend=virtual-guest recommend_rc=0 recommend_changed=no verify_audit_changed=no",
                     "== observe v116-locale-a rc=0 lines=4 c_utf8=listed",
                     "== observe v116-kmod-dry-run loaded_after=no modules_load_d=0",
                     "== observe v116-crypto-set policy=DEFAULT rc=0 lines=0 first= show_after=DEFAULT"):
            self.assertIn(line, r.out)
        self.assertRegex(r.out, r"== observe v116-sysctl-order rc=0 headers=\d+ sysctl_conf=not-listed masked=0 ")


class TimeBudget(unittest.TestCase):
    def run_budget(self, budget, **over):
        text = open(TARGET, encoding="utf-8").read()
        assert text.count("V6_BUDGET=1200   #") == 1
        return run_section("rocky9", budget=budget, **over)

    def test_a_spent_budget_fails_the_rest_and_still_restores(self):
        r = run_section("rocky9", budget=0)
        self.assertEqual(r.ok, ["v116-no-residue"], r.out)   # nothing else runs once the budget is spent ...
        self.assertIn("v116-pg-plan", r.bad)
        self.assertIn("budget left", r.out)
        # ... and what the section touched is put back
        self.assertEqual(r.state["hostname"]["static"], "fixture-vm")
        self.assertEqual(r.state["sysctl"]["vm.dirty_expire_centisecs"], "3000")
        self.assertEqual(r.root_left, [], r.out)

    def test_the_postgresql_block_needs_its_share_of_the_budget(self):
        text = section()
        self.assertIn('[ "$PGLEFT" -ge 540 ]', text)
        self.assertIn("V6_BUDGET=1200   #", text)

    def test_every_command_of_the_section_is_bounded(self):
        code = "\n".join(l for l in section().splitlines() if not l.lstrip().startswith("#"))
        tools = r"(?:dnf|apt-get|apt-cache|tuned-adm|systemctl|hostnamectl|timedatectl|userdel|groupdel|modprobe|ssh|update-crypto-policies|locale)"
        seen = 0
        for line in code.splitlines():
            # a tool in command position: at the start, after $( ; && || then else {, or after sudo / env
            for m in re.finditer(r"(?:^\s*|\$\(|;\s+|&&\s+|\|\|\s+|\bthen\s+|\belse\s+|\{\s+|v6[tr] \d+ )(?:sudo\s+)?(?:env \S+ )?(%s|\"\$EXE\"|\"\$CPT\")(?=\s)" % tools, line):
                seen += 1
                self.assertRegex(line[:m.start(1)], r"v6[tr] \d+ (?:sudo )?(?:env \S+ )?$", line)
        self.assertGreater(seen, 60)
        self.assertNotIn("V6TMO_PG", code)
        self.assertIn('v6t 300 "$EXE" "$c" "$f" --sudo --format json', code)


class ShortCircuits(unittest.TestCase):
    def test_disposable_names_in_use_fail_and_are_kept(self):
        def plant(root, st):
            os.makedirs(root + "/opt/sinter-acc-v116"); open(root + "/opt/sinter-acc-v116/keep-me", "w").write("x")
            os.makedirs(root + "/etc/sinter-acc"); st["users"].append("sinteracc")
        with tempfile.TemporaryDirectory():
            r = run_section("rocky9", keep=plant)
        for c in ("v116-audit-fresh-drift", "v116-bundle-nested", "v116-bundle-carry", "v116-directory-parents",
                  "v116-skip-resource-backup", "v116-file-merge", "v116-no-residue"):
            self.assertIn(c, r.bad, r.out)
        self.assertIn("sinteracc", r.state["users"])
        self.assertIn("sinter-acc-v116", r.root_left)

    def test_restores_run_from_the_trap_when_the_harness_stops(self):
        """Killed in the middle (after the hostname change): the EXIT trap puts the name back."""
        text = section()
        cut = text.index('  v6x hn3 apply "$V6/hn1.yaml"')
        body = text[:cut] + "  exit 143\n" + text[cut:]   # stops right after the hostname change
        with tempfile.TemporaryDirectory(prefix="v1160-") as d:
            b = os.path.join(d, "bin"); os.mkdir(b)
            open(os.path.join(b, "sinter"), "w").write(FAKE_SINTER); open(os.path.join(b, "fake-tools"), "w").write(FAKE_TOOLS)
            for n in ("sinter", "fake-tools"):
                os.chmod(os.path.join(b, n), 0o755)
            for n in TOOL_NAMES:
                os.symlink("fake-tools", os.path.join(b, n))
            root = os.path.join(d, "root"); os.mkdir(root); sp = os.path.join(d, "state.json")
            json.dump(world("rocky9", root, bin=b), open(sp, "w"))
            s = os.path.join(d, "x"); os.mkdir(s)
            prelude = ('set -u\ncheck() { echo "== check $1 $2"; }\nnot_applicable() { :; }\nna_allowed() { return 1; }\n'
                       'sudo() { [ "$1" = -n ] && shift; "$@"; }\nsleep() { :; }\n'
                       'EXE="%s/sinter"; S="%s"; WORK="%s"; LABEL=rocky9; SSHUSER=sinter; SSHKEY=x\n' % (b, s, d))
            body = body.replace('V6ROOT=""   #', "V6ROOT='%s'   #" % root)
            env = dict(os.environ, FAKE_ROOT=root, FAKE_STATE=sp, FAKE_DEFECT="", PATH=b + os.pathsep + os.environ["PATH"])
            p = subprocess.run(["bash", "-c", prelude + body], capture_output=True, text=True, env=env, timeout=600, cwd=d)
            self.assertEqual(p.returncode, 143, p.stdout + p.stderr)
            st = json.load(open(sp))
            self.assertEqual(st["hostname"]["static"], "fixture-vm", p.stdout)
            self.assertEqual(open(root + "/etc/hostname").read(), "fixture-vm\n")
            self.assertEqual(open(root + "/etc/hosts").read(), "127.0.0.1 localhost\n")
            self.assertEqual(st["sysctl"]["vm.dirty_expire_centisecs"], "3000")
            self.assertEqual(os.listdir(root + "/opt"), [])   # the base directory too
            self.assertIn("V116_HOSTNAME_RESTORE static=fixture-vm", p.stdout)


class RawVerdictOnSectionLogs(unittest.TestCase):
    """raw-verdict.py on whole logs: the section's lines plus the other checks of the expected list."""

    def full_log(self, label, r, drop=None, extra=()):
        others = [c for c in IDS if not c.startswith("v116-") and c != "nm-profile-crud"]
        lines = ["== acceptance start 2026-09-01T01:00:30Z label=%s" % label]
        if label.startswith("ubuntu"):
            lines += ["== observe nm-presence nmcli=absent service=not-found", "== check nm-profile-crud NOT_APPLICABLE NM_NOT_INSTALLED"]
        else:
            lines.append("== check nm-profile-crud ok")
        lines += ["== check %s ok" % c for c in others]
        sec = [l for l in r.out.splitlines() if l.startswith("== ") and not l.startswith("== section end") and l != drop]
        lines += sec + list(extra)
        ok = len([l for l in lines if re.match(r"^== check \S+ ok$", l)])
        na = len([l for l in lines if " NOT_APPLICABLE " in l])
        bad = len([l for l in lines if re.match(r"^== check \S+ FAIL$", l)])
        lines.append("== acceptance end 2026-09-01T01:30:00Z passed=%d failed=%d skipped=0 not_applicable=%d" % (ok, bad, na))
        return "\n".join(lines) + "\n"

    def verdict(self, text, label, rc="0"):
        with tempfile.TemporaryDirectory() as t:
            raw = os.path.join(t, "raw.log")
            open(raw, "w").write(text)
            p = subprocess.run([sys.executable, RAW_VERDICT, raw, IDS_PATH, "2026-09-01T01:00:00Z", rc, TABLE_PATH, label],
                               capture_output=True, text=True)
            return p.returncode, p.stdout.strip()

    def test_pass_logs_pass(self):
        for label, over, n in (("rocky9", {}, 0), ("ubuntu2404", {"tuned_installed": False}, 5),
                               ("rocky10", {"no_module_streams": True}, 1),
                               ("ubuntu2604", {"tuned_installed": False, "tuned_candidate": "(none)", "no_dummy": True}, 9)):
            with self.subTest(label=label):
                r = run_section(label, **over)
                text = self.full_log(label, r)
                self.assertEqual(self.verdict(text, label), (0, "PASS"), r.out)
                self.assertEqual(len(re.findall(r"(?m)^== check \S+ NOT_APPLICABLE ", text)), n)

    def test_not_applicable_without_its_proof_fails(self):
        cases = (("ubuntu2404", {"tuned_installed": False}, "v116-os", "NOT_DNF_HOST"),
                 ("rocky10", {"no_module_streams": True}, "v116-dnf-modules", "NO_MODULE_STREAMS"),
                 ("ubuntu2604", {"tuned_installed": False, "tuned_candidate": "(none)"}, "v116-tuned", "TUNED_NOT_AVAILABLE"),
                 ("rhel9", {"no_dummy": True}, "v116-kmod", "MODULE_UNAVAILABLE"))
        for label, over, key, reason in cases:
            with self.subTest(reason=reason):
                r = run_section(label, **over)
                obs = [l for l in r.out.splitlines() if l.startswith("== observe %s " % key)]
                self.assertEqual(len(obs), 1, r.out)
                rc, v = self.verdict(self.full_log(label, r, drop=obs[0]), label)
                self.assertEqual(rc, 1); self.assertTrue(v.startswith("NOT_APPLICABLE_NOT_PROVEN"), v)
                rc, v = self.verdict(self.full_log(label, r, extra=[obs[0]]), label)   # twice
                self.assertEqual(rc, 1); self.assertTrue(v.startswith("NOT_APPLICABLE_NOT_PROVEN"), v)
                forged = {"NOT_DNF_HOST": obs[0].replace("dnf=absent", "dnf=link:dnf-3"),
                          "NO_MODULE_STREAMS": obs[0].replace("rows=0", "rows=3"),
                          "TUNED_NOT_AVAILABLE": obs[0].replace("candidate=none", "candidate=present"),
                          "MODULE_UNAVAILABLE": obs[0].replace("modprobe_n_rc=1", "modprobe_n_rc=0")}[reason]
                text = self.full_log(label, r).replace(obs[0] + "\n", forged + "\n")
                rc, v = self.verdict(text, label)
                self.assertEqual(rc, 1); self.assertTrue(v.startswith("NOT_APPLICABLE_NOT_PROVEN"), v)
                # the table does not list another label
                other = "rocky9" if label.startswith("ubuntu") else "ubuntu2404"
                if reason != "MODULE_UNAVAILABLE":
                    rc, v = self.verdict(self.full_log(label, r), other)
                    self.assertEqual(rc, 1); self.assertTrue(v.startswith("NOT_APPLICABLE_NOT_ALLOWED"), v)

    def test_a_failed_section_check_is_not_pass(self):
        r = run_section("rocky9", "crypto-weaken")
        rc, v = self.verdict(self.full_log("rocky9", r), "rocky9", rc="1")
        self.assertEqual((rc, v), (1, "FAIL"))


class SanitizedLogsPassTheReleaseScan(unittest.TestCase):
    """Audit G B-1: every label's log, after sanitize.py, has no finding in the release checker's scan."""

    def test_every_label(self):
        cam = load_module(os.path.join(RELEASE, "check_acceptance_manifest.py"), "cam_v1160_scan")
        cases = [(l, {}) for l in ("rocky9", "rocky10", "rhel9", "rhel10", "alma9", "alma10")] + \
                [("ubuntu2404", {"tuned_installed": False}), ("ubuntu2604", {"tuned_installed": False, "tuned_candidate": "(none)", "no_dummy": True})]
        cases[1][1]["no_module_streams"] = True

        def one(case):
            label, over = case
            return label, run_section(label, **dict(over))
        with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 2)) as ex:
            runs = list(ex.map(one, cases))
        for label, r in runs:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as t:
                # on a target the section's paths are the host's own (V6ROOT is empty) and the work
                # directory is /var/tmp/sinter-acceptance; the stand-in's temporary prefixes stand for those
                text = r.out
                for k, v in sorted(r.prefixes.items(), key=lambda kv: -len(kv[0])):
                    text = text.replace(k, v)
                raw, out = os.path.join(t, "raw.log"), os.path.join(t, "out.log")
                with open(raw, "w") as f:
                    f.write(text)
                env = dict(os.environ, SINTER_PROJECT="synthetic-project-0001", SINTER_ZONE="synthetic-zone-1a",
                           SINTER_SPECS="fixture-vm:%s:no:no" % label)
                p = subprocess.run([sys.executable, os.path.join(HARNESS, "sanitize.py"), label, raw, out],
                                   capture_output=True, text=True, env=env)
                self.assertEqual(p.returncode, 0, p.stderr)
                with open(out) as f:
                    clean = f.read()
                errors = []
                cam.scan(clean, "logs/%s.log" % label, set(), set(LABELS), errors)
                self.assertEqual(errors, [], "\n".join(clean.splitlines()[int(e.split(":")[1]) - 1] for e in errors[:5]))
                self.assertIn("V116_CARRY_RESTORE sinteracc_accounts=", clean)
                self.assertRegex(clean, r"V116_NO_RESIDUE .* names=ok .* accounts=ok ")


class ManifestCheckerProofs(unittest.TestCase):
    """check_acceptance_manifest.py applies the same proofs as raw-verdict.py (NA_PROOFS == PROOFS)."""

    def test_same_rules_as_the_raw_verdict(self):
        cam = load_module(os.path.join(RELEASE, "check_acceptance_manifest.py"), "cam_v1160")
        rv = load_module(RAW_VERDICT, "rv_v1160")
        self.assertEqual(sorted(cam.NA_PROOFS), sorted(rv.PROOFS))
        for k in rv.PROOFS:
            self.assertEqual(cam.NA_PROOFS[k][:2], rv.PROOFS[k][:2], k)
        samples = ["== observe v116-os family=debian major=24 dnf=absent", "== observe v116-os family=redhat major=9 dnf=link:dnf-3",
                   "== observe v116-dnf-modules modules_d=empty list=empty rows=0 source=cache",
                   "== observe v116-dnf-modules modules_d=nonempty list=empty rows=0 source=cache",
                   "== observe v116-tuned installed=no candidate=none", "== observe v116-tuned installed=yes candidate=present",
                   "== observe v116-kmod loaded=no modprobe_n_rc=1", "== observe v116-kmod loaded=yes modprobe_n_rc=1",
                   "== observe nm-presence nmcli=absent service=not-found"]
        for reason in rv.PROOFS:
            for line in samples:
                self.assertEqual(cam.na_proven(line + "\n", reason), rv.proven(line + "\n", reason), (reason, line))

    def test_bundle_check_accepts_a_proven_v116_entry_and_refuses_the_rest(self):
        cam = load_module(os.path.join(RELEASE, "check_acceptance_manifest.py"), "cam_v1160b")
        table = open(TABLE_PATH, "rb").read()
        log = ("== acceptance start x\n== observe v116-kmod loaded=no modprobe_n_rc=1\n== check v116-kernel-module NOT_APPLICABLE MODULE_UNAVAILABLE\n"
               "== check a ok\n== acceptance end x passed=1 failed=0 skipped=0 not_applicable=1\n")
        facts = {"counts": {"rocky9": {"passed": 1, "failed": 0, "skipped": 0, "not_applicable": 1}},
                 "na": {"rocky9": [("v116-kernel-module", "MODULE_UNAVAILABLE")]}}
        errors = []
        cam.check_na_bundle({"harness/applicability.json": table, "logs/rocky9.log": log.encode()}, facts, errors)
        self.assertEqual(errors, [])
        for bad in (log.replace("modprobe_n_rc=1", "modprobe_n_rc=0"), log.replace("== observe v116-kmod loaded=no modprobe_n_rc=1\n", "")):
            errors = []
            cam.check_na_bundle({"harness/applicability.json": table, "logs/rocky9.log": bad.encode()}, facts, errors)
            self.assertEqual(errors, ["logs/rocky9.log: NOT_APPLICABLE v116-kernel-module MODULE_UNAVAILABLE is not proven by the observation line"])
        # PG on a RHEL label is not listed
        log2 = log.replace("v116-kernel-module NOT_APPLICABLE MODULE_UNAVAILABLE", "v116-pg-plan NOT_APPLICABLE NOT_DNF_HOST")
        facts["na"]["rocky9"] = [("v116-pg-plan", "NOT_DNF_HOST")]
        errors = []
        cam.check_na_bundle({"harness/applicability.json": table, "logs/rocky9.log": log2.encode()}, facts, errors)
        self.assertEqual(errors, ["logs/rocky9.log: NOT_APPLICABLE v116-pg-plan NOT_DNF_HOST is not allowed for rocky9"])


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Static(unittest.TestCase):
    def test_expected_ids_once_and_table_entries(self):
        ids = [l.strip() for l in open(IDS_PATH) if l.strip()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 105)
        self.assertEqual(len(V116), 29)  # 28 of RC 2 and v116-secrets-keygen (RC 3)
        text = section()
        for c in V116:
            self.assertEqual(ids.count(c), 1, c)
            self.assertRegex(text, r"check %s (ok|FAIL)" % re.escape(c))
        doc = json.loads(open(TABLE_PATH).read())
        got = sorted((e["check"], e["reason"], tuple(e["targets"])) for e in doc["entries"] if e["check"].startswith("v116-"))
        U = ("ubuntu2404", "ubuntu2604"); ALL = U + ("rocky9", "rocky10", "rhel9", "rhel10", "alma9", "alma10")
        want = sorted([(c, "NOT_DNF_HOST", U) for c in PG] + [("v116-dnf-module", "NO_MODULE_STREAMS", ("rocky10", "rhel10", "alma10"))]
                      + [(c, "TUNED_NOT_AVAILABLE", U) for c in TUNED] + [("v116-kernel-module", "MODULE_UNAVAILABLE", ALL)])
        self.assertEqual(got, want)

    def test_not_applicable_only_after_its_observation_and_through_na_allowed(self):
        text = section()
        calls = re.findall(r"(?m)^\s*(?:for id in \$\w+; do )?not_applicable (\S+) (\S+)", text)
        self.assertEqual(sorted(set(r for _, r in calls)), ["MODULE_UNAVAILABLE", "NOT_DNF_HOST", "NO_MODULE_STREAMS", "TUNED_NOT_AVAILABLE"])
        for reason, obs in (("NO_MODULE_STREAMS", 'echo "== observe v116-dnf-modules '), ("TUNED_NOT_AVAILABLE", 'echo "== observe v116-tuned installed='),
                            ("MODULE_UNAVAILABLE", 'echo "== observe v116-kmod '), ("NOT_DNF_HOST", 'echo "== observe v116-os ')):
            self.assertEqual(text.count(obs), 1, obs)
            ms = list(re.finditer(r"not_applicable \S+ %s" % reason, text))
            self.assertTrue(ms, reason)
            for m in ms:
                self.assertLess(text.index(obs), m.start(), reason)
                self.assertIn("na_allowed", text[max(0, m.start() - 700):m.start()], reason)
        code = re.sub(r"(?m)^\s*#.*$", "", text)
        self.assertNotRegex(code, r"\bskip \w")
        self.assertNotRegex(code, r"--host (?!127)")
        for bad in ("firewall-cmd", "systemctl restart sshd", "reboot", "nmcli", "kernel_args", "grub"):
            self.assertNotIn(bad, code)

    def test_every_change_is_armed_before_it_is_made(self):
        text = section()
        for fn in ("v6r_base", "v6r_carry", "v6r_writable", "v6r_etc", "v6r_repo", "v6r_dnfmod", "v6r_crypto", "v6r_sysctl",
                   "v6r_hostname", "v6r_tz", "v6r_locale", "v6r_kmod", "v6r_tuned", "v6r_pg"):
            self.assertIn("v6_arm %s" % fn, text, fn)
        self.assertIn("trap v6_restore_all EXIT", text)
        self.assertIn("trap - EXIT TERM HUP INT", text)

    def test_the_embedded_postgresql_bundle_is_the_example(self):
        """Byte for byte: every file of examples/bundles/postgresql-pgdg17, and nothing else."""
        text = section()
        emb = dict(re.findall(r"^v6_emb (\S+) <<'V116EOF'\n(.*?)^V116EOF$", text, re.S | re.M))
        files = {}
        for root, _, fs in os.walk(PG_EXAMPLE):
            for f in fs:
                path = os.path.join(root, f)
                with open(path, "rb") as fh:
                    files[os.path.relpath(path, PG_EXAMPLE)] = fh.read()
        self.assertEqual(sorted(emb), sorted(files))
        for k, b in files.items():
            self.assertEqual(emb[k].encode("ascii"), b, k)
        self.assertNotIn("V6PGSRC", text)

    def test_a_changed_embedded_bundle_is_detected(self):
        # the comparison above is not vacuous: one changed byte is a difference
        text = section().replace("name: postgresql17-server", "name: postgresql17-serveR", 1)
        emb = dict(re.findall(r"^v6_emb (\S+) <<'V116EOF'\n(.*?)^V116EOF$", text, re.S | re.M))
        with open(os.path.join(PG_EXAMPLE, "03_package.yaml")) as fh:
            self.assertNotEqual(emb["03_package.yaml"], fh.read())

    def test_shell_syntax(self):
        p = subprocess.run(["bash", "-n", TARGET], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)


@unittest.skipUnless(os.environ.get("SINTER_ACCEPTANCE_REAL_BIN"), "SINTER_ACCEPTANCE_REAL_BIN not set")
class RealBinaryLoadsEveryRecipe(unittest.TestCase):
    """Every recipe the section writes loads with a built sinter (validate needs no target)."""

    def test_validate(self):
        exe = os.environ["SINTER_ACCEPTANCE_REAL_BIN"]
        for label in ("rocky9", "ubuntu2404", "rocky10"):
            with tempfile.TemporaryDirectory(prefix="v1160-real-") as keep:
                r = run_section(label, grab=keep, **({"tuned_installed": False} if label.startswith("ubuntu") else {}))
                with open(os.path.join(keep, "list.txt")) as f:
                    recipes = sorted(set(f.read().splitlines()))
                self.assertGreater(len(recipes), 20, r.out)
                for f in recipes:
                    p = subprocess.run([exe, "validate", f], capture_output=True, text=True)
                    want = 2 if os.path.basename(f) in ("t.yaml", "dr0.yaml") else 0
                    self.assertEqual(p.returncode, want, f + "\n" + open(f).read() + p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
