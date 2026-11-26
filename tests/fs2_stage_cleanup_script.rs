//! The fixed staging script (`src/fsstage.sh`, DESIGN §23.5, §63.2) run for real under
//! `/bin/sh`, with stand-in tools instead of coreutils, findutils and util-linux, to test
//! the cleanup of the staging directory: where it is removed, where it is left, and what
//! the one `CLEANUP:` line says.
//!
//! Only two things in the text are changed: `PATH` (so the stand-ins are found) and a
//! shell function `cd` in front of the script that maps `cd -P -- /proc/self/fd/4` to the
//! path of descriptor 4 (macOS has no `/proc`). Every branch and all the quoting of the
//! real script run here. The stand-ins model GNU `stat`, `readlink`, `mktemp`, `ln -T`,
//! `mv -T`, `find` and `setpriv --regid`: owner and group are what a state file says (so
//! that a run that is not root can play root and the random group G), and on macOS the
//! link count of a removed directory held open is reported as 0, as Linux does. They can
//! also act as another account would between two steps. They are not those tools: the
//! real GNU `find -inum -empty -delete` and the real `/proc/self/fd` link count are
//! `tests/fs2_script_real.rs`, on Linux (its root-only cases as root).
#![cfg(unix)]

use sinter::executor::{Completion, Output};
use sinter::fsstage::{parse_cleanup, Cleanup, SCRIPT, UNSHOWN_PATH};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PRELUDE: &str = r#"#!/usr/bin/env python3
import os, sys, json, fcntl, random, string, fnmatch, stat as st_mod, subprocess
STATE = os.environ["STUB_STATE"]
def state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {}
def put(ino, **kw):
    s = state(); e = s.get(str(ino), {}); e.update(kw); s[str(ino)] = e
    json.dump(s, open(STATE, "w"))
def drop(ino):
    s = state(); s.pop(str(ino), None); json.dump(s, open(STATE, "w"))
def log(line):
    open(os.environ["STUB_LOG"], "a").write(line + "\n")
def fdpath(n):
    if sys.platform.startswith("linux"):
        return os.readlink("/proc/self/fd/%d" % n)
    return fcntl.fcntl(n, 50, b"\0" * 1024).rstrip(b"\0").decode("utf-8", "surrogateescape")
PRE = "/proc/self/fd/"
def fdnum(p):
    if p.startswith(PRE) and p[len(PRE):].isdigit():
        return int(p[len(PRE):])
    return None
def resolve(p):
    if p.startswith(PRE):
        n, _, tail = p[len(PRE):].partition("/")
        return fdpath(int(n)) + ("/" + tail if tail else "")
    return p
def owner(st):
    e = state().get(str(st.st_ino), {})
    return e.get("uid", int(os.environ["STUB_ME"])), e.get("gid", st.st_gid)
def other_account_acts():
    # Another account, between the publication and the cleanup.
    act = os.environ.get("STUB_AFTER_PUBLISH")
    if not act:
        return
    d, s = fdpath(4), fdpath(5)
    name = os.path.basename(s)
    g = state().get(str(os.fstat(5).st_ino), {}).get("gid")
    if act == "rename":
        os.rename(s, os.path.join(d, os.environ["STUB_NEWNAME"]))
    elif act == "fill":
        open(os.path.join(s, "theirs"), "w").write("x")
    elif act.startswith("decoy-"):
        os.rename(s, os.path.join(d, "moved"))
        p = os.path.join(d, name)
        os.mkdir(p, 0o700)
        ino = os.lstat(p).st_ino
        if act == "decoy-owner":
            put(ino, uid=1002, gid=g)
        elif act == "decoy-group":
            put(ino, uid=0, gid=1002)
        elif act == "decoy-inode":
            put(ino, uid=0, gid=g)
"#;

const TOOLS: &[(&str, &str)] = &[
    (
        "id",
        r#"
assert sys.argv[1:] == ["-u"]
print(os.environ["STUB_ME"])
"#,
    ),
    ("fdpath", r#"print(fdpath(int(sys.argv[1])))"#),
    (
        "stat",
        r#"
a = sys.argv[1:]
follow = a[0] == "-L"
if follow:
    a = a[1:]
assert a[0] == "-c" and len(a) == 3, a
fmt, path = a[1], a[2]
n = fdnum(path)
try:
    if n is not None:
        if n == 5 and os.environ.get("STUB_NLINK_FAIL"):
            sys.exit(1)
        st = os.fstat(n)
        nlink = st.st_nlink
        if sys.platform == "darwin":
            # Linux reports 0 for a removed directory held open; APFS does not.
            try:
                cur = os.lstat(fdpath(n))
                if (cur.st_dev, cur.st_ino) != (st.st_dev, st.st_ino):
                    nlink = 0
            except OSError:
                nlink = 0
    else:
        st = os.stat(path) if follow else os.lstat(path)
        nlink = st.st_nlink
except OSError:
    sys.exit(1)
uid, gid = owner(st)
out = fmt.replace("%u", str(uid)).replace("%g", str(gid)).replace("%a", "%o" % (st.st_mode & 0o7777))
out = out.replace("%d", str(st.st_dev)).replace("%i", str(st.st_ino)).replace("%h", str(nlink))
print(out)
"#,
    ),
    (
        "readlink",
        r#"
p = sys.argv[-1]
n = fdnum(p)
try:
    sys.stdout.write((fdpath(n) if n is not None else os.readlink(p)) + "\n")
except OSError:
    sys.exit(1)
"#,
    ),
    (
        "mktemp",
        r#"
a = sys.argv[1:]
assert a[:3] == ["-d", "-p", "."], a
tmpl = a[3]
k = len(tmpl) - len(tmpl.rstrip("X"))
while True:
    name = tmpl[:-k] + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(k))
    try:
        os.mkdir(name, 0o700)
        break
    except FileExistsError:
        continue
print("./" + name)
"#,
    ),
    (
        "setpriv",
        r#"
a = sys.argv[1:]
assert a[0] == "--regid" and a[2] == "--clear-groups", a
log("setpriv " + " ".join(a[:3]))
r = subprocess.run(a[3:], stdout=subprocess.PIPE)
if r.returncode:
    sys.exit(r.returncode)
name = r.stdout.decode().strip()
put(os.lstat(name).st_ino, gid=int(a[1]))
sys.stdout.write(r.stdout.decode())
"#,
    ),
    ("chown", r#"log("chown " + " ".join(sys.argv[1:]))"#),
    (
        "ln",
        r#"
a = sys.argv[1:]
assert a[:2] == ["-T", "--"], a
try:
    os.link(a[2], resolve(a[3]))
except OSError as e:
    sys.stderr.write("ln: %s\n" % e.strerror); sys.exit(1)
other_account_acts()
"#,
    ),
    (
        "mv",
        r#"
a = sys.argv[1:]
assert a[:3] == ["-T", "-f", "--"], a
try:
    os.rename(a[3], resolve(a[4]))
except OSError as e:
    sys.stderr.write("mv: %s\n" % e.strerror); sys.exit(1)
other_account_acts()
"#,
    ),
    (
        "find",
        r#"
a = sys.argv[1:]
log("find " + " ".join(a))
assert a[:2] == ["-P", "."], a
i, maxd, mind, preds = 2, None, 0, []
while i < len(a):
    t = a[i]
    if t == "-maxdepth":
        maxd = int(a[i + 1]); i += 2
    elif t == "-mindepth":
        mind = int(a[i + 1]); i += 2
    elif t in ("-name", "-type", "-user", "-gid", "-inum"):
        preds.append((t, a[i + 1])); i += 2
    elif t in ("-empty", "-delete"):
        preds.append((t, None)); i += 1
    else:
        sys.stderr.write("find stand-in: unexpected %s\n" % t); sys.exit(2)
assert maxd == 1 and preds[-1][0] == "-delete", a
rc = 0
for p in (["."] if mind == 0 else []) + ["./" + e for e in sorted(os.listdir("."))]:
    for t, v in preds:
        try:
            st = os.lstat(p)
        except OSError:
            break
        uid, gid = owner(st)
        if t == "-name":
            ok = fnmatch.fnmatchcase("." if p == "." else os.path.basename(p), v)
        elif t == "-type":
            ok = v == "d" and st_mod.S_ISDIR(st.st_mode)
        elif t == "-user":
            ok = uid == int(v)
        elif t == "-gid":
            ok = gid == int(v)
        elif t == "-inum":
            ok = st.st_ino == int(v)
        elif t == "-empty":
            ok = st_mod.S_ISDIR(st.st_mode) and not os.listdir(p)
        else:
            swap = os.environ.get("STUB_FIND_SWAP")
            if swap:
                # Another account swaps a directory of its own in between the checks and
                # the removal (unlinkat(AT_REMOVEDIR) of the name).
                os.rename(p, "./moved")
                os.mkdir(p, 0o755)
                put(os.lstat(p).st_ino, uid=1002, gid=1002)
                if swap == "full":
                    open(os.path.join(p, "theirs"), "w").write("x")
            try:
                ino = os.lstat(p).st_ino
                os.rmdir(p)
                drop(ino)
            except OSError as e:
                sys.stderr.write("find: cannot delete %s: %s\n" % (p, e.strerror)); rc = 1
            ok = True
        if not ok:
            break
sys.exit(rc)
"#,
    ),
];

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

struct Fx {
    tmp: tempfile::TempDir,
}

struct Staged {
    s: String,
    g: String,
    sid: String,
    pid: String,
}

impl Fx {
    /// `D`: a directory of the given mode.
    fn new(mode: u32) -> Self {
        let f = Fx {
            tmp: tempfile::tempdir().unwrap(),
        };
        let bin = f.path("bin");
        std::fs::create_dir(&bin).unwrap();
        for (name, body) in TOOLS {
            let p = bin.join(name);
            std::fs::write(&p, format!("{PRELUDE}\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(f.path("state"), "{}").unwrap();
        std::fs::write(f.path("log"), "").unwrap();
        std::fs::create_dir(f.path("d")).unwrap();
        f.chmod_d(mode);
        f
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.tmp.path().canonicalize().unwrap().join(rel)
    }

    fn d(&self) -> PathBuf {
        self.path("d")
    }

    fn chmod_d(&self, mode: u32) {
        std::fs::set_permissions(self.d(), std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn script(&self) -> String {
        let line = "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n";
        assert_eq!(SCRIPT.matches(line).count(), 1);
        assert_eq!(
            SCRIPT.matches("cd -P -- /proc/self/fd/4").count(),
            1,
            "the script enters <dir> through fd 4 once: update the cd stand-in"
        );
        let cd = "cd() { if [ \"$#\" = 3 ] && [ \"$3\" = /proc/self/fd/4 ]; then \
                  command cd -P -- \"$(fdpath 4)\"; else command cd \"$@\"; fi; }\n";
        format!(
            "{cd}{}",
            SCRIPT.replace(
                line,
                &format!("PATH='{}':/usr/bin:/bin\n", self.path("bin").display()),
            )
        )
    }

    fn run(&self, me: &str, args: &[&str], stdin: &[u8], env: &[(&str, &str)]) -> Out {
        use std::io::Write;
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(self.script()).arg("sh").args(args);
        c.env("STUB_LOG", self.path("log"))
            .env("STUB_STATE", self.path("state"))
            .env("STUB_ME", me)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            c.env(k, v);
        }
        let mut child = c.spawn().unwrap();
        let _ = child.stdin.take().unwrap().write_all(stdin);
        let o = child.wait_with_output().unwrap();
        Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    fn stage(&self, me: &str) -> Staged {
        let d = self.d();
        let o = self.run(
            me,
            &["stage", d.to_str().unwrap(), "-", "0640", "0", "0"],
            b"DATA\n",
            &[],
        );
        assert_eq!(o.code, 0, "stage: {:?} {:?}", o.stdout, o.stderr);
        let f: Vec<&str> = o.stdout.trim_end().split(' ').collect();
        assert_eq!(f.len(), 4, "{:?}", o.stdout);
        Staged {
            s: f[0].into(),
            g: f[1].into(),
            sid: f[2].into(),
            pid: f[3].into(),
        }
    }

    fn publish(&self, me: &str, kind: &str, st: &Staged, env: &[(&str, &str)]) -> Out {
        let d = self.d();
        self.run(
            me,
            &[
                "publish",
                kind,
                "file",
                d.to_str().unwrap(),
                "-",
                &st.s,
                &st.g,
                &st.sid,
                &st.pid,
                "x.conf",
            ],
            b"",
            env,
        )
    }

    fn discard(&self, me: &str, st: &Staged, g: &str) -> Out {
        let d = self.d();
        self.run(
            me,
            &["discard", d.to_str().unwrap(), "-", &st.s, g, &st.sid],
            b"",
            &[],
        )
    }

    fn entries(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.d())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn finds(&self) -> Vec<String> {
        std::fs::read_to_string(self.path("log"))
            .unwrap()
            .lines()
            .filter(|l| l.starts_with("find "))
            .map(String::from)
            .collect()
    }
}

fn cleanup_of(o: &Out) -> Cleanup {
    parse_cleanup(&Output {
        completion: Completion::Exited(o.code),
        stdout: o.stdout.as_bytes().to_vec(),
        stderr: o.stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    })
}

fn cleanup_lines(o: &Out) -> usize {
    o.stdout
        .lines()
        .filter(|l| l.starts_with("CLEANUP:"))
        .count()
}

/// D: root's directory others can write to, without the sticky bit.
const OPEN: u32 = 0o777;

#[test]
fn as_root_the_staging_directory_is_removed_in_a_writable_parent_when_its_identity_matches() {
    for kind in ["new", "replace"] {
        let f = Fx::new(OPEN);
        let st = f.stage("0");
        assert_ne!(st.g, "-", "as root the staging directory has the group G");
        let p = f.publish("0", kind, &st, &[]);
        assert_eq!(p.code, 0, "{kind}: {:?} {:?}", p.stdout, p.stderr);
        assert_eq!(p.stdout, "CLEANUP:clean\n", "{kind}");
        assert_eq!(cleanup_of(&p), Cleanup::Clean);
        assert_eq!(std::fs::read(f.d().join("x.conf")).unwrap(), b"DATA\n");
        assert_eq!(
            f.entries(),
            vec!["x.conf".to_string()],
            "{kind}: nothing left"
        );
        let ino = st.sid.split(':').nth(1).unwrap();
        assert_eq!(
            f.finds(),
            vec![format!(
                "find -P . -maxdepth 1 -mindepth 1 -name {} -type d -user 0 -gid {} -inum {ino} -empty -delete",
                st.s, st.g
            )],
            "{kind}: one entry, by name, owner, group G and inode"
        );
    }
    // discard takes the same way.
    let f = Fx::new(OPEN);
    let st = f.stage("0");
    let q = f.discard("0", &st, &st.g);
    assert_eq!(
        (q.code, q.stdout.as_str()),
        (0, "CLEANUP:clean\n"),
        "{}",
        q.stderr
    );
    assert!(f.entries().is_empty());
}

#[test]
fn a_staging_directory_renamed_away_is_left_and_reported_where_it_is() {
    let f = Fx::new(OPEN);
    let st = f.stage("0");
    let p = f.publish(
        "0",
        "new",
        &st,
        &[
            ("STUB_AFTER_PUBLISH", "rename"),
            ("STUB_NEWNAME", "theirs-now"),
        ],
    );
    assert_eq!(p.code, 0, "the publication stands: {:?}", p.stderr);
    let at = f.d().join("theirs-now");
    assert_eq!(p.stdout, format!("CLEANUP:left:{}\n", at.display()));
    assert_eq!(cleanup_of(&p), Cleanup::Left(at.display().to_string()));
    assert!(
        at.is_dir(),
        "nothing matched its name, so nothing was removed"
    );
    assert_eq!(std::fs::read(f.d().join("x.conf")).unwrap(), b"DATA\n");
}

#[test]
fn a_staging_directory_that_is_not_empty_is_never_removed() {
    let f = Fx::new(OPEN);
    let st = f.stage("0");
    let p = f.publish("0", "new", &st, &[("STUB_AFTER_PUBLISH", "fill")]);
    assert_eq!(p.code, 0, "{:?}", p.stderr);
    let s = f.d().join(&st.s);
    assert_eq!(p.stdout, format!("CLEANUP:left:{}\n", s.display()));
    assert_eq!(std::fs::read(s.join("theirs")).unwrap(), b"x");
}

#[test]
fn a_decoy_with_the_same_name_but_another_owner_group_or_inode_is_not_removed() {
    for decoy in ["decoy-owner", "decoy-group", "decoy-inode"] {
        let f = Fx::new(OPEN);
        let st = f.stage("0");
        let p = f.publish("0", "new", &st, &[("STUB_AFTER_PUBLISH", decoy)]);
        assert_eq!(p.code, 0, "{decoy}: {:?}", p.stderr);
        assert!(f.d().join(&st.s).is_dir(), "{decoy}: the decoy stays");
        let moved = f.d().join("moved");
        assert!(moved.is_dir(), "{decoy}");
        assert_eq!(
            p.stdout,
            format!("CLEANUP:left:{}\n", moved.display()),
            "{decoy}: read from the directory held open, not from the name"
        );
    }
}

#[test]
fn a_directory_swapped_in_after_the_checks_is_removed_only_when_empty_and_the_outcome_is_read_from_fd_5(
) {
    // The race of DESIGN §63.2 (c): between find's checks and its removal another account
    // puts its own directory at the name. An empty one is removed (that account could remove
    // it itself: D is writable and not sticky); a non-empty one never is. Either way the
    // staging directory itself is left and reported where it now is.
    for swap in ["empty", "full"] {
        let f = Fx::new(OPEN);
        let st = f.stage("0");
        let p = f.publish("0", "new", &st, &[("STUB_FIND_SWAP", swap)]);
        assert_eq!(p.code, 0, "{swap}: {:?}", p.stderr);
        let moved = f.d().join("moved");
        assert_eq!(
            p.stdout,
            format!("CLEANUP:left:{}\n", moved.display()),
            "{swap}"
        );
        let name = f.d().join(&st.s);
        if swap == "empty" {
            assert!(!name.exists(), "the swapped-in empty directory is gone");
        } else {
            assert_eq!(
                std::fs::read(name.join("theirs")).unwrap(),
                b"x",
                "a directory that is not empty is never removed"
            );
        }
    }
}

#[test]
fn a_renamed_name_with_a_newline_cannot_forge_a_second_cleanup_line() {
    for (name, why) in [
        (".sinter-stage.x\nCLEANUP:clean", "a forged clean"),
        ("x\nCLEANUP:unknown\n", "a forged unknown"),
        ("tab\there", "a tab"),
        ("esc\u{1b}[31m", "an escape sequence"),
    ] {
        let f = Fx::new(OPEN);
        let st = f.stage("0");
        let p = f.publish(
            "0",
            "new",
            &st,
            &[("STUB_AFTER_PUBLISH", "rename"), ("STUB_NEWNAME", name)],
        );
        assert_eq!(p.code, 0, "{why}: {:?}", p.stderr);
        assert_eq!(p.stdout, format!("CLEANUP:left:{UNSHOWN_PATH}\n"), "{why}");
        assert_eq!(cleanup_lines(&p), 1, "{why}");
        assert_eq!(cleanup_of(&p), Cleanup::Left(UNSHOWN_PATH.into()), "{why}");
        assert!(f.d().join(name).is_dir(), "{why}: left as it is");
    }
}

#[test]
fn a_parent_nobody_else_can_change_keeps_the_old_rule() {
    // Root, a parent of mode 0755: removed by name with the group G, as before (no
    // -mindepth, no inode).
    let f = Fx::new(0o755);
    let st = f.stage("0");
    let p = f.publish("0", "new", &st, &[]);
    assert_eq!(
        (p.code, p.stdout.as_str()),
        (0, "CLEANUP:clean\n"),
        "{}",
        p.stderr
    );
    assert_eq!(
        f.finds(),
        vec![format!(
            "find -P . -maxdepth 1 -name {} -type d -user 0 -gid {} -empty -delete",
            st.s, st.g
        )]
    );
    assert_eq!(f.entries(), vec!["x.conf".to_string()]);
    // Unprivileged, a parent of mode 0700: by name with the inode, as before.
    let f = Fx::new(0o700);
    let st = f.stage("1001");
    assert_eq!(st.g, "-");
    let p = f.publish("1001", "new", &st, &[]);
    assert_eq!(
        (p.code, p.stdout.as_str()),
        (0, "CLEANUP:clean\n"),
        "{}",
        p.stderr
    );
    let ino = st.sid.split(':').nth(1).unwrap();
    assert_eq!(
        f.finds(),
        vec![format!(
            "find -P . -maxdepth 1 -name {} -type d -user 1001 -inum {ino} -empty -delete",
            st.s
        )]
    );
    // A sticky parent that everyone can write to: as before.
    let f = Fx::new(0o1777);
    let st = f.stage("1001");
    let p = f.publish("1001", "new", &st, &[]);
    assert_eq!(
        (p.code, p.stdout.as_str()),
        (0, "CLEANUP:clean\n"),
        "{}",
        p.stderr
    );
}

#[test]
fn without_the_group_identity_nothing_is_removed_in_a_writable_parent() {
    // Unprivileged: staging there is refused before anything is made.
    let f = Fx::new(OPEN);
    let d = f.d();
    let o = f.run(
        "1001",
        &["stage", d.to_str().unwrap(), "-", "0640", "1001", "1001"],
        b"DATA\n",
        &[],
    );
    assert_eq!(o.code, 3, "{:?}", o.stderr);
    assert!(f.entries().is_empty());
    // Unprivileged, the parent became writable after staging: left, no removal attempted.
    let f = Fx::new(0o700);
    let st = f.stage("1001");
    f.chmod_d(OPEN);
    let p = f.publish("1001", "new", &st, &[]);
    assert_eq!(p.code, 0, "{:?}", p.stderr);
    let s = f.d().join(&st.s);
    assert_eq!(p.stdout, format!("CLEANUP:left:{}\n", s.display()));
    assert!(f.finds().is_empty(), "no removal is attempted");
    assert!(s.is_dir());
    // Root, but no group given ("-"): no identity, so no removal there either.
    let f = Fx::new(OPEN);
    let st = f.stage("0");
    let q = f.discard("0", &st, "-");
    assert_eq!(q.code, 0, "{:?}", q.stderr);
    assert_eq!(
        q.stdout,
        format!("CLEANUP:left:{}\n", f.d().join(&st.s).display())
    );
    assert!(f.finds().is_empty());
}

#[test]
fn a_link_count_that_cannot_be_read_is_unknown_and_the_publication_stands() {
    let f = Fx::new(OPEN);
    let st = f.stage("0");
    let p = f.publish("0", "new", &st, &[("STUB_NLINK_FAIL", "1")]);
    assert_eq!(
        (p.code, p.stdout.as_str()),
        (5, "CLEANUP:unknown\n"),
        "{}",
        p.stderr
    );
    assert_eq!(cleanup_of(&p), Cleanup::Unknown);
    assert_eq!(std::fs::read(f.d().join("x.conf")).unwrap(), b"DATA\n");
}

#[test]
fn the_stand_ins_see_what_the_script_made() {
    // Guard of the harness: the staging directory really is 0700, and the publication made
    // one file with the staged inode.
    let f = Fx::new(OPEN);
    let st = f.stage("0");
    let s = f.d().join(&st.s);
    assert_eq!(std::fs::metadata(&s).unwrap().mode() & 0o7777, 0o700);
    let pino = std::fs::metadata(s.join("payload")).unwrap().ino();
    let p = f.publish("0", "new", &st, &[]);
    assert_eq!(p.code, 0, "{:?}", p.stderr);
    assert_eq!(std::fs::metadata(f.d().join("x.conf")).unwrap().ino(), pino);
    assert!(Path::new(&f.d()).is_dir());
}
