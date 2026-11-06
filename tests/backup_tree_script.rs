//! The fixed backup script (`src/fsbackup.sh`, DESIGN §40.7) run for real under
//! `/bin/sh`, with stand-in tools instead of util-linux and coreutils: only `PATH`
//! in the text is changed, so every branch and all the quoting of the real script
//! run here. The stand-ins model GNU `stat`, `dd`, `touch` and `setpriv`, and can
//! behave as a hostile account would. They are not those tools: real behaviour is
//! `tests/backup_tree_real.rs`, on Linux as root.
#![cfg(unix)]

use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const OWNER: &str = "1001";

const TOOLS: &[(&str, &str)] = &[
    ("id", "print(0)"),
    (
        "setsid",
        r#"
assert sys.argv[1] == "-w"
open(os.environ["STUB_LOG"], "a").write("setsid\n")
os.execvp(sys.argv[2], sys.argv[2:])
"#,
    ),
    (
        "setpriv",
        r#"
args = sys.argv[1:]
open(os.environ["STUB_LOG"], "a").write("setpriv " + " ".join(args[: args.index("--")]) + "\n")
args = args[args.index("--") + 1:]
os.execvp(args[0], args)
"#,
    ),
    (
        "stat",
        r#"
assert sys.argv[1] == "-c"
path = sys.argv[sys.argv.index("--") + 1]
open(os.environ["STUB_LOG"], "a").write("stat-as-account " + path + "\n")
if os.environ.get("STUB_STAT"):
    print(os.environ["STUB_STAT"]); sys.exit(0)
try:
    st = os.lstat(path)
except OSError:
    sys.exit(1)
owner = os.environ.get("STUB_OWNER", "1001")
print("%x %s %s %d %d %d.%09d %d.%09d %d %d %d.%09d" % (st.st_mode, owner, "1001", st.st_nlink, st.st_size,
    int(st.st_mtime), st.st_mtime_ns % 10**9, int(st.st_ctime), st.st_ctime_ns % 10**9, st.st_dev, st.st_ino,
    int(st.st_atime), st.st_atime_ns % 10**9))
"#,
    ),
    (
        "dd",
        r#"
args = dict(a.split("=", 1) for a in sys.argv[1:])
assert "nofollow" in args["iflag"]
path = args["if"]
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
except OSError:
    sys.exit(1)
out = sys.stdout.buffer
data = os.read(fd, 1 << 24)
out.write(data)
out.write(os.environ.get("STUB_EXTRA", "").encode())
out.flush()
if os.environ.get("STUB_DD_FAIL"):
    sys.exit(1)
if os.environ.get("STUB_SWAP"):
    with open(path, "a") as f:
        f.write("changed while read")
"#,
    ),
    (
        "chmod",
        r#"os.chmod(sys.argv[sys.argv.index("--") + 1], int(sys.argv[1], 8))"#,
    ),
    (
        "chown",
        r#"open(os.environ["STUB_LOG"], "a").write("chown " + " ".join(sys.argv[1:]) + "\n")"#,
    ),
    (
        "touch",
        r#"
flag, _, stamp, _, path = sys.argv[1:]
t = float(stamp.lstrip("@"))
st = os.stat(path)
os.utime(path, (st.st_atime, t) if flag == "-m" else (t, st.st_mtime))
"#,
    ),
    (
        "getfacl",
        r#"print(os.environ.get("STUB_ACL", "user::rw-\nuser:1002:r--\ngroup::---\nmask::r--\nother::---"))"#,
    ),
    (
        "setfacl",
        r#"open(os.environ["STUB_LOG"], "a").write("setfacl " + sys.stdin.read().replace("\n", ",") + "\n")"#,
    ),
];

struct Fx {
    dir: tempfile::TempDir,
}

impl Fx {
    fn new() -> Self {
        let f = Fx {
            dir: tempfile::tempdir().unwrap(),
        };
        let bin = f.path("bin");
        std::fs::create_dir(&bin).unwrap();
        for (name, body) in TOOLS {
            let p = bin.join(name);
            std::fs::write(
                &p,
                format!("#!/usr/bin/env python3\nimport os, sys\n{body}\n"),
            )
            .unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::create_dir(f.path("store")).unwrap();
        std::fs::write(f.path("log"), "").unwrap();
        f
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn source(&self, name: &str, body: &str, mode: u32) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    fn script(&self) -> String {
        let text = sinter::fsbackup::SCRIPT;
        let line = "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n";
        assert_eq!(text.matches(line).count(), 1);
        text.replace(
            line,
            &format!("PATH='{}':/usr/bin:/bin\n", self.path("bin").display()),
        )
    }

    fn run_args(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(self.script()).arg("sh").args(args);
        c.env("STUB_LOG", self.path("log"));
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    }

    fn copy(&self, src: &Path, acl: &str, env: &[(&str, &str)]) -> Output {
        let dest = self.path("store/copy");
        self.run_args(
            &[
                OWNER,
                "1001",
                src.to_str().unwrap(),
                dest.to_str().unwrap(),
                "1000",
                acl,
            ],
            env,
        )
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.path("log")).unwrap()
    }
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn assert_refused(f: &Fx, o: &Output, says: &str) {
    assert_eq!(o.status.code(), Some(3), "{}", err(o));
    assert!(err(o).contains(says), "wanted {says:?} in {}", err(o));
    assert!(
        !f.path("store/copy").exists(),
        "a refused copy leaves nothing"
    );
}

#[test]
fn the_digest_in_the_binary_is_this_script() {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(sinter::fsbackup::SCRIPT.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, sinter::fsbackup::SCRIPT_SHA256);
}

#[test]
fn a_private_file_is_copied_with_its_metadata() {
    let f = Fx::new();
    let src = f.source("pgpass", "secret-canary-content", 0o600);
    let old = 1_600_000_000i64;
    let times = std::fs::FileTimes::new()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(old as u64));
    std::fs::OpenOptions::new()
        .write(true)
        .open(&src)
        .unwrap()
        .set_times(times)
        .unwrap();
    let o = f.copy(&src, "0", &[]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(String::from_utf8_lossy(&o.stdout), "OK 21\n");
    let dest = f.path("store/copy");
    assert_eq!(
        std::fs::read_to_string(&dest).unwrap(),
        "secret-canary-content"
    );
    let md = std::fs::metadata(&dest).unwrap();
    assert_eq!(md.mode() & 0o7777, 0o600);
    assert_eq!(md.mtime(), old);
    let log = f.log();
    assert!(log.contains("chown 1001:1001 -- "), "{log}");
    // The source is only ever touched through the identity switch.
    assert!(
        log.contains("setpriv --reuid 1001 --regid 1001 --init-groups --no-new-privs"),
        "{log}"
    );
    assert!(log.matches("stat-as-account").count() == 2, "{log}");
    assert!(!err(&o).contains("secret-canary"), "{}", err(&o));
    assert!(!String::from_utf8_lossy(&o.stdout).contains("secret-canary"));
    assert!(!log.contains("secret-canary"), "{log}");
}

#[test]
fn hostile_names_stay_arguments() {
    let f = Fx::new();
    for name in [
        "a b",
        "-rf",
        "x;touch pwned",
        "$(touch pwned)",
        "q'uo\"te",
        "new\nline",
    ] {
        let src = f.source(name, "x", 0o600);
        let o = f.copy(&src, "0", &[]);
        assert_eq!(o.status.code(), Some(0), "{name:?}: {}", err(&o));
        std::fs::remove_file(f.path("store/copy")).unwrap();
    }
    assert!(!f.path("pwned").exists());
    assert!(!Path::new("pwned").exists());
}

#[test]
fn only_a_plain_file_of_the_account_is_copied() {
    let f = Fx::new();
    let src = f.source("plain", "x", 0o600);

    let link = f.path("link");
    symlink(f.path("plain"), &link).unwrap();
    assert_refused(&f, &f.copy(&link, "0", &[]), "not a regular file");

    let d = f.path("adir");
    std::fs::create_dir(&d).unwrap();
    assert_refused(&f, &f.copy(&d, "0", &[]), "not a regular file");

    let o = f.copy(&src, "0", &[("STUB_OWNER", "1002")]);
    assert_refused(&f, &o, "not owned by the account");

    let hard = f.source("hard", "x", 0o600);
    std::fs::hard_link(&hard, f.path("hard2")).unwrap();
    assert_refused(&f, &f.copy(&hard, "0", &[]), "more than one hard link");

    let suid = f.source("suid", "x", 0o4755);
    assert_refused(&f, &f.copy(&suid, "0", &[]), "setuid or setgid");

    let big = f.source("big", &"x".repeat(1001), 0o600);
    assert_refused(&f, &f.copy(&big, "0", &[]), "larger than the limit");

    let absent = f.path("absent");
    assert_refused(&f, &f.copy(&absent, "0", &[]), "cannot observe");
}

#[test]
fn what_the_account_says_is_not_believed() {
    let f = Fx::new();
    let src = f.source("plain", "x", 0o600);
    // Metadata that is not metadata.
    for bad in [
        "garbage",
        "; rm -rf /tmp/never",
        "$(touch pwned)",
        "81a4 1001 1001 1 1",
        "81a4 1001 1001 1 1 1.0 1.0 1 1 1.0 extra",
        "zzzz 1001 1001 1 1 1.0 1.0 1 1 1.0",
        "81a4 1001 1001 1 -1 1.0 1.0 1 1 1.0",
        "81a4 1001 1001 1 1 1.0.0 1.0 1 1 1.0",
        "123456789 1001 1001 1 1 1.0 1.0 1 1 1.0",
    ] {
        let o = f.copy(&src, "0", &[("STUB_STAT", bad)]);
        assert_refused(&f, &o, "unexpected metadata");
    }
    assert!(!f.path("pwned").exists() && !Path::new("pwned").exists());
    // More bytes than it said (a tampered reader): refused and removed.
    let o = f.copy(&src, "0", &[("STUB_EXTRA", "more")]);
    assert_refused(&f, &o, "does not have the size");
    // An endless reader is cut at the limit.
    let long = "y".repeat(5000);
    let o = f.copy(&src, "0", &[("STUB_EXTRA", &long)]);
    assert_eq!(o.status.code(), Some(3), "{}", err(&o));
    assert!(!f.path("store/copy").exists());
    // A file that changes while it is read.
    let o = f.copy(&src, "0", &[("STUB_SWAP", "1")]);
    assert_refused(&f, &o, "changed while it was being read");
    let src = f.source("plain2", "x", 0o600);
    // A read that fails.
    let o = f.copy(&src, "0", &[("STUB_DD_FAIL", "1")]);
    assert_refused(&f, &o, "cannot read the file as its account");
}

#[test]
fn an_existing_destination_is_never_replaced() {
    let f = Fx::new();
    let src = f.source("plain", "x", 0o600);
    let dest = f.path("store/copy");
    std::fs::write(&dest, "older").unwrap();
    let o = f.copy(&src, "0", &[]);
    assert_eq!(o.status.code(), Some(3), "{}", err(&o));
    assert!(err(&o).contains("destination exists"), "{}", err(&o));
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "older");
    // A link at the destination is not written through.
    std::fs::remove_file(&dest).unwrap();
    let elsewhere = f.path("elsewhere");
    symlink(&elsewhere, &dest).unwrap();
    let o = f.copy(&src, "0", &[]);
    assert_eq!(o.status.code(), Some(3), "{}", err(&o));
    assert!(!elsewhere.exists());
}

#[test]
fn an_acl_travels_only_as_acl_text() {
    let f = Fx::new();
    let src = f.source("plain", "x", 0o640);
    let o = f.copy(&src, "1", &[]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert!(
        f.log().contains("setfacl user::rw-,user:1002:r--"),
        "{}",
        f.log()
    );
    std::fs::remove_file(f.path("store/copy")).unwrap();
    let o = f.copy(&src, "1", &[("STUB_ACL", "user::rw-\n$(touch pwned)")]);
    assert_refused(&f, &o, "unexpected ACL text");
    assert!(!f.path("pwned").exists());
    // Text over the cap is refused, not cut.
    let long = "u".repeat(70000);
    let o = f.copy(&src, "1", &[("STUB_ACL", &long)]);
    assert_refused(&f, &o, "unexpected ACL text");
}

#[test]
fn bad_arguments_and_a_non_root_shell_are_refused() {
    let f = Fx::new();
    let src = f.source("plain", "x", 0o600);
    let s = src.to_str().unwrap();
    let dest = f.path("store/copy");
    let d = dest.to_str().unwrap();
    for args in [
        vec![],
        vec![OWNER, "1001", s, d, "1000"],
        vec!["x", "1001", s, d, "1000", "0"],
        vec![OWNER, "1;1", s, d, "1000", "0"],
        vec![OWNER, "1001", "rel", d, "1000", "0"],
        vec![OWNER, "1001", s, "rel", "1000", "0"],
        vec![OWNER, "1001", s, d, "-1", "0"],
        vec![OWNER, "1001", s, d, "1000", "2"],
        vec!["0", "0", s, d, "1000", "0"],
    ] {
        let o = f.run_args(&args, &[]);
        assert_eq!(o.status.code(), Some(3), "{args:?}: {}", err(&o));
    }
    std::fs::write(f.path("bin/id"), "#!/bin/sh\necho 1000\n").unwrap();
    let o = f.copy(&src, "0", &[]);
    assert_refused(&f, &o, "not running as root");
}
