//! FS-2 I4/I5: the fixed staging script (`src/fsstage.sh`) itself, run for real.
//!
//! `fs2_staging_script.rs` tests how the product reads the script's answers against a model of
//! it; nothing there runs the script. These tests run the very text the binary carries
//! (`sinter::fsstage::SCRIPT`) as `sh -c <script> sh <op> <args…>` on a Linux host, in private
//! directories, with dummy content, and check what really happens on disk: `ln -T` and `mv -T`
//! never create anything inside an existing directory or link, a publication goes to the
//! directory that was pinned and not to whatever its path leads to later, a refusal publishes
//! nothing, the trap removes a staging directory whose fill failed, and the script survives
//! the failures it used to trip over.
//!
//! `SINTER_TEST_SH` selects the shell that runs the script (default `sh`): run the suite with
//! `SINTER_TEST_SH=dash` on a Debian/Ubuntu host to exercise dash. Root-only behaviour (the
//! group identity) is covered when the suite itself runs as root.
#![cfg(target_os = "linux")]

use sinter::fsstage::SCRIPT;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

fn shell() -> String {
    std::env::var("SINTER_TEST_SH").unwrap_or_else(|_| "sh".to_string())
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Run a script text. `env` entries are passed to the shell (a test hook for the variants).
fn run_script(script: &str, args: &[&str], stdin: &[u8], env: &[(&str, &str)], cwd: &Path) -> Out {
    let mut cmd = Command::new(shell());
    cmd.arg("-c").arg(script).arg("sh").args(args);
    cmd.current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn the shell");
    {
        let mut si = child.stdin.take().unwrap();
        let _ = si.write_all(stdin);
    }
    let o = child.wait_with_output().unwrap();
    use std::os::unix::process::ExitStatusExt;
    Out {
        code: o
            .status
            .code()
            .unwrap_or_else(|| 128 + o.status.signal().unwrap_or(0)),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn run(args: &[&str]) -> Out {
    run_script(SCRIPT, args, b"", &[], Path::new("/"))
}

/// A private working directory: 0700, owned by the test user, so an unprivileged run
/// accepts it as a directory nobody else can rename entries in.
fn work() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let d = t.path().canonicalize().unwrap().join("w");
    fs::create_dir(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
    (t, d)
}

fn id(flag: &str) -> String {
    let o = Command::new("id").arg(flag).output().unwrap();
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}

struct Staged {
    s: String,
    g: String,
    sid: String,
    pid: String,
}

fn stage_with(
    script: &str,
    env: &[(&str, &str)],
    dir: &Path,
    content: &[u8],
    mode: &str,
) -> (Out, Option<Staged>) {
    let (uid, gid) = (id("-u"), id("-g"));
    let out = run_script(
        script,
        &["stage", dir.to_str().unwrap(), "-", mode, &uid, &gid],
        content,
        env,
        Path::new("/"),
    );
    let st = if out.code == 0 {
        let f: Vec<&str> = out.stdout.lines().last().unwrap_or("").split(' ').collect();
        assert_eq!(f.len(), 4, "stage answer: {:?}", out.stdout);
        Some(Staged {
            s: f[0].to_string(),
            g: f[1].to_string(),
            sid: f[2].to_string(),
            pid: f[3].to_string(),
        })
    } else {
        None
    };
    (out, st)
}

fn stage(dir: &Path, content: &[u8]) -> Staged {
    let (o, st) = stage_with(SCRIPT, &[], dir, content, "0640");
    st.unwrap_or_else(|| panic!("stage failed: rc {} {:?} {:?}", o.code, o.stdout, o.stderr))
}

fn publish_with(
    script: &str,
    env: &[(&str, &str)],
    kind: &str,
    what: &str,
    dir: &Path,
    st: &Staged,
    base: &str,
) -> Out {
    run_script(
        script,
        &[
            "publish",
            kind,
            what,
            dir.to_str().unwrap(),
            "-",
            &st.s,
            &st.g,
            &st.sid,
            &st.pid,
            base,
        ],
        b"",
        env,
        Path::new("/"),
    )
}

fn publish(kind: &str, dir: &Path, st: &Staged, base: &str) -> Out {
    publish_with(SCRIPT, &[], kind, "file", dir, st, base)
}

fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn strays(dir: &Path) -> Vec<String> {
    entries(dir)
        .into_iter()
        .filter(|n| n.starts_with(".sinter-stage."))
        .collect()
}

fn last_line(o: &Out) -> &str {
    o.stdout.lines().last().unwrap_or("")
}

#[test]
fn stage_then_publish_new_makes_the_file_and_leaves_nothing_behind() {
    let (_t, d) = work();
    let st = stage(&d, b"DATA\n");
    assert_eq!(
        strays(&d),
        vec![st.s.clone()],
        "the staging directory is left for publish"
    );
    let p = publish("new", &d, &st, "t.conf");
    assert_eq!(p.code, 0, "{p:?}", p = (p.code, &p.stdout, &p.stderr));
    assert_eq!(last_line(&p), "CLEANUP:clean");
    assert_eq!(fs::read(d.join("t.conf")).unwrap(), b"DATA\n");
    assert_eq!(
        fs::metadata(d.join("t.conf")).unwrap().mode() & 0o7777,
        0o640
    );
    assert_eq!(
        entries(&d),
        vec!["t.conf".to_string()],
        "no staging directory remains"
    );
}

#[test]
fn publish_new_never_replaces_or_enters_an_existing_name() {
    // `ln -T`: without -T a name that is a directory (or a link to one) makes the file appear
    // inside it; with it every one of these is a failed publication that changes nothing.
    for kind in [
        "file",
        "dir",
        "symlink-to-dir",
        "dangling",
        "symlink-to-file",
        "fifo",
    ] {
        let (_t, d) = work();
        let other = d.join("other");
        fs::create_dir(&other).unwrap();
        let name = d.join("t.conf");
        match kind {
            "file" => fs::write(&name, b"THEIRS\n").unwrap(),
            "dir" => fs::create_dir(&name).unwrap(),
            "symlink-to-dir" => symlink(&other, &name).unwrap(),
            "dangling" => symlink(d.join("missing"), &name).unwrap(),
            "symlink-to-file" => {
                fs::write(d.join("real"), b"REAL\n").unwrap();
                symlink(d.join("real"), &name).unwrap();
            }
            "fifo" => {
                assert!(Command::new("mkfifo")
                    .arg(&name)
                    .status()
                    .unwrap()
                    .success());
            }
            _ => unreachable!(),
        }
        let before = fs::symlink_metadata(&name).unwrap();
        let st = stage(&d, b"DATA\n");
        let p = publish("new", &d, &st, "t.conf");
        assert_eq!(p.code, 4, "{kind}: {:?} {:?}", p.stdout, p.stderr);
        assert_eq!(last_line(&p), "CLEANUP:clean", "{kind}");
        let after = fs::symlink_metadata(&name).unwrap();
        assert_eq!(
            (before.ino(), before.mode()),
            (after.ino(), after.mode()),
            "{kind}: the name is untouched"
        );
        assert!(
            entries(&other).is_empty(),
            "{kind}: nothing was made inside the directory"
        );
        assert!(
            !d.join("missing").exists(),
            "{kind}: a dangling link was not followed"
        );
        if kind == "file" {
            assert_eq!(fs::read(&name).unwrap(), b"THEIRS\n");
        }
        if kind == "symlink-to-file" {
            assert_eq!(fs::read(d.join("real")).unwrap(), b"REAL\n");
        }
        if kind == "dir" {
            assert!(entries(&name).is_empty(), "nothing inside the directory");
        }
        assert!(
            strays(&d).is_empty(),
            "{kind}: the staging directory was cleaned up"
        );
    }
}

#[test]
fn publish_replace_never_enters_a_directory_and_replaces_a_link_by_itself() {
    // `mv -T -f`: onto a directory it fails (and the directory stays empty); onto a link to a
    // directory it replaces the link, never the directory the link points to.
    let (_t, d) = work();
    let dir_name = d.join("t.conf");
    fs::create_dir(&dir_name).unwrap();
    let st = stage(&d, b"DATA\n");
    let p = publish("replace", &d, &st, "t.conf");
    assert_eq!(p.code, 4, "{:?} {:?}", p.stdout, p.stderr);
    assert!(
        dir_name.is_dir() && entries(&dir_name).is_empty(),
        "nothing moved into the directory"
    );
    assert!(strays(&d).is_empty());

    let (_t, d) = work();
    let other = d.join("other");
    fs::create_dir(&other).unwrap();
    fs::write(other.join("keep"), b"K").unwrap();
    symlink(&other, d.join("t.conf")).unwrap();
    let st = stage(&d, b"DATA\n");
    let p = publish("replace", &d, &st, "t.conf");
    assert_eq!(p.code, 0, "{:?} {:?}", p.stdout, p.stderr);
    assert!(
        fs::symlink_metadata(d.join("t.conf"))
            .unwrap()
            .file_type()
            .is_file(),
        "the link itself was replaced"
    );
    assert_eq!(fs::read(d.join("t.conf")).unwrap(), b"DATA\n");
    assert_eq!(
        entries(&other),
        vec!["keep".to_string()],
        "the directory it pointed to is untouched"
    );

    let (_t, d) = work();
    fs::write(d.join("t.conf"), b"OLD\n").unwrap();
    let st = stage(&d, b"NEW\n");
    let p = publish("replace", &d, &st, "t.conf");
    assert_eq!(p.code, 0);
    assert_eq!(fs::read(d.join("t.conf")).unwrap(), b"NEW\n");
    assert!(strays(&d).is_empty());
}

#[test]
fn a_publication_goes_to_the_pinned_directory_not_to_the_path() {
    // The script's publish arm, with the directory renamed away and a decoy put at its path
    // right after the directory was pinned. The file must land in the pinned (renamed)
    // directory: the final name is resolved through fd 4, not through the path.
    let anchor = "  enter_s \"$dir\" \"$did\" \"$s\" \"$G\" \"$sid\"\n";
    assert!(
        SCRIPT.matches(anchor).count() == 1,
        "the publish arm changed: update this test"
    );
    let variant = SCRIPT.replacen(
        anchor,
        &format!("{anchor}  mv -- \"$dir\" \"$dir.moved\"; mkdir -m 755 -- \"$dir\"\n"),
        1,
    );
    // `new` (ln -T) and `replace` (mv -T -f) are two different commands: both are checked.
    for kind in ["new", "replace"] {
        let (_t, d) = work();
        let st = stage(&d, b"DATA\n");
        let p = publish_with(&variant, &[], kind, "file", &d, &st, "t.conf");
        let moved = PathBuf::from(format!("{}.moved", d.display()));
        assert_eq!(p.code, 0, "{kind}: {:?} {:?}", p.stdout, p.stderr);
        assert_eq!(
            fs::read(moved.join("t.conf")).unwrap(),
            b"DATA\n",
            "{kind}: published into the pinned directory"
        );
        assert!(
            entries(&d).is_empty(),
            "{kind}: the decoy at the path stays empty"
        );
    }
}

#[test]
fn a_directory_identity_that_does_not_match_is_refused_and_a_matching_one_is_accepted() {
    let (_t, d) = work();
    let (uid, gid) = (id("-u"), id("-g"));
    let ds = Command::new("stat")
        .args(["-c", "%d:%i"])
        .arg(&d)
        .output()
        .unwrap();
    let did = String::from_utf8(ds.stdout).unwrap().trim().to_string();
    let o = run(&["stage", d.to_str().unwrap(), "1:1", "0640", &uid, &gid]);
    assert_eq!(o.code, 3, "{:?}", o.stderr);
    assert!(entries(&d).is_empty());
    let o = run_script(
        SCRIPT,
        &["stage", d.to_str().unwrap(), &did, "0640", &uid, &gid],
        b"DATA\n",
        &[],
        Path::new("/"),
    );
    assert_eq!(o.code, 0, "{:?}", o.stderr);
    assert_eq!(strays(&d).len(), 1);
}

#[test]
fn a_refused_publication_publishes_nothing_and_removes_nothing_that_is_not_its_own() {
    let (_t, d) = work();
    let st = stage(&d, b"DATA\n");
    // a wrong payload identity
    let bad = Staged {
        pid: "1:1".into(),
        s: st.s.clone(),
        g: st.g.clone(),
        sid: st.sid.clone(),
    };
    let p = publish("new", &d, &bad, "t.conf");
    assert_eq!(p.code, 3, "{:?}", p.stderr);
    assert!(p.stderr.contains("REJECT"), "{}", p.stderr);
    assert!(!d.join("t.conf").exists());
    assert_eq!(strays(&d), vec![st.s.clone()], "a refusal removes nothing");

    // the staging directory replaced by someone else's directory of the same name
    let s_path = d.join(&st.s);
    fs::rename(&s_path, d.join("moved-away")).unwrap();
    fs::create_dir(&s_path).unwrap();
    fs::write(s_path.join("payload"), b"THEIRS").unwrap();
    let p = publish("new", &d, &st, "t.conf");
    assert_eq!(p.code, 3, "{:?}", p.stderr);
    assert_eq!(
        fs::read(s_path.join("payload")).unwrap(),
        b"THEIRS",
        "their directory is not touched"
    );
    assert!(!d.join("t.conf").exists());
    let q = run(&["discard", d.to_str().unwrap(), "-", &st.s, &st.g, &st.sid]);
    assert_eq!(q.code, 3, "discard also refuses: {:?}", q.stderr);
    assert_eq!(fs::read(s_path.join("payload")).unwrap(), b"THEIRS");
}

#[test]
fn discard_removes_the_staging_directory_it_made() {
    let (_t, d) = work();
    let st = stage(&d, b"DATA\n");
    let q = run(&["discard", d.to_str().unwrap(), "-", &st.s, &st.g, &st.sid]);
    assert_eq!(q.code, 0, "{:?}", q.stderr);
    assert_eq!(last_line(&q), "CLEANUP:clean");
    assert!(entries(&d).is_empty());
}

#[test]
fn a_directory_that_is_not_an_absolute_path_is_refused_before_anything_is_made() {
    let (_t, d) = work();
    let (uid, gid) = (id("-u"), id("-g"));
    for rel in ["", ".", "w", "../w"] {
        let o = run_script(
            SCRIPT,
            &["stage", rel, "-", "0640", &uid, &gid],
            b"X",
            &[],
            d.parent().unwrap(),
        );
        assert_eq!(o.code, 3, "{rel:?}: {:?}", o.stderr);
        assert!(
            strays(d.parent().unwrap()).is_empty() && strays(&d).is_empty(),
            "{rel:?}: nothing made"
        );
        let o = run_script(
            SCRIPT,
            &["stagelink", rel, "-", "/x"],
            b"",
            &[],
            d.parent().unwrap(),
        );
        assert_eq!(o.code, 3, "link {rel:?}: {:?}", o.stderr);
        assert!(strays(d.parent().unwrap()).is_empty() && strays(&d).is_empty());
    }
}

#[test]
fn a_fill_that_fails_removes_its_staging_directory() {
    // The payload cannot be written (file size limit): the EXIT trap removes the staging
    // directory and says so; no secret-bearing leftover.
    let (_t, d) = work();
    let (uid, gid) = (id("-u"), id("-g"));
    let big = vec![b'x'; 65536];
    let mut cmd = Command::new(shell());
    cmd.arg("-c")
        .arg("ulimit -f 1; exec \"$@\"")
        .arg("x")
        .arg(shell())
        .arg("-c")
        .arg(SCRIPT)
        .arg("sh")
        .args(["stage", d.to_str().unwrap(), "-", "0640", &uid, &gid])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let mut si = child.stdin.take().unwrap();
    let _ = si.write_all(&big);
    drop(si);
    let o = child.wait_with_output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(!o.status.success(), "the stage failed");
    assert!(
        out.lines()
            .last()
            .unwrap_or("")
            .starts_with("CLEANUP:clean"),
        "{out:?}"
    );
    assert!(
        strays(&d).is_empty(),
        "nothing is left behind: {:?}",
        entries(&d)
    );
}

/// A variant that makes the named `stat` call fail, as a shell function in front of the script.
fn with_failing_stat(cond: &str) -> String {
    // `set -eu` and the script's PATH reset come after this line, so the function is what the
    // script's `stat` resolves to.
    format!("stat() {{ if {cond}; then return 1; fi; command stat \"$@\"; }}\n{SCRIPT}")
}

#[test]
fn a_payload_identity_that_cannot_be_read_fails_the_stage_and_cleans_up() {
    let (_t, d) = work();
    let v = with_failing_stat(
        "[ \"${FAILPAYLOAD-}\" = 1 ] && [ \"$2\" = '%d:%i' ] && [ \"$3\" = payload ]",
    );
    let (o, st) = stage_with_env(&v, &[("FAILPAYLOAD", "1")], &d);
    assert!(
        st.is_none(),
        "no answer is given: rc {} {:?}",
        o.code,
        o.stdout
    );
    assert_ne!(o.code, 0);
    assert!(
        !o.stdout.lines().any(|l| l.starts_with(".sinter-stage.")),
        "no stage answer: {:?}",
        o.stdout
    );
    assert!(
        strays(&d).is_empty(),
        "the trap removed the staging directory: {:?}",
        entries(&d)
    );
}

fn stage_with_env(script: &str, env: &[(&str, &str)], d: &Path) -> (Out, Option<Staged>) {
    stage_with(script, env, d, b"DATA\n", "0640")
}

#[test]
fn a_cleanup_check_that_fails_after_the_publication_does_not_undo_it() {
    // After `ln`, the staging directory's parent cannot be classified (`stat` fails): the
    // directory is left and reported, the script ends normally. It used to die with an unbound
    // variable (exit 1) after the file was already published.
    let (_t, d) = work();
    let st = stage(&d, b"DATA\n");
    let v = with_failing_stat("[ \"${FAILTRUSTED-}\" = 1 ] && [ \"$2\" = '%u %a' ]");
    let p = publish_with(
        &v,
        &[("FAILTRUSTED", "1")],
        "new",
        "file",
        &d,
        &st,
        "t.conf",
    );
    assert_eq!(p.code, 0, "{:?} {:?}", p.stdout, p.stderr);
    assert_eq!(fs::read(d.join("t.conf")).unwrap(), b"DATA\n", "published");
    assert!(
        last_line(&p).starts_with("CLEANUP:left:/"),
        "{:?}",
        p.stdout
    );
    assert_eq!(
        strays(&d),
        vec![st.s.clone()],
        "the empty directory is left, as reported"
    );
    assert!(entries(&d.join(&st.s)).is_empty());
}

#[test]
fn the_cleanup_line_carries_the_path_verbatim() {
    // `echo` in dash interprets backslash sequences; the path must come out unchanged.
    let t = tempfile::tempdir().unwrap();
    let d = t.path().canonicalize().unwrap().join("a\\nb\\tc");
    fs::create_dir(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
    let st = stage(&d, b"DATA\n");
    let v = with_failing_stat("[ \"${FAILTRUSTED-}\" = 1 ] && [ \"$2\" = '%u %a' ]");
    let p = publish_with(
        &v,
        &[("FAILTRUSTED", "1")],
        "new",
        "file",
        &d,
        &st,
        "t.conf",
    );
    assert_eq!(p.code, 0, "{:?} {:?}", p.stdout, p.stderr);
    assert_eq!(
        last_line(&p),
        format!("CLEANUP:left:{}/{}", d.display(), st.s),
        "the backslashes survive"
    );
}

#[test]
fn a_filesystem_whose_new_directories_do_not_have_link_count_2_still_stages() {
    // The identity of the staging directory is owner, group (root), mode, emptiness and the
    // name it was made under: not its link count (btrfs, for one, reports 1).
    let (_t, d) = work();
    let v = format!(
        "stat() {{ if [ \"$1\" = -c ] && [ \"$2\" = '%a %h' ] && [ \"$3\" = . ]; then echo '700 3'; else command stat \"$@\"; fi; }}\n{SCRIPT}"
    );
    let (o, st) = stage_with_env(&v, &[], &d);
    assert!(st.is_some(), "rc {} {:?} {:?}", o.code, o.stdout, o.stderr);
    assert!(
        !SCRIPT.contains("%a %h"),
        "the link count is not part of the proof"
    );
}

#[test]
fn a_refusal_after_the_directory_was_made_says_a_stray_may_remain() {
    // Contract: nothing existing is removed on a refusal (no deletion that guesses); the empty
    // directory just made may stay, and the message says so.
    let (_t, d) = work();
    let v = SCRIPT.replace("!= 700 ]", "!= 7000 ]");
    assert_ne!(v, SCRIPT, "the mode check changed: update this test");
    let (o, st) = stage_with_env(&v, &[], &d);
    assert!(st.is_none());
    assert_eq!(o.code, 3, "{:?}", o.stderr);
    assert!(
        o.stderr.contains("stray .sinter-stage.* may remain"),
        "{}",
        o.stderr
    );
    assert!(
        entries(&d).iter().all(|n| n.starts_with(".sinter-stage.")),
        "nothing else was touched"
    );
}

#[test]
fn a_setgid_directory_and_a_directory_others_can_change_are_refused_before_anything_is_made() {
    let (_t, d) = work();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o2700)).unwrap();
    let (uid, gid) = (id("-u"), id("-g"));
    let o = run(&["stage", d.to_str().unwrap(), "-", "0640", &uid, &gid]);
    assert_eq!(o.code, 3, "{:?}", o.stderr);
    assert!(o.stderr.contains("setgid"), "{}", o.stderr);
    assert!(entries(&d).is_empty());

    if !is_root() {
        // unprivileged: a group- or other-writable directory without the sticky bit
        for mode in [0o770, 0o707, 0o777] {
            fs::set_permissions(&d, fs::Permissions::from_mode(mode)).unwrap();
            let o = run(&["stage", d.to_str().unwrap(), "-", "0640", &uid, &gid]);
            assert_eq!(o.code, 3, "{mode:o}: {:?}", o.stderr);
            assert!(entries(&d).is_empty(), "{mode:o}");
        }
        // with the sticky bit and our own ownership it is accepted
        fs::set_permissions(&d, fs::Permissions::from_mode(0o1777)).unwrap();
        let st = stage(&d, b"DATA\n");
        let p = publish("new", &d, &st, "t.conf");
        assert_eq!(p.code, 0, "{:?}", p.stderr);
    }
}

#[test]
fn malformed_arguments_are_refused() {
    let (_t, d) = work();
    for args in [
        vec![],
        vec!["nonsense"],
        vec!["stage", "/x"],
        vec!["publish", "new", "file", "/x"],
        vec![
            "discard",
            "/x",
            "-",
            ".sinter-stage.AbCd1234",
            "-",
            "1:1",
            "extra",
        ],
    ] {
        let o = run(&args);
        assert_eq!(o.code, 3, "{args:?}: {:?}", o.stderr);
    }
    // a stage name that is not ours is never entered or removed
    let victim = d.join("victim");
    fs::create_dir(&victim).unwrap();
    let o = run(&["discard", d.to_str().unwrap(), "-", "victim", "-", "1:1"]);
    assert_eq!(o.code, 3, "{:?}", o.stderr);
    assert!(victim.is_dir());
    // ... not even when it is ours, empty, and its identity is given correctly
    let vid = Command::new("stat")
        .args(["-c", "%d:%i"])
        .arg(&victim)
        .output()
        .unwrap();
    let vid = String::from_utf8(vid.stdout).unwrap().trim().to_string();
    let o = run(&["discard", d.to_str().unwrap(), "-", "victim", "-", &vid]);
    assert_eq!(o.code, 3, "{:?}", o.stderr);
    assert!(
        victim.is_dir(),
        "a directory that is not named .sinter-stage.* is never removed"
    );
}

#[test]
fn a_link_or_rename_that_dies_by_a_signal_is_not_reported_as_not_published() {
    // `ln` / `mv` do the work and are then reported as killed (status above 128): the name may
    // exist, so the script must not answer 4 ("nothing published") and must not clean up.
    for (kind, tool) in [("new", "ln"), ("replace", "mv")] {
        let (_t, d) = work();
        let st = stage(&d, b"DATA\n");
        let v = format!("{tool}() {{ command {tool} \"$@\"; return 137; }}\n{SCRIPT}");
        let p = publish_with(&v, &[], kind, "file", &d, &st, "t.conf");
        assert_eq!(
            fs::read(d.join("t.conf")).unwrap(),
            b"DATA\n",
            "{kind}: it was published"
        );
        assert_eq!(p.code, 1, "{kind}: {:?} {:?}", p.stdout, p.stderr);
        assert_ne!(p.code, 4, "{kind}");
        assert!(
            !p.stdout.contains("CLEANUP:"),
            "{kind}: no cleanup behind an unknown: {:?}",
            p.stdout
        );
    }
}

#[test]
fn a_link_is_staged_and_published_by_the_script() {
    let (_t, d) = work();
    let o = run(&["stagelink", d.to_str().unwrap(), "-", "/etc/one"]);
    assert_eq!(o.code, 0, "{:?}", o.stderr);
    let f: Vec<&str> = last_line(&o).split(' ').collect();
    assert_eq!(f.len(), 4, "{:?}", o.stdout);
    let st = Staged {
        s: f[0].into(),
        g: f[1].into(),
        sid: f[2].into(),
        pid: f[3].into(),
    };
    // a staged link is not a file: publishing it as one is refused, as is the reverse
    let p = publish_with(SCRIPT, &[], "new", "file", &d, &st, "lnk");
    assert_eq!(p.code, 3, "{:?}", p.stderr);
    assert!(fs::symlink_metadata(d.join("lnk")).is_err());
    let p = publish_with(SCRIPT, &[], "new", "link", &d, &st, "lnk");
    assert_eq!(p.code, 0, "{:?} {:?}", p.stdout, p.stderr);
    assert_eq!(
        fs::read_link(d.join("lnk")).unwrap(),
        PathBuf::from("/etc/one")
    );
    assert_eq!(
        entries(&d),
        vec!["lnk".to_string()],
        "no staging directory remains"
    );

    // replacing a link by `mv -T -f` replaces the link itself, not what it points to
    let target = d.join("target-dir");
    fs::create_dir(&target).unwrap();
    symlink(&target, d.join("lnk2")).unwrap();
    let o = run(&["stagelink", d.to_str().unwrap(), "-", "/etc/two"]);
    let f: Vec<&str> = last_line(&o).split(' ').collect();
    let st = Staged {
        s: f[0].into(),
        g: f[1].into(),
        sid: f[2].into(),
        pid: f[3].into(),
    };
    let p = publish_with(SCRIPT, &[], "replace", "link", &d, &st, "lnk2");
    assert_eq!(p.code, 0, "{:?}", p.stderr);
    assert_eq!(
        fs::read_link(d.join("lnk2")).unwrap(),
        PathBuf::from("/etc/two")
    );
    assert!(entries(&target).is_empty());
}
