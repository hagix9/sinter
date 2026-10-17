//! `examples/openstack/tools/stage-rpm-repo.sh`, the helper that puts the OpenStack RPM repository on the
//! target. Run with a stand-in `ssh`/`sudo` that execute the "remote" command locally, on a tiny fake archive:
//! the checks are about verification (archive hash, member hashes, target-side hashes), refusal on any mismatch,
//! and argument handling, not about real ssh. The test directory is under /tmp (small files; the script refuses
//! `--dest` paths with spaces).
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/openstack/tools/stage-rpm-repo.sh"
);

fn sh(dir: &Path, cmd: &str) {
    let st = Command::new("/bin/bash")
        .arg("-c")
        .arg(cmd)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(st.success(), "{cmd}");
}

struct Fx {
    dir: tempfile::TempDir,
}

impl Fx {
    fn new() -> Fx {
        let dir = tempfile::Builder::new()
            .prefix("sinter-stage-")
            .tempdir_in("/tmp")
            .unwrap();
        let d = dir.path();
        // a fake "remote": ssh runs the command locally, sudo is transparent
        let bin = d.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(
            bin.join("ssh"),
            "#!/bin/bash\nwhile [ $# -gt 0 ]; do case \"$1\" in -o|-i|-p) shift 2 ;; -*) shift ;; *) break ;; esac; done\nshift\nexec bash -c \"$*\"\n",
        )
        .unwrap();
        fs::write(bin.join("sudo"), "#!/bin/sh\nexec \"$@\"\n").unwrap();
        // the "target" may be a macOS developer machine without GNU coreutils
        fs::write(
            bin.join("sha256sum"),
            "#!/bin/sh\nif [ -x /usr/bin/sha256sum ]; then exec /usr/bin/sha256sum \"$@\"; else exec shasum -a 256 \"$@\"; fi\n",
        )
        .unwrap();
        sh(d, "chmod +x bin/ssh bin/sudo bin/sha256sum");
        // an archive laid out like the release: top/repo/{noarch,repodata}, top/SHA256SUMS.repo
        sh(
            d,
            "mkdir -p src/openstack-rpm-test/repo/noarch src/openstack-rpm-test/repo/repodata \
             && printf 'rpm-a' > src/openstack-rpm-test/repo/noarch/a-1.noarch.rpm \
             && printf 'rpm-b' > src/openstack-rpm-test/repo/noarch/b-1.noarch.rpm \
             && printf '<repomd/>' > src/openstack-rpm-test/repo/repodata/repomd.xml \
             && (cd src/openstack-rpm-test/repo && (sha256sum ./noarch/*.rpm ./repodata/repomd.xml 2>/dev/null || shasum -a 256 ./noarch/*.rpm ./repodata/repomd.xml) > ../SHA256SUMS.repo) \
             && tar -C src -czf openstack-rpm-test.tar.gz openstack-rpm-test \
             && (sha256sum openstack-rpm-test.tar.gz 2>/dev/null || shasum -a 256 openstack-rpm-test.tar.gz) > SHA256SUMS",
        );
        Fx { dir }
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    fn run(&self, args: &[&str]) -> (i32, String) {
        let path = format!("{}:/usr/bin:/bin", self.p("bin").display());
        let out = Command::new("/bin/bash")
            .arg(SCRIPT)
            .args(args)
            .env("PATH", path)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code().unwrap_or(-1), text)
    }
    fn dest(&self) -> String {
        self.p("dest").display().to_string()
    }
    fn stage(&self, archive: &str, sums: &str) -> (i32, String) {
        let a = self.p(archive).display().to_string();
        let s = self.p(sums).display().to_string();
        self.run(&[
            "--archive",
            &a,
            "--sums",
            &s,
            "--host",
            "t",
            "--dest",
            &self.dest(),
        ])
    }
}

#[test]
fn the_script_is_valid_bash_and_executable() {
    let st = Command::new("/bin/bash")
        .arg("-n")
        .arg(SCRIPT)
        .status()
        .unwrap();
    assert!(st.success());
    use std::os::unix::fs::PermissionsExt;
    assert_ne!(
        fs::metadata(SCRIPT).unwrap().permissions().mode() & 0o111,
        0
    );
}

#[test]
fn argument_errors_are_refused_before_anything_happens() {
    let f = Fx::new();
    for args in [
        vec!["--archive", "x"],                                           // no --host
        vec!["--host", "t"],                                              // neither method
        vec!["--host", "t", "--archive", "x", "--from-builder", "b"],     // both methods
        vec!["--host", "t", "--from-builder", "b", "--dest", "/opt/a b"], // space in dest
        vec![
            "--host",
            "t",
            "--from-builder",
            "b",
            "--dest",
            "relative/path",
        ],
        vec!["--bogus"],
    ] {
        let (code, out) = f.run(&args);
        assert_ne!(code, 0, "{args:?}\n{out}");
    }
    assert!(!f.p("dest").exists());
}

#[test]
fn a_verified_archive_is_staged_and_checked_on_the_target() {
    let f = Fx::new();
    let (code, out) = f.stage("openstack-rpm-test.tar.gz", "SHA256SUMS");
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("archive SHA-256 OK") && out.contains("verified on the target"),
        "{out}"
    );
    assert!(f.p("dest/noarch/a-1.noarch.rpm").exists() && f.p("dest/repodata/repomd.xml").exists());
    assert!(out.contains("2 RPMs"), "{out}");
}

#[test]
fn a_wrong_or_missing_checksum_stops_before_anything_is_copied() {
    let f = Fx::new();
    // the list does not match the archive
    sh(
        f.dir.path(),
        "sed 's/^[0-9a-f]\\{8\\}/00000000/' SHA256SUMS > BAD",
    );
    let (code, out) = f.stage("openstack-rpm-test.tar.gz", "BAD");
    assert_ne!(code, 0);
    assert!(out.contains("MISMATCH"), "{out}");
    // the archive is not listed at all
    sh(f.dir.path(), "echo '0  other.tar.gz' > OTHER");
    let (code, out) = f.stage("openstack-rpm-test.tar.gz", "OTHER");
    assert_ne!(code, 0);
    assert!(out.contains("not listed"), "{out}");
    assert!(
        !f.p("dest").exists(),
        "nothing may be copied after a failed check"
    );
}

#[test]
fn a_file_corrupted_inside_a_valid_archive_is_refused() {
    let f = Fx::new();
    // corrupt a member, repack, and publish a list that matches the (corrupt) archive: only the inner list can catch it
    sh(
        f.dir.path(),
        "printf 'x' >> src/openstack-rpm-test/repo/noarch/a-1.noarch.rpm \
         && tar -C src -czf corrupt.tar.gz openstack-rpm-test \
         && (sha256sum corrupt.tar.gz 2>/dev/null || shasum -a 256 corrupt.tar.gz) > CSUMS",
    );
    let (code, out) = f.stage("corrupt.tar.gz", "CSUMS");
    assert_ne!(code, 0);
    assert!(out.contains("does not match SHA256SUMS.repo"), "{out}");
    assert!(!f.p("dest").exists());
}

#[test]
fn corruption_in_transit_is_caught_by_the_check_on_the_target() {
    let f = Fx::new();
    // a transport that damages one file while extracting on the "remote"
    fs::write(
        f.p("bin/ssh"),
        "#!/bin/bash\nwhile [ $# -gt 0 ]; do case \"$1\" in -o|-i|-p) shift 2 ;; -*) shift ;; *) break ;; esac; done\nshift\nbash -c \"$*\"; rc=$?\ncase \"$*\" in *' -xf -'*) printf x >> \"$DAMAGE\" ;; esac\nexit $rc\n",
    )
    .unwrap();
    let damage = f.p("dest/noarch/a-1.noarch.rpm");
    let path = format!("{}:/usr/bin:/bin", f.p("bin").display());
    let out = Command::new("/bin/bash")
        .arg(SCRIPT)
        .args([
            "--archive",
            &f.p("openstack-rpm-test.tar.gz").display().to_string(),
            "--sums",
            &f.p("SHA256SUMS").display().to_string(),
            "--host",
            "t",
            "--dest",
            &f.dest(),
        ])
        .env("PATH", path)
        .env("DAMAGE", &damage)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(out.status.code().unwrap_or(-1), 0, "{text}");
    assert!(text.contains("verification on the target FAILED"), "{text}");
}
