//! The fixed backup script on real Linux tools, as root (DESIGN §40.7). Without
//! root each test says so and passes without checking anything, so this file is
//! evidence only from a run as root: the release gate's root suite does not run as
//! root, and a real-target run is a separate step.
#![cfg(target_os = "linux")]

use std::os::unix::fs::{chown, symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Output};

const NOBODY: u32 = 65534;

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

fn copy(src: &Path, dest: &Path) -> Output {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(sinter::fsbackup::SCRIPT)
        .arg("sh")
        .args([
            NOBODY.to_string(),
            NOBODY.to_string(),
            src.display().to_string(),
            dest.display().to_string(),
            sinter::fsbackup::MAX_BYTES.to_string(),
            "0".to_string(),
        ])
        .output()
        .unwrap()
}

#[test]
fn a_private_file_of_another_account_is_read_as_that_account() {
    if !is_root() {
        eprintln!("skipped: needs root");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let tree = d.path().join("tree");
    std::fs::create_dir(&tree).unwrap();
    std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o700)).unwrap();
    chown(&tree, Some(NOBODY), Some(NOBODY)).unwrap();
    let store = d.path().join("store");
    std::fs::create_dir(&store).unwrap();
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();

    let src = tree.join(".pgpass");
    std::fs::write(&src, "content").unwrap();
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600)).unwrap();
    chown(&src, Some(NOBODY), Some(NOBODY)).unwrap();

    let dest = store.join("copy");
    let o = copy(&src, &dest);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "content");
    let (a, b) = (
        std::fs::metadata(&src).unwrap(),
        std::fs::metadata(&dest).unwrap(),
    );
    assert_eq!(
        (b.uid(), b.gid(), b.mode() & 0o7777),
        (NOBODY, NOBODY, 0o600)
    );
    assert_eq!(a.mtime(), b.mtime());
    std::fs::remove_file(&dest).unwrap();

    // A link to something only root can read: refused, nothing copied.
    let secret = d.path().join("root-only");
    std::fs::write(&secret, "root secret").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = tree.join("link");
    symlink(&secret, &link).unwrap();
    let o = copy(&link, &dest);
    assert_eq!(o.status.code(), Some(3));
    assert!(!dest.exists());

    // A file the account does not own, in its directory: refused.
    let foreign = tree.join("foreign");
    std::fs::write(&foreign, "x").unwrap();
    let o = copy(&foreign, &dest);
    assert_eq!(o.status.code(), Some(3));
    assert!(!dest.exists());
}
