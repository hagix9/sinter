//! Durable, symlink-safe file writes shared by `sinter secrets` and
//! `sinter serve init` / `rotate-key`.
//!
//! * [`full_sync`]: `fsync`, plus `F_FULLFSYNC` on macOS.
//! * [`create_exclusive`]: create a file that must not exist (`O_EXCL`,
//!   `O_NOFOLLOW`) and write it; removed again on failure.
//! * [`publish_new`]: write a temporary file next to the target, sync it and
//!   hard-link it to the final name, which never replaces an existing entry
//!   (falls back to [`create_exclusive`] where hard links are unavailable).
//! * [`replace`]: write a temporary file next to the target, sync it and
//!   rename it over the target (an atomic replacement).
//!
//! Nothing here ever follows a symbolic link at the final name or the
//! temporary name, and nothing is logged.
#![cfg(unix)]

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// `fsync`, and on macOS `F_FULLFSYNC` (plain `fsync` there does not force the
/// drive to flush its cache).
pub fn full_sync(f: &File) -> std::io::Result<()> {
    f.sync_all()?;
    #[cfg(target_os = "macos")]
    unsafe {
        libc::fcntl(f.as_raw_fd(), libc::F_FULLFSYNC);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = f.as_raw_fd();
    Ok(())
}

/// Create `out` exclusively (it must not exist) and write `data` into it. The
/// file is visible while it is being written, so a failure removes it again.
pub fn create_exclusive(out: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(out)?;
    let r = f.write_all(data).and_then(|_| full_sync(&f));
    if r.is_err() {
        drop(f);
        let _ = std::fs::remove_file(out);
    }
    r
}

struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn parent_of(out: &Path) -> PathBuf {
    match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// A synced temporary file next to `out`, mode `mode`, holding `data`.
fn write_temp(out: &Path, data: &[u8], mode: u32) -> std::io::Result<TempFile> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let path = parent_of(out).join(format!(".sinter-tmp-{:x}-{:x}", std::process::id(), nanos));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let tmp = TempFile { path, armed: true };
    f.write_all(data)?;
    full_sync(&f)?;
    Ok(tmp)
}

fn sync_dir(out: &Path) {
    if let Ok(d) = File::open(parent_of(out)) {
        let _ = full_sync(&d);
    }
}

/// Publish `data` at `out`, which must not exist: never a replacement. The
/// content is complete and synced before the name appears (hard link), except
/// on filesystems without hard links, where an exclusive create is used.
/// Returns `AlreadyExists` if `out` exists (a symbolic link included).
pub fn publish_new(out: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let tmp = write_temp(out, data, mode)?;
    match std::fs::hard_link(&tmp.path, out) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(e),
        Err(_) => {
            drop(tmp);
            create_exclusive(out, data, mode)?;
            sync_dir(out);
            return Ok(());
        }
    }
    drop(tmp);
    sync_dir(out);
    Ok(())
}

/// Replace `out` atomically with `data` (rename over it). The caller checks
/// beforehand that `out` is the regular file it means to replace.
pub fn replace(out: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let mut tmp = write_temp(out, data, mode)?;
    std::fs::rename(&tmp.path, out)?;
    tmp.armed = false;
    sync_dir(out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn publish_new_never_replaces_and_leaves_no_temp() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        publish_new(&p, b"one", 0o600).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let e = publish_new(&p, b"two", 0o600).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "no temporary file may remain: {names:?}");
    }

    #[test]
    fn publish_new_refuses_a_symlink_at_the_name() {
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(publish_new(&link, b"x", 0o600).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }

    #[test]
    fn replace_is_atomic_and_keeps_mode() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        publish_new(&p, b"old", 0o600).unwrap();
        replace(&p, b"new", 0o600).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let names: Vec<_> = std::fs::read_dir(d.path()).unwrap().collect();
        assert_eq!(names.len(), 1);
    }
}
