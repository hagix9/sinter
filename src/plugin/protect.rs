//! Protected reading of the plugin root on the controller (DESIGN §38.5).
//!
//! The root is resolved once (an operator-configured path may contain
//! symbolic links, e.g. from a dotfile manager) and then walked again from
//! `/` one component at a time with `O_NOFOLLOW`, so a link introduced after
//! resolution is refused. Every directory is checked on its open descriptor:
//!
//! * an ancestor of the root must be owned by root or by this user, and not
//!   writable by group or others unless it is sticky (like `/tmp`);
//! * the root and its `catalogs`/`plugins` directories must be owned by root
//!   or by this user and not writable by group or others (no sticky
//!   exception);
//! * a file must be a regular file (a final symlink is refused), owned by
//!   root or by this user, not writable by group or others, and not larger
//!   than the limit.
//!
//! A file is read from the descriptor that was checked, and its identity
//! (device, inode, size, modification and change time) must be the same
//! before and after the read; the digest is taken over exactly the bytes
//! that are then parsed. ACLs are not inspected (DESIGN §38.5, limits).

use crate::error::SinterError;
use sha2::{Digest, Sha256};
use std::path::Path;

/// The bytes of one protected file and their SHA-256 (lowercase hex).
pub(crate) struct Loaded {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn refuse(msg: impl Into<String>) -> SinterError {
    SinterError::schema(format!("plugin: {}", msg.into()))
}

/// A file or directory name the loader builds itself. Never a path.
fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 128
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

#[cfg(unix)]
mod imp {
    use super::{name_ok, refuse, sha256_hex, Loaded};
    use crate::error::Result;
    use std::ffi::CString;
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};

    /// Which directories above the root are checked. Production always
    /// checks every ancestor; tests may start the ancestor checks at a
    /// boundary they created (the shared test volume is not under their
    /// control), while still walking every component with `O_NOFOLLOW`.
    pub(crate) enum Ancestors {
        All,
        #[cfg(test)]
        Below(std::path::PathBuf),
    }

    pub(crate) struct TrustedDir {
        fd: OwnedFd,
        shown: String,
    }

    fn euid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    fn owner_ok(md: &std::fs::Metadata) -> bool {
        md.uid() == 0 || md.uid() == euid()
    }

    fn openat(
        dir: Option<&OwnedFd>,
        name: &std::ffi::OsStr,
        flags: i32,
    ) -> std::io::Result<OwnedFd> {
        let c = CString::new(name.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let base = dir.map(|d| d.as_raw_fd()).unwrap_or(libc::AT_FDCWD);
        // SAFETY: `c` is a valid NUL-terminated string and `base` is either
        // AT_FDCWD or a descriptor this function's caller owns.
        let fd = unsafe { libc::openat(base, c.as_ptr(), flags | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by openat and is owned by nobody else.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn fstat(fd: &OwnedFd) -> std::io::Result<std::fs::Metadata> {
        let dup = fd.try_clone()?;
        File::from(dup).metadata()
    }

    const DIR_FLAGS: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;

    fn open_err(shown: &str, e: std::io::Error) -> crate::error::SinterError {
        if e.raw_os_error() == Some(libc::ELOOP) || e.raw_os_error() == Some(libc::ENOTDIR) {
            refuse(format!(
                "{}: refusing a symbolic link or non-directory",
                shown
            ))
        } else {
            refuse(format!("{}: cannot open: {}", shown, e.kind()))
        }
    }

    impl TrustedDir {
        pub(crate) fn open_root(path: &Path, ancestors: &Ancestors) -> Result<TrustedDir> {
            let shown_root = super::shown(path);
            let real = std::fs::canonicalize(path).map_err(|e| {
                refuse(format!(
                    "{}: cannot resolve the plugin root: {}",
                    shown_root,
                    e.kind()
                ))
            })?;
            let boundary: Option<std::path::PathBuf> = match ancestors {
                Ancestors::All => None,
                #[cfg(test)]
                Ancestors::Below(b) => Some(
                    std::fs::canonicalize(b)
                        .map_err(|e| refuse(format!("test boundary: {}", e.kind())))?,
                ),
            };
            let comps: Vec<_> = real.components().collect();
            if !matches!(comps.first(), Some(Component::RootDir)) {
                return Err(refuse(format!(
                    "{}: plugin root must be absolute",
                    shown_root
                )));
            }
            let mut fd =
                openat(None, std::ffi::OsStr::new("/"), DIR_FLAGS).map_err(|e| open_err("/", e))?;
            let mut walked = std::path::PathBuf::from("/");
            let last = comps.len() - 1;
            for (i, c) in comps.iter().enumerate() {
                if i > 0 {
                    let Component::Normal(n) = c else {
                        return Err(refuse(format!("{}: unexpected path component", shown_root)));
                    };
                    walked.push(n);
                    fd = openat(Some(&fd), n, DIR_FLAGS)
                        .map_err(|e| open_err(&super::shown(&walked), e))?;
                }
                let md = fstat(&fd)
                    .map_err(|e| refuse(format!("{}: {}", super::shown(&walked), e.kind())))?;
                let shown = super::shown(&walked);
                if i == last {
                    check_strict_dir(&md, &shown)?;
                } else if boundary.as_ref().is_none_or(|b| walked.starts_with(b)) {
                    if !owner_ok(&md) {
                        return Err(refuse(format!(
                            "{}: an ancestor of the plugin root is owned by another user",
                            shown
                        )));
                    }
                    let mode = md.mode();
                    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                        return Err(refuse(format!(
                            "{}: an ancestor of the plugin root is writable by group or others (mode {:o})",
                            shown,
                            mode & 0o7777
                        )));
                    }
                }
            }
            Ok(TrustedDir {
                fd,
                shown: shown_root,
            })
        }

        pub(crate) fn subdir(&self, name: &str) -> Result<TrustedDir> {
            let shown = format!("{}/{}", self.shown, name);
            if !name_ok(name) {
                return Err(refuse(format!("{}: invalid name", shown)));
            }
            let fd = openat(Some(&self.fd), std::ffi::OsStr::new(name), DIR_FLAGS)
                .map_err(|e| open_err(&shown, e))?;
            let md = fstat(&fd).map_err(|e| refuse(format!("{}: {}", shown, e.kind())))?;
            check_strict_dir(&md, &shown)?;
            Ok(TrustedDir { fd, shown })
        }

        /// Open, check and read one file of this directory (at most `limit`
        /// bytes). `after_open` is a test seam between the checks on the
        /// opened descriptor and the read; production passes a no-op.
        pub(crate) fn read_file_with(
            &self,
            name: &str,
            limit: usize,
            after_open: &mut dyn FnMut(),
        ) -> Result<Loaded> {
            let shown = format!("{}/{}", self.shown, name);
            if !name_ok(name) {
                return Err(refuse(format!("{}: invalid name", shown)));
            }
            let fd = openat(
                Some(&self.fd),
                std::ffi::OsStr::new(name),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    refuse(format!("{}: refusing a symbolic link", shown))
                } else if e.kind() == std::io::ErrorKind::NotFound {
                    refuse(format!("{}: not installed", shown))
                } else {
                    refuse(format!("{}: cannot open: {}", shown, e.kind()))
                }
            })?;
            let before = fstat(&fd).map_err(|e| refuse(format!("{}: {}", shown, e.kind())))?;
            if !before.file_type().is_file() {
                return Err(refuse(format!("{}: not a regular file", shown)));
            }
            if !owner_ok(&before) {
                return Err(refuse(format!("{}: owned by another user", shown)));
            }
            if before.mode() & 0o022 != 0 {
                return Err(refuse(format!(
                    "{}: writable by group or others (mode {:o})",
                    shown,
                    before.mode() & 0o7777
                )));
            }
            if before.len() > limit as u64 {
                return Err(refuse(format!(
                    "{}: larger than the {} byte limit",
                    shown, limit
                )));
            }
            after_open();
            let mut file = File::from(fd);
            let mut bytes = Vec::with_capacity(before.len() as usize);
            (&mut file)
                .take(limit as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| refuse(format!("{}: cannot read: {}", shown, e.kind())))?;
            if bytes.len() > limit {
                return Err(refuse(format!(
                    "{}: larger than the {} byte limit",
                    shown, limit
                )));
            }
            let after = file
                .metadata()
                .map_err(|e| refuse(format!("{}: {}", shown, e.kind())))?;
            let same = before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.len() == after.len()
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec()
                && bytes.len() as u64 == after.len();
            if !same {
                return Err(refuse(format!(
                    "{}: changed while it was being read",
                    shown
                )));
            }
            let sha256 = sha256_hex(&bytes);
            Ok(Loaded { bytes, sha256 })
        }

        pub(crate) fn shown(&self) -> &str {
            &self.shown
        }

        // -------------------------------------------------------------
        // Writing (PM-3, DESIGN §38.16). Every call works on this
        // directory's descriptor with a name the caller built (`name_ok`),
        // never follows a symbolic link, and never changes the mode or
        // owner of an existing file or directory.
        // -------------------------------------------------------------

        /// What `name` is, without following a final symbolic link.
        pub(crate) fn entry(&self, name: &str) -> Result<Entry> {
            let shown = format!("{}/{}", self.shown, name);
            let c = cname(name, &shown)?;
            // SAFETY: an all-zero `stat` is a valid value to be overwritten.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: `c` is NUL-terminated, `st` is a valid out pointer and
            // the descriptor is owned by `self`.
            let rc = unsafe {
                libc::fstatat(
                    self.fd.as_raw_fd(),
                    c.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Ok(Entry::Absent);
                }
                return Err(refuse(format!("{}: {}", shown, e.kind())));
            }
            Ok(match st.st_mode & libc::S_IFMT {
                libc::S_IFDIR => Entry::Dir,
                libc::S_IFREG => Entry::File,
                _ => Entry::Other,
            })
        }

        /// Create the directory `name` (mode 0700, whatever the umask or an
        /// inherited ACL) and open it with the strict checks. `Ok(false)`
        /// when it already existed (then it is only opened and checked).
        ///
        /// A failure after `mkdirat` created the directory says so
        /// (`published`), so the caller can remove it again.
        pub(crate) fn make_dir(
            &self,
            name: &str,
        ) -> std::result::Result<(bool, TrustedDir), WriteFailure> {
            let shown = format!("{}/{}", self.shown, name);
            let c = cname(name, &shown).map_err(WriteFailure::before)?;
            // SAFETY: valid NUL-terminated name and owned descriptor.
            let rc = unsafe { libc::mkdirat(self.fd.as_raw_fd(), c.as_ptr(), 0o700) };
            let created = if rc == 0 {
                true
            } else {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EEXIST) {
                    return Err(WriteFailure::before(refuse(format!(
                        "{}: cannot create: {}",
                        shown,
                        e.kind()
                    ))));
                }
                false
            };
            let after = |e: crate::error::SinterError| WriteFailure {
                error: e,
                published: created,
            };
            hook(&format!("after-mkdir:{}", name)).map_err(after)?;
            let fd = openat(Some(&self.fd), std::ffi::OsStr::new(name), DIR_FLAGS)
                .map_err(|e| after(open_err(&shown, e)))?;
            if created {
                fchmod(&fd, 0o700, &shown).map_err(after)?;
            }
            let md = fstat(&fd).map_err(|e| after(refuse(format!("{}: {}", shown, e.kind()))))?;
            check_strict_dir(&md, &shown).map_err(after)?;
            Ok((created, TrustedDir { fd, shown }))
        }

        /// Write `bytes` to a new temporary file of this directory (mode
        /// 0600, checked on its descriptor) and fsync it. Returns its name.
        fn write_temp(&self, name: &str, bytes: &[u8]) -> Result<String> {
            use std::io::Write;
            let tmp = format!(".{}.tmp-{}-{:08x}", name, pid(), temp_nonce());
            let shown = format!("{}/{}", self.shown, tmp);
            let fd = openat(
                Some(&self.fd),
                std::ffi::OsStr::new(&tmp),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            )
            .map_err(|e| refuse(format!("{}: cannot create: {}", shown, e.kind())))?;
            let result = (|| -> Result<()> {
                fchmod(&fd, 0o600, &shown)?;
                let md = fstat(&fd).map_err(|e| refuse(format!("{}: {}", shown, e.kind())))?;
                if !md.file_type().is_file() || !owner_ok(&md) || md.mode() & 0o077 != 0 {
                    return Err(refuse(format!(
                        "{}: the new file is not a private regular file (mode {:o})",
                        shown,
                        md.mode() & 0o7777
                    )));
                }
                let mut f = File::from(
                    fd.try_clone()
                        .map_err(|e| refuse(format!("{}: {}", shown, e.kind())))?,
                );
                f.write_all(bytes)
                    .and_then(|_| f.sync_all())
                    .map_err(|e| refuse(format!("{}: cannot write: {}", shown, e.kind())))
            })();
            if let Err(e) = result {
                let _ = self.unlink(&tmp);
                return Err(e);
            }
            Ok(tmp)
        }

        /// Create the new file `name` with `bytes`: written to a private
        /// temporary file, fsynced, then hard-linked to `name`, which fails
        /// when `name` exists (an existing file is never replaced), and the
        /// temporary name removed. The directory is fsynced.
        ///
        /// A failure after the link was made (`published`) means `name` now
        /// exists with these bytes even though making that durable failed.
        pub(crate) fn place_new_file(
            &self,
            name: &str,
            bytes: &[u8],
        ) -> std::result::Result<(), WriteFailure> {
            let shown = format!("{}/{}", self.shown, name);
            let c = cname(name, &shown).map_err(WriteFailure::before)?;
            let tmp = self.write_temp(name, bytes).map_err(WriteFailure::before)?;
            let ct = cname(&tmp, &shown).map_err(WriteFailure::before)?;
            // SAFETY: valid names, both relative to the owned descriptor.
            let rc = unsafe {
                libc::linkat(
                    self.fd.as_raw_fd(),
                    ct.as_ptr(),
                    self.fd.as_raw_fd(),
                    c.as_ptr(),
                    0,
                )
            };
            let linked = if rc == 0 {
                Ok(())
            } else {
                let e = std::io::Error::last_os_error();
                Err(if e.raw_os_error() == Some(libc::EEXIST) {
                    refuse(format!("{}: already exists; it is never replaced", shown))
                } else {
                    refuse(format!("{}: cannot create: {}", shown, e.kind()))
                })
            };
            let _ = self.unlink(&tmp);
            linked.map_err(WriteFailure::before)?;
            hook(&format!("sync-after-link:{}", name))
                .and_then(|_| self.sync())
                .map_err(WriteFailure::after)
        }

        /// Replace `name` atomically with `bytes` (a private temporary file,
        /// fsynced, renamed over `name`; the directory is fsynced).
        ///
        /// A failure after the rename (`published`) means `name` now has the
        /// new bytes even though making that durable failed.
        pub(crate) fn replace_file(
            &self,
            name: &str,
            bytes: &[u8],
        ) -> std::result::Result<(), WriteFailure> {
            let shown = format!("{}/{}", self.shown, name);
            let c = cname(name, &shown).map_err(WriteFailure::before)?;
            let tmp = self.write_temp(name, bytes).map_err(WriteFailure::before)?;
            let ct = cname(&tmp, &shown).map_err(WriteFailure::before)?;
            // SAFETY: valid names, both relative to the owned descriptor.
            let rc = unsafe {
                libc::renameat(
                    self.fd.as_raw_fd(),
                    ct.as_ptr(),
                    self.fd.as_raw_fd(),
                    c.as_ptr(),
                )
            };
            if rc != 0 {
                let e = std::io::Error::last_os_error();
                let _ = self.unlink(&tmp);
                return Err(WriteFailure::before(refuse(format!(
                    "{}: cannot replace: {}",
                    shown,
                    e.kind()
                ))));
            }
            hook(&format!("sync-after-rename:{}", name))
                .and_then(|_| self.sync())
                .map_err(WriteFailure::after)
        }

        fn unlink(&self, name: &str) -> std::io::Result<()> {
            let c = CString::new(name)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
            // SAFETY: valid name relative to the owned descriptor.
            if unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }

        /// Remove the file `name` of this directory (never a directory, never
        /// through a link: `unlinkat` removes the link itself).
        pub(crate) fn remove_file(&self, name: &str) -> Result<()> {
            let shown = format!("{}/{}", self.shown, name);
            cname(name, &shown)?;
            hook(&format!("remove:{}", name))?;
            self.unlink(name)
                .map_err(|e| refuse(format!("{}: cannot remove: {}", shown, e.kind())))
        }

        /// Remove the file `name` and fsync the directory. A failure after
        /// the file was removed (`published`) means it is gone even though
        /// making that durable failed.
        pub(crate) fn remove_file_synced(
            &self,
            name: &str,
        ) -> std::result::Result<(), WriteFailure> {
            self.remove_file(name).map_err(WriteFailure::before)?;
            hook(&format!("sync-after-unlink:{}", name))
                .and_then(|_| self.sync())
                .map_err(WriteFailure::after)
        }

        /// Remove the empty directory `name` of this directory.
        pub(crate) fn remove_dir(&self, name: &str) -> Result<()> {
            let shown = format!("{}/{}", self.shown, name);
            let c = cname(name, &shown)?;
            // SAFETY: valid name relative to the owned descriptor.
            if unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
                let e = std::io::Error::last_os_error();
                return Err(refuse(format!("{}: cannot remove: {}", shown, e.kind())));
            }
            Ok(())
        }

        /// fsync this directory.
        pub(crate) fn sync(&self) -> Result<()> {
            let f = File::from(
                self.fd
                    .try_clone()
                    .map_err(|e| refuse(format!("{}: {}", self.shown, e.kind())))?,
            );
            f.sync_all()
                .map_err(|e| refuse(format!("{}: cannot sync: {}", self.shown, e.kind())))
        }

        /// Take the exclusive lock `name` of this directory (a private
        /// regular file, created when missing, never through a link) without
        /// waiting: another holder is a refusal.
        pub(crate) fn lock(&self, name: &str) -> Result<DirLock> {
            let shown = format!("{}/{}", self.shown, name);
            cname(name, &shown)?;
            let fd = openat(
                Some(&self.fd),
                std::ffi::OsStr::new(name),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    refuse(format!("{}: refusing a symbolic link", shown))
                } else {
                    refuse(format!("{}: cannot open: {}", shown, e.kind()))
                }
            })?;
            let md = fstat(&fd).map_err(|e| refuse(format!("{}: {}", shown, e.kind())))?;
            if !md.file_type().is_file() || !owner_ok(&md) {
                return Err(refuse(format!(
                    "{}: not a regular file of this user",
                    shown
                )));
            }
            if md.mode() & 0o077 != 0 {
                if md.uid() != euid() {
                    return Err(refuse(format!(
                        "{}: writable or readable by others (mode {:o})",
                        shown,
                        md.mode() & 0o7777
                    )));
                }
                fchmod(&fd, 0o600, &shown)?;
            }
            // SAFETY: the descriptor is owned and open.
            if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let e = std::io::Error::last_os_error();
                return Err(if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    refuse(format!(
                        "{}: another plugin install or remove is running on this root",
                        shown
                    ))
                } else {
                    refuse(format!("{}: cannot lock: {}", shown, e.kind()))
                });
            }
            Ok(DirLock { _fd: fd })
        }
    }

    /// A write that failed, and whether its change was already visible
    /// (`published`: the link, rename, removal or directory creation took
    /// place; only making it durable, or a later check, failed).
    #[derive(Debug)]
    pub(crate) struct WriteFailure {
        pub error: crate::error::SinterError,
        pub published: bool,
    }

    impl WriteFailure {
        fn before(error: crate::error::SinterError) -> Self {
            WriteFailure {
                error,
                published: false,
            }
        }
        fn after(error: crate::error::SinterError) -> Self {
            WriteFailure {
                error,
                published: true,
            }
        }
    }

    /// Test-only failure injection at a named point of a write (for example
    /// `sync-after-link:trust.toml`). Compiled only into test builds: in
    /// every other build `hook` always succeeds and nothing can arm it.
    #[cfg(test)]
    pub(crate) mod hooks {
        use std::cell::RefCell;
        thread_local! {
            static FAIL: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        }
        /// Fail at these points on this thread until [`clear`].
        pub(crate) fn fail_at(points: &[&str]) {
            FAIL.with(|f| *f.borrow_mut() = points.iter().map(|p| p.to_string()).collect());
        }
        pub(crate) fn clear() {
            FAIL.with(|f| f.borrow_mut().clear());
        }
        pub(super) fn armed(point: &str) -> bool {
            FAIL.with(|f| f.borrow().iter().any(|p| p == point))
        }
    }

    #[cfg(test)]
    fn hook(point: &str) -> Result<()> {
        if hooks::armed(point) {
            return Err(refuse(format!("injected failure at {}", point)));
        }
        Ok(())
    }

    #[cfg(not(test))]
    #[inline(always)]
    fn hook(_point: &str) -> Result<()> {
        Ok(())
    }

    /// What a name of a directory is (without following a final link).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Entry {
        Absent,
        Dir,
        File,
        /// A symbolic link, FIFO, socket or device.
        Other,
    }

    /// An exclusive `flock` held until dropped.
    pub(crate) struct DirLock {
        _fd: OwnedFd,
    }

    fn cname(name: &str, shown: &str) -> Result<CString> {
        if !name_ok(name) {
            return Err(refuse(format!("{}: invalid name", shown)));
        }
        CString::new(name).map_err(|_| refuse(format!("{}: invalid name", shown)))
    }

    fn fchmod(fd: &OwnedFd, mode: libc::mode_t, shown: &str) -> Result<()> {
        // SAFETY: the descriptor is owned and open.
        if unsafe { libc::fchmod(fd.as_raw_fd(), mode) } != 0 {
            let e = std::io::Error::last_os_error();
            return Err(refuse(format!("{}: cannot set mode: {}", shown, e.kind())));
        }
        Ok(())
    }

    fn temp_nonce() -> u32 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        n ^ (pid().rotate_left(16))
    }

    /// This process's id, for temporary names only.
    fn pid() -> u32 {
        // SAFETY: getpid has no preconditions and cannot fail.
        unsafe { libc::getpid() as u32 }
    }

    /// Create the directories of `path` that do not exist yet, from its
    /// deepest existing ancestor, each with mode 0700 and without following
    /// a symbolic link (DESIGN §38.16). The existing part is resolved once
    /// and walked again from `/` with the ancestor checks of `open_root`.
    /// Returns the directories created, outermost first. Nothing is created
    /// when `path` exists (a dangling link counts as existing: opening it is
    /// then refused).
    ///
    /// On failure the directories created so far are returned with the
    /// error, so the caller can remove them again.
    #[allow(clippy::type_complexity)]
    pub(crate) fn create_missing_dirs(
        path: &Path,
        ancestors: &Ancestors,
    ) -> std::result::Result<
        Vec<std::path::PathBuf>,
        (crate::error::SinterError, Vec<std::path::PathBuf>),
    > {
        let mut created = Vec::new();
        match missing_dirs(path, ancestors, Some(&mut created)) {
            Ok(_) => Ok(created),
            Err(e) => Err((e, created)),
        }
    }

    /// The directories [`create_missing_dirs`] would create, after the same
    /// ancestor checks, without creating anything.
    pub(crate) fn create_missing_dirs_plan(
        path: &Path,
        ancestors: &Ancestors,
    ) -> Result<Vec<std::path::PathBuf>> {
        missing_dirs(path, ancestors, None)
    }

    /// Open an existing directory that is an ancestor of a plugin root (the
    /// ancestor rules: owned by root or this user, not writable by group or
    /// others unless sticky), walking every component without following a
    /// link. Used only to remove a directory install itself created.
    pub(crate) fn open_dir_relaxed(path: &Path, ancestors: &Ancestors) -> Result<TrustedDir> {
        let shown_root = super::shown(path);
        let real = std::fs::canonicalize(path)
            .map_err(|e| refuse(format!("{}: cannot resolve: {}", shown_root, e.kind())))?;
        let (fd, _) = walk_ancestors(&real, ancestors, &shown_root)?;
        Ok(TrustedDir {
            fd,
            shown: shown_root,
        })
    }

    /// Walk `real` (canonical) from `/` without following links, applying
    /// the ancestor rules to every component (below the test boundary).
    fn walk_ancestors(
        real: &Path,
        ancestors: &Ancestors,
        shown_root: &str,
    ) -> Result<(OwnedFd, std::path::PathBuf)> {
        let boundary: Option<std::path::PathBuf> = match ancestors {
            Ancestors::All => None,
            #[cfg(test)]
            Ancestors::Below(b) => Some(
                std::fs::canonicalize(b)
                    .map_err(|e| refuse(format!("test boundary: {}", e.kind())))?,
            ),
        };
        let check_ancestor = |fd: &OwnedFd, walked: &Path| -> Result<()> {
            let shown = super::shown(walked);
            let md = fstat(fd).map_err(|e| refuse(format!("{}: {}", shown, e.kind())))?;
            if !md.file_type().is_dir() {
                return Err(refuse(format!("{}: not a directory", shown)));
            }
            if boundary.as_ref().is_none_or(|b| walked.starts_with(b)) {
                if !owner_ok(&md) {
                    return Err(refuse(format!(
                        "{}: an ancestor of the plugin root is owned by another user",
                        shown
                    )));
                }
                let mode = md.mode();
                if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                    return Err(refuse(format!(
                        "{}: an ancestor of the plugin root is writable by group or others (mode {:o})",
                        shown,
                        mode & 0o7777
                    )));
                }
            }
            Ok(())
        };
        let mut fd =
            openat(None, std::ffi::OsStr::new("/"), DIR_FLAGS).map_err(|e| open_err("/", e))?;
        let mut walked = std::path::PathBuf::from("/");
        check_ancestor(&fd, &walked)?;
        for c in real.components().skip(1) {
            let Component::Normal(n) = c else {
                return Err(refuse(format!("{}: unexpected path component", shown_root)));
            };
            walked.push(n);
            fd =
                openat(Some(&fd), n, DIR_FLAGS).map_err(|e| open_err(&super::shown(&walked), e))?;
            check_ancestor(&fd, &walked)?;
        }
        Ok((fd, walked))
    }

    /// With `created`, create the missing directories and record each one in
    /// it as soon as it exists; without, only list them.
    fn missing_dirs(
        path: &Path,
        ancestors: &Ancestors,
        created: Option<&mut Vec<std::path::PathBuf>>,
    ) -> Result<Vec<std::path::PathBuf>> {
        let shown_root = super::shown(path);
        if std::fs::symlink_metadata(path).is_ok() {
            return Ok(Vec::new());
        }
        if !path.is_absolute() {
            return Err(refuse(format!(
                "{}: plugin root must be absolute",
                shown_root
            )));
        }
        let mut base = path.to_path_buf();
        let mut missing: Vec<std::ffi::OsString> = Vec::new();
        loop {
            match std::fs::symlink_metadata(&base) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let name = base.file_name().map(|n| n.to_os_string()).ok_or_else(|| {
                        refuse(format!("{}: no existing directory above it", shown_root))
                    })?;
                    missing.push(name);
                    base = base
                        .parent()
                        .ok_or_else(|| {
                            refuse(format!("{}: no existing directory above it", shown_root))
                        })?
                        .to_path_buf();
                }
                Err(e) => return Err(refuse(format!("{}: {}", shown_root, e.kind()))),
            }
        }
        missing.reverse();
        for n in &missing {
            if !n.to_str().is_some_and(name_ok) {
                return Err(refuse(format!(
                    "{}: a directory to create has an unsupported name",
                    shown_root
                )));
            }
        }
        let real = std::fs::canonicalize(&base).map_err(|e| {
            refuse(format!(
                "{}: cannot resolve: {}",
                super::shown(&base),
                e.kind()
            ))
        })?;
        let (mut fd, mut walked) = walk_ancestors(&real, ancestors, &shown_root)?;
        let Some(created) = created else {
            let mut out = Vec::new();
            let mut p = base.clone();
            for n in &missing {
                p.push(n);
                out.push(p.clone());
            }
            return Ok(out);
        };
        let mut shown_path = base.clone();
        for n in &missing {
            shown_path.push(n);
            let dir = TrustedDir {
                fd,
                shown: super::shown(&walked),
            };
            let name = n.to_str().expect("checked above");
            let (made, sub) = match dir.make_dir(name) {
                Ok(x) => x,
                Err(w) => {
                    if w.published {
                        created.push(shown_path.clone());
                    }
                    return Err(w.error);
                }
            };
            walked.push(n);
            if made {
                created.push(shown_path.clone());
                hook(&format!("sync-after-mkdir:{}", name))?;
                dir.sync()?;
            }
            fd = sub.fd;
        }
        Ok(created.clone())
    }

    fn check_strict_dir(md: &std::fs::Metadata, shown: &str) -> Result<()> {
        if !md.file_type().is_dir() {
            return Err(refuse(format!("{}: not a directory", shown)));
        }
        if !owner_ok(md) {
            return Err(refuse(format!("{}: owned by another user", shown)));
        }
        if md.mode() & 0o022 != 0 {
            return Err(refuse(format!(
                "{}: writable by group or others (mode {:o})",
                shown,
                md.mode() & 0o7777
            )));
        }
        Ok(())
    }
}

#[cfg(all(unix, test))]
pub(crate) use imp::hooks;
#[cfg(unix)]
pub(crate) use imp::{
    create_missing_dirs, create_missing_dirs_plan, open_dir_relaxed, Ancestors, Entry, TrustedDir,
};

#[cfg(not(unix))]
mod imp_other {
    use super::refuse;
    use crate::error::Result;
    use std::path::Path;

    pub(crate) enum Ancestors {
        All,
    }

    /// Resource Plugins need the descriptor-based checks above, which this
    /// platform does not provide: refuse (fail closed).
    pub(crate) struct TrustedDir;

    impl TrustedDir {
        pub(crate) fn open_root(_path: &Path, _a: &Ancestors) -> Result<TrustedDir> {
            Err(refuse("Resource Plugins require a Unix controller"))
        }
        pub(crate) fn subdir(&self, _name: &str) -> Result<TrustedDir> {
            Err(refuse("Resource Plugins require a Unix controller"))
        }
        pub(crate) fn read_file_with(
            &self,
            _name: &str,
            _limit: usize,
            _after_open: &mut dyn FnMut(),
        ) -> Result<super::Loaded> {
            Err(refuse("Resource Plugins require a Unix controller"))
        }
        pub(crate) fn shown(&self) -> &str {
            ""
        }
    }
}

#[cfg(not(unix))]
pub(crate) use imp_other::{Ancestors, TrustedDir};

/// A path for messages: control characters are escaped.
pub(crate) fn shown(path: &Path) -> String {
    path.to_string_lossy().escape_debug().to_string()
}
