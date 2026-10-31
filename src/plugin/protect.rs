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

#[cfg(unix)]
pub(crate) use imp::{Ancestors, TrustedDir};

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
