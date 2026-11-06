//! Inventory auto-detection for the selector argument (DESIGN §39.3).
//!
//! Detection runs only when a selector was given and no `--inventory` was; a
//! run without a selector never gets here, so a file appearing next to a recipe
//! cannot change what an existing command does.
//!
//! A detected file arrives without having been named, so it is held to more
//! than an explicit `--inventory`:
//!
//! * the places are the current directory and the recipe's directory, and
//!   neither parents nor the home directory are searched;
//! * exactly one file may be found; Sinter never picks by priority;
//! * a symbolic link is refused, also when another candidate exists: a
//!   candidate that exists and cannot be used never falls through to another;
//! * the file and the directory holding it must be owned by this user or root
//!   and not writable by group or others;
//! * it may not set `known_hosts` (which could satisfy strict host-key checking
//!   for a host of the file's choosing), and every `identity_files` entry must
//!   be absolute after `~` expansion, because a relative one would depend on
//!   where the command is run.
//!
//! Every check is made on an open descriptor, and the bytes parsed are read from
//! that descriptor, so there is no window between checking a file and reading
//! it. The file is read once: replacing it afterwards changes nothing about the
//! run. Limits: ACLs that the mode bits do not show are not inspected, and the
//! ancestors of the directory are only checked for symbolic links. Replacing an
//! ancestor can only bring in files and directories this user or root already
//! owns, since the owner checks apply to what is opened.

use crate::error::{Result, SinterError};
use crate::inventory::{parse_inventory, Inventory};
use std::ffi::CString;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// The file names detection looks for.
pub const DETECTED_NAMES: [&str; 3] = ["hosts.yaml", "hosts.yml", "hosts.toml"];
/// Largest detected inventory read.
pub const MAX_DETECTED_BYTES: u64 = 1024 * 1024;

const ASK: &str = "name a file you trust with --inventory";

/// Who a refusal is about, and what the person can do instead: the rules are the
/// same for everything that arrives without having been named (DESIGN §40.1).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Who {
    pub(crate) label: &'static str,
    pub(crate) ask: &'static str,
}

const INVENTORY: Who = Who {
    label: "auto-detected inventory",
    ask: ASK,
};

fn refuse_as(who: Who, path: &Path, what: impl std::fmt::Display) -> SinterError {
    SinterError::schema(format!(
        "{} {}: {what}; {}",
        who.label,
        path.display(),
        who.ask
    ))
}

fn refuse(path: &Path, what: impl std::fmt::Display) -> SinterError {
    refuse_as(INVENTORY, path, what)
}

fn open_at(dir: Option<&OwnedFd>, name: &std::ffi::OsStr, flags: i32) -> std::io::Result<OwnedFd> {
    let c = CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let base = dir.map_or(libc::AT_FDCWD, |d| d.as_raw_fd());
    // SAFETY: `c` is a valid NUL-terminated string, and `base` is AT_FDCWD or a
    // descriptor the caller keeps open for this call.
    let fd = unsafe { libc::openat(base, c.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn fstat(fd: &OwnedFd) -> std::io::Result<Metadata> {
    File::from(fd.try_clone()?).metadata()
}

fn owner_allowed(owner: u32, me: u32) -> bool {
    owner == 0 || owner == me
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn owner_ok(md: &Metadata, me: u32) -> bool {
    owner_allowed(md.uid(), me)
}

/// A symbolic link that may stand on the way to the recipe's directory. Root's
/// links are the system's own layout only to someone else: everything a root run
/// clones or unpacks is root's too, so for root the owner says nothing.
fn link_is_system_layout(link_owner: u32, me: u32) -> bool {
    link_owner == 0 && me != 0
}

/// A place to look in.
struct Place {
    fd: OwnedFd,
    md: Metadata,
    /// Absolute, for messages and for the inventory's path.
    shown: PathBuf,
}

/// The directory of a recipe path. A symbolic link anywhere on the way there is
/// refused, except one owned by root when this user is not root: those are the
/// system's own layout (for example `/var` and `/tmp` on macOS), not something a
/// project can bring along.
fn recipe_place(recipe: &Path, cwd: &Path, me: u32) -> Result<Place> {
    place_as(INVENTORY, recipe, cwd, me)
}

fn place_as(who: Who, recipe: &Path, cwd: &Path, me: u32) -> Result<Place> {
    let dir = match recipe.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    // `join` keeps an absolute `dir` as it is.
    let shown: PathBuf = cwd.join(dir).components().collect();
    let mut walked = cwd.to_path_buf();
    for c in dir.components() {
        walked.push(c);
        if matches!(c, Component::Normal(_)) {
            let md = std::fs::symlink_metadata(&walked).map_err(|e| {
                refuse_as(who, &shown, format!("cannot inspect the directory: {e}"))
            })?;
            if md.file_type().is_symlink() && !link_is_system_layout(md.uid(), me) {
                return Err(refuse_as(
                    who,
                    &shown,
                    format!(
                        "the recipe's directory is reached through the symbolic link {}",
                        walked.strip_prefix(cwd).unwrap_or(&walked).display()
                    ),
                ));
            }
        }
    }
    // The walk above saw the whole path; this also holds if the last component
    // was changed into a link since.
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
    let fd = open_at(None, shown.as_os_str(), flags).map_err(|e| {
        refuse_as(
            who,
            &shown,
            format!("cannot open the recipe's directory: {e}"),
        )
    })?;
    let md = fstat(&fd).map_err(|e| refuse_as(who, &shown, e))?;
    Ok(Place { fd, md, shown })
}

/// One candidate: exists, opened and not yet judged.
struct Found {
    fd: OwnedFd,
    path: PathBuf,
    /// The directory holding it.
    dir: Metadata,
}

/// Open every candidate of one place. A name that is absent is skipped; every
/// other failure is an error, because a candidate exists that cannot be judged.
fn open_candidates(place: &Place, found: &mut Vec<Found>) -> Result<()> {
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY;
    for name in DETECTED_NAMES {
        let path = place.shown.join(name);
        match open_at(Some(&place.fd), std::ffi::OsStr::new(name), flags) {
            Ok(fd) => found.push(Found {
                fd,
                path,
                dir: place.md.clone(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::EMLINK)) => {
                return Err(refuse(&path, "refusing a symbolic link"));
            }
            Err(e) => return Err(refuse(&path, format!("cannot open it: {e}"))),
        }
    }
    Ok(())
}

/// Judge the descriptor, then read it. `after_check` is a test seam between the
/// checks and the read; production passes a no-op.
fn read_trusted(
    found: Found,
    me: u32,
    after_check: &mut dyn FnMut(),
) -> Result<(Vec<u8>, PathBuf)> {
    read_trusted_as(INVENTORY, found, me, after_check)
}

fn read_trusted_as(
    who: Who,
    found: Found,
    me: u32,
    after_check: &mut dyn FnMut(),
) -> Result<(Vec<u8>, PathBuf)> {
    let Found { fd, path, dir } = found;
    let before = fstat(&fd).map_err(|e| refuse_as(who, &path, e))?;
    if !before.file_type().is_file() {
        return Err(refuse_as(who, &path, "not a regular file"));
    }
    if !owner_ok(&before, me) {
        return Err(refuse_as(who, &path, "owned by another user"));
    }
    if before.mode() & 0o022 != 0 {
        return Err(refuse_as(
            who,
            &path,
            format!(
                "writable by group or others (mode {:o})",
                before.mode() & 0o7777
            ),
        ));
    }
    if !owner_ok(&dir, me) {
        return Err(refuse_as(
            who,
            &path,
            "its directory is owned by another user",
        ));
    }
    if dir.mode() & 0o022 != 0 {
        return Err(refuse_as(
            who,
            &path,
            format!(
                "its directory is writable by group or others (mode {:o})",
                dir.mode() & 0o7777
            ),
        ));
    }
    let too_large = || {
        refuse_as(
            who,
            &path,
            format!("larger than {MAX_DETECTED_BYTES} bytes"),
        )
    };
    if before.len() > MAX_DETECTED_BYTES {
        return Err(too_large());
    }
    after_check();
    let mut file = File::from(fd);
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(MAX_DETECTED_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| refuse_as(who, &path, format!("cannot read it: {e}")))?;
    if bytes.len() as u64 > MAX_DETECTED_BYTES {
        return Err(too_large());
    }
    let after = file.metadata().map_err(|e| refuse_as(who, &path, e))?;
    let same = before.len() == after.len()
        && before.nlink() == after.nlink()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && bytes.len() as u64 == after.len();
    if !same {
        return Err(refuse_as(who, &path, "it changed while it was being read"));
    }
    Ok((bytes, path))
}

/// What only an explicit `--inventory` may say.
fn check_detected_fields(inv: &Inventory) -> Result<()> {
    for (name, h) in &inv.hosts {
        if h.known_hosts.is_some() {
            return Err(refuse(
                &inv.path,
                format!("host {name} sets known_hosts, which only an explicit --inventory may do"),
            ));
        }
        if h.identity_files.iter().any(|p| !p.is_absolute()) {
            return Err(refuse(
                &inv.path,
                format!(
                    "host {name} has a relative identity_files entry, whose meaning depends on the current directory (write an absolute path or ~/...)"
                ),
            ));
        }
    }
    Ok(())
}

/// Find, check and load the inventory for a selector run of `recipe`. Every
/// problem is exit 2 before any `ssh -G` or connection, and nothing falls back
/// to another file, to `--host` behaviour or to the local host.
pub fn detect_inventory(recipe: &Path) -> Result<Inventory> {
    let cwd = std::env::current_dir().map_err(|e| {
        SinterError::schema(format!(
            "cannot determine the current directory to look for an inventory: {e}; {ASK}"
        ))
    })?;
    detect_from(&cwd, recipe, &mut || {})
}

/// [`detect_inventory`] for a recipe found through a project's `recipe_paths`:
/// only the current directory, since a shared recipe directory's inventory is not
/// this project's (DESIGN §40.3).
pub fn detect_inventory_here() -> Result<Inventory> {
    let cwd = std::env::current_dir().map_err(|e| {
        SinterError::schema(format!(
            "cannot determine the current directory to look for an inventory: {e}; {ASK}"
        ))
    })?;
    detect_from(&cwd, Path::new("recipe"), &mut || {})
}

/// Open one name in the place and judge it. A symbolic link is refused.
fn read_in_place(who: Who, place: Place, name: &std::ffi::OsStr) -> Result<(Vec<u8>, PathBuf)> {
    let path = place.shown.join(name);
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY;
    let fd = open_at(Some(&place.fd), name, flags).map_err(|e| {
        if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::EMLINK)) {
            refuse_as(who, &path, "refusing a symbolic link")
        } else {
            refuse_as(who, &path, format!("cannot open it: {e}"))
        }
    })?;
    let found = Found {
        fd,
        path,
        dir: place.md,
    };
    read_trusted_as(who, found, euid(), &mut || {})
}

/// The bytes of `name` in the directory `cwd`, when it passes the rules of a
/// detected file: the file and its directory are judged on open descriptors.
pub(crate) fn read_candidate_trusted(
    who: Who,
    cwd: &Path,
    name: &str,
) -> Result<(Vec<u8>, PathBuf)> {
    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let fd = open_at(None, cwd.as_os_str(), flags)
        .map_err(|e| refuse_as(who, cwd, format!("cannot open the directory: {e}")))?;
    let md = fstat(&fd).map_err(|e| refuse_as(who, cwd, e))?;
    let place = Place {
        fd,
        md,
        shown: cwd.to_path_buf(),
    };
    read_in_place(who, place, std::ffi::OsStr::new(name))
}

/// The bytes of a file a project file names, under the same rules; a symbolic
/// link on the way there is treated as on the way to a recipe's directory.
pub(crate) fn read_named_trusted(who: Who, path: &Path) -> Result<(Vec<u8>, PathBuf)> {
    let cwd = std::env::current_dir().map_err(|e| {
        refuse_as(
            who,
            path,
            format!("cannot determine the current directory: {e}"),
        )
    })?;
    let name = path
        .file_name()
        .ok_or_else(|| refuse_as(who, path, "it names no file"))?;
    let place = place_as(who, path, &cwd, euid())?;
    read_in_place(who, place, name)
}

/// `cwd` is the absolute current directory, as the operating system reports it.
fn detect_from(cwd: &Path, recipe: &Path, after_check: &mut dyn FnMut()) -> Result<Inventory> {
    let cwd_flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let cwd_fd = open_at(None, cwd.as_os_str(), cwd_flags)
        .map_err(|e| refuse(cwd, format!("cannot open the current directory: {e}")))?;
    let cwd_md = fstat(&cwd_fd).map_err(|e| refuse(cwd, e))?;
    let here = Place {
        fd: cwd_fd,
        md: cwd_md,
        shown: cwd.to_path_buf(),
    };
    let me = euid();
    let there = recipe_place(recipe, cwd, me)?;
    let same_place = here.md.dev() == there.md.dev() && here.md.ino() == there.md.ino();

    let mut found = Vec::new();
    open_candidates(&here, &mut found)?;
    let searched = if same_place {
        here.shown.display().to_string()
    } else {
        open_candidates(&there, &mut found)?;
        format!("{} and {}", here.shown.display(), there.shown.display())
    };
    if found.len() > 1 {
        let list: Vec<String> = found.iter().map(|f| f.path.display().to_string()).collect();
        return Err(SinterError::schema(format!(
            "several inventories were found ({}); Sinter never picks one, {ASK}",
            list.join(", ")
        )));
    }
    let Some(one) = found.pop() else {
        return Err(SinterError::schema(format!(
            "no inventory for the selector: looked for {} in {searched} (parent directories and the home directory are not searched); name one with --inventory, or use --host for one host",
            DETECTED_NAMES.join(", ")
        )));
    };
    let (bytes, path) = read_trusted(one, me, after_check)?;
    let text = String::from_utf8(bytes).map_err(|_| refuse(&path, "not valid UTF-8"))?;
    let inv = parse_inventory(&text, &path)?;
    check_detected_fields(&inv)?;
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const GOOD: &str = "hosts:\n  web01:\n    address: 192.0.2.11\n";

    struct Project {
        dir: tempfile::TempDir,
    }

    impl Project {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let p = Project { dir };
            p.mkdir("recipes");
            p
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.dir.path().join(rel)
        }

        fn mkdir(&self, rel: &str) {
            std::fs::create_dir_all(self.path(rel)).unwrap();
            std::fs::set_permissions(self.path(rel), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }

        fn write(&self, rel: &str, body: &str) {
            std::fs::write(self.path(rel), body).unwrap();
            std::fs::set_permissions(self.path(rel), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }

        /// Run detection from `cwd` (relative to the project).
        fn detect(&self, cwd: &str, recipe: &str) -> Result<Inventory> {
            self.detect_with(cwd, recipe, &mut || {})
        }

        fn detect_with(
            &self,
            cwd: &str,
            recipe: &str,
            hook: &mut dyn FnMut(),
        ) -> Result<Inventory> {
            let cwd: PathBuf = self.path(cwd).components().collect();
            detect_from(&cwd, Path::new(recipe), hook)
        }
    }

    fn refused(r: Result<Inventory>, want: &str) {
        let e = r.expect_err(want);
        assert_eq!(e.kind, crate::error::ErrorKind::Schema, "{}", e.message);
        assert!(e.message.contains(want), "{want}: {}", e.message);
    }

    #[test]
    fn finds_one_file_in_either_place() {
        for (name, body) in [
            ("hosts.yaml", GOOD),
            ("hosts.yml", GOOD),
            ("hosts.toml", "[hosts.web01]\naddress = \"192.0.2.11\"\n"),
        ] {
            for (place, cwd, recipe) in [
                ("", ".", "r.yaml"),
                ("", ".", "recipes/r.yaml"),
                ("recipes/", ".", "recipes/r.yaml"),
                ("recipes/", "recipes", "r.yaml"),
                ("", "recipes", "../r.yaml"),
            ] {
                let p = Project::new();
                p.write(&format!("{place}{name}"), body);
                let inv = p
                    .detect(cwd, recipe)
                    .unwrap_or_else(|e| panic!("{place}{name} {cwd} {recipe}: {}", e.message));
                assert_eq!(inv.hosts["web01"].address, "192.0.2.11");
                assert!(inv.path.is_absolute(), "{}", inv.path.display());
                assert!(inv.path.ends_with(name), "{}", inv.path.display());
                let shown = inv.path.display().to_string();
                assert!(!shown.contains("/./"), "{shown}");
            }
        }
    }

    #[test]
    fn an_absolute_recipe_path_works_through_the_system_layout() {
        // Root gets no exception for root's links, and on macOS a temporary
        // directory lies behind one (`link_is_system_layout`).
        if euid() == 0 {
            return;
        }
        let p = Project::new();
        p.write("recipes/hosts.yaml", GOOD);
        let abs = p.path("recipes/r.yaml").display().to_string();
        assert!(p.detect(".", &abs).is_ok());
    }

    #[test]
    fn nothing_found_names_the_places_and_never_searches_parents() {
        let p = Project::new();
        p.mkdir("recipes/deep");
        p.write("hosts.yaml", GOOD);
        p.write("recipes/hosts.yaml", GOOD);
        // Both are parents of the only two places searched here.
        let e = p.detect("recipes/deep", "r.yaml").unwrap_err();
        assert!(e.message.contains("no inventory"), "{}", e.message);
        assert!(e.message.contains("hosts.toml"), "{}", e.message);
        assert!(e.message.contains("--inventory"), "{}", e.message);
    }

    #[test]
    fn several_candidates_are_refused_and_none_is_picked() {
        let p = Project::new();
        p.write("hosts.yaml", GOOD);
        p.write("hosts.yml", GOOD);
        refused(p.detect(".", "r.yaml"), "several inventories");

        let p = Project::new();
        p.write("hosts.yaml", GOOD);
        p.write("recipes/hosts.yaml", GOOD);
        let e = p.detect(".", "recipes/r.yaml").unwrap_err();
        assert!(e.message.contains("several inventories"), "{}", e.message);
        assert!(e.message.contains("recipes"), "{}", e.message);

        // Different names of one file are candidates too: their format differs.
        let p = Project::new();
        p.write("hosts.yaml", GOOD);
        std::fs::hard_link(p.path("hosts.yaml"), p.path("hosts.toml")).unwrap();
        refused(p.detect(".", "r.yaml"), "several inventories");
    }

    #[test]
    fn the_same_directory_reached_twice_is_one_place() {
        let p = Project::new();
        p.write("hosts.yaml", GOOD);
        for recipe in ["r.yaml", "./r.yaml", "../{}/r.yaml"] {
            let base = p.dir.path().file_name().unwrap().to_str().unwrap();
            let recipe = recipe.replace("{}", base);
            assert!(p.detect(".", &recipe).is_ok(), "{recipe}");
        }
    }

    #[test]
    fn symbolic_links_are_refused() {
        // A link to a good file, a dangling link, and a link that hides behind
        // a good candidate elsewhere.
        let p = Project::new();
        p.write("real.yaml", GOOD);
        symlink(p.path("real.yaml"), p.path("hosts.yaml")).unwrap();
        refused(p.detect(".", "r.yaml"), "symbolic link");

        let p = Project::new();
        symlink(p.path("nowhere"), p.path("hosts.yaml")).unwrap();
        refused(p.detect(".", "r.yaml"), "symbolic link");

        let p = Project::new();
        p.write("recipes/hosts.yaml", GOOD);
        symlink(p.path("recipes/hosts.yaml"), p.path("hosts.yml")).unwrap();
        refused(p.detect(".", "recipes/r.yaml"), "symbolic link");
    }

    #[test]
    fn a_recipe_directory_reached_through_a_link_is_refused() {
        let p = Project::new();
        p.mkdir("elsewhere/sub");
        p.write("elsewhere/hosts.yaml", GOOD);
        p.write("elsewhere/sub/hosts.yaml", GOOD);
        symlink(p.path("elsewhere"), p.path("link")).unwrap();
        // The last component, an earlier one, and an absolute path.
        refused(p.detect(".", "link/r.yaml"), "symbolic link");
        refused(p.detect(".", "link/sub/r.yaml"), "symbolic link");
        let abs = p.path("link/r.yaml").display().to_string();
        refused(p.detect(".", &abs), "symbolic link");
        // The recipe file itself may be a link: its directory is where it was
        // named, not where it points.
        p.write("elsewhere/r.yaml", "");
        symlink(p.path("elsewhere/r.yaml"), p.path("r.yaml")).unwrap();
        p.write("hosts.yaml", GOOD);
        assert!(p.detect(".", "r.yaml").is_ok());
    }

    #[test]
    fn only_root_links_seen_by_another_user_are_the_system_layout() {
        assert!(link_is_system_layout(0, 501));
        // A root run owns every link it cloned or unpacked.
        assert!(!link_is_system_layout(0, 0));
        assert!(!link_is_system_layout(501, 501));
        assert!(!link_is_system_layout(502, 501));
        assert!(!link_is_system_layout(501, 0));
    }

    #[test]
    fn modes_are_checked_on_the_file_and_its_directory() {
        for mode in [0o664, 0o646, 0o666, 0o777] {
            let p = Project::new();
            p.write("hosts.yaml", GOOD);
            std::fs::set_permissions(p.path("hosts.yaml"), PermissionsExt::from_mode(mode))
                .unwrap();
            refused(p.detect(".", "r.yaml"), "writable by group or others");
        }
        for mode in [0o775, 0o757, 0o777, 0o1777] {
            let p = Project::new();
            p.write("recipes/hosts.yaml", GOOD);
            std::fs::set_permissions(p.path("recipes"), PermissionsExt::from_mode(mode)).unwrap();
            refused(
                p.detect(".", "recipes/r.yaml"),
                "its directory is writable by group or others",
            );
        }
        // Read-only and owner-only are fine.
        for mode in [0o400, 0o600, 0o640, 0o644] {
            let p = Project::new();
            p.write("hosts.yaml", GOOD);
            std::fs::set_permissions(p.path("hosts.yaml"), PermissionsExt::from_mode(mode))
                .unwrap();
            assert!(p.detect(".", "r.yaml").is_ok(), "{mode:o}");
        }
    }

    #[test]
    fn owner_is_this_user_or_root() {
        assert!(owner_allowed(501, 501));
        assert!(owner_allowed(0, 501));
        assert!(owner_allowed(0, 0));
        assert!(!owner_allowed(502, 501));
        assert!(!owner_allowed(501, 0));
        assert!(owner_ok(
            &std::fs::metadata(tempfile::tempdir().unwrap().path()).unwrap(),
            euid()
        ));
        assert!(owner_ok(&std::fs::metadata("/").unwrap(), euid()));
        // Really giving a file away needs root, and the release gate is not root:
        // `another_users_file_and_directory_are_refused` is what runs there.
        if euid() == 0 {
            let give_away = |path: &Path| {
                let c = CString::new(path.as_os_str().as_bytes()).unwrap();
                // SAFETY: `c` is a valid path string.
                assert_eq!(unsafe { libc::chown(c.as_ptr(), 12345, 12345) }, 0);
            };
            let p = Project::new();
            p.write("hosts.yaml", GOOD);
            give_away(&p.path("hosts.yaml"));
            refused(p.detect(".", "r.yaml"), "owned by another user");

            let p = Project::new();
            p.write("recipes/hosts.yaml", GOOD);
            give_away(&p.path("recipes"));
            refused(
                p.detect(".", "recipes/r.yaml"),
                "its directory is owned by another user",
            );
        }
    }

    #[test]
    fn another_users_file_and_directory_are_refused() {
        // Without root nothing here can belong to another user, so the same
        // descriptors and metadata are judged as seen by a stand-in user.
        let real = euid();
        if real == 0 {
            return; // Root's own branch is in `owner_is_this_user_or_root`.
        }
        let other = real + 1;
        let open = |path: &Path| open_at(None, path.as_os_str(), libc::O_RDONLY).unwrap();
        let judge = |path: &Path, dir: &Path, me: u32| {
            let found = Found {
                fd: open(path),
                path: path.to_path_buf(),
                dir: std::fs::metadata(dir).unwrap(),
            };
            read_trusted(found, me, &mut || {}).map(|(bytes, _)| bytes)
        };
        let p = Project::new();
        p.write("hosts.yaml", GOOD);
        let (file, dir) = (p.path("hosts.yaml"), p.dir.path().to_path_buf());
        assert_eq!(judge(&file, &dir, real).unwrap(), GOOD.as_bytes());
        let e = judge(&file, &dir, other).unwrap_err();
        assert!(e.message.contains("owned by another user"), "{}", e.message);
        assert!(!e.message.contains("its directory"), "{}", e.message);
        // A root-owned file gets past the file's own check, so the directory is
        // what is judged. It is refused before the file is read.
        let e = judge(Path::new("/etc/passwd"), &dir, other).unwrap_err();
        assert!(
            e.message.contains("its directory is owned by another user"),
            "{}",
            e.message
        );
    }

    #[test]
    fn what_is_not_a_regular_file_is_refused_without_hanging() {
        let p = Project::new();
        std::fs::create_dir(p.path("hosts.yaml")).unwrap();
        refused(p.detect(".", "r.yaml"), "not a regular file");

        let p = Project::new();
        let c = CString::new(p.path("hosts.yaml").as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid path string.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        refused(p.detect(".", "r.yaml"), "not a regular file");
    }

    #[test]
    fn an_invalid_file_is_an_error_not_a_miss() {
        let p = Project::new();
        p.write("hosts.yaml", "hosts: [\n");
        refused(p.detect(".", "r.yaml"), "invalid inventory");

        let p = Project::new();
        std::fs::write(p.path("hosts.yaml"), [0xff, 0xfe, 0x00]).unwrap();
        std::fs::set_permissions(p.path("hosts.yaml"), PermissionsExt::from_mode(0o644)).unwrap();
        refused(p.detect(".", "r.yaml"), "UTF-8");

        let p = Project::new();
        let big = " ".repeat(MAX_DETECTED_BYTES as usize + 1);
        p.write("hosts.yaml", &big);
        refused(p.detect(".", "r.yaml"), "larger than");
    }

    #[test]
    fn known_hosts_and_relative_keys_are_refused_in_a_detected_file() {
        for (body, want) in [
            (
                "hosts:\n  web01:\n    known_hosts: ./evil\n",
                "sets known_hosts",
            ),
            (
                "hosts:\n  web01:\n    known_hosts: /etc/ssh/ssh_known_hosts\n",
                "sets known_hosts",
            ),
            // Any host, also one no selector would name.
            (
                "hosts:\n  web01: {}\n  other:\n    known_hosts: ~/.ssh/k\n",
                "sets known_hosts",
            ),
            (
                "hosts:\n  web01:\n    identity_files: [keys/id]\n",
                "relative identity_files",
            ),
            (
                "hosts:\n  web01:\n    identity_files: [\"~other/id\"]\n",
                "relative identity_files",
            ),
        ] {
            let p = Project::new();
            p.write("hosts.yaml", body);
            refused(p.detect(".", "r.yaml"), want);
        }
        // Absolute keys stay allowed: a host may need its own key (DESIGN §39.4).
        let p = Project::new();
        p.write(
            "hosts.yaml",
            "hosts:\n  web01:\n    identity_files: [/etc/sinter/id, ~/.ssh/id_lab]\n",
        );
        assert_eq!(
            p.detect(".", "r.yaml").unwrap().hosts["web01"]
                .identity_files
                .len(),
            2
        );
    }

    #[test]
    fn a_malicious_address_is_refused() {
        let p = Project::new();
        p.write(
            "hosts.yaml",
            "hosts:\n  web01:\n    address: \"-oProxyCommand=x\"\n",
        );
        let e = p.detect(".", "r.yaml").unwrap_err();
        assert_eq!(e.kind, crate::error::ErrorKind::Schema);
    }

    #[test]
    fn a_change_while_reading_is_refused() {
        // In-place change after the checks: the very file read has changed.
        let p = Project::new();
        p.write("hosts.yaml", GOOD);
        let path = p.path("hosts.yaml");
        let mut hook = || {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b"  web02: {}\n").unwrap();
        };
        refused(p.detect_with(".", "r.yaml", &mut hook), "changed while");
    }

    #[test]
    fn replacing_the_name_after_the_checks_is_refused_and_never_read() {
        // The swap cannot reach the descriptor, and it also changes the checked
        // file's link count, so it is noticed: refused, not silently ignored.
        let p = Project::new();
        p.write("hosts.yaml", GOOD);
        p.write("evil", "hosts:\n  web01:\n    address: 198.51.100.66\n");
        let (from, to) = (p.path("evil"), p.path("hosts.yaml"));
        let mut hook = || std::fs::rename(&from, &to).unwrap();
        refused(p.detect_with(".", "r.yaml", &mut hook), "changed while");
    }
}
