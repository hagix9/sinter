//! Pre-apply backup of recipe-declared paths (`backup.paths`).
//!
//! This is deliberately not a backup product and not a rollback mechanism:
//! before `apply` mutates anything, each declared path is copied, on the
//! target itself, into a fresh per-invocation directory so an operator can
//! inspect or restore the previous state by hand. Sinter never restores,
//! prunes, or reads back backup content.
//!
//! Store (on the target):
//!
//! * `--sudo`: `/var/lib/sinter/backups/<run-id>/`
//! * otherwise: `$HOME/.sinter/backups/<run-id>/` of the target user
//! * a path's `directory`, else its recipe's `backup.directory`, else a project
//!   file's: `<that directory>/<run-id>/` (DESIGN §40.6). One apply can use several.
//!
//! Inside the run directory the original absolute path is reproduced, e.g.
//! `/var/lib/sinter/backups/20260928T101530Z-3f9a2c1d/etc/ssh/sshd_config`.
//! The run id is `<UTC timestamp>-<random>`, shared by every target of one
//! invocation; each target stores on its own host, so hosts are separated
//! physically. Store directories Sinter creates are mode 0700 and every
//! ancestor must pass the DESIGN §23 trust check.
//!
//! Semantics:
//!
//! * plan: lists the declared paths as planned; creates nothing, observes
//!   nothing.
//! * apply: copies every path before the first resource runs. Any failure
//!   aborts the invocation before any resource runs (exit 5); a partially
//!   written run directory is left in place and named in the error.
//! * audit: backups are not desired state and are not audited.
//! * An absent path is recorded as `absent` (the pre-apply state was "does
//!   not exist"); it is not a failure.
//! * Regular files, directories (recursively) and symlinks (as links, never
//!   followed) are copied with `cp -a`. Mode (including POSIX ACLs),
//!   ownership and timestamps must be preserved or the backup fails; other
//!   extended attributes and SELinux labels are preserved on a best-effort
//!   basis (GNU `cp -a`). Other object types (devices, FIFOs, sockets) fail.
//! * Content is never read by the controller and never printed; only paths,
//!   object kinds and the store location appear in output.
//! * A regular file in another account's directory tree is read as that account
//!   and written as root (DESIGN §40.7, [`crate::fsbackup`]). Nothing else in
//!   such a tree is copied.

use crate::error::{Result, SinterError};
use crate::progress::StageTracker;
use crate::targetfs::{ObjKind, TargetFs};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupStatus {
    /// Plan: would be copied by apply.
    Planned,
    /// Apply: copied into the run directory.
    BackedUp,
    /// Apply: the path did not exist; nothing to copy.
    Absent,
    /// Apply: copying this path failed (backup failure report only).
    Failed,
    /// Apply: not attempted because the backup failed earlier (backup
    /// failure report only).
    NotRun,
}

impl BackupStatus {
    pub fn label(self) -> &'static str {
        match self {
            BackupStatus::Planned => "planned",
            BackupStatus::BackedUp => "backed_up",
            BackupStatus::Absent => "absent",
            BackupStatus::Failed => "failed",
            BackupStatus::NotRun => "not_run",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackupEntry {
    pub path: String,
    pub status: BackupStatus,
    /// `file`, `directory` or `symlink` when copied.
    pub kind: Option<&'static str>,
    /// Copy location on the target when copied.
    pub destination: Option<String>,
    /// The store this path goes to, when known.
    pub store: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BackupReport {
    /// Set by apply.
    pub run_id: Option<String>,
    /// Run directory on the target when there is exactly one, set by apply.
    pub directory: Option<String>,
    /// Every run directory this invocation made, in order.
    pub directories: Vec<String>,
    pub entries: Vec<BackupEntry>,
}

/// Store root for a target execution identity.
pub fn store_root(sudo: bool, home: &str) -> String {
    if sudo {
        "/var/lib/sinter/backups".to_string()
    } else {
        format!("{}/.sinter/backups", home.trim_end_matches('/'))
    }
}

/// The directories `perform` creates, in order, when they are absent: the
/// store's base and the store root. The run directory below the root is also
/// created, under a name no recipe can know in advance.
pub(crate) fn store_chain(sudo: bool, home: &str) -> Vec<String> {
    let base = if sudo {
        "/var/lib/sinter".to_string()
    } else {
        format!("{}/.sinter", home.trim_end_matches('/'))
    };
    vec![base, store_root(sudo, home)]
}

/// A fresh run id: `YYYYMMDDTHHMMSSZ-<8 hex>` (UTC).
pub fn new_run_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut rnd = [0u8; 4];
    let got = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut rnd));
    if got.is_err() {
        // Uniqueness is still enforced by the non-`-p` mkdir of the run dir.
        let n = std::process::id() ^ (now as u32);
        rnd = n.to_be_bytes();
    }
    format!(
        "{}-{:02x}{:02x}{:02x}{:02x}",
        utc_stamp(now),
        rnd[0],
        rnd[1],
        rnd[2],
        rnd[3]
    )
}

/// `YYYYMMDDTHHMMSSZ` for a Unix timestamp (proleptic Gregorian, UTC).
pub fn utc_stamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (H. Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Plan-mode report: declared paths only; nothing observed or created.
pub fn planned(paths: &[String]) -> BackupReport {
    planned_in(paths, &BTreeMap::new(), None)
}

/// [`planned`], saying where each path would go: what the recipe names, else
/// `fallback` when it is known.
pub fn planned_in(
    paths: &[String],
    stores: &BTreeMap<String, String>,
    fallback: Option<&str>,
) -> BackupReport {
    BackupReport {
        run_id: None,
        directory: None,
        directories: Vec::new(),
        entries: paths
            .iter()
            .map(|p| BackupEntry {
                path: p.clone(),
                status: BackupStatus::Planned,
                kind: None,
                destination: None,
                store: stores
                    .get(p)
                    .cloned()
                    .or_else(|| fallback.map(str::to_string)),
            })
            .collect(),
    }
}

/// A store path from a recipe or a project file: absolute, normalized, not
/// the root directory (DESIGN §40.6). A pure check, made before anything runs.
pub fn validate_store_dir(path: &str) -> Result<()> {
    crate::paths::validate_path(path)
        .map_err(|e| SinterError::schema(format!("backup store {path}: {}", e.message)))?;
    if path == "/" {
        return Err(SinterError::schema(
            "backup store: the root directory cannot be the store",
        ));
    }
    if path.chars().any(char::is_control) {
        return Err(SinterError::schema(
            "backup store: the path has a control character",
        ));
    }
    Ok(())
}

/// What `plan` can say about a store named by the operator without creating
/// anything: the checks apply makes first. Read-only.
pub(crate) fn check_named_store(fs: &mut TargetFs, dir: &str, paths: &[String]) -> Result<()> {
    for p in paths {
        check_overlap(p, dir)?;
    }
    fs.check_trusted_parents_strict(dir)?;
    if fs.shared_parent() {
        return Err(SinterError::apply(format!(
            "backup store {dir} is directly in a shared directory (sticky and writable by other \
             accounts, such as /tmp), where anyone can make that name first; use another location"
        )));
    }
    let st = fs.inspect(dir)?;
    match st.kind {
        ObjKind::Absent => Ok(()),
        ObjKind::Dir => {
            check_existing_store_dir(fs, dir, &st)?;
            // The walk of the run directory judges the store itself (an ACL, which
            // the mode does not show): plan says what apply would. It only reads.
            fs.check_trusted_parents_strict(&format!("{dir}/run"))
        }
        other => Err(SinterError::apply(format!(
            "backup store path {} is a {}, not a directory",
            dir,
            other.describe()
        ))),
    }
}

/// `a` is `b` or lies inside it.
fn inside(a: &str, b: &str) -> bool {
    a == b || a.starts_with(&format!("{}/", b))
}

/// Declared paths may not overlap. One of two overlapping paths is a directory,
/// and a copy of it can leave whatever its owner put there in the run directory,
/// a symbolic link included, for the other copy to write through as the invocation
/// (DESIGN §40.7). A pure check on the declaration, so it holds in every phase.
pub fn check_declared_overlap(paths: &[String]) -> Result<()> {
    for (i, a) in paths.iter().enumerate() {
        for b in &paths[i + 1..] {
            if inside(a, b) || inside(b, a) {
                return Err(SinterError::schema(format!(
                    "backup paths {a} and {b} overlap: the copy of one could redirect the other; declare only one of them"
                )));
            }
        }
    }
    Ok(())
}

/// One store may not contain another: its run directories would lie in the other's
/// tree, and what one copy left there would be in the way of the other.
fn check_stores_apart(a: &str, b: &str) -> Result<()> {
    if a != b && (inside(a, b) || inside(b, a)) {
        return Err(SinterError::schema(format!(
            "backup stores {a} and {b} overlap: one would lie inside the other; use one store, or two apart"
        )));
    }
    Ok(())
}

/// What a recipe's declaration alone can say about its stores (DESIGN §40.6): no
/// path overlaps any store, whichever path names it, and no store contains another.
/// A pure check, so it holds in every phase.
pub fn check_declared_stores(paths: &[String], stores: &BTreeMap<String, String>) -> Result<()> {
    let dirs: Vec<&String> = stores.values().collect();
    for (i, a) in dirs.iter().enumerate() {
        for b in &dirs[i + 1..] {
            check_stores_apart(a, b)?;
        }
        for p in paths {
            check_overlap(p, a).map_err(|e| SinterError::schema(e.message))?;
        }
    }
    Ok(())
}

/// The stores of one run in the order of the declaration, each once, and the store
/// of each path: its own, else `fallback`.
fn stores_of<'a>(
    paths: &'a [String],
    stores: &'a BTreeMap<String, String>,
    fallback: &'a str,
) -> Vec<&'a str> {
    let mut roots: Vec<&str> = Vec::new();
    for p in paths {
        let root = stores.get(p).map_or(fallback, String::as_str);
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    roots
}

/// The checks of every store a plan would use, read-only: what apply would refuse
/// before it makes anything. `named` is the project file's store.
pub(crate) fn check_planned_stores(
    fs: &mut TargetFs,
    paths: &[String],
    stores: &BTreeMap<String, String>,
    named: Option<&str>,
) -> Result<()> {
    let default = store_root(fs.sudo(), &fs.home_env());
    let fallback = named.unwrap_or(&default);
    let roots = stores_of(paths, stores, fallback);
    for (i, a) in roots.iter().enumerate() {
        for b in &roots[i + 1..] {
            check_stores_apart(a, b)?;
        }
        for p in paths {
            check_overlap(p, a)?;
        }
    }
    for root in &roots {
        if *root != default || named == Some(*root) || stores.values().any(|d| d == root) {
            check_named_store(fs, root, paths)?;
        }
    }
    Ok(())
}

/// Reject a declared path that contains, or lies inside, the store root.
pub fn check_overlap(path: &str, root: &str) -> Result<()> {
    if inside(root, path) || inside(path, root) {
        return Err(SinterError::apply(format!(
            "backup path {} overlaps the backup store {}",
            path, root
        )));
    }
    Ok(())
}

/// Where a backup failure happened, for the structured failure report.
struct Progress<'a> {
    run_id: &'a str,
    paths: &'a [String],
    /// Run directories this invocation has created so far.
    run_dirs: &'a [String],
    /// Entries completed before the failure.
    done: &'a [BackupEntry],
    /// The path whose copy failed, if the failure was per-path.
    failed: Option<&'a str>,
}

/// Build the apply error for a backup failure. The error carries a
/// structured [`BackupReport`] (paths, statuses, kinds, locations — never
/// content) so machine-readable output can report it; the message keeps the
/// human wording.
fn fail(p: &Progress<'_>, e: SinterError) -> SinterError {
    let where_ = if p.run_dirs.is_empty() {
        String::new()
    } else {
        format!(
            "; partial backup left at {} (not removed)",
            p.run_dirs.join(", ")
        )
    };
    let mut entries: Vec<BackupEntry> = p.done.to_vec();
    for path in &p.paths[p.done.len()..] {
        let status = if Some(path.as_str()) == p.failed {
            BackupStatus::Failed
        } else {
            BackupStatus::NotRun
        };
        entries.push(BackupEntry {
            path: path.clone(),
            status,
            kind: None,
            destination: None,
            store: None,
        });
    }
    let mut err = SinterError::apply(format!(
        "backup failed; no resource was executed: {}{}",
        e.message, where_
    ));
    err.backup = Some(Box::new(BackupReport {
        run_id: Some(p.run_id.to_string()),
        directory: match p.run_dirs {
            [one] => Some(one.clone()),
            _ => None,
        },
        directories: p.run_dirs.to_vec(),
        entries,
    }));
    err
}

/// Ensure `dir` exists as a trusted directory, creating it 0700 if absent.
/// The directory is created with `mkdir -m 0700` (RW-020), so with GNU
/// coreutils it never exists with a wider mode; the `chmod 0700` that follows
/// is kept, for a `mkdir` that sets the mode only after creating the entry.
fn ensure_dir(fs: &mut TargetFs, dir: &str) -> Result<()> {
    fs.check_trusted_parents_strict(dir)?;
    let permit = fs.mutation_permit()?;
    let st = fs.inspect(dir)?;
    match st.kind {
        ObjKind::Dir => check_existing_store_dir(fs, dir, &st),
        ObjKind::Absent => match fs.mkdir_private(&permit, dir) {
            Ok(()) => fs.chmod(&permit, dir, 0o700),
            Err(e) => {
                // A concurrent invocation may have created it between the
                // inspection and mkdir. Accept only a directory that passes
                // the same checks as a pre-existing one; never chmod it.
                let again = fs.inspect(dir)?;
                if again.kind == ObjKind::Dir {
                    check_existing_store_dir(fs, dir, &again)
                } else {
                    Err(e)
                }
            }
        },
        other => Err(SinterError::apply(format!(
            "backup store path {} is a {}, not a directory",
            dir,
            other.describe()
        ))),
    }
}

/// An existing store directory must be owned by a trusted principal and not
/// be group/other writable (its ACLs are checked by the later §23 check of
/// the run directory's ancestors).
fn check_existing_store_dir(fs: &TargetFs, dir: &str, st: &crate::targetfs::Stat) -> Result<()> {
    let trusted = st.uid == 0 || (!fs.sudo() && st.uid == fs.target_uid());
    if !trusted {
        return Err(SinterError::apply(format!(
            "backup store directory {} is owned by uid {}, outside the trusted set",
            dir, st.uid
        )));
    }
    if st.mode & 0o022 != 0 {
        return Err(SinterError::apply(format!(
            "backup store directory {} grants group or other write access",
            dir
        )));
    }
    Ok(())
}

/// Apply-mode backup. Runs before any resource; any error aborts apply.
///
/// `stage` observes the copy of each declared path (one item per path, with no
/// identity: a backup path is target data). Store setup before the first copy
/// is not an item. It never influences the copy.
pub(crate) fn perform(
    fs: &mut TargetFs,
    paths: &[String],
    stores: &BTreeMap<String, String>,
    run_id: &str,
    named_store: Option<&str>,
    stage: &mut StageTracker<'_>,
) -> Result<BackupReport> {
    let sudo = fs.sudo();
    let home = fs.home_env();
    let default = store_root(sudo, &home);
    let fallback = named_store.unwrap_or(&default);
    let before_store = Progress {
        run_id,
        paths,
        run_dirs: &[],
        done: &[],
        failed: None,
    };
    check_declared_overlap(paths).map_err(|e| fail(&before_store, e))?;
    let roots = stores_of(paths, stores, fallback);
    for (i, a) in roots.iter().enumerate() {
        for b in &roots[i + 1..] {
            check_stores_apart(a, b).map_err(|e| fail(&before_store, e))?;
        }
        for p in paths {
            check_overlap(p, a).map_err(|e| fail(&before_store, e))?;
        }
    }
    // Every store is checked and made before the first copy, so a store that
    // cannot be used stops the apply with nothing copied.
    let mut run_dirs: Vec<String> = Vec::new();
    for root in &roots {
        let failing = Progress {
            run_dirs: &run_dirs,
            ..before_store
        };
        if *root == default && named_store != Some(*root) && !stores.values().any(|d| d == root) {
            // Create the store chain below an existing trusted base.
            for d in &store_chain(sudo, &home) {
                ensure_dir(fs, d).map_err(|e| fail(&failing, e))?;
            }
        } else {
            // Only the named directory is made: its parent is the operator's to have.
            check_named_store(fs, root, paths).map_err(|e| fail(&failing, e))?;
            ensure_dir(fs, root).map_err(|e| fail(&failing, e))?;
        }
        let run_dir = format!("{}/{}", root, run_id);
        fs.check_trusted_parents_strict(&run_dir)
            .map_err(|e| fail(&failing, e))?;
        let permit = fs.mutation_permit()?;
        // Plain (non `-p`) mkdir, mode 0700 from the start: an existing run
        // directory is a collision and fails. It is not ours, so the failure
        // report does not name it.
        fs.mkdir_private(&permit, &run_dir).map_err(|e| {
            fail(
                &failing,
                SinterError::apply(format!(
                    "cannot create backup run directory {} (collision or store error): {}",
                    run_dir, e.message
                )),
            )
        })?;
        run_dirs.push(run_dir.clone());
        let created = Progress {
            run_dirs: &run_dirs,
            ..before_store
        };
        fs.chmod(&permit, &run_dir, 0o700)
            .map_err(|e| fail(&created, e))?;
    }

    let permit = fs.mutation_permit()?;
    let mut entries: Vec<BackupEntry> = Vec::new();
    for p in paths {
        stage.item_started(None);
        let root = stores.get(p).map_or(fallback, String::as_str);
        let run_dir = format!("{}/{}", root, run_id);
        match copy_one(fs, &permit, p, &run_dir) {
            Ok(mut entry) => {
                entry.store = Some(root.to_string());
                entries.push(entry);
            }
            Err(e) => {
                let at = Progress {
                    run_dirs: &run_dirs,
                    done: &entries,
                    failed: Some(p),
                    ..before_store
                };
                return Err(fail(
                    &at,
                    SinterError::apply(format!("{}: {}", p, e.message)),
                ));
            }
        }
    }
    Ok(BackupReport {
        run_id: Some(run_id.to_string()),
        directory: match &run_dirs[..] {
            [one] => Some(one.clone()),
            _ => None,
        },
        directories: run_dirs,
        entries,
    })
}

fn copy_one(
    fs: &mut TargetFs,
    permit: &crate::targetfs::MutationPermit,
    path: &str,
    run_dir: &str,
) -> Result<BackupEntry> {
    // The walk itself is the invocation's. Inside another account's tree it
    // settles that account's identity, and the path is then handled as that
    // account only (DESIGN §40.7). A non-root invocation has no such tree: for it
    // this walk is the strict one.
    fs.check_trusted_parents(path)?;
    if let Some(tree) = fs.tree_identity().cloned() {
        return copy_from_tree(fs, permit, &tree, path, run_dir);
    }
    let st = fs.inspect(path)?;
    // The parents are trusted here, but a directory of another account is the top of
    // its tree: it is not walked as the invocation (DESIGN §40.7).
    if st.kind == ObjKind::Dir && !fs.is_trusted_owner(st.uid) {
        return Err(SinterError::apply(format!(
            "a directory owned by uid {} is not backed up: root does not walk a tree another account controls, and copying a live data directory file by file is not a consistent backup; list the files, and use the service's own backup tool for its data",
            st.uid
        )));
    }
    // FS2-A3. A directory directly in a shared directory is not copied: the
    // entry gate judged only the directory itself, and `cp -a` would read
    // everything below it as root, including what other accounts put there.
    // Refused before anything is read or created for it. A file or a symlink
    // there passed the gate (owned by a trusted principal, one hard link) and
    // is copied as before; a directory elsewhere is copied as before.
    if st.kind == ObjKind::Dir && fs.shared_parent() {
        return Err(SinterError::apply(
            "a directory directly in a shared directory (sticky and writable by other \
             accounts, such as /tmp) is not backed up: its contents can be placed there by \
             other accounts; list the files to back up instead",
        ));
    }
    let kind = match st.kind {
        ObjKind::Absent => {
            return Ok(BackupEntry {
                path: path.to_string(),
                status: BackupStatus::Absent,
                kind: None,
                destination: None,
                store: None,
            })
        }
        ObjKind::File => "file",
        ObjKind::Dir => "directory",
        ObjKind::Symlink => "symlink",
        other => {
            return Err(SinterError::apply(format!(
                "unsupported object type {} for backup",
                other.describe()
            )))
        }
    };
    let dest = format!("{}{}", run_dir, path);
    let (parent, _) = crate::paths::parent_and_name(path);
    if parent != "/" {
        fs.mkdir_p(permit, &format!("{}{}", run_dir, parent))?;
    }
    fs.backup_copy(permit, path, &dest)?;
    Ok(BackupEntry {
        path: path.to_string(),
        status: BackupStatus::BackedUp,
        kind: Some(kind),
        destination: Some(dest),
        store: None,
    })
}

/// One path inside another account's tree. Every observation of it runs as the
/// account (the identity the walk just set); the checks here give the reason a
/// person can act on, and the script repeats them on what it really reads.
fn copy_from_tree(
    fs: &mut TargetFs,
    permit: &crate::targetfs::MutationPermit,
    tree: &crate::targetfs::TreeIdentity,
    path: &str,
    run_dir: &str,
) -> Result<BackupEntry> {
    let refuse = |what: String| {
        SinterError::apply(format!(
            "in the directory tree of uid {} at {}: {what}",
            tree.uid, tree.root
        ))
    };
    if tree.in_shared {
        return Err(refuse(
            "it is directly in a shared directory (such as /tmp), where any account can have \
             made it, and a backup has no owner to compare with; it is not backed up"
                .to_string(),
        ));
    }
    let st = fs.inspect(path)?;
    match st.kind {
        ObjKind::Absent => {
            fs.leave_tree();
            return Ok(BackupEntry {
                path: path.to_string(),
                status: BackupStatus::Absent,
                kind: None,
                destination: None,
                store: None,
            });
        }
        ObjKind::File => {}
        ObjKind::Dir => {
            return Err(refuse(
                "a directory there is not backed up: root does not walk a tree another account \
                 controls, and copying a live data directory file by file is not a consistent \
                 backup; list the files, and use the service's own backup tool for its data"
                    .to_string(),
            ))
        }
        other => {
            return Err(refuse(format!(
                "a {} there is not backed up, only a regular file",
                other.describe()
            )))
        }
    }
    if st.uid != tree.uid {
        return Err(refuse(format!(
            "the file is owned by uid {}, not by the account of the tree",
            st.uid
        )));
    }
    if st.mode & 0o6000 != 0 {
        return Err(refuse("the file is setuid or setgid".to_string()));
    }
    let links = fs.hard_links(path)?;
    if links != 1 {
        return Err(refuse(format!(
            "the file has {links} hard links, so it is reachable under another name"
        )));
    }
    let x = fs.xattrs(path)?;
    if !x.inspected {
        return Err(refuse(
            "its access metadata cannot be inspected, so an ACL could be lost".to_string(),
        ));
    }
    let acl = x.attrs.contains_key("system.posix_acl_access");
    // From here on the invocation works in its own private run directory.
    fs.leave_tree();
    let dest = format!("{}{}", run_dir, path);
    let (parent, _) = crate::paths::parent_and_name(path);
    fs.mkdir_p(permit, &format!("{}{}", run_dir, parent))?;
    fs.backup_tree_copy(permit, tree, path, &dest, acl)?;
    Ok(BackupEntry {
        path: path.to_string(),
        status: BackupStatus::BackedUp,
        kind: Some("file"),
        destination: Some(dest),
        store: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{Executor, FakeExecutor, FakeTarget};

    // -----------------------------------------------------------------
    // FS2-A3: a directory directly in a shared directory is not copied.
    // -----------------------------------------------------------------

    const RUN_DIR: &str = "/root/.sinter-test-run";

    fn shared_fs() -> TargetFs {
        let mut t = FakeTarget::ubuntu2404().with_fake_fs().as_root();
        {
            let fs = t.fs.as_mut().unwrap();
            fs.mkdir_node("/tmp", 0o1777, 0, 0);
            // A nested shared directory with a file of another account in it.
            fs.mkdir_node("/tmp/pub", 0o1777, 0, 0);
            fs.put_file("/tmp/pub/theirs", b"alice\n", 0o644, 1001, 1001);
            // A root-only directory directly in /tmp, and a root file and link.
            fs.mkdir_node("/tmp/rootdir", 0o755, 0, 0);
            fs.put_file("/tmp/rootdir/f", b"y\n", 0o644, 0, 0);
            fs.put_file("/tmp/one", b"mine\n", 0o644, 0, 0);
            fs.put_symlink("/tmp/lnk", "/etc/x", 0, 0);
            fs.put_file("/tmp/theirs.conf", b"alice\n", 0o644, 1001, 1001);
            // Not in a shared directory.
            fs.mkdir_node("/etc/app2", 0o755, 0, 0);
            fs.put_file("/etc/app2/a", b"z\n", 0o644, 0, 0);
            fs.mkdir_node("/root", 0o700, 0, 0);
            fs.mkdir_node(RUN_DIR, 0o700, 0, 0);
        }
        TargetFs::new_for(
            Executor::Fake(Box::new(FakeExecutor::new(t, false))),
            false,
            0,
            0,
            "/root".to_string(),
            Some(crate::platform::PackageBackend::Apt),
            true,
            false,
            true,
            None,
        )
    }

    fn copies(fs: &TargetFs) -> usize {
        fs.log()
            .iter()
            .filter(|c| c.program.ends_with("/cp"))
            .count()
    }

    fn made_dirs(fs: &TargetFs) -> usize {
        fs.log()
            .iter()
            .filter(|c| c.program.ends_with("/mkdir"))
            .count()
    }

    fn below_run_dir(fs: &TargetFs) -> Vec<String> {
        fs.fake_fs()
            .unwrap()
            .nodes
            .keys()
            .filter(|k| k.starts_with(&format!("{}/", RUN_DIR)))
            .cloned()
            .collect()
    }

    #[test]
    fn declared_paths_may_not_overlap_in_any_order() {
        let list = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for bad in [
            ["/srv/app", "/srv"],
            ["/srv", "/srv/app"],
            ["/srv/app", "/srv/app/sub/x"],
        ] {
            let e = check_declared_overlap(&list(&bad)).unwrap_err();
            assert!(e.message.contains("overlap"), "{}", e.message);
        }
        assert!(check_declared_overlap(&list(&["/srv/app", "/srv/apple", "/srv/b/x"])).is_ok());
    }

    #[test]
    fn a_directory_directly_in_a_shared_directory_is_refused_before_anything_is_read_or_made() {
        // Both the nested shared directory (other accounts' files inside) and a
        // root-only directory: the rule is about where the directory is.
        for dir in ["/tmp/pub", "/tmp/rootdir"] {
            let mut fs = shared_fs();
            let permit = fs.mutation_permit().unwrap();
            let e = copy_one(&mut fs, &permit, dir, RUN_DIR).unwrap_err();
            assert!(
                e.message.contains("directly in a shared directory"),
                "{dir}: {}",
                e.message
            );
            assert!(!e.message.contains("1001"), "{dir}: no uid: {}", e.message);
            assert_eq!(copies(&fs), 0, "{dir}: cp -a is never run");
            assert_eq!(made_dirs(&fs), 0, "{dir}: nothing is made for it");
            assert!(
                below_run_dir(&fs).is_empty(),
                "{dir}: {:?}",
                below_run_dir(&fs)
            );
            // Nothing below the directory was read either: only `lstat`s of
            // the directory and of its ancestors were issued.
            for c in fs.log() {
                let reads_below = c.args.iter().any(|a| a.starts_with(&format!("{}/", dir)));
                assert!(!reads_below, "{dir}: {:?}", c);
            }
        }
    }

    #[test]
    fn files_and_links_in_a_shared_directory_and_directories_elsewhere_are_still_copied() {
        for (path, kind) in [
            ("/tmp/one", "file"),
            ("/tmp/lnk", "symlink"),
            ("/etc/app2", "directory"),
        ] {
            let mut fs = shared_fs();
            let permit = fs.mutation_permit().unwrap();
            let entry = copy_one(&mut fs, &permit, path, RUN_DIR)
                .unwrap_or_else(|e| panic!("{path}: {}", e.message));
            assert_eq!(entry.status, BackupStatus::BackedUp, "{path}");
            assert_eq!(entry.kind, Some(kind), "{path}");
            assert_eq!(copies(&fs), 1, "{path}");
            assert!(
                below_run_dir(&fs).contains(&format!("{}{}", RUN_DIR, path)),
                "{path}: {:?}",
                below_run_dir(&fs)
            );
        }
    }

    #[test]
    fn an_entry_of_another_account_in_a_shared_directory_is_still_refused_by_the_gate() {
        let mut fs = shared_fs();
        let permit = fs.mutation_permit().unwrap();
        let e = copy_one(&mut fs, &permit, "/tmp/theirs.conf", RUN_DIR).unwrap_err();
        assert!(e.message.contains("belongs to uid 1001"), "{}", e.message);
        assert_eq!(copies(&fs), 0);
    }

    #[test]
    fn utc_stamp_known_values() {
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(utc_stamp(951_782_400), "20000229T000000Z");
        assert_eq!(utc_stamp(1_790_590_530), "20260928T101530Z");
    }

    #[test]
    fn run_id_shape() {
        let id = new_run_id();
        let (stamp, rnd) = id.split_once('-').unwrap();
        assert_eq!(stamp.len(), 16);
        assert!(stamp.ends_with('Z'));
        assert_eq!(rnd.len(), 8);
        assert!(rnd.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn store_roots() {
        assert_eq!(store_root(true, "/root"), "/var/lib/sinter/backups");
        assert_eq!(store_root(false, "/home/u"), "/home/u/.sinter/backups");
        assert_eq!(store_root(false, "/home/u/"), "/home/u/.sinter/backups");
    }

    #[test]
    fn store_chains() {
        assert_eq!(
            store_chain(true, "/root"),
            ["/var/lib/sinter", "/var/lib/sinter/backups"]
        );
        assert_eq!(
            store_chain(false, "/home/u/"),
            ["/home/u/.sinter", "/home/u/.sinter/backups"]
        );
    }

    #[test]
    fn overlap_with_store_is_rejected() {
        let root = "/var/lib/sinter/backups";
        for p in [
            "/var",
            "/var/lib",
            "/var/lib/sinter",
            root,
            "/var/lib/sinter/backups/x",
        ] {
            assert!(check_overlap(p, root).is_err(), "{p}");
        }
        for p in ["/etc", "/var/lib/sinterx", "/var/lib/other"] {
            assert!(check_overlap(p, root).is_ok(), "{p}");
        }
    }

    #[test]
    fn planned_report_lists_paths_only() {
        let r = planned(&["/etc/a".to_string(), "/etc/b".to_string()]);
        assert!(r.run_id.is_none() && r.directory.is_none());
        assert_eq!(r.entries.len(), 2);
        assert!(r
            .entries
            .iter()
            .all(|e| e.status == BackupStatus::Planned && e.destination.is_none()));
    }
}
