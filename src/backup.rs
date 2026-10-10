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

use crate::error::{Result, SinterError};
use crate::progress::StageTracker;
use crate::targetfs::{ObjKind, TargetFs};

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
}

#[derive(Debug, Clone)]
pub struct BackupReport {
    /// Set by apply.
    pub run_id: Option<String>,
    /// Run directory on the target, set by apply.
    pub directory: Option<String>,
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
    BackupReport {
        run_id: None,
        directory: None,
        entries: paths
            .iter()
            .map(|p| BackupEntry {
                path: p.clone(),
                status: BackupStatus::Planned,
                kind: None,
                destination: None,
            })
            .collect(),
    }
}

/// Reject a declared path that contains, or lies inside, the store root.
pub fn check_overlap(path: &str, root: &str) -> Result<()> {
    let inside = |a: &str, b: &str| a == b || a.starts_with(&format!("{}/", b));
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
    /// Run directory, once this invocation created it.
    run_dir: Option<&'a str>,
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
    let where_ = match p.run_dir {
        Some(d) => format!("; partial backup left at {} (not removed)", d),
        None => String::new(),
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
        });
    }
    let mut err = SinterError::apply(format!(
        "backup failed; no resource was executed: {}{}",
        e.message, where_
    ));
    err.backup = Some(Box::new(BackupReport {
        run_id: Some(p.run_id.to_string()),
        directory: p.run_dir.map(str::to_string),
        entries,
    }));
    err
}

/// Ensure `dir` exists as a trusted directory, creating it 0700 if absent.
fn ensure_dir(fs: &mut TargetFs, dir: &str) -> Result<()> {
    fs.check_trusted_parents(dir)?;
    let permit = fs.mutation_permit()?;
    let st = fs.inspect(dir)?;
    match st.kind {
        ObjKind::Dir => check_existing_store_dir(fs, dir, &st),
        ObjKind::Absent => match fs.mkdir(&permit, dir) {
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
    run_id: &str,
    stage: &mut StageTracker<'_>,
) -> Result<BackupReport> {
    let sudo = fs.sudo();
    let home = fs.home_env();
    let root = store_root(sudo, &home);
    let before_store = Progress {
        run_id,
        paths,
        run_dir: None,
        done: &[],
        failed: None,
    };
    for p in paths {
        check_overlap(p, &root).map_err(|e| fail(&before_store, e))?;
    }
    // Create the store chain below an existing trusted base.
    for d in &store_chain(sudo, &home) {
        ensure_dir(fs, d).map_err(|e| fail(&before_store, e))?;
    }
    let run_dir = format!("{}/{}", root, run_id);
    fs.check_trusted_parents(&run_dir)
        .map_err(|e| fail(&before_store, e))?;
    let permit = fs.mutation_permit()?;
    // Plain mkdir: an existing run directory is a collision and fails. It is
    // not ours, so the failure report names no directory.
    fs.mkdir(&permit, &run_dir).map_err(|e| {
        fail(
            &before_store,
            SinterError::apply(format!(
                "cannot create backup run directory {} (collision or store error): {}",
                run_dir, e.message
            )),
        )
    })?;
    let created = Progress {
        run_dir: Some(&run_dir),
        ..before_store
    };
    fs.chmod(&permit, &run_dir, 0o700)
        .map_err(|e| fail(&created, e))?;

    let mut entries: Vec<BackupEntry> = Vec::new();
    for p in paths {
        stage.item_started(None);
        match copy_one(fs, &permit, p, &run_dir) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                let at = Progress {
                    done: &entries,
                    failed: Some(p),
                    ..created
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
        directory: Some(run_dir),
        entries,
    })
}

fn copy_one(
    fs: &mut TargetFs,
    permit: &crate::targetfs::MutationPermit,
    path: &str,
    run_dir: &str,
) -> Result<BackupEntry> {
    fs.check_trusted_parents(path)?;
    let st = fs.inspect(path)?;
    let kind = match st.kind {
        ObjKind::Absent => {
            return Ok(BackupEntry {
                path: path.to_string(),
                status: BackupStatus::Absent,
                kind: None,
                destination: None,
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
