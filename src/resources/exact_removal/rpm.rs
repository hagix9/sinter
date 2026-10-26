//! DNF4 side of exact-target removal: `rpm -e --test` / `rpm -e` on the
//! installed package's own NEVRA, never `dnf remove`.

use super::{
    complete_stdout, excerpt, exit_code, valid_arch, valid_rpm_evr_part, valid_rpm_name, DryRun,
    ExactIdentity, FailureCause, Inventory, Refusal,
};
use crate::executor::Output;
use std::collections::BTreeSet;

/// The only configuration directories `dnf` reads protected-package lists from.
const PROTECTED_DIRS: [&str; 2] = ["/etc/yum/protected.d", "/etc/dnf/protected.d"];
pub(in crate::resources) const DNF_CONF: &str = "/etc/dnf/dnf.conf";
/// dnf-automatic reads its own `[base]` overrides from here, including
/// `persistdir`.
pub(in crate::resources) const AUTOMATIC_CONF: &str = "/etc/dnf/automatic.conf";

/// dnf's process lock for the rpm database. dnf holds it by writing its PID
/// into this file (a `flock` only serialises the read-modify-write), and
/// deletes the file when it finishes.
const DNF_LOCK_FILE: &str = "/var/lib/dnf/rpmdb_lock.pid";
/// The directory dnf keeps that file in unless `persistdir` says otherwise.
pub(in crate::resources) const DNF_PERSISTDIR: &str = "/var/lib/dnf";
pub(in crate::resources) const ERASE_PROGRAM: &str = "/usr/bin/sh";
/// Exit codes of the erase wrapper itself; rpm has not run when it exits so.
pub(in crate::resources) const EXIT_LOCK_BUSY: i32 = 75;
pub(in crate::resources) const EXIT_DNF_ACTIVE: i32 = 76;
pub(in crate::resources) const EXIT_LOCK_UNREADABLE: i32 = 77;
pub(in crate::resources) const EXIT_LOCK_REPLACED: i32 = 78;

/// The erase wrapper (a fixed script; the NEVRA is `$1`, never part of the
/// text). It takes dnf's lock the way dnf does and becomes `rpm -e`:
///
/// 1. open the lock file and `flock` it without waiting (a dnf that is just
///    taking or releasing the lock holds it for an instant) - exit 75;
/// 2. check that the file we locked is still the file at that path, because
///    dnf deletes the file without taking the flock - exit 78;
/// 3. read the PID in it: a live process is a running dnf - exit 76; anything
///    that is not a PID, or cannot be read - exit 77; then check once more that
///    the file is still the one we hold (exit 78);
/// 4. `exec rpm -e`, which keeps the flock through the inherited descriptor,
///    so a dnf that starts meanwhile waits until rpm is done.
///
/// The paths are parameters only so that the script can be run in a test
/// (`fd_path` is `/dev/fd/9`, the locked descriptor).
pub(in crate::resources) fn erase_script(
    lock: &str,
    fd_path: &str,
    flock: &str,
    cat: &str,
    proc_dir: &str,
    rpm: &str,
) -> String {
    format!(
        "exec 9>>'{lock}' || exit {unreadable}\n\
'{flock}' -n 9 || exit {busy}\n\
[ '{fd_path}' -ef '{lock}' ] || exit {replaced}\n\
p=$('{cat}' '{lock}') || exit {unreadable}\n\
case \"$p\" in\n\
  \"\") ;;\n\
  *[!0-9]*) exit {unreadable} ;;\n\
  *) if [ -e \"{proc_dir}\"/\"$p\"/stat ]; then exit {active}; fi ;;\n\
esac\n\
[ '{fd_path}' -ef '{lock}' ] || exit {replaced}\n\
exec '{rpm}' -e -- \"$1\"\n",
        busy = EXIT_LOCK_BUSY,
        active = EXIT_DNF_ACTIVE,
        unreadable = EXIT_LOCK_UNREADABLE,
        replaced = EXIT_LOCK_REPLACED,
    )
}

/// What the protected-package configuration says about a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::resources) enum Protection {
    No,
    Yes,
    /// The configuration uses a construct this code cannot evaluate.
    Unevaluable,
}

pub(in crate::resources) struct RpmExact;

impl RpmExact {
    pub(in crate::resources) fn valid_name(name: &str) -> bool {
        valid_rpm_name(name)
    }

    /// One `NAME EPOCHNUM VERSION RELEASE ARCH` record per matching package.
    /// `operand` is a bare name or a NEVRA; the answer's NAME is compared with
    /// the requested name by the caller.
    pub(in crate::resources) fn identity_args(operand: &str) -> Vec<String> {
        vec![
            "-q".to_string(),
            "--queryformat".to_string(),
            "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\n".to_string(),
            "--".to_string(),
            operand.to_string(),
        ]
    }

    pub(in crate::resources) fn inventory_args() -> Vec<String> {
        vec![
            "-qa".to_string(),
            "--queryformat".to_string(),
            "%{NAME}\\t%{ARCH}\\n".to_string(),
        ]
    }

    /// Dependency-only verification of every installed package: no file
    /// verification, no scripts, no digest or signature checks. It reports
    /// `Unsatisfied dependencies for ...` lines.
    pub(in crate::resources) fn verify_args() -> Vec<String> {
        vec![
            "-Va".to_string(),
            "--nofiles".to_string(),
            "--noscripts".to_string(),
            "--nodigest".to_string(),
            "--nosignature".to_string(),
        ]
    }

    pub(in crate::resources) fn test_args(operand: &str) -> Vec<String> {
        vec![
            "-e".to_string(),
            "--test".to_string(),
            "--".to_string(),
            operand.to_string(),
        ]
    }

    /// The removing command: `rpm -e -- NEVRA`, run under dnf's lock (see
    /// [`erase_script`]) so that a dnf transaction (dnf, dnf-automatic, yum)
    /// can neither be in progress while rpm checks dependencies nor start
    /// before rpm is done. Arguments of [`ERASE_PROGRAM`].
    pub(in crate::resources) fn erase_args(operand: &str) -> Vec<String> {
        vec![
            "-c".to_string(),
            erase_script(
                DNF_LOCK_FILE,
                "/dev/fd/9",
                "/usr/bin/flock",
                "/usr/bin/cat",
                "/proc",
                "/usr/bin/rpm",
            ),
            "sinter-erase".to_string(),
            operand.to_string(),
        ]
    }

    /// Every `*.conf` file (symlinks followed, like libdnf) in the protected
    /// directories, one `cat` per file followed by a newline, so a file without
    /// a final newline cannot run into the next file's first line. Only
    /// coreutils programs are executed.
    pub(in crate::resources) fn protected_dirs_args() -> Vec<String> {
        let mut args: Vec<String> = vec!["-L".to_string()];
        args.extend(PROTECTED_DIRS.iter().map(|d| (*d).to_string()));
        for word in [
            "-maxdepth",
            "1",
            "-type",
            "f",
            "-name",
            "*.conf",
            "-exec",
            "/usr/bin/cat",
            "{}",
            ";",
            "-exec",
            "/usr/bin/printf",
            "\\n",
            ";",
        ] {
            args.push(word.to_string());
        }
        args
    }

    /// The text of the protected files. A protected directory that does not
    /// exist is an empty list, as it is for dnf; any other failure - in
    /// particular `find` failing to run `cat` or `printf` - is not an answer.
    pub(in crate::resources) fn protected_files_text(out: &Output) -> Result<String, &'static str> {
        const FAILED: &str = "the command failed";
        let text = complete_stdout(out).map_err(|_| FAILED)?;
        match exit_code(out) {
            Some(0) if out.stderr.is_empty() => Ok(text.to_string()),
            Some(1) => {
                let err = String::from_utf8_lossy(&out.stderr);
                let lines: Vec<&str> = err.lines().filter(|l| !l.trim().is_empty()).collect();
                let only_missing_dirs = !lines.is_empty()
                    && lines.iter().all(|l| {
                        l.starts_with("find: ")
                            && l.contains("No such file or directory")
                            && PROTECTED_DIRS.iter().any(|d| l.contains(d))
                    });
                if only_missing_dirs {
                    Ok(text.to_string())
                } else {
                    Err(FAILED)
                }
            }
            _ => Err(FAILED),
        }
    }

    pub(in crate::resources) fn dnf_conf_args() -> Vec<String> {
        vec!["--".to_string(), DNF_CONF.to_string()]
    }

    pub(in crate::resources) fn automatic_conf_args() -> Vec<String> {
        vec!["--".to_string(), AUTOMATIC_CONF.to_string()]
    }

    pub(in crate::resources) fn uname_args() -> Vec<String> {
        vec!["-r".to_string()]
    }

    pub(in crate::resources) fn parse_identity(
        out: &Output,
        requested: &str,
    ) -> Result<ExactIdentity, Refusal> {
        const WHAT: &str = "the package identity";
        let text = complete_stdout(out).map_err(|_| Refusal::Unestablished(WHAT))?;
        match exit_code(out) {
            Some(0) => {}
            Some(1) if text.contains("is not installed") => {
                return Err(Refusal::Changed("the installed package"));
            }
            _ => return Err(Refusal::Unestablished(WHAT)),
        }
        if !out.stderr.is_empty() || text.is_empty() || !text.ends_with('\n') {
            return Err(Refusal::Unestablished(WHAT));
        }
        if text.contains('\r') {
            return Err(Refusal::Unestablished(WHAT));
        }
        let mut records = text.split_terminator('\n');
        let first = records.next().ok_or(Refusal::Unestablished(WHAT))?;
        if records.next().is_some() {
            return Err(Refusal::Ambiguous);
        }
        let fields: Vec<&str> = first.split('\t').collect();
        let [name, epoch, version, release, arch] = fields.as_slice() else {
            return Err(Refusal::Unestablished(WHAT));
        };
        if *name != requested
            || !valid_rpm_name(name)
            || epoch.is_empty()
            || !epoch.chars().all(|c| c.is_ascii_digit())
            || !valid_rpm_evr_part(version)
            || !valid_rpm_evr_part(release)
            || !valid_arch(arch)
        {
            return Err(Refusal::Unestablished(WHAT));
        }
        Ok(ExactIdentity {
            name: (*name).to_string(),
            arch: (*arch).to_string(),
            version: (*version).to_string(),
            release: Some((*release).to_string()),
            epoch: Some((*epoch).to_string()),
        })
    }

    pub(in crate::resources) fn parse_inventory(out: &Output) -> Result<Inventory, &'static str> {
        const WHAT: &str = "the installed-package list";
        let text = complete_stdout(out).map_err(|_| WHAT)?;
        if exit_code(out) != Some(0) || !out.stderr.is_empty() {
            return Err(WHAT);
        }
        if !text.is_empty() && !text.ends_with('\n') {
            return Err(WHAT);
        }
        let mut pairs = Vec::new();
        for line in text.split_terminator('\n') {
            let fields: Vec<&str> = line.split('\t').collect();
            let [name, arch] = fields.as_slice() else {
                return Err(WHAT);
            };
            // `gpg-pubkey` records carry the architecture `(none)`; every
            // other token must be a plain architecture.
            if name.is_empty()
                || arch.is_empty()
                || name.contains(|c: char| c.is_whitespace() || c.is_control())
                || arch.contains(|c: char| c.is_whitespace() || c.is_control())
            {
                return Err(WHAT);
            }
            pairs.push(((*name).to_string(), (*arch).to_string()));
        }
        if pairs.is_empty() {
            return Err(WHAT);
        }
        Ok(Inventory::from_pairs(pairs))
    }

    /// The problems `rpm -Va --nofiles ...` reports: a header line
    /// `Unsatisfied dependencies for NEVRA:` followed by indented detail
    /// lines. Any other line is output this code does not understand, and an
    /// answer it does not understand is not "no problem": it is an error.
    pub(in crate::resources) fn verify_issues(
        out: &Output,
    ) -> Result<BTreeSet<String>, &'static str> {
        const WHAT: &str = "the rpm dependency verification";
        let text = complete_stdout(out).map_err(|_| WHAT)?;
        if exit_code(out).is_none() {
            return Err(WHAT);
        }
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        let mut issues = BTreeSet::new();
        let mut header: Option<&str> = None;
        for line in text.lines().chain(err.lines()) {
            if line.trim().is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("Unsatisfied dependencies for ") {
                header = Some(rest.trim_end());
                issues.insert(line.trim().to_string());
            } else if line.starts_with(char::is_whitespace) && header.is_some() {
                issues.insert(format!("{} {}", header.unwrap_or(""), line.trim()));
            } else {
                return Err(WHAT);
            }
        }
        Ok(issues)
    }

    /// Classify `rpm -e --test`.
    pub(in crate::resources) fn classify_dry_run(out: &Output) -> DryRun {
        if out.stdout_truncated || out.stderr_truncated {
            return DryRun::Refused(Refusal::DryRunFailed("output was truncated".to_string()));
        }
        let all = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        match exit_code(out) {
            Some(0) if out.stdout.is_empty() && out.stderr.is_empty() => DryRun::Clean,
            Some(0) => DryRun::Refused(Refusal::DryRunFailed(excerpt(
                &[out.stderr.as_slice(), out.stdout.as_slice()].concat(),
            ))),
            _ => {
                if all.contains("Failed dependencies") {
                    DryRun::Refused(Refusal::ReverseDependencies(Self::dependents(&all)))
                } else if all.contains("is not installed") {
                    DryRun::Refused(Refusal::Changed("the installed package"))
                } else if all.contains("Permission denied") {
                    DryRun::Refused(Refusal::Privilege)
                } else if all.contains("transaction lock") {
                    DryRun::Refused(Refusal::LockBusy)
                } else {
                    DryRun::Refused(Refusal::DryRunFailed(excerpt(
                        &[out.stderr.as_slice(), out.stdout.as_slice()].concat(),
                    )))
                }
            }
        }
    }

    /// The installed packages rpm names after `is needed by (installed) `.
    fn dependents(text: &str) -> Vec<String> {
        const MARK: &str = "is needed by (installed) ";
        let mut names = BTreeSet::new();
        for line in text.lines() {
            if let Some(at) = line.find(MARK) {
                let nevra = line[at + MARK.len()..].trim();
                // Only a plain NEVRA is quoted back: the text comes from the host.
                if !nevra.is_empty()
                    && nevra.len() <= 256
                    && nevra.chars().all(|c| {
                        c.is_ascii_alphanumeric()
                            || matches!(c, '.' | '_' | '+' | '~' | '^' | ':' | '-')
                    })
                {
                    names.insert(nevra.to_string());
                }
            }
        }
        names.into_iter().collect()
    }

    /// Whether a failed removal stopped before changing anything.
    pub(in crate::resources) fn classify_failure(out: &Output) -> FailureCause {
        if Self::wrapper_note(out).is_some() {
            return FailureCause::RefusedBeforeChange;
        }
        let all = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        // The wrapper could not even open dnf's lock file: rpm never ran.
        if all.contains(DNF_LOCK_FILE)
            || all.contains("Failed dependencies")
            || all.contains("transaction lock")
            || all.contains("is not installed")
        {
            FailureCause::RefusedBeforeChange
        } else {
            FailureCause::Other
        }
    }

    /// A fixed sentence for the wrapper's own exit codes (rpm did not run).
    pub(in crate::resources) fn wrapper_note(out: &Output) -> Option<&'static str> {
        match exit_code(out) {
            Some(EXIT_LOCK_BUSY) => Some("the dnf lock is held by another process"),
            Some(EXIT_DNF_ACTIVE) => Some("a dnf transaction is in progress"),
            Some(EXIT_LOCK_UNREADABLE) => Some("the dnf lock file could not be read"),
            Some(EXIT_LOCK_REPLACED) => Some("the dnf lock file changed while it was being taken"),
            Some(126 | 127) => Some("the lock wrapper could not be run (sh, flock or cat missing)"),
            _ => None,
        }
    }

    /// Entries of the protected-package files, read the way libdnf reads them
    /// (`addFromFile`): a line whose first non-blank character is `#` is a
    /// comment and nothing else is - a `#` later in a line is just another
    /// word, so it can only protect more, never less. Words are separated by
    /// white space or commas (libdnf splits on space and comma only; splitting
    /// on every white space protects a superset).
    pub(in crate::resources) fn parse_protected_files(text: &str) -> Vec<String> {
        let mut entries = Vec::new();
        for line in text.lines() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            entries.extend(Self::words(line));
        }
        entries
    }

    fn words(text: &str) -> impl Iterator<Item = String> + '_ {
        text.split(|c: char| c.is_whitespace() || c == ',')
            .filter(|t| !t.is_empty())
            .map(str::to_string)
    }

    /// The `protected_packages` option of `dnf.conf` (with indented
    /// continuation lines). The value is taken as written, including a `#`.
    pub(in crate::resources) fn parse_dnf_conf_protected(text: &str) -> Vec<String> {
        let mut entries = Vec::new();
        let mut collecting = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if line.starts_with(char::is_whitespace) && collecting {
                if !trimmed.starts_with('#') {
                    entries.extend(Self::words(trimmed));
                }
                continue;
            }
            collecting = false;
            if trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            if let Some((key, value)) = trimmed.split_once('=') {
                if key.trim() == "protected_packages" {
                    entries.extend(Self::words(value));
                    collecting = true;
                }
            }
        }
        entries
    }

    /// `dnf` itself is always protected. A `glob:` entry names *files* to
    /// read more entries from (libdnf), not package names; the two default
    /// directories are read directly, any other is not evaluated, and a
    /// protection that cannot be evaluated refuses the removal.
    pub(in crate::resources) fn protection(entries: &[String], name: &str) -> Protection {
        const DEFAULT_GLOBS: [&str; 2] = [
            "glob:/etc/yum/protected.d/*.conf",
            "glob:/etc/dnf/protected.d/*.conf",
        ];
        if name == "dnf" || entries.iter().any(|e| e == name) {
            return Protection::Yes;
        }
        if entries
            .iter()
            .any(|e| e.starts_with("glob:") && !DEFAULT_GLOBS.contains(&e.as_str()))
        {
            return Protection::Unevaluable;
        }
        Protection::No
    }

    /// The paths libdnf uses to find the running kernel package: the image
    /// of the kernel `uname -r` names.
    pub(in crate::resources) fn kernel_image_paths(uname: &str) -> Vec<String> {
        let release = uname.trim();
        vec![
            format!("/boot/vmlinuz-{}", release),
            format!("/lib/modules/{}/vmlinuz", release),
        ]
    }

    /// Whether `path` is a plausible kernel image path to hand to `rpm -qf`.
    pub(in crate::resources) fn valid_kernel_release(uname: &str) -> bool {
        let release = uname.trim();
        !release.is_empty()
            && release.len() <= 128
            && release
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~'))
    }

    pub(in crate::resources) fn owner_args(path: &str) -> Vec<String> {
        vec![
            "-qf".to_string(),
            "--queryformat".to_string(),
            "%{NAME}\\n".to_string(),
            "--".to_string(),
            path.to_string(),
        ]
    }

    /// The package that owns a kernel image. `None` when nothing owns the
    /// path (it does not exist, or no package owns it): that kernel is not an
    /// installed package. Any other answer is an error.
    pub(in crate::resources) fn parse_owner(out: &Output) -> Result<Option<String>, &'static str> {
        const WHAT: &str = "the owner of the running kernel";
        let text = complete_stdout(out).map_err(|_| WHAT)?;
        match exit_code(out) {
            Some(0) if out.stderr.is_empty() => {
                let mut lines = text.lines();
                match (lines.next(), lines.next()) {
                    (Some(name), None) if valid_rpm_name(name) => Ok(Some(name.to_string())),
                    _ => Err(WHAT),
                }
            }
            Some(1) => {
                let all = format!("{}\n{}", text, String::from_utf8_lossy(&out.stderr));
                if all.contains("is not owned by any package")
                    || all.contains("No such file or directory")
                {
                    Ok(None)
                } else {
                    Err(WHAT)
                }
            }
            _ => Err(WHAT),
        }
    }

    /// Every `persistdir` value a dnf configuration file sets. dnf keeps its
    /// lock there, so any value other than the default means the lock file is
    /// somewhere else (or could be).
    pub(in crate::resources) fn conf_persistdirs(text: &str) -> Vec<String> {
        let mut values = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            if let Some((key, value)) = trimmed.split_once('=') {
                if key.trim() == "persistdir" {
                    values.push(value.trim().to_string());
                }
            }
        }
        values
    }
}
