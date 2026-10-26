//! APT side of exact-target removal: `dpkg --dry-run --remove` /
//! `dpkg --remove`, never `apt-get remove`.

use super::{
    complete_stdout, excerpt, exit_code, valid_apt_name, valid_apt_version, valid_arch, DryRun,
    ExactIdentity, FailureCause, Inventory, Refusal,
};
use crate::executor::Output;
use std::collections::BTreeSet;

/// The status string of a cleanly installed package.
const INSTALLED: &str = "install ok installed";

pub(in crate::resources) struct AptExact;

impl AptExact {
    pub(in crate::resources) fn valid_name(name: &str) -> bool {
        valid_apt_name(name)
    }

    /// Status, name, architecture, version, Essential and Protected of the
    /// named package, one record per installed instance.
    pub(in crate::resources) fn identity_args(name: &str) -> Vec<String> {
        vec![
            "-W".to_string(),
            "-f=${Status}\\t${Package}\\t${Architecture}\\t${Version}\\t${Essential}\\t${Protected}\\n"
                .to_string(),
            "--".to_string(),
            name.to_string(),
        ]
    }

    pub(in crate::resources) fn inventory_args() -> Vec<String> {
        vec![
            "-W".to_string(),
            "-f=${Status}\\t${Package}\\t${Architecture}\\n".to_string(),
        ]
    }

    pub(in crate::resources) fn audit_args() -> Vec<String> {
        vec!["--audit".to_string()]
    }

    /// `name` is validated by [`valid_apt_name`], so it can neither be an
    /// option nor a pattern (`*`, `?`, `[`).
    pub(in crate::resources) fn dry_run_args(name: &str) -> Vec<String> {
        let mut args = Self::refuse_args();
        args.extend(["--dry-run".to_string(), "--remove".to_string()]);
        args.push(name.to_string());
        args
    }

    pub(in crate::resources) fn remove_args(name: &str) -> Vec<String> {
        let mut args = Self::refuse_args();
        args.extend(["--remove".to_string(), name.to_string()]);
        args
    }

    /// The command line is read after `dpkg.cfg`, `~/.dpkg.cfg` and
    /// `DPKG_FORCE`, so these cancel a `force-depends` or
    /// `force-remove-essential` that configuration turned on.
    fn refuse_args() -> Vec<String> {
        [
            "--refuse-depends",
            "--refuse-remove-essential",
            "--refuse-remove-protected",
        ]
        .iter()
        .map(|a| (*a).to_string())
        .collect()
    }

    /// `apt-get -s check`: a read-only check for broken dependencies. The
    /// simulate flag keeps apt from taking the dpkg locks, so a concurrent
    /// dpkg or apt does not make the check fail by itself.
    pub(in crate::resources) fn check_args() -> Vec<String> {
        vec!["-s".to_string(), "check".to_string()]
    }

    pub(in crate::resources) fn parse_identity(
        out: &Output,
        requested: &str,
    ) -> Result<ExactIdentity, Refusal> {
        const WHAT: &str = "the package identity";
        let text = complete_stdout(out).map_err(|_| Refusal::Unestablished(WHAT))?;
        if exit_code(out) != Some(0) || !out.stderr.is_empty() {
            return Err(Refusal::Unestablished(WHAT));
        }
        if text.is_empty() || !text.ends_with('\n') || text.contains('\r') {
            return Err(Refusal::Unestablished(WHAT));
        }
        // `dpkg-query -W NAME` also lists instances that are not installed
        // (another architecture's leftover configuration, a never-installed
        // architecture). They cannot make a removal ambiguous.
        let mut records = text.split_terminator('\n').filter(|record| {
            let status = record.split('\t').next().unwrap_or("");
            !(status.ends_with(" config-files") || status.ends_with(" not-installed"))
        });
        let first = records.next().ok_or(Refusal::Unestablished(WHAT))?;
        if records.next().is_some() {
            return Err(Refusal::Ambiguous);
        }
        let fields: Vec<&str> = first.split('\t').collect();
        let [status, name, arch, version, essential, protected] = fields.as_slice() else {
            return Err(Refusal::Unestablished(WHAT));
        };
        if *name != requested
            || !valid_apt_name(name)
            || !valid_arch(arch)
            || !valid_apt_version(version)
        {
            return Err(Refusal::Unestablished(WHAT));
        }
        if !matches!(*essential, "" | "yes" | "no") || !matches!(*protected, "" | "yes" | "no") {
            return Err(Refusal::Unestablished(WHAT));
        }
        if *status != INSTALLED {
            return Err(Refusal::NotClean);
        }
        if *essential == "yes" {
            return Err(Refusal::SystemProtected("essential"));
        }
        if *protected == "yes" {
            return Err(Refusal::SystemProtected("protected"));
        }
        Ok(ExactIdentity {
            name: (*name).to_string(),
            arch: (*arch).to_string(),
            version: (*version).to_string(),
            release: None,
            epoch: None,
        })
    }

    /// The set of cleanly installed packages. An empty list is not a valid
    /// answer on a working system, so it is rejected instead of trusted.
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
            let [status, name, arch] = fields.as_slice() else {
                return Err(WHAT);
            };
            // dpkg also allows `_` and one-letter names; this list is only
            // compared, never passed to a command.
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.' | '_'))
                || !valid_arch(arch)
            {
                return Err(WHAT);
            }
            if *status == INSTALLED {
                pairs.push(((*name).to_string(), (*arch).to_string()));
            }
        }
        if pairs.is_empty() {
            return Err(WHAT);
        }
        Ok(Inventory::from_pairs(pairs))
    }

    /// The lines `dpkg --audit` reports (packages that are only partly
    /// installed or configured). A clean database reports nothing.
    pub(in crate::resources) fn audit_issues(
        out: &Output,
    ) -> Result<BTreeSet<String>, &'static str> {
        const WHAT: &str = "the dpkg audit";
        let text = complete_stdout(out).map_err(|_| WHAT)?;
        if exit_code(out) != Some(0) {
            return Err(WHAT);
        }
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        Ok(text
            .lines()
            .chain(err.lines())
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// The dependency problems `apt-get check` reports (exit 100 with a list of
    /// unmet dependencies). Progress lines are not problems; a lock or cache
    /// failure is an answer this code does not have.
    pub(in crate::resources) fn check_issues(
        out: &Output,
    ) -> Result<BTreeSet<String>, &'static str> {
        const WHAT: &str = "the apt dependency check";
        let text = complete_stdout(out).map_err(|_| WHAT)?;
        if !matches!(exit_code(out), Some(0 | 100)) {
            return Err(WHAT);
        }
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        let mut issues = BTreeSet::new();
        for line in text.lines().chain(err.lines()) {
            let line = line.trim();
            if line.is_empty()
                || line == "Reading package lists..."
                || line == "Building dependency tree..."
                || line == "Reading state information..."
                || line.starts_with("Reading package lists... ")
                || line.starts_with("Building dependency tree... ")
                || line.starts_with("Reading state information... ")
            {
                continue;
            }
            if line.starts_with("E: Could not get lock")
                || line.starts_with("E: Unable to acquire")
                || line.starts_with("E: Unable to lock")
            {
                return Err(WHAT);
            }
            issues.insert(line.to_string());
        }
        // Exit 100 without a single explanatory line is still a problem.
        if exit_code(out) == Some(100) && issues.is_empty() {
            issues.insert("apt-get check exited 100".to_string());
        }
        Ok(issues)
    }

    /// Classify `dpkg --dry-run --remove`.
    pub(in crate::resources) fn classify_dry_run(out: &Output, name: &str) -> DryRun {
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if out.stdout_truncated || out.stderr_truncated {
            return DryRun::Refused(Refusal::DryRunFailed("output was truncated".to_string()));
        }
        match exit_code(out) {
            Some(0) => {
                if !stderr.trim().is_empty() {
                    // A warning such as "ignoring request to remove X which
                    // isn't installed" exits 0 but is not a clean plan.
                    return DryRun::Refused(Self::refusal_from_failure(
                        &stdout,
                        &stderr,
                        &out.stderr,
                    ));
                }
                // dpkg lists what it would remove. Anything but the target is
                // not an exact-target plan.
                for line in stdout.lines() {
                    // A dry-run prints `Would remove or purge X (V) ...`; the
                    // real run prints `Removing X (V) ...`.
                    let Some(rest) = line
                        .strip_prefix("Would remove or purge ")
                        .or_else(|| line.strip_prefix("Removing "))
                    else {
                        continue;
                    };
                    let listed = rest.split_whitespace().next().unwrap_or("");
                    let listed = listed.split(':').next().unwrap_or("");
                    if listed != name {
                        return DryRun::Refused(Refusal::DryRunFailed(
                            "the plan names another package".to_string(),
                        ));
                    }
                }
                DryRun::Clean
            }
            _ => DryRun::Refused(Self::refusal_from_failure(&stdout, &stderr, &out.stderr)),
        }
    }

    fn refusal_from_failure(stdout: &str, stderr: &str, raw_stderr: &[u8]) -> Refusal {
        let all = format!("{}\n{}", stderr, stdout);
        let lower = all.to_ascii_lowercase();
        if lower.contains("dependency problems prevent removal") {
            return Refusal::ReverseDependencies(Self::dependents(&all));
        }
        if lower.contains("essential package") {
            return Refusal::SystemProtected("essential");
        }
        if lower.contains("protected package") || lower.contains("is protected") {
            return Refusal::SystemProtected("protected");
        }
        if lower.contains("frontend lock") || lower.contains("locked by another process") {
            return Refusal::LockBusy;
        }
        if lower.contains("superuser privilege") || lower.contains("permission denied") {
            return Refusal::Privilege;
        }
        if lower.contains("isn't installed") || lower.contains("is not installed") {
            return Refusal::Changed("the installed package");
        }
        Refusal::DryRunFailed(excerpt(raw_stderr))
    }

    /// Names of the packages dpkg says depend on the target:
    /// ` libfoo depends on bar (>= 1).`
    fn dependents(text: &str) -> Vec<String> {
        let mut names = BTreeSet::new();
        for line in text.lines() {
            let line = line.trim_start();
            let mut parts = line.split_whitespace();
            let (Some(who), Some(verb)) = (parts.next(), parts.next()) else {
                continue;
            };
            if matches!(verb, "depends" | "pre-depends") && parts.next() == Some("on") {
                let who = who.split(':').next().unwrap_or(who);
                if valid_apt_name(who) {
                    names.insert(who.to_string());
                }
            }
        }
        names.into_iter().collect()
    }

    /// How far a failed `dpkg --remove` got.
    ///
    /// The words in the output alone prove nothing: a maintainer script can
    /// print any of them after the package is gone. dpkg prints its
    /// `Removing NAME (VERSION) ...` line to stdout before it runs the
    /// pre-removal script, so a refusal that dpkg reported itself, with no
    /// such line, is the only output that counts as "nothing was changed".
    /// Everything else stays unproven and is never reported as unchanged.
    pub(in crate::resources) fn classify_failure(
        out: &Output,
        name: &str,
        arch: &str,
    ) -> FailureCause {
        let stdout = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        if stdout
            .lines()
            .any(|l| l.trim_start().starts_with("removing "))
        {
            return FailureCause::Started;
        }
        if out.stdout_truncated || out.stderr_truncated {
            return FailureCause::Unproven;
        }
        let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
        if Self::refused_by_dpkg(
            &stderr,
            &name.to_ascii_lowercase(),
            &arch.to_ascii_lowercase(),
        ) {
            FailureCause::RefusedBeforeChange
        } else {
            FailureCause::Unproven
        }
    }

    /// dpkg's own refusals, matched as whole lines of its diagnostics (lower
    /// case input): a dependency problem for this package, a lock held by
    /// another process, missing privilege, an ambiguous name, an essential
    /// package.
    fn refused_by_dpkg(stderr: &str, name: &str, arch: &str) -> bool {
        let qualified = format!("{}:{}", name, arch);
        let lines: Vec<&str> = stderr.lines().collect();
        lines.iter().enumerate().any(|(i, line)| {
            if let Some(subject) = line
                .strip_prefix("dpkg: dependency problems prevent removal of ")
                .and_then(|rest| rest.strip_suffix(':'))
            {
                return subject == name || subject == qualified;
            }
            if let Some(subject) = line
                .strip_prefix("dpkg: error processing package ")
                .and_then(|rest| rest.strip_suffix(" (--remove):"))
            {
                return (subject == name || subject == qualified)
                    && lines
                        .get(i + 1)
                        .is_some_and(|next| next.contains("essential package"));
            }
            if let Some(rest) = line.strip_prefix("dpkg: error: ") {
                return rest.contains("locked by another process")
                    || rest == "requested operation requires superuser privilege"
                    || rest
                        == format!(
                            "ambiguous package name '{}' with more than one installed instance",
                            name
                        );
            }
            false
        })
    }
}
