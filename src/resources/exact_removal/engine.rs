//! The command sequence of an exact-target removal.
//!
//! Every step before the removing command is read-only and ends in a refusal
//! with `Change::None`. The removing command receives the installed package's
//! own identity as its only operand. Afterwards the package database is read
//! back: the target must be gone, no other package may be gone, and no new
//! database problem may exist.

use super::{
    excerpt, optional_text, rpm::Protection, AptExact, DryRun, ExactIdentity, FailureCause,
    Inventory, Refusal, RpmExact,
};
use crate::engine::Engine;
use crate::error::{ErrorKind, Result, SinterError};
use crate::executor::{Completion, ExecRequest, Output};
use crate::model::FrozenResource;
use crate::platform::PackageBackend;
use crate::result::*;
use crate::targetfs::MutationPermit;
use std::collections::{BTreeMap, BTreeSet};

use super::super::{baseline_env, changed_result_sensitive, PackageState};

const DPKG: &str = "/usr/bin/dpkg";
const DPKG_QUERY: &str = "/usr/bin/dpkg-query";
const RPM: &str = "/usr/bin/rpm";
const FIND: &str = "/usr/bin/find";
const CAT: &str = "/usr/bin/cat";
const UNAME: &str = "/usr/bin/uname";
const APT_GET: &str = "/usr/bin/apt-get";

/// Recipe `env` names that reach the removing tools. Anything else (for
/// example `DPKG_FORCE`, `DPKG_ADMINDIR`, `DPKG_FRONTEND_LOCKED`, `LANGUAGE`)
/// could change what dpkg or rpm does or how its answers read, so it is
/// dropped for these commands.
const PASSED_ENV: [&str; 4] = [
    "DEBIAN_FRONTEND",
    "DEBIAN_PRIORITY",
    "NEEDRESTART_MODE",
    "NEEDRESTART_SUSPEND",
];

/// Seconds for a read-only step and for the removing command.
const QUERY_TIMEOUT: u64 = 120;
const VERIFY_TIMEOUT: u64 = 300;
const MUTATION_TIMEOUT: u64 = 300;

struct Run<'a> {
    res: &'a FrozenResource,
    name: &'a str,
    sensitive: bool,
    backend: PackageBackend,
    env: &'a BTreeMap<String, String>,
    permit: &'a MutationPermit,
}

impl Run<'_> {
    fn disp(&self) -> &str {
        if self.sensitive {
            "[redacted]"
        } else {
            self.name
        }
    }
}

/// What the package database looked like before the removing command.
struct Baseline {
    inventory: Inventory,
    issues: BTreeSet<String>,
}

type Step<T> = std::result::Result<T, ResourceResult>;

/// Return the early result of a step that did not produce a value.
macro_rules! gate {
    ($step:expr) => {
        match $step {
            Ok(value) => value,
            Err(result) => return Ok(result),
        }
    };
}

impl Engine {
    /// Remove exactly the package `name` with the low-level tool of
    /// `backend`. The caller has already established that the package is
    /// installed and that Apply mode applies.
    pub(in crate::resources) fn run_exact_package_removal(
        &mut self,
        res: &FrozenResource,
        name: &str,
        sensitive: bool,
        backend: PackageBackend,
        package_env: &BTreeMap<String, String>,
        permit: &MutationPermit,
    ) -> Result<ResourceResult> {
        let run = Run {
            res,
            name,
            sensitive,
            backend,
            env: package_env,
            permit,
        };
        let valid = match backend {
            PackageBackend::Apt => AptExact::valid_name(name),
            PackageBackend::Dnf => RpmExact::valid_name(name),
        };
        if !valid {
            return Ok(Self::refusal(&run, &Refusal::InvalidName));
        }
        let mut result = match backend {
            PackageBackend::Apt => self.apt_exact_removal(&run),
            PackageBackend::Dnf => self.rpm_exact_removal(&run),
        }?;
        // Recipe env names the removal commands do not get are dropped; say so
        // (a count only: the names may be sensitive).
        let dropped = package_env
            .keys()
            .filter(|name| !PASSED_ENV.contains(&name.as_str()))
            .count();
        if dropped > 0 {
            result.notes.push(format!(
                "{} environment variable(s) from with.env were not passed to the package \
                 removal commands (only {} are)",
                dropped,
                PASSED_ENV.join(", ")
            ));
        }
        Ok(result)
    }

    // ---------------------------------------------------------------------
    // APT
    // ---------------------------------------------------------------------

    fn apt_exact_removal(&mut self, run: &Run) -> Result<ResourceResult> {
        let out = gate!(self.query(run, DPKG_QUERY, AptExact::identity_args(run.name))?);
        let identity =
            gate!(AptExact::parse_identity(&out, run.name).map_err(|r| Self::refusal(run, &r)));

        let audit = gate!(self.query(run, DPKG, AptExact::audit_args())?);
        let mut issues =
            gate!(AptExact::audit_issues(&audit).map_err(|w| Self::unestablished(run, &audit, w)));
        let check = gate!(self.query(run, APT_GET, AptExact::check_args())?);
        issues.extend(
            gate!(AptExact::check_issues(&check).map_err(|w| Self::unestablished(run, &check, w)))
                .into_iter()
                .map(|line| format!("apt-get check: {}", line)),
        );
        let inv = gate!(self.query(run, DPKG_QUERY, AptExact::inventory_args())?);
        let inventory =
            gate!(AptExact::parse_inventory(&inv).map_err(|w| Self::unestablished(run, &inv, w)));

        let dry = gate!(self.query(run, DPKG, AptExact::dry_run_args(run.name))?);
        if let DryRun::Refused(reason) = AptExact::classify_dry_run(&dry, run.name) {
            return Ok(Self::refusal(run, &reason));
        }

        // The removing command takes a bare name, so confirm the identity once
        // more immediately before it. dpkg checks the dependencies itself
        // under its own database lock.
        let again = gate!(self.query(run, DPKG_QUERY, AptExact::identity_args(run.name))?);
        match AptExact::parse_identity(&again, run.name) {
            Ok(now) if now == identity => {}
            Ok(_) => return Ok(Self::refusal(run, &Refusal::Changed("the package version"))),
            Err(reason) => return Ok(Self::refusal(run, &reason)),
        }

        self.exact_mutation(
            run,
            DPKG,
            AptExact::remove_args(run.name),
            &identity,
            &Baseline { inventory, issues },
        )
    }

    // ---------------------------------------------------------------------
    // DNF4 (rpm)
    // ---------------------------------------------------------------------

    fn rpm_exact_removal(&mut self, run: &Run) -> Result<ResourceResult> {
        let out = gate!(self.query(run, RPM, RpmExact::identity_args(run.name))?);
        let identity =
            gate!(RpmExact::parse_identity(&out, run.name).map_err(|r| Self::refusal(run, &r)));
        let Some(operand) = identity.rpm_operand() else {
            return Ok(Self::refusal(
                run,
                &Refusal::Unestablished("the package identity"),
            ));
        };

        gate!(self.rpm_protection(run, &identity)?);

        // The NEVRA must resolve to exactly the package that was identified,
        // not to a different package that happens to carry that name.
        gate!(self.rpm_operand_matches(run, &operand, &identity)?);

        let inv = gate!(self.query(run, RPM, RpmExact::inventory_args())?);
        let inventory =
            gate!(RpmExact::parse_inventory(&inv).map_err(|w| Self::unestablished(run, &inv, w)));
        let verify = gate!(self.query_with(run, RPM, RpmExact::verify_args(), VERIFY_TIMEOUT)?);
        let issues = gate!(
            RpmExact::verify_issues(&verify).map_err(|w| Self::unestablished(run, &verify, w))
        );

        let test = gate!(self.query(run, RPM, RpmExact::test_args(&operand))?);
        if let DryRun::Refused(reason) = RpmExact::classify_dry_run(&test) {
            return Ok(Self::refusal(run, &reason));
        }

        gate!(self.rpm_operand_matches(run, &operand, &identity)?);

        self.exact_mutation(
            run,
            super::rpm::ERASE_PROGRAM,
            RpmExact::erase_args(&operand),
            &identity,
            &Baseline { inventory, issues },
        )
    }

    /// The protections `dnf remove` applies and `rpm -e` does not: the DNF
    /// protected-package lists and the running kernel. Also the one
    /// precondition of the lock wrapper: dnf keeps its lock where the wrapper
    /// looks for it.
    fn rpm_protection(&mut self, run: &Run, identity: &ExactIdentity) -> Result<Step<()>> {
        const WHAT: &str = "the DNF protected-package list";
        let dirs = match self.query(run, FIND, RpmExact::protected_dirs_args())? {
            Ok(out) => out,
            Err(result) => return Ok(Err(result)),
        };
        let conf = match self.query(run, CAT, RpmExact::dnf_conf_args())? {
            Ok(out) => out,
            Err(result) => return Ok(Err(result)),
        };
        let (Ok(dirs), Ok(conf)) = (RpmExact::protected_files_text(&dirs), optional_text(&conf))
        else {
            return Ok(Err(Self::refusal(run, &Refusal::Unestablished(WHAT))));
        };
        // dnf keeps its process lock under `persistdir` (dnf-automatic can
        // override it too); the wrapper only knows the default location.
        let automatic = match self.query(run, CAT, RpmExact::automatic_conf_args())? {
            Ok(out) => out,
            Err(result) => return Ok(Err(result)),
        };
        let Ok(automatic) = optional_text(&automatic) else {
            return Ok(Err(Self::refusal(
                run,
                &Refusal::Unestablished("the dnf-automatic configuration"),
            )));
        };
        for text in [&conf, &automatic] {
            if RpmExact::conf_persistdirs(text)
                .iter()
                .any(|dir| dir.trim_end_matches('/') != super::rpm::DNF_PERSISTDIR)
            {
                return Ok(Err(Self::refusal(
                    run,
                    &Refusal::Unestablished("the location of the dnf lock (custom persistdir)"),
                )));
            }
        }
        let mut entries = RpmExact::parse_protected_files(&dirs);
        entries.extend(RpmExact::parse_dnf_conf_protected(&conf));
        match RpmExact::protection(&entries, &identity.name) {
            Protection::No => {}
            Protection::Yes => return Ok(Err(Self::refusal(run, &Refusal::DnfProtected))),
            Protection::Unevaluable => {
                return Ok(Err(Self::refusal(run, &Refusal::Unestablished(WHAT))));
            }
        }
        {
            let out = match self.query(run, UNAME, RpmExact::uname_args())? {
                Ok(out) => out,
                Err(result) => return Ok(Err(result)),
            };
            let release = match (super::exit_code(&out), super::complete_stdout(&out)) {
                (Some(0), Ok(text))
                    if out.stderr.is_empty() && RpmExact::valid_kernel_release(text) =>
                {
                    text.trim().to_string()
                }
                _ => {
                    return Ok(Err(Self::refusal(
                        run,
                        &Refusal::Unestablished("the running kernel"),
                    )));
                }
            };
            // The package that owns the running kernel's image, as libdnf
            // finds it, is the one dnf refuses to remove.
            for path in RpmExact::kernel_image_paths(&release) {
                let out = match self.query(run, RPM, RpmExact::owner_args(&path))? {
                    Ok(out) => out,
                    Err(result) => return Ok(Err(result)),
                };
                match RpmExact::parse_owner(&out) {
                    Ok(Some(owner)) if owner == identity.name => {
                        return Ok(Err(Self::refusal(run, &Refusal::RunningKernel)));
                    }
                    Ok(_) => {}
                    Err(w) => {
                        return Ok(Err(Self::refusal(run, &Refusal::Unestablished(w))));
                    }
                }
            }
        }
        Ok(Ok(()))
    }

    fn rpm_operand_matches(
        &mut self,
        run: &Run,
        operand: &str,
        identity: &ExactIdentity,
    ) -> Result<Step<()>> {
        let out = match self.query(run, RPM, RpmExact::identity_args(operand))? {
            Ok(out) => out,
            Err(result) => return Ok(Err(result)),
        };
        match RpmExact::parse_identity(&out, run.name) {
            Ok(found) if &found == identity => Ok(Ok(())),
            Ok(_) => Ok(Err(Self::refusal(
                run,
                &Refusal::Changed("the installed package"),
            ))),
            Err(reason) => Ok(Err(Self::refusal(run, &reason))),
        }
    }

    // ---------------------------------------------------------------------
    // the removing command and its verification
    // ---------------------------------------------------------------------

    /// True when dpkg answered with one of its two "ignoring request to
    /// remove" warnings for exactly this package instance and did not report
    /// removing anything. dpkg 1.22 (`deferred_remove`, `warning()` adds the
    /// "dpkg: warning: " prefix) says, for a request about a package that is
    /// not there:
    ///
    /// ```text
    /// dpkg: warning: ignoring request to remove NAME which isn't installed
    /// dpkg: warning: ignoring request to remove NAME, only the config
    ///  files of which are on the system; use --purge to remove them too
    /// ```
    ///
    /// `NAME` is printed as `NAME:ARCH` when the name alone would be
    /// ambiguous. The subject has to be this package, or this package with the
    /// architecture of the instance that was being removed: a longer name that
    /// merely starts with it, or another architecture, does not count. The
    /// rest of the line must be dpkg's text, not just similar words.
    pub(in crate::resources) fn dpkg_ignored_the_request(
        out: &Output,
        name: &str,
        arch: &str,
    ) -> bool {
        const PREFIX: &str = "dpkg: warning: ignoring request to remove ";
        const NOT_INSTALLED: &str = " which isn't installed";
        const CONFIG_FILES: &str = ", only the config";
        const CONFIG_FILES_NEXT: &str =
            " files of which are on the system; use --purge to remove them too";

        if out.stdout_truncated || out.stderr_truncated {
            return false;
        }
        let stdout = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        if stdout
            .lines()
            .any(|l| l.trim_start().starts_with("removing "))
        {
            return false;
        }
        let name = name.to_ascii_lowercase();
        let qualified = format!("{}:{}", name, arch.to_ascii_lowercase());
        let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
        let lines: Vec<&str> = stderr.lines().collect();
        lines.iter().enumerate().any(|(i, line)| {
            let Some(rest) = line.strip_prefix(PREFIX) else {
                return false;
            };
            // A package name cannot contain a space or a comma, so the first
            // of them ends the subject.
            let Some(end) = rest.find([' ', ',']) else {
                return false;
            };
            let (subject, tail) = rest.split_at(end);
            if subject != name && subject != qualified {
                return false;
            }
            match tail {
                NOT_INSTALLED => true,
                CONFIG_FILES => lines.get(i + 1) == Some(&CONFIG_FILES_NEXT),
                _ => false,
            }
        })
    }

    /// How far the failed removing command got, from its own output.
    fn failure_cause(run: &Run, out: &Output, identity: &ExactIdentity) -> FailureCause {
        match run.backend {
            PackageBackend::Apt => AptExact::classify_failure(out, run.name, &identity.arch),
            PackageBackend::Dnf => RpmExact::classify_failure(out),
        }
    }

    fn exact_mutation(
        &mut self,
        run: &Run,
        program: &str,
        args: Vec<String>,
        identity: &ExactIdentity,
        baseline: &Baseline,
    ) -> Result<ResourceResult> {
        let sensitive = run.sensitive;
        let tool = match run.backend {
            PackageBackend::Apt => "dpkg",
            PackageBackend::Dnf => "rpm",
        };
        let mut req = self.exact_request(run, program, args);
        req.timeout_secs = MUTATION_TIMEOUT;
        let out = if self.fs.fault() == Some("package_mutation_dispatch_fail") {
            Err(SinterError::apply(format!(
                "injected {} remove dispatch failure",
                run.backend.label()
            )))
        } else {
            self.fs.exec(run.permit, &req)
        };
        // Nothing else is sent to the target until the removing command's
        // completion is established.
        let out = match out {
            Ok(out) => out,
            Err(e) => {
                return Err(SinterError::apply(format!(
                    "{} remove {} failed to dispatch: {}",
                    tool,
                    run.disp(),
                    e.message
                )));
            }
        };
        let code = match &out.completion {
            Completion::Indeterminate { reason, .. } => {
                let mut r = changed_result_sensitive(run.res, sensitive);
                r.execution = Execution::Indeterminate;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "{} operation did not complete: {}",
                    run.backend.label(),
                    reason
                ));
                return Ok(r);
            }
            Completion::Signaled(s) => {
                let mut r = changed_result_sensitive(run.res, sensitive);
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Unknown;
                r.reason = Some(format!(
                    "{} operation terminated by signal {}",
                    run.backend.label(),
                    s
                ));
                return Ok(r);
            }
            Completion::Exited(code) => *code,
        };

        if self.fs.fault() == Some("package_reobserve_indeterminate") {
            let mut r = changed_result_sensitive(run.res, sensitive);
            r.change = Change::Changed;
            r.execution = Execution::Indeterminate;
            r.verification = Verification::Unknown;
            r.reason = Some("injected package re-observation indeterminate after mutation".into());
            return Ok(r);
        }
        if self.fs.fault() == Some("package_reobserve_fail") {
            let mut r = changed_result_sensitive(run.res, sensitive);
            r.change = Change::Changed;
            r.execution = Execution::Failed;
            r.verification = Verification::Failed;
            r.reason = Some("injected package re-observation failure after mutation".into());
            return Ok(r);
        }

        let after = self.observe_package_sensitive(run.backend, run.name, sensitive);
        let failure_note = if let Some(note) = RpmExact::wrapper_note(&out) {
            format!(": {}", note)
        } else if sensitive {
            String::new()
        } else {
            let note = excerpt(&[out.stderr.as_slice(), out.stdout.as_slice()].concat());
            if note.is_empty() {
                String::new()
            } else {
                format!(": {}", note)
            }
        };
        let lower_output = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        )
        .to_ascii_lowercase();
        let scriptlet_failed = lower_output.contains("scriptlet failed")
            || lower_output.contains("script subprocess returned");
        // dpkg configured (dpkg.cfg, DPKG_FORCE) to ignore dependency problems
        // says so and exits 0 after removing the package regardless.
        let forced_removal = lower_output.contains("removing anyway");

        if code != 0 {
            return Ok(match after {
                Err(e) => {
                    let mut r = changed_result_sensitive(run.res, sensitive);
                    r.execution = if e.kind == ErrorKind::Indeterminate {
                        Execution::Indeterminate
                    } else {
                        Execution::Failed
                    };
                    r.change = Change::Possible;
                    r.verification = Verification::Unknown;
                    r.reason = Some(format!(
                        "{} remove {} failed with exit code {} and the package state could not be \
                         read back: {}",
                        tool,
                        run.disp(),
                        code,
                        e.message
                    ));
                    r
                }
                Ok(PackageState::Installed) => {
                    let untouched = Self::failure_cause(run, &out, identity)
                        == FailureCause::RefusedBeforeChange;
                    let mut r = changed_result_sensitive(run.res, sensitive);
                    r.execution = Execution::Failed;
                    if untouched {
                        r.change = Change::None;
                        r.verification = Verification::NotPerformed;
                    } else {
                        // Package scripts may have run before the failure.
                        r.change = Change::Possible;
                        r.verification = Verification::Failed;
                    }
                    r.reason = Some(format!(
                        "{} remove {} failed with exit code {}; the package is still installed{}",
                        tool,
                        run.disp(),
                        code,
                        failure_note
                    ));
                    r
                }
                Ok(PackageState::Absent) => {
                    let cause = Self::failure_cause(run, &out, identity);
                    let mut r = changed_result_sensitive(run.res, sensitive);
                    r.execution = Execution::Failed;
                    if cause == FailureCause::RefusedBeforeChange {
                        // The tool refused because the package was already
                        // gone: someone else removed it, this command did not.
                        r.change = Change::None;
                        r.verification = Verification::Verified;
                        let mut reason = format!(
                            "{} remove {} failed with exit code {}; the package was already gone \
                             when the command ran{}",
                            tool,
                            run.disp(),
                            code,
                            failure_note
                        );
                        // APT: what else changed is still checked, as for a
                        // successful removal.
                        if run.backend == PackageBackend::Apt {
                            if let Some(problem) =
                                self.post_removal_problem(run, identity, baseline)
                            {
                                r.verification = problem.verification;
                                reason.push_str("; ");
                                reason.push_str(&problem.reason);
                            }
                        }
                        r.reason = Some(reason);
                        return Ok(r);
                    }
                    if cause == FailureCause::Unproven {
                        // The package is gone and the command failed, but
                        // nothing shows that dpkg refused first: this command
                        // may have removed it, or another process did.
                        r.change = Change::Possible;
                        r.verification = Verification::Verified;
                        let mut reason = format!(
                            "{} remove {} failed with exit code {} and the package is gone; \
                             nothing shows whether this command or another process removed \
                             it{}",
                            tool,
                            run.disp(),
                            code,
                            failure_note
                        );
                        if let Some(problem) = self.post_removal_problem(run, identity, baseline) {
                            r.verification = problem.verification;
                            reason.push_str("; ");
                            reason.push_str(&problem.reason);
                        }
                        r.reason = Some(reason);
                        return Ok(r);
                    }
                    // Partial failure: the package is gone but the tool
                    // reported an error, typically a failing removal script.
                    r.change = Change::Changed;
                    r.verification = Verification::Verified;
                    let mut reason = format!(
                        "{} remove {} reported exit code {} after the package was removed; a \
                         package script may have failed{}",
                        tool,
                        run.disp(),
                        code,
                        failure_note
                    );
                    if let Some(problem) = self.post_removal_problem(run, identity, baseline) {
                        r.verification = problem.verification;
                        reason.push_str("; ");
                        reason.push_str(&problem.reason);
                    }
                    r.reason = Some(reason);
                    r
                }
            });
        }

        let after = match after {
            Ok(state) => state,
            Err(e) => {
                let mut r = changed_result_sensitive(run.res, sensitive);
                r.change = Change::Changed;
                r.execution = if e.kind == ErrorKind::Indeterminate {
                    Execution::Indeterminate
                } else {
                    Execution::Failed
                };
                r.verification = if r.execution == Execution::Indeterminate {
                    Verification::Unknown
                } else {
                    Verification::Failed
                };
                r.reason = Some(format!(
                    "package mutation succeeded but re-observation failed: {}",
                    e.message
                ));
                return Ok(r);
            }
        };
        if matches!(after, PackageState::Installed) {
            let mut r = changed_result_sensitive(run.res, sensitive);
            r.change = Change::Possible;
            r.execution = Execution::Failed;
            r.verification = Verification::Failed;
            r.reason = Some("package state did not reach desired state after mutation".into());
            return Ok(r);
        }

        // dpkg only warns, and exits 0, for a request about a package that is
        // already gone: someone else removed it, this command did not. Only
        // dpkg's own warning for this very package, with no "Removing" line,
        // counts; a maintainer script that merely mentions the words does not.
        if run.backend == PackageBackend::Apt
            && Self::dpkg_ignored_the_request(&out, run.name, &identity.arch)
        {
            let mut r = changed_result_sensitive(run.res, sensitive);
            r.change = Change::None;
            r.execution = Execution::Failed;
            r.verification = Verification::Verified;
            let mut reason = format!(
                "{} remove {} was a no-op: the package was already gone when the command \
                 ran (removed by another process)",
                tool,
                run.disp()
            );
            if let Some(problem) = self.post_removal_problem(run, identity, baseline) {
                r.verification = problem.verification;
                reason.push_str("; ");
                reason.push_str(&problem.reason);
            }
            r.reason = Some(reason);
            return Ok(r);
        }

        // The package is gone. Now prove nothing else went with it.
        let mut r = changed_result_sensitive(run.res, sensitive);
        r.change = Change::Changed;
        r.verification = Verification::Verified;
        if let Some(problem) = self.post_removal_problem(run, identity, baseline) {
            r.execution = Execution::Failed;
            r.verification = problem.verification;
            r.reason = Some(problem.reason);
            return Ok(r);
        }
        if forced_removal {
            r.execution = Execution::Failed;
            r.verification = Verification::Failed;
            r.reason = Some(format!(
                "{} remove {} removed the package although dependency problems were reported \
                 and dpkg was configured to ignore them; inspect the host",
                tool,
                run.disp()
            ));
        } else if scriptlet_failed {
            r.execution = Execution::Failed;
            r.reason = Some(format!(
                "{} remove {} removed the package but a package script reported a failure{}",
                tool,
                run.disp(),
                failure_note
            ));
        }
        Ok(r)
    }

    /// Compare the database with the baseline. `None` means the removal left
    /// exactly the target gone and introduced no database problem.
    fn post_removal_problem(
        &mut self,
        run: &Run,
        identity: &ExactIdentity,
        baseline: &Baseline,
    ) -> Option<PostProblem> {
        let unreadable = |what: &str| {
            Some(PostProblem {
                verification: Verification::Unknown,
                reason: format!(
                    "the package was removed but {} could not be read back afterwards",
                    what
                ),
            })
        };
        // A check that cannot complete is reported as unknown, never as clean,
        // and never as a hard error: the removal itself has already happened.
        let inventory = match run.backend {
            PackageBackend::Apt => self
                .after_query(run, DPKG_QUERY, AptExact::inventory_args(), QUERY_TIMEOUT)
                .map(|out| AptExact::parse_inventory(&out)),
            PackageBackend::Dnf => self
                .after_query(run, RPM, RpmExact::inventory_args(), QUERY_TIMEOUT)
                .map(|out| RpmExact::parse_inventory(&out)),
        };
        let Some(Ok(inventory)) = inventory else {
            return unreadable("the installed-package list");
        };
        let gone = baseline.inventory.unexpected_removals(&inventory, identity);
        if !gone.is_empty() {
            let mut reason = format!(
                "the package was removed but {} other package(s) were removed as well",
                gone.len()
            );
            if !run.sensitive {
                let shown: Vec<&str> = gone.iter().take(8).map(String::as_str).collect();
                reason.push_str(&format!(" ({})", shown.join(", ")));
            }
            return Some(PostProblem {
                verification: Verification::Failed,
                reason,
            });
        }
        if !baseline
            .inventory
            .target_dropped_by_one(&inventory, identity)
        {
            return Some(PostProblem {
                verification: Verification::Failed,
                reason: "the installed-package list does not show the removal of exactly the \
                         requested package"
                    .to_string(),
            });
        }
        let issues = match run.backend {
            PackageBackend::Apt => {
                let audit = self
                    .after_query(run, DPKG, AptExact::audit_args(), QUERY_TIMEOUT)
                    .map(|out| AptExact::audit_issues(&out));
                let check = self
                    .after_query(run, APT_GET, AptExact::check_args(), QUERY_TIMEOUT)
                    .map(|out| AptExact::check_issues(&out));
                match (audit, check) {
                    (Some(Ok(mut audit)), Some(Ok(check))) => {
                        audit.extend(check.into_iter().map(|l| format!("apt-get check: {}", l)));
                        Some(Ok(audit))
                    }
                    _ => None,
                }
            }
            PackageBackend::Dnf => self
                .after_query(run, RPM, RpmExact::verify_args(), VERIFY_TIMEOUT)
                .map(|out| RpmExact::verify_issues(&out)),
        };
        let Some(Ok(issues)) = issues else {
            return unreadable("the package database check");
        };
        let new: Vec<&String> = issues.difference(&baseline.issues).collect();
        if !new.is_empty() {
            return Some(PostProblem {
                verification: Verification::Failed,
                reason: format!(
                    "the package was removed but {} new package database problem(s) appeared \
                     (broken dependencies or partly configured packages); inspect the host",
                    new.len()
                ),
            });
        }
        None
    }

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    fn exact_request(&self, run: &Run, program: &str, args: Vec<String>) -> ExecRequest {
        let mut req = ExecRequest::new(program);
        req.env = baseline_env(self.fs.home_env());
        req.env.extend(
            run.env
                .iter()
                .filter(|(name, _)| PASSED_ENV.contains(&name.as_str()))
                .map(|(name, value)| (name.clone(), value.clone())),
        );
        req.sensitive = run.sensitive;
        req.args = args;
        req.timeout_secs = QUERY_TIMEOUT;
        req
    }

    fn query(&mut self, run: &Run, program: &str, args: Vec<String>) -> Result<Step<Output>> {
        self.query_with(run, program, args, QUERY_TIMEOUT)
    }

    /// Run a read-only step. A command that could not run is a hard error; one
    /// that did not complete is a result with `Change::None`.
    fn query_with(
        &mut self,
        run: &Run,
        program: &str,
        args: Vec<String>,
        timeout: u64,
    ) -> Result<Step<Output>> {
        let mut req = self.exact_request(run, program, args);
        req.timeout_secs = timeout;
        let out = self.fs.exec(run.permit, &req)?;
        let stop = match &out.completion {
            Completion::Exited(_) => return Ok(Ok(out)),
            Completion::Signaled(s) => (
                Execution::Failed,
                format!("a check was terminated by signal {}", s),
            ),
            Completion::Indeterminate { reason, .. } => (
                Execution::Indeterminate,
                format!("a check did not complete: {}", reason),
            ),
        };
        let mut r = changed_result_sensitive(run.res, run.sensitive);
        r.change = Change::None;
        r.verification = Verification::NotPerformed;
        r.execution = stop.0;
        r.reason = Some(format!(
            "package removal of {} stopped: {}; nothing was changed",
            run.disp(),
            stop.1
        ));
        Ok(Err(r))
    }

    /// A read-only step after the removal. Any way of not getting a completed
    /// answer is `None`; the caller reports the check as unknown.
    fn after_query(
        &mut self,
        run: &Run,
        program: &str,
        args: Vec<String>,
        timeout: u64,
    ) -> Option<Output> {
        match self.query_with(run, program, args, timeout) {
            Ok(Ok(out)) => Some(out),
            _ => None,
        }
    }

    /// A baseline answer that could not be read: a privilege problem when the
    /// output says so, otherwise an answer that could not be established.
    fn unestablished(run: &Run, out: &Output, what: &'static str) -> ResourceResult {
        if super::lacks_privilege(out) {
            Self::refusal(run, &Refusal::Privilege)
        } else {
            Self::refusal(run, &Refusal::Unestablished(what))
        }
    }

    /// A removal stopped before any mutating command.
    fn refusal(run: &Run, reason: &Refusal) -> ResourceResult {
        let mut r = changed_result_sensitive(run.res, run.sensitive);
        r.change = Change::None;
        r.verification = Verification::NotPerformed;
        r.execution = Execution::Failed;
        r.reason = Some(format!(
            "{}; nothing was changed",
            reason.render(run.disp(), run.sensitive)
        ));
        r
    }
}

struct PostProblem {
    verification: Verification,
    reason: String,
}
