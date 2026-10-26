//! Exact-target package removal (WP-PKG-CORE-REPAIR P1).
//!
//! `state: absent` on APT and DNF4 hosts removes exactly the named package.
//! The package manager's resolver (`apt-get remove`, `dnf remove`) is never
//! asked to choose a removal set; the low-level tool is used instead:
//!
//! - APT: `dpkg --dry-run --remove NAME`, then `dpkg --remove NAME`
//! - DNF4: `rpm -e --test NEVRA`, then `rpm -e NEVRA`
//!
//! Neither tool removes a reverse dependency: `dpkg --remove` and `rpm -e`
//! refuse when the removal would break an installed package, and no force
//! option (`--force-depends`, `--nodeps`, `--allmatches`) is ever passed. The
//! refusal is made by the tool itself while it holds its own database lock,
//! so a package installed between Sinter's dry-run and the real removal
//! cannot be removed along with the target.
//!
//! This module holds the pure part: name validation, argv, record parsers and
//! failure classification. The engine (`engine.rs`) sequences the commands.
//! Everything here is fail-closed: an answer that cannot be parsed completely
//! is a refusal, never a default.
//!
//! Sensitive data: refusal text is built from fixed phrases. The package name
//! and any other package name taken from tool output are rendered only when
//! the resource is not sensitive.

mod apt;
mod engine;
mod rpm;
#[cfg(test)]
mod tests;

use crate::executor::{Completion, Output};
use std::collections::BTreeMap;
use std::fmt;

/// Longest accepted package name, architecture and version token.
const MAX_NAME: usize = 128;
const MAX_ARCH: usize = 32;
const MAX_VERSION: usize = 128;
/// Most dependent names rendered into one refusal.
const MAX_LISTED: usize = 8;
/// Most lines and characters of tool output quoted into a failure reason.
const EXCERPT_LINES: usize = 3;
const EXCERPT_CHARS: usize = 200;

/// The identity of the one installed package a removal is allowed to remove.
///
/// For APT `version` is the full Debian version and `release`/`epoch` are
/// `None`; for DNF4 `version` and `release` are the RPM VERSION and RELEASE.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct ExactIdentity {
    pub(super) name: String,
    pub(super) arch: String,
    pub(super) version: String,
    pub(super) release: Option<String>,
    pub(super) epoch: Option<String>,
}

impl fmt::Debug for ExactIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExactIdentity")
            .field("name", &"<redacted>")
            .finish()
    }
}

impl ExactIdentity {
    /// The `name-version-release.arch` operand `rpm -e` receives. It is the
    /// installed package's own NEVRA, so the tool can only match that one
    /// package.
    pub(super) fn rpm_operand(&self) -> Option<String> {
        let release = self.release.as_ref()?;
        Some(format!(
            "{}-{}-{}.{}",
            self.name, self.version, release, self.arch
        ))
    }
}

/// The installed set as `(name, architecture)` with the number of installed
/// instances. A removal other than the target shows up as a key whose count
/// dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Inventory {
    counts: BTreeMap<(String, String), u32>,
}

impl Inventory {
    pub(super) fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Inventory {
        let mut counts = BTreeMap::new();
        for key in pairs {
            *counts.entry(key).or_insert(0u32) += 1;
        }
        Inventory { counts }
    }

    /// Keys whose instance count dropped from `self` (before) to `after`,
    /// excluding exactly one instance of `target`.
    pub(super) fn unexpected_removals(
        &self,
        after: &Inventory,
        target: &ExactIdentity,
    ) -> Vec<String> {
        let mut gone = Vec::new();
        for (key, before) in &self.counts {
            let now = after.counts.get(key).copied().unwrap_or(0);
            let mut dropped = before.saturating_sub(now);
            if key.0 == target.name && key.1 == target.arch {
                dropped = dropped.saturating_sub(1);
            }
            if dropped > 0 {
                gone.push(format!("{}.{}", key.0, key.1));
            }
        }
        gone
    }

    /// Whether the target lost exactly one instance.
    pub(super) fn target_dropped_by_one(&self, after: &Inventory, target: &ExactIdentity) -> bool {
        let key = (target.name.clone(), target.arch.clone());
        let before = self.counts.get(&key).copied().unwrap_or(0);
        let now = after.counts.get(&key).copied().unwrap_or(0);
        before >= 1 && now + 1 == before
    }
}

/// Why a removal was stopped before the removing command ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Refusal {
    /// The name is outside the character set the backend can have.
    InvalidName,
    /// A query could not be completed or parsed; the string is a fixed phrase.
    Unestablished(&'static str),
    /// More than one installed package matches the name.
    Ambiguous,
    /// The package is installed but not in a clean `installed` state.
    NotClean,
    /// Essential or protected by the package manager.
    SystemProtected(&'static str),
    /// Listed in the DNF protected-package configuration.
    DnfProtected,
    /// The package provides the running kernel.
    RunningKernel,
    /// Installed packages depend on the target. Names are rendered only for a
    /// non-sensitive resource.
    ReverseDependencies(Vec<String>),
    /// The package database is locked by another process.
    LockBusy,
    /// The account running the tool may not change the package database.
    Privilege,
    /// The package changed between planning and the removing command.
    Changed(&'static str),
    /// The dry-run failed for a reason the classifier does not know.
    DryRunFailed(String),
}

impl Refusal {
    pub(super) fn render(&self, name_disp: &str, sensitive: bool) -> String {
        match self {
            Refusal::InvalidName => format!(
                "package removal of {} refused: the name is not valid for this package manager",
                name_disp
            ),
            Refusal::Unestablished(what) => format!(
                "package removal of {} refused: {} could not be established",
                name_disp, what
            ),
            Refusal::Ambiguous => format!(
                "package removal of {} refused: more than one installed package matches the name \
                 (another architecture or version is installed too)",
                name_disp
            ),
            Refusal::NotClean => format!(
                "package removal of {} refused: the package is not in a clean installed state",
                name_disp
            ),
            Refusal::SystemProtected(kind) => format!(
                "package removal of {} refused: the package is {} and cannot be removed by Sinter",
                name_disp, kind
            ),
            Refusal::DnfProtected => format!(
                "package removal of {} refused: the package is protected by the DNF \
                 protected-package configuration",
                name_disp
            ),
            Refusal::RunningKernel => format!(
                "package removal of {} refused: the package provides the running kernel",
                name_disp
            ),
            Refusal::ReverseDependencies(dependents) => {
                let mut text = if dependents.is_empty() {
                    format!(
                        "package removal of {} refused: installed packages depend on it",
                        name_disp
                    )
                } else {
                    format!(
                        "package removal of {} refused: {} installed package(s) depend on it",
                        name_disp,
                        dependents.len()
                    )
                };
                if !sensitive && !dependents.is_empty() {
                    let shown: Vec<&str> = dependents
                        .iter()
                        .take(MAX_LISTED)
                        .map(String::as_str)
                        .collect();
                    text.push_str(&format!(" ({}", shown.join(", ")));
                    if dependents.len() > MAX_LISTED {
                        text.push_str(", ...");
                    }
                    text.push(')');
                }
                text.push_str("; remove or replace the dependent packages first");
                text
            }
            Refusal::LockBusy => format!(
                "package removal of {} refused: the package database is in use by another process",
                name_disp
            ),
            Refusal::Privilege => format!(
                "package removal of {} refused: the account has no privilege to change the package \
                 database (run as root or use --sudo)",
                name_disp
            ),
            Refusal::Changed(what) => format!(
                "package removal of {} refused: {} changed while the removal was being prepared",
                name_disp, what
            ),
            Refusal::DryRunFailed(note) => {
                let mut text = format!(
                    "package removal of {} refused: the removal check failed",
                    name_disp
                );
                if !sensitive && !note.is_empty() {
                    text.push_str(&format!(" ({})", note));
                }
                text
            }
        }
    }
}

/// What the removing command's failure tells about the package state. It is
/// only used to describe the failure; whether the package is gone is decided
/// by observing the database afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FailureCause {
    /// The tool refused before it changed anything (dependencies, lock).
    RefusedBeforeChange,
    /// APT only: dpkg had begun the removal (its `Removing` line is on
    /// stdout), so package scripts may have run.
    Started,
    /// APT only: nothing shows how far dpkg got. It is neither a refusal dpkg
    /// itself reported before it started nor a removal that started.
    Unproven,
    /// Anything else, including scriptlet failure (DNF4).
    Other,
}

/// The classification of a dry-run (`dpkg --dry-run`, `rpm -e --test`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DryRun {
    /// The tool would remove the target and nothing else.
    Clean,
    Refused(Refusal),
}

/// Fixed-size, control-character-free excerpt of tool output for a failure
/// reason. Only used for non-sensitive resources.
pub(super) fn excerpt(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut lines: Vec<String> = Vec::new();
    for line in text.lines() {
        let cleaned: String = line
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let cleaned = cleaned.trim();
        if cleaned.is_empty() {
            continue;
        }
        let mut clipped: String = cleaned.chars().take(EXCERPT_CHARS).collect();
        if cleaned.chars().count() > EXCERPT_CHARS {
            clipped.push_str("...");
        }
        lines.push(clipped);
        if lines.len() == EXCERPT_LINES {
            break;
        }
    }
    lines.join(" | ")
}

/// A complete, valid-UTF-8 capture with nothing on stderr, or the fixed reason
/// the capture cannot be trusted.
pub(super) fn complete_stdout(out: &Output) -> Result<&str, &'static str> {
    if out.stdout_truncated || out.stderr_truncated {
        return Err("output was truncated");
    }
    std::str::from_utf8(&out.stdout).map_err(|_| "output was not valid UTF-8")
}

/// Whether a command failed because the account may not read or change the
/// package database.
pub(super) fn lacks_privilege(out: &Output) -> bool {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    )
    .to_ascii_lowercase();
    text.contains("superuser privilege")
        || text.contains("permission denied")
        || text.contains("you do not have permission")
}

/// The exit code of a completed command, or `None` for a signal or an
/// indeterminate completion.
pub(super) fn exit_code(out: &Output) -> Option<i32> {
    match out.completion {
        Completion::Exited(code) => Some(code),
        _ => None,
    }
}

/// The stdout of a command that may legitimately find nothing: a missing file
/// or directory (exit 1 with only "No such file or directory" on stderr) is an
/// empty answer; every other failure is not.
pub(super) fn optional_text(out: &Output) -> Result<String, &'static str> {
    const FAILED: &str = "the command failed";
    let text = complete_stdout(out).map_err(|_| FAILED)?;
    match exit_code(out) {
        Some(0) if out.stderr.is_empty() => Ok(text.to_string()),
        Some(1) => {
            let err = String::from_utf8_lossy(&out.stderr);
            let lines: Vec<&str> = err.lines().filter(|l| !l.trim().is_empty()).collect();
            if !lines.is_empty()
                && lines
                    .iter()
                    .all(|l| l.contains("No such file or directory"))
            {
                Ok(text.to_string())
            } else {
                Err(FAILED)
            }
        }
        _ => Err(FAILED),
    }
}

fn token_ok(token: &str, max: usize, allowed: impl Fn(char) -> bool) -> bool {
    !token.is_empty() && token.len() <= max && token.chars().all(allowed)
}

/// Debian package name: lower-case letters, digits and `+ - .`, starting with
/// a letter or digit, at least two characters.
pub(super) fn valid_apt_name(name: &str) -> bool {
    name.len() >= 2
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && token_ok(name, MAX_NAME, |c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '-' | '.')
        })
}

/// RPM package name: letters, digits and `. _ + -`, starting with a letter or
/// digit. `~` and `^` are not valid in a name.
pub(super) fn valid_rpm_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && token_ok(name, MAX_NAME, |c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-')
        })
}

pub(super) fn valid_arch(arch: &str) -> bool {
    token_ok(arch, MAX_ARCH, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
    })
}

/// Debian version: letters, digits and `. + ~ : -`.
pub(super) fn valid_apt_version(version: &str) -> bool {
    token_ok(version, MAX_VERSION, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '~' | ':' | '-')
    })
}

/// RPM VERSION or RELEASE: letters, digits and `. _ + ~ ^`, no `-`.
pub(super) fn valid_rpm_evr_part(part: &str) -> bool {
    token_ok(part, MAX_VERSION, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '~' | '^')
    })
}

pub(super) use apt::AptExact;
pub(super) use rpm::RpmExact;
