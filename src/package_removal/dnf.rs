//! DNF4/DNF5 removal-preview grammar (Stage R1).
//!
//! The two backends share the removal table sections measured in Stage R0:
//! `Removing:`, `Removing dependent packages:` and
//! `Removing unused dependencies:`. They differ in their summary and abort
//! grammar, so the backend is an explicit input and is never inferred:
//!
//! * DNF4: `Remove <N> Packages`, stderr `Operation aborted.`, optional
//!   `Freed space:`.
//! * DNF5: `Removing: <N> package(s)`, stderr
//!   `Operation aborted by the user.` (R0 printed an `After this operation, ...`
//!   line before it; that line is accepted when present but is not required,
//!   because it is informational and the abort line plus the table are the
//!   proof of a completed preview).
//!
//! A normal `--assumeno` abort is exit 1 **only** when the complete table and
//! the exact abort line are both present. Exit code alone is never treated as
//! success or failure.

use super::{
    PackageIdentity, PlannedRemoval, PreviewExit, PreviewInput, RemovalBackend, RemovalPreview,
    RemovalReason, RemovalSafetyError,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Requested,
    Dependent,
    Unused,
}

pub(super) fn parse(
    backend: RemovalBackend,
    requested: &str,
    input: PreviewInput<'_>,
    no_autoremove: bool,
) -> Result<RemovalPreview, RemovalSafetyError> {
    debug_assert!(backend.is_dnf());
    let _ = PackageIdentity::new(requested, None, None)?;
    if input.stdout_truncated || input.stderr_truncated {
        return Err(RemovalSafetyError::parse(None));
    }
    let stdout = std::str::from_utf8(input.stdout).map_err(|_| RemovalSafetyError::parse(None))?;
    let stderr = std::str::from_utf8(input.stderr).map_err(|_| RemovalSafetyError::parse(None))?;

    let (stderr_is_noop, stderr_noop_name) = validate_stderr(backend, input.exit_code, stderr)?;

    let mut rows: Vec<PlannedRemoval> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut section: Option<Section> = None;
    let mut summary: Option<usize> = None;
    let mut seen_header = false;
    let mut nothing_to_do = false;
    let mut no_match_name: Option<String> = None;

    for (index, raw_line) in stdout.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "Dependencies resolved." || is_divider(trimmed) {
            continue;
        }
        if is_header(trimmed) {
            if seen_header {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            seen_header = true;
            continue;
        }
        if trimmed == "Transaction Summary" || trimmed == "Transaction Summary:" {
            section = None;
            continue;
        }
        if let Some(next) = section_of(trimmed) {
            section = Some(next);
            continue;
        }
        if is_forbidden_section(trimmed) || trimmed.ends_with(':') {
            return Err(RemovalSafetyError::parse(Some(line_number)));
        }
        if let Some((count_backend, count)) = parse_summary(backend, trimmed) {
            if count_backend != backend {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            if summary.replace(count).is_some() {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            section = None;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Freed space:") {
            if rest.trim().is_empty() {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            continue;
        }
        if trimmed == "Nothing to do." {
            if !rows.is_empty() {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            nothing_to_do = true;
            continue;
        }
        if trimmed == "Complete!" {
            if !rows.is_empty() {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("No match for argument:") {
            if !rows.is_empty() {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            let name = rest.trim();
            if name.is_empty() || name.split_whitespace().count() != 1 {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            PackageIdentity::new(name, None, None)
                .map_err(|_| RemovalSafetyError::parse(Some(line_number)))?;
            if no_match_name.replace(name.to_string()).is_some() {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            continue;
        }
        if raw_line.starts_with(char::is_whitespace) {
            let Some(current) = section else {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            };
            let planned = parse_row(trimmed, requested, current, line_number)?;
            if !seen.insert((
                planned.identity().name().to_string(),
                planned.identity().architecture().map(ToOwned::to_owned),
                planned.identity().version().map(ToOwned::to_owned),
            )) {
                return Err(RemovalSafetyError::identity());
            }
            rows.push(planned);
            continue;
        }
        return Err(RemovalSafetyError::parse(Some(line_number)));
    }

    if no_autoremove
        && rows
            .iter()
            .any(|p| p.reason() == RemovalReason::UnusedDependency)
    {
        return Err(RemovalSafetyError::parse(None));
    }

    if input.exit_code == 1 {
        if rows.is_empty() {
            return Err(RemovalSafetyError::abort_unexpected());
        }
        let summary_count = summary.ok_or_else(|| RemovalSafetyError::parse(None))?;
        if summary_count != rows.len() {
            return Err(RemovalSafetyError::summary(summary_count, rows.len()));
        }
        if !rows
            .iter()
            .any(|p| p.identity().is_requested_name(requested))
        {
            return Err(RemovalSafetyError::requested_missing());
        }
        return Ok(RemovalPreview::new(
            backend,
            requested.to_string(),
            rows,
            summary_count,
            PreviewExit::Aborted,
            backend.command_identity(no_autoremove),
            input.backend_version,
        ));
    }
    if input.exit_code != 0 {
        return Err(RemovalSafetyError::command_failed());
    }

    if rows.is_empty() {
        if nothing_to_do {
            let noop_matches = match backend {
                RemovalBackend::Dnf4 => no_match_name.as_deref() == Some(requested),
                RemovalBackend::Dnf5 => {
                    stderr_is_noop && stderr_noop_name.as_deref() == Some(requested)
                }
                RemovalBackend::Apt => false,
            };
            if !noop_matches {
                return Err(RemovalSafetyError::requested_missing());
            }
            return Ok(RemovalPreview::new(
                backend,
                requested.to_string(),
                Vec::new(),
                0,
                PreviewExit::NoOp,
                backend.command_identity(no_autoremove),
                input.backend_version,
            ));
        }
        return Err(RemovalSafetyError::parse(None));
    }

    if stderr_is_noop {
        return Err(RemovalSafetyError::parse(None));
    }
    if !seen_header {
        return Err(RemovalSafetyError::parse(None));
    }
    let summary_count = summary.ok_or_else(|| RemovalSafetyError::parse(None))?;
    if summary_count != rows.len() {
        return Err(RemovalSafetyError::summary(summary_count, rows.len()));
    }
    if !rows
        .iter()
        .any(|p| p.identity().is_requested_name(requested))
    {
        return Err(RemovalSafetyError::requested_missing());
    }
    Ok(RemovalPreview::new(
        backend,
        requested.to_string(),
        rows,
        summary_count,
        PreviewExit::Completed,
        backend.command_identity(no_autoremove),
        input.backend_version,
    ))
}

fn validate_stderr(
    backend: RemovalBackend,
    exit_code: i32,
    stderr: &str,
) -> Result<(bool, Option<String>), RemovalSafetyError> {
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    match (backend, exit_code) {
        (RemovalBackend::Dnf4, 1) => {
            if lines == ["Operation aborted."] {
                Ok((false, None))
            } else {
                Err(RemovalSafetyError::abort_unexpected())
            }
        }
        (RemovalBackend::Dnf5, 1) => {
            let abort = lines
                .iter()
                .filter(|line| **line == "Operation aborted by the user.")
                .count();
            let after = lines
                .iter()
                .filter(|line| line.starts_with("After this operation,"))
                .count();
            if abort == 1 && after <= 1 && lines.len() == abort + after {
                Ok((false, None))
            } else {
                Err(RemovalSafetyError::abort_unexpected())
            }
        }
        (RemovalBackend::Dnf4, 0) => {
            if lines.is_empty() {
                Ok((false, None))
            } else if lines == ["No packages marked for removal."] {
                Ok((true, None))
            } else {
                Err(RemovalSafetyError::parse(None))
            }
        }
        (RemovalBackend::Dnf5, 0) => {
            if lines.is_empty() {
                Ok((false, None))
            } else if lines.len() == 1 {
                let name = lines[0]
                    .strip_prefix("No packages to remove for argument: ")
                    .map(str::trim)
                    .filter(|name| !name.is_empty() && name.split_whitespace().count() == 1)
                    .ok_or_else(|| RemovalSafetyError::parse(None))?;
                PackageIdentity::new(name, None, None)
                    .map_err(|_| RemovalSafetyError::parse(None))?;
                Ok((true, Some(name.to_string())))
            } else {
                Err(RemovalSafetyError::parse(None))
            }
        }
        _ => Err(RemovalSafetyError::command_failed()),
    }
}

fn section_of(line: &str) -> Option<Section> {
    match line {
        "Removing:" => Some(Section::Requested),
        "Removing dependent packages:" => Some(Section::Dependent),
        "Removing unused dependencies:" => Some(Section::Unused),
        _ => None,
    }
}

fn is_forbidden_section(line: &str) -> bool {
    matches!(
        line,
        "Installing:"
            | "Installing dependencies:"
            | "Installing weak dependencies:"
            | "Upgrading:"
            | "Upgrading dependencies:"
            | "Downgrading:"
            | "Reinstalling:"
            | "Cleanup:"
    )
}

fn is_divider(line: &str) -> bool {
    line.len() >= 10 && line.bytes().all(|b| b == b'=')
}

fn is_header(line: &str) -> bool {
    let f: Vec<&str> = line.split_whitespace().collect();
    f.len() == 5
        && f[0] == "Package"
        && (f[1] == "Arch" || f[1] == "Architecture")
        && f[2] == "Version"
        && (f[3] == "Repo" || f[3] == "Repository")
        && f[4] == "Size"
}

fn parse_summary(backend: RemovalBackend, line: &str) -> Option<(RemovalBackend, usize)> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() != 3 {
        return None;
    }
    let (expected_verb, singular, plural) = match backend {
        RemovalBackend::Dnf4 => ("Remove", "Package", "Packages"),
        RemovalBackend::Dnf5 => ("Removing:", "package", "packages"),
        RemovalBackend::Apt => return None,
    };
    if f[0] != expected_verb {
        return None;
    }
    let count = parse_count(f[1])?;
    let noun = if count == 1 { singular } else { plural };
    if f[2] != noun {
        return None;
    }
    Some((backend, count))
}

fn parse_count(text: &str) -> Option<usize> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

fn parse_row(
    line: &str,
    requested: &str,
    section: Section,
    line_number: usize,
) -> Result<PlannedRemoval, RemovalSafetyError> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 5 {
        return Err(RemovalSafetyError::parse(Some(line_number)));
    }
    if !valid_repository(f[3]) {
        return Err(RemovalSafetyError::parse(Some(line_number)));
    }
    if !f[4..].iter().all(|token| valid_size_token(token)) {
        return Err(RemovalSafetyError::parse(Some(line_number)));
    }
    let identity = PackageIdentity::new(f[0], Some(f[1]), Some(f[2]))
        .map_err(|_| RemovalSafetyError::parse(Some(line_number)))?;
    let reason = match section {
        Section::Requested => {
            if identity.is_requested_name(requested) {
                RemovalReason::Requested
            } else {
                // A row in the requested section that is not the requested
                // name cannot be promoted to `Requested`. It remains unknown
                // and is rejected by the exact-set decision.
                RemovalReason::Unknown
            }
        }
        Section::Dependent => RemovalReason::Dependent,
        Section::Unused => RemovalReason::UnusedDependency,
    };
    Ok(PlannedRemoval::new(identity, reason))
}

fn valid_repository(repo: &str) -> bool {
    !repo.is_empty()
        && repo.len() <= 128
        && repo.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'@' | b'+' | b'-')
        })
}

fn valid_size_token(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(|b| {
            b.is_ascii_digit()
                || matches!(
                    b,
                    b'.' | b','
                        | b'%'
                        | b'K'
                        | b'M'
                        | b'G'
                        | b'T'
                        | b'k'
                        | b'm'
                        | b'g'
                        | b't'
                        | b'B'
                        | b'i'
                )
        })
}
