//! APT removal-preview grammar (Stage R1).
//!
//! Only `apt-get -s remove` is modelled. The authoritative removal records are
//! the `Remv <name> [<version>]` lines; `The following packages will be
//! REMOVED:` is prose and is never trusted on its own. The summary's
//! `<N> to remove` must equal the number of parsed `Remv` records.
//!
//! Root and non-root simulations differ by the leading simulation note only
//! (measured in Stage R0). Both forms are accepted; the note is never part of
//! the removal set. `--auto-remove` is deliberately not modelled or enabled:
//! R0 measured that it can include baseline auto-installed packages.

use super::{
    PackageIdentity, PlannedRemoval, PreviewCommandIdentity, PreviewExit, PreviewInput,
    RemovalBackend, RemovalPreview, RemovalReason, RemovalSafetyError,
};
use std::collections::BTreeSet;

pub(super) fn parse(
    requested: &str,
    input: PreviewInput<'_>,
) -> Result<RemovalPreview, RemovalSafetyError> {
    // Validate the requested name through the same identity boundary as the
    // rows. It is not otherwise used to build an identity: APT prints no
    // architecture for the request.
    let _ = PackageIdentity::new(requested, None, None)?;
    if input.stdout_truncated || input.stderr_truncated {
        return Err(RemovalSafetyError::parse(None));
    }
    let stdout = std::str::from_utf8(input.stdout).map_err(|_| RemovalSafetyError::parse(None))?;
    let stderr = std::str::from_utf8(input.stderr).map_err(|_| RemovalSafetyError::parse(None))?;
    if input.exit_code != 0 {
        return Err(RemovalSafetyError::command_failed());
    }
    // R0 measured an empty stderr for both root and non-root simulations.
    if !stderr.trim().is_empty() {
        return Err(RemovalSafetyError::parse(None));
    }

    let mut auto_block = false;
    let mut removed_list = false;
    let mut display_seen = false;
    let mut display_names: BTreeSet<String> = BTreeSet::new();
    let mut noop_name: Option<String> = None;
    let mut remv: Vec<(PackageIdentity, RemovalReason)> = Vec::new();
    let mut summary: Option<usize> = None;

    for (index, raw_line) in stdout.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if auto_block {
            if trimmed.starts_with("Use '") && trimmed.ends_with("to remove them.") {
                auto_block = false;
                continue;
            }
            if raw_line.starts_with(char::is_whitespace) {
                // The auto-installed list is display-only. It is not a removal
                // set; the `Remv` lines below remain authoritative.
                continue;
            }
            return Err(RemovalSafetyError::parse(Some(line_number)));
        }

        if removed_list {
            if raw_line.starts_with(char::is_whitespace) {
                // The display list may wrap across lines. It is validated as a
                // list of name-shaped tokens, but its membership is not the
                // removal set.
                for token in trimmed.split_whitespace() {
                    if !looks_like_display_name(token) {
                        return Err(RemovalSafetyError::parse(Some(line_number)));
                    }
                    let base = token.split(':').next().unwrap_or(token);
                    if base.is_empty() || !super::valid_package_name(base) {
                        return Err(RemovalSafetyError::parse(Some(line_number)));
                    }
                    display_names.insert(base.to_string());
                }
                continue;
            }
            removed_list = false;
        }

        if trimmed == "NOTE: This is only a simulation!"
            || trimmed.starts_with("apt-get needs root privileges for real execution.")
            || trimmed == "Keep also in mind that locking is deactivated,"
            || trimmed == "so don't depend on the relevance to the real current situation!"
            || trimmed == "Reading package lists..."
            || trimmed == "Building dependency tree..."
            || trimmed == "Reading state information..."
        {
            continue;
        }

        if trimmed
            == "The following packages were automatically installed and are no longer required:"
        {
            auto_block = true;
            continue;
        }
        if trimmed == "The following packages will be REMOVED:" {
            removed_list = true;
            display_seen = true;
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("Remv ") {
            let identity = parse_remv(rest, line_number)?;
            remv.push((identity, RemovalReason::Unknown));
            continue;
        }

        if let Some((count, _not_upgraded)) = parse_apt_summary(trimmed) {
            if summary.replace(count).is_some() {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            continue;
        }

        if trimmed.starts_with("Package '") && trimmed.ends_with("is not installed, so not removed")
        {
            let name = trimmed
                .strip_prefix("Package '")
                .and_then(|rest| rest.split_once('\''))
                .map(|(name, _)| name)
                .unwrap_or("");
            let base = name.split(':').next().unwrap_or(name);
            if base.is_empty() || base != requested {
                return Err(RemovalSafetyError::requested_missing());
            }
            PackageIdentity::new(base, None, None)
                .map_err(|_| RemovalSafetyError::parse(Some(line_number)))?;
            if noop_name.replace(base.to_string()).is_some() {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            continue;
        }

        if trimmed.starts_with("Inst ") || trimmed.starts_with("Conf ") {
            return Err(RemovalSafetyError::parse(Some(line_number)));
        }

        return Err(RemovalSafetyError::parse(Some(line_number)));
    }

    let summary_count = summary.ok_or_else(|| RemovalSafetyError::parse(None))?;
    if noop_name.is_some() && !remv.is_empty() {
        // The two answers contradict each other: a no-op response cannot
        // accompany `Remv` records.
        return Err(RemovalSafetyError::parse(None));
    }
    if remv.is_empty() {
        if summary_count == 0 && noop_name.is_some() {
            return Ok(RemovalPreview::new(
                RemovalBackend::Apt,
                requested.to_string(),
                Vec::new(),
                0,
                PreviewExit::NoOp,
                PreviewCommandIdentity::AptSimulatedRemove,
                input.backend_version,
            ));
        }
        return Err(RemovalSafetyError::summary(0, summary_count));
    }
    if summary_count != remv.len() {
        return Err(RemovalSafetyError::summary(summary_count, remv.len()));
    }

    // The display list is not the authority, but it must not contradict the
    // `Remv` records. A missing or contradictory list is not a preview whose
    // removal set can be established.
    let remv_names: BTreeSet<String> = remv
        .iter()
        .map(|(identity, _)| identity.name().to_string())
        .collect();
    if !display_seen || display_names != remv_names {
        return Err(RemovalSafetyError::parse(None));
    }

    let mut seen = BTreeSet::new();
    let mut planned = Vec::with_capacity(remv.len());
    for (identity, _) in remv {
        if !seen.insert((
            identity.name().to_string(),
            identity.architecture().map(ToOwned::to_owned),
            identity.version().map(ToOwned::to_owned),
        )) {
            return Err(RemovalSafetyError::identity());
        }
        let reason = if identity.is_requested_name(requested) {
            RemovalReason::Requested
        } else {
            // APT prints no dependent/unused label on `Remv`. Do not invent
            // one; the exact-set decision rejects it unless explicitly
            // allow-listed.
            RemovalReason::Unknown
        };
        planned.push(PlannedRemoval::new(identity, reason));
    }

    if !planned
        .iter()
        .any(|p| p.identity().is_requested_name(requested))
    {
        return Err(RemovalSafetyError::requested_missing());
    }

    Ok(RemovalPreview::new(
        RemovalBackend::Apt,
        requested.to_string(),
        planned,
        summary_count,
        PreviewExit::Completed,
        PreviewCommandIdentity::AptSimulatedRemove,
        input.backend_version,
    ))
}

/// Parse `Remv <name>[:<arch>] [<version>]`.
fn parse_remv(rest: &str, line_number: usize) -> Result<PackageIdentity, RemovalSafetyError> {
    let (name_part, version) = match rest.rsplit_once(" [") {
        Some((name, version)) => {
            let version = version
                .strip_suffix(']')
                .ok_or_else(|| RemovalSafetyError::parse(Some(line_number)))?;
            (name, Some(version))
        }
        None => (rest, None),
    };
    let (name, arch) = match name_part.split_once(':') {
        Some((name, arch)) => {
            if name.is_empty() || arch.is_empty() || arch.contains(':') {
                return Err(RemovalSafetyError::parse(Some(line_number)));
            }
            (name, Some(arch))
        }
        None => (name_part, None),
    };
    PackageIdentity::new(name, arch, version)
        .map_err(|_| RemovalSafetyError::parse(Some(line_number)))
}

/// Parse the exact APT simulation summary line:
/// `0 upgraded, 0 newly installed, <N> to remove and <M> not upgraded.`
fn parse_apt_summary(line: &str) -> Option<(usize, usize)> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() != 12 {
        return None;
    }
    if f[0] != "0"
        || f[1] != "upgraded,"
        || f[2] != "0"
        || f[3] != "newly"
        || f[4] != "installed,"
        || f[6] != "to"
        || f[7] != "remove"
        || f[8] != "and"
        || f[10] != "not"
        || f[11] != "upgraded."
    {
        return None;
    }
    let remove = parse_count(f[5])?;
    let not_upgraded = parse_count(f[9])?;
    Some((remove, not_upgraded))
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

/// A display-list token. It is intentionally looser than a package identity
/// (APT may wrap names across lines) but still excludes control characters and
/// option-like tokens; the authoritative set is `Remv`.
fn looks_like_display_name(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= super::MAX_PACKAGE_NAME
        && !token.starts_with('-')
        && token.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-' | b'~' | b':')
        })
}
