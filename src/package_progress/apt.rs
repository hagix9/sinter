//! APT progress grammar (WP-PKG-PROGRESS Phase 2).
//!
//! APT can write machine-readable records to a file descriptor
//! (`-o APT::Status-Fd=1`, documented in APT's `doc/progress-reporting.md` and
//! implemented in `apt-pkg/install-progress.cc` / `apt-pkg/acquire.cc`). Sinter
//! adds that option only for the package mutation and only while a progress
//! consumer is attached, so a run without progress keeps the exact argv and
//! the exact stdout it had before.
//!
//! Two record families are understood:
//!
//! ```text
//! dlstatus:<file-index>:<percent>:<localized description>
//! pmstatus:<package>:<percent>:<localized action>
//! pmstatus:dpkg-exec:<percent>:Running dpkg
//! pmerror:<package>:<percent>:<error text>
//! pmconffile:<package>:<percent>:<conffile prompt text>
//! ```
//!
//! * `dlstatus` percent is APT's aggregate download progress, weighted
//!   `0.8 * bytes + 0.2 * items`. It is reported as
//!   [`PercentScope::DownloadAggregate`](crate::progress::PercentScope) and is
//!   never presented as an install percentage.
//! * `pmstatus` percent is transaction-wide dpkg operation progress
//!   (`PackagesDone / PackagesTotal`), not a per-package percentage. It is
//!   reported as [`PercentScope::TransactionOperation`](crate::progress::PercentScope);
//!   the package field names the package currently being processed.
//! * `pmerror` / `pmconffile` carry free-form text and are ignored: their text
//!   never reaches an event.
//!
//! When no status records appear (an APT that ignores the option, or a parser
//! attached to something else), the human-readable stage markers are parsed
//! instead: `Need to get`, `Fetched`, `Unpacking`, `Setting up` and
//! `Processing triggers`. They carry no percentage, so nothing is invented.
//!
//! Everything here is bounded per line (the line splitter already caps a line
//! at 4 KiB and drops invalid UTF-8) and allocation is proportional to the
//! line. A malformed record yields `None`; it never aborts the execution.

use super::{sanitize_package_name, PackageObservation, PackageParser};
use crate::progress::{
    PackagePhase, PackageScope, PercentScope, ProgressConfidence, ProgressSource,
};

/// Parses APT's `status-fd` records and, as a fallback, its stage markers.
///
/// The two sources overlap: with `APT::Status-Fd=1` APT still prints
/// `Unpacking`, `Setting up`, `Fetched` and the trigger lines. Those human
/// markers carry no percentage, so letting them through after a machine record
/// would replace a measured `install 40%` with a percent-less event. Both
/// sides are therefore de-duplicated by phase, not by text:
///
/// * once a `dlstatus` record was parsed, the stale `Need to get` line is
///   ignored (its byte total is not shown during a percentage-bearing
///   download);
/// * once a `pmstatus` record was parsed, the install/config/trigger markers
///   are ignored, and so are the download markers — a human download line
///   flushed late must not move the display back from installing to
///   downloading;
/// * an invalid machine record changes nothing: it is not evidence that the
///   machine stream is available.
#[derive(Debug, Default)]
pub struct AptProgressParser {
    /// A valid `dlstatus` record has been parsed.
    seen_download_status: bool,
    /// A valid `pmstatus` record has been parsed.
    seen_package_status: bool,
}

impl AptProgressParser {
    pub fn new() -> Self {
        AptProgressParser::default()
    }
}

impl PackageParser for AptProgressParser {
    fn observe(&mut self, line: &str) -> Option<PackageObservation> {
        if let Some(rest) = line.strip_prefix("dlstatus:") {
            let observation = download_status(rest)?;
            self.seen_download_status = true;
            return Some(observation);
        }
        if let Some(rest) = line.strip_prefix("pmstatus:") {
            // `dpkg-exec` is parsed for validation but not reported: see
            // `package_status`.
            if rest.split(':').next() == Some("dpkg-exec") {
                if package_status(rest).is_some() {
                    self.seen_package_status = true;
                }
                return None;
            }
            let observation = package_status(rest)?;
            self.seen_package_status = true;
            return Some(observation);
        }
        // Free-form records: never displayed, never parsed further.
        if line.starts_with("pmerror:") || line.starts_with("pmconffile:") {
            return None;
        }
        marker(self, line)
    }
}

/// `dlstatus:<index>:<percent>:<description>`.
fn download_status(rest: &str) -> Option<PackageObservation> {
    let mut parts = rest.splitn(3, ':');
    let index = parts.next()?.trim().parse::<u32>().ok();
    let percent = parse_percent(parts.next()?)?;
    let description = parts.next().unwrap_or_default();
    let (files_done, files_total) = file_counts(description);
    let mut obs = PackageObservation::new(
        PackagePhase::Downloading,
        PackageScope::Transaction,
        ProgressSource::AptStatusFdDl,
        ProgressConfidence::Measured,
    );
    obs.percent = Some(percent);
    obs.percent_scope = Some(PercentScope::DownloadAggregate);
    obs.files_done = files_done.or(index);
    obs.files_total = files_total;
    Some(obs)
}

/// `pmstatus:<who>:<percent>:<action>`.
fn package_status(rest: &str) -> Option<PackageObservation> {
    let mut parts = rest.splitn(3, ':');
    let who = parts.next()?.trim();
    let percent = parse_percent(parts.next()?)?;
    let action = parts.next().unwrap_or_default();
    let phase = phase_of(action)?;
    let mut obs = PackageObservation::new(
        phase,
        PackageScope::Transaction,
        ProgressSource::AptStatusFdPm,
        ProgressConfidence::Measured,
    );
    obs.percent = Some(percent);
    obs.percent_scope = Some(PercentScope::TransactionOperation);
    // `dpkg-exec` is an overall "running dpkg" marker with no package and no
    // direction: the same record appears in an install and in a remove. The
    // direction cannot be known when it arrives, and the percent it carries is
    // repeated by the next real package record (verified on 24.04 and 26.04),
    // so it is not reported rather than guessing "installing".
    if who == "dpkg-exec" {
        return None;
    }
    // An invalid name is dropped without dropping the phase.
    obs.package = sanitize_package_name(who);
    Some(obs)
}

/// The phase an APT `pmstatus` action describes. Unknown actions are ignored.
///
/// The strings are the ones `dpkgpm.cc` passes to `StatusChanged`: its state
/// tables use `N_("Unpacking %s")`, `N_("Installing %s")`,
/// `N_("Preparing to configure %s")`, `N_("Configuring %s")`,
/// `N_("Installed %s")`, `N_("Preparing for removal of %s")`,
/// `N_("Preparing to completely remove %s")`, `N_("Removing %s")`,
/// `N_("Completely removing %s")`, `N_("Completely removed %s")` and
/// `N_("Running post-installation trigger %s")`. Longest prefix first:
/// "Preparing to configure" and "Preparing to completely remove" also start
/// with "Preparing", and "Installed" vs "Installing" must not be confused.
fn phase_of(action: &str) -> Option<PackagePhase> {
    let action = action.trim_start();
    if action.starts_with("Preparing to configure")
        || action.starts_with("Configuring")
        || action.starts_with("Installed")
    {
        Some(PackagePhase::Configuring)
    } else if action.starts_with("Preparing to completely remove")
        || action.starts_with("Preparing for removal of")
        || action.starts_with("Completely removing")
        || action.starts_with("Completely removed")
        || action.starts_with("Removing")
        || action.starts_with("Purging")
    {
        Some(PackagePhase::Removing)
    } else if action.starts_with("Running post-installation trigger") {
        Some(PackagePhase::Triggering)
    } else if action.starts_with("Unpacking")
        || action.starts_with("Installing")
        || action.starts_with("Preparing")
        || action.starts_with("Running dpkg")
    {
        Some(PackagePhase::Installing)
    } else {
        None
    }
}

/// Human-readable markers, used when no `status-fd` records appear — or only
/// for the information the machine records do not carry (the exact `Fetched`
/// totals).
fn marker(parser: &AptProgressParser, line: &str) -> Option<PackageObservation> {
    if let Some(rest) = line.strip_prefix("Need to get ") {
        if parser.seen_download_status || parser.seen_package_status {
            return None;
        }
        let body = rest.strip_suffix(" of archives.").unwrap_or(rest);
        let (needed, total) = need_sizes(body)?;
        // `Need to get 0 B/26.0 kB` means everything is already in the cache:
        // there is no download to report, and showing a download phase would
        // be a phase that never happens.
        if needed == 0 {
            return None;
        }
        let mut obs = PackageObservation::new(
            PackagePhase::Downloading,
            PackageScope::Transaction,
            ProgressSource::AptOutputMarker,
            ProgressConfidence::Measured,
        );
        obs.bytes_total = Some(total);
        return Some(obs);
    }
    if let Some(rest) = line.strip_prefix("Fetched ") {
        // A download line flushed after the install has begun is stale; the
        // measured install percentage must stay visible.
        if parser.seen_package_status {
            return None;
        }
        return fetched(rest);
    }
    if (line.starts_with("Unpacking ") || line.starts_with("Setting up "))
        && parser.seen_package_status
    {
        return None;
    }
    if let Some(rest) = line.strip_prefix("Unpacking ") {
        let mut obs = PackageObservation::new(
            PackagePhase::Installing,
            PackageScope::Package,
            ProgressSource::AptOutputMarker,
            ProgressConfidence::Measured,
        );
        obs.package = first_name(rest);
        return Some(obs);
    }
    if let Some(rest) = line.strip_prefix("Setting up ") {
        let mut obs = PackageObservation::new(
            PackagePhase::Configuring,
            PackageScope::Package,
            ProgressSource::AptOutputMarker,
            ProgressConfidence::Measured,
        );
        obs.package = first_name(rest);
        return Some(obs);
    }
    if line.starts_with("Processing triggers") {
        if parser.seen_package_status {
            return None;
        }
        return Some(PackageObservation::new(
            PackagePhase::Triggering,
            PackageScope::Transaction,
            ProgressSource::AptOutputMarker,
            ProgressConfidence::Measured,
        ));
    }
    // `Get:` lines are deliberately ignored: their grammar varies and
    // `dlstatus` already reports the file index and total.
    None
}

/// `Fetched <size> in <duration> (<rate>/s)`.
fn fetched(rest: &str) -> Option<PackageObservation> {
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let bytes = size_at(&tokens, 0)?;
    let in_at = tokens.iter().position(|t| *t == "in")?;
    let time_tokens: Vec<&str> = tokens
        .iter()
        .skip(in_at + 1)
        .take_while(|t| !t.starts_with('('))
        .copied()
        .collect();
    let seconds = duration(&time_tokens)?;
    let rate = tokens
        .iter()
        .position(|t| t.starts_with('('))
        .and_then(|at| {
            let cleaned: Vec<String> = tokens[at..]
                .iter()
                .map(|t| t.trim_matches(|c| c == '(' || c == ')').to_string())
                .collect();
            let refs: Vec<&str> = cleaned.iter().map(String::as_str).collect();
            size_at(&refs, 0)
        });
    let mut obs = PackageObservation::new(
        PackagePhase::Downloading,
        PackageScope::Transaction,
        ProgressSource::AptOutputMarker,
        // The line prints the totals; a computed rate would be derived, the
        // printed one is measured.
        ProgressConfidence::Measured,
    );
    obs.bytes_downloaded = Some(bytes);
    obs.bytes_total = Some(bytes);
    obs.rate_bps =
        rate.or_else(|| (seconds > 0.0).then(|| (bytes as f64 / seconds).round() as u64));
    Some(obs)
}

/// The first `<number> <unit>` pair at or after `at`.
fn size_at(tokens: &[&str], at: usize) -> Option<u64> {
    let mut i = at;
    while i + 1 < tokens.len() {
        if let Some(value) = parse_size(tokens[i], tokens[i + 1]) {
            return Some(value);
        }
        i += 1;
    }
    None
}

/// The `(needed, total)` sizes of a `Need to get` payload. A partially
/// cached transaction prints `12.3 MB/80.1 MB`; a fully cached one
/// `0 B/80.1 MB`. With no slash, both are the same.
fn need_sizes(text: &str) -> Option<(u64, u64)> {
    let cleaned = text.replace('/', " ");
    let tokens: Vec<&str> = cleaned.split_whitespace().collect();
    let mut sizes = Vec::new();
    let mut i = 0;
    while i + 1 < tokens.len() {
        if let Some(value) = parse_size(tokens[i], tokens[i + 1]) {
            sizes.push(value);
            i += 2;
        } else {
            i += 1;
        }
    }
    match sizes.as_slice() {
        [] => None,
        [only] => Some((*only, *only)),
        [needed, .., total] => Some((*needed, *total)),
    }
}

/// Decimal (SI) units, the ones APT prints under `LC_ALL=C`.
fn parse_size(number: &str, unit: &str) -> Option<u64> {
    let value: f64 = number.parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    // A rate prints its unit as `MB/s`; the magnitude is the same.
    let multiplier = match unit.trim_end_matches("/s") {
        "B" => 1.0,
        "kB" => 1000.0,
        "MB" => 1000.0 * 1000.0,
        "GB" => 1000.0 * 1000.0 * 1000.0,
        _ => return None,
    };
    Some((value * multiplier).round() as u64)
}

/// `3s`, `1min 2s`, `1h 2min`. Returns seconds.
fn duration(tokens: &[&str]) -> Option<f64> {
    let mut seconds = 0.0;
    let mut seen = false;
    for token in tokens {
        let (value, unit) = token.split_at(token.find(|c: char| !c.is_ascii_digit())?);
        if value.is_empty() {
            return None;
        }
        let value: f64 = value.parse().ok()?;
        seconds += match unit {
            "s" | "sec" | "secs" => value,
            "min" | "mins" => value * 60.0,
            "h" => value * 3600.0,
            _ => return None,
        };
        seen = true;
    }
    seen.then_some(seconds)
}

/// The package token of a marker: the first word, which APT prints as
/// `name[:arch]`, optionally followed by `(version) ...`.
fn first_name(rest: &str) -> Option<String> {
    sanitize_package_name(rest.split_whitespace().next()?)
}

/// A status-fd percentage: a finite float in `0..=100`, floored so a
/// transaction never appears complete before it is.
fn parse_percent(text: &str) -> Option<u8> {
    let value: f64 = text.trim().parse().ok()?;
    if !value.is_finite() || value < 0.0 || value > 100.0 {
        return None;
    }
    Some(value.floor() as u8)
}

/// `Retrieving file 3 of 7` → `(Some(3), Some(7))`. Anything else is ignored:
/// the description is localized and never trusted beyond this shape.
fn file_counts(description: &str) -> (Option<u32>, Option<u32>) {
    let Some(rest) = description
        .find("file ")
        .map(|at| &description[at + "file ".len()..])
    else {
        return (None, None);
    };
    let mut words = rest.split_whitespace();
    let Some(index) = words.next().and_then(|w| w.parse::<u32>().ok()) else {
        return (None, None);
    };
    if words.next() != Some("of") {
        return (None, None);
    }
    let Some(total) = words.next().and_then(|w| w.parse::<u32>().ok()) else {
        return (None, None);
    };
    (Some(index), Some(total))
}

#[cfg(test)]
mod tests;
