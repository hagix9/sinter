//! DNF progress grammar (WP-PKG-PROGRESS Phase 3).
//!
//! DNF has no `APT::Status-Fd` equivalent: DNF4 disables its live download
//! meter when stdout is not a terminal (`dnf/cli/progress.py`,
//! `MultiFileProgressMeter._update`: `if not self.isatty: return`), and DNF5
//! prints only *completed* progress bars when it is not interactive
//! (`libdnf5-cli/progressbar/multi_progress_bar.cpp`). Sinter runs package
//! mutations over a pipe or an SSH channel, so **no live percentage exists to
//! read**. This parser therefore never sets a percent and never invents one:
//! it reports the phases and counts DNF actually printed.
//!
//! It understands the two grammars without assuming which one it is talking
//! to. They are syntactically disjoint:
//!
//! DNF4 (`dnf/cli/output.py`, `dnf/cli/progress.py`, `dnf/base.py`) writes
//! its transaction display to **stdout** and its download meter to
//! **stderr**. In a non-TTY only the last line of each action is printed:
//!
//! ```text
//! Running transaction check
//! Running transaction
//!   Installing       : python36-3.6.8-39.module+el8.10.0+1910+234ad790.x86_64  1/1
//!   Verifying        : python36-3.6.8-39.module+el8.10.0+1910+234ad790.x86_64  1/1
//! Downloading Packages:
//! (1/2): python3-pip-9.0.3-24.el8.rocky.0.noarch.rpm  1.0 MB/s | 6.5 kB  00:00
//! Total                                               648 kB/s | 6.5 kB  00:00
//! ```
//!
//! DNF5 writes its stage lines and progress bars to **stderr**
//! (`dnf5/context.cpp`, `libdnf5-cli/progressbar/*`):
//!
//! ```text
//! Updating and loading repositories:
//! Repositories loaded.
//! Running transaction
//! [ 1/ 2] Prepare transaction  100% | 3.2 MiB/s | 12.0 MiB | 00:00
//! [ 2/ 2] Installing python3.11-0:3.11.7-1.el9.x86_64  100% | 3.2 MiB/s | 30.0 MiB | 00:24
//! ```
//!
//! The `100%` in a DNF5 bar is one completed *item's* percent, not the
//! transaction's, so it is not reported as a percentage either.
//!
//! The figures DNF prints are human-formatted and rounded
//! (`dnf/cli/format.py::format_number` is 1024-based and keeps three
//! significant digits; `libdnf5-cli/utils/units.cpp::format_size` keeps one
//! decimal). Converting `6.5 kB` back to a byte count would invent precision
//! DNF never printed, so a byte count or rate is reported only when the
//! printed unit is exactly bytes (`512 B`, `648 B/s`); everything else leaves
//! those fields absent.
//!
//! Completion and failure are not phases: `Complete!` and DNF's `Error:`
//! lines are ignored here, because whether a mutation succeeded is decided by
//! the exit code and the resource's re-observation, never by a progress line.
//!
//! Two lines that look like phases are deliberately *not* reported:
//! `Running transaction` (DNF4/DNF5) and `Prepare transaction` (DNF5). Both are
//! printed for a removal as well as for an install — `dnf/base.py` logs
//! `Running transaction` unconditionally before running the transaction — so
//! reporting "installing" for them would misclassify a remove. The first
//! direction-specific action line (`Installing …` or `Erasing …`) establishes
//! the phase instead. This is a deliberate correction of the Phase 0 mapping,
//! which proposed `Running transaction` → installing before the direction
//! neutrality was established from source.

use super::{sanitize_package_name, PackageObservation, PackageParser};
use crate::progress::{PackagePhase, PackageScope, ProgressConfidence, ProgressSource};

/// Parses DNF4's transaction/download lines and DNF5's completed progress
/// bars into phase observations. Stateless: every bound below belongs to the
/// line splitter, the emitter and the sink.
#[derive(Debug, Default)]
pub struct DnfProgressParser;

impl DnfProgressParser {
    pub fn new() -> Self {
        DnfProgressParser
    }
}

impl PackageParser for DnfProgressParser {
    fn observe(&mut self, line: &str) -> Option<PackageObservation> {
        let line = line.trim_end();
        // The splitter already drops a line over MAX_LINE whole; keeping the
        // same bound here means a parser test or a future caller cannot feed
        // an unbounded string into the scanners.
        if line.is_empty() || line.len() > super::MAX_LINE {
            return None;
        }
        // DNF5 bars are the only records that start with `[`.
        if line.starts_with('[') {
            return dnf5_bar(line);
        }
        marker(line)
            .or_else(|| action_line(line))
            .or_else(|| download_line(line))
    }
}

/// A standalone phase marker either CLI prints verbatim under
/// `LC_ALL=C.UTF-8` (Sinter pins that locale for every target command).
fn marker(line: &str) -> Option<PackageObservation> {
    let (phase, source) = match line {
        "Running transaction check" | "Running transaction test" => {
            (PackagePhase::Resolving, ProgressSource::DnfOutputMarker)
        }
        "Updating and loading repositories:" | "Repositories loaded." => {
            (PackagePhase::Resolving, ProgressSource::DnfOutputMarker)
        }
        "Downloading Packages:" => (PackagePhase::Downloading, ProgressSource::DnfOutputMarker),
        _ => return None,
    };
    Some(observation(phase, PackageScope::Transaction, source))
}

/// DNF4's non-TTY transaction display:
/// `  <Action> : <NEVRA>  <done>/<total>` (`dnf/cli/output.py`,
/// `CliTransactionDisplay._out_progress`).
///
/// The line is indented by two spaces and the action is padded to the widest
/// action name, so the separator is found by the first `": "`. The displayed
/// count is the transaction-set index/total DNF prints for the action.
fn action_line(line: &str) -> Option<PackageObservation> {
    let rest = line.strip_prefix("  ")?;
    let (label, tail) = rest.split_once(": ")?;
    let phase = action_phase(label.trim_end())?;
    let last = tail.split_whitespace().last()?;
    let (done, total) = counts(last)?;
    // An action without a package name (transaction preparation) leaves the
    // name absent rather than reporting a non-package token.
    let package = tail
        .split_whitespace()
        .next()
        .and_then(sanitize_package_name);
    let mut obs = observation(
        phase,
        if package.is_some() {
            PackageScope::Package
        } else {
            PackageScope::Transaction
        },
        ProgressSource::DnfTransactionLine,
    );
    obs.package = package;
    obs.packages_done = Some(done);
    obs.packages_total = Some(total);
    Some(obs)
}

/// The phase a DNF4 action label describes (`dnf/transaction.py::ACTIONS`).
/// DNF5's bar descriptions use the same verbs plus `Prepare transaction`,
/// `Verify package files` and `Running scriptlets`.
///
/// `Preparing` / `Prepare transaction` is absent on purpose: DNF runs it for
/// any transaction, so it says nothing about direction.
///
/// The event vocabulary has one install phase, so `Upgrading`,
/// `Downgrading`, `Reinstalling` and `Obsoleting` are reported as
/// [`PackagePhase::Installing`]: the event never claims more than "an install
/// transaction is processing this package". `Cleanup` (the old package of an
/// upgrade) and `Erasing` are removals.
fn action_phase(label: &str) -> Option<PackagePhase> {
    match label {
        "Installing" | "Upgrading" | "Downgrading" | "Reinstalling" | "Obsoleting" => {
            Some(PackagePhase::Installing)
        }
        "Erasing" | "Cleanup" | "Removing" => Some(PackagePhase::Removing),
        "Verifying" | "Verify package files" => Some(PackagePhase::Verifying),
        "Running scriptlet" | "Running scriptlets" => Some(PackagePhase::Triggering),
        _ => None,
    }
}

/// DNF5's non-interactive completed bar:
/// `[<done>/<total>] <description> <percent>% | <rate>/s | <size> | <time>`
/// (`libdnf5-cli/progressbar/download_progress_bar.cpp`).
///
/// Only the description is classified. The percent is one completed item's,
/// never the transaction's, and the rate/size are rounded by
/// `format_size`.
fn dnf5_bar(line: &str) -> Option<PackageObservation> {
    let rest = line.strip_prefix('[')?;
    let (counts_text, tail) = rest.split_once(']')?;
    let (done, total) = counts(counts_text.trim())?;
    let tail = tail.strip_prefix(' ')?;
    // The bar is `description  <pct>% | <rate>/s | <size> | <time>`; a line
    // without the rate/size separators is some other bracket-prefixed output.
    let (before, _) = tail.split_once(" | ")?;
    let before = before.trim_end();
    let split = before.rfind(' ')?;
    let percent = before[split + 1..].strip_suffix('%')?;
    // `???` is DNF5's "unknown total"; anything else must be a percentage.
    if percent != "???" && percent.parse::<u8>().ok().filter(|p| *p <= 100).is_none() {
        return None;
    }
    let description = before[..split].trim_end();
    if description.is_empty() {
        return None;
    }

    // A download bar names the package file; anything else (metadata bars,
    // repository descriptions) is ignored.
    if package_file(description).is_some() {
        let mut obs = observation(
            PackagePhase::Downloading,
            PackageScope::Transaction,
            ProgressSource::DnfDownloadLine,
        );
        obs.files_done = Some(done);
        obs.files_total = Some(total);
        return Some(obs);
    }

    // A transaction bar is `<Action> <NEVRA>` or one of the two standalone
    // descriptions. `Prepare transaction` is direction-neutral (DN5 creates
    // the same bar for an install and for a remove), so it is not a phase.
    if description == "Verify package files" {
        return Some(observation(
            PackagePhase::Verifying,
            PackageScope::Transaction,
            ProgressSource::DnfTransactionLine,
        ));
    }
    if description == "Running scriptlets" {
        return Some(observation(
            PackagePhase::Triggering,
            PackageScope::Transaction,
            ProgressSource::DnfTransactionLine,
        ));
    }
    let (label, package) = description.split_once(' ')?;
    let phase = action_phase(label)?;
    let package = sanitize_package_name(package.trim())?;
    let mut obs = observation(
        phase,
        PackageScope::Package,
        ProgressSource::DnfTransactionLine,
    );
    obs.package = Some(package);
    Some(obs)
}

/// DNF4's download meter completion lines (`dnf/cli/progress.py::end`) on
/// stderr:
///
/// ```text
/// <file>.rpm                 1.0 MB/s | 6.5 kB     00:00
/// (3/7): <file>.rpm          648 kB/s | 6.5 kB     00:00
/// Total                      648 kB/s | 6.5 kB     00:00
/// ```
///
/// A repository or metadata completion line (`Sinter test repo  1.3 MB/s |
/// 1.3 kB  00:00`) is not a package and is ignored, as are the `[FAILED]` /
/// `[SKIPPED]` / `[MIRROR]` status forms.
fn download_line(line: &str) -> Option<PackageObservation> {
    if line.starts_with('[') {
        return None;
    }
    // Two fields: `<text> <rate>/s | <size> <time>`. The meter prints no
    // separator between the size and the elapsed time.
    let mut fields = line.split(" | ");
    let left = fields.next()?;
    let right = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    let right: Vec<&str> = right.split_whitespace().collect();
    if right.len() < 2 || !is_time(right[right.len() - 1]) {
        return None;
    }
    let size = size_tokens(&right[..right.len() - 1])?;

    let words: Vec<&str> = left.split_whitespace().collect();
    if words.len() < 2 {
        return None;
    }
    let rate_unit = words[words.len() - 1];
    let rate_number = words[words.len() - 2];
    if !rate_unit.ends_with("B/s") {
        return None;
    }
    let text = words[..words.len() - 2].join(" ");
    let rate = exact(rate_number, rate_unit);

    let (file_counts, description) = match text.split_once("): ") {
        Some((prefix, rest)) if prefix.starts_with('(') => {
            let counts = counts(&prefix[1..])?;
            (Some(counts), rest)
        }
        _ => (None, text.as_str()),
    };
    let total_line = description == "Total";
    if !total_line && package_file(description).is_none() {
        return None;
    }

    let mut obs = observation(
        PackagePhase::Downloading,
        PackageScope::Transaction,
        ProgressSource::DnfDownloadLine,
    );
    // The file name is not the package name; the renderer does not show one
    // during a download and the contract keeps `package` for the package
    // currently being processed.
    if let Some((done, total)) = file_counts {
        obs.files_done = Some(done);
        obs.files_total = Some(total);
    }
    if let Some(bytes) = exact(size.0, size.1) {
        // Only an exact byte count is reported: `6.5 kB` is a rounded display,
        // not a measurement of 6656 bytes.
        obs.bytes_downloaded = Some(bytes);
        obs.bytes_total = Some(bytes);
    }
    obs.rate_bps = rate;
    Some(obs)
}

/// `(number, unit)` of the size field, e.g. `("6.5", "kB")` or `("648",
/// "B")`. Both DNF4's `6.5 kB` and DNF5's `6.5 KiB` shapes are accepted; the
/// unit is preserved because only `B` is exact.
fn size_tokens<'a>(words: &[&'a str]) -> Option<(&'a str, &'a str)> {
    match words {
        [number, unit] => Some((*number, *unit)),
        _ => None,
    }
}

/// An exact byte count: only the `B` unit is printed without rounding.
fn exact(number: &str, unit: &str) -> Option<u64> {
    if unit != "B" && unit != "B/s" {
        return None;
    }
    let value: f64 = number.parse().ok()?;
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > u64::MAX as f64 {
        return None;
    }
    Some(value as u64)
}

/// `<done>/<total>`, with DNF5's padded `[ 1/ 2]` accepted. A total of zero
/// or a done beyond the total is not a count this parser trusts.
fn counts(text: &str) -> Option<(u32, u32)> {
    let (done, total) = text.split_once('/')?;
    let done: u32 = done.trim().parse().ok()?;
    let total: u32 = total.trim().parse().ok()?;
    if total == 0 || done > total {
        return None;
    }
    Some((done, total))
}

/// `00:00`, `1:02:03` or DNF's `--:--` placeholder. Guards the download-line
/// grammar against unrelated ` | `-separated log text.
fn is_time(text: &str) -> bool {
    if text == "--:--" || text == "--:--:--" {
        return true;
    }
    let parts: Vec<&str> = text.split(':').collect();
    // `MM:SS` (DNF4 keeps minutes unbounded: `123:45`) or `H:MM:SS`.
    if !(2..=3).contains(&parts.len()) {
        return false;
    }
    parts
        .iter()
        .all(|part| !part.is_empty() && part.len() <= 4 && part.bytes().all(|b| b.is_ascii_digit()))
}

/// A package payload file name (`*.rpm`, `*.drpm`) as printed by the meter.
fn package_file(text: &str) -> Option<&str> {
    let name = text.split_whitespace().last()?;
    if name.ends_with(".rpm") || name.ends_with(".drpm") {
        Some(name)
    } else {
        None
    }
}

fn observation(
    phase: PackagePhase,
    scope: PackageScope,
    source: ProgressSource,
) -> PackageObservation {
    PackageObservation::new(phase, scope, source, ProgressConfidence::Measured)
}

#[cfg(test)]
mod tests;
