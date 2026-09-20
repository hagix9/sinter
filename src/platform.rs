use crate::error::{Result, SinterError};
use crate::executor::{Completion, Output};
use crate::resources::PackageState;

/// The package-management backend selected for a detected target platform.
///
/// Backend selection is driven by the target's `/etc/os-release` identity
/// (via `facts.os.family`), never by probing for a package manager binary or
/// by guessing. An unknown/unsupported family yields `None` and callers must
/// fail explicitly rather than falling back to either backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageBackend {
    /// Debian/Ubuntu family: dpkg-query + apt-get.
    Apt,
    /// RHEL family (Rocky, AlmaLinux, RHEL, CentOS, Fedora, ...): rpm + dnf.
    Dnf,
}

impl PackageBackend {
    /// Select the backend for a detected OS family string.
    /// `None` means the platform has no supported package manager.
    pub fn for_os_family(family: &str) -> Option<Self> {
        match family {
            "debian" => Some(Self::Apt),
            "redhat" => Some(Self::Dnf),
            _ => None,
        }
    }

    /// Human-facing backend name used in diagnostics ("apt"/"dnf").
    pub fn label(&self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Dnf => "dnf",
        }
    }

    /// The package-database query binary required for observation.
    pub fn query_program(&self) -> &'static str {
        match self {
            Self::Apt => "/usr/bin/dpkg-query",
            Self::Dnf => "/usr/bin/rpm",
        }
    }

    /// The package-manager binary required for mutation.
    pub fn manager_program(&self) -> &'static str {
        match self {
            Self::Apt => "/usr/bin/apt-get",
            Self::Dnf => "/usr/bin/dnf",
        }
    }

    /// Exact argv (excluding the program) for an install/remove mutation.
    ///
    /// DESIGN §27: no version pinning, and automatic repository metadata
    /// refresh is never performed. dnf has no flag combination for "cached
    /// metadata only, but package payloads may still download" (the
    /// apt-get contract):
    ///
    /// - `-C` (`--cacheonly`) alone is too strong: it also blocks package
    ///   payload downloads, breaking installs on hosts that do not retain
    ///   downloaded packages (the default `keepcache=0`).
    /// - `metadata_expire=-1` prevents refresh of *present* metadata, but
    ///   dnf still fetches when a repository's metadata is absent, and
    ///   librepo re-resolves mirror lists over the network whenever a
    ///   package payload must be downloaded — even when a cached mirror
    ///   list exists.
    ///
    /// So an install mutation runs strictly cache-only (`-C`) against a
    /// private snapshot of the metadata cache (`dnf_snapshot`): every
    /// enabled repository's repodata and resolved mirror list is verified
    /// usable offline in the snapshot, and every payload the transaction
    /// needs is prefetched into the snapshot's package directories
    /// beforehand (payload downloads are allowed; metadata downloads are
    /// not). `-C` then makes a metadata fetch impossible by construction.
    /// `*.skip_if_unavailable=0` turns any unusable repository into a hard
    /// error rather than a silent skip. Removal needs no repository at
    /// all: `--disablerepo=*` makes a fetch impossible by construction.
    ///
    /// `dnf_snapshot` is the verified private cachedir path; it is
    /// mandatory for dnf installs.
    pub fn mutate_args(
        &self,
        want_installed: bool,
        name: &str,
        dnf_snapshot: Option<&str>,
    ) -> Vec<String> {
        match self {
            Self::Apt => {
                let action = if want_installed { "install" } else { "remove" };
                vec!["-y".to_string(), action.to_string(), name.to_string()]
            }
            Self::Dnf => {
                if want_installed {
                    let snap =
                        dnf_snapshot.expect("dnf install requires a verified metadata snapshot");
                    vec![
                        "-C".to_string(),
                        format!("--setopt=cachedir={}", snap),
                        "--setopt=*.skip_if_unavailable=0".to_string(),
                        "-y".to_string(),
                        "install".to_string(),
                        name.to_string(),
                    ]
                } else {
                    vec![
                        "--disablerepo=*".to_string(),
                        "-y".to_string(),
                        "remove".to_string(),
                        name.to_string(),
                    ]
                }
            }
        }
    }

    /// argv that loads every enabled repository's metadata strictly from a
    /// private snapshot cachedir. Exits non-zero when any enabled
    /// repository's repodata is missing or unusable offline — proving the
    /// snapshot is complete enough that the subsequent install mutation
    /// can never fetch repository metadata (DESIGN §27).
    pub fn dnf_snapshot_check_args(snap: &str, name: &str) -> Vec<String> {
        vec![
            "-C".to_string(),
            format!("--setopt=cachedir={}", snap),
            "--setopt=*.skip_if_unavailable=0".to_string(),
            "repoquery".to_string(),
            "--queryformat".to_string(),
            "%{name}".to_string(),
            name.to_string(),
        ]
    }

    /// argv for the cache-only dry-run install whose transaction table is
    /// the exact payload set the real mutation needs. `--assumeno` aborts
    /// after resolution (exit 1, "Operation aborted") without touching the
    /// rpmdb or the network.
    pub fn dnf_dry_run_args(snap: &str, name: &str) -> Vec<String> {
        vec![
            "-C".to_string(),
            format!("--setopt=cachedir={}", snap),
            "--setopt=*.skip_if_unavailable=0".to_string(),
            "install".to_string(),
            "--assumeno".to_string(),
            name.to_string(),
        ]
    }

    /// argv that delegates payload transport to native dnf/librepo:
    /// download — but never install — the exact resolved package set into
    /// the snapshot's per-repository package caches. This is the one step
    /// allowed to touch the network (DESIGN §27): repository transport,
    /// mirror resolution and any per-repository client authentication are
    /// librepo's, not Sinter's. `*.metadata_expire=-1` keeps the prepared
    /// snapshot metadata authoritative — no refresh — and
    /// `*.skip_if_unavailable=0` keeps every enabled repository a hard
    /// requirement rather than a silent skip. `*.keepcache=1` retains the
    /// downloaded payloads for the later `dnf -C install`. `-C` cannot be
    /// used here because it would also block the payload transfer itself;
    /// metadata freshness is pinned by `metadata_expire` instead, and the
    /// earlier `-C` snapshot check has already proven every repository's
    /// metadata is present. The requested operands are exact
    /// `name-[epoch:]version-release.arch` identities from the frozen
    /// transaction, never bare names dnf could re-resolve.
    pub fn dnf_payload_download_args(snap: &str, nevras: &[String]) -> Vec<String> {
        let mut v = vec![
            format!("--setopt=cachedir={}", snap),
            "--setopt=*.metadata_expire=-1".to_string(),
            "--setopt=*.skip_if_unavailable=0".to_string(),
            "--setopt=*.keepcache=1".to_string(),
            "-y".to_string(),
            "install".to_string(),
            "--downloadonly".to_string(),
        ];
        v.extend(nevras.iter().cloned());
        v
    }

    /// argv reading the identity metadata of one RPM payload file: one
    /// `|`-separated `name|epoch|version|release|arch` record, verified
    /// against the frozen transaction row before the payload may satisfy
    /// it. A file name only locates a candidate; rpm's own parse of the
    /// header is what proves the payload's identity.
    pub fn rpm_package_file_args(path: &str) -> Vec<String> {
        vec![
            "-qp".to_string(),
            "--queryformat".to_string(),
            "%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}\\n".to_string(),
            path.to_string(),
        ]
    }

    /// argv listing enabled repositories verbosely (id plus mirror
    /// resolution configuration).
    pub fn dnf_repolist_args() -> Vec<String> {
        vec!["-C".to_string(), "repolist".to_string(), "-v".to_string()]
    }

    /// Classify a completed package-database query into a clean state.
    ///
    /// Both backends distinguish a positively-confirmed "not installed" from
    /// an ambiguous/errored query: anything that cannot be interpreted is an
    /// observation error, never silently "absent" (DESIGN §27), and a Present
    /// answer likewise requires a complete, unambiguous record — exit 0 alone
    /// is not proof of installation (IA-01). `name_disp` is the presentation
    /// form of the package name (already redacted when the resource is
    /// sensitive); the raw name is only matched internally.
    pub fn classify_observation(
        &self,
        out: &Output,
        name: &str,
        name_disp: &str,
        sensitive: bool,
    ) -> Result<PackageState> {
        match self {
            Self::Apt => match &out.completion {
                Completion::Exited(0) => {
                    // Present contract: a complete, single-record, valid
                    // capture whose record is one dpkg status line.
                    require_package_record(out, name_disp)?;
                    let status = utf8_package_stream(out, name_disp, sensitive)?;
                    // dpkg-query -f=${Status} emits exactly one status record with
                    // no terminator, so the complete capture is the record. The
                    // bytes are never trimmed or otherwise normalized: leading or
                    // trailing whitespace the protocol does not emit, a blank
                    // record, or a second record is output the contract does not
                    // define and must not be rounded to a state (RA2-01).
                    if status.is_empty() {
                        return Err(SinterError::apply(format!(
                            "package observation for {} produced no status record",
                            name_disp
                        )));
                    }
                    if status.contains('\n') || status.contains('\r') {
                        return Err(SinterError::apply(format!(
                            "package observation for {} produced multiple result records",
                            name_disp
                        )));
                    }
                    crate::resources::classify_dpkg_status(status)
                }
                // Confirmed absent: dpkg-query found no matching package. Only
                // the narrow absence contract applies — an exit-1 capture that
                // carries stdout, extra diagnostics, truncation, or an
                // unrecognized message leaves the state undetermined.
                Completion::Exited(1) if dpkg_reports_absent(out, name) => Ok(PackageState::Absent),
                Completion::Exited(c) => {
                    Err(observation_error(*self, name_disp, *c, out, sensitive))
                }
                Completion::Signaled(s) => Err(SinterError::apply(format!(
                    "package observation for {} terminated by signal {}",
                    name_disp, s
                ))),
                Completion::Indeterminate { reason, .. } => {
                    Err(SinterError::indeterminate(format!(
                        "package observation for {} did not complete: {}",
                        name_disp, reason
                    )))
                }
            },
            Self::Dnf => match &out.completion {
                Completion::Exited(0) => {
                    // Present contract: exit 0 alone does not prove installation.
                    // The capture must be complete and contain exactly one
                    // identity record — the package NAME field, emitted by the
                    // fixed `--queryformat` — with no diagnostic alongside it.
                    require_package_record(out, name_disp)?;
                    let record = utf8_package_stream(out, name_disp, sensitive)?;
                    // The fixed queryformat emits no separator or terminator, so
                    // the complete capture is the single record. Any line
                    // terminator is a second matched package or an extra record,
                    // which the identity comparison below cannot accept.
                    if record.is_empty() {
                        return Err(SinterError::apply(format!(
                            "package observation for {} produced no package identity record",
                            name_disp
                        )));
                    }
                    if record.contains('\n') || record.contains('\r') {
                        return Err(SinterError::apply(format!(
                            "package observation for {} produced multiple result records",
                            name_disp
                        )));
                    }
                    // The record must prove the installed package *is* the
                    // requested package: whole-record equality on the NAME field.
                    // A prefix such as `<name>-garbage`, a record about another
                    // package, or a bare malformed fragment is rejected, so exit 0
                    // alone never establishes installation (RA2-01).
                    if record != name {
                        return Err(SinterError::apply(format!(
                            "package observation for {} named a different package",
                            name_disp
                        )));
                    }
                    Ok(PackageState::Installed)
                }
                // rpm -q exits 1 for "not installed" but also for other
                // failures (e.g. a broken rpmdb). Only a positive
                // "is not installed" marker counts as absent.
                Completion::Exited(1) if rpm_reports_absent(out, name) => Ok(PackageState::Absent),
                Completion::Exited(c) => {
                    Err(observation_error(*self, name_disp, *c, out, sensitive))
                }
                Completion::Signaled(s) => Err(SinterError::apply(format!(
                    "package observation for {} terminated by signal {}",
                    name_disp, s
                ))),
                Completion::Indeterminate { reason, .. } => {
                    Err(SinterError::indeterminate(format!(
                        "package observation for {} did not complete: {}",
                        name_disp, reason
                    )))
                }
            },
        }
    }
}

/// A package answer must come from a complete capture: a truncated stream
/// cannot prove the record is the whole answer (IA-01). A diagnostic on stderr
/// alongside an apparent success makes the result ambiguous.
fn require_package_record(out: &Output, name_disp: &str) -> Result<()> {
    if out.stdout_truncated || out.stderr_truncated {
        return Err(SinterError::apply(format!(
            "package observation for {} captured truncated output: the result is incomplete",
            name_disp
        )));
    }
    if !out.stderr.is_empty() {
        return Err(SinterError::apply(format!(
            "package observation for {} carried an unexpected diagnostic",
            name_disp
        )));
    }
    Ok(())
}

/// Strictly decode the package record stream as UTF-8. Both backends emit
/// textual records; lossy decoding could repair malformed bytes into a
/// syntactically valid record (IA-01 §10).
fn utf8_package_stream<'a>(out: &'a Output, name_disp: &str, sensitive: bool) -> Result<&'a str> {
    std::str::from_utf8(&out.stdout).map_err(|_| {
        SinterError::apply(format!(
            "package observation for {} captured invalid UTF-8 output{}",
            name_disp,
            if sensitive { " (value redacted)" } else { "" }
        ))
    })
}

/// Whether an `rpm -q` exit-1 result positively and unambiguously reports
/// the package as not installed.
///
/// Reference behavior (rpm 4.16, Rocky Linux 9.8, verified on-target):
/// `rpm -q <absent>` exits 1, writes exactly
/// `package <name> is not installed\n` to stdout, and writes nothing to
/// stderr. The marker is locale-stable (identical under LC_ALL=ja_JP.UTF-8).
///
/// Fail closed (DESIGN §27: observation failure is never absence): the
/// marker must be the complete, exact byte content of stdout with stderr
/// empty. A marker on the wrong stream, leading/trailing whitespace, an
/// extra blank line, mixed diagnostics (e.g. an rpmdb error), substring
/// matches inside unrelated output, truncation, or malformed bytes all
/// make the observation uninterpretable and are classified as errors by
/// the caller, never as `Absent`.
fn rpm_reports_absent(out: &Output, name: &str) -> bool {
    if out.stdout_truncated || out.stderr_truncated {
        return false;
    }
    // Byte-exact comparison also rejects non-UTF-8 output.
    let marker = format!("package {} is not installed\n", name);
    out.stdout == marker.as_bytes() && out.stderr.is_empty()
}

/// Whether a `dpkg-query -W -f=${Status} -- <name>` exit-1 result positively
/// and unambiguously reports the package as not installed.
///
/// Reference behavior (dpkg 1.21/1.22, Debian and Ubuntu, verified
/// on-target): the query exits 1, writes nothing to stdout, and writes
/// exactly `dpkg-query: no packages found matching <name>\n` to stderr.
///
/// Fail closed (IA-01/RA2-01): exit 1 is *also* what a broken query reports, so
/// the absence answer must be the complete, exact, single-line diagnostic with
/// empty stdout, no truncation, and valid bytes. Byte-exact comparison with
/// the defined marker also rejects non-UTF-8 output, a missing terminator, an
/// extra blank record, and leading/trailing whitespace. A marker mixed with
/// another diagnostic, a truncated stream, a marker on the wrong stream, or an
/// exit-1 with an unrecognized message is an observation error, never
/// `Absent`.
fn dpkg_reports_absent(out: &Output, name: &str) -> bool {
    if out.stdout_truncated || out.stderr_truncated {
        return false;
    }
    if !out.stdout.is_empty() {
        return false;
    }
    let canonical = format!("dpkg-query: no packages found matching {}\n", name);
    let bare = format!("no packages found matching {}\n", name);
    out.stderr == canonical.as_bytes() || out.stderr == bare.as_bytes()
}

fn observation_error(
    backend: PackageBackend,
    name_disp: &str,
    code: i32,
    out: &Output,
    sensitive: bool,
) -> SinterError {
    if sensitive {
        SinterError::apply(format!(
            "package observation failed for {}: {} query exited {}",
            name_disp,
            backend.label(),
            code
        ))
    } else {
        SinterError::apply(format!(
            "package observation failed for {}: {} query exited {} ({})",
            name_disp,
            backend.label(),
            code,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exited(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            completion: Completion::Exited(code),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    #[test]
    fn family_selects_backend() {
        assert_eq!(
            PackageBackend::for_os_family("debian"),
            Some(PackageBackend::Apt)
        );
        assert_eq!(
            PackageBackend::for_os_family("redhat"),
            Some(PackageBackend::Dnf)
        );
        assert_eq!(PackageBackend::for_os_family("arch"), None);
        assert_eq!(PackageBackend::for_os_family("alpine"), None);
        assert_eq!(PackageBackend::for_os_family(""), None);
    }

    #[test]
    fn dnf_mutation_args_are_exact() {
        // Install runs strictly cache-only against a verified private
        // metadata snapshot whose payloads were prefetched: the mutation
        // has no path to the network for repository metadata at all.
        assert_eq!(
            PackageBackend::Dnf.mutate_args(true, "httpd", Some("/var/tmp/snap")),
            vec![
                "-C",
                "--setopt=cachedir=/var/tmp/snap",
                "--setopt=*.skip_if_unavailable=0",
                "-y",
                "install",
                "httpd"
            ]
        );
        // Remove consults no repository at all, so a metadata fetch is
        // impossible by construction.
        assert_eq!(
            PackageBackend::Dnf.mutate_args(false, "httpd", None),
            vec!["--disablerepo=*", "-y", "remove", "httpd"]
        );
        // apt argv is unchanged from v0.1.
        assert_eq!(
            PackageBackend::Apt.mutate_args(true, "nano", None),
            vec!["-y", "install", "nano"]
        );
    }

    #[test]
    #[should_panic(expected = "verified metadata snapshot")]
    fn dnf_install_without_snapshot_is_rejected() {
        let _ = PackageBackend::Dnf.mutate_args(true, "httpd", None);
    }

    #[test]
    fn dnf_payload_download_args_are_exact() {
        // Native payload transport: exact NEVRA operands, the snapshot
        // cachedir, metadata expiry pinned (never refreshed), payloads
        // retained for the `-C` install — and never `-C` itself, which
        // would block the transfer.
        assert_eq!(
            PackageBackend::dnf_payload_download_args(
                "/var/tmp/snap",
                &[
                    "nano-1.0-1.el9.x86_64".to_string(),
                    "libnano-2:3.0-1.el9.x86_64".to_string()
                ]
            ),
            vec![
                "--setopt=cachedir=/var/tmp/snap".to_string(),
                "--setopt=*.metadata_expire=-1".to_string(),
                "--setopt=*.skip_if_unavailable=0".to_string(),
                "--setopt=*.keepcache=1".to_string(),
                "-y".to_string(),
                "install".to_string(),
                "--downloadonly".to_string(),
                "nano-1.0-1.el9.x86_64".to_string(),
                "libnano-2:3.0-1.el9.x86_64".to_string()
            ]
        );
        // The payload identity query is the fixed `|`-separated record.
        assert_eq!(
            PackageBackend::rpm_package_file_args(
                "/var/tmp/snap/baseos-x/packages/a-1-1.x86_64.rpm"
            ),
            vec![
                "-qp".to_string(),
                "--queryformat".to_string(),
                "%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}\\n".to_string(),
                "/var/tmp/snap/baseos-x/packages/a-1-1.x86_64.rpm".to_string()
            ]
        );
    }

    #[test]
    fn dnf_snapshot_check_args_are_exact() {
        // The snapshot-usability check runs entirely from the snapshot
        // cache (`-C`) so it can never retrieve metadata itself; forced
        // skip_if_unavailable=0 turns a missing repo into an error, never
        // a silent skip.
        assert_eq!(
            PackageBackend::dnf_snapshot_check_args("/var/tmp/snap", "httpd"),
            vec![
                "-C".to_string(),
                "--setopt=cachedir=/var/tmp/snap".to_string(),
                "--setopt=*.skip_if_unavailable=0".to_string(),
                "repoquery".to_string(),
                "--queryformat".to_string(),
                "%{name}".to_string(),
                "httpd".to_string()
            ]
        );
        assert_eq!(
            PackageBackend::dnf_repolist_args(),
            vec!["-C".to_string(), "repolist".to_string(), "-v".to_string()]
        );
    }

    #[test]
    fn rpm_classification() {
        // The fixed `--queryformat %{NAME}` contract: exit 0 with exactly the
        // package NAME on stdout proves the requested package is installed.
        let installed = exited(0, "nano", "");
        assert_eq!(
            PackageBackend::Dnf
                .classify_observation(&installed, "nano", "nano", false)
                .unwrap(),
            PackageState::Installed
        );
        // Reference rpm 4.16: absent marker on stdout, stderr empty.
        let absent = exited(1, "package nano is not installed\n", "");
        assert_eq!(
            PackageBackend::Dnf
                .classify_observation(&absent, "nano", "nano", false)
                .unwrap(),
            PackageState::Absent
        );
        // exit 1 without the positive marker is an error, not absence.
        let ambiguous = exited(1, "", "error: rpmdb open failed");
        assert!(PackageBackend::Dnf
            .classify_observation(&ambiguous, "nano", "nano", false)
            .is_err());
        // A NEVRA-shaped record is not the defined identity record: the old
        // prefix-based acceptance (`<name>-<anything>`) is gone (RA2-01).
        let nevra = exited(0, "nano-7.2-2.el9.x86_64\n", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&nevra, "nano", "nano", false)
            .is_err());
        // other non-zero exits are errors.
        let err = exited(2, "", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&err, "nano", "nano", false)
            .is_err());
        // signaled -> definite failure, indeterminate -> indeterminate.
        let sig = Output {
            completion: Completion::Signaled(9),
            stdout: vec![],
            stderr: vec![],
            stdout_truncated: false,
            stderr_truncated: false,
        };
        let e = PackageBackend::Dnf
            .classify_observation(&sig, "nano", "nano", false)
            .unwrap_err();
        assert_eq!(e.kind, crate::error::ErrorKind::Apply);
        let ind = Output {
            completion: Completion::Indeterminate {
                started: true,
                reason: "timeout".into(),
            },
            stdout: vec![],
            stderr: vec![],
            stdout_truncated: false,
            stderr_truncated: false,
        };
        let e = PackageBackend::Dnf
            .classify_observation(&ind, "nano", "nano", false)
            .unwrap_err();
        assert_eq!(e.kind, crate::error::ErrorKind::Indeterminate);
    }

    #[test]
    fn rpm_absent_marker_is_exact_stdout_only() {
        // Reference: exit 1 + stdout exactly "package <name> is not
        // installed\n" + stderr empty. Anything looser is an error.
        let out = exited(1, "package nano is not installed\n", "");
        assert!(rpm_reports_absent(&out, "nano"));
        // Marker on the wrong stream is not a valid absent answer.
        let out = exited(1, "", "package nano is not installed\n");
        assert!(!rpm_reports_absent(&out, "nano"));
        // Whitespace anywhere invalidates the exact contract.
        let out = exited(1, " package nano is not installed\n", "");
        assert!(!rpm_reports_absent(&out, "nano"));
        let out = exited(1, "package nano is not installed\n ", "");
        assert!(!rpm_reports_absent(&out, "nano"));
        let out = exited(1, "package nano is not installed\n\n", "");
        assert!(!rpm_reports_absent(&out, "nano"));
        let out = exited(1, "package nano is not installed\n", " ");
        assert!(!rpm_reports_absent(&out, "nano"));
        let out = exited(1, "package nano is not installed", "");
        assert!(!rpm_reports_absent(&out, "nano"));
        // A different package's marker does not prove this one absent.
        let out = exited(1, "package other is not installed\n", "");
        assert!(!rpm_reports_absent(&out, "nano"));
    }

    #[test]
    fn rpm_absent_classification_fails_closed_on_any_ambiguity() {
        // Marker plus an rpmdb/database error is an observation failure,
        // never absence (audit P1-02).
        let mixed = exited(
            1,
            "package nano is not installed\n",
            "error: cannot open Packages database in /var/lib/rpm\n",
        );
        assert!(PackageBackend::Dnf
            .classify_observation(&mixed, "nano", "nano", false)
            .is_err());
        let mixed_rev = exited(
            1,
            "error: cannot open Packages database in /var/lib/rpm\n",
            "package nano is not installed\n",
        );
        assert!(PackageBackend::Dnf
            .classify_observation(&mixed_rev, "nano", "nano", false)
            .is_err());
        // Marker only as a substring of unrelated output is not absence.
        let substr = exited(1, "", "warning: package nano is not installed anyway\n");
        assert!(PackageBackend::Dnf
            .classify_observation(&substr, "nano", "nano", false)
            .is_err());
        // Additional diagnostics on the same stream invalidate the result.
        let extra_line = exited(1, "package nano is not installed\nextra noise\n", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&extra_line, "nano", "nano", false)
            .is_err());
        // An extra blank line after the marker is unexpected output.
        let blank = exited(1, "package nano is not installed\n\n", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&blank, "nano", "nano", false)
            .is_err());
        // Whitespace-only opposite stream is unexpected stream usage.
        let ws_err = exited(1, "package nano is not installed\n", "  \n");
        assert!(PackageBackend::Dnf
            .classify_observation(&ws_err, "nano", "nano", false)
            .is_err());
        // Marker embedded in unrelated stdout text is a substring match.
        let substr_out = exited(1, "warning: package nano is not installed anyway\n", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&substr_out, "nano", "nano", false)
            .is_err());
        // Truncated output cannot prove the marker is the complete result.
        let mut trunc_out = exited(1, "package nano is not installed\n", "");
        trunc_out.stdout_truncated = true;
        assert!(PackageBackend::Dnf
            .classify_observation(&trunc_out, "nano", "nano", false)
            .is_err());
        let mut trunc_err = exited(1, "", "package nano is not installed\n");
        trunc_err.stderr_truncated = true;
        assert!(PackageBackend::Dnf
            .classify_observation(&trunc_err, "nano", "nano", false)
            .is_err());
        // Malformed bytes cannot establish a clean absent result.
        let bad = Output {
            completion: Completion::Exited(1),
            stdout: vec![0xff, 0xfe],
            stderr: b"package nano is not installed\n".to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        };
        assert!(PackageBackend::Dnf
            .classify_observation(&bad, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn sensitive_observation_error_is_redacted() {
        let out = exited(2, "", "leaks secret pkg name in stderr");
        let e = PackageBackend::Dnf
            .classify_observation(&out, "secretpkg", "[redacted]", true)
            .unwrap_err();
        assert!(!e.message.contains("secret pkg name"));
        assert!(e.message.contains("[redacted]"));
    }

    // -----------------------------------------------------------------
    // IA-01: fail-closed package observation contracts. Each case asserts
    // the semantic outcome (Installed / Absent / observation failure), never
    // merely that a string was rejected.
    // -----------------------------------------------------------------

    fn trunc(mut o: Output, stdout: bool, stderr: bool) -> Output {
        o.stdout_truncated = stdout;
        o.stderr_truncated = stderr;
        o
    }

    #[test]
    fn apt_present_contract_requires_a_complete_clean_record() {
        // Clean present answer: dpkg-query -f=${Status} emits exactly one
        // unterminated status record.
        let o = exited(0, "install ok installed", "");
        assert_eq!(
            PackageBackend::Apt
                .classify_observation(&o, "nano", "nano", false)
                .unwrap(),
            PackageState::Installed
        );
        // Clean absent answer (reference dpkg form).
        let o = exited(1, "", "dpkg-query: no packages found matching nano\n");
        assert_eq!(
            PackageBackend::Apt
                .classify_observation(&o, "nano", "nano", false)
                .unwrap(),
            PackageState::Absent
        );
        // Legacy/bare absence form is still a complete, exact record.
        let o = exited(1, "", "no packages found matching nano\n");
        assert_eq!(
            PackageBackend::Apt
                .classify_observation(&o, "nano", "nano", false)
                .unwrap(),
            PackageState::Absent
        );
    }

    #[test]
    fn apt_present_record_never_normalizes_whitespace() {
        // Leading/trailing whitespace the protocol never emits, or a second
        // record, must not be trimmed into a trusted state (RA2-01).
        for bad in [
            " install ok installed",
            "install ok installed ",
            "install ok installed\n",
            "install ok installed\n\n",
            "install ok installed\ninstall ok installed",
        ] {
            let o = exited(0, bad, "");
            assert!(
                PackageBackend::Apt
                    .classify_observation(&o, "nano", "nano", false)
                    .is_err(),
                "dpkg record {:?} must not classify as a clean state",
                bad
            );
        }
    }

    #[test]
    fn apt_exit_zero_with_truncated_stdout_is_not_installed() {
        let o = trunc(exited(0, "install ok installed", ""), true, false);
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
        let o = trunc(exited(0, "install ok installed", ""), false, true);
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn apt_exit_zero_with_malformed_status_output_is_not_installed() {
        // Half-configured is a real dpkg state: it is not "installed" and the
        // observation must fail rather than be rounded either way.
        let o = exited(0, "install ok half-configured", "");
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
        // An empty status with a successful exit is not an answer.
        let o = exited(0, "", "");
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn apt_exit_zero_with_unexpected_diagnostic_is_not_installed() {
        let o = exited(
            0,
            "install ok installed",
            "dpkg-query: warning: database unreadable\n",
        );
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn apt_exit_one_with_an_unrelated_error_is_not_absent() {
        let o = exited(1, "", "dpkg-query: error: cannot open dpkg status file\n");
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn apt_exit_one_with_an_ambiguous_absence_diagnostic_is_not_absent() {
        // The marker plus a second diagnostic line is ambiguous.
        let o = exited(
            1,
            "",
            "dpkg-query: no packages found matching nano\nwarning: db corrupt\n",
        );
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
        // Truncated absence diagnostic.
        let o = trunc(
            exited(1, "", "dpkg-query: no packages found matchin"),
            true,
            false,
        );
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
        // Marker on the wrong stream.
        let o = exited(1, "dpkg-query: no packages found matching nano\n", "");
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
        // A different package's marker does not prove this one absent.
        let o = exited(1, "", "dpkg-query: no packages found matching other\n");
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
        // A substring of unrelated output is not the exact record.
        let o = exited(
            1,
            "",
            "note: no packages found matching nano in this build root\n",
        );
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn apt_invalid_utf8_never_becomes_a_state() {
        let o = Output {
            completion: Completion::Exited(0),
            stdout: b"install ok installed".to_vec(),
            stderr: vec![0xff, 0xfe],
            stdout_truncated: false,
            stderr_truncated: false,
        };
        assert!(PackageBackend::Apt
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn rpm_present_contract_requires_a_complete_single_record() {
        // Clean installed answer: exactly the package NAME, no terminator.
        let o = exited(0, "nano", "");
        assert_eq!(
            PackageBackend::Dnf
                .classify_observation(&o, "nano", "nano", false)
                .unwrap(),
            PackageState::Installed
        );
        // Clean absent answer (reference rpm 4.16 form).
        let o = exited(1, "package nano is not installed\n", "");
        assert_eq!(
            PackageBackend::Dnf
                .classify_observation(&o, "nano", "nano", false)
                .unwrap(),
            PackageState::Absent
        );
    }

    #[test]
    fn rpm_present_record_rejects_prefix_garbage_and_wrong_identity() {
        // The reproduced false PASS: `<name>-garbage` used to be accepted as
        // proof `nano` was installed. Whole-record NAME equality rejects it
        // (RA2-01).
        let o = exited(0, "nano-garbage", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
        // A bare malformed prefix is not an identity record.
        let o = exited(0, "nan", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
        // A record about another package proves nothing about this one.
        let o = exited(0, "other", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn rpm_exit_zero_with_truncated_output_is_not_installed() {
        let o = trunc(exited(0, "nano", ""), true, false);
        assert!(PackageBackend::Dnf
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
        let o = trunc(exited(0, "nano", ""), false, true);
        assert!(PackageBackend::Dnf
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn rpm_exit_zero_with_malformed_output_is_not_installed() {
        // No record at all: exit 0 proves nothing on its own.
        let o = exited(0, "", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn rpm_exit_zero_with_contradictory_diagnostic_is_not_installed() {
        // An installed answer printed alongside an rpmdb error is not a
        // trustworthy observation.
        let o = exited(
            0,
            "nano",
            "error: cannot open Packages database in /var/lib/rpm\n",
        );
        assert!(PackageBackend::Dnf
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn rpm_exit_zero_with_multiple_result_records_is_not_installed() {
        // Two matched packages concatenate under the fixed queryformat; the
        // result cannot equal the single requested name.
        let o = exited(0, "nanonano", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
        // A trailing blank record is equally disqualifying.
        let o = exited(0, "nano\n", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn rpm_exit_zero_naming_another_package_is_not_installed() {
        let o = exited(0, "other", "");
        assert!(PackageBackend::Dnf
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn rpm_invalid_utf8_never_becomes_a_state() {
        let o = Output {
            completion: Completion::Exited(0),
            stdout: vec![0xff, 0xfe],
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        };
        assert!(PackageBackend::Dnf
            .classify_observation(&o, "nano", "nano", false)
            .is_err());
    }

    #[test]
    fn sensitive_package_errors_never_include_raw_stderr() {
        // A sensitive resource's observation error must not echo captured
        // output that could carry secret-derived material.
        let o = exited(2, "", "secret value in stderr");
        let e = PackageBackend::Apt
            .classify_observation(&o, "secretpkg", "[redacted]", true)
            .unwrap_err();
        assert!(!e.message.contains("secret value in stderr"));
        assert!(e.message.contains("[redacted]"));
    }
}
