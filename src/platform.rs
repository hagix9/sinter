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
    /// DESIGN §27: no version pinning, no explicit repository metadata
    /// refresh. For dnf, `metadata_expire=-1` prevents an implicit metadata
    /// refresh so behavior matches the apt contract of using the existing
    /// cache only.
    pub fn mutate_args(&self, want_installed: bool, name: &str) -> Vec<String> {
        let action = if want_installed { "install" } else { "remove" };
        match self {
            Self::Apt => vec!["-y".to_string(), action.to_string(), name.to_string()],
            Self::Dnf => vec![
                "--setopt=metadata_expire=-1".to_string(),
                "-y".to_string(),
                action.to_string(),
                name.to_string(),
            ],
        }
    }

    /// Classify a completed package-database query into a clean state.
    ///
    /// Both backends distinguish a positively-confirmed "not installed" from
    /// an ambiguous/errored query: anything that cannot be interpreted is an
    /// observation error, never silently "absent" (DESIGN §27). `name_disp`
    /// is the presentation form of the package name (already redacted when
    /// the resource is sensitive); the raw name is only matched internally.
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
                    let status = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    crate::resources::classify_dpkg_status(&status)
                }
                // Confirmed absent: dpkg-query found no matching package.
                Completion::Exited(1) => Ok(PackageState::Absent),
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
                Completion::Exited(0) => Ok(PackageState::Installed),
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

/// Whether an `rpm -q` exit-1 result positively reports the package as not
/// installed. rpm prints "package <name> is not installed"; the baseline
/// environment fixes LC_ALL=C.UTF-8 so the marker is locale-stable. Any
/// other exit-1 output is an inspection failure, not absence.
fn rpm_reports_absent(out: &Output, name: &str) -> bool {
    let marker = format!("package {} is not installed", name);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    stdout.contains(&marker) || stderr.contains(&marker)
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
        assert_eq!(
            PackageBackend::Dnf.mutate_args(true, "httpd"),
            vec!["--setopt=metadata_expire=-1", "-y", "install", "httpd"]
        );
        assert_eq!(
            PackageBackend::Dnf.mutate_args(false, "httpd"),
            vec!["--setopt=metadata_expire=-1", "-y", "remove", "httpd"]
        );
        // apt argv is unchanged from v0.1.
        assert_eq!(
            PackageBackend::Apt.mutate_args(true, "nano"),
            vec!["-y", "install", "nano"]
        );
    }

    #[test]
    fn rpm_classification() {
        let installed = exited(0, "nano-7.2-2.el9.x86_64\n", "");
        assert_eq!(
            PackageBackend::Dnf
                .classify_observation(&installed, "nano", "nano", false)
                .unwrap(),
            PackageState::Installed
        );
        let absent = exited(1, "", "package nano is not installed\n");
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
    fn rpm_absent_marker_checks_both_streams() {
        // rpm writes the marker to stderr, but accept either stream so a
        // harmless redirection difference cannot manufacture fake "absent".
        let out = exited(1, "package nano is not installed\n", "");
        assert!(rpm_reports_absent(&out, "nano"));
        let out = exited(1, "", "package nano is not installed\n");
        assert!(rpm_reports_absent(&out, "nano"));
        // A different package's marker does not prove this one absent.
        let out = exited(1, "", "package other is not installed\n");
        assert!(!rpm_reports_absent(&out, "nano"));
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
}
