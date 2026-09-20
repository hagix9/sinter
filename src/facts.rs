use crate::error::{Result, SinterError};
use crate::expressions::{EvalVal, ExprError};
use crate::value::Value;

#[derive(Debug, Clone)]
pub struct Facts {
    pub hostname: String,
    pub os_name: String,
    pub os_family: String,
    pub os_version: String,
    pub arch: String,
}

impl Facts {
    pub fn lookup(&self, path: &[String]) -> std::result::Result<EvalVal, ExprError> {
        let joined = path.join(".");
        let v = match joined.as_str() {
            "hostname" => Value::Str(self.hostname.clone()),
            "os.name" => Value::Str(self.os_name.clone()),
            "os.family" => Value::Str(self.os_family.clone()),
            "os.version" => Value::Str(self.os_version.clone()),
            "arch" => Value::Str(self.arch.clone()),
            other => {
                return Err(ExprError(format!("unknown fact: facts.{}", other)));
            }
        };
        Ok(EvalVal::known(v))
    }
}

/// Derive the os family from an os-release ID / ID_LIKE.
pub fn derive_family(id: &str, id_like: &str) -> String {
    let id = id.to_ascii_lowercase();
    let id_like = id_like.to_ascii_lowercase();
    let tokens: Vec<&str> = id_like.split_whitespace().collect();
    if id == "ubuntu" || id == "debian" || tokens.contains(&"debian") || tokens.contains(&"ubuntu")
    {
        "debian".to_string()
    } else if matches!(
        id.as_str(),
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "ol"
    ) || tokens.contains(&"fedora")
        || tokens.contains(&"rhel")
        || tokens.contains(&"centos")
    {
        "redhat".to_string()
    } else if id == "arch" || tokens.contains(&"arch") {
        "arch".to_string()
    } else {
        id
    }
}

/// Parse /etc/os-release content into (name, version).
pub fn parse_os_release(content: &str) -> (String, String, String) {
    let mut name = String::new();
    let mut id = String::new();
    let mut id_like = String::new();
    let mut version = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches('"').to_string();
            match k.trim() {
                "NAME" => name = v,
                "ID" => id = v,
                "ID_LIKE" => id_like = v,
                "VERSION_ID" => version = v,
                _ => {}
            }
        }
    }
    let _ = id_like;
    (name, id, version)
}

impl Facts {
    pub fn from_observed(hostname: String, os_release: &str, arch: String) -> Result<Facts> {
        if hostname.is_empty() {
            return Err(SinterError::connect("could not determine target hostname"));
        }
        let (name, id, version) = parse_os_release(os_release);
        if name.is_empty() && id.is_empty() {
            return Err(SinterError::connect(
                "could not determine target operating system from /etc/os-release",
            ));
        }
        let id_like = os_release
            .lines()
            .find_map(|l| l.trim().strip_prefix("ID_LIKE="))
            .unwrap_or("")
            .trim_matches('"')
            .to_string();
        let os_name = if !name.is_empty() { name } else { id.clone() };
        Ok(Facts {
            hostname,
            os_name,
            os_family: derive_family(&id, &id_like),
            os_version: version,
            arch,
        })
    }
}

pub fn normalize_arch(raw: &str) -> String {
    match raw.trim() {
        "x86_64" | "amd64" => "x86_64".to_string(),
        "aarch64" | "arm64" => "aarch64".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_ubuntu() {
        assert_eq!(derive_family("ubuntu", "debian"), "debian");
    }

    #[test]
    fn family_rhel_relatives() {
        // Rocky Linux 9: ID="rocky", ID_LIKE="rhel centos fedora"
        assert_eq!(derive_family("rocky", "rhel centos fedora"), "redhat");
        // RHEL-family detection must not depend on the exact ID spelling.
        assert_eq!(derive_family("rhel", "rhel fedora"), "redhat");
        assert_eq!(derive_family("centos", "rhel fedora"), "redhat");
        assert_eq!(derive_family("almalinux", "rhel centos fedora"), "redhat");
        // A derivative declaring only ID_LIKE=rhel still resolves.
        assert_eq!(derive_family("someel", "rhel"), "redhat");
        assert_eq!(derive_family("fedora", ""), "redhat");
        // Oracle Linux (ID=ol) classifies as RHEL-family: expected
        // compatible, not acceptance-tested.
        assert_eq!(derive_family("ol", "fedora"), "redhat");
    }

    #[test]
    fn family_unknown_does_not_match() {
        assert_eq!(derive_family("opensuse-leap", "suse"), "opensuse-leap");
        assert_eq!(derive_family("alpine", ""), "alpine");
    }

    #[test]
    fn parse_release() {
        let c = "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\nID_LIKE=debian\n";
        let (n, id, v) = parse_os_release(c);
        assert_eq!(n, "Ubuntu");
        assert_eq!(id, "ubuntu");
        assert_eq!(v, "24.04");
    }

    /// Real `/etc/os-release` of an Ubuntu 26.04.1 LTS target (verified
    /// on-target). Family derivation must resolve to `debian` exactly as it
    /// does for 24.04 — no version gate exists anywhere in detection.
    #[test]
    fn parse_ubuntu2604_release() {
        let c = "PRETTY_NAME=\"Ubuntu 26.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"26.04\"\n\
                 VERSION=\"26.04.1 LTS (Resolute Raccoon)\"\nVERSION_CODENAME=resolute\n\
                 ID=ubuntu\nID_LIKE=debian\nUBUNTU_CODENAME=resolute\nLOGO=ubuntu-logo\n";
        let (name, id, version) = parse_os_release(c);
        assert_eq!(name, "Ubuntu");
        assert_eq!(id, "ubuntu");
        assert_eq!(version, "26.04");
        assert_eq!(derive_family(&id, "debian"), "debian");
    }

    /// Real `/etc/os-release` of a Rocky Linux 10.2 target (verified
    /// on-target), including `PLATFORM_ID="platform:el10"` and the RHEL
    /// `ID_LIKE` chain. Family derivation must resolve to `redhat`.
    #[test]
    fn parse_rocky10_release() {
        let c = "NAME=\"Rocky Linux\"\nVERSION=\"10.2 (Red Quartz)\"\nRELEASE_TYPE=\"stable\"\n\
                 ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"10.2\"\n\
                 PLATFORM_ID=\"platform:el10\"\nCPE_NAME=\"cpe:/o:rocky:rocky:10::baseos\"\n";
        let (name, id, version) = parse_os_release(c);
        assert_eq!(name, "Rocky Linux");
        assert_eq!(id, "rocky");
        assert_eq!(version, "10.2");
        assert_eq!(derive_family(&id, "rhel centos fedora"), "redhat");
    }

    /// Real `/etc/os-release` of a RHEL 9.8 x86_64 GCE target (captured
    /// on-target, `rhel-9-v20260908`). Family derivation must resolve to
    /// `redhat` and select the Dnf backend.
    #[test]
    fn parse_rhel9_release() {
        let c = "NAME=\"Red Hat Enterprise Linux\"\nVERSION=\"9.8 (Plow)\"\nID=\"rhel\"\n\
                 ID_LIKE=\"fedora\"\nVERSION_ID=\"9.8\"\nPLATFORM_ID=\"platform:el9\"\n\
                 PRETTY_NAME=\"Red Hat Enterprise Linux 9.8 (Plow)\"\nANSI_COLOR=\"0;31\"\n\
                 LOGO=\"fedora-logo-icon\"\nCPE_NAME=\"cpe:/o:redhat:enterprise_linux:9::baseos\"\n\
                 HOME_URL=\"https://www.redhat.com/\"\n\
                 DOCUMENTATION_URL=\"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9\"\n\
                 BUG_REPORT_URL=\"https://issues.redhat.com/\"\n\n\
                 REDHAT_BUGZILLA_PRODUCT=\"Red Hat Enterprise Linux 9\"\n\
                 REDHAT_BUGZILLA_PRODUCT_VERSION=9.8\n\
                 REDHAT_SUPPORT_PRODUCT=\"Red Hat Enterprise Linux\"\n\
                 REDHAT_SUPPORT_PRODUCT_VERSION=\"9.8\"\n";
        let (name, id, version) = parse_os_release(c);
        assert_eq!(name, "Red Hat Enterprise Linux");
        assert_eq!(id, "rhel");
        assert_eq!(version, "9.8");
        let family = derive_family(&id, "fedora");
        assert_eq!(family, "redhat");
        assert_eq!(
            crate::platform::PackageBackend::for_os_family(&family),
            Some(crate::platform::PackageBackend::Dnf)
        );
    }

    /// Real `/etc/os-release` of a RHEL 10.2 x86_64 GCE target (captured
    /// on-target, `rhel-10-v20260908`). Family derivation must resolve to
    /// `redhat` and select the Dnf backend.
    #[test]
    fn parse_rhel10_release() {
        let c = "NAME=\"Red Hat Enterprise Linux\"\nVERSION=\"10.2 (Coughlan)\"\n\
                 RELEASE_TYPE=stable\nID=\"rhel\"\nID_LIKE=\"centos fedora\"\n\
                 VERSION_ID=\"10.2\"\nPLATFORM_ID=\"platform:el10\"\n\
                 PRETTY_NAME=\"Red Hat Enterprise Linux 10.2 (Coughlan)\"\n\
                 ANSI_COLOR=\"0;31\"\nLOGO=\"fedora-logo-icon\"\n\
                 CPE_NAME=\"cpe:/o:redhat:enterprise_linux:10.2\"\n\
                 HOME_URL=\"https://www.redhat.com/\"\nVENDOR_NAME=\"Red Hat\"\n\
                 VENDOR_URL=\"https://www.redhat.com/\"\n\
                 DOCUMENTATION_URL=\"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/10\"\n\
                 BUG_REPORT_URL=\"https://issues.redhat.com/\"\n\n\
                 REDHAT_BUGZILLA_PRODUCT=\"Red Hat Enterprise Linux 10\"\n\
                 REDHAT_BUGZILLA_PRODUCT_VERSION=10.2\n\
                 REDHAT_SUPPORT_PRODUCT=\"Red Hat Enterprise Linux\"\n\
                 REDHAT_SUPPORT_PRODUCT_VERSION=\"10.2\"\n";
        let (name, id, version) = parse_os_release(c);
        assert_eq!(name, "Red Hat Enterprise Linux");
        assert_eq!(id, "rhel");
        assert_eq!(version, "10.2");
        let family = derive_family(&id, "centos fedora");
        assert_eq!(family, "redhat");
        assert_eq!(
            crate::platform::PackageBackend::for_os_family(&family),
            Some(crate::platform::PackageBackend::Dnf)
        );
    }

    /// Real `/etc/os-release` of an AlmaLinux 9.8 x86_64 GCE target
    /// (captured on-target, `almalinux-9-v20260811`). Family derivation
    /// must resolve to `redhat` and select the Dnf backend.
    #[test]
    fn parse_almalinux9_release() {
        let c = "NAME=\"AlmaLinux\"\nVERSION=\"9.8 (Olive Jaguar)\"\nID=\"almalinux\"\n\
                 ID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.8\"\n\
                 PLATFORM_ID=\"platform:el9\"\nPRETTY_NAME=\"AlmaLinux 9.8 (Olive Jaguar)\"\n\
                 ANSI_COLOR=\"0;34\"\nLOGO=\"fedora-logo-icon\"\n\
                 CPE_NAME=\"cpe:/o:almalinux:almalinux:9::baseos\"\n\
                 HOME_URL=\"https://almalinux.org/\"\n\
                 DOCUMENTATION_URL=\"https://wiki.almalinux.org/\"\n\
                 BUG_REPORT_URL=\"https://bugs.almalinux.org/\"\n\n\
                 ALMALINUX_MANTISBT_PROJECT=\"AlmaLinux-9\"\n\
                 ALMALINUX_MANTISBT_PROJECT_VERSION=\"9.8\"\n\
                 REDHAT_SUPPORT_PRODUCT=\"AlmaLinux\"\n\
                 REDHAT_SUPPORT_PRODUCT_VERSION=\"9.8\"\nSUPPORT_END=2032-06-01\n";
        let (name, id, version) = parse_os_release(c);
        assert_eq!(name, "AlmaLinux");
        assert_eq!(id, "almalinux");
        assert_eq!(version, "9.8");
        let family = derive_family(&id, "rhel centos fedora");
        assert_eq!(family, "redhat");
        assert_eq!(
            crate::platform::PackageBackend::for_os_family(&family),
            Some(crate::platform::PackageBackend::Dnf)
        );
    }

    /// Real `/etc/os-release` of an AlmaLinux 10.2 x86_64 GCE target
    /// (captured on-target, `almalinux-10-v20260811`). Family derivation
    /// must resolve to `redhat` and select the Dnf backend.
    #[test]
    fn parse_almalinux10_release() {
        let c = "NAME=\"AlmaLinux\"\nVERSION=\"10.2 (Lavender Lion)\"\n\
                 RELEASE_TYPE=stable\nID=\"almalinux\"\n\
                 ID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"10.2\"\n\
                 PLATFORM_ID=\"platform:el10\"\n\
                 PRETTY_NAME=\"AlmaLinux 10.2 (Lavender Lion)\"\n\
                 ANSI_COLOR=\"0;34\"\nLOGO=\"fedora-logo-icon\"\n\
                 CPE_NAME=\"cpe:/o:almalinux:almalinux:10.2\"\n\
                 HOME_URL=\"https://almalinux.org/\"\nVENDOR_NAME=\"AlmaLinux\"\n\
                 VENDOR_URL=\"https://almalinux.org/\"\n\
                 BUG_REPORT_URL=\"https://bugs.almalinux.org/\"\n\n\
                 ALMALINUX_MANTISBT_PROJECT=\"AlmaLinux-10\"\n\
                 ALMALINUX_MANTISBT_PROJECT_VERSION=\"10.2\"\n\
                 REDHAT_SUPPORT_PRODUCT=\"AlmaLinux\"\n\
                 REDHAT_SUPPORT_PRODUCT_VERSION=\"10.2\"\nSUPPORT_END=2035-06-01\n";
        let (name, id, version) = parse_os_release(c);
        assert_eq!(name, "AlmaLinux");
        assert_eq!(id, "almalinux");
        assert_eq!(version, "10.2");
        let family = derive_family(&id, "rhel centos fedora");
        assert_eq!(family, "redhat");
        assert_eq!(
            crate::platform::PackageBackend::for_os_family(&family),
            Some(crate::platform::PackageBackend::Dnf)
        );
    }
}
