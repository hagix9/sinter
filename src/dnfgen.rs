//! Which DNF generation a target has, for the types that support DNF 4
//! only (`dnf_repository`, `dnf_module`).
//!
//! The package backend comes from the detected OS identity, as for
//! `package`. The generation comes from `/usr/bin/dnf` itself: on a DNF 4
//! host it is a symbolic link to `dnf-3`, on a DNF 5 host to `dnf5`. Only
//! `lstat` and `readlink` are used (read-only, already part of every plan);
//! no `dnf` command is run to find out. Anything else, including a regular
//! `/usr/bin/dnf`, is not guessed about: the resource is refused.

use crate::engine::Engine;
use crate::error::{Result, SinterError};
use crate::platform::PackageBackend;
use crate::targetfs::ObjKind;

/// The program whose link target tells the DNF generation.
pub const DNF_BIN: &str = "/usr/bin/dnf";

/// What the link target of [`DNF_BIN`] says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnfGeneration {
    Dnf4,
    Dnf5,
    /// Neither a DNF 4 nor a DNF 5 program name.
    Unknown,
}

/// Classify the link target of `/usr/bin/dnf` by its last path component:
/// `dnf5` is DNF 5; `dnf-3`, another `dnf-<n>` or `dnf4...` is DNF 4 (the
/// names the `package` resource accepts as DNF 4).
pub fn classify_dnf_link(target: &str) -> DnfGeneration {
    let base = target.rsplit('/').next().unwrap_or("");
    if base == "dnf5" {
        DnfGeneration::Dnf5
    } else if base.starts_with("dnf-") || base.starts_with("dnf4") {
        DnfGeneration::Dnf4
    } else {
        DnfGeneration::Unknown
    }
}

impl Engine {
    /// Refuse a target a DNF 4 only type (`type_name`) does not support:
    /// one whose package manager is not DNF, and one whose `/usr/bin/dnf`
    /// is DNF 5 or cannot be told apart. Read-only (`stat`, `readlink`).
    /// The wording is the same for every type that calls this.
    pub(crate) fn require_dnf4(&mut self, res_id: &str, type_name: &str) -> Result<()> {
        if self.fs.pkg_backend != Some(PackageBackend::Dnf) {
            return Err(SinterError::apply(format!(
                "{}: {} is not supported on this host (its package manager is not DNF)",
                res_id, type_name
            )));
        }
        let unknown = || {
            SinterError::apply(format!(
                "{}: {} is not supported on this host: {} is not a symbolic link to \
                 a DNF 4 program, so the DNF generation cannot be told (only DNF 4 is supported)",
                res_id, type_name, DNF_BIN
            ))
        };
        if self.fs.inspect(DNF_BIN)?.kind != ObjKind::Symlink {
            return Err(unknown());
        }
        match classify_dnf_link(&self.fs.readlink(DNF_BIN)?) {
            DnfGeneration::Dnf4 => Ok(()),
            DnfGeneration::Dnf5 => Err(SinterError::apply(format!(
                "{}: {} is not supported on this host: it uses DNF 5, which this type does \
                 not support in this release",
                res_id, type_name
            ))),
            DnfGeneration::Unknown => Err(unknown()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_targets_are_classified_by_their_last_component() {
        for t in ["dnf-3", "/usr/bin/dnf-3", "dnf-4", "dnf4", "../bin/dnf-3"] {
            assert_eq!(classify_dnf_link(t), DnfGeneration::Dnf4, "{t}");
        }
        for t in ["dnf5", "/usr/bin/dnf5"] {
            assert_eq!(classify_dnf_link(t), DnfGeneration::Dnf5, "{t}");
        }
        for t in [
            "",
            "dnf",
            "/usr/bin/dnf",
            "dnf5-old",
            "dnf50",
            "microdnf",
            "yum",
            "/opt/tools/wrapper",
            "dnf5/",
            "/usr/bin/dnf5/x",
        ] {
            assert_eq!(classify_dnf_link(t), DnfGeneration::Unknown, "{t:?}");
        }
    }
}
