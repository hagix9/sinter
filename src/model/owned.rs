//! Paths a native type owns that are not its `path`: `timezone`
//! (`/etc/localtime`), `locale` (both locale files, whatever the OS) and
//! `kernel_module` (its file in `/etc/modules-load.d` and its blacklist file
//! in `/etc/modprobe.d`). A `file`, `template`, `directory`, `link`,
//! `systemd_timer`, `sysctl` or `file_merge` on one of them in the same
//! recipe is a load-time conflict, in either order.

use super::file_merge::MergeOwners;
use std::collections::BTreeMap;

/// Claim `paths` for resource `id` of type `type_`. Returns the peer and
/// the message of the first conflict; nothing is claimed then.
pub(super) fn claim(
    path_owner: &mut BTreeMap<String, String>,
    merges: &MergeOwners,
    paths: &[String],
    id: &str,
    type_: &str,
) -> Option<(String, String)> {
    for p in paths {
        if let Some(peer) = merges.first_on(p) {
            return Some((
                peer.to_string(),
                format!(
                    "conflicting management of path {}: {} ({}) owns the whole path and {} (file_merge) manages a part of it",
                    p, id, type_, peer
                ),
            ));
        }
        if let Some(prev) = path_owner.get(p) {
            if prev != id {
                return Some((
                    prev.clone(),
                    format!(
                        "conflicting ownership of path {} by resources {} and {} ({} owns it)",
                        p, prev, id, type_
                    ),
                ));
            }
        }
    }
    for p in paths {
        path_owner.insert(p.clone(), id.to_string());
    }
    None
}
