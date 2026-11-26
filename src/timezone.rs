//! `timezone`: the system time zone of a host, as the symbolic link
//! `/etc/localtime` into `/usr/share/zoneinfo`, changed with `timedatectl`.
//!
//! Everything here is pure: the zone name grammar, the fixed argv of the
//! change and the reading of the link target. The engine part
//! (`timezone_engine`) observes and changes.

use std::collections::BTreeMap;

use crate::error::{Result, SinterError};
use crate::value::Value;

/// `with` fields of a `timezone`.
pub const FIELDS: &[&str] = &["name"];

/// The one program this type runs.
pub const TOOL: &str = "/usr/bin/timedatectl";

/// The link that names the system time zone. The type owns this path: a
/// `file`, `template`, `link` or `file_merge` on it in the same recipe is a
/// load error.
pub const LOCALTIME: &str = "/etc/localtime";

/// Where the zone files live.
pub const ZONEINFO: &str = "/usr/share/zoneinfo";

/// Longest accepted zone name, in bytes.
pub const MAX_NAME: usize = 64;

/// Seconds `timedatectl set-timezone` may take.
pub const TIMEOUT_SECS: u64 = 60;

/// Carried by every plan and apply result that changes the zone.
pub const PROGRAMS_NOTE: &str = "programs that are already running keep the time zone they started with until they are restarted, and Sinter restarts nothing; the clock, NTP synchronization and the RTC mode are not changed";

const NAME_RULE: &str = "an IANA zone name such as Asia/Tokyo or UTC: 1 to 3 components of A-Z, a-z, 0-9, _, + and - separated by /, not starting with -, at most 64 bytes";

/// Whether `s` has the shape of a zone name: 1 to 3 components of
/// `[A-Za-z0-9_+-]+` separated by `/`, at most [`MAX_NAME`] bytes, no
/// component starting with `-`. No `.` at all, so no `.`/`..` component and
/// no leading `/`. Used for both declared and observed names.
pub fn valid_grammar(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_NAME {
        return false;
    }
    let parts: Vec<&str> = s.split('/').collect();
    parts.len() <= 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && !p.starts_with('-')
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-'))
        })
}

/// Check a declared zone name: the grammar of [`valid_grammar`], and not
/// one of the trees or names that are not a zone of their own (`posix/...`,
/// `right/...`, `posixrules`, `localtime`).
pub fn check_name(s: &str) -> std::result::Result<(), String> {
    if !valid_grammar(s) {
        return Err(format!("name is not a zone name ({})", NAME_RULE));
    }
    let first = s.split('/').next().unwrap_or("");
    if first == "posix" || first == "right" {
        return Err(
            "name must not use the posix/ or right/ tree; declare the zone itself (for example Asia/Tokyo)"
                .to_string(),
        );
    }
    if s == "posixrules" || s == "localtime" {
        return Err(format!("name {} is not a time zone", s));
    }
    Ok(())
}

fn bad(ctx: &str, why: &str, redact: bool) -> SinterError {
    SinterError::schema(if redact {
        format!(
            "{}: timezone name is not accepted (details withheld for a sensitive resource)",
            ctx
        )
    } else {
        format!("{}: timezone {}", ctx, why)
    })
}

/// Load-time check of the written `with` map (schema error, exit 2). A
/// `name` that still holds an interpolation is judged when the recipe is
/// frozen.
pub fn check_literals(with: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<()> {
    match with.get("name") {
        None | Some(Value::Null) => Err(SinterError::schema(format!(
            "{}: timezone name is required",
            ctx
        ))),
        Some(Value::Str(s)) if crate::expressions::has_interpolation(s) => Ok(()),
        Some(Value::Str(s)) => check_name(s).map_err(|why| bad(ctx, &why, redact)),
        Some(_) => Err(SinterError::schema(format!(
            "{}: timezone name must be a string",
            ctx
        ))),
    }
}

/// The declared zone of an evaluated (or resolved) resource.
pub fn name_from_values(vals: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<String> {
    match vals.get("name") {
        Some(Value::Str(s)) => {
            check_name(s).map_err(|why| bad(ctx, &why, redact))?;
            Ok(s.clone())
        }
        _ => Err(SinterError::schema(format!(
            "{}: timezone name must be a string",
            ctx
        ))),
    }
}

/// The zone file a declared name must exist as.
pub fn zone_file(name: &str) -> String {
    format!("{}/{}", ZONEINFO, name)
}

/// The fixed argv of the change, after the program [`TOOL`]. No `--`: the
/// grammar excludes a leading `-`.
pub fn set_args(name: &str) -> Vec<String> {
    vec!["set-timezone".to_string(), name.to_string()]
}

/// The zone the target of `/etc/localtime` names: after the absolute prefix
/// `/usr/share/zoneinfo/`, or after one or more leading `../` and then
/// `usr/share/zoneinfo/` (relative to `/etc`). Anything else is refused:
/// Sinter does not resolve other links or guess.
pub fn zone_from_link(target: &str) -> std::result::Result<String, String> {
    let rest = if let Some(r) = target.strip_prefix("/usr/share/zoneinfo/") {
        r
    } else {
        let mut t = target;
        let mut ups = 0;
        while let Some(r) = t.strip_prefix("../") {
            t = r;
            ups += 1;
        }
        match t.strip_prefix("usr/share/zoneinfo/") {
            Some(r) if ups > 0 => r,
            _ => {
                return Err(
                    "it does not point into /usr/share/zoneinfo (absolute, or relative as ../usr/share/zoneinfo/<zone>)"
                        .to_string(),
                )
            }
        }
    };
    if !valid_grammar(rest) {
        return Err("the part after /usr/share/zoneinfo/ is not a zone name".to_string());
    }
    Ok(rest.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let max = format!("{}/{}", "A".repeat(31), "b".repeat(32));
        assert_eq!(max.len(), 64);
        for ok in [
            "UTC",
            "Asia/Tokyo",
            "America/Argentina/Buenos_Aires",
            "Etc/GMT+5",
            "Etc/GMT-14",
            "America/Port-au-Prince",
            "GMT0",
            max.as_str(),
        ] {
            assert!(check_name(ok).is_ok(), "{ok}");
        }
        let too_long = format!("{}/{}", "A".repeat(32), "b".repeat(32));
        for bad in [
            "",
            "/Asia/Tokyo",
            "Asia/Tokyo/",
            "Asia//Tokyo",
            "../etc/shadow",
            "Asia/./Tokyo",
            "Asia/..",
            ".",
            "a/b/c/d",
            "Asia/Tokyo ",
            "Asia/Tok yo",
            "-UTC",
            "Asia/-x",
            "Asia\\Tokyo",
            "Asia/Tokyo\n",
            "Asia/Tōkyō",
            "posix/Asia/Tokyo",
            "right/UTC",
            "posix",
            "posixrules",
            "localtime",
            too_long.as_str(),
        ] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        assert!(check_name("posix/UTC").unwrap_err().contains("posix/"));
    }

    #[test]
    fn link_targets() {
        assert_eq!(
            zone_from_link("/usr/share/zoneinfo/Asia/Tokyo").unwrap(),
            "Asia/Tokyo"
        );
        assert_eq!(
            zone_from_link("../usr/share/zoneinfo/Etc/UTC").unwrap(),
            "Etc/UTC"
        );
        assert_eq!(
            zone_from_link("../../usr/share/zoneinfo/UTC").unwrap(),
            "UTC"
        );
        // Observed names are judged by the grammar only.
        assert_eq!(
            zone_from_link("/usr/share/zoneinfo/posix/UTC").unwrap(),
            "posix/UTC"
        );
        for bad in [
            "",
            "usr/share/zoneinfo/UTC",
            "/usr/share/zoneinfo/",
            "/usr/share/zoneinfo",
            "/usr/lib/zoneinfo/UTC",
            "/etc/zoneinfo/UTC",
            "../usr/share/zoneinfo/../../etc/shadow",
            "/usr/share/zoneinfo/Asia/../../../etc/shadow",
            "../usr/share/zoneinfo/Asia/Tokyo/",
            "./usr/share/zoneinfo/UTC",
            "/usr/share/zoneinfo//UTC",
        ] {
            assert!(zone_from_link(bad).is_err(), "{bad:?}");
        }
        assert_eq!(set_args("UTC"), ["set-timezone", "UTC"]);
        assert_eq!(zone_file("Asia/Tokyo"), "/usr/share/zoneinfo/Asia/Tokyo");
    }

    #[test]
    fn a_sensitive_name_error_names_nothing() {
        let mut with = BTreeMap::new();
        with.insert(
            "name".to_string(),
            Value::Str("Synthetic/Zo ne".to_string()),
        );
        let e = check_literals(&with, "r", true).unwrap_err().message;
        assert!(e.contains("withheld") && !e.contains("Synthetic"), "{e}");
        let e = check_literals(&with, "r", false).unwrap_err().message;
        assert!(e.contains("not a zone name"), "{e}");
    }
}
