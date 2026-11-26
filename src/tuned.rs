//! `tuned`: the TuneD profile selected on a host (`tuned-adm`).
//!
//! Everything here is pure: the declaration grammar, the paths TuneD keeps
//! its state and its profiles in, the fixed argv of the calls and the
//! parsers of the state file and of the one-line answers. The engine part
//! (`tuned_engine`) observes, decides and runs the tool.
//!
//! No `tuned-adm` output form is measured on a real host. The selected
//! profile is therefore read from TuneD's own state file, and a command
//! answer is accepted only in one exact form.

use std::collections::BTreeMap;

use crate::error::{Result, SinterError};
use crate::value::Value;

/// `with` fields of a `tuned`.
pub const FIELDS: &[&str] = &["profile", "recommended", "state", "verify"];

/// The one program this type runs.
pub const TOOL: &str = "/usr/sbin/tuned-adm";

/// The unit that applies the selected profile. Observed, never changed.
pub const SERVICE: &str = "tuned.service";

/// Where TuneD records the selected profile.
pub const ACTIVE_PROFILE: &str = "/etc/tuned/active_profile";

/// Where a profile `<name>` lives as `<dir>/<name>/tuned.conf`: the local
/// and the vendor tree, each in the newer and in the older layout.
pub const PROFILE_DIRS: [&str; 4] = [
    "/etc/tuned/profiles",
    "/etc/tuned",
    "/usr/lib/tuned/profiles",
    "/usr/lib/tuned",
];

/// Longest accepted profile name, in bytes.
pub const MAX_PROFILE: usize = 64;

/// Seconds `tuned-adm profile` or `tuned-adm off` may take.
pub const TIMEOUT_SECS: u64 = 300;

/// Carried by every plan and apply result that selects a profile.
pub const SETTINGS_NOTE: &str = "a TuneD profile sets kernel parameters and other tunables; a value that a sysctl resource or a file in /etc/sysctl.d sets can be overridden by the profile and the other way round (TuneD's reapply_sysctl setting decides the order), and Sinter does not resolve that: declare each setting in one place";

/// Carried by a plan result when `verify: true` is set.
pub const VERIFY_PLAN_NOTE: &str = "verify: tuned-adm verify is not run in plan (whether it is free of side effects is not measured); apply runs it after the change and audit runs it";

const PROFILE_RULE: &str = "[A-Za-z0-9][A-Za-z0-9_.-]{0,63}";

/// One profile name: `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. It cannot start
/// with `-` (an option) or `.`, and holds no `/` and no blank.
pub fn valid_profile(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    s.len() <= MAX_PROFILE
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// What the recipe wants: exactly one of the three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    /// This profile is selected.
    Profile(String),
    /// The profile TuneD recommends for the host is selected.
    Recommended,
    /// No profile is selected.
    Off,
}

/// A fully checked `tuned` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunedSpec {
    pub intent: Intent,
    /// Also check, in apply after a change and in audit, that the selected
    /// profile is applied (`tuned-adm verify`).
    pub verify: bool,
}

/// A literal boolean field: absent or null is false; anything but a literal
/// boolean is refused, so the flag is visible in the recipe text.
fn literal_bool(with: &BTreeMap<String, Value>, key: &str, ctx: &str) -> Result<bool> {
    match with.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(SinterError::schema(format!(
            "{}: tuned {} must be a literal boolean (true or false)",
            ctx, key
        ))),
    }
}

/// `state` as written: `active` (the default) or `off`. Returns whether it
/// is `off`. Only the two literal words are accepted (Sinter's YAML reads a
/// bare `off` as the string it is).
fn literal_off(with: &BTreeMap<String, Value>, ctx: &str) -> Result<bool> {
    match with.get("state") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Str(s)) if s == "active" => Ok(false),
        Some(Value::Str(s)) if s == "off" => Ok(true),
        Some(_) => Err(SinterError::schema(format!(
            "{}: tuned state must be the literal active or off",
            ctx
        ))),
    }
}

fn bad_profile(ctx: &str, redact: bool) -> SinterError {
    SinterError::schema(if redact {
        format!(
            "{}: tuned profile is not accepted (details withheld for a sensitive resource)",
            ctx
        )
    } else {
        format!(
            "{}: tuned profile is not a profile name ({})",
            ctx, PROFILE_RULE
        )
    })
}

impl TunedSpec {
    /// The shape every declaration must have whatever its variables hold:
    /// the literals, and exactly one of `profile`, `recommended: true` and
    /// `state: off`. Returns `(off, recommended, verify)`.
    fn shape(with: &BTreeMap<String, Value>, ctx: &str) -> Result<(bool, bool, bool)> {
        let off = literal_off(with, ctx)?;
        let recommended = literal_bool(with, "recommended", ctx)?;
        let verify = literal_bool(with, "verify", ctx)?;
        let has_profile = match with.get("profile") {
            None | Some(Value::Null) => false,
            Some(Value::Str(_)) => true,
            Some(_) => {
                return Err(SinterError::schema(format!(
                    "{}: tuned profile must be a string",
                    ctx
                )))
            }
        };
        let chosen = usize::from(off) + usize::from(recommended) + usize::from(has_profile);
        if chosen == 0 {
            return Err(SinterError::schema(format!(
                "{}: tuned needs exactly one of profile, recommended: true or state: off",
                ctx
            )));
        }
        if chosen > 1 {
            return Err(SinterError::schema(format!(
                "{}: tuned takes exactly one of profile, recommended: true and state: off; more than one is set",
                ctx
            )));
        }
        if off && verify {
            return Err(SinterError::schema(format!(
                "{}: tuned verify: true needs a profile; with state: off there is nothing to verify",
                ctx
            )));
        }
        Ok((off, recommended, verify))
    }

    /// Load-time check of the written `with` map (schema error, exit 2). A
    /// `profile` that still holds an interpolation is judged when the recipe
    /// is frozen. `redact` withholds the offending part from the message.
    pub fn check_literals(with: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<()> {
        Self::shape(with, ctx)?;
        match with.get("profile") {
            Some(Value::Str(s))
                if !crate::expressions::has_interpolation(s) && !valid_profile(s) =>
            {
                Err(bad_profile(ctx, redact))
            }
            _ => Ok(()),
        }
    }

    /// The spec of an evaluated (or resolved) resource.
    pub fn from_values(vals: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<Self> {
        let (off, recommended, verify) = Self::shape(vals, ctx)?;
        let intent = if off {
            Intent::Off
        } else if recommended {
            Intent::Recommended
        } else {
            match vals.get("profile") {
                Some(Value::Str(s)) if valid_profile(s) => Intent::Profile(s.clone()),
                _ => return Err(bad_profile(ctx, redact)),
            }
        };
        Ok(TunedSpec { intent, verify })
    }
}

/// The files that make `name` a profile, in the order of [`PROFILE_DIRS`].
pub fn profile_files(name: &str) -> Vec<String> {
    PROFILE_DIRS
        .iter()
        .map(|d| format!("{}/{}/tuned.conf", d, name))
        .collect()
}

/// The fixed argv of the change, after the program [`TOOL`]: select
/// `desired`, or switch tuning off.
pub fn change_args(desired: Option<&str>) -> Vec<String> {
    match desired {
        Some(name) => vec!["profile".to_string(), name.to_string()],
        None => vec!["off".to_string()],
    }
}

/// The change as a person would type it, for messages.
pub fn change_text(desired: Option<&str>) -> &'static str {
    match desired {
        Some(_) => "tuned-adm profile",
        None => "tuned-adm off",
    }
}

/// One line with an optional final newline, as a profile name.
fn one_profile_line(bytes: &[u8]) -> std::result::Result<Option<String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "it is not valid UTF-8".to_string())?;
    if text.chars().all(|c| matches!(c, ' ' | '\t' | '\n' | '\r')) {
        return Ok(None);
    }
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.contains('\n') {
        return Err("it has more than one line".to_string());
    }
    if !valid_profile(line) {
        return Err(format!("it is not one profile name ({})", PROFILE_RULE));
    }
    Ok(Some(line.to_string()))
}

/// Parse `/etc/tuned/active_profile`: empty or only blanks and newlines is
/// "no profile selected"; exactly one line that is one profile name is that
/// profile. Anything else (several names on a line as TuneD writes for
/// merged profiles, a second line, other characters) is refused.
pub fn parse_active_profile(bytes: &[u8]) -> std::result::Result<Option<String>, String> {
    one_profile_line(bytes)
}

/// Parse the standard output of `tuned-adm recommend`: exactly one line that
/// is one profile name, with an optional final newline.
pub fn parse_recommend(stdout: &[u8]) -> std::result::Result<String, String> {
    match one_profile_line(stdout)? {
        Some(name) => Ok(name),
        None => Err("it is empty".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    fn s(v: &str) -> Value {
        Value::Str(v.to_string())
    }

    #[test]
    fn profile_grammar_is_exact() {
        for ok in [
            "balanced",
            "virtual-guest",
            "throughput-performance",
            "site_db.v2",
            "0a",
            "A",
            &"a".repeat(64),
        ] {
            assert!(valid_profile(ok), "{ok}");
        }
        for bad in [
            "",
            "-balanced",
            ".hidden",
            "_x",
            "a b",
            "a/b",
            "../x",
            "a\n",
            "a:b",
            "é",
            "--help",
            &"a".repeat(65),
        ] {
            assert!(!valid_profile(bad), "{bad:?}");
        }
    }

    #[test]
    fn exactly_one_intent_is_required() {
        let t = Value::Bool(true);
        let f = Value::Bool(false);
        let ok: Vec<(BTreeMap<String, Value>, Intent, bool)> = vec![
            (
                with(&[("profile", s("balanced"))]),
                Intent::Profile("balanced".into()),
                false,
            ),
            (
                with(&[("profile", s("balanced")), ("state", s("active"))]),
                Intent::Profile("balanced".into()),
                false,
            ),
            (
                with(&[("profile", s("balanced")), ("recommended", f.clone())]),
                Intent::Profile("balanced".into()),
                false,
            ),
            (
                with(&[("recommended", t.clone()), ("verify", t.clone())]),
                Intent::Recommended,
                true,
            ),
            (with(&[("state", s("off"))]), Intent::Off, false),
            (
                with(&[("state", s("off")), ("verify", f.clone())]),
                Intent::Off,
                false,
            ),
        ];
        for (w, intent, verify) in ok {
            assert!(TunedSpec::check_literals(&w, "r", false).is_ok(), "{w:?}");
            let spec = TunedSpec::from_values(&w, "r", false).unwrap();
            assert_eq!((spec.intent, spec.verify), (intent, verify), "{w:?}");
        }
        let bad: Vec<(BTreeMap<String, Value>, &str)> = vec![
            (with(&[]), "needs exactly one"),
            (with(&[("state", s("active"))]), "needs exactly one"),
            (with(&[("recommended", f.clone())]), "needs exactly one"),
            (
                with(&[("profile", s("balanced")), ("recommended", t.clone())]),
                "more than one",
            ),
            (
                with(&[("profile", s("balanced")), ("state", s("off"))]),
                "more than one",
            ),
            (
                with(&[("recommended", t.clone()), ("state", s("off"))]),
                "more than one",
            ),
            (
                with(&[("state", s("off")), ("verify", t.clone())]),
                "nothing to verify",
            ),
            (with(&[("state", s("stopped"))]), "active or off"),
            (with(&[("state", f.clone())]), "active or off"),
            (with(&[("state", s("{{ vars.s }}"))]), "active or off"),
            (
                with(&[("recommended", s("true"))]),
                "recommended must be a literal boolean",
            ),
            (
                with(&[("profile", s("balanced")), ("verify", s("{{ vars.v }}"))]),
                "verify must be a literal boolean",
            ),
            (with(&[("profile", Value::Int(1))]), "must be a string"),
            (with(&[("profile", s("a b"))]), "not a profile name"),
            (with(&[("profile", s("-x"))]), "not a profile name"),
            (with(&[("profile", s(""))]), "not a profile name"),
        ];
        for (w, want) in bad {
            let e = TunedSpec::check_literals(&w, "r", false).unwrap_err();
            assert_eq!(e.kind, crate::error::ErrorKind::Schema);
            assert!(e.message.contains(want), "{want}: {}", e.message);
            assert!(TunedSpec::from_values(&w, "r", false).is_err(), "{w:?}");
        }
    }

    #[test]
    fn an_interpolated_profile_is_judged_later_and_a_bad_one_is_withheld_when_sensitive() {
        let later = with(&[("profile", s("{{ vars.profile }}"))]);
        assert!(TunedSpec::check_literals(&later, "r", false).is_ok());
        // Once resolved it must be a name.
        assert!(TunedSpec::from_values(&later, "r", false).is_err());
        let e = TunedSpec::check_literals(&with(&[("profile", s("synthetic bad"))]), "r", true)
            .unwrap_err();
        assert!(!e.message.contains("synthetic"), "{}", e.message);
        assert!(e.message.contains("withheld"), "{}", e.message);
    }

    #[test]
    fn the_state_file_is_one_name_or_nothing() {
        assert_eq!(parse_active_profile(b"").unwrap(), None);
        assert_eq!(parse_active_profile(b"\n").unwrap(), None);
        assert_eq!(parse_active_profile(b" \t\n\n").unwrap(), None);
        assert_eq!(
            parse_active_profile(b"virtual-guest\n").unwrap().as_deref(),
            Some("virtual-guest")
        );
        assert_eq!(
            parse_active_profile(b"balanced").unwrap().as_deref(),
            Some("balanced")
        );
        let cases: &[(&[u8], &str)] = &[
            (b"balanced powersave\n", "not one profile name"),
            (b"balanced\npowersave\n", "more than one line"),
            (b"balanced\n\n", "more than one line"),
            (b" balanced\n", "not one profile name"),
            (b"balanced \n", "not one profile name"),
            (b"balanced\r\n", "not one profile name"),
            (b"# comment\n", "not one profile name"),
            (b"\xff\n", "UTF-8"),
        ];
        for (bytes, want) in cases {
            let e = parse_active_profile(bytes).unwrap_err();
            assert!(
                e.contains(want),
                "{:?}: {e}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn a_recommendation_is_exactly_one_name() {
        assert_eq!(
            parse_recommend(b"virtual-guest\n").unwrap(),
            "virtual-guest"
        );
        assert_eq!(parse_recommend(b"balanced").unwrap(), "balanced");
        let cases: &[(&[u8], &str)] = &[
            (b"", "empty"),
            (b"\n", "empty"),
            (b"balanced\nnote\n", "more than one line"),
            (b"Recommended profile: balanced\n", "not one profile name"),
            (b"\xff", "UTF-8"),
        ];
        for (bytes, want) in cases {
            let e = parse_recommend(bytes).unwrap_err();
            assert!(
                e.contains(want),
                "{:?}: {e}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn profile_files_and_argv() {
        assert_eq!(
            profile_files("site-db"),
            [
                "/etc/tuned/profiles/site-db/tuned.conf",
                "/etc/tuned/site-db/tuned.conf",
                "/usr/lib/tuned/profiles/site-db/tuned.conf",
                "/usr/lib/tuned/site-db/tuned.conf"
            ]
        );
        assert_eq!(change_args(Some("balanced")), ["profile", "balanced"]);
        assert_eq!(change_args(None), ["off"]);
        assert_eq!(change_text(Some("x")), "tuned-adm profile");
        assert_eq!(change_text(None), "tuned-adm off");
    }
}
