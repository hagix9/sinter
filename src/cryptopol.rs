//! `crypto_policy`: the system-wide cryptographic policy of a RHEL-family
//! host (`update-crypto-policies`), its grammar, the rules that keep a
//! recipe from weakening cryptography without saying so, and the parser of
//! the tool's `--show` answer.
//!
//! Everything here is pure: no target is touched. The engine part
//! (`cryptopol_engine`) observes, decides and runs the tool.

use std::collections::BTreeMap;

use crate::error::{Result, SinterError};
use crate::value::Value;

/// `with` fields of a `crypto_policy`.
pub const FIELDS: &[&str] = &["policy", "allow_weaker"];

/// The one program this type runs.
pub const TOOL: &str = "/usr/bin/update-crypto-policies";

/// Where policy definitions live: the vendor tree, then the local one.
pub const POLICY_DIRS: [&str; 2] = [
    "/usr/share/crypto-policies/policies",
    "/etc/crypto-policies/policies",
];

/// Subpolicies accepted without `allow_weaker`: vendor modules that only
/// remove algorithms. Everything else (for example `SHA1`, `AD-SUPPORT`,
/// `NO-ENFORCE-EMS`, a site-defined module) needs the explicit flag,
/// because Sinter cannot tell whether it weakens the policy.
pub const HARDENING_MODULES: &[&str] = &["NO-SHA1", "NO-CAMELLIA", "OSPP"];

/// At most this many subpolicies.
pub const MAX_SUBPOLICIES: usize = 8;

/// Seconds `update-crypto-policies --set` may take.
pub const TIMEOUT_SECS: u64 = 300;

/// Carried by every plan and apply result that changes the policy.
pub const SERVICES_NOTE: &str = "running services (including sshd) keep the previous policy until they are restarted, and Sinter restarts nothing and does not reboot here; a stricter policy can make NEW SSH connections fail (old key types or algorithms), so verify a second connection before closing the current one; the vendor recommends a reboot for the policy to take full effect";

const PART_RULE: &str = "[A-Z0-9][A-Z0-9_-]{0,31}";

/// One policy or subpolicy name: `[A-Z0-9][A-Z0-9_-]{0,31}`.
pub fn valid_part(s: &str) -> bool {
    let ok_first = |c: char| c.is_ascii_uppercase() || c.is_ascii_digit();
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if ok_first(c) => {}
        _ => return false,
    }
    s.len() <= 32 && chars.all(|c| ok_first(c) || c == '_' || c == '-')
}

/// `BASE[:SUBPOLICY...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub base: String,
    pub subs: Vec<String>,
}

impl Policy {
    /// Parse the grammar. The error names no value.
    pub fn parse(text: &str) -> std::result::Result<Policy, String> {
        let mut parts = text.split(':');
        let base = parts.next().unwrap_or("");
        if !valid_part(base) {
            return Err(format!(
                "the base policy is not a policy name ({})",
                PART_RULE
            ));
        }
        let mut subs: Vec<String> = Vec::new();
        for p in parts {
            if !valid_part(p) {
                return Err(format!(
                    "a subpolicy is not a subpolicy name ({})",
                    PART_RULE
                ));
            }
            if subs.iter().any(|s| s == p) {
                return Err("a subpolicy is listed twice".to_string());
            }
            subs.push(p.to_string());
        }
        if subs.len() > MAX_SUBPOLICIES {
            return Err(format!(
                "more than {} subpolicies are listed",
                MAX_SUBPOLICIES
            ));
        }
        Ok(Policy {
            base: base.to_string(),
            subs,
        })
    }

    /// The policy as `update-crypto-policies` takes and prints it.
    pub fn text(&self) -> String {
        let mut out = self.base.clone();
        for s in &self.subs {
            out.push(':');
            out.push_str(s);
        }
        out
    }
}

/// The order Sinter knows between base policies; a base outside it (a
/// custom policy, `EMPTY`, `FIPS`) is not ordered.
fn base_rank(base: &str) -> Option<u8> {
    match base {
        "LEGACY" => Some(0),
        "DEFAULT" => Some(1),
        "FUTURE" => Some(2),
        _ => None,
    }
}

/// A fully checked `crypto_policy` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySpec {
    pub policy: Policy,
    pub allow_weaker: bool,
}

impl PolicySpec {
    /// Build the spec, applying the rules that hold whatever the host's
    /// current policy is. The error names the offending part.
    pub fn from_parts(policy: &str, allow_weaker: bool) -> std::result::Result<Self, String> {
        let policy = Policy::parse(policy)?;
        if policy.base == "FIPS" {
            return Err(
                "the FIPS policy is not supported: switching FIPS mode needs fips-mode-setup and a reboot, which Sinter does not do"
                    .to_string(),
            );
        }
        if !allow_weaker {
            if policy.base == "LEGACY" {
                return Err(
                    "the LEGACY policy weakens cryptography; it is refused unless allow_weaker: true is set"
                        .to_string(),
                );
            }
            if let Some(s) = policy
                .subs
                .iter()
                .find(|s| !HARDENING_MODULES.contains(&s.as_str()))
            {
                return Err(format!(
                    "Sinter cannot tell whether the subpolicy {} weakens the policy; it is refused unless allow_weaker: true is set (accepted without it: {})",
                    s,
                    HARDENING_MODULES.join(", ")
                ));
            }
        }
        Ok(PolicySpec {
            policy,
            allow_weaker,
        })
    }

    /// Load-time check of the written `with` map (schema error, exit 2).
    /// `allow_weaker` must be a literal boolean; a `policy` that still holds
    /// an interpolation is judged when the recipe is frozen. `redact`
    /// withholds the offending part from the message.
    pub fn check_literals(with: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<()> {
        let allow_weaker = Self::literal_allow_weaker(with, ctx)?;
        match with.get("policy") {
            Some(Value::Str(s)) if !crate::expressions::has_interpolation(s) => {
                Self::from_parts(s, allow_weaker)
                    .map(|_| ())
                    .map_err(|why| schema_error(ctx, &why, redact))
            }
            Some(Value::Str(_)) => Ok(()),
            None | Some(Value::Null) => Err(SinterError::schema(format!(
                "{}: crypto_policy policy is required",
                ctx
            ))),
            Some(_) => Err(SinterError::schema(format!(
                "{}: crypto_policy policy must be a string",
                ctx
            ))),
        }
    }

    /// `allow_weaker` as written: absent or null is false; only a literal
    /// boolean is accepted, so the flag is visible in the recipe text.
    pub fn literal_allow_weaker(with: &BTreeMap<String, Value>, ctx: &str) -> Result<bool> {
        match with.get("allow_weaker") {
            None | Some(Value::Null) => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(SinterError::schema(format!(
                "{}: crypto_policy allow_weaker must be a literal boolean (true or false)",
                ctx
            ))),
        }
    }

    /// The spec of an evaluated resource.
    pub fn from_values(vals: &BTreeMap<String, Value>, ctx: &str, redact: bool) -> Result<Self> {
        let allow_weaker = Self::literal_allow_weaker(vals, ctx)?;
        match vals.get("policy") {
            Some(Value::Str(s)) => {
                Self::from_parts(s, allow_weaker).map_err(|why| schema_error(ctx, &why, redact))
            }
            _ => Err(SinterError::schema(format!(
                "{}: crypto_policy policy must be a string",
                ctx
            ))),
        }
    }

    /// Why changing the host from `current` to the declared policy is
    /// refused, if it is. Only asked when the two differ.
    pub fn change_refusal(&self, current: &Policy) -> Option<String> {
        if current.base == "FIPS" {
            return Some(format!(
                "the host's current policy is {}; leaving FIPS mode needs fips-mode-setup and a reboot, which Sinter does not do",
                current.text()
            ));
        }
        if self.allow_weaker {
            return None;
        }
        if current.base != self.policy.base {
            match (base_rank(&current.base), base_rank(&self.policy.base)) {
                (Some(cur), Some(want)) if cur > want => {
                    return Some(format!(
                        "the host's current base policy {} is stronger than the declared {}; lowering the base policy must be explicit (allow_weaker: true)",
                        current.base, self.policy.base
                    ))
                }
                (Some(_), Some(_)) => {}
                _ => {
                    return Some(format!(
                        "Sinter cannot order the base policies {} (current) and {} (declared), so it cannot tell whether the change weakens the policy; it must be explicit (allow_weaker: true)",
                        current.base, self.policy.base
                    ))
                }
            }
        }
        // Removing a hardening module weakens the policy. Removing any other
        // applied module needs no flag: the declared policy passed the
        // static rules on its own, so what remains is a base (and hardening
        // modules) Sinter knows.
        if let Some(dropped) = current
            .subs
            .iter()
            .find(|s| HARDENING_MODULES.contains(&s.as_str()) && !self.policy.subs.contains(s))
        {
            return Some(format!(
                "the hardening subpolicy {} is applied on the host and missing from the declared policy; removing it weakens the policy, so it must be explicit (allow_weaker: true)",
                dropped
            ));
        }
        None
    }

    /// The definition files the declared policy needs: what it is (for the
    /// message) and the candidate paths, vendor tree first.
    pub fn definition_files(&self) -> Vec<(String, Vec<String>)> {
        let mut out = vec![(
            format!("policy {}", self.policy.base),
            POLICY_DIRS
                .iter()
                .map(|d| format!("{}/{}.pol", d, self.policy.base))
                .collect(),
        )];
        for s in &self.policy.subs {
            out.push((
                format!("subpolicy {}", s),
                POLICY_DIRS
                    .iter()
                    .map(|d| format!("{}/modules/{}.pmod", d, s))
                    .collect(),
            ));
        }
        out
    }

    /// The fixed argv of the change, after the program [`TOOL`].
    pub fn change_args(&self) -> Vec<String> {
        vec!["--set".to_string(), self.policy.text()]
    }
}

fn schema_error(ctx: &str, why: &str, redact: bool) -> SinterError {
    SinterError::schema(if redact {
        format!(
            "{}: crypto_policy policy is not accepted (details withheld for a sensitive resource)",
            ctx
        )
    } else {
        format!("{}: crypto_policy: {}", ctx, why)
    })
}

/// Parse the standard output of `update-crypto-policies --show`: exactly one
/// line in the policy grammar, with an optional final newline. Anything else
/// (no output, a second line, blanks, lower case) is refused.
pub fn parse_show(stdout: &[u8]) -> std::result::Result<Policy, String> {
    let text = std::str::from_utf8(stdout).map_err(|_| "it is not valid UTF-8".to_string())?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line.is_empty() {
        return Err("it is empty".to_string());
    }
    if line.contains('\n') {
        return Err("it has more than one line".to_string());
    }
    Policy::parse(line).map_err(|_| "it is not one policy name".to_string())
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

    fn p(text: &str) -> Policy {
        Policy::parse(text).unwrap()
    }

    #[test]
    fn grammar_is_exact() {
        for ok in [
            "DEFAULT",
            "FUTURE",
            "DEFAULT:NO-SHA1",
            "DEFAULT:NO-SHA1:OSPP",
            "LEGACY:AD-SUPPORT-LEGACY",
            "MY_POLICY1",
            "0A",
            &"A".repeat(32),
            "A:B1:B2:B3:B4:B5:B6:B7:B8",
        ] {
            let parsed = Policy::parse(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
            assert_eq!(parsed.text(), ok);
        }
        for bad in [
            "",
            "default",
            "DEFAULT:",
            ":NO-SHA1",
            "DEFAULT::NO-SHA1",
            "DEFAULT:no-sha1",
            "-DEFAULT",
            "_X",
            "DEFAULT NO-SHA1",
            "DEFAULT\n",
            "DEFAULT:NO-SHA1:NO-SHA1",
            "DEFAULT/../X",
            "--set",
            &"A".repeat(33),
            "A:B1:B2:B3:B4:B5:B6:B7:B8:B9",
        ] {
            assert!(Policy::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(p("DEFAULT:NO-SHA1").base, "DEFAULT");
        assert_eq!(p("DEFAULT:NO-SHA1").subs, ["NO-SHA1"]);
    }

    #[test]
    fn static_rules_refuse_silent_weakening() {
        for ok in [
            "DEFAULT",
            "FUTURE",
            "DEFAULT:NO-SHA1",
            "FUTURE:NO-CAMELLIA:OSPP",
            "SITE1",
        ] {
            assert!(PolicySpec::from_parts(ok, false).is_ok(), "{ok}");
        }
        // FIPS is refused with and without the flag.
        for flag in [false, true] {
            let e = PolicySpec::from_parts("FIPS", flag).unwrap_err();
            assert!(e.contains("fips-mode-setup"), "{e}");
            assert!(PolicySpec::from_parts("FIPS:OSPP", flag).is_err());
        }
        let e = PolicySpec::from_parts("LEGACY", false).unwrap_err();
        assert!(e.contains("allow_weaker: true"), "{e}");
        assert!(PolicySpec::from_parts("LEGACY", true).is_ok());
        for sub in [
            "SHA1",
            "AD-SUPPORT",
            "AD-SUPPORT-LEGACY",
            "NO-ENFORCE-EMS",
            "SITE-MODULE",
        ] {
            let text = format!("DEFAULT:{sub}");
            let e = PolicySpec::from_parts(&text, false).unwrap_err();
            assert!(
                e.contains(sub) && e.contains("cannot tell") && e.contains("allow_weaker"),
                "{e}"
            );
            assert!(PolicySpec::from_parts(&text, true).is_ok(), "{text}");
        }
        // One unlisted module among listed ones is enough.
        assert!(PolicySpec::from_parts("DEFAULT:NO-SHA1:SHA1", false).is_err());
    }

    #[test]
    fn literals_are_checked_at_load() {
        let ok = with(&[("policy", s("DEFAULT:NO-SHA1"))]);
        assert!(PolicySpec::check_literals(&ok, "r", false).is_ok());
        let later = with(&[("policy", s("{{ vars.policy }}"))]);
        assert!(PolicySpec::check_literals(&later, "r", false).is_ok());
        let cases: Vec<(BTreeMap<String, Value>, &str)> = vec![
            (with(&[]), "policy is required"),
            (with(&[("policy", Value::Int(1))]), "must be a string"),
            (with(&[("policy", s("default"))]), "not a policy name"),
            (with(&[("policy", s("LEGACY"))]), "allow_weaker"),
            (
                with(&[("policy", s("LEGACY")), ("allow_weaker", s("true"))]),
                "literal boolean",
            ),
            (
                with(&[
                    ("policy", s("DEFAULT")),
                    ("allow_weaker", s("{{ vars.x }}")),
                ]),
                "literal boolean",
            ),
            (
                with(&[("policy", s("FIPS")), ("allow_weaker", Value::Bool(true))]),
                "FIPS",
            ),
        ];
        for (w, want) in cases {
            let e = PolicySpec::check_literals(&w, "r", false).unwrap_err();
            assert_eq!(e.kind, crate::error::ErrorKind::Schema);
            assert!(e.message.contains(want), "{want}: {}", e.message);
        }
        let e = PolicySpec::check_literals(&with(&[("policy", s("DEFAULT:SHA1"))]), "r", true)
            .unwrap_err();
        assert!(!e.message.contains("SHA1"), "{}", e.message);
    }

    #[test]
    fn lowering_the_base_must_be_explicit() {
        let spec = |text: &str, flag: bool| PolicySpec::from_parts(text, flag).unwrap();
        // Raising, or staying on the base, needs no flag.
        assert!(spec("FUTURE", false)
            .change_refusal(&p("DEFAULT"))
            .is_none());
        assert!(spec("DEFAULT", false)
            .change_refusal(&p("LEGACY"))
            .is_none());
        assert!(spec("DEFAULT:NO-SHA1", false)
            .change_refusal(&p("DEFAULT"))
            .is_none());
        // Lowering does.
        let why = spec("DEFAULT", false).change_refusal(&p("FUTURE")).unwrap();
        assert!(
            why.contains("FUTURE is stronger than the declared DEFAULT"),
            "{why}"
        );
        assert!(spec("DEFAULT", true).change_refusal(&p("FUTURE")).is_none());
        assert!(spec("LEGACY", true).change_refusal(&p("DEFAULT")).is_none());
    }

    #[test]
    fn unknown_bases_are_not_ordered() {
        let spec = |text: &str, flag: bool| PolicySpec::from_parts(text, flag).unwrap();
        for (current, desired) in [
            ("SITE1", "DEFAULT"),
            ("DEFAULT", "SITE1"),
            ("EMPTY", "FUTURE"),
        ] {
            let why = spec(desired, false).change_refusal(&p(current)).unwrap();
            assert!(why.contains("cannot order"), "{why}");
            assert!(spec(desired, true).change_refusal(&p(current)).is_none());
        }
        // The same custom base with another module is not a base change.
        assert!(spec("SITE1:NO-SHA1", false)
            .change_refusal(&p("SITE1"))
            .is_none());
    }

    #[test]
    fn removing_an_applied_hardening_subpolicy_must_be_explicit() {
        let spec = |text: &str, flag: bool| PolicySpec::from_parts(text, flag).unwrap();
        for (current, named) in [
            ("DEFAULT:NO-SHA1", "NO-SHA1"),
            ("DEFAULT:NO-CAMELLIA", "NO-CAMELLIA"),
            ("DEFAULT:OSPP:NO-SHA1", "OSPP"),
            ("DEFAULT:SHA1:NO-SHA1", "NO-SHA1"),
        ] {
            let why = spec("DEFAULT", false).change_refusal(&p(current)).unwrap();
            assert!(
                why.contains(&format!("hardening subpolicy {named}"))
                    && why.contains("missing from the declared policy"),
                "{why}"
            );
            assert!(spec("DEFAULT", true).change_refusal(&p(current)).is_none());
        }
        // Keeping one hardening module while dropping another still needs it.
        assert!(spec("DEFAULT:NO-SHA1", false)
            .change_refusal(&p("DEFAULT:NO-SHA1:OSPP"))
            .is_some());
        // A module outside the hardening list may be removed without the
        // flag: the declared policy passed the static rules on its own.
        for current in [
            "DEFAULT:SHA1",
            "DEFAULT:AD-SUPPORT",
            "DEFAULT:NO-ENFORCE-EMS",
            "DEFAULT:SITE-MODULE",
        ] {
            assert!(
                spec("DEFAULT", false).change_refusal(&p(current)).is_none(),
                "{current}"
            );
            assert!(
                spec("DEFAULT:NO-SHA1", false)
                    .change_refusal(&p(current))
                    .is_none(),
                "{current}"
            );
            assert!(
                spec("FUTURE", false).change_refusal(&p(current)).is_none(),
                "{current}"
            );
        }
        // The base rules still hold while a module is removed.
        assert!(spec("DEFAULT", false)
            .change_refusal(&p("FUTURE:SHA1"))
            .unwrap()
            .contains("stronger"));
        assert!(spec("DEFAULT", false)
            .change_refusal(&p("SITE1:SHA1"))
            .unwrap()
            .contains("cannot order"));
        // Keeping it while raising the base is fine.
        assert!(spec("FUTURE:NO-SHA1", false)
            .change_refusal(&p("DEFAULT:NO-SHA1"))
            .is_none());
    }

    #[test]
    fn a_fips_host_is_never_changed() {
        for flag in [false, true] {
            let spec = PolicySpec::from_parts("DEFAULT", flag).unwrap();
            for current in ["FIPS", "FIPS:OSPP"] {
                let why = spec.change_refusal(&p(current)).unwrap();
                assert!(why.contains("fips-mode-setup"), "{why}");
            }
        }
    }

    #[test]
    fn definition_files_and_argv() {
        let spec = PolicySpec::from_parts("DEFAULT:NO-SHA1", false).unwrap();
        assert_eq!(spec.change_args(), ["--set", "DEFAULT:NO-SHA1"]);
        let files = spec.definition_files();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].0, "policy DEFAULT");
        assert_eq!(
            files[0].1,
            [
                "/usr/share/crypto-policies/policies/DEFAULT.pol",
                "/etc/crypto-policies/policies/DEFAULT.pol"
            ]
        );
        assert_eq!(files[1].0, "subpolicy NO-SHA1");
        assert_eq!(
            files[1].1,
            [
                "/usr/share/crypto-policies/policies/modules/NO-SHA1.pmod",
                "/etc/crypto-policies/policies/modules/NO-SHA1.pmod"
            ]
        );
    }

    #[test]
    fn show_output_is_one_policy_line_or_an_error() {
        assert_eq!(parse_show(b"DEFAULT\n").unwrap(), p("DEFAULT"));
        assert_eq!(parse_show(b"DEFAULT:NO-SHA1\n").unwrap().subs, ["NO-SHA1"]);
        assert_eq!(parse_show(b"FUTURE").unwrap(), p("FUTURE"));
        let cases: &[(&[u8], &str)] = &[
            (b"", "empty"),
            (b"\n", "empty"),
            (b"DEFAULT\nFUTURE\n", "more than one line"),
            (b"DEFAULT\n\n", "more than one line"),
            (b" DEFAULT\n", "not one policy name"),
            (b"DEFAULT \n", "not one policy name"),
            (b"default\n", "not one policy name"),
            (b"DEFAULT\r\n", "not one policy name"),
            (b"Error: something\n", "not one policy name"),
            (b"\xff\n", "UTF-8"),
        ];
        for (bytes, want) in cases {
            let e = parse_show(bytes).unwrap_err();
            assert!(
                e.contains(want),
                "{:?}: {e}",
                String::from_utf8_lossy(bytes)
            );
        }
    }
}
