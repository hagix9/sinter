//! `dnf_module`: the declared state of one DNF module (enabled with a
//! stream, disabled, or reset), the closed parser of DNF 4's own module
//! state file and the comparison between the two.
//!
//! Everything here is pure: no target is touched. The engine part
//! (`dnfmod_engine`) reads the state file, decides and runs `dnf module`.
//!
//! DNF 4 persists what `dnf module enable|disable|reset` decided in
//! `/etc/dnf/modules.d/<name>.module`, one INI section per module:
//!
//! ```text
//! [nodejs]
//! name=nodejs
//! stream=20
//! profiles=
//! state=enabled
//! ```
//!
//! The parser accepts exactly that shape and nothing else. A file it does
//! not fully understand is an observation error, never a guessed state.

use std::collections::BTreeMap;

use crate::error::{Result, SinterError};
use crate::value::Value;

/// `with` fields of a `dnf_module`. `env` is the same mutation-only field a
/// `package` has (it reaches `dnf module ...` only), including the
/// recipe-wide default.
pub const FIELDS: &[&str] = &["name", "stream", "state", "env"];

/// The directory DNF 4 keeps one `<name>.module` file per module in.
pub const MODULES_DIR: &str = "/etc/dnf/modules.d";

/// The package manager, as for `package`.
pub const DNF: &str = "/usr/bin/dnf";

/// Seconds a `dnf module` change may take (the `package` mutation's limit).
pub const TIMEOUT_SECS: u64 = 300;

const TOKEN_RULE: &str = "[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}";

/// A module name or a stream name: `[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}`.
/// It cannot start with `-` (an option), and holds no `/`, `:`, whitespace
/// or glob character, so it is safe as one argv word and as a file name.
pub fn valid_token(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    s.len() <= 64 && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-'))
}

/// What the recipe wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Desired {
    /// Enabled with exactly this stream.
    Enabled(String),
    Disabled,
    /// Neither enabled nor disabled: the distribution default.
    Reset,
}

/// A fully checked `dnf_module` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSpec {
    pub name: String,
    pub desired: Desired,
}

impl ModuleSpec {
    /// Build the spec from resolved values. The error text names no value
    /// (the caller decides whether values may be shown).
    pub fn from_parts(
        name: &str,
        stream: Option<&str>,
        state: &str,
    ) -> std::result::Result<Self, String> {
        if !valid_token(name) {
            return Err(format!("name is not a valid module name ({})", TOKEN_RULE));
        }
        if let Some(s) = stream {
            if !valid_token(s) {
                return Err(format!(
                    "stream is not a valid stream name ({})",
                    TOKEN_RULE
                ));
            }
        }
        let desired = match (state, stream) {
            ("enabled", Some(s)) => Desired::Enabled(s.to_string()),
            ("enabled", None) => return Err("stream is required when state is enabled".to_string()),
            ("disabled" | "reset", Some(_)) => {
                return Err(format!(
                    "stream is not allowed when state is {} (only an enabled module has a stream)",
                    state
                ))
            }
            ("disabled", None) => Desired::Disabled,
            ("reset", None) => Desired::Reset,
            _ => return Err("state must be enabled, disabled or reset".to_string()),
        };
        Ok(ModuleSpec {
            name: name.to_string(),
            desired,
        })
    }

    /// Load-time check of the written `with` map (DESIGN: schema error,
    /// exit 2). A string that still holds an interpolation is judged when
    /// the recipe is frozen (`name`, `stream` and `state` are static), so
    /// only literals are judged here; the cross-field rule is applied as
    /// soon as all three are literal.
    pub fn check_literals(with: &BTreeMap<String, Value>, ctx: &str) -> Result<()> {
        let literal = |key: &str| -> Result<Option<Option<String>>> {
            match with.get(key) {
                None | Some(Value::Null) => Ok(Some(None)),
                Some(Value::Str(s)) if crate::expressions::has_interpolation(s) => Ok(None),
                Some(Value::Str(s)) => Ok(Some(Some(s.clone()))),
                Some(Value::Int(_)) | Some(Value::Float(_)) if key == "stream" => {
                    Err(SinterError::schema(format!(
                        "{}: dnf_module stream must be a string; quote it (for example stream: \"20\")",
                        ctx
                    )))
                }
                Some(_) => Err(SinterError::schema(format!(
                    "{}: dnf_module {} must be a string",
                    ctx, key
                ))),
            }
        };
        let name = literal("name")?;
        let stream = literal("stream")?;
        let state = literal("state")?;
        if let Some(None) = state {
            return Err(SinterError::schema(format!(
                "{}: dnf_module state is required and must be enabled, disabled or reset",
                ctx
            )));
        }
        if let Some(Some(n)) = &name {
            if !valid_token(n) {
                return Err(SinterError::schema(format!(
                    "{}: dnf_module name is not a valid module name ({})",
                    ctx, TOKEN_RULE
                )));
            }
        }
        if let Some(Some(s)) = &stream {
            if !valid_token(s) {
                return Err(SinterError::schema(format!(
                    "{}: dnf_module stream is not a valid stream name ({})",
                    ctx, TOKEN_RULE
                )));
            }
        }
        if let Some(Some(s)) = &state {
            if !matches!(s.as_str(), "enabled" | "disabled" | "reset") {
                return Err(SinterError::schema(format!(
                    "{}: dnf_module state must be enabled, disabled or reset",
                    ctx
                )));
            }
        }
        if let (Some(Some(n)), Some(stream), Some(Some(state))) = (&name, &stream, &state) {
            Self::from_parts(n, stream.as_deref(), state)
                .map_err(|why| SinterError::schema(format!("{}: dnf_module {}", ctx, why)))?;
        }
        Ok(())
    }

    /// The spec of an evaluated resource (every value is known by then).
    pub fn from_values(vals: &BTreeMap<String, Value>, ctx: &str) -> Result<Self> {
        let text = |key: &str| -> Result<Option<String>> {
            match vals.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Str(s)) => Ok(Some(s.clone())),
                Some(_) => Err(SinterError::schema(format!(
                    "{}: dnf_module {} must be a string",
                    ctx, key
                ))),
            }
        };
        let name = text("name")?
            .ok_or_else(|| SinterError::schema(format!("{}: dnf_module name is required", ctx)))?;
        let stream = text("stream")?;
        let state = text("state")?
            .ok_or_else(|| SinterError::schema(format!("{}: dnf_module state is required", ctx)))?;
        Self::from_parts(&name, stream.as_deref(), &state)
            .map_err(|why| SinterError::schema(format!("{}: dnf_module {}", ctx, why)))
    }

    /// DNF 4's state file of this module.
    pub fn state_path(&self) -> String {
        format!("{}/{}.module", MODULES_DIR, self.name)
    }

    /// The fixed argv of the change, after the program [`DNF`].
    pub fn change_args(&self) -> Vec<String> {
        let (verb, operand) = match &self.desired {
            Desired::Enabled(stream) => ("enable", format!("{}:{}", self.name, stream)),
            Desired::Disabled => ("disable", self.name.clone()),
            Desired::Reset => ("reset", self.name.clone()),
        };
        vec![
            "-y".to_string(),
            "module".to_string(),
            verb.to_string(),
            operand,
        ]
    }

    /// The desired state in the words of the observation.
    pub fn desired_text(&self) -> String {
        match &self.desired {
            Desired::Enabled(s) => format!("state=enabled stream={}", s),
            Desired::Disabled => "state=disabled".to_string(),
            Desired::Reset => "state=default".to_string(),
        }
    }

    /// Every dimension in which the observation differs from the declared
    /// state: `(dimension, observed, desired)`. Empty means satisfied.
    pub fn drift(&self, obs: &Observed) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        let want = match &self.desired {
            Desired::Enabled(_) => ModuleState::Enabled,
            Desired::Disabled => ModuleState::Disabled,
            Desired::Reset => ModuleState::Default,
        };
        if obs.state != want {
            out.push((
                "state".to_string(),
                obs.state.label().to_string(),
                want.label().to_string(),
            ));
        }
        if let Desired::Enabled(stream) = &self.desired {
            if obs.stream != *stream {
                out.push((
                    "stream".to_string(),
                    if obs.stream.is_empty() {
                        "(none)".to_string()
                    } else {
                        obs.stream.clone()
                    },
                    stream.clone(),
                ));
            }
        }
        out
    }

    /// Why a needed change is refused before anything runs, if it is.
    /// Only asked when [`Self::drift`] is not empty.
    pub fn refusal(&self, obs: &Observed) -> Option<String> {
        match &self.desired {
            Desired::Enabled(stream)
                if obs.state == ModuleState::Enabled && obs.stream != *stream =>
            {
                Some(format!(
                    "module {} is enabled with stream {}; Sinter does not switch an enabled module stream to {}. Review the packages installed from the current stream, reset the module explicitly first (a dnf_module with state: reset in an earlier run), then enable the new stream",
                    self.name, obs.stream, stream
                ))
            }
            Desired::Disabled | Desired::Reset if !obs.profiles.is_empty() => Some(format!(
                "module {} has installed profiles ({}); removing or re-streaming their packages is a package decision Sinter does not make here, so the module is not {}",
                self.name,
                obs.profiles.join(", "),
                if self.desired == Desired::Disabled {
                    "disabled"
                } else {
                    "reset"
                }
            )),
            _ => None,
        }
    }
}

/// The module state DNF recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleState {
    /// No state file, or a state file whose `state` is empty or missing.
    Default,
    Enabled,
    Disabled,
}

impl ModuleState {
    pub fn label(self) -> &'static str {
        match self {
            ModuleState::Default => "default",
            ModuleState::Enabled => "enabled",
            ModuleState::Disabled => "disabled",
        }
    }
}

/// What the state file says about one module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub state: ModuleState,
    /// Empty when the file names no stream.
    pub stream: String,
    /// Installed profiles (`profiles=`), in file order.
    pub profiles: Vec<String>,
}

impl Observed {
    /// No state file: the module is in its default state.
    pub fn absent() -> Self {
        Observed {
            state: ModuleState::Default,
            stream: String::new(),
            profiles: Vec::new(),
        }
    }

    /// The observation in the words of [`ModuleSpec::desired_text`].
    pub fn text(&self) -> String {
        if self.stream.is_empty() {
            format!("state={}", self.state.label())
        } else {
            format!("state={} stream={}", self.state.label(), self.stream)
        }
    }
}

fn trim_blank(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

/// Parse `<name>.module` as DNF 4 writes it. Accepted: UTF-8 without NUL or
/// CR; empty lines; exactly one section `[<name>]`; under it the keys
/// `name`, `stream`, `profiles` and `state`, each at most once, as
/// `key=value` (blanks around the key and the value are dropped, as
/// libdnf's reader does). Everything else is refused with a reason: a
/// comment, another section, an unknown or repeated key, a continuation
/// line, a `name` that is not the module, a stream or profile that is not a
/// plain token, a `state` other than `enabled`, `disabled` or empty, and an
/// enabled module without a stream.
pub fn parse_state_file(name: &str, bytes: &[u8]) -> std::result::Result<Observed, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "it is not valid UTF-8".to_string())?;
    if text.contains('\0') {
        return Err("it contains a NUL byte".to_string());
    }
    if text.contains('\r') {
        return Err("it contains a carriage return (CRLF line ends are not accepted)".to_string());
    }
    let mut in_section = false;
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for (i, line) in text.split('\n').enumerate() {
        let n = i + 1;
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(format!(
                "line {} starts with a blank (continuation lines are not accepted)",
                n
            ));
        }
        if line.starts_with('#') || line.starts_with(';') {
            return Err(format!("line {} is a comment, which is not accepted", n));
        }
        if let Some(rest) = line.strip_prefix('[') {
            let id = rest
                .strip_suffix(']')
                .ok_or_else(|| format!("line {} is not a complete section header", n))?;
            if in_section {
                return Err(format!("line {} starts a second section", n));
            }
            if id != name {
                return Err(format!(
                    "line {} is a section for another module than {}",
                    n, name
                ));
            }
            in_section = true;
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {} is not key=value", n))?;
        if !in_section {
            return Err(format!("line {} comes before the section header", n));
        }
        let key = trim_blank(key);
        let value = trim_blank(value);
        if !matches!(key, "name" | "stream" | "profiles" | "state") {
            return Err(format!("line {} has a key Sinter does not know", n));
        }
        if seen.insert(key, value).is_some() {
            return Err(format!("line {} repeats the key {}", n, key));
        }
    }
    if !in_section {
        return Err(format!("it has no [{}] section", name));
    }
    if let Some(v) = seen.get("name") {
        if *v != name {
            return Err(format!("its name key is not {}", name));
        }
    }
    let stream = seen.get("stream").copied().unwrap_or("");
    if !stream.is_empty() && !valid_token(stream) {
        return Err("its stream is not a plain stream name".to_string());
    }
    let mut profiles = Vec::new();
    let raw_profiles = seen.get("profiles").copied().unwrap_or("");
    if !raw_profiles.is_empty() {
        for p in raw_profiles.split(',') {
            let p = trim_blank(p);
            if !valid_token(p) {
                return Err(
                    "its profiles are not a comma-separated list of plain names".to_string()
                );
            }
            profiles.push(p.to_string());
        }
    }
    let state = match seen.get("state").copied().unwrap_or("") {
        "" => ModuleState::Default,
        "enabled" => ModuleState::Enabled,
        "disabled" => ModuleState::Disabled,
        _ => return Err("its state is not enabled, disabled or empty".to_string()),
    };
    if state == ModuleState::Enabled && stream.is_empty() {
        return Err("it says enabled without a stream".to_string());
    }
    Ok(Observed {
        state,
        stream: stream.to_string(),
        profiles,
    })
}

/// The text the state file has after `dnf module` wrote it (the scripted
/// target and the tests use it; Sinter itself never writes this file).
pub fn render_state_file(name: &str, stream: &str, profiles: &str, state: &str) -> String {
    format!(
        "[{name}]\nname={name}\nstream={stream}\nprofiles={profiles}\nstate={state}\n",
        name = name,
        stream = stream,
        profiles = profiles,
        state = state
    )
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
    fn token_grammar_is_exact() {
        for ok in [
            "nodejs",
            "postgresql",
            "389-ds",
            "a",
            "A1_.+-",
            &"a".repeat(64),
        ] {
            assert!(valid_token(ok), "{ok}");
        }
        for bad in [
            "",
            "-y",
            ".hidden",
            "_x",
            "a b",
            "a:b",
            "a/b",
            "a*",
            "a\n",
            "é",
            &"a".repeat(65),
        ] {
            assert!(!valid_token(bad), "{bad:?}");
        }
    }

    #[test]
    fn spec_requires_a_stream_exactly_for_enabled() {
        assert_eq!(
            ModuleSpec::from_parts("nodejs", Some("20"), "enabled")
                .unwrap()
                .desired,
            Desired::Enabled("20".into())
        );
        assert!(ModuleSpec::from_parts("nodejs", None, "enabled")
            .unwrap_err()
            .contains("stream is required"));
        for state in ["disabled", "reset"] {
            assert!(ModuleSpec::from_parts("nodejs", None, state).is_ok());
            assert!(ModuleSpec::from_parts("nodejs", Some("20"), state)
                .unwrap_err()
                .contains("not allowed"));
        }
        assert!(ModuleSpec::from_parts("nodejs", None, "present").is_err());
        assert!(ModuleSpec::from_parts("-x", None, "reset").is_err());
        assert!(ModuleSpec::from_parts("nodejs", Some("a:b"), "enabled").is_err());
    }

    #[test]
    fn change_argv_is_fixed() {
        let argv = |stream: Option<&str>, state: &str| {
            ModuleSpec::from_parts("nodejs", stream, state)
                .unwrap()
                .change_args()
        };
        assert_eq!(
            argv(Some("20"), "enabled"),
            ["-y", "module", "enable", "nodejs:20"]
        );
        assert_eq!(
            argv(None, "disabled"),
            ["-y", "module", "disable", "nodejs"]
        );
        assert_eq!(argv(None, "reset"), ["-y", "module", "reset", "nodejs"]);
    }

    #[test]
    fn literals_are_checked_at_load() {
        let ok = with(&[
            ("name", s("nodejs")),
            ("stream", s("20")),
            ("state", s("enabled")),
        ]);
        assert!(ModuleSpec::check_literals(&ok, "r").is_ok());
        let cases: Vec<(BTreeMap<String, Value>, &str)> = vec![
            (
                with(&[("name", s("nodejs")), ("state", s("enabled"))]),
                "stream is required",
            ),
            (
                with(&[
                    ("name", s("nodejs")),
                    ("stream", Value::Int(20)),
                    ("state", s("enabled")),
                ]),
                "quote it",
            ),
            (
                with(&[
                    ("name", s("nodejs")),
                    ("stream", s("20")),
                    ("state", s("reset")),
                ]),
                "not allowed",
            ),
            (with(&[("name", s("nodejs"))]), "state is required"),
            (
                with(&[("name", s("node js")), ("state", s("reset"))]),
                "valid module name",
            ),
            (
                with(&[("name", s("nodejs")), ("state", s("installed"))]),
                "enabled, disabled or reset",
            ),
            (
                with(&[("name", s("nodejs")), ("state", Value::Bool(true))]),
                "must be a string",
            ),
        ];
        for (w, want) in cases {
            let e = ModuleSpec::check_literals(&w, "r").unwrap_err();
            assert_eq!(e.kind, crate::error::ErrorKind::Schema);
            assert!(e.message.contains(want), "{want}: {}", e.message);
        }
        // An interpolated value is left to the freeze step.
        let later = with(&[
            ("name", s("{{ vars.module }}")),
            ("stream", s("20")),
            ("state", s("reset")),
        ]);
        assert!(ModuleSpec::check_literals(&later, "r").is_ok());
    }

    #[test]
    fn parses_the_file_dnf_writes() {
        let o = parse_state_file(
            "nodejs",
            b"[nodejs]\nname=nodejs\nstream=20\nprofiles=\nstate=enabled\n",
        )
        .unwrap();
        assert_eq!(o.state, ModuleState::Enabled);
        assert_eq!(o.stream, "20");
        assert!(o.profiles.is_empty());

        let o = parse_state_file(
            "nodejs",
            b"[nodejs]\nname=nodejs\nstream=\nprofiles=\nstate=disabled\n\n",
        )
        .unwrap();
        assert_eq!(o.state, ModuleState::Disabled);
        assert_eq!(o.stream, "");

        let o = parse_state_file(
            "postgresql",
            b"[postgresql]\nname = postgresql\nstream = 16\nprofiles = server, client\nstate = enabled\n",
        )
        .unwrap();
        assert_eq!(o.profiles, ["server", "client"]);
        assert_eq!(o.text(), "state=enabled stream=16");
    }

    #[test]
    fn an_empty_or_missing_state_is_the_default() {
        for body in [
            "[nodejs]\nname=nodejs\nstream=\nprofiles=\nstate=\n",
            "[nodejs]\nname=nodejs\nstream=18\nprofiles=\n",
            "[nodejs]\n",
        ] {
            let o = parse_state_file("nodejs", body.as_bytes()).unwrap();
            assert_eq!(o.state, ModuleState::Default, "{body:?}");
        }
        assert_eq!(Observed::absent().state, ModuleState::Default);
    }

    #[test]
    fn everything_else_is_refused_not_guessed() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "no [nodejs] section"),
            (b"\n\n", "no [nodejs] section"),
            (b"[nodejs]\r\nstate=enabled\r\n", "carriage return"),
            (b"[nodejs]\nstate=enabled\0\n", "NUL"),
            (b"[nodejs]\nstate=\xff\n", "UTF-8"),
            (b"[other]\nstate=enabled\nstream=1\n", "another module"),
            (
                b"[nodejs]\nstate=enabled\nstream=20\n[other]\nstate=disabled\n",
                "second section",
            ),
            (
                b"[nodejs]\nstate=enabled\nstream=20\n[nodejs]\n",
                "second section",
            ),
            (b"[nodejs\nstate=enabled\n", "complete section header"),
            (b"state=enabled\n[nodejs]\n", "before the section"),
            (b"[nodejs]\nstate=enabled\nstate=disabled\n", "repeats"),
            (b"[nodejs]\nversion=1\nstate=enabled\n", "does not know"),
            (b"[nodejs]\nenabled=1\n", "does not know"),
            (b"[nodejs]\n# note\nstate=enabled\n", "comment"),
            (b"[nodejs]\n; note\n", "comment"),
            (b"[nodejs]\nstate=enabled\n stream=20\n", "continuation"),
            (b"[nodejs]\nstate\n", "not key=value"),
            (b"[nodejs]\nname=other\nstate=disabled\n", "name key"),
            (b"[nodejs]\nstate=installed\n", "enabled, disabled or empty"),
            (b"[nodejs]\nstate=1\n", "enabled, disabled or empty"),
            (
                b"[nodejs]\nstate=Enabled\nstream=20\n",
                "enabled, disabled or empty",
            ),
            (b"[nodejs]\nstate=enabled\n", "without a stream"),
            (b"[nodejs]\nstate=enabled\nstream=\n", "without a stream"),
            (
                b"[nodejs]\nstate=enabled\nstream=2 0\n",
                "plain stream name",
            ),
            (
                b"[nodejs]\nstate=enabled\nstream=20\nprofiles=a,,b\n",
                "profiles",
            ),
            (
                b"[nodejs]\nstate=enabled\nstream=20\nprofiles=a/b\n",
                "profiles",
            ),
        ];
        for (bytes, want) in cases {
            let e = parse_state_file("nodejs", bytes).unwrap_err();
            assert!(
                e.contains(want),
                "{:?}: {e}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    fn obs(state: ModuleState, stream: &str, profiles: &[&str]) -> Observed {
        Observed {
            state,
            stream: stream.to_string(),
            profiles: profiles.iter().map(|p| p.to_string()).collect(),
        }
    }

    #[test]
    fn mapping_between_desired_and_observed() {
        let enabled = ModuleSpec::from_parts("nodejs", Some("20"), "enabled").unwrap();
        let disabled = ModuleSpec::from_parts("nodejs", None, "disabled").unwrap();
        let reset = ModuleSpec::from_parts("nodejs", None, "reset").unwrap();

        assert!(enabled
            .drift(&obs(ModuleState::Enabled, "20", &[]))
            .is_empty());
        assert_eq!(
            enabled.drift(&obs(ModuleState::Enabled, "18", &[])),
            [("stream".to_string(), "18".to_string(), "20".to_string())]
        );
        assert_eq!(
            enabled.drift(&Observed::absent()),
            [
                (
                    "state".to_string(),
                    "default".to_string(),
                    "enabled".to_string()
                ),
                ("stream".to_string(), "(none)".to_string(), "20".to_string())
            ]
        );
        assert_eq!(enabled.drift(&obs(ModuleState::Disabled, "", &[])).len(), 2);

        assert!(disabled
            .drift(&obs(ModuleState::Disabled, "", &[]))
            .is_empty());
        assert_eq!(
            disabled.drift(&obs(ModuleState::Enabled, "20", &[])),
            [(
                "state".to_string(),
                "enabled".to_string(),
                "disabled".to_string()
            )]
        );

        assert!(reset.drift(&Observed::absent()).is_empty());
        // A reset module may keep a stream text; only the state decides.
        assert!(reset
            .drift(&obs(ModuleState::Default, "18", &[]))
            .is_empty());
        assert_eq!(
            reset.drift(&obs(ModuleState::Disabled, "", &[])),
            [(
                "state".to_string(),
                "disabled".to_string(),
                "default".to_string()
            )]
        );
    }

    #[test]
    fn refusals_are_the_stream_switch_and_installed_profiles() {
        let enabled = ModuleSpec::from_parts("nodejs", Some("20"), "enabled").unwrap();
        let disabled = ModuleSpec::from_parts("nodejs", None, "disabled").unwrap();
        let reset = ModuleSpec::from_parts("nodejs", None, "reset").unwrap();

        let why = enabled
            .refusal(&obs(ModuleState::Enabled, "18", &[]))
            .unwrap();
        assert!(why.contains("does not switch"), "{why}");
        assert!(why.contains("state: reset"), "{why}");
        // Enabling from the default or from disabled is not a switch.
        assert!(enabled.refusal(&Observed::absent()).is_none());
        assert!(enabled
            .refusal(&obs(ModuleState::Disabled, "", &[]))
            .is_none());
        assert!(enabled
            .refusal(&obs(ModuleState::Default, "18", &[]))
            .is_none());

        for spec in [&disabled, &reset] {
            let why = spec
                .refusal(&obs(ModuleState::Enabled, "20", &["common"]))
                .unwrap();
            assert!(why.contains("installed profiles (common)"), "{why}");
            assert!(spec
                .refusal(&obs(ModuleState::Enabled, "20", &[]))
                .is_none());
        }
    }

    #[test]
    fn rendered_file_round_trips() {
        let text = render_state_file("nodejs", "20", "", "enabled");
        let o = parse_state_file("nodejs", text.as_bytes()).unwrap();
        assert_eq!(o, obs(ModuleState::Enabled, "20", &[]));
    }
}
