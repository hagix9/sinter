//! The `systemd_timer` resource (DESIGN §42): what is specific to a timer.
//!
//! A timer is one unit file under `/etc/systemd/system` plus, optionally, the
//! enablement and activity of the unit `<name>.timer`. Nothing here talks to
//! a target. The engine runs the unit file through the `file` resource code
//! (content write, backup, diff, manager input and the automatic
//! daemon-reload) and the activation through the `service` resource code;
//! audit uses the matching `file` and `service` audits. This module holds the
//! parts that are only a timer's: the field rules, the deterministic unit
//! text, and the synthetic `file`/`service` resources the engine hands on.

use std::collections::BTreeMap;

use crate::error::{Result, SinterError};
use crate::model::FrozenResource;
use crate::value::Value;

/// Directory the unit file is written to (the administrator's unit
/// directory of the system manager).
pub const UNIT_DIR: &str = "/etc/systemd/system";

/// Unit suffixes a timer may activate (§28's unit types other than `timer`).
const TRIGGER_SUFFIXES: [&str; 7] = [
    "service",
    "socket",
    "target",
    "path",
    "mount",
    "automount",
    "swap",
];

/// Time-span units accepted by Sinter (a subset of systemd's grammar).
const SPAN_UNITS: [&str; 26] = [
    "us", "usec", "ms", "msec", "s", "sec", "second", "seconds", "m", "min", "minute", "minutes",
    "h", "hr", "hour", "hours", "d", "day", "days", "w", "week", "weeks", "M", "month", "months",
    "y",
];
const SPAN_UNITS_EXTRA: [&str; 2] = ["year", "years"];

/// The `with` fields of a `systemd_timer` (`model::SYSTEMD_TIMER_FIELDS`).
pub(crate) const FIELDS: &[&str] = crate::model::SYSTEMD_TIMER_FIELDS;

/// Requested activity of the timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerState {
    Running,
    Stopped,
    Absent,
}

/// A timer whose fields have all been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerSpec {
    pub name: String,
    pub unit: Option<String>,
    pub on_calendar: Vec<String>,
    pub on_boot_sec: Option<String>,
    pub on_unit_active_sec: Option<String>,
    pub persistent: Option<bool>,
    pub accuracy_sec: Option<String>,
    pub randomized_delay_sec: Option<String>,
    pub description: Option<String>,
    pub state: Option<TimerState>,
    pub enabled: Option<bool>,
}

/// `name`: 1–200 bytes of `[A-Za-z0-9:_.-]`, not starting with `.` or `-`,
/// and not itself ending in `.timer` (the suffix is added by Sinter).
pub fn valid_timer_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && !s.starts_with('.')
        && !s.starts_with('-')
        && !s.ends_with(".timer")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.' | b'-'))
}

/// `unit`: the same characters, ending in a unit suffix other than `timer`.
pub fn valid_triggered_unit(s: &str) -> bool {
    let Some((stem, suffix)) = s.rsplit_once('.') else {
        return false;
    };
    s.len() <= 256
        && TRIGGER_SUFFIXES.contains(&suffix)
        && !stem.is_empty()
        && !stem.starts_with('.')
        && !stem.starts_with('-')
        && stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.' | b'-'))
}

/// A time span: ASCII, at most 64 bytes, either a bare non-negative integer
/// (seconds) or one or more `<number><unit>` groups separated by optional
/// spaces. A number may have a fractional part. Nothing else of systemd's
/// grammar is accepted.
pub fn valid_time_span(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 || !s.is_ascii() || s.starts_with(' ') || s.ends_with(' ') {
        return false;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    let b = s.as_bytes();
    let mut i = 0;
    let mut groups = 0;
    while i < b.len() {
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
        if i < b.len() && b[i] == b'.' {
            i += 1;
            let frac = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i == frac {
                return false;
            }
        }
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        let u = i;
        while i < b.len() && b[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit = &s[u..i];
        if unit.is_empty() || !(SPAN_UNITS.contains(&unit) || SPAN_UNITS_EXTRA.contains(&unit)) {
            return false;
        }
        groups += 1;
    }
    groups > 0
}

/// Free text written into the unit (`OnCalendar=`, `Description=`): printable
/// ASCII without `\` (line continuation) and `%` (specifiers), no leading or
/// trailing space, and within `max` bytes.
fn valid_unit_text(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && !s.starts_with(' ')
        && !s.ends_with(' ')
        && s.bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'\\' && b != b'%')
}

/// One `on_calendar` expression (checked again on the target, §42.4).
pub fn valid_calendar(s: &str) -> bool {
    valid_unit_text(s, 128) && !s.starts_with('-')
}

pub fn valid_description(s: &str) -> bool {
    valid_unit_text(s, 256)
}

/// The unit file path of a timer.
pub fn unit_path(name: &str) -> String {
    format!("{}/{}.timer", UNIT_DIR, name)
}

/// The systemd unit name of a timer.
pub fn timer_unit(name: &str) -> String {
    format!("{}.timer", name)
}

/// Whether a value is a string with an interpolation (`{{ ... }}`), which is
/// checked only once evaluated.
fn interpolated(v: &Value) -> bool {
    matches!(v, Value::Str(s) if crate::expressions::has_interpolation(s))
}

fn bad(ctx: &str, msg: &str) -> SinterError {
    SinterError::schema(format!("{}: systemd_timer {}", ctx, msg))
}

impl TimerSpec {
    /// Check the fields. With `literal_only`, a string field that still holds
    /// an interpolation is accepted unchecked (it is checked again once
    /// evaluated, with `literal_only = false`); every other rule applies.
    pub fn check(
        map: &BTreeMap<String, Value>,
        ctx: &str,
        literal_only: bool,
    ) -> Result<Option<TimerSpec>> {
        for k in map.keys() {
            if !FIELDS.contains(&k.as_str()) {
                return Err(bad(ctx, &format!("has unknown field {}", k)));
            }
        }
        let mut deferred = false;
        let mut text = |key: &str, check: fn(&str) -> bool, what: &str| -> Result<Option<String>> {
            match map.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(v) if literal_only && interpolated(v) => {
                    deferred = true;
                    Ok(Some(String::new()))
                }
                Some(Value::Str(s)) if check(s) => Ok(Some(s.clone())),
                Some(Value::Str(_)) => Err(bad(ctx, &format!("{} is not {}", key, what))),
                Some(other) => Err(bad(
                    ctx,
                    &format!("{} must be a string, got {}", key, other.type_name()),
                )),
            }
        };
        let name = text("name", valid_timer_name, "a valid timer name ([A-Za-z0-9:_.-], 1-200 bytes, not starting with . or -, without .timer)")?
            .ok_or_else(|| bad(ctx, "requires name"))?;
        let unit = text(
            "unit",
            valid_triggered_unit,
            "a unit name with a suffix other than .timer",
        )?;
        let span = "a time span (an integer, or groups like 5min or 1h 30m)";
        let on_boot_sec = text("on_boot_sec", valid_time_span, span)?;
        let on_unit_active_sec = text("on_unit_active_sec", valid_time_span, span)?;
        let accuracy_sec = text("accuracy_sec", valid_time_span, span)?;
        let randomized_delay_sec = text("randomized_delay_sec", valid_time_span, span)?;
        let description = text(
            "description",
            valid_description,
            "1-256 bytes of printable ASCII without \\ or %, without leading or trailing space",
        )?;
        let mut state_deferred = false;
        let state = match map.get("state") {
            None | Some(Value::Null) => None,
            Some(v) if literal_only && interpolated(v) => {
                deferred = true;
                state_deferred = true;
                None
            }
            Some(Value::Str(s)) => Some(match s.as_str() {
                "running" => TimerState::Running,
                "stopped" => TimerState::Stopped,
                "absent" => TimerState::Absent,
                _ => return Err(bad(ctx, "state must be running, stopped or absent")),
            }),
            Some(_) => return Err(bad(ctx, "state must be running, stopped or absent")),
        };
        let boolean = |key: &str, deferred: &mut bool| -> Result<Option<bool>> {
            match map.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Bool(b)) => Ok(Some(*b)),
                Some(v) if literal_only && interpolated(v) => {
                    *deferred = true;
                    Ok(Some(false))
                }
                Some(_) => Err(bad(ctx, &format!("{} must be a boolean", key))),
            }
        };
        let persistent = boolean("persistent", &mut deferred)?;
        let enabled = boolean("enabled", &mut deferred)?;
        let on_calendar = match map.get("on_calendar") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Str(s)) if literal_only && interpolated(&Value::Str(s.clone())) => {
                deferred = true;
                vec![String::new()]
            }
            Some(Value::Str(s)) => vec![s.clone()],
            Some(Value::List(items)) => {
                if items.is_empty() {
                    return Err(bad(ctx, "on_calendar must not be an empty list"));
                }
                let mut out = Vec::new();
                for v in items {
                    match v {
                        Value::Str(s)
                            if literal_only && crate::expressions::has_interpolation(s) =>
                        {
                            deferred = true;
                            out.push(String::new());
                        }
                        Value::Str(s) => out.push(s.clone()),
                        _ => {
                            return Err(bad(
                                ctx,
                                "on_calendar must be a string or a list of strings",
                            ))
                        }
                    }
                }
                out
            }
            Some(_) => {
                return Err(bad(
                    ctx,
                    "on_calendar must be a string or a list of strings",
                ))
            }
        };
        for c in &on_calendar {
            if !(c.is_empty() && literal_only) && !valid_calendar(c) {
                return Err(bad(
                    ctx,
                    "on_calendar entries must be 1-128 bytes of printable ASCII without \\ or %, without leading or trailing space, not starting with -",
                ));
            }
        }
        if state == Some(TimerState::Absent) {
            if let Some(other) = map.keys().find(|k| *k != "name" && *k != "state") {
                return Err(bad(
                    ctx,
                    &format!("state absent allows only name, not {}", other),
                ));
            }
        } else if !state_deferred
            && on_calendar.is_empty()
            && on_boot_sec.is_none()
            && on_unit_active_sec.is_none()
        {
            return Err(bad(
                ctx,
                "requires at least one of on_calendar, on_boot_sec, on_unit_active_sec",
            ));
        }
        if persistent.is_some() && on_calendar.is_empty() {
            return Err(bad(ctx, "persistent requires on_calendar"));
        }
        if deferred {
            return Ok(None);
        }
        Ok(Some(TimerSpec {
            name,
            unit,
            on_calendar,
            on_boot_sec,
            on_unit_active_sec,
            persistent,
            accuracy_sec,
            randomized_delay_sec,
            description,
            state,
            enabled,
        }))
    }

    /// The unit the timer activates.
    pub fn triggered_unit(&self) -> String {
        self.unit
            .clone()
            .unwrap_or_else(|| format!("{}.service", self.name))
    }

    /// Whether the timer's activation is managed in a way that needs the
    /// triggered unit to exist.
    pub fn needs_trigger_unit(&self) -> bool {
        self.state == Some(TimerState::Running) || self.enabled == Some(true)
    }

    /// The unit file text (DESIGN §42.3): fixed key order, `\n` line ends,
    /// one trailing newline.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str("# Managed by Sinter (systemd_timer). Local changes are replaced.\n");
        s.push_str("[Unit]\n");
        match &self.description {
            Some(d) => s.push_str(&format!("Description={}\n", d)),
            None => s.push_str(&format!("Description=Sinter timer {}\n", self.name)),
        }
        s.push_str("\n[Timer]\n");
        for c in &self.on_calendar {
            s.push_str(&format!("OnCalendar={}\n", c));
        }
        if let Some(v) = &self.on_boot_sec {
            s.push_str(&format!("OnBootSec={}\n", v));
        }
        if let Some(v) = &self.on_unit_active_sec {
            s.push_str(&format!("OnUnitActiveSec={}\n", v));
        }
        if let Some(p) = self.persistent {
            s.push_str(&format!("Persistent={}\n", p));
        }
        if let Some(v) = &self.accuracy_sec {
            s.push_str(&format!("AccuracySec={}\n", v));
        }
        if let Some(v) = &self.randomized_delay_sec {
            s.push_str(&format!("RandomizedDelaySec={}\n", v));
        }
        if let Some(u) = &self.unit {
            s.push_str(&format!("Unit={}\n", u));
        }
        s.push_str("\n[Install]\nWantedBy=timers.target\n");
        s
    }

    /// The synthetic `file` resource for the unit file (`state` present, or
    /// absent for `state: absent`). It carries the timer's id, origin and
    /// sensitivity so results, backups and diagnostics name the timer.
    pub fn file_part(&self, res: &FrozenResource) -> FrozenResource {
        let mut f = res.clone();
        f.type_ = "file".to_string();
        f.notify = Vec::new();
        f.depends_on = Vec::new();
        f.when = None;
        f.register = None;
        f.service_name = None;
        let path = unit_path(&self.name);
        f.path = Some(path.clone());
        let mut with = BTreeMap::new();
        with.insert("path".to_string(), Value::Str(path));
        if self.state == Some(TimerState::Absent) {
            with.insert("state".to_string(), Value::Str("absent".to_string()));
        } else {
            with.insert("state".to_string(), Value::Str("present".to_string()));
            with.insert("content".to_string(), Value::Str(self.render()));
            with.insert("owner".to_string(), Value::Str("root".to_string()));
            with.insert("group".to_string(), Value::Str("root".to_string()));
            with.insert("mode".to_string(), Value::Str("0644".to_string()));
        }
        f.with = with;
        f
    }

    /// The synthetic `service` resource for the timer unit's activation, or
    /// `None` when neither `state` nor `enabled` is managed. `state: absent`
    /// stops and disables first (the unit file is removed afterwards).
    pub fn service_part(&self, res: &FrozenResource) -> Option<FrozenResource> {
        let (state, enabled) = match self.state {
            Some(TimerState::Absent) => (Some("stopped"), Some(false)),
            Some(TimerState::Running) => (Some("running"), self.enabled),
            Some(TimerState::Stopped) => (Some("stopped"), self.enabled),
            None => (None, self.enabled),
        };
        if state.is_none() && enabled.is_none() {
            return None;
        }
        let mut s = res.clone();
        s.type_ = "service".to_string();
        s.notify = Vec::new();
        s.depends_on = Vec::new();
        s.when = None;
        s.register = None;
        s.path = None;
        s.service_name = Some(timer_unit(&self.name));
        let mut with = BTreeMap::new();
        if let Some(st) = state {
            with.insert("state".to_string(), Value::Str(st.to_string()));
        }
        if let Some(e) = enabled {
            with.insert("enabled".to_string(), Value::Bool(e));
        }
        s.with = with;
        Some(s)
    }
}

/// What `systemctl show --property=FragmentPath,DropInPaths -- <unit>`
/// reported, checked strictly (each property exactly once).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitFiles {
    pub fragment_path: String,
    pub drop_in_paths: String,
}

/// Parse the answer to the FragmentPath/DropInPaths observation.
pub fn parse_unit_files(stdout: &str) -> std::result::Result<UnitFiles, String> {
    let mut fragment: Option<String> = None;
    let mut dropins: Option<String> = None;
    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err("unexpected line in unit file observation".into());
        };
        let slot = match k {
            "FragmentPath" => &mut fragment,
            "DropInPaths" => &mut dropins,
            _ => {
                return Err(format!(
                    "unexpected property {} in unit file observation",
                    k
                ))
            }
        };
        if slot.replace(v.to_string()).is_some() {
            return Err(format!("property {} reported twice", k));
        }
    }
    match (fragment, dropins) {
        (Some(f), Some(d)) => Ok(UnitFiles {
            fragment_path: f,
            drop_in_paths: d,
        }),
        _ => Err("unit file observation lacks FragmentPath or DropInPaths".into()),
    }
}

/// The reason a timer must not be touched, from its unit files and its
/// `UnitFileState`, or `None` when Sinter may manage it (DESIGN §42.3, §42.5).
pub fn refusal(name: &str, files: &UnitFiles, unit_file_state: &str) -> Option<String> {
    if unit_file_state == "masked" {
        return Some(format!(
            "timer {} is masked; Sinter does not unmask units",
            timer_unit(name)
        ));
    }
    let own = unit_path(name);
    if !files.fragment_path.is_empty() && files.fragment_path != own {
        return Some(format!(
            "a unit file for {} exists outside {} ({}); Sinter does not shadow or remove it",
            timer_unit(name),
            UNIT_DIR,
            files.fragment_path
        ));
    }
    if !files.drop_in_paths.trim().is_empty() {
        return Some(format!(
            "timer {} has drop-ins ({}); Sinter does not manage drop-ins",
            timer_unit(name),
            files.drop_in_paths.trim()
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }
    fn s(v: &str) -> Value {
        Value::Str(v.to_string())
    }

    #[test]
    fn time_spans() {
        for ok in [
            "0", "30", "5min", "1h 30m", "1h30m", "2.5s", "1 week", "3 years", "10 us",
        ] {
            assert!(valid_time_span(ok), "{ok}");
        }
        for bad in [
            "",
            " 5min",
            "5min ",
            "5 parsecs",
            "min",
            "1.h",
            "-5s",
            "5s;rm",
            "1h\n",
            "1µs",
            "5%",
            "x5m",
        ] {
            assert!(!valid_time_span(bad), "{bad}");
        }
        assert!(!valid_time_span(&"1s ".repeat(30)));
    }

    #[test]
    fn names() {
        for ok in ["backup", "db-dump_1", "a.b", "x:y"] {
            assert!(valid_timer_name(ok), "{ok}");
        }
        for bad in [
            "", ".x", "-x", "a b", "a/b", "a@b", "a\\b", "x.timer", "../x",
        ] {
            assert!(!valid_timer_name(bad), "{bad}");
        }
        assert!(valid_triggered_unit("job.service"));
        assert!(!valid_triggered_unit("job.timer"));
        assert!(!valid_triggered_unit("job"));
        assert!(!valid_triggered_unit("-x.service"));
    }

    #[test]
    fn calendar_text() {
        assert!(valid_calendar("*-*-* 03:00:00"));
        assert!(valid_calendar("Mon..Fri 08:00"));
        for bad in [
            "", " daily", "daily ", "-1", "a\\", "50%", "daily\nx", "\tdaily",
        ] {
            assert!(!valid_calendar(bad), "{bad:?}");
        }
    }

    #[test]
    fn rules() {
        let ok = TimerSpec::check(
            &map(&[("name", s("t")), ("on_boot_sec", s("5min"))]),
            "r",
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(ok.triggered_unit(), "t.service");
        assert!(TimerSpec::check(&map(&[("name", s("t"))]), "r", false)
            .unwrap_err()
            .message
            .contains("requires at least one of"));
        assert!(TimerSpec::check(
            &map(&[
                ("name", s("t")),
                ("on_boot_sec", s("1m")),
                ("persistent", Value::Bool(true))
            ]),
            "r",
            false
        )
        .unwrap_err()
        .message
        .contains("persistent requires on_calendar"));
        assert!(TimerSpec::check(
            &map(&[
                ("name", s("t")),
                ("state", s("absent")),
                ("enabled", Value::Bool(false))
            ]),
            "r",
            false
        )
        .unwrap_err()
        .message
        .contains("allows only name"));
        let absent = TimerSpec::check(
            &map(&[("name", s("t")), ("state", s("absent"))]),
            "r",
            false,
        )
        .unwrap()
        .unwrap();
        assert_eq!(absent.state, Some(TimerState::Absent));
        assert!(TimerSpec::check(
            &map(&[("name", s("t")), ("on_calendar", Value::List(vec![]))]),
            "r",
            false
        )
        .is_err());
        assert!(TimerSpec::check(
            &map(&[
                ("name", s("t")),
                ("on_boot_sec", s("1m")),
                ("bogus", s("x"))
            ]),
            "r",
            false
        )
        .is_err());
        // A state from a variable may resolve to absent: the trigger rule is
        // judged once it is evaluated.
        assert!(TimerSpec::check(
            &map(&[("name", s("t")), ("state", s("{{ vars.st }}"))]),
            "r",
            true
        )
        .unwrap()
        .is_none());
        assert!(TimerSpec::check(
            &map(&[("name", s("t")), ("state", s("running"))]),
            "r",
            false
        )
        .is_err());
        // An interpolated field is checked later.
        assert!(TimerSpec::check(
            &map(&[("name", s("t")), ("on_calendar", s("{{ vars.when }}"))]),
            "r",
            true
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn render_is_deterministic_and_ordered() {
        let spec = TimerSpec::check(
            &map(&[
                ("name", s("backup")),
                ("unit", s("backup-run.service")),
                ("on_calendar", Value::List(vec![s("daily"), s("Sat 12:00")])),
                ("on_boot_sec", s("5min")),
                ("on_unit_active_sec", s("1h")),
                ("persistent", Value::Bool(true)),
                ("accuracy_sec", s("1min")),
                ("randomized_delay_sec", s("10min")),
                ("description", s("Nightly backup")),
            ]),
            "r",
            false,
        )
        .unwrap()
        .unwrap();
        let want = "# Managed by Sinter (systemd_timer). Local changes are replaced.\n[Unit]\nDescription=Nightly backup\n\n[Timer]\nOnCalendar=daily\nOnCalendar=Sat 12:00\nOnBootSec=5min\nOnUnitActiveSec=1h\nPersistent=true\nAccuracySec=1min\nRandomizedDelaySec=10min\nUnit=backup-run.service\n\n[Install]\nWantedBy=timers.target\n";
        assert_eq!(spec.render(), want);
        assert_eq!(spec.render(), spec.clone().render());
    }

    #[test]
    fn unit_file_observation_and_refusal() {
        let f =
            parse_unit_files("FragmentPath=/etc/systemd/system/t.timer\nDropInPaths=\n").unwrap();
        assert_eq!(refusal("t", &f, "enabled"), None);
        assert!(parse_unit_files("FragmentPath=a\n").is_err());
        assert!(parse_unit_files("FragmentPath=a\nFragmentPath=b\nDropInPaths=\n").is_err());
        assert!(parse_unit_files("FragmentPath=a\nDropInPaths=\nOther=x\n").is_err());
        let vendor =
            parse_unit_files("FragmentPath=/usr/lib/systemd/system/t.timer\nDropInPaths=\n")
                .unwrap();
        assert!(refusal("t", &vendor, "enabled")
            .unwrap()
            .contains("outside"));
        let dropin =
            parse_unit_files("FragmentPath=\nDropInPaths=/etc/systemd/system/t.timer.d/x.conf\n")
                .unwrap();
        assert!(refusal("t", &dropin, "").unwrap().contains("drop-ins"));
        let none = parse_unit_files("FragmentPath=\nDropInPaths=\n").unwrap();
        assert!(refusal("t", &none, "masked").unwrap().contains("masked"));
        assert_eq!(refusal("t", &none, ""), None);
    }
}
