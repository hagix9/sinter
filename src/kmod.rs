//! `kernel_module`: one kernel module, loaded now and at boot, or kept out
//! of alias-based autoloading, through files of Sinter's own in
//! `/etc/modules-load.d` and `/etc/modprobe.d` and `modprobe`.
//!
//! Everything here is pure: the name grammar, the files Sinter writes, the
//! fixed argv of the two `modprobe` calls. The engine part (`kmod_engine`)
//! observes and changes.

use std::collections::BTreeMap;

use crate::error::{Result, SinterError};
use crate::model::FrozenResource;
use crate::value::Value;

/// `with` fields of a `kernel_module`.
pub const FIELDS: &[&str] = &["name", "state", "runtime", "persist"];

/// The one program this type runs.
pub const TOOL: &str = "/usr/sbin/modprobe";

/// Where the boot-time load list lives.
pub const LOAD_DIR: &str = "/etc/modules-load.d";

/// Where the blacklist lives.
pub const BLACKLIST_DIR: &str = "/etc/modprobe.d";

/// Where the running kernel lists its modules.
pub const SYS_MODULE: &str = "/sys/module";

/// Where module files live; a planned change below one of them may provide
/// a module.
pub const MODULE_TREES: &[&str] = &["/lib/modules", "/usr/lib/modules"];

/// First line of every file Sinter writes.
pub const HEADER: &str = "# Managed by Sinter (kernel_module). Local changes are replaced.\n";

/// Longest accepted module name, in bytes.
pub const MAX_NAME: usize = 64;

/// Seconds `modprobe` may take.
pub const TIMEOUT_SECS: u64 = 120;

/// Carried by a result that changes the boot-time file.
pub const BOOT_NOTE: &str = "the boot-time setting is Sinter's own file; other files in /etc/modules-load.d and /etc/modprobe.d (a blacklist or install line elsewhere) and the kernel command line are not evaluated, and the state after a reboot is not verified";

/// Carried by a result of `state: absent` that removes the file.
pub const ABSENT_NOTE: &str = "only Sinter's boot-time file is removed; the module is not unloaded (Sinter never runs modprobe -r) and stays loaded until a reboot";

/// Carried by a result of `state: blacklisted` that changes a file.
pub const BLACKLIST_NOTE: &str = "the module is not unloaded (Sinter never runs modprobe -r) and stays loaded until a reboot; after a reboot it can still be loaded explicitly or as a dependency of another module: blacklist only stops alias-based autoloading";

/// Carried by a result that changes the boot-time file while the loaded
/// state is not managed.
pub const NOT_RUNNING_NOTE: &str =
    "the module is not loaded now (runtime: false); the file takes effect at the next boot";

/// What a `kernel_module` declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModState {
    /// Loaded now (`runtime`) and at boot (`persist`); Sinter's blacklist
    /// file for it absent.
    Present,
    /// Sinter's boot-time file absent; the module is not unloaded.
    Absent,
    /// Sinter's blacklist file present and its boot-time file absent; the
    /// module is not unloaded.
    Blacklisted,
}

/// Whether `s` is a module name: `[A-Za-z0-9_-]{1,64}`.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The form a module name is compared, written and loaded in: `-` and `_`
/// are the same module to the kernel, so every `-` becomes `_`.
pub fn normalize(name: &str) -> String {
    name.replace('-', "_")
}

/// Sinter's boot-time file for a (normalized) module.
pub fn load_path(name: &str) -> String {
    format!("{}/sinter-{}.conf", LOAD_DIR, name)
}

/// Sinter's blacklist file for a (normalized) module.
pub fn blacklist_path(name: &str) -> String {
    format!("{}/sinter-blacklist-{}.conf", BLACKLIST_DIR, name)
}

/// Where the running kernel shows a (normalized) loaded module.
pub fn sys_path(name: &str) -> String {
    format!("{}/{}", SYS_MODULE, name)
}

/// Every path a module's resource owns, whatever its state (§59).
pub fn owned_paths(name: &str) -> Vec<String> {
    vec![load_path(name), blacklist_path(name)]
}

/// A fully checked `kernel_module` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSpec {
    /// Normalized (`_`).
    pub name: String,
    pub state: ModState,
    /// Load it now (only with `present`).
    pub runtime: bool,
    /// Keep Sinter's boot-time file (only with `present`).
    pub persist: bool,
}

fn bad(ctx: &str, msg: &str) -> SinterError {
    SinterError::schema(format!("{}: kernel_module {}", ctx, msg))
}

fn literal_bool(with: &BTreeMap<String, Value>, key: &str, ctx: &str) -> Result<Option<bool>> {
    match with.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(bad(
            ctx,
            &format!("{} must be a literal boolean (true or false)", key),
        )),
    }
}

/// `state` as written: only a literal, so what the resource does is
/// visible in the recipe text.
fn literal_state(with: &BTreeMap<String, Value>, ctx: &str) -> Result<ModState> {
    match with.get("state") {
        None | Some(Value::Null) => Ok(ModState::Present),
        Some(Value::Str(s)) if s == "present" => Ok(ModState::Present),
        Some(Value::Str(s)) if s == "absent" => Ok(ModState::Absent),
        Some(Value::Str(s)) if s == "blacklisted" => Ok(ModState::Blacklisted),
        Some(_) => Err(bad(
            ctx,
            "state must be the literal present, absent or blacklisted",
        )),
    }
}

impl ModuleSpec {
    /// The rules that do not depend on the evaluated `name`. Returns
    /// `(state, runtime, persist)`.
    fn flags(with: &BTreeMap<String, Value>, ctx: &str) -> Result<(ModState, bool, bool)> {
        let state = literal_state(with, ctx)?;
        let runtime = literal_bool(with, "runtime", ctx)?;
        let persist = literal_bool(with, "persist", ctx)?;
        if state != ModState::Present {
            for (key, given) in [
                ("runtime", runtime.is_some()),
                ("persist", persist.is_some()),
            ] {
                if given {
                    return Err(bad(
                        ctx,
                        &format!(
                            "{} is accepted only with state: present (absent and blacklisted manage Sinter's files only and never unload a module)",
                            key
                        ),
                    ));
                }
            }
            return Ok((state, false, false));
        }
        let (runtime, persist) = (runtime.unwrap_or(true), persist.unwrap_or(true));
        if !runtime && !persist {
            return Err(bad(
                ctx,
                "runtime and persist are both false: nothing would be managed",
            ));
        }
        Ok((state, runtime, persist))
    }

    /// The name rule, as a schema error.
    pub fn check_name(name: &str, ctx: &str) -> Result<()> {
        if valid_name(name) {
            return Ok(());
        }
        Err(bad(
            ctx,
            "name is not a module name ([A-Za-z0-9_-], 1 to 64 bytes)",
        ))
    }

    /// Load-time check of the written `with` map (schema error, exit 2). A
    /// `name` that still holds an interpolation is judged once resolved.
    pub fn check_literals(with: &BTreeMap<String, Value>, ctx: &str) -> Result<()> {
        Self::flags(with, ctx)?;
        match with.get("name") {
            None | Some(Value::Null) => Err(bad(ctx, "name is required")),
            Some(Value::Str(s)) if crate::expressions::has_interpolation(s) => Ok(()),
            Some(Value::Str(s)) => Self::check_name(s, ctx),
            Some(_) => Err(bad(ctx, "name must be a string")),
        }
    }

    /// The spec of an evaluated resource.
    pub fn from_values(vals: &BTreeMap<String, Value>, ctx: &str) -> Result<Self> {
        let (state, runtime, persist) = Self::flags(vals, ctx)?;
        let name = match vals.get("name") {
            Some(Value::Str(s)) => {
                Self::check_name(s, ctx)?;
                normalize(s)
            }
            _ => return Err(bad(ctx, "name must be a string")),
        };
        Ok(ModuleSpec {
            name,
            state,
            runtime,
            persist,
        })
    }

    /// The exact content of Sinter's boot-time file.
    pub fn render_load(&self) -> String {
        format!("{}{}\n", HEADER, self.name)
    }

    /// The exact content of Sinter's blacklist file.
    pub fn render_blacklist(&self) -> String {
        format!("{}blacklist {}\n", HEADER, self.name)
    }

    fn file_part(res: &FrozenResource, path: String, content: Option<String>) -> FrozenResource {
        let mut f = res.clone();
        f.type_ = "file".to_string();
        f.notify = Vec::new();
        f.depends_on = Vec::new();
        f.when = None;
        f.register = None;
        f.path = Some(path.clone());
        let mut with = BTreeMap::new();
        with.insert("path".to_string(), Value::Str(path));
        match content {
            None => {
                with.insert("state".to_string(), Value::Str("absent".to_string()));
            }
            Some(c) => {
                with.insert("state".to_string(), Value::Str("present".to_string()));
                with.insert("content".to_string(), Value::Str(c));
                with.insert("owner".to_string(), Value::Str("root".to_string()));
                with.insert("group".to_string(), Value::Str("root".to_string()));
                with.insert("mode".to_string(), Value::Str("0644".to_string()));
            }
        }
        f.with = with;
        f
    }

    /// The synthetic `file` resource for Sinter's boot-time file: present
    /// with `present` (and `persist`), absent otherwise. `None` when the
    /// file is not managed (`present` with `persist: false`).
    pub fn load_part(&self, res: &FrozenResource) -> Option<FrozenResource> {
        match self.state {
            ModState::Present if !self.persist => None,
            ModState::Present => Some(Self::file_part(
                res,
                load_path(&self.name),
                Some(self.render_load()),
            )),
            ModState::Absent | ModState::Blacklisted => {
                Some(Self::file_part(res, load_path(&self.name), None))
            }
        }
    }

    /// The synthetic `file` resource for Sinter's blacklist file: present
    /// with `blacklisted`, absent with `present`. `None` with `absent`
    /// (the blacklist file is not managed then).
    pub fn blacklist_part(&self, res: &FrozenResource) -> Option<FrozenResource> {
        match self.state {
            ModState::Present => Some(Self::file_part(res, blacklist_path(&self.name), None)),
            ModState::Blacklisted => Some(Self::file_part(
                res,
                blacklist_path(&self.name),
                Some(self.render_blacklist()),
            )),
            ModState::Absent => None,
        }
    }

    /// The fixed argv of the availability check (a dry run), after the
    /// program [`TOOL`].
    pub fn dry_run_args(&self) -> Vec<String> {
        dry_run_args(&self.name)
    }

    /// The fixed argv of the load, after the program [`TOOL`].
    pub fn load_args(&self) -> Vec<String> {
        vec!["--".to_string(), self.name.clone()]
    }
}

/// The fixed argv of `modprobe -n -v -- <name>`, after the program [`TOOL`].
pub fn dry_run_args(name: &str) -> Vec<String> {
    vec![
        "-n".to_string(),
        "-v".to_string(),
        "--".to_string(),
        name.to_string(),
    ]
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
    fn names() {
        let max = "a".repeat(64);
        for ok in [
            "dummy",
            "br_netfilter",
            "nf-conntrack",
            "8021q",
            "-x",
            max.as_str(),
        ] {
            assert!(valid_name(ok), "{ok}");
        }
        let long = "a".repeat(65);
        for bad in [
            "",
            "a b",
            "a/b",
            "a.ko",
            "..",
            "a=b",
            "dummy\n",
            "d\u{fc}mmy",
            "*",
            long.as_str(),
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert_eq!(normalize("nf-conntrack"), "nf_conntrack");
        assert_eq!(
            load_path("br_netfilter"),
            "/etc/modules-load.d/sinter-br_netfilter.conf"
        );
        assert_eq!(
            blacklist_path("pcspkr"),
            "/etc/modprobe.d/sinter-blacklist-pcspkr.conf"
        );
        assert_eq!(sys_path("loop"), "/sys/module/loop");
    }

    #[test]
    fn spec_defaults_flags_and_files() {
        let sp = ModuleSpec::from_values(&with(&[("name", s("br-netfilter"))]), "r").unwrap();
        assert_eq!(
            (sp.name.as_str(), sp.state, sp.runtime, sp.persist),
            ("br_netfilter", ModState::Present, true, true)
        );
        assert_eq!(
            sp.render_load(),
            "# Managed by Sinter (kernel_module). Local changes are replaced.\nbr_netfilter\n"
        );
        assert_eq!(sp.load_args(), ["--", "br_netfilter"]);
        assert_eq!(sp.dry_run_args(), ["-n", "-v", "--", "br_netfilter"]);
        let bl = ModuleSpec::from_values(
            &with(&[("name", s("pcspkr")), ("state", s("blacklisted"))]),
            "r",
        )
        .unwrap();
        assert_eq!(
            bl.render_blacklist(),
            "# Managed by Sinter (kernel_module). Local changes are replaced.\nblacklist pcspkr\n"
        );
        let e = |pairs: &[(&str, Value)]| {
            ModuleSpec::check_literals(&with(pairs), "r")
                .unwrap_err()
                .message
        };
        assert!(e(&[]).contains("name is required"));
        assert!(e(&[("name", s("a b"))]).contains("not a module name"));
        assert!(e(&[("name", Value::Int(1))]).contains("must be a string"));
        assert!(e(&[("name", s("x")), ("state", s("loaded"))]).contains("literal present"));
        assert!(e(&[("name", s("x")), ("state", s("{{ s }}"))]).contains("literal present"));
        assert!(e(&[
            ("name", s("x")),
            ("state", s("absent")),
            ("runtime", Value::Bool(true))
        ])
        .contains("only with state: present"));
        assert!(e(&[
            ("name", s("x")),
            ("state", s("blacklisted")),
            ("persist", Value::Bool(false))
        ])
        .contains("only with state: present"));
        assert!(e(&[
            ("name", s("x")),
            ("runtime", Value::Bool(false)),
            ("persist", Value::Bool(false))
        ])
        .contains("both false"));
        assert!(e(&[("name", s("x")), ("runtime", s("true"))]).contains("literal boolean"));
    }
}
