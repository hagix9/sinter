//! Scripted Red Hat family tools for the in-process fake target (test
//! support): `dnf module enable|disable|reset` as DNF 4 persists it, and
//! `update-crypto-policies --show|--set` with one policy string.
//!
//! The model is deliberately small. It answers only the commands Sinter
//! sends, refuses everything else with a non-zero exit so a test notices an
//! unexpected command, and its texts and exit codes are NOT confirmed on a
//! real host.

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use crate::executor::{Completion, FakeTarget, Output};
use crate::fakesys::FakeFs;

/// What a scripted change command does instead of its normal behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FakeChange {
    /// Do what the real tool does.
    #[default]
    Normal,
    /// Exit 1 with a diagnostic; nothing changes.
    Fail,
    /// Exit 0 although nothing changed.
    SucceedWithoutChange,
    /// Terminated by SIGKILL after the change was made.
    KilledAfterChange,
    /// The completion cannot be established (a timeout or a lost
    /// connection); the change was made.
    IndeterminateAfterChange,
}

/// What one scripted `update-crypto-policies --show` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FakeShow {
    /// The current policy on one line.
    #[default]
    Normal,
    /// Exit 1 with a diagnostic.
    Fail,
    /// Exit 0 with text that is not a policy.
    Garbage,
    /// Exit 0 with the policy and a second line.
    ExtraLines,
    /// Exit 0 with no output at all.
    Empty,
    /// Exit 0 with a diagnostic on standard error only.
    StderrOnly,
    /// Exit 0 with the policy on standard output and a warning on standard
    /// error.
    WithWarning,
    /// Exit 0 with the policy, but the capture was truncated.
    Truncated,
    /// The completion cannot be established (a timeout).
    Indeterminate,
}

/// The shared scripted state. Clones of a [`FakeTarget`] share it, so a test
/// keeps a handle and reads what a run left behind.
#[derive(Debug, Default)]
pub struct FakeEl {
    /// `name:stream` pairs the enabled repositories offer. `None`: every
    /// module and stream exists.
    pub module_streams: Option<BTreeSet<String>>,
    /// How `dnf module enable|disable|reset` behaves.
    pub module_change: FakeChange,
    /// `dnf module reset` removes the state file instead of writing an
    /// empty `state=`.
    pub module_reset_removes_file: bool,
    /// Every `dnf module ...` argv received, in order.
    pub module_calls: Vec<Vec<String>>,
    /// The system-wide crypto policy `update-crypto-policies` reports.
    pub crypto_policy: String,
    /// Answers of the next `--show` calls, in order; `Normal` once empty.
    pub crypto_show: VecDeque<FakeShow>,
    /// How `--set` behaves.
    pub crypto_set: FakeChange,
    /// Another administrator: right before the n-th (0-based) `--show`
    /// call, the policy becomes this.
    pub crypto_external_change: Option<(usize, String)>,
    /// Every `update-crypto-policies` argv received, in order.
    pub crypto_calls: Vec<Vec<String>>,
    /// The scripted host tools that are not specific to the Red Hat family
    /// (`sysctl`, `hostnamectl`), kept here so they share this handle.
    pub host: crate::fake_host::FakeHostTools,
    /// The scripted OS base-setting tools (`timedatectl`, `localectl`,
    /// `locale`, `modprobe`).
    pub osbase: crate::fake_osbase::FakeOsBase,
}

/// The handle type stored in [`FakeTarget`].
pub type FakeElHandle = Arc<Mutex<FakeEl>>;

fn exited(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn interrupted(completion: Completion) -> Output {
    Output {
        completion,
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

/// The outcome of a scripted change whose normal effect `change` performs.
fn scripted(mode: FakeChange, tool: &str, change: impl FnOnce() -> Output) -> Output {
    match mode {
        FakeChange::Normal => change(),
        FakeChange::Fail => exited(1, "", &format!("{}: injected failure\n", tool)),
        FakeChange::SucceedWithoutChange => exited(0, "", ""),
        FakeChange::KilledAfterChange => {
            let _ = change();
            interrupted(Completion::Signaled(9))
        }
        FakeChange::IndeterminateAfterChange => {
            let _ = change();
            interrupted(Completion::Indeterminate {
                started: true,
                reason: "injected timeout".to_string(),
            })
        }
    }
}

fn ensure_modules_dir(fs: &mut FakeFs) {
    for dir in ["/etc/dnf", crate::dnfmod::MODULES_DIR] {
        if !fs.nodes.contains_key(dir) {
            fs.mkdir_node(dir, 0o755, 0, 0);
        }
    }
}

/// Whether `args` is a `dnf module` command (any options before `module`).
pub(crate) fn is_dnf_module(args: &[String]) -> bool {
    args.iter()
        .find(|a| !a.starts_with('-'))
        .is_some_and(|a| a == "module")
}

/// Serve `dnf [-y] module enable|disable|reset <spec>` against the scripted
/// filesystem, the way DNF 4 persists it in `/etc/dnf/modules.d`.
pub(crate) fn dnf_module(
    el: &FakeElHandle,
    fs: Option<&mut FakeFs>,
    is_root: bool,
    args: &[String],
) -> Output {
    let mut el = el.lock().unwrap_or_else(|e| e.into_inner());
    el.module_calls.push(args.to_vec());
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let (verb, operand) = match a.as_slice() {
        ["-y", "module", verb @ ("enable" | "disable" | "reset"), operand] => (*verb, *operand),
        _ => return exited(2, "", "fake dnf: unmodeled module command\n"),
    };
    if !is_root {
        return exited(
            1,
            "",
            "Error: This command has to be run with superuser privileges (under the root user on most systems).\n",
        );
    }
    let Some(fs) = fs else {
        return exited(1, "", "fake dnf: no modeled filesystem\n");
    };
    let (name, stream) = match (verb, operand.split_once(':')) {
        ("enable", Some((n, s))) => (n, s),
        ("enable", None) => return exited(1, "", "fake dnf: enable needs name:stream\n"),
        (_, Some(_)) => return exited(1, "", "fake dnf: unexpected stream\n"),
        (_, None) => (operand, ""),
    };
    let path = format!("{}/{}.module", crate::dnfmod::MODULES_DIR, name);
    let current = fs
        .file_bytes(&path)
        .and_then(|b| crate::dnfmod::parse_state_file(name, &b).ok());
    if verb == "enable" {
        if let Some(offered) = &el.module_streams {
            if !offered.contains(operand) {
                return exited(
                    1,
                    "",
                    &format!(
                        "Error: Problems in request:\nmissing groups or modules: {}\n",
                        operand
                    ),
                );
            }
        }
        if let Some(cur) = &current {
            if cur.state == crate::dnfmod::ModuleState::Enabled && cur.stream != stream {
                return exited(
                    1,
                    "",
                    "Error: It is not possible to switch enabled streams of a module unless explicitly enabled via configuration option module_stream_switch.\n",
                );
            }
        }
    }
    let profiles = current
        .as_ref()
        .map(|c| c.profiles.join(", "))
        .unwrap_or_default();
    let remove = verb == "reset" && el.module_reset_removes_file;
    let mode = el.module_change;
    scripted(mode, "dnf", || {
        ensure_modules_dir(fs);
        if remove {
            fs.nodes.remove(&path);
        } else {
            let (stream, state) = match verb {
                "enable" => (stream, "enabled"),
                "disable" => ("", "disabled"),
                _ => ("", ""),
            };
            let text = crate::dnfmod::render_state_file(name, stream, &profiles, state);
            fs.put_file(&path, text.as_bytes(), 0o644, 0, 0);
        }
        exited(0, "Complete!\n", "")
    })
}

/// Serve `update-crypto-policies --show` and `--set <POLICY>`.
pub(crate) fn update_crypto_policies(
    el: &FakeElHandle,
    fs: Option<&FakeFs>,
    is_root: bool,
    args: &[String],
) -> Output {
    let mut el = el.lock().unwrap_or_else(|e| e.into_inner());
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["--show"] => {
            let nth = el
                .crypto_calls
                .iter()
                .filter(|c| c.first().map(String::as_str) == Some("--show"))
                .count();
            el.crypto_calls.push(args.to_vec());
            if let Some((when, policy)) = el.crypto_external_change.clone() {
                if when == nth {
                    el.crypto_policy = policy;
                    el.crypto_external_change = None;
                }
            }
            let line = format!("{}\n", el.crypto_policy);
            match el.crypto_show.pop_front().unwrap_or_default() {
                FakeShow::Normal => exited(0, &line, ""),
                FakeShow::Fail => exited(1, "", "update-crypto-policies: injected failure\n"),
                FakeShow::Garbage => exited(0, "Traceback (most recent call last):\n", ""),
                FakeShow::ExtraLines => exited(0, &format!("{}note: synthetic\n", line), ""),
                FakeShow::Empty => exited(0, "", ""),
                FakeShow::StderrOnly => exited(0, "", "warning: synthetic\n"),
                FakeShow::WithWarning => exited(0, &line, "warning: synthetic\n"),
                FakeShow::Truncated => {
                    let mut out = exited(0, &line, "");
                    out.stdout_truncated = true;
                    out
                }
                FakeShow::Indeterminate => interrupted(Completion::Indeterminate {
                    started: true,
                    reason: "injected timeout".to_string(),
                }),
            }
        }
        ["--set", policy] => {
            el.crypto_calls.push(args.to_vec());
            if !is_root {
                return exited(1, "", "You must be root to run update-crypto-policies.\n");
            }
            let Ok(parsed) = crate::cryptopol::Policy::parse(policy) else {
                return exited(1, "", "fake update-crypto-policies: bad policy\n");
            };
            let defined = |file: String| {
                fs.is_some_and(|fs| {
                    crate::cryptopol::POLICY_DIRS
                        .iter()
                        .any(|d| fs.file_bytes(&format!("{}/{}", d, file)).is_some())
                })
            };
            if !defined(format!("{}.pol", parsed.base))
                || !parsed
                    .subs
                    .iter()
                    .all(|s| defined(format!("modules/{}.pmod", s)))
            {
                return exited(
                    1,
                    "",
                    "Unknown policy or subpolicy: the definition file was not found\n",
                );
            }
            let mode = el.crypto_set;
            let policy = policy.to_string();
            scripted(mode, "update-crypto-policies", || {
                el.crypto_policy = policy.clone();
                exited(
                    0,
                    &format!(
                        "Setting system policy to {}\nNote: System-wide crypto policies are applied on application start-up.\nIt is recommended to restart the system for the change of policies\nto fully take place.\n",
                        policy
                    ),
                    "",
                )
            })
        }
        _ => {
            el.crypto_calls.push(args.to_vec());
            exited(2, "", "fake update-crypto-policies: unmodeled command\n")
        }
    }
}

impl FakeTarget {
    /// A RHEL-family host with `update-crypto-policies`, the vendor policy
    /// definitions (`DEFAULT`, `LEGACY`, `FUTURE`, `FIPS`, `EMPTY` and the
    /// modules `NO-SHA1`, `SHA1`, `OSPP`, `AD-SUPPORT`, `AD-SUPPORT-LEGACY`,
    /// `NO-ENFORCE-EMS`) and `current` as the applied policy. Needs
    /// `with_fake_fs` first.
    pub fn with_crypto_policies(mut self, current: &str) -> Self {
        self.executables.insert(crate::cryptopol::TOOL.to_string());
        self.el
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .crypto_policy = current.to_string();
        let fs = self
            .fs
            .as_mut()
            .expect("with_crypto_policies needs with_fake_fs first");
        for dir in [
            "/usr/share",
            "/usr/share/crypto-policies",
            "/usr/share/crypto-policies/policies",
            "/usr/share/crypto-policies/policies/modules",
            "/etc/crypto-policies",
            "/etc/crypto-policies/policies",
            "/etc/crypto-policies/policies/modules",
        ] {
            if !fs.nodes.contains_key(dir) {
                fs.mkdir_node(dir, 0o755, 0, 0);
            }
        }
        let vendor = crate::cryptopol::POLICY_DIRS[0];
        for base in ["DEFAULT", "LEGACY", "FUTURE", "FIPS", "EMPTY"] {
            let path = format!("{}/{}.pol", vendor, base);
            if !fs.nodes.contains_key(&path) {
                fs.put_file(&path, b"# synthetic policy\n", 0o644, 0, 0);
            }
        }
        for module in [
            "NO-SHA1",
            "SHA1",
            "OSPP",
            "AD-SUPPORT",
            "AD-SUPPORT-LEGACY",
            "NO-ENFORCE-EMS",
        ] {
            let path = format!("{}/modules/{}.pmod", vendor, module);
            if !fs.nodes.contains_key(&path) {
                fs.put_file(&path, b"# synthetic module\n", 0o644, 0, 0);
            }
        }
        self
    }

    /// The scripted Red Hat family tools of this target (shared with every
    /// clone of it).
    pub fn el(&self) -> FakeElHandle {
        Arc::clone(&self.el)
    }

    /// Put a DNF 4 module state file on the scripted filesystem, as
    /// `dnf module` would have left it.
    pub fn with_module_state(
        mut self,
        name: &str,
        stream: &str,
        profiles: &str,
        state: &str,
    ) -> Self {
        let fs = self
            .fs
            .as_mut()
            .expect("with_module_state needs with_fake_fs first");
        ensure_modules_dir(fs);
        let text = crate::dnfmod::render_state_file(name, stream, profiles, state);
        fs.put_file(
            &format!("{}/{}.module", crate::dnfmod::MODULES_DIR, name),
            text.as_bytes(),
            0o644,
            0,
            0,
        );
        self
    }
}
