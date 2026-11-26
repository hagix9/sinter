//! Scripted Red Hat family tools for the in-process fake target (test
//! support): `dnf module enable|disable|reset` as DNF 4 persists it.
//!
//! The model is deliberately small. It answers only the commands Sinter
//! sends, refuses everything else with a non-zero exit so a test notices an
//! unexpected command, and its texts and exit codes are NOT confirmed on a
//! real host.

use std::collections::BTreeSet;
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

impl FakeTarget {
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
