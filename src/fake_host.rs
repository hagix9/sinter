//! Scripted host tools for the in-process fake target (test support):
//! `sysctl -n -- <name>` and `sysctl -w -- <name>=<value>` over a map of
//! kernel parameters, and `hostnamectl --static|--transient|set-hostname`
//! over two names.
//!
//! The model is deliberately small. It answers only the commands Sinter
//! sends, refuses everything else with a non-zero exit so a test notices an
//! unexpected command, and its texts and exit codes are NOT confirmed on a
//! real host.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::executor::{Completion, FakeTarget, Output};
use crate::fake_el::{FakeChange, FakeElHandle};

/// What one scripted read-only call answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FakeRead {
    /// The value on one line.
    #[default]
    Normal,
    /// Exit 1 with a diagnostic.
    Fail,
    /// Exit 0 with the value and a second line.
    ExtraLines,
    /// Exit 0 with no output at all.
    Empty,
    /// Exit 0 with the value, and a diagnostic on standard error.
    WithStderr,
    /// Exit 0 with the value, but the capture was truncated.
    Truncated,
    /// Terminated by SIGKILL.
    Killed,
    /// The completion cannot be established (a timeout).
    Indeterminate,
}

/// The scripted state of the host tools. It lives inside the shared
/// [`crate::fake_el::FakeEl`] state, so clones of a [`FakeTarget`] share it
/// and a test reads what a run left behind.
#[derive(Debug, Default)]
pub struct FakeHostTools {
    /// Kernel parameters as the kernel prints them (fields of a multi-value
    /// parameter separated by tabs).
    pub sysctl: BTreeMap<String, String>,
    /// Parameters that refuse `-w` (exit 255, nothing changes).
    pub sysctl_read_only: BTreeSet<String>,
    /// How `sysctl -w` behaves.
    pub sysctl_write: FakeChange,
    /// Answers of the next `sysctl -n` calls, in order; `Normal` once empty.
    pub sysctl_reads: VecDeque<FakeRead>,
    /// What the kernel stores instead of a written value (rounding or
    /// clamping): written text -> stored text.
    pub sysctl_stores: BTreeMap<String, String>,
    /// Every `sysctl` argv received, in order.
    pub sysctl_calls: Vec<Vec<String>>,
    /// The static host name (`/etc/hostname`); empty: not set.
    pub static_name: String,
    /// The transient (running) host name.
    pub transient_name: String,
    /// How `hostnamectl set-hostname` behaves.
    pub hostname_set: FakeChange,
    /// Another source (DHCP) owns the running name: `set-hostname` leaves
    /// the transient name as it is.
    pub hostname_transient_kept: bool,
    /// Answers of the next `hostnamectl --static` / `--transient` calls, in
    /// order; `Normal` once empty.
    pub hostname_reads: VecDeque<FakeRead>,
    /// Every `hostnamectl` argv received, in order.
    pub hostnamectl_calls: Vec<Vec<String>>,
}

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

fn timeout() -> Output {
    interrupted(Completion::Indeterminate {
        started: true,
        reason: "injected timeout".to_string(),
    })
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
            timeout()
        }
    }
}

/// One scripted read: `line` is the normal standard output.
fn read(mode: FakeRead, tool: &str, line: &str) -> Output {
    match mode {
        FakeRead::Normal => exited(0, line, ""),
        FakeRead::Fail => exited(1, "", &format!("{}: injected failure\n", tool)),
        FakeRead::ExtraLines => exited(0, &format!("{}synthetic second line\n", line), ""),
        FakeRead::Empty => exited(0, "", ""),
        FakeRead::WithStderr => exited(0, line, &format!("{}: synthetic warning\n", tool)),
        FakeRead::Truncated => {
            let mut out = exited(0, line, "");
            out.stdout_truncated = true;
            out
        }
        FakeRead::Killed => interrupted(Completion::Signaled(9)),
        FakeRead::Indeterminate => timeout(),
    }
}

/// Serve `sysctl -n -- <name>` and `sysctl -w -- <name>=<value>`.
pub(crate) fn sysctl(el: &FakeElHandle, is_root: bool, args: &[String]) -> Output {
    let mut el = el.lock().unwrap_or_else(|e| e.into_inner());
    let host = &mut el.host;
    host.sysctl_calls.push(args.to_vec());
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["-n", "--", name] => {
            let mode = host.sysctl_reads.pop_front().unwrap_or_default();
            match host.sysctl.get(*name) {
                Some(value) => read(mode, "sysctl", &format!("{}\n", value)),
                None => exited(
                    255,
                    "",
                    &format!(
                        "sysctl: cannot stat /proc/sys/{}: No such file or directory\n",
                        name.replace('.', "/")
                    ),
                ),
            }
        }
        ["-w", "--", assignment] => {
            let Some((name, value)) = assignment.split_once('=') else {
                return exited(255, "", "fake sysctl: not an assignment\n");
            };
            if !host.sysctl.contains_key(name) {
                return exited(
                    255,
                    "",
                    &format!(
                        "sysctl: cannot stat /proc/sys/{}: No such file or directory\n",
                        name.replace('.', "/")
                    ),
                );
            }
            if !is_root || host.sysctl_read_only.contains(name) {
                return exited(
                    255,
                    "",
                    &format!(
                        "sysctl: permission denied on key \"{}\"{}\n",
                        name,
                        if is_root { "" } else { ", ignoring" }
                    ),
                );
            }
            let stored = host
                .sysctl_stores
                .get(value)
                .cloned()
                .unwrap_or_else(|| value.replace(' ', "\t"));
            let mode = host.sysctl_write;
            let echo = format!("{} = {}\n", name, value);
            scripted(mode, "sysctl", || {
                host.sysctl.insert(name.to_string(), stored);
                exited(0, &echo, "")
            })
        }
        _ => exited(2, "", "fake sysctl: unmodeled command\n"),
    }
}

/// Serve `hostnamectl --static`, `hostnamectl --transient` and
/// `hostnamectl set-hostname <name>`.
pub(crate) fn hostnamectl(el: &FakeElHandle, is_root: bool, args: &[String]) -> Output {
    let mut el = el.lock().unwrap_or_else(|e| e.into_inner());
    let host = &mut el.host;
    host.hostnamectl_calls.push(args.to_vec());
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        [which @ ("--static" | "--transient")] => {
            let mode = host.hostname_reads.pop_front().unwrap_or_default();
            let name = if *which == "--static" {
                &host.static_name
            } else {
                &host.transient_name
            };
            read(mode, "hostnamectl", &format!("{}\n", name))
        }
        ["set-hostname", name] => {
            if !is_root {
                return exited(
                    1,
                    "",
                    "Could not set static hostname: Interactive authentication required.\n",
                );
            }
            let mode = host.hostname_set;
            let keep_transient = host.hostname_transient_kept;
            scripted(mode, "hostnamectl", || {
                host.static_name = name.to_string();
                if !keep_transient {
                    host.transient_name = name.to_string();
                }
                exited(0, "", "")
            })
        }
        _ => exited(2, "", "fake hostnamectl: unmodeled command\n"),
    }
}

impl FakeTarget {
    /// A host with `/usr/bin/hostnamectl` and these static and transient
    /// names (an empty static name: not set).
    pub fn with_hostnamectl(mut self, static_name: &str, transient: &str) -> Self {
        self.executables.insert(crate::hostname::TOOL.to_string());
        {
            let mut el = self.el.lock().unwrap_or_else(|e| e.into_inner());
            el.host.static_name = static_name.to_string();
            el.host.transient_name = transient.to_string();
        }
        self
    }

    /// A host with `/usr/sbin/sysctl`, the directory `/etc/sysctl.d` and
    /// these kernel parameters (`name`, text as the kernel prints it). Needs
    /// `with_fake_fs` first.
    pub fn with_sysctl(mut self, parameters: &[(&str, &str)]) -> Self {
        self.executables.insert(crate::sysctl::TOOL.to_string());
        {
            let mut el = self.el.lock().unwrap_or_else(|e| e.into_inner());
            for (name, value) in parameters {
                el.host.sysctl.insert(name.to_string(), value.to_string());
            }
        }
        let fs = self
            .fs
            .as_mut()
            .expect("with_sysctl needs with_fake_fs first");
        if !fs.nodes.contains_key(crate::sysctl::CONF_DIR) {
            fs.mkdir_node(crate::sysctl::CONF_DIR, 0o755, 0, 0);
        }
        self
    }
}
