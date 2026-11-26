//! Scripted host tools for the in-process fake target (test support):
//! `sysctl -n -- <name>` and `sysctl -w -- <name>=<value>` over a map of
//! kernel parameters, `hostnamectl --static|--transient|set-hostname`
//! over two names, and `tuned-adm profile|off|recommend|verify` over
//! TuneD's state file on the scripted filesystem.
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
    /// How `tuned-adm profile <name>` and `tuned-adm off` behave.
    pub tuned_change: FakeChange,
    /// The profile `tuned-adm recommend` prints.
    pub tuned_recommended: String,
    /// Answers of the next `tuned-adm recommend` calls, in order; `Normal`
    /// once empty.
    pub tuned_recommend_reads: VecDeque<FakeRead>,
    /// Another administrator: at the next `tuned-adm recommend`, the state
    /// file `/etc/tuned/active_profile` gets this content.
    pub tuned_external_selection: Option<String>,
    /// The exit code of `tuned-adm verify` (0: applied, 1: not applied).
    pub tuned_verify_exit: i32,
    /// How the next `tuned-adm verify` calls end, in order; `Normal` (exit
    /// with `tuned_verify_exit`) once empty.
    pub tuned_verify_reads: VecDeque<FakeRead>,
    /// Every `tuned-adm` argv received, in order.
    pub tuned_calls: Vec<Vec<String>>,
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

/// Serve `tuned-adm profile <name>`, `tuned-adm off`, `tuned-adm recommend`
/// and `tuned-adm verify`. The selection lives in
/// `/etc/tuned/active_profile` on the scripted filesystem, as TuneD keeps
/// it; `daemon_active` is whether `tuned.service` is active.
pub(crate) fn tuned_adm(
    el: &FakeElHandle,
    fs: Option<&mut crate::fakesys::FakeFs>,
    is_root: bool,
    daemon_active: bool,
    args: &[String],
) -> Output {
    const NO_DAEMON: &str = "Cannot talk to TuneD daemon via DBus. Is TuneD daemon running?\n";
    let mut el = el.lock().unwrap_or_else(|e| e.into_inner());
    let host = &mut el.host;
    host.tuned_calls.push(args.to_vec());
    let Some(fs) = fs else {
        return exited(1, "", "fake tuned-adm: no modeled filesystem\n");
    };
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["recommend"] => {
            if let Some(content) = host.tuned_external_selection.take() {
                fs.put_file(
                    crate::tuned::ACTIVE_PROFILE,
                    content.as_bytes(),
                    0o644,
                    0,
                    0,
                );
            }
            let mode = host.tuned_recommend_reads.pop_front().unwrap_or_default();
            read(mode, "tuned-adm", &format!("{}\n", host.tuned_recommended))
        }
        ["verify"] => {
            let mode = host.tuned_verify_reads.pop_front().unwrap_or_default();
            if mode != FakeRead::Normal {
                return read(mode, "tuned-adm", "synthetic\n");
            }
            if !daemon_active {
                return exited(1, "", NO_DAEMON);
            }
            match host.tuned_verify_exit {
                0 => exited(
                    0,
                    "Verification succeeded, current system settings match the preset profile.\n",
                    "",
                ),
                code => exited(
                    code,
                    "Verification failed, current system settings differ from the preset profile.\n",
                    "",
                ),
            }
        }
        ["profile", _] | ["off"] => {
            if !is_root {
                return exited(1, "", "fake tuned-adm: not authorized\n");
            }
            if !daemon_active {
                return exited(1, "", NO_DAEMON);
            }
            let content = match a.as_slice() {
                ["profile", name] => {
                    let defined = crate::tuned::profile_files(name)
                        .iter()
                        .any(|f| fs.file_bytes(f).is_some());
                    if !defined {
                        return exited(
                            1,
                            "",
                            &format!("Requested profile '{}' doesn't exist.\n", name),
                        );
                    }
                    format!("{}\n", name)
                }
                _ => String::new(),
            };
            let mode = host.tuned_change;
            scripted(mode, "tuned-adm", || {
                fs.put_file(
                    crate::tuned::ACTIVE_PROFILE,
                    content.as_bytes(),
                    0o644,
                    0,
                    0,
                );
                fs.put_file("/etc/tuned/profile_mode", b"manual\n", 0o644, 0, 0);
                exited(0, "", "")
            })
        }
        _ => exited(2, "", "fake tuned-adm: unmodeled command\n"),
    }
}

impl FakeTarget {
    /// A host with TuneD installed: `/usr/sbin/tuned-adm`, an active
    /// `tuned.service` (override it with `with_service`), the vendor
    /// profiles `balanced`, `virtual-guest` and `throughput-performance`
    /// in the newer layout (`/usr/lib/tuned/profiles`) and `powersave` in
    /// the older one (`/usr/lib/tuned`), `virtual-guest` as the
    /// recommendation, and `selected` in `/etc/tuned/active_profile`
    /// (`None`: an empty file, as after `tuned-adm off`). Needs
    /// `with_fake_fs` first.
    pub fn with_tuned(mut self, selected: Option<&str>) -> Self {
        self.executables.insert(crate::tuned::TOOL.to_string());
        self.services.insert(
            crate::tuned::SERVICE.to_string(),
            (
                "loaded".to_string(),
                "active".to_string(),
                "enabled".to_string(),
            ),
        );
        self.el
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .host
            .tuned_recommended = "virtual-guest".to_string();
        let fs = self
            .fs
            .as_mut()
            .expect("with_tuned needs with_fake_fs first");
        let mut dirs: Vec<String> = ["/etc/tuned", "/usr/lib/tuned", "/usr/lib/tuned/profiles"]
            .map(String::from)
            .to_vec();
        let mut files = Vec::new();
        for (dir, name) in [
            ("/usr/lib/tuned/profiles", "balanced"),
            ("/usr/lib/tuned/profiles", "virtual-guest"),
            ("/usr/lib/tuned/profiles", "throughput-performance"),
            ("/usr/lib/tuned", "powersave"),
        ] {
            dirs.push(format!("{}/{}", dir, name));
            files.push(format!("{}/{}/tuned.conf", dir, name));
        }
        for dir in dirs {
            if !fs.nodes.contains_key(&dir) {
                fs.mkdir_node(&dir, 0o755, 0, 0);
            }
        }
        for file in files {
            fs.put_file(&file, b"[main]\nsummary=synthetic profile\n", 0o644, 0, 0);
        }
        let content = selected.map(|s| format!("{}\n", s)).unwrap_or_default();
        fs.put_file(
            crate::tuned::ACTIVE_PROFILE,
            content.as_bytes(),
            0o644,
            0,
            0,
        );
        self
    }

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
