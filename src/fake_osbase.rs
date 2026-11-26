//! Scripted OS base-setting tools for the in-process fake target (test
//! support): `timedatectl set-timezone`, over the link `/etc/localtime` on
//! the scripted filesystem.
//!
//! The model is deliberately small. It answers only the commands Sinter
//! sends, refuses everything else with a non-zero exit so a test notices an
//! unexpected command, and its texts and exit codes are NOT confirmed on a
//! real host.

use crate::executor::{Completion, FakeTarget, Output};
use crate::fake_el::{FakeChange, FakeElHandle};
use crate::fakesys::FakeFs;

/// The scripted state of these tools. It lives inside the shared
/// [`crate::fake_el::FakeEl`] state, so clones of a [`FakeTarget`] share it
/// and a test reads what a run left behind.
#[derive(Debug, Default)]
pub struct FakeOsBase {
    /// How `timedatectl set-timezone` behaves.
    pub timezone_set: FakeChange,
    /// `set-timezone` writes the absolute target
    /// `/usr/share/zoneinfo/<zone>` instead of `../usr/share/zoneinfo/<zone>`.
    pub timezone_absolute_link: bool,
    /// Every `timedatectl` argv received, in order.
    pub timedatectl_calls: Vec<Vec<String>>,
}

pub(crate) fn exited(code: i32, stdout: &str, stderr: &str) -> Output {
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

fn is_file(fs: &FakeFs, path: &str) -> bool {
    fs.file_bytes(path).is_some()
}

/// Serve `timedatectl set-timezone <zone>`: the zone file must exist; the
/// link `/etc/localtime` is replaced.
pub(crate) fn timedatectl(
    el: &FakeElHandle,
    fs: Option<&mut FakeFs>,
    is_root: bool,
    args: &[String],
) -> Output {
    let mut el = el.lock().unwrap_or_else(|e| e.into_inner());
    let st = &mut el.osbase;
    st.timedatectl_calls.push(args.to_vec());
    let Some(fs) = fs else {
        return exited(1, "", "fake timedatectl: no modeled filesystem\n");
    };
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["set-timezone", zone] => {
            if !is_root {
                return exited(
                    1,
                    "",
                    "Failed to set time zone: Interactive authentication required.\n",
                );
            }
            if !is_file(fs, &crate::timezone::zone_file(zone)) {
                return exited(
                    1,
                    "",
                    &format!(
                        "Failed to set time zone: Invalid or not installed time zone '{}'\n",
                        zone
                    ),
                );
            }
            let target = if st.timezone_absolute_link {
                format!("/usr/share/zoneinfo/{}", zone)
            } else {
                format!("../usr/share/zoneinfo/{}", zone)
            };
            scripted(st.timezone_set, "timedatectl", || {
                fs.nodes.remove(crate::timezone::LOCALTIME);
                fs.put_symlink(crate::timezone::LOCALTIME, &target, 0, 0);
                exited(0, "", "")
            })
        }
        _ => exited(2, "", "fake timedatectl: unmodeled command\n"),
    }
}

/// Create `path` and its missing parents as root-owned 0755 directories.
fn mkdirs(fs: &mut FakeFs, path: &str) {
    let mut cur = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        cur.push('/');
        cur.push_str(part);
        if !fs.nodes.contains_key(&cur) {
            fs.mkdir_node(&cur, 0o755, 0, 0);
        }
    }
}

impl FakeTarget {
    /// A host with `/usr/bin/timedatectl`, these zone files below
    /// `/usr/share/zoneinfo` and `/etc/localtime` as the link
    /// `../usr/share/zoneinfo/<current>` (`None`: no link). Needs
    /// `with_fake_fs` first.
    pub fn with_timezones(mut self, zones: &[&str], current: Option<&str>) -> Self {
        self.executables.insert(crate::timezone::TOOL.to_string());
        let fs = self
            .fs
            .as_mut()
            .expect("with_timezones needs with_fake_fs first");
        mkdirs(fs, crate::timezone::ZONEINFO);
        for zone in zones {
            let path = crate::timezone::zone_file(zone);
            if let Some((dir, _)) = path.rsplit_once('/') {
                mkdirs(fs, dir);
            }
            fs.put_file(&path, b"TZif synthetic\n", 0o644, 0, 0);
        }
        if let Some(cur) = current {
            fs.put_symlink(
                crate::timezone::LOCALTIME,
                &format!("../usr/share/zoneinfo/{}", cur),
                0,
                0,
            );
        }
        self
    }
}
