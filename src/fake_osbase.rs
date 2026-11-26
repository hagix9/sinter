//! Scripted OS base-setting tools for the in-process fake target (test
//! support): `timedatectl set-timezone`, over the link `/etc/localtime` on
//! the scripted filesystem; `localectl set-locale` over the locale file on
//! the scripted filesystem and `locale -a` over a list; `modprobe -n -v`
//! and `modprobe` over a set of available modules and the directories
//! `/sys/module/<name>` on the scripted filesystem.
//!
//! The model is deliberately small. It answers only the commands Sinter
//! sends, refuses everything else with a non-zero exit so a test notices an
//! unexpected command, and its texts and exit codes are NOT confirmed on a
//! real host.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::executor::{Completion, FakeTarget, Output};
use crate::fake_el::{FakeChange, FakeElHandle};
use crate::fake_host::FakeRead;
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
    /// The locale file `localectl` rewrites (`/etc/locale.conf` or
    /// `/etc/default/locale`).
    pub locale_conf: String,
    /// How `localectl set-locale` behaves.
    pub locale_set: FakeChange,
    /// `set-locale` replaces the whole set: keys it is not given are
    /// dropped. Otherwise they are kept.
    pub locale_replaces_all: bool,
    /// What `locale -a` lists, in order.
    pub locales: Vec<String>,
    /// Answers of the next `locale -a` calls, in order; `Normal` once
    /// empty.
    pub locale_list_reads: VecDeque<FakeRead>,
    /// Every `localectl` argv received, in order.
    pub localectl_calls: Vec<Vec<String>>,
    /// Every `locale` argv received, in order.
    pub locale_calls: Vec<Vec<String>>,
    /// Modules `modprobe` can load (normalized names).
    pub modules: BTreeSet<String>,
    /// How `modprobe -- <name>` behaves.
    pub module_load: FakeChange,
    /// Answers of the next `modprobe -n -v` calls, in order; `Normal`
    /// once empty.
    pub module_dry_reads: VecDeque<FakeRead>,
    /// Every `modprobe` argv received, in order.
    pub modprobe_calls: Vec<Vec<String>>,
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

/// One scripted read: `body` is the normal standard output.
fn read(mode: FakeRead, tool: &str, body: &str) -> Output {
    match mode {
        FakeRead::Normal => exited(0, body, ""),
        FakeRead::Fail => exited(1, "", &format!("{}: injected failure\n", tool)),
        FakeRead::ExtraLines => exited(0, &format!("{}synthetic second line\n", body), ""),
        FakeRead::Empty => exited(0, "", ""),
        FakeRead::WithStderr => exited(0, body, &format!("{}: synthetic warning\n", tool)),
        FakeRead::Truncated => {
            let mut out = exited(0, body, "");
            out.stdout_truncated = true;
            out
        }
        FakeRead::Killed => interrupted(Completion::Signaled(9)),
        FakeRead::Indeterminate => timeout(),
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

/// Serve `locale -a`.
pub(crate) fn locale(el: &FakeElHandle, args: &[String]) -> Output {
    let mut el = el.lock().unwrap_or_else(|e| e.into_inner());
    let st = &mut el.osbase;
    st.locale_calls.push(args.to_vec());
    match args {
        [a] if a == "-a" => {
            let mode = st.locale_list_reads.pop_front().unwrap_or_default();
            let body: String = st.locales.iter().map(|l| format!("{}\n", l)).collect();
            read(mode, "locale", &body)
        }
        _ => exited(2, "", "fake locale: unmodeled command\n"),
    }
}

/// Serve `localectl set-locale KEY=value ...`: the locale file is rewritten
/// as `KEY=value` lines (`LANG` first), keeping or dropping the keys it was
/// not given ([`FakeOsBase::locale_replaces_all`]). Comments are dropped.
pub(crate) fn localectl(
    el: &FakeElHandle,
    fs: Option<&mut FakeFs>,
    is_root: bool,
    args: &[String],
) -> Output {
    let mut el = el.lock().unwrap_or_else(|e| e.into_inner());
    let st = &mut el.osbase;
    st.localectl_calls.push(args.to_vec());
    let Some(fs) = fs else {
        return exited(1, "", "fake localectl: no modeled filesystem\n");
    };
    let Some((first, rest)) = args.split_first() else {
        return exited(2, "", "fake localectl: unmodeled command\n");
    };
    if first != "set-locale" || rest.is_empty() {
        return exited(2, "", "fake localectl: unmodeled command\n");
    }
    if !is_root {
        return exited(
            1,
            "",
            "Failed to issue method call: Interactive authentication required.\n",
        );
    }
    let mut given = BTreeMap::new();
    for a in rest {
        let Some((k, v)) = a.split_once('=') else {
            return exited(1, "", "Failed to set locale: Invalid locale assignment\n");
        };
        given.insert(k.to_string(), v.to_string());
    }
    let path = st.locale_conf.clone();
    let mut keys: BTreeMap<String, String> = if st.locale_replaces_all {
        BTreeMap::new()
    } else {
        fs.file_bytes(&path)
            .and_then(|b| crate::locale::parse_conf(&b).ok())
            .unwrap_or_default()
    };
    keys.extend(given);
    let mut body = String::new();
    if let Some(v) = keys.remove("LANG") {
        body.push_str(&format!("LANG={}\n", v));
    }
    for (k, v) in &keys {
        body.push_str(&format!("{}={}\n", k, v));
    }
    scripted(st.locale_set, "localectl", || {
        fs.nodes.remove(&path);
        fs.put_file(&path, body.as_bytes(), 0o644, 0, 0);
        exited(0, "", "")
    })
}

/// Serve `modprobe -n -v -- <name>` (a dry run) and `modprobe -- <name>`
/// (the load: `/sys/module/<name>` appears).
pub(crate) fn modprobe(
    el: &FakeElHandle,
    fs: Option<&mut FakeFs>,
    is_root: bool,
    args: &[String],
) -> Output {
    const DIR: &str = "/lib/modules/6.0.0-synthetic";
    let mut el = el.lock().unwrap_or_else(|e| e.into_inner());
    let st = &mut el.osbase;
    st.modprobe_calls.push(args.to_vec());
    let Some(fs) = fs else {
        return exited(1, "", "fake modprobe: no modeled filesystem\n");
    };
    let not_found = |name: &str| {
        exited(
            1,
            "",
            &format!(
                "modprobe: FATAL: Module {} not found in directory {}\n",
                name, DIR
            ),
        )
    };
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["-n", "-v", "--", name] => {
            let mode = st.module_dry_reads.pop_front().unwrap_or_default();
            if mode != FakeRead::Normal {
                return read(mode, "modprobe", "synthetic\n");
            }
            let norm = crate::kmod::normalize(name);
            if !st.modules.contains(&norm) {
                return not_found(name);
            }
            exited(
                0,
                &format!("insmod {}/kernel/synthetic/{}.ko.xz \n", DIR, norm),
                "",
            )
        }
        ["--", name] => {
            let norm = crate::kmod::normalize(name);
            if !st.modules.contains(&norm) {
                return not_found(name);
            }
            if !is_root {
                return exited(
                    1,
                    "",
                    &format!(
                        "modprobe: ERROR: could not insert '{}': Operation not permitted\n",
                        norm
                    ),
                );
            }
            scripted(st.module_load, "modprobe", || {
                let path = crate::kmod::sys_path(&norm);
                if !fs.nodes.contains_key(&path) {
                    fs.mkdir_node(&path, 0o755, 0, 0);
                }
                exited(0, "", "")
            })
        }
        _ => exited(2, "", "fake modprobe: unmodeled command\n"),
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
    /// A host with `/usr/sbin/modprobe` that can load `available`, the
    /// directories `/etc/modules-load.d`, `/etc/modprobe.d` and
    /// `/sys/module`, and `loaded` loaded (`/sys/module/<name>`). Needs
    /// `with_fake_fs` first.
    pub fn with_modules(mut self, available: &[&str], loaded: &[&str]) -> Self {
        self.executables.insert(crate::kmod::TOOL.to_string());
        {
            let mut el = self.el.lock().unwrap_or_else(|e| e.into_inner());
            el.osbase.modules = available
                .iter()
                .map(|m| crate::kmod::normalize(m))
                .collect();
        }
        let fs = self
            .fs
            .as_mut()
            .expect("with_modules needs with_fake_fs first");
        for dir in [
            crate::kmod::LOAD_DIR,
            crate::kmod::BLACKLIST_DIR,
            crate::kmod::SYS_MODULE,
        ] {
            mkdirs(fs, dir);
        }
        for m in loaded {
            mkdirs(fs, &crate::kmod::sys_path(&crate::kmod::normalize(m)));
        }
        self
    }

    /// A host with `/usr/bin/localectl` and `/usr/bin/locale`, these
    /// locales in `locale -a`, and the locale file of the target's OS
    /// family (`/etc/default/locale` for Ubuntu, `/etc/locale.conf`
    /// otherwise) with `content` (`None`: no file). Needs `with_fake_fs`
    /// first.
    pub fn with_locales(mut self, locales: &[&str], content: Option<&str>) -> Self {
        self.executables.insert(crate::locale::TOOL.to_string());
        self.executables
            .insert(crate::locale::LIST_TOOL.to_string());
        let path = if self.os_release.contains("ID_LIKE=debian") {
            crate::locale::DEBIAN_CONF
        } else {
            crate::locale::RHEL_CONF
        };
        {
            let mut el = self.el.lock().unwrap_or_else(|e| e.into_inner());
            el.osbase.locale_conf = path.to_string();
            el.osbase.locales = locales.iter().map(|l| l.to_string()).collect();
        }
        let fs = self
            .fs
            .as_mut()
            .expect("with_locales needs with_fake_fs first");
        if let Some((dir, _)) = path.rsplit_once('/') {
            mkdirs(fs, dir);
        }
        if let Some(c) = content {
            fs.put_file(path, c.as_bytes(), 0o644, 0, 0);
        }
        self
    }

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
