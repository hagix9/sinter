//! Scripted systemd manager and filesystem for [`FakeTarget`].
//!
//! Test infrastructure only (the CLI never constructs it). It lets a test
//! drive the production file/template/link/service/handler/audit code through
//! the real observation and mutation contracts while the *target* behaves like
//! a small, honest model of the three independent facts that matter for
//! `daemon-reload`:
//!
//! * the **disk** state of a unit (a revision per unit, bumped whenever the
//!   scripted filesystem changes a recognized unit file or drop-in);
//! * the **loaded** manager state (what the manager last read, changed only by
//!   `daemon-reload`, a native implicit reload, or a first lazy load);
//! * `NeedDaemonReload`, derived from the two (and blindable per unit to model
//!   the same/backward-mtime false negative).
//!
//! Nothing here fabricates state: an unmodeled command fails honestly.

use crate::executor::{Completion, Output};
use crate::manager::{path_shape, resolve_input};
use std::collections::{BTreeMap, BTreeSet};

/// What `systemctl show --property=UnitPath` returns by default.
pub const FAKE_UNIT_PATH_OUTPUT: &str = "UnitPath=/etc/systemd/system.control /run/systemd/system.control /run/systemd/transient /run/systemd/generator.early /etc/systemd/system /etc/systemd/system.attached /run/systemd/system /run/systemd/system.attached /run/systemd/generator /usr/local/lib/systemd/system /usr/lib/systemd/system /run/systemd/generator.late\n";

/// How a scripted `NeedDaemonReload` answer is damaged for adversarial tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeedOverride {
    /// Omit the `NeedDaemonReload` record entirely.
    Missing,
    /// Emit the record twice.
    Duplicate,
    /// Emit this literal value (for example `maybe`).
    Value(String),
}

#[derive(Debug, Clone)]
pub struct FakeManager {
    /// Complete answer to the UnitPath query; `None` serves the default.
    pub unit_path_output: Option<Output>,
    /// Disk revision per unit (absent = no unit file on disk).
    pub disk: BTreeMap<String, u64>,
    /// Loaded revision per unit (what the manager last read).
    pub loaded: BTreeMap<String, u64>,
    /// Units whose staleness `NeedDaemonReload` cannot see.
    pub need_blind: BTreeSet<String>,
    /// Units the manager holds a cached not-found stub for: a unit file that
    /// appears on disk stays invisible until a reload.
    pub cached_not_found: BTreeSet<String>,
    /// Forced completion of `daemon-reload`; `None` is a successful reload.
    pub reload_completion: Option<Completion>,
    /// stderr served with a forced non-zero reload.
    pub reload_stderr: String,
    /// Damaged `NeedDaemonReload` answers per unit.
    pub need_override: BTreeMap<String, NeedOverride>,
    /// After a successful reload, this many `show` calls fail (a lost answer).
    pub show_fail_after_reload: usize,
    /// stderr served by those failing `show` calls (a fixed default when
    /// `None`); lets a test plant a unique canary in target diagnostics.
    pub show_fail_stderr: Option<String>,
    /// Completion of those failing `show` calls (exit 1 when `None`).
    pub show_fail_completion: Option<Completion>,
    /// Units that report `NeedDaemonReload=yes` again once a reload has run
    /// (the unit changed again, or the reload did not capture it).
    pub stale_after_reload: BTreeSet<String>,
    /// State a unit takes once the manager has reloaded (a reload can change
    /// what an observation reports, for example a new `[Install]` section).
    pub after_reload: BTreeMap<String, (String, String, String)>,
    /// Units that `enable` also activates (socket/target style behavior).
    pub enable_starts: BTreeSet<String>,
    /// `enable`/`disable` natively reload the manager (as real systemd does).
    pub implicit_reload_on_enable: bool,
    /// Units the manager unloads right after a successful `stop` (real systemd
    /// garbage-collects an inactive unit nothing references): the unit leaves
    /// the loaded table, so a following `reset-failed` finds it not loaded. A
    /// later `show` loads it again from disk, as the real one does.
    pub unload_on_stop: BTreeSet<String>,
    /// Forced answer per mutating verb (`stop`, `reset-failed`, ...), served
    /// instead of the verb's normal effect.
    pub verb_override: BTreeMap<String, Output>,
    /// After a successful `stop`, this many `show` calls fail.
    pub show_fail_after_stop: usize,
    /// Explicit `daemon-reload` invocations served.
    pub reload_count: usize,
    /// Native implicit reloads performed by enable/disable.
    pub implicit_reload_count: usize,
    pub(crate) show_failures_left: usize,
    pub(crate) forced_stale: BTreeSet<String>,
    pub(crate) rev: u64,
}

impl Default for FakeManager {
    fn default() -> Self {
        FakeManager {
            unit_path_output: None,
            disk: BTreeMap::new(),
            loaded: BTreeMap::new(),
            need_blind: BTreeSet::new(),
            cached_not_found: BTreeSet::new(),
            reload_completion: None,
            reload_stderr: String::new(),
            need_override: BTreeMap::new(),
            show_fail_after_reload: 0,
            show_fail_stderr: None,
            show_fail_completion: None,
            stale_after_reload: BTreeSet::new(),
            after_reload: BTreeMap::new(),
            enable_starts: BTreeSet::new(),
            implicit_reload_on_enable: true,
            unload_on_stop: BTreeSet::new(),
            verb_override: BTreeMap::new(),
            show_fail_after_stop: 0,
            reload_count: 0,
            implicit_reload_count: 0,
            show_failures_left: 0,
            forced_stale: BTreeSet::new(),
            rev: 0,
        }
    }
}

impl FakeManager {
    /// Does the manager's cached view of `unit` differ from the disk in a way
    /// `NeedDaemonReload` reports?
    pub fn need_daemon_reload(&self, unit: &str) -> bool {
        if self.need_blind.contains(unit) {
            return false;
        }
        self.loaded.get(unit) != self.disk.get(unit)
    }

    /// Synchronize the loaded view with the disk. `services` is the loaded
    /// unit table: (LoadState, ActiveState, UnitFileState).
    pub(crate) fn sync(&mut self, services: &mut BTreeMap<String, (String, String, String)>) {
        let on_disk: Vec<(String, u64)> = self.disk.iter().map(|(k, v)| (k.clone(), *v)).collect();
        for (unit, rev) in on_disk {
            self.loaded.insert(unit.clone(), rev);
            match services.get_mut(&unit) {
                Some(entry) => {
                    if entry.0 == "not-found" {
                        entry.0 = "loaded".to_string();
                        if entry.2.is_empty() {
                            entry.2 = "disabled".to_string();
                        }
                    }
                }
                None => {
                    services.insert(
                        unit,
                        (
                            "loaded".to_string(),
                            "inactive".to_string(),
                            "disabled".to_string(),
                        ),
                    );
                }
            }
        }
        let gone: Vec<String> = self
            .loaded
            .keys()
            .filter(|u| !self.disk.contains_key(*u))
            .cloned()
            .collect();
        for unit in gone {
            self.loaded.remove(&unit);
            let running = services
                .get(&unit)
                .map(|e| e.1 == "active")
                .unwrap_or(false);
            if running {
                // A running unit whose fragment was removed stays running but
                // is no longer loadable from disk.
                if let Some(e) = services.get_mut(&unit) {
                    e.0 = "not-found".to_string();
                }
            } else {
                services.remove(&unit);
            }
        }
        self.cached_not_found.clear();
        for (unit, state) in &self.after_reload {
            if services.contains_key(unit) {
                services.insert(unit.clone(), state.clone());
            }
        }
    }

    /// A first `show`/`enable` of a never-loaded unit that exists on disk
    /// loads it from disk (a cached not-found stub blocks this).
    pub(crate) fn lazy_load(
        &mut self,
        unit: &str,
        services: &mut BTreeMap<String, (String, String, String)>,
        honor_cache: bool,
    ) {
        if services.contains_key(unit) {
            return;
        }
        if honor_cache && self.cached_not_found.contains(unit) {
            return;
        }
        if let Some(rev) = self.disk.get(unit).copied() {
            self.loaded.insert(unit.to_string(), rev);
            services.insert(
                unit.to_string(),
                (
                    "loaded".to_string(),
                    "inactive".to_string(),
                    "disabled".to_string(),
                ),
            );
        }
    }

    /// The disk copy of a recognized unit file/drop-in changed. Revisions
    /// are monotonic, so a recreated unit never aliases an older loaded one.
    pub fn disk_changed(&mut self, unit: &str, present: bool) {
        self.rev += 1;
        if present {
            self.disk.insert(unit.to_string(), self.rev);
        } else {
            self.disk.remove(unit);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeKind {
    Dir,
    File(Vec<u8>),
    Symlink(String),
}

#[derive(Debug, Clone)]
pub struct FakeNode {
    pub kind: FakeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub ino: u64,
    pub mtime: u64,
    pub ctime: u64,
}

/// A path whose recognizable manager input changed:
/// `(path, is_link, present_after)`.
pub(crate) type TouchedPath = (String, bool, bool);

/// A minimal in-memory filesystem answering exactly the commands the file,
/// template and link resources issue.
#[derive(Debug, Clone)]
pub struct FakeFs {
    pub nodes: BTreeMap<String, FakeNode>,
    next_ino: u64,
    clock: u64,
    /// Keep reporting the original mtime after a content change (the
    /// same/backward-mtime case `NeedDaemonReload` cannot detect).
    pub freeze_mtime: bool,
    staging_counter: u64,
}

impl Default for FakeFs {
    fn default() -> Self {
        let mut fs = FakeFs {
            nodes: BTreeMap::new(),
            next_ino: 100,
            clock: 1,
            freeze_mtime: false,
            staging_counter: 0,
        };
        for d in [
            "/",
            "/etc",
            "/etc/systemd",
            "/etc/systemd/system",
            "/etc/systemd/system/multi-user.target.wants",
            "/etc/systemd/system.conf.d",
            "/etc/systemd/user",
            "/etc/systemd/network",
            "/usr",
            "/usr/lib",
            "/usr/lib/systemd",
            "/usr/lib/systemd/system",
            "/usr/lib/systemd/user",
            "/etc/app",
            "/opt",
            "/opt/units",
            "/opt/units/system",
        ] {
            fs.mkdir_node(d, 0o755, 0, 0);
        }
        fs
    }
}

fn exited(code: i32, stdout: String, stderr: String) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.into_bytes(),
        stderr: stderr.into_bytes(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn ok() -> Output {
    exited(0, String::new(), String::new())
}

fn parent_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
        None => "/".to_string(),
    }
}

impl FakeFs {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn ino(&mut self) -> u64 {
        self.next_ino += 1;
        self.next_ino
    }

    pub fn mkdir_node(&mut self, path: &str, mode: u32, uid: u32, gid: u32) {
        let (t, i) = (self.tick(), self.ino());
        self.nodes.insert(
            path.to_string(),
            FakeNode {
                kind: FakeKind::Dir,
                mode,
                uid,
                gid,
                ino: i,
                mtime: t,
                ctime: t,
            },
        );
    }

    pub fn put_file(&mut self, path: &str, data: &[u8], mode: u32, uid: u32, gid: u32) {
        let (t, i) = (self.tick(), self.ino());
        self.nodes.insert(
            path.to_string(),
            FakeNode {
                kind: FakeKind::File(data.to_vec()),
                mode,
                uid,
                gid,
                ino: i,
                mtime: t,
                ctime: t,
            },
        );
    }

    pub fn file_bytes(&self, path: &str) -> Option<Vec<u8>> {
        match self.nodes.get(path) {
            Some(FakeNode {
                kind: FakeKind::File(b),
                ..
            }) => Some(b.clone()),
            _ => None,
        }
    }

    fn stat_time(t: u64) -> String {
        format!(
            "2026-10-02 {:02}:{:02}:{:02}.000000000 +0000",
            (t / 3600) % 24,
            (t / 60) % 60,
            t % 60
        )
    }

    fn stat(&self, path: &str) -> Output {
        match self.nodes.get(path) {
            None => exited(
                1,
                String::new(),
                format!(
                    "stat: cannot statx {}: No such file or directory\n",
                    crate::targetfs::q(path)
                ),
            ),
            Some(n) => {
                let (kind, size) = match &n.kind {
                    FakeKind::Dir => ("directory", 4096),
                    FakeKind::File(b) if b.is_empty() => ("regular empty file", 0),
                    FakeKind::File(b) => ("regular file", b.len()),
                    FakeKind::Symlink(t) => ("symbolic link", t.len()),
                };
                exited(
                    0,
                    format!(
                        "{}|{:o}|{}|{}|{}|2049|{}|{}|{}\n",
                        kind,
                        n.mode & 0o7777,
                        n.uid,
                        n.gid,
                        size,
                        n.ino,
                        Self::stat_time(n.mtime),
                        Self::stat_time(n.ctime)
                    ),
                    String::new(),
                )
            }
        }
    }

    fn fail(msg: &str) -> Output {
        exited(1, String::new(), format!("{}\n", msg))
    }

    /// Serve one filesystem command, mutating the model. Returns the output
    /// and the paths whose *recognizable manager input* changed
    /// (`(path, is_link, present_after)`).
    pub(crate) fn run(
        &mut self,
        prog: &str,
        args: &[String],
        stdin: Option<&[u8]>,
        uid: u32,
        gid: u32,
    ) -> Option<(Output, Vec<TouchedPath>)> {
        let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let mut touched: Vec<TouchedPath> = Vec::new();
        let out = match (prog, a.as_slice()) {
            ("stat", ["-c", "%F|%a|%u|%g|%s|%d|%i|%y|%z", "--", p]) => {
                let mut o = self.stat(p);
                if self.freeze_mtime && o.completion == Completion::Exited(0) {
                    // report a constant timestamp for regular files
                    if let Some(FakeNode {
                        kind: FakeKind::File(_),
                        ..
                    }) = self.nodes.get(*p)
                    {
                        let text = String::from_utf8_lossy(&o.stdout).to_string();
                        let mut parts: Vec<String> =
                            text.trim_end().split('|').map(|s| s.to_string()).collect();
                        if parts.len() == 9 {
                            parts[7] = Self::stat_time(1);
                            parts[8] = Self::stat_time(1);
                            o.stdout = format!("{}\n", parts.join("|")).into_bytes();
                        }
                    }
                }
                o
            }
            ("sha256sum", ["--", p]) => match self.nodes.get(*p) {
                Some(FakeNode {
                    kind: FakeKind::File(b),
                    ..
                }) => exited(
                    0,
                    format!("{}  {}\n", crate::resources::sha256_hex(b), p),
                    String::new(),
                ),
                _ => Self::fail(&format!("sha256sum: {}: No such file or directory", p)),
            },
            ("cat", ["--", p]) => match self.nodes.get(*p) {
                Some(FakeNode {
                    kind: FakeKind::File(b),
                    ..
                }) => Output {
                    completion: Completion::Exited(0),
                    stdout: b.clone(),
                    stderr: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                },
                _ => Self::fail(&format!("cat: {}: No such file or directory", p)),
            },
            ("readlink", ["-n", "--", p]) => match self.nodes.get(*p) {
                Some(FakeNode {
                    kind: FakeKind::Symlink(t),
                    ..
                }) => Output {
                    completion: Completion::Exited(0),
                    stdout: t.clone().into_bytes(),
                    stderr: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                },
                _ => exited(1, String::new(), String::new()),
            },
            ("getfattr", ["-d", "-m", "-", "-e", "base64", "--absolute-names", "--", p]) => {
                if self.nodes.contains_key(*p) {
                    ok()
                } else {
                    Self::fail(&format!("getfattr: {}: No such file or directory", p))
                }
            }
            ("mktemp", ["-d", "-p", dir, tmpl]) if tmpl.starts_with(".sinter-stage.") => {
                if !self.nodes.contains_key(*dir) {
                    return Some((Self::fail("mktemp: parent missing"), touched));
                }
                self.staging_counter += 1;
                let p = format!("{}/.sinter-stage.fk{}", dir, self.staging_counter);
                self.mkdir_node(&p, 0o700, uid, gid);
                exited(0, format!("{}\n", p), String::new())
            }
            ("chmod", [mode, "--", p]) => match self.nodes.get_mut(*p) {
                Some(n) => {
                    n.mode = u32::from_str_radix(mode, 8).unwrap_or(n.mode);
                    self.clock += 1;
                    n.ctime = self.clock;
                    ok()
                }
                None => Self::fail("chmod: no such file"),
            },
            ("chown", [owner, "--", p]) => match self.nodes.get_mut(*p) {
                Some(n) => {
                    if let Some((u, g)) = owner.split_once(':') {
                        n.uid = u.parse().unwrap_or(n.uid);
                        n.gid = g.parse().unwrap_or(n.gid);
                    }
                    self.clock += 1;
                    n.ctime = self.clock;
                    ok()
                }
                None => Self::fail("chown: no such file"),
            },
            ("mkdir", ["--", p]) => {
                if self.nodes.contains_key(*p) || !self.nodes.contains_key(&parent_of(p)) {
                    Self::fail("mkdir: cannot create directory")
                } else {
                    self.mkdir_node(p, 0o755, uid, gid);
                    ok()
                }
            }
            ("rmdir", [p]) | ("rmdir", ["--", p]) => match self.nodes.get(*p) {
                Some(FakeNode {
                    kind: FakeKind::Dir,
                    ..
                }) => {
                    let prefix = format!("{}/", p);
                    if self.nodes.keys().any(|k| k.starts_with(&prefix)) {
                        Self::fail("rmdir: directory not empty")
                    } else {
                        self.nodes.remove(*p);
                        ok()
                    }
                }
                _ => Self::fail("rmdir: failed"),
            },
            ("rm", ["-f", "--", p]) => {
                if let Some(n) = self.nodes.get(*p) {
                    let link = matches!(n.kind, FakeKind::Symlink(_));
                    if !matches!(n.kind, FakeKind::Dir) {
                        self.nodes.remove(*p);
                        touched.push((p.to_string(), link, false));
                    }
                }
                ok()
            }
            ("dd", ["status=none", of]) if of.starts_with("of=") => {
                let p = &of[3..];
                if !self.nodes.contains_key(&parent_of(p)) {
                    Self::fail("dd: failed to open")
                } else {
                    let data = stdin.unwrap_or(&[]).to_vec();
                    self.put_file(p, &data, 0o644, uid, gid);
                    ok()
                }
            }
            ("mv", ["-T", "-f", "--", from, to]) => match self.nodes.remove(*from) {
                None => Self::fail("mv: cannot stat source"),
                Some(mut n) => {
                    let link = matches!(n.kind, FakeKind::Symlink(_));
                    self.clock += 1;
                    n.mtime = self.clock;
                    n.ctime = self.clock;
                    self.nodes.insert(to.to_string(), n);
                    touched.push((to.to_string(), link, true));
                    ok()
                }
            },
            ("ln", ["-s", "--", target, link]) => {
                if self.nodes.contains_key(*link) || !self.nodes.contains_key(&parent_of(link)) {
                    Self::fail("ln: failed to create symbolic link")
                } else {
                    let (t, i) = (self.tick(), self.ino());
                    self.nodes.insert(
                        link.to_string(),
                        FakeNode {
                            kind: FakeKind::Symlink(target.to_string()),
                            mode: 0o777,
                            uid,
                            gid,
                            ino: i,
                            mtime: t,
                            ctime: t,
                        },
                    );
                    touched.push((link.to_string(), true, true));
                    ok()
                }
            }
            _ => return None,
        };
        Some((out, touched))
    }

    /// Unit (if any) whose disk copy a touched path changes, given the
    /// default UnitPath roots.
    pub(crate) fn unit_of_touched(path: &str, link: bool) -> Option<String> {
        let roots: Vec<String> = FAKE_UNIT_PATH_OUTPUT
            .trim_end()
            .trim_start_matches("UnitPath=")
            .split(' ')
            .map(|s| s.to_string())
            .collect();
        let shape = path_shape(path, link)?;
        resolve_input(&shape, &roots)?.unit
    }
}
