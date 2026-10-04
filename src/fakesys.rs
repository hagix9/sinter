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

// ---------------------------------------------------------------------------
// scripted local account database
// ---------------------------------------------------------------------------

/// One passwd record of the scripted target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

/// One group record of the scripted target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeGroup {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

/// A small, honest model of the local account databases and of the shadow-utils
/// commands Sinter's `user`/`group` resources issue. `root` always exists;
/// `useradd`, `usermod`, `userdel`, `groupadd` and `groupdel` obey the real
/// tools' documented refusals (existing name, used id, missing group, a user's
/// primary group, a user with running processes). Everything else is a test
/// knob. It cannot prove real shadow-utils behavior: that stays real-OS
/// acceptance.
#[derive(Debug, Clone)]
pub struct FakeAccounts {
    /// Accounts in the local files database (besides `root`).
    pub users: Vec<FakeUser>,
    pub groups: Vec<FakeGroup>,
    /// Accounts only another identity source (NSS: LDAP/SSSD) provides: found
    /// by an ordinary lookup, absent from `getent -s files`.
    pub nss_users: Vec<FakeUser>,
    pub nss_groups: Vec<FakeGroup>,
    /// Users with running processes: `userdel` and `usermod -d` fail.
    pub running_users: BTreeSet<String>,
    /// `USERGROUPS_ENAB yes`: `useradd` without `-g` creates a same-name
    /// group, and `userdel` removes that group when nothing else uses it.
    pub usergroups_enab: bool,
    /// Forced answer per command basename (`useradd`, ...), served instead of
    /// the command's effect.
    pub forced: BTreeMap<String, Output>,
    /// Commands that apply their effect and then exit non-zero.
    pub fail_after_effect: BTreeSet<String>,
    /// The `-s files` lookup itself fails with this completion (a getent that
    /// does not support the option).
    pub files_lookup_fails: Option<Completion>,
    /// Stored shadow password fields by user name (what `getent -s files
    /// shadow` shows after the name). A local user without an entry has
    /// `initial_shadow`.
    pub shadows: BTreeMap<String, String>,
    /// The field a fresh or unlisted local account has (`!` on Ubuntu and
    /// RHEL 10, `!!` on RHEL 9).
    pub initial_shadow: String,
    /// Local users whose shadow record does not exist (`getent` exit 2).
    pub no_shadow_users: BTreeSet<String>,
    /// Forced answer to the shadow lookup (an unreadable database, ...).
    pub forced_shadow: Option<Output>,
    /// Every modeled account command that reached the target, in order:
    /// program basename, argv and standard input. Clones of the target share
    /// it, so a test can read it after the run.
    pub calls: CallLog,
}

/// One modeled account command: program basename, argv, standard input.
pub type FakeCall = (String, Vec<String>, Option<Vec<u8>>);

/// The shared log of [`FakeCall`]s.
pub type CallLog = std::sync::Arc<std::sync::Mutex<Vec<FakeCall>>>;

impl Default for FakeAccounts {
    fn default() -> Self {
        FakeAccounts {
            users: Vec::new(),
            groups: Vec::new(),
            nss_users: Vec::new(),
            nss_groups: Vec::new(),
            running_users: BTreeSet::new(),
            usergroups_enab: true,
            forced: BTreeMap::new(),
            fail_after_effect: BTreeSet::new(),
            files_lookup_fails: None,
            shadows: BTreeMap::new(),
            initial_shadow: "!".to_string(),
            no_shadow_users: BTreeSet::new(),
            forced_shadow: None,
            calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

fn out(code: i32, stdout: String, stderr: String) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.into_bytes(),
        stderr: stderr.into_bytes(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn user_line(u: &FakeUser) -> String {
    format!("{}:x:{}:{}::{}:{}\n", u.name, u.uid, u.gid, u.home, u.shell)
}

fn group_line(g: &FakeGroup) -> String {
    format!("{}:x:{}:{}\n", g.name, g.gid, g.members.join(","))
}

impl FakeAccounts {
    fn root_user() -> FakeUser {
        FakeUser {
            name: "root".into(),
            uid: 0,
            gid: 0,
            home: "/root".into(),
            shell: "/bin/bash".into(),
        }
    }

    fn root_group() -> FakeGroup {
        FakeGroup {
            name: "root".into(),
            gid: 0,
            members: vec![],
        }
    }

    /// The identity the fake target logs in as (the executor's `fakeuser`).
    fn login(target_uid: u32, target_gid: u32, home: &str) -> (FakeUser, FakeGroup) {
        (
            FakeUser {
                name: "fakeuser".into(),
                uid: target_uid,
                gid: target_gid,
                home: home.to_string(),
                shell: "/bin/sh".into(),
            },
            FakeGroup {
                name: "fakegroup".into(),
                gid: target_gid,
                members: vec![],
            },
        )
    }

    fn files_users(&self, login: &FakeUser) -> Vec<FakeUser> {
        let mut v = vec![Self::root_user(), login.clone()];
        v.extend(self.users.iter().cloned());
        v
    }

    fn files_groups(&self, login: &FakeGroup) -> Vec<FakeGroup> {
        let mut v = vec![Self::root_group(), login.clone()];
        v.extend(self.groups.iter().cloned());
        v
    }

    /// `getent [-s files] passwd|group [key]`.
    pub(crate) fn getent(
        &self,
        local_only: bool,
        db: &str,
        key: Option<&str>,
        target: (u32, u32, &str),
    ) -> Output {
        if local_only {
            if let Some(c) = &self.files_lookup_fails {
                return Output {
                    completion: c.clone(),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                };
            }
        }
        let (lu, lg) = Self::login(target.0, target.1, target.2);
        match db {
            "passwd" => {
                let mut all = self.files_users(&lu);
                if !local_only {
                    all.extend(self.nss_users.iter().cloned());
                }
                match key {
                    None => out(0, all.iter().map(user_line).collect(), String::new()),
                    Some(k) => {
                        let hit = match k.parse::<u32>() {
                            Ok(id) => all.iter().find(|u| u.uid == id),
                            Err(_) => all.iter().find(|u| u.name == k),
                        };
                        match hit {
                            Some(u) => out(0, user_line(u), String::new()),
                            None => out(2, String::new(), String::new()),
                        }
                    }
                }
            }
            "group" => {
                let mut all = self.files_groups(&lg);
                if !local_only {
                    all.extend(self.nss_groups.iter().cloned());
                }
                match key {
                    None => out(0, all.iter().map(group_line).collect(), String::new()),
                    Some(k) => {
                        let hit = match k.parse::<u32>() {
                            Ok(id) => all.iter().find(|g| g.gid == id),
                            Err(_) => all.iter().find(|g| g.name == k),
                        };
                        match hit {
                            Some(g) => out(0, group_line(g), String::new()),
                            None => out(2, String::new(), String::new()),
                        }
                    }
                }
            }
            _ => out(2, String::new(), String::new()),
        }
    }

    fn next_free(&self, from: u32, step: i64, login: (u32, u32)) -> u32 {
        let mut n = from as i64;
        loop {
            let id = n as u32;
            let used = id == login.0
                || id == login.1
                || id == 0
                || self.users.iter().any(|u| u.uid == id)
                || self.groups.iter().any(|g| g.gid == id);
            if !used {
                return id;
            }
            n += step;
        }
    }

    /// `getent -s files shadow <name>`. Only root can read it; anyone else
    /// gets glibc's silent "not found".
    pub(crate) fn shadow_getent(
        &self,
        name: Option<&str>,
        root: bool,
        target: (u32, u32, &str),
    ) -> Output {
        if let Some(o) = &self.forced_shadow {
            return o.clone();
        }
        let Some(name) = name else {
            return out(2, String::new(), String::new());
        };
        let (lu, _) = Self::login(target.0, target.1, target.2);
        if !root
            || self.no_shadow_users.contains(name)
            || !self.files_users(&lu).iter().any(|u| u.name == name)
        {
            return out(2, String::new(), String::new());
        }
        let field = self
            .shadows
            .get(name)
            .map(String::as_str)
            .unwrap_or(&self.initial_shadow);
        out(
            0,
            format!("{}:{}:19000:0:99999:7:::\n", name, field),
            String::new(),
        )
    }

    /// `chpasswd -e` reading `name:hash` lines on standard input: no PAM, no
    /// hash validation (shadow before 4.19), only root, and every line must
    /// name an existing local user. All lines are applied or none.
    fn chpasswd(
        &mut self,
        args: &[String],
        stdin: Option<&[u8]>,
        root: bool,
        lu: &FakeUser,
    ) -> Output {
        if !root {
            return out(1, String::new(), "chpasswd: Permission denied.".into());
        }
        if args != ["-e"] {
            return out(
                1,
                String::new(),
                "chpasswd: this fake models only chpasswd -e".into(),
            );
        }
        let Some(text) = stdin.and_then(|b| std::str::from_utf8(b).ok()) else {
            return out(1, String::new(), "chpasswd: no input".into());
        };
        let mut updates = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let Some((name, hash)) = line.split_once(':') else {
                return out(
                    1,
                    String::new(),
                    format!("chpasswd: line {}: missing new password", n + 1),
                );
            };
            if !self.all_users(lu).iter().any(|u| u.name == name) {
                return out(
                    1,
                    String::new(),
                    format!(
                        "chpasswd: (line {}, user {}) password not changed",
                        n + 1,
                        name
                    ),
                );
            }
            updates.push((name.to_string(), hash.to_string()));
        }
        for (name, hash) in updates {
            self.shadows.insert(name, hash);
        }
        out(0, String::new(), String::new())
    }

    /// Run one of the modeled shadow-utils commands. `None` = not modeled.
    pub(crate) fn command(
        &mut self,
        prog: &str,
        args: &[String],
        stdin: Option<&[u8]>,
        root: bool,
        target: (u32, u32, &str),
    ) -> Option<Output> {
        if !matches!(
            prog,
            "useradd" | "usermod" | "userdel" | "groupadd" | "groupdel" | "chpasswd"
        ) {
            return None;
        }
        if let Ok(mut log) = self.calls.lock() {
            log.push((prog.to_string(), args.to_vec(), stdin.map(|b| b.to_vec())));
        }
        if let Some(o) = self.forced.get(prog) {
            return Some(o.clone());
        }
        let (lu, lg) = Self::login(target.0, target.1, target.2);
        let result = match prog {
            "groupadd" => self.groupadd(args, &lu, &lg),
            "groupdel" => self.groupdel(args),
            "useradd" => self.useradd(args, &lu, &lg),
            "usermod" => self.usermod(args),
            "chpasswd" => self.chpasswd(args, stdin, root, &lu),
            _ => self.userdel(args),
        };
        if self.fail_after_effect.contains(prog) && result.is_success() {
            return Some(out(
                1,
                String::new(),
                format!("{}: injected failure after effect", prog),
            ));
        }
        Some(result)
    }

    fn all_groups(&self, lg: &FakeGroup) -> Vec<FakeGroup> {
        self.files_groups(lg)
    }

    fn all_users(&self, lu: &FakeUser) -> Vec<FakeUser> {
        self.files_users(lu)
    }

    fn groupadd(&mut self, args: &[String], lu: &FakeUser, lg: &FakeGroup) -> Output {
        let mut gid: Option<u32> = None;
        let mut system = false;
        let mut name: Option<&str> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--system" => system = true,
                "-g" => {
                    i += 1;
                    gid = args.get(i).and_then(|v| v.parse().ok());
                    if gid.is_none() {
                        return out(3, String::new(), "groupadd: invalid group ID".into());
                    }
                }
                other if other.starts_with('-') => {
                    return out(
                        2,
                        String::new(),
                        format!("groupadd: invalid option {}", other),
                    )
                }
                other => name = Some(other),
            }
            i += 1;
        }
        let Some(name) = name else {
            return out(2, String::new(), "groupadd: missing group name".into());
        };
        if self.all_groups(lg).iter().any(|g| g.name == name) {
            return out(
                9,
                String::new(),
                format!("groupadd: group '{}' already exists", name),
            );
        }
        let gid = match gid {
            Some(g) => {
                if self.all_groups(lg).iter().any(|x| x.gid == g) {
                    return out(
                        4,
                        String::new(),
                        format!("groupadd: GID '{}' already exists", g),
                    );
                }
                g
            }
            None if system => self.next_free(998, -1, (lu.uid, lg.gid)),
            None => self.next_free(1001, 1, (lu.uid, lg.gid)),
        };
        self.groups.push(FakeGroup {
            name: name.to_string(),
            gid,
            members: vec![],
        });
        out(0, String::new(), String::new())
    }

    fn groupdel(&mut self, args: &[String]) -> Output {
        let [name] = args else {
            return out(2, String::new(), "groupdel: expected one group name".into());
        };
        let Some(pos) = self.groups.iter().position(|g| &g.name == name) else {
            return out(
                6,
                String::new(),
                format!("groupdel: group '{}' does not exist", name),
            );
        };
        let gid = self.groups[pos].gid;
        if self.users.iter().any(|u| u.gid == gid) {
            return out(
                8,
                String::new(),
                "groupdel: cannot remove the primary group of user".to_string(),
            );
        }
        self.groups.remove(pos);
        out(0, String::new(), String::new())
    }

    fn useradd(&mut self, args: &[String], lu: &FakeUser, lg: &FakeGroup) -> Output {
        let (mut uid, mut group, mut groups, mut shell, mut home) = (
            None::<u32>,
            None::<String>,
            None::<String>,
            None::<String>,
            None::<String>,
        );
        let (mut system, mut name) = (false, None::<String>);
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            let val = |i: &mut usize| -> Option<String> {
                *i += 1;
                args.get(*i).cloned()
            };
            match a {
                "--system" => system = true,
                "-m" | "-M" => {}
                "-u" => uid = val(&mut i).and_then(|v| v.parse().ok()),
                "-g" => group = val(&mut i),
                "-G" => groups = val(&mut i),
                "-s" => shell = val(&mut i),
                "-d" => home = val(&mut i),
                o if o.starts_with('-') => {
                    return out(2, String::new(), format!("useradd: invalid option {}", o))
                }
                o => name = Some(o.to_string()),
            }
            i += 1;
        }
        let Some(name) = name else {
            return out(2, String::new(), "useradd: missing user name".into());
        };
        if self.all_users(lu).iter().any(|u| u.name == name) {
            return out(
                9,
                String::new(),
                format!("useradd: user '{}' already exists", name),
            );
        }
        let uid = match uid {
            Some(u) => {
                if self.all_users(lu).iter().any(|x| x.uid == u) {
                    return out(
                        4,
                        String::new(),
                        format!("useradd: UID {} is not unique", u),
                    );
                }
                u
            }
            None if system => self.next_free(998, -1, (lu.uid, lg.gid)),
            None => self.next_free(1001, 1, (lu.uid, lg.gid)),
        };
        let supp: Vec<String> = groups
            .map(|g| g.split(',').map(String::from).collect())
            .unwrap_or_default();
        for g in &supp {
            if !self.all_groups(lg).iter().any(|x| &x.name == g) {
                return out(
                    6,
                    String::new(),
                    format!("useradd: group '{}' does not exist", g),
                );
            }
        }
        let gid = match group {
            Some(g) => match self.all_groups(lg).iter().find(|x| x.name == g) {
                Some(x) => x.gid,
                None => {
                    return out(
                        6,
                        String::new(),
                        format!("useradd: group '{}' does not exist", g),
                    )
                }
            },
            None if self.usergroups_enab => {
                if self.all_groups(lg).iter().any(|x| x.name == name) {
                    return out(
                        9,
                        String::new(),
                        format!(
                            "useradd: group {} exists - if you want to add this user to that group, use -g.",
                            name
                        ),
                    );
                }
                let gid = if self.all_groups(lg).iter().any(|x| x.gid == uid) {
                    self.next_free(1001, 1, (lu.uid, lg.gid))
                } else {
                    uid
                };
                self.groups.push(FakeGroup {
                    name: name.clone(),
                    gid,
                    members: vec![],
                });
                gid
            }
            None => 100,
        };
        for g in &supp {
            if let Some(x) = self.groups.iter_mut().find(|x| &x.name == g) {
                x.members.push(name.clone());
            }
        }
        self.users.push(FakeUser {
            home: home.unwrap_or_else(|| format!("/home/{}", name)),
            shell: shell.unwrap_or_else(|| "/bin/sh".into()),
            name,
            uid,
            gid,
        });
        out(0, String::new(), String::new())
    }

    fn usermod(&mut self, args: &[String]) -> Output {
        let (mut group, mut shell, mut home, mut groups) = (
            None::<String>,
            None::<String>,
            None::<String>,
            None::<String>,
        );
        let (mut append, mut name) = (false, None::<String>);
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            let val = |i: &mut usize| -> Option<String> {
                *i += 1;
                args.get(*i).cloned()
            };
            match a {
                "-a" => append = true,
                "-g" => group = val(&mut i),
                "-s" => shell = val(&mut i),
                "-d" => home = val(&mut i),
                "-G" => groups = val(&mut i),
                o if o.starts_with('-') => {
                    return out(2, String::new(), format!("usermod: invalid option {}", o))
                }
                o => name = Some(o.to_string()),
            }
            i += 1;
        }
        let Some(name) = name else {
            return out(2, String::new(), "usermod: missing user name".into());
        };
        let Some(pos) = self.users.iter().position(|u| u.name == name) else {
            return out(
                6,
                String::new(),
                format!("usermod: user '{}' does not exist", name),
            );
        };
        if groups.is_some() && !append {
            return out(
                2,
                String::new(),
                "usermod: this fake only models -a -G".into(),
            );
        }
        if home.is_some() && self.running_users.contains(&name) {
            return out(
                8,
                String::new(),
                format!("usermod: user {} is currently used by process 4242", name),
            );
        }
        let new_gid = match &group {
            Some(g) => match self.groups.iter().find(|x| &x.name == g) {
                Some(x) => Some(x.gid),
                None if g == "root" => Some(0),
                None if g == "fakegroup" => None,
                None => {
                    return out(
                        6,
                        String::new(),
                        format!("usermod: group '{}' does not exist", g),
                    )
                }
            },
            None => None,
        };
        let supp: Vec<String> = groups
            .map(|g| g.split(',').map(String::from).collect())
            .unwrap_or_default();
        for g in &supp {
            if !self.groups.iter().any(|x| &x.name == g) && g != "root" && g != "fakegroup" {
                return out(
                    6,
                    String::new(),
                    format!("usermod: group '{}' does not exist", g),
                );
            }
        }
        if let Some(g) = new_gid {
            self.users[pos].gid = g;
        }
        if let Some(s) = shell {
            self.users[pos].shell = s;
        }
        if let Some(h) = home {
            self.users[pos].home = h;
        }
        for g in &supp {
            if let Some(x) = self.groups.iter_mut().find(|x| &x.name == g) {
                if !x.members.contains(&name) {
                    x.members.push(name.clone());
                }
            }
        }
        out(0, String::new(), String::new())
    }

    fn userdel(&mut self, args: &[String]) -> Output {
        if args.iter().any(|a| a.starts_with('-')) {
            return out(
                2,
                String::new(),
                "userdel: this fake models only plain userdel".into(),
            );
        }
        let [name] = args else {
            return out(2, String::new(), "userdel: expected one user name".into());
        };
        let Some(pos) = self.users.iter().position(|u| &u.name == name) else {
            return out(
                6,
                String::new(),
                format!("userdel: user '{}' does not exist", name),
            );
        };
        if self.running_users.contains(name) {
            return out(
                8,
                String::new(),
                format!("userdel: user {} is currently used by process 4242", name),
            );
        }
        let gone = self.users.remove(pos);
        self.shadows.remove(name);
        for g in &mut self.groups {
            g.members.retain(|m| m != name);
        }
        if self.usergroups_enab && !self.users.iter().any(|u| u.gid == gone.gid) {
            self.groups
                .retain(|g| !(g.gid == gone.gid && g.name == gone.name));
        }
        out(0, String::new(), String::new())
    }
}
