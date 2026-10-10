use crate::error::{Result, SinterError};
use crate::executor::{Completion, ExecRequest, Executor, Output};
use crate::paths::{ancestor_dirs, mode_to_string, parent_and_name};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjKind {
    Absent,
    File,
    Dir,
    Symlink,
    Other,
}

impl ObjKind {
    pub fn describe(self) -> &'static str {
        match self {
            ObjKind::Absent => "absent",
            ObjKind::File => "file",
            ObjKind::Dir => "directory",
            ObjKind::Symlink => "symlink",
            ObjKind::Other => "other",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Stat {
    pub kind: ObjKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub dev: u64,
    pub ino: u64,
    pub mtime: String,
    pub ctime: String,
}

#[derive(Debug, Clone, Default)]
pub struct Xattrs {
    pub attrs: BTreeMap<String, String>,
    /// True when the enumeration was performed successfully.
    pub inspected: bool,
}

impl Xattrs {
    /// Return the first access/label-affecting attribute that makes replacement
    /// unsafe under DESIGN §24.4.
    ///
    /// `security.selinux` is deliberately NOT unsafe: a MAC label can only
    /// restrict access (never grant discretionary write, so it is irrelevant
    /// to the parent trust boundary), and the captured label is restored on
    /// the staged file before atomic publication via `preserved_attrs`.
    /// Every other `security.*`/`trusted.*` attribute and all POSIX/NFSv4
    /// ACL attributes remain disqualifying because they cannot be safely
    /// preserved through replacement.
    pub fn unsafe_attr(&self) -> Option<String> {
        for name in self.attrs.keys() {
            if name == "security.selinux" {
                continue;
            }
            if name.starts_with("security.")
                || name.starts_with("trusted.")
                || name.starts_with("system.posix_acl")
                || name.starts_with("system.nfs4_acl")
                || name == "system.posix_acl_access"
                || name == "system.posix_acl_default"
            {
                return Some(name.clone());
            }
        }
        None
    }

    pub fn user_attrs(&self) -> impl Iterator<Item = (&String, &String)> {
        self.attrs.iter().filter(|(k, _)| k.starts_with("user."))
    }

    /// Attributes carried over to the replacement object before publication:
    /// all `user.*` attributes plus the `security.selinux` label. Other
    /// security/ACL attributes are never copied — they are disqualifying via
    /// `unsafe_attr` instead.
    pub fn preserved_attrs(&self) -> impl Iterator<Item = (&String, &String)> {
        self.attrs
            .iter()
            .filter(|(k, _)| k.starts_with("user.") || k.as_str() == "security.selinux")
    }
}

/// Classification of a getfacl capture under DESIGN §24.4.
enum AclClass {
    /// All three base entries are present and well-formed.
    Complete { extended: bool },
    /// Required base entries are missing (including empty output).
    Incomplete,
    /// A base entry is present but malformed (e.g. `user::garbage`).
    Malformed,
}

/// Typed cleanup outcome. Cleanup must never overwrite publication truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupState {
    Ok,
    Failed,
    Indeterminate,
}

fn is_valid_acl_perm(p: &str) -> bool {
    // POSIX ACL permission string is exactly three positional slots:
    //   position 1: r or -
    //   position 2: w or -
    //   position 3: x or -
    let mut it = p.chars();
    match (it.next(), it.next(), it.next(), it.next()) {
        (Some(r), Some(w), Some(x), None) => {
            matches!(r, 'r' | '-') && matches!(w, 'w' | '-') && matches!(x, 'x' | '-')
        }
        _ => false,
    }
}

/// Whether a getfattr `-e base64` value can be authoritatively interpreted.
fn is_valid_xattr_encoded(v: &str) -> bool {
    if v.is_empty() {
        return true;
    }
    if let Some(rest) = v.strip_prefix("0s") {
        return rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    }
    if let Some(rest) = v.strip_prefix("0x") {
        return rest.chars().all(|c| c.is_ascii_hexdigit());
    }
    false
}

/// Interpret one single-operand `getfattr -d -m - -e base64` capture. Only a
/// complete, successful enumeration is authoritative: any abnormal completion,
/// truncation, invalid UTF-8 or uninterpretable attribute line yields
/// `inspected == false`, which callers must treat as a refusal, never as "no
/// attributes".
fn interpret_getfattr_capture(out: &Output) -> Xattrs {
    let code = match out.completion {
        Completion::Exited(c) => c,
        _ => {
            return Xattrs {
                attrs: BTreeMap::new(),
                inspected: false,
            }
        }
    };
    if code != 0 {
        return Xattrs {
            attrs: BTreeMap::new(),
            inspected: false,
        };
    }
    if out.stdout_truncated || out.stderr_truncated {
        return Xattrs {
            attrs: BTreeMap::new(),
            inspected: false,
        };
    }
    let text = match std::str::from_utf8(&out.stdout) {
        Ok(text) => text,
        Err(_) => {
            return Xattrs {
                attrs: BTreeMap::new(),
                inspected: false,
            }
        }
    };
    parse_getfattr_text(text)
}

/// Parse the attribute lines of one object's `getfattr -e base64` output.
/// The same predicate serves the single-operand capture and each attributed
/// block of a batched capture, so a batch can never be more permissive than
/// the sequential observation.
fn parse_getfattr_text(text: &str) -> Xattrs {
    let mut attrs = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Xattrs {
                attrs,
                inspected: false,
            };
        };
        if k.trim().is_empty() {
            return Xattrs {
                attrs,
                inspected: false,
            };
        }
        let value = v.trim();
        // getfattr -e base64 emits `0s<base64>` (or empty). Reject values
        // that cannot be authoritatively interpreted (DESIGN §24.4).
        if !is_valid_xattr_encoded(value) {
            return Xattrs {
                attrs,
                inspected: false,
            };
        }
        attrs.insert(k.trim().to_string(), value.to_string());
    }
    Xattrs {
        attrs,
        inspected: true,
    }
}

/// Parse a getfacl `-c -p` capture. Distinguishes a complete ACL (possibly
/// without extended entries) from empty/incomplete/malformed output.
fn classify_acl_text(text: &str) -> AclClass {
    let mut has_user = false;
    let mut has_group = false;
    let mut has_other = false;
    let mut extended = false;
    let mut saw_any = false;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        saw_any = true;
        let fields: Vec<&str> = line.split(':').collect();
        match fields.as_slice() {
            ["user", "", perm] => {
                if !is_valid_acl_perm(perm) {
                    return AclClass::Malformed;
                }
                has_user = true;
            }
            ["group", "", perm] => {
                if !is_valid_acl_perm(perm) {
                    return AclClass::Malformed;
                }
                has_group = true;
            }
            ["other", "", perm] => {
                if !is_valid_acl_perm(perm) {
                    return AclClass::Malformed;
                }
                has_other = true;
            }
            ["user", name, perm] => {
                if name.is_empty() || perm.is_empty() {
                    return AclClass::Malformed;
                }
                extended = true;
            }
            ["group", name, perm] => {
                if name.is_empty() || perm.is_empty() {
                    return AclClass::Malformed;
                }
                extended = true;
            }
            ["mask", "", perm] => {
                if !is_valid_acl_perm(perm) {
                    return AclClass::Malformed;
                }
                extended = true;
            }
            ["default", rest @ ..] => {
                if rest.is_empty() {
                    return AclClass::Malformed;
                }
                extended = true;
            }
            _ => return AclClass::Malformed,
        }
    }

    if !saw_any || !(has_user && has_group && has_other) {
        return AclClass::Incomplete;
    }
    AclClass::Complete { extended }
}

/// Zero-cost capability token proving a `TargetFs` may mutate the target.
///
/// The defense is layered, not a single compile-time promise, and each layer
/// is stated exactly:
///
/// * The type has a private field and a private constructor, and it is not
///   `Clone`/`Copy`. Outside of `TargetFs::mutation_permit` there is no way to
///   *construct* a value of this type, so code which never calls that method
///   (the entire Audit control path) cannot obtain one — that is a
///   compile-time property of the Audit path specifically.
/// * `TargetFs::mutation_permit` is `pub(crate)` and returns `Err` at runtime
///   unless the `TargetFs` was constructed with mutation allowed. It is the
///   authority boundary for the rest of the crate: reaching it does not by
///   itself grant mutation, and on a read-only (Plan/Audit) target it always
///   fails closed.
/// * Raw command execution (`TargetFs::exec`) is `pub(crate)` and requires a
///   borrowed `&MutationPermit`, so it inherits the same runtime check.
/// * Every mutating helper (`chmod`, `chown`, `mkdir`, `rmdir`, `rm`, `ln`,
///   `mv`, `write_bytes`, `set_xattr`, ...) takes `&MutationPermit` as well.
/// * `Engine::run_audit` refuses to start when a permit is obtainable at all,
///   and Audit never dispatches through the Plan/Apply control flow.
///
/// So the accurate claim is: an Audit runner has no reachable construction of
/// the token, and every mutation channel additionally re-checks authority at
/// runtime and fails closed. It is *not* claimed that an arbitrary
/// crate-internal call site is literally rejected by the type system —
/// `mutation_permit` is the runtime authority gate that backstops the
/// structural one.
pub struct MutationPermit(());

/// The exact property list requested for a service/unit observation. The
/// answer must contain each of these four properties exactly once.
/// `NeedDaemonReload` is a limited observation: `no` does not prove the
/// loaded definition equals the bytes on disk.
pub const SERVICE_SHOW_PROPERTIES: &str = "LoadState,ActiveState,UnitFileState,NeedDaemonReload";

impl MutationPermit {
    // Only `TargetFs::mutation_permit` may construct this. Private field +
    // private constructor = code which does not call that method cannot name
    // a value of this type; the runtime check in `mutation_permit` remains
    // the authority gate for call sites that can reach it.
    fn new() -> Self {
        MutationPermit(())
    }
}

pub struct TargetFs {
    // The raw executor is private: command execution reaches the target only
    // through the observation methods or the permit-gated `exec` below, so a
    // read-only TargetFs cannot be turned into a mutation channel (RA-01).
    ex: Executor,
    pub sudo: bool,
    pub target_uid: u32,
    pub target_gid: u32,
    pub home: String,
    /// Package backend selected from the detected platform. `None` means the
    /// platform has no supported package manager; package resources must fail
    /// explicitly rather than guessing a backend.
    pub pkg_backend: Option<crate::platform::PackageBackend>,
    has_getfattr: bool,
    has_getfacl: bool,
    allow_mutation: bool,
    fault: Option<String>,
    /// Successful, non-sensitive account lookups already made by this
    /// `TargetFs` (performance WP-P1). See [`IdentityMemo`].
    identity_memo: IdentityMemo,
}

/// Memo of account lookups (`getent passwd|group <key>`) that already
/// succeeded on this target, so a recipe whose resources share an owner or a
/// group does not repeat the same remote round trip per resource.
///
/// * **Scope:** a field of one `TargetFs`, which is owned by one `Engine`,
///   which is built for one (recipe, host). It is never static, never shared
///   between engines or hosts, and dies with the engine.
/// * **Key:** `(database, key, field)`. `passwd foo` and `group foo` are
///   different entries, and "the uid of user `foo`" (field 2) is different from
///   "the primary gid of uid `foo`" (field 3).
/// * **Value:** the single parsed number the caller asked for. The raw record
///   (home directory, shell, GECOS, ...) is never kept.
/// * **Only successes are stored.** An unknown account, a non-zero exit, an
///   indeterminate completion and a malformed record all stay live: the next
///   lookup asks the target again. "Not found" is deliberately not cached
///   because an earlier resource may create the account.
/// * **Sensitive lookups bypass the memo** (read and write), so a name that
///   came from a secret is never held here and its command is still issued
///   exactly as before.
/// * **Invalidation:** every operation that holds a [`MutationPermit`] — the
///   raw `exec` channel and every mutating helper — empties the memo before it
///   is dispatched, because any of them may change the account databases
///   (`useradd`, `groupmod`, a package scriptlet, a file written to
///   `/etc/passwd`, ...). Plan and audit hold no permit, so their memo stays
///   valid for the whole run.
#[derive(Debug, Default)]
struct IdentityMemo {
    entries: BTreeMap<(&'static str, String, usize), u32>,
}

impl IdentityMemo {
    fn get(&self, database: &'static str, key: &str, field: usize) -> Option<u32> {
        self.entries
            .get(&(database, key.to_string(), field))
            .copied()
    }

    fn insert(&mut self, database: &'static str, key: &str, field: usize, value: u32) {
        self.entries
            .insert((database, key.to_string(), field), value);
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

fn base_env() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    env.insert("LANG".to_string(), "C.UTF-8".to_string());
    env.insert("LC_ALL".to_string(), "C.UTF-8".to_string());
    env
}

impl TargetFs {
    #[allow(clippy::too_many_arguments)]
    pub fn new_for(
        ex: Executor,
        sudo: bool,
        target_uid: u32,
        target_gid: u32,
        home: String,
        pkg_backend: Option<crate::platform::PackageBackend>,
        has_getfattr: bool,
        has_getfacl: bool,
        allow_mutation: bool,
        fault: Option<String>,
    ) -> Self {
        TargetFs {
            ex,
            sudo,
            target_uid,
            target_gid,
            home,
            pkg_backend,
            has_getfattr,
            has_getfacl,
            allow_mutation,
            fault,
            identity_memo: IdentityMemo::default(),
        }
    }

    pub fn fault(&self) -> Option<&str> {
        self.fault.as_deref()
    }

    /// Runtime authority gate for the mutation boundary. Returns a mutation
    /// permit only when this `TargetFs` was constructed with mutation allowed.
    /// Every mutating method — and the raw `exec` channel — requires the
    /// resulting `&MutationPermit`, so a read-only (Plan/Audit) `TargetFs`
    /// fails closed here even if a caller somehow reached a mutation path.
    /// `pub(crate)` so Apply-only resource code in `resources.rs` can obtain
    /// the permit it must then thread into each mutation call; Audit code
    /// never calls this.
    pub(crate) fn mutation_permit(&self) -> Result<MutationPermit> {
        if self.allow_mutation {
            Ok(MutationPermit::new())
        } else {
            Err(SinterError::plan(
                "internal error: observation attempted a mutation",
            ))
        }
    }

    /// Raw command execution is a mutation-capable operation: the same
    /// channel runs recipe commands, package mutations, service mutations,
    /// and handler actions. It therefore requires a `MutationPermit`, which
    /// only a mutation-enabled TargetFs can produce (RA-01).
    pub(crate) fn exec(&mut self, _permit: &MutationPermit, req: &ExecRequest) -> Result<Output> {
        self.identity_memo.clear();
        self.ex.run(req)
    }

    /// The statistics handle of the executor (performance measurement).
    pub fn exec_stats(&self) -> crate::executor::ExecStatsHandle {
        self.ex.stats_handle()
    }

    /// Label the commands that follow for the statistics. Diagnostic only.
    pub(crate) fn set_stats_scope(&self, scope: &'static str) {
        self.ex.stats_handle().set_scope(scope);
    }

    pub fn log(&self) -> Vec<crate::executor::CommandRecord> {
        self.ex.log()
    }

    pub fn target_uid(&self) -> u32 {
        self.target_uid
    }

    pub fn target_gid(&self) -> u32 {
        self.target_gid
    }

    pub fn sudo(&self) -> bool {
        self.sudo
    }
}

impl TargetFs {
    pub fn home_env(&self) -> String {
        if self.sudo {
            "/root".to_string()
        } else {
            self.home.clone()
        }
    }

    /// Run a program with exact argv and no shell, under the baseline
    /// environment. Recipe-controlled values must only ever be passed through
    /// this path so they can never become shell syntax in internal operations.
    /// Private: arbitrary argv is a mutation-capable channel, so only the
    /// fixed-argv observation wrappers below (or permit-gated mutating
    /// helpers) may reach it (RA-01).
    fn run_argv(&mut self, program: &str, args: &[String]) -> Result<Output> {
        self.run_argv_sensitivity(program, args, false)
    }

    fn run_argv_sensitivity(
        &mut self,
        program: &str,
        args: &[String],
        sensitive: bool,
    ) -> Result<Output> {
        let req = self.argv_request(program, args, sensitive);
        self.ex.run(&req)
    }

    /// The exact request `run_argv_sensitivity` dispatches for this program and
    /// argv: fixed argv, no shell, baseline environment. Building it is a pure
    /// local operation, so a caller can measure a request before deciding
    /// whether to dispatch it (see [`TargetFs::batched_parent_walk_applies`]).
    fn argv_request(&self, program: &str, args: &[String], sensitive: bool) -> ExecRequest {
        let mut req = ExecRequest::new(program);
        req.args = args.to_vec();
        req.env = base_env();
        req.env.insert("HOME".to_string(), self.home_env());
        req.sensitive = sensitive;
        req
    }

    /// Query dpkg for a package's status using exact argv.
    pub fn dpkg_query(&mut self, name: &str) -> Result<Output> {
        self.dpkg_query_sensitive(name, false)
    }

    pub fn dpkg_query_sensitive(&mut self, name: &str, sensitive: bool) -> Result<Output> {
        self.run_argv_sensitivity(
            "/usr/bin/dpkg-query",
            &[
                "-W".to_string(),
                "-f=${Status}".to_string(),
                "--".to_string(),
                name.to_string(),
            ],
            sensitive,
        )
    }

    /// Query the detected platform's package database for a package using
    /// exact argv. The backend was selected from /etc/os-release metadata at
    /// capability-detection time; `None` (unsupported platform) is an explicit
    /// error, never a silent fallback (DESIGN §27).
    pub fn package_query_sensitive(&mut self, name: &str, sensitive: bool) -> Result<Output> {
        match self.pkg_backend {
            Some(crate::platform::PackageBackend::Apt) => {
                self.dpkg_query_sensitive(name, sensitive)
            }
            Some(crate::platform::PackageBackend::Dnf) => self.rpm_query_sensitive(name, sensitive),
            None => Err(SinterError::apply(
                "package resources require a supported target platform",
            )),
        }
    }

    /// Query rpm for a package's presence using exact argv. The query uses a
    /// fixed `--queryformat` that returns exactly the package `NAME` field
    /// with no separator and no terminator, so the complete capture *is* the
    /// single identity record: the caller can prove the installed package is
    /// the requested one by whole-record equality instead of inferring
    /// identity from human-readable NEVRA text (RA2-01). `rpm -q` exits 0
    /// when installed and 1 otherwise; callers must distinguish confirmed
    /// "not installed" from a broken query (see
    /// PackageBackend::classify_observation).
    pub fn rpm_query_sensitive(&mut self, name: &str, sensitive: bool) -> Result<Output> {
        self.run_argv_sensitivity(
            "/usr/bin/rpm",
            &[
                "-q".to_string(),
                "--queryformat".to_string(),
                "%{NAME}".to_string(),
                "--".to_string(),
                name.to_string(),
            ],
            sensitive,
        )
    }

    /// Show a systemd unit's relevant properties using exact argv.
    pub fn systemctl_show(&mut self, name: &str) -> Result<Output> {
        self.systemctl_show_sensitive(name, false)
    }

    pub fn systemctl_show_sensitive(&mut self, name: &str, sensitive: bool) -> Result<Output> {
        // The unit name follows `--`: option parsing ends there, so a
        // manifest-controlled name like `-H…` can never become an option.
        self.run_argv_sensitivity(
            "/usr/bin/systemctl",
            &[
                "show".to_string(),
                format!("--property={}", SERVICE_SHOW_PROPERTIES),
                "--".to_string(),
                name.to_string(),
            ],
            sensitive,
        )
    }

    /// Read the system manager's unit load path. Read-only; the argv is
    /// fixed and carries no recipe-controlled value. The property is a
    /// manager property, so no unit operand (and no `--`) is present.
    pub fn systemctl_show_unit_path(&mut self) -> Result<Output> {
        self.run_argv(
            "/usr/bin/systemctl",
            &["show".to_string(), "--property=UnitPath".to_string()],
        )
    }

    /// Read-only account database lookup for the `user`/`group` resources,
    /// exact argv, no shell. `local_only` selects glibc's `-s files`, which
    /// consults only the local /etc/passwd or /etc/group; otherwise the
    /// ordinary NSS-wide lookup runs (used only to tell a local-only absence
    /// from an account some other identity source provides). `key` of `None`
    /// enumerates the database. `database` is always a fixed literal and
    /// `key` is a validated account name or a decimal id, never an option.
    pub(crate) fn account_getent(
        &mut self,
        local_only: bool,
        database: &str,
        key: Option<&str>,
        sensitive: bool,
    ) -> Result<Output> {
        let mut args: Vec<String> = Vec::new();
        if local_only {
            args.push("-s".to_string());
            args.push("files".to_string());
        }
        args.push(database.to_string());
        if let Some(k) = key {
            args.push(k.to_string());
        }
        self.run_argv_sensitivity("/usr/bin/getent", &args, sensitive)
    }

    fn run_argv_ok(&mut self, program: &str, args: &[String]) -> Result<Output> {
        self.run_argv_ok_sensitivity(program, args, false, false)
    }

    /// Mutating helper operations: after dispatch, abnormal completion must not
    /// be reported as a definite non-mutation.
    fn run_argv_ok_mutating(&mut self, program: &str, args: &[String]) -> Result<Output> {
        self.run_argv_ok_sensitivity(program, args, true, false)
    }

    fn run_argv_ok_mutating_sensitive(
        &mut self,
        program: &str,
        args: &[String],
        sensitive: bool,
    ) -> Result<Output> {
        self.run_argv_ok_sensitivity(program, args, true, sensitive)
    }

    fn run_argv_ok_sensitivity(
        &mut self,
        program: &str,
        args: &[String],
        mutating: bool,
        sensitive: bool,
    ) -> Result<Output> {
        let out = self.run_argv_sensitivity(program, args, sensitive)?;
        match out.completion {
            Completion::Exited(0) => Ok(out),
            Completion::Exited(c) => {
                let msg = format!(
                    "target operation {} failed (exit {}): {}",
                    if sensitive { "[redacted]" } else { program },
                    c,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                // Nonzero exit is a definite command failure. Mutating helpers
                // that need extra conservatism use `.changed()` at the call site
                // after a prior successful step.
                let _ = mutating;
                Err(SinterError::apply(msg))
            }
            Completion::Signaled(s) => {
                let msg = format!(
                    "target operation {} terminated by signal {}",
                    if sensitive { "[redacted]" } else { program },
                    s
                );
                // Dispatched then killed: mutation completion unknown.
                Err(SinterError::indeterminate(msg))
            }
            Completion::Indeterminate { reason, .. } => Err(SinterError::indeterminate(reason)),
        }
    }

    /// Create a private staging directory beneath the destination parent, using
    /// a non-predictable name. No recipe-controlled text is used in the name, so
    /// no shell syntax can leak. The directory is created mode 0700.
    pub fn make_staging_dir(&mut self, dir: &str) -> Result<String> {
        let _permit = self.mutation_permit()?;
        self.identity_memo.clear();
        let out = self.run_argv_ok(
            "/usr/bin/mktemp",
            &[
                "-d".to_string(),
                "-p".to_string(),
                dir.to_string(),
                ".sinter-stage.XXXXXXXX".to_string(),
            ],
        )?;
        let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if p.is_empty() {
            return Err(SinterError::apply("could not create staging directory"));
        }
        // mktemp -d creates 0700; enforce it defensively.
        self.run_argv_ok(
            "/bin/chmod",
            &["700".to_string(), "--".to_string(), p.clone()],
        )?;
        Ok(p)
    }

    /// Inspect an object without following a final symlink. See
    /// [`interpret_stat`] for the strict observation contract: absence is a
    /// positive result and any ambiguous or incomplete capture is an error.
    pub fn inspect(&mut self, path: &str) -> Result<Stat> {
        let out = self.run_argv(
            "/usr/bin/stat",
            &[
                "-c".to_string(),
                "%F|%a|%u|%g|%s|%d|%i|%y|%z".to_string(),
                "--".to_string(),
                path.to_string(),
            ],
        )?;
        interpret_stat(&out, path)
    }

    /// Strict `readlink -n` observation contract (IA-01):
    ///
    /// * exit 0, no truncation, valid UTF-8, empty stderr, exactly one target
    ///   record -> the complete link target string
    /// * any other completion or an ambiguous capture -> an observation error
    ///
    /// The target object's existence is deliberately not implied by this call; a
    /// dangling symlink whose declared target string matches remains compliant.
    pub fn readlink(&mut self, path: &str) -> Result<String> {
        let out = self.run_argv_ok(
            "/usr/bin/readlink",
            &["-n".to_string(), "--".to_string(), path.to_string()],
        )?;
        readlink_record(&out, path)
    }

    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let out = self.run_argv_ok("/bin/cat", &["--".to_string(), path.to_string()])?;
        if out.stdout_truncated {
            return Err(SinterError::apply(format!(
                "file {} exceeds the readable capture limit",
                path
            )));
        }
        Ok(out.stdout)
    }

    /// Strict `sha256sum` observation contract (IA-01):
    ///
    /// Returns `Some(digest)` only when the capture is complete, stderr is
    /// empty, and exactly one well-formed `<64 lowercase-hex>  <name>`
    /// record is present. A truncated capture, a diagnostic on stderr, a
    /// malformed digest, a wrong separator, an unexpected extra record, or
    /// a record about a different path is an observation error — a captured
    /// prefix is never compared against the expected digest.
    ///
    /// A command failure returns `None`, which means "no trustworthy digest
    /// was obtained"; callers must treat that as an observation failure, never
    /// as a digest mismatch and never as absence (the object's existence is
    /// established separately by `inspect`).
    pub fn sha256(&mut self, path: &str) -> Result<Option<String>> {
        let out = self.run_argv("/usr/bin/sha256sum", &["--".to_string(), path.to_string()])?;
        interpret_sha256(&out, path)
    }

    /// The actionable reason extended-attribute inspection is unavailable on
    /// this target, when it is. `/usr/bin/getfattr` is a hard target
    /// requirement for managing filesystem paths: without it Sinter cannot
    /// enumerate the access metadata that proves a path is safe to write
    /// (DESIGN §24.4), so every filesystem resource must fail closed. Stock
    /// Ubuntu cloud images ship no `attr` package, so the message names the
    /// program and the package instead of leaving the refusal unexplained.
    /// `None` means inspection is available; a refusal then means a genuine
    /// inspection failure, not a missing tool.
    pub fn xattr_inspection_unavailable(&self) -> Option<String> {
        if self.has_getfattr {
            return None;
        }
        Some(
            "; the target has no /usr/bin/getfattr, so access metadata cannot \
             be inspected (install the 'attr' package: apt install attr on \
             Debian/Ubuntu, dnf install attr on RHEL family)"
                .to_string(),
        )
    }

    /// Enumerate extended attributes and POSIX ACLs. Values are returned in
    /// getfattr base64 form (`0s...`) so arbitrary bytes round-trip exactly.
    /// `inspected` is true only when the required inspections completed; an
    /// inspection failure is reported honestly and must be treated as a refusal
    /// by callers, never as "no metadata".
    pub fn xattrs(&mut self, path: &str) -> Result<Xattrs> {
        if !self.has_getfattr {
            return Ok(Xattrs {
                attrs: BTreeMap::new(),
                inspected: false,
            });
        }
        let out = self.run_argv(
            "/usr/bin/getfattr",
            &[
                "-d".to_string(),
                "-m".to_string(),
                "-".to_string(),
                "-e".to_string(),
                "base64".to_string(),
                "--absolute-names".to_string(),
                "--".to_string(),
                path.to_string(),
            ],
        )?;
        // Only a complete successful enumeration is authoritative. Abnormal
        // or incomplete output must fail closed rather than become "no attrs".
        let parsed = interpret_getfattr_capture(&out);
        if !parsed.inspected {
            return Ok(parsed);
        }
        let mut attrs = parsed.attrs;

        // Detect POSIX ACLs honestly. getfattr may not surface
        // system.posix_acl_access on all filesystems, so use getfacl explicitly.
        if self.has_getfacl {
            let acl = self.run_argv(
                "/usr/bin/getfacl",
                &[
                    "-p".to_string(),
                    "-c".to_string(),
                    "--".to_string(),
                    path.to_string(),
                ],
            );
            match acl {
                Ok(o) => match o.completion {
                    Completion::Exited(0) if !o.stdout_truncated && !o.stderr_truncated => {
                        let Ok(acl_text) = std::str::from_utf8(&o.stdout) else {
                            return Ok(Xattrs {
                                attrs,
                                inspected: false,
                            });
                        };
                        // A successful getfacl capture must include the three
                        // well-formed base entries. Empty, incomplete, or
                        // malformed base entries mean the observation is not
                        // authoritative (DESIGN §24.4).
                        match classify_acl_text(acl_text) {
                            AclClass::Complete { extended } => {
                                if extended {
                                    attrs
                                        .entry("system.posix_acl_access".to_string())
                                        .or_insert_with(|| "present".to_string());
                                }
                            }
                            AclClass::Incomplete | AclClass::Malformed => {
                                return Ok(Xattrs {
                                    attrs,
                                    inspected: false,
                                });
                            }
                        }
                    }
                    _ => {
                        return Ok(Xattrs {
                            attrs,
                            inspected: false,
                        })
                    }
                },
                Err(_) => {
                    return Ok(Xattrs {
                        attrs,
                        inspected: false,
                    })
                }
            }
        }

        Ok(Xattrs {
            attrs,
            inspected: true,
        })
    }

    /// Apply publication metadata to a staging object. Ownership is applied
    /// before mode so that a mode carrying set-ID bits is never transiently
    /// held while owned by the wrong principal.
    pub fn set_metadata(&mut self, path: &str, mode: u32, uid: u32, gid: u32) -> Result<()> {
        let permit = self.mutation_permit()?;
        self.chown(&permit, path, uid, gid)?;
        // chown already mutated. Any later chmod failure — including
        // Indeterminate — must preserve the known change.
        if let Err(e) = self.chmod(&permit, path, mode) {
            return Err(e.changed());
        }
        Ok(())
    }

    pub fn chmod(&mut self, _permit: &MutationPermit, path: &str, mode: u32) -> Result<()> {
        self.identity_memo.clear();
        // Permit required: this method is unreachable on a read-only TargetFs.
        self.run_argv_ok_mutating(
            "/bin/chmod",
            &[mode_to_string(mode), "--".to_string(), path.to_string()],
        )?;
        // Controlled injection: real chmod already applied, then completion is
        // reported as abnormal. Mutation is known.
        if self.fault() == Some("chmod_success_then_abnormal") {
            return Err(SinterError::indeterminate(
                "injected abnormal completion after successful chmod",
            )
            .changed());
        }
        Ok(())
    }

    pub fn chown(
        &mut self,
        _permit: &MutationPermit,
        path: &str,
        uid: u32,
        gid: u32,
    ) -> Result<()> {
        self.identity_memo.clear();
        self.run_argv_ok_mutating(
            "/bin/chown",
            &[
                format!("{}:{}", uid, gid),
                "--".to_string(),
                path.to_string(),
            ],
        )?;
        if self.fault() == Some("chown_success_then_abnormal") {
            return Err(SinterError::indeterminate(
                "injected abnormal completion after successful chown",
            )
            .changed());
        }
        Ok(())
    }

    pub fn mkdir(&mut self, _permit: &MutationPermit, path: &str) -> Result<()> {
        self.identity_memo.clear();
        self.run_argv_ok_mutating("/bin/mkdir", &["--".to_string(), path.to_string()])?;
        Ok(())
    }

    /// `mkdir -p` for directories inside a freshly created private backup
    /// run directory (never used on managed paths).
    pub(crate) fn mkdir_p(&mut self, _permit: &MutationPermit, path: &str) -> Result<()> {
        self.identity_memo.clear();
        self.run_argv_ok_mutating(
            "/bin/mkdir",
            &["-p".to_string(), "--".to_string(), path.to_string()],
        )?;
        Ok(())
    }

    /// Copy `src` to exactly `dest` for a pre-apply backup: `cp -a` never
    /// follows a symlink and recurses into directories; the explicit
    /// `--preserve` list makes a failure to keep mode (incl. ACLs), ownership
    /// or timestamps fatal. Any completion other than exit 0 is an error.
    /// Output is not captured into results; only stderr text of a failure is
    /// reported (it never contains file content).
    pub(crate) fn backup_copy(
        &mut self,
        _permit: &MutationPermit,
        src: &str,
        dest: &str,
    ) -> Result<()> {
        self.identity_memo.clear();
        let mut req = ExecRequest::new("/bin/cp");
        req.args = vec![
            "-a".to_string(),
            "--preserve=mode,ownership,timestamps".to_string(),
            "--no-target-directory".to_string(),
            "--".to_string(),
            src.to_string(),
            dest.to_string(),
        ];
        req.env = base_env();
        req.env.insert("HOME".to_string(), self.home_env());
        req.timeout_secs = BACKUP_COPY_TIMEOUT_SECS;
        let out = self.ex.run(&req)?;
        match out.completion {
            Completion::Exited(0) => Ok(()),
            Completion::Exited(c) => Err(SinterError::apply(format!(
                "copy failed (exit {}): {}",
                c,
                crate::diff::sanitize_line(String::from_utf8_lossy(&out.stderr).trim())
            ))),
            Completion::Signaled(s) => Err(SinterError::apply(format!(
                "copy terminated by signal {}; the backup copy may be incomplete",
                s
            ))),
            Completion::Indeterminate { reason, .. } => Err(SinterError::apply(format!(
                "copy did not complete ({}); the backup copy may be incomplete",
                reason
            ))),
        }
    }

    pub fn rmdir(&mut self, _permit: &MutationPermit, path: &str) -> Result<()> {
        self.identity_memo.clear();
        self.run_argv_ok_mutating("/bin/rmdir", &["--".to_string(), path.to_string()])?;
        Ok(())
    }

    /// Whether the directory `path` has any entry, observed read-only with
    /// `find <path> -mindepth 1 -maxdepth 1 -print -quit`, which prints at
    /// most one name. `None` when the answer is not a clean one (a non-zero
    /// exit, a diagnostic): the caller must not guess.
    pub fn dir_has_entries(&mut self, path: &str) -> Result<Option<bool>> {
        let args: Vec<String> = [path, "-mindepth", "1", "-maxdepth", "1", "-print", "-quit"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = self.run_argv("/usr/bin/find", &args)?;
        Ok(match out.completion {
            Completion::Exited(0) if out.stderr.is_empty() => Some(!out.stdout.is_empty()),
            _ => None,
        })
    }

    /// Remove a file only if it is the exact object we created (regular file).
    pub fn remove_file(&mut self, _permit: &MutationPermit, path: &str) -> Result<()> {
        self.identity_memo.clear();
        self.run_argv_ok_mutating(
            "/bin/rm",
            &["-f".to_string(), "--".to_string(), path.to_string()],
        )?;
        Ok(())
    }

    /// Remove a symlink only, refusing to follow it.
    pub fn remove_symlink(&mut self, _permit: &MutationPermit, path: &str) -> Result<()> {
        self.identity_memo.clear();
        self.run_argv_ok_mutating(
            "/bin/rm",
            &["-f".to_string(), "--".to_string(), path.to_string()],
        )?;
        Ok(())
    }

    pub fn symlink(
        &mut self,
        _permit: &MutationPermit,
        target: &str,
        link_path: &str,
    ) -> Result<()> {
        self.identity_memo.clear();
        if target.contains('\0') {
            return Err(SinterError::schema(
                "symlink target may not contain NUL bytes",
            ));
        }
        // Target may be derived from sensitive values; never log raw argv.
        self.run_argv_ok_mutating_sensitive(
            "/bin/ln",
            &[
                "-s".to_string(),
                "--".to_string(),
                target.to_string(),
                link_path.to_string(),
            ],
            true,
        )?;
        Ok(())
    }

    /// Atomically replace a symlink using a private staging directory so the
    /// staging name cannot be predicted or pre-created by another user.
    ///
    /// Publication state and cleanup state are separate facts. Cleanup must
    /// never rewrite whether the destination was published.
    pub fn symlink_replace(
        &mut self,
        permit: &MutationPermit,
        target: &str,
        link_path: &str,
        observed: &Stat,
    ) -> Result<()> {
        self.identity_memo.clear();
        let (dir, name) = parent_and_name(link_path);
        let stage_dir = self.make_staging_dir(&dir)?;
        let tmp = format!("{}/{}", stage_dir, name);
        let result = (|| -> Result<()> {
            self.run_argv_ok_mutating_sensitive(
                "/bin/ln",
                &[
                    "-s".to_string(),
                    "--".to_string(),
                    target.to_string(),
                    tmp.clone(),
                ],
                true,
            )?;
            if self.fault() == Some("symlink_drift_before_publish")
                || self.fault() == Some("symlink_drift_cleanup_fail")
            {
                self.remove_symlink(permit, link_path)?;
                self.symlink(permit, "/sinter-injected-drift", link_path)?;
            }
            let current = self.inspect(link_path)?;
            if !same_identity(observed, &current) {
                return Err(SinterError::apply(format!(
                    "target drift detected at {} before symlink publication",
                    link_path
                )));
            }
            self.run_argv_ok_mutating(
                "/bin/mv",
                &[
                    "-T".to_string(),
                    "-f".to_string(),
                    "--".to_string(),
                    tmp.clone(),
                    link_path.to_string(),
                ],
            )?;
            Ok(())
        })();

        // Publication completion unknown: do not clean staging (could destroy
        // evidence) and preserve indeterminate semantics exactly.
        if matches!(result, Err(ref e) if e.kind == crate::error::ErrorKind::Indeterminate) {
            return result;
        }

        // Cleanup is a separate fact. Classify rm BEFORE attempting rmdir.
        let cleanup = if self.fault() == Some("symlink_cleanup_fail")
            || self.fault() == Some("symlink_drift_cleanup_fail")
        {
            CleanupState::Failed
        } else if self.fault() == Some("symlink_cleanup_rm_indeterminate") {
            // Simulate rm completion unknown: do not rmdir.
            CleanupState::Indeterminate
        } else {
            let cleanup_payload = self.run_argv(
                "/bin/rm",
                &["-f".to_string(), "--".to_string(), tmp.clone()],
            );
            match cleanup_payload {
                Ok(ref out) if out.is_success() => {
                    // rm succeeded; only then may rmdir run.
                    let cleanup_dir = self.run_argv("/bin/rmdir", std::slice::from_ref(&stage_dir));
                    match cleanup_dir {
                        Ok(ref out) if out.is_success() => CleanupState::Ok,
                        Ok(ref out)
                            if matches!(out.completion, Completion::Indeterminate { .. }) =>
                        {
                            CleanupState::Indeterminate
                        }
                        _ => CleanupState::Failed,
                    }
                }
                Ok(ref out) if matches!(out.completion, Completion::Indeterminate { .. }) => {
                    // rm completion unknown: do not rmdir (additional mutation).
                    CleanupState::Indeterminate
                }
                Err(ref e) if e.kind == crate::error::ErrorKind::Indeterminate => {
                    CleanupState::Indeterminate
                }
                _ => CleanupState::Failed,
            }
        };

        match result {
            Ok(()) => {
                // Destination was published. Cleanup failure is reported after
                // the known mutation, never as a pre-publication failure.
                match cleanup {
                    CleanupState::Ok => Ok(()),
                    CleanupState::Indeterminate => Err(SinterError::indeterminate(
                        "symlink published but staging cleanup completion is unknown",
                    )
                    .changed()),
                    CleanupState::Failed => Err(SinterError::apply(
                        "symlink published but staging cleanup failed",
                    )
                    .changed()),
                }
            }
            Err(e) => {
                // Pre-publication failure. Preserve the original error kind and
                // mutation state; cleanup outcome must not rewrite it to changed.
                Err(e)
            }
        }
    }

    pub fn rename(&mut self, _permit: &MutationPermit, from: &str, to: &str) -> Result<()> {
        self.identity_memo.clear();
        // Controlled failure-injection inside the real rename operation so the
        // publish error path that classifies rename outcomes is exercised.
        if self.fault() == Some("rename_fail") {
            return Err(SinterError::apply("injected rename failure"));
        }
        if self.fault() == Some("rename_indeterminate") {
            return Err(SinterError::indeterminate("injected rename indeterminate"));
        }
        self.run_argv_ok_mutating(
            "/bin/mv",
            &[
                "-T".to_string(),
                "-f".to_string(),
                "--".to_string(),
                from.to_string(),
                to.to_string(),
            ],
        )?;
        // Controlled injection: real rename already published, then completion
        // is reported as abnormal. Publication is a known mutation.
        if self.fault() == Some("rename_success_then_abnormal") {
            return Err(SinterError::indeterminate(
                "injected abnormal completion after successful rename",
            )
            .changed());
        }
        Ok(())
    }

    /// Write exact bytes to a path by streaming them over stdin to `dd`. The
    /// destination path is passed as a single argv element, so no recipe-
    /// controlled value can become shell syntax, and no shell is invoked.
    pub fn write_bytes(&mut self, _permit: &MutationPermit, path: &str, data: &[u8]) -> Result<()> {
        self.identity_memo.clear();
        if path.contains('\0') {
            return Err(SinterError::schema("path may not contain NUL bytes"));
        }
        let mut req = ExecRequest::new("/bin/dd");
        req.args = vec!["status=none".to_string(), format!("of={}", path)];
        req.env = base_env();
        req.env.insert("HOME".to_string(), self.home_env());
        req.stdin = Some(data.to_vec());
        let out = self.ex.run(&req)?;
        match out.completion {
            Completion::Exited(0) => Ok(()),
            Completion::Exited(c) => Err(SinterError::apply(format!(
                "failed writing {}: exit {} ({})",
                path,
                c,
                String::from_utf8_lossy(&out.stderr).trim()
            ))),
            Completion::Signaled(s) => Err(SinterError::apply(format!(
                "failed writing {}: signal {}",
                path, s
            ))),
            Completion::Indeterminate { reason, .. } => Err(SinterError::indeterminate(reason)),
        }
    }

    /// Set an extended attribute using exact argv; never a shell string.
    pub fn set_xattr(
        &mut self,
        _permit: &MutationPermit,
        name: &str,
        value: &str,
        path: &str,
    ) -> Result<()> {
        self.identity_memo.clear();
        self.run_argv_ok(
            "/usr/bin/setfattr",
            &[
                "-n".to_string(),
                name.to_string(),
                "-v".to_string(),
                value.to_string(),
                "--".to_string(),
                path.to_string(),
            ],
        )?;
        Ok(())
    }

    /// Copy preservable xattrs (`user.*` and `security.selinux`) from `from`
    /// onto `to`. Other security/ACL attributes are deliberately not copied —
    /// they are disqualifying via `unsafe_attr` instead.
    pub fn copy_user_xattrs(
        &mut self,
        permit: &MutationPermit,
        from: &str,
        to: &str,
    ) -> Result<()> {
        self.identity_memo.clear();
        if !self.has_getfattr {
            return Ok(());
        }
        let x = self.xattrs(from)?;
        for (name, value) in x.preserved_attrs() {
            self.set_xattr(permit, name, value, to)?;
        }
        Ok(())
    }

    pub fn resolve_uid(&mut self, spec: &str) -> Result<u32> {
        self.resolve_uid_sensitive(spec, false)
    }

    pub fn resolve_uid_sensitive(&mut self, spec: &str, sensitive: bool) -> Result<u32> {
        if let Ok(n) = spec.parse::<u32>() {
            return Ok(n);
        }
        self.memoized_getent_field("passwd", spec, 2, 7, "user", sensitive)
    }

    pub fn resolve_gid(&mut self, spec: &str) -> Result<u32> {
        self.resolve_gid_sensitive(spec, false)
    }

    pub fn resolve_gid_sensitive(&mut self, spec: &str, sensitive: bool) -> Result<u32> {
        if let Ok(n) = spec.parse::<u32>() {
            return Ok(n);
        }
        self.memoized_getent_field("group", spec, 2, 4, "group", sensitive)
    }

    pub fn primary_gid_of_uid(&mut self, uid: u32) -> Result<u32> {
        self.primary_gid_of_uid_sensitive(uid, false)
    }

    /// The primary gid of `uid`. A lookup made for a sensitive resource is
    /// redacted and bypasses the memo, like the owner and group lookups.
    pub fn primary_gid_of_uid_sensitive(&mut self, uid: u32, sensitive: bool) -> Result<u32> {
        self.memoized_getent_field("passwd", &uid.to_string(), 3, 7, "uid", sensitive)
    }

    /// [`Self::getent_field`] with the [`IdentityMemo`]: a repeat of a lookup
    /// that already succeeded, with no mutation in between, is answered
    /// without a target command. Failures are returned unchanged and never
    /// stored; sensitive lookups never touch the memo.
    fn memoized_getent_field(
        &mut self,
        database: &'static str,
        key: &str,
        field: usize,
        expected_fields: usize,
        what: &str,
        sensitive: bool,
    ) -> Result<u32> {
        if !sensitive {
            if let Some(v) = self.identity_memo.get(database, key, field) {
                return Ok(v);
            }
        }
        let v = self.getent_field(database, key, field, expected_fields, what, sensitive)?;
        if !sensitive {
            self.identity_memo.insert(database, key, field, v);
        }
        Ok(v)
    }

    /// Strict `getent <db> <key>` observation contract (IA-01): a complete,
    /// valid, single-line record whose field count is exactly the database's.
    /// A truncated capture, invalid bytes, a second record, or an entry whose
    /// shape does not match the database cannot identify the account and is an
    /// observation error rather than a guessed value.
    fn getent_field(
        &mut self,
        database: &str,
        key: &str,
        field: usize,
        expected_fields: usize,
        what: &str,
        sensitive: bool,
    ) -> Result<u32> {
        let out = self.run_argv_sensitivity(
            "/usr/bin/getent",
            &[database.to_string(), key.to_string()],
            sensitive,
        )?;
        let unknown = || {
            if sensitive {
                SinterError::apply(format!("unknown {} (value redacted)", what))
            } else {
                SinterError::apply(format!("unknown {}: {}", what, key))
            }
        };
        match out.completion {
            Completion::Exited(0) => {
                require_complete(&out, key)?;
                // A diagnostic next to the record makes the answer ambiguous.
                if !out.stderr.is_empty() {
                    return Err(SinterError::apply(format!(
                        "account lookup for {} returned an unexpected diagnostic",
                        if sensitive { "[redacted]" } else { key }
                    )));
                }
                let text = utf8_stream(&out.stdout, key)?;
                // getent terminates its single record with exactly one
                // newline; an unterminated capture, a second record, or any
                // surrounding whitespace is not the defined answer and is
                // never trimmed into one (RA2-01).
                let Some(line) = text.strip_suffix('\n') else {
                    return Err(unknown());
                };
                if line.is_empty() || line.contains('\n') || line.contains('\r') {
                    return Err(unknown());
                }
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() != expected_fields {
                    return Err(unknown());
                }
                parts[field].parse::<u32>().map_err(|_| unknown())
            }
            Completion::Indeterminate { reason, .. } => Err(SinterError::indeterminate(format!(
                "account lookup for {} did not complete: {}",
                if sensitive { "[redacted]" } else { key },
                reason
            ))),
            _ => Err(unknown()),
        }
    }

    pub fn same_filesystem(&mut self, a: &str, b: &str) -> Result<bool> {
        let sa = self.inspect(a)?;
        let sb = self.inspect(b)?;
        if sa.kind == ObjKind::Absent || sb.kind == ObjKind::Absent {
            // Compare against the parent directory of the missing side.
            let (pa, _) = parent_and_name(a);
            let (pb, _) = parent_and_name(b);
            let sa = if sa.kind == ObjKind::Absent {
                self.inspect(&pa)?
            } else {
                sa
            };
            let sb = if sb.kind == ObjKind::Absent {
                self.inspect(&pb)?
            } else {
                sb
            };
            if sa.kind == ObjKind::Absent || sb.kind == ObjKind::Absent {
                return Ok(false);
            }
            return Ok(sa.dev == sb.dev);
        }
        Ok(sa.dev == sb.dev)
    }

    /// Check the parent-path trust boundary (DESIGN §23).
    ///
    /// On a target whose `getfacl` capability is absent (and when the pre-dispatch
    /// guard of [`TargetFs::batched_parent_walk_applies`] passes) the ancestors
    /// are observed with one `stat` batch followed, only if every record is
    /// acceptable, by one `getfattr` batch. Every other case runs the sequential
    /// walk unchanged. The choice is made before the first command is sent and a
    /// dispatched batch is never retried through the sequential walk.
    pub fn check_trusted_parents(&mut self, path: &str) -> Result<()> {
        let dirs = ancestor_dirs(path);
        if self.batched_parent_walk_applies(&dirs) {
            return self.check_trusted_parents_batched(path, &dirs);
        }
        for dir in dirs {
            let st = self.inspect(&dir)?;
            self.check_parent_stat(&dir, &st)?;
            // Effective writability cannot be proven from mode bits alone when
            // extended access metadata (ACLs) is present. If inspection cannot
            // be completed, fail closed rather than assume safety.
            let x = if self.fault.as_deref() == Some("uninspectable_parent") {
                Xattrs {
                    attrs: std::collections::BTreeMap::new(),
                    inspected: false,
                }
            } else {
                self.xattrs(&dir)?
            };
            self.check_parent_xattrs(&dir, &x)?;
        }
        Ok(())
    }

    /// Type, owner and mode verdict for one ancestor (shared by the sequential
    /// and the batched walk so both apply exactly the same predicate).
    fn check_parent_stat(&self, dir: &str, st: &Stat) -> Result<()> {
        match st.kind {
            ObjKind::Absent => {
                return Err(SinterError::apply(format!(
                    "required parent path {} does not exist; create it first, for example with \
                     a directory resource that this resource depends on",
                    dir
                )))
            }
            ObjKind::Symlink => {
                return Err(SinterError::apply(format!(
                    "parent path {} is a symlink; refusing to follow it (use the path the \
                     symlink resolves to)",
                    dir
                )))
            }
            ObjKind::Dir => {}
            other => {
                return Err(SinterError::apply(format!(
                    "parent path {} has unexpected type {}",
                    dir,
                    other.describe()
                )))
            }
        }
        let trusted_owner = st.uid == 0 || (!self.sudo && st.uid == self.target_uid);
        if !trusted_owner {
            return Err(SinterError::apply(format!(
                "parent path {} is owned by uid {}, outside the trusted set{}",
                dir,
                st.uid,
                if self.sudo {
                    " (with --sudo only root-owned parents are trusted: connect as that user \
                     without --sudo, or use a root-owned location such as /opt or /srv)"
                } else {
                    " (only directories owned by root or the connecting user are trusted)"
                }
            )));
        }
        if st.mode & 0o022 != 0 {
            return Err(SinterError::apply(format!(
                "parent path {} grants group or other write access; refusing unsafe path ({}); \
                 another user could replace entries below it: remove that write access \
                 (for example mode 0755) or use another location",
                dir,
                mode_to_string(st.mode)
            )));
        }
        Ok(())
    }

    /// Extended access metadata verdict for one ancestor (shared by both walks).
    fn check_parent_xattrs(&self, dir: &str, x: &Xattrs) -> Result<()> {
        if !x.inspected {
            return Err(SinterError::apply(format!(
                "cannot inspect access metadata of parent path {}; refusing unsafe path{}",
                dir,
                self.xattr_inspection_unavailable().unwrap_or_default()
            )));
        }
        if x.unsafe_attr().is_some() {
            return Err(SinterError::apply(format!(
                "parent path {} carries extended access metadata; cannot prove it is non-writable \
                 (an ACL can grant write access that the mode does not show: remove it, \
                 for example with setfacl -b, or use another location)",
                dir
            )));
        }
        Ok(())
    }

    /// Whether this walk uses the batched observation. Decided **before** any
    /// command is dispatched and only from local facts:
    ///
    /// * the target's existing `getfacl` capability snapshot is negative (the
    ///   per-ancestor `getfacl` of the sequential walk cannot be batched, and
    ///   interposing it would reintroduce the ordering problems rejected in
    ///   WP-P2 research), and `getfattr` is present (otherwise the sequential
    ///   walk produces its existing actionable refusal);
    /// * no fault injection that targets the sequential walk is active;
    /// * every ancestor is made only of characters whose `stat`/`getfattr`
    ///   batch grammar is proven (no control character other than TAB and LF);
    /// * both completed remote commands fit the conservative size guard
    ///   [`BATCHED_WALK_MAX_COMMAND_BYTES`].
    ///
    /// No remote probe is made and nothing is sent when this returns `false`.
    pub(crate) fn batched_parent_walk_applies(&self, dirs: &[String]) -> bool {
        if self.has_getfacl || !self.has_getfattr {
            return false;
        }
        if self.fault.as_deref() == Some("uninspectable_parent") {
            return false;
        }
        if dirs.is_empty() {
            return false;
        }
        if dirs
            .iter()
            .any(|d| d.chars().any(|c| c.is_control() && c != '\t' && c != '\n'))
        {
            return false;
        }
        let stat = self.argv_request("/usr/bin/stat", &batched_stat_args(dirs), false);
        let getfattr = self.argv_request("/usr/bin/getfattr", &batched_getfattr_args(dirs), false);
        [stat, getfattr].iter().all(|req| {
            crate::executor::build_remote_command(req, self.sudo, &self.home_env()).len()
                <= BATCHED_WALK_MAX_COMMAND_BYTES
        })
    }

    /// Path-C walk: one `stat` for every ancestor, a complete gate over all of
    /// its records, then (only on success) one `getfattr` for every ancestor.
    /// Any failure, anomaly or unacceptable record refuses; nothing is retried
    /// and nothing falls back to the sequential walk after dispatch.
    fn check_trusted_parents_batched(&mut self, path: &str, dirs: &[String]) -> Result<()> {
        let out = self.run_argv("/usr/bin/stat", &batched_stat_args(dirs))?;
        let stats = interpret_stat_batch(&out, path, dirs)?;
        // Complete stat gate: every record is validated before getfattr exists.
        for (dir, st) in dirs.iter().zip(stats.iter()) {
            self.check_parent_stat(dir, st)?;
        }
        let out = self.run_argv("/usr/bin/getfattr", &batched_getfattr_args(dirs))?;
        let xs = interpret_getfattr_batch(&out, path, dirs)?;
        for (dir, x) in dirs.iter().zip(xs.iter()) {
            self.check_parent_xattrs(dir, x)?;
        }
        Ok(())
    }

    /// Reject an unexpected final-component symlink for a managed mutation.
    pub fn reject_final_symlink(&mut self, path: &str) -> Result<()> {
        let st = self.inspect(path)?;
        if st.kind == ObjKind::Symlink {
            return Err(SinterError::apply(format!(
                "final path {} is a symlink; refusing to follow it",
                path
            )));
        }
        Ok(())
    }
}

pub fn absent_stat() -> Stat {
    Stat {
        kind: ObjKind::Absent,
        mode: 0,
        uid: 0,
        gid: 0,
        size: 0,
        dev: 0,
        ino: 0,
        mtime: String::new(),
        ctime: String::new(),
    }
}

/// Interpret exactly one `readlink -n` record: the complete target string.
///
/// `readlink -n` prints the target bytes with **no terminator and nothing
/// else**, so the *complete capture* is the record: the whole stdout byte
/// content is the link target string. Consequently no line-splitting,
/// trimming, or prefix acceptance may touch it (RA2-01):
///
/// * a capture whose bytes contain any line terminator (`\n`, `\r`) is not
///   the single defined record — it either carries a second record or
///   unexpected trailing bytes — and is an observation error, never a target
///   string that happens to match the desired value;
/// * an empty capture is not a target record;
/// * truncation, invalid UTF-8, or an unexpected diagnostic is an error.
///
/// A captured prefix is therefore never returned as the target. Note that a
/// target string containing a line terminator can never be observed as
/// compliant under this contract; that is the intended fail-closed behavior,
/// and recipe targets containing line terminators are not representable.
pub(crate) fn readlink_record(out: &Output, path: &str) -> Result<String> {
    require_complete(out, path)?;
    // A diagnostic next to the target string makes the record ambiguous.
    if !out.stderr.is_empty() {
        return Err(SinterError::apply(format!(
            "cannot read link {}: the capture carried an unexpected diagnostic",
            path
        )));
    }
    let text = utf8_stream(&out.stdout, path)?;
    // The capture is exactly one unterminated record. Any line terminator is
    // output the contract does not define, so it must not be normalized away
    // into a string that could be compared toward PASS.
    if text.is_empty() {
        return Err(SinterError::apply(format!(
            "readlink of {} produced no target record",
            path
        )));
    }
    if text.contains('\n') || text.contains('\r') {
        return Err(SinterError::apply(format!(
            "readlink of {} produced output outside the single target record",
            path
        )));
    }
    Ok(text.to_string())
}

/// Strict `stat -c` observation contract (IA-01 / RA2-01):
///
/// * exit 0, no truncation, valid UTF-8, empty stderr, exactly one
///   newline-terminated nine-field record whose every field matches the
///   defined grammar -> a complete `Stat`
/// * a nonzero exit whose capture is *exactly* one recognized missing-object
///   diagnostic with no stdout -> `ObjKind::Absent`
/// * anything else (truncation, a missing or extra terminator, extra output,
///   malformed fields, a marker mixed with another diagnostic, an
///   unrecognized error) -> an observation error, because the object's state
///   could not be determined
///
/// A syntactically plausible prefix is never compared against expected state,
/// and the record is never normalized (trimmed) before validation: the record
/// boundary is part of the contract.
pub(crate) fn interpret_stat(out: &Output, path: &str) -> Result<Stat> {
    match out.completion {
        Completion::Exited(0) => {
            require_complete(out, path)?;
            // stderr is not part of the success contract: a diagnostic
            // alongside the record makes the observation ambiguous.
            if !out.stderr.is_empty() {
                return Err(SinterError::apply(format!(
                    "cannot inspect {}: the capture carried an unexpected diagnostic",
                    path
                )));
            }
            let text = utf8_stream(&out.stdout, path)?;
            parse_stat_line(text)
                .map_err(|e| SinterError::apply(format!("cannot inspect {}: {}", path, e)))
        }
        Completion::Exited(_) => {
            // Absence is a positive observation, not a fallback: only the
            // narrow, complete absence contract may become `Absent`.
            match classify_absence(out, path, "/usr/bin/stat") {
                AbsenceVerdict::Absent => Ok(absent_stat()),
                AbsenceVerdict::Ambiguous => Err(SinterError::apply(format!(
                    "cannot inspect {}: {}",
                    path,
                    diagnostic_summary(&out.stderr)
                ))),
            }
        }
        Completion::Signaled(s) => Err(SinterError::apply(format!(
            "inspection of {} terminated by signal {}",
            path, s
        ))),
        Completion::Indeterminate { ref reason, .. } => Err(SinterError::indeterminate(format!(
            "inspection of {} did not complete: {}",
            path, reason
        ))),
    }
}

/// Largest completed remote command (as built by
/// [`crate::executor::build_remote_command`], i.e. including the `env -i`
/// baseline, the optional `sudo -n --` wrapper and all quoting) that the
/// batched parent walk will send. A walk whose `stat` or `getfattr` command
/// would be larger runs the sequential walk instead, decided before anything
/// is dispatched.
///
/// This is an internal, conservative safety margin, **not** a transport
/// contract. 16 KiB is far below every limit known on the path: the Linux
/// per-argument limit (`MAX_ARG_STRLEN`, 131,072 bytes; commands up to 131,070
/// bytes were measured to run through OpenSSH on all eight reference targets)
/// and the 32,768-byte payload / 35,000-byte packet every SSH implementation
/// must accept (RFC 4253 §6.1), which also bounds an unproven libssh2 request
/// path. Typical walks are a few hundred bytes to a few KiB; only
/// pathologically deep or long paths fall back, and falling back costs nothing
/// but the optimisation.
pub(crate) const BATCHED_WALK_MAX_COMMAND_BYTES: usize = 16 * 1024;

/// `stat` format of the batched observation: the nine sequential fields, then
/// the operand name, NUL-terminated. NUL cannot occur in a path, so a record
/// boundary is unambiguous for any file name.
const BATCHED_STAT_FORMAT: &str = "--printf=%F|%a|%u|%g|%s|%d|%i|%y|%z|%n\\0";

fn batched_stat_args(dirs: &[String]) -> Vec<String> {
    let mut args = vec![BATCHED_STAT_FORMAT.to_string(), "--".to_string()];
    args.extend(dirs.iter().cloned());
    args
}

fn batched_getfattr_args(dirs: &[String]) -> Vec<String> {
    let mut args: Vec<String> = ["-d", "-m", "-", "-e", "base64", "--absolute-names", "--"]
        .iter()
        .map(|a| a.to_string())
        .collect();
    args.extend(dirs.iter().cloned());
    args
}

/// Interpret one batched `stat --printf` capture covering `dirs`, in order.
///
/// The capture is accepted only when it is the complete, clean answer: exit 0,
/// not truncated, empty stderr, valid UTF-8, NUL-terminated, exactly one
/// record per operand, each record naming the operand it must describe, and
/// every record passing the same nine-field grammar as the sequential
/// observation. Any other outcome — a non-zero exit (including a partial
/// answer), a signal, an indeterminate completion, a missing, extra, duplicate
/// or misattributed record — is an error: nothing is salvaged from a prefix.
pub(crate) fn interpret_stat_batch(out: &Output, path: &str, dirs: &[String]) -> Result<Vec<Stat>> {
    let what = format!("the parent paths of {}", path);
    match out.completion {
        Completion::Exited(0) => {}
        Completion::Exited(c) => {
            return Err(SinterError::apply(format!(
                "cannot inspect {}: stat exited with status {} (a parent directory may be missing or inaccessible)",
                what, c
            )))
        }
        Completion::Signaled(s) => {
            return Err(SinterError::apply(format!(
                "inspection of {} terminated by signal {}",
                what, s
            )))
        }
        Completion::Indeterminate { ref reason, .. } => {
            return Err(SinterError::indeterminate(format!(
                "inspection of {} did not complete: {}",
                what, reason
            )))
        }
    }
    require_complete(out, &what)?;
    if !out.stderr.is_empty() {
        return Err(SinterError::apply(format!(
            "cannot inspect {}: the capture carried an unexpected diagnostic",
            what
        )));
    }
    let text = utf8_stream(&out.stdout, &what)?;
    let body = text.strip_suffix('\0').ok_or_else(|| {
        SinterError::apply(format!(
            "cannot inspect {}: the stat output is not terminated by the expected record separator",
            what
        ))
    })?;
    let records: Vec<&str> = body.split('\0').collect();
    if records.len() != dirs.len() {
        return Err(SinterError::apply(format!(
            "cannot inspect {}: expected {} stat records, got {}",
            what,
            dirs.len(),
            records.len()
        )));
    }
    let mut stats = Vec::with_capacity(dirs.len());
    for (dir, record) in dirs.iter().zip(records) {
        // Nine fields, then the operand name (which may itself contain `|`).
        let parts: Vec<&str> = record.splitn(10, '|').collect();
        if parts.len() != 10 {
            return Err(SinterError::apply(format!(
                "cannot inspect {}: malformed stat record",
                dir
            )));
        }
        if parts[9] != dir {
            return Err(SinterError::apply(format!(
                "cannot inspect {}: the stat record describes a different operand",
                dir
            )));
        }
        let st = parse_stat_fields(&parts[..9])
            .map_err(|e| SinterError::apply(format!("cannot inspect {}: {}", dir, e)))?;
        stats.push(st);
    }
    Ok(stats)
}

/// The name `getfattr` prints in a `# file:` header: the operand with
/// backslash, line feed and carriage return written as octal escapes.
fn getfattr_header_name(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '\\' => out.push_str("\\134"),
            '\n' => out.push_str("\\012"),
            '\r' => out.push_str("\\015"),
            _ => out.push(c),
        }
    }
    out
}

/// Interpret one batched `getfattr -d -m - -e base64` capture covering
/// `dirs`, in order, returning one [`Xattrs`] per operand.
///
/// `getfattr` prints a block only for an object that has attributes, so an
/// operand without a block is an object without attributes — but only when the
/// whole capture is complete and clean (exit 0, not truncated, empty stderr,
/// valid UTF-8, every block terminated). Each block must be headed by one of
/// the expected operands, in operand order and at most once. A non-zero exit,
/// signal, indeterminate completion, unknown / duplicate / out-of-order header,
/// stray line or unterminated block is an error; nothing is salvaged. Each
/// block is then interpreted by the same predicate as the sequential capture.
pub(crate) fn interpret_getfattr_batch(
    out: &Output,
    path: &str,
    dirs: &[String],
) -> Result<Vec<Xattrs>> {
    let what = format!("the access metadata of the parent paths of {}", path);
    match out.completion {
        Completion::Exited(0) => {}
        Completion::Exited(c) => {
            return Err(SinterError::apply(format!(
                "cannot inspect {}: getfattr exited with status {}",
                what, c
            )))
        }
        Completion::Signaled(s) => {
            return Err(SinterError::apply(format!(
                "inspection of {} terminated by signal {}",
                what, s
            )))
        }
        Completion::Indeterminate { ref reason, .. } => {
            return Err(SinterError::indeterminate(format!(
                "inspection of {} did not complete: {}",
                what, reason
            )))
        }
    }
    require_complete(out, &what)?;
    if !out.stderr.is_empty() {
        return Err(SinterError::apply(format!(
            "cannot inspect {}: the capture carried an unexpected diagnostic",
            what
        )));
    }
    let text = utf8_stream(&out.stdout, &what)?;
    let malformed =
        |why: &str| SinterError::apply(format!("cannot inspect {}: getfattr output {}", what, why));
    let mut blocks: Vec<Option<String>> = vec![None; dirs.len()];
    if !text.is_empty() {
        if !text.ends_with("\n\n") {
            return Err(malformed("is not terminated"));
        }
        let expected: BTreeMap<String, usize> = dirs
            .iter()
            .enumerate()
            .map(|(i, d)| (getfattr_header_name(d), i))
            .collect();
        let mut lines: Vec<&str> = text.split('\n').collect();
        lines.pop(); // the empty remainder after the final line feed
        let mut current: Option<(usize, String)> = None;
        let mut last: Option<usize> = None;
        for line in lines {
            if let Some(name) = line.strip_prefix("# file: ") {
                if current.is_some() {
                    return Err(malformed("has an unterminated block"));
                }
                let Some(&idx) = expected.get(name) else {
                    return Err(malformed("names an unexpected object"));
                };
                if blocks[idx].is_some() {
                    return Err(malformed("repeats an object"));
                }
                if last.is_some_and(|l| idx <= l) {
                    return Err(malformed("is out of operand order"));
                }
                last = Some(idx);
                current = Some((idx, format!("{}\n", line)));
            } else if line.is_empty() {
                let Some((idx, block)) = current.take() else {
                    return Err(malformed("has a stray blank line"));
                };
                blocks[idx] = Some(block);
            } else {
                let Some((_, block)) = current.as_mut() else {
                    return Err(malformed("has a line outside any block"));
                };
                block.push_str(line);
                block.push('\n');
            }
        }
        if current.is_some() {
            return Err(malformed("has an unterminated block"));
        }
    }
    Ok(blocks
        .into_iter()
        .map(|b| match b {
            Some(text) => parse_getfattr_text(&text),
            None => Xattrs {
                attrs: BTreeMap::new(),
                inspected: true,
            },
        })
        .collect())
}

/// Interpret a `sha256sum` capture. See [`TargetFs::sha256`] for the
/// contract: a complete, single, well-formed record yields the digest; a
/// command failure yields `None` (no trustworthy digest); everything else is
/// an observation error.
pub(crate) fn interpret_sha256(out: &Output, path: &str) -> Result<Option<String>> {
    match out.completion {
        Completion::Exited(0) => Ok(Some(parse_sha256_record(out, path)?)),
        Completion::Exited(_) => Ok(None),
        Completion::Signaled(_) | Completion::Indeterminate { .. } => Err(
            SinterError::indeterminate(format!("digest of {} did not complete", path)),
        ),
    }
}

/// Interpret exactly one `<digest>  <name>` record from a successful
/// `sha256sum` capture. The grammar is fixed and every part of it is
/// validated; no part of the record is inferred from a prefix (IA-01).
pub(crate) fn parse_sha256_record(out: &Output, path: &str) -> Result<String> {
    require_complete(out, path)?;
    // stderr is not part of the success contract: a diagnostic alongside
    // the record makes the observation ambiguous, so it is never ignored
    // or normalized into a trustworthy digest.
    if !out.stderr.is_empty() {
        return Err(SinterError::apply(format!(
            "digest of {} carried an unexpected diagnostic",
            path
        )));
    }
    let text = utf8_stream(&out.stdout, path)?;
    // `sha256sum` terminates its single record with exactly one newline. The
    // terminator is part of the contract: an unterminated capture or a second
    // record is output the contract does not define and is never normalized
    // into a record (RA2-01).
    let line = text
        .strip_suffix('\n')
        .ok_or_else(|| SinterError::apply(format!("digest of {} produced no output", path)))?;
    if line.contains('\n') || line.contains('\r') {
        return Err(SinterError::apply(format!(
            "digest of {} produced unexpected additional output",
            path
        )));
    }
    let b = line.as_bytes();
    // 64 digest characters, exactly two separator spaces, then a name.
    if b.len() < 67 {
        return Err(SinterError::apply(format!(
            "digest output for {} is malformed",
            path
        )));
    }
    let digest = &b[..64];
    if !digest
        .iter()
        .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
    {
        return Err(SinterError::apply(format!(
            "digest output for {} is not a valid SHA-256 digest",
            path
        )));
    }
    if &b[64..66] != b"  " {
        return Err(SinterError::apply(format!(
            "digest output for {} has an unexpected record structure",
            path
        )));
    }
    // Index 66 is a char boundary: every byte before it is ASCII.
    let name = &line[66..];
    if name.is_empty() {
        return Err(SinterError::apply(format!(
            "digest output for {} is malformed",
            path
        )));
    }
    // The record must describe the path that was actually hashed.
    if name != path && name != coreutils_escaped_name(path) {
        return Err(SinterError::apply(format!(
            "digest output for {} names a different path",
            path
        )));
    }
    Ok(String::from_utf8(digest.to_vec()).expect("validated ASCII"))
}

fn same_identity(previous: &Stat, current: &Stat) -> bool {
    previous.kind == current.kind
        && previous.dev == current.dev
        && previous.ino == current.ino
        && previous.mtime == current.mtime
        && previous.ctime == current.ctime
}

/// Verdict for a failed observation that may or may not prove absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AbsenceVerdict {
    /// The capture positively and unambiguously reports the object is missing.
    Absent,
    /// The capture is ambiguous or unrecognized: the object's state cannot be
    /// determined, so the caller must fail closed instead of guessing.
    Ambiguous,
}

/// Strict filesystem-absence contract (IA-01 / RA2-01). Absence is a
/// *positive* observation, never a fallback for an unreadable error stream:
/// the capture must be complete, must carry no stdout, and must consist of
/// exactly one recognized missing-object diagnostic on stderr whose every
/// field — program identity, operand path, and message — matches the exact
/// form coreutils emits for the path being inspected.
///
/// `program` is the argv[0] Audit actually dispatched (for example
/// `/usr/bin/stat`): coreutils echoes argv[0] verbatim, so the diagnostic's
/// program field must be that exact path or its basename. A diagnostic
/// attributed to any other program does not prove this observation's object
/// is absent.
///
/// Anything else leaves the object's state undetermined and is reported as
/// `Ambiguous`, which callers must turn into an observation error — never
/// into absence and never into a compliance answer:
///
/// * the recognized message as a substring of a longer diagnostic (e.g. a
///   permission refusal that merely contains the wording)
/// * the recognized wording for a different path
/// * a diagnostic attributed to a program Audit did not dispatch
/// * the marker mixed with another diagnostic on the same stream
/// * an extra blank record or any trailing/leading junk
/// * a truncated stream (the diagnostic may continue past the capture limit)
/// * invalid bytes (lossy decoding could repair the message)
/// * non-empty stdout alongside the diagnostic
/// * an unrecognized error
pub(crate) fn classify_absence(out: &Output, path: &str, program: &str) -> AbsenceVerdict {
    if out.stdout_truncated || out.stderr_truncated {
        return AbsenceVerdict::Ambiguous;
    }
    if !out.stdout.is_empty() {
        return AbsenceVerdict::Ambiguous;
    }
    let Ok(text) = std::str::from_utf8(&out.stderr) else {
        return AbsenceVerdict::Ambiguous;
    };
    // Exactly one complete diagnostic line: coreutils terminates it with a
    // single newline and emits nothing else. A missing terminator means the
    // capture is not the defined record; a second line — blank or not — is
    // extra evidence the observation is not the single missing-object answer.
    let Some(line) = text.strip_suffix('\n') else {
        return AbsenceVerdict::Ambiguous;
    };
    if line.is_empty() || line.contains('\n') || line.contains('\r') {
        return AbsenceVerdict::Ambiguous;
    }
    // coreutils writes `<program>: <subject>: <message>`. Every field is
    // validated; the message is never matched as a substring of other text.
    let Some((program_field, rest)) = line.split_once(": ") else {
        return AbsenceVerdict::Ambiguous;
    };
    // The diagnostic must be attributed to the program this observation
    // dispatched, in the exact argv[0] form or its basename.
    let basename = program.rsplit('/').next().unwrap_or(program);
    if program_field != program && program_field != basename {
        return AbsenceVerdict::Ambiguous;
    }
    // The recognized operand/subject forms for that program, byte-exact.
    let subjects: &[String] = match basename {
        // GNU coreutils `stat` reports `cannot statx '<path>'` (8.x) or
        // `cannot stat '<path>'` (older releases).
        "stat" => &[
            format!("cannot statx {}", q(path)),
            format!("cannot stat {}", q(path)),
        ],
        // GNU coreutils `readlink` prints the operand path unquoted.
        "readlink" => &[path.to_string()],
        _ => return AbsenceVerdict::Ambiguous,
    };
    for subject in subjects {
        // Whole-field equality, with one narrow extension: Rust coreutils
        // (uutils, the default on Ubuntu 26.04) renders OS errors through
        // Rust's io::Error Display, which appends ` (os error N)` where N is
        // the errno. Accept that suffix only when N is the errno the message
        // itself names — never an arbitrary error number or trailing text.
        for (message, errno) in [("No such file or directory", 2), ("Not a directory", 20)] {
            // A permission diagnostic such as
            // `...: Permission denied: no such file or directory` does not
            // match, because its subject field is longer.
            if rest == format!("{}: {}", subject, message)
                || rest == format!("{}: {} (os error {})", subject, message, errno)
            {
                return AbsenceVerdict::Absent;
            }
        }
    }
    AbsenceVerdict::Ambiguous
}

/// Render an uninterpretable diagnostic stream for an error message without
/// lossy UTF-8 repair and without trimming (RA2-01: no normalization of
/// captured bytes; invalid bytes are described, never repaired into text).
/// The audit layer redacts this whole message for sensitive resources.
fn diagnostic_summary(stderr: &[u8]) -> String {
    match std::str::from_utf8(stderr) {
        Ok("") => "the capture carried an unrecognized diagnostic".to_string(),
        Ok(text) => format!("the capture carried an unrecognized diagnostic: {:?}", text),
        Err(_) => "the capture carried an unrecognized diagnostic with invalid UTF-8".to_string(),
    }
}

/// Reject an incomplete capture. A truncated stream can never prove a
/// complete observation, and comparing a captured prefix against expected
/// state can never produce a PASS (IA-01).
fn require_complete(out: &Output, what: &str) -> Result<()> {
    if out.stdout_truncated || out.stderr_truncated {
        return Err(SinterError::apply(format!(
            "observation of {} captured truncated output: the result is incomplete",
            what
        )));
    }
    Ok(())
}

/// Strictly decode a capture stream as UTF-8. Observation grammars here are
/// textual: lossy decoding could turn malformed bytes into a syntactically
/// valid record, so invalid UTF-8 is an observation failure (IA-01 §10).
fn utf8_stream<'a>(bytes: &'a [u8], what: &str) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| {
        SinterError::apply(format!(
            "observation of {} captured invalid UTF-8 output",
            what
        ))
    })
}

/// Whether a field is a coreutils `%y`/`%z` timestamp
/// (`YYYY-MM-DD HH:MM:SS[.frac] [+-]HHMM`). GNU coreutils formats these with
/// `strftime`'s numeric timezone, so the offset is always present and always
/// four digits. A field that does not match this shape means the record is not
/// the observation the contract defines, so it is rejected instead of silently
/// carried into a comparison (IA-01).
fn is_timestamp_field(s: &str) -> bool {
    fn digits(b: &[u8]) -> bool {
        !b.is_empty() && b.iter().all(|c| c.is_ascii_digit())
    }
    fn range(b: &[u8], lo: u8, hi: u8) -> bool {
        let n = (b[0] - b'0') * 10 + (b[1] - b'0');
        n >= lo && n <= hi
    }
    let b = s.as_bytes();
    // YYYY-MM-DD HH:MM:SS is 19 characters; a numeric offset follows.
    if b.len() < 25 {
        return false;
    }
    if !(digits(&b[0..4])
        && b[4] == b'-'
        && digits(&b[5..7])
        && range(&b[5..7], 1, 12)
        && b[7] == b'-'
        && digits(&b[8..10])
        && range(&b[8..10], 1, 31)
        && b[10] == b' '
        && digits(&b[11..13])
        && range(&b[11..13], 0, 23)
        && b[13] == b':'
        && digits(&b[14..16])
        && range(&b[14..16], 0, 59)
        && b[16] == b':'
        && digits(&b[17..19])
        && range(&b[17..19], 0, 60))
    {
        return false;
    }
    let mut i = 19;
    // Optional fractional seconds.
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    if i >= b.len() || b[i] != b' ' {
        return false;
    }
    i += 1;
    // Numeric UTC offset, exactly `[+-]HHMM`.
    b.len() == i + 5 && (b[i] == b'+' || b[i] == b'-') && digits(&b[i + 1..])
}

/// The form GNU coreutils uses for a name that contains a backslash or a
/// newline: a leading backslash with C-style escapes. `sha256sum` prints this
/// form so its record boundary stays unambiguous.
fn coreutils_escaped_name(name: &str) -> String {
    if !name.contains('\\') && !name.contains('\n') {
        return name.to_string();
    }
    let mut out = String::from("\\");
    for c in name.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn parse_stat_line(text: &str) -> std::result::Result<Stat, String> {
    // Exactly one record, terminated by the single newline `stat -c` always
    // emits. The terminator is part of the contract: an unterminated capture
    // is not the defined record, and a capture with any further line is
    // output the contract does not define, so the whole observation is
    // ambiguous (IA-01/RA2-01). Nothing is trimmed: trimming would fold a
    // forbidden extra blank record into a valid-looking one.
    let line = text.strip_suffix('\n').ok_or_else(|| {
        "stat output is not terminated by the expected record newline".to_string()
    })?;
    if line.contains('\n') || line.contains('\r') {
        return Err("stat produced unexpected additional output".to_string());
    }
    // Exactly nine fields in a fixed order. A missing or extra field is an
    // ambiguous observation, never a partially-parsed one.
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() != 9 {
        return Err(format!("unexpected stat output: {:?}", line));
    }
    parse_stat_fields(&parts)
}

/// Validate and convert the nine `stat` fields (`%F|%a|%u|%g|%s|%d|%i|%y|%z`).
/// This is the single field grammar for both the one-record `stat -c`
/// observation and each record of a batched `stat --printf` capture, so a
/// batch is exactly as strict as the sequential observation (IA-01).
fn parse_stat_fields(parts: &[&str]) -> std::result::Result<Stat, String> {
    debug_assert_eq!(parts.len(), 9);
    let kind = match parts[0] {
        "regular file" | "regular empty file" => ObjKind::File,
        "directory" => ObjKind::Dir,
        "symbolic link" => ObjKind::Symlink,
        _ => ObjKind::Other,
    };
    let mode = u32::from_str_radix(parts[1], 8).map_err(|e| e.to_string())?;
    let uid = parts[2]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let gid = parts[3]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let size = parts[4]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let dev = parts[5]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let ino = parts[6]
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    // Every field must match the defined grammar; a malformed timestamp or
    // an empty field is not silently ignored.
    if parts[7].is_empty() || parts[8].is_empty() {
        return Err("stat output is missing a timestamp field".to_string());
    }
    if !is_timestamp_field(parts[7]) || !is_timestamp_field(parts[8]) {
        return Err("stat output has a malformed timestamp field".to_string());
    }
    let mtime = parts[7].to_string();
    let ctime = parts[8].to_string();
    Ok(Stat {
        kind,
        mode,
        uid,
        gid,
        size,
        dev,
        ino,
        mtime,
        ctime,
    })
}

pub fn q(s: &str) -> String {
    let mut out = String::from("'");
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Bound for one backup copy (a directory tree may be large).
pub const BACKUP_COPY_TIMEOUT_SECS: u64 = 1800;

pub fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Strict standard-alphabet base64 decoder (padding required). Returns None
/// on any malformed input.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, chunk) in b.chunks(4).enumerate() {
        let last = i == b.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (j, &c) in chunk.iter().enumerate() {
            let v = if j >= 4 - pad { 0 } else { val(c)? };
            n = (n << 6) | v;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_roundtrip() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"hello\n", &[0, 255, 1]] {
            assert_eq!(b64_decode(&b64_encode(data)).unwrap(), data);
        }
        assert!(b64_decode("Zg=").is_none());
        assert!(b64_decode("Z===").is_none());
        assert!(b64_decode("Zg==Zg==").is_none());
        assert!(b64_decode("Zm9v!").is_none());
    }

    #[test]
    fn base64_roundtrip_known() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"hello\n"), "aGVsbG8K");
        assert_eq!(b64_encode(&[0, 255, 1]), "AP8B");
    }

    #[test]
    fn acl_complete_without_extended() {
        let text = "user::rw-\ngroup::r--\nother::r--\n";
        match classify_acl_text(text) {
            AclClass::Complete { extended } => assert!(!extended),
            _ => panic!("expected complete, got incomplete/malformed"),
        }
    }

    #[test]
    fn acl_complete_with_extended() {
        let text = "user::rw-\nuser:alice:r--\ngroup::r--\nmask::r--\nother::r--\n";
        match classify_acl_text(text) {
            AclClass::Complete { extended } => assert!(extended),
            _ => panic!("expected complete extended"),
        }
    }

    #[test]
    fn acl_empty_is_incomplete() {
        assert!(matches!(classify_acl_text(""), AclClass::Incomplete));
        assert!(matches!(
            classify_acl_text("\n# comment only\n"),
            AclClass::Incomplete
        ));
    }

    #[test]
    fn acl_missing_base_entry_is_incomplete() {
        assert!(matches!(
            classify_acl_text("user::rw-\ngroup::r--\n"),
            AclClass::Incomplete
        ));
    }

    #[test]
    fn acl_malformed_base_entry_is_malformed() {
        assert!(matches!(
            classify_acl_text("user::garbage\ngroup::r--\nother::r--\n"),
            AclClass::Malformed
        ));
        assert!(matches!(
            classify_acl_text("user::rw\ngroup::r--\nother::r--\n"),
            AclClass::Malformed
        ));
    }

    #[test]
    fn acl_permission_positions_are_strict() {
        for ok in ["rwx", "rw-", "r-x", "r--", "-wx", "-w-", "--x", "---"] {
            assert!(is_valid_acl_perm(ok), "must accept {:?}", ok);
        }
        for bad in [
            "rrr", "www", "xxx", "xrw", "wr-", "xr-", "rw", "rwx-", "", "rwxr",
        ] {
            assert!(!is_valid_acl_perm(bad), "must reject {:?}", bad);
        }
    }

    #[test]
    fn selinux_label_is_preservable_not_unsafe() {
        // SELinux-enforcing RHEL-family targets label every object; a MAC
        // label cannot grant discretionary write and is restored on the
        // staged file before publication, so it must not disqualify.
        let mut attrs = BTreeMap::new();
        attrs.insert(
            "security.selinux".to_string(),
            "0sdW5jb25maW5lZF91Om9iamVjdF9yOnVzZXJfaG9tZV90OnMw".to_string(),
        );
        let x = Xattrs {
            attrs,
            inspected: true,
        };
        assert_eq!(x.unsafe_attr(), None);
        assert_eq!(
            x.preserved_attrs()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>(),
            vec!["security.selinux"]
        );
    }

    #[test]
    fn other_security_attrs_still_unsafe() {
        for name in [
            "security.capability",
            "security.ima",
            "security.evm",
            "trusted.overlay.opaque",
            "system.posix_acl_access",
        ] {
            let mut attrs = BTreeMap::new();
            attrs.insert(name.to_string(), "0sYQ==".to_string());
            let x = Xattrs {
                attrs,
                inspected: true,
            };
            assert_eq!(x.unsafe_attr().as_deref(), Some(name));
            assert_eq!(x.preserved_attrs().count(), 0);
        }
    }

    #[test]
    fn xattr_encoded_values_validated() {
        assert!(is_valid_xattr_encoded(""));
        assert!(is_valid_xattr_encoded("0sYQ=="));
        assert!(is_valid_xattr_encoded("0s"));
        assert!(is_valid_xattr_encoded("0x6162"));
        assert!(!is_valid_xattr_encoded("garbage"));
        assert!(!is_valid_xattr_encoded("0s!!!"));
        assert!(!is_valid_xattr_encoded("0xzz"));
    }

    /// A target without `/usr/bin/getfattr` cannot prove a path is safe to
    /// write, so the refusal must name the program and the package that
    /// provides it. Stock Ubuntu cloud images ship no `attr` package, which
    /// is why the hint is the only difference between an actionable error
    /// and an unexplained one (DESIGN §24.4 stays fail-closed either way).
    #[test]
    fn missing_getfattr_yields_an_actionable_refusal_reason() {
        let with = TargetFs::new_for(
            Executor::Fake(Box::new(crate::executor::FakeExecutor::new(
                crate::executor::FakeTarget::rocky9(),
                false,
            ))),
            false,
            1000,
            1000,
            "/home/fake".to_string(),
            Some(crate::platform::PackageBackend::Dnf),
            true,
            true,
            true,
            None,
        );
        assert!(with.xattr_inspection_unavailable().is_none());

        // Ubuntu 26.04 stock image: no attr package, no inspection.
        let without = TargetFs::new_for(
            Executor::Fake(Box::new(crate::executor::FakeExecutor::new(
                crate::executor::FakeTarget::ubuntu2604(),
                false,
            ))),
            false,
            1000,
            1000,
            "/home/fake".to_string(),
            Some(crate::platform::PackageBackend::Apt),
            false,
            false,
            true,
            None,
        );
        let reason = without
            .xattr_inspection_unavailable()
            .expect("a getfattr-less target must explain the refusal");
        assert!(reason.contains("/usr/bin/getfattr"));
        assert!(reason.contains("attr"));
    }

    // -----------------------------------------------------------------
    // IA-01: fail-closed observation contracts. Every case below asserts the
    // semantic result, not merely that a parser rejected input: incomplete,
    // truncated, malformed, or ambiguous evidence can never produce a value
    // that could be compared toward PASS.
    // -----------------------------------------------------------------

    fn out_exit(code: i32, stdout: &[u8], stderr: &[u8]) -> Output {
        Output {
            completion: Completion::Exited(code),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    const STAT_LINE: &str = "regular file|644|1000|1000|12|2051|1234567|2026-09-19 09:30:00.000000000 +0000|2026-09-19 09:30:00.000000000 +0000";

    #[test]
    fn stat_contract_accepts_a_complete_record() {
        let st = parse_stat_line(&format!("{}\n", STAT_LINE)).expect("valid record");
        assert_eq!(st.kind, ObjKind::File);
        assert_eq!(st.mode, 0o644);
        assert_eq!(st.uid, 1000);
        assert_eq!(st.gid, 1000);
        assert_eq!(st.size, 12);
        assert_eq!(st.mtime, "2026-09-19 09:30:00.000000000 +0000");
        assert_eq!(st.kind.describe(), "file");
        // A wrong type is still a valid observation: the caller compares it
        // against the desired type and reports DRIFT.
        let dir_line = STAT_LINE.replacen("regular file", "directory", 1);
        assert_eq!(
            parse_stat_line(&format!("{}\n", dir_line))
                .expect("valid record")
                .kind,
            ObjKind::Dir
        );
    }

    #[test]
    fn stat_contract_rejects_a_missing_terminator() {
        // `stat -c` always terminates its record; an unterminated capture is
        // not the defined observation.
        assert!(parse_stat_line(STAT_LINE).is_err());
    }

    #[test]
    fn stat_contract_rejects_an_extra_blank_record() {
        // A valid record followed by a blank line: trim() would fold this
        // into a valid-looking record, so the framing must be exact (RA2-01).
        assert!(parse_stat_line(&format!("{}\n\n", STAT_LINE)).is_err());
        assert!(parse_stat_line(&format!("{}\r\n", STAT_LINE)).is_err());
        // A leading blank record is equally disqualifying.
        assert!(parse_stat_line(&format!("\n{}\n", STAT_LINE)).is_err());
    }

    #[test]
    fn stat_contract_rejects_trailing_bytes_after_the_record() {
        // Any byte after the single terminating newline is extra output.
        assert!(parse_stat_line(&format!("{}\n ", STAT_LINE)).is_err());
        assert!(parse_stat_line(&format!("{}\nextra\n", STAT_LINE)).is_err());
    }

    #[test]
    fn stat_contract_rejects_a_missing_field() {
        // Eight fields where nine are defined: no partial parse is allowed.
        let bad = "regular file|644|1000|1000|12|2051|1234567|2026-09-19 09:30:00.000000000 +0000";
        assert!(parse_stat_line(bad).is_err());
    }
    #[test]
    fn stat_contract_rejects_an_extra_ambiguous_field() {
        let bad = format!("{}|extra\n", STAT_LINE);
        assert!(parse_stat_line(&bad).is_err());
    }

    #[test]
    fn stat_contract_rejects_an_invalid_numeric_field() {
        let bad = STAT_LINE.replacen("1000|1000", "root|1000", 1);
        assert!(parse_stat_line(&bad).is_err());
        let bad_mode = STAT_LINE.replacen("|644|", "|abc|", 1);
        assert!(parse_stat_line(&bad_mode).is_err());
    }

    #[test]
    fn stat_contract_rejects_unexpected_diagnostic_output() {
        // A valid-looking record plus a second line of output: the capture is
        // not the single defined observation.
        let bad = format!("{}\nwarning: stat: deprecated option\n", STAT_LINE);
        assert!(parse_stat_line(&bad).is_err());
        assert!(parse_stat_line("").is_err());
    }

    #[test]
    fn stat_contract_rejects_a_malformed_timestamp_field() {
        let bad = STAT_LINE.replacen("+0000", "garbage", 1);
        assert!(parse_stat_line(&bad).is_err());
        let empty_ts = STAT_LINE.replacen(
            "2026-09-19 09:30:00.000000000 +0000|2026-09-19 09:30:00.000000000 +0000",
            "|2026-09-19 09:30:00.000000000 +0000",
            1,
        );
        assert!(parse_stat_line(&empty_ts).is_err());
    }

    #[test]
    fn stat_contract_treats_truncated_output_as_incomplete() {
        // The capture limit cut the record mid-field. However plausible the
        // prefix looks, it must never become a Stat the caller could compare.
        let mut o = out_exit(0, STAT_LINE.as_bytes(), b"");
        o.stdout_truncated = true;
        assert!(interpret_stat(&o, "/f").is_err());
        // stderr truncation is equally unusable.
        let mut o = out_exit(0, format!("{}\n", STAT_LINE).as_bytes(), b"");
        o.stderr_truncated = true;
        assert!(interpret_stat(&o, "/f").is_err());
    }

    #[test]
    fn stat_contract_treats_a_valid_wrong_type_as_drift_evidence() {
        // A complete, valid observation proving the object is not the desired
        // type: this is ordinary evidence the caller turns into DRIFT, so the
        // observation itself must succeed.
        let dir_line = STAT_LINE.replacen("regular file", "directory", 1);
        let st = interpret_stat(
            &out_exit(0, format!("{}\n", dir_line).as_bytes(), b""),
            "/f",
        )
        .expect("a complete wrong-type observation is still an observation");
        assert_eq!(st.kind, ObjKind::Dir);
    }

    #[test]
    fn stat_contract_proves_absence_only_with_a_clean_missing_result() {
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/gone': No such file or directory\n",
        );
        assert_eq!(interpret_stat(&o, "/gone").unwrap().kind, ObjKind::Absent);
    }

    #[test]
    fn stat_contract_treats_an_unknown_diagnostic_as_an_error_not_absence() {
        let o = out_exit(1, b"", b"stat: cannot statx '/x': Input/output error\n");
        assert!(interpret_stat(&o, "/x").is_err());
    }

    #[test]
    fn timestamp_field_shape_is_strict() {
        assert!(is_timestamp_field("2026-09-19 09:30:00.000000000 +0000"));
        assert!(is_timestamp_field("2026-09-19 09:30:00 -0500"));
        assert!(is_timestamp_field("2026-01-31 23:59:60 -1200"));
        assert!(!is_timestamp_field(""));
        assert!(!is_timestamp_field("yesterday"));
        assert!(!is_timestamp_field("2026-09-19 09:30:00"));
        assert!(!is_timestamp_field("2026-13-19 09:30:00 +0000"));
        assert!(!is_timestamp_field("2026-00-19 09:30:00 +0000"));
        assert!(!is_timestamp_field("2026-09-32 09:30:00 +0000"));
        assert!(!is_timestamp_field("2026-09-19 24:30:00 +0000"));
        assert!(!is_timestamp_field("2026-09-19 09:60:00 +0000"));
        assert!(!is_timestamp_field("2026-09-19 09:30:00."));
        assert!(!is_timestamp_field("2026-09-19 09:30:00 +00"));
        assert!(!is_timestamp_field("2026-09-19 09:30:00 UTC"));
        assert!(!is_timestamp_field("2026-09-19 09:30:00 0"));
    }

    #[test]
    fn absence_contract_accepts_only_a_clean_recognized_missing_result() {
        // stat on a missing path: one diagnostic line, no stdout, and every
        // field (program, operand path, message) matching the exact form.
        // coreutils echoes argv[0] verbatim, so production emits the full
        // dispatched path.
        let o = out_exit(
            1,
            b"",
            b"/usr/bin/stat: cannot statx '/gone': No such file or directory\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Absent
        );
        // The basename form is the same contract.
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/gone': No such file or directory\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Absent
        );
        // The legacy coreutils verb form is still the same contract.
        let o = out_exit(
            1,
            b"",
            b"stat: cannot stat '/gone': No such file or directory\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Absent
        );
        // readlink on a missing path, under the readlink dispatch.
        let o = out_exit(1, b"", b"readlink: /gone: No such file or directory\n");
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/readlink"),
            AbsenceVerdict::Absent
        );
        // ENOTDIR for a path under a non-directory.
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/etc/hosts/x': Not a directory\n",
        );
        assert_eq!(
            classify_absence(&o, "/etc/hosts/x", "/usr/bin/stat"),
            AbsenceVerdict::Absent
        );
        // A path containing ': ' still splits at the defined field boundary.
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/tmp/a: b': No such file or directory\n",
        );
        assert_eq!(
            classify_absence(&o, "/tmp/a: b", "/usr/bin/stat"),
            AbsenceVerdict::Absent
        );
    }

    #[test]
    fn absence_contract_accepts_the_uutils_errno_suffixed_missing_result() {
        // Rust coreutils (uutils, default on Ubuntu 26.04) renders the OS
        // error through io::Error Display: the same missing-path diagnostic
        // with a ` (os error N)` suffix where N is the errno. The exact form
        // observed on the Ubuntu 26.04 acceptance target.
        let o = out_exit(
            1,
            b"",
            b"stat: cannot stat '/gone': No such file or directory (os error 2)\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Absent
        );
        // The full dispatched argv[0] and the statx verb form obey the same
        // contract.
        let o = out_exit(
            1,
            b"",
            b"/usr/bin/stat: cannot statx '/gone': No such file or directory (os error 2)\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Absent
        );
        // ENOTDIR pairs with its own errno, 20.
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/etc/hosts/x': Not a directory (os error 20)\n",
        );
        assert_eq!(
            classify_absence(&o, "/etc/hosts/x", "/usr/bin/stat"),
            AbsenceVerdict::Absent
        );
        // The readlink operand form under the readlink dispatch.
        let o = out_exit(
            1,
            b"",
            b"readlink: /gone: No such file or directory (os error 2)\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/readlink"),
            AbsenceVerdict::Absent
        );
        // End to end: the observation boundary reports the object absent.
        let o = out_exit(
            1,
            b"",
            b"stat: cannot stat '/gone': No such file or directory (os error 2)\n",
        );
        assert_eq!(interpret_stat(&o, "/gone").unwrap().kind, ObjKind::Absent);
    }

    #[test]
    fn absence_contract_rejects_a_wrong_errno_suffix() {
        // The suffix must carry the errno the message names: ENOENT is 2.
        for errno in [1, 5, 13, 20, 22] {
            let o = out_exit(
                1,
                b"",
                format!(
                    "stat: cannot stat '/gone': No such file or directory (os error {})\n",
                    errno
                )
                .as_bytes(),
            );
            assert_eq!(
                classify_absence(&o, "/gone", "/usr/bin/stat"),
                AbsenceVerdict::Ambiguous
            );
        }
        // ENOTDIR's errno is 20, not 2.
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/etc/hosts/x': Not a directory (os error 2)\n",
        );
        assert_eq!(
            classify_absence(&o, "/etc/hosts/x", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
    }

    #[test]
    fn absence_contract_rejects_a_malformed_or_extended_errno_suffix() {
        for stderr in [
            // Missing close paren.
            "stat: cannot stat '/gone': No such file or directory (os error 2\n",
            // Non-numeric errno field.
            "stat: cannot stat '/gone': No such file or directory (os error x)\n",
            // Duplicated suffix.
            "stat: cannot stat '/gone': No such file or directory (os error 2) (os error 2)\n",
            // Trailing text after the valid suffix.
            "stat: cannot stat '/gone': No such file or directory (os error 2) extra\n",
            // Suffix attached to different wording.
            "stat: cannot stat '/gone': No such file or directories (os error 2)\n",
            // Missing space before the suffix.
            "stat: cannot stat '/gone': No such file or directory(os error 2)\n",
        ] {
            let o = out_exit(1, b"", stderr.as_bytes());
            assert_eq!(
                classify_absence(&o, "/gone", "/usr/bin/stat"),
                AbsenceVerdict::Ambiguous
            );
        }
    }

    #[test]
    fn absence_contract_rejects_a_marker_mixed_with_another_error() {
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/gone': No such file or directory\nerror: I/O failure\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
    }

    #[test]
    fn absence_contract_rejects_a_missing_extra_blank_record() {
        // The recognized diagnostic followed by a blank line: the capture is
        // not the single defined missing-object answer (RA2-01).
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/gone': No such file or directory\n\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
        // A leading blank record is equally disqualifying.
        let o = out_exit(
            1,
            b"",
            b"\nstat: cannot statx '/gone': No such file or directory\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
    }

    #[test]
    fn absence_contract_rejects_the_recognized_wording_for_another_path() {
        // A genuine missing diagnostic, but about a different object: it does
        // not prove this path is absent.
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/other': No such file or directory\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
    }

    #[test]
    fn absence_contract_rejects_an_unexpected_program_identity() {
        // The wording is right, but the diagnostic is attributed to a program
        // this observation never dispatched.
        let o = out_exit(
            1,
            b"",
            b"ls: cannot statx '/gone': No such file or directory\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
        // A readlink diagnostic cannot answer a stat observation, and vice
        // versa: the operand form differs between the two programs.
        let o = out_exit(1, b"", b"readlink: /gone: No such file or directory\n");
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/gone': No such file or directory\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/readlink"),
            AbsenceVerdict::Ambiguous
        );
        // The readlink contract does not accept the quoted stat operand form.
        let o = out_exit(1, b"", b"readlink: '/gone': No such file or directory\n");
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/readlink"),
            AbsenceVerdict::Ambiguous
        );
    }

    #[test]
    fn absence_contract_rejects_a_truncated_missing_diagnostic() {
        let mut o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/gone': No such file or directory\n",
        );
        o.stderr_truncated = true;
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
        // A truncated stdout is equally unusable.
        let mut o = out_exit(1, b"regular file|644", b"");
        o.stdout_truncated = true;
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
    }

    #[test]
    fn absence_contract_rejects_an_unterminated_diagnostic() {
        // No trailing newline: this is not the complete defined record.
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/gone': No such file or directory",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
    }

    #[test]
    fn absence_contract_rejects_an_unknown_diagnostic() {
        let o = out_exit(1, b"", b"stat: cannot statx '/x': Input/output error\n");
        assert_eq!(
            classify_absence(&o, "/x", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
        let o = out_exit(1, b"", b"unexpected internal error\n");
        assert_eq!(
            classify_absence(&o, "/x", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
        // Empty stderr carries no diagnostic at all.
        let o = out_exit(1, b"", b"");
        assert_eq!(
            classify_absence(&o, "/x", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
    }

    #[test]
    fn absence_contract_rejects_a_permission_error_with_misleading_text() {
        // The wording appears inside a permission refusal; the real state is
        // unknown, so absence must not be inferred from a substring.
        let o = out_exit(
            1,
            b"",
            b"stat: cannot statx '/x': Permission denied: no such file or directory\n",
        );
        assert_eq!(
            classify_absence(&o, "/x", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
    }

    #[test]
    fn absence_contract_rejects_stdout_alongside_the_marker() {
        let o = out_exit(
            1,
            b"regular file|644|0|0|0|0|0|2026-09-19 09:30:00 +0000|2026-09-19 09:30:00 +0000\n",
            b"stat: cannot statx '/gone': No such file or directory\n",
        );
        assert_eq!(
            classify_absence(&o, "/gone", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
    }

    #[test]
    fn absence_contract_rejects_invalid_bytes() {
        let o = out_exit(1, b"", &[0xff, 0xfe]);
        assert_eq!(
            classify_absence(&o, "/x", "/usr/bin/stat"),
            AbsenceVerdict::Ambiguous
        );
    }

    // --- sha256sum contract ---------------------------------------

    fn sha_out(stdout: &str) -> Output {
        out_exit(0, stdout.as_bytes(), b"")
    }

    #[test]
    fn sha256_contract_accepts_a_complete_matching_record() {
        let path = "/etc/motd";
        let digest = crate::resources::sha256_hex(b"hello");
        let o = sha_out(&format!("{}  {}\n", digest, path));
        assert_eq!(parse_sha256_record(&o, path).unwrap(), digest);
    }

    #[test]
    fn sha256_contract_rejects_an_expected_prefix_with_truncated_remainder() {
        // The capture limit cut the record after the digest prefix. The
        // beginning matches the expected digest, which is exactly the
        // false-PASS shape this contract exists to close.
        let path = "/etc/motd";
        let digest = crate::resources::sha256_hex(b"hello");
        let mut o = sha_out(&format!("{}  {}", digest, path));
        o.stdout_truncated = true;
        assert!(interpret_sha256(&o, path).is_err());
        // Truncation of stderr is equally disqualifying.
        let mut o = sha_out(&format!("{}  {}\n", digest, path));
        o.stderr_truncated = true;
        assert!(interpret_sha256(&o, path).is_err());
    }

    #[test]
    fn sha256_contract_rejects_stderr_alongside_a_valid_record() {
        // exit 0 + a perfectly valid record + any stderr diagnostic: the
        // capture is ambiguous and must fail closed rather than accept the
        // record as authoritative.
        let path = "/etc/motd";
        let digest = crate::resources::sha256_hex(b"hello");
        let o = out_exit(
            0,
            format!("{}  {}\n", digest, path).as_bytes(),
            b"sha256sum: WARNING: 1 listed file could not be read\n",
        );
        assert!(interpret_sha256(&o, path).is_err());
        assert!(parse_sha256_record(&o, path).is_err());
        // The diagnostic bytes are rejected, never echoed into the error.
        let e = parse_sha256_record(&o, path).unwrap_err().to_string();
        assert!(
            !e.contains("could not be read"),
            "stderr leaked into the observation error: {e}"
        );
    }

    #[test]
    fn sha256_contract_rejects_a_malformed_short_hash() {
        let path = "/etc/motd";
        let o = sha_out("abc123  /etc/motd\n");
        assert!(parse_sha256_record(&o, path).is_err());
        // Nothing at all.
        assert!(parse_sha256_record(&sha_out(""), path).is_err());
    }

    #[test]
    fn sha256_contract_rejects_a_non_hex_digest() {
        let path = "/etc/motd";
        let bad = "g".repeat(64);
        let o = sha_out(&format!("{}  {}\n", bad, path));
        assert!(parse_sha256_record(&o, path).is_err());
        // Uppercase hex is not the defined GNU output form.
        let upper = crate::resources::sha256_hex(b"hello").to_uppercase();
        let o = sha_out(&format!("{}  {}\n", upper, path));
        assert!(parse_sha256_record(&o, path).is_err());
    }

    #[test]
    fn sha256_contract_rejects_a_valid_digest_with_malformed_trailing_structure() {
        let path = "/etc/motd";
        let digest = crate::resources::sha256_hex(b"hello");
        // One space instead of the two-space record separator.
        let o = sha_out(&format!("{} {}\n", digest, path));
        assert!(parse_sha256_record(&o, path).is_err());
        // No separator at all.
        let o = sha_out(&format!("{}{}\n", digest, path));
        assert!(parse_sha256_record(&o, path).is_err());
        // Empty filename field.
        let o = sha_out(&format!("{}  \n", digest));
        assert!(parse_sha256_record(&o, path).is_err());
    }

    #[test]
    fn sha256_contract_rejects_unexpected_multiple_result_lines() {
        let path = "/etc/motd";
        let digest = crate::resources::sha256_hex(b"hello");
        let o = sha_out(&format!("{}  {}\n{}  {}\n", digest, path, digest, path));
        assert!(parse_sha256_record(&o, path).is_err());
        // A trailing diagnostic line is also a second record.
        let o = sha_out(&format!("{}  {}\nwarning: binary mode\n", digest, path));
        assert!(parse_sha256_record(&o, path).is_err());
    }

    #[test]
    fn sha256_contract_rejects_a_record_without_the_defined_terminator() {
        // `sha256sum` always terminates its record; an unterminated capture is
        // not the defined record, even when the digest itself looks complete
        // (RA2-01).
        let path = "/etc/motd";
        let digest = crate::resources::sha256_hex(b"hello");
        let o = sha_out(&format!("{}  {}", digest, path));
        assert!(parse_sha256_record(&o, path).is_err());
        // A trailing blank record is equally disqualifying.
        let o = sha_out(&format!("{}  {}\n\n", digest, path));
        assert!(parse_sha256_record(&o, path).is_err());
    }

    #[test]
    fn sha256_contract_rejects_a_record_about_a_different_path() {
        let path = "/etc/motd";
        let digest = crate::resources::sha256_hex(b"hello");
        let o = sha_out(&format!("{}  /etc/other\n", digest));
        assert!(parse_sha256_record(&o, path).is_err());
    }

    #[test]
    fn sha256_contract_rejects_invalid_utf8() {
        let path = "/etc/motd";
        let digest = crate::resources::sha256_hex(b"hello");
        let mut bytes = format!("{}  {}\n", digest, path).into_bytes();
        bytes.extend_from_slice(&[0xff, 0xfe]);
        let o = out_exit(0, &bytes, b"");
        assert!(parse_sha256_record(&o, path).is_err());
    }

    #[test]
    fn sha256_contract_accepts_the_coreutils_escaped_name_form() {
        // A path containing a backslash is printed escaped; the record stays
        // unambiguous and is still recognized.
        let path = "/tmp/we\\ird";
        let digest = crate::resources::sha256_hex(b"hello");
        let o = sha_out(&format!("{}  {}\n", digest, coreutils_escaped_name(path)));
        assert_eq!(parse_sha256_record(&o, path).unwrap(), digest);
        assert_eq!(coreutils_escaped_name("/tmp/plain"), "/tmp/plain");
        assert_eq!(coreutils_escaped_name("/tmp/a\nb"), "\\/tmp/a\\nb");
    }

    // --- readlink contract -----------------------------------------

    #[test]
    fn readlink_contract_accepts_a_complete_single_target() {
        let o = out_exit(0, b"/desired/target", b"");
        assert_eq!(readlink_record(&o, "/link").unwrap(), "/desired/target");
    }

    #[test]
    fn readlink_contract_rejects_a_forbidden_trailing_newline() {
        // `readlink -n` emits no terminator, so a trailing newline is output
        // the contract does not define. It must never be normalized away into
        // a target string that could be compared toward PASS (RA2-01).
        let o = out_exit(0, b"/desired/target\n", b"");
        assert!(readlink_record(&o, "/link").is_err());
        let o = out_exit(0, b"/desired/target\r\n", b"");
        assert!(readlink_record(&o, "/link").is_err());
        let o = out_exit(0, b"/desired/target\n\n", b"");
        assert!(readlink_record(&o, "/link").is_err());
        // A trailing byte that is not a line terminator becomes part of the
        // candidate target string, so it can only ever produce a mismatch:
        // the exact comparison can never turn it into a PASS.
        let o = out_exit(0, b"/desired/target ", b"");
        assert_eq!(readlink_record(&o, "/link").unwrap(), "/desired/target ");
        assert_ne!(readlink_record(&o, "/link").unwrap(), "/desired/target");
    }

    #[test]
    fn readlink_contract_rejects_a_target_with_extra_output() {
        // A second line means the capture is not the single target record.
        let o = out_exit(0, b"/etc/alternatives/mta\nextra\n", b"");
        assert!(readlink_record(&o, "/link").is_err());
        let o = out_exit(0, b"", b"");
        assert!(readlink_record(&o, "/link").is_err());
    }

    #[test]
    fn readlink_contract_rejects_a_diagnostic_alongside_the_target() {
        let o = out_exit(0, b"/target\n", b"readlink: warning: something\n");
        assert!(readlink_record(&o, "/link").is_err());
    }

    #[test]
    fn readlink_contract_rejects_truncation_even_when_the_target_matches() {
        // Captured stdout is exactly the expected target, but the capture was
        // truncated: the real target string may continue past the limit, so
        // the prefix must never be compared toward PASS.
        let mut o = out_exit(0, b"/desired/target", b"");
        o.stdout_truncated = true;
        assert!(readlink_record(&o, "/link").is_err());
        let mut o = out_exit(0, b"/desired/target\n", b"");
        o.stderr_truncated = true;
        assert!(readlink_record(&o, "/link").is_err());
    }

    #[test]
    fn readlink_contract_rejects_invalid_utf8() {
        let o = out_exit(0, &[0x2f, 0xff, 0xfe], b"");
        assert!(readlink_record(&o, "/link").is_err());
    }

    // -----------------------------------------------------------------
    // Account-lookup memo (performance WP-P1).
    // -----------------------------------------------------------------

    fn memo_fs(target: crate::executor::FakeTarget) -> TargetFs {
        TargetFs::new_for(
            Executor::Fake(Box::new(crate::executor::FakeExecutor::new(target, false))),
            false,
            1000,
            1000,
            "/home/fake".to_string(),
            Some(crate::platform::PackageBackend::Apt),
            true,
            false,
            true,
            None,
        )
    }

    fn memo_target() -> crate::executor::FakeTarget {
        crate::executor::FakeTarget::ubuntu2404()
            .with_fake_fs()
            .with_fs_dir("/d")
            .with_group("app", 990)
            .with_user("app", 990, 990, "/h", "/bin/sh")
    }

    /// `(database, key)` of every `getent` the target received, in order.
    fn getent_calls(fs: &TargetFs) -> Vec<(String, String)> {
        fs.log()
            .iter()
            .filter(|c| c.program.ends_with("getent"))
            .map(|c| (c.args[0].clone(), c.args[1].clone()))
            .collect()
    }

    #[test]
    fn memo_answers_a_repeated_lookup_without_a_second_command() {
        let mut fs = memo_fs(memo_target());
        for _ in 0..5 {
            assert_eq!(fs.resolve_uid("app").unwrap(), 990);
            assert_eq!(fs.resolve_gid("app").unwrap(), 990);
            assert_eq!(fs.primary_gid_of_uid(990).unwrap(), 990);
        }
        assert_eq!(
            getent_calls(&fs),
            [
                ("passwd".to_string(), "app".to_string()),
                ("group".to_string(), "app".to_string()),
                ("passwd".to_string(), "990".to_string()),
            ]
        );
        assert_eq!(fs.exec_stats().snapshot().count_program("getent"), 3);
    }

    #[test]
    fn memo_keeps_user_and_group_namespaces_apart() {
        // The same name in both databases with different numbers: a hit on the
        // wrong namespace would return the other number.
        let t = crate::executor::FakeTarget::ubuntu2404()
            .with_group("shared", 2002)
            .with_group("shared-primary", 1001)
            .with_user("shared", 1001, 1001, "/h", "/bin/sh");
        let mut fs = memo_fs(t);
        for _ in 0..3 {
            assert_eq!(fs.resolve_uid("shared").unwrap(), 1001);
            assert_eq!(fs.resolve_gid("shared").unwrap(), 2002);
        }
        assert_eq!(
            getent_calls(&fs),
            [
                ("passwd".to_string(), "shared".to_string()),
                ("group".to_string(), "shared".to_string()),
            ]
        );
    }

    #[test]
    fn memo_distinguishes_a_uid_from_the_primary_gid_of_that_uid() {
        // `shared`'s uid is 1001 and its primary gid is 3003: "the uid of
        // `shared`" and "the primary gid of uid 1001" are different facts.
        let t = crate::executor::FakeTarget::ubuntu2404()
            .with_group("g3003", 3003)
            .with_user("shared", 1001, 3003, "/h", "/bin/sh");
        let mut fs = memo_fs(t);
        for _ in 0..2 {
            assert_eq!(fs.resolve_uid("shared").unwrap(), 1001);
            assert_eq!(fs.primary_gid_of_uid(1001).unwrap(), 3003);
        }
        assert_eq!(getent_calls(&fs).len(), 2);
    }

    #[test]
    fn memo_looks_up_each_distinct_identity_once() {
        let t = memo_target()
            .with_group("other", 991)
            .with_user("other", 991, 991, "/h", "/bin/sh");
        let mut fs = memo_fs(t);
        for _ in 0..3 {
            assert_eq!(fs.resolve_uid("app").unwrap(), 990);
            assert_eq!(fs.resolve_uid("other").unwrap(), 991);
            assert_eq!(fs.resolve_gid("app").unwrap(), 990);
            assert_eq!(fs.resolve_gid("other").unwrap(), 991);
        }
        assert_eq!(getent_calls(&fs).len(), 4);
    }

    #[test]
    fn memo_does_not_cache_a_missing_account() {
        let mut fs = memo_fs(memo_target());
        assert!(fs.resolve_uid("ghost").is_err());
        assert!(fs.resolve_uid("ghost").is_err());
        assert!(fs.resolve_gid("ghost").is_err());
        assert!(fs.resolve_gid("ghost").is_err());
        assert_eq!(getent_calls(&fs).len(), 4, "every miss asks the target");
        assert!(fs.identity_memo.entries.is_empty());
    }

    #[test]
    fn memo_does_not_cache_failed_or_malformed_lookups() {
        let ok = out_exit(0, b"app:x:990:990::/h:/bin/sh\n", b"");
        let queued = vec![
            // execution failure
            out_exit(2, b"", b""),
            // transport/timeout: completion cannot be established
            Output {
                completion: Completion::Indeterminate {
                    started: true,
                    reason: "timed out".to_string(),
                },
                stdout: Vec::new(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            },
            // malformed: too few fields, not a number, two records, diagnostic
            out_exit(0, b"app:x:990\n", b""),
            out_exit(0, b"app:x:abc:990::/h:/bin/sh\n", b""),
            out_exit(
                0,
                b"app:x:990:990::/h:/bin/sh\napp:x:990:990::/h:/bin/sh\n",
                b"",
            ),
            out_exit(0, b"app:x:990:990::/h:/bin/sh\n", b"warning\n"),
            // truncated record
            Output {
                stdout_truncated: true,
                ..ok.clone()
            },
        ];
        let n = queued.len();
        let mut fs = memo_fs(memo_target().with_observations("getent", queued));
        for i in 0..n {
            assert!(fs.resolve_uid("app").is_err(), "failure {} must surface", i);
            assert!(
                fs.identity_memo.entries.is_empty(),
                "failure {} must not be stored",
                i
            );
        }
        // The queue is exhausted: the next lookup is live, succeeds, is stored.
        assert_eq!(fs.resolve_uid("app").unwrap(), 990);
        assert_eq!(fs.resolve_uid("app").unwrap(), 990);
        assert_eq!(getent_calls(&fs).len(), n + 1);
    }

    #[test]
    fn memo_never_stores_or_reads_a_sensitive_lookup() {
        let mut fs = memo_fs(memo_target());
        assert_eq!(fs.resolve_uid_sensitive("app", true).unwrap(), 990);
        assert_eq!(fs.resolve_uid_sensitive("app", true).unwrap(), 990);
        assert_eq!(fs.resolve_gid_sensitive("app", true).unwrap(), 990);
        assert!(fs.identity_memo.entries.is_empty());
        // A sensitive request is not answered from a non-sensitive entry.
        assert_eq!(fs.resolve_uid("app").unwrap(), 990);
        assert_eq!(fs.resolve_uid_sensitive("app", true).unwrap(), 990);
        // Four sensitive lookups, each a real (redacted) command; one ordinary.
        let stats = fs.exec_stats().snapshot();
        assert_eq!(stats.count_program("[redacted]"), 4);
        assert_eq!(getent_calls(&fs).len(), 1);
        assert_eq!(fs.identity_memo.entries.len(), 1);
    }

    #[test]
    fn memo_stores_only_a_number_never_the_record() {
        let mut fs = memo_fs(memo_target());
        fs.resolve_uid("app").unwrap();
        let dump = format!("{:?}", fs.identity_memo);
        assert!(!dump.contains("/bin/sh"), "{}", dump);
        assert!(!dump.contains("/h"), "{}", dump);
        assert_eq!(fs.identity_memo.entries.len(), 1);
    }

    #[test]
    fn memos_of_two_targets_never_share_an_answer() {
        let a = crate::executor::FakeTarget::ubuntu2404()
            .with_group("app", 1000)
            .with_user("app", 1000, 1000, "/h", "/bin/sh");
        let b = crate::executor::FakeTarget::ubuntu2404()
            .with_group("app", 2000)
            .with_user("app", 2000, 2000, "/h", "/bin/sh");
        let (mut fa, mut fb) = (memo_fs(a), memo_fs(b));
        assert_eq!(fa.resolve_uid("app").unwrap(), 1000);
        assert_eq!(fb.resolve_uid("app").unwrap(), 2000);
        assert_eq!(fa.resolve_uid("app").unwrap(), 1000);
        assert_eq!(fb.resolve_gid("app").unwrap(), 2000);
        assert_eq!(fa.resolve_gid("app").unwrap(), 1000);
        // Each paid for its own first lookups.
        assert_eq!(getent_calls(&fa).len(), 2);
        assert_eq!(getent_calls(&fb).len(), 2);
    }

    #[test]
    fn every_mutating_operation_empties_the_memo() {
        type Op = Box<dyn Fn(&mut TargetFs, &MutationPermit)>;
        let permit_ops: Vec<(&str, Op)> = vec![
            (
                "exec",
                Box::new(|f, p| {
                    let mut r = ExecRequest::new("/bin/true");
                    r.env = base_env();
                    let _ = f.exec(p, &r);
                }),
            ),
            (
                "chmod",
                Box::new(|f, p| {
                    let _ = f.chmod(p, "/d/x", 0o600);
                }),
            ),
            (
                "chown",
                Box::new(|f, p| {
                    let _ = f.chown(p, "/d/x", 0, 0);
                }),
            ),
            (
                "mkdir",
                Box::new(|f, p| {
                    let _ = f.mkdir(p, "/d/new");
                }),
            ),
            (
                "mkdir_p",
                Box::new(|f, p| {
                    let _ = f.mkdir_p(p, "/d/a/b");
                }),
            ),
            (
                "rmdir",
                Box::new(|f, p| {
                    let _ = f.rmdir(p, "/d/new");
                }),
            ),
            (
                "remove_file",
                Box::new(|f, p| {
                    let _ = f.remove_file(p, "/d/x");
                }),
            ),
            (
                "remove_symlink",
                Box::new(|f, p| {
                    let _ = f.remove_symlink(p, "/d/l");
                }),
            ),
            (
                "symlink",
                Box::new(|f, p| {
                    let _ = f.symlink(p, "/t", "/d/l");
                }),
            ),
            (
                "rename",
                Box::new(|f, p| {
                    let _ = f.rename(p, "/d/x", "/d/y");
                }),
            ),
            (
                "write_bytes",
                Box::new(|f, p| {
                    let _ = f.write_bytes(p, "/d/x", b"x");
                }),
            ),
            (
                "set_xattr",
                Box::new(|f, p| {
                    let _ = f.set_xattr(p, "user.a", "b", "/d/x");
                }),
            ),
            (
                "copy_user_xattrs",
                Box::new(|f, p| {
                    let _ = f.copy_user_xattrs(p, "/d/x", "/d/y");
                }),
            ),
            (
                "backup_copy",
                Box::new(|f, p| {
                    let _ = f.backup_copy(p, "/d/x", "/d/b");
                }),
            ),
            (
                // Delegates to `make_staging_dir`, which clears as well, so
                // this entry proves the outcome, not the direct call alone.
                "symlink_replace",
                Box::new(|f, p| {
                    let observed = f.inspect("/d/l").unwrap();
                    let _ = f.symlink_replace(p, "/t", "/d/l", &observed);
                }),
            ),
        ];
        for (name, op) in permit_ops {
            let mut fs = memo_fs(memo_target());
            let permit = fs.mutation_permit().unwrap();
            fs.resolve_uid("app").unwrap();
            assert_eq!(fs.identity_memo.entries.len(), 1, "{name}: primed");
            op(&mut fs, &permit);
            assert!(fs.identity_memo.entries.is_empty(), "{name} must clear");
        }
        // The two helpers that obtain their own permit.
        let mut fs = memo_fs(memo_target());
        fs.resolve_uid("app").unwrap();
        let _ = fs.make_staging_dir("/d");
        assert!(fs.identity_memo.entries.is_empty(), "make_staging_dir");
        let mut fs = memo_fs(memo_target());
        fs.resolve_uid("app").unwrap();
        let _ = fs.set_metadata("/d/x", 0o600, 0, 0);
        assert!(fs.identity_memo.entries.is_empty(), "set_metadata");
    }

    #[test]
    fn observations_do_not_empty_the_memo() {
        let mut fs = memo_fs(memo_target());
        fs.resolve_uid("app").unwrap();
        let _ = fs.inspect("/d");
        let _ = fs.sha256("/d/none");
        assert_eq!(fs.identity_memo.entries.len(), 1);
    }

    #[test]
    fn a_mutation_makes_the_next_lookup_live_and_current() {
        let mut fs = memo_fs(memo_target());
        let permit = fs.mutation_permit().unwrap();
        assert_eq!(fs.primary_gid_of_uid(990).unwrap(), 990);
        let mut r = ExecRequest::new("/usr/sbin/groupadd");
        r.args = vec!["-g".to_string(), "995".to_string(), "newg".to_string()];
        fs.exec(&permit, &r).unwrap();
        let mut r = ExecRequest::new("/usr/sbin/usermod");
        r.args = vec!["-g".to_string(), "newg".to_string(), "app".to_string()];
        fs.exec(&permit, &r).unwrap();
        assert_eq!(fs.primary_gid_of_uid(990).unwrap(), 995, "no stale answer");
        assert_eq!(getent_calls(&fs).len(), 2);
    }

    // -----------------------------------------------------------------
    // WP-P1 remediation: the primary-gid lookup carries the sensitivity of
    // the resource it is made for.
    // -----------------------------------------------------------------

    /// A target whose `getent` answers are scripted, in order, one per call.
    fn scripted_getent(lines: &[&str]) -> TargetFs {
        let queued = lines
            .iter()
            .map(|l| out_exit(0, format!("{}\n", l).as_bytes(), b""))
            .collect();
        memo_fs(memo_target().with_observations("getent", queued))
    }

    const APP_PRIMARY_111: &str = "app:x:990:111::/h:/bin/sh";
    const APP_PRIMARY_222: &str = "app:x:990:222::/h:/bin/sh";

    #[test]
    fn a_sensitive_primary_gid_lookup_never_reads_the_memo() {
        // Ordinary lookup first (gid 111, memoized); the target then answers
        // 222. A sensitive lookup must ask again and see 222, not 111.
        let mut fs = scripted_getent(&[APP_PRIMARY_111, APP_PRIMARY_222]);
        assert_eq!(fs.primary_gid_of_uid(990).unwrap(), 111);
        assert_eq!(fs.identity_memo.entries.len(), 1);
        assert_eq!(fs.primary_gid_of_uid_sensitive(990, true).unwrap(), 222);
        // ... and the ordinary entry is untouched by it.
        assert_eq!(fs.primary_gid_of_uid(990).unwrap(), 111);
        let stats = fs.exec_stats().snapshot();
        assert_eq!(stats.count_program("getent"), 1);
        assert_eq!(stats.count_program("[redacted]"), 1);
    }

    #[test]
    fn a_sensitive_primary_gid_lookup_never_writes_the_memo() {
        // Sensitive lookup first (gid 111); the target then answers 222. The
        // ordinary lookup afterwards must ask itself, not reuse 111.
        let mut fs = scripted_getent(&[APP_PRIMARY_111, APP_PRIMARY_222]);
        assert_eq!(fs.primary_gid_of_uid_sensitive(990, true).unwrap(), 111);
        assert!(fs.identity_memo.entries.is_empty());
        assert_eq!(fs.primary_gid_of_uid(990).unwrap(), 222);
        assert_eq!(fs.identity_memo.entries.len(), 1);
        let stats = fs.exec_stats().snapshot();
        assert_eq!(stats.count_program("getent"), 1);
        assert_eq!(stats.count_program("[redacted]"), 1);
    }

    #[test]
    fn a_sensitive_primary_gid_lookup_is_redacted_in_the_log() {
        let mut fs = memo_fs(memo_target());
        assert_eq!(fs.primary_gid_of_uid_sensitive(990, true).unwrap(), 990);
        let log = fs.log();
        let rec = log.last().unwrap();
        assert!(rec.sensitive);
        assert!(!format!("{:?}", rec).contains("990"), "{:?}", rec);
        // The failure message names no uid either.
        let mut fs = memo_fs(memo_target());
        let e = fs.primary_gid_of_uid_sensitive(4321, true).unwrap_err();
        assert!(!e.message.contains("4321"), "{}", e.message);
    }

    // -----------------------------------------------------------------
    // Path C: the batched trusted-parent walk (performance WP-P2).
    // -----------------------------------------------------------------

    use crate::executor::{FakeExecutor, FakeTarget};

    const PC_TS: &str = "2026-09-19 09:30:00.000000000 +0000";

    /// A named scripted-platform preset.
    type PcPlatform = (&'static str, fn() -> FakeTarget);

    fn pc_out(code: i32, stdout: &[u8], stderr: &str) -> Output {
        Output {
            completion: Completion::Exited(code),
            stdout: stdout.to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    /// One batched `stat` record: nine fields, the operand name, NUL.
    fn pc_rec(kind: &str, mode: &str, uid: &str, name: &str) -> String {
        format!("{kind}|{mode}|{uid}|0|4096|2049|100|{PC_TS}|{PC_TS}|{name}\0")
    }

    fn pc_good_stat(dirs: &[String]) -> String {
        dirs.iter()
            .map(|d| pc_rec("directory", "755", "0", d))
            .collect()
    }

    /// `/`, `/d1`, `/d1/d2`, ... : `n` ancestors.
    fn pc_dirs(n: usize) -> Vec<String> {
        let mut v = vec!["/".to_string()];
        let mut cur = String::new();
        for i in 1..n {
            cur.push_str(&format!("/d{}", i));
            v.push(cur.clone());
        }
        v
    }

    fn pc_path(n: usize) -> String {
        let last = pc_dirs(n).pop().unwrap();
        if last == "/" {
            "/f".to_string()
        } else {
            format!("{}/f", last)
        }
    }

    fn pc_target(n: usize) -> FakeTarget {
        let mut t = FakeTarget::ubuntu2404().with_fake_fs();
        for d in pc_dirs(n).iter().skip(1) {
            t = t.with_fs_dir(d);
        }
        t
    }

    fn pc_fs_with(t: FakeTarget, getfacl: bool, getfattr: bool, sudo: bool) -> TargetFs {
        TargetFs::new_for(
            Executor::Fake(Box::new(FakeExecutor::new(t, sudo))),
            sudo,
            1000,
            1000,
            "/home/fake".to_string(),
            Some(crate::platform::PackageBackend::Apt),
            getfattr,
            getfacl,
            false,
            None,
        )
    }

    fn pc_fs(t: FakeTarget) -> TargetFs {
        pc_fs_with(t, false, true, false)
    }

    /// One token per command the target received: `stat-batch:<operands>`,
    /// `stat`, `getfattr:<operands>`, `getfacl`.
    fn pc_trace(fs: &TargetFs) -> Vec<String> {
        fs.log()
            .iter()
            .map(|c| {
                let p = c.program.rsplit('/').next().unwrap();
                match p {
                    "stat" if c.args.first().is_some_and(|a| a.starts_with("--printf=")) => {
                        format!("stat-batch:{}", c.args.len() - 2)
                    }
                    "getfattr" => format!("getfattr:{}", c.args.len() - 7),
                    other => other.to_string(),
                }
            })
            .collect()
    }

    fn pc_stat_override(t: FakeTarget, out: Output) -> FakeTarget {
        t.with_observations("stat", vec![out])
    }

    fn pc_getfattr_override(t: FakeTarget, out: Output) -> FakeTarget {
        t.with_observations("getfattr", vec![out])
    }

    #[test]
    fn path_c_issues_exactly_two_commands_for_any_depth() {
        for n in [1usize, 2, 3, 6] {
            let mut fs = pc_fs(pc_target(n));
            fs.check_trusted_parents(&pc_path(n)).unwrap();
            assert_eq!(
                pc_trace(&fs),
                [format!("stat-batch:{n}"), format!("getfattr:{n}")],
                "n = {n}"
            );
            // The operands are the unchanged ancestor list, in order.
            let log = fs.log();
            assert_eq!(log[0].args[2..], pc_dirs(n)[..], "stat operands, n = {n}");
            assert_eq!(
                log[1].args[7..],
                pc_dirs(n)[..],
                "getfattr operands, n = {n}"
            );
            assert_eq!(pc_dirs(n), ancestor_dirs(&pc_path(n)));
        }
    }

    #[test]
    fn path_c_batch_commands_are_direct_argv() {
        let mut fs = pc_fs(pc_target(3));
        fs.check_trusted_parents(&pc_path(3)).unwrap();
        for rec in fs.log() {
            assert!(rec.program == "/usr/bin/stat" || rec.program == "/usr/bin/getfattr");
            assert!(!rec.sudo);
            assert!(!rec.sensitive);
        }
        let log = fs.log();
        assert_eq!(
            log[0].args[..2],
            [
                "--printf=%F|%a|%u|%g|%s|%d|%i|%y|%z|%n\\0".to_string(),
                "--".to_string()
            ]
        );
        assert_eq!(
            log[1].args[..7],
            ["-d", "-m", "-", "-e", "base64", "--absolute-names", "--"].map(String::from)
        );
    }

    #[test]
    fn path_c_branch_follows_the_getfacl_capability_and_nothing_else() {
        // The same capability decides the branch on every platform: the
        // operating system is never consulted.
        let platforms: [PcPlatform; 4] = [
            ("ubuntu2404", FakeTarget::ubuntu2404),
            ("ubuntu2604", FakeTarget::ubuntu2604),
            ("rocky9", FakeTarget::rocky9),
            ("rocky10", FakeTarget::rocky10),
        ];
        for (name, make) in platforms {
            let target = || {
                make()
                    .with_fake_fs()
                    .with_fs_dir("/d1")
                    .with_fs_dir("/d1/d2")
            };
            let mut absent = pc_fs_with(target(), false, true, false);
            absent.check_trusted_parents("/d1/d2/f").unwrap();
            assert_eq!(pc_trace(&absent), ["stat-batch:3", "getfattr:3"], "{name}");

            let mut present = pc_fs_with(target(), true, true, false);
            present.check_trusted_parents("/d1/d2/f").unwrap();
            assert_eq!(
                pc_trace(&present),
                [
                    "stat",
                    "getfattr:1",
                    "getfacl",
                    "stat",
                    "getfattr:1",
                    "getfacl",
                    "stat",
                    "getfattr:1",
                    "getfacl"
                ],
                "{name}: getfacl present keeps the sequential walk"
            );
        }
    }

    #[test]
    fn path_c_getfacl_present_walk_is_the_unchanged_sequential_walk() {
        // Per ancestor, in order: stat, getfattr, getfacl - one operand each.
        let mut fs = pc_fs_with(pc_target(3), true, true, false);
        fs.check_trusted_parents(&pc_path(3)).unwrap();
        let log = fs.log();
        assert_eq!(log.len(), 9);
        for (i, dir) in pc_dirs(3).iter().enumerate() {
            let (s, g, l) = (&log[3 * i], &log[3 * i + 1], &log[3 * i + 2]);
            assert_eq!(s.args, ["-c", "%F|%a|%u|%g|%s|%d|%i|%y|%z", "--", dir]);
            assert_eq!(g.args.last().unwrap(), dir);
            assert_eq!(l.args, ["-p", "-c", "--", dir]);
        }
    }

    #[test]
    fn path_c_missing_getfattr_keeps_the_existing_actionable_refusal() {
        let mut fs = pc_fs_with(pc_target(2), false, false, false);
        let e = fs.check_trusted_parents(&pc_path(2)).unwrap_err();
        assert!(e.message.contains("attr"), "{}", e.message);
        assert_eq!(
            pc_trace(&fs),
            ["stat"],
            "sequential walk, stopped at the first ancestor"
        );
    }

    #[test]
    fn path_c_uninspectable_parent_fault_uses_the_sequential_walk() {
        let mut fs = TargetFs::new_for(
            Executor::Fake(Box::new(FakeExecutor::new(pc_target(2), false))),
            false,
            1000,
            1000,
            "/home/fake".to_string(),
            None,
            true,
            false,
            false,
            Some("uninspectable_parent".to_string()),
        );
        let e = fs.check_trusted_parents(&pc_path(2)).unwrap_err();
        assert!(
            e.message.contains("cannot inspect access metadata"),
            "{}",
            e.message
        );
        assert_eq!(pc_trace(&fs), ["stat"]);
    }

    #[test]
    fn path_c_unsafe_stat_record_never_reaches_getfattr() {
        // An unsafe ancestor at every position, in every way CURRENT refuses.
        let n = 4;
        let dirs = pc_dirs(n);
        let unsafe_records: [(&str, &str, &str, &str); 6] = [
            ("symlink", "symbolic link", "777", "0"),
            ("wrong owner", "directory", "755", "4242"),
            ("group/other writable", "directory", "775", "0"),
            ("other writable", "directory", "757", "0"),
            ("regular file", "regular file", "644", "0"),
            ("fifo", "fifo", "644", "0"),
        ];
        for k in [0usize, 1, n - 2, n - 1] {
            for (what, kind, mode, uid) in unsafe_records {
                let stdout: String = dirs
                    .iter()
                    .enumerate()
                    .map(|(i, d)| {
                        if i == k {
                            pc_rec(kind, mode, uid, d)
                        } else {
                            pc_rec("directory", "755", "0", d)
                        }
                    })
                    .collect();
                let t = pc_stat_override(pc_target(n), pc_out(0, stdout.as_bytes(), ""));
                let mut fs = pc_fs(t);
                let e = fs
                    .check_trusted_parents(&pc_path(n))
                    .expect_err(&format!("{what} at {k} must refuse"));
                assert!(e.message.contains(&dirs[k]), "{what} at {k}: {}", e.message);
                assert_eq!(
                    pc_trace(&fs),
                    [format!("stat-batch:{n}")],
                    "{what} at {k}: getfattr must not run after a failed stat gate"
                );
            }
        }
    }

    #[test]
    fn path_c_first_failing_ancestor_decides_the_reason_in_ancestor_order() {
        let dirs = pc_dirs(3);
        let stdout = format!(
            "{}{}{}",
            pc_rec("directory", "755", "0", &dirs[0]),
            pc_rec("directory", "775", "0", &dirs[1]),
            pc_rec("symbolic link", "777", "0", &dirs[2]),
        );
        let t = pc_stat_override(pc_target(3), pc_out(0, stdout.as_bytes(), ""));
        let mut fs = pc_fs(t);
        let e = fs.check_trusted_parents(&pc_path(3)).unwrap_err();
        assert!(e.message.contains("group or other write"), "{}", e.message);
        assert!(e.message.contains(&dirs[1]), "{}", e.message);
    }

    fn pc_stat_failure_cases(n: usize) -> Vec<(&'static str, Output)> {
        let dirs = pc_dirs(n);
        let good = pc_good_stat(&dirs);
        let mut trunc = pc_out(0, good.as_bytes(), "");
        trunc.stdout_truncated = true;
        let mut err_trunc = pc_out(0, good.as_bytes(), "");
        err_trunc.stderr_truncated = true;
        let without_last: String = dirs[..n - 1]
            .iter()
            .map(|d| pc_rec("directory", "755", "0", d))
            .collect();
        let extra = format!("{}{}", good, pc_rec("directory", "755", "0", "/zz"));
        let duplicate = format!("{}{}", good, pc_rec("directory", "755", "0", &dirs[n - 1]));
        let mut swapped: Vec<String> = dirs.clone();
        swapped.swap(0, n - 1);
        let swapped_stdout: String = swapped
            .iter()
            .map(|d| pc_rec("directory", "755", "0", d))
            .collect();
        let mut v = vec![
            (
                "non-zero with a complete body",
                pc_out(1, good.as_bytes(), ""),
            ),
            (
                "non-zero with a partial body",
                pc_out(
                    1,
                    without_last.as_bytes(),
                    "stat: cannot statx 'x': No such file or directory\n",
                ),
            ),
            (
                "non-zero and empty",
                pc_out(
                    1,
                    b"",
                    "stat: cannot statx 'x': No such file or directory\n",
                ),
            ),
            (
                "exit 0 with stderr",
                pc_out(0, good.as_bytes(), "stat: warning\n"),
            ),
            ("stdout truncated", trunc),
            ("stderr truncated", err_trunc),
            ("record missing", pc_out(0, without_last.as_bytes(), "")),
            ("record extra", pc_out(0, extra.as_bytes(), "")),
            ("record duplicated", pc_out(0, duplicate.as_bytes(), "")),
            (
                "records out of order",
                pc_out(0, swapped_stdout.as_bytes(), ""),
            ),
            ("empty output", pc_out(0, b"", "")),
            (
                "not NUL terminated",
                pc_out(0, good.trim_end_matches('\0').as_bytes(), ""),
            ),
            (
                "cut in the middle of a record",
                pc_out(0, &good.as_bytes()[..good.len() - 30], ""),
            ),
            (
                "newline instead of NUL",
                pc_out(0, good.replace('\0', "\n").as_bytes(), ""),
            ),
            ("invalid UTF-8", pc_out(0, b"\xff\xfe\0", "")),
        ];
        v.push((
            "signal",
            Output {
                completion: Completion::Signaled(9),
                ..pc_out(0, good.as_bytes(), "")
            },
        ));
        v.push((
            "indeterminate",
            Output {
                completion: Completion::Indeterminate {
                    started: true,
                    reason: "timed out".to_string(),
                },
                ..pc_out(0, b"", "")
            },
        ));
        v
    }

    #[test]
    fn path_c_stat_batch_failures_refuse_before_getfattr_and_never_retry() {
        for n in [1usize, 2, 3, 6] {
            for (what, out) in pc_stat_failure_cases(n) {
                if n == 1 && matches!(what, "record missing" | "records out of order") {
                    continue; // one operand has no shorter non-empty or reordered form
                }
                let mut fs = pc_fs(pc_stat_override(pc_target(n), out));
                let r = fs.check_trusted_parents(&pc_path(n));
                assert!(r.is_err(), "n={n} {what}: must refuse");
                // Exactly the one dispatched batch: no getfattr, and no
                // sequential retry that the (healthy) fake would have accepted.
                assert_eq!(pc_trace(&fs), [format!("stat-batch:{n}")], "n={n} {what}");
            }
        }
    }

    #[test]
    fn path_c_indeterminate_stat_batch_is_an_indeterminate_error() {
        let out = Output {
            completion: Completion::Indeterminate {
                started: true,
                reason: "timed out".to_string(),
            },
            ..pc_out(0, b"", "")
        };
        let mut fs = pc_fs(pc_stat_override(pc_target(3), out));
        let e = fs.check_trusted_parents(&pc_path(3)).unwrap_err();
        assert_eq!(e.kind, crate::error::ErrorKind::Indeterminate);
    }

    #[test]
    fn path_c_stat_batch_message_does_not_expose_the_capture() {
        let canary = "CANARY-9d31";
        let body = format!("directory|755|0|0|4096|2049|100|{PC_TS}|{PC_TS}|/{canary}\0");
        let mut fs = pc_fs(pc_stat_override(
            pc_target(1),
            pc_out(0, body.as_bytes(), ""),
        ));
        let e = fs.check_trusted_parents("/f").unwrap_err();
        assert!(!e.message.contains(canary), "{}", e.message);
        let mut fs = pc_fs(pc_stat_override(
            pc_target(1),
            pc_out(1, canary.as_bytes(), canary),
        ));
        let e = fs.check_trusted_parents("/f").unwrap_err();
        assert!(!e.message.contains(canary), "{}", e.message);
    }

    const PC_ATTR: &str = "# file: /d1\nuser.note=0sYQ==\n\n";

    #[test]
    fn path_c_getfattr_batch_failures_refuse_without_retry() {
        let n = 3;
        let dirs = pc_dirs(n);
        let good = pc_good_stat(&dirs);
        let blocks = |header: &str| format!("# file: {header}\nuser.note=0sYQ==\n\n");
        let mut trunc = pc_out(0, PC_ATTR.as_bytes(), "");
        trunc.stdout_truncated = true;
        let cases: Vec<(&str, Output)> = vec![
            (
                "non-zero",
                pc_out(1, b"", "getfattr: /d1: No such file or directory\n"),
            ),
            ("non-zero with a body", pc_out(1, PC_ATTR.as_bytes(), "")),
            ("exit 0 with stderr", pc_out(0, b"", "getfattr: warning\n")),
            ("truncated", trunc),
            (
                "unterminated block",
                pc_out(0, b"# file: /d1\nuser.note=0sYQ==\n", ""),
            ),
            (
                "missing final blank line",
                pc_out(
                    0,
                    b"# file: /d1\nuser.note=0sYQ==\n\n# file: /d1/d2\nuser.n=0sYQ==\n",
                    "",
                ),
            ),
            ("unknown object", pc_out(0, blocks("/other").as_bytes(), "")),
            (
                "repeated object",
                pc_out(
                    0,
                    format!("{}{}", blocks("/d1"), blocks("/d1")).as_bytes(),
                    "",
                ),
            ),
            (
                "out of operand order",
                pc_out(
                    0,
                    format!("{}{}", blocks("/d1/d2"), blocks("/d1")).as_bytes(),
                    "",
                ),
            ),
            ("stray blank line", pc_out(0, b"\n\n", "")),
            (
                "line outside any block",
                pc_out(0, b"user.note=0sYQ==\n\n", ""),
            ),
            (
                "malformed attribute line",
                pc_out(0, b"# file: /d1\nnoequals\n\n", ""),
            ),
            (
                "malformed value",
                pc_out(0, b"# file: /d1\nuser.note=zz!\n\n", ""),
            ),
            (
                "invalid UTF-8",
                pc_out(0, b"# file: /d1\nuser.note=\xff\n\n", ""),
            ),
            (
                "signal",
                Output {
                    completion: Completion::Signaled(15),
                    ..pc_out(0, b"", "")
                },
            ),
        ];
        for (what, out) in cases {
            let t = pc_getfattr_override(
                pc_stat_override(pc_target(n), pc_out(0, good.as_bytes(), "")),
                out,
            );
            let mut fs = pc_fs(t);
            assert!(
                fs.check_trusted_parents(&pc_path(n)).is_err(),
                "{what}: must refuse"
            );
            assert_eq!(
                pc_trace(&fs),
                ["stat-batch:3", "getfattr:3"],
                "{what}: exactly the two dispatched batches, no retry"
            );
        }
    }

    #[test]
    fn path_c_access_affecting_attributes_refuse_and_benign_ones_pass() {
        let n = 3;
        let dirs = pc_dirs(n);
        let good = pc_good_stat(&dirs);
        let unsafe_names = [
            "trusted.overlay.opaque",
            "security.capability",
            "system.posix_acl_access",
            "system.posix_acl_default",
            "system.nfs4_acl",
        ];
        for name in unsafe_names {
            for (idx, dir) in dirs.iter().enumerate() {
                let body = format!("# file: {dir}\n{name}=0sAAAA\n\n");
                let t = pc_getfattr_override(
                    pc_stat_override(pc_target(n), pc_out(0, good.as_bytes(), "")),
                    pc_out(0, body.as_bytes(), ""),
                );
                let mut fs = pc_fs(t);
                let e = fs
                    .check_trusted_parents(&pc_path(n))
                    .expect_err(&format!("{name} on {idx} must refuse"));
                assert!(
                    e.message.contains("extended access metadata"),
                    "{}",
                    e.message
                );
                assert!(
                    e.message.contains(dir.as_str()),
                    "attributed to {dir}: {}",
                    e.message
                );
                assert!(
                    !e.message.contains(name),
                    "no attribute name or value is echoed"
                );
                assert_eq!(pc_trace(&fs), ["stat-batch:3", "getfattr:3"]);
            }
        }
        for name in ["user.note", "security.selinux"] {
            let body = format!("# file: /d1\n{name}=0sYQ==\n\n");
            let t = pc_getfattr_override(
                pc_stat_override(pc_target(n), pc_out(0, good.as_bytes(), "")),
                pc_out(0, body.as_bytes(), ""),
            );
            let mut fs = pc_fs(t);
            fs.check_trusted_parents(&pc_path(n))
                .unwrap_or_else(|e| panic!("{name} must pass: {}", e.message));
        }
    }

    #[test]
    fn path_c_empty_clean_getfattr_means_no_attributes() {
        let dirs = pc_dirs(3);
        let xs = interpret_getfattr_batch(&pc_out(0, b"", ""), "/f", &dirs).unwrap();
        assert_eq!(xs.len(), 3);
        assert!(xs.iter().all(|x| x.inspected && x.attrs.is_empty()));
    }

    #[test]
    fn path_c_getfattr_batch_attributes_each_block_to_its_own_ancestor() {
        let dirs = pc_dirs(4);
        let body =
            "# file: /d1\nuser.a=0sQQ==\n\n# file: /d1/d2/d3\nuser.b=0sQg==\nuser.c=0sQw==\n\n";
        let xs = interpret_getfattr_batch(&pc_out(0, body.as_bytes(), ""), "/f", &dirs).unwrap();
        assert!(xs[0].attrs.is_empty());
        assert_eq!(xs[1].attrs.keys().collect::<Vec<_>>(), ["user.a"]);
        assert!(xs[2].attrs.is_empty());
        assert_eq!(xs[3].attrs.keys().collect::<Vec<_>>(), ["user.b", "user.c"]);
        assert!(xs.iter().all(|x| x.inspected));
    }

    #[test]
    fn path_c_batched_grammar_is_as_strict_as_the_sequential_grammar() {
        // Every nine-field variant is judged identically by the one-record
        // `stat -c` parser and by a batched record.
        let fields = |f: [&str; 9]| f.join("|");
        let ok = [
            "directory",
            "755",
            "0",
            "0",
            "4096",
            "2049",
            "100",
            PC_TS,
            PC_TS,
        ];
        let mut corpus: Vec<[&str; 9]> = vec![ok];
        let variants: [(usize, &str); 20] = [
            (1, "9"),
            (1, ""),
            (1, "+755"),
            (2, "-1"),
            (2, "abc"),
            (2, "4294967296"),
            (3, "4294967296"),
            (4, "18446744073709551616"),
            (4, "-5"),
            (5, "18446744073709551616"),
            (5, "x"),
            (6, "18446744073709551616"),
            (6, ""),
            (7, ""),
            (7, "2026-13-01 00:00:00.000000000 +0000"),
            (7, "2026-09-19 09:30:00 +00"),
            (8, ""),
            (8, "garbage"),
            (8, "2026-09-19 25:30:00.000000000 +0000"),
            (0, "regular file"),
        ];
        for (idx, v) in variants {
            let mut f = ok;
            f[idx] = v;
            corpus.push(f);
        }
        for f in corpus {
            let line = fields(f);
            let sequential = parse_stat_line(&format!("{line}\n"));
            let record = format!("{line}|/x\0");
            let batched = interpret_stat_batch(
                &pc_out(0, record.as_bytes(), ""),
                "/x/f",
                &["/x".to_string()],
            );
            assert_eq!(
                sequential.is_ok(),
                batched.is_ok(),
                "grammar divergence for {line:?}: sequential {sequential:?}, batched {batched:?}"
            );
            if let (Ok(a), Ok(b)) = (&sequential, &batched) {
                assert_eq!(
                    (a.kind, a.mode, a.uid, a.gid, a.size, a.dev, a.ino),
                    (b[0].kind, b[0].mode, b[0].uid, b[0].gid, b[0].size, b[0].dev, b[0].ino)
                );
            }
        }
    }

    #[test]
    fn path_c_numeric_and_timestamp_corruption_is_refused_at_every_position() {
        let n = 3;
        let dirs = pc_dirs(n);
        let corruptions = [
            (
                "size overflow",
                "directory|755|0|0|18446744073709551616|2049|100|TS|TS",
            ),
            (
                "inode overflow",
                "directory|755|0|0|4096|2049|18446744073709551616|TS|TS",
            ),
            ("device non-numeric", "directory|755|0|0|4096|x|100|TS|TS"),
            (
                "device overflow",
                "directory|755|0|0|4096|18446744073709551616|100|TS|TS",
            ),
            ("uid negative", "directory|755|-1|0|4096|2049|100|TS|TS"),
            ("malformed mtime", "directory|755|0|0|4096|2049|100|nope|TS"),
            ("empty ctime", "directory|755|0|0|4096|2049|100|TS|"),
            ("mode not octal", "directory|8|0|0|4096|2049|100|TS|TS"),
        ];
        for k in 0..n {
            for (what, rec) in corruptions {
                let rec = rec.replace("TS", PC_TS);
                let stdout: String = dirs
                    .iter()
                    .enumerate()
                    .map(|(i, d)| {
                        if i == k {
                            format!("{rec}|{d}\0")
                        } else {
                            pc_rec("directory", "755", "0", d)
                        }
                    })
                    .collect();
                let mut fs = pc_fs(pc_stat_override(
                    pc_target(n),
                    pc_out(0, stdout.as_bytes(), ""),
                ));
                assert!(
                    fs.check_trusted_parents(&pc_path(n)).is_err(),
                    "{what} at {k}"
                );
                assert_eq!(pc_trace(&fs), ["stat-batch:3"], "{what} at {k}");
            }
        }
    }

    #[test]
    fn path_c_unusual_file_names_are_attributed_exactly() {
        // Names that contain the field separator, a line feed, a backslash,
        // quotes, spaces, a tab and non-ASCII text.
        let dirs: Vec<String> = [
            "/",
            "/a b",
            "/a|b",
            "/a\\b",
            "/a\nb",
            "/it's \"q\" $x",
            "/t\tab",
            "/ünï",
            "/-dash",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let stat_body = pc_good_stat(&dirs);
        let st = interpret_stat_batch(&pc_out(0, stat_body.as_bytes(), ""), "/f", &dirs).unwrap();
        assert_eq!(st.len(), dirs.len());
        assert!(st.iter().all(|s| s.kind == ObjKind::Dir));
        // A record whose name is a different (even similar) operand is refused.
        let wrong = stat_body.replace("/a|b", "/a|c");
        assert!(interpret_stat_batch(&pc_out(0, wrong.as_bytes(), ""), "/f", &dirs).is_err());

        let mut body = String::new();
        for d in &dirs {
            body.push_str(&format!(
                "# file: {}\nuser.k=0sYQ==\n\n",
                getfattr_header_name(d)
            ));
        }
        let xs = interpret_getfattr_batch(&pc_out(0, body.as_bytes(), ""), "/f", &dirs).unwrap();
        assert!(xs.iter().all(|x| x.inspected && x.attrs.len() == 1));
        // getfattr writes a backslash as `\134` and a line feed as `\012`.
        assert_eq!(getfattr_header_name("/a\\b"), "/a\\134b");
        assert_eq!(getfattr_header_name("/a\nb"), "/a\\012b");
        // The unescaped form of a name with a line feed must not match.
        let raw = "# file: /a\nb\nuser.k=0sYQ==\n\n";
        assert!(interpret_getfattr_batch(
            &pc_out(0, raw.as_bytes(), ""),
            "/f",
            &["/".to_string(), "/a\nb".to_string()]
        )
        .is_err());
    }

    /// Length of the longer of the two batch commands for a walk whose single
    /// non-root ancestor has a `len`-character name.
    fn pc_command_len(fs: &TargetFs, name_len: usize) -> usize {
        let dirs = vec!["/".to_string(), format!("/{}", "a".repeat(name_len))];
        [
            fs.argv_request("/usr/bin/stat", &batched_stat_args(&dirs), false),
            fs.argv_request("/usr/bin/getfattr", &batched_getfattr_args(&dirs), false),
        ]
        .iter()
        .map(|r| crate::executor::build_remote_command(r, fs.sudo, &fs.home_env()).len())
        .max()
        .unwrap()
    }

    #[test]
    fn path_c_size_guard_is_exact_and_decided_before_dispatch() {
        for sudo in [false, true] {
            let fs = pc_fs_with(pc_target(1), false, true, sudo);
            // Largest name length whose commands still fit.
            // One plain character adds exactly one byte, so start from the
            // arithmetic estimate and let the loops settle on the boundary.
            let mut inside = BATCHED_WALK_MAX_COMMAND_BYTES - pc_command_len(&fs, 0);
            while pc_command_len(&fs, inside) > BATCHED_WALK_MAX_COMMAND_BYTES {
                inside -= 1;
            }
            while pc_command_len(&fs, inside + 1) <= BATCHED_WALK_MAX_COMMAND_BYTES {
                inside += 1;
            }
            let outside = inside + 1;
            assert!(pc_command_len(&fs, inside) <= BATCHED_WALK_MAX_COMMAND_BYTES);
            assert!(pc_command_len(&fs, outside) > BATCHED_WALK_MAX_COMMAND_BYTES);
            // Exactly one character apart: the guard sits on the boundary.
            assert_eq!(
                pc_command_len(&fs, outside) - pc_command_len(&fs, inside),
                1
            );
            for (len, expect_batch) in [(inside, true), (outside, false)] {
                let dirs = vec!["/".to_string(), format!("/{}", "a".repeat(len))];
                assert_eq!(
                    fs.batched_parent_walk_applies(&dirs),
                    expect_batch,
                    "sudo={sudo} len={len}"
                );
                // Run it: the first command the target ever sees tells which
                // walk was chosen - nothing precedes the decision.
                let mut t = FakeTarget::ubuntu2404().with_fake_fs();
                t = t.with_fs_dir(&dirs[1]);
                let mut run = pc_fs_with(t, false, true, sudo);
                run.check_trusted_parents(&format!("{}/f", dirs[1]))
                    .unwrap();
                let trace = pc_trace(&run);
                if expect_batch {
                    assert_eq!(trace, ["stat-batch:2", "getfattr:2"]);
                } else {
                    assert_eq!(trace, ["stat", "getfattr:1", "stat", "getfattr:1"]);
                }
            }
        }
    }

    #[test]
    fn path_c_guard_counts_the_sudo_wrapper_and_quoting() {
        let plain = pc_fs_with(pc_target(1), false, true, false);
        let sudo = pc_fs_with(pc_target(1), false, true, true);
        assert!(pc_command_len(&sudo, 100) > pc_command_len(&plain, 100));
        // A name made of quotes quadruples under POSIX quoting, so it falls
        // back far earlier than a plain name of the same length.
        let quotes = vec!["/".to_string(), format!("/{}", "'".repeat(5000))];
        let plain_names = vec!["/".to_string(), format!("/{}", "a".repeat(5000))];
        assert!(!plain.batched_parent_walk_applies(&quotes));
        assert!(plain.batched_parent_walk_applies(&plain_names));
    }

    #[test]
    fn path_c_control_characters_select_the_sequential_walk() {
        let fs = pc_fs_with(pc_target(1), false, true, false);
        let with = |name: &str| vec!["/".to_string(), format!("/{name}")];
        for bad in [
            "a\u{1}b",
            "a\rb",
            "a\u{7f}b",
            "a\u{85}b",
            "a\u{1b}[0m",
            "a\u{0c}b",
        ] {
            assert!(!fs.batched_parent_walk_applies(&with(bad)), "{bad:?}");
        }
        for ok in [
            "a b", "a\tb", "a\nb", "a'b", "a\"b", "a\\b", "a|b", "a$b", "ünï", "-dash",
        ] {
            assert!(fs.batched_parent_walk_applies(&with(ok)), "{ok:?}");
        }
    }

    #[test]
    fn path_c_matches_the_sequential_walk_on_every_trust_decision() {
        // Differential test over the whole decision space of one ancestor:
        // kind x owner x mode x privilege. The batched and the sequential
        // walks must agree on accept/refuse for every combination.
        use crate::fakesys::FakeKind;
        let kinds = ["dir", "symlink", "file"];
        let owners = [0u32, 1000, 4242];
        let modes = [0o755u32, 0o700, 0o775, 0o757, 0o777, 0o1777, 0o2755];
        let mut combos = 0;
        for sudo in [false, true] {
            for kind in kinds {
                for uid in owners {
                    for mode in modes {
                        let target = |_: ()| {
                            let mut t = pc_target(3);
                            let fs = t.fs.as_mut().unwrap();
                            let node = fs.nodes.get_mut("/d1").unwrap();
                            node.uid = uid;
                            node.mode = mode;
                            node.kind = match kind {
                                "dir" => FakeKind::Dir,
                                "symlink" => FakeKind::Symlink("/x".to_string()),
                                _ => FakeKind::File(b"x".to_vec()),
                            };
                            t
                        };
                        let mut batched = pc_fs_with(target(()), false, true, sudo);
                        let mut sequential = pc_fs_with(target(()), true, true, sudo);
                        let b = batched.check_trusted_parents(&pc_path(3));
                        let s = sequential.check_trusted_parents(&pc_path(3));
                        assert_eq!(
                            b.is_ok(),
                            s.is_ok(),
                            "sudo={sudo} kind={kind} uid={uid} mode={mode:o}: batched {b:?} vs sequential {s:?}"
                        );
                        if let (Err(b), Err(s)) = (&b, &s) {
                            assert_eq!(
                                b.message, s.message,
                                "same reason, sudo={sudo} {kind} {uid} {mode:o}"
                            );
                        }
                        combos += 1;
                    }
                }
            }
        }
        assert_eq!(combos, 2 * 3 * 3 * 7);
    }

    #[test]
    fn path_c_missing_ancestor_is_a_refusal_with_one_command() {
        // /d1/d2 does not exist on the target.
        let mut t = FakeTarget::ubuntu2404().with_fake_fs().with_fs_dir("/d1");
        t = t.with_fs_dir("/d1/d3");
        let mut fs = pc_fs(t);
        let e = fs.check_trusted_parents("/d1/d2/d3/f").unwrap_err();
        assert!(
            e.message.contains("parent directory may be missing"),
            "{}",
            e.message
        );
        assert_eq!(pc_trace(&fs), ["stat-batch:4"]);
    }

    #[test]
    fn path_c_does_not_require_one_device_across_the_ancestors() {
        // CURRENT never compared the devices of the ancestors with each other
        // (a mount below the root is legitimate); the batch must not start to.
        let dirs = pc_dirs(3);
        let body: String = dirs
            .iter()
            .enumerate()
            .map(|(i, d)| {
                format!(
                    "directory|755|0|0|4096|{}|100|{PC_TS}|{PC_TS}|{d}\0",
                    2049 + i * 1000
                )
            })
            .collect();
        let mut fs = pc_fs(pc_stat_override(
            pc_target(3),
            pc_out(0, body.as_bytes(), ""),
        ));
        fs.check_trusted_parents(&pc_path(3)).unwrap();
        assert_eq!(pc_trace(&fs), ["stat-batch:3", "getfattr:3"]);
    }

    #[test]
    fn path_c_same_filesystem_stays_a_separate_fresh_observation() {
        let mut t = pc_target(2).with_fs_file("/d1/f", "x");
        t = t.with_fs_dir("/d1/g");
        let mut fs = pc_fs(t);
        fs.check_trusted_parents("/d1/f").unwrap();
        let before = fs.log().len();
        assert!(fs.same_filesystem("/d1", "/d1/f").unwrap());
        let after = pc_trace(&fs);
        // The comparison reads its own single-operand `stat -c` records; it
        // reuses nothing from the batch.
        assert_eq!(after[before..], ["stat", "stat"]);
        assert!(fs.log()[before..].iter().all(|c| c.args[0] == "-c"));
    }

    #[test]
    fn single_operand_getfattr_interpretation_is_unchanged() {
        let ok = |s: &str| interpret_getfattr_capture(&pc_out(0, s.as_bytes(), ""));
        assert!(ok("").inspected && ok("").attrs.is_empty());
        let x = ok("# file: /d\nuser.a=0sYQ==\nsecurity.selinux=0sYQ==\n\n");
        assert!(x.inspected);
        assert_eq!(x.attrs.len(), 2);
        assert!(x.unsafe_attr().is_none());
        assert!(!ok("noequals\n").inspected);
        assert!(!ok("k=zz!\n").inspected);
        assert!(!interpret_getfattr_capture(&pc_out(1, b"", "")).inspected);
        let mut t = pc_out(0, b"", "");
        t.stdout_truncated = true;
        assert!(!interpret_getfattr_capture(&t).inspected);
        assert!(!interpret_getfattr_capture(&pc_out(0, b"\xff", "")).inspected);
    }

    // Captures from real tools on the research hosts (tests/fixtures/path_c).
    macro_rules! pc_capture {
        ($name:literal) => {
            (
                include_str!(concat!("../tests/fixtures/path_c/", $name, ".dirs"))
                    .lines()
                    .map(String::from)
                    .collect::<Vec<String>>(),
                include_bytes!(concat!("../tests/fixtures/path_c/", $name, ".stat.bin")).as_slice(),
                include_bytes!(concat!("../tests/fixtures/path_c/", $name, ".getfattr.bin"))
                    .as_slice(),
            )
        };
    }

    /// A walk context for the capture host's test user (the owner recorded for
    /// the first ancestor of the capture).
    fn pc_capture_fs(uid: u32) -> TargetFs {
        TargetFs::new_for(
            Executor::Fake(Box::new(FakeExecutor::new(FakeTarget::ubuntu2404(), false))),
            false,
            uid,
            uid,
            "/home/a0000".to_string(),
            None,
            true,
            false,
            false,
            None,
        )
    }

    /// Run a captured chain through the production batch interpretation and
    /// the shared per-ancestor verdicts, exactly as the walk does.
    fn pc_walk_captures(dirs: &[String], stat: &[u8], getfattr: &[u8]) -> Result<()> {
        let stats = interpret_stat_batch(&pc_out(0, stat, ""), "/x/f", dirs)?;
        let fs = pc_capture_fs(stats[0].uid);
        for (d, st) in dirs.iter().zip(&stats) {
            fs.check_parent_stat(d, st)?;
        }
        let xs = interpret_getfattr_batch(&pc_out(0, getfattr, ""), "/x/f", dirs)?;
        for (d, x) in dirs.iter().zip(&xs) {
            fs.check_parent_xattrs(d, x)?;
        }
        Ok(())
    }

    #[test]
    fn path_c_accepts_real_captures_of_safe_chains_from_every_tool_family() {
        for (host, (dirs, stat, getfattr)) in [
            (
                "ubuntu24 GNU 9.4 / attr 2.5.2",
                pc_capture!("ubuntu24_safe"),
            ),
            (
                "ubuntu26 uutils 0.8.0 / attr 2.5.2",
                pc_capture!("ubuntu26_safe"),
            ),
            (
                "rocky98 GNU 8.32 / attr 2.6.0 + SELinux labels",
                pc_capture!("rocky98_safe"),
            ),
            (
                "rocky102 GNU 9.5 / attr 2.6.0",
                pc_capture!("rocky102_safe"),
            ),
            ("ubuntu24 user xattr", pc_capture!("ubuntu24_xattr")),
        ] {
            assert_eq!(dirs.len(), 3, "{host}");
            pc_walk_captures(&dirs, stat, getfattr)
                .unwrap_or_else(|e| panic!("{host}: {}", e.message));
        }
    }

    #[test]
    fn path_c_attributes_real_getfattr_blocks_to_their_ancestors() {
        let (dirs, _, getfattr) = pc_capture!("rocky98_safe");
        let xs = interpret_getfattr_batch(&pc_out(0, getfattr, ""), "/x/f", &dirs).unwrap();
        assert!(xs.iter().all(|x| x.inspected));
        assert!(xs
            .iter()
            .all(|x| x.attrs.keys().collect::<Vec<_>>() == ["security.selinux"]));
        let (dirs, _, getfattr) = pc_capture!("ubuntu24_xattr");
        let xs = interpret_getfattr_batch(&pc_out(0, getfattr, ""), "/x/f", &dirs).unwrap();
        // Only the middle ancestor carried an attribute.
        assert!(
            xs[0].attrs.is_empty() && xs[2].attrs.is_empty()
                || xs.iter().filter(|x| !x.attrs.is_empty()).count() == 1
        );
        assert_eq!(xs.iter().map(|x| x.attrs.len()).sum::<usize>(), 1);
    }

    #[test]
    fn path_c_refuses_real_captures_of_unsafe_chains() {
        for (what, (dirs, stat, getfattr), needle) in [
            (
                "symlink ancestor",
                pc_capture!("rocky98_symlink"),
                "symlink",
            ),
            (
                "group/other writable ancestor",
                pc_capture!("rocky98_mode"),
                "group or other write",
            ),
            (
                "foreign-owned ancestor",
                pc_capture!("rocky98_owner"),
                "outside the trusted set",
            ),
        ] {
            let e = pc_walk_captures(&dirs, stat, getfattr)
                .expect_err(&format!("{what} must be refused"));
            assert!(e.message.contains(needle), "{what}: {}", e.message);
        }
    }

    #[test]
    fn path_c_refuses_real_acl_captures_at_whichever_gate_sees_them() {
        // A named *access* ACL entry raises the group bits `stat` reports to the
        // ACL mask, so the stat gate already refuses; a *default* ACL leaves the
        // mode alone and only the attribute gate sees it. The attribute gate
        // refuses both on its own, which is what matters when a mask hides
        // nothing.
        for (what, (dirs, stat, getfattr), first_gate) in [
            (
                "access ACL",
                pc_capture!("rocky98_aclc"),
                "group or other write",
            ),
            (
                "default ACL",
                pc_capture!("rocky98_dacl"),
                "extended access metadata",
            ),
        ] {
            let e = pc_walk_captures(&dirs, stat, getfattr).expect_err(what);
            assert!(e.message.contains(first_gate), "{what}: {}", e.message);
            let fs = pc_capture_fs(1000);
            let xs = interpret_getfattr_batch(&pc_out(0, getfattr, ""), "/x/f", &dirs).unwrap();
            let refused: Vec<_> = dirs
                .iter()
                .zip(&xs)
                .filter_map(|(d, x)| fs.check_parent_xattrs(d, x).err())
                .collect();
            assert_eq!(
                refused.len(),
                1,
                "{what}: exactly one ancestor carries the ACL"
            );
            assert!(
                refused[0].message.contains("extended access metadata"),
                "{}",
                refused[0].message
            );
        }
    }

    #[test]
    fn path_c_refuses_a_real_partial_stat_failure() {
        let (dirs, stat, _) = pc_capture!("rocky98_missing");
        let stderr = include_str!("../tests/fixtures/path_c/rocky98_missing.stat.stderr");
        assert!(!stat.is_empty(), "the real failure still printed a record");
        let e = interpret_stat_batch(&pc_out(1, stat, stderr), "/x/f", &dirs).unwrap_err();
        assert!(e.message.contains("exited with status 1"), "{}", e.message);
        // Even offered as if it had succeeded, the missing records refuse it.
        assert!(interpret_stat_batch(&pc_out(0, stat, ""), "/x/f", &dirs).is_err());
    }

    #[test]
    fn path_c_walks_are_independent_invocations() {
        // Two walks over the same path send two complete, fresh batch pairs:
        // nothing observed by the first is reused by the second.
        let mut fs = pc_fs(pc_target(3));
        fs.check_trusted_parents(&pc_path(3)).unwrap();
        fs.check_trusted_parents(&pc_path(3)).unwrap();
        fs.check_trusted_parents(&pc_path(3)).unwrap();
        assert_eq!(
            pc_trace(&fs),
            [
                "stat-batch:3",
                "getfattr:3",
                "stat-batch:3",
                "getfattr:3",
                "stat-batch:3",
                "getfattr:3"
            ]
        );
        assert_eq!(fs.exec_stats().snapshot().total(), 6);
    }

    #[test]
    fn path_c_batch_requests_are_counted_as_one_command_each() {
        let mut fs = pc_fs(pc_target(6));
        fs.check_trusted_parents(&pc_path(6)).unwrap();
        let s = fs.exec_stats().snapshot();
        assert_eq!(s.total(), 2);
        assert_eq!(s.count_program("stat"), 1);
        assert_eq!(s.count_program("getfattr"), 1);
        // A failed batch is still one counted command.
        let mut fs = pc_fs(pc_stat_override(pc_target(6), pc_out(1, b"", "x\n")));
        assert!(fs.check_trusted_parents(&pc_path(6)).is_err());
        let s = fs.exec_stats().snapshot();
        assert_eq!(s.total(), 1);
        assert_eq!(s.count_program("stat"), 1);
        assert_eq!(s.not_successful(), 1);
    }
}
