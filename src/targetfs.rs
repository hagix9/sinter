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
        self.ex.run(req)
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
        let mut req = ExecRequest::new(program);
        req.args = args.to_vec();
        req.env = base_env();
        req.env.insert("HOME".to_string(), self.home_env());
        req.sensitive = sensitive;
        self.ex.run(&req)
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
        self.run_argv_sensitivity(
            "/usr/bin/systemctl",
            &[
                "show".to_string(),
                name.to_string(),
                "--property=LoadState,ActiveState,UnitFileState".to_string(),
            ],
            sensitive,
        )
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
        let code = match out.completion {
            Completion::Exited(c) => c,
            _ => {
                return Ok(Xattrs {
                    attrs: BTreeMap::new(),
                    inspected: false,
                })
            }
        };
        if code != 0 {
            return Ok(Xattrs {
                attrs: BTreeMap::new(),
                inspected: false,
            });
        }
        if out.stdout_truncated || out.stderr_truncated {
            return Ok(Xattrs {
                attrs: BTreeMap::new(),
                inspected: false,
            });
        }
        let text = match std::str::from_utf8(&out.stdout) {
            Ok(text) => text,
            Err(_) => {
                return Ok(Xattrs {
                    attrs: BTreeMap::new(),
                    inspected: false,
                })
            }
        };
        let mut attrs = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                return Ok(Xattrs {
                    attrs,
                    inspected: false,
                });
            };
            if k.trim().is_empty() {
                return Ok(Xattrs {
                    attrs,
                    inspected: false,
                });
            }
            let value = v.trim();
            // getfattr -e base64 emits `0s<base64>` (or empty). Reject values
            // that cannot be authoritatively interpreted (DESIGN §24.4).
            if !is_valid_xattr_encoded(value) {
                return Ok(Xattrs {
                    attrs,
                    inspected: false,
                });
            }
            attrs.insert(k.trim().to_string(), value.to_string());
        }

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
        self.run_argv_ok_mutating("/bin/mkdir", &["--".to_string(), path.to_string()])?;
        Ok(())
    }

    pub fn rmdir(&mut self, _permit: &MutationPermit, path: &str) -> Result<()> {
        self.run_argv_ok_mutating("/bin/rmdir", &["--".to_string(), path.to_string()])?;
        Ok(())
    }

    /// Remove a file only if it is the exact object we created (regular file).
    pub fn remove_file(&mut self, _permit: &MutationPermit, path: &str) -> Result<()> {
        self.run_argv_ok_mutating(
            "/bin/rm",
            &["-f".to_string(), "--".to_string(), path.to_string()],
        )?;
        Ok(())
    }

    /// Remove a symlink only, refusing to follow it.
    pub fn remove_symlink(&mut self, _permit: &MutationPermit, path: &str) -> Result<()> {
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
        self.getent_field("passwd", spec, 2, 7, "user", sensitive)
    }

    pub fn resolve_gid(&mut self, spec: &str) -> Result<u32> {
        self.resolve_gid_sensitive(spec, false)
    }

    pub fn resolve_gid_sensitive(&mut self, spec: &str, sensitive: bool) -> Result<u32> {
        if let Ok(n) = spec.parse::<u32>() {
            return Ok(n);
        }
        self.getent_field("group", spec, 2, 4, "group", sensitive)
    }

    pub fn primary_gid_of_uid(&mut self, uid: u32) -> Result<u32> {
        self.getent_field("passwd", &uid.to_string(), 3, 7, "uid", false)
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
    pub fn check_trusted_parents(&mut self, path: &str) -> Result<()> {
        for dir in ancestor_dirs(path) {
            let st = self.inspect(&dir)?;
            match st.kind {
                ObjKind::Absent => {
                    return Err(SinterError::apply(format!(
                        "required parent path {} does not exist",
                        dir
                    )))
                }
                ObjKind::Symlink => {
                    return Err(SinterError::apply(format!(
                        "parent path {} is a symlink; refusing to follow it",
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
                    "parent path {} is owned by uid {}, outside the trusted set",
                    dir, st.uid
                )));
            }
            if st.mode & 0o022 != 0 {
                return Err(SinterError::apply(format!(
                    "parent path {} grants group or other write access; refusing unsafe path ({})",
                    dir,
                    mode_to_string(st.mode)
                )));
            }
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
            if !x.inspected {
                return Err(SinterError::apply(format!(
                    "cannot inspect access metadata of parent path {}; refusing unsafe path{}",
                    dir,
                    self.xattr_inspection_unavailable().unwrap_or_default()
                )));
            }
            if x.unsafe_attr().is_some() {
                return Err(SinterError::apply(format!(
                    "parent path {} carries extended access metadata; cannot prove it is non-writable",
                    dir
                )));
            }
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
        for message in ["No such file or directory", "Not a directory"] {
            // Whole-field equality: a permission diagnostic such as
            // `...: Permission denied: no such file or directory` does not
            // match, because its subject field is longer.
            if rest == format!("{}: {}", subject, message) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
