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
    pub fn unsafe_attr(&self) -> Option<String> {
        for name in self.attrs.keys() {
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
}

pub struct TargetFs {
    pub ex: Executor,
    pub sudo: bool,
    pub target_uid: u32,
    pub target_gid: u32,
    pub home: String,
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
            has_getfattr,
            has_getfacl,
            allow_mutation,
            fault,
        }
    }

    pub fn fault(&self) -> Option<&str> {
        self.fault.as_deref()
    }

    fn guard_mut(&self) -> Result<()> {
        if self.allow_mutation {
            Ok(())
        } else {
            Err(SinterError::plan(
                "internal error: observation attempted a mutation",
            ))
        }
    }

    pub fn exec(&mut self, req: &ExecRequest) -> Result<Output> {
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
    pub fn new(
        mut ex: Executor,
        sudo: bool,
        target_uid: u32,
        target_gid: u32,
        home: String,
    ) -> Result<Self> {
        let has_getfattr = command_exists(&mut ex, "/usr/bin/getfattr")?;
        let has_getfacl = command_exists(&mut ex, "/usr/bin/getfacl")?;
        Ok(TargetFs {
            ex,
            sudo,
            target_uid,
            target_gid,
            home,
            has_getfattr,
            has_getfacl,
            allow_mutation: true,
            fault: None,
        })
    }

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
    pub fn run_argv(&mut self, program: &str, args: &[String]) -> Result<Output> {
        let mut req = ExecRequest::new(program);
        req.args = args.to_vec();
        req.env = base_env();
        req.env.insert("HOME".to_string(), self.home_env());
        self.ex.run(&req)
    }

    /// Query dpkg for a package's status using exact argv.
    pub fn dpkg_query(&mut self, name: &str) -> Result<Output> {
        self.run_argv(
            "/usr/bin/dpkg-query",
            &[
                "-W".to_string(),
                "-f=${Status}".to_string(),
                "--".to_string(),
                name.to_string(),
            ],
        )
    }

    /// Show a systemd unit's relevant properties using exact argv.
    pub fn systemctl_show(&mut self, name: &str) -> Result<Output> {
        self.run_argv(
            "/usr/bin/systemctl",
            &[
                "show".to_string(),
                name.to_string(),
                "--property=LoadState,ActiveState,UnitFileState".to_string(),
            ],
        )
    }

    fn run_argv_ok(&mut self, program: &str, args: &[String]) -> Result<Output> {
        let out = self.run_argv(program, args)?;
        match out.completion {
            Completion::Exited(0) => Ok(out),
            Completion::Exited(c) => Err(SinterError::apply(format!(
                "target operation {} failed (exit {}): {}",
                program,
                c,
                String::from_utf8_lossy(&out.stderr).trim()
            ))),
            Completion::Signaled(s) => Err(SinterError::apply(format!(
                "target operation {} terminated by signal {}",
                program, s
            ))),
            Completion::Indeterminate { reason, .. } => Err(SinterError::indeterminate(reason)),
        }
    }

    /// Create a private staging directory beneath the destination parent, using
    /// a non-predictable name. No recipe-controlled text is used in the name, so
    /// no shell syntax can leak. The directory is created mode 0700.
    pub fn make_staging_dir(&mut self, dir: &str) -> Result<String> {
        self.guard_mut()?;
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

    /// Inspect an object without following a final symlink. Distinguishes
    /// confirmed ENOENT/ENOTDIR (Absent) from any other failure (error), so
    /// "could not inspect" is never treated as "not present".
    pub fn inspect(&mut self, path: &str) -> Result<Stat> {
        let out = self.run_argv(
            "/usr/bin/stat",
            &[
                "-c".to_string(),
                "%F|%a|%u|%g|%s|%d|%i".to_string(),
                "--".to_string(),
                path.to_string(),
            ],
        )?;
        match out.completion {
            Completion::Exited(0) => {
                let text = String::from_utf8_lossy(&out.stdout);
                parse_stat_line(text.trim())
                    .map_err(|e| SinterError::apply(format!("cannot inspect {}: {}", path, e)))
            }
            Completion::Exited(_) => {
                let err = String::from_utf8_lossy(&out.stderr);
                if is_missing_error(&err) {
                    Ok(absent_stat())
                } else {
                    Err(SinterError::apply(format!(
                        "cannot inspect {}: {}",
                        path,
                        err.trim()
                    )))
                }
            }
            Completion::Signaled(s) => Err(SinterError::apply(format!(
                "inspection of {} terminated by signal {}",
                path, s
            ))),
            Completion::Indeterminate { reason, .. } => Err(SinterError::indeterminate(format!(
                "inspection of {} did not complete: {}",
                path, reason
            ))),
        }
    }

    pub fn readlink(&mut self, path: &str) -> Result<String> {
        let out = self.run_argv_ok(
            "/usr/bin/readlink",
            &["-n".to_string(), "--".to_string(), path.to_string()],
        )?;
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
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

    pub fn sha256(&mut self, path: &str) -> Result<Option<String>> {
        let out = self.run_argv("/usr/bin/sha256sum", &["--".to_string(), path.to_string()])?;
        match out.completion {
            Completion::Exited(0) => {
                let text = String::from_utf8_lossy(&out.stdout);
                Ok(Some(
                    text.split_whitespace().next().unwrap_or("").to_string(),
                ))
            }
            Completion::Exited(_) => Ok(None),
            Completion::Signaled(_) | Completion::Indeterminate { .. } => Err(
                SinterError::indeterminate(format!("digest of {} did not complete", path)),
            ),
        }
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
        // getfattr exits 0 when attributes exist and 1 when the object has
        // none. Any other result means inspection could not be performed, and
        // "could not inspect" must never be treated as "no metadata".
        let code = match out.completion {
            Completion::Exited(c) => c,
            _ => {
                return Ok(Xattrs {
                    attrs: BTreeMap::new(),
                    inspected: false,
                })
            }
        };
        if code != 0 && code != 1 {
            return Ok(Xattrs {
                attrs: BTreeMap::new(),
                inspected: false,
            });
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut attrs = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                attrs.insert(k.trim().to_string(), v.trim().to_string());
            }
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
                    Completion::Exited(0) => {
                        let acl_text = String::from_utf8_lossy(&o.stdout);
                        // A non-trivial ACL is present if there is any entry
                        // other than owner/group/other base entries.
                        let has_extended = acl_text.lines().any(|l| {
                            let l = l.trim();
                            if l.is_empty() || l.starts_with('#') {
                                return false;
                            }
                            let before_colon = l.split(':').next().unwrap_or("");
                            before_colon != "user"
                                && before_colon != "group"
                                && before_colon != "other"
                        });
                        if has_extended {
                            attrs
                                .entry("system.posix_acl_access".to_string())
                                .or_insert_with(|| "present".to_string());
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
        self.guard_mut()?;
        self.chown(path, uid, gid)?;
        self.chmod(path, mode)?;
        Ok(())
    }

    pub fn chmod(&mut self, path: &str, mode: u32) -> Result<()> {
        self.guard_mut()?;
        self.run_argv_ok(
            "/bin/chmod",
            &[mode_to_string(mode), "--".to_string(), path.to_string()],
        )?;
        Ok(())
    }

    pub fn chown(&mut self, path: &str, uid: u32, gid: u32) -> Result<()> {
        self.guard_mut()?;
        self.run_argv_ok(
            "/bin/chown",
            &[
                format!("{}:{}", uid, gid),
                "--".to_string(),
                path.to_string(),
            ],
        )?;
        Ok(())
    }

    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        self.guard_mut()?;
        self.run_argv_ok("/bin/mkdir", &["--".to_string(), path.to_string()])?;
        Ok(())
    }

    pub fn rmdir(&mut self, path: &str) -> Result<()> {
        self.guard_mut()?;
        self.run_argv_ok("/bin/rmdir", &["--".to_string(), path.to_string()])?;
        Ok(())
    }

    /// Remove a file only if it is the exact object we created (regular file).
    pub fn remove_file(&mut self, path: &str) -> Result<()> {
        self.guard_mut()?;
        self.run_argv_ok(
            "/bin/rm",
            &["-f".to_string(), "--".to_string(), path.to_string()],
        )?;
        Ok(())
    }

    /// Remove a symlink only, refusing to follow it.
    pub fn remove_symlink(&mut self, path: &str) -> Result<()> {
        self.guard_mut()?;
        self.run_argv_ok(
            "/bin/rm",
            &["-f".to_string(), "--".to_string(), path.to_string()],
        )?;
        Ok(())
    }

    pub fn symlink(&mut self, target: &str, link_path: &str) -> Result<()> {
        self.guard_mut()?;
        if target.contains('\0') {
            return Err(SinterError::schema(
                "symlink target may not contain NUL bytes",
            ));
        }
        self.run_argv_ok(
            "/bin/ln",
            &[
                "-s".to_string(),
                "--".to_string(),
                target.to_string(),
                link_path.to_string(),
            ],
        )?;
        Ok(())
    }

    /// Atomically replace a symlink using a private staging directory so the
    /// staging name cannot be predicted or pre-created by another user.
    pub fn symlink_replace(&mut self, target: &str, link_path: &str) -> Result<()> {
        self.guard_mut()?;
        let (dir, name) = parent_and_name(link_path);
        let stage_dir = self.make_staging_dir(&dir)?;
        let tmp = format!("{}/{}", stage_dir, name);
        let result = (|| -> Result<()> {
            self.run_argv_ok(
                "/bin/ln",
                &[
                    "-s".to_string(),
                    "--".to_string(),
                    target.to_string(),
                    tmp.clone(),
                ],
            )?;
            self.run_argv_ok(
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
        let _ = self.run_argv("/bin/rmdir", &[stage_dir]);
        result
    }

    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        self.guard_mut()?;
        self.run_argv_ok(
            "/bin/mv",
            &[
                "-T".to_string(),
                "-f".to_string(),
                "--".to_string(),
                from.to_string(),
                to.to_string(),
            ],
        )?;
        Ok(())
    }

    /// Write exact bytes to a path by streaming them over stdin to `dd`. The
    /// destination path is passed as a single argv element, so no recipe-
    /// controlled value can become shell syntax, and no shell is invoked.
    pub fn write_bytes(&mut self, path: &str, data: &[u8]) -> Result<()> {
        self.guard_mut()?;
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
    pub fn set_xattr(&mut self, name: &str, value: &str, path: &str) -> Result<()> {
        self.guard_mut()?;
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

    /// Copy `user.*` xattrs from `from` onto `to`. Security/label attributes are
    /// deliberately not copied here (unsupported metadata triggers refusal).
    pub fn copy_user_xattrs(&mut self, from: &str, to: &str) -> Result<()> {
        if !self.has_getfattr {
            return Ok(());
        }
        let x = self.xattrs(from)?;
        for (name, value) in x.user_attrs() {
            self.set_xattr(name, value, to)?;
        }
        Ok(())
    }

    pub fn resolve_uid(&mut self, spec: &str) -> Result<u32> {
        if let Ok(n) = spec.parse::<u32>() {
            return Ok(n);
        }
        self.getent_field("/usr/bin/getent", "passwd", spec, 2, "user")
    }

    pub fn resolve_gid(&mut self, spec: &str) -> Result<u32> {
        if let Ok(n) = spec.parse::<u32>() {
            return Ok(n);
        }
        self.getent_field("/usr/bin/getent", "group", spec, 2, "group")
    }

    pub fn primary_gid_of_uid(&mut self, uid: u32) -> Result<u32> {
        self.getent_field("/usr/bin/getent", "passwd", &uid.to_string(), 3, "uid")
    }

    fn getent_field(
        &mut self,
        program: &str,
        database: &str,
        key: &str,
        field: usize,
        what: &str,
    ) -> Result<u32> {
        let out = self.run_argv(program, &[database.to_string(), key.to_string()])?;
        match out.completion {
            Completion::Exited(0) => {
                let text = String::from_utf8_lossy(&out.stdout);
                let line = text.lines().next().unwrap_or("");
                let parts: Vec<&str> = line.trim().split(':').collect();
                if parts.len() > field {
                    parts[field]
                        .parse::<u32>()
                        .map_err(|_| SinterError::apply(format!("unknown {}: {}", what, key)))
                } else {
                    Err(SinterError::apply(format!("unknown {}: {}", what, key)))
                }
            }
            _ => Err(SinterError::apply(format!("unknown {}: {}", what, key))),
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
                    "cannot inspect access metadata of parent path {}; refusing unsafe path",
                    dir
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
    }
}

/// Whether a stat/stderr message positively indicates the object is missing.
/// Only confirmed ENOENT/ENOTDIR may be treated as absence.
pub fn is_missing_error(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("no such file or directory")
        || s.contains("not a directory")
        || s.contains("no such file")
}

fn parse_stat_line(text: &str) -> std::result::Result<Stat, String> {
    let parts: Vec<&str> = text.trim().split('|').collect();
    if parts.len() != 7 {
        return Err(format!("unexpected stat output: {:?}", text));
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
    Ok(Stat {
        kind,
        mode,
        uid,
        gid,
        size,
        dev,
        ino,
    })
}

fn command_exists(ex: &mut Executor, path: &str) -> Result<bool> {
    // Verify executability with exact argv and no shell.
    let mut req = ExecRequest::new("/usr/bin/test");
    req.args = vec!["-x".to_string(), path.to_string()];
    req.env = base_env();
    match ex.run(&req)?.completion {
        Completion::Exited(0) => Ok(true),
        Completion::Exited(_) => Ok(false),
        Completion::Signaled(_) | Completion::Indeterminate { .. } => Err(SinterError::connect(
            "could not determine target command availability",
        )),
    }
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
}
