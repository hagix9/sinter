//! Plan, apply and audit of `kernel_module`.
//!
//! The boot-time setting and the blacklist are whole files of Sinter's own
//! and go through the `file` resource code unchanged (atomic write, parent
//! checks, diff). Whether a module is loaded is the `lstat` of
//! `/sys/module/<name>` (read-only). Whether it can be loaded is asked with
//! `modprobe -n -v -- <name>` (a dry run, read-only), only when a load is
//! needed. The load is `modprobe -- <name>`; its exit code never decides
//! success: `/sys/module/<name>` is observed again. Nothing here unloads a
//! module (`modprobe -r` is never run).
//!
//! Order in apply for `present`: the loaded state and the availability are
//! observed first (so an unknown module is refused before anything is
//! written), then the files, then the load.

use crate::engine::{Engine, Mode};
use crate::error::{Result, SinterError};
use crate::executor::Completion;
use crate::expressions::EvalVal;
use crate::kmod::{
    ModState, ModuleSpec, ABSENT_NOTE, BLACKLIST_NOTE, BOOT_NOTE, MODULE_TREES, NOT_RUNNING_NOTE,
    SYS_MODULE, TIMEOUT_SECS, TOOL,
};
use crate::model::FrozenResource;
use crate::osbase::{before_any_change, reobservation_failed, stderr_excerpt};
use crate::resources::{changed_result_sensitive, unchanged_result};
use crate::result::{Change, Diff, DiffBody, Execution, ResourceResult, Verification};
use crate::targetfs::ObjKind;
use crate::timer_engine::{merge, plain_values};

const WHAT: &str = "modprobe";

/// What audit found, for `audit.rs`.
pub(crate) struct ModuleAudit {
    /// The synthetic file resource for Sinter's boot-time file, when managed.
    pub(crate) load_file: Option<FrozenResource>,
    /// The synthetic file resource for Sinter's blacklist file, when managed.
    pub(crate) blacklist_file: Option<FrozenResource>,
    /// The loaded state, when managed and not as declared: (observed,
    /// desired).
    pub(crate) loaded: Option<(String, String)>,
}

impl Engine {
    fn kmod_evaluate(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ModuleSpec> {
        let vals = self.eval_with(res, item)?;
        ModuleSpec::from_values(&plain_values(&vals)?, &res.id)
    }

    /// Whether the running kernel has the module (`/sys/module/<name>` is a
    /// directory; a built-in module that appears there counts as loaded).
    /// Read-only. `/sys/module` itself must be a directory; any other
    /// object type or a failed observation is an error, never "not loaded".
    fn kmod_loaded(&mut self, res: &FrozenResource, name: &str) -> Result<bool> {
        let base = self.observe_stat(res, SYS_MODULE)?;
        if base.kind != ObjKind::Dir {
            return Err(SinterError::apply(format!(
                "{}: the loaded modules could not be observed: {} is {} (sysfs is not available)",
                res.id,
                SYS_MODULE,
                if base.kind == ObjKind::Absent {
                    "missing".to_string()
                } else {
                    base.kind.describe().to_string()
                }
            )));
        }
        let path = crate::kmod::sys_path(name);
        match self.observe_stat(res, &path)?.kind {
            ObjKind::Dir => Ok(true),
            ObjKind::Absent => Ok(false),
            other => Err(SinterError::apply(format!(
                "{}: whether module {} is loaded could not be observed: {} exists as {}",
                res.id,
                name,
                path,
                other.describe()
            ))),
        }
    }

    /// Whether `modprobe` can load the module for the running kernel (a dry
    /// run). Read-only. Exit 0: available; exit 1: not available (a plan
    /// error, unless an earlier planned change may provide it: then a
    /// note); anything else is an observation error.
    fn kmod_available(&mut self, res: &FrozenResource, name: &str) -> Result<Vec<String>> {
        self.osbase_tool(res, TOOL, "kernel_module", false)?;
        let out = self.fs.modprobe_dry_run(name)?;
        let what = format!(
            "{}: whether module {} can be loaded could not be observed: modprobe -n -v",
            res.id, name
        );
        match &out.completion {
            Completion::Exited(0) => {}
            Completion::Exited(1) => {
                if self.opts.mode == Mode::Plan {
                    if let Some(why) = MODULE_TREES
                        .iter()
                        .find_map(|t| self.planned.affecting_subtree(t))
                    {
                        return Ok(vec![format!(
                            "module {} is not available for the running kernel now; checked again at apply ({})",
                            name, why
                        )]);
                    }
                }
                let detail = stderr_excerpt(&out.stderr);
                return Err(SinterError::apply(format!(
                    "{}: module {} is not available for the running kernel{}; nothing was changed",
                    res.id,
                    name,
                    if detail.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", detail)
                    }
                )));
            }
            Completion::Exited(code) => {
                let detail = stderr_excerpt(&out.stderr);
                return Err(SinterError::apply(format!(
                    "{} exited {}{}",
                    what,
                    code,
                    if detail.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", detail)
                    }
                )));
            }
            Completion::Signaled(s) => {
                return Err(SinterError::apply(format!(
                    "{} was terminated by signal {}",
                    what, s
                )))
            }
            Completion::Indeterminate { .. } => {
                return Err(SinterError::indeterminate(format!(
                    "{} did not complete",
                    what
                )))
            }
        }
        if out.stdout_truncated || out.stderr_truncated {
            return Err(SinterError::apply(format!(
                "{}: its output was truncated",
                what
            )));
        }
        Ok(Vec::new())
    }

    /// Audit, the part that is not the files: the spec's file resources and
    /// the loaded-state drift. Read-only.
    pub(crate) fn kmod_audit(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ModuleAudit> {
        let spec = self.kmod_evaluate(res, item)?;
        let mut loaded = None;
        if spec.state == ModState::Present && spec.runtime && !self.kmod_loaded(res, &spec.name)? {
            loaded = Some(("not loaded".to_string(), "loaded".to_string()));
        }
        Ok(ModuleAudit {
            load_file: spec.load_part(res),
            blacklist_file: spec.blacklist_part(res),
            loaded,
        })
    }

    pub(crate) fn run_kernel_module(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let sensitive = res.sensitive || res.derived_sensitive;
        let spec = self.kmod_evaluate(res, item)?;
        let apply = self.opts.mode == Mode::Apply;

        // Read-only, and first: a module the running kernel cannot load is
        // refused before a file is written.
        let mut notes = Vec::new();
        let needs_load = if spec.state == ModState::Present && spec.runtime {
            let loaded = self
                .kmod_loaded(res, &spec.name)
                .map_err(before_any_change)?;
            if !loaded {
                notes = self
                    .kmod_available(res, &spec.name)
                    .map_err(before_any_change)?;
            }
            !loaded
        } else {
            false
        };
        if apply && needs_load && !self.fs.runs_as_root() {
            return Err(SinterError::apply(format!(
                "{}: kernel_module needs root to load a module: connect as root or use --sudo; nothing was changed",
                res.id
            )));
        }

        let mut parts: Vec<ResourceResult> = Vec::new();
        let mut files_changed = false;
        let mut files_planned = false;
        // The blacklist first: with `present` it is removed before the
        // boot-time file exists, so the two never ask for opposite things.
        for file in [spec.blacklist_part(res), spec.load_part(res)]
            .into_iter()
            .flatten()
        {
            let fr = self.run_file(&file, None)?;
            // The file's parent walk may have switched to the account that
            // owns the directory; the tool runs as the invocation itself.
            self.fs.clear_identity();
            files_changed |= apply && fr.change == Change::Changed;
            files_planned |= fr.change != Change::None;
            let failed = matches!(fr.execution, Execution::Failed | Execution::Indeterminate);
            parts.push(fr);
            if failed {
                let mut r = merge(res, parts);
                if needs_load {
                    r.notes.push(
                        "the module was not loaded because a file of Sinter's could not be written"
                            .to_string(),
                    );
                }
                return Ok(r);
            }
        }

        if spec.state == ModState::Present && spec.runtime {
            let part = if needs_load {
                self.kmod_load(res, &spec, sensitive, files_changed)?
            } else {
                unchanged_result(res, "module already loaded")
            };
            parts.push(part);
        }

        let mut r = merge(res, parts);
        r.notes.extend(notes);
        if files_planned {
            match spec.state {
                ModState::Present => {
                    r.notes.push(BOOT_NOTE.to_string());
                    if !spec.runtime {
                        r.notes.push(NOT_RUNNING_NOTE.to_string());
                    }
                }
                ModState::Absent => r.notes.push(ABSENT_NOTE.to_string()),
                ModState::Blacklisted => {
                    r.notes.push(BLACKLIST_NOTE.to_string());
                    r.notes.push(BOOT_NOTE.to_string());
                }
            }
        }
        Ok(r)
    }

    /// The load part: what plan reports, and in apply the load with its
    /// verification. `files_changed`: a file was already changed by this
    /// resource, so an error here reports that change as certain.
    fn kmod_load(
        &mut self,
        res: &FrozenResource,
        spec: &ModuleSpec,
        sensitive: bool,
        files_changed: bool,
    ) -> Result<ResourceResult> {
        let mut r = changed_result_sensitive(res, sensitive);
        r.diff = Some(Diff {
            body: DiffBody::Summary {
                current: "not loaded".to_string(),
                desired: "loaded".to_string(),
            },
        });
        r.notes
            .push(format!("module {}: not loaded -> loaded", spec.name));
        if self.opts.mode == Mode::Plan {
            return Ok(r);
        }
        let subject = format!("module {}", spec.name);
        if !self.osbase_exec(
            res,
            &mut r,
            TOOL,
            spec.load_args(),
            TIMEOUT_SECS,
            sensitive,
            WHAT,
            &format!("whether {} is loaded", subject),
            files_changed,
        )? {
            return Ok(r);
        }
        // Exit 0 is only the tool's claim. The running kernel decides.
        match self.kmod_loaded(res, &spec.name) {
            Ok(true) => {
                r.change = Change::Changed;
                r.verification = Verification::Verified;
            }
            Ok(false) => {
                r.execution = Execution::Failed;
                r.change = Change::Possible;
                r.verification = Verification::Failed;
                r.reason = Some(format!(
                    "modprobe reported success but {} does not exist, so {} is not loaded (a built-in module without parameters does not appear there)",
                    crate::kmod::sys_path(&spec.name),
                    subject
                ));
            }
            Err(e) => reobservation_failed(&mut r, &e, WHAT, &subject, sensitive),
        }
        Ok(r)
    }
}
