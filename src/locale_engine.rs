//! Plan, apply and audit of `locale`.
//!
//! The default lives in one file whose place depends on the OS family
//! (`/etc/locale.conf` on the Red Hat family, `/etc/default/locale` on the
//! Debian family); an unknown family is refused. Observation reads that file
//! (read-only, the partial-edit observation: never followed, size-capped,
//! re-checked) with a closed parser. One link is known: on the Debian family
//! `/etc/default/locale` may be the OS's own link to `/etc/locale.conf`
//! (`../locale.conf` or `/etc/locale.conf`, owned by root; Ubuntu 24.04 and
//! later). Then `/etc/locale.conf` is read as above (a regular file or
//! absent; a link there is refused, so there is no chain), and the link is
//! observed again afterwards; any other link is refused (DESIGN §61). Whether a declared locale exists is
//! asked with `locale -a` (read-only, fixed argv). The change is `localectl
//! set-locale KEY=value ...`; its exit code never decides success: the file
//! is read again and every declared key must have its value. Sinter never
//! writes the file itself, never installs or generates a locale and
//! restarts nothing.

use std::collections::BTreeMap;

use crate::engine::{Engine, Mode};
use crate::error::{ErrorKind, Result, SinterError};
use crate::executor::Completion;
use crate::expressions::EvalVal;
use crate::locale::{LocaleSpec, LIST_TOOL, LOCALE_DIR, SESSIONS_NOTE, TIMEOUT_SECS, TOOL};
use crate::model::FrozenResource;
use crate::osbase::{before_any_change, reobservation_failed, shown, stderr_excerpt};
use crate::resources::{changed_result_sensitive, unchanged_result};
use crate::result::{Change, Diff, DiffBody, Execution, ResourceResult, Verification};
use crate::targetfs::ObjKind;
use crate::timer_engine::plain_values;

/// Where the default is read from: the file itself, or `/etc/locale.conf`
/// through the Debian family's known link (its text kept to observe it
/// again).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocaleSource {
    pub read: &'static str,
    pub link: Option<String>,
}

impl LocaleSource {
    fn describe(&self, conf: &str) -> String {
        match &self.link {
            Some(t) => format!("{} (through the link {} -> {})", self.read, conf, t),
            None => self.read.to_string(),
        }
    }
}

const WHAT: &str = "localectl set-locale";
const SUBJECT: &str = "the default locale";

/// The declared keys as `KEY=value`, values from `map` (`(not set)` when
/// absent), for a diff summary.
fn summary(spec: &LocaleSpec, map: &BTreeMap<String, String>) -> String {
    spec.settings
        .keys()
        .map(|k| format!("{}={}", k, crate::locale::shown_setting(map, k)))
        .collect::<Vec<_>>()
        .join(" ")
}

impl Engine {
    fn locale_evaluate(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<LocaleSpec> {
        let vals = self.eval_with(res, item)?;
        LocaleSpec::from_values(&plain_values(&vals)?, &res.id, sensitive)
    }

    /// Where this host keeps the default.
    fn locale_conf(&self, res: &FrozenResource) -> Result<&'static str> {
        crate::locale::conf_path(&self.facts.os_family).ok_or_else(|| {
            SinterError::apply(format!(
                "{}: locale is not supported on this host: Sinter knows where the default locale is kept only on the Red Hat family ({}) and the Debian family ({}), and this host's OS family is {}",
                res.id,
                crate::locale::RHEL_CONF,
                crate::locale::DEBIAN_CONF,
                if self.facts.os_family.is_empty() {
                    "unknown".to_string()
                } else {
                    shown(&self.facts.os_family)
                }
            ))
        })
    }

    /// `lstat` of `path` and, for a link, its text. Read-only.
    fn locale_link(
        &mut self,
        res: &FrozenResource,
        path: &str,
        audit: bool,
    ) -> Result<(ObjKind, u32, Option<String>)> {
        if audit {
            return crate::audit::audit_link_observe(self, path);
        }
        let st = self.observe_stat(res, path)?;
        if st.kind != ObjKind::Symlink {
            return Ok((st.kind, st.uid, None));
        }
        let text = self.observe_readlink(res, path)?;
        Ok((st.kind, st.uid, Some(text)))
    }

    /// Where the default is read from (see [`LocaleSource`]). Only the
    /// Debian family's file may be a link, only one of
    /// [`crate::locale::DEBIAN_LINKS`] and only owned by root; any other link
    /// is refused and nothing is read through it.
    fn locale_source(
        &mut self,
        res: &FrozenResource,
        conf: &'static str,
        audit: bool,
    ) -> Result<LocaleSource> {
        if conf != crate::locale::DEBIAN_CONF {
            return Ok(LocaleSource {
                read: conf,
                link: None,
            });
        }
        let (kind, uid, text) = self.locale_link(res, conf, audit)?;
        let Some(text) = text else {
            debug_assert!(kind != ObjKind::Symlink);
            return Ok(LocaleSource {
                read: conf,
                link: None,
            });
        };
        if uid != 0 || !crate::locale::DEBIAN_LINKS.contains(&text.as_str()) {
            return Err(SinterError::apply(format!(
                "{}: the default locale could not be observed: {} is a symlink{}; Sinter follows it only when it is the OS's own link to {} ({}) owned by root, and refuses any other link",
                res.id,
                conf,
                if uid != 0 { " not owned by root" } else { " to another target" },
                crate::locale::RHEL_CONF,
                crate::locale::DEBIAN_LINKS.join(" or ")
            )));
        }
        Ok(LocaleSource {
            read: crate::locale::RHEL_CONF,
            link: Some(text),
        })
    }

    /// The keys the locale file sets (empty when the file is absent; through
    /// the known link, also when the link dangles) and where they were read.
    /// Read-only. Another link, a link at the file that is read, another
    /// object type, an oversized file or a second hard link, a refused
    /// parent, a failed read, content outside the closed grammar or a link
    /// that changed while it was read is an error, never "not set".
    fn locale_read(
        &mut self,
        res: &FrozenResource,
        conf: &'static str,
        audit: bool,
    ) -> Result<(BTreeMap<String, String>, LocaleSource)> {
        let src = self.locale_source(res, conf, audit)?;
        let bytes = if audit {
            crate::audit::audit_partial_read(self, src.read)?
        } else {
            self.partial_observe(res, src.read)?.1
        };
        if src.link.is_some() {
            // The link is observed again after the read: a link replaced or
            // retargeted meanwhile means the read is not about this host's
            // default.
            let again = self.locale_link(res, conf, audit)?;
            if again.0 != ObjKind::Symlink || again.1 != 0 || again.2 != src.link {
                return Err(SinterError::apply(format!(
                    "{}: the default locale could not be observed: {} changed while it was read; refusing",
                    res.id, conf
                )));
            }
        }
        let Some(bytes) = bytes else {
            return Ok((BTreeMap::new(), src));
        };
        let map = crate::locale::parse_conf(&bytes).map_err(|why| {
            SinterError::apply(format!(
                "{}: the default locale could not be observed: {} is not understood ({}); Sinter does not guess what it sets",
                res.id,
                src.describe(conf),
                why
            ))
        })?;
        Ok((map, src))
    }

    /// Every declared locale other than `C`/`POSIX` must be one `locale -a`
    /// lists (codesets compared loosely). In plan, a locale an earlier
    /// planned change may still provide is a note instead; apply checks
    /// again. Read-only.
    fn locale_available(&mut self, res: &FrozenResource, spec: &LocaleSpec) -> Result<Vec<String>> {
        let wanted: Vec<&String> = spec
            .settings
            .values()
            .filter(|v| !crate::locale::always_available(v))
            .collect();
        if wanted.is_empty() {
            return Ok(Vec::new());
        }
        let deferral = (self.opts.mode == Mode::Plan)
            .then(|| self.planned.affecting_subtree(LOCALE_DIR))
            .flatten();
        if !self.fs.executable_present(LIST_TOOL, false)? {
            if let Some(why) = &deferral {
                return Ok(vec![format!(
                    "{} was not found now, so the declared locales are checked at apply ({})",
                    LIST_TOOL, why
                )]);
            }
            return Err(SinterError::apply(format!(
                "{}: the installed locales could not be listed: {} was not found; nothing was changed",
                res.id, LIST_TOOL
            )));
        }
        let out = self.fs.locale_list()?;
        let what = format!(
            "{}: the installed locales could not be listed: locale -a",
            res.id
        );
        match &out.completion {
            Completion::Exited(0) => {}
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
        let have = crate::locale::parse_locale_list(&out.stdout).map_err(|why| {
            SinterError::apply(format!(
                "{}: its output is not a list of locales ({})",
                what, why
            ))
        })?;
        let mut notes = Vec::new();
        for v in wanted {
            if have.contains(&crate::locale::availability_key(v)) {
                continue;
            }
            if let Some(why) = &deferral {
                notes.push(format!(
                    "locale {} is not installed on this host now; checked again at apply ({})",
                    shown(v),
                    why
                ));
                continue;
            }
            return Err(SinterError::apply(format!(
                "{}: locale {} is not installed on this host; install or generate it first (a language-pack / glibc-langpack package, or locale-gen) — Sinter does not do that",
                res.id,
                shown(v)
            )));
        }
        Ok(notes)
    }

    /// Audit: observe and compare, nothing else. One drift dimension per
    /// declared key that differs (`LANG`, `LC_TIME`, ...).
    pub(crate) fn locale_audit(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<Vec<(String, String, String)>> {
        let spec = self.locale_evaluate(res, item, sensitive)?;
        let path = self.locale_conf(res)?;
        let (current, _) = self.locale_read(res, path, true)?;
        Ok(spec
            .differing(&current)
            .into_iter()
            .map(|k| {
                let observed = crate::locale::shown_setting(&current, &k);
                let desired = spec.settings[&k].clone();
                (k, observed, desired)
            })
            .collect())
    }

    pub(crate) fn run_locale(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let sensitive = res.sensitive || res.derived_sensitive;
        let spec = self.locale_evaluate(res, item, sensitive)?;
        // A sensitive resource names neither a value nor what was read.
        let hide = |e: SinterError| -> SinterError {
            if sensitive && e.kind != ErrorKind::Unknown {
                let mut out = e;
                out.message = format!(
                    "{}: the locale could not be handled (details withheld for a sensitive resource)",
                    res.id
                );
                out
            } else {
                e
            }
        };
        let path = self.locale_conf(res).map_err(hide)?;
        let (current, src) = self
            .locale_read(res, path, false)
            .map_err(before_any_change)
            .map_err(hide)?;
        if spec.differing(&current).is_empty() {
            return Ok(unchanged_result(res, "default locale already set"));
        }
        let mut notes = self
            .locale_available(res, &spec)
            .map_err(before_any_change)
            .map_err(hide)?;
        self.osbase_tool(res, TOOL, "locale", false).map_err(hide)?;

        let mut r = changed_result_sensitive(res, sensitive);
        r.diff = Some(Diff {
            body: if sensitive {
                DiffBody::Redacted
            } else {
                DiffBody::Summary {
                    current: summary(&spec, &current),
                    desired: summary(&spec, &spec.settings),
                }
            },
        });
        if !sensitive {
            r.notes.append(&mut notes);
        }
        r.notes.push(SESSIONS_NOTE.to_string());
        if self.opts.mode == Mode::Plan {
            return Ok(r);
        }

        if !self.fs.runs_as_root() {
            return Err(SinterError::apply(format!(
                "{}: locale needs root: connect as root or use --sudo; nothing was changed",
                res.id
            )));
        }
        if !self.osbase_exec(
            res,
            &mut r,
            TOOL,
            spec.set_args(),
            TIMEOUT_SECS,
            sensitive,
            WHAT,
            SUBJECT,
            false,
        )? {
            return Ok(r);
        }

        // Exit 0 is only the tool's claim. The file decides, for the
        // declared keys only.
        match self.locale_read(res, path, false) {
            Ok((_, after_src)) if after_src != src => {
                // localectl replaced or removed the OS's link (or made one):
                // the default may now be kept in two places. Sinter does not
                // write either file, so it says so and does not claim success.
                r.execution = Execution::Failed;
                r.change = Change::Changed;
                r.verification = Verification::Failed;
                r.reason = Some(if sensitive {
                    format!(
                        "localectl changed how {} is kept; Sinter does not restore it (details withheld for a sensitive resource)",
                        path
                    )
                } else {
                    format!(
                        "localectl changed how {} is kept: before {}, now {}; Sinter does not restore it",
                        path,
                        src.describe(path),
                        after_src.describe(path)
                    )
                });
            }
            Ok((after, after_src)) => {
                let path = after_src.read;
                let wrong = spec.differing(&after);
                if wrong.is_empty() {
                    r.change = Change::Changed;
                    r.verification = Verification::Verified;
                } else {
                    r.execution = Execution::Failed;
                    r.change = if after == current {
                        Change::Possible
                    } else {
                        Change::Changed
                    };
                    r.verification = Verification::Failed;
                    r.reason = Some(if sensitive {
                        format!(
                            "localectl reported success but {} does not set the declared value of {}",
                            path,
                            wrong.join(", ")
                        )
                    } else {
                        format!(
                            "localectl reported success but {} has {} (declared: {})",
                            path,
                            wrong
                                .iter()
                                .map(|k| format!(
                                    "{}={}",
                                    k,
                                    crate::locale::shown_setting(&after, k)
                                ))
                                .collect::<Vec<_>>()
                                .join(" "),
                            wrong
                                .iter()
                                .map(|k| format!("{}={}", k, spec.settings[k]))
                                .collect::<Vec<_>>()
                                .join(" ")
                        )
                    });
                }
                // Keys Sinter does not manage are not checked; say when
                // the tool changed or dropped one.
                let lost: Vec<&String> = current
                    .iter()
                    .filter(|(k, v)| !spec.settings.contains_key(*k) && after.get(*k) != Some(*v))
                    .map(|(k, _)| k)
                    .collect();
                if !lost.is_empty() {
                    r.notes.push(format!(
                        "localectl changed or removed settings Sinter does not manage: {}; declare them to keep them",
                        lost.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")
                    ));
                }
            }
            Err(e) => reobservation_failed(&mut r, &e, WHAT, SUBJECT, sensitive),
        }
        Ok(r)
    }
}
