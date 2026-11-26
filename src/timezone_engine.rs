//! Plan, apply and audit of `timezone`.
//!
//! Observation is read-only: the `lstat` of `/etc/localtime` and, when it is
//! a symbolic link, its target (`readlink`), which must name a zone below
//! `/usr/share/zoneinfo`. A copied zone file, a missing link and any other
//! target are observation errors: Sinter does not guess a zone. The change
//! is `timedatectl set-timezone <name>`; its exit code never decides
//! success: the link is observed again and must name the declared zone.
//! Nothing here touches the clock, NTP, the RTC mode or a service.

use crate::engine::{Engine, Mode};
use crate::error::{ErrorKind, Result, SinterError};
use crate::expressions::EvalVal;
use crate::model::FrozenResource;
use crate::osbase::{before_any_change, reobservation_failed, shown};
use crate::resources::{changed_result_sensitive, unchanged_result};
use crate::result::{Change, Diff, DiffBody, Execution, ResourceResult, Verification};
use crate::targetfs::ObjKind;
use crate::timer_engine::plain_values;
use crate::timezone::{LOCALTIME, PROGRAMS_NOTE, TIMEOUT_SECS, TOOL};

const WHAT: &str = "timedatectl set-timezone";
const SUBJECT: &str = "the time zone";

impl Engine {
    fn timezone_evaluate(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<String> {
        let vals = self.eval_with(res, item)?;
        crate::timezone::name_from_values(&plain_values(&vals)?, &res.id, sensitive)
    }

    /// The zone `/etc/localtime` names. Read-only. Only a symbolic link into
    /// `/usr/share/zoneinfo` is a state; everything else is an error.
    fn timezone_observe(&mut self, res: &FrozenResource) -> Result<String> {
        let st = self.observe_stat(res, LOCALTIME)?;
        match st.kind {
            ObjKind::Symlink => {}
            ObjKind::Absent => {
                return Err(SinterError::apply(format!(
                    "{}: the time zone could not be observed: {} does not exist; Sinter does not guess a zone (the system default is not known)",
                    res.id, LOCALTIME
                )))
            }
            ObjKind::File => {
                return Err(SinterError::apply(format!(
                    "{}: the time zone could not be observed: {} is a regular file (a copied zone file), not a symbolic link into /usr/share/zoneinfo; Sinter does not guess a zone from a copied file. Replace it with the link (for example with timedatectl set-timezone) first",
                    res.id, LOCALTIME
                )))
            }
            other => {
                return Err(SinterError::apply(format!(
                    "{}: the time zone could not be observed: {} exists as {}, not as a symbolic link into /usr/share/zoneinfo",
                    res.id,
                    LOCALTIME,
                    other.describe()
                )))
            }
        }
        let target = self.observe_readlink(res, LOCALTIME)?;
        crate::timezone::zone_from_link(&target).map_err(|why| {
            SinterError::apply(format!(
                "{}: the time zone could not be observed: the link {} -> {} is not understood ({}); Sinter does not guess a zone",
                res.id,
                LOCALTIME,
                shown(&target),
                why
            ))
        })
    }

    /// The declared zone must exist as a regular file below
    /// `/usr/share/zoneinfo`. In plan, a zone file an earlier planned change
    /// may still provide (for example a `tzdata` package) is a note
    /// instead; apply checks again.
    fn timezone_zone_file(&mut self, res: &FrozenResource, name: &str) -> Result<Vec<String>> {
        let path = crate::timezone::zone_file(name);
        match self.observe_stat(res, &path)?.kind {
            ObjKind::File => Ok(Vec::new()),
            ObjKind::Absent => {
                if self.opts.mode == Mode::Plan {
                    if let Some(why) = self.planned.affecting(&path) {
                        return Ok(vec![format!(
                            "the zone file {} does not exist now; checked again at apply ({})",
                            path, why
                        )]);
                    }
                }
                Err(SinterError::apply(format!(
                    "{}: time zone {} is not installed on this host ({} does not exist); install the time zone data (tzdata) first — Sinter does not do that",
                    res.id,
                    shown(name),
                    path
                )))
            }
            other => Err(SinterError::apply(format!(
                "{}: {} exists as {}; a zone must be a regular file",
                res.id,
                path,
                other.describe()
            ))),
        }
    }

    /// Audit: observe and compare, nothing else. The drift (`observed`,
    /// `desired`) when the zone differs.
    pub(crate) fn timezone_audit(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
        sensitive: bool,
    ) -> Result<Option<(String, String)>> {
        let name = self.timezone_evaluate(res, item, sensitive)?;
        let current = self.timezone_observe(res)?;
        Ok((current != name).then_some((current, name)))
    }

    pub(crate) fn run_timezone(
        &mut self,
        res: &FrozenResource,
        item: Option<&EvalVal>,
    ) -> Result<ResourceResult> {
        let sensitive = res.sensitive || res.derived_sensitive;
        let name = self.timezone_evaluate(res, item, sensitive)?;
        // A sensitive resource names neither the zone nor what was read.
        let hide = |e: SinterError| -> SinterError {
            if sensitive && e.kind != ErrorKind::Unknown {
                let mut out = e;
                out.message = format!(
                    "{}: the timezone could not be handled (details withheld for a sensitive resource)",
                    res.id
                );
                out
            } else {
                e
            }
        };
        let current = self
            .timezone_observe(res)
            .map_err(before_any_change)
            .map_err(hide)?;
        if current == name {
            return Ok(unchanged_result(res, "time zone already set"));
        }
        let mut notes = self
            .timezone_zone_file(res, &name)
            .map_err(before_any_change)
            .map_err(hide)?;
        self.osbase_tool(res, TOOL, "timezone", false)
            .map_err(hide)?;

        let mut r = changed_result_sensitive(res, sensitive);
        r.diff = Some(Diff {
            body: if sensitive {
                DiffBody::Redacted
            } else {
                DiffBody::Summary {
                    current: current.clone(),
                    desired: name.clone(),
                }
            },
        });
        r.notes.append(&mut notes);
        r.notes.push(PROGRAMS_NOTE.to_string());
        if self.opts.mode == Mode::Plan {
            return Ok(r);
        }

        if !self.fs.runs_as_root() {
            return Err(SinterError::apply(format!(
                "{}: timezone needs root: connect as root or use --sudo; nothing was changed",
                res.id
            )));
        }
        let args = crate::timezone::set_args(&name);
        if !self.osbase_exec(
            res,
            &mut r,
            TOOL,
            args,
            TIMEOUT_SECS,
            sensitive,
            WHAT,
            SUBJECT,
            false,
        )? {
            return Ok(r);
        }

        // Exit 0 is only the tool's claim. The link decides.
        match self.timezone_observe(res) {
            Ok(after) if after == name => {
                r.change = Change::Changed;
                r.verification = Verification::Verified;
            }
            Ok(after) => {
                r.execution = Execution::Failed;
                r.change = if after == current {
                    Change::Possible
                } else {
                    Change::Changed
                };
                r.verification = Verification::Failed;
                r.reason = Some(if sensitive {
                    "timedatectl reported success but /etc/localtime does not name the declared zone"
                        .to_string()
                } else {
                    format!(
                        "timedatectl reported success but /etc/localtime names {} (declared: {})",
                        shown(&after),
                        shown(&name)
                    )
                });
            }
            Err(e) => reobservation_failed(&mut r, &e, WHAT, SUBJECT, sensitive),
        }
        Ok(r)
    }
}
