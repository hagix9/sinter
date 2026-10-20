//! The hosts a run may touch once `--limit` has been applied (DESIGN §19.2).
//!
//! [`Limited`] is the only thing [`crate::inventory_targets`] accepts, and the
//! only way to make one is [`limit`]: a path that forgets `--limit` does not
//! compile, so a run cannot silently go back to every host the recipes
//! target. The fields are private to this module for the same reason.

use sinter::error::Result;
use sinter::inventory::{match_limit, Inventory, ParsedLimit, Resolution};
use std::collections::BTreeSet;

/// The recipes' target resolutions with `--limit` applied, the hosts that may
/// be touched (`None`: no `--limit`) and the items as given, for display.
pub(crate) struct Limited {
    resolutions: Vec<Resolution>,
    allowed: Option<BTreeSet<String>>,
    items: Option<Vec<String>>,
}

impl Limited {
    /// Per recipe, every inventory host; `selected()` is what will run.
    pub(crate) fn resolutions(&self) -> &[Resolution] {
        &self.resolutions
    }

    /// `Some` exactly when `--limit` was applied.
    pub(crate) fn allowed(&self) -> Option<&BTreeSet<String>> {
        self.allowed.as_ref()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<Resolution>,
        Option<BTreeSet<String>>,
        Option<Vec<String>>,
    ) {
        (self.resolutions, self.allowed, self.items)
    }
}

/// Apply `--limit` to the resolutions: refuse a `--limit` that names nothing
/// the inventory defines, is ambiguous, or would run nothing; otherwise leave
/// out every targeted host that is not named. Always call it, with or without
/// `--limit`: without one the resolutions come back untouched.
pub(crate) fn limit(
    inv: &Inventory,
    mut resolutions: Vec<Resolution>,
    limit: &ParsedLimit,
) -> Result<Limited> {
    if !limit.given() {
        return Ok(Limited {
            resolutions,
            allowed: None,
            items: None,
        });
    }
    let allowed = match_limit(inv, &resolutions, limit)?;
    #[cfg(test)]
    let unmarked = resolutions.clone();
    for r in &mut resolutions {
        r.apply_allowed(&allowed);
    }
    #[cfg(test)]
    let (resolutions, allowed) = tests::tamper(resolutions, unmarked, allowed);
    #[cfg(not(test))]
    let allowed = Some(allowed);
    Ok(Limited {
        resolutions,
        allowed,
        items: Some(limit.items()),
    })
}

/// Test hooks that corrupt a `Limited`, to prove the checks in
/// `inventory_targets` stop a run before any host is resolved or contacted.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::Cell;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Tamper {
        None,
        /// The marks of the hosts left out are lost; `allowed` is intact.
        DropMarks,
        /// `allowed` is lost (as if `--limit` were not applied) although the
        /// marks are intact.
        ForgetAllowed,
    }

    thread_local! {
        static TAMPER: Cell<Tamper> = const { Cell::new(Tamper::None) };
    }

    pub(crate) fn set(t: Tamper) {
        TAMPER.with(|c| c.set(t));
    }

    pub(super) fn tamper(
        marked: Vec<Resolution>,
        unmarked: Vec<Resolution>,
        allowed: BTreeSet<String>,
    ) -> (Vec<Resolution>, Option<BTreeSet<String>>) {
        match TAMPER.with(Cell::get) {
            Tamper::None => (marked, Some(allowed)),
            Tamper::DropMarks => (unmarked, Some(allowed)),
            Tamper::ForgetAllowed => (marked, None),
        }
    }
}
