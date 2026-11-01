//! The call values the two `TargetFs` plugin channels accept, and the
//! classification of their outcomes (DESIGN §38.8, §38.10).
//!
//! Neither channel accepts a program or argv. A call is built here, only from
//! a [`VerifiedOp`] (which only verification can produce) of the matching
//! class that the Owner's trust file enabled, with every operand checked
//! again just before dispatch.

use super::verify::{operand_ok, ArgToken, OpClass, VerifiedOp};
use crate::error::{Result, SinterError};
use crate::executor::{Completion, Output};
use std::collections::BTreeMap;

/// Render an operation's argv with checked operands. The message names the
/// slot, never the value.
fn render(op: &VerifiedOp, values: &BTreeMap<String, String>) -> Result<Vec<String>> {
    let operand = |slot: &str| -> Result<String> {
        let max = op.slot_max_len(slot).ok_or_else(|| {
            SinterError::apply(format!(
                "plugin operation {}: undeclared slot {}",
                op.id(),
                slot
            ))
        })?;
        let v = values.get(slot).ok_or_else(|| {
            SinterError::apply(format!(
                "plugin operation {}: no value for slot {}",
                op.id(),
                slot
            ))
        })?;
        if !operand_ok(v, max) {
            return Err(SinterError::apply(format!(
                "plugin operation {}: the value for slot {} is not a valid operand (not shown)",
                op.id(),
                slot
            )));
        }
        Ok(v.clone())
    };
    op.argv()
        .iter()
        .map(|t| match t {
            ArgToken::Literal(l) => Ok(l.clone()),
            ArgToken::Slot(s) => operand(s),
            ArgToken::Prefixed { prefix, slot } => Ok(format!("{}{}", prefix, operand(slot)?)),
        })
        .collect()
}

macro_rules! call_type {
    ($name:ident, $class:expr, $what:literal) => {
        /// A dispatchable plugin operation. Only [`Self::new`] builds it.
        #[derive(Debug)]
        pub struct $name {
            program: String,
            argv: Vec<String>,
            timeout_secs: u64,
            sensitive: bool,
            op_id: String,
        }

        impl $name {
            pub(crate) fn new(
                op: &VerifiedOp,
                values: &BTreeMap<String, String>,
                sensitive: bool,
            ) -> Result<Self> {
                if op.class() != $class || !op.is_enabled() {
                    return Err(SinterError::apply(format!(
                        "internal error: plugin operation {} is not {}",
                        op.id(),
                        $what
                    )));
                }
                Ok($name {
                    program: op.program().to_string(),
                    argv: render(op, values)?,
                    timeout_secs: op.timeout_secs(),
                    sensitive,
                    op_id: op.id().to_string(),
                })
            }
            pub(crate) fn program(&self) -> &str {
                &self.program
            }
            pub(crate) fn argv(&self) -> &[String] {
                &self.argv
            }
            pub(crate) fn timeout_secs(&self) -> u64 {
                self.timeout_secs
            }
            pub(crate) fn sensitive(&self) -> bool {
                self.sensitive
            }
            pub(crate) fn op_id(&self) -> &str {
                &self.op_id
            }
        }
    };
}

call_type!(
    ObserveCall,
    OpClass::Observe,
    "an attested observe operation"
);
call_type!(MutateCall, OpClass::Mutate, "an allowed mutate operation");

/// What an observation established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observed {
    State(String),
    /// The observation failed or its result is not one the catalog lists.
    Error(String),
}

/// Classify an observation (DESIGN §38.10): a listed exit code gives its
/// state, or with an output map the trimmed output must equal one template
/// exactly. Everything else is an error. Standard error is never read, and
/// standard output only through the closed map.
pub(crate) fn classify_observation(
    op: &VerifiedOp,
    values: &BTreeMap<String, String>,
    out: &Output,
) -> Observed {
    match &out.completion {
        Completion::Exited(c) => match op.exit_map().get(c) {
            None => Observed::Error(format!(
                "observation {} ended with exit code {}, which the catalog does not list",
                op.id(),
                c
            )),
            Some(state) if op.stdout_map().is_empty() => Observed::State(state.clone()),
            Some(_) => {
                if out.stdout_truncated {
                    return Observed::Error(format!("observation {}: output truncated", op.id()));
                }
                let got = String::from_utf8_lossy(&out.stdout);
                let got = got.trim_end_matches(['\n', '\r']);
                for (tmpl, state) in op.stdout_map() {
                    let mut want = tmpl.clone();
                    for (k, v) in values {
                        want = want.replace(&format!("{{{}}}", k), v);
                    }
                    if got == want {
                        return Observed::State(state.clone());
                    }
                }
                Observed::Error(format!(
                    "observation {}: output is not one the catalog lists (not shown)",
                    op.id()
                ))
            }
        },
        Completion::Signaled(sig) => Observed::Error(format!(
            "observation {} was terminated by signal {}",
            op.id(),
            sig
        )),
        Completion::Indeterminate { .. } => Observed::Error(format!(
            "observation {}: completion unknown (timeout or lost connection)",
            op.id()
        )),
    }
}

/// How a dispatched mutation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutated {
    /// A listed success exit code.
    Ok,
    /// An exit code the catalog does not list as success: the change may
    /// have been partly made.
    Failed(String),
    /// Signal, timeout or lost connection after dispatch: unknown.
    Unknown(String),
}

pub(crate) fn classify_mutation(op: &VerifiedOp, out: &Output) -> Mutated {
    match &out.completion {
        Completion::Exited(c) if op.exit_map().contains_key(c) => Mutated::Ok,
        Completion::Exited(c) => Mutated::Failed(format!(
            "operation {} ended with exit code {}, which the catalog does not list as success; the change may have been partly made (not retried)",
            op.id(),
            c
        )),
        Completion::Signaled(sig) => Mutated::Unknown(format!(
            "operation {} was terminated by signal {} after dispatch; whether it changed the target is unknown (not retried)",
            op.id(),
            sig
        )),
        Completion::Indeterminate { .. } => Mutated::Unknown(format!(
            "operation {}: completion unknown after dispatch (timeout or lost connection); whether it changed the target is unknown (not retried)",
            op.id()
        )),
    }
}
