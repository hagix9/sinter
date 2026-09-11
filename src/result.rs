#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Execution {
    NotRun,
    Succeeded,
    Failed,
    Indeterminate,
}

impl Execution {
    pub fn label(self) -> &'static str {
        match self {
            Execution::NotRun => "not_run",
            Execution::Succeeded => "succeeded",
            Execution::Failed => "failed",
            Execution::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    None,
    Changed,
    Possible,
}

impl Change {
    pub fn label(self) -> &'static str {
        match self {
            Change::None => "none",
            Change::Changed => "changed",
            Change::Possible => "possible",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    NotApplicable,
    NotPerformed,
    Verified,
    Failed,
    Unknown,
}

impl Verification {
    pub fn label(self) -> &'static str {
        match self {
            Verification::NotApplicable => "not_applicable",
            Verification::NotPerformed => "not_performed",
            Verification::Verified => "verified",
            Verification::Failed => "failed",
            Verification::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Normal,
    SkippedByCondition,
    GuardSatisfied,
    BlockedByDependency,
    BlockedByFailFast,
}

impl Disposition {
    pub fn label(self) -> &'static str {
        match self {
            Disposition::Normal => "normal",
            Disposition::SkippedByCondition => "skipped_by_condition",
            Disposition::GuardSatisfied => "guard_satisfied",
            Disposition::BlockedByDependency => "blocked_by_dependency",
            Disposition::BlockedByFailFast => "blocked_by_fail_fast",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffBody {
    Text {
        removed: Vec<String>,
        added: Vec<String>,
    },
    Summary {
        current: String,
        desired: String,
    },
    Redacted,
}

#[derive(Debug, Clone)]
pub struct Diff {
    pub body: DiffBody,
}

#[derive(Debug, Clone)]
pub struct ResourceResult {
    pub id: String,
    pub type_: String,
    pub origin: String,
    pub execution: Execution,
    pub change: Change,
    pub verification: Verification,
    pub disposition: Disposition,
    pub reason: Option<String>,
    pub unknown: bool,
    pub sensitive: bool,
    pub diff: Option<Diff>,
    pub notes: Vec<String>,
    pub handler_notifications: Vec<String>,
    pub loop_index: Option<usize>,
}

impl ResourceResult {
    pub fn skipped(id: &str, type_: &str, origin: &str) -> Self {
        ResourceResult {
            id: id.to_string(),
            type_: type_.to_string(),
            origin: origin.to_string(),
            execution: Execution::NotRun,
            change: Change::None,
            verification: Verification::NotPerformed,
            disposition: Disposition::SkippedByCondition,
            reason: Some("condition evaluated to false".to_string()),
            unknown: false,
            sensitive: false,
            diff: None,
            notes: Vec::new(),
            handler_notifications: Vec::new(),
            loop_index: None,
        }
    }

    /// Whether this result satisfies a dependent resource's dependency.
    pub fn satisfies_dependency(&self) -> bool {
        match self.disposition {
            Disposition::GuardSatisfied => true,
            Disposition::SkippedByCondition
            | Disposition::BlockedByDependency
            | Disposition::BlockedByFailFast => false,
            Disposition::Normal => {
                self.execution == Execution::Succeeded
                    && self.verification != Verification::Failed
                    && self.verification != Verification::Unknown
            }
        }
    }

    /// Whether this result represents an unresolved/unknown dependency rather
    /// than a definite block. In plan mode a command that was not executed is
    /// Unknown, so its dependents cannot be predicted either.
    pub fn is_unknown_dependency(&self) -> bool {
        self.unknown
            || (self.disposition == Disposition::Normal
                && self.execution == Execution::Succeeded
                && self.verification == Verification::Unknown)
    }

    pub fn is_failure(&self) -> bool {
        self.execution == Execution::Failed
    }

    pub fn is_indeterminate(&self) -> bool {
        self.execution == Execution::Indeterminate
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerOutcomeState {
    NotRun,
    Succeeded,
    Failed,
    Indeterminate,
}

#[derive(Debug, Clone)]
pub struct HandlerResult {
    pub id: String,
    pub service: String,
    pub action: String,
    pub state: HandlerOutcomeState,
    pub reason: Option<String>,
    pub sensitive: bool,
}
