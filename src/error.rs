use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Schema,
    Connect,
    Plan,
    Apply,
    Indeterminate,
    /// A runtime value is Unknown in the current mode (distinct from failure).
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationState {
    None,
    Changed,
    Possible,
}

impl ErrorKind {
    pub fn exit_code(self) -> i32 {
        match self {
            ErrorKind::Schema => 2,
            ErrorKind::Connect => 3,
            ErrorKind::Plan => 4,
            ErrorKind::Apply => 5,
            ErrorKind::Indeterminate => 6,
            // Unknown is never a terminal CLI failure by itself.
            ErrorKind::Unknown => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SinterError {
    pub kind: ErrorKind,
    pub message: String,
    pub mutation: MutationState,
}

impl SinterError {
    pub fn schema(msg: impl Into<String>) -> Self {
        SinterError {
            kind: ErrorKind::Schema,
            message: msg.into(),
            mutation: MutationState::None,
        }
    }
    pub fn connect(msg: impl Into<String>) -> Self {
        SinterError {
            kind: ErrorKind::Connect,
            message: msg.into(),
            mutation: MutationState::None,
        }
    }
    pub fn plan(msg: impl Into<String>) -> Self {
        SinterError {
            kind: ErrorKind::Plan,
            message: msg.into(),
            mutation: MutationState::None,
        }
    }
    pub fn apply(msg: impl Into<String>) -> Self {
        SinterError {
            kind: ErrorKind::Apply,
            message: msg.into(),
            mutation: MutationState::None,
        }
    }
    pub fn indeterminate(msg: impl Into<String>) -> Self {
        SinterError {
            kind: ErrorKind::Indeterminate,
            message: msg.into(),
            mutation: MutationState::Possible,
        }
    }
    pub fn unknown(msg: impl Into<String>) -> Self {
        SinterError {
            kind: ErrorKind::Unknown,
            message: msg.into(),
            mutation: MutationState::None,
        }
    }

    pub fn changed(mut self) -> Self {
        self.mutation = MutationState::Changed;
        self
    }

    pub fn possible(mut self) -> Self {
        self.mutation = MutationState::Possible;
        self
    }
}

impl fmt::Display for SinterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SinterError {}

pub type Result<T> = std::result::Result<T, SinterError>;
