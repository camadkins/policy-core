use std::fmt;

/// Errors that can occur in the policy enforcement crate.
#[derive(Debug)]
pub enum Error {
    /// A policy violation occurred
    Violation(Violation),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Violation(v) => write!(f, "Policy violation: {}", v),
        }
    }
}

impl std::error::Error for Error {}

impl From<Violation> for Error {
    fn from(v: Violation) -> Self {
        Error::Violation(v)
    }
}

/// A policy violation with details about what failed.
#[derive(Debug)]
pub struct Violation {
    /// The kind of violation that occurred
    pub kind: ViolationKind,
    /// Human-readable message explaining the violation
    pub message: String,
}

impl Violation {
    /// Creates a new violation.
    pub fn new(kind: ViolationKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for Violation {}

/// The kind of policy violation.
#[derive(Debug, PartialEq)]
pub enum ViolationKind {
    /// Authentication is required but missing
    Unauthenticated,
    /// Authorization failed for a specific action
    Unauthorized {
        /// The action that was not authorized
        action: &'static str,
    },
}

impl fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ViolationKind::Unauthenticated => write!(f, "Unauthenticated"),
            ViolationKind::Unauthorized { action } => write!(f, "Unauthorized for '{}'", action),
        }
    }
}
