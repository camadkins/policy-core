use std::fmt;

/// Errors that can occur in the policy enforcement crate.
#[derive(Debug)]
pub enum Error {
    /// A policy violation occurred
    Violation(Violation),
}

impl fmt::Display for Error {
    /// Formats the error as a human-readable policy message.
    ///
    /// Violations are displayed with the prefix "Policy violation: " followed by the violation's formatted representation.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::{Error, Violation, ViolationKind};
    ///
    /// let v = Violation::new(ViolationKind::Unauthenticated, "token missing");
    /// let e = Error::Violation(v);
    /// assert_eq!(format!("{}", e), "Policy violation: Unauthenticated: token missing");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Violation(v) => write!(f, "Policy violation: {}", v),
        }
    }
}

impl std::error::Error for Error {}

impl From<Violation> for Error {
    /// Converts a `Violation` into the crate's top-level `Error`.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::{Error, Violation, ViolationKind};
    ///
    /// let v = Violation::new(ViolationKind::Unauthenticated, "missing token");
    /// let e: Error = v.into();
    /// match e {
    ///     Error::Violation(v) => assert_eq!(v.kind, ViolationKind::Unauthenticated),
    ///     _ => panic!("expected violation"),
    /// }
    /// ```
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
    /// Create a `Violation` with the specified kind and message.
    ///
    /// `kind` specifies the category of the violation; `message` is a human-readable explanation.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::{Violation, ViolationKind};
    ///
    /// let v = Violation::new(ViolationKind::Unauthenticated, "authentication required");
    /// assert_eq!(v.kind, ViolationKind::Unauthenticated);
    /// assert_eq!(v.message, "authentication required");
    /// ```
    pub fn new(kind: ViolationKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for Violation {
    /// Formats the violation as "<kind>: <message>".
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::{Violation, ViolationKind};
    ///
    /// let v = Violation::new(ViolationKind::Unauthenticated, "missing token");
    /// assert_eq!(format!("{}", v), "Unauthenticated: missing token");
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for Violation {}

impl From<crate::SanitizationError> for Violation {
    fn from(err: crate::SanitizationError) -> Self {
        Violation::new(
            ViolationKind::Unauthenticated,
            format!("Sanitization failed: {}", err),
        )
    }
}

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
    /// Logging capability was not granted
    MissingLogCapability,
    /// HTTP capability was not granted
    MissingHttpCapability,
    /// Audit capability was not granted
    MissingAuditCapability,
}

impl fmt::Display for ViolationKind {
    /// Formats a `ViolationKind` into a human-readable label.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::ViolationKind;
    ///
    /// assert_eq!(format!("{}", ViolationKind::Unauthenticated), "Unauthenticated");
    /// assert_eq!(
    ///     format!("{}", ViolationKind::Unauthorized { action: "delete" }),
    ///     "Unauthorized for 'delete'"
    /// );
    /// assert_eq!(
    ///     format!("{}", ViolationKind::MissingLogCapability),
    ///     "Missing logging capability"
    /// );
    /// assert_eq!(
    ///     format!("{}", ViolationKind::MissingHttpCapability),
    ///     "Missing HTTP capability"
    /// );
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ViolationKind::Unauthenticated => write!(f, "Unauthenticated"),
            ViolationKind::Unauthorized { action } => write!(f, "Unauthorized for '{}'", action),
            ViolationKind::MissingLogCapability => write!(f, "Missing logging capability"),
            ViolationKind::MissingHttpCapability => write!(f, "Missing HTTP capability"),
            ViolationKind::MissingAuditCapability => write!(f, "Missing audit capability"),
        }
    }
}
