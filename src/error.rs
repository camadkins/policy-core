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
#[derive(Debug, Clone, PartialEq)]
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

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::Secret;
    use proptest::prelude::*;

    // Strategy: Generate arbitrary ViolationKind
    fn arb_violation_kind() -> impl Strategy<Value = ViolationKind> {
        prop_oneof![
            Just(ViolationKind::Unauthenticated),
            prop_oneof![
                Just("log"),
                Just("http"),
                Just("audit"),
                Just("read"),
                Just("write"),
            ]
            .prop_map(|action| ViolationKind::Unauthorized { action }),
            Just(ViolationKind::MissingLogCapability),
            Just(ViolationKind::MissingHttpCapability),
            Just(ViolationKind::MissingAuditCapability),
        ]
    }

    proptest! {
        /// Property: Violation Display never leaks secrets beyond what's in the message
        #[test]
        fn proptest_violation_display_no_secret_leakage(
            kind in arb_violation_kind(),
            secret_value in prop::string::string_regex("[A-Z0-9]{10,20}").unwrap(),
            safe_message in prop::string::string_regex("[a-z ]{5,30}").unwrap()
        ) {
            // Create a secret (should never appear in violation display)
            let _secret = Secret::new(secret_value.clone());

            // Create a violation with a safe message that does NOT contain the secret
            let violation = Violation::new(kind, safe_message.clone());

            // Display the violation
            let display_output = format!("{}", violation);

            // The secret value should NOT appear in the display output
            // (since we deliberately didn't put it in the message)
            prop_assert!(
                !display_output.contains(&secret_value),
                "Violation display should not leak secret '{}', got: '{}'",
                secret_value,
                display_output
            );

            // The display should contain the safe message we provided
            prop_assert!(
                display_output.contains(&safe_message),
                "Violation display should contain message '{}', got: '{}'",
                safe_message,
                display_output
            );
        }

        /// Property: ViolationKind Display output matches expected patterns
        #[test]
        fn proptest_violation_kind_display_stable(kind in arb_violation_kind()) {
            let display_output = format!("{}", kind);

            // Verify the display matches expected patterns
            match kind {
                ViolationKind::Unauthenticated => {
                    prop_assert_eq!(display_output, "Unauthenticated");
                }
                ViolationKind::Unauthorized { action } => {
                    prop_assert!(display_output.starts_with("Unauthorized for '"));
                    prop_assert!(display_output.ends_with('\''));
                    prop_assert!(display_output.contains(action));
                }
                ViolationKind::MissingLogCapability => {
                    prop_assert_eq!(display_output, "Missing logging capability");
                }
                ViolationKind::MissingHttpCapability => {
                    prop_assert_eq!(display_output, "Missing HTTP capability");
                }
                ViolationKind::MissingAuditCapability => {
                    prop_assert_eq!(display_output, "Missing audit capability");
                }
            }
        }
    }
}
