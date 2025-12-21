/// A policy requirement that must be satisfied.
///
/// This enum represents all possible policy requirements.
/// Policies are evaluated during `PolicyGate::build()`.
#[derive(Debug)]
pub enum PolicyReq {
    /// Requires an authenticated principal
    Authenticated,
    /// Requires authorization for a specific action
    Authorized { action: &'static str },
}

/// Policy requiring authentication.
///
/// Use this to require that a principal is present in the request metadata.
pub struct Authenticated;

/// Policy requiring authorization for a specific action.
///
/// Use this to require that the principal is authorized to perform
/// a particular action (e.g., "log", "write", "admin").
pub struct Authorized {
    action: &'static str,
}

impl Authorized {
    /// Creates an `Authorized` policy requirement for the specified action.
    ///
    /// The returned `Authorized` indicates that a principal must be authorized to perform `action`.
    ///
    /// # Examples
    ///
    /// ```
    /// let req = Authorized::for_action("read:items");
    /// assert_eq!(req.action, "read:items");
    /// ```
    pub fn for_action(action: &'static str) -> Self {
        Self { action }
    }
}

// Conversions to PolicyReq
impl From<Authenticated> for PolicyReq {
    /// Convert an `Authenticated` marker into the corresponding `PolicyReq::Authenticated` variant.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::policy::{PolicyReq, Authenticated};
    ///
    /// let req: PolicyReq = Authenticated.into();
    /// assert!(matches!(req, PolicyReq::Authenticated));
    /// ```
    fn from(_: Authenticated) -> Self {
        PolicyReq::Authenticated
    }
}

impl From<Authorized> for PolicyReq {
    /// Converts an `Authorized` policy into a `PolicyReq::Authorized`, preserving the action.
    ///
    /// # Examples
    ///
    /// ```
    /// let a = Authorized { action: "read" };
    /// let req = PolicyReq::from(a);
    /// match req {
    ///     PolicyReq::Authorized { action } => assert_eq!(action, "read"),
    ///     _ => panic!("expected authorized"),
    /// }
    /// ```
    fn from(auth: Authorized) -> Self {
        PolicyReq::Authorized {
            action: auth.action,
        }
    }
}