/// A policy requirement that must be satisfied.
///
/// This enum represents all possible policy requirements.
/// Policies are evaluated during `PolicyGate::build()`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PolicyReq {
    /// Requires an authenticated principal
    Authenticated,
    /// Requires authorization for a specific action
    Authorized { action: &'static str },
}

/// Standard action names for authorization policies.
///
/// These constants define the canonical action names used throughout the crate.
/// Using these constants instead of string literals prevents typos and provides
/// a single source of truth for action names.
///
/// # Examples
///
/// ```
/// use policy_core::{Authorized, actions};
///
/// let log_policy = Authorized::for_action(actions::LOG);
/// let http_policy = Authorized::for_action(actions::HTTP);
/// ```
pub mod actions {
    /// Logging action - grants LogCap capability
    pub const LOG: &str = "log";
    /// HTTP action - grants HttpCap capability
    pub const HTTP: &str = "http";
    /// Audit action - grants AuditCap capability
    pub const AUDIT: &str = "audit";
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
    /// use policy_core::Authorized;
    ///
    /// let req = Authorized::for_action("read:items");
    /// ```
    pub fn for_action(action: &'static str) -> Self {
        Self { action }
    }
}

// Conversions to PolicyReq
impl From<Authenticated> for PolicyReq {
    /// Convert an `Authenticated` marker into the corresponding `PolicyReq::Authenticated` variant.
    ///
    /// Note: `PolicyReq` is an internal type used by the policy gate.
    fn from(_: Authenticated) -> Self {
        PolicyReq::Authenticated
    }
}

impl From<Authorized> for PolicyReq {
    /// Converts an `Authorized` policy into a `PolicyReq::Authorized`, preserving the action.
    ///
    /// Note: `PolicyReq` is an internal type used by the policy gate.
    fn from(auth: Authorized) -> Self {
        PolicyReq::Authorized {
            action: auth.action,
        }
    }
}
