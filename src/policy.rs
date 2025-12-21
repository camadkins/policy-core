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
    /// Creates an authorization requirement for the given action.
    pub fn for_action(action: &'static str) -> Self {
        Self { action }
    }
}

// Conversions to PolicyReq
impl From<Authenticated> for PolicyReq {
    fn from(_: Authenticated) -> Self {
        PolicyReq::Authenticated
    }
}

impl From<Authorized> for PolicyReq {
    fn from(auth: Authorized) -> Self {
        PolicyReq::Authorized {
            action: auth.action,
        }
    }
}
