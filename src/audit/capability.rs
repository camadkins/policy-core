//! Audit capability type.
//!
//! `AuditCap` is a zero-sized, unforgeable proof that a context has been
//! authorized to emit audit events. It cannot be constructed outside this
//! crate, ensuring all audit operations go through policy validation.

/// Capability proving authorization to emit audit events.
///
/// This is a zero-sized type that acts as compile-time proof of authorization.
/// It can only be constructed within this crate through legitimate policy
/// validation flows.
///
/// # Example
///
/// ```
/// use policy_core::{PolicyGate, RequestMeta, Principal, Authorized};
///
/// let meta = RequestMeta {
///     request_id: "req-123".to_string(),
///     principal: Some(Principal {
///         id: "admin-1".to_string(),
///         name: "Admin".to_string(),
///     }),
/// };
/// let ctx = PolicyGate::new(meta)
///     .require(Authorized::for_action("audit"))
///     .build()
///     .unwrap();
///
/// // AuditCap is granted if the "audit" action was authorized
/// assert!(ctx.audit_cap().is_some());
/// ```
#[derive(Debug, Clone, Copy)]
pub struct AuditCap {
    // BREAKING CHANGE WARNING: This field MUST remain private.
    // Making it public allows external code to forge audit capabilities via struct literal,
    // bypassing all policy validation and enabling unauthorized audit event emission.
    _private: (),
}

impl AuditCap {
    /// Creates a new `AuditCap`.
    ///
    /// This is `pub(crate)` to prevent external forgery. Only the policy
    /// gate can create capabilities after validating authorization.
    ///
    /// BREAKING CHANGE WARNING: Changing visibility to `pub` allows CAPABILITY FORGERY.
    /// External code could emit audit events without authorization, enabling audit trail
    /// manipulation and compliance violations (CWE-778: Insufficient Logging).
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_cap_is_zero_sized() {
        assert_eq!(std::mem::size_of::<AuditCap>(), 0);
    }

    #[test]
    fn audit_cap_can_be_cloned_and_copied() {
        let cap = AuditCap::new();
        let _cap2 = cap;
        let _cap3 = cap; // Copy, not clone (AuditCap is Copy)
    }

    #[test]
    fn audit_cap_has_debug_impl() {
        let cap = AuditCap::new();
        let debug_str = format!("{:?}", cap);
        assert!(debug_str.contains("AuditCap"));
    }
}
