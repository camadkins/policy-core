use crate::capability::LogCap;

/// Execution context containing request metadata and capabilities.
///
/// `Ctx` represents a validated execution environment. It holds:
/// - Request metadata (request ID, user info, etc.)
/// - Granted capabilities (proof that policies passed)
///
/// # Construction
///
/// `Ctx` cannot be constructed by user code. It is created exclusively
/// by `PolicyGate` after validating policies.
///
/// # Examples
///
/// ```no_run
/// // This will not compile - no public constructor:
/// // let ctx = policy_core::Ctx::new("req-123".to_string());
/// ```
#[derive(Debug, Clone)]
pub struct Ctx {
    request_id: String,
    log_cap: Option<LogCap>,
}

impl Ctx {
    /// Creates a new context with a request ID and optional logging capability.
    ///
    /// This is `pub(crate)` so only code within policy-core can create Ctx.
    /// PolicyGate calls this after validating policies.
    #[allow(dead_code)] // Will be used by PolicyGate in Milestone 2
    pub(crate) fn new_unchecked(request_id: String, log_cap: Option<LogCap>) -> Self {
        Self {
            request_id,
            log_cap,
        }
    }

    /// Returns the request ID for this context.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the logging capability if present.
    ///
    /// Returns `Some(LogCap)` if logging policies were satisfied,
    /// `None` otherwise.
    pub fn log_cap(&self) -> Option<LogCap> {
        self.log_cap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctx_owns_capabilities() {
        let cap = LogCap::new();
        let ctx = Ctx::new_unchecked("req-123".to_string(), Some(cap));

        assert_eq!(ctx.request_id(), "req-123");
        assert!(ctx.log_cap().is_some());
    }

    #[test]
    fn ctx_without_capability() {
        let ctx = Ctx::new_unchecked("req-456".to_string(), None);

        assert_eq!(ctx.request_id(), "req-456");
        assert!(ctx.log_cap().is_none());
    }

    #[test]
    fn ctx_cannot_be_constructed_publicly() {
        // This test documents that Ctx::new_unchecked is not public.
        // If you try to call it from outside the crate, it won't compile:

        // let ctx = policy_core::Ctx::new_unchecked("test".to_string(), None); // Error!
    }
}
