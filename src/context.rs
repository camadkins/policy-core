use crate::capability::{HttpCap, LogCap};
use crate::error::{Violation, ViolationKind};
use crate::http::PolicyHttp;
use crate::logging::PolicyLog;

/// Execution context containing request metadata and capabilities.
///
/// `Ctx` represents a validated execution environment. It holds:
/// - Request metadata (request ID, user info, etc.)
/// - Granted capabilities (proof that policies passed)
///
/// # Construction
///
/// `Ctx` cannot be constructed by user code. In Milestone 2, it will be
/// created exclusively by `PolicyGate` after validating policies.
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
    http_cap: Option<HttpCap>,
}

impl Ctx {
    /// Creates a new context with a request ID and optional capabilities.
    ///
    /// This is `pub(crate)` so only code within policy-core can create Ctx.
    /// PolicyGate calls this after validating policies.
    #[allow(dead_code)] // Will be used by PolicyGate
    pub(crate) fn new_unchecked(
        request_id: String,
        log_cap: Option<LogCap>,
        http_cap: Option<HttpCap>,
    ) -> Self {
        Self {
            request_id,
            log_cap,
            http_cap,
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

    /// Returns the HTTP capability if present.
    ///
    /// Returns `Some(HttpCap)` if HTTP policies were satisfied,
    /// `None` otherwise.
    pub fn http_cap(&self) -> Option<HttpCap> {
        self.http_cap
    }

    /// Returns a capability-gated logger.
    ///
    /// # Errors
    ///
    /// Returns `Err(Violation)` if `LogCap` was not granted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use policy_core::{PolicyGate, RequestMeta, Principal, Authenticated, Authorized, Secret};
    /// # let meta = RequestMeta {
    /// #     request_id: "req-1".to_string(),
    /// #     principal: Some(Principal { id: "u1".to_string(), name: "Alice".to_string() }),
    /// # };
    /// # let ctx = PolicyGate::new(meta)
    /// #     .require(Authenticated)
    /// #     .require(Authorized::for_action("log"))
    /// #     .build()
    /// #     .unwrap();
    /// let logger = ctx.log().expect("LogCap required");
    ///
    /// let secret = Secret::new("password123");
    /// logger.info(format_args!("User logged in: {:?}", secret));
    /// // Logs: "User logged in: [REDACTED]"
    /// ```
    pub fn log(&self) -> Result<PolicyLog<'_>, Violation> {
        if self.log_cap.is_some() {
            Ok(PolicyLog::new())
        } else {
            Err(Violation::new(
                ViolationKind::MissingLogCapability,
                "Logging capability not granted",
            ))
        }
    }

    /// Returns a capability-gated HTTP client.
    ///
    /// # Errors
    ///
    /// Returns `Err(Violation)` if `HttpCap` was not granted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use policy_core::{PolicyGate, RequestMeta, Principal, Authenticated, Authorized};
    /// # use policy_core::{Tainted, Sanitizer, StringSanitizer};
    /// # let meta = RequestMeta {
    /// #     request_id: "req-1".to_string(),
    /// #     principal: Some(Principal { id: "u1".to_string(), name: "Alice".to_string() }),
    /// # };
    /// # let ctx = PolicyGate::new(meta)
    /// #     .require(Authenticated)
    /// #     .require(Authorized::for_action("http"))
    /// #     .build()
    /// #     .unwrap();
    /// let http = ctx.http().expect("HttpCap required");
    ///
    /// let sanitizer = StringSanitizer::new(256);
    /// let url = Tainted::new("https://api.example.com".to_string());
    /// let verified_url = sanitizer.sanitize(url).unwrap();
    ///
    /// http.get(&verified_url);
    /// ```
    pub fn http(&self) -> Result<PolicyHttp<'_>, Violation> {
        if self.http_cap.is_some() {
            Ok(PolicyHttp::new())
        } else {
            Err(Violation::new(
                ViolationKind::MissingHttpCapability,
                "HTTP capability not granted",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctx_owns_capabilities() {
        let log_cap = LogCap::new();
        let http_cap = HttpCap::new();
        let ctx = Ctx::new_unchecked("req-123".to_string(), Some(log_cap), Some(http_cap));

        assert_eq!(ctx.request_id(), "req-123");
        assert!(ctx.log_cap().is_some());
        assert!(ctx.http_cap().is_some());
    }

    #[test]
    fn ctx_without_capability() {
        let ctx = Ctx::new_unchecked("req-456".to_string(), None, None);

        assert_eq!(ctx.request_id(), "req-456");
        assert!(ctx.log_cap().is_none());
        assert!(ctx.http_cap().is_none());
    }

    #[test]
    fn ctx_cannot_be_constructed_publicly() {
        // This test documents that Ctx::new_unchecked is not public.
        // If you try to call it from outside the crate, it won't compile:

        // let ctx = policy_core::Ctx::new_unchecked("test".to_string(), None, None); // Error!
    }

    #[test]
    fn ctx_log_requires_capability() {
        let ctx_with_cap = Ctx::new_unchecked("req-1".to_string(), Some(LogCap::new()), None);
        assert!(ctx_with_cap.log().is_ok());

        let ctx_without_cap = Ctx::new_unchecked("req-2".to_string(), None, None);
        let result = ctx_without_cap.log();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind,
            ViolationKind::MissingLogCapability
        );
    }

    #[test]
    fn ctx_http_requires_capability() {
        let ctx_with_cap = Ctx::new_unchecked("req-1".to_string(), None, Some(HttpCap::new()));
        assert!(ctx_with_cap.http().is_ok());

        let ctx_without_cap = Ctx::new_unchecked("req-2".to_string(), None, None);
        let result = ctx_without_cap.http();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind,
            ViolationKind::MissingHttpCapability
        );
    }
}
