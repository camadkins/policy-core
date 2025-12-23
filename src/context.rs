use std::marker::PhantomData;

use crate::audit::{AuditCap, PolicyAudit};
use crate::capability::{HttpCap, LogCap};
use crate::error::{Violation, ViolationKind};
use crate::http::PolicyHttp;
use crate::logging::PolicyLog;
use crate::request::Principal;
use crate::state::{Authed, Authorized, Unauthed};

/// Execution context containing request metadata and capabilities.
///
/// `Ctx<S>` is generic over its authentication/authorization state:
/// - `Ctx<Unauthed>`: No principal, no capabilities
/// - `Ctx<Authed>`: Has principal, no capabilities
/// - `Ctx<Authorized>`: Has principal and capabilities
///
/// # Type-State Progression
///
/// Contexts progress through states via explicit transitions:
/// ```text
/// Ctx<Unauthed> --authenticate--> Ctx<Authed> --authorize--> Ctx<Authorized>
/// ```
///
/// Only `Ctx<Authorized>` can access privileged operations like logging and HTTP.
///
/// # Construction
///
/// `Ctx` cannot be constructed by user code. Use `PolicyGate` to obtain a
/// fully validated `Ctx<Authorized>`, or use the state transition methods
/// for manual progression.
///
/// # Examples
///
/// ```
/// use policy_core::{PolicyGate, RequestMeta, Principal, Authenticated, Authorized};
///
/// // Using PolicyGate (returns Ctx<Authorized> directly):
/// let meta = RequestMeta {
///     request_id: "req-123".to_string(),
///     principal: Some(Principal {
///         id: "user-1".to_string(),
///         name: "Alice".to_string(),
///     }),
/// };
///
/// let ctx = PolicyGate::new(meta)
///     .require(Authenticated)
///     .require(Authorized::for_action("log"))
///     .build()
///     .expect("policies satisfied");
///
/// // ctx is Ctx<Authorized> and can access privileged operations
/// let logger = ctx.log().expect("LogCap granted");
/// ```
#[derive(Debug, Clone)]
pub struct Ctx<S = Authorized> {
    request_id: String,
    principal: Option<Principal>,
    log_cap: Option<LogCap>,
    http_cap: Option<HttpCap>,
    audit_cap: Option<AuditCap>,
    _state: PhantomData<S>,
}

// ============================================================================
// Shared methods (available on all states)
// ============================================================================

impl<S> Ctx<S> {
    /// Returns the request ID for this context.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the principal if present.
    ///
    /// Returns `Some(Principal)` for `Ctx<Authed>` and `Ctx<Authorized>`,
    /// `None` for `Ctx<Unauthed>`.
    pub fn principal(&self) -> Option<&Principal> {
        self.principal.as_ref()
    }
}

// ============================================================================
// Ctx<Unauthed> - Initial state
// ============================================================================

impl Ctx<Unauthed> {
    /// Creates a new unauthenticated context with only a request ID.
    ///
    /// This is `pub(crate)` so only code within policy-core can create it.
    #[allow(dead_code)] // Used in tests
    pub(crate) fn new_unauthed(request_id: String) -> Self {
        Self {
            request_id,
            principal: None,
            log_cap: None,
            http_cap: None,
            audit_cap: None,
            _state: PhantomData,
        }
    }

    /// Authenticates the context by validating a principal.
    ///
    /// This transition requires a principal to be provided. If the principal
    /// is valid, the context progresses to `Ctx<Authed>`.
    ///
    /// # Errors
    ///
    /// Returns `Err(Violation)` if the principal is `None`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // This example shows the API but cannot be compiled in doctests
    /// // because Ctx::new_unauthed is pub(crate). See unit tests for working examples.
    /// use policy_core::{Ctx, Principal};
    ///
    /// let ctx = Ctx::new_unauthed("req-1".to_string());
    /// let principal = Principal {
    ///     id: "user-1".to_string(),
    ///     name: "Alice".to_string(),
    /// };
    ///
    /// let authed_ctx = ctx.authenticate(Some(principal)).expect("valid principal");
    /// ```
    pub fn authenticate(self, principal: Option<Principal>) -> Result<Ctx<Authed>, Violation> {
        if let Some(p) = principal {
            Ok(Ctx {
                request_id: self.request_id,
                principal: Some(p),
                log_cap: None,
                http_cap: None,
                audit_cap: None,
                _state: PhantomData,
            })
        } else {
            Err(Violation::new(
                ViolationKind::Unauthenticated,
                "Authentication required: principal not provided",
            ))
        }
    }
}

// ============================================================================
// Ctx<Authed> - Authenticated but not authorized
// ============================================================================

impl Ctx<Authed> {
    /// Authorizes the context by granting capabilities.
    ///
    /// This transition validates that the authenticated principal has
    /// permission to perform requested actions and grants corresponding
    /// capabilities.
    ///
    /// # Arguments
    ///
    /// * `log_cap` - Optional logging capability
    /// * `http_cap` - Optional HTTP capability
    /// * `audit_cap` - Optional audit capability
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Assuming we have a Ctx<Authed>:
    /// let authorized_ctx = authed_ctx.authorize(Some(LogCap::new()), None, None);
    /// ```
    pub fn authorize(
        self,
        log_cap: Option<LogCap>,
        http_cap: Option<HttpCap>,
        audit_cap: Option<AuditCap>,
    ) -> Ctx<Authorized> {
        Ctx {
            request_id: self.request_id,
            principal: self.principal,
            log_cap,
            http_cap,
            audit_cap,
            _state: PhantomData,
        }
    }
}

// ============================================================================
// Ctx<Authorized> - Fully authorized with capabilities
// ============================================================================

impl Ctx<Authorized> {
    /// Creates a new context with a request ID and optional capabilities.
    ///
    /// This is `pub(crate)` so only code within policy-core can create it.
    /// PolicyGate calls this after validating policies.
    ///
    /// This is a compatibility shim for existing code that uses the old
    /// non-generic Ctx API. New code should use state transitions.
    #[allow(dead_code)] // Will be used by PolicyGate
    pub(crate) fn new_unchecked(
        request_id: String,
        log_cap: Option<LogCap>,
        http_cap: Option<HttpCap>,
    ) -> Self {
        Self {
            request_id,
            principal: None,
            log_cap,
            http_cap,
            audit_cap: None,
            _state: PhantomData,
        }
    }

    /// Creates a new authorized context with full state.
    ///
    /// This is `pub(crate)` and used internally for state transitions
    /// and PolicyGate integration.
    pub(crate) fn new_authorized(
        request_id: String,
        principal: Option<Principal>,
        log_cap: Option<LogCap>,
        http_cap: Option<HttpCap>,
        audit_cap: Option<AuditCap>,
    ) -> Self {
        Self {
            request_id,
            principal,
            log_cap,
            http_cap,
            audit_cap,
            _state: PhantomData,
        }
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

    /// Returns the audit capability if present.
    ///
    /// Returns `Some(AuditCap)` if audit policies were satisfied,
    /// `None` otherwise.
    pub fn audit_cap(&self) -> Option<AuditCap> {
        self.audit_cap
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
    /// // Logs: "User logged in: [REDACTED]" (with request_id included)
    /// ```
    pub fn log(&self) -> Result<PolicyLog<'_>, Violation> {
        if self.log_cap.is_some() {
            Ok(PolicyLog::new(&self.request_id))
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
            Ok(PolicyHttp::new(&self.request_id))
        } else {
            Err(Violation::new(
                ViolationKind::MissingHttpCapability,
                "HTTP capability not granted",
            ))
        }
    }

    /// Returns a capability-gated audit event emitter.
    ///
    /// # Errors
    ///
    /// Returns `Err(Violation)` if `AuditCap` was not granted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use policy_core::{PolicyGate, RequestMeta, Principal, Authenticated, Authorized};
    /// # use policy_core::audit::{AuditEvent, AuditEventKind, AuditOutcome};
    /// # let meta = RequestMeta {
    /// #     request_id: "req-1".to_string(),
    /// #     principal: Some(Principal { id: "u1".to_string(), name: "Admin".to_string() }),
    /// # };
    /// # let ctx = PolicyGate::new(meta)
    /// #     .require(Authenticated)
    /// #     .require(Authorized::for_action("audit"))
    /// #     .build()
    /// #     .unwrap();
    /// let audit = ctx.audit().expect("AuditCap required");
    ///
    /// let event = AuditEvent::new(
    ///     ctx.request_id(),
    ///     ctx.principal().map(|p| &p.name),
    ///     AuditEventKind::AdminAction,
    ///     AuditOutcome::Success,
    /// );
    ///
    /// audit.emit(&event);
    /// ```
    pub fn audit(&self) -> Result<PolicyAudit<'_>, Violation> {
        if self.audit_cap.is_some() {
            Ok(PolicyAudit::new())
        } else {
            Err(Violation::new(
                ViolationKind::MissingAuditCapability,
                "Audit capability not granted",
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

    // ========================================================================
    // Type-state tests
    // ========================================================================

    #[test]
    fn unauthed_ctx_has_no_principal() {
        let ctx = Ctx::new_unauthed("req-unauth".to_string());
        assert_eq!(ctx.request_id(), "req-unauth");
        assert!(ctx.principal().is_none());
    }

    #[test]
    fn authenticate_with_principal_succeeds() {
        let ctx = Ctx::new_unauthed("req-auth".to_string());
        let principal = Principal {
            id: "user-1".to_string(),
            name: "Alice".to_string(),
        };

        let authed_ctx = ctx
            .authenticate(Some(principal))
            .expect("should authenticate");

        assert_eq!(authed_ctx.request_id(), "req-auth");
        assert!(authed_ctx.principal().is_some());
        assert_eq!(authed_ctx.principal().unwrap().id, "user-1");
    }

    #[test]
    fn authenticate_without_principal_fails() {
        let ctx = Ctx::new_unauthed("req-auth-fail".to_string());

        let result = ctx.authenticate(None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, ViolationKind::Unauthenticated);
    }

    #[test]
    fn authorize_grants_capabilities() {
        let ctx = Ctx::new_unauthed("req-authz".to_string());
        let principal = Principal {
            id: "user-2".to_string(),
            name: "Bob".to_string(),
        };

        let authed_ctx = ctx.authenticate(Some(principal)).unwrap();
        let authorized_ctx = authed_ctx.authorize(Some(LogCap::new()), Some(HttpCap::new()), None);

        assert_eq!(authorized_ctx.request_id(), "req-authz");
        assert!(authorized_ctx.principal().is_some());
        assert!(authorized_ctx.log_cap().is_some());
        assert!(authorized_ctx.http_cap().is_some());
        assert!(authorized_ctx.audit_cap().is_none());
    }

    #[test]
    fn full_state_progression() {
        // Unauthed -> Authed -> Authorized
        let unauthed = Ctx::new_unauthed("req-progression".to_string());
        assert!(unauthed.principal().is_none());

        let principal = Principal {
            id: "user-3".to_string(),
            name: "Charlie".to_string(),
        };
        let authed = unauthed.authenticate(Some(principal)).unwrap();
        assert!(authed.principal().is_some());

        let authorized = authed.authorize(Some(LogCap::new()), None, None);
        assert!(authorized.principal().is_some());
        assert!(authorized.log_cap().is_some());
        assert!(authorized.http_cap().is_none());
        assert!(authorized.audit_cap().is_none());
    }

    #[test]
    fn authorized_ctx_can_access_log() {
        let ctx = Ctx::new_authorized(
            "req-log".to_string(),
            Some(Principal {
                id: "user-4".to_string(),
                name: "Dana".to_string(),
            }),
            Some(LogCap::new()),
            None,
            None,
        );

        assert!(ctx.log().is_ok());
    }

    #[test]
    fn authorized_ctx_can_access_http() {
        let ctx = Ctx::new_authorized(
            "req-http".to_string(),
            Some(Principal {
                id: "user-5".to_string(),
                name: "Eve".to_string(),
            }),
            None,
            Some(HttpCap::new()),
            None,
        );

        assert!(ctx.http().is_ok());
    }

    #[test]
    fn authorized_ctx_can_access_audit() {
        let ctx = Ctx::new_authorized(
            "req-audit".to_string(),
            Some(Principal {
                id: "user-6".to_string(),
                name: "Frank".to_string(),
            }),
            None,
            None,
            Some(AuditCap::new()),
        );

        assert!(ctx.audit().is_ok());
    }

    #[test]
    fn ctx_audit_requires_capability() {
        let ctx_with_cap =
            Ctx::new_authorized("req-1".to_string(), None, None, None, Some(AuditCap::new()));
        assert!(ctx_with_cap.audit().is_ok());

        let ctx_without_cap = Ctx::new_unchecked("req-2".to_string(), None, None);
        let result = ctx_without_cap.audit();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind,
            ViolationKind::MissingAuditCapability
        );
    }
}
