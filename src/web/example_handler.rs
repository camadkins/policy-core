//! Example handlers demonstrating web integration with policy enforcement.
//!
//! This module shows realistic request handler flows that integrate
//! policy-core's enforcement mechanisms with web-style request processing.
//!
//! **These examples are for documentation and testing only.**
//! They demonstrate proper usage patterns without requiring actual HTTP infrastructure.

use crate::audit::{AuditEvent, AuditEventKind, AuditOutcome};
use crate::error::Violation;
use crate::{Authenticated, Authorized, PolicyGate, Sanitizer, StringSanitizer};

use super::{extract_authed, extract_unauthed, ExtractMetadata, RequestAdapter};

/// Result of a public endpoint handler (no authentication required).
///
/// This demonstrates how to handle requests that don't require authentication
/// but still need taint-safe input processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSearchResult {
    /// Request ID for tracing
    pub request_id: String,
    /// Sanitized search query
    pub query: String,
    /// Number of results (simulated)
    pub result_count: usize,
}

/// Handles a public search endpoint.
///
/// This handler demonstrates:
/// - Unauthenticated request processing
/// - Tainted input sanitization
/// - No capability requirements
///
/// # Examples
///
/// ```
/// use policy_core::web::{RequestAdapter, example_handler::handle_public_search};
///
/// let mut adapter = RequestAdapter::new("req-search-001".to_string());
/// adapter.add_query_param("q".to_string(), "  rust policy  ".to_string());
///
/// let result = handle_public_search(&adapter).expect("valid search");
/// assert_eq!(result.query, "rust policy"); // Trimmed by sanitizer
/// ```
pub fn handle_public_search(adapter: &RequestAdapter) -> Result<PublicSearchResult, Violation> {
    // 1. Extract unauthenticated context and inputs
    let extraction = extract_unauthed(adapter);

    // 2. Get search query from tainted inputs
    let tainted_query = extraction.inputs.get_query("q").ok_or_else(|| {
        Violation::new(
            crate::error::ViolationKind::InvalidInput,
            "Missing query parameter 'q'",
        )
    })?;

    // 3. Sanitize query (prevent injection, enforce length limits)
    let sanitizer = StringSanitizer::new(200).unwrap();
    let verified_query = sanitizer.sanitize(tainted_query)?;

    // 4. Perform search (simulated - no capabilities needed for public endpoint)
    let result_count = verified_query.as_ref().split_whitespace().count() * 10;

    Ok(PublicSearchResult {
        request_id: extraction.context.request_id().to_string(),
        query: verified_query.as_ref().clone(),
        result_count,
    })
}

/// Result of an authenticated data fetch.
#[derive(Debug, Clone)]
pub struct UserDataResult {
    /// Request ID for tracing
    pub request_id: String,
    /// Authenticated user's ID
    pub user_id: String,
    /// Data description (simulated)
    pub data: String,
}

/// Handles an authenticated user data endpoint.
///
/// This handler demonstrates:
/// - Authenticated request processing
/// - Authorization with capability granting
/// - Logging with automatic request-id inclusion
/// - Compile-time enforcement (cannot access .log() without LogCap)
///
/// # Examples
///
/// ```
/// use policy_core::web::{RequestAdapter, example_handler::handle_user_data};
/// use policy_core::Principal;
///
/// let mut adapter = RequestAdapter::new("req-user-001".to_string());
/// adapter.set_principal(Some(Principal {
///     id: "user-123".to_string(),
///     name: "Alice".to_string(),
/// }));
///
/// let result = handle_user_data(&adapter).expect("authenticated and authorized");
/// assert_eq!(result.user_id, "user-123");
/// ```
pub fn handle_user_data(adapter: &RequestAdapter) -> Result<UserDataResult, Violation> {
    // 1. Extract authenticated context (fails if no principal)
    let _extraction = extract_authed(adapter)?;

    // 2. Build metadata for PolicyGate
    let meta = adapter.extract_metadata();

    // 3. Apply policies to get authorized context with capabilities
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .build()?;

    // 4. Access capability-gated logger
    let logger = ctx.log()?;

    // 5. Log with automatic request-id inclusion
    logger.info(format_args!(
        "Fetching data for user: {}",
        ctx.principal().unwrap().id
    ));

    // 6. Simulate data fetch
    let data = format!("User data for {}", ctx.principal().unwrap().name);

    Ok(UserDataResult {
        request_id: ctx.request_id().to_string(),
        user_id: ctx.principal().unwrap().id.clone(),
        data,
    })
}

/// Result of an API call to external service.
#[derive(Debug, Clone)]
pub struct ApiCallResult {
    /// Request ID for tracing
    pub request_id: String,
    /// Number of API calls made
    pub api_calls: usize,
    /// Success status
    pub success: bool,
}

/// Handles an endpoint that makes external API calls.
///
/// This handler demonstrates:
/// - Full authorization flow
/// - HTTP capability gating
/// - Tainted URL sanitization
/// - Request-id propagation to external calls
///
/// # Examples
///
/// ```
/// use policy_core::web::{RequestAdapter, example_handler::handle_api_call};
/// use policy_core::Principal;
///
/// let mut adapter = RequestAdapter::new("req-api-001".to_string());
/// adapter.set_principal(Some(Principal {
///     id: "user-456".to_string(),
///     name: "Bob".to_string(),
/// }));
/// adapter.add_query_param("url".to_string(), "https://api.example.com/data".to_string());
///
/// let result = handle_api_call(&adapter).expect("authorized");
/// assert!(result.success);
/// assert_eq!(result.api_calls, 1);
/// ```
pub fn handle_api_call(adapter: &RequestAdapter) -> Result<ApiCallResult, Violation> {
    // 1. Extract authenticated context
    let extraction = extract_authed(adapter)?;

    // 2. Build authorized context with HTTP capability
    let meta = adapter.extract_metadata();
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .require(Authorized::for_action("log"))
        .build()?;

    // 3. Get capability-gated HTTP client
    let http = ctx.http()?;
    let logger = ctx.log()?;

    // 4. Extract and sanitize tainted URL
    let tainted_url = extraction.inputs.get_query("url").ok_or_else(|| {
        Violation::new(
            crate::error::ViolationKind::InvalidInput,
            "Missing URL parameter",
        )
    })?;

    let sanitizer = StringSanitizer::new(256).unwrap();
    let verified_url = sanitizer.sanitize(tainted_url)?;

    // 5. Make HTTP call with verified URL and request-id context
    logger.info(format_args!(
        "Making API call to: {}",
        verified_url.as_ref()
    ));
    http.get(&verified_url);

    Ok(ApiCallResult {
        request_id: ctx.request_id().to_string(),
        api_calls: http.request_count(),
        success: true,
    })
}

/// Handles an admin action with full audit trail.
///
/// This handler demonstrates:
/// - Authentication and authorization
/// - Audit capability gating
/// - Structured audit event emission
/// - Request-id inclusion in audit events
///
/// # Examples
///
/// ```
/// use policy_core::web::{RequestAdapter, example_handler::handle_admin_action};
/// use policy_core::Principal;
///
/// let mut adapter = RequestAdapter::new("req-admin-001".to_string());
/// adapter.set_principal(Some(Principal {
///     id: "admin-1".to_string(),
///     name: "Admin User".to_string(),
/// }));
/// adapter.add_query_param("action".to_string(), "delete_user".to_string());
/// adapter.add_query_param("target".to_string(), "user-999".to_string());
///
/// let result = handle_admin_action(&adapter).expect("admin authorized");
/// assert!(result.success);
/// ```
pub fn handle_admin_action(adapter: &RequestAdapter) -> Result<AdminActionResult, Violation> {
    // 1. Extract authenticated context
    let extraction = extract_authed(adapter)?;

    // 2. Require admin-level authorization
    let meta = adapter.extract_metadata();
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("audit"))
        .require(Authorized::for_action("log"))
        .build()?;

    // 3. Get audit capability
    let audit = ctx.audit()?;
    let logger = ctx.log()?;

    // 4. Sanitize inputs
    let sanitizer = StringSanitizer::new(100).unwrap();

    let tainted_action = extraction.inputs.get_query("action").ok_or_else(|| {
        Violation::new(crate::error::ViolationKind::InvalidInput, "Missing action")
    })?;

    let verified_action = sanitizer.sanitize(tainted_action)?;

    let tainted_target = extraction.inputs.get_query("target").ok_or_else(|| {
        Violation::new(crate::error::ViolationKind::InvalidInput, "Missing target")
    })?;

    let verified_target = sanitizer.sanitize(tainted_target)?;

    // 5. Log the action
    logger.info(format_args!(
        "Admin {} performing: {} on {}",
        ctx.principal().unwrap().name,
        verified_action.as_ref(),
        verified_target.as_ref()
    ));

    // 6. Emit structured audit event with request-id
    let event = AuditEvent::new(
        ctx.request_id(),
        ctx.principal().map(|p| &p.name),
        AuditEventKind::AdminAction,
        AuditOutcome::Success,
    )
    .with_action(verified_action.as_ref());

    audit.emit(&event);

    Ok(AdminActionResult {
        request_id: ctx.request_id().to_string(),
        action: verified_action.as_ref().clone(),
        target: verified_target.as_ref().clone(),
        success: true,
    })
}

/// Result of an admin action.
#[derive(Debug, Clone)]
pub struct AdminActionResult {
    /// Request ID for tracing
    pub request_id: String,
    /// Action performed
    pub action: String,
    /// Target of the action
    pub target: String,
    /// Success status
    pub success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Principal;

    #[test]
    fn public_search_works_without_auth() {
        let mut adapter = RequestAdapter::new("req-search-test".to_string());
        adapter.add_query_param("q".to_string(), "  test query  ".to_string());

        let result = handle_public_search(&adapter).expect("should succeed");

        assert_eq!(result.request_id, "req-search-test");
        assert_eq!(result.query, "test query"); // Trimmed
        assert_eq!(result.result_count, 20); // 2 words * 10
    }

    #[test]
    fn public_search_requires_query_param() {
        let adapter = RequestAdapter::new("req-search-fail".to_string());

        let result = handle_public_search(&adapter);
        assert!(result.is_err());
    }

    #[test]
    fn user_data_requires_authentication() {
        let adapter = RequestAdapter::new("req-no-auth".to_string());

        let result = handle_user_data(&adapter);
        assert!(result.is_err());
    }

    #[test]
    fn user_data_succeeds_with_auth() {
        let mut adapter = RequestAdapter::new("req-user-test".to_string());
        adapter.set_principal(Some(Principal {
            id: "user-123".to_string(),
            name: "Test User".to_string(),
        }));

        let result = handle_user_data(&adapter).expect("should succeed");

        assert_eq!(result.request_id, "req-user-test");
        assert_eq!(result.user_id, "user-123");
        assert!(result.data.contains("Test User"));
    }

    #[test]
    fn api_call_requires_authentication() {
        let mut adapter = RequestAdapter::new("req-api-no-auth".to_string());
        adapter.add_query_param("url".to_string(), "https://example.com".to_string());

        let result = handle_api_call(&adapter);
        assert!(result.is_err());
    }

    #[test]
    fn api_call_succeeds_with_auth_and_valid_url() {
        let mut adapter = RequestAdapter::new("req-api-test".to_string());
        adapter.set_principal(Some(Principal {
            id: "user-456".to_string(),
            name: "API User".to_string(),
        }));
        adapter.add_query_param(
            "url".to_string(),
            "https://api.example.com/data".to_string(),
        );

        let result = handle_api_call(&adapter).expect("should succeed");

        assert_eq!(result.request_id, "req-api-test");
        assert_eq!(result.api_calls, 1);
        assert!(result.success);
    }

    #[test]
    fn admin_action_requires_auth() {
        let mut adapter = RequestAdapter::new("req-admin-no-auth".to_string());
        adapter.add_query_param("action".to_string(), "delete".to_string());
        adapter.add_query_param("target".to_string(), "user-1".to_string());

        let result = handle_admin_action(&adapter);
        assert!(result.is_err());
    }

    #[test]
    fn admin_action_succeeds_with_full_auth() {
        let mut adapter = RequestAdapter::new("req-admin-test".to_string());
        adapter.set_principal(Some(Principal {
            id: "admin-1".to_string(),
            name: "Admin".to_string(),
        }));
        adapter.add_query_param("action".to_string(), "disable_account".to_string());
        adapter.add_query_param("target".to_string(), "user-999".to_string());

        let result = handle_admin_action(&adapter).expect("should succeed");

        assert_eq!(result.request_id, "req-admin-test");
        assert_eq!(result.action, "disable_account");
        assert_eq!(result.target, "user-999");
        assert!(result.success);
    }
}
