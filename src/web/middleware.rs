//! Middleware/extractor functions for building Ctx from HTTP requests.
//!
//! This module provides the boundary layer between HTTP frameworks and
//! policy-core's context types. It handles:
//! - Extracting request metadata and tainted inputs
//! - Building unauthenticated or authenticated contexts
//! - NOT granting capabilities (that's PolicyGate's job)
//!
//! # Design Principles
//!
//! 1. **No Authorization Here**: These extractors build `Ctx<Unauthed>` or
//!    `Ctx<Authed>`. They do NOT grant capabilities. Authorization happens
//!    via `PolicyGate` after extraction.
//!
//! 2. **Taint at Boundary**: All external inputs are wrapped in `Tainted<T>`
//!    by the `RequestAdapter`.
//!
//! 3. **Explicit Context**: No globals, no ambient state. Everything flows
//!    through explicit values.
//!
//! # Integration Flow
//!
//! ```text
//! HTTP Request
//!   ↓
//! Framework-specific code builds RequestAdapter
//!   ↓
//! Call extract_unauthed() or extract_authed()
//!   ↓
//! Receive (Ctx<Unauthed/Authed>, TaintedInputs)
//!   ↓
//! Application code calls PolicyGate.build()
//!   ↓
//! Receive Ctx<Authorized> with capabilities
//! ```

use crate::context::Ctx;
use crate::error::Violation;
use crate::state::{Authed, Unauthed};

use super::{ExtractMetadata, ExtractTaintedInputs, RequestAdapter, TaintedInputs};

/// Extraction result containing an unauthenticated context and tainted inputs.
///
/// This type pairs a `Ctx<Unauthed>` with all untrusted inputs from the request.
/// Applications should:
/// 1. Use the context for request tracking
/// 2. Sanitize tainted inputs before use
/// 3. Call `PolicyGate` for authorization
///
/// # Examples
///
/// ```
/// use policy_core::web::{RequestAdapter, extract_unauthed};
///
/// let adapter = RequestAdapter::new("req-001".to_string());
/// let extraction = extract_unauthed(&adapter);
///
/// assert_eq!(extraction.context.request_id(), "req-001");
/// assert!(extraction.context.principal().is_none());
/// ```
#[derive(Debug)]
pub struct UnauthenticatedExtraction {
    /// The unauthenticated context (no principal)
    pub context: Ctx<Unauthed>,
    /// All untrusted inputs from the request
    pub inputs: TaintedInputs,
}

/// Extraction result containing an authenticated context and tainted inputs.
///
/// This type pairs a `Ctx<Authed>` with all untrusted inputs from the request.
/// Applications should:
/// 1. Use the authenticated context for request tracking and principal info
/// 2. Sanitize tainted inputs before use
/// 3. Call `PolicyGate` for authorization
///
/// # Examples
///
/// ```
/// use policy_core::web::{RequestAdapter, extract_authed};
/// use policy_core::Principal;
///
/// let mut adapter = RequestAdapter::new("req-002".to_string());
/// adapter.set_principal(Some(Principal {
///     id: "user-1".to_string(),
///     name: "Alice".to_string(),
/// }));
///
/// let extraction = extract_authed(&adapter).expect("principal present");
/// assert_eq!(extraction.context.request_id(), "req-002");
/// assert!(extraction.context.principal().is_some());
/// ```
#[derive(Debug)]
pub struct AuthenticatedExtraction {
    /// The authenticated context (has principal)
    pub context: Ctx<Authed>,
    /// All untrusted inputs from the request
    pub inputs: TaintedInputs,
}

/// Extracts an unauthenticated context from a request adapter.
///
/// This function creates a `Ctx<Unauthed>` with only the request ID.
/// Use this for public endpoints that don't require authentication.
///
/// The returned context:
/// - Has a request ID (for tracing/logging)
/// - Has NO principal
/// - Has NO capabilities
///
/// # Arguments
///
/// * `adapter` - The request adapter containing request metadata
///
/// # Returns
///
/// An `UnauthenticatedExtraction` containing the context and tainted inputs.
///
/// # Examples
///
/// ```
/// use policy_core::web::{RequestAdapter, extract_unauthed};
///
/// let mut adapter = RequestAdapter::new("req-public".to_string());
/// adapter.add_query_param("search".to_string(), "query".to_string());
///
/// let extraction = extract_unauthed(&adapter);
///
/// // Context has request ID
/// assert_eq!(extraction.context.request_id(), "req-public");
///
/// // But no principal
/// assert!(extraction.context.principal().is_none());
///
/// // Inputs are tainted
/// assert!(extraction.inputs.has_query_param("search"));
/// ```
pub fn extract_unauthed(adapter: &RequestAdapter) -> UnauthenticatedExtraction {
    let meta = adapter.extract_metadata();
    let inputs = adapter.extract_tainted_inputs();

    UnauthenticatedExtraction {
        context: Ctx::new_unauthed(meta.request_id),
        inputs,
    }
}

/// Extracts an authenticated context from a request adapter.
///
/// This function creates a `Ctx<Authed>` with a request ID and principal.
/// Use this for endpoints that require authentication.
///
/// The returned context:
/// - Has a request ID (for tracing/logging)
/// - Has a principal (authenticated user/service)
/// - Has NO capabilities (authorization happens via PolicyGate)
///
/// # Arguments
///
/// * `adapter` - The request adapter containing request metadata
///
/// # Returns
///
/// * `Ok(AuthenticatedExtraction)` if a principal is present
/// * `Err(Violation)` if no principal is present
///
/// # Errors
///
/// Returns `Err(Violation::Unauthenticated)` if `adapter` has no principal.
/// This typically indicates middleware should return 401 Unauthorized.
///
/// # Examples
///
/// ```
/// use policy_core::web::{RequestAdapter, extract_authed};
/// use policy_core::Principal;
///
/// // With principal - succeeds
/// let mut adapter = RequestAdapter::new("req-auth".to_string());
/// adapter.set_principal(Some(Principal {
///     id: "user-1".to_string(),
///     name: "Alice".to_string(),
/// }));
///
/// let extraction = extract_authed(&adapter).expect("should succeed");
/// assert_eq!(extraction.context.principal().unwrap().id, "user-1");
/// ```
///
/// ```
/// use policy_core::web::{RequestAdapter, extract_authed};
///
/// // Without principal - fails
/// let adapter = RequestAdapter::new("req-no-auth".to_string());
/// let result = extract_authed(&adapter);
/// assert!(result.is_err());
/// ```
pub fn extract_authed(adapter: &RequestAdapter) -> Result<AuthenticatedExtraction, Violation> {
    let meta = adapter.extract_metadata();
    let inputs = adapter.extract_tainted_inputs();

    // Start with Unauthed context
    let unauthed = Ctx::new_unauthed(meta.request_id);

    // Transition to Authed (fails if no principal)
    let authed = unauthed.authenticate(meta.principal)?;

    Ok(AuthenticatedExtraction {
        context: authed,
        inputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Principal;

    #[test]
    fn extract_unauthed_succeeds_without_principal() {
        let adapter = RequestAdapter::new("req-unauth-test".to_string());
        let extraction = extract_unauthed(&adapter);

        assert_eq!(extraction.context.request_id(), "req-unauth-test");
        assert!(extraction.context.principal().is_none());
    }

    #[test]
    fn extract_unauthed_includes_tainted_inputs() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        adapter.add_query_param("q".to_string(), "search".to_string());
        adapter.add_header("X-Custom".to_string(), "value".to_string());

        let extraction = extract_unauthed(&adapter);

        assert_eq!(extraction.inputs.query_params_count(), 1);
        assert_eq!(extraction.inputs.headers_count(), 1);
    }

    #[test]
    fn extract_authed_succeeds_with_principal() {
        let mut adapter = RequestAdapter::new("req-auth-test".to_string());
        adapter.set_principal(Some(Principal {
            id: "user-123".to_string(),
            name: "Test User".to_string(),
        }));

        let extraction = extract_authed(&adapter).expect("should succeed with principal");

        assert_eq!(extraction.context.request_id(), "req-auth-test");
        assert!(extraction.context.principal().is_some());
        assert_eq!(extraction.context.principal().unwrap().id, "user-123");
    }

    #[test]
    fn extract_authed_fails_without_principal() {
        let adapter = RequestAdapter::new("req-no-principal".to_string());
        let result = extract_authed(&adapter);

        assert!(result.is_err());
    }

    #[test]
    fn extract_authed_includes_tainted_inputs() {
        let mut adapter = RequestAdapter::new("req-2".to_string());
        adapter.set_principal(Some(Principal {
            id: "user-1".to_string(),
            name: "Alice".to_string(),
        }));
        adapter.add_query_param("filter".to_string(), "active".to_string());
        adapter.add_path_param("id".to_string(), "42".to_string());

        let extraction = extract_authed(&adapter).expect("should succeed");

        assert_eq!(extraction.inputs.query_params_count(), 1);
        assert_eq!(extraction.inputs.path_params_count(), 1);
    }

    #[test]
    fn unauthed_context_has_no_capabilities() {
        let adapter = RequestAdapter::new("req-3".to_string());
        let extraction = extract_unauthed(&adapter);

        // Ctx<Unauthed> doesn't have capability methods
        // Just verify it was created successfully
        assert_eq!(extraction.context.request_id(), "req-3");
    }

    #[test]
    fn authed_context_has_no_capabilities() {
        let mut adapter = RequestAdapter::new("req-4".to_string());
        adapter.set_principal(Some(Principal {
            id: "user-1".to_string(),
            name: "Bob".to_string(),
        }));

        let extraction = extract_authed(&adapter).expect("should succeed");

        // Ctx<Authed> doesn't have capability methods either
        // Only Ctx<Authorized> has .log(), .http(), etc.
        assert!(extraction.context.principal().is_some());
    }
}
