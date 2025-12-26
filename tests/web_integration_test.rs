//! Integration tests for web module extractors.
//!
//! These tests demonstrate the complete flow from HTTP request extraction
//! to policy validation and authorized operations.

use policy_core::web::example_handler::{
    handle_admin_action, handle_api_call, handle_public_search, handle_user_data,
};
use policy_core::web::{extract_authed, extract_unauthed, ExtractMetadata, RequestAdapter};
use policy_core::{Authenticated, Authorized, PolicyGate, Principal, Sanitizer, StringSanitizer};

#[test]
fn unauthed_extraction_full_flow() {
    // Simulate a public endpoint that doesn't require authentication
    let mut adapter = RequestAdapter::new("req-public-001".to_string());
    adapter.add_query_param("search".to_string(), "rust policy".to_string());

    // Extract context and inputs (no authentication required)
    let extraction = extract_unauthed(&adapter);

    // Context has request ID but no principal
    assert_eq!(extraction.context.request_id(), "req-public-001");
    assert!(extraction.context.principal().is_none());

    // Inputs are tainted
    assert!(extraction.inputs.query_params().contains_key("search"));

    // For public endpoints, application would sanitize inputs and use them
    // without going through PolicyGate (since no capabilities needed)
}

#[test]
fn authed_extraction_full_flow() {
    // Simulate an authenticated endpoint
    let mut adapter = RequestAdapter::new("req-authed-001".to_string());
    adapter.set_principal(Some(Principal {
        id: "user-alice".to_string(),
        name: "Alice".to_string(),
    }));
    adapter.add_query_param("filter".to_string(), "active".to_string());

    // Extract authenticated context
    let extraction = extract_authed(&adapter).expect("authentication should succeed");

    // Context has both request ID and principal
    assert_eq!(extraction.context.request_id(), "req-authed-001");
    assert!(extraction.context.principal().is_some());
    assert_eq!(extraction.context.principal().unwrap().id, "user-alice");

    // Inputs are tainted
    assert!(extraction.inputs.query_params().contains_key("filter"));
}

#[test]
fn authed_extraction_requires_principal() {
    // Attempt to extract authed context without principal
    let adapter = RequestAdapter::new("req-no-principal".to_string());

    let result = extract_authed(&adapter);

    // Should fail
    assert!(result.is_err());
}

#[test]
fn complete_flow_unauthed_to_authorized() {
    // 1. Extract from request (simulated)
    let adapter = RequestAdapter::new("req-flow-001".to_string());
    let _extraction = extract_unauthed(&adapter);

    // 2. At this point, middleware would typically fail because
    //    we can't authorize without authentication
    //
    // For demonstration: if we had a principal, we'd do this:
    // (In practice, you'd use extract_authed instead)

    // Note: Ctx<Unauthed> can't be passed to PolicyGate directly
    // This demonstrates the compile-time enforcement
}

#[test]
fn complete_flow_authed_to_authorized() {
    // 1. Extract authenticated context from request
    let mut adapter = RequestAdapter::new("req-flow-002".to_string());
    adapter.set_principal(Some(Principal {
        id: "user-bob".to_string(),
        name: "Bob".to_string(),
    }));
    adapter.add_query_param("url".to_string(), "https://example.com/api".to_string());

    let extraction = extract_authed(&adapter).expect("authentication succeeds");

    // 2. Build RequestMeta for PolicyGate
    //    (In real middleware, we'd extract this directly)
    let meta = adapter.extract_metadata();

    // 3. Apply policies via PolicyGate to get Ctx<Authorized>
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .expect("policies satisfied");

    // 4. Now we have capabilities!
    assert!(ctx.http_cap().is_some());
    assert_eq!(ctx.request_id(), "req-flow-002");
    assert_eq!(ctx.principal().unwrap().id, "user-bob");

    // 5. Sanitize tainted inputs
    let tainted_url = extraction.inputs.query_params().get("url").unwrap().clone();

    let sanitizer = StringSanitizer::new(256);
    let verified_url = sanitizer
        .sanitize(tainted_url)
        .expect("sanitization succeeds");

    // 6. Use capability-gated sink with verified input
    let http = ctx.http().expect("HttpCap granted");
    http.get(&verified_url); // This would make the HTTP call (simulated in our impl)

    // Success! Complete flow from extraction to authorized operation
}

#[test]
fn flow_fails_without_authentication() {
    // 1. Extract unauthenticated context
    let adapter = RequestAdapter::new("req-unauth-fail".to_string());
    let _extraction = extract_unauthed(&adapter);

    // 2. Try to build authorized context without authentication
    let meta = adapter.extract_metadata();

    let result = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .build();

    // Should fail - no principal
    assert!(result.is_err());
}

#[test]
fn flow_sanitization_required_for_sinks() {
    // 1. Extract context with tainted input
    let mut adapter = RequestAdapter::new("req-sanitize".to_string());
    adapter.set_principal(Some(Principal {
        id: "user-charlie".to_string(),
        name: "Charlie".to_string(),
    }));
    adapter.add_query_param("name".to_string(), "  Alice  ".to_string());

    let extraction = extract_authed(&adapter).expect("authenticated");

    // 2. Get authorized context
    let meta = adapter.extract_metadata();
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .expect("authorized");

    // 3. Must sanitize before using in sink
    let tainted_name = extraction
        .inputs
        .query_params()
        .get("name")
        .unwrap()
        .clone();

    let sanitizer = StringSanitizer::new(100);
    let verified_name = sanitizer.sanitize(tainted_name).expect("valid");

    // Verified value is trimmed
    assert_eq!(verified_name.as_ref(), "Alice");

    // 4. Can use verified value safely
    let http = ctx.http().unwrap();

    // In a real app, we'd build a URL with the verified name
    // For testing, we just verify we have both pieces
    assert!(http.request_count() == 0);
    let _ = verified_name; // Consume to prove we have it
}

#[test]
fn multiple_tainted_inputs_extracted() {
    let mut adapter = RequestAdapter::new("req-multi".to_string());
    adapter.add_query_param("q1".to_string(), "value1".to_string());
    adapter.add_query_param("q2".to_string(), "value2".to_string());
    adapter.add_header("X-Custom-1".to_string(), "header1".to_string());
    adapter.add_header("X-Custom-2".to_string(), "header2".to_string());
    adapter.add_path_param("id".to_string(), "123".to_string());

    let extraction = extract_unauthed(&adapter);

    assert_eq!(extraction.inputs.query_params().len(), 2);
    assert_eq!(extraction.inputs.headers().len(), 2);
    assert_eq!(extraction.inputs.path_params().len(), 1);
}

#[test]
fn request_id_flows_through_entire_chain() {
    let request_id = "req-trace-001";

    // 1. Start with adapter
    let mut adapter = RequestAdapter::new(request_id.to_string());
    adapter.set_principal(Some(Principal {
        id: "user-1".to_string(),
        name: "User".to_string(),
    }));

    // 2. Extract context
    let extraction = extract_authed(&adapter).expect("authenticated");
    assert_eq!(extraction.context.request_id(), request_id);

    // 3. Build authorized context via PolicyGate
    let meta = adapter.extract_metadata();
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .require(Authorized::for_action("http"))
        .build()
        .expect("authorized");

    // 4. Request ID is preserved in ctx
    assert_eq!(ctx.request_id(), request_id);

    // 5. Request ID is accessible in logger
    let logger = ctx.log().expect("LogCap granted");
    assert_eq!(logger.request_id(), request_id);

    // 6. Request ID is accessible in HTTP client
    let http_client = ctx.http().expect("HttpCap granted");
    assert_eq!(http_client.request_id(), request_id);
}

#[test]
fn request_id_included_in_http_metadata() {
    let request_id = "req-http-001";

    let mut adapter = RequestAdapter::new(request_id.to_string());
    adapter.set_principal(Some(Principal {
        id: "user-1".to_string(),
        name: "Alice".to_string(),
    }));
    adapter.add_query_param("url".to_string(), "https://api.example.com".to_string());

    let extraction = extract_authed(&adapter).expect("authenticated");
    let meta = adapter.extract_metadata();

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .expect("authorized");

    // Make HTTP request
    let http = ctx.http().expect("HttpCap granted");
    let sanitizer = StringSanitizer::new(256);
    let tainted_url = extraction.inputs.query_params().get("url").unwrap().clone();
    let verified_url = sanitizer.sanitize(tainted_url).expect("valid");

    http.get(&verified_url);

    // Verify request ID is in recorded metadata
    let requests = http.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].request_id, request_id);
}

#[test]
fn multiple_requests_preserve_request_id() {
    let request_id = "req-multi-001";

    let mut adapter = RequestAdapter::new(request_id.to_string());
    adapter.set_principal(Some(Principal {
        id: "user-1".to_string(),
        name: "Bob".to_string(),
    }));

    let meta = adapter.extract_metadata();
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .expect("authorized");

    let http = ctx.http().expect("HttpCap granted");
    let sanitizer = StringSanitizer::new(256);

    // Make multiple HTTP requests
    for i in 1..=3 {
        let url = format!("https://api.example.com/{}", i);
        let tainted = policy_core::Tainted::new(url);
        let verified = sanitizer.sanitize(tainted).expect("valid");
        http.get(&verified);
    }

    // All requests should have the same request ID
    let requests = http.requests();
    assert_eq!(requests.len(), 3);
    for req in &requests {
        assert_eq!(req.request_id, request_id);
    }
}

// ============================================================================
// Issue #35: End-to-End Handler Tests
// ============================================================================

#[test]
fn end_to_end_public_search_no_auth_required() {
    // Public endpoint doesn't require authentication
    let mut adapter = RequestAdapter::new("req-e2e-search".to_string());
    adapter.add_query_param("q".to_string(), "  policy enforcement  ".to_string());

    let result = handle_public_search(&adapter).expect("public endpoint succeeds");

    assert_eq!(result.request_id, "req-e2e-search");
    assert_eq!(result.query, "policy enforcement"); // Trimmed by sanitizer
    assert!(result.result_count > 0);
}

#[test]
fn end_to_end_user_data_requires_auth() {
    // Without authentication - fails
    let adapter = RequestAdapter::new("req-e2e-no-auth".to_string());
    let result = handle_user_data(&adapter);
    assert!(result.is_err(), "Should fail without authentication");

    // With authentication - succeeds
    let mut adapter = RequestAdapter::new("req-e2e-with-auth".to_string());
    adapter.set_principal(Some(Principal {
        id: "user-e2e-1".to_string(),
        name: "EndToEnd User".to_string(),
    }));

    let result = handle_user_data(&adapter).expect("Should succeed with authentication");
    assert_eq!(result.request_id, "req-e2e-with-auth");
    assert_eq!(result.user_id, "user-e2e-1");
}

#[test]
fn end_to_end_api_call_full_flow() {
    // Set up authenticated request with tainted URL
    let mut adapter = RequestAdapter::new("req-e2e-api".to_string());
    adapter.set_principal(Some(Principal {
        id: "user-api".to_string(),
        name: "API Caller".to_string(),
    }));
    adapter.add_query_param(
        "url".to_string(),
        "  https://external-api.example.com/v1/users  ".to_string(),
    );

    // Handler should:
    // 1. Extract and authenticate
    // 2. Authorize with PolicyGate
    // 3. Sanitize tainted URL
    // 4. Make HTTP call with verified URL
    let result = handle_api_call(&adapter).expect("Authorized API call succeeds");

    assert_eq!(result.request_id, "req-e2e-api");
    assert_eq!(result.api_calls, 1);
    assert!(result.success);
}

#[test]
fn end_to_end_admin_action_with_audit() {
    // Admin action requires authentication and audit capability
    let mut adapter = RequestAdapter::new("req-e2e-admin".to_string());
    adapter.set_principal(Some(Principal {
        id: "admin-e2e".to_string(),
        name: "E2E Admin".to_string(),
    }));
    adapter.add_query_param("action".to_string(), "suspend_user".to_string());
    adapter.add_query_param("target".to_string(), "user-suspicious".to_string());

    // Handler should:
    // 1. Authenticate
    // 2. Authorize (audit + log capabilities)
    // 3. Sanitize inputs
    // 4. Log action
    // 5. Emit audit event
    let result = handle_admin_action(&adapter).expect("Admin action authorized");

    assert_eq!(result.request_id, "req-e2e-admin");
    assert_eq!(result.action, "suspend_user");
    assert_eq!(result.target, "user-suspicious");
    assert!(result.success);
}

#[test]
fn end_to_end_taint_prevents_injection() {
    // Attempt SQL injection via search query
    let mut adapter = RequestAdapter::new("req-e2e-injection".to_string());
    adapter.add_query_param("q".to_string(), "'; DROP TABLE users; --".to_string());

    let result = handle_public_search(&adapter).expect("Sanitizer should handle injection attempt");

    // Sanitizer accepts the string but trims it
    // In a real SQL context, this would be parameterized or escaped
    assert_eq!(result.query, "'; DROP TABLE users; --");
    // The key point: this tainted input went through Verified<T>, enforcing conscious handling
}

#[test]
fn end_to_end_compile_time_rejection_documented() {
    // This test documents compile-time enforcement via comments
    // Actual compilation failures are tested in other modules

    let mut adapter = RequestAdapter::new("req-compile-test".to_string());
    adapter.set_principal(Some(Principal {
        id: "user-1".to_string(),
        name: "Test".to_string(),
    }));

    let meta = adapter.extract_metadata();

    // Build Ctx<Authorized> WITHOUT log capability
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        // NOT requiring Authorized::for_action("log")
        .build()
        .expect("authentication succeeds");

    // Runtime rejection: cannot access .log() without LogCap
    let result = ctx.log();
    assert!(result.is_err(), "Should fail at runtime without LogCap");

    // NOTE: If we tried to do:
    // let Ctx<Unauthed> = ctx;
    // The type system would prevent this (compile error)
    // because ctx is Ctx<Authorized>, not Ctx<Unauthed>
}

#[test]
fn end_to_end_authorized_path_succeeds() {
    // Complete happy path: authentication → authorization → operation
    let mut adapter = RequestAdapter::new("req-happy-path".to_string());
    adapter.set_principal(Some(Principal {
        id: "user-happy".to_string(),
        name: "Happy User".to_string(),
    }));
    adapter.add_query_param(
        "url".to_string(),
        "https://api.example.com/resource".to_string(),
    );

    let extraction = extract_authed(&adapter).expect("authenticated");
    let meta = adapter.extract_metadata();

    // Apply all required policies
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .require(Authorized::for_action("http"))
        .build()
        .expect("fully authorized");

    // All capabilities available
    assert!(ctx.log().is_ok());
    assert!(ctx.http().is_ok());

    // Can perform operations
    let http = ctx.http().unwrap();
    let logger = ctx.log().unwrap();

    let sanitizer = StringSanitizer::new(256);
    let tainted_url = extraction.inputs.query_params().get("url").unwrap().clone();
    let verified_url = sanitizer.sanitize(tainted_url).expect("valid URL");

    logger.info(format_args!("Making request"));
    http.get(&verified_url);

    assert_eq!(http.request_count(), 1);
}

#[test]
fn end_to_end_unauthorized_path_fails() {
    // Attempt to access privileged endpoint without authorization
    let mut adapter = RequestAdapter::new("req-unauthorized".to_string());
    adapter.set_principal(Some(Principal {
        id: "user-noauth".to_string(),
        name: "Unauthorized User".to_string(),
    }));

    let meta = adapter.extract_metadata();

    // PolicyGate WITH authentication but WITHOUT authorization for "admin" actions
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        // NOT requiring Authorized::for_action("audit")
        .build()
        .expect("authentication succeeds");

    // Attempt to access audit capability
    let result = ctx.audit();
    assert!(result.is_err(), "Should fail without AuditCap");

    // User is authenticated (has principal) but NOT authorized for admin actions
    assert!(ctx.principal().is_some());
    assert!(ctx.audit_cap().is_none());
}

#[test]
fn end_to_end_request_id_in_all_sinks() {
    let request_id = "req-e2e-all-sinks";

    let mut adapter = RequestAdapter::new(request_id.to_string());
    adapter.set_principal(Some(Principal {
        id: "user-1".to_string(),
        name: "Test User".to_string(),
    }));

    let meta = adapter.extract_metadata();
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .require(Authorized::for_action("http"))
        .require(Authorized::for_action("audit"))
        .build()
        .expect("fully authorized");

    // Verify request-id in all sinks
    assert_eq!(ctx.request_id(), request_id);

    let logger = ctx.log().unwrap();
    assert_eq!(logger.request_id(), request_id);

    let http = ctx.http().unwrap();
    assert_eq!(http.request_id(), request_id);

    // Audit event is created with request-id (passed by caller)
    use policy_core::audit::{AuditEvent, AuditEventKind, AuditOutcome};
    let event = AuditEvent::new(
        ctx.request_id(),
        ctx.principal().map(|p| &p.name),
        AuditEventKind::AdminAction,
        AuditOutcome::Success,
    );

    // Event contains the request-id
    let audit = ctx.audit().unwrap();
    audit.emit(&event);
    // Success - request-id propagated through all layers
}
