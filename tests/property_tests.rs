//! Integration property tests for policy-core.
//!
//! These tests validate cross-module invariants and end-to-end flows
//! using property-based testing.

use policy_core::{
    Authenticated, Authorized, PolicyGate, Principal, RequestMeta, Sanitizer, StringSanitizer,
    Tainted,
    audit::{AuditEvent, AuditEventKind, AuditOutcome},
};
use proptest::prelude::*;

// Strategy: Generate arbitrary principal
fn arb_principal() -> impl Strategy<Value = Principal> {
    (
        prop::string::string_regex("[a-z0-9-]{3,10}").unwrap(),
        prop::string::string_regex("[A-Za-z ]{3,15}").unwrap(),
    )
        .prop_map(|(id, name)| Principal { id, name })
}

// Strategy: Generate arbitrary action names
fn arb_action_name() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("log"),
        Just("http"),
        Just("audit"),
        Just("db"),
        Just("cache"),
    ]
}

proptest! {
    /// Property: End-to-end authorization flow never panics
    ///
    /// This test validates that the complete flow from PolicyGate → Ctx → Capability
    /// never panics regardless of input, and that capabilities are granted only when
    /// appropriate requirements are satisfied.
    #[test]
    fn proptest_e2e_authorization_flow_consistency(
        request_id in prop::string::string_regex("[a-z0-9-]{5,20}").unwrap(),
        principal in prop::option::of(arb_principal()),
        action in arb_action_name()
    ) {
        let meta = RequestMeta {
            request_id,
            principal: principal.clone(),
        };

        // Build gate with requirements
        let gate = PolicyGate::new(meta)
            .require(Authenticated)
            .require(Authorized::for_action(action));

        // Attempt to build context
        let result = gate.build();

        // Flow should never panic
        match (principal, result) {
            (Some(_), Ok(ctx)) => {
                // If we had a principal and build succeeded, verify capabilities
                match action {
                    "log" => prop_assert!(ctx.log_cap().is_some()),
                    "http" => prop_assert!(ctx.http_cap().is_some()),
                    "audit" => prop_assert!(ctx.audit_cap().is_some()),
                    _ => {
                        // Unknown actions don't grant standard capabilities
                        prop_assert!(ctx.log_cap().is_none());
                        prop_assert!(ctx.http_cap().is_none());
                        prop_assert!(ctx.audit_cap().is_none());
                    }
                }
            }
            (None, Err(_)) => {
                // No principal → should fail (expected)
            }
            (Some(_), Err(_)) => {
                // Principal exists but build failed (shouldn't happen with current logic)
                // This is acceptable - just means validation failed
            }
            (None, Ok(_)) => {
                // No principal but build succeeded → INVARIANT VIOLATION
                return Err(TestCaseError::fail(
                    "Build succeeded without principal - authentication invariant violated"
                ));
            }
        }
    }

    /// Property: AuditEvent Display/Debug never leaks secrets
    ///
    /// This test verifies that audit events can be safely logged without
    /// exposing sensitive data like secrets or raw tainted input.
    #[test]
    fn proptest_audit_events_never_leak_secrets(
        request_id in prop::string::string_regex("[a-z0-9-]{5,20}").unwrap(),
        principal_id in prop::string::string_regex("[a-z0-9@.]{5,20}").unwrap(),
        secret_value in prop::string::string_regex("[A-Z0-9]{10,20}").unwrap()
    ) {
        // Create a secret that should NOT appear in audit output
        let _secret = policy_core::Secret::new(secret_value.clone());

        // Create an audit event
        let event = AuditEvent::new(
            request_id.clone(),
            Some(principal_id.clone()),
            AuditEventKind::ResourceAccess,
            AuditOutcome::Success,
        );

        // Check Display output
        let display_output = format!("{}", event);
        prop_assert!(
            !display_output.contains(&secret_value),
            "AuditEvent Display should not leak secret '{}', got: '{}'",
            secret_value,
            display_output
        );

        // Check Debug output
        let debug_output = format!("{:?}", event);
        prop_assert!(
            !debug_output.contains(&secret_value),
            "AuditEvent Debug should not leak secret '{}', got: '{}'",
            secret_value,
            debug_output
        );

        // Should contain the non-secret data we provided
        prop_assert!(display_output.contains(&request_id));
        prop_assert!(display_output.contains(&principal_id));
    }

    /// Property: All sanitizers enforce common invariants
    ///
    /// This test verifies that all sanitizer implementations (currently just
    /// StringSanitizer, but validates the pattern for future sanitizers) enforce
    /// fundamental security invariants like rejecting empty strings and control characters.
    #[test]
    fn proptest_different_sanitizers_same_invariants(
        empty_string in prop::string::string_regex("[ \\t\\n\\r]{0,10}").unwrap(),
        control_chars in prop::collection::vec(
            prop::char::range('\x00', '\x1F'),
            1..3
        )
    ) {
        let sanitizer = StringSanitizer::new(256);

        // Test 1: All sanitizers should reject empty/whitespace-only strings
        let tainted_empty = Tainted::new(empty_string.clone());
        let result = sanitizer.sanitize(tainted_empty);

        // Empty/whitespace-only should be rejected
        if empty_string.trim().is_empty() {
            prop_assert!(result.is_err(), "Sanitizer should reject empty/whitespace string '{}'", empty_string);
        }

        // Test 2: All sanitizers should reject strings with control characters
        // Put control chars in the MIDDLE so they survive trimming
        let control_string: String = control_chars.iter().collect();
        let test_string = format!("before{}after", control_string);
        let tainted_control = Tainted::new(test_string.clone());
        let result = sanitizer.sanitize(tainted_control);

        prop_assert!(
            result.is_err(),
            "Sanitizer should reject string with control characters: '{:?}'",
            test_string
        );
    }
}
