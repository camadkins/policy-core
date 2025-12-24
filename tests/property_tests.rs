//! Integration property tests for policy-core.
//!
//! These tests validate cross-module invariants and end-to-end flows
//! using property-based testing.

use policy_core::{
    Authenticated, Authorized, PolicyGate, Principal, RequestMeta, Sanitizer, StringSanitizer,
    Tainted,
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
            (Some(_), Err(e)) => {
                // Principal exists but build failed → INVARIANT VIOLATION
                // With current M2 logic, principal existence satisfies all policies
                return Err(TestCaseError::fail(format!(
                    "Build failed despite principal existing - M2 invariant violated: {:?}",
                    e
                )));
            }
            (None, Ok(_)) => {
                // No principal but build succeeded → INVARIANT VIOLATION
                return Err(TestCaseError::fail(
                    "Build succeeded without principal - authentication invariant violated"
                ));
            }
        }
    }

    /// Property: StringSanitizer enforces fundamental security invariants
    ///
    /// This test verifies that StringSanitizer correctly rejects empty/whitespace-only
    /// strings and strings containing control characters.
    #[test]
    fn proptest_string_sanitizer_invariants(
        empty_string in prop::string::string_regex("[ \\t\\n\\r]{0,10}").unwrap(),
        control_chars in prop::collection::vec(
            prop_oneof![
                prop::char::range('\x00', '\x1F'),  // C0 controls
                Just('\x7F'),                        // DEL
                prop::char::range('\u{80}', '\u{9F}'),  // C1 controls
            ],
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
