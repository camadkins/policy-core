//! Integration property tests for policy-core.
//!
//! These tests validate cross-module invariants and end-to-end flows
//! using property-based testing.

use policy_core::{
    actions, Authenticated, Authorized, PolicyGate, Principal, RequestMeta, Sanitizer,
    StringSanitizer, Tainted,
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
        Just(actions::LOG),
        Just(actions::HTTP),
        Just(actions::AUDIT),
        Just("db"),    // Non-standard action for testing unknown capabilities
        Just("cache"), // Non-standard action for testing unknown capabilities
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
        let build_result = gate.build();

        // Guard: No principal should fail
        if principal.is_none() {
            prop_assert!(
                build_result.is_err(),
                "Build succeeded without principal - authentication invariant violated"
            );
            return Ok(());
        }

        // Guard: Principal exists, build must succeed
        let ctx = build_result.map_err(|e| {
            TestCaseError::fail(format!(
                "PolicyGate build failed with valid Principal present. \
                 Expected: Principal existence satisfies authentication policies in basic authorization mode. \
                 Error: {:?}",
                e
            ))
        })?;

        // Verify capability matches requested action
        match action {
            actions::LOG => prop_assert!(ctx.log_cap().is_some()),
            actions::HTTP => prop_assert!(ctx.http_cap().is_some()),
            actions::AUDIT => prop_assert!(ctx.audit_cap().is_some()),
            _ => {
                // Unknown actions don't grant standard capabilities
                prop_assert!(ctx.log_cap().is_none());
                prop_assert!(ctx.http_cap().is_none());
                prop_assert!(ctx.audit_cap().is_none());
            }
        }
    }

    /// Property: StringSanitizer enforces fundamental security invariants
    ///
    /// This test verifies that StringSanitizer correctly rejects:
    /// - Empty/whitespace-only strings (prevents validation bypass)
    /// - Control characters (prevents injection attacks)
    ///
    /// ## Real-World Threats Prevented
    ///
    /// ### Log Injection (CWE-117)
    ///
    /// **Attack:** User submits `"normaluser\nadmin logged in successfully"`
    ///
    /// **Impact:** The embedded newline `\n` creates a fake log entry. When logs are parsed,
    /// it appears that "admin logged in successfully" is a separate legitimate entry,
    /// corrupting the audit trail and enabling privilege escalation attacks.
    ///
    /// **Defense:** StringSanitizer rejects all C0 control characters (0x00-0x1F),
    /// including `\n`, `\r`, and `\t`.
    ///
    /// ### Terminal Escape Injection
    ///
    /// **Attack:** Input `"\x1b[2J\x1b[H[SYSTEM] All clear"` (ANSI clear screen + cursor home)
    ///
    /// **Impact:** When an administrator views application logs in a terminal,
    /// the ANSI escape sequences are interpreted, clearing the screen and repositioning
    /// the cursor. The attacker can hide previous log entries or display fake system messages.
    ///
    /// **Defense:** ANSI escape sequences start with ESC (`\x1b`, a C0 control character),
    /// which StringSanitizer rejects.
    ///
    /// ### CRLF Injection (HTTP Header Injection)
    ///
    /// **Attack:** Input `"value\r\nX-Injected: malicious\r\n\r\n<script>alert(1)</script>"`
    ///
    /// **Impact:** If this string is used in HTTP headers or responses, the CRLF sequence
    /// (`\r\n`) injects additional headers or even HTML content, enabling XSS, cache poisoning,
    /// or session fixation attacks.
    ///
    /// **Defense:** Both `\r` (0x0D) and `\n` (0x0A) are rejected as control characters.
    ///
    /// ## Additional Protections
    ///
    /// - **C1 control characters** (0x80-0x9F): Unicode control codes rejected to prevent
    ///   bidirectional text spoofing and other Unicode-based attacks
    /// - **DEL character** (0x7F): Historically caused issues in terminal processing
    /// - **Empty/whitespace bypass**: Prevents attackers from submitting empty strings
    ///   to bypass required field validation
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
        let sanitizer = StringSanitizer::new(256).unwrap();

        // Test 1: All sanitizers should reject empty/whitespace-only strings
        let tainted_empty = Tainted::new(empty_string.clone());
        let empty_check = sanitizer.sanitize(tainted_empty);

        // Empty/whitespace-only should be rejected
        if empty_string.trim().is_empty() {
            prop_assert!(empty_check.is_err(), "Sanitizer should reject empty/whitespace string '{}'", empty_string);
        }

        // Test 2: All sanitizers should reject strings with control characters
        // Put control chars in the MIDDLE so they survive trimming
        let control_string: String = control_chars.iter().collect();
        let test_string = format!("before{}after", control_string);
        let tainted_control = Tainted::new(test_string.clone());
        let control_check = sanitizer.sanitize(tainted_control);

        prop_assert!(
            control_check.is_err(),
            "Sanitizer should reject string with control characters: '{:?}'",
            test_string
        );
    }
}
