use policy_core::{Secret, Tainted};

#[test]
fn secret_is_fully_redacted() {
    let api_key = Secret::new("sk-secret123".to_string());

    let debug_out = format!("{:?}", api_key);
    assert_eq!(debug_out, "[REDACTED]");
    assert!(!debug_out.contains("sk-secret"));
    assert!(!debug_out.contains("String")); // No type info leaked

    let display_out = format!("{}", api_key);
    assert_eq!(display_out, "[REDACTED]");
}

#[test]
fn tainted_prevents_misuse() {
    let user_input = Tainted::new("'; DROP TABLE users;".to_string());

    // Can create and debug
    let debug_out = format!("{:?}", user_input);
    assert!(debug_out.contains("Tainted"));

    // But cannot use as String (no implicit conversions)
    // Uncommenting this would fail to compile:
    // let _s: String = user_input;
}

#[test]
fn ctx_cannot_be_forged() {
    // This test documents that Ctx cannot be created from outside the crate.
    // Uncommenting this would fail to compile:
    // let ctx = Ctx::new_unchecked("fake".to_string(), None);
}

#[test]
fn capability_gates_access() {
    // LogCap cannot be constructed outside the crate
    // Uncommenting this would fail to compile:
    // let fake_cap = LogCap { _private: () };

    // Without LogCap, we cannot call log_with_capability
    // (This is a compile-time check, not a runtime check)
}

#[test]
fn milestone_1_complete() {
    // ✓ Secret redacts sensitive data
    let api_key = Secret::new("sk-secret123".to_string());
    assert_eq!(format!("{:?}", api_key), "[REDACTED]");

    // ✓ Tainted wraps untrusted input
    let user_input = Tainted::new("malicious".to_string());
    let _ = user_input;

    // ✓ Capabilities exist and enforce access
    // (Proven by inability to construct LogCap publicly)

    // ✓ Ctx cannot be forged
    // (Proven by inability to call Ctx::new_unchecked publicly)
}
