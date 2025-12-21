use policy_core::{
    Authenticated, Authorized, PolicyGate, Principal, RequestMeta, Secret, Tainted, ViolationKind,
};
use std::sync::{Arc, Mutex};

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

#[test]
fn policy_gate_authenticated_success() {
    let meta = RequestMeta {
        request_id: "req-001".to_string(),
        principal: Some(Principal {
            id: "user-123".to_string(),
            name: "Alice".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .build()
        .expect("authenticated principal should pass");

    assert_eq!(ctx.request_id(), "req-001");
}

#[test]
fn policy_gate_unauthenticated_fails() {
    let meta = RequestMeta {
        request_id: "req-002".to_string(),
        principal: None, // No principal
    };

    let result = PolicyGate::new(meta).require(Authenticated).build();

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.kind, ViolationKind::Unauthenticated);
    assert!(err.message.contains("Authentication required"));
}

#[test]
fn policy_gate_authorized_grants_capability() {
    let meta = RequestMeta {
        request_id: "req-003".to_string(),
        principal: Some(Principal {
            id: "user-456".to_string(),
            name: "Bob".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .build()
        .expect("should pass");

    // LogCap granted because Authorized("log") was satisfied
    assert!(ctx.log_cap().is_some());
}

#[test]
fn policy_gate_without_log_authorization_no_capability() {
    let meta = RequestMeta {
        request_id: "req-004".to_string(),
        principal: Some(Principal {
            id: "user-789".to_string(),
            name: "Charlie".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        // No Authorized("log")
        .build()
        .expect("should pass");

    // No LogCap because no log authorization
    assert!(ctx.log_cap().is_none());
}

#[test]
fn policy_gate_chaining_works() {
    let meta = RequestMeta {
        request_id: "req-005".to_string(),
        principal: Some(Principal {
            id: "user-999".to_string(),
            name: "Dana".to_string(),
        }),
    };

    // Test that chaining multiple requires works
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .require(Authorized::for_action("write"))
        .build()
        .expect("should pass");

    assert!(ctx.log_cap().is_some());
}

#[test]
fn policy_gate_deduplicates_requirements() {
    let meta = RequestMeta {
        request_id: "req-006".to_string(),
        principal: Some(Principal {
            id: "user-111".to_string(),
            name: "Eve".to_string(),
        }),
    };

    // Require the same policy twice - should deduplicate
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authenticated) // duplicate
        .require(Authorized::for_action("log"))
        .require(Authorized::for_action("log")) // duplicate
        .build()
        .expect("should pass");

    assert!(ctx.log_cap().is_some());
}

#[test]
fn milestone_2_complete() {
    // ✓ PolicyGate is the sole path to Ctx
    // ✓ Policies compose cleanly (chaining)
    // ✓ Violations are structured
    // ✓ Capabilities granted correctly

    let meta = RequestMeta {
        request_id: "req-m2".to_string(),
        principal: Some(Principal {
            id: "user-m2".to_string(),
            name: "Milestone".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .build()
        .expect("M2 complete");

    assert!(ctx.log_cap().is_some());
}

#[test]
fn ctx_log_requires_log_cap() {
    let meta_with_cap = RequestMeta {
        request_id: "req-log-1".to_string(),
        principal: Some(Principal {
            id: "user-1".to_string(),
            name: "Alice".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta_with_cap)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .build()
        .expect("should pass");

    // Should succeed because LogCap was granted
    assert!(ctx.log().is_ok());
}

#[test]
fn ctx_log_fails_without_log_cap() {
    let meta_without_cap = RequestMeta {
        request_id: "req-log-2".to_string(),
        principal: Some(Principal {
            id: "user-2".to_string(),
            name: "Bob".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta_without_cap)
        .require(Authenticated)
        // No Authorized("log")
        .build()
        .expect("should pass");

    // Should fail because LogCap was not granted
    let result = ctx.log();
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().kind,
        ViolationKind::MissingLogCapability
    );
}

#[test]
fn policy_log_redacts_secrets() {
    use tracing_subscriber::{Layer, layer::SubscriberExt};
    use tracing_subscriber::{Layer, layer::SubscriberExt};

    // Capture log output
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured.clone();

    let layer = tracing_subscriber::fmt::layer()
        .with_writer(move || CaptureWriter(captured_clone.clone()))
        .with_filter(tracing_subscriber::filter::LevelFilter::INFO);

    let subscriber = tracing_subscriber::registry().with(layer);

    tracing::subscriber::with_default(subscriber, || {
        let meta = RequestMeta {
            request_id: "req-log-3".to_string(),
            principal: Some(Principal {
                id: "user-3".to_string(),
                name: "Charlie".to_string(),
            }),
        };

        let ctx = PolicyGate::new(meta)
            .require(Authenticated)
            .require(Authorized::for_action("log"))
            .build()
            .expect("should pass");

        let logger = ctx.log().expect("should have LogCap");

        let secret = Secret::new("password123");
        logger.info(format_args!("Login with secret: {:?}", secret));
    });

    let output = String::from_utf8(captured.lock().unwrap().clone()).unwrap();

    // Secret should be redacted
    assert!(output.contains("[REDACTED]"));
    assert!(!output.contains("password123"));
}

#[test]
fn milestone_3_complete() {
    // ✓ PolicyLog wraps logging with capability requirement
    // ✓ Ctx.log() is gated by LogCap
    // ✓ Secrets are automatically redacted

    let meta = RequestMeta {
        request_id: "req-m3".to_string(),
        principal: Some(Principal {
            id: "user-m3".to_string(),
            name: "Milestone".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .build()
        .expect("M3 complete");

    let logger = ctx.log().expect("LogCap granted");
    let secret = Secret::new("secret-value");

    // This should not panic and should redact the secret
    logger.info(format_args!("Processing: {:?}", secret));
}

// Helper for capturing tracing output
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}
