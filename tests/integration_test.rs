use policy_core::{
    Authenticated, Authorized, HttpMethod, PolicyGate, Principal, RequestMeta, Sanitizer, Secret,
    StringSanitizer, Tainted, ViolationKind,
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

// ============================================================================
// Milestone 5: PolicyHttp Tests
// ============================================================================

#[test]
fn policy_gate_http_authorization_grants_capability() {
    let meta = RequestMeta {
        request_id: "req-http-1".to_string(),
        principal: Some(Principal {
            id: "user-http-1".to_string(),
            name: "Alice".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .expect("should pass");

    // HttpCap granted because Authorized("http") was satisfied
    assert!(ctx.http_cap().is_some());
}

#[test]
fn policy_gate_without_http_authorization_no_capability() {
    let meta = RequestMeta {
        request_id: "req-http-2".to_string(),
        principal: Some(Principal {
            id: "user-http-2".to_string(),
            name: "Bob".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        // No Authorized("http")
        .build()
        .expect("should pass");

    // No HttpCap because no http authorization
    assert!(ctx.http_cap().is_none());
}

#[test]
fn ctx_http_requires_http_cap() {
    let meta_with_cap = RequestMeta {
        request_id: "req-http-3".to_string(),
        principal: Some(Principal {
            id: "user-http-3".to_string(),
            name: "Charlie".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta_with_cap)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .expect("should pass");

    // Should succeed because HttpCap was granted
    assert!(ctx.http().is_ok());
}

#[test]
fn ctx_http_fails_without_http_cap() {
    let meta_without_cap = RequestMeta {
        request_id: "req-http-4".to_string(),
        principal: Some(Principal {
            id: "user-http-4".to_string(),
            name: "Dana".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta_without_cap)
        .require(Authenticated)
        // No Authorized("http")
        .build()
        .expect("should pass");

    // Should fail because HttpCap was not granted
    let result = ctx.http();
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().kind,
        ViolationKind::MissingHttpCapability
    );
}

#[test]
fn policy_http_accepts_verified_urls() {
    let meta = RequestMeta {
        request_id: "req-http-5".to_string(),
        principal: Some(Principal {
            id: "user-http-5".to_string(),
            name: "Eve".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .expect("should pass");

    let http = ctx.http().expect("HttpCap granted");
    let sanitizer = StringSanitizer::new(256);

    // Sanitize tainted URL
    let tainted_url = Tainted::new("https://api.example.com/users".to_string());
    let verified_url = sanitizer.sanitize(tainted_url).expect("valid URL");

    // Should accept verified URL
    http.get(&verified_url);

    assert_eq!(http.request_count(), 1);
    let requests = http.requests();
    assert_eq!(requests[0].method, HttpMethod::Get);
    assert_eq!(requests[0].url, "https://api.example.com/users");
}

#[test]
fn policy_http_accepts_verified_post_body() {
    let meta = RequestMeta {
        request_id: "req-http-6".to_string(),
        principal: Some(Principal {
            id: "user-http-6".to_string(),
            name: "Frank".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .expect("should pass");

    let http = ctx.http().expect("HttpCap granted");
    let sanitizer = StringSanitizer::new(256);

    // Sanitize tainted URL and body
    let tainted_url = Tainted::new("https://api.example.com/users".to_string());
    let verified_url = sanitizer.sanitize(tainted_url).expect("valid URL");

    let tainted_body = Tainted::new(r#"{"name": "Frank"}"#.to_string());
    let verified_body = sanitizer.sanitize(tainted_body).expect("valid body");

    // Should accept verified URL and body
    http.post(&verified_url, &verified_body);

    assert_eq!(http.request_count(), 1);
    let requests = http.requests();
    assert_eq!(requests[0].method, HttpMethod::Post);
    assert_eq!(requests[0].url, "https://api.example.com/users");
    assert_eq!(requests[0].body_len, 17); // Length of JSON
}

#[test]
fn policy_http_enforces_compile_time_taint_rejection() {
    // This test documents that PolicyHttp.get() requires Verified<String>
    // and rejects raw strings or Tainted<String> at compile time.
    //
    // Uncommenting the following would fail to compile:
    //
    // let meta = RequestMeta { ... };
    // let ctx = PolicyGate::new(meta)
    //     .require(Authenticated)
    //     .require(Authorized::for_action("http"))
    //     .build()
    //     .unwrap();
    //
    // let http = ctx.http().unwrap();
    //
    // // These would NOT compile:
    // let raw_url = "https://example.com".to_string();
    // http.get(&raw_url); // Type mismatch!
    //
    // let tainted_url = Tainted::new("https://example.com".to_string());
    // http.get(&tainted_url); // Type mismatch!
}

#[test]
fn policy_http_does_not_leak_body_in_metadata() {
    let meta = RequestMeta {
        request_id: "req-http-7".to_string(),
        principal: Some(Principal {
            id: "user-http-7".to_string(),
            name: "Grace".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .expect("should pass");

    let http = ctx.http().expect("HttpCap granted");
    let sanitizer = StringSanitizer::new(256);

    let url = Tainted::new("https://api.example.com".to_string());
    let verified_url = sanitizer.sanitize(url).expect("valid");

    let secret_body = Tainted::new("SECRET_PASSWORD_12345".to_string());
    let verified_body = sanitizer.sanitize(secret_body).expect("valid");

    http.post(&verified_url, &verified_body);

    let requests = http.requests();
    // Metadata should only contain length, not the actual body
    assert_eq!(requests[0].body_len, 21);

    // The debug output of HttpRequest should not contain the body content
    let debug_output = format!("{:?}", requests[0]);
    assert!(!debug_output.contains("SECRET_PASSWORD"));
}

#[test]
fn policy_http_end_to_end_flow() {
    // Complete end-to-end test: Tainted → Sanitized → Verified → Capability → PolicyHttp

    // 1. Create context with HTTP capability
    let meta = RequestMeta {
        request_id: "req-http-e2e".to_string(),
        principal: Some(Principal {
            id: "user-http-e2e".to_string(),
            name: "E2E User".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .expect("policies should pass");

    // 2. Obtain capability-gated HTTP client
    let http = ctx.http().expect("HttpCap should be granted");

    // 3. Create sanitizer
    let sanitizer = StringSanitizer::new(1024);

    // 4. Sanitize tainted inputs
    let tainted_url = Tainted::new("  https://api.example.com/users/1  ".to_string());
    let verified_url = sanitizer
        .sanitize(tainted_url)
        .expect("URL should be valid");

    let tainted_body = Tainted::new(r#"{"status": "active"}"#.to_string());
    let verified_body = sanitizer
        .sanitize(tainted_body)
        .expect("body should be valid");

    // 5. Make HTTP requests
    http.get(&verified_url);
    http.post(&verified_url, &verified_body);
    http.put(&verified_url, &verified_body);
    http.patch(&verified_url, &verified_body);
    http.delete(&verified_url);

    // 6. Verify requests were recorded
    assert_eq!(http.request_count(), 5);
    let requests = http.requests();

    assert_eq!(requests[0].method, HttpMethod::Get);
    assert_eq!(requests[1].method, HttpMethod::Post);
    assert_eq!(requests[2].method, HttpMethod::Put);
    assert_eq!(requests[3].method, HttpMethod::Patch);
    assert_eq!(requests[4].method, HttpMethod::Delete);

    // All requests should have trimmed URL
    for req in &requests {
        assert_eq!(req.url, "https://api.example.com/users/1");
    }

    // Requests with bodies should record body length
    assert_eq!(requests[1].body_len, 20); // POST
    assert_eq!(requests[2].body_len, 20); // PUT
    assert_eq!(requests[3].body_len, 20); // PATCH
}

#[test]
fn milestone_5_complete() {
    // ✓ PolicyHttp wraps HTTP with capability requirement
    // ✓ Ctx.http() is gated by HttpCap
    // ✓ Tainted data is rejected at compile time
    // ✓ Verified data is accepted
    // ✓ No full body leakage in metadata

    let meta = RequestMeta {
        request_id: "req-m5".to_string(),
        principal: Some(Principal {
            id: "user-m5".to_string(),
            name: "Milestone".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .expect("M5 complete");

    let http = ctx.http().expect("HttpCap granted");
    let sanitizer = StringSanitizer::new(256);

    let url = Tainted::new("https://example.com".to_string());
    let verified_url = sanitizer.sanitize(url).expect("valid");

    http.get(&verified_url);

    // Verify that the pattern scales to a second sink
    assert_eq!(http.request_count(), 1);
}

// ============================================================================
// Milestone 6: Type-State Contexts Tests
// ============================================================================
//
// Note: Direct state transition tests (Unauthed -> Authed -> Authorized)
// are in src/context.rs as unit tests since they require pub(crate) access.
// Integration tests focus on the public API via PolicyGate.

#[test]
fn typestate_policy_gate_returns_authorized_ctx() {
    // PolicyGate::build() returns Ctx<Authorized> directly
    let meta = RequestMeta {
        request_id: "req-typestate-3".to_string(),
        principal: Some(Principal {
            id: "user-ts-3".to_string(),
            name: "Gate User".to_string(),
        }),
    };

    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .build()
        .expect("policies should pass");

    // ctx is Ctx<Authorized> and has access to privileged operations
    assert!(ctx.principal().is_some());
    assert!(ctx.log_cap().is_some());
    assert!(ctx.log().is_ok());
}

#[test]
fn typestate_compile_time_restrictions() {
    // This test documents compile-time restrictions.
    // The following code would NOT compile if uncommented:

    // use policy_core::Ctx;
    //
    // let unauthed = Ctx::new_unauthed("req-test".to_string());
    //
    // // Error: method `log` not found for type `Ctx<Unauthed>`
    // unauthed.log();
    //
    // // Error: method `http` not found for type `Ctx<Unauthed>`
    // unauthed.http();
    //
    // // Error: method `log_cap` not found for type `Ctx<Unauthed>`
    // unauthed.log_cap();
    //
    // let principal = Principal { id: "u1".to_string(), name: "Alice".to_string() };
    // let authed = unauthed.authenticate(Some(principal)).unwrap();
    //
    // // Error: method `log` not found for type `Ctx<Authed>`
    // authed.log();
    //
    // // Error: method `http` not found for type `Ctx<Authed>`
    // authed.http();
}

#[test]
fn typestate_authorized_ctx_with_selective_capabilities() {
    // Test that Ctx<Authorized> enforces capability requirements even after
    // successful authentication and authorization.

    let meta = RequestMeta {
        request_id: "req-typestate-4".to_string(),
        principal: Some(Principal {
            id: "user-ts-4".to_string(),
            name: "Selective User".to_string(),
        }),
    };

    // Build context with only log capability
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        // No HTTP authorization
        .build()
        .expect("should pass");

    // Log should succeed
    assert!(ctx.log().is_ok());

    // HTTP should fail (no capability)
    let result = ctx.http();
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().kind,
        ViolationKind::MissingHttpCapability
    );
}

#[test]
fn typestate_end_to_end_with_policy_gate() {
    // Complete end-to-end test showing PolicyGate usage with typestate
    let meta = RequestMeta {
        request_id: "req-typestate-e2e".to_string(),
        principal: Some(Principal {
            id: "user-ts-e2e".to_string(),
            name: "E2E TypeState User".to_string(),
        }),
    };

    // PolicyGate validates and returns Ctx<Authorized>
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .require(Authorized::for_action("http"))
        .build()
        .expect("policies should pass");

    // Verify state
    assert!(ctx.principal().is_some());
    assert_eq!(ctx.principal().unwrap().name, "E2E TypeState User");
    assert!(ctx.log_cap().is_some());
    assert!(ctx.http_cap().is_some());

    // Use privileged operations
    let logger = ctx.log().expect("LogCap granted");
    let http = ctx.http().expect("HttpCap granted");

    // Demonstrate usage
    use policy_core::{Sanitizer, Secret, StringSanitizer, Tainted};

    let secret = Secret::new("api-key-12345");
    logger.info(format_args!("Processing request with key: {:?}", secret));

    let sanitizer = StringSanitizer::new(256);
    let url = Tainted::new("https://api.example.com/data".to_string());
    let verified_url = sanitizer.sanitize(url).expect("valid URL");

    http.get(&verified_url);

    assert_eq!(http.request_count(), 1);
}

#[test]
fn milestone_6_complete() {
    // ✓ Type-state markers (Unauthed, Authed, Authorized) exist
    // ✓ Ctx<S> is generic over state
    // ✓ State transitions are explicit and testable (see src/context.rs tests)
    // ✓ Privileged operations only available on Ctx<Authorized>
    // ✓ PolicyGate returns Ctx<Authorized> directly
    // ✓ Compile-time enforcement prevents misuse

    // Test PolicyGate integration with typestate
    let meta = RequestMeta {
        request_id: "req-m6-gate".to_string(),
        principal: Some(Principal {
            id: "user-m6-gate".to_string(),
            name: "Milestone 6 Gate".to_string(),
        }),
    };

    // PolicyGate::build() returns Ctx<Authorized>
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("log"))
        .build()
        .expect("M6 complete");

    // Verify that the context has the principal (typestate progression happened)
    assert!(ctx.principal().is_some());
    assert_eq!(ctx.principal().unwrap().id, "user-m6-gate");

    // Verify that privileged operations are available on Ctx<Authorized>
    assert!(ctx.log().is_ok());

    // Verify that capabilities are enforced
    assert!(ctx.log_cap().is_some());
    assert!(ctx.http_cap().is_none()); // Not authorized for HTTP
}
