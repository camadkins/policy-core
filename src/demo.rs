//! End-to-end demonstration of taint tracking.
//!
//! This module demonstrates the complete flow of taint tracking:
//! 1. Raw untrusted input is wrapped in `Tainted<T>` at the boundary
//! 2. A `Sanitizer` validates and promotes to `Verified<T>`
//! 3. A `Sink` accepts only `Verified<T>` and performs side effects
//!
//! # Security Properties
//!
//! - Untrusted data cannot reach sinks without sanitization (compile-time enforcement)
//! - No implicit conversions allow bypassing the sanitizer
//! - Sinks reject tainted data at runtime if explicitly passed to untrusted APIs
//!
//! # Example: User Input Pipeline
//!
//! ```ignore
//! use policy_core::demo::process_user_input;
//!
//! // Simulate receiving untrusted user input
//! let user_input = "  hello world  ";
//!
//! // Process through the taint tracking pipeline
//! let result = process_user_input(user_input);
//!
//! // Valid input flows through successfully
//! assert!(result.is_ok());
//! let output = result.unwrap();
//! assert_eq!(output, vec!["hello world"]); // Trimmed and verified
//! ```
//!
//! # Compile-Time Rejection Example
//!
//! The following code will NOT compile, demonstrating type-level enforcement:
//!
//! ```compile_fail
//! use policy_core::{Tainted, VecSink, Sink};
//!
//! let tainted = Tainted::new("unsafe data".to_string());
//! let sink = VecSink::new();
//!
//! // This does not compile - type mismatch!
//! // Expected &Verified<String>, got &Tainted<String>
//! sink.sink(&tainted);
//! ```

use crate::{
    Authenticated, Authorized, PolicyGate, Principal, RequestMeta, Sanitizer, Sink,
    StringSanitizer, Tainted, VecSink,
};

/// Processes untrusted user input through the taint tracking pipeline.
///
/// This function demonstrates the canonical flow:
/// 1. **Taint Origin**: Raw input is wrapped as `Tainted<String>` at the boundary
/// 2. **Sanitization**: A `StringSanitizer` validates and promotes to `Verified<String>`
/// 3. **Sink**: A `VecSink` accepts the verified value and stores it
///
/// # Arguments
///
/// * `raw_input` - Untrusted input string (e.g., from HTTP request, user form, etc.)
///
/// # Returns
///
/// Returns `Ok(Vec<String>)` containing the sanitized value on success,
/// or `Err(String)` with an error description on failure.
///
/// # Security
///
/// This function enforces:
/// - All input is treated as tainted at the boundary
/// - Validation occurs before any side effects
/// - Only verified data reaches the sink
///
/// # Examples
///
/// ```ignore
/// use policy_core::demo::process_user_input;
///
/// // Valid input is sanitized and stored
/// let result = process_user_input("  valid input  ");
/// assert!(result.is_ok());
/// assert_eq!(result.unwrap(), vec!["valid input"]);
///
/// // Empty input is rejected during sanitization
/// let result = process_user_input("   ");
/// assert!(result.is_err());
///
/// // Control characters are rejected
/// let result = process_user_input("bad\ninput");
/// assert!(result.is_err());
/// ```
#[allow(dead_code)]
fn process_user_input(raw_input: &str) -> Result<Vec<String>, String> {
    // Step 1: TAINT ORIGIN
    // At the boundary, wrap untrusted input as Tainted<T>
    // This marks it as requiring validation before use
    let tainted = Tainted::new(raw_input.to_string());

    // Step 2: SANITIZATION
    // Use a real sanitizer to validate and promote to Verified<T>
    // This is the ONLY way to create Verified<T> from Tainted<T>
    let sanitizer = StringSanitizer::new(256);
    let verified = sanitizer
        .sanitize(tainted)
        .map_err(|e| format!("Sanitization failed: {}", e))?;

    // Step 3: SINK
    // Pass verified value to a sink that accepts ONLY Verified<T>
    // This performs the actual side effect (in this case, storage)
    let sink = VecSink::new();
    sink.sink(&verified)
        .map_err(|e| format!("Sink failed: {}", e))?;

    // Return the observable result
    Ok(sink.into_vec())
}

/// Demonstrates batch processing of multiple untrusted inputs.
///
/// This function shows how to process multiple tainted values,
/// accumulating only the successfully verified ones.
///
/// # Arguments
///
/// * `raw_inputs` - Collection of untrusted input strings
///
/// # Returns
///
/// Returns a tuple of (successes, failures) where:
/// - `successes` contains all sanitized values
/// - `failures` contains error messages for rejected inputs
///
/// # Examples
///
/// ```ignore
/// use policy_core::demo::batch_process_inputs;
///
/// let inputs = vec![
///     "  valid1  ",
///     "",              // Empty - will fail
///     "valid2",
///     "bad\ndata",     // Control char - will fail
///     "  valid3  ",
/// ];
///
/// let (successes, failures) = batch_process_inputs(&inputs);
///
/// assert_eq!(successes, vec!["valid1", "valid2", "valid3"]);
/// assert_eq!(failures.len(), 2);
/// ```
#[allow(dead_code)]
fn batch_process_inputs(raw_inputs: &[&str]) -> (Vec<String>, Vec<String>) {
    let sanitizer = StringSanitizer::new(256);
    let sink = VecSink::new();

    let mut failures = Vec::new();

    for raw_input in raw_inputs {
        // Taint each input at the boundary
        let tainted = Tainted::new(raw_input.to_string());

        // Attempt sanitization
        match sanitizer.sanitize(tainted) {
            Ok(verified) => {
                // Only verified values reach the sink
                if let Err(e) = sink.sink(&verified) {
                    failures.push(format!("Sink error: {}", e));
                }
            }
            Err(e) => {
                // Collect sanitization failures (without leaking input)
                failures.push(format!("Sanitization failed: {}", e.kind()));
            }
        }
    }

    (sink.into_vec(), failures)
}

/// Demonstrates explicit runtime rejection of untrusted data.
///
/// This function shows what happens when code attempts to bypass sanitization
/// by calling the explicit "untrusted" API on a sink.
///
/// # Returns
///
/// Always returns `Err` because tainted values cannot be sunk without sanitization.
///
/// # Examples
///
/// ```ignore
/// use policy_core::demo::attempt_bypass;
///
/// let result = attempt_bypass("malicious input");
///
/// // Attempt is rejected at runtime
/// assert!(result.is_err());
/// let err = result.unwrap_err();
/// assert!(err.contains("Rejected"));
/// assert!(err.contains("unverified"));
/// ```
#[allow(dead_code)]
fn attempt_bypass(raw_input: &str) -> Result<Vec<String>, String> {
    let tainted = Tainted::new(raw_input.to_string());
    let sink = VecSink::new();

    // Attempt to bypass sanitization using the explicit untrusted API
    // This will ALWAYS fail - demonstrating runtime rejection
    sink.sink_untrusted(tainted)
        .map_err(|e| format!("Rejected: {}", e.kind()))?;

    Ok(sink.into_vec())
}

/// Demonstrates the complete HTTP request flow with taint tracking and capabilities.
///
/// This function shows the full end-to-end flow for Milestone 5:
/// 1. **Policy Gate**: Validates authentication and authorization
/// 2. **Capability**: Obtains HttpCap from validated context
/// 3. **Taint Origin**: Wraps untrusted URL and body as `Tainted<String>`
/// 4. **Sanitization**: Validates and promotes to `Verified<String>`
/// 5. **HTTP Sink**: PolicyHttp accepts only verified data
///
/// # Arguments
///
/// * `user_id` - User identifier for authentication
/// * `raw_url` - Untrusted URL string
/// * `raw_body` - Untrusted request body
///
/// # Returns
///
/// Returns `Ok(())` if the request was recorded successfully,
/// or `Err(String)` with an error description on failure.
///
/// # Security
///
/// This function enforces:
/// - Authentication and HTTP authorization via PolicyGate
/// - All URLs and bodies are treated as tainted at the boundary
/// - Validation occurs before any HTTP operations
/// - Only verified data reaches PolicyHttp
///
/// # Examples
///
/// ```ignore
/// use policy_core::demo::process_http_request;
///
/// // Valid request with authenticated user
/// let result = process_http_request(
///     "user-123",
///     "https://api.example.com/data",
///     r#"{"key": "value"}"#,
/// );
/// assert!(result.is_ok());
/// ```
#[allow(dead_code)]
fn process_http_request(user_id: &str, raw_url: &str, raw_body: &str) -> Result<(), String> {
    // Step 1: POLICY GATE
    // Create request metadata with authenticated principal
    let meta = RequestMeta {
        request_id: format!("req-{}", user_id),
        principal: Some(Principal {
            id: user_id.to_string(),
            name: format!("User {}", user_id),
        }),
    };

    // Build context with authentication and HTTP authorization
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("http"))
        .build()
        .map_err(|e| format!("Policy violation: {}", e))?;

    // Step 2: CAPABILITY
    // Obtain capability-gated HTTP client
    // This will fail if HttpCap was not granted
    let http = ctx
        .http()
        .map_err(|e| format!("Missing HTTP capability: {}", e))?;

    // Step 3: TAINT ORIGIN
    // At the boundary, wrap untrusted inputs as Tainted<T>
    let tainted_url = Tainted::new(raw_url.to_string());
    let tainted_body = Tainted::new(raw_body.to_string());

    // Step 4: SANITIZATION
    // Use a real sanitizer to validate and promote to Verified<T>
    let sanitizer = StringSanitizer::new(1024);
    let verified_url = sanitizer
        .sanitize(tainted_url)
        .map_err(|e| format!("URL sanitization failed: {}", e))?;
    let verified_body = sanitizer
        .sanitize(tainted_body)
        .map_err(|e| format!("Body sanitization failed: {}", e))?;

    // Step 5: HTTP SINK
    // PolicyHttp accepts ONLY Verified<String> for URLs and bodies
    // This is enforced at compile time
    http.post(&verified_url, &verified_body);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_happy_path() {
        // Simulate receiving untrusted input from a user
        let user_input = "  Hello, World!  ";

        // Process through the complete pipeline
        let result = process_user_input(user_input);

        // Should succeed and contain the sanitized value
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.len(), 1);
        assert_eq!(output[0], "Hello, World!"); // Trimmed but preserved
    }

    #[test]
    fn end_to_end_sanitization_trims() {
        let result = process_user_input("  test  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["test"]);
    }

    #[test]
    fn end_to_end_rejects_empty() {
        // Empty input should be rejected during sanitization
        let result = process_user_input("   ");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Sanitization failed"));
    }

    #[test]
    fn end_to_end_rejects_control_chars() {
        // Newlines should be rejected during sanitization
        let result = process_user_input("hello\nworld");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Sanitization failed"));
    }

    #[test]
    fn end_to_end_rejects_null_bytes() {
        // Null bytes should be rejected during sanitization
        let result = process_user_input("hello\0world");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Sanitization failed"));
    }

    #[test]
    fn end_to_end_rejects_too_long() {
        // Very long input exceeding max length
        let long_input = "x".repeat(1000);
        let result = process_user_input(&long_input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Sanitization failed"));
    }

    #[test]
    fn batch_processing_filters_correctly() {
        let long_input = "x".repeat(300);
        let inputs = vec![
            "  valid1  ",
            "", // Empty - will fail
            "valid2",
            "bad\ndata", // Control char - will fail
            "  valid3  ",
            long_input.as_str(), // Too long - will fail
        ];

        let (successes, failures) = batch_process_inputs(&inputs);

        // Only the three valid inputs should succeed
        assert_eq!(successes.len(), 3);
        assert_eq!(successes, vec!["valid1", "valid2", "valid3"]);

        // Three inputs should have failed
        assert_eq!(failures.len(), 3);
    }

    #[test]
    fn batch_processing_preserves_order() {
        let inputs = vec!["first", "second", "third"];
        let (successes, _) = batch_process_inputs(&inputs);
        assert_eq!(successes, vec!["first", "second", "third"]);
    }

    #[test]
    fn runtime_rejection_fails() {
        // Attempting to bypass sanitization should fail
        let result = attempt_bypass("any input");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Rejected"));
        assert!(err.contains("unverified"));
    }

    #[test]
    fn runtime_rejection_no_side_effects() {
        // Create a sink and verify it's empty
        let sink = VecSink::new();
        assert_eq!(sink.len(), 0);

        // Attempt to sink tainted data via untrusted API
        let tainted = Tainted::new("malicious".to_string());
        let result = sink.sink_untrusted(tainted);

        // Should fail
        assert!(result.is_err());

        // Should NOT have modified the sink
        assert_eq!(sink.len(), 0);
        assert!(sink.is_empty());
    }

    #[test]
    fn compile_time_rejection_documented() {
        // This test documents that the following code would NOT compile:
        //
        // let raw_input = "unsafe".to_string();
        // let sink = VecSink::new();
        // sink.sink(&raw_input); // ← Type error! Expected &Verified<String>, got &String
        //
        // let tainted = Tainted::new("unsafe".to_string());
        // sink.sink(&tainted); // ← Type error! Expected &Verified<String>, got &Tainted<String>
        //
        // The type system prevents these calls at compile time.
        // Only this works:
        let sanitizer = StringSanitizer::new(256);
        let tainted = Tainted::new("safe".to_string());
        let verified = sanitizer.sanitize(tainted).unwrap();
        let sink = VecSink::new();
        sink.sink(&verified).unwrap(); // ✓ Compiles - verified type
    }

    #[test]
    fn unicode_flows_through_pipeline() {
        let result = process_user_input("  Hello 世界  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["Hello 世界"]);
    }

    #[test]
    fn error_messages_do_not_leak_input() {
        // Process input that will be rejected (contains newline - a control character)
        let secret_input = "SECRET_API_KEY\n12345";
        let result = process_user_input(secret_input);

        assert!(result.is_err());
        let error_msg = result.unwrap_err();

        // Error message should NOT contain the actual secret
        assert!(!error_msg.contains("SECRET_API_KEY"));
        assert!(!error_msg.contains("12345"));
        // But should contain useful information
        assert!(error_msg.contains("Sanitization failed"));
    }

    // ========================================================================
    // Milestone 5: PolicyHttp Demo Tests
    // ========================================================================

    #[test]
    fn http_end_to_end_happy_path() {
        // Valid HTTP request with authenticated user and verified data
        let result = process_http_request(
            "user-123",
            "https://api.example.com/users",
            r#"{"name": "Alice"}"#,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn http_end_to_end_sanitizes_url() {
        // URL with whitespace should be trimmed during sanitization
        let result = process_http_request(
            "user-456",
            "  https://api.example.com/data  ",
            r#"{"value": 42}"#,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn http_end_to_end_rejects_invalid_url() {
        // URL containing control characters should be rejected
        let result = process_http_request("user-789", "https://example.com\n/hack", "{}");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("URL sanitization failed"));
    }

    #[test]
    fn http_end_to_end_rejects_invalid_body() {
        // Body containing control characters should be rejected
        let result = process_http_request("user-999", "https://api.example.com", "bad\nbody\ndata");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Body sanitization failed"));
    }

    #[test]
    fn http_end_to_end_requires_authentication() {
        // This test documents that unauthenticated requests would fail
        // at the policy gate (we can't easily test this with the current
        // function signature that requires a user_id)
        //
        // If we modified process_http_request to accept Option<Principal>,
        // passing None would fail with "Policy violation: Unauthenticated"
    }
}
