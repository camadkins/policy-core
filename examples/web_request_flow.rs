//! Web request flow demonstration.
//!
//! This example shows how to integrate policy-core with web frameworks:
//! 1. Extract request metadata
//! 2. Mark all inputs as tainted
//! 3. Validate policies
//! 4. Sanitize inputs
//! 5. Perform operations with capabilities
//!
//! Run with: `cargo run --example web_request_flow`

use policy_core::{
    Authenticated, Authorized, PolicyGate, Principal, RequestMeta, Sanitizer, Sink,
    StringSanitizer, Tainted, VecSink, actions,
};

/// Simulates extracting metadata from an HTTP request
fn extract_request_metadata(auth_header: Option<&str>) -> RequestMeta {
    let principal = auth_header.and_then(|header| {
        if header.starts_with("Bearer ") {
            Some(Principal {
                id: "user-123".to_string(),
                name: "Alice".to_string(),
            })
        } else {
            None
        }
    });

    RequestMeta {
        request_id: format!("req-{}", uuid::generate_simple()),
        principal,
    }
}

/// Simulates UUID generation
mod uuid {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(1);

    pub fn generate_simple() -> String {
        format!("{:08x}", COUNTER.fetch_add(1, Ordering::SeqCst))
    }
}

/// Simulates a web request handler
fn handle_user_input_request(
    auth_header: Option<&str>,
    user_input: String,
) -> Result<String, Box<dyn std::error::Error>> {
    println!("\n=== Processing Request ===");

    // Step 1: Extract metadata from request
    let metadata = extract_request_metadata(auth_header);
    println!("1. Extracted metadata");
    println!("   Request ID: {}", metadata.request_id);
    println!(
        "   Principal: {:?}",
        metadata.principal.as_ref().map(|p| &p.name)
    );

    // Step 2: Mark all inputs as tainted
    let tainted_input = Tainted::new(user_input.clone());
    println!("2. Marked input as tainted");
    println!("   Raw input: {:?}", user_input);

    // Step 3: Validate policies
    let ctx = PolicyGate::new(metadata)
        .require(Authenticated)
        .require(Authorized::for_action(actions::LOG))
        .build()?;

    println!("3. ✓ Policies validated");

    // Step 4: Sanitize input
    let sanitizer = StringSanitizer::new(256);
    let verified_input = sanitizer.sanitize(tainted_input)?;
    println!("4. ✓ Input sanitized");
    println!("   Verified: {:?}", verified_input.as_ref());

    // Step 5: Perform operations with capabilities
    let sink = VecSink::new();
    sink.sink(&verified_input)?;
    println!("5. ✓ Sent to sink");

    if let Ok(log) = ctx.log() {
        log.info(format_args!(
            "Processed user input: {}",
            verified_input.as_ref()
        ));
        println!("6. ✓ Logged with capability");
    }

    Ok(format!("Processed: {}", verified_input.as_ref()))
}

fn main() {
    println!("=== Web Request Flow Example ===");

    // Scenario 1: Authenticated request with valid input
    println!("\n--- Scenario 1: Success Case ---");
    match handle_user_input_request(Some("Bearer token123"), "  Hello, world!  ".to_string()) {
        Ok(result) => println!("✓ Success: {}", result),
        Err(e) => eprintln!("✗ Error: {}", e),
    }

    // Scenario 2: Unauthenticated request
    println!("\n--- Scenario 2: Unauthenticated ---");
    match handle_user_input_request(None, "Attempt".to_string()) {
        Ok(result) => println!("Unexpected success: {}", result),
        Err(e) => println!("✓ Expected error: {}", e),
    }

    // Scenario 3: Invalid input (control characters)
    println!("\n--- Scenario 3: Invalid Input ---");
    match handle_user_input_request(Some("Bearer token123"), "Bad\x00Input".to_string()) {
        Ok(result) => println!("Unexpected success: {}", result),
        Err(e) => println!("✓ Expected error: {}", e),
    }

    // Scenario 4: Batch processing
    println!("\n--- Scenario 4: Batch Requests ---");
    let requests = [
        (Some("Bearer token123"), "Valid input 1"),
        (Some("Bearer token123"), "Valid input 2"),
        (None, "No auth"),
        (Some("Bearer token123"), ""),
    ];

    let mut successful = 0;
    let mut failed = 0;

    for (i, (auth, input)) in requests.iter().enumerate() {
        print!("  Request {}: ", i + 1);
        match handle_user_input_request(*auth, input.to_string()) {
            Ok(_) => {
                println!("✓ Success");
                successful += 1;
            }
            Err(e) => {
                println!("✗ Failed ({})", e);
                failed += 1;
            }
        }
    }

    println!("\n  Summary: {} successful, {} failed", successful, failed);

    println!("\n=== Key Takeaways ===");
    println!("1. All external inputs are marked as Tainted<T>");
    println!("2. Policy validation happens before processing");
    println!("3. Sanitization is explicit and required");
    println!("4. Capabilities gate all privileged operations");
    println!("5. Failures are structured and actionable");
    println!("\nThis pattern ensures:");
    println!("  - No untrusted data reaches sinks");
    println!("  - No operations without proper authorization");
    println!("  - Clear audit trail of all operations");
}
