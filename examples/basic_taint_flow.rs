//! Basic taint tracking demonstration.
//!
//! This example shows the core security pattern of policy-core:
//! 1. Mark untrusted input as Tainted<T>
//! 2. Validate through a Sanitizer
//! 3. Get Verified<T> as proof of validation
//! 4. Only Verified<T> can reach sinks
//!
//! Run with: `cargo run --example basic_taint_flow`

use policy_core::{Sanitizer, Sink, StringSanitizer, Tainted, VecSink};

fn main() {
    println!("=== Basic Taint Flow Example ===\n");

    // Create a sink for demonstrating safe operations
    let sink = VecSink::new();
    let sanitizer = StringSanitizer::new(256).unwrap(); // Max length: 256 chars

    // Scenario 1: Valid input - success case
    println!("--- Scenario 1: Valid Input ---");
    let valid_input = "  Hello, world!  ";
    println!("Raw input: {:?}", valid_input);

    let tainted = Tainted::new(valid_input.to_string());
    println!("Marked as Tainted<String>");

    match sanitizer.sanitize(tainted) {
        Ok(verified) => {
            println!("Sanitization succeeded!");
            println!("Verified value: {:?}", verified.as_ref());

            // Send to sink - only Verified<T> is accepted
            if let Err(e) = sink.sink(&verified) {
                eprintln!("Sink error: {}", e);
            } else {
                println!("Successfully sent to sink");
            }
        }
        Err(e) => {
            eprintln!("Sanitization failed: {}", e);
        }
    }

    println!("\n--- Scenario 2: Empty Input (After Trimming) ---");
    let empty_input = "   ";
    println!("Raw input: {:?}", empty_input);

    let tainted = Tainted::new(empty_input.to_string());
    match sanitizer.sanitize(tainted) {
        Ok(_) => println!("Unexpected success"),
        Err(e) => println!("Sanitization failed (expected): {}", e),
    }

    println!("\n--- Scenario 3: Input with Control Characters ---");
    let dangerous_input = "Hello\x00World\x1B";
    println!("Raw input: {:?}", dangerous_input);

    let tainted = Tainted::new(dangerous_input.to_string());
    match sanitizer.sanitize(tainted) {
        Ok(_) => println!("Unexpected success"),
        Err(e) => println!("Sanitization failed (expected): {}", e),
    }

    println!("\n--- Scenario 4: Batch Processing ---");
    let inputs = [
        "Valid input",
        "Another valid one",
        "", // Will be rejected after trim
        "Contains\x00null",
        "   Whitespace everywhere   ",
    ];

    for (i, input) in inputs.iter().enumerate() {
        let tainted = Tainted::new(input.to_string());
        match sanitizer.sanitize(tainted) {
            Ok(verified) => {
                println!("Input {}: SUCCESS - {:?}", i + 1, verified.as_ref());
                let _ = sink.sink(&verified);
            }
            Err(e) => {
                println!("Input {}: FAILED - {}", i + 1, e);
            }
        }
    }

    // Show what made it through to the sink
    println!("\n--- Final Sink Contents ---");
    println!("Successfully processed {} items:", sink.to_vec().len());
    for item in sink.to_vec() {
        println!("  - {:?}", item);
    }

    println!("\n=== Key Takeaways ===");
    println!("1. All external input is wrapped in Tainted<T>");
    println!("2. Sanitizers enforce validation rules");
    println!("3. Only Verified<T> can reach sinks");
    println!("4. Compile-time enforcement prevents bypass");
    println!("\nTry uncommenting this line to see a compile error:");
    println!("// let t = Tainted::new(\"bypass\".to_string());");
    println!("// sink.sink(&t);  // Error: expected &Verified<String>, got &Tainted<String>");
}
