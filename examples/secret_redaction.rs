//! Secret redaction demonstration.
//!
//! This example shows how Secret<T> prevents accidental exposure of sensitive
//! values (API keys, passwords, tokens) in logs, debug output, and error messages.
//!
//! Run with: `cargo run --example secret_redaction`

use policy_core::Secret;

/// Simulates a configuration struct that might contain secrets
#[derive(Debug)]
struct AppConfig {
    #[allow(dead_code)]
    app_name: String,
    api_key: Secret<String>,
    database_password: Secret<String>,
    #[allow(dead_code)]
    public_endpoint: String,
}

impl AppConfig {
    fn new(name: &str, key: &str, password: &str, endpoint: &str) -> Self {
        Self {
            app_name: name.to_string(),
            api_key: Secret::new(key.to_string()),
            database_password: Secret::new(password.to_string()),
            public_endpoint: endpoint.to_string(),
        }
    }
}

fn main() {
    println!("=== Secret Redaction Example ===\n");

    // Create configuration with sensitive values
    let config = AppConfig::new(
        "MyApp",
        "sk-1234567890abcdef",      // API key
        "super_secret_db_password", // Database password
        "https://api.example.com",
    );

    println!("--- Scenario 1: Debug Output (Automatic Redaction) ---");
    println!("Full config: {:#?}", config);
    println!("\nNotice: Secrets are shown as [REDACTED]");

    println!("\n--- Scenario 2: Display Output ---");
    println!("API key: {}", config.api_key);
    println!("DB password: {}", config.database_password);

    println!("\n--- Scenario 3: Explicit Access (When Needed) ---");
    // Accessing the secret requires explicit, visible method call
    let actual_key = config.api_key.expose_secret();
    println!("Explicitly exposed API key: {}", actual_key);
    println!("Note: expose_secret() is intentionally verbose");

    println!("\n--- Scenario 4: Secrets in Error Messages ---");
    let error_with_secret = format!("Auth failed with key: {}", config.api_key);
    println!("Error message: {}", error_with_secret);
    println!("Secret remains redacted even in errors");

    println!("\n--- Scenario 5: Secrets in Collections ---");
    let secrets = vec![
        Secret::new("password123".to_string()),
        Secret::new("api_key_xyz".to_string()),
        Secret::new("token_abc".to_string()),
    ];
    println!("Collection of secrets: {:?}", secrets);
    println!("All automatically redacted");

    println!("\n=== Key Takeaways ===");
    println!("1. Secret<T> redacts values in Debug and Display");
    println!("2. Prevents accidental leaks in logs and errors");
    println!("3. Explicit expose_secret() required for access");
    println!("4. Works in collections and nested structures");
    println!("5. No implicit conversions or trait implementations");
    println!("\nTry this: Search your logs for '[REDACTED]' to verify secrets are protected");
}
