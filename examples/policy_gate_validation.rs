//! Policy gate and type-state progression demonstration.
//!
//! This example shows:
//! 1. Type-state progression: Unauthed → Authed → Authorized
//! 2. Policy validation through PolicyGate
//! 3. Capability-based access control
//! 4. Structured error handling
//!
//! Run with: `cargo run --example policy_gate_validation`

use policy_core::{actions, Authenticated, Authorized, PolicyGate, Principal, RequestMeta};

fn main() {
    println!("=== Policy Gate Validation Example ===\n");

    // Scenario 1: Unauthenticated request (no principal)
    println!("--- Scenario 1: Unauthenticated Request ---");
    let unauthenticated_meta = RequestMeta {
        request_id: "req-001".to_string(),
        principal: None,
    };

    let result = PolicyGate::new(unauthenticated_meta.clone())
        .require(Authenticated)
        .build();

    match result {
        Ok(_) => println!("Unexpected success"),
        Err(e) => println!("Policy violation (expected): {}", e),
    }

    // Scenario 2: Authenticated but not authorized
    println!("\n--- Scenario 2: Authenticated but Unauthorized ---");
    let authenticated_meta = RequestMeta {
        request_id: "req-002".to_string(),
        principal: Some(Principal {
            id: "user-123".to_string(),
            name: "Alice".to_string(),
        }),
    };

    let result = PolicyGate::new(authenticated_meta.clone())
        .require(Authenticated)
        .require(Authorized::for_action(actions::LOG))
        .build();

    match result {
        Ok(_) => println!("Unexpected success"),
        Err(e) => println!("Policy violation (expected): {}", e),
    }

    // Scenario 3: Fully authorized with multiple capabilities
    println!("\n--- Scenario 3: Multiple Capabilities ---");
    let authorized_meta = RequestMeta {
        request_id: "req-003".to_string(),
        principal: Some(Principal {
            id: "admin-456".to_string(),
            name: "Bob".to_string(),
        }),
    };

    let authorized_ctx = PolicyGate::new(authorized_meta.clone())
        .require(Authenticated)
        .require(Authorized::for_action(actions::LOG))
        .require(Authorized::for_action(actions::HTTP))
        .require(Authorized::for_action(actions::AUDIT))
        .build()
        .expect("Authorization should succeed");

    println!("✓ Authorization successful");
    println!("  Request ID: {}", authorized_ctx.request_id());
    println!("  Principal: {}", authorized_ctx.principal().unwrap().name);
    println!("  Capabilities granted:");

    if authorized_ctx.log_cap().is_some() {
        println!("    - LogCap (can log)");
        if let Ok(log) = authorized_ctx.log() {
            log.info(format_args!("This message uses the logging capability"));
        }
    }

    if authorized_ctx.http_cap().is_some() {
        println!("    - HttpCap (can make HTTP requests)");
    }

    if authorized_ctx.audit_cap().is_some() {
        println!("    - AuditCap (can write audit events)");
    }

    // Scenario 4: Partial authorization (only some capabilities)
    println!("\n--- Scenario 4: Partial Authorization ---");
    let partial_authorized = PolicyGate::new(authenticated_meta.clone())
        .require(Authenticated)
        .require(Authorized::for_action(actions::LOG))
        // Note: NOT authorized for HTTP or AUDIT
        .build()
        .expect("Partial authorization should succeed");

    println!("✓ Partial authorization successful");
    println!("  Capabilities granted:");

    if partial_authorized.log_cap().is_some() {
        println!("    - LogCap: granted");
    }

    if partial_authorized.http_cap().is_none() {
        println!("    - HttpCap: NOT granted");
    }

    if partial_authorized.audit_cap().is_none() {
        println!("    - AuditCap: NOT granted");
    }

    // Scenario 5: Multiple policy requirements
    println!("\n--- Scenario 5: Multiple Policy Requirements ---");
    let result = PolicyGate::new(authorized_meta.clone())
        .require(Authenticated)
        .require(Authorized::for_action(actions::LOG))
        .require(Authorized::for_action(actions::AUDIT))
        .build();

    match result {
        Ok(ctx) => {
            println!("✓ All policies satisfied");
            println!("  Request ID: {}", ctx.request_id());
            if let Some(principal) = ctx.principal() {
                println!("  Principal: {}", principal.name);
            }
        }
        Err(e) => {
            println!("Policy violation: {}", e);
        }
    }

    println!("\n=== Key Takeaways ===");
    println!("1. PolicyGate enforces explicit policy validation");
    println!("2. Type-state tracks authentication/authorization state");
    println!("3. Capabilities prove authorization");
    println!("4. Missing capabilities prevent operations at compile time");
    println!("5. Policy violations fail early with structured errors");
    println!("\nType safety example:");
    println!("// ctx.log()  // Only works on Ctx<Authorized> with LogCap");
}
