//! Audit trail demonstration.
//!
//! This example shows how to use the audit trail system for compliance logging:
//! 1. Create audit events with structured data
//! 2. Record events to an audit trail
//! 3. Query the audit log
//! 4. Demonstrate different event types and outcomes
//!
//! Run with: `cargo run --example audit_trail`

use policy_core::{
    Authenticated, Authorized, PolicyGate, Principal, RequestMeta, actions,
    audit::{AuditEvent, AuditEventKind, AuditOutcome, AuditTrail},
};

fn main() {
    println!("=== Audit Trail Example ===\n");

    // Create an audit trail for recording events
    let trail = AuditTrail::new();

    // Scenario 1: Authentication Events
    println!("--- Scenario 1: Authentication Events ---");

    let login_attempt = AuditEvent::new(
        "req-login-001",
        Some("alice@example.com"),
        AuditEventKind::Authentication,
        AuditOutcome::Success,
    )
    .with_action("login");

    trail.record(login_attempt);
    println!("✓ Recorded successful login");

    let failed_login = AuditEvent::new(
        "req-login-002",
        Some("attacker@bad.com"),
        AuditEventKind::Authentication,
        AuditOutcome::Error,
    )
    .with_action("login_failed");

    trail.record(failed_login);
    println!("✓ Recorded failed login attempt");

    // Scenario 2: Authorization Events
    println!("\n--- Scenario 2: Authorization Events ---");

    let meta = RequestMeta {
        request_id: "req-admin-001".to_string(),
        principal: Some(Principal {
            id: "user-admin".to_string(),
            name: "Admin User".to_string(),
        }),
    };

    let ctx_result = PolicyGate::new(meta.clone())
        .require(Authenticated)
        .require(Authorized::for_action(actions::AUDIT))
        .build();

    match ctx_result {
        Ok(ctx) => {
            let auth_event = AuditEvent::new(
                ctx.request_id(),
                ctx.principal().map(|p| p.name.as_str()),
                AuditEventKind::Authorization,
                AuditOutcome::Success,
            )
            .with_action(actions::AUDIT);

            trail.record(auth_event);
            println!("✓ Recorded successful authorization");

            // Use the audit capability
            if let Ok(audit) = ctx.audit() {
                let admin_event = AuditEvent::new(
                    ctx.request_id(),
                    ctx.principal().map(|p| p.name.as_str()),
                    AuditEventKind::AdminAction,
                    AuditOutcome::Success,
                )
                .with_action("access_admin_panel");

                audit.emit(&admin_event);
                println!("✓ Emitted admin action event");
            }
        }
        Err(e) => {
            let denied_event = AuditEvent::new(
                &meta.request_id,
                None::<&str>,
                AuditEventKind::Authorization,
                AuditOutcome::Denied,
            )
            .with_action(actions::AUDIT);

            trail.record(denied_event);
            println!("✓ Recorded authorization denial: {}", e);
        }
    }

    // Scenario 3: Resource Access Events
    println!("\n--- Scenario 3: Resource Access Events ---");

    let data_access = AuditEvent::new(
        "req-data-001",
        Some("Alice"),
        AuditEventKind::ResourceAccess,
        AuditOutcome::Success,
    )
    .with_action("read")
    .with_resource_id("customer:12345");

    trail.record(data_access);
    println!("✓ Recorded resource access");

    // Scenario 4: State Changes
    println!("\n--- Scenario 4: State Changes ---");

    let state_change = AuditEvent::new(
        "req-change-001",
        Some("admin"),
        AuditEventKind::StateChange,
        AuditOutcome::Success,
    )
    .with_action("update_user")
    .with_resource_id("user:789");

    trail.record(state_change);
    println!("✓ Recorded state change");

    // Query the audit trail
    println!("\n--- Audit Trail Summary ---");
    let events = trail.events();
    println!("Total events recorded: {}", events.len());

    println!("\n=== Key Takeaways ===");
    println!("1. Audit events are structured and queryable");
    println!("2. Different event types for different operations");
    println!("3. Outcomes track success/error/denial");
    println!("4. AuditCap gates audit trail access");
    println!("5. Provides compliance-grade audit logging");
    println!("\nIn production:");
    println!("  - Persist audit trail to immutable storage");
    println!("  - Implement retention policies");
    println!("  - Add encryption for sensitive audit data");
    println!("  - Enable querying by time range, principal, or event type");
}
