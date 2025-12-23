//! PolicyAudit wrapper for emitting audit events through tracing.
//!
//! This module integrates audit events with the existing tracing infrastructure,
//! allowing audit events to be emitted as structured log entries.

use super::{AuditEvent, AuditTrail};
use std::marker::PhantomData;

/// Capability-gated audit event emitter.
///
/// `PolicyAudit` wraps access to audit event emission, ensuring that only
/// authorized contexts (those holding `AuditCap`) can emit audit events.
///
/// This type is lifetime-bound to the context that creates it, preventing
/// it from being used beyond the context's lifetime.
///
/// # Example
///
/// ```no_run
/// # use policy_core::{PolicyGate, RequestMeta, Principal, Authenticated, Authorized};
/// # use policy_core::audit::{AuditEvent, AuditEventKind, AuditOutcome};
/// # let meta = RequestMeta {
/// #     request_id: "req-1".to_string(),
/// #     principal: Some(Principal { id: "u1".to_string(), name: "Admin".to_string() }),
/// # };
/// # let ctx = PolicyGate::new(meta)
/// #     .require(Authenticated)
/// #     .require(Authorized::for_action("audit"))
/// #     .build()
/// #     .unwrap();
/// let audit = ctx.audit().expect("AuditCap required");
///
/// let event = AuditEvent::new(
///     ctx.request_id(),
///     ctx.principal().map(|p| &p.name),
///     AuditEventKind::AdminAction,
///     AuditOutcome::Success,
/// )
/// .with_action("delete_user");
///
/// audit.emit(&event);
/// ```
#[derive(Debug)]
pub struct PolicyAudit<'a> {
    _ctx_lifetime: PhantomData<&'a ()>,
}

impl<'a> PolicyAudit<'a> {
    /// Creates a new `PolicyAudit`.
    ///
    /// This is `pub(crate)` to prevent external construction.
    /// Only `Ctx::audit()` should create instances.
    pub(crate) fn new() -> Self {
        Self {
            _ctx_lifetime: PhantomData,
        }
    }

    /// Emits an audit event through the tracing infrastructure.
    ///
    /// The event is logged as a structured tracing event with fields
    /// extracted from the `AuditEvent`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use policy_core::{PolicyGate, RequestMeta, Principal, Authenticated, Authorized};
    /// # use policy_core::audit::{AuditEvent, AuditEventKind, AuditOutcome};
    /// # let meta = RequestMeta {
    /// #     request_id: "req-1".to_string(),
    /// #     principal: Some(Principal { id: "u1".to_string(), name: "Admin".to_string() }),
    /// # };
    /// # let ctx = PolicyGate::new(meta)
    /// #     .require(Authenticated)
    /// #     .require(Authorized::for_action("audit"))
    /// #     .build()
    /// #     .unwrap();
    /// let audit = ctx.audit().unwrap();
    ///
    /// let event = AuditEvent::new(
    ///     "req-123",
    ///     Some("admin@example.com"),
    ///     AuditEventKind::StateChange,
    ///     AuditOutcome::Success,
    /// )
    /// .with_action("update_permissions");
    ///
    /// audit.emit(&event);
    /// ```
    pub fn emit(&self, event: &AuditEvent) {
        // Emit the event through tracing with structured fields
        tracing::info!(
            target: "policy_audit",
            request_id = %event.request_id(),
            principal = ?event.principal(),
            kind = %event.kind(),
            outcome = %event.outcome(),
            action = ?event.action(),
            resource_id = ?event.resource_id(),
            method = ?event.method(),
            redacted_url = ?event.redacted_url(),
            body_len = ?event.body_len(),
            "audit event"
        );
    }

    /// Emits an audit event and also records it to the provided trail.
    ///
    /// This is a convenience method that both emits the event through tracing
    /// and stores it in an `AuditTrail` for later inspection.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use policy_core::{PolicyGate, RequestMeta, Principal, Authenticated, Authorized};
    /// # use policy_core::audit::{AuditEvent, AuditEventKind, AuditOutcome, AuditTrail};
    /// # let meta = RequestMeta {
    /// #     request_id: "req-1".to_string(),
    /// #     principal: Some(Principal { id: "u1".to_string(), name: "Admin".to_string() }),
    /// # };
    /// # let ctx = PolicyGate::new(meta)
    /// #     .require(Authenticated)
    /// #     .require(Authorized::for_action("audit"))
    /// #     .build()
    /// #     .unwrap();
    /// let audit = ctx.audit().unwrap();
    /// let trail = AuditTrail::new();
    ///
    /// let event = AuditEvent::new(
    ///     "req-123",
    ///     Some("admin@example.com"),
    ///     AuditEventKind::AdminAction,
    ///     AuditOutcome::Success,
    /// );
    ///
    /// audit.emit_and_record(&event, &trail);
    ///
    /// assert_eq!(trail.len(), 1);
    /// ```
    pub fn emit_and_record(&self, event: &AuditEvent, trail: &AuditTrail) {
        self.emit(event);
        trail.record(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEventKind, AuditOutcome};

    #[test]
    fn policy_audit_can_be_created() {
        let _audit = PolicyAudit::new();
    }

    #[test]
    fn policy_audit_emit_does_not_panic() {
        let audit = PolicyAudit::new();
        let event = AuditEvent::new(
            "req-test",
            Some("user@example.com"),
            AuditEventKind::Authentication,
            AuditOutcome::Success,
        );

        // Should not panic
        audit.emit(&event);
    }

    #[test]
    fn policy_audit_emit_and_record() {
        let audit = PolicyAudit::new();
        let trail = AuditTrail::new();

        let event = AuditEvent::new(
            "req-123",
            Some("admin@example.com"),
            AuditEventKind::AdminAction,
            AuditOutcome::Success,
        )
        .with_action("delete_resource");

        audit.emit_and_record(&event, &trail);

        // Verify the event was recorded
        assert_eq!(trail.len(), 1);
        let events = trail.events();
        assert_eq!(events[0].request_id(), "req-123");
        assert_eq!(events[0].action(), Some("delete_resource"));
    }

    #[test]
    fn policy_audit_emit_works_without_trail() {
        // This test verifies that emit() can be called even when
        // no trail is provided (it just logs through tracing)
        let audit = PolicyAudit::new();
        let event = AuditEvent::new(
            "req-no-trail",
            None::<String>,
            AuditEventKind::SecurityEvent,
            AuditOutcome::Denied,
        );

        // Should not panic
        audit.emit(&event);
    }
}
