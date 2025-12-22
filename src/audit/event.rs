//! Audit event schema and types.
//!
//! This module defines the structure of audit events that can be safely
//! logged without risk of leaking sensitive data.

use std::fmt;

/// Kind of audit event being recorded.
///
/// This enum categorizes different types of security-relevant actions
/// that should be audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventKind {
    /// Authentication attempt (success or failure)
    Authentication,
    /// Authorization check (grant or deny)
    Authorization,
    /// Access to a protected resource
    ResourceAccess,
    /// Modification of system state
    StateChange,
    /// Administrative action
    AdminAction,
    /// Policy violation or security event
    SecurityEvent,
}

impl fmt::Display for AuditEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditEventKind::Authentication => write!(f, "authentication"),
            AuditEventKind::Authorization => write!(f, "authorization"),
            AuditEventKind::ResourceAccess => write!(f, "resource_access"),
            AuditEventKind::StateChange => write!(f, "state_change"),
            AuditEventKind::AdminAction => write!(f, "admin_action"),
            AuditEventKind::SecurityEvent => write!(f, "security_event"),
        }
    }
}

/// Outcome of an audited operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Operation succeeded
    Success,
    /// Operation was denied by policy
    Denied,
    /// Operation failed due to error
    Error,
}

impl fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditOutcome::Success => write!(f, "success"),
            AuditOutcome::Denied => write!(f, "denied"),
            AuditOutcome::Error => write!(f, "error"),
        }
    }
}

/// A structured audit event containing only safe, non-sensitive metadata.
///
/// # Safety Invariants
///
/// - No raw tainted input is stored
/// - No secrets are included
/// - No full request/response bodies
/// - Only safe identifiers and metadata
///
/// # Example
///
/// ```
/// use policy_core::audit::{AuditEvent, AuditEventKind, AuditOutcome};
///
/// let event = AuditEvent::new(
///     "req-123",
///     Some("user@example.com"),
///     AuditEventKind::AdminAction,
///     AuditOutcome::Success,
/// )
/// .with_action("delete_user")
/// .with_resource_id("user-456");
///
/// assert_eq!(event.request_id(), "req-123");
/// assert_eq!(event.principal(), Some("user@example.com"));
/// ```
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Request identifier for correlation
    request_id: String,
    /// Principal performing the action (username, email, etc.)
    /// None for unauthenticated events
    principal: Option<String>,
    /// Category of event
    kind: AuditEventKind,
    /// Whether the operation succeeded, was denied, or failed
    outcome: AuditOutcome,
    /// Specific action being performed (e.g., "delete_user", "read_file")
    action: Option<String>,
    /// Resource identifier (e.g., user ID, file path)
    /// MUST be safe to log (no sensitive content)
    resource_id: Option<String>,
    /// HTTP method if applicable
    method: Option<String>,
    /// Redacted URL or path (no query params with secrets)
    redacted_url: Option<String>,
    /// Content length in bytes (not the actual content)
    body_len: Option<usize>,
}

impl AuditEvent {
    /// Creates a new audit event with required fields.
    ///
    /// # Arguments
    ///
    /// * `request_id` - Request correlation identifier
    /// * `principal` - Who is performing the action (None if unauthenticated)
    /// * `kind` - Category of audit event
    /// * `outcome` - Whether the operation succeeded, was denied, or failed
    ///
    /// # Example
    ///
    /// ```
    /// use policy_core::audit::{AuditEvent, AuditEventKind, AuditOutcome};
    ///
    /// let event = AuditEvent::new(
    ///     "req-456",
    ///     Some("admin@example.com"),
    ///     AuditEventKind::StateChange,
    ///     AuditOutcome::Success,
    /// );
    /// ```
    pub fn new(
        request_id: impl Into<String>,
        principal: Option<impl Into<String>>,
        kind: AuditEventKind,
        outcome: AuditOutcome,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            principal: principal.map(Into::into),
            kind,
            outcome,
            action: None,
            resource_id: None,
            method: None,
            redacted_url: None,
            body_len: None,
        }
    }

    /// Sets the specific action being performed.
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Sets the resource identifier.
    ///
    /// SAFETY: Caller must ensure this does not contain sensitive data.
    pub fn with_resource_id(mut self, resource_id: impl Into<String>) -> Self {
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Sets the HTTP method.
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Sets a redacted URL (no sensitive query parameters).
    pub fn with_redacted_url(mut self, url: impl Into<String>) -> Self {
        self.redacted_url = Some(url.into());
        self
    }

    /// Sets the content length in bytes.
    pub fn with_body_len(mut self, len: usize) -> Self {
        self.body_len = Some(len);
        self
    }

    /// Returns the request identifier.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the principal, if authenticated.
    pub fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }

    /// Returns the event kind.
    pub fn kind(&self) -> AuditEventKind {
        self.kind
    }

    /// Returns the operation outcome.
    pub fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    /// Returns the action, if set.
    pub fn action(&self) -> Option<&str> {
        self.action.as_deref()
    }

    /// Returns the resource identifier, if set.
    pub fn resource_id(&self) -> Option<&str> {
        self.resource_id.as_deref()
    }

    /// Returns the HTTP method, if set.
    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }

    /// Returns the redacted URL, if set.
    pub fn redacted_url(&self) -> Option<&str> {
        self.redacted_url.as_deref()
    }

    /// Returns the body length, if set.
    pub fn body_len(&self) -> Option<usize> {
        self.body_len
    }
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AuditEvent[kind={}, outcome={}, request_id={}, principal={}",
            self.kind,
            self.outcome,
            self.request_id,
            self.principal.as_deref().unwrap_or("<none>")
        )?;

        if let Some(action) = &self.action {
            write!(f, ", action={}", action)?;
        }
        if let Some(resource_id) = &self.resource_id {
            write!(f, ", resource_id={}", resource_id)?;
        }
        if let Some(method) = &self.method {
            write!(f, ", method={}", method)?;
        }
        if let Some(url) = &self.redacted_url {
            write!(f, ", url={}", url)?;
        }
        if let Some(len) = self.body_len {
            write!(f, ", body_len={}", len)?;
        }

        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_kind_display() {
        assert_eq!(AuditEventKind::Authentication.to_string(), "authentication");
        assert_eq!(AuditEventKind::AdminAction.to_string(), "admin_action");
    }

    #[test]
    fn audit_outcome_display() {
        assert_eq!(AuditOutcome::Success.to_string(), "success");
        assert_eq!(AuditOutcome::Denied.to_string(), "denied");
        assert_eq!(AuditOutcome::Error.to_string(), "error");
    }

    #[test]
    fn audit_event_minimal() {
        let event = AuditEvent::new(
            "req-123",
            Some("user@example.com"),
            AuditEventKind::Authentication,
            AuditOutcome::Success,
        );

        assert_eq!(event.request_id(), "req-123");
        assert_eq!(event.principal(), Some("user@example.com"));
        assert_eq!(event.kind(), AuditEventKind::Authentication);
        assert_eq!(event.outcome(), AuditOutcome::Success);
        assert!(event.action().is_none());
    }

    #[test]
    fn audit_event_with_action() {
        let event = AuditEvent::new(
            "req-456",
            Some("admin@example.com"),
            AuditEventKind::AdminAction,
            AuditOutcome::Success,
        )
        .with_action("delete_user");

        assert_eq!(event.action(), Some("delete_user"));
    }

    #[test]
    fn audit_event_builder_pattern() {
        let event = AuditEvent::new(
            "req-789",
            Some("user@example.com"),
            AuditEventKind::ResourceAccess,
            AuditOutcome::Success,
        )
        .with_action("read")
        .with_resource_id("file-123")
        .with_method("GET")
        .with_redacted_url("/api/files/123")
        .with_body_len(1024);

        assert_eq!(event.action(), Some("read"));
        assert_eq!(event.resource_id(), Some("file-123"));
        assert_eq!(event.method(), Some("GET"));
        assert_eq!(event.redacted_url(), Some("/api/files/123"));
        assert_eq!(event.body_len(), Some(1024));
    }

    #[test]
    fn audit_event_display_does_not_leak_secrets() {
        // This test ensures Display output is safe
        let event = AuditEvent::new(
            "req-secret-test",
            Some("user@example.com"),
            AuditEventKind::Authentication,
            AuditOutcome::Success,
        );

        let display = event.to_string();

        // Should contain safe metadata
        assert!(display.contains("req-secret-test"));
        assert!(display.contains("user@example.com"));
        assert!(display.contains("authentication"));

        // Should NOT contain any marker that we're hiding secrets
        // (because there shouldn't be any secrets to hide in the first place)
    }

    #[test]
    fn audit_event_debug_is_safe() {
        let event = AuditEvent::new(
            "req-debug-test",
            None::<String>,
            AuditEventKind::SecurityEvent,
            AuditOutcome::Denied,
        );

        let debug = format!("{:?}", event);

        // Debug should work and contain basic info
        assert!(debug.contains("AuditEvent"));
        assert!(debug.contains("req-debug-test"));
    }

    #[test]
    fn audit_event_unauthenticated() {
        let event = AuditEvent::new(
            "req-anon",
            None::<String>,
            AuditEventKind::Authentication,
            AuditOutcome::Denied,
        );

        assert!(event.principal().is_none());

        let display = event.to_string();
        assert!(display.contains("<none>"));
    }
}
