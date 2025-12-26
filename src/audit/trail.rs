//! In-memory audit trail recorder.
//!
//! This module provides a simple in-memory audit event recorder for
//! testing and demonstration purposes.

use super::AuditEvent;
use std::cell::RefCell;

/// In-memory recorder for audit events.
///
/// This is a simple implementation that stores events in a vector.
/// In production, you would typically integrate with a persistent
/// audit logging system.
///
/// # Example
///
/// ```
/// use policy_core::audit::{AuditTrail, AuditEvent, AuditEventKind, AuditOutcome};
///
/// let trail = AuditTrail::new();
///
/// let event = AuditEvent::new(
///     "req-123",
///     Some("user@example.com"),
///     AuditEventKind::AdminAction,
///     AuditOutcome::Success,
/// );
///
/// trail.record(event);
///
/// assert_eq!(trail.events().len(), 1);
/// ```
pub struct AuditTrail {
    events: RefCell<Vec<AuditEvent>>,
}

impl AuditTrail {
    /// Creates a new empty audit trail.
    pub fn new() -> Self {
        Self {
            events: RefCell::new(Vec::new()),
        }
    }

    /// Records an audit event.
    ///
    /// Events are stored in memory in the order they are recorded.
    pub fn record(&self, event: AuditEvent) {
        self.events.borrow_mut().push(event);
    }

    /// Provides borrowed access to events via callback (zero-copy).
    ///
    /// This method allows you to access the event list without cloning by
    /// passing a closure that receives a borrowed slice.
    ///
    /// # Performance
    ///
    /// This is the most efficient way to read events when you don't need to
    /// own them. The closure receives `&[AuditEvent]` and can iterate, filter,
    /// or perform any read operation without allocating.
    ///
    /// # Example
    ///
    /// ```
    /// use policy_core::audit::{AuditTrail, AuditEvent, AuditEventKind, AuditOutcome};
    ///
    /// let trail = AuditTrail::new();
    /// trail.record(AuditEvent::new(
    ///     "req-1",
    ///     Some("user@example.com"),
    ///     AuditEventKind::AdminAction,
    ///     AuditOutcome::Success,
    /// ));
    ///
    /// // Zero-copy access via callback
    /// trail.with_events(|events| {
    ///     println!("Event count: {}", events.len());
    ///     for event in events {
    ///         println!("  {}", event.request_id());
    ///     }
    /// });
    /// ```
    pub fn with_events<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[AuditEvent]) -> R,
    {
        f(&self.events.borrow())
    }

    /// Returns an iterator over events (lazy cloning).
    ///
    /// # Performance Note
    ///
    /// Due to `RefCell` interior mutability, this method clones the vector
    /// before returning an iterator. However, iteration happens lazily, so if
    /// you only need a few events, this can be more efficient than processing
    /// the entire cloned vector.
    ///
    /// For zero-copy access, prefer [`with_events()`](Self::with_events).
    ///
    /// # Example
    ///
    /// ```
    /// use policy_core::audit::{AuditTrail, AuditEvent, AuditEventKind, AuditOutcome};
    ///
    /// let trail = AuditTrail::new();
    /// trail.record(AuditEvent::new(
    ///     "req-1",
    ///     Some("user@example.com"),
    ///     AuditEventKind::AdminAction,
    ///     AuditOutcome::Success,
    /// ));
    ///
    /// // Iterator-based access
    /// for event in trail.iter() {
    ///     println!("{}", event.request_id());
    /// }
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = AuditEvent> {
        self.events.borrow().clone().into_iter()
    }

    /// Returns a snapshot of all recorded events.
    ///
    /// # Performance Note
    ///
    /// **This method clones the entire event vector.**
    ///
    /// This is intentional to avoid holding an immutable borrow of the internal
    /// `RefCell`, but it means the cost is O(n) where n is the number of events.
    ///
    /// **Deprecated:** Use [`iter()`](Self::iter) for lazy iteration or
    /// [`with_events()`](Self::with_events) for zero-copy access.
    ///
    /// This method is designed for:
    /// - Testing and verification (reading a small number of events)
    /// - Periodic snapshots for export/persistence
    ///
    /// For large audit trails, consider:
    /// - Using `len()` or `is_empty()` for simple checks (no cloning)
    /// - Using `with_events()` for zero-copy access
    /// - Using `iter()` for lazy iteration
    /// - Integrating with a persistent audit backend directly
    ///
    /// # Example
    ///
    /// ```
    /// use policy_core::audit::{AuditTrail, AuditEvent, AuditEventKind, AuditOutcome};
    ///
    /// let trail = AuditTrail::new();
    /// trail.record(AuditEvent::new(
    ///     "req-1",
    ///     Some("user@example.com"),
    ///     AuditEventKind::AdminAction,
    ///     AuditOutcome::Success,
    /// ));
    ///
    /// // events() clones the vector - fine for small trails
    /// let snapshot = trail.events();
    /// assert_eq!(snapshot.len(), 1);
    /// ```
    #[deprecated(
        since = "0.2.0",
        note = "Use `iter()` or `with_events()` for better performance"
    )]
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.borrow().clone()
    }

    /// Returns the number of recorded events.
    pub fn len(&self) -> usize {
        self.events.borrow().len()
    }

    /// Returns true if no events have been recorded.
    pub fn is_empty(&self) -> bool {
        self.events.borrow().is_empty()
    }

    /// Clears all recorded events.
    pub fn clear(&self) {
        self.events.borrow_mut().clear();
    }
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::{AuditEventKind, AuditOutcome};

    #[test]
    fn audit_trail_starts_empty() {
        let trail = AuditTrail::new();
        assert!(trail.is_empty());
        assert_eq!(trail.len(), 0);
    }

    #[test]
    #[allow(deprecated)]
    fn audit_trail_records_events() {
        let trail = AuditTrail::new();

        let event1 = AuditEvent::new(
            "req-1",
            Some("user1@example.com"),
            AuditEventKind::Authentication,
            AuditOutcome::Success,
        );

        let event2 = AuditEvent::new(
            "req-2",
            Some("user2@example.com"),
            AuditEventKind::Authorization,
            AuditOutcome::Denied,
        );

        trail.record(event1);
        trail.record(event2);

        assert_eq!(trail.len(), 2);
        assert!(!trail.is_empty());

        let events = trail.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].request_id(), "req-1");
        assert_eq!(events[1].request_id(), "req-2");
    }

    #[test]
    fn audit_trail_can_be_cleared() {
        let trail = AuditTrail::new();

        trail.record(AuditEvent::new(
            "req-1",
            None::<String>,
            AuditEventKind::SecurityEvent,
            AuditOutcome::Error,
        ));

        assert_eq!(trail.len(), 1);

        trail.clear();

        assert_eq!(trail.len(), 0);
        assert!(trail.is_empty());
    }

    #[test]
    fn audit_trail_default() {
        let trail = AuditTrail::default();
        assert!(trail.is_empty());
    }
}
