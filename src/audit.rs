//! Audit trail support for compliance-grade logging.
//!
//! This module provides:
//! - `AuditCap`: Capability proving authorization to emit audit events
//! - `AuditEvent`: Structured audit event schema
//! - `AuditTrail`: In-memory audit event recorder
//! - `PolicyAudit`: Capability-gated audit event emitter
//!
//! Audit events are designed to be safe by default:
//! - No storage of raw tainted input
//! - No exposure of secrets in Debug/Display
//! - Only safe metadata is recorded

pub(crate) mod capability;
mod event;
mod policy_audit;
mod trail;

pub use capability::AuditCap;
pub use event::{AuditEvent, AuditEventKind, AuditOutcome};
pub use policy_audit::PolicyAudit;
pub use trail::AuditTrail;
