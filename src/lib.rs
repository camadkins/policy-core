//! Policy enforcement framework using capabilities and taint tracking.
//!
//! This crate provides compile-time enforcement of security policies through:
//! - **Capabilities**: Typed proof objects that grant access to privileged operations
//! - **Taint tracking**: Prevention of untrusted data flowing into sensitive sinks
//! - **Explicit context**: All privileged operations require validated context
//!
//! # Core Types
//!
//! - [`Secret<T>`]: Wrapper that redacts sensitive values in logs/output
//! - [`Tainted<T>`]: Wrapper for untrusted data requiring sanitization
//! - [`Ctx`]: Validated execution context holding capabilities
//! - [`LogCap`]: Capability proving authorization for logging operations
//! - [`PolicyGate`]: Builder for validating policies and creating contexts
//!
//! # Examples
//!
//! ```
//! use policy_core::{Secret, PolicyGate, RequestMeta, Principal, Authenticated, Authorized};
//!
//! // Secrets are automatically redacted
//! let api_key = Secret::new("super-secret-key".to_string());
//! println!("{:?}", api_key); // Prints: [REDACTED]
//!
//! // PolicyGate enforces requirements
//! let meta = RequestMeta {
//!     request_id: "req-123".to_string(),
//!     principal: Some(Principal {
//!         id: "user-1".to_string(),
//!         name: "Alice".to_string(),
//!     }),
//! };
//!
//! let ctx = PolicyGate::new(meta)
//!     .require(Authenticated)
//!     .require(Authorized::for_action("log"))
//!     .build()
//!     .expect("policies satisfied");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod capability;
mod context;
mod error;
mod gate;
mod policy;
mod request;
mod secret;
mod tainted;

pub use capability::{LogCap, log_with_capability};
pub use context::Ctx;
pub use error::{Error, Violation, ViolationKind};
pub use gate::PolicyGate;
pub use policy::{Authenticated, Authorized};
pub use request::{Principal, RequestMeta};
pub use secret::Secret;
pub use tainted::Tainted;
