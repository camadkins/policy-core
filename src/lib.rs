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
//!
//! # Examples
//!
//! ```
//! use policy_core::Secret;
//!
//! // Secrets are automatically redacted
//! let api_key = Secret::new("super-secret-key".to_string());
//! println!("{:?}", api_key); // Prints: [REDACTED]
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod capability;
mod context;
mod secret;
mod tainted;

pub use capability::{LogCap, log_with_capability};
pub use context::Ctx;
pub use secret::Secret;
pub use tainted::Tainted;
