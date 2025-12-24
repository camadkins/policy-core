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
//! - [`Verified<T>`]: Wrapper for validated/sanitized data safe to use
//! - [`Sanitizer<T>`]: Trait for sanitizing tainted values into verified values
//! - [`Sink<T>`]: Trait for operations that accept only verified values
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

pub mod audit;
mod capability;
mod context;
mod demo;
mod error;
mod gate;
mod http;
mod logging;
mod policy;
mod request;
mod sanitizer;
mod secret;
mod sink;
mod state;
mod tainted;
mod verified;
pub mod web;

pub use capability::{HttpCap, LogCap, log_with_capability};
pub use context::Ctx;
pub use error::{Error, Violation, ViolationKind};
pub use gate::PolicyGate;
pub use http::{HttpMethod, HttpRequest, PolicyHttp};
pub use logging::PolicyLog;
pub use policy::{Authenticated, Authorized};
pub use request::{Principal, RequestMeta};
pub use sanitizer::{
    AcceptAllSanitizer, RejectAllSanitizer, SanitizationError, SanitizationErrorKind, Sanitizer,
    StringSanitizer,
};
pub use secret::Secret;
pub use sink::{Sink, SinkError, SinkErrorKind, VecSink};
pub use state::{Authed, Authorized as AuthorizedState, Unauthed};
pub use tainted::Tainted;
pub use verified::Verified;

#[cfg(test)]
pub(crate) mod test_utils {
    use proptest::prelude::*;

    /// Strategy: Generate valid strings (no control chars, non-empty after trim)
    pub fn arb_valid_string(max_len: usize) -> impl Strategy<Value = String> {
        prop::string::string_regex(&format!("[a-zA-Z0-9 _-]{{1,{}}}", max_len))
            .expect("valid regex")
            .prop_filter("non-empty after trim", |s| !s.trim().is_empty())
            .prop_map(|s| s.trim().to_string())
    }
}
