//! Web framework integration surface.
//!
//! This module provides the boundary between HTTP frameworks and policy-core's
//! enforcement mechanisms. It handles:
//! - Mapping HTTP requests to domain types (RequestMeta)
//! - Introducing taint at the boundary (untrusted inputs → `Tainted<T>`)
//! - Request-ID extraction and propagation
//!
//! # Design Principles
//!
//! 1. **No Framework Dependencies**: This module contains no framework-specific code.
//!    It defines interfaces that framework-specific code can implement.
//!
//! 2. **Taint at Boundary**: All external inputs (headers, query params, body fields)
//!    are wrapped in `Tainted<T>` at extraction time.
//!
//! 3. **No Authorization**: The web boundary does not grant capabilities.
//!    It only extracts metadata and marks inputs as untrusted.
//!    Authorization happens via `PolicyGate`.
//!
//! 4. **Explicit Context**: No global state. All context flows through values.
//!
//! # Integration Model
//!
//! Framework-specific extractors should:
//! 1. Build a `RequestAdapter` from framework request types
//! 2. Call `.extract_metadata()` to get `RequestMeta`
//! 3. Call `.extract_tainted_inputs()` to get tainted user inputs
//! 4. Pass `RequestMeta` to `PolicyGate` for policy validation
//! 5. Pass tainted inputs to application code for sanitization
//!
//! # Example Flow
//!
//! ```ignore
//! // In a framework-specific integration (e.g., axum, actix):
//!
//! // 1. Extract from HTTP request
//! let adapter = RequestAdapter::from_http_request(http_req);
//! let meta = adapter.extract_metadata();
//! let inputs = adapter.extract_tainted_inputs();
//!
//! // 2. Validate policies
//! let ctx = PolicyGate::new(meta)
//!     .require(Authenticated)
//!     .require(Authorized::for_action("http"))
//!     .build()?;
//!
//! // 3. Sanitize inputs
//! let sanitizer = StringSanitizer::new(256);
//! let verified_name = sanitizer.sanitize(inputs.get("name").unwrap().clone())?;
//!
//! // 4. Perform authorized operation
//! let http = ctx.http()?;
//! http.get(&verified_url);
//! ```

mod adapter;
pub mod example_handler;
mod extract;
mod middleware;

pub use adapter::{RequestAdapter, TaintedInputs};
pub use extract::{ExtractMetadata, ExtractTaintedInputs};
pub use middleware::{
    extract_authed, extract_unauthed, AuthenticatedExtraction, UnauthenticatedExtraction,
};
