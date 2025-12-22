//! Extraction boundary traits for web integration.
//!
//! This module defines the core abstraction for extracting policy-core types
//! from framework-specific request types.

use crate::request::RequestMeta;

use super::TaintedInputs;

/// Extracts request metadata from a framework-specific request.
///
/// This trait defines the boundary between web framework types and
/// policy-core's `RequestMeta`. Framework-specific integrations should
/// implement this trait to provide:
/// - Request ID extraction/generation
/// - Principal extraction from session/auth headers
///
/// # Design Notes
///
/// This trait intentionally does NOT:
/// - Grant capabilities (that's PolicyGate's job)
/// - Perform authorization (that's PolicyGate's job)
/// - Sanitize inputs (that's the application's job)
///
/// It ONLY maps framework types to domain types.
///
/// # Examples
///
/// ```
/// use policy_core::web::ExtractMetadata;
/// use policy_core::{RequestMeta, Principal};
///
/// // Example framework-specific implementation
/// struct MyFrameworkRequest {
///     request_id: String,
///     user: Option<String>,
/// }
///
/// impl ExtractMetadata for MyFrameworkRequest {
///     fn extract_metadata(&self) -> RequestMeta {
///         RequestMeta {
///             request_id: self.request_id.clone(),
///             principal: self.user.as_ref().map(|u| Principal {
///                 id: u.clone(),
///                 name: u.clone(),
///             }),
///         }
///     }
/// }
/// ```
pub trait ExtractMetadata {
    /// Extracts request metadata for policy validation.
    ///
    /// Returns a `RequestMeta` containing:
    /// - `request_id`: Unique identifier for this request
    /// - `principal`: Authenticated user/service, if available
    fn extract_metadata(&self) -> RequestMeta;
}

/// Extracts tainted inputs from a framework-specific request.
///
/// This trait defines how to collect untrusted user inputs from various
/// parts of an HTTP request (query params, headers, path params, body fields).
///
/// All extracted inputs MUST be wrapped in `Tainted<T>` to enforce
/// sanitization before use in sinks.
///
/// # Design Notes
///
/// This trait enforces taint at the boundary. Every value that crosses
/// the HTTP boundary is considered untrusted until explicitly sanitized.
///
/// Framework integrations should extract:
/// - Query parameters (e.g., `?search=foo`)
/// - Request headers (e.g., `User-Agent`, custom headers)
/// - Path parameters (e.g., `/users/:id`)
/// - Form/JSON body fields (future extension)
///
/// # Examples
///
/// ```
/// use policy_core::web::{ExtractTaintedInputs, TaintedInputs};
/// use policy_core::Tainted;
/// use std::collections::HashMap;
///
/// // Example framework-specific implementation
/// struct MyFrameworkRequest {
///     query: HashMap<String, String>,
/// }
///
/// impl ExtractTaintedInputs for MyFrameworkRequest {
///     fn extract_tainted_inputs(&self) -> TaintedInputs {
///         // Use RequestAdapter as a helper for building TaintedInputs
///         use policy_core::web::RequestAdapter;
///         let mut adapter = RequestAdapter::new("req-1".to_string());
///
///         for (k, v) in &self.query {
///             adapter.add_query_param(k.clone(), v.clone());
///         }
///
///         adapter.extract_tainted_inputs()
///     }
/// }
/// ```
pub trait ExtractTaintedInputs {
    /// Extracts all untrusted inputs from the request.
    ///
    /// Returns a `TaintedInputs` collection with all user-controlled
    /// values wrapped in `Tainted<T>`.
    fn extract_tainted_inputs(&self) -> TaintedInputs;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Principal;
    use crate::web::RequestAdapter;

    // Test implementation for documentation
    struct TestRequest {
        id: String,
        user: Option<String>,
    }

    impl ExtractMetadata for TestRequest {
        fn extract_metadata(&self) -> RequestMeta {
            RequestMeta {
                request_id: self.id.clone(),
                principal: self.user.as_ref().map(|u| Principal {
                    id: u.clone(),
                    name: u.clone(),
                }),
            }
        }
    }

    impl ExtractTaintedInputs for TestRequest {
        fn extract_tainted_inputs(&self) -> TaintedInputs {
            // Minimal implementation for testing
            let adapter = RequestAdapter::new(self.id.clone());
            adapter.extract_tainted_inputs()
        }
    }

    #[test]
    fn extract_metadata_trait_works() {
        let req = TestRequest {
            id: "test-1".to_string(),
            user: Some("alice".to_string()),
        };

        let meta = req.extract_metadata();
        assert_eq!(meta.request_id, "test-1");
        assert!(meta.principal.is_some());
    }

    #[test]
    fn extract_tainted_inputs_trait_works() {
        let req = TestRequest {
            id: "test-2".to_string(),
            user: None,
        };

        let inputs = req.extract_tainted_inputs();
        // Just verify it returns successfully
        assert_eq!(inputs.query_params().len(), 0);
    }
}
