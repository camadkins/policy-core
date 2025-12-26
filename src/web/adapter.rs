//! Request adapter for mapping HTTP requests to policy-core types.

use std::collections::HashMap;

use crate::request::{Principal, RequestMeta};
use crate::Tainted;

use super::{ExtractMetadata, ExtractTaintedInputs};

/// Adapter for converting framework-specific HTTP requests into policy-core types.
///
/// `RequestAdapter` is the primary integration point between web frameworks
/// and policy-core. It provides a framework-agnostic interface for:
/// - Extracting request metadata (request-id, principal)
/// - Collecting untrusted inputs as tainted values
///
/// # Design Notes
///
/// This type intentionally contains simple, owned data to avoid coupling
/// to any specific framework's request types. Framework-specific code
/// should implement `From<FrameworkRequest>` for `RequestAdapter`.
///
/// # Examples
///
/// ```
/// use policy_core::web::{RequestAdapter, ExtractMetadata, ExtractTaintedInputs};
/// use policy_core::{RequestMeta, Principal};
///
/// // Building from raw parts (framework integration would use From<FrameworkRequest>)
/// let mut adapter = RequestAdapter::new("req-12345".to_string());
/// adapter.set_principal(Some(Principal {
///     id: "user-1".to_string(),
///     name: "Alice".to_string(),
/// }));
/// adapter.add_query_param("search".to_string(), "user input".to_string());
///
/// // Extract metadata for PolicyGate
/// let meta = adapter.extract_metadata();
/// assert_eq!(meta.request_id, "req-12345");
///
/// // Extract tainted inputs for sanitization
/// let inputs = adapter.extract_tainted_inputs();
/// assert!(inputs.query_params().contains_key("search"));
/// ```
#[derive(Debug, Clone)]
pub struct RequestAdapter {
    /// Unique request identifier (required)
    request_id: String,
    /// Authenticated principal (optional)
    principal: Option<Principal>,
    /// Query parameters from URL (all tainted)
    query_params: HashMap<String, String>,
    /// Request headers (all tainted)
    headers: HashMap<String, String>,
    /// Path parameters from routing (all tainted)
    path_params: HashMap<String, String>,
}

impl RequestAdapter {
    /// Creates a new request adapter with the given request ID.
    ///
    /// All other fields are initialized as empty. Use builder-style methods
    /// to populate them.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::web::RequestAdapter;
    ///
    /// let adapter = RequestAdapter::new("req-001".to_string());
    /// ```
    pub fn new(request_id: String) -> Self {
        Self {
            request_id,
            principal: None,
            query_params: HashMap::new(),
            headers: HashMap::new(),
            path_params: HashMap::new(),
        }
    }

    /// Sets the authenticated principal for this request.
    ///
    /// This should be called after successful authentication, typically
    /// by framework-specific middleware that validates session tokens,
    /// JWT claims, etc.
    pub fn set_principal(&mut self, principal: Option<Principal>) {
        self.principal = principal;
    }

    /// Adds a query parameter to the adapter.
    ///
    /// All query parameters will be wrapped in `Tainted<T>` when extracted.
    pub fn add_query_param(&mut self, key: String, value: String) {
        self.query_params.insert(key, value);
    }

    /// Adds a header to the adapter.
    ///
    /// All headers will be wrapped in `Tainted<T>` when extracted.
    pub fn add_header(&mut self, key: String, value: String) {
        self.headers.insert(key, value);
    }

    /// Adds a path parameter to the adapter.
    ///
    /// All path parameters will be wrapped in `Tainted<T>` when extracted.
    pub fn add_path_param(&mut self, key: String, value: String) {
        self.path_params.insert(key, value);
    }

    /// Returns a reference to the request ID.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns a reference to the principal, if present.
    pub fn principal(&self) -> Option<&Principal> {
        self.principal.as_ref()
    }
}

impl ExtractMetadata for RequestAdapter {
    fn extract_metadata(&self) -> RequestMeta {
        RequestMeta {
            request_id: self.request_id.clone(),
            principal: self.principal.clone(),
        }
    }
}

impl ExtractTaintedInputs for RequestAdapter {
    fn extract_tainted_inputs(&self) -> TaintedInputs {
        TaintedInputs {
            query_params: self
                .query_params
                .iter()
                .map(|(k, v)| (k.clone(), Tainted::new(v.clone())))
                .collect(),
            headers: self
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), Tainted::new(v.clone())))
                .collect(),
            path_params: self
                .path_params
                .iter()
                .map(|(k, v)| (k.clone(), Tainted::new(v.clone())))
                .collect(),
        }
    }
}

/// Collection of tainted inputs extracted from an HTTP request.
///
/// All values are wrapped in `Tainted<T>` to enforce sanitization before use.
/// This type provides read-only access to inputs - modification is not allowed.
///
/// # Examples
///
/// ```
/// use policy_core::web::{RequestAdapter, ExtractTaintedInputs};
/// use policy_core::{Sanitizer, StringSanitizer};
///
/// let mut adapter = RequestAdapter::new("req-1".to_string());
/// adapter.add_query_param("username".to_string(), "alice".to_string());
///
/// let inputs = adapter.extract_tainted_inputs();
/// let tainted_username = inputs.query_params().get("username").unwrap();
///
/// // Must sanitize before use
/// let sanitizer = StringSanitizer::new(50);
/// let verified_username = sanitizer.sanitize(tainted_username.clone()).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct TaintedInputs {
    query_params: HashMap<String, Tainted<String>>,
    headers: HashMap<String, Tainted<String>>,
    path_params: HashMap<String, Tainted<String>>,
}

impl TaintedInputs {
    /// Returns a reference to the tainted query parameters.
    pub fn query_params(&self) -> &HashMap<String, Tainted<String>> {
        &self.query_params
    }

    /// Returns a reference to the tainted headers.
    pub fn headers(&self) -> &HashMap<String, Tainted<String>> {
        &self.headers
    }

    /// Returns a reference to the tainted path parameters.
    pub fn path_params(&self) -> &HashMap<String, Tainted<String>> {
        &self.path_params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_adapter_new() {
        let adapter = RequestAdapter::new("req-test".to_string());
        assert_eq!(adapter.request_id(), "req-test");
        assert!(adapter.principal().is_none());
    }

    #[test]
    fn request_adapter_set_principal() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        let principal = Principal {
            id: "user-1".to_string(),
            name: "Alice".to_string(),
        };

        adapter.set_principal(Some(principal.clone()));
        assert_eq!(adapter.principal().unwrap().id, "user-1");
    }

    #[test]
    fn request_adapter_add_query_param() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        adapter.add_query_param("search".to_string(), "test".to_string());

        let inputs = adapter.extract_tainted_inputs();
        assert!(inputs.query_params().contains_key("search"));
    }

    #[test]
    fn request_adapter_add_header() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        adapter.add_header("X-Custom".to_string(), "value".to_string());

        let inputs = adapter.extract_tainted_inputs();
        assert!(inputs.headers().contains_key("X-Custom"));
    }

    #[test]
    fn request_adapter_add_path_param() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        adapter.add_path_param("id".to_string(), "123".to_string());

        let inputs = adapter.extract_tainted_inputs();
        assert!(inputs.path_params().contains_key("id"));
    }

    #[test]
    fn extract_metadata_includes_request_id() {
        let adapter = RequestAdapter::new("req-meta".to_string());
        let meta = adapter.extract_metadata();
        assert_eq!(meta.request_id, "req-meta");
    }

    #[test]
    fn extract_metadata_includes_principal() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        let principal = Principal {
            id: "user-1".to_string(),
            name: "Bob".to_string(),
        };
        adapter.set_principal(Some(principal));

        let meta = adapter.extract_metadata();
        assert!(meta.principal.is_some());
        assert_eq!(meta.principal.unwrap().id, "user-1");
    }

    #[test]
    fn extract_tainted_inputs_wraps_all_inputs() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        adapter.add_query_param("q".to_string(), "search term".to_string());
        adapter.add_header("User-Agent".to_string(), "browser".to_string());
        adapter.add_path_param("user_id".to_string(), "42".to_string());

        let inputs = adapter.extract_tainted_inputs();

        assert_eq!(inputs.query_params().len(), 1);
        assert_eq!(inputs.headers().len(), 1);
        assert_eq!(inputs.path_params().len(), 1);
    }

    #[test]
    fn tainted_inputs_are_read_only() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        adapter.add_query_param("key".to_string(), "value".to_string());

        let inputs = adapter.extract_tainted_inputs();
        let params = inputs.query_params();

        // This verifies the API is read-only - we can only get references
        assert!(params.get("key").is_some());
    }

    #[test]
    fn multiple_extractions_produce_independent_copies() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        adapter.add_query_param("k".to_string(), "v".to_string());

        let inputs1 = adapter.extract_tainted_inputs();
        let inputs2 = adapter.extract_tainted_inputs();

        // Both should have the same data
        assert_eq!(inputs1.query_params().len(), inputs2.query_params().len());
    }
}
