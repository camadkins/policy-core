//! Request adapter for mapping HTTP requests to policy-core types.

use std::collections::HashMap;
use std::sync::Arc;

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
/// assert!(inputs.has_query_param("search"));
/// ```
#[derive(Debug, Clone)]
pub struct RequestAdapter {
    /// Unique request identifier (required)
    request_id: String,
    /// Authenticated principal (optional)
    principal: Option<Principal>,
    /// Query parameters from URL (all tainted)
    /// Uses Arc for cheap cloning during extraction
    query_params: Arc<HashMap<String, String>>,
    /// Request headers (all tainted)
    /// Uses Arc for cheap cloning during extraction
    headers: Arc<HashMap<String, String>>,
    /// Path parameters from routing (all tainted)
    /// Uses Arc for cheap cloning during extraction
    path_params: Arc<HashMap<String, String>>,
}

impl RequestAdapter {
    /// Validates that a request ID is safe for logging.
    ///
    /// Rejects request IDs containing control characters that could enable
    /// log injection attacks (CWE-117).
    fn validate_request_id(request_id: &str) -> Result<(), String> {
        // Check for control characters or non-printable characters
        if request_id
            .chars()
            .any(|c| c.is_control() || c == '\u{007F}')
        {
            return Err(format!(
                "request_id contains control characters (length: {})",
                request_id.len()
            ));
        }

        // Enforce reasonable length to prevent DoS
        if request_id.is_empty() {
            return Err("request_id cannot be empty".to_string());
        }

        if request_id.len() > 256 {
            return Err(format!(
                "request_id exceeds maximum length of 256 (got: {})",
                request_id.len()
            ));
        }

        Ok(())
    }

    /// Creates a new request adapter with the given request ID.
    ///
    /// All other fields are initialized as empty. Use builder-style methods
    /// to populate them.
    ///
    /// # Panics
    ///
    /// Panics if the request_id contains control characters, is empty, or exceeds
    /// 256 characters. This is a programming error that should be caught during
    /// development.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::web::RequestAdapter;
    ///
    /// let adapter = RequestAdapter::new("req-001".to_string());
    /// ```
    pub fn new(request_id: String) -> Self {
        // Validate request_id to prevent log injection (issue #80)
        if let Err(e) = Self::validate_request_id(&request_id) {
            panic!("Invalid request_id: {}", e);
        }

        Self {
            request_id,
            principal: None,
            query_params: Arc::new(HashMap::new()),
            headers: Arc::new(HashMap::new()),
            path_params: Arc::new(HashMap::new()),
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
        Arc::make_mut(&mut self.query_params).insert(key, value);
    }

    /// Adds a header to the adapter.
    ///
    /// All headers will be wrapped in `Tainted<T>` when extracted.
    pub fn add_header(&mut self, key: String, value: String) {
        Arc::make_mut(&mut self.headers).insert(key, value);
    }

    /// Adds a path parameter to the adapter.
    ///
    /// All path parameters will be wrapped in `Tainted<T>` when extracted.
    pub fn add_path_param(&mut self, key: String, value: String) {
        Arc::make_mut(&mut self.path_params).insert(key, value);
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
            query_params: Arc::clone(&self.query_params),
            headers: Arc::clone(&self.headers),
            path_params: Arc::clone(&self.path_params),
        }
    }
}

/// Collection of tainted inputs extracted from an HTTP request.
///
/// All values are wrapped in `Tainted<T>` to enforce sanitization before use.
/// This type provides read-only access to inputs - modification is not allowed.
///
/// Uses `Arc` internally for efficient sharing of input data without cloning.
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
/// let tainted_username = inputs.get_query("username").unwrap();
///
/// // Must sanitize before use
/// let sanitizer = StringSanitizer::new(50).unwrap();
/// let verified_username = sanitizer.sanitize(tainted_username).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct TaintedInputs {
    query_params: Arc<HashMap<String, String>>,
    headers: Arc<HashMap<String, String>>,
    path_params: Arc<HashMap<String, String>>,
}

impl TaintedInputs {
    /// Gets a tainted query parameter by key.
    ///
    /// Returns `None` if the key doesn't exist.
    pub fn get_query(&self, key: &str) -> Option<Tainted<String>> {
        self.query_params.get(key).map(|v| Tainted::new(v.clone()))
    }

    /// Gets a tainted header by key.
    ///
    /// Returns `None` if the key doesn't exist.
    pub fn get_header(&self, key: &str) -> Option<Tainted<String>> {
        self.headers.get(key).map(|v| Tainted::new(v.clone()))
    }

    /// Gets a tainted path parameter by key.
    ///
    /// Returns `None` if the key doesn't exist.
    pub fn get_path_param(&self, key: &str) -> Option<Tainted<String>> {
        self.path_params.get(key).map(|v| Tainted::new(v.clone()))
    }

    /// Returns an iterator over query parameters as (key, Tainted<value>) pairs.
    pub fn query_params(&self) -> impl Iterator<Item = (&str, Tainted<String>)> + '_ {
        self.query_params
            .iter()
            .map(|(k, v)| (k.as_str(), Tainted::new(v.clone())))
    }

    /// Returns an iterator over headers as (key, Tainted<value>) pairs.
    pub fn headers(&self) -> impl Iterator<Item = (&str, Tainted<String>)> + '_ {
        self.headers
            .iter()
            .map(|(k, v)| (k.as_str(), Tainted::new(v.clone())))
    }

    /// Returns an iterator over path parameters as (key, Tainted<value>) pairs.
    pub fn path_params(&self) -> impl Iterator<Item = (&str, Tainted<String>)> + '_ {
        self.path_params
            .iter()
            .map(|(k, v)| (k.as_str(), Tainted::new(v.clone())))
    }

    /// Checks if a query parameter with the given key exists.
    pub fn has_query_param(&self, key: &str) -> bool {
        self.query_params.contains_key(key)
    }

    /// Checks if a header with the given key exists.
    pub fn has_header(&self, key: &str) -> bool {
        self.headers.contains_key(key)
    }

    /// Checks if a path parameter with the given key exists.
    pub fn has_path_param(&self, key: &str) -> bool {
        self.path_params.contains_key(key)
    }

    /// Returns the number of query parameters without cloning.
    ///
    /// This is more efficient than `.query_params().count()` as it
    /// avoids iterating and cloning all values.
    pub fn query_params_count(&self) -> usize {
        self.query_params.len()
    }

    /// Returns the number of headers without cloning.
    ///
    /// This is more efficient than `.headers().count()` as it
    /// avoids iterating and cloning all values.
    pub fn headers_count(&self) -> usize {
        self.headers.len()
    }

    /// Returns the number of path parameters without cloning.
    ///
    /// This is more efficient than `.path_params().count()` as it
    /// avoids iterating and cloning all values.
    pub fn path_params_count(&self) -> usize {
        self.path_params.len()
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
        assert!(inputs.has_query_param("search"));
    }

    #[test]
    fn request_adapter_add_header() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        adapter.add_header("X-Custom".to_string(), "value".to_string());

        let inputs = adapter.extract_tainted_inputs();
        assert!(inputs.has_header("X-Custom"));
    }

    #[test]
    fn request_adapter_add_path_param() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        adapter.add_path_param("id".to_string(), "123".to_string());

        let inputs = adapter.extract_tainted_inputs();
        assert!(inputs.has_path_param("id"));
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

        assert_eq!(inputs.query_params_count(), 1);
        assert_eq!(inputs.headers_count(), 1);
        assert_eq!(inputs.path_params_count(), 1);
    }

    #[test]
    fn tainted_inputs_are_read_only() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        adapter.add_query_param("key".to_string(), "value".to_string());

        let inputs = adapter.extract_tainted_inputs();

        // This verifies the API provides tainted values
        assert!(inputs.get_query("key").is_some());
    }

    #[test]
    fn multiple_extractions_produce_independent_copies() {
        let mut adapter = RequestAdapter::new("req-1".to_string());
        adapter.add_query_param("k".to_string(), "v".to_string());

        let inputs1 = adapter.extract_tainted_inputs();
        let inputs2 = adapter.extract_tainted_inputs();

        // Both should have the same data (via Arc sharing)
        assert_eq!(
            inputs1.query_params().count(),
            inputs2.query_params().count()
        );
    }

    // Tests for request_id validation (issue #80)

    #[test]
    fn request_adapter_accepts_valid_request_id() {
        let adapter = RequestAdapter::new("req-12345".to_string());
        assert_eq!(adapter.request_id(), "req-12345");
    }

    #[test]
    #[should_panic(expected = "Invalid request_id")]
    fn request_adapter_rejects_newline_in_request_id() {
        let _adapter = RequestAdapter::new("req-123\nmalicious".to_string());
    }

    #[test]
    #[should_panic(expected = "Invalid request_id")]
    fn request_adapter_rejects_carriage_return_in_request_id() {
        let _adapter = RequestAdapter::new("req-123\rmalicious".to_string());
    }

    #[test]
    #[should_panic(expected = "Invalid request_id")]
    fn request_adapter_rejects_null_byte_in_request_id() {
        let _adapter = RequestAdapter::new("req-123\0".to_string());
    }

    #[test]
    #[should_panic(expected = "Invalid request_id")]
    fn request_adapter_rejects_empty_request_id() {
        let _adapter = RequestAdapter::new("".to_string());
    }

    #[test]
    #[should_panic(expected = "Invalid request_id")]
    fn request_adapter_rejects_too_long_request_id() {
        let long_id = "a".repeat(257);
        let _adapter = RequestAdapter::new(long_id);
    }

    #[test]
    fn request_adapter_accepts_max_length_request_id() {
        let max_id = "a".repeat(256);
        let adapter = RequestAdapter::new(max_id.clone());
        assert_eq!(adapter.request_id(), &max_id);
    }
}
