use std::cell::RefCell;
use std::fmt;

use crate::Verified;

/// HTTP method for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// HTTP GET method
    Get,
    /// HTTP POST method
    Post,
    /// HTTP PUT method
    Put,
    /// HTTP DELETE method
    Delete,
    /// HTTP PATCH method
    Patch,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Patch => write!(f, "PATCH"),
        }
    }
}

/// Metadata about a recorded HTTP request.
///
/// This structure captures the essential details of an HTTP request without
/// storing the full request body to avoid leaking sensitive data in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// HTTP method used
    pub method: HttpMethod,
    /// Target URL (verified)
    pub url: String,
    /// Length of the request body in bytes
    pub body_len: usize,
}

/// A capability-gated HTTP client interface.
///
/// `PolicyHttp` is obtained from `Ctx::http()` and requires `HttpCap`.
/// It is lifetime-bound to the context to prevent misuse.
///
/// This implementation records HTTP request metadata for testing without
/// performing actual network I/O, making tests deterministic and offline.
///
/// # Security Properties
///
/// - Requires `HttpCap` to construct (capability-gated)
/// - Accepts only `Verified<String>` for URLs and request bodies
/// - Rejects tainted data at compile time
/// - Does not leak full request bodies in recorded metadata
///
/// # Examples
///
/// ```no_run
/// # use policy_core::{PolicyGate, RequestMeta, Principal, Authenticated, Authorized};
/// # use policy_core::{Tainted, Sanitizer, StringSanitizer};
/// # let meta = RequestMeta {
/// #     request_id: "req-1".to_string(),
/// #     principal: Some(Principal { id: "u1".to_string(), name: "Alice".to_string() }),
/// # };
/// # let ctx = PolicyGate::new(meta)
/// #     .require(Authenticated)
/// #     .require(Authorized::for_action("http"))
/// #     .build()
/// #     .unwrap();
/// let http = ctx.http().expect("HttpCap required");
///
/// // URLs and bodies must be verified
/// let sanitizer = StringSanitizer::new(256);
/// let url = Tainted::new("https://api.example.com/users".to_string());
/// let verified_url = sanitizer.sanitize(url).unwrap();
///
/// let body = Tainted::new(r#"{"name": "Alice"}"#.to_string());
/// let verified_body = sanitizer.sanitize(body).unwrap();
///
/// http.post(&verified_url, &verified_body);
/// ```
#[derive(Debug)]
pub struct PolicyHttp<'a> {
    // Lifetime ensures this can't outlive the Ctx
    _ctx_lifetime: std::marker::PhantomData<&'a ()>,
    // Recorded requests for testing/verification
    requests: RefCell<Vec<HttpRequest>>,
}

impl<'a> PolicyHttp<'a> {
    /// Creates a new PolicyHttp.
    ///
    /// This is `pub(crate)` - only `Ctx` can create it.
    pub(crate) fn new() -> Self {
        Self {
            _ctx_lifetime: std::marker::PhantomData,
            requests: RefCell::new(Vec::new()),
        }
    }

    /// Records an HTTP GET request.
    ///
    /// # Arguments
    ///
    /// * `url` - The verified target URL
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use policy_core::{PolicyHttp, Verified};
    /// # let http = PolicyHttp::new();
    /// # let verified_url = Verified::new_unchecked("https://api.example.com".to_string());
    /// http.get(&verified_url);
    /// ```
    pub fn get(&self, url: &Verified<String>) {
        self.record_request(
            HttpMethod::Get,
            url,
            &Verified::new_unchecked(String::new()),
        );
    }

    /// Records an HTTP POST request with a body.
    ///
    /// # Arguments
    ///
    /// * `url` - The verified target URL
    /// * `body` - The verified request body
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use policy_core::{PolicyHttp, Verified};
    /// # let http = PolicyHttp::new();
    /// # let url = Verified::new_unchecked("https://api.example.com".to_string());
    /// # let body = Verified::new_unchecked(r#"{"key": "value"}"#.to_string());
    /// http.post(&url, &body);
    /// ```
    pub fn post(&self, url: &Verified<String>, body: &Verified<String>) {
        self.record_request(HttpMethod::Post, url, body);
    }

    /// Records an HTTP PUT request with a body.
    ///
    /// # Arguments
    ///
    /// * `url` - The verified target URL
    /// * `body` - The verified request body
    pub fn put(&self, url: &Verified<String>, body: &Verified<String>) {
        self.record_request(HttpMethod::Put, url, body);
    }

    /// Records an HTTP DELETE request.
    ///
    /// # Arguments
    ///
    /// * `url` - The verified target URL
    pub fn delete(&self, url: &Verified<String>) {
        self.record_request(
            HttpMethod::Delete,
            url,
            &Verified::new_unchecked(String::new()),
        );
    }

    /// Records an HTTP PATCH request with a body.
    ///
    /// # Arguments
    ///
    /// * `url` - The verified target URL
    /// * `body` - The verified request body
    pub fn patch(&self, url: &Verified<String>, body: &Verified<String>) {
        self.record_request(HttpMethod::Patch, url, body);
    }

    /// Internal method to record a request.
    fn record_request(&self, method: HttpMethod, url: &Verified<String>, body: &Verified<String>) {
        let request = HttpRequest {
            method,
            url: url.as_ref().clone(),
            body_len: body.as_ref().len(),
        };
        self.requests.borrow_mut().push(request);
    }

    /// Returns the number of recorded requests.
    ///
    /// This is useful for testing and verification.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use policy_core::{PolicyHttp, Verified};
    /// # let http = PolicyHttp::new();
    /// assert_eq!(http.request_count(), 0);
    ///
    /// # let url = Verified::new_unchecked("https://example.com".to_string());
    /// http.get(&url);
    /// assert_eq!(http.request_count(), 1);
    /// ```
    pub fn request_count(&self) -> usize {
        self.requests.borrow().len()
    }

    /// Returns a snapshot of all recorded requests.
    ///
    /// This is useful for testing and verification.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use policy_core::{PolicyHttp, Verified, HttpMethod};
    /// # let http = PolicyHttp::new();
    /// # let url = Verified::new_unchecked("https://example.com".to_string());
    /// # let body = Verified::new_unchecked("data".to_string());
    /// http.post(&url, &body);
    ///
    /// let requests = http.requests();
    /// assert_eq!(requests.len(), 1);
    /// assert_eq!(requests[0].method, HttpMethod::Post);
    /// assert_eq!(requests[0].url, "https://example.com");
    /// assert_eq!(requests[0].body_len, 4);
    /// ```
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.requests.borrow().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Sanitizer, StringSanitizer, Tainted};

    #[test]
    fn http_method_display() {
        assert_eq!(format!("{}", HttpMethod::Get), "GET");
        assert_eq!(format!("{}", HttpMethod::Post), "POST");
        assert_eq!(format!("{}", HttpMethod::Put), "PUT");
        assert_eq!(format!("{}", HttpMethod::Delete), "DELETE");
        assert_eq!(format!("{}", HttpMethod::Patch), "PATCH");
    }

    #[test]
    fn policy_http_records_get_request() {
        let http = PolicyHttp::new();
        let url = Verified::new_unchecked("https://api.example.com/users".to_string());

        http.get(&url);

        assert_eq!(http.request_count(), 1);
        let requests = http.requests();
        assert_eq!(requests[0].method, HttpMethod::Get);
        assert_eq!(requests[0].url, "https://api.example.com/users");
        assert_eq!(requests[0].body_len, 0);
    }

    #[test]
    fn policy_http_records_post_request() {
        let http = PolicyHttp::new();
        let url = Verified::new_unchecked("https://api.example.com/users".to_string());
        let body = Verified::new_unchecked(r#"{"name": "Alice"}"#.to_string());

        http.post(&url, &body);

        assert_eq!(http.request_count(), 1);
        let requests = http.requests();
        assert_eq!(requests[0].method, HttpMethod::Post);
        assert_eq!(requests[0].url, "https://api.example.com/users");
        assert_eq!(requests[0].body_len, 17); // Length of JSON
    }

    #[test]
    fn policy_http_records_multiple_requests() {
        let http = PolicyHttp::new();
        let url1 = Verified::new_unchecked("https://example.com/1".to_string());
        let url2 = Verified::new_unchecked("https://example.com/2".to_string());
        let body = Verified::new_unchecked("data".to_string());

        http.get(&url1);
        http.post(&url2, &body);
        http.delete(&url1);

        assert_eq!(http.request_count(), 3);
        let requests = http.requests();
        assert_eq!(requests[0].method, HttpMethod::Get);
        assert_eq!(requests[1].method, HttpMethod::Post);
        assert_eq!(requests[2].method, HttpMethod::Delete);
    }

    #[test]
    fn policy_http_enforces_verified_urls() {
        let http = PolicyHttp::new();

        // This works - verified URL:
        let verified_url = Verified::new_unchecked("https://example.com".to_string());
        http.get(&verified_url);

        // These would NOT compile if uncommented (good!):
        // let raw_url = "https://example.com".to_string();
        // http.get(&raw_url); // Type mismatch!

        // let tainted_url = Tainted::new("https://example.com".to_string());
        // http.get(&tainted_url); // Type mismatch!
    }

    #[test]
    fn policy_http_with_sanitizer_integration() {
        let http = PolicyHttp::new();
        let sanitizer = StringSanitizer::new(256);

        // Sanitize tainted URL
        let tainted_url = Tainted::new("  https://api.example.com/data  ".to_string());
        let verified_url = sanitizer.sanitize(tainted_url).expect("valid URL");

        // Sanitize tainted body
        let tainted_body = Tainted::new(r#"{"key": "value"}"#.to_string());
        let verified_body = sanitizer.sanitize(tainted_body).expect("valid body");

        http.post(&verified_url, &verified_body);

        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://api.example.com/data"); // Trimmed
        assert_eq!(requests[0].body_len, 16);
    }

    #[test]
    fn policy_http_records_put_request() {
        let http = PolicyHttp::new();
        let url = Verified::new_unchecked("https://api.example.com/users/1".to_string());
        let body = Verified::new_unchecked(r#"{"name": "Bob"}"#.to_string());

        http.put(&url, &body);

        let requests = http.requests();
        assert_eq!(requests[0].method, HttpMethod::Put);
        assert_eq!(requests[0].url, "https://api.example.com/users/1");
    }

    #[test]
    fn policy_http_records_patch_request() {
        let http = PolicyHttp::new();
        let url = Verified::new_unchecked("https://api.example.com/users/1".to_string());
        let body = Verified::new_unchecked(r#"{"status": "active"}"#.to_string());

        http.patch(&url, &body);

        let requests = http.requests();
        assert_eq!(requests[0].method, HttpMethod::Patch);
    }

    #[test]
    fn policy_http_does_not_leak_body_in_metadata() {
        let http = PolicyHttp::new();
        let url = Verified::new_unchecked("https://api.example.com".to_string());
        let secret_body = Verified::new_unchecked("SECRET_PASSWORD_12345".to_string());

        http.post(&url, &secret_body);

        let requests = http.requests();
        // Metadata should only contain length, not the actual body
        assert_eq!(requests[0].body_len, 21);

        // The debug output of HttpRequest should not contain the body content
        let debug_output = format!("{:?}", requests[0]);
        assert!(!debug_output.contains("SECRET_PASSWORD"));
    }
}
