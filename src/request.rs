/// Metadata about an incoming request or operation.
///
/// Contains the request identifier and optional principal (authenticated user/service).
#[derive(Debug)]
pub struct RequestMeta {
    /// Unique identifier for this request
    pub request_id: String,
    /// Authenticated principal, if any
    pub principal: Option<Principal>,
}

/// An authenticated user or service principal.
#[derive(Debug)]
pub struct Principal {
    /// Unique identifier for this principal
    pub id: String,
    /// Display name
    pub name: String,
}
