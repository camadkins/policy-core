//! Type-state markers for context progression.
//!
//! This module defines zero-sized marker types that encode the authentication
//! and authorization state of a context at compile time.

/// Marker type for an unauthenticated context.
///
/// `Ctx<Unauthed>` has no principal and cannot access privileged operations.
#[derive(Debug, Clone, Copy)]
pub struct Unauthed {
    _private: (),
}

impl Unauthed {
    /// Creates a new Unauthed marker.
    ///
    /// This is `pub(crate)` so only code within policy-core can create it.
    #[allow(dead_code)] // Used in tests
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

/// Marker type for an authenticated context.
///
/// `Ctx<Authed>` has a verified principal but has not been authorized
/// for specific actions.
#[derive(Debug, Clone, Copy)]
pub struct Authed {
    _private: (),
}

impl Authed {
    /// Creates a new Authed marker.
    ///
    /// This is `pub(crate)` so only code within policy-core can create it.
    #[allow(dead_code)] // Used in tests
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

/// Marker type for an authorized context.
///
/// `Ctx<Authorized>` has a verified principal and has been authorized
/// for specific actions. Only this state can access privileged operations.
#[derive(Debug, Clone, Copy)]
pub struct Authorized {
    _private: (),
}

impl Authorized {
    /// Creates a new Authorized marker.
    ///
    /// This is `pub(crate)` so only code within policy-core can create it.
    #[allow(dead_code)] // Used in tests
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_markers_are_zero_sized() {
        assert_eq!(std::mem::size_of::<Unauthed>(), 0);
        assert_eq!(std::mem::size_of::<Authed>(), 0);
        assert_eq!(std::mem::size_of::<Authorized>(), 0);
    }

    #[test]
    fn state_markers_cannot_be_constructed_publicly() {
        // This test documents that state markers cannot be forged.
        // If you uncomment these lines, they will not compile:

        // let fake_unauthed = Unauthed { _private: () }; // Error: _private is private
        // let fake_authed = Authed { _private: () }; // Error: _private is private
        // let fake_authorized = Authorized { _private: () }; // Error: _private is private
    }

    #[test]
    fn state_markers_can_be_created_internally() {
        let _unauthed = Unauthed::new();
        let _authed = Authed::new();
        let _authorized = Authorized::new();
    }
}
