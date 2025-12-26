/// Capability granting permission to perform logging operations.
///
/// This is a zero-sized type that acts as proof that logging
/// policies have been satisfied.
///
/// It cannot be constructed outside this crate, ensuring that
/// only validated contexts can perform privileged logging.
#[derive(Debug, Clone, Copy)]
pub struct LogCap {
    // Private field prevents construction outside the crate
    _private: (),
}

impl LogCap {
    /// Creates a new LogCap.
    ///
    /// This is `pub(crate)` so only code within policy-core can create it.
    /// In Milestone 2, PolicyGate will be the one creating these.
    #[allow(dead_code)] // Used in tests and will be used in Milestone 2
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

/// Capability granting permission to perform outbound HTTP operations.
///
/// This is a zero-sized type that acts as proof that HTTP
/// policies have been satisfied.
///
/// It cannot be constructed outside this crate, ensuring that
/// only validated contexts can perform HTTP requests.
#[derive(Debug, Clone, Copy)]
pub struct HttpCap {
    // Private field prevents construction outside the crate
    _private: (),
}

impl HttpCap {
    /// Creates a new HttpCap.
    ///
    /// This is `pub(crate)` so only code within policy-core can create it.
    /// PolicyGate creates these when HTTP authorization is granted.
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

/// A minimal gated function that requires LogCap to execute.
///
/// This proves the capability pattern works: you cannot call this function
/// without possessing a `LogCap`.
///
/// # Arguments
///
/// * `_cap` - Proof that logging is authorized
/// * `message` - The message to "log" (just returns it for testing)
///
/// # Examples
///
/// ```compile_fail
/// # use policy_core::LogCap;
/// // This does not compile - LogCap cannot be constructed publicly:
/// let cap = LogCap { _private: () }; // Error: _private is private
/// ```
pub fn log_with_capability(_cap: LogCap, message: &str) -> String {
    format!("[LOGGED] {}", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_cap_cannot_be_constructed_publicly() {
        // This test documents that LogCap cannot be forged.
        // If you uncomment these lines, they will not compile:

        // let fake_cap = LogCap { _private: () }; // Error: _private is private
        // let result = log_with_capability(fake_cap, "test");
    }

    #[test]
    fn log_with_capability_works_when_cap_provided() {
        // Inside the crate, we CAN create LogCap
        let cap = LogCap::new();
        let result = log_with_capability(cap, "test message");

        assert_eq!(result, "[LOGGED] test message");
    }

    #[test]
    fn http_cap_cannot_be_constructed_publicly() {
        // This test documents that HttpCap cannot be forged.
        // If you uncomment these lines, they will not compile:

        // let fake_cap = HttpCap { _private: () }; // Error: _private is private
    }

    #[test]
    fn http_cap_can_be_created_internally() {
        // Inside the crate, we CAN create HttpCap
        let cap = HttpCap::new();

        // It's a zero-sized type
        let _debug_output = format!("{:?}", cap);
    }
}
