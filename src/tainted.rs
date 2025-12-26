use std::fmt;

/// A wrapper for untrusted data that must be explicitly sanitized before use.
///
/// `Tainted<T>` marks data from untrusted sources (user input, external APIs, etc.)
/// and prevents accidental use in security-sensitive contexts. The value cannot be
/// accessed without explicit validation or sanitization (added in Milestone 4).
///
/// # Security Properties
///
/// - Does NOT implement `Deref` or any implicit conversion traits
/// - Inner value is completely inaccessible without sanitization
/// - Prevents tainted data from flowing into sinks
///
/// # Examples
///
/// ```
/// use policy_core::Tainted;
///
/// let user_input = Tainted::new("'; DROP TABLE users; --".to_string());
///
/// // Debug output shows it's tainted (for development)
/// println!("{:?}", user_input); // Tainted { inner: "'; DROP..." }
///
/// // But you CANNOT use the value directly:
/// // let query = format!("SELECT * FROM users WHERE name = '{}'", user_input); // Won't compile!
/// ```
// BREAKING CHANGE WARNING: Do NOT remove Clone - tainted values need to be duplicated for validation flow.
#[derive(Clone)]
pub struct Tainted<T> {
    // BREAKING CHANGE WARNING: This field MUST remain private.
    // Making it public bypasses taint tracking entirely (CWE-20: Improper Input Validation).
    // External code must go through Sanitizer trait to access the value.
    inner: T,
}

impl<T> Tainted<T> {
    /// Wraps an untrusted value in `Tainted`.
    ///
    /// Use this for any data from external sources that has not been validated.
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Extracts the inner value for sanitization.
    ///
    /// # Safety (Policy-Level)
    ///
    /// This method is `pub(crate)` to restrict access to code within this crate.
    /// It should ONLY be called by sanitizer implementations that will validate
    /// the value before wrapping it in `Verified<T>`.
    ///
    /// External code cannot call this method and must go through the `Sanitizer` trait.
    ///
    /// BREAKING CHANGE WARNING: Changing visibility to `pub` creates a CRITICAL SECURITY BYPASS.
    /// External code could extract raw values without validation, defeating the entire
    /// taint tracking system and enabling injection attacks (CWE-74, CWE-89, CWE-117).
    pub(crate) fn into_inner(self) -> T {
        self.inner
    }
}

// BREAKING CHANGE WARNING: Do NOT add Deref, AsRef, Borrow, From<T>, Into<T>, or any other
// implicit conversion traits to Tainted<T>. These would bypass the sanitization requirement
// and allow tainted data to flow into sinks, defeating the security model entirely.

impl<T: fmt::Debug> fmt::Debug for Tainted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tainted")
            .field("inner", &self.inner)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tainted_wraps_value() {
        let user_input = Tainted::new("malicious input".to_string());
        let debug_output = format!("{:?}", user_input);

        // Debug shows it's tainted
        assert!(debug_output.contains("Tainted"));
        assert!(debug_output.contains("malicious input"));
    }

    #[test]
    fn tainted_prevents_direct_access() {
        let tainted = Tainted::new(42);

        // These would not compile if uncommented (good!):
        // let value = tainted.inner; // ← private field
        // let value = *tainted; // ← no Deref
        // let value: &i32 = tainted.as_ref(); // ← no AsRef

        // We can create it, but can't use it (yet)
        let _ = tainted;
    }

    #[test]
    fn tainted_cannot_be_used_as_t() {
        let tainted_str = Tainted::new("unsafe".to_string());

        // This function requires a String, not a Tainted<String>
        #[allow(dead_code)]
        fn takes_string(_s: String) {}

        // This would not compile if uncommented:
        // takes_string(tainted_str); // Type mismatch!

        let _ = tainted_str;
    }

    mod proptests {
        use super::*;
        use crate::{sanitizer::StringSanitizer, test_utils::arb_valid_string, Sanitizer};
        use proptest::prelude::*;

        proptest! {
            /// Property: Cloning a Tainted value results in identical sanitization outcomes
            #[test]
            fn proptest_tainted_clone_preserves_value(input in arb_valid_string(256)) {
                let sanitizer = StringSanitizer::new(256);

                // Create tainted value and clone it
                let tainted1 = Tainted::new(input.clone());
                let tainted2 = tainted1.clone();

                // Sanitize both
                let verified1 = sanitizer.sanitize(tainted1).expect("valid input should pass");
                let verified2 = sanitizer.sanitize(tainted2).expect("valid input should pass");

                // Both should produce identical verified values
                prop_assert_eq!(verified1.as_ref(), verified2.as_ref());
                prop_assert_eq!(verified1.as_ref(), &input);
            }
        }
    }
}
