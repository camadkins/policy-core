/// A wrapper for data that has been validated/sanitized and is safe to use.
///
/// `Verified<T>` represents a value that has undergone validation or sanitization
/// and can be safely passed to security-sensitive operations (sinks). Unlike raw values
/// or [`Tainted<T>`](crate::Tainted), `Verified<T>` provides compile-time proof that
/// the value has been processed through a controlled validation path.
///
/// # Construction Invariants
///
/// **IMPORTANT:** `Verified<T>` cannot be constructed directly by external code.
/// There are no public constructors, and no `From<T>` or `Into<Verified<T>>` implementations
/// that would allow arbitrary values to be wrapped.
///
/// Construction is restricted to crate-internal code through `new_unchecked`,
/// which is intentionally `pub(crate)`. Higher-level abstractions (e.g., `Sanitizer` in Milestone 4)
/// are responsible for enforcing validation rules before calling this constructor.
///
/// # Access
///
/// Unlike [`Secret<T>`](crate::Secret) which requires explicit "scary" access,
/// `Verified<T>` provides safe, ergonomic access to the underlying value:
///
/// - [`AsRef::as_ref`]: Borrow the verified value (via standard `AsRef<T>` trait)
/// - [`into_inner`](Self::into_inner): Consume and extract the value
///
/// # Security Properties
///
/// - No public construction (enforces validation bottleneck)
/// - Does NOT implement `Deref` (explicit access only)
/// - Does NOT implement `Default` (no arbitrary "empty" verified values)
/// - Safe to use in security-sensitive contexts
///
/// # Examples
///
/// External callers cannot create `Verified<T>` directly:
///
/// ```compile_fail
/// use policy_core::Verified;
///
/// // This will not compile - no public constructor:
/// let verified = Verified::new("data".to_string());
/// ```
///
/// Access to verified values is explicit and ergonomic:
///
/// ```ignore
/// // (This example requires crate-internal construction, shown for illustration only)
/// use policy_core::Verified;
///
/// # fn get_verified_value() -> Verified<String> {
/// #     // Only crate-internal code can do this:
/// #     Verified::new_unchecked("safe-data".to_string())
/// # }
/// let verified = get_verified_value();
///
/// // Borrow the value
/// let value_ref: &String = verified.as_ref();
/// assert_eq!(value_ref, "safe-data");
///
/// // Or consume it
/// let value: String = verified.into_inner();
/// assert_eq!(value, "safe-data");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified<T> {
    inner: T,
}

impl<T> Verified<T> {
    /// Creates a `Verified<T>` without performing validation.
    ///
    /// # Safety (Policy-Level)
    ///
    /// This function is `pub(crate)` to restrict construction to code within this crate.
    /// It does NOT perform any validation itself - callers are responsible for ensuring
    /// that the value has been properly validated before wrapping it.
    ///
    /// Higher-level abstractions (e.g., `Sanitizer`) must enforce validation rules
    /// before calling this constructor. This is a policy-level safety requirement,
    /// not a memory-safety concern.
    ///
    /// # Usage
    ///
    /// This should only be called by trusted validation/sanitization code paths
    /// within the crate that have verified the input according to appropriate rules.
    #[allow(dead_code)] // Used by future sanitization code and tests
    pub(crate) fn new_unchecked(value: T) -> Self {
        Self { inner: value }
    }

    /// Consumes the `Verified<T>` and returns the inner value.
    ///
    /// Since the value has been verified, it's safe to extract and use directly.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use policy_core::Verified;
    /// # let verified = Verified::new_unchecked("data".to_string());
    /// let value = verified.into_inner();
    /// assert_eq!(value, "data");
    /// ```
    pub fn into_inner(self) -> T {
        self.inner
    }
}

/// Provides access to the verified value via the standard `AsRef` trait.
///
/// This allows `Verified<T>` to integrate seamlessly with Rust's standard library
/// and other code that expects `AsRef<T>`.
impl<T> AsRef<T> for Verified<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_as_ref_returns_reference() {
        let verified = Verified::new_unchecked("test-data".to_string());
        let value_ref = verified.as_ref();

        assert_eq!(value_ref, "test-data");
        assert_eq!(value_ref.len(), 9);
    }

    #[test]
    fn verified_into_inner_returns_value() {
        let verified = Verified::new_unchecked(42);
        let value = verified.into_inner();

        assert_eq!(value, 42);
    }

    #[test]
    fn verified_as_ref_does_not_consume() {
        let verified = Verified::new_unchecked(vec![1, 2, 3]);

        // Can call as_ref multiple times
        let ref1 = verified.as_ref();
        let ref2 = verified.as_ref();

        assert_eq!(ref1, ref2);
        assert_eq!(ref1, &vec![1, 2, 3]);

        // Can still consume after borrowing
        let value = verified.into_inner();
        assert_eq!(value, vec![1, 2, 3]);
    }

    #[test]
    fn verified_derives_work() {
        let v1 = Verified::new_unchecked("data".to_string());
        let v2 = v1.clone();

        // Clone works
        assert_eq!(v1, v2);

        // Debug works
        let debug_output = format!("{:?}", v1);
        assert!(debug_output.contains("Verified"));
        assert!(debug_output.contains("data"));
    }

    #[test]
    fn verified_prevents_direct_construction() {
        // This test documents that construction is restricted.
        // If the following were uncommented, they would not compile:

        // let v = Verified { inner: 42 }; // ← private field
        // let v = Verified::new(42); // ← no such method
        // let v: Verified<i32> = 42.into(); // ← no From impl

        // Only internal code can construct:
        let _ = Verified::new_unchecked(42);
    }

    #[test]
    fn verified_no_deref() {
        let verified = Verified::new_unchecked(String::from("test"));

        // This would not compile if uncommented (good!):
        // let s: &str = &*verified; // ← no Deref

        // Must use explicit access:
        let s: &String = verified.as_ref();
        assert_eq!(s, "test");
    }

    mod proptests {
        use super::*;
        use crate::{sanitizer::StringSanitizer, test_utils::arb_valid_string, Sanitizer, Tainted};
        use proptest::prelude::*;

        proptest! {
            /// Property: Valid input survives the Tainted → Sanitizer → Verified flow
            #[test]
            fn proptest_tainted_to_verified_preserves_valid_data(input in arb_valid_string(256)) {
                let sanitizer = StringSanitizer::new(256);
                let tainted = Tainted::new(input.clone());

                // Sanitize the tainted input
                let verified = sanitizer.sanitize(tainted).expect("valid input should pass");

                // The verified value should equal the original (after trimming)
                prop_assert_eq!(verified.as_ref(), &input);
            }

            /// Property: as_ref() returns the same value as into_inner()
            #[test]
            fn proptest_verified_as_ref_equals_inner(value in prop::string::string_regex("[a-zA-Z0-9 _-]{1,50}").unwrap()) {
                let verified = Verified::new_unchecked(value.clone());

                // Get reference via as_ref()
                let ref_value = verified.as_ref();

                // Clone to test again since into_inner consumes
                let verified2 = Verified::new_unchecked(value.clone());
                let inner_value = verified2.into_inner();

                // Both should be equal
                prop_assert_eq!(ref_value, &inner_value);
                prop_assert_eq!(ref_value, &value);
            }
        }
    }
}
