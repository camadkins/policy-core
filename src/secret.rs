use std::fmt;

/// A wrapper that prevents accidental exposure of sensitive values.
///
/// `Secret<T>` ensures that sensitive data (passwords, API keys, tokens, etc.)
/// cannot be accidentally logged, printed, or displayed. The wrapped value
/// can only be accessed through the explicit [`expose_secret`](Self::expose_secret) method.
///
/// # Security Properties
///
/// - Does NOT implement `Deref`, `AsRef`, `Borrow`, `Clone`, or `Copy`
/// - Debug and Display output is always `[REDACTED]`
/// - No type information is leaked in formatted output
/// - Access requires explicit, intentionally "scary" method call
///
/// # Examples
///
/// ```
/// use policy_core::Secret;
///
/// let api_key = Secret::new("sk-1234567890".to_string());
///
/// // Safe: secrets are automatically redacted
/// println!("{:?}", api_key); // Prints: [REDACTED]
/// println!("{}", api_key);   // Prints: [REDACTED]
///
/// // Explicit access when needed
/// let key_value = api_key.expose_secret();
/// assert_eq!(key_value, "sk-1234567890");
/// ```
// BREAKING CHANGE WARNING: Do NOT add Clone, Copy, or Default derives.
// These would bypass redaction protections and allow secrets to be duplicated carelessly.
pub struct Secret<T> {
    // BREAKING CHANGE WARNING: This field MUST remain private.
    // Making it public exposes secrets directly, defeating automatic redaction (CWE-532).
    inner: T,
}

impl<T> Secret<T> {
    /// Wraps a sensitive value in a `Secret`.
    ///
    /// The value will be protected from accidental exposure through
    /// Debug, Display, or any implicit conversions.
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Explicitly exposes the secret value.
    ///
    /// # Security Warning
    ///
    /// This method intentionally has a verbose name to make it clear
    /// that secret material is being accessed. Use with caution and
    /// ensure the exposed value is not logged or displayed.
    pub fn expose_secret(&self) -> &T {
        &self.inner
    }
}

// BREAKING CHANGE WARNING: Do NOT implement Deref, AsRef, Borrow, Display (that shows the value),
// Debug (that shows the value), or any other trait that would expose the secret implicitly.
// The ONLY access should be through expose_secret(), which has an intentionally scary name.

impl<T> fmt::Debug for Secret<T> {
    /// BREAKING CHANGE WARNING: This MUST unconditionally return "[REDACTED]".
    /// Changing this to show the actual value (even in debug builds) defeats the
    /// entire purpose of Secret<T> and enables accidental secret exposure in logs (CWE-532).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> fmt::Display for Secret<T> {
    /// BREAKING CHANGE WARNING: This MUST unconditionally return "[REDACTED]".
    /// Changing this to show the actual value exposes secrets in user-facing output,
    /// error messages, and logs (CWE-532: Insertion of Sensitive Information into Log File).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_redacts_debug() {
        let password = Secret::new("hunter2".to_string());
        let debug_output = format!("{:?}", password);

        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("hunter2"));
        assert!(!debug_output.contains("String")); // No type leak
    }

    #[test]
    fn secret_redacts_display() {
        let api_key = Secret::new("sk-1234567890");
        let display_output = format!("{}", api_key);

        assert_eq!(display_output, "[REDACTED]");
        assert!(!display_output.contains("sk-"));
    }

    #[test]
    fn secret_exposes_when_explicit() {
        let secret = Secret::new(42);
        assert_eq!(*secret.expose_secret(), 42);
    }

    #[test]
    fn secret_no_implicit_access() {
        let secret = Secret::new(vec![1, 2, 3]);

        // This would not compile if uncommented (good!):
        // let _ = *secret; // No Deref
        // let _ = secret.clone(); // No Clone
        // let vec_ref: &Vec<i32> = secret.as_ref(); // No AsRef

        // Only explicit access works:
        let vec_ref = secret.expose_secret();
        assert_eq!(vec_ref, &vec![1, 2, 3]);
    }
}
