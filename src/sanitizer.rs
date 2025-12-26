use std::fmt;

use crate::{Tainted, Verified};

/// Error returned when sanitization fails.
///
/// This error indicates that a tainted value failed validation and could not
/// be promoted to a `Verified<T>`. The error does not leak sensitive information
/// about the rejected input.
///
/// # Examples
///
/// ```
/// use policy_core::{SanitizationError, SanitizationErrorKind};
///
/// let error = SanitizationError::new(SanitizationErrorKind::InvalidInput, "value too long");
/// assert_eq!(error.kind(), SanitizationErrorKind::InvalidInput);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizationError {
    kind: SanitizationErrorKind,
    message: String,
}

impl SanitizationError {
    /// Creates a new sanitization error.
    pub fn new(kind: SanitizationErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns the error kind.
    pub fn kind(&self) -> SanitizationErrorKind {
        self.kind
    }

    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SanitizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sanitization failed ({}): {}", self.kind, self.message)
    }
}

impl std::error::Error for SanitizationError {}

/// Kind of sanitization error.
///
/// Categorizes why sanitization failed without leaking sensitive details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizationErrorKind {
    /// Input failed validation rules.
    InvalidInput,
    /// Input contains forbidden patterns.
    ForbiddenPattern,
    /// Input format is malformed.
    MalformedInput,
    /// Input is empty or contains only whitespace.
    Empty,
    /// Input exceeds maximum allowed length.
    TooLong,
    /// Input contains control or non-printable characters.
    ContainsControlChars,
}

impl fmt::Display for SanitizationErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => write!(f, "invalid input"),
            Self::ForbiddenPattern => write!(f, "forbidden pattern"),
            Self::MalformedInput => write!(f, "malformed input"),
            Self::Empty => write!(f, "empty input"),
            Self::TooLong => write!(f, "input too long"),
            Self::ContainsControlChars => write!(f, "contains control characters"),
        }
    }
}

/// Trait for sanitizing tainted values into verified values.
///
/// `Sanitizer<T>` defines the interface for converting untrusted, tainted data
/// into verified data that is safe to use in security-sensitive contexts.
///
/// # Invariants
///
/// Implementations MUST:
/// - Validate/sanitize the input according to their policy rules
/// - Only call `Verified::new_unchecked` after validation succeeds
/// - Return `Err(SanitizationError)` if validation fails
/// - Not leak sensitive information in errors
///
/// # Security Considerations
///
/// Sanitizers are critical security boundaries that defend against **injection attacks**,
/// where untrusted input is embedded in structured data formats (logs, commands, SQL, markup).
///
/// ## Common Injection Threats
///
/// | Attack Type | Vector | Impact | Defense |
/// |-------------|--------|--------|---------|
/// | **Log Injection** (CWE-117) | Newlines (`\n`, `\r`) | Forge audit entries, hide malicious activity | Reject control characters |
/// | **Command Injection** (CWE-78) | Shell metacharacters (`;`, `|`, `` ` ``) | Execute arbitrary OS commands | Context-specific sanitization |
/// | **SQL Injection** (CWE-89) | Quotes (`'`, `"`), semicolons | Manipulate database queries, exfiltrate data | Parameterized queries + input validation |
/// | **Path Traversal** (CWE-22) | `../` sequences | Escape restricted directories, read arbitrary files | Path canonicalization |
/// | **XSS** (CWE-79) | HTML tags (`<script>`) | Execute malicious JavaScript in user browsers | HTML escaping + CSP |
///
/// ## Why Control Characters Are Dangerous
///
/// Control characters (ASCII 0x00-0x1F, DEL 0x7F, Unicode C0/C1) can:
/// - **Forge structure**: Newlines create fake log entries or HTTP headers
/// - **Hide content**: Null bytes (`\0`) truncate strings in C-based parsers
/// - **Manipulate terminals**: ANSI escapes (`\x1b[...`) clear screens, change colors
/// - **Bypass validation**: Invisible characters appear as empty but pass length checks
///
/// ## Sanitizer Design Guidelines
///
/// When implementing custom sanitizers:
/// 1. **Reject, don't modify**: Prefer rejecting invalid input over attempting to "fix" it
/// 2. **Fail closed**: Default to rejection when validation is uncertain
/// 3. **Context-aware**: Different sinks need different validation (logs vs. SQL vs. shell)
/// 4. **No information leakage**: Don't include rejected input in error messages
/// 5. **Document threats**: Explain which attacks your sanitizer prevents
///
/// See individual sanitizer implementations (`StringSanitizer`, etc.) for specific
/// validation rules and security properties.
///
/// # Examples
///
/// ```
/// use policy_core::{Tainted, Verified, Sanitizer, SanitizationError};
///
/// // Sanitizers will be used like this:
/// # struct MySanitizer;
/// # impl Sanitizer<String> for MySanitizer {
/// #     fn sanitize(&self, input: Tainted<String>) -> Result<Verified<String>, SanitizationError> {
/// #         unimplemented!()
/// #     }
/// # }
/// let sanitizer = MySanitizer;
/// let tainted_input = Tainted::new("some untrusted data".to_string());
///
/// // Sanitizer performs validation and returns Verified on success
/// // let verified = sanitizer.sanitize(tainted_input)?;
/// ```
pub trait Sanitizer<T> {
    /// Sanitizes a tainted value, returning a verified value on success.
    ///
    /// # Errors
    ///
    /// Returns `SanitizationError` if the input fails validation.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use policy_core::{Tainted, Sanitizer};
    /// # let sanitizer = todo!();
    /// let tainted = Tainted::new("input".to_string());
    /// let verified = sanitizer.sanitize(tainted)?;
    /// ```
    fn sanitize(&self, input: Tainted<T>) -> Result<Verified<T>, SanitizationError>;
}

/// A trivial sanitizer that accepts all input (for testing only).
///
/// **WARNING:** This sanitizer performs NO validation and should only be used
/// in tests or as a placeholder. It unconditionally promotes tainted values
/// to verified values.
///
/// # Examples
///
/// ```
/// use policy_core::{Tainted, Sanitizer, AcceptAllSanitizer};
///
/// let sanitizer = AcceptAllSanitizer;
/// let tainted = Tainted::new("any value".to_string());
/// let verified = sanitizer.sanitize(tainted).expect("always succeeds");
///
/// assert_eq!(verified.as_ref(), "any value");
/// ```
#[derive(Debug, Clone, Copy)]
pub struct AcceptAllSanitizer;

impl<T> Sanitizer<T> for AcceptAllSanitizer {
    fn sanitize(&self, input: Tainted<T>) -> Result<Verified<T>, SanitizationError> {
        // Extract the inner value from the tainted wrapper
        let value = input.into_inner();
        // Unconditionally wrap it as verified (no validation!)
        Ok(Verified::new_unchecked(value))
    }
}

/// A trivial sanitizer that rejects all input (for testing only).
///
/// This sanitizer always fails validation, useful for testing error paths.
///
/// # Examples
///
/// ```
/// use policy_core::{Tainted, Sanitizer, RejectAllSanitizer, SanitizationErrorKind};
///
/// let sanitizer = RejectAllSanitizer;
/// let tainted = Tainted::new("any value".to_string());
/// let result = sanitizer.sanitize(tainted);
///
/// assert!(result.is_err());
/// assert_eq!(result.unwrap_err().kind(), SanitizationErrorKind::InvalidInput);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RejectAllSanitizer;

impl<T> Sanitizer<T> for RejectAllSanitizer {
    fn sanitize(&self, _input: Tainted<T>) -> Result<Verified<T>, SanitizationError> {
        Err(SanitizationError::new(
            SanitizationErrorKind::InvalidInput,
            "rejected by policy",
        ))
    }
}

/// A string sanitizer that enforces basic safety and length constraints.
///
/// This sanitizer validates and normalizes untrusted string input by:
/// - Trimming leading and trailing whitespace
/// - Rejecting empty strings (after trimming)
/// - Rejecting strings containing control or non-printable characters
/// - Enforcing a maximum length constraint (default: 256 characters)
///
/// # Security Properties
///
/// - Prevents injection of control characters (newlines, null bytes, etc.)
/// - Ensures non-empty meaningful input
/// - Prevents excessive memory consumption via length limits
/// - Does not leak rejected input in error messages
///
/// # Examples
///
/// ```
/// use policy_core::{Tainted, Sanitizer, StringSanitizer};
///
/// // Valid input with whitespace is trimmed
/// let sanitizer = StringSanitizer::new(256);
/// let tainted = Tainted::new("  hello world  ".to_string());
/// let verified = sanitizer.sanitize(tainted).expect("should succeed");
/// assert_eq!(verified.as_ref(), "hello world");
///
/// // Empty input (after trimming) is rejected
/// let tainted = Tainted::new("   ".to_string());
/// assert!(sanitizer.sanitize(tainted).is_err());
///
/// // Control characters are rejected
/// let tainted = Tainted::new("hello\nworld".to_string());
/// assert!(sanitizer.sanitize(tainted).is_err());
/// ```
#[derive(Debug, Clone, Copy)]
pub struct StringSanitizer {
    max_len: usize,
}

impl StringSanitizer {
    /// Creates a new string sanitizer with the specified maximum length.
    ///
    /// # Arguments
    ///
    /// * `max_len` - Maximum allowed length for the sanitized string (must be > 0)
    ///
    /// # Panics
    ///
    /// Panics if `max_len` is 0.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::StringSanitizer;
    ///
    /// let sanitizer = StringSanitizer::new(100);
    /// ```
    pub fn new(max_len: usize) -> Self {
        assert!(max_len > 0, "max_len must be greater than 0");
        Self { max_len }
    }

    /// Creates a string sanitizer with the default maximum length of 256 characters.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::StringSanitizer;
    ///
    /// let sanitizer = StringSanitizer::default_limits();
    /// ```
    pub fn default_limits() -> Self {
        Self::new(256)
    }

    /// Checks if a character is a control or non-printable character.
    ///
    /// Returns `true` for:
    /// - ASCII control characters (0x00-0x1F)
    /// - Delete character (0x7F)
    /// - Other non-printable Unicode characters
    fn is_control_char(c: char) -> bool {
        c.is_control() || c == '\u{007F}'
    }
}

impl Sanitizer<String> for StringSanitizer {
    fn sanitize(&self, input: Tainted<String>) -> Result<Verified<String>, SanitizationError> {
        // Extract the raw string from the tainted wrapper
        let raw = input.into_inner();

        // Trim leading and trailing whitespace
        let trimmed = raw.trim();

        // Reject empty strings (after trimming)
        if trimmed.is_empty() {
            return Err(SanitizationError::new(
                SanitizationErrorKind::Empty,
                "input is empty or contains only whitespace",
            ));
        }

        // Check for control or non-printable characters
        if trimmed.chars().any(Self::is_control_char) {
            return Err(SanitizationError::new(
                SanitizationErrorKind::ContainsControlChars,
                "input contains control or non-printable characters",
            ));
        }

        // Check length constraint
        if trimmed.len() > self.max_len {
            return Err(SanitizationError::new(
                SanitizationErrorKind::TooLong,
                format!("input exceeds maximum length of {}", self.max_len),
            ));
        }

        // All validation passed - create verified value
        Ok(Verified::new_unchecked(trimmed.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitization_error_creation() {
        let error = SanitizationError::new(SanitizationErrorKind::InvalidInput, "test message");

        assert_eq!(error.kind(), SanitizationErrorKind::InvalidInput);
        assert_eq!(error.message(), "test message");
    }

    #[test]
    fn sanitization_error_display() {
        let error = SanitizationError::new(SanitizationErrorKind::ForbiddenPattern, "contains SQL");

        let output = format!("{}", error);
        assert!(output.contains("sanitization failed"));
        assert!(output.contains("forbidden pattern"));
        assert!(output.contains("contains SQL"));
    }

    #[test]
    fn accept_all_sanitizer_succeeds() {
        let sanitizer = AcceptAllSanitizer;
        let tainted = Tainted::new("test input".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.as_ref(), "test input");
    }

    #[test]
    fn accept_all_sanitizer_preserves_value() {
        let sanitizer = AcceptAllSanitizer;
        let tainted = Tainted::new(vec![1, 2, 3, 4, 5]);

        let verified = sanitizer.sanitize(tainted).expect("should succeed");

        assert_eq!(verified.as_ref(), &vec![1, 2, 3, 4, 5]);
        assert_eq!(verified.into_inner(), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn reject_all_sanitizer_fails() {
        let sanitizer = RejectAllSanitizer;
        let tainted = Tainted::new("test input".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), SanitizationErrorKind::InvalidInput);
        assert_eq!(error.message(), "rejected by policy");
    }

    #[test]
    fn sanitizer_enforces_tainted_input() {
        // This test documents that sanitize() requires Tainted<T> input
        let sanitizer = AcceptAllSanitizer;
        let tainted = Tainted::new(42);

        // This works:
        let _verified = sanitizer.sanitize(tainted);

        // This would NOT compile if uncommented (good!):
        // let raw_value = 42;
        // let verified = sanitizer.sanitize(raw_value); // Type mismatch!
    }

    #[test]
    fn sanitizer_returns_verified_output() {
        let sanitizer = AcceptAllSanitizer;
        let tainted = Tainted::new("data".to_string());

        let verified = sanitizer.sanitize(tainted).expect("should succeed");

        // Verified can be accessed via AsRef
        let _: &String = verified.as_ref();

        // Or consumed
        let _: String = verified.into_inner();
    }

    #[test]
    fn error_kinds_display() {
        assert_eq!(
            format!("{}", SanitizationErrorKind::InvalidInput),
            "invalid input"
        );
        assert_eq!(
            format!("{}", SanitizationErrorKind::ForbiddenPattern),
            "forbidden pattern"
        );
        assert_eq!(
            format!("{}", SanitizationErrorKind::MalformedInput),
            "malformed input"
        );
        assert_eq!(format!("{}", SanitizationErrorKind::Empty), "empty input");
        assert_eq!(
            format!("{}", SanitizationErrorKind::TooLong),
            "input too long"
        );
        assert_eq!(
            format!("{}", SanitizationErrorKind::ContainsControlChars),
            "contains control characters"
        );
    }

    // StringSanitizer tests

    #[test]
    fn string_sanitizer_accepts_valid_input() {
        let sanitizer = StringSanitizer::new(256);
        let tainted = Tainted::new("hello world".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.as_ref(), "hello world");
    }

    #[test]
    fn string_sanitizer_trims_whitespace() {
        let sanitizer = StringSanitizer::new(256);
        let tainted = Tainted::new("  hello world  ".to_string());

        let verified = sanitizer.sanitize(tainted).expect("should succeed");

        assert_eq!(verified.as_ref(), "hello world");
    }

    #[test]
    fn string_sanitizer_rejects_empty_string() {
        let sanitizer = StringSanitizer::new(256);
        let tainted = Tainted::new("".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), SanitizationErrorKind::Empty);
    }

    #[test]
    fn string_sanitizer_rejects_whitespace_only() {
        let sanitizer = StringSanitizer::new(256);
        let tainted = Tainted::new("   \t\t  ".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), SanitizationErrorKind::Empty);
    }

    #[test]
    fn string_sanitizer_rejects_newline() {
        let sanitizer = StringSanitizer::new(256);
        let tainted = Tainted::new("hello\nworld".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), SanitizationErrorKind::ContainsControlChars);
    }

    #[test]
    fn string_sanitizer_rejects_null_byte() {
        let sanitizer = StringSanitizer::new(256);
        let tainted = Tainted::new("hello\0world".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), SanitizationErrorKind::ContainsControlChars);
    }

    #[test]
    fn string_sanitizer_rejects_carriage_return() {
        let sanitizer = StringSanitizer::new(256);
        let tainted = Tainted::new("hello\rworld".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), SanitizationErrorKind::ContainsControlChars);
    }

    #[test]
    fn string_sanitizer_rejects_tab() {
        let sanitizer = StringSanitizer::new(256);
        let tainted = Tainted::new("hello\tworld".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), SanitizationErrorKind::ContainsControlChars);
    }

    #[test]
    fn string_sanitizer_rejects_too_long() {
        let sanitizer = StringSanitizer::new(10);
        let tainted = Tainted::new("this is a very long string".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), SanitizationErrorKind::TooLong);
        assert!(error.message().contains("10"));
    }

    #[test]
    fn string_sanitizer_accepts_at_max_length() {
        let sanitizer = StringSanitizer::new(10);
        let tainted = Tainted::new("exactly10!".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.as_ref(), "exactly10!");
    }

    #[test]
    fn string_sanitizer_default_limits() {
        let sanitizer = StringSanitizer::default_limits();
        let tainted = Tainted::new("test".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_ok());
    }

    #[test]
    fn string_sanitizer_accepts_unicode() {
        let sanitizer = StringSanitizer::new(256);
        let tainted = Tainted::new("Hello 世界".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.as_ref(), "Hello 世界");
    }

    #[test]
    fn string_sanitizer_error_does_not_leak_input() {
        let sanitizer = StringSanitizer::new(10);
        let secret_input = "SECRET_PASSWORD_12345";
        let tainted = Tainted::new(secret_input.to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_err());
        let error = result.unwrap_err();
        let error_message = format!("{}", error);

        // Error message should NOT contain the actual secret input
        assert!(!error_message.contains(secret_input));
        // But should contain useful information about the constraint
        assert!(error_message.contains("10"));
    }

    #[test]
    #[should_panic(expected = "max_len must be greater than 0")]
    fn string_sanitizer_panics_on_zero_max_len() {
        let _sanitizer = StringSanitizer::new(0);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::test_utils::arb_valid_string;
    use proptest::prelude::*;

    // Strategy: Generate arbitrary printable strings
    fn arb_printable_string() -> impl Strategy<Value = String> {
        prop::string::string_regex("[\\x20-\\x7E]{0,500}").expect("valid regex for printable ASCII")
    }

    // Strategy: Generate strings with whitespace
    fn arb_whitespace_string() -> impl Strategy<Value = String> {
        prop::string::string_regex("[ \\t\\n\\r]{0,50}").expect("valid regex for whitespace")
    }

    // Strategy: Generate strings with control characters
    fn arb_string_with_control_chars() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::char::range('\x00', '\x1F'), 1..10)
            .prop_map(|chars| chars.into_iter().collect())
    }

    proptest! {
        /// Property: Sanitizing an already-sanitized value is idempotent
        #[test]
        fn proptest_sanitizer_is_idempotent(input in arb_valid_string(256)) {
            let sanitizer = StringSanitizer::new(256);
            let tainted = Tainted::new(input);

            // First sanitization
            let verified1 = sanitizer.sanitize(tainted).unwrap();

            // Second sanitization (on already verified value)
            let tainted2 = Tainted::new(verified1.as_ref().to_string());
            let verified2 = sanitizer.sanitize(tainted2).unwrap();

            // Should be identical
            prop_assert_eq!(verified1.as_ref(), verified2.as_ref());
        }

        /// Property: Sanitizer trims leading and trailing whitespace
        #[test]
        fn proptest_sanitizer_trims_leading_trailing_whitespace(
            prefix in arb_whitespace_string(),
            content in prop::string::string_regex("[a-zA-Z0-9]{1,50}").unwrap(),
            suffix in arb_whitespace_string()
        ) {
            let input = format!("{}{}{}", prefix, content, suffix);
            let sanitizer = StringSanitizer::new(256);
            let tainted = Tainted::new(input);

            if let Ok(verified) = sanitizer.sanitize(tainted) {
                let result = verified.as_ref();
                // Should have no leading or trailing whitespace
                prop_assert_eq!(result, result.trim());
                // Should still contain the original content
                prop_assert!(result.contains(&content));
            }
        }

        /// Property: Sanitizer preserves interior whitespace
        #[test]
        fn proptest_sanitizer_preserves_interior_whitespace(
            word1 in prop::string::string_regex("[a-zA-Z]{1,10}").unwrap(),
            word2 in prop::string::string_regex("[a-zA-Z]{1,10}").unwrap()
        ) {
            let input = format!("{}  {}", word1, word2);  // Two spaces
            let sanitizer = StringSanitizer::new(256);
            let tainted = Tainted::new(input);

            if let Ok(verified) = sanitizer.sanitize(tainted) {
                // Interior whitespace should be preserved
                prop_assert!(verified.as_ref().contains("  "));
            }
        }

        /// Property: Verified strings never exceed max_len
        #[test]
        fn proptest_sanitizer_never_exceeds_max_length(
            input in arb_printable_string(),
            max_len in 1usize..=256
        ) {
            let sanitizer = StringSanitizer::new(max_len);
            let tainted = Tainted::new(input);

            if let Ok(verified) = sanitizer.sanitize(tainted) {
                prop_assert!(verified.as_ref().len() <= max_len);
            }
        }

        /// Property: String at exactly max_len is accepted, max_len+1 is rejected
        #[test]
        fn proptest_sanitizer_boundary_at_max_length(max_len in 1usize..=100) {
            let sanitizer = StringSanitizer::new(max_len);

            // String of exactly max_len should be accepted
            let exact_input = "a".repeat(max_len);
            let tainted_exact = Tainted::new(exact_input.clone());
            prop_assert!(sanitizer.sanitize(tainted_exact).is_ok());

            // String of max_len + 1 should be rejected
            let too_long_input = "a".repeat(max_len + 1);
            let tainted_too_long = Tainted::new(too_long_input);
            let result = sanitizer.sanitize(tainted_too_long);
            prop_assert!(result.is_err());
            if let Err(e) = result {
                prop_assert!(matches!(e.kind, SanitizationErrorKind::TooLong));
            }
        }

        /// Property: Sanitizer rejects strings with control characters
        #[test]
        fn proptest_sanitizer_rejects_control_chars(
            control_chars in arb_string_with_control_chars(),
            word1 in prop::string::string_regex("[a-zA-Z0-9]{1,10}").unwrap(),
            word2 in prop::string::string_regex("[a-zA-Z0-9]{1,10}").unwrap()
        ) {
            // Put control chars in the middle so they won't be trimmed away
            let input = format!("{}{}{}", word1, control_chars, word2);
            let sanitizer = StringSanitizer::new(256);
            let tainted = Tainted::new(input);

            let result = sanitizer.sanitize(tainted);
            prop_assert!(result.is_err());
            if let Err(e) = result {
                prop_assert!(matches!(e.kind, SanitizationErrorKind::ContainsControlChars));
            }
        }

        /// Property: Error messages never leak the rejected input value
        #[test]
        fn proptest_sanitizer_errors_never_leak_input(
            secret_value in prop::string::string_regex("[A-Z]{5,20}").unwrap()
        ) {
            // Create input that will definitely be rejected (contains control char)
            // Use uppercase secret to avoid accidental matches with error message words
            let bad_input = format!("USER_SECRET_{}\x00", secret_value);
            let sanitizer = StringSanitizer::new(256);
            let tainted = Tainted::new(bad_input.clone());

            if let Err(error) = sanitizer.sanitize(tainted) {
                let error_message = error.to_string();
                // Error message should NOT contain the secret value we embedded
                prop_assert!(
                    !error_message.contains(&secret_value),
                    "Error message '{}' should not contain secret '{}'",
                    error_message,
                    secret_value
                );
            }
        }
    }
}
