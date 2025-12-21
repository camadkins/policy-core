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
        let tainted = Tainted::new("Hello 世界 🌍".to_string());

        let result = sanitizer.sanitize(tainted);

        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.as_ref(), "Hello 世界 🌍");
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
