use std::cell::RefCell;
use std::fmt;

use crate::{Tainted, Verified};

/// Error returned when sinking a value fails.
///
/// This error indicates that a value could not be written to a sink, either
/// due to an I/O error or because the value was not properly verified.
///
/// # Examples
///
/// ```
/// use policy_core::{SinkError, SinkErrorKind};
///
/// let error = SinkError::new(SinkErrorKind::Unverified);
/// assert_eq!(error.kind(), SinkErrorKind::Unverified);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkError {
    kind: SinkErrorKind,
    message: Option<String>,
}

impl SinkError {
    /// Creates a new sink error with the specified kind.
    pub fn new(kind: SinkErrorKind) -> Self {
        Self {
            kind,
            message: None,
        }
    }

    /// Creates a new sink error with a custom message.
    pub fn with_message(kind: SinkErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: Some(message.into()),
        }
    }

    /// Returns the error kind.
    pub fn kind(&self) -> SinkErrorKind {
        self.kind
    }

    /// Returns the error message, if any.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(msg) = &self.message {
            write!(f, "sink error ({}): {}", self.kind, msg)
        } else {
            write!(f, "sink error ({})", self.kind)
        }
    }
}

impl std::error::Error for SinkError {}

/// Kind of sink error.
///
/// Categorizes why a sink operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkErrorKind {
    /// Value was not verified before sinking.
    Unverified,
    /// I/O error occurred during sink operation.
    Io,
    /// Sink is full or has reached capacity.
    Full,
}

impl fmt::Display for SinkErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unverified => write!(f, "unverified input"),
            Self::Io => write!(f, "I/O error"),
            Self::Full => write!(f, "sink full"),
        }
    }
}

/// Trait for sinks that accept only verified values.
///
/// `Sink<T>` defines the interface for writing verified data to side-effecting
/// operations (files, logs, databases, etc.). The trait enforces at compile time
/// that only `Verified<T>` values can be written, preventing tainted data from
/// flowing into sinks.
///
/// # Compile-Time Safety
///
/// The `sink` method accepts only `&Verified<T>`, which means:
/// - Raw values of type `T` cannot be sunk directly (compile error)
/// - `Tainted<T>` values cannot be sunk directly (compile error)
/// - Only values that have passed through a `Sanitizer` can be sunk
///
/// # Examples
///
/// ```
/// use policy_core::{Tainted, Verified, Sanitizer, Sink, VecSink, StringSanitizer};
///
/// let sink = VecSink::new();
/// let sanitizer = StringSanitizer::new(256).unwrap();
///
/// // Tainted input must be sanitized first
/// let tainted = Tainted::new("hello world".to_string());
/// let verified = sanitizer.sanitize(tainted).expect("should succeed");
///
/// // Verified values can be sunk
/// sink.sink(&verified).expect("should succeed");
///
/// // This would NOT compile:
/// // let tainted = Tainted::new("bad".to_string());
/// // sink.sink(&tainted); // Type mismatch!
/// ```
// BREAKING CHANGE WARNING: Do NOT modify the Sink trait signature.
// The sink() method MUST accept &Verified<T>, not &T or &Tainted<T>.
// Changing this defeats the entire validation bottleneck and allows unvalidated data into sinks.
pub trait Sink<T> {
    /// Writes a verified value to the sink.
    ///
    /// # Errors
    ///
    /// Returns `SinkError` if the sink operation fails (e.g., I/O error, capacity exceeded).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use policy_core::{Verified, Sink, VecSink};
    ///
    /// # let sink = VecSink::new();
    /// # let verified = Verified::new_unchecked("data".to_string());
    /// // Only verified values can be sunk
    /// sink.sink(&verified).expect("should succeed");
    /// ```
    /// BREAKING CHANGE WARNING: This signature MUST accept `&Verified<T>`, not `&T` or `&Tainted<T>`.
    /// Changing it to accept `&T` or `&Tainted<T>` bypasses validation and enables injection attacks
    /// (CWE-74, CWE-89, CWE-117, CWE-79).
    fn sink(&self, value: &Verified<T>) -> Result<(), SinkError>;

    /// Attempts to sink an unverified value (always fails).
    ///
    /// This method provides a runtime rejection path for tainted values.
    /// It exists primarily for demonstration and explicit error handling,
    /// as tainted values should be rejected at compile time via the type system.
    ///
    /// # Errors
    ///
    /// Always returns `SinkError` with kind `Unverified`, as tainted values
    /// must be sanitized before sinking.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::{Tainted, Sink, VecSink, SinkErrorKind};
    ///
    /// let sink = VecSink::new();
    /// let tainted = Tainted::new("unsafe".to_string());
    ///
    /// let result = sink.sink_untrusted(tainted);
    /// assert!(result.is_err());
    /// assert_eq!(result.unwrap_err().kind(), SinkErrorKind::Unverified);
    /// ```
    /// BREAKING CHANGE WARNING: This method MUST unconditionally return Err.
    /// Allowing tainted values to be sunk bypasses validation and enables all injection attacks.
    fn sink_untrusted(&self, _value: Tainted<T>) -> Result<(), SinkError> {
        Err(SinkError::new(SinkErrorKind::Unverified))
    }
}

/// A demonstration sink that collects verified strings into an in-memory vector.
///
/// `VecSink` provides a simple, observable sink for testing and demonstration.
/// It accepts only `Verified<String>` values and stores them in an internal vector.
///
/// # Security Properties
///
/// - Accepts only `Verified<String>` on the main path (compile-time enforcement)
/// - Rejects `Tainted<String>` at runtime if `sink_untrusted` is called
/// - Does not perform sanitization itself (delegates to `Sanitizer` implementations)
/// - Uses interior mutability to allow shared access while collecting values
///
/// # Examples
///
/// ```
/// use policy_core::{Tainted, Verified, Sanitizer, Sink, VecSink, StringSanitizer};
///
/// let sink = VecSink::new();
/// let sanitizer = StringSanitizer::new(256).unwrap();
///
/// // Sanitize and sink verified values
/// let tainted = Tainted::new("  hello  ".to_string());
/// let verified = sanitizer.sanitize(tainted).expect("valid input");
/// sink.sink(&verified).expect("should succeed");
///
/// // Check collected values
/// let values = sink.into_vec();
/// assert_eq!(values, vec!["hello"]);
/// ```
#[derive(Debug)]
pub struct VecSink {
    values: RefCell<Vec<String>>,
}

impl VecSink {
    /// Creates a new empty vector sink.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::VecSink;
    ///
    /// let sink = VecSink::new();
    /// ```
    pub fn new() -> Self {
        Self {
            values: RefCell::new(Vec::new()),
        }
    }

    /// Returns the number of values in the sink.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::VecSink;
    ///
    /// let sink = VecSink::new();
    /// assert_eq!(sink.len(), 0);
    /// ```
    pub fn len(&self) -> usize {
        self.values.borrow().len()
    }

    /// Returns `true` if the sink contains no values.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::VecSink;
    ///
    /// let sink = VecSink::new();
    /// assert!(sink.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.values.borrow().is_empty()
    }

    /// Provides borrowed access to values via callback (zero-copy).
    ///
    /// This method allows you to access the value list without cloning by
    /// passing a closure that receives a borrowed slice.
    ///
    /// # Performance
    ///
    /// This is the most efficient way to read values when you don't need to
    /// own them. The closure receives `&[String]` and can iterate, filter,
    /// or perform any read operation without allocating.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::{VecSink, Sink, Verified, Tainted, Sanitizer, StringSanitizer};
    ///
    /// let sink = VecSink::new();
    /// let sanitizer = StringSanitizer::new(100).unwrap();
    /// let verified = sanitizer.sanitize(Tainted::new("test".to_string())).unwrap();
    /// sink.sink(&verified).unwrap();
    ///
    /// // Zero-copy access via callback
    /// sink.with_values(|values| {
    ///     println!("Value count: {}", values.len());
    ///     for value in values {
    ///         println!("  {}", value);
    ///     }
    /// });
    /// ```
    pub fn with_values<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[String]) -> R,
    {
        f(&self.values.borrow())
    }

    /// Returns an iterator over values (lazy cloning).
    ///
    /// # Performance Note
    ///
    /// Due to `RefCell` interior mutability, this method clones the vector
    /// before returning an iterator. However, iteration happens lazily, so if
    /// you only need a few values, this can be more efficient than processing
    /// the entire cloned vector.
    ///
    /// For zero-copy access, prefer [`with_values()`](Self::with_values).
    /// To consume the sink and take ownership, use [`into_vec()`](Self::into_vec).
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::{VecSink, Sink, Verified, Tainted, Sanitizer, StringSanitizer};
    ///
    /// let sink = VecSink::new();
    /// let sanitizer = StringSanitizer::new(100).unwrap();
    /// let verified = sanitizer.sanitize(Tainted::new("test".to_string())).unwrap();
    /// sink.sink(&verified).unwrap();
    ///
    /// // Iterator-based access
    /// for value in sink.iter() {
    ///     println!("{}", value);
    /// }
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = String> {
        self.values.borrow().clone().into_iter()
    }

    /// Consumes the sink and returns the collected values.
    ///
    /// This is the most efficient way to extract values when you're done with
    /// the sink, as it moves the data instead of cloning.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::VecSink;
    ///
    /// let sink = VecSink::new();
    /// let values = sink.into_vec();
    /// assert_eq!(values.len(), 0);
    /// ```
    pub fn into_vec(self) -> Vec<String> {
        self.values.into_inner()
    }

    /// Returns a snapshot of the current values in the sink.
    ///
    /// # Performance Note
    ///
    /// **This method clones the entire value vector.**
    ///
    /// **Deprecated:** Use [`iter()`](Self::iter) for lazy iteration,
    /// [`with_values()`](Self::with_values) for zero-copy access, or
    /// [`into_vec()`](Self::into_vec) to consume the sink.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::VecSink;
    ///
    /// let sink = VecSink::new();
    /// let values = sink.to_vec();
    /// assert!(values.is_empty());
    /// ```
    #[deprecated(
        since = "0.2.0",
        note = "Use `iter()`, `with_values()`, or `into_vec()` for better performance"
    )]
    pub fn to_vec(&self) -> Vec<String> {
        self.values.borrow().clone()
    }
}

impl Default for VecSink {
    fn default() -> Self {
        Self::new()
    }
}

impl Sink<String> for VecSink {
    fn sink(&self, value: &Verified<String>) -> Result<(), SinkError> {
        // Extract the verified string and push it to the vector
        let verified_str = value.as_ref();
        self.values.borrow_mut().push(verified_str.clone());
        Ok(())
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::{Sanitizer, StringSanitizer};

    #[test]
    fn sink_error_creation() {
        let error = SinkError::new(SinkErrorKind::Unverified);
        assert_eq!(error.kind(), SinkErrorKind::Unverified);
        assert_eq!(error.message(), None);
    }

    #[test]
    fn sink_error_with_message() {
        let error = SinkError::with_message(SinkErrorKind::Io, "disk full");
        assert_eq!(error.kind(), SinkErrorKind::Io);
        assert_eq!(error.message(), Some("disk full"));
    }

    #[test]
    fn sink_error_display() {
        let error = SinkError::new(SinkErrorKind::Unverified);
        let output = format!("{}", error);
        assert!(output.contains("unverified input"));
    }

    #[test]
    fn sink_error_kinds_display() {
        assert_eq!(format!("{}", SinkErrorKind::Unverified), "unverified input");
        assert_eq!(format!("{}", SinkErrorKind::Io), "I/O error");
        assert_eq!(format!("{}", SinkErrorKind::Full), "sink full");
    }

    #[test]
    fn vec_sink_accepts_verified() {
        let sink = VecSink::new();
        let verified = Verified::new_unchecked("test".to_string());

        let result = sink.sink(&verified);

        assert!(result.is_ok());
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.to_vec(), vec!["test"]);
    }

    #[test]
    fn vec_sink_multiple_values() {
        let sink = VecSink::new();

        for i in 0..5 {
            let verified = Verified::new_unchecked(format!("value-{}", i));
            sink.sink(&verified).expect("should succeed");
        }

        assert_eq!(sink.len(), 5);
        let values = sink.into_vec();
        assert_eq!(
            values,
            vec!["value-0", "value-1", "value-2", "value-3", "value-4"]
        );
    }

    #[test]
    fn vec_sink_rejects_untrusted() {
        let sink = VecSink::new();
        let tainted = Tainted::new("unsafe data".to_string());

        let result = sink.sink_untrusted(tainted);

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), SinkErrorKind::Unverified);

        // Verify no side effects occurred
        assert_eq!(sink.len(), 0);
    }

    #[test]
    fn vec_sink_with_sanitizer() {
        let sink = VecSink::new();
        let sanitizer = StringSanitizer::new(256).unwrap();

        // Sanitize tainted input
        let tainted = Tainted::new("  hello world  ".to_string());
        let verified = sanitizer.sanitize(tainted).expect("valid input");

        // Sink the verified value
        sink.sink(&verified).expect("should succeed");

        // Verify the trimmed value was stored
        assert_eq!(sink.to_vec(), vec!["hello world"]);
    }

    #[test]
    fn vec_sink_enforces_verified_type() {
        let sink = VecSink::new();

        // This compiles - verified values work:
        let verified = Verified::new_unchecked("safe".to_string());
        let _ = sink.sink(&verified);

        // These would NOT compile if uncommented (good!):
        // let raw_string = "raw".to_string();
        // sink.sink(&raw_string); // Type mismatch!

        // let tainted = Tainted::new("tainted".to_string());
        // sink.sink(&tainted); // Type mismatch!
    }

    #[test]
    fn vec_sink_default() {
        let sink = VecSink::default();
        assert!(sink.is_empty());
        assert_eq!(sink.len(), 0);
    }

    #[test]
    fn vec_sink_is_empty() {
        let sink = VecSink::new();
        assert!(sink.is_empty());

        let verified = Verified::new_unchecked("test".to_string());
        sink.sink(&verified).unwrap();

        assert!(!sink.is_empty());
    }

    #[test]
    fn vec_sink_preserves_sanitization() {
        let sink = VecSink::new();
        let sanitizer = StringSanitizer::new(50).unwrap();

        // Create multiple tainted inputs that need sanitization
        let inputs = vec!["  one  ", "  two  ", "  three  "];

        for input in inputs {
            let tainted = Tainted::new(input.to_string());
            let verified = sanitizer.sanitize(tainted).expect("valid");
            sink.sink(&verified).expect("should succeed");
        }

        // All values should be trimmed
        assert_eq!(sink.to_vec(), vec!["one", "two", "three"]);
    }

    #[test]
    fn vec_sink_runtime_rejection_no_side_effects() {
        let sink = VecSink::new();

        // Add a verified value
        let verified = Verified::new_unchecked("safe".to_string());
        sink.sink(&verified).expect("should succeed");
        assert_eq!(sink.len(), 1);

        // Try to add tainted via runtime path
        let tainted = Tainted::new("unsafe".to_string());
        let result = sink.sink_untrusted(tainted);

        // Should fail
        assert!(result.is_err());

        // Should not have modified the sink
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.to_vec(), vec!["safe"]);
    }
}
