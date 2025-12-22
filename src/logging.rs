use std::fmt;

/// A capability-gated logging interface.
///
/// `PolicyLog` is obtained from `Ctx::log()` and requires `LogCap`.
/// It is lifetime-bound to the context to prevent misuse.
///
/// Secret values are automatically redacted when logged due to
/// their `Debug` and `Display` implementations.
///
/// All log messages automatically include the request ID for tracing.
#[derive(Debug)]
pub struct PolicyLog<'a> {
    // Lifetime ensures this can't outlive the Ctx
    _ctx_lifetime: std::marker::PhantomData<&'a ()>,
    request_id: &'a str,
}

impl<'a> PolicyLog<'a> {
    /// Creates a new PolicyLog with a request ID.
    ///
    /// This is `pub(crate)` - only `Ctx` can create it.
    pub(crate) fn new(request_id: &'a str) -> Self {
        Self {
            _ctx_lifetime: std::marker::PhantomData,
            request_id,
        }
    }

    /// Returns the request ID associated with this logger.
    pub fn request_id(&self) -> &str {
        self.request_id
    }

    /// Logs an info-level message with request ID.
    ///
    /// Use with `format_args!` for efficient formatting:
    /// ```no_run
    /// # use policy_core::{PolicyLog, Secret};
    /// # fn example(log: &PolicyLog) {
    /// let secret = Secret::new("password");
    /// log.info(format_args!("Processing with key: {:?}", secret));
    /// # }
    /// ```
    pub fn info(&self, args: fmt::Arguments<'_>) {
        tracing::info!(request_id = %self.request_id, "{}", args);
    }

    /// Logs a warning-level message with request ID.
    pub fn warn(&self, args: fmt::Arguments<'_>) {
        tracing::warn!(request_id = %self.request_id, "{}", args);
    }

    /// Logs an error-level message with request ID.
    pub fn error(&self, args: fmt::Arguments<'_>) {
        tracing::error!(request_id = %self.request_id, "{}", args);
    }

    /// Logs a debug-level message with request ID.
    pub fn debug(&self, args: fmt::Arguments<'_>) {
        tracing::debug!(request_id = %self.request_id, "{}", args);
    }
}
