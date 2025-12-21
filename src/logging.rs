use std::fmt;

/// A capability-gated logging interface.
///
/// `PolicyLog` is obtained from `Ctx::log()` and requires `LogCap`.
/// It is lifetime-bound to the context to prevent misuse.
///
/// Secret values are automatically redacted when logged due to
/// their `Debug` and `Display` implementations.
#[derive(Debug)]
pub struct PolicyLog<'a> {
    // Lifetime ensures this can't outlive the Ctx
    _ctx_lifetime: std::marker::PhantomData<&'a ()>,
}

impl<'a> PolicyLog<'a> {
    /// Creates a new PolicyLog.
    ///
    /// This is `pub(crate)` - only `Ctx` can create it.
    pub(crate) fn new() -> Self {
        Self {
            _ctx_lifetime: std::marker::PhantomData,
        }
    }

    /// Logs an info-level message.
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
        tracing::info!("{}", args);
    }

    /// Logs a warning-level message.
    pub fn warn(&self, args: fmt::Arguments<'_>) {
        tracing::warn!("{}", args);
    }

    /// Logs an error-level message.
    pub fn error(&self, args: fmt::Arguments<'_>) {
        tracing::error!("{}", args);
    }

    /// Logs a debug-level message.
    pub fn debug(&self, args: fmt::Arguments<'_>) {
        tracing::debug!("{}", args);
    }
}
