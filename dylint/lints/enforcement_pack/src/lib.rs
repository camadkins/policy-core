//! Enforcement pack: Custom lints for policy-core invariants.
//!
//! This lint library enforces architectural invariants at compile time,
//! preventing accidental bypass of capability gating and structured logging.
//!
//! ## Implemented Lints
//!
//! - `NO_PRINTLN`: Forbids println!, eprintln!, and dbg! macros to enforce
//!   structured logging via PolicyLog and prevent secret leakage.

#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;
extern crate rustc_lint;
extern crate rustc_session;
extern crate rustc_span;

use rustc_ast::{Expr, ExprKind, MacCall};
use rustc_lint::{EarlyContext, EarlyLintPass};
use rustc_session::{declare_lint_pass, declare_tool_lint};

declare_tool_lint! {
    /// **What it does:** Forbids use of `println!`, `eprintln!`, and `dbg!` macros in library code.
    ///
    /// **Why is this bad?** These macros bypass structured logging and sink controls:
    /// - They write directly to stdout/stderr, bypassing `PolicyLog`
    /// - They cannot be capability-gated
    /// - They may leak secrets that would otherwise be redacted
    /// - They produce unstructured output unsuitable for audit trails
    ///
    /// **Known problems:** None.
    ///
    /// **Example:**
    /// ```rust,ignore
    /// // Bad - bypasses PolicyLog
    /// println!("User logged in: {}", user_id);
    /// eprintln!("Error: {}", err);
    /// dbg!(secret_value);
    ///
    /// // Good - uses structured logging
    /// use policy_core::PolicyLog;
    /// policy_log.info("User logged in", &[("user_id", &user_id)]);
    /// ```
    pub enforcement_pack::NO_PRINTLN,
    Deny,
    "use of println!, eprintln!, or dbg! macros; use PolicyLog instead"
}

declare_lint_pass!(NoPrintln => [NO_PRINTLN]);

impl EarlyLintPass for NoPrintln {
    fn check_expr(&mut self, cx: &EarlyContext<'_>, expr: &Expr) {
        if let ExprKind::MacCall(mac) = &expr.kind {
            check_macro(cx, mac, expr.span);
        }
    }
}

fn check_macro(cx: &EarlyContext<'_>, mac: &MacCall, span: rustc_span::Span) {
    let path = &mac.path;

    // Check if this is a single-segment macro call (println, eprintln, dbg)
    if path.segments.len() != 1 {
        return;
    }

    let macro_name = path.segments[0].ident.name.as_str();

    match macro_name {
        "println" => {
            rustc_lint::LintContext::span_lint(cx, NO_PRINTLN, span, |diag| {
                diag.help("use `tracing::info!` or `PolicyLog` for structured logging");
                diag.note("`println!` bypasses capability gating and may leak secrets");
            });
        }
        "eprintln" => {
            rustc_lint::LintContext::span_lint(cx, NO_PRINTLN, span, |diag| {
                diag.help("use `tracing::error!` or `PolicyLog` for structured logging");
                diag.note("`eprintln!` bypasses capability gating and may leak secrets");
            });
        }
        "dbg" => {
            rustc_lint::LintContext::span_lint(cx, NO_PRINTLN, span, |diag| {
                diag.help("use `tracing::debug!` or `PolicyLog` for structured logging");
                diag.note("`dbg!` bypasses capability gating and may leak secrets");
            });
        }
        _ => {}
    }
}

#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub extern "C" fn register_lints(_sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    lint_store.register_lints(&[&NO_PRINTLN]);
    lint_store.register_early_pass(|| Box::new(NoPrintln));
}

#[unsafe(no_mangle)]
pub fn dylint_version() -> *mut std::os::raw::c_char {
    std::ffi::CString::new(dylint_linting::DYLINT_VERSION)
        .expect("version string contains null byte")
        .into_raw()
}
