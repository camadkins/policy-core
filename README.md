# policy-core

> Compile-time policy enforcement and taint tracking patterns in Rust.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![Crates.io](https://img.shields.io/crates/v/policy-core.svg)](https://crates.io/crates/policy-core)
[![Documentation](https://docs.rs/policy-core/badge.svg)](https://docs.rs/policy-core)
[![CI Status](https://github.com/camadkins/policy-core/workflows/CI/badge.svg)](https://github.com/camadkins/policy-core/actions)

## Overview

Untrusted input is wrapped in a `Tainted<T>` type with no public accessors. To perform side effects—logging, database writes, HTTP requests—the data must pass through a `Sanitizer` that validates it and returns `Verified<T>`. Sinks accept only `Verified<T>`, making compile-time bypass structurally impossible.

## Project Status

**Version 0.1.0 (Pre-Release)**

This is the initial public release of `policy-core`. The library demonstrates compile-time policy enforcement patterns using Rust's type system.

**What's Ready:**
- Core abstractions (`Tainted<T>`, `Verified<T>`, `Sanitizer`, `Sink`)
- Capability-based access control (`LogCap`, `AuditCap`, etc.)
- Type-state contexts (`Ctx<Unauthed>` → `Ctx<Authed>` → `Ctx<Authorized>`)
- Web framework integration (Axum extractors, middleware)
- Enforcement pack (Dylint lint: `NO_PRINTLN`)
- Comprehensive test suite (159 tests)
- API documentation

**Limitations:**
- Not formally verified or security-audited
- Example sanitizers require domain-specific customization for production
- v0.1.0 API may evolve based on real-world usage

**Production Use:** This library is suitable for projects that understand its security model (see [SECURITY.md](SECURITY.md) and [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md)). It provides structural guarantees through the type system but is not a complete security solution. Use as part of defense-in-depth strategy.

See [Security & Limitations](#security--limitations) for details.

The data flow:
```text
Tainted<T> → Sanitizer → Verified<T> → Sink
```

## Quick Start

Add `policy-core` to your project:

```bash
cargo add policy-core
```

Here's a minimal example demonstrating taint tracking:

```rust
use policy_core::{Tainted, Sanitizer, StringSanitizer, Sink, VecSink};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Mark untrusted input as tainted
    let user_input = Tainted::new("  hello world  ".to_string());

    // Step 2: Sanitize with validation rules
    let sanitizer = StringSanitizer::new(256);
    let verified = sanitizer.sanitize(user_input)?;

    // Step 3: Pass verified data to sink
    let sink = VecSink::new();
    sink.sink(&verified)?;

    // Verify the result (trimmed whitespace)
    assert_eq!(sink.to_vec(), vec!["hello world"]);

    println!("Success! Input was validated and processed safely.");
    Ok(())
}
```

The type system prevents bypassing validation at compile time. See the [Common Usage Patterns](#common-usage-patterns) below for when to use each abstraction, or explore the [`examples/`](examples/) directory for complete demonstrations. Read the [full documentation](https://docs.rs/policy-core) for detailed API reference.

## Common Usage Patterns

These patterns demonstrate when and how to use policy-core's core abstractions. See the [`examples/`](examples/) directory for complete working code.

### Pattern: Working with Tainted Data

**When to use:** Mark all external input—user forms, API requests, file contents—as tainted at system boundaries.

**Key insight:** `Tainted<T>` prevents accidental use of unvalidated data. The type system forces explicit validation before sinks accept the data.

**Reference:** [`examples/basic_taint_flow.rs`](examples/basic_taint_flow.rs), integration tests in `tests/taint_tracking_test.rs`

### Pattern: Building Authorization Contexts

**When to use:** Create verified contexts that carry proof of authentication and authorization through your application.

**Key insight:** `PolicyGate` validates policies before constructing a `Ctx`. Operations requiring specific capabilities demand the corresponding `Ctx` state as a parameter.

**Reference:** [`examples/policy_gate_validation.rs`](examples/policy_gate_validation.rs), see [Core Concepts](#core-concepts) below

### Pattern: Using Capabilities

**When to use:** Gate access to sensitive operations (logging, database writes, HTTP calls) behind unforgeable capability tokens.

**Key insight:** Capabilities have `pub(crate)` constructors. External code cannot forge them—they must be granted through policy validation.

**Reference:** [`examples/audit_trail.rs`](examples/audit_trail.rs), see the [End-to-End example](#example-end-to-end-flow) below

For complete demonstrations of these patterns integrated together, see [`src/demo.rs`](src/demo.rs) and the full integration test suite.

## Core Concepts

### `Tainted<T>`

Marks data from untrusted sources (user input, network requests, files). The inner value is inaccessible:

* No `Deref`, `AsRef`, `From`, or `Into` implementations
* Inner field is private; only `pub(crate)` accessor exists
* Cannot be passed to sinks (compile error)

### `Sanitizer`

Validates and promotes tainted data to verified data:

```rust
pub trait Sanitizer<T> {
    fn sanitize(&self, input: Tainted<T>) -> Result<Verified<T>, SanitizationError>;
}
```

Implementations define validation rules and call `Verified::new_unchecked` only after validation succeeds. Errors do not leak rejected input.

The crate includes `StringSanitizer`, which trims whitespace, rejects control characters, and enforces length limits.

### `Verified<T>`

Data that has passed validation:

* No public constructor—only `pub(crate) fn new_unchecked`
* No `Deref`, `From`, `Into`, or `Default`
* Explicit accessors: `as_ref()` and `into_inner()`
* External code cannot create `Verified<T>` except through a `Sanitizer`

This creates a validation bottleneck: all paths from untrusted input to sinks must pass through explicit sanitization.

### `Sink`

Operations that perform side effects (writes, logs, network calls):

```rust
pub trait Sink<T> {
    fn sink(&self, value: &Verified<T>) -> Result<(), SinkError>;
}
```

By accepting only `&Verified<T>`, sinks reject `Tainted<T>` at compile time.

The crate includes `VecSink`, an in-memory sink for testing.

## Architecture: Tainted → Sanitized → Verified → Sink

```text
┌─────────────┐
│ Raw Input   │  (user form, API call, file)
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│  Tainted<T>     │  Mark as untrusted at boundary
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│   Sanitizer     │  Validate according to policy
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  Verified<T>    │  Guaranteed safe by construction
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│     Sink        │  Perform side effect
└─────────────────┘
```

**Key properties:**

* No implicit conversions bypass sanitization
* `Tainted<T>` to `Verified<T>` transition requires explicit validation
* Compile errors prevent accidental misuse
* Type invariants enforced through visibility (`pub(crate)` constructors)

## Enforcement Pack (Static Analysis)

The `dylint/` directory contains custom Dylint lints that enforce architectural invariants at compile time.

**Purpose:** Prevent accidental bypass of capability gating, taint tracking, and explicit context patterns (see `ARCHITECT.local.md`).

**Run locally:**

```bash
cargo install cargo-dylint dylint-link
cargo dylint --all --workspace
```

**CI:** Lints run automatically on every PR. Deny-level violations fail the build.

**Documentation:** See [`dylint/README.md`](dylint/README.md) for:
- Enforcement philosophy and scope
- Implemented lints and future work
- Suppression policy (strict, auditable exceptions only)
- Reviewer guidance for policy-affecting changes

## Dependencies

`policy-core` keeps dependencies minimal:

* **`tracing`** — Structured logging for policy decisions, sanitizer results, and sink activity. Does not affect type-level guarantees.

* **`tracing-subscriber`** — Test and demo support for log collection. Used to show how policy decisions surface in logs while keeping side effects in-memory.

Core types (`Tainted<T>`, `Verified<T>`, `Sanitizer`, `Sink`) depend only on the standard library. Logging is optional.

## Example: End-to-End Flow

```rust
use policy_core::{Tainted, Sanitizer, StringSanitizer, Sink, VecSink};

// Step 1: Mark untrusted input as tainted
let user_input = Tainted::new("  hello world  ".to_string());

// Step 2: Sanitize with validation rules
let sanitizer = StringSanitizer::new(256);
let verified = sanitizer
    .sanitize(user_input)
    .expect("valid input passes");

// Step 3: Pass verified data to sink
let sink = VecSink::new();
sink.sink(&verified).expect("sink succeeds");

// Verify the side effect
assert_eq!(sink.to_vec(), vec!["hello world"]); // trimmed

// ❌ This does NOT compile (type error):
// let tainted = Tainted::new("unsafe".to_string());
// sink.sink(&tainted); // Expected &Verified<String>, got &Tainted<String>
```

The sanitizer trims whitespace, rejects empty strings, blocks control characters, and enforces length limits. Invalid input produces a `SanitizationError` without leaking the rejected value.

## Status & Roadmap

**Completed:**

* Milestone 1: Core types (`Secret<T>`, `Tainted<T>`, `Ctx`, capabilities)
* Milestone 2: Policy gate builder with structured validation
* Milestone 3: Capability-gated logging with secret redaction
* Milestone 4: Taint tracking (`Verified<T>`, `Sanitizer`, `Sink`)
* Milestone 5: End-to-end demo with in-memory sink
* Milestone 6: Type-state contexts (`Ctx<Unauthed>` → `Ctx<Authed>` → `Ctx<Authorized>`)
* Milestone 7: Audit trail support (`AuditCap`, structured events)
* Milestone 8: Web framework integration (Axum extractors, middleware)
* Milestone 9: Enforcement pack infrastructure (Dylint lints, CI integration)
* Milestone 10: Documentation and publishing readiness

## Security & Limitations

This library is not formally verified or security-audited. It demonstrates patterns, not a complete security solution.

**Limitations:**

* Sanitizers implement example validation rules. Production systems require domain-specific logic.
* Type-level enforcement prevents many errors but is not absolute. Unsafe code, deserialization, or FFI can break invariants.
* This does not replace standard security practices: authentication, authorization, encryption, rate limiting, and input validation at system boundaries remain necessary.
* The type system cannot prevent all logic errors. Review sanitizer implementations carefully.

Use this to explore patterns and inform architecture decisions. Do not deploy this as-is in security-critical systems.

## Contributing

Contributions are accepted. Open an issue to discuss significant changes before starting work.

**Guidelines:**

* Respect the core philosophy: explicit policies, no hidden conversions, compile-time safety where possible
* Add tests for new sanitizers or sinks
* Run `cargo fmt`, `cargo clippy --all-features -- -D warnings`, `cargo test --all-features`, and `cargo dylint --all --workspace`
* Document what guarantees do and do not exist

## License

This project is licensed under the [MIT License](LICENSE).
