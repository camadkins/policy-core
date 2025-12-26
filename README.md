# policy-core

> Compile-time policy enforcement and taint tracking for Rust.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)
[![Crates.io](https://img.shields.io/crates/v/policy-core.svg)](https://crates.io/crates/policy-core)
[![Documentation](https://docs.rs/policy-core/badge.svg)](https://docs.rs/policy-core)
[![CI Status](https://github.com/camadkins/policy-core/workflows/CI/badge.svg)](https://github.com/camadkins/policy-core/actions)

## What is policy-core?

`policy-core` prevents injection attacks, unauthorized access, and accidental data leaks using Rust's type system. Untrusted input is wrapped in a `Tainted<T>` type with no public accessors. To perform side effects—logging, database writes, HTTP requests—the data must pass through a `Sanitizer` that validates it and returns `Verified<T>`. Sinks accept only `Verified<T>`, making compile-time bypass structurally impossible.

```text
Tainted<T> → Sanitizer → Verified<T> → Sink
```

## Key Features

- **Type-safe taint tracking** — Prevents injection attacks at compile time
- **Capability-based access control** — Unforgeable tokens gate logging, database, and HTTP operations
- **Zero-cost abstractions** — No runtime overhead; guarantees enforced by the type system
- **Type-state contexts** — Encode authentication and authorization state in types (`Ctx<Unauthed>` → `Ctx<Authed>` → `Ctx<Authorized>`)
- **Web framework integration** — Axum extractors and middleware for production use
- **Static analysis** — Custom Dylint lints enforce architectural invariants at compile time
- **No unsafe code** — Core abstractions built on safe Rust

## Installation

```bash
cargo add policy-core
```

## Quick Start

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

The type system prevents bypassing validation at compile time. Attempting to pass `Tainted<T>` directly to a sink results in a compile error. See the [`examples/`](examples/) directory for complete demonstrations.

## How It Works

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

## Common Usage Patterns

These patterns demonstrate when and how to use policy-core's core abstractions. See the [`examples/`](examples/) directory for complete working code.

### Pattern: Working with Tainted Data

**When to use:** Mark all external input—user forms, API requests, file contents—as tainted at system boundaries.

**Key insight:** `Tainted<T>` prevents accidental use of unvalidated data. The type system forces explicit validation before sinks accept the data.

**Reference:** [`examples/basic_taint_flow.rs`](examples/basic_taint_flow.rs), integration tests in `tests/taint_tracking_test.rs`

### Pattern: Building Authorization Contexts

**When to use:** Create verified contexts that carry proof of authentication and authorization through your application.

**Key insight:** `PolicyGate` validates policies before constructing a `Ctx`. Operations requiring specific capabilities demand the corresponding `Ctx` state as a parameter.

**Reference:** [`examples/policy_gate_validation.rs`](examples/policy_gate_validation.rs)

### Pattern: Using Capabilities

**When to use:** Gate access to sensitive operations (logging, database writes, HTTP calls) behind unforgeable capability tokens.

**Key insight:** Capabilities have `pub(crate)` constructors. External code cannot forge them—they must be granted through policy validation.

**Reference:** [`examples/audit_trail.rs`](examples/audit_trail.rs)

For complete demonstrations of these patterns integrated together, see [`src/demo.rs`](src/demo.rs) and the full integration test suite.

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

## Enforcement Pack (Static Analysis)

The `dylint/` directory contains custom Dylint lints that enforce architectural invariants at compile time.

**Purpose:** Prevent accidental bypass of capability gating, taint tracking, and explicit context patterns.

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

## Security & Limitations

This library is not formally verified or security-audited. It demonstrates patterns, not a complete security solution.

**Limitations:**

* Sanitizers implement example validation rules. Production systems require domain-specific logic.
* Type-level enforcement prevents many errors but is not absolute. Unsafe code, deserialization, or FFI can break invariants.
* This does not replace standard security practices: authentication, authorization, encryption, rate limiting, and input validation at system boundaries remain necessary.
* The type system cannot prevent all logic errors. Review sanitizer implementations carefully.

Use this library as part of a defense-in-depth strategy. See [SECURITY.md](SECURITY.md) and [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md) for detailed discussions.

## Documentation

- **API Reference:** [docs.rs/policy-core](https://docs.rs/policy-core)
- **Examples:** [`examples/`](examples/) directory
- **Security Model:** [SECURITY.md](SECURITY.md)
- **Design Rationale:** [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md)
- **Enforcement Pack:** [`dylint/README.md`](dylint/README.md)

## Contributing

Contributions are accepted. Open an issue to discuss significant changes before starting work.

**Guidelines:**

* Respect the core philosophy: explicit policies, no hidden conversions, compile-time safety where possible
* Add tests for new sanitizers or sinks
* Run `cargo fmt`, `cargo clippy --all-features -- -D warnings`, `cargo test --all-features`, and `cargo dylint --all --workspace`
* Document what guarantees do and do not exist

## License

This project is licensed under the [MIT License](LICENSE).
