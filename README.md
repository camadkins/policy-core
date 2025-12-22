# policy-core

> Compile-time policy enforcement and taint tracking patterns in Rust.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2024-orange.svg)](https://www.rust-lang.org)

## Overview

`policy-core` is a research project exploring compile-time enforcement of security policies through Rust's type system. The goal is to demonstrate patterns that prevent untrusted data from reaching sensitive operations without explicit validation.

Untrusted input is wrapped in a `Tainted<T>` type with no public accessors. To perform side effects—logging, database writes, HTTP requests—the data must pass through a `Sanitizer` that validates it and returns `Verified<T>`. Sinks accept only `Verified<T>`, making compile-time bypass structurally impossible.

This is a demonstration project. It shows architectural patterns for taint tracking, capability-based access control, and explicit validation. The type system enforces some invariants, but the project is not formally verified or security-audited. Do not use this as a production security framework.

The data flow:
```text
Tainted<T> → Sanitizer → Verified<T> → Sink
```

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

**Planned:**

* Type-state contexts (`Ctx<Unauthed>` → `Ctx<Authed>`)
* Database and HTTP sink integrations
* Web framework middleware (Axum/Actix)
* Lint rules to detect policy bypass attempts

This is an experimental project. APIs are subject to change.

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
* Run `cargo fmt`, `cargo clippy --all-features -- -D warnings`, and `cargo test --all-features`
* Document what guarantees do and do not exist

## License

This project is licensed under the [MIT License](LICENSE).
