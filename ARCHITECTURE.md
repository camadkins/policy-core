# Architecture

This document describes the architectural design and core concepts of `policy-core`.

## Core Problem

Modern applications often fail at policy enforcement because:
- Context is implicit or global
- Authorization is scattered across the codebase
- Dangerous operations are callable without proof of authorization
- Sanitization is optional and unenforced
- Auditing is added as an afterthought

`policy-core` addresses these problems by making policy violations structurally difficult through Rust's type system.

---

## Design Principles

### 1. Explicit Context Over Ambient State

There is no global context in `policy-core`.

All privileged actions require an explicit `Ctx` value that:
- Is constructed deliberately through validation
- Encodes policy decisions
- Carries capabilities proving authorization

If a function needs authority, it declares this requirement in its signature.

**Example:**
```rust
// Clear from the signature that logging capability is required
fn process_request(ctx: &Ctx<Authorized>) {
    ctx.log().info("Processing request");
}
```

---

### 2. Capabilities, Not Roles

Instead of roles, flags, or booleans, `policy-core` uses **typed capability objects**.

Capabilities are:
- Typed proof objects
- Granted only after successful policy validation
- Required to call privileged operations

Possession of a capability implies authorization. Absence makes misuse impossible.

**Example:**
```rust
// LogCap is a capability - you can only get it through policy validation
pub fn log_message(cap: LogCap, message: &str) { ... }
```

---

### 3. Make Invalid States Unrepresentable

Whenever possible, invalid usage fails at compile time, not runtime.

**Examples:**
- Logging without `LogCap` → compile error
- Using tainted input in a sink → compile error
- Calling privileged methods without the right context state → compile error

Runtime checks exist only where static enforcement is impossible.

---

### 4. Enforcement Must Be Hard to Bypass

`policy-core` assumes developers will accidentally do the wrong thing.

Therefore:
- Dangerous operations are wrapped in capability-gated types
- Raw APIs are discouraged
- Secret redaction is automatic
- Sanitization is enforced through types

If bypass is easy, the design is incomplete.

---

## Core Components

### Context (`Ctx`)

`Ctx<S>` represents a validated execution context where `S` encodes the authentication/authorization state.

**Responsibilities:**
- Carries request metadata (request ID, principal)
- Holds granted capabilities
- Serves as the root object for privileged operations

**Rules:**
- `Ctx` is immutable once built
- `Ctx` is created only through `PolicyGate`
- Capabilities within `Ctx` cannot be forged

**Type-State Progression:**
```text
Ctx<Unauthed> → Ctx<Authed> → Ctx<Authorized>
```

---

### PolicyGate

`PolicyGate` is the only way to obtain a valid `Ctx`.

**Responsibilities:**
- Accept raw inputs (request metadata)
- Apply policy requirements
- Fail early with structured violations
- Produce a valid `Ctx` or an error

**Usage:**
```rust
let ctx = PolicyGate::new(request_meta)
    .require(Authenticated)
    .require(Authorized::for_action("log"))
    .build()?;  // Ctx<Authorized> or error
```

Policies are:
- Explicit and visible in code
- Composable through the builder pattern
- Order-independent

---

### Capabilities

Capabilities are zero-sized or lightweight marker types that prove authorization.

**Rules:**
- Cannot be constructed outside the crate
- Only issued after successful policy validation
- Gate access to privileged operations

**Available Capabilities:**
- `LogCap` - Authorizes logging operations
- `HttpCap` - Authorizes HTTP requests
- `AuditCap` - Authorizes audit trail access

Capabilities are not data—they are **proof of authorization**.

---

### Taint Tracking

Untrusted data from external sources is always marked as tainted.

**Types:**
- `Tainted<T>` - Untrusted, restricted data
- `Verified<T>` - Sanitized, safe data
- `Sanitizer<T>` - Trait for validation logic

**Rules:**
- `Tainted` values cannot reach sinks (compile error)
- Sanitization must be explicit
- Sanitizers are narrow and context-specific

**Data Flow:**
```text
Tainted<T> → Sanitizer → Verified<T> → Sink
```

The goal is to force conscious validation decisions, not to sanitize everything automatically.

**Example:**
```rust
let user_input = Tainted::new(raw_string);
let sanitizer = StringSanitizer::new(max_length);
let verified = sanitizer.sanitize(user_input)?;
sink.sink(&verified)?;  // Only accepts Verified<T>
```

---

### Sinks

A sink is any operation that can cause harm if misused:
- Logging
- Database operations
- HTTP calls
- Filesystem access
- Audit trails

**Rules:**
- All sinks are wrapped in capability-gated types
- All sinks require appropriate capabilities
- All sinks respect taint tracking and secret redaction
- Direct use of raw sinks should be avoided

**Example:**
```rust
// PolicyLog wraps logging and requires LogCap
let log = ctx.log();  // Only available if ctx has LogCap
log.info("Safe to log");
```

---

### Secrets

`Secret<T>` wraps sensitive values (API keys, passwords, tokens) and prevents accidental exposure.

**Properties:**
- `Debug` and `Display` output `[REDACTED]`
- No implicit conversions or trait implementations
- Explicit `expose_secret()` required for access

**Example:**
```rust
let api_key = Secret::new("sk-1234567890".to_string());
println!("{:?}", api_key);  // Prints: [REDACTED]
let key = api_key.expose_secret();  // Explicit, visible in code
```

---

## Enforcement Strategy

### Compile-Time Enforcement

The primary enforcement mechanism is Rust's type system:

**Type Errors:**
- Missing capabilities
- Missing trait bounds
- Absent methods on wrong state types

**Runtime Checks:**
- Policy validation (required policies satisfied?)
- Sanitization logic (does input meet criteria?)

Compile-time errors are preferred wherever possible.

### Static Analysis (Lints)

Even with safe APIs, developers might:
- Import raw sinks directly
- Copy unsafe patterns

Therefore, custom lints (via Dylint) catch:
- Direct use of raw sinks
- Attempts to forge capabilities
- Taint tracking bypasses

See [`dylint/README.md`](dylint/README.md) for enforcement pack documentation.

---

## Integration Patterns

### Web Framework Integration

The `web` module provides framework-agnostic integration:

1. **Extract request metadata** → `RequestMeta`
2. **Mark all inputs as tainted** → `Tainted<T>`
3. **Validate policies** → `Ctx<Authorized>` (via `PolicyGate`)
4. **Sanitize inputs** → `Verified<T>`
5. **Perform operations** with capabilities from `Ctx`

**Example flow:**
```rust
fn handler(req: HttpRequest) -> Result<Response> {
    // 1. Extract
    let meta = RequestAdapter::extract_metadata(&req);
    let inputs = RequestAdapter::extract_tainted_inputs(&req);

    // 2. Validate
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("process"))
        .build()?;

    // 3. Sanitize
    let sanitizer = StringSanitizer::new(256);
    let verified_input = sanitizer.sanitize(inputs.body)?;

    // 4. Operate with capabilities
    ctx.log().info("Processing request");
    ctx.http().post(verified_url, &verified_input)?;

    Ok(Response::ok())
}
```

---

## What This Crate Is Not

`policy-core` does **not** attempt to:
- Be a complete authentication system
- Replace web frameworks
- Automatically infer trust or sanitization
- Hide all complexity from developers
- Provide policy-as-data DSLs
- Be opinionated about storage engines

If it isn't about **compile-time enforcement**, it's out of scope.

---

## Design Validation

A design is considered sound if:

- Privileged actions are impossible without proof (capabilities)
- Tainted data cannot silently flow into sinks
- Capabilities cannot be forged
- Bypass requires deliberate, visible effort
- The compiler provides helpful errors

These invariants guide all architectural decisions.

---

## Further Reading

- [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md) - Why these design choices were made
- [dylint/README.md](dylint/README.md) - Static analysis enforcement
- [API Documentation](https://docs.rs/policy-core) - Detailed type documentation
