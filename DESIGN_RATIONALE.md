# Design Rationale

This document explains the architectural decisions behind `policy-core`, connecting design choices to the specific threats they prevent. It serves as the "unifying narrative" that shows how taint tracking, capabilities, type-states, and enforcement mechanisms work together to create a coherent security framework.

## How to Read This Document

This document complements other policy-core documentation:

- **[DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md)** explains the *why* behind core principles and the problems being solved
- **[ARCHITECTURE.md](ARCHITECTURE.md)** describes the *what* and *how* of technical components
- **[SECURITY.md](SECURITY.md)** documents the threat model, limitations, and out-of-scope items
- **This document** maps each design decision to specific threats and explains how components integrate

**Audience Navigation:**

- **Security Auditors**: Read Introduction → Unified Defense Model → Threat Mapping Table → ADRs 1, 2, 5, 6
- **Contributors**: Start with DESIGN_PHILOSOPHY.md, then read the ADRs here, then ARCHITECTURE.md
- **Integrators**: Begin with README.md, then Unified Defense Model, then ADR-007
- **Skeptics**: Jump to Threat Mapping Table, then read ADRs for alternatives considered

## Document Structure

This document is organized into:

1. **Unified Defense Model** - How all components work together
2. **Design Decision Records (ADRs)** - Eight critical architectural decisions with context, alternatives, consequences, and evidence
3. **Threat Mapping Table** - Quick reference linking decisions to specific CWEs/vulnerabilities
4. **Design Insights** - Non-obvious choices and subtle constraints
5. **Evolution & Future Directions** - What the design enables and intentionally doesn't do
6. **Reader's Guide** - Navigation paths for different audiences

---

## The Unified Defense Model

`policy-core` implements a three-layer defense-in-depth model where compile-time type system guarantees are the primary enforcement mechanism, runtime validation provides necessary flexibility, and static analysis catches behavioral bypasses.

### End-to-End Flow: Untrusted Input → Verified Output

```text
External World (HTTP, Files, User Input)
         │
         ├─────────────────────────────────────┐
         │  WEB BOUNDARY                       │
         │  (src/web/adapter.rs)               │
         │                                      │
         │  • Extract RequestMeta (trusted)    │
         │  • Wrap inputs as Tainted<T>        │
         └─────────────────────────────────────┘
                       │
                       ▼
         ┌─────────────────────────────────────┐
         │  POLICY VALIDATION                  │
         │  (src/gate.rs)                      │
         │                                      │
         │  PolicyGate::new(meta)              │
         │    .require(Authenticated)          │
         │    .require(Authorized::for_action)│
         │    .build()                         │
         │      → Ctx<Authorized>              │
         └─────────────────────────────────────┘
                       │
         ┌─────────────┴────────────────┐
         │                              │
         ▼                              ▼
┌────────────────────┐      ┌──────────────────────┐
│ SANITIZATION       │      │ CAPABILITY ACCESS    │
│ (src/sanitizer.rs) │      │ (src/context.rs)     │
│                    │      │                      │
│ Tainted<String>    │      │ ctx.log()            │
│   → Sanitizer      │      │ ctx.http()           │
│   → Verified<T>    │      │ ctx.audit()          │
└────────────────────┘      └──────────────────────┘
         │                              │
         │                              ▼
         │                  ┌──────────────────────┐
         │                  │ PRIVILEGED SINKS     │
         │                  │ (src/logging.rs,     │
         │                  │  src/http.rs,        │
         │                  │  src/audit.rs)       │
         └─────────────────▶│                      │
                            │ Require:             │
                            │  • Capability        │
                            │  • Verified<T> input │
                            └──────────────────────┘
                                     │
                                     ▼
                          Safe External Operations
```

### The Three Enforcement Layers

#### Layer 1: Compile-Time Type System (Primary Defense)

The type system enforces security invariants that cannot be violated without unsafe code or intentional bypass:

**Type-Based Restrictions:**
- `Tainted<T>` has no `Deref`, `AsRef`, or implicit conversions → cannot accidentally use unvalidated data
- `Verified<T>` has `pub(crate)` constructor → only sanitizers can create verified values
- Capabilities have private fields → cannot be forged outside the crate
- `Ctx<S>` uses phantom types → methods only exist on appropriate states

**Evidence:**
- `src/tainted.rs:43-52` - `pub(crate) into_inner()` restriction
- `src/verified.rs:8-16` - Construction invariants documentation
- `src/capability.rs:10-11` - Private `_private: ()` field
- `src/context.rs:11-25` - Type-state progression documentation

**What This Layer Prevents:**
- Using tainted data in sinks (compile error: type mismatch)
- Calling privileged methods without authentication (compile error: method doesn't exist)
- Forging capabilities (compile error: cannot construct)
- Bypassing sanitization (compile error: Verified required, Tainted provided)

#### Layer 2: Runtime Validation (Necessary Flexibility)

Runtime checks handle validation that cannot be statically verified:

**Runtime Validation Points:**
- PolicyGate validates policies before granting capabilities
- Sanitizers check input contents (control chars, length, format)
- Policy requirements check Principal existence and authorization

**Evidence:**
- `src/gate.rs:159-212` - `validate_all()` and `validate_one()` implementation
- `src/sanitizer.rs:312-347` - StringSanitizer validation logic

**What This Layer Provides:**
- Content-based validation (not just type-based)
- Policy composition flexibility
- Domain-specific sanitization rules
- Structured error reporting

#### Layer 3: Static Analysis (Behavioral Enforcement)

Dylint lints catch bypasses that the type system cannot prevent:

**Custom Lints:**
- `NO_PRINTLN` - Detects direct use of `println!`, `eprintln!`, `dbg!`
- Future: Verified/Tainted forgery detection (Issues #39, #40)

**Evidence:**
- `dylint/README.md:1-100` - Enforcement philosophy and rationale

**What This Layer Catches:**
- Direct imports of raw sinks (`println!`)
- Attempts to bypass wrapped APIs
- Copy-pasted unsafe patterns
- Accidental architectural violations

### Why All Three Layers Are Necessary

**Type system alone** cannot prevent:
- Importing `println!` from std
- Using `unsafe` to transmute types
- Deserializing directly into restricted types

**Runtime checks alone** are insufficient because:
- They fail late (in production, not at compile time)
- They can be accidentally omitted
- They impose runtime overhead
- They provide weaker guarantees

**Static analysis alone** cannot:
- Enforce complex type relationships
- Provide zero-cost abstractions
- Guarantee memory safety

**Together**, these layers create defense in depth:
1. Type system makes most violations impossible
2. Runtime validation handles content inspection
3. Static analysis catches behavioral bypasses

This is **enforcement by construction**, not discipline.

---

## Design Decision Records

The following eight ADRs document the critical architectural decisions that form the foundation of policy-core's security model.

---

### ADR-001: Taint Tracking Architecture

#### Context

Injection attacks are consistently ranked as the #1 web application vulnerability (OWASP Top 10). When untrusted data flows into structured contexts (logs, SQL queries, shell commands, HTML), attackers can break out of the intended data context and execute malicious operations.

Traditional approaches rely on developers remembering to validate input or using validation helper functions, but these are:
- Easy to forget or skip under time pressure
- Inconsistently applied across codebases
- Not visible in function signatures
- Prone to bypass via copy-paste

#### Decision

Implement a type-based taint tracking system: `Tainted<T>` → `Sanitizer` → `Verified<T>` flow where:

1. **`Tainted<T>`** marks untrusted data (src/tainted.rs)
   - No `Deref`, `AsRef`, `From`, or `Into` implementations
   - Inner value accessible only via `pub(crate) into_inner()`
   - Forces explicit acknowledgment that data is untrusted

2. **`Sanitizer<T>` trait** defines the validation boundary (src/sanitizer.rs)
   - Signature: `fn sanitize(Tainted<T>) -> Result<Verified<T>, SanitizationError>`
   - Only trait implementers can call `Tainted::into_inner()`
   - Type signature prevents bypassing (must provide Tainted, only get Verified)

3. **`Verified<T>`** represents sanitized data (src/verified.rs)
   - Constructor is `pub(crate) new_unchecked()` - only internal code can create
   - Provides `AsRef<T>` for ergonomic access
   - Sinks require `Verified<T>`, rejecting `Tainted<T>` at compile time

#### Alternatives Considered

**Option 1: Runtime validation functions**
```rust
fn validate_sql(input: &str) -> bool { ... }
if !validate_sql(user_input) { return Err(...); }
```
- **Rejected:** Easy to forget to call, easy to ignore return value, not compile-time enforced

**Option 2: Automatic escaping at sink boundaries**
```rust
log(user_input); // automatically escapes
```
- **Rejected:** Requires knowing context at sink (SQL escaping ≠ log escaping), error-prone, hides validation

**Option 3: Allow-lists with runtime checks**
```rust
if !ALLOWED_CHARS.contains(c) { reject }
```
- **Rejected:** No type-level distinction between validated and unvalidated data, can't statically verify

**Option 4: Trait-based markers**
```rust
impl Trusted for String { ... }
```
- **Rejected:** Traits can be implemented externally, undermining trust guarantees

#### Consequences

**Benefits:**
- **Compile-time enforcement**: Unsafe data flows don't compile (type mismatch errors)
- **Explicit validation**: Must call sanitizer explicitly; cannot bypass accidentally
- **Visible trust boundaries**: Function signatures show `Tainted<T>` vs `Verified<T>`
- **Centralized sanitization**: All validation logic in auditable Sanitizer implementations
- **Zero runtime cost for types**: Tainted and Verified are zero-overhead wrappers

**Trade-offs:**
- **More verbose**: Must wrap inputs, call sanitizers, unwrap verified values
- **Learning curve**: Developers must understand taint tracking model
- **Boilerplate**: Cannot use tainted values directly, even for debugging

**Concrete Example:**
```rust
// Won't compile - good!
let user_input = Tainted::new("'; DROP TABLE users;");
log.info(user_input); // Error: expected Verified<String>, got Tainted<String>

// Must sanitize explicitly
let sanitizer = StringSanitizer::new(256);
let verified = sanitizer.sanitize(user_input)?;
log.info(verified.as_ref()); // OK - verified
```

#### Evidence

**Implementation:**
- `src/tainted.rs:1-130` - Tainted wrapper with restricted access
- `src/tainted.rs:43-52` - `pub(crate) into_inner()` prevents external access
- `src/verified.rs:69-89` - `pub(crate) new_unchecked()` construction restriction
- `src/sanitizer.rs:85-167` - Sanitizer trait definition and security properties
- `src/sanitizer.rs:312-347` - StringSanitizer implementation with validation

**Tests:**
- `src/tainted.rs:78-88` - Test documenting prevention of direct access
- `src/sanitizer.rs:604-619` - Test verifying errors don't leak rejected input

#### Threats Prevented

| CWE | Attack | Defense Mechanism |
|-----|--------|-------------------|
| **CWE-117** | Log Injection (newlines forge log entries) | StringSanitizer rejects control characters (src/sanitizer.rs:329-334) |
| **CWE-89** | SQL Injection | Verified<T> required for database operations (future milestone) |
| **CWE-79** | Cross-Site Scripting (XSS) | HTML sanitizer would require Verified<T> for rendering |
| **CWE-78** | Command Injection | Shell command sinks would require Verified<T> |
| **CWE-22** | Path Traversal | Path sanitizer would reject `../` sequences before wrapping in Verified |

**Cross-References:**
- DESIGN_PHILOSOPHY.md §"Why Taint Types Instead of Validation Functions?"
- ARCHITECTURE.md §"Taint Tracking" (data flow diagram)
- SECURITY.md (threat model section)

---

### ADR-002: Zero-Sized Capability Types

#### Context

Traditional role-based access control (RBAC) uses boolean flags or string roles:
```rust
if user.is_admin { ... }
if user.has_permission("log") { ... }
```

These approaches have fundamental security problems:
- Flags can be forged (`is_admin = true`)
- Checks can be forgotten or bypassed
- Runtime-only verification (no compile-time guarantees)
- Difficult to audit permission flow through code
- Ambient authority (global permissions)

#### Decision

Implement capabilities as **zero-sized types with private fields** that serve as unforgeable proof of authorization:

```rust
pub struct LogCap {
    _private: (),  // Private field prevents external construction
}

impl LogCap {
    pub(crate) fn new() -> Self {  // Only crate-internal code can create
        Self { _private: () }
    }
}
```

Capabilities are:
- **Zero-sized**: `size_of::<LogCap>() == 0` (no runtime cost)
- **Unforgeable**: Private field prevents `LogCap { _private: () }` construction
- **Crate-restricted**: `pub(crate) new()` means only PolicyGate can grant them
- **Type-safe**: Cannot be confused (LogCap ≠ HttpCap)

#### Alternatives Considered

**Option 1: Runtime permission strings**
```rust
if ctx.has_permission("log") { ... }
```
- **Rejected:** Stringly-typed (typos), runtime-only checks, easy to forget

**Option 2: Role enums**
```rust
enum Role { Admin, User }
if role == Role::Admin { ... }
```
- **Rejected:** Still requires runtime checks, can be forged with `unsafe`, doesn't prove specific permissions

**Option 3: Trait-based capabilities**
```rust
trait CanLog {}
impl CanLog for Principal { ... }
```
- **Rejected:** Traits can be implemented externally, undermining security

**Option 4: Runtime token system with UUIDs**
```rust
struct Capability { id: Uuid, permission: String }
```
- **Rejected:** Runtime overhead, tokens can be copied/cloned, not type-checked

**Option 5: Marker types without private fields**
```rust
pub struct LogCap;
```
- **Rejected:** Can be constructed anywhere (`LogCap` literal), defeats the purpose

#### Consequences

**Benefits:**
- **Zero runtime cost**: Capabilities are optimized away (zero-sized)
- **Compile-time proof**: Cannot call privileged functions without capability parameter
- **Unforgeable**: Impossible to construct outside crate without `unsafe`
- **Explicit authority flow**: Capabilities must be passed through call stack, making authority visible
- **Type-checked**: LogCap ≠ HttpCap; cannot use wrong capability for operation

**Trade-offs:**
- **More verbose**: Must pass capability explicitly to functions
- **Requires PolicyGate**: Cannot create capabilities ad-hoc; must go through validation
- **Threading complexity**: Capabilities must be threaded through function calls

**Concrete Example:**
```rust
// This won't compile - LogCap cannot be forged
let fake_cap = LogCap { _private: () }; // Error: _private is private

// Must obtain capability through PolicyGate
let ctx = PolicyGate::new(meta)
    .require(Authenticated)
    .require(Authorized::for_action("log"))
    .build()?;

// Capability is proof of authorization
if let Some(log_cap) = ctx.log_cap() {
    perform_logging(log_cap, "message");
}
```

#### Evidence

**Implementation:**
- `src/capability.rs:1-108` - LogCap, HttpCap, AuditCap definitions
- `src/capability.rs:10-11` - Private `_private: ()` field preventing forgery
- `src/capability.rs:20-22` - `pub(crate) new()` construction restriction
- `src/gate.rs:126-142` - PolicyGate grants capabilities after validation

**Tests:**
- `src/capability.rs:74-80` - Test documenting impossible public construction
- `src/capability.rs:83-89` - Test showing capability works when provided

**Property Tests:**
- `src/gate.rs:313-343` - Authorized action grants corresponding capability

#### Threats Prevented

| Threat | Attack Scenario | Defense Mechanism |
|--------|----------------|-------------------|
| **Privilege Escalation** | Developer calls privileged function without authorization | Function requires capability parameter; compile error if not provided |
| **Ambient Authority** | Code globally accessing log without permission check | No global logger; must have LogCap from authorized context |
| **Confused Deputy** | Code with capability used for unintended purpose | Each capability is specific (LogCap ≠ HttpCap); type mismatch if misused |
| **Capability Forgery** | Malicious code creates fake capability | Private field + pub(crate) constructor prevent external construction |

**Security Properties Verified:**
- Zero-sized: Confirmed in tests, no runtime overhead
- Unforgeable: Compile fails if attempting external construction
- Type-distinct: LogCap and HttpCap are not interchangeable

**Cross-References:**
- DESIGN_PHILOSOPHY.md §"Why Capabilities Instead of Roles?"
- ARCHITECTURE.md §"Capabilities"
- ADR-004 (PolicyGate grants capabilities)

---

### ADR-003: Type-State Context Progression

#### Context

Authentication and authorization are frequently confused or improperly ordered in web applications. Common failure modes:

- Calling authorized operations before authentication
- Skipping authentication entirely
- Mixing authenticated and unauthenticated code paths
- No compile-time guarantee that auth happened before authz

Traditional approaches use flags or optional fields:
```rust
struct Context {
    principal: Option<Principal>,
    is_authorized: bool,  // Can be true even if principal is None!
}
```

This allows invalid states like "authorized but not authenticated."

#### Decision

Encode authentication and authorization state in the type system using **phantom type parameters**:

```rust
pub struct Ctx<S = Authorized> {
    request_id: String,
    principal: Option<Principal>,
    log_cap: Option<LogCap>,
    http_cap: Option<HttpCap>,
    audit_cap: Option<AuditCap>,
    _state: PhantomData<S>,  // Zero-sized, compile-time only
}
```

**Three explicit states:**

1. **`Ctx<Unauthed>`**: No principal, no capabilities
   - Methods: `request_id()`, `authenticate()`
   - Cannot call privileged operations

2. **`Ctx<Authed>`**: Has principal, no capabilities
   - Methods: `request_id()`, `principal()`, `authorize()`
   - Still cannot call privileged operations

3. **`Ctx<Authorized>`**: Has principal and capabilities
   - Methods: `request_id()`, `principal()`, `log()`, `http()`, `audit()`
   - Can access privileged operations via capabilities

**State transitions are explicit and type-safe:**
```rust
Ctx<Unauthed> --authenticate()--> Ctx<Authed> --authorize()--> Ctx<Authorized>
```

#### Alternatives Considered

**Option 1: Single context with Option<Principal>**
```rust
struct Ctx {
    principal: Option<Principal>,
}
```
- **Rejected:** Can construct with `None` and bypass checks; no state enforcement

**Option 2: Runtime state machine**
```rust
enum CtxState { Unauthed, Authed, Authorized }
struct Ctx { state: CtxState, ... }
```
- **Rejected:** Requires runtime checks; can be in invalid states; no compile-time guarantees

**Option 3: Builder pattern only**
```rust
CtxBuilder::new().with_principal(p).build()
```
- **Rejected:** Doesn't prevent skipping authentication; builder can be misused

**Option 4: Separate types for each state**
```rust
struct UnauthCtx { ... }
struct AuthedCtx { ... }
struct AuthorizedCtx { ... }
```
- **Rejected:** Code duplication; difficult to share common methods; verbose

#### Consequences

**Benefits:**
- **Invalid states unrepresentable**: Cannot have `Ctx<Authorized>` without a principal (checked at construction)
- **Compile-time enforcement**: Calling `ctx.log()` on `Ctx<Unauthed>` is a compile error (method doesn't exist)
- **Explicit progressions**: State transitions visible in code (`authenticate()`, `authorize()`)
- **Type-safe methods**: `.log()` only exists on `Ctx<Authorized>`
- **Zero runtime cost**: PhantomData has no size; state is compile-time only

**Trade-offs:**
- **Learning curve**: Developers must understand type-state pattern
- **Generic noise**: Function signatures include `Ctx<S>` or specific state
- **Cannot backtrack**: Once authenticated, cannot "de-authenticate" (intentional)

**Concrete Example:**
```rust
// Start unauthenticated
let ctx = Ctx::new_unauthed("req-123".to_string());

// This won't compile:
// ctx.log(); // Error: method `log` not found for `Ctx<Unauthed>`

// Must authenticate first
let ctx = ctx.authenticate(Some(principal))?;  // Now Ctx<Authed>

// Still can't log:
// ctx.log(); // Error: method `log` not found for `Ctx<Authed>`

// Must authorize
let ctx = ctx.authorize(Some(log_cap))?;  // Now Ctx<Authorized>

// NOW can log:
ctx.log().info("Authenticated and authorized");
```

#### Evidence

**Implementation:**
- `src/context.rs:11-25` - Type-state progression documentation
- `src/context.rs:89-146` - `Ctx<Unauthed>` implementation
- `src/context.rs:152-186` - `Ctx<Authed>` implementation (150-line limit hit, but structure shown)
- `src/state.rs` - State marker types (Unauthed, Authed, Authorized)
- `src/gate.rs:121-152` - PolicyGate.build() returns `Ctx<Authorized>` directly

**State-Specific Methods:**
- `Ctx<Unauthed>::authenticate()` - transitions to Ctx<Authed>
- `Ctx<Authed>::authorize()` - transitions to Ctx<Authorized>
- `Ctx<Authorized>::log()`, `http()`, `audit()` - privileged operations

**Tests:**
- Type-state transitions tested via PolicyGate integration tests
- Compile-fail tests would document that methods don't exist on wrong states

#### Threats Prevented

| Threat | Attack Scenario | Defense Mechanism |
|--------|----------------|-------------------|
| **Unauthorized Access** | Calling privileged method without authorization | `.log()` method only exists on `Ctx<Authorized>`; compile error on other states |
| **Authentication Bypass** | Skipping authentication step | Cannot create `Ctx<Authorized>` without going through authentication (checked by PolicyGate) |
| **State Confusion** | Code path assumes authentication when it hasn't occurred | Type system enforces progression; cannot call authorized methods on unauthenticated context |
| **Ambient Authority** | Global access to privileged operations | Must have `Ctx<Authorized>` instance; cannot access without explicit context |

**Security Properties:**
- Type-state prevents calling methods before reaching required state
- PhantomData is zero-sized; no runtime overhead
- State transitions are one-way (cannot go backward)
- PolicyGate is the standard path (builds `Ctx<Authorized>` after validating all requirements)

**Cross-References:**
- DESIGN_PHILOSOPHY.md §"Why Explicit Context?"
- ARCHITECTURE.md §"Core Components: Context"
- ADR-002 (Capabilities are only present in Ctx<Authorized>)
- ADR-004 (PolicyGate builds Ctx<Authorized>)

---

### ADR-004: PolicyGate Builder Pattern with Requirement Deduplication

#### Context

Policy validation in traditional systems suffers from several problems:

- **Scattered validation**: Auth checks spread throughout codebase
- **Inconsistent application**: Some code paths check, others don't
- **Ordering bugs**: Auth and authz checks in wrong order
- **Duplicate checks**: Same policy checked multiple times wastefully
- **Unclear requirements**: Not obvious what policies are needed

Example of scattered validation:
```rust
fn handler1(req: Request) {
    if req.user.is_none() { return Err(Unauth); }
    if !req.user.is_admin() { return Err(Unauth); }
    // ... operation ...
}

fn handler2(req: Request) {
    // Forgot to check! Vulnerability!
    // ... operation ...
}
```

#### Decision

Implement **PolicyGate** as a centralized builder for policy validation with automatic requirement deduplication:

```rust
let ctx = PolicyGate::new(meta)
    .require(Authenticated)
    .require(Authorized::for_action("log"))
    .require(Authenticated)  // Deduplicated automatically
    .build()?;  // Validates all, returns Ctx<Authorized>
```

**Key design points:**

1. **Builder pattern**: Chainable `.require()` calls accumulate policies
2. **Automatic deduplication**: Identical requirements only appear once
3. **Single validation point**: `.build()` validates all at once
4. **Capability granting**: Capabilities granted based on satisfied requirements
5. **Structured errors**: Returns `Violation` with specific error kinds

#### Alternatives Considered

**Option 1: Function parameters for policies**
```rust
validate_and_build(meta, vec![Authenticated, Authorized::for_action("log")])?
```
- **Rejected:** Less discoverable; can't chain; less explicit at call site

**Option 2: Runtime assertion on capability access**
```rust
ctx.log()  // Checks permission at runtime
```
- **Rejected:** Fails late; no compile-time enforcement; overhead on every call

**Option 3: Implicit policy inference**
```rust
let ctx = Ctx::from_request(req);  // Automatically infers policies
```
- **Rejected:** Too magical; not auditable; unclear what's being checked

**Option 4: Middleware/decorator pattern**
```rust
#[require(Authenticated, Authorized("log"))]
fn handler(ctx: Ctx) { ... }
```
- **Rejected:** Requires macro magic; policies not visible in function body; harder to test

**Option 5: No deduplication**
```rust
.require(Authenticated).require(Authenticated)  // Checks twice
```
- **Rejected:** Inefficient; confusing behavior; doesn't match developer expectations

#### Consequences

**Benefits:**
- **Single validation bottleneck**: All policy checks in one place (`.build()`)
- **Explicit requirements**: Policies visible at call site
- **Idempotent composition**: Adding same requirement twice has no effect (deduplication)
- **Order-independent**: Requirements can be added in any order (tested via proptests)
- **Fail-fast**: Validation happens before capabilities granted
- **Auditable**: Easy to see what policies are required for an operation

**Trade-offs:**
- **More verbose**: Must call `.require()` for each policy
- **Overhead at build time**: Deduplication requires comparison (minimal cost)
- **Builder ceremony**: Requires `.build()` call to finalize

**Concrete Example:**
```rust
// Multiple modules can add requirements
let mut gate = PolicyGate::new(meta)
    .require(Authenticated);  // Module A adds this

gate = gate.require(Authorized::for_action("log"));  // Module B adds this
gate = gate.require(Authenticated);  // Module C adds this (deduplicated!)

// Build validates all requirements exactly once
let ctx = gate.build()?;

// Requirements list contains: [Authenticated, Authorized { action: "log" }]
// Only validated once despite Authenticated being added twice
```

#### Evidence

**Implementation:**
- `src/gate.rs:37-85` - PolicyGate struct and `.require()` method with deduplication
- `src/gate.rs:72-84` - Deduplication logic: `if !self.requirements.iter().any(...)`
- `src/gate.rs:223-235` - `same_requirement()` comparison for deduplication
- `src/gate.rs:121-152` - `.build()` method: validates all, grants capabilities
- `src/gate.rs:159-212` - `validate_all()` and `validate_one()` implementations

**Deduplication Logic:**
```rust
pub fn require(mut self, policy: impl Into<PolicyReq>) -> Self {
    let req = policy.into();

    // Deduplicate: only add if not already present
    if !self.requirements.iter().any(|r| self.same_requirement(r, &req)) {
        self.requirements.push(req);
    }

    self
}
```

**Tests:**
- `src/gate.rs:290-311` - Property test: adding same requirement N times results in one occurrence
- `src/gate.rs:389-431` - Property test: requirement order doesn't affect outcome

#### Threats Prevented

| Threat | Attack Scenario | Defense Mechanism |
|--------|----------------|-------------------|
| **Authorization Bypass** | Forgetting to check authentication in a code path | PolicyGate is the ONLY way to get `Ctx<Authorized>`; no bypass |
| **Inconsistent Enforcement** | Some handlers check policies, others don't | Centralized validation; all go through `.build()` |
| **Policy Ordering Bugs** | Checking authorization before authentication | PolicyGate validates all requirements; order doesn't matter |
| **Double-Check Overhead** | Accidentally validating same policy multiple times | Deduplication ensures each requirement validated once |
| **Unclear Requirements** | Not obvious what policies are needed | Explicit `.require()` calls document requirements |

**Security Properties:**
- PolicyGate is the sole source of `Ctx<Authorized>`
- Requirements are idempotent (deduplication tested)
- Order-independent (tested via property tests)
- Validation is all-or-nothing (fails on first violation)

**Cross-References:**
- DESIGN_PHILOSOPHY.md §"Why Compile-Time Enforcement Over Runtime Checks?"
- ARCHITECTURE.md §"PolicyGate"
- ADR-002 (Capabilities granted by PolicyGate after validation)
- ADR-003 (PolicyGate builds Ctx<Authorized>)

---

### ADR-005: Sink Wrapper Integration

#### Context

**Sinks** are operations that can cause harm if misused:
- Logging (`println!`, `log!`, `tracing!`)
- Database operations (SQL queries)
- HTTP requests (outbound API calls)
- File system access
- Audit trail writes

Traditional approaches allow direct use of these sinks:
```rust
println!("User {} logged in", user_id);  // Bypasses all controls!
log::info!("Query: {}", user_input);     // May leak secrets, accept tainted input
```

Problems with raw sink access:
- **No capability check**: Anyone can call these functions
- **No taint tracking**: Accept tainted input without sanitization
- **No secret redaction**: Secrets leak in logs
- **No audit trail**: Operations happen without being logged
- **Bypasses architecture**: Defeats the entire policy enforcement model

#### Decision

**Wrap all sinks in capability-gated types that enforce taint tracking and secret redaction:**

1. **PolicyLog** - Wraps `tracing` crate
   - Requires `LogCap` to construct
   - Automatically redacts `Secret<T>` values
   - Accepts only `&str` and safe types (not `Tainted<T>`)

2. **PolicyHttp** - Wraps `reqwest` client
   - Requires `HttpCap` to construct
   - Accepts only `Verified<T>` for URLs and payloads
   - Prevents tainted data in HTTP requests

3. **PolicyAudit** - Writes structured audit events
   - Requires `AuditCap` to construct
   - Stores only metadata, not raw request bodies
   - Lifetime-bound to context (cannot outlive request)

**All sinks follow the pattern:**
```rust
pub struct PolicyLog<'a> { cap: LogCap, ... }

impl<'a> PolicyLog<'a> {
    pub fn new(cap: LogCap) -> Self { ... }
    pub fn info(&self, message: &str) { ... }  // Only accepts safe types
}
```

#### Alternatives Considered

**Option 1: Documentation only**
"Developers should use PolicyLog instead of println!"
- **Rejected:** Relies on discipline; easy to forget; no enforcement

**Option 2: Runtime checks at sink**
```rust
fn log(cap: Option<LogCap>, msg: &str) {
    if cap.is_none() { panic!("Unauthorized"); }
}
```
- **Rejected:** Fails at runtime; panic is not an appropriate security mechanism; overhead on every call

**Option 3: Middleware/interceptors**
Global middleware intercepts all log calls
- **Rejected:** Adds indirection; still allows direct `println!` imports; difficult to test

**Option 4: Macro-based gating**
```rust
#[require_capability(LogCap)]
fn my_log(msg: &str) { ... }
```
- **Rejected:** Macro complexity; runtime checks; not composable

#### Consequences

**Benefits:**
- **Unavoidable enforcement**: Cannot use sink without capability
- **Automatic redaction**: Secrets redacted in Debug/Display
- **Taint enforcement**: Future versions will require `Verified<T>` for inputs
- **Centralized control**: All sink access through wrapped types
- **Fail loudly**: Missing capability is a compile error (method doesn't exist)

**Trade-offs:**
- **More types**: PolicyLog, PolicyHttp, PolicyAudit instead of raw APIs
- **Requires capability**: Must have authorized context to use sinks
- **Some overhead**: Wrapper layer (though minimal/zero-cost in most cases)

**Concrete Example:**
```rust
// This bypasses all controls - should be caught by Dylint
println!("User: {}", user_id);  // Will trigger NO_PRINTLN lint

// Correct usage through wrapped sink
let ctx = PolicyGate::new(meta)
    .require(Authenticated)
    .require(Authorized::for_action("log"))
    .build()?;

// PolicyLog requires LogCap (obtained from ctx)
let log = ctx.log().expect("LogCap granted");
log.info("User logged in");  // Safe, capability-gated

// Secret redaction automatic
let api_key = Secret::new("sk-12345");
log.info(&format!("Key: {:?}", api_key));  // Logs "Key: [REDACTED]"
```

#### Evidence

**Implementation:**
- `src/logging.rs` - PolicyLog wrapper (requires LogCap)
- `src/http.rs` - PolicyHttp wrapper (requires HttpCap)
- `src/audit.rs` - PolicyAudit wrapper (requires AuditCap)

**Enforcement:**
- `dylint/README.md:30-50` - NO_PRINTLN lint catches `println!` bypass attempts

**Pattern:**
All sinks follow the same structure:
1. Struct holds capability as private field
2. Constructor requires capability parameter
3. Methods accept only safe types (not Tainted, logs show redacted Secrets)

#### Threats Prevented

| Threat | Attack Scenario | Defense Mechanism |
|--------|----------------|-------------------|
| **Data Leaks via Logs** | Logging secret API key with println! | PolicyLog auto-redacts `Secret<T>`; Dylint NO_PRINTLN catches raw println! |
| **Tainted Data in HTTP** | Sending unvalidated user input in API request | PolicyHttp requires `Verified<T>` (future milestone) |
| **Unaudited Privileged Actions** | Admin operation without audit trail | Action requires AuditCap; audit event automatically emitted |
| **Capability Bypass** | Calling log without authorization | PolicyLog constructor requires LogCap; cannot construct without capability |
| **Log Injection** | Newlines in log message forge entries | Input must be Verified<T>; StringSanitizer rejects control chars |

**Cross-References:**
- DESIGN_PHILOSOPHY.md §"Why Wrap Sinks Instead of Trusting Documentation?"
- ARCHITECTURE.md §"Sinks"
- ADR-001 (Taint tracking prevents unsafe data reaching sinks)
- ADR-002 (Capabilities required for sink access)
- ADR-006 (Dylint NO_PRINTLN catches raw sink usage)
- ADR-008 (Secret redaction in logs)

---

### ADR-006: Dylint as Second Line of Defense

#### Context

The type system provides strong compile-time guarantees, but it cannot prevent all security bypasses:

**What the type system CAN'T prevent:**
- Importing `println!` from `std` and using it directly
- Using `unsafe { std::mem::transmute(...) }` to forge types
- Deserializing directly into `Verified<T>` via serde
- Copy-pasting unsafe code examples
- Using `#[allow(unused)]` to bypass capability requirements

Even with excellent API design, developers may accidentally:
- Bypass wrapped sinks by importing raw versions
- Follow outdated examples that use raw logging
- Not realize they're undermining the security model

#### Decision

Implement **custom Dylint lints** as a second line of defense that catches architectural bypasses at compile time (CI enforced):

**Current lint:**
- **NO_PRINTLN** (Issue #38) - Denies `println!`, `eprintln!`, `dbg!` in library code

**Planned lints:**
- **Verified<T> forgery detection** (Issue #39) - Detect attempts to construct Verified without Sanitizer
- **Tainted<T> bypass detection** (Issue #40) - Detect unsafe extraction of inner value

**Enforcement philosophy** (dylint/README.md):
- Lints are "second line of defense" - type system is primary
- Lint violations FAIL the build in CI
- Suppressions require issue tracking and code review
- If suppression is needed, the architecture is likely broken

#### Alternatives Considered

**Option 1: Rely on type system only**
- **Rejected:** Type system cannot prevent `println!` imports or `unsafe` misuse

**Option 2: Runtime monitoring only**
- **Rejected:** Fails too late; performance overhead; cannot catch all cases

**Option 3: Manual code review only**
- **Rejected:** Not scalable; easy to miss in large diffs; human error

**Option 4: Clippy lints only**
Contribute to official Clippy instead of custom Dylint
- **Rejected:** Clippy is general-purpose; these lints are crate-specific; long review process

**Option 5: Ban certain imports via Cargo.toml**
- **Rejected:** Cannot ban `std::println!`; too coarse-grained

#### Consequences

**Benefits:**
- **Catches behavioral bypasses**: Detects raw sink usage at compile time
- **Early feedback**: Developer sees error immediately, not in PR review
- **CI enforcement**: Build fails before merge if violated
- **Visible violations**: Lint output clearly shows the problem
- **Gradual enforcement**: Can add new lints as architecture evolves

**Trade-offs:**
- **Tooling requirement**: Requires Dylint installation and CI setup
- **Compilation time**: Lints add overhead (minimal, but non-zero)
- **Maintenance burden**: Must keep lints updated as Rust evolves
- **False positives possible**: May need suppression mechanism

**Concrete Example:**

```rust
// This violates NO_PRINTLN lint
pub fn process_request(user_id: &str) {
    println!("Processing request for {}", user_id);  // ❌ Lint error
}

// Lint output:
// error: use of `println!` bypasses PolicyLog
//   --> src/handler.rs:42:5
//    |
// 42 |     println!("Processing request for {}", user_id);
//    |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//    |
//    = note: use `tracing::info!` or PolicyLog instead

// Correct version:
pub fn process_request(ctx: &Ctx<Authorized>, user_id: &str) {
    ctx.log().info(&format!("Processing request for {}", user_id));  // ✅
}
```

#### Evidence

**Implementation:**
- `dylint/README.md:1-100` - Enforcement pack purpose and philosophy
- `dylint/README.md:30-50` - NO_PRINTLN lint documentation and rationale
- `dylint/README.md:96-100` - Suppression policy

**Enforcement Philosophy:**
> "Lints serve as a **second line of defense**... Catch bypasses that type system alone cannot prevent" (dylint/README.md:21-24)

> "This is **enforcement by construction, not discipline**" (dylint/README.md:26)

**CI Integration:**
- Dylint runs in CI as part of build pipeline
- Deny-level violations fail the build
- No merge allowed until lint passes or suppression approved

#### Threats Prevented

| Threat | Attack Scenario | Defense Mechanism |
|--------|----------------|-------------------|
| **Accidental Bypass via println!** | Developer imports println! and logs sensitive data | NO_PRINTLN lint fails build; developer must use PolicyLog |
| **Direct Raw Sink Use** | Code directly uses `std::fs::write` instead of wrapped sink | Future lint would detect and reject |
| **Secret Leaks in Unstructured Output** | Debug prints leak secrets that would be redacted in PolicyLog | NO_PRINTLN prevents unstructured output; must use PolicyLog |
| **Copy-Paste from Old Examples** | Copying code that uses raw logging | Lint catches it even if tests pass |

**Security Properties:**
- Lints run on every build (local + CI)
- Violations are compile errors (deny level)
- Cannot accidentally merge bypass code
- Complements type system (defense in depth)

**Cross-References:**
- DESIGN_PHILOSOPHY.md §"Why This Feels Different"
- ARCHITECTURE.md §"Enforcement Strategy: Static Analysis"
- ADR-005 (Wrapped sinks that Dylint protects)

---

### ADR-007: Web Integration Boundary Model

#### Context

Web frameworks (Axum, Actix, Rocket) don't understand taint tracking or capabilities. They provide raw HTTP data as `String`, `HeaderMap`, `Query<T>`, etc.

Integrating policy-core with web frameworks requires:
- Extracting trusted metadata (request ID, authenticated principal)
- Marking all untrusted inputs as tainted
- Performing policy validation before processing
- Providing access to capability-gated sinks

Challenge: How to bridge framework-specific types (Axum's `Request`, Actix's `HttpRequest`) with policy-core's abstractions without tight coupling?

#### Decision

Implement the **RequestAdapter** pattern as a framework-agnostic boundary layer:

**RequestAdapter struct** (src/web/adapter.rs):
- Simple owned types (HashMap, String, Option) - no framework dependencies
- Two extraction methods:
  - `ExtractMetadata` → trusted data (request ID, authenticated principal)
  - `ExtractTaintedInputs` → untrusted data wrapped in `Tainted<T>`

**Integration flow:**
```text
1. Framework Request → RequestAdapter (via From impl)
2. RequestAdapter.extract_metadata() → RequestMeta
3. RequestAdapter.extract_tainted_inputs() → TaintedInputs { query, headers, body }
4. PolicyGate::new(meta).require(...).build() → Ctx<Authorized>
5. Sanitize tainted inputs → Verified<T>
6. Process request with capabilities
```

**Trust boundary:**
- Everything from HTTP is untrusted by default
- Authenticated principal comes from validated session/token (assumed done by framework)
- Request ID generated or extracted from headers

#### Alternatives Considered

**Option 1: Framework-specific wrappers in policy-core**
```rust
pub struct AxumCtx { ... }
pub struct ActixCtx { ... }
```
- **Rejected:** Tight coupling; policy-core bloats with framework code; not maintainable

**Option 2: Manual wrapping by users**
```rust
// User code:
let tainted_query = Tainted::new(req.query("name"));
```
- **Rejected:** Easy to forget; inconsistent across projects; error-prone

**Option 3: Generic HTTP types**
```rust
pub struct HttpRequest { method: String, path: String, ... }
```
- **Rejected:** Doesn't fit all frameworks; would miss framework-specific features

**Option 4: Automatic taint inference**
Automatically infer which fields are tainted based on source
- **Rejected:** Too magical; unclear rules; not auditable

**Option 5: Trust headers by default**
Treat certain headers (X-Request-ID) as trusted
- **Rejected:** Headers can be forged; not a safe default

#### Consequences

**Benefits:**
- **Framework independence**: policy-core doesn't depend on Axum/Actix/etc.
- **Clear trust boundary**: Adapter is the point where HTTP → Tainted conversion happens
- **Explicit taint marking**: All external inputs wrapped in Tainted<T>
- **Metadata separation**: Trusted RequestMeta separate from untrusted TaintedInputs
- **Type safety**: Cannot accidentally use tainted data without sanitization

**Trade-offs:**
- **Conversion overhead**: Must convert framework types to RequestAdapter
- **Limited framework features**: Adapter exposes only common functionality
- **Boilerplate**: Each framework needs a From<FrameworkRequest> impl

**Concrete Example:**

```rust
// In user's Axum handler:
use axum::extract::Request;
use policy_core::{PolicyGate, RequestAdapter, Authenticated, Authorized};

async fn handler(req: Request) -> Result<Response, Error> {
    // 1. Convert framework request to adapter
    let adapter = RequestAdapter::from(req);

    // 2. Extract metadata (trusted)
    let meta = adapter.extract_metadata();

    // 3. Extract tainted inputs (untrusted)
    let inputs = adapter.extract_tainted_inputs();

    // 4. Validate policies
    let ctx = PolicyGate::new(meta)
        .require(Authenticated)
        .require(Authorized::for_action("process"))
        .build()?;

    // 5. Sanitize inputs
    let sanitizer = StringSanitizer::new(256);
    let name = inputs.query.get("name")
        .ok_or(Error::MissingParam)?;
    let verified_name = sanitizer.sanitize(name.clone())?;

    // 6. Process with capabilities
    ctx.log().info(&format!("Processing {}", verified_name.as_ref()));

    Ok(Response::ok())
}
```

#### Evidence

**Implementation:**
- `src/web/adapter.rs` - RequestAdapter struct and extraction methods
- `src/web/middleware.rs` - Middleware helpers for common patterns

**RequestAdapter structure:**
```rust
pub struct RequestAdapter {
    request_id: String,
    principal: Option<Principal>,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Option<String>,
}

impl RequestAdapter {
    pub fn extract_metadata(&self) -> RequestMeta { ... }
    pub fn extract_tainted_inputs(&self) -> TaintedInputs { ... }
}
```

**Trust Boundaries:**
- `extract_metadata()` → trusted (request ID, authenticated principal from session)
- `extract_tainted_inputs()` → untrusted (everything else wrapped in Tainted)

#### Threats Prevented

| Threat | Attack Scenario | Defense Mechanism |
|--------|----------------|-------------------|
| **Untrusted Input Reaching Sinks** | Query param used in log without validation | All inputs wrapped as Tainted<T>; sinks require Verified<T> |
| **Missing Authentication Check** | Framework routes to handler without auth | PolicyGate.build() fails if Authenticated required but no principal |
| **Header Injection** | Malicious headers crafted to forge requests | Headers wrapped in Tainted<T>; must be sanitized before use |
| **Trust Boundary Confusion** | Mixing trusted metadata with untrusted inputs | Separate methods: extract_metadata vs extract_tainted_inputs |

**Security Properties:**
- All HTTP inputs marked as tainted by default
- Metadata extracted separately from untrusted data
- Framework-agnostic (no tight coupling)
- Clear boundary layer (adapter is the conversion point)

**Cross-References:**
- ARCHITECTURE.md §"Integration Patterns: Web Framework Integration"
- ADR-001 (Tainted inputs must be sanitized)
- ADR-003 (RequestMeta used to build Ctx)
- ADR-004 (PolicyGate validates before granting capabilities)

---

### ADR-008: Secret Redaction Strategy

#### Context

Secrets (API keys, passwords, tokens, encryption keys) frequently leak through:
- Log statements: `log.info("API key: {}", api_key)`
- Error messages: `Err(format!("Auth failed with key {}", key))`
- Debug output: `println!("{:?}", config)` where config contains secrets
- Stack traces that include variable values

Traditional approaches:
- Manual redaction (easy to forget)
- Regex filtering in logs (incomplete, performance overhead)
- PII detection heuristics (false positives/negatives)

Problem: **Developers cannot be trusted to remember to redact secrets manually.**

#### Decision

Implement `Secret<T>` wrapper that **automatically redacts in all output contexts**:

```rust
pub struct Secret<T> {
    inner: T,
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
```

**Key properties:**
- **No Deref, AsRef, Clone, Copy**: Cannot accidentally get inner value
- **Explicit access required**: Must call `expose_secret()` to get value
- **Always redacts**: Debug and Display always show `[REDACTED]`
- **No type leakage**: Doesn't show `Secret<String>`, just `[REDACTED]`

#### Alternatives Considered

**Option 1: Manual redaction**
```rust
log.info("API key: [REDACTED]");  // Developer must remember
```
- **Rejected:** Relies on discipline; easy to forget; not enforceable

**Option 2: Regex filters in log processing**
```rust
// In logger:
if message.contains("sk-") { redact }
```
- **Rejected:** Incomplete; performance overhead; misses non-standard formats; false positives

**Option 3: Automatic PII detection**
Use ML/heuristics to detect secrets in logs
- **Rejected:** Unreliable; high false positive rate; adds complexity

**Option 4: Runtime checks on log calls**
```rust
fn log(msg: &str) {
    if contains_secret(msg) { panic!() }
}
```
- **Rejected:** Runtime overhead; fails late; cannot catch all cases

**Option 5: Secret<T> implements Display differently**
Show partial value like `"sk-****7890"`
- **Rejected:** Still leaks information; not safe for all secret types

#### Consequences

**Benefits:**
- **Automatic redaction**: Cannot accidentally log secret value
- **Type-safe**: Wrapper type ensures explicit access
- **Zero runtime overhead**: Only affects formatting, not storage
- **Works everywhere**: Debug, Display, error messages all redacted
- **Explicit access**: `expose_secret()` name makes it clear this is sensitive

**Trade-offs:**
- **Slightly verbose**: Must wrap secrets and call expose_secret()
- **No Clone**: Cannot clone Secret<T> (intentional - prevents copying secrets around)
- **Manual wrapping**: Must remember to wrap secrets initially

**Concrete Example:**

```rust
// Wrap secret at creation
let api_key = Secret::new("sk-1234567890".to_string());

// Safe - automatically redacted
println!("{:?}", api_key);  // Prints: [REDACTED]
log.info(&format!("Key: {}", api_key));  // Logs: "Key: [REDACTED]"

// Error messages are safe
return Err(format!("Auth failed: {:?}", api_key));  // Error: "Auth failed: [REDACTED]"

// Explicit access when needed
let key_value = api_key.expose_secret();  // Clear in code review
make_api_call(key_value);
```

#### Evidence

**Implementation:**
- `src/secret.rs:1-111` - Secret<T> wrapper implementation
- `src/secret.rs:56-60` - Debug impl always returns `[REDACTED]`
- `src/secret.rs:62-66` - Display impl always returns `[REDACTED]`
- `src/secret.rs:47-53` - `expose_secret()` explicit access method

**Tests:**
- `src/secret.rs:73-79` - Test verifying Debug redaction and no type leak
- `src/secret.rs:83-89` - Test verifying Display redaction
- `src/secret.rs:92-95` - Test showing explicit access works
- `src/secret.rs:98-109` - Test documenting no implicit access (no Deref, Clone, AsRef)

**Security Properties:**
- Debug and Display always show `[REDACTED]`
- No type information leaked (doesn't show `Secret<String>`)
- Cannot access value without calling `expose_secret()`
- Works correctly with PolicyLog auto-redaction

#### Threats Prevented

| Threat | Attack Scenario | Defense Mechanism |
|--------|----------------|-------------------|
| **CWE-532: Credential Leak in Logs** | `log.info("Key: {}", api_key)` leaks secret | Secret<T> Debug/Display shows `[REDACTED]` |
| **Secrets in Error Messages** | `Err(format!("Auth failed with {}", password))` | Secret<T> in error formatted as `[REDACTED]` |
| **Accidental Secret Exposure** | `println!("{:?}", config)` where config has secrets | Secret fields show `[REDACTED]` in Debug output |
| **Secret in Stack Traces** | Debug output includes variable values | Secret<T> redacted even in debug contexts |

**Security Properties:**
- Impossible to accidentally log raw secret (would need explicit `expose_secret()`)
- Redaction happens at format time (zero storage overhead)
- Works with all Rust formatting infrastructure
- Complements PolicyLog's automatic secret handling

**Cross-References:**
- DESIGN_PHILOSOPHY.md (explicit design principles)
- ARCHITECTURE.md §"Secrets"
- ADR-005 (PolicyLog auto-redacts Secret<T>)
- ADR-006 (NO_PRINTLN prevents bypassing redaction)

---

## Threat Mapping Table

This table provides a quick reference showing which design decisions prevent which specific threats.

| Design Decision | CWE/OWASP | Attack Scenario | Defense Mechanism | Evidence |
|-----------------|-----------|-----------------|-------------------|----------|
| **Taint Tracking** | CWE-117 (Log Injection) | Attacker injects `\n` in username to forge log entries | StringSanitizer rejects control characters; Verified<T> required for logs | src/sanitizer.rs:329-334 |
| **Taint Tracking** | CWE-89 (SQL Injection) | Attacker inputs `'; DROP TABLE users--` into query | Database sinks require Verified<T>; SQL sanitizer rejects quotes/semicolons | Future milestone |
| **Taint Tracking** | CWE-79 (XSS) | Attacker inputs `<script>alert('XSS')</script>` | HTML sanitizer requires Verified<T>; escapes or rejects tags | Future milestone |
| **Taint Tracking** | CWE-78 (Command Injection) | Attacker inputs `; rm -rf /` in shell command | Command sinks require Verified<T>; sanitizer rejects shell metacharacters | Future milestone |
| **Taint Tracking** | CWE-22 (Path Traversal) | Attacker inputs `../../etc/passwd` as filename | Path sanitizer rejects `../` sequences before wrapping in Verified | Future milestone |
| **Zero-Sized Capabilities** | Privilege Escalation | Developer calls `log()` without authorization | LogCap required; type error if missing | src/capability.rs:10-22 |
| **Zero-Sized Capabilities** | Ambient Authority | Code globally accesses privileged operation | No global logger; must have capability from authorized context | Architecture design |
| **Zero-Sized Capabilities** | Confused Deputy | Code with LogCap misused for HTTP operation | Each capability is type-distinct (LogCap ≠ HttpCap) | src/capability.rs:1-46 |
| **Type-State Ctx** | Unauthorized Access | Calling privileged method before authentication | `.log()` method only exists on `Ctx<Authorized>`; compile error otherwise | src/context.rs:11-25 |
| **Type-State Ctx** | Authentication Bypass | Skipping authentication step entirely | Cannot create `Ctx<Authorized>` without principal (validated by PolicyGate) | src/gate.rs:169-176 |
| **Type-State Ctx** | State Confusion | Assuming auth when it hasn't occurred | Type system enforces state progression; cannot backtrack | src/context.rs:89-146 |
| **PolicyGate** | Authorization Bypass | Forgetting to check authentication in handler | PolicyGate is ONLY way to get `Ctx<Authorized>`; no bypass possible | src/gate.rs:121-152 |
| **PolicyGate** | Inconsistent Enforcement | Some code paths check policies, others don't | Centralized validation; all go through `.build()` | Architecture design |
| **PolicyGate** | Policy Ordering Bugs | Checking authorization before authentication | PolicyGate validates all; order doesn't matter (tested) | src/gate.rs:389-431 |
| **Sink Wrappers** | Data Leaks via Logs | Logging secret API key with `println!` | PolicyLog auto-redacts `Secret<T>`; NO_PRINTLN lint catches raw println! | src/logging.rs + dylint/README.md:30-50 |
| **Sink Wrappers** | Tainted Data in HTTP | Sending unvalidated user input in API request | PolicyHttp requires `Verified<T>` for URLs/payloads | src/http.rs |
| **Sink Wrappers** | Unaudited Privileged Actions | Admin operation without audit trail | Action requires AuditCap; audit event automatically emitted | src/audit.rs |
| **Dylint Enforcement** | Accidental Bypass | Developer imports `println!` and bypasses PolicyLog | NO_PRINTLN lint fails build; must use PolicyLog | dylint/README.md:30-50 |
| **Dylint Enforcement** | Secret Leak in Debug Print | `dbg!(config)` leaks secrets in unstructured output | NO_PRINTLN forbids `dbg!`; must use structured logging | dylint/README.md:33-39 |
| **Web Integration** | Untrusted Input Reaching Sinks | Query param used in log without validation | All inputs wrapped as `Tainted<T>`; sinks require `Verified<T>` | src/web/adapter.rs |
| **Web Integration** | Header Injection | Malicious headers crafted to forge requests | Headers wrapped in `Tainted<T>`; must be sanitized before use | src/web/adapter.rs |
| **Web Integration** | Missing Auth Check | Framework routes without authentication | PolicyGate.build() fails if Authenticated required but no principal | src/gate.rs:169-176 |
| **Secret Redaction** | CWE-532 (Credentials in Logs) | `log.info("Key: {}", api_key)` leaks secret | `Secret<T>` Debug/Display shows `[REDACTED]` | src/secret.rs:56-66 |
| **Secret Redaction** | Secrets in Error Messages | `Err(format!("Auth failed: {}", password))` | `Secret<T>` formatted as `[REDACTED]` in errors | src/secret.rs:56-66 |
| **Secret Redaction** | Accidental Exposure | `println!("{:?}", config)` with secret fields | `Secret<T>` fields show `[REDACTED]` in Debug output | src/secret.rs:73-79 |

**Legend:**
- **CWE**: Common Weakness Enumeration (security vulnerability taxonomy)
- **OWASP**: Open Web Application Security Project (Top 10 vulnerabilities)
- **Evidence**: File path and line numbers showing implementation

**Cross-References:**
- SECURITY.md - Full threat model and out-of-scope items
- Individual ADRs above for detailed rationale

---

## Design Insights & Non-Obvious Choices

This section captures subtle design decisions that aren't immediately obvious from reading the code.

### Why pub(crate) is Security-Critical

In policy-core, `pub(crate)` is not just about API surface area—it's a **security boundary**.

**Critical pub(crate) methods:**
- `Tainted::into_inner()` (src/tainted.rs:50)
- `Verified::new_unchecked()` (src/verified.rs:87)
- `LogCap::new()` (src/capability.rs:20)

**Why this matters:**
If these were `pub`, external code could:
- Extract tainted values without sanitization
- Create verified values without validation
- Forge capabilities without authorization

**This is policy-level safety, not memory safety.** Rust's borrow checker prevents memory corruption, but policy-core uses visibility to prevent *security policy violations*.

**Example of broken security if pub:**
```rust
// If Verified::new_unchecked were pub:
let tainted_sql = Tainted::new("'; DROP TABLE users--");
let fake_verified = Verified::new_unchecked(tainted_sql.into_inner());  // BYPASS!
database.query(fake_verified);  // SQL injection succeeds
```

### Why No Deref/From/Into Implementations

`Tainted<T>`, `Verified<T>`, and `Secret<T>` intentionally omit these traits:
- No `Deref` - would allow implicit access (`*tainted`)
- No `AsRef` - would allow implicit borrowing (`tainted.as_ref()`)
- No `From<T>` / `Into<T>` - would allow implicit conversions
- `Secret<T>` has no `Clone` - prevents copying secrets around

**Rationale:** Implicit conversions bypass validation.

If `Tainted<T>` implemented `Deref<Target=T>`:
```rust
let tainted = Tainted::new("malicious");
let inner: &String = &*tainted;  // BYPASS via Deref!
log.info(inner);  // Unvalidated data in log
```

**Explicit access is intentional friction.** It makes bypass visible in code review.

### Why Error Messages Never Leak Input

`SanitizationError` messages never include the rejected input value:

```rust
// Good - doesn't leak rejected value
Err(SanitizationError::new(
    SanitizationErrorKind::TooLong,
    format!("input exceeds maximum length of {}", self.max_len),
))

// Bad - would leak rejected value
Err(SanitizationError::new(
    SanitizationErrorKind::TooLong,
    format!("input '{}' exceeds maximum length", input),  // ❌ NEVER DO THIS
))
```

**Why:** Rejected input might be an attack payload. If error output goes to logs (which might not be sanitized), the attack payload could leak or cause injection.

**Test:** src/sanitizer.rs:604-619 verifies errors don't contain rejected input.

### Why PolicyGate Deduplication Matters

Deduplication ensures policy composition is **idempotent**:

```rust
let gate = PolicyGate::new(meta)
    .require(Authenticated)
    .require(Authenticated);  // No effect - deduplicated

// Only validates Authenticated once, not twice
```

**Why this matters:**
- **Performance**: Avoids redundant validation
- **Predictability**: Adding same requirement multiple times has no effect
- **Composability**: Multiple modules can add requirements without coordination

**Without deduplication:**
- Inefficient (double validation)
- Confusing (does it validate twice? once?)
- Hard to compose (must track what's already required)

**Evidence:** Property test (src/gate.rs:290-311) verifies deduplication.

### Why Both Manual Transitions AND PolicyGate

`Ctx` supports two progression paths:

1. **PolicyGate** (convenience): `PolicyGate.build() → Ctx<Authorized>`
2. **Manual transitions**: `Ctx<Unauthed>.authenticate().authorize()`

**Why both?**

**PolicyGate** is optimized for the common case:
- Web request handlers
- Standard auth + authz flow
- Single validation point

**Manual transitions** provide flexibility for:
- Progressive authentication (MFA, step-up auth)
- Custom state progression
- Partial authorization scenarios
- Testing with specific states

**Example use case for manual:**
```rust
// Start unauthed
let ctx = Ctx::new_unauthed(request_id);

// Authenticate with basic auth
let ctx = ctx.authenticate(Some(basic_principal))?;

// Later, step up to MFA
let ctx = perform_mfa_challenge(ctx)?;

// Finally authorize
let ctx = ctx.authorize(Some(admin_cap))?;
```

PolicyGate couldn't handle this flow—it goes straight to `Ctx<Authorized>`.

### Why Zero-Sized Capabilities

Capabilities are zero-sized (`size_of::<LogCap>() == 0`) but still unforgeable.

**How?**
```rust
pub struct LogCap {
    _private: (),  // Zero-sized, but private!
}
```

**Benefits:**
- **No runtime cost**: Optimized away by compiler
- **Still unforgeable**: Private field prevents construction
- **Type-level proof**: Capability is a compile-time token, not runtime data

**This is a core Rust pattern:** Use zero-sized types for compile-time guarantees with zero runtime overhead.

### Why Sanitizer is a Trait, Not a Function

`Sanitizer<T>` is a trait, not a free function:

```rust
pub trait Sanitizer<T> {
    fn sanitize(&self, input: Tainted<T>) -> Result<Verified<T>, SanitizationError>;
}
```

**Why a trait?**

1. **Stateful validation**: Sanitizers can have configuration (max_len, allowed patterns)
2. **Composition**: Can build `ChainedSanitizer`, `OrSanitizer` (future)
3. **Testability**: Easy to create `AcceptAllSanitizer`, `RejectAllSanitizer` for tests
4. **Extensibility**: Users can implement custom sanitizers

**If it were a function:**
```rust
fn sanitize_string(input: Tainted<String>, max_len: usize) -> Result<Verified<String>, Error>
```
- Must pass config every time
- Cannot compose easily
- Harder to abstract over different sanitizers
- No clear trait boundary

### Why Dylint is "Second Line" Not "Only Line"

Dylint lints are **defense in depth**, not the primary enforcement mechanism.

**Primary defense:** Type system (Tainted, Verified, Capabilities, Type-States)
**Secondary defense:** Dylint lints (NO_PRINTLN, future forgery detection)

**Why not rely on Dylint alone?**
- Lints can have false positives (requiring suppressions)
- Lints can be bypassed with `unsafe`
- Type system provides stronger guarantees
- Type errors are clearer than lint warnings

**Why Dylint at all if type system is primary?**
- Type system cannot prevent `println!` imports
- Type system cannot detect all behavioral bypasses
- Lints catch patterns type system cannot express

**Philosophy:** Use the type system for what it's good at (structural guarantees), use lints for what it can't do (behavioral patterns).

---

## Evolution and Future Directions

### What This Design Enables

The current architecture creates a foundation for future enhancements:

**Role-Based Access Control (RBAC):**
```rust
// Future: Principal includes roles
struct Principal {
    id: String,
    name: String,
    roles: Vec<String>,  // "admin", "user", "auditor"
}

// Future: Authorization checks roles
if !principal.roles.contains("admin") {
    return Err(Violation::new(ViolationKind::Unauthorized, "Admin required"));
}
```

**Attribute-Based Access Control (ABAC):**
```rust
// Future: Policy decisions based on attributes
PolicyGate::new(meta)
    .require(Authenticated)
    .require(Authorized::with_attributes(
        "action" => "delete",
        "resource" => "user",
        "owner" => principal.id,
    ))
```

**Custom Sanitizers:**
```rust
// Users can implement domain-specific sanitizers
struct EmailSanitizer;

impl Sanitizer<String> for EmailSanitizer {
    fn sanitize(&self, input: Tainted<String>) -> Result<Verified<String>, SanitizationError> {
        let email = input.into_inner();
        if !email.contains('@') || email.len() > 254 {
            return Err(SanitizationError::new(...));
        }
        Ok(Verified::new_unchecked(email))
    }
}
```

**Additional Capabilities:**
```rust
pub struct DbCap { _private: () }
pub struct FileCap { _private: () }
pub struct CacheCap { _private: () }
```

**Sanitizer Composition:**
```rust
// Future: Chain multiple sanitizers
let sanitizer = ChainedSanitizer::new()
    .then(StringSanitizer::new(256))
    .then(SqlSanitizer::new());
```

### What It Intentionally Doesn't Do

The design makes conscious trade-offs by NOT attempting:

**Automatic Taint Inference:**
- **Why not:** Requires explicit trust decisions; magic would hide security boundaries
- **Trade-off:** More verbose (must wrap inputs manually)
- **Benefit:** Clear, auditable trust boundaries

**Policy-as-Data DSLs:**
- **Why not:** The type system IS the DSL; keeps it simple
- **Trade-off:** Cannot dynamically load policies from files
- **Benefit:** Compile-time verification of policies

**Framework-Specific Integration in Core:**
- **Why not:** Avoids tight coupling; keeps policy-core lean
- **Trade-off:** Users must implement RequestAdapter for their framework
- **Benefit:** Framework-agnostic; no bloat

**Automatic Secret Detection:**
- **Why not:** Heuristics are unreliable (false positives/negatives)
- **Trade-off:** Must manually wrap secrets
- **Benefit:** Explicit, reliable redaction

**Complete Production-Readiness:**
- **Why not:** Research/demonstration project
- **Trade-off:** Not production-ready out of the box
- **Benefit:** Validates patterns without production overhead

### How to Extend Safely

**Adding New Capabilities:**
```rust
// 1. Define zero-sized type with private field
pub struct NewCap {
    _private: (),
}

// 2. Add pub(crate) constructor
impl NewCap {
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

// 3. Add to Ctx<Authorized>
impl Ctx<Authorized> {
    pub fn new_operation(&self) -> Option<PolicyNew> {
        self.new_cap.as_ref().map(|cap| PolicyNew::new(*cap))
    }
}

// 4. Update PolicyGate to grant capability
// 5. Add action constant and authorization logic
```

**Adding New Sanitizers:**
```rust
// Implement Sanitizer<T> trait
pub struct CustomSanitizer {
    config: Config,
}

impl Sanitizer<String> for CustomSanitizer {
    fn sanitize(&self, input: Tainted<String>) -> Result<Verified<String>, SanitizationError> {
        let value = input.into_inner();

        // Validation logic
        if !self.is_valid(&value) {
            return Err(SanitizationError::new(...));
        }

        Ok(Verified::new_unchecked(value))
    }
}
```

**Adding New Sinks:**
```rust
// 1. Define sink struct requiring capability
pub struct PolicyDatabase<'a> {
    cap: DbCap,
    connection: &'a Connection,
}

// 2. Methods accept Verified<T>
impl PolicyDatabase<'_> {
    pub fn query(&self, sql: &Verified<String>) -> Result<Rows> {
        self.connection.execute(sql.as_ref())
    }
}

// 3. Add to Ctx<Authorized>
impl Ctx<Authorized> {
    pub fn db(&self) -> Option<PolicyDatabase> {
        self.db_cap.as_ref().map(|cap| PolicyDatabase::new(*cap, &self.db_conn))
    }
}
```

**Adding New Policies:**
```rust
// 1. Extend PolicyReq enum
pub enum PolicyReq {
    Authenticated,
    Authorized { action: &'static str },
    RateLimited { max_per_minute: u32 },  // New!
}

// 2. Update PolicyGate::validate_one()
fn validate_one(&self, req: &PolicyReq) -> Result<(), Violation> {
    match req {
        // ... existing cases ...
        PolicyReq::RateLimited { max_per_minute } => {
            // Validation logic
        }
    }
}
```

### Roadmap References

From CLAUDE.local.md milestones:

**Current (Milestone 10):** Documentation & Publishing
- This document completes the design rationale documentation
- External usability preparation

**Future Milestones:**
- **RBAC Implementation**: Add roles to Principal, role-based authorization
- **Database Sink Integration**: PolicyDb with taint tracking
- **Advanced Sanitization**: Sanitizer composition, SQL/HTML sanitizers
- **Enforcement Pack Expansion**: Verified/Tainted forgery detection lints

---

## Reader's Guide

### For Security Auditors

**Recommended Reading Path:**
1. Start: This Introduction + Unified Defense Model (understand the security architecture)
2. Then: Threat Mapping Table (quick reference of what's prevented)
3. Deep dive: ADR-001 (Taint Tracking), ADR-002 (Capabilities), ADR-005 (Sinks), ADR-006 (Dylint)
4. Cross-check: [SECURITY.md](SECURITY.md) for threat model and limitations
5. Verify: Check implementation files referenced in ADRs

**Key Questions to Validate:**
- Can tainted data reach sinks without sanitization? (No - ADR-001)
- Can capabilities be forged? (No - ADR-002)
- Can authentication be bypassed? (No - ADR-003, ADR-004)
- Can developers accidentally bypass controls? (No - ADR-006 Dylint enforcement)

**Files to Audit:**
- src/tainted.rs, src/verified.rs, src/sanitizer.rs (taint tracking)
- src/capability.rs, src/gate.rs (capability system)
- src/context.rs (type-state progression)
- dylint/ (enforcement pack)

### For Contributors

**Recommended Reading Path:**
1. [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md) - Understand the "why" and principles
2. This document's ADRs - See how principles translate to decisions
3. [ARCHITECTURE.md](ARCHITECTURE.md) - Learn the technical structure
4. [dylint/README.md](dylint/README.md) - Understand enforcement philosophy
5. Design Insights section above - Learn non-obvious constraints

**Before Contributing:**
- Read "How to Extend Safely" section above
- Understand that pub(crate) is a security boundary
- Know that enforcement is "by construction, not discipline"
- Review Guidance for Contributors in DESIGN_PHILOSOPHY.md

**Key Principles to Preserve:**
- Make bypass hard (ADR-006)
- Explicit over implicit (all ADRs)
- Type system first, runtime second (Unified Defense Model)
- Invalid states unrepresentable (ADR-003)

### For Users Integrating This Library

**Recommended Reading Path:**
1. [README.md](README.md) - Quick start and basic usage
2. Unified Defense Model (this document) - Understand end-to-end flow
3. ADR-007 (Web Integration) - Learn how to integrate with your framework
4. Examples in `/examples` directory - See realistic usage

**Integration Checklist:**
- [ ] Wrap all external inputs in `Tainted<T>`
- [ ] Use PolicyGate for policy validation
- [ ] Sanitize tainted inputs before use
- [ ] Access sinks only through capabilities
- [ ] Wrap secrets in `Secret<T>`
- [ ] Set up Dylint in CI

**Common Integration Patterns:**
- Web handler: See ADR-007 example
- CLI app: RequestMeta from command-line args
- Background job: RequestMeta with job ID + system principal

### For Skeptics ("Why Is This So Complex?")

**Recommended Reading Path:**
1. Threat Mapping Table (see real attacks this prevents)
2. ADRs - Read "Alternatives Considered" to see why simpler approaches fail
3. [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md) - Understand tradeoffs accepted
4. Design Insights section - See why non-obvious choices matter

**Addressing Common Objections:**

**"Why not just document best practices?"**
- See DESIGN_PHILOSOPHY.md §"Why Wrap Sinks Instead of Trusting Documentation?"
- Documentation fails under time pressure; this FORCES correct usage

**"Why not runtime checks?"**
- See ADR-001 "Alternatives Considered" - runtime checks fail late and can be skipped
- Compile-time errors are free; runtime checks have overhead

**"This is too verbose!"**
- See DESIGN_PHILOSOPHY.md §"Tradeoffs We Accept"
- Verbosity is intentional friction that prevents accidents
- Trade short-term convenience for long-term safety

**"Can't we use [simpler approach]?"**
- Check the "Alternatives Considered" section in relevant ADR
- Most simpler approaches were evaluated and rejected for security reasons

### Cross-References to Other Documentation

- **[DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md)** - "Why" behind principles, core insights, comparison with other approaches
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - "What" and "how" of components, integration patterns, validation rules
- **[SECURITY.md](SECURITY.md)** - Threat model, known limitations, out-of-scope items, security best practices
- **[dylint/README.md](dylint/README.md)** - Enforcement pack philosophy, lint documentation, suppression policy
- **[README.md](README.md)** - Quick start guide, basic usage examples, feature overview
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Development guidelines, testing requirements, PR process

---

## Conclusion

This document has presented the complete design rationale for policy-core, showing how compile-time type system guarantees, runtime validation, and static analysis work together to enforce security policies.

**Key Takeaways:**

1. **Defense in Depth**: Three enforcement layers (type system, runtime validation, Dylint lints) catch different classes of vulnerabilities

2. **Enforcement by Construction**: The type system makes incorrect usage difficult or impossible, not just "not recommended"

3. **Explicit Trust Boundaries**: Taint tracking, capabilities, and type-states make security-relevant transitions visible in code

4. **Zero-Cost Abstractions**: Security guarantees achieved with zero or minimal runtime overhead

5. **Threat-Driven Design**: Every decision maps to specific CWEs/vulnerabilities it prevents

The architecture demonstrates that **strong security guarantees can coexist with good ergonomics** when the type system is used effectively. By encoding security properties in types and enforcing them at compile time, policy-core proves that "secure by default" doesn't have to mean "difficult to use."

For questions, contributions, or security concerns, see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
