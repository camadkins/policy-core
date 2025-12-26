# Design Philosophy

This document explains why `policy-core` is designed the way it is, including the problems it solves, alternatives considered, and tradeoffs accepted.

## The Problem

Across real-world systems, policy enforcement failures follow a common pattern:

- Authorization logic is scattered throughout the codebase
- Context is implicit or accessed through globals
- Dangerous operations are callable without proof of authorization
- Sanitization is optional and inconsistently applied
- Audit logging is retrofitted late or never implemented

These failures don't happen because developers are careless. They happen because **the system makes the wrong thing easy**.

`policy-core` exists to reverse that incentive structure.

---

## Core Insight

> **Policy enforcement fails when it relies on convention instead of structure.**

If enforcement depends on:
- Remembering to check a flag
- Calling the right helper function
- Following documentation
- Code review catching mistakes

Then it will eventually fail.

`policy-core` enforces policy by **construction**, not discipline. The type system makes incorrect usage difficult or impossible.

---

## Design Decisions

### Why Explicit Context (`Ctx`)?

**Alternative Considered: Global or Thread-Local Context**

Many frameworks use global or thread-local state for the current user, request ID, etc.

**Why we rejected it:**
- Dependencies are invisible in function signatures
- Difficult to audit authority flow
- Easy to misuse in async/concurrent code
- Encourages "just grab what you need" behavior

**Our Approach: Explicit `Ctx`**

All privileged actions require a `Ctx` value passed explicitly as a parameter.

**Benefits:**
- Authority dependencies are visible in function signatures
- Call graphs accurately reflect privilege requirements
- Testing is simpler and more honest
- The compiler enforces proper propagation
- No spooky action at a distance

Yes, this is more verbose. That's intentional—authority should be visible.

---

### Why Capabilities Instead of Roles?

**Alternative Considered: Boolean Flags or Role Strings**

Traditional approaches use:
- `is_admin: bool`
- `has_permission("log")`
- Role-based access control with string comparisons

**Why we rejected them:**
- Easy to forge (`is_admin = true`)
- Easy to forget to check
- Hard to prove correctness statically
- Stringly-typed (typos, case sensitivity)

**Our Approach: Typed Capabilities**

Capabilities are **typed proof objects** (like `LogCap`, `HttpCap`, `AuditCap`).

If you have one, you're authorized. If you don't, you cannot proceed.

**Benefits:**
- No runtime branching on permission checks
- No string-based access control
- No ambient authority
- Enforced by the type system
- Cannot be forged outside the crate

This design mirrors successful patterns in OS kernels and capability-secure systems.

**Example:**
```rust
// This function MUST have LogCap to call - the type system ensures it
fn log_message(cap: LogCap, message: &str) {
    // ...
}
```

---

### Why Wrap Sinks Instead of Trusting Documentation?

**Alternative Considered: "Just Use the API Correctly"**

The traditional approach relies on:
- Developer memory
- Good documentation
- Code review
- Good intentions

**Why this fails:**
- Copy/paste bypasses safeguards
- New contributors miss context
- Time pressure favors shortcuts
- Documentation gets outdated

**Our Approach: Wrapped, Capability-Gated Sinks**

Dangerous operations (logging, database, HTTP, etc.) are wrapped in types that require capabilities.

**Benefits:**
- Enforcement is unavoidable
- Redaction happens automatically
- Taint rules are centralized
- Violations fail loudly and early
- Raw sinks can be detected by lints

**Example:**
```rust
// PolicyLog wraps logging and requires LogCap
let log = ctx.log();  // Only works if ctx has LogCap
log.info("Message");  // Secrets automatically redacted
```

---

### Why Taint Types Instead of Validation Functions?

**Alternative Considered: Runtime Validation Helpers**

Traditional approaches provide functions like:
- `validate_sql(input)` → boolean
- `sanitize_html(input)` → String

**Why they were rejected:**
- Easy to forget to call
- Easy to apply inconsistently
- No enforcement that results are actually used
- Trust boundaries not visible in types

**Our Approach: `Tainted<T>` → `Verified<T>`**

Untrusted data is **structurally restricted** until validated.

- External inputs are wrapped in `Tainted<T>`
- Sinks only accept `Verified<T>`
- The transition requires explicit sanitization

**Benefits:**
- Unsafe data flows don't compile
- Sanitization is explicit and visible
- Reviewers can see trust boundaries in types
- The compiler enforces discipline

**Example:**
```rust
let user_input = Tainted::new(raw_string);  // From external source
let sanitizer = StringSanitizer::new(256);
let verified = sanitizer.sanitize(user_input)?;  // Explicit validation
sink.sink(&verified)?;  // Only accepts Verified<T>

// This doesn't compile:
// sink.sink(&user_input)?;  // Error: expected Verified, got Tainted
```

---

### Why Compile-Time Enforcement Over Runtime Checks?

**Alternative Considered: Runtime Authorization Everywhere**

Traditional systems check authorization at runtime:
```rust
if !user.is_authorized("log") {
    return Err("Unauthorized");
}
```

**Why this is problematic:**
- Failures occur late (in production)
- Tests often miss edge cases
- Developers may disable checks under pressure
- Easy to forget the check entirely

**Our Approach: Compile-Time First**

We prefer:
- Missing methods (method only exists on `Ctx<Authorized>`)
- Unsatisfied trait bounds
- Type mismatches

Over:
- Runtime panics
- `Err(Unauthorized)` returns
- Log warnings

Runtime checks exist only where static enforcement is impossible (e.g., checking if a specific user has a specific permission for a specific resource).

**Example:**
```rust
// This method only exists on Ctx<Authorized>, not Ctx<Unauthed>
fn process(ctx: &Ctx<Authorized>) {
    ctx.log().info("Authorized");  // Compile-time guarantee
}
```

---

## Why This Feels Different

This crate intentionally:
- Adds friction
- Requires explicit choices
- Forces developers to confront policy decisions
- Uses more types and longer signatures

That friction is a **feature**, not a bug.

If using the crate feels "too strict," it's probably doing its job correctly.

---

## Tradeoffs We Accept

The following downsides are accepted knowingly:

**Costs:**
- More boilerplate
- Steeper learning curve
- More types to understand
- Longer function signatures
- Occasional complex compiler errors

**Benefits:**
- Stronger correctness guarantees
- Earlier failure detection
- Better auditability
- Fewer production security incidents
- Clearer authority boundaries

We optimize for **long-term safety** over short-term convenience.

---

## What This Crate Is NOT

`policy-core` does **not** attempt to:

- Be a complete authentication system
- Replace your web framework
- Automatically infer trust or sanitization
- Eliminate all runtime checks
- Provide policy-as-data DSLs
- Make unsafe operations convenient

If a use case requires weakening enforcement to improve convenience, this crate is not the right tool.

---

## Intended Usage

Correct usage of `policy-core` is:
- **Explicit** - Authority is visible in signatures
- **Deliberate** - Policy decisions are conscious
- **Defensive** - Assume inputs are hostile
- **Slightly inconvenient** - Safety has a cost

Users are expected to:
- Pass context explicitly through call chains
- Handle policy validation failures
- Sanitize inputs consciously
- Accept compiler guidance on safety

This may feel different from typical Rust libraries. That's intentional.

---

## Guidance for Contributors

Before proposing changes, consider:

1. **Does this make bypass easier?**
   - If yes, the change is likely wrong

2. **Does this weaken compile-time guarantees?**
   - Avoid moving enforcement to runtime

3. **Does this hide authority or capabilities?**
   - Keep privilege visible

4. **Does this make unsafe data flows compile?**
   - Unsafe should not compile

5. **Does this reduce explicitness?**
   - Explicitness is a feature

If a proposed change conflicts with these principles, it should be carefully justified.

---

## Comparison with Other Approaches

### vs. Middleware/Decorators
Middleware operates at runtime and uses conventions. `policy-core` uses compile-time types.

### vs. Aspect-Oriented Programming
AOP hides cross-cutting concerns. `policy-core` makes authority explicit.

### vs. Effect Systems
Effect systems track capabilities implicitly. `policy-core` makes them explicit parameters.

### vs. Dependent Types
Dependent types can encode richer properties. `policy-core` uses practical Rust type system features.

---

## Real-World Inspiration

This design draws from:

- **Capability-based security** (E language, Capsicum)
- **Type-state patterns** (Rust API design)
- **Taint tracking** (Perl tainting, information flow control)
- **Principle of Least Privilege** (security research)
- **Secure by default** (Rust philosophy)

---

## Final Principle

> **If policy enforcement can be bypassed accidentally, it will be bypassed eventually.**

`policy-core` ensures that bypass requires:
- **Intent** - You must deliberately work around it
- **Effort** - It won't happen by accident
- **Visibility** - It's obvious in code review

Security through type system enforcement, not convention.

---

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture and core components
- [README.md](README.md) - Quick start and examples
- [dylint/README.md](dylint/README.md) - Static analysis enforcement
