# DESIGN_RATIONALE.md — Why This Policy Enforcement Crate Exists

## Purpose of This Document

This document explains **why** the policy enforcement crate is designed the way it is.

It records:
- The problems this crate is meant to solve
- The alternatives that were considered and rejected
- The tradeoffs that were consciously accepted
- The expectations placed on users and contributors

This document exists to prevent the system from being “simplified” into something unsafe.

If a proposed change conflicts with the reasoning here, the change should be rejected
unless the rationale itself is explicitly revised.

---

## Background: The Failure Pattern

Across real-world systems, policy failures follow the same pattern:

- Authorization logic is scattered
- Context is implicit or global
- Dangerous operations are callable without proof
- Sanitization is optional and inconsistently applied
- Audit logging is retrofitted late (or never)

These failures do not happen because developers are careless.
They happen because **the system makes the wrong thing easy**.

This crate exists to reverse that incentive structure.

---

## Core Insight

> **Policy enforcement fails when it relies on convention instead of structure.**

If enforcement depends on:
- “Remembering” to check a flag
- Calling the right helper
- Following documentation
- Code review vigilance

Then it will eventually fail.

This crate enforces policy by **construction**, not discipline.

---

## Why Explicit Context (`Ctx`)?

### Rejected Alternative: Global / Thread-Local Context
**Why it was rejected:**
- Invisible dependencies
- Difficult to audit
- Easy to misuse in async/concurrent code
- Encourages “just grab it” behavior

### Chosen Approach: Explicit `Ctx`
All privileged actions require a `Ctx` value passed explicitly.

**Benefits:**
- Dependencies are visible in function signatures
- Call graphs reflect authority
- Testing is simpler and more honest
- The compiler enforces propagation

Yes, it is more verbose. That is intentional.

---

## Why Capabilities Instead of Roles or Flags?

### Rejected Alternative: Roles / Booleans
Examples:
- `is_admin: bool`
- `has_permission("log")`

**Why they were rejected:**
- Easy to forge
- Easy to misuse
- Easy to forget to check
- Hard to prove correctness statically

### Chosen Approach: Capabilities
Capabilities are **typed proof objects**.

If you have one:
- You are authorized
If you do not:
- You cannot proceed

**Benefits:**
- No runtime branching on permissions
- No stringly-typed access control
- No ambient authority
- Enforced by the type system

This mirrors successful designs in OS kernels and capability-secure systems.

---

## Why Wrap Sinks Instead of Trusting Users?

### Rejected Alternative: “Just Use the API Correctly”
This relies on:
- Developer memory
- Documentation
- Code review
- Good intentions

**Why it fails:**
- Copy/paste bypasses safeguards
- New contributors miss context
- Pressure favors shortcuts

### Chosen Approach: Wrapped Sinks
Dangerous operations (logging, DB, HTTP, etc.) are wrapped and gated.

**Benefits:**
- Enforcement is unavoidable
- Redaction is automatic
- Taint rules are centralized
- Violations are loud and early

If a sink is not wrapped, the design is incomplete.

---

## Why Taint Types Instead of Runtime Validation Helpers?

### Rejected Alternative: Validation Functions
Examples:
- `validate_sql(input)`
- `sanitize_html(input)`

**Why they were rejected:**
- Easy to forget
- Easy to apply inconsistently
- No enforcement that results are used
- No visibility in types

### Chosen Approach: `Tainted<T>` → `Verified<T>`
Untrusted data is **structurally restricted** until validated.

**Benefits:**
- Unsafe flows do not compile
- Sanitization is explicit
- Reviewers can see trust boundaries
- The compiler enforces discipline

The goal is not convenience — it is correctness.

---

## Why Compile-Time Enforcement Over Runtime Checks?

### Rejected Alternative: Runtime Authorization Everywhere
**Why it was rejected:**
- Failures occur late
- Errors surface in production
- Tests often miss edge cases
- Developers disable checks under pressure

### Chosen Approach: Compile-Time First
Prefer:
- Missing methods
- Unsatisfied trait bounds
- Type mismatches

Over:
- Panics
- `Err(Unauthorized)`
- Log warnings

Runtime checks exist only where static enforcement is impossible.

---

## Why This Is Harder Than Typical Libraries

This crate intentionally:
- Adds friction
- Requires explicit choices
- Forces developers to confront policy decisions

That friction is a **feature**, not a flaw.

If using the crate feels “too strict,” that usually indicates
it is doing its job.

---

## Tradeoffs Accepted

The following downsides are accepted knowingly:

- More boilerplate
- Steeper learning curve
- More types
- Longer signatures
- Occasional compiler complexity

These are traded for:
- Stronger guarantees
- Earlier failure
- Better auditability
- Fewer production incidents

---

## What This Crate Is *Not*

This crate does **not** attempt to:
- Be an authentication provider
- Replace web frameworks
- Automatically infer trust
- Eliminate all runtime checks
- Provide policy DSLs
- Make unsafe things easy

If a use case requires weakening enforcement, this crate is not the right tool.

---

## Intended Usage Style

Correct usage is:
- Explicit
- Deliberate
- Defensive
- Slightly inconvenient

Developers are expected to:
- Pass context explicitly
- Handle policy failures
- Sanitize inputs consciously
- Accept compiler guidance

This crate optimizes for **long-term safety**, not short-term speed.

---

## Guidance for Future Changes

Before adding or modifying behavior, ask:

1. Does this make bypass easier?
2. Does this weaken compile-time guarantees?
3. Does this hide authority?
4. Does this make unsafe flows compile?
5. Does this reduce explicitness?

If the answer to any is “yes,” the change is likely wrong.

---

## Final Principle

> **If policy enforcement can be bypassed accidentally, it will be bypassed eventually.**

This crate exists to ensure that bypass requires
intent, effort, and visibility.

End of document.
