# ARCHITECT.md — Policy Enforcement Crate Design Contract

## Purpose of This Document

This document defines the **architectural invariants, design philosophy, and non-goals**
of the policy enforcement crate.

If there is ever a conflict between:
- convenience and correctness
- ergonomics and security
- flexibility and enforceability

**This document wins.**

Claude (and humans) must treat this as the highest-level design authority.

---

## Core Problem Statement

Modern applications fail policy enforcement because:
- Context is implicit or global
- Authorization is scattered
- Dangerous sinks are callable without proof
- Sanitization is optional and unenforced
- Auditing is bolted on later

This crate exists to **make policy violations structurally difficult** and
**correct usage the path of least resistance**.

---

## Design Philosophy

### 1. Explicit Context Over Ambient State
There is **no global context**.

All privileged actions require an explicit `Ctx` value that:
- Is constructed deliberately
- Encodes policy decisions
- Carries capabilities

If a function needs authority, it must *say so in its signature*.

---

### 2. Capabilities, Not Roles
We do not use roles, flags, or booleans.

Instead:
- Capabilities are **typed proof objects**
- Possession implies authorization
- Absence makes misuse impossible or painful

A function that performs a dangerous action:
- Requires a capability
- Cannot be called without it

---

### 3. Make Invalid States Unrepresentable
Whenever feasible, invalid usage should fail at **compile time**, not runtime.

Examples:
- Logging without `LogCap` should not compile
- Using tainted input in a sink should not compile
- Calling privileged methods in the wrong context state should not compile

Runtime checks exist only where static enforcement is impossible.

---

### 4. Enforcement Must Be Hard to Bypass
This crate assumes **developers will accidentally do the wrong thing**.

Therefore:
- Dangerous sinks are wrapped
- Raw APIs are discouraged or linted
- Redaction is automatic
- Sanitization is enforced by types

If bypass is easy, the design is considered a failure.

---

## Core Architectural Concepts

### Context (`Ctx`)
`Ctx` represents a **validated execution context**.

Responsibilities:
- Carries request metadata (request-id, user, etc.)
- Holds granted capabilities
- Serves as the root object for privileged operations

Rules:
- `Ctx` is immutable once built
- `Ctx` is created only via `PolicyGate`
- Capabilities are not constructible outside the crate

---

### PolicyGate
`PolicyGate` is the **only way to obtain a `Ctx`**.

Responsibilities:
- Accept raw inputs
- Apply policies
- Fail early with structured violations
- Produce a valid `Ctx` or nothing

Policies are:
- Explicit
- Composable
- Order-independent unless documented

---

### Capabilities
Capabilities are **zero-sized or lightweight marker types**.

Rules:
- They cannot be forged outside the crate
- They are only issued after policy success
- They gate access to sinks and privileged methods

Examples:
- `LogCap`
- `DbCap`
- `AuditCap`

Capabilities are **not data** — they are *proof*.

---

### Taint Tracking
Untrusted data is always tainted.

Types:
- `Tainted<T>` — untrusted, restricted
- `Verified<T>` — sanitized and safe

Rules:
- Tainted values cannot reach sinks
- Sanitization must be explicit
- Sanitizers are narrow and context-specific

The goal is not to sanitize everything —  
the goal is to **force conscious validation decisions**.

---

### Sinks
A sink is any operation that can cause harm if misused:
- Logging
- Databases
- HTTP calls
- Filesystem access
- Audit trails

Rules:
- All sinks are wrapped
- All sinks require capabilities
- All sinks respect taint and redaction
- Raw sinks should be linted against

If a sink exists without enforcement, the architecture is incomplete.

---

## Type-State (Advanced, Optional)

Type-state encodes **policy progression** in the type system.

Example:
```
Ctx<Unauthed> → Ctx<Authed> → Ctx<Authorized>
```

Rules:
- State transitions must be explicit
- Privileged methods exist only on correct states
- Error messages must remain understandable

Type-state is powerful but optional due to complexity.
If it harms ergonomics without real safety gain, it should be avoided.

---

## Enforcement Philosophy

### Compile-Time > Runtime
Prefer:
- Type errors
- Missing trait bounds
- Absent methods

Over:
- Panics
- Runtime authorization failures

Runtime checks exist only when the type system cannot express the rule.

---

### Lints as a Second Line of Defense
Even with good APIs, developers may:
- Import raw sinks
- Copy-paste unsafe examples

Therefore:
- Lints exist to catch bypasses
- CI should fail on violations
- Messages must explain how to fix the issue

---

## Non-Goals (Explicitly Out of Scope)

This crate does **not** attempt to:
- Be a full authentication system
- Replace existing web frameworks
- Magically infer trust or sanitization
- Hide all complexity from developers
- Provide policy-as-data DSLs
- Be opinionated about storage engines

If it isn’t about **enforcement**, it doesn’t belong here.

---

## Evolution Rules

- New features must preserve existing invariants
- Ergonomics improvements must not weaken enforcement
- Breaking changes require strong justification
- “Nice to have” features are rejected by default

The crate should grow **slowly and deliberately**.

---

## Litmus Tests

A design is acceptable only if:

- Privileged actions are impossible without proof
- Tainted data cannot silently flow into sinks
- Capabilities cannot be forged
- Bypass requires deliberate effort
- The compiler helps more than it hinders

If any of these fail, the architecture must be revisited.

---

End of document.
