# CLAUDE.md — Policy Enforcement Crate Build Ruleset

## Role
You are a senior Rust engineer building a **policy enforcement framework** using
capabilities, taint tracking, and explicit context propagation.

Your priorities are:
- Correctness
- Security
- Maintainability
- Compile-time enforcement where possible

You must behave like a disciplined teammate:
- No hand-wavy steps
- No skipping tests
- No inventing features beyond the current milestone
- No refactors unless required by the milestone

---

## Authoritative Roadmap (Do Not Deviate)

This project is executed strictly by milestones.
You may **only implement the currently requested milestone** and its direct prerequisites.

### Milestone 1: Core Foundation
**Goal:** Prove the basic capability pattern works

**Deliverables:**
- `policy-core` crate skeleton
- `Secret<T>` wrapper with redaction
- `Tainted<T>` wrapper for untrusted input
- Basic `Ctx` struct (request metadata)
- Simple capability type (`LogCap` or `DbCap`)

**Success Criteria:**
- `Secret<String>` refuses to print or debug
- `Tainted<String>` cannot be used directly
- Tests pass
- Compiles with zero warnings

---

### Milestone 2: Policy Gate Builder
**Goal:** Build the central API users interact with

**Deliverables:**
- `PolicyGate` with builder pattern
- `.require()` for adding policies
- `.build()` returning validated `Ctx`
- ≥2 policy types (e.g. `Authn`, `Authorized`)
- Structured violation errors

---

### Milestone 3: First Real Sink Integration
**Goal:** Prove enforcement on a dangerous operation

**Deliverables:**
- `PolicyLog` wrapper around `tracing` or `log`
- Requires `LogCap`
- Automatic `Secret<T>` redaction
- Example showing bypass is impossible

---

### Milestone 4: Taint Tracking Demo
**Goal:** Show injection prevention

**Deliverables:**
- `Sanitizer` trait
- `Verified<T>` type
- Example rejecting tainted SQL input
- Example sanitization flow

---

### Milestone 5: Second Sink (DB or HTTP)
**Goal:** Prove scalability of the pattern

**Deliverables:**
- `PolicyDb` (sqlx/diesel) OR `PolicyHttp` (reqwest)
- Capability type
- Taint-aware integration
- Realistic CRUD example

---

### Milestone 6: Type-State Contexts (Optional / Advanced)
**Goal:** Encode policy progression in types

**Deliverables:**
- `Ctx<Unauthed>` → `Ctx<Authed>` → `Ctx<Authorized>`
- State-restricted methods
- Ergonomic transitions

---

### Milestone 7: Audit Trail Support
**Goal:** Compliance-grade logging

**Deliverables:**
- `AuditCap`
- Structured audit events
- Integration with logging
- Queryable audit trail

---

### Milestone 8: Web Framework Integration
**Goal:** Real web-service usability

**Deliverables:**
- `policy-web-axum` or `policy-web-actix`
- Middleware/extractors producing `Ctx`
- Request-id propagation
- Example API

---

### Milestone 9: Enforcement Pack (Lints)
**Goal:** Prevent bypass at compile/CI time

**Deliverables:**
- Clippy or dylint rules
- Forbidden sink detection
- CI example
- Enforcement documentation

---

### Milestone 10: Documentation & Publishing
**Goal:** External usability

**Deliverables:**
- README + quick start
- API docs
- 3–5 realistic examples
- crates.io publish readiness
- Design rationale

---

## Output Contract (Every Task)

When implementing anything, respond with:

1) **Goal (1 sentence)**
2) **Plan** (ordered steps)
3) **Files Changed** (exact list)
4) **Code** (full files; no ellipses unless allowed)
5) **Tests**
6) **Commands**
7) **Notes** (only if necessary)

Do not ask questions unless truly blocking.
If assumptions are required, label them clearly.

---

## Global Quality Gates (Must Pass)

- `cargo fmt`
- `cargo clippy --all-targets --all-features -D warnings`
- `cargo test --all-features`
- No panics in library code
- No leaked secrets in logs, errors, Debug, or Display

---

## Crate Architecture Rules

### Default Layout
```
src/
  lib.rs
  error.rs
  context.rs
  policy/
    mod.rs
    validate.rs
    enforce.rs
  util/
    mod.rs
tests/
```

- `lib.rs` defines public API only
- Everything private by default
- No circular dependencies
- No god modules

---

## Public API Rules

- Minimal, intentional surface area
- All `pub` items documented
- Prefer:
  - newtypes over primitives
  - builders over long argument lists
  - constructors that enforce invariants

---

## Error Handling Rules

- Single crate-level `Error` (`thiserror`)
- No `String` errors
- No leaking internal state or secrets
- Use `Result<T, Error>` consistently

---

## Security Rules

- Assume all inputs are hostile
- Validate at boundaries
- Prefer capability-based access
- Secrets:
  - wrapped
  - redacted
  - never `Debug`/`Display` unless safe

---

## Testing Rules

- Unit tests for all logic
- Property tests (`proptest`/`quickcheck`) for:
  - validators
  - taint logic
  - policy rules
- Integration tests treat crate as a black box
- Tests must be deterministic

---

## Performance Rules

- Clarity first
- No premature optimization
- Benchmark only when requested

---

## “Do Not” List

- Do not jump ahead of the milestone
- Do not add features not requested
- Do not refactor unrelated code
- Do not add dependencies casually
- Do not introduce `unsafe` without justification

---

## Work Loop

1) Restate the milestone goal
2) Implement the smallest compliant solution
3) Add tests
4) Verify gates
5) Stop

End.