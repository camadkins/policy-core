# Policy-Core Enforcement Pack (Dylint)

This directory contains custom Dylint lints that enforce policy-core invariants at compile time.

## Purpose

The enforcement pack exists because **enforcement must be hard to bypass** (ARCHITECT.local.md §4).

This crate's architecture relies on structural guarantees:
- **Explicit context over ambient state** — no global authority
- **Capabilities, not roles** — typed proof objects gate access
- **Make invalid states unrepresentable** — compile-time prevention where possible
- **Wrapped sinks** — dangerous operations (logging, DB, HTTP) require capabilities

Even with well-designed APIs, developers may accidentally:
- Import raw sinks (`println!`, `std::fs::write`, etc.)
- Bypass capability gates
- Copy-paste unsafe examples
- Undermine taint/verified boundaries

Lints serve as a **second line of defense** (ARCHITECT.local.md, Enforcement Philosophy):
- Catch bypasses that type system alone cannot prevent
- Enforce patterns that preserve architectural invariants
- Fail builds before policy violations reach production

This is **enforcement by construction, not discipline** (DESIGN_RATIONALE.local.md, Core Insight).

## Implemented Lints

### NO_PRINTLN (Issue #38)

**Level:** Deny
**What it forbids:** Use of `println!`, `eprintln!`, and `dbg!` macros in library code.

**Why:** These macros bypass structured logging and capability controls:
- They write directly to stdout/stderr, bypassing `PolicyLog`
- They cannot be capability-gated (no `LogCap` required)
- They may leak secrets that would otherwise be redacted by `Secret<T>`
- They produce unstructured output unsuitable for audit trails

**Fix:** Use `tracing::info!`, `tracing::error!`, or `PolicyLog` instead.

**Example:**
```rust
// ❌ Bad - bypasses PolicyLog
println!("User logged in: {}", user_id);

// ✅ Good - uses structured logging
tracing::info!("User logged in: {}", user_id);
```

## Future Lints

- **Verified<T> forgeability prevention** (Issue #39): Detect attempts to construct `Verified<T>` outside approved paths
- **Tainted<T> bypass detection** (Issue #40): Detect flows from `Tainted<T>` to sinks without sanitization

---

## Running the Enforcement Pack

### Prerequisites

Install cargo-dylint:

```bash
cargo install cargo-dylint dylint-link
```

### Local Development

From the repository root:

```bash
# Run all enforcement pack lints on the workspace
cargo dylint --all --workspace

# Run a specific lint
cargo dylint no_println --workspace

# Run with explanations
cargo dylint --all --workspace -- -W help
```

### CI Integration

The enforcement pack runs automatically in CI via `.github/workflows/ci.yml`.

**Deny-level violations fail the build.**

CI executes:
```bash
cargo dylint --all --workspace
```

If the build fails due to an enforcement pack lint, you must either:
1. Fix the code to comply with the invariant
2. Follow the suppression policy below (exceptional cases only)

---

## Suppression Policy

> **"If policy enforcement can be bypassed accidentally, it will be bypassed eventually."**
> — DESIGN_RATIONALE.local.md, Final Principle

Suppressions (via `#[allow(enforcement_pack::LINT_NAME)]`) are **exceptions to architectural invariants** and must be treated as such.

### Rules

**Every suppression MUST include:**

1. **A one-line justification comment** tied to a principle in `ARCHITECT.local.md` or `DESIGN_RATIONALE.local.md`
2. **A tracking issue reference** (GitHub issue number)
3. **A removal condition** — when/why the suppression can be removed (or "permanent" with explicit rationale)

**Template:**

```rust
// EXCEPTION: <one-line reason tied to architectural principle>
// TRACKING: Issue #<num>
// REMOVE WHEN: <condition, date, or "permanent: <reason>">
#[allow(enforcement_pack::LINT_NAME)]
fn example() {
    // suppressed code here
}
```

### Forbidden Suppressions

Suppressions are **not permitted** for code that:
- Routes around capability gating (e.g., using raw sinks without `LogCap`, `DbCap`, etc.)
- Risks leaking `Secret<T>` values via `Debug`, `Display`, or unstructured logging
- Introduces taint bypass paths (e.g., constructing `Verified<T>` without sanitization)
- Creates unaudited side effects outside wrapped sinks (`PolicyLog`, `PolicyHttp`, `PolicyAudit`)

If a suppression is needed for one of these cases, **the architecture is broken** — file an issue to fix the design, do not suppress.

### Examples

**Valid suppression (temporary):**

```rust
// EXCEPTION: FFI boundary for C library integration; reviewed for safety
// TRACKING: Issue #123
// REMOVE WHEN: Custom sanitizer lands in Milestone 10
#[allow(enforcement_pack::taint_bypass)]
fn legacy_c_api_wrapper(input: Tainted<String>) -> Verified<String> {
    // ... manual validation ...
}
```

**Valid suppression (permanent):**

```rust
// EXCEPTION: Test harness deliberately bypasses sanitizer to test error paths
// TRACKING: Issue #456
// REMOVE WHEN: permanent (test code only)
#[allow(enforcement_pack::verified_forgeability)]
#[cfg(test)]
fn forge_verified_for_test(value: String) -> Verified<String> {
    // ... test helper ...
}
```

**Invalid suppression (violates architectural invariants):**

```rust
// ❌ REJECTED: This bypasses capability gating
#[allow(enforcement_pack::no_println)]
fn log_user_action(user_id: &str) {
    println!("User {} logged in", user_id); // No LogCap required
}
```

**Correct approach:**

```rust
// ✅ Use capability-gated sink
fn log_user_action(ctx: &Ctx, user_id: &str) -> Result<(), Error> {
    ctx.log().info("User logged in", &[("user_id", user_id)])?;
    Ok(())
}
```

---

## Reviewer Guidance

PRs that add or modify suppressions are **policy-affecting changes** and require elevated scrutiny.

### Review Checklist

When reviewing a PR with `#[allow(enforcement_pack::...)]`:

- [ ] **Justification is present and tied to architectural principles** (not generic "needed for testing")
- [ ] **Tracking issue exists** and is referenced
- [ ] **Removal condition is explicit** (or rationale for "permanent" is sound)
- [ ] **Suppression does not violate forbidden categories** (capability bypass, secret leak, taint bypass, unaudited side effects)
- [ ] **Alternatives were considered** — could the code be refactored to comply instead?
- [ ] **Scope is minimal** — suppression applies to the smallest possible code block

### Preferred Alternatives to Suppression

In order of preference:

1. **Refactor to comply** — adjust code to use capability-gated sinks, explicit sanitization, etc.
2. **Fix the lint** — if the lint has false positives, improve the lint logic (file an issue)
3. **Defer the change** — if compliance is too complex, defer the feature until the architecture supports it
4. **Suppress (last resort)** — only if all above options are infeasible and the exception is genuinely justified

### Normalization Risk

**Do not normalize suppressions.**

If multiple suppressions appear for the same lint in unrelated code:
- Treat it as a design smell
- Consider whether the architectural invariant is too strict (file an issue to discuss)
- Consider whether the code is systematically violating a core principle (reject the pattern)

Suppressions should remain rare and conspicuous.

---

## Development

### Adding a New Lint

1. Add the lint implementation to `lints/enforcement_pack/src/lib.rs`
2. Create UI tests in `lints/enforcement_pack/ui-tests/`
3. Document the lint purpose, fix, and examples in this README
4. Test locally: `cargo test` in the dylint directory
5. Verify CI integration: push to a branch and check workflow results

### Lint Crate Structure

```text
dylint/
├── Cargo.toml              # Workspace manifest
├── README.md               # This file
└── lints/
    └── enforcement_pack/   # Main lint crate
        ├── Cargo.toml      # Lint crate manifest
        ├── src/
        │   └── lib.rs      # Lint implementations
        └── ui-tests/       # UI test cases
            ├── *.rs        # Test inputs
            └── *.stderr    # Expected outputs
```

---

## Scope and Boundaries

The enforcement pack protects **architectural invariants** defined in `ARCHITECT.local.md` and `DESIGN_RATIONALE.local.md`.

**What it is:**
- Compile-time guardrails against accidental bypass
- Detection of patterns that undermine capability gating, taint tracking, and explicit context
- Governance for repo-level policy enforcement

**What it is NOT:**
- Runtime authentication or authorization logic
- Application-level business policy
- Framework-specific middleware
- A replacement for tests, code review, or security audits

Enforcement pack lints exist to prevent developers from **accidentally** violating structural guarantees. They do not prevent all misuse, and they cannot replace sound design or review.

---

## Related Documentation

- **ARCHITECT.local.md** — Core architectural invariants and design philosophy
- **DESIGN_RATIONALE.local.md** — Why this crate is designed the way it is
- **CLAUDE.local.md** — Build ruleset and milestone roadmap
- **README.md** (repo root) — Overview and usage examples

---

## Issues

- **#36**: Milestone 9 — Enforcement pack (Dylint lints)
- **#38**: NO_PRINTLN lint (completed)
- **#39**: Verified<T> forgeability prevention (future)
- **#40**: Documentation: enforcement philosophy & suppression policy (current)
