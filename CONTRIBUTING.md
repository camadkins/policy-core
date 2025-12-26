# Contributing to policy-core

Thank you for your interest in contributing to `policy-core`! This document provides guidelines for contributing to the project.

## Project Philosophy

Before contributing, please read [ARCHITECTURE.md](ARCHITECTURE.md) and [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md) to understand the project's design principles and goals.

**Key Principles:**
- **Explicit over implicit** - Authority and context must be visible
- **Compile-time over runtime** - Prefer type errors to runtime failures
- **Security over convenience** - Safety is more important than ergonomics
- **Enforcement by construction** - Make incorrect usage difficult or impossible

## Development Setup

### Prerequisites

- Rust stable (edition 2021)
- Rust nightly (for dylint enforcement pack)

### Clone and Build

```bash
git clone https://github.com/camadkins/policy-core.git
cd policy-core
cargo build
cargo test
```

### Install Development Tools

```bash
# For enforcement pack lints
cargo install cargo-dylint dylint-link

# Optional: for property testing
cargo install cargo-fuzz
```

## Running Tests

### Unit and Integration Tests

```bash
cargo test --all-features
```

### Documentation Tests

```bash
cargo test --doc --all-features
```

### Property Tests

```bash
cargo test --test property_tests
```

### Examples

```bash
cargo build --examples
cargo run --example basic_taint_flow
cargo run --example secret_redaction
cargo run --example policy_gate_validation
cargo run --example web_request_flow
cargo run --example audit_trail
```

## Code Quality Standards

All contributions must pass these quality gates:

### 1. Formatting

```bash
cargo fmt --all -- --check
```

### 2. Linting

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### 3. Enforcement Pack

```bash
cargo dylint --all --workspace
```

### 4. Documentation

- All public items must have doc comments
- Code examples in doc comments should compile and run
- Use `#![deny(missing_docs)]` to catch missing documentation

### 5. Tests

- Add tests for all new functionality
- Ensure existing tests pass
- Consider adding property tests for validators and sanitizers

## Pull Request Process

### 1. Before Starting

- Open an issue to discuss significant changes
- Check that the change aligns with the project philosophy
- Read [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md) to understand design constraints

### 2. Making Changes

- Create a feature branch from `main`
- Make focused, atomic commits with clear messages
- Write tests for your changes
- Update documentation as needed
- Run all quality gates locally

### 3. Submitting

- Push your branch and open a pull request
- Fill out the PR template completely
- Link to any related issues
- Ensure CI passes

### 4. Review Process

- Maintainers will review your PR
- Address feedback and requested changes
- Be patient - security-focused reviews take time
- Once approved, maintainers will merge

## Commit Message Guidelines

Use clear, descriptive commit messages:

```
feat: add capability for database operations
fix: prevent taint bypass through clone
docs: clarify Verified<T> construction invariants
test: add property tests for StringSanitizer
refactor: simplify policy gate builder pattern
```

Prefixes:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only
- `test:` - Adding or updating tests
- `refactor:` - Code change that neither fixes a bug nor adds a feature
- `perf:` - Performance improvement
- `chore:` - Maintenance tasks

## What to Contribute

### Good Contributions

- Bug fixes with tests
- Documentation improvements
- Additional examples
- Property tests for validators
- Integration with new web frameworks
- New sanitizers with strong guarantees
- Performance improvements (with benchmarks)

### Requires Discussion

- New capability types
- Changes to core types (`Ctx`, `PolicyGate`, etc.)
- API changes
- New policy types
- Architectural changes

### Not Accepted

- Changes that weaken compile-time guarantees
- Features that make bypass easier
- Convenience features that hide authority
- Runtime-only enforcement where compile-time is possible

## Adding New Features

### New Sanitizers

1. Implement the `Sanitizer<T>` trait
2. Add comprehensive tests (unit + property)
3. Document the validation rules
4. Document security properties and attack scenarios
5. Add an example if it demonstrates a new pattern

### New Capabilities

1. Discuss the need in an issue first
2. Define the capability type (usually zero-sized)
3. Make constructor `pub(crate)`
4. Add corresponding policy type
5. Create wrapper type requiring the capability
6. Add tests demonstrating enforcement
7. Update documentation

### New Policy Types

1. Discuss in an issue first
2. Ensure it aligns with capability-based model
3. Implement the `Policy` trait
4. Add tests for success and failure cases
5. Document when and why to use it

## Documentation Guidelines

### Doc Comments

- Start with a single-line summary
- Explain **why**, not just **what**
- Include examples showing correct usage
- Use `compile_fail` examples to show what doesn't compile
- Cross-reference related types
- Document security properties explicitly

Example:

```rust
/// Validates and sanitizes strings for use in SQL queries.
///
/// This sanitizer prevents SQL injection by rejecting:
/// - Control characters
/// - Single quotes and double quotes
/// - SQL keywords
///
/// # Security Properties
///
/// - Prevents SQL injection attacks
/// - Rejects empty or whitespace-only input
/// - Enforces maximum length limits
///
/// # Examples
///
/// ```
/// use policy_core::{Sanitizer, StringSanitizer, Tainted};
///
/// let sanitizer = StringSanitizer::new(256);
/// let input = Tainted::new("user@example.com".to_string());
/// let verified = sanitizer.sanitize(input)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Compile Failures
///
/// ```compile_fail
/// # use policy_core::{Tainted, Sink, VecSink};
/// let tainted = Tainted::new("unsafe".to_string());
/// let sink = VecSink::new();
/// sink.sink(&tainted); // Error: expected Verified<T>
/// ```
pub struct StringSanitizer { /* ... */ }
```

## Testing Guidelines

### Unit Tests

- Test each public API function
- Test error cases
- Test edge cases (empty input, maximum length, etc.)

### Integration Tests

- Test end-to-end flows
- Test that compile errors occur where expected
- Test policy violations produce correct errors

### Property Tests

Use `proptest` for validators and sanitizers:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn sanitizer_rejects_control_characters(s in ".*\\x00.*") {
        let tainted = Tainted::new(s);
        let sanitizer = StringSanitizer::new(1000);
        assert!(sanitizer.sanitize(tainted).is_err());
    }
}
```

## Reporting Issues

### Bug Reports

Include:
- Rust version (`rustc --version`)
- Minimal reproduction case
- Expected behavior
- Actual behavior
- Error messages (full output)

### Feature Requests

Include:
- Use case description
- How it aligns with project philosophy
- Alternatives considered
- Example usage

### Security Issues

**Do not open public issues for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for reporting security issues.

## Code Review Checklist

Before requesting review, verify:

- [ ] All tests pass locally
- [ ] `cargo fmt` has been run
- [ ] `cargo clippy` passes with `-D warnings`
- [ ] `cargo dylint --all --workspace` passes
- [ ] Documentation is complete
- [ ] Examples compile and run
- [ ] CHANGELOG.md is updated (if applicable)
- [ ] Commit messages are clear
- [ ] PR description explains the change
- [ ] Related issues are linked

## Style Guidelines

### Code Style

- Follow Rust standard style (enforced by `rustfmt`)
- Prefer explicit types over `impl Trait` in public APIs
- Use descriptive variable names
- Keep functions focused and small
- Avoid unnecessary complexity

### Error Messages

- Be specific about what went wrong
- Suggest how to fix the issue
- Don't leak sensitive information

### Comments

- Explain **why**, not **what**
- Document assumptions and invariants
- Reference attack scenarios for security code

## License

By contributing to policy-core, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Read the documentation: [ARCHITECTURE.md](ARCHITECTURE.md), [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md)
- Check existing issues and PRs
- Open a discussion issue for questions
- Be patient and respectful

Thank you for contributing to policy-core!
