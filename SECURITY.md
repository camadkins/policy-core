# Security Policy

<!-- Note: This file uses relative links (e.g., ARCHITECTURE.md) instead of absolute GitHub URLs
     for maximum portability across forks, branches, and local clones. -->

## Project Status

**IMPORTANT:** `policy-core` is a **research and demonstration project** exploring compile-time policy enforcement patterns in Rust. It is **NOT** production-ready and should **NOT** be used in security-critical systems without extensive review and testing.

## Security Limitations

### This Library Does NOT Provide

1. **Formal Verification** - The type system prevents many errors, but is not formally proven
2. **Complete Protection** - Security requires defense in depth; this is one layer
3. **Automatic Security** - Developers must still use the library correctly
4. **Protection Against All Attacks** - Novel attack vectors may exist
5. **Cryptographic Guarantees** - No encryption, signing, or cryptographic primitives

### Known Limitations

1. **Unsafe Code Escape Hatch**
   - Rust's `unsafe` blocks can bypass type system guarantees
   - The crate forbids `unsafe` internally but cannot prevent external use
   - Dependencies may use `unsafe`

2. **Deserialization Risks**
   - Deserializing directly into `Verified<T>` or capabilities breaks invariants
   - Always deserialize into `Tainted<T>` or raw types, then validate

3. **FFI Boundaries**
   - Foreign function interfaces bypass Rust's type system
   - Carefully validate data crossing FFI boundaries

4. **Logic Errors**
   - Sanitizers implement example validation rules
   - Real applications need domain-specific validation logic
   - Review sanitizer implementations carefully

5. **Timing Attacks**
   - Not designed to prevent timing side-channels
   - Comparison operations may leak information through timing

6. **Denial of Service**
   - No built-in rate limiting or resource exhaustion protection
   - Applications must implement DoS protection separately

### Explicitly Out of Scope

- Authentication implementation (you provide the `Principal`)
- Authorization decision logic (you define the policies)
- Cryptography (use dedicated crypto libraries)
- Network security (use TLS/HTTPS)
- Database security (use parameterized queries)
- Access control lists (use proper authorization services)

## Supported Versions

Currently, only the latest version receives security updates:

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

### For Security Issues

If you discover a security vulnerability in `policy-core`:

1. **Email**: Send details to the repository owner via GitHub
2. **GitHub Security Advisory**: Use the "Security" tab → "Report a vulnerability"
3. **Private Issue**: Request a private security issue

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if available)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: As soon as possible
  - High: Within 30 days
  - Medium/Low: Next release

### Disclosure Policy

- We follow responsible disclosure
- We will credit reporters (unless they prefer anonymity)
- We will coordinate disclosure timing
- We will publish security advisories for confirmed issues

## Security Best Practices

### When Using policy-core

1. **Understand the Guarantees**
   - Read [ARCHITECTURE.md](ARCHITECTURE.md) and [DESIGN_PHILOSOPHY.md](DESIGN_PHILOSOPHY.md)
   - Understand what the type system prevents and what it doesn't

2. **Taint All External Input**
   - Wrap all user input, file data, network data in `Tainted<T>`
   - Never deserialize directly into `Verified<T>`

3. **Validate Domain Rules**
   - Create domain-specific sanitizers
   - Don't rely solely on `StringSanitizer`
   - Consider the specific threats for your application

4. **Don't Bypass Enforcement**
   - Never use `unsafe` to bypass type system
   - Don't use `transmute` or pointer casts to convert types
   - Respect the `pub(crate)` boundaries

5. **Review Sanitizers Carefully**
   - Sanitizers are trust boundaries
   - Audit their validation logic
   - Test with malicious input

6. **Audit Trail Usage**
   - Log security-relevant events
   - Protect audit logs from tampering
   - Monitor for suspicious patterns

7. **Defense in Depth**
   - Use `policy-core` as one layer
   - Implement authentication separately
   - Use parameterized queries for databases
   - Apply rate limiting
   - Use TLS for network communication

### What NOT to Do

- Don't use in production without thorough testing
- Don't assume it prevents all security issues
- Don't disable enforcement lints without review
- Don't bypass type system with `unsafe`
- Don't trust input without validation
- Don't rely solely on this library for security

## Security Testing

### Running Security Tests

```bash
# All tests including security-focused ones
cargo test --all-features

# Property tests (fuzzing-like behavior)
cargo test --test property_tests

# Enforcement pack (detects bypass patterns)
cargo dylint --all --workspace
```

### Adding Security Tests

When adding new features, include tests for:

- Boundary conditions
- Invalid input handling
- Bypass attempts
- Error message safety (no information leakage)

See [CONTRIBUTING.md](CONTRIBUTING.md) for testing guidelines.

## Threat Model

### Threats This Library Addresses

1. **Accidental Misuse**
   - Prevents unvalidated data from reaching sinks (compile error)
   - Prevents capability forgery (type system)
   - Prevents secret leakage in logs (automatic redaction)

2. **Code Review Gaps**
   - Makes authority flow visible in signatures
   - Enforces validation through types
   - Lints detect bypass patterns

### Threats This Library Does NOT Address

1. **Intentional Bypass by Malicious Developer**
   - Cannot prevent determined attacker with code access
   - Cannot prevent use of `unsafe` or FFI

2. **Implementation Bugs**
   - Logic errors in sanitizers
   - Bugs in the library itself

3. **Runtime Attacks**
   - Memory corruption
   - Timing attacks
   - Side-channel attacks

4. **External Dependencies**
   - Vulnerabilities in Rust stdlib
   - Vulnerabilities in `tracing` crate
   - Vulnerabilities in transitive dependencies

## Secure Development

### Code Review Focus

When reviewing changes, ensure:

- No `unsafe` code without strong justification
- No public constructors for `Verified<T>` or capabilities
- Sanitizers don't leak rejected input in errors
- Error messages don't contain secrets
- Type system prevents bypass

### CI/CD Security

- All PRs require passing tests
- Enforcement pack lints must pass
- No warnings allowed (`-D warnings`)
- Dependabot enabled for dependency updates

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities. Contributors will be credited in:

- Security advisories
- CHANGELOG.md
- Release notes

## Additional Resources

- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE List](https://cwe.mitre.org/)

## Contact

For security concerns:
- GitHub Security Advisories (preferred)
- Private issue requests
- Repository owner contact via GitHub

For general questions:
- GitHub Issues (for non-security topics)
- [CONTRIBUTING.md](CONTRIBUTING.md)
