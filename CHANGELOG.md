# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Milestone 1: Core Foundation
- `Secret<T>` wrapper with automatic redaction in Debug/Display
- `Tainted<T>` wrapper for untrusted input
- `Ctx` struct for request metadata
- Basic capability types (`LogCap`, `HttpCap`)

#### Milestone 2: Policy Gate Builder
- `PolicyGate` with builder pattern for policy validation
- `.require()` method for adding policy requirements
- `.build()` returning validated `Ctx`
- `Authenticated` and `Authorized` policy types
- Structured `Violation` and `Error` types

#### Milestone 3: Logging Integration
- `PolicyLog` wrapper with capability-gating
- Automatic `Secret<T>` redaction in logs
- Request ID propagation

#### Milestone 4: Taint Tracking
- `Sanitizer` trait for validation logic
- `Verified<T>` type for validated data
- `Sink` trait for operations accepting only verified data
- `StringSanitizer` with whitespace trimming, control character rejection, length limits
- `VecSink` for in-memory testing

#### Milestone 5: End-to-End Demo
- `demo` module with narrative taint flow demonstration
- Integration tests covering all core functionality

#### Milestone 6: Type-State Contexts
- Type-state progression: `Ctx<Unauthed>` → `Ctx<Authed>` → `Ctx<Authorized>`
- State-restricted methods on `Ctx`
- Compile-time enforcement of authentication/authorization flow

#### Milestone 7: Audit Trail Support
- `AuditCap` capability for audit operations
- `AuditEvent` with structured event schema
- `AuditEventKind` enum (Authentication, Authorization, ResourceAccess, StateChange, AdminAction)
- `AuditOutcome` enum (Success, Error, Denied)
- `AuditTrail` for in-memory event recording
- `PolicyAudit` for capability-gated event emission

#### Milestone 8: Web Framework Integration
- `web` module with framework-agnostic integration surface
- `RequestAdapter` for extracting metadata
- `ExtractMetadata` and `ExtractTaintedInputs` traits
- Example handlers demonstrating integration patterns
- Automatic taint marking at request boundaries

#### Milestone 9: Enforcement Pack
- Dylint custom lint infrastructure
- `no_println` lint preventing raw stdout usage
- CI integration for enforcement lints
- Enforcement philosophy and suppression policy documentation

#### Milestone 10: Documentation & Publishing
- Comprehensive README with Quick Start guide
- `ARCHITECTURE.md` documenting technical architecture
- `DESIGN_PHILOSOPHY.md` explaining design rationale
- Five runnable examples:
  - `basic_taint_flow` - Core taint tracking pattern
  - `secret_redaction` - Automatic secret protection
  - `policy_gate_validation` - Policy enforcement and capabilities
  - `web_request_flow` - Web framework integration
  - `audit_trail` - Compliance logging
- CI job for building and running examples
- crates.io metadata for publishing
- Community files (CONTRIBUTING, SECURITY, CODE_OF_CONDUCT)
- GitHub issue and PR templates

### Changed
- Upgraded `#![warn(missing_docs)]` to `#![deny(missing_docs)]` for strict documentation enforcement
- Fixed documentation warnings (HTML tags, empty code blocks, private links)

### Security
- Code audit addressing 10 findings (A-001 through A-010)
- Added action constants to prevent magic strings
- Enhanced sanitizer documentation with attack scenarios
- Improved error handling and validation

## [0.1.0] - Unreleased

Initial release candidate prepared for crates.io publishing.

[Unreleased]: https://github.com/camadkins/policy-core/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/camadkins/policy-core/releases/tag/v0.1.0
