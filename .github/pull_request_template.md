## Description

<!-- Provide a clear description of your changes -->

## Related Issues

<!-- Link to related issues using "Fixes #123" or "Relates to #456" -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Code quality improvement (refactoring, performance, etc.)

## Testing

<!-- Describe the tests you added or ran -->

- [ ] Added unit tests
- [ ] Added integration tests
- [ ] Added property tests
- [ ] All existing tests pass
- [ ] Added doc tests for new public APIs

## Quality Checklist

**Required before merge** (see [CONTRIBUTING.md](../CONTRIBUTING.md)):

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --all-features` passes
- [ ] `cargo test --doc --all-features` passes
- [ ] `cargo dylint --all --workspace` passes
- [ ] `cargo build --examples` succeeds
- [ ] All examples run without errors
- [ ] All public items have doc comments
- [ ] CHANGELOG.md updated (if applicable)

## Design Philosophy Compliance

Does this PR maintain policy-core's design principles?

- [ ] Explicit over implicit (no hidden authority or context)
- [ ] Compile-time over runtime (prefers type errors to runtime failures)
- [ ] Security over convenience (no weakening of guarantees)
- [ ] Enforcement by construction (incorrect usage is difficult/impossible)

**If this PR changes core types or patterns:**
- [ ] I have read [DESIGN_PHILOSOPHY.md](../DESIGN_PHILOSOPHY.md)
- [ ] I have discussed this change in an issue first
- [ ] I have documented why runtime enforcement is necessary (if applicable)

## Security Considerations

<!-- Does this PR affect security guarantees? -->

- [ ] No security implications
- [ ] Maintains existing security properties
- [ ] Introduces new security properties (describe below)
- [ ] Requires security review (tag maintainers)

**If security-relevant:**
<!-- Explain the security implications and mitigations -->

## Breaking Changes

<!-- If this is a breaking change, describe the migration path -->

## Additional Notes

<!-- Any other context reviewers should know -->
