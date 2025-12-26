use crate::{
    audit::AuditCap,
    capability::{HttpCap, LogCap},
    context::Ctx,
    error::{Violation, ViolationKind},
    policy::{actions, PolicyReq},
    request::RequestMeta,
    state::Authorized,
};

/// The policy enforcement gate.
///
/// `PolicyGate` is the only way to construct a valid `Ctx`.
/// It validates policy requirements before granting capabilities.
///
/// # Examples
///
/// ```
/// use policy_core::{PolicyGate, RequestMeta, Principal, Authenticated, Authorized};
///
/// let meta = RequestMeta {
///     request_id: "req-123".to_string(),
///     principal: Some(Principal {
///         id: "user-1".to_string(),
///         name: "Alice".to_string(),
///     }),
/// };
///
/// let ctx = PolicyGate::new(meta)
///     .require(Authenticated)
///     .require(Authorized::for_action("log"))
///     .build()
///     .expect("policies should pass");
///
/// assert!(ctx.log_cap().is_some());
/// ```
pub struct PolicyGate {
    meta: RequestMeta,
    requirements: Vec<PolicyReq>,
}

impl PolicyGate {
    /// Creates a new policy gate with the given request metadata.
    pub fn new(meta: RequestMeta) -> Self {
        Self {
            meta,
            requirements: Vec::new(),
        }
    }

    /// Adds a policy requirement to the gate, deduplicating identical requirements.
    ///
    /// If an equivalent requirement is already present it will not be added again.
    /// Returns the updated gate to allow method chaining.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::{PolicyGate, RequestMeta, Principal, Authenticated};
    ///
    /// let meta = RequestMeta {
    ///     request_id: "req-123".to_string(),
    ///     principal: Some(Principal {
    ///         id: "u1".to_string(),
    ///         name: "Alice".to_string(),
    ///     }),
    /// };
    /// let gate = PolicyGate::new(meta)
    ///     .require(Authenticated)
    ///     .require(Authenticated); // second call is deduplicated
    /// ```
    pub fn require(mut self, policy: impl Into<PolicyReq>) -> Self {
        let req = policy.into();

        // Deduplicate: only add if not already present
        if !self
            .requirements
            .iter()
            .any(|r| self.same_requirement(r, &req))
        {
            self.requirements.push(req);
        }

        self
    }

    /// Builds a `Ctx<Authorized>` from the gate after validating accumulated policy requirements.
    ///
    /// This method performs the full type-state progression internally:
    /// - Validates all policy requirements
    /// - Authenticates (if Authenticated policy is present)
    /// - Authorizes (grants capabilities based on satisfied policies)
    ///
    /// Returns a fully authorized context that can access privileged operations.
    ///
    /// # Errors
    ///
    /// Returns a `Violation` if any policy requirement fails validation.
    ///
    /// # Examples
    ///
    /// ```
    /// use policy_core::{PolicyGate, RequestMeta, Principal, Authenticated, Authorized};
    ///
    /// let meta = RequestMeta {
    ///     request_id: "req-123".to_string(),
    ///     principal: Some(Principal {
    ///         id: "u1".to_string(),
    ///         name: "Alice".to_string(),
    ///     }),
    /// };
    /// let ctx = PolicyGate::new(meta)
    ///     .require(Authenticated)
    ///     .require(Authorized::for_action("log"))
    ///     .build()
    ///     .unwrap();
    ///
    /// // ctx is Ctx<Authorized>
    /// assert!(ctx.log_cap().is_some());
    /// ```
    pub fn build(self) -> Result<Ctx<Authorized>, Violation> {
        // 1. Validate all policies FIRST
        self.validate_all()?;

        // 2. Grant capabilities based on satisfied requirements
        let log_cap = if self.requires_authorization(actions::LOG) {
            Some(LogCap::new())
        } else {
            None
        };

        let http_cap = if self.requires_authorization(actions::HTTP) {
            Some(HttpCap::new())
        } else {
            None
        };

        let audit_cap = if self.requires_authorization(actions::AUDIT) {
            Some(AuditCap::new())
        } else {
            None
        };

        // 3. Build Ctx<Authorized> with the principal from metadata
        Ok(Ctx::new_authorized(
            self.meta.request_id,
            self.meta.principal,
            log_cap,
            http_cap,
            audit_cap,
        ))
    }

    /// Check that all configured policy requirements are satisfied.
    ///
    /// Returns `Ok(())` if every requirement validates successfully, or `Err(Violation)` for the first requirement that fails.
    ///
    /// Note: This is an internal method called by `build()`.
    fn validate_all(&self) -> Result<(), Violation> {
        for req in &self.requirements {
            self.validate_one(req)?;
        }
        Ok(())
    }

    /// Validates a single policy requirement.
    fn validate_one(&self, req: &PolicyReq) -> Result<(), Violation> {
        match req {
            PolicyReq::Authenticated => {
                if self.meta.principal.is_none() {
                    return Err(Violation::new(
                        ViolationKind::Unauthenticated,
                        "Authentication required",
                    ));
                }
            }
            PolicyReq::Authorized { action: _ } => {
                if self.meta.principal.is_none() {
                    return Err(Violation::new(
                        ViolationKind::Unauthenticated,
                        "Cannot authorize unauthenticated principal",
                    ));
                }
                // Authorization validation (basic implementation):
                //
                // Currently, authorization is simplified: any authenticated principal
                // is authorized for any action. This model is suitable for:
                // - Early-stage systems with coarse-grained access control
                // - Prototypes where all authenticated users have equal privileges
                // - Internal tools with implicit trust assumptions
                //
                // Future enhancement: Role-Based Access Control (RBAC)
                //
                // A production authorization system would check whether the principal
                // has specific permissions for the requested action. This typically involves:
                // - Checking principal.roles against action requirements
                // - Querying a policy decision point (PDP) or authorization service
                // - Evaluating attribute-based policies (ABAC) for fine-grained control
                //
                // Example future logic:
                //   match action {
                //       "admin" => require_role(&principal, "admin"),
                //       "log" => require_any_role(&principal, &["user", "admin"]),
                //       _ => Ok(()),
                //   }
                //
                // The simplified implementation here is intentional and will be enhanced
                // in future iterations as access control requirements evolve.
            }
        }
        Ok(())
    }

    /// Determines whether any requirement authorizes the specified action.
    ///
    /// Returns `true` if a `PolicyReq::Authorized` with the given action exists among the gate's requirements, `false` otherwise.
    fn requires_authorization(&self, action: &str) -> bool {
        self.requirements
            .iter()
            .any(|req| matches!(req, PolicyReq::Authorized { action: a } if *a == action))
    }

    /// Determine whether two policy requirements are equivalent for deduplication.
    ///
    /// Two requirements are considered equivalent when they are both `PolicyReq::Authenticated`
    /// or when they are both `PolicyReq::Authorized` with the same `action`.
    fn same_requirement(&self, a: &PolicyReq, b: &PolicyReq) -> bool {
        match (a, b) {
            (PolicyReq::Authenticated, PolicyReq::Authenticated) => true,
            (PolicyReq::Authorized { action: a1 }, PolicyReq::Authorized { action: a2 }) => {
                a1 == a2
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::request::Principal;
    use proptest::prelude::*;

    // Strategy: Generate arbitrary request metadata
    fn arb_request_meta() -> impl Strategy<Value = RequestMeta> {
        (
            prop::string::string_regex("[a-z0-9-]{5,20}").unwrap(),
            prop::option::of(arb_principal()),
        )
            .prop_map(|(request_id, principal)| RequestMeta {
                request_id,
                principal,
            })
    }

    // Strategy: Generate arbitrary principal
    fn arb_principal() -> impl Strategy<Value = Principal> {
        (
            prop::string::string_regex("[a-z0-9-]{3,10}").unwrap(),
            prop::string::string_regex("[A-Za-z ]{3,15}").unwrap(),
        )
            .prop_map(|(id, name)| Principal { id, name })
    }

    // Strategy: Generate arbitrary action names
    fn arb_action_name() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just(actions::LOG),
            Just(actions::HTTP),
            Just(actions::AUDIT),
            Just("db"),    // Non-standard action for testing unknown capabilities
            Just("cache"), // Non-standard action for testing unknown capabilities
        ]
    }

    // Strategy: Generate arbitrary policy requirements
    fn arb_policy_req() -> impl Strategy<Value = PolicyReq> {
        prop_oneof![
            Just(PolicyReq::Authenticated),
            arb_action_name().prop_map(|action| PolicyReq::Authorized { action }),
        ]
    }

    // Strategy: Generate a vector of policy requirements
    fn arb_policy_requirements() -> impl Strategy<Value = Vec<PolicyReq>> {
        prop::collection::vec(arb_policy_req(), 0..10)
    }

    proptest! {
        /// Property: Adding the same requirement N times results in it appearing only once
        #[test]
        fn proptest_gate_deduplicates_requirements(
            meta in arb_request_meta(),
            req in arb_policy_req(),
            count in 1usize..10
        ) {
            let mut gate = PolicyGate::new(meta);

            // Add the same requirement multiple times
            for _ in 0..count {
                gate = gate.require(req.clone());
            }

            // Count how many times this requirement appears
            let occurrences = gate.requirements.iter()
                .filter(|r| gate.same_requirement(r, &req))
                .count();

            // Should appear exactly once due to deduplication
            prop_assert_eq!(occurrences, 1);
        }

        /// Property: Authorized::for_action("X") results in the corresponding capability being granted
        #[test]
        fn proptest_gate_authorized_action_grants_capability(
            request_id in prop::string::string_regex("[a-z0-9-]{5,20}").unwrap(),
            principal in arb_principal(),
            action in arb_action_name()
        ) {
            let meta = RequestMeta {
                request_id,
                principal: Some(principal),
            };

            let ctx = PolicyGate::new(meta)
                .require(crate::policy::Authenticated)
                .require(crate::policy::Authorized::for_action(action))
                .build()
                .unwrap();

            // Check that the corresponding capability was granted
            match action {
                actions::LOG => prop_assert!(ctx.log_cap().is_some()),
                actions::HTTP => prop_assert!(ctx.http_cap().is_some()),
                actions::AUDIT => prop_assert!(ctx.audit_cap().is_some()),
                _ => {
                    // For unknown actions, no capability should be granted
                    prop_assert!(ctx.log_cap().is_none());
                    prop_assert!(ctx.http_cap().is_none());
                    prop_assert!(ctx.audit_cap().is_none());
                }
            }
        }

        /// Property: Building with the same requirements yields an identical context
        #[test]
        fn proptest_gate_build_is_deterministic(
            meta in arb_request_meta(),
            requirements in arb_policy_requirements()
        ) {
            // Skip if requirements need authentication but no principal
            if requirements.iter().any(|r| matches!(r, PolicyReq::Authenticated | PolicyReq::Authorized { .. }))
                && meta.principal.is_none()
            {
                return Ok(());
            }

            // Build context twice with same requirements
            let mut gate1 = PolicyGate::new(meta.clone());
            for req in &requirements {
                gate1 = gate1.require(req.clone());
            }

            let mut gate2 = PolicyGate::new(meta);
            for req in &requirements {
                gate2 = gate2.require(req.clone());
            }

            let ctx1 = gate1.build();
            let ctx2 = gate2.build();

            // Both should succeed or both should fail
            match (ctx1, ctx2) {
                (Ok(c1), Ok(c2)) => {
                    // Capabilities should match
                    prop_assert_eq!(c1.log_cap().is_some(), c2.log_cap().is_some());
                    prop_assert_eq!(c1.http_cap().is_some(), c2.http_cap().is_some());
                    prop_assert_eq!(c1.audit_cap().is_some(), c2.audit_cap().is_some());
                }
                (Err(_), Err(_)) => {
                    // Both failed as expected
                }
                _ => {
                    return Err(TestCaseError::fail("Inconsistent build results"));
                }
            }
        }

        /// Property: Requirement order doesn't affect the outcome
        #[test]
        fn proptest_gate_requirement_order_irrelevant(
            meta in arb_request_meta(),
            mut requirements in arb_policy_requirements()
        ) {
            // Skip if requirements need authentication but no principal
            if requirements.iter().any(|r| matches!(r, PolicyReq::Authenticated | PolicyReq::Authorized { .. }))
                && meta.principal.is_none()
            {
                return Ok(());
            }

            // Build with original order
            let mut gate1 = PolicyGate::new(meta.clone());
            for req in &requirements {
                gate1 = gate1.require(req.clone());
            }
            let ctx1 = gate1.build();

            // Build with reversed order
            requirements.reverse();
            let mut gate2 = PolicyGate::new(meta);
            for req in &requirements {
                gate2 = gate2.require(req.clone());
            }
            let ctx2 = gate2.build();

            // Results should be identical regardless of order
            match (ctx1, ctx2) {
                (Ok(c1), Ok(c2)) => {
                    prop_assert_eq!(c1.log_cap().is_some(), c2.log_cap().is_some());
                    prop_assert_eq!(c1.http_cap().is_some(), c2.http_cap().is_some());
                    prop_assert_eq!(c1.audit_cap().is_some(), c2.audit_cap().is_some());
                }
                (Err(_), Err(_)) => {
                    // Both failed as expected (order-independent failure)
                }
                _ => {
                    return Err(TestCaseError::fail("Order affected build outcome"));
                }
            }
        }
    }
}
