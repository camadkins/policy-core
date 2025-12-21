use crate::{
    capability::LogCap,
    context::Ctx,
    error::{Violation, ViolationKind},
    policy::PolicyReq,
    request::RequestMeta,
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

    /// Adds a policy requirement.
    ///
    /// Requirements are deduplicated automatically.
    /// Returns `self` for method chaining.
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

    /// Validates all policies and builds a `Ctx`.
    ///
    /// Returns `Err(Violation)` if any policy fails.
    /// On success, returns a `Ctx` with granted capabilities.
    pub fn build(self) -> Result<Ctx, Violation> {
        // 1. Validate all policies FIRST
        self.validate_all()?;

        // 2. Grant capabilities based on satisfied requirements
        let log_cap = if self.requires_authorization("log") {
            Some(LogCap::new())
        } else {
            None
        };

        // 3. Build Ctx using existing pub(crate) constructor
        Ok(Ctx::new_unchecked(self.meta.request_id, log_cap))
    }

    /// Validates all policy requirements.
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
                // For M2, just check that principal exists
                // M3+ will add real permission/role checks
            }
        }
        Ok(())
    }

    /// Checks if a specific authorization is required.
    fn requires_authorization(&self, action: &str) -> bool {
        self.requirements
            .iter()
            .any(|req| matches!(req, PolicyReq::Authorized { action: a } if *a == action))
    }

    /// Checks if two requirements are the same (for deduplication).
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
