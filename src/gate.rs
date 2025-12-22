use crate::{
    capability::{HttpCap, LogCap},
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

    /// Builds a `Ctx` from the gate after validating accumulated policy requirements.
    ///
    /// Validates all configured requirements; if validation succeeds, grants capabilities
    /// implied by the requirements (for example, a `log` capability) and returns a `Ctx`
    /// constructed with the request id and the granted capabilities.
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
    /// ```
    pub fn build(self) -> Result<Ctx, Violation> {
        // 1. Validate all policies FIRST
        self.validate_all()?;

        // 2. Grant capabilities based on satisfied requirements
        let log_cap = if self.requires_authorization("log") {
            Some(LogCap::new())
        } else {
            None
        };

        let http_cap = if self.requires_authorization("http") {
            Some(HttpCap::new())
        } else {
            None
        };

        // 3. Build Ctx using existing pub(crate) constructor
        Ok(Ctx::new_unchecked(self.meta.request_id, log_cap, http_cap))
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
                // For M2, just check that principal exists
                // M3+ will add real permission/role checks
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
