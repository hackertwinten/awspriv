//! IAM SimulatePrincipalPolicy fallback.
//!
//! When direct IAM read is denied but the principal can still call
//! `iam:SimulatePrincipalPolicy`, this is the next-best stealth primitive.
//! A single API call evaluates ~50 actions at once and reports which are
//! Allowed / Denied without performing them. CloudTrail sees one
//! `iam:SimulatePrincipalPolicy` event regardless of batch size.
//!
//! Limitations:
//!   * Requires `iam:SimulatePrincipalPolicy` on the principal — most
//!     read-only roles don't have it.
//!   * Resource scoping is approximated with `Resource: ["*"]`. Real
//!     evaluations may differ if policies use specific resource ARNs.
//!   * Some action evaluations need context keys we don't supply — those
//!     come back as implicitDeny and are treated as Denied.

use aws_sdk_iam::Client as IamClient;
use std::collections::BTreeSet;

use crate::counter::Counter;
use crate::error::is_access_denied;

const BATCH_SIZE: usize = 50;

#[derive(Debug, Default)]
pub struct SimulateResult {
    pub allowed: BTreeSet<String>,
    pub call_count: u32,
}

pub async fn run(
    iam: &IamClient,
    principal_arn: &str,
    actions: &[&str],
    counter: &Counter,
) -> Option<SimulateResult> {
    let mut out = SimulateResult::default();

    for chunk in actions.chunks(BATCH_SIZE) {
        counter.inc("iam:SimulatePrincipalPolicy");
        out.call_count += 1;

        let resp = iam
            .simulate_principal_policy()
            .policy_source_arn(principal_arn)
            .set_action_names(Some(chunk.iter().map(|s| s.to_string()).collect()))
            .resource_arns("*")
            .send()
            .await;

        match resp {
            Ok(o) => {
                for r in o.evaluation_results() {
                    let action = r.eval_action_name();
                    // Compare via `.as_str()` — robust against future SDK
                    // additions to the PolicyEvaluationDecisionType enum.
                    // SDK ≥ 1.108: eval_decision() returns &PolicyEvaluationDecisionType
                    // directly (not Option), so no .map() needed.
                    let allowed = r.eval_decision().as_str() == "allowed";
                    if allowed {
                        out.allowed.insert(action.to_string());
                    }
                }
            }
            Err(e) => {
                let s = format!("{}", e);
                if is_access_denied(&s) {
                    tracing::debug!("iam:SimulatePrincipalPolicy denied — bailing out");
                    return None;
                }
                tracing::warn!("simulate failed: {}", crate::error::short(&e));
                return None;
            }
        }
    }

    Some(out)
}
