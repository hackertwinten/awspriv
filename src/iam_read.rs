//! IAM self-read path — the stealthy enumeration primitive.
//!
//! Behaviour:
//!   * Uses the principal name extracted from `sts:GetCallerIdentity`. We do
//!     NOT call `iam:ListUsers` — that's a classic enumeration signature.
//!   * Fail-fast on the first AccessDenied. If the principal can't even
//!     `GetUser` itself, hammering ten more IAM endpoints just generates
//!     denied-call patterns in CloudTrail.
//!   * Returns parsed policies, ready to be scored locally.
//!
//! Trail volume in the happy path: 4–8 calls, all `iam:Get*` / `iam:List*`,
//! all matching the call signature of `aws iam get-user` + policy fetch.

use aws_sdk_iam::Client as IamClient;

use crate::counter::Counter;
use crate::error::is_access_denied;
use crate::identity::Identity;
use crate::policy::{self, ParsedPolicy};

#[derive(Debug, Default)]
pub struct IamReadResult {
    pub policies: Vec<ParsedPolicy>,
    /// URL-decoded raw policy JSON documents (for the report's verbose output).
    pub raw_documents: Vec<String>,
    /// Whether `AdministratorAccess` is among the attached managed policies.
    pub has_admin_attachment: bool,
    /// IAM-side actions confirmed during the read.
    pub confirmed_actions: Vec<&'static str>,
}

pub async fn try_read(iam: &IamClient, id: &Identity, counter: &Counter) -> Option<IamReadResult> {
    // Assumed-role sessions can't be enumerated via `iam:GetUser`. We could
    // try `ListAttachedRolePolicies` on the role, but that requires the
    // session to have iam:* perms — usually it doesn't. Skip cleanly.
    if id.is_assumed_role {
        tracing::debug!("identity is an assumed role — skipping IAM self-read");
        return None;
    }
    let user = id.principal_name.as_deref()?;

    let mut out = IamReadResult::default();
    let mut got_anything = false;

    // 1) GetUser confirms basic IAM read on ourselves.
    counter.inc("iam:GetUser");
    match iam.get_user().user_name(user).send().await {
        Ok(_) => {
            out.confirmed_actions.push("iam:GetUser");
            got_anything = true;
        }
        Err(e) => {
            let s = format!("{}", e);
            if is_access_denied(&s) {
                tracing::debug!("iam:GetUser denied — abandoning IAM read");
                return None;
            }
            tracing::warn!(
                "iam:GetUser failed (not access-denied): {}",
                crate::error::short(&e)
            );
        }
    }

    // 2) Attached managed policies.
    counter.inc("iam:ListAttachedUserPolicies");
    if let Ok(o) = iam.list_attached_user_policies().user_name(user).send().await {
        out.confirmed_actions.push("iam:ListAttachedUserPolicies");
        got_anything = true;

        for ap in o.attached_policies() {
            let Some(arn) = ap.policy_arn() else { continue };

            if arn.ends_with(":policy/AdministratorAccess") {
                out.has_admin_attachment = true;
            }

            counter.inc("iam:GetPolicy");
            let Ok(p) = iam.get_policy().policy_arn(arn).send().await else {
                continue;
            };
            out.confirmed_actions.push("iam:GetPolicy");

            let Some(default_ver) = p
                .policy()
                .and_then(|pp| pp.default_version_id())
                .map(|s| s.to_string())
            else {
                continue;
            };

            counter.inc("iam:GetPolicyVersion");
            let Ok(v) = iam
                .get_policy_version()
                .policy_arn(arn)
                .version_id(&default_ver)
                .send()
                .await
            else {
                continue;
            };
            out.confirmed_actions.push("iam:GetPolicyVersion");

            if let Some(doc) = v.policy_version().and_then(|pv| pv.document()) {
                let parsed = policy::parse(doc);
                let raw = urlencoding::decode(doc)
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|_| doc.to_string());
                out.raw_documents.push(raw);
                out.policies.push(parsed);
            }
        }
    }

    // 3) Inline user policies.
    counter.inc("iam:ListUserPolicies");
    if let Ok(o) = iam.list_user_policies().user_name(user).send().await {
        out.confirmed_actions.push("iam:ListUserPolicies");
        got_anything = true;

        for name in o.policy_names() {
            counter.inc("iam:GetUserPolicy");
            if let Ok(p) = iam
                .get_user_policy()
                .user_name(user)
                .policy_name(name)
                .send()
                .await
            {
                out.confirmed_actions.push("iam:GetUserPolicy");
                // `policy_document()` returns &str in modern aws-sdk-iam.
                let doc = p.policy_document();
                let parsed = policy::parse(doc);
                let raw = urlencoding::decode(doc)
                    .map(|s| s.into_owned())
                    .unwrap_or_else(|_| doc.to_string());
                out.raw_documents.push(raw);
                out.policies.push(parsed);
            }
        }
    }

    if got_anything {
        Some(out)
    } else {
        None
    }
}
