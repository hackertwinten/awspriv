//! IAM self-read path — the stealthy enumeration primitive.
//!
//! Behaviour:
//!   * Uses the principal name extracted from `sts:GetCallerIdentity`. We do
//!     NOT call `iam:ListUsers` / `iam:GetAccountAuthorizationDetails` — those
//!     are the classic enumeration signatures anomaly detection watches for.
//!   * All calls here (`GetUser`, `ListGroupsForUser`, `List*Policies`,
//!     `Get*Policy*`) ride the same signature as a routine console/SDK
//!     "load my user page" flow.
//!   * Fail-fast on the first AccessDenied for `GetUser`. If the principal
//!     can't even `GetUser` itself, hammering more IAM endpoints just generates
//!     denied-call patterns in CloudTrail. Sub-branches (attached / inline /
//!     group) each degrade gracefully so a limited IAM scope still yields
//!     whatever it can read.
//!   * Returns parsed policies, ready to be scored locally.
//!
//! Trail volume in the happy path: 5–10 calls, all `iam:Get*` / `iam:List*`.

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
    /// Whether `AdministratorAccess` is among the attached managed policies
    /// (user- or group-level).
    pub has_admin_attachment: bool,
    /// IAM-side actions confirmed during the read.
    pub confirmed_actions: Vec<&'static str>,
    /// Advisory notes surfaced to the report (e.g. permissions boundary).
    pub notes: Vec<String>,
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

    // 1) GetUser confirms basic IAM read on ourselves. Also surfaces a
    //    permissions boundary if one is attached — a boundary CAPS effective
    //    permissions, so we note it (we do not yet intersect it; see #008).
    counter.inc("iam:GetUser");
    match iam.get_user().user_name(user).send().await {
        Ok(o) => {
            out.confirmed_actions.push("iam:GetUser");
            got_anything = true;
            if let Some(arn) = o
                .user()
                .and_then(|u| u.permissions_boundary())
                .and_then(|pb| pb.permissions_boundary_arn())
            {
                out.notes.push(format!(
                    "permissions boundary attached ({arn}) — effective permissions \
                     may be capped below what these policies grant (not evaluated)"
                ));
            }
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

    // 2) Attached managed policies (user-level).
    counter.inc("iam:ListAttachedUserPolicies");
    if let Ok(o) = iam.list_attached_user_policies().user_name(user).send().await {
        out.confirmed_actions.push("iam:ListAttachedUserPolicies");
        got_anything = true;
        for ap in o.attached_policies() {
            if let Some(arn) = ap.policy_arn() {
                fetch_managed_policy(iam, arn, counter, &mut out).await;
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
                ingest_doc(p.policy_document(), &mut out);
            }
        }
    }

    // 4) Group-derived permissions. Users commonly get their real power from a
    //    group (the canonical `Admins` group holding AdministratorAccess), so a
    //    read that stops at user-level policies mis-scores admins as MINIMAL
    //    (#006). `ListGroupsForUser` is targeted and rides the normal get-user
    //    flow. Degrades gracefully: a denial here still returns user results.
    counter.inc("iam:ListGroupsForUser");
    if let Ok(o) = iam.list_groups_for_user().user_name(user).send().await {
        out.confirmed_actions.push("iam:ListGroupsForUser");
        got_anything = true;
        for g in o.groups() {
            let group = g.group_name();
            read_group_policies(iam, group, counter, &mut out).await;
        }
    }

    if got_anything {
        Some(out)
    } else {
        None
    }
}

/// Read a single group's attached-managed + inline policies into `out`.
async fn read_group_policies(
    iam: &IamClient,
    group: &str,
    counter: &Counter,
    out: &mut IamReadResult,
) {
    counter.inc("iam:ListAttachedGroupPolicies");
    if let Ok(o) = iam
        .list_attached_group_policies()
        .group_name(group)
        .send()
        .await
    {
        out.confirmed_actions.push("iam:ListAttachedGroupPolicies");
        for ap in o.attached_policies() {
            if let Some(arn) = ap.policy_arn() {
                fetch_managed_policy(iam, arn, counter, out).await;
            }
        }
    }

    counter.inc("iam:ListGroupPolicies");
    if let Ok(o) = iam.list_group_policies().group_name(group).send().await {
        out.confirmed_actions.push("iam:ListGroupPolicies");
        for name in o.policy_names() {
            counter.inc("iam:GetGroupPolicy");
            if let Ok(p) = iam
                .get_group_policy()
                .group_name(group)
                .policy_name(name)
                .send()
                .await
            {
                out.confirmed_actions.push("iam:GetGroupPolicy");
                ingest_doc(p.policy_document(), out);
            }
        }
    }
}

/// Resolve a managed-policy ARN to its default-version document and ingest it.
/// Shared by user- and group-level attached policies. Flags AdministratorAccess.
async fn fetch_managed_policy(
    iam: &IamClient,
    arn: &str,
    counter: &Counter,
    out: &mut IamReadResult,
) {
    if arn.ends_with(":policy/AdministratorAccess") {
        out.has_admin_attachment = true;
    }

    counter.inc("iam:GetPolicy");
    let Ok(p) = iam.get_policy().policy_arn(arn).send().await else {
        return;
    };
    out.confirmed_actions.push("iam:GetPolicy");

    let Some(default_ver) = p
        .policy()
        .and_then(|pp| pp.default_version_id())
        .map(|s| s.to_string())
    else {
        return;
    };

    counter.inc("iam:GetPolicyVersion");
    let Ok(v) = iam
        .get_policy_version()
        .policy_arn(arn)
        .version_id(&default_ver)
        .send()
        .await
    else {
        return;
    };
    out.confirmed_actions.push("iam:GetPolicyVersion");

    if let Some(doc) = v.policy_version().and_then(|pv| pv.document()) {
        ingest_doc(doc, out);
    }
}

/// Parse a (possibly URL-encoded) policy document and store both the parsed
/// result and the decoded raw JSON for the verbose report.
fn ingest_doc(doc: &str, out: &mut IamReadResult) {
    let parsed = policy::parse(doc);
    let raw = urlencoding::decode(doc)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| doc.to_string());
    out.raw_documents.push(raw);
    out.policies.push(parsed);
}
