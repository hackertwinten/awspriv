//! Local IAM policy parser.
//!
//! This is the engine behind stealth mode: once we have a policy document
//! (typically pulled with `iam:GetPolicyVersion` or `iam:GetUserPolicy`), we
//! parse it locally and never go back to the AWS API to ask "can I do X?".
//!
//! Coverage:
//!   * Statement as object or array
//!   * Action / NotAction as string or array
//!   * Effect Allow + Effect Deny (Deny subtracts from the Allow set)
//!   * Wildcard expansion (`iam:*`, `s3:Get*`, `*`) against the catalog
//!   * Detection of `*` action (admin) and `*` resource (unscoped)
//!
//! Limitations (called out in README):
//!   * Conditions are not evaluated. We treat them as advisory.
//!   * NotAction approximated as "all catalog actions" minus listed.
//!   * SCPs / permission boundaries / session policies are NOT visible at
//!     this level — for that, use SimulatePrincipalPolicy.

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;

use crate::catalog;

#[derive(Debug, Clone, Default)]
pub struct ParsedPolicy {
    /// Concrete actions allowed (after wildcard expansion + Deny subtraction).
    pub allowed: BTreeSet<String>,
    /// Raw wildcard patterns that appeared in Allow statements (e.g. `iam:*`).
    /// Useful for the report — tells the operator about implicit power that
    /// might cover actions outside our catalog.
    pub allowed_wildcards: BTreeSet<String>,
    /// True if any Allow contains `Action: "*"` (full admin).
    pub admin: bool,
    /// True if any Allow has `Resource: "*"`. Combined with sensitive actions
    /// this means unscoped access (e.g. read all S3 buckets, not just one).
    pub has_wildcard_resource: bool,
    /// Free-form notes (NotAction usage, conditions, parse anomalies).
    pub notes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PolicyDoc {
    #[serde(rename = "Statement")]
    statement: Value, // object | array
}

#[derive(Debug, Deserialize)]
struct Statement {
    #[serde(rename = "Effect")]
    effect: String,
    #[serde(rename = "Action")]
    action: Option<Value>,
    #[serde(rename = "NotAction")]
    not_action: Option<Value>,
    #[serde(rename = "Resource")]
    resource: Option<Value>,
    #[serde(rename = "Condition")]
    condition: Option<Value>,
}

/// Parse a policy document. The doc may be either:
///   * An IAM policy JSON string (most likely), or
///   * URL-encoded JSON (the form `iam:GetPolicyVersion` returns).
pub fn parse(doc: &str) -> ParsedPolicy {
    // Decode URL-encoding if present. AWS returns `Document` URL-encoded.
    let decoded = match urlencoding::decode(doc) {
        Ok(s) => s.into_owned(),
        Err(_) => doc.to_string(),
    };

    let json: PolicyDoc = match serde_json::from_str(&decoded) {
        Ok(p) => p,
        Err(e) => {
            return ParsedPolicy {
                notes: vec![format!("policy parse failed: {}", e)],
                ..Default::default()
            }
        }
    };

    let statements: Vec<Statement> = match json.statement {
        Value::Array(arr) => arr
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect(),
        v @ Value::Object(_) => serde_json::from_value(v).into_iter().collect(),
        _ => Vec::new(),
    };

    let mut allow_set: BTreeSet<String> = BTreeSet::new();
    let mut allow_wildcards: BTreeSet<String> = BTreeSet::new();
    let mut deny_set: BTreeSet<String> = BTreeSet::new();
    // Denies that are resource-scoped or conditional. We can't match them
    // against the (unscoped) allow set without resource evaluation, so rather
    // than subtract them globally — which would under-report a broad Allow —
    // we collect them for a note and leave the allow set intact.
    let mut scoped_denies: BTreeSet<String> = BTreeSet::new();
    let mut admin = false;
    let mut wildcard_resource = false;
    let mut notes = Vec::new();

    for st in statements {
        let actions = collect_strings(st.action.as_ref());
        let not_actions = collect_strings(st.not_action.as_ref());
        let resources = collect_strings(st.resource.as_ref());

        // Resource flag — note it once.
        let stmt_resource_wild = resources.iter().any(|r| r == "*");
        if stmt_resource_wild {
            wildcard_resource = true;
        }

        // Conditions are advisory at this level.
        let has_condition = st.condition.is_some();
        if has_condition {
            notes.push("statement has Condition — actual access may be narrower".into());
        }

        let is_allow = st.effect.eq_ignore_ascii_case("Allow");
        let is_deny = st.effect.eq_ignore_ascii_case("Deny");

        // A Deny only removes a permission everywhere when it is unconditional
        // AND applies to every resource (`Resource: "*"`). A Deny scoped to one
        // resource, or gated by a Condition, must NOT be subtracted from a
        // broadly-allowed action — doing so under-reports the grant (#5).
        let deny_is_global = is_deny && stmt_resource_wild && !has_condition;

        if !not_actions.is_empty() {
            notes.push(format!(
                "{} statement uses NotAction ({}) — coverage approximated",
                st.effect,
                not_actions.join(", ")
            ));
            // `Allow NotAction: [X]` grants "everything except X". It is NOT
            // automatically admin — `Allow NotAction:["s3:*"] Resource:"<one arn>"`
            // is a routine scoping idiom. Only expand it into a broad grant when
            // the statement is unscoped (Resource: "*"); otherwise just note it,
            // since we can't yet reason about the specific resource (see #5).
            if is_allow {
                if stmt_resource_wild {
                    // Effective allow ≈ (all catalog actions) minus the excluded
                    // set. Deliberately does NOT set `admin` — this scores high
                    // via the composite (breadth + risk sums) without forcing the
                    // 100/CRITICAL admin trump reserved for literal `Action: "*"`.
                    let excluded: BTreeSet<String> = not_actions
                        .iter()
                        .flat_map(|na| {
                            if na.contains('*') {
                                catalog::expand_glob(na)
                                    .into_iter()
                                    .map(|m| m.action.to_string())
                                    .collect::<Vec<_>>()
                            } else {
                                vec![na.clone()]
                            }
                        })
                        .collect();
                    for m in catalog::expand_glob("*") {
                        let a = m.action.to_string();
                        if !excluded.contains(&a) {
                            allow_set.insert(a);
                        }
                    }
                    allow_wildcards.insert(format!("NotAction:[{}]", not_actions.join(",")));
                } else {
                    notes.push(
                        "Allow+NotAction on a scoped resource — effective actions not \
                         expanded (resource-specific; not treated as admin)"
                            .into(),
                    );
                }
            }
            // Deny + NotAction is scope-sensitive and deferred to #5: note only.
        }

        for action in &actions {
            if action == "*" && is_allow {
                admin = true;
                allow_wildcards.insert("*".into());
                continue;
            }
            if action.contains('*') {
                if is_allow {
                    allow_wildcards.insert(action.clone());
                    for m in catalog::expand_glob(action) {
                        allow_set.insert(m.action.to_string());
                    }
                } else if is_deny {
                    let sink = if deny_is_global {
                        &mut deny_set
                    } else {
                        &mut scoped_denies
                    };
                    for m in catalog::expand_glob(action) {
                        sink.insert(m.action.to_string());
                    }
                }
                continue;
            }
            if is_allow {
                allow_set.insert(action.clone());
            } else if deny_is_global {
                deny_set.insert(action.clone());
            } else if is_deny {
                scoped_denies.insert(action.clone());
            }
        }
    }

    // Apply only the global (unconditional, resource-wildcard) Denies.
    for d in &deny_set {
        allow_set.remove(d);
    }

    // Resource-scoped / conditional Denies are reported but not subtracted, so
    // the operator knows a narrower Deny exists without us under-reporting the
    // Allow it partially overlaps.
    let scoped_only: Vec<&String> = scoped_denies.difference(&deny_set).collect();
    if !scoped_only.is_empty() {
        let mut names: Vec<&str> = scoped_only.iter().map(|s| s.as_str()).collect();
        names.sort_unstable();
        notes.push(format!(
            "scoped/conditional Deny not applied globally (review): {}",
            names.join(", ")
        ));
    }

    ParsedPolicy {
        allowed: allow_set,
        allowed_wildcards: allow_wildcards,
        admin,
        has_wildcard_resource: wildcard_resource,
        notes,
    }
}

/// Merge multiple parsed policies into a single effective set.
pub fn merge(policies: &[ParsedPolicy]) -> ParsedPolicy {
    let mut out = ParsedPolicy::default();
    for p in policies {
        out.allowed.extend(p.allowed.iter().cloned());
        out.allowed_wildcards
            .extend(p.allowed_wildcards.iter().cloned());
        if p.admin {
            out.admin = true;
        }
        if p.has_wildcard_resource {
            out.has_wildcard_resource = true;
        }
        out.notes.extend(p.notes.iter().cloned());
    }
    out
}

/// Cap an identity-based grant by a permissions boundary.
///
/// Effective permissions are the **intersection** of the identity policies and
/// the boundary: an action is allowed only if BOTH permit it. `admin` (the
/// literal `Action: "*"`) survives only if both sides are admin.
///
/// Because our admin signal is a flag rather than an enumerated set, an admin
/// side is treated as "allows everything", so the intersection collapses to the
/// other side's allow set. Resource-wildcard status also intersects (unscoped
/// only if both are).
pub fn intersect(base: &ParsedPolicy, boundary: &ParsedPolicy) -> ParsedPolicy {
    let admin = base.admin && boundary.admin;

    let allowed: BTreeSet<String> = if boundary.admin {
        base.allowed.clone()
    } else if base.admin {
        boundary.allowed.clone()
    } else {
        base.allowed.intersection(&boundary.allowed).cloned().collect()
    };

    let allowed_wildcards: BTreeSet<String> = if boundary.admin {
        base.allowed_wildcards.clone()
    } else if base.admin {
        boundary.allowed_wildcards.clone()
    } else {
        base.allowed_wildcards
            .intersection(&boundary.allowed_wildcards)
            .cloned()
            .collect()
    };

    let mut notes = base.notes.clone();
    notes.push("effective permissions capped by a permissions boundary".into());
    notes.extend(boundary.notes.iter().map(|n| format!("boundary: {n}")));

    ParsedPolicy {
        allowed,
        allowed_wildcards,
        admin,
        has_wildcard_resource: base.has_wildcard_resource && boundary.has_wildcard_resource,
        notes,
    }
}

fn collect_strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_allow() {
        let doc = r#"{
            "Version":"2012-10-17",
            "Statement":[{
                "Effect":"Allow",
                "Action":["s3:GetObject","s3:ListBucket"],
                "Resource":"*"
            }]
        }"#;
        let p = parse(doc);
        assert!(p.allowed.contains("s3:GetObject"));
        assert!(p.allowed.contains("s3:ListBucket"));
        assert!(p.has_wildcard_resource);
        assert!(!p.admin);
    }

    #[test]
    fn detects_admin_wildcard() {
        let doc = r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
        let p = parse(doc);
        assert!(p.admin);
    }

    #[test]
    fn deny_subtracts_from_allow() {
        let doc = r#"{"Statement":[
            {"Effect":"Allow","Action":"iam:*","Resource":"*"},
            {"Effect":"Deny","Action":"iam:DeleteUser","Resource":"*"}
        ]}"#;
        let p = parse(doc);
        assert!(p.allowed.contains("iam:CreatePolicyVersion"));
        assert!(!p.allowed.contains("iam:DeleteUser"));
    }

    #[test]
    fn resource_scoped_deny_is_not_subtracted() {
        // A Deny scoped to one user must NOT remove the action from a
        // Resource:"*" Allow — that would under-report the grant (#5).
        let doc = r#"{"Statement":[
            {"Effect":"Allow","Action":"iam:*","Resource":"*"},
            {"Effect":"Deny","Action":"iam:CreateAccessKey","Resource":"arn:aws:iam::123:user/bob"}
        ]}"#;
        let p = parse(doc);
        assert!(
            p.allowed.contains("iam:CreateAccessKey"),
            "scoped Deny should leave the broadly-allowed action in place"
        );
        assert!(
            p.notes.iter().any(|n| n.contains("scoped/conditional Deny")),
            "scoped Deny should be surfaced as a note"
        );
    }

    #[test]
    fn conditional_deny_is_not_subtracted() {
        // A Deny gated by a Condition is not unconditional, so it must not be
        // applied globally.
        let doc = r#"{"Statement":[
            {"Effect":"Allow","Action":"iam:*","Resource":"*"},
            {"Effect":"Deny","Action":"iam:AttachUserPolicy","Resource":"*",
             "Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}
        ]}"#;
        let p = parse(doc);
        assert!(p.allowed.contains("iam:AttachUserPolicy"));
        assert!(p.notes.iter().any(|n| n.contains("scoped/conditional Deny")));
    }

    #[test]
    fn unconditional_wildcard_deny_still_subtracts() {
        // Regression guard: the global-Deny path is unchanged.
        let doc = r#"{"Statement":[
            {"Effect":"Allow","Action":"iam:*","Resource":"*"},
            {"Effect":"Deny","Action":"iam:CreateAccessKey","Resource":"*"}
        ]}"#;
        let p = parse(doc);
        assert!(!p.allowed.contains("iam:CreateAccessKey"));
    }

    #[test]
    fn statement_can_be_object_not_array() {
        let doc = r#"{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}"#;
        let p = parse(doc);
        assert!(p.allowed.contains("s3:GetObject"));
    }

    #[test]
    fn allow_notaction_scoped_resource_is_not_admin() {
        // The false-CRITICAL case: excluding a service on a specific
        // resource is a scoping idiom, not admin.
        let doc = r#"{"Statement":[{
            "Effect":"Allow",
            "NotAction":["s3:*"],
            "Resource":"arn:aws:ec2:us-east-1:123456789012:instance/i-abc"
        }]}"#;
        let p = parse(doc);
        assert!(!p.admin, "scoped Allow+NotAction must not be admin");
        assert!(
            p.allowed.is_empty(),
            "resource-scoped NotAction should not expand into a broad allow set"
        );
    }

    #[test]
    fn allow_notaction_wildcard_resource_is_broad_but_not_admin() {
        // Unscoped Allow+NotAction: broad (everything except the excluded set)
        // but still not the literal-`*` admin trump.
        let doc = r#"{"Statement":[{
            "Effect":"Allow",
            "NotAction":["s3:*"],
            "Resource":"*"
        }]}"#;
        let p = parse(doc);
        assert!(!p.admin, "Allow+NotAction on * is broad but not the admin trump");
        // Excluded service is absent...
        assert!(!p.allowed.contains("s3:GetObject"));
        // ...while other catalog actions are present.
        assert!(p.allowed.contains("iam:CreateAccessKey"));
        assert!(p.has_wildcard_resource);
    }

    #[test]
    fn literal_action_star_is_still_admin() {
        let doc = r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
        let p = parse(doc);
        assert!(p.admin);
    }

    #[test]
    fn handles_url_encoded_doc() {
        let doc = "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22*%22%7D%5D%7D";
        let p = parse(doc);
        assert!(p.allowed.contains("s3:GetObject"));
    }

    fn allow(actions: &[&str], admin: bool) -> ParsedPolicy {
        ParsedPolicy {
            allowed: actions.iter().map(|s| s.to_string()).collect(),
            admin,
            ..Default::default()
        }
    }

    #[test]
    fn boundary_caps_admin_to_boundary_allow() {
        // AdministratorAccess identity, read-only boundary -> not admin, only
        // the boundary's actions survive (#7).
        let base = allow(&[], true);
        let boundary = allow(&["s3:GetObject", "s3:ListBucket"], false);
        let eff = intersect(&base, &boundary);
        assert!(!eff.admin, "boundary must strip admin");
        assert_eq!(eff.allowed.len(), 2);
        assert!(eff.allowed.contains("s3:GetObject"));
    }

    #[test]
    fn admin_boundary_leaves_identity_untouched() {
        let base = allow(&["iam:CreateAccessKey"], false);
        let boundary = allow(&[], true);
        let eff = intersect(&base, &boundary);
        assert!(!eff.admin, "admin only if BOTH sides are admin");
        assert!(eff.allowed.contains("iam:CreateAccessKey"));
    }

    #[test]
    fn both_admin_stays_admin() {
        let eff = intersect(&allow(&[], true), &allow(&[], true));
        assert!(eff.admin);
    }

    #[test]
    fn scoped_intersection_keeps_only_the_overlap() {
        let base = allow(&["s3:GetObject", "kms:Decrypt"], false);
        let boundary = allow(&["kms:Decrypt", "ec2:DescribeInstances"], false);
        let eff = intersect(&base, &boundary);
        assert_eq!(eff.allowed.iter().cloned().collect::<Vec<_>>(), vec!["kms:Decrypt"]);
    }

    #[test]
    fn empty_boundary_denies_everything() {
        let base = allow(&["s3:GetObject"], false);
        let boundary = allow(&[], false);
        let eff = intersect(&base, &boundary);
        assert!(eff.allowed.is_empty());
        assert!(!eff.admin);
    }
}
