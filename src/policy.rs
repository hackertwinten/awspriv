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
    let mut admin = false;
    let mut wildcard_resource = false;
    let mut notes = Vec::new();

    for st in statements {
        let actions = collect_strings(st.action.as_ref());
        let not_actions = collect_strings(st.not_action.as_ref());
        let resources = collect_strings(st.resource.as_ref());

        // Resource flag — note it once.
        if resources.iter().any(|r| r == "*") {
            wildcard_resource = true;
        }

        // Conditions are advisory at this level.
        if st.condition.is_some() {
            notes.push("statement has Condition — actual access may be narrower".into());
        }

        let is_allow = st.effect.eq_ignore_ascii_case("Allow");
        let is_deny = st.effect.eq_ignore_ascii_case("Deny");

        if !not_actions.is_empty() {
            notes.push(format!(
                "{} statement uses NotAction ({}) — coverage approximated",
                st.effect,
                not_actions.join(", ")
            ));
            // Allow + NotAction "X" ≈ full admin minus X. Treat as admin signal
            // for scoring; the user gets a note.
            if is_allow {
                admin = true;
            }
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
                    for m in catalog::expand_glob(action) {
                        deny_set.insert(m.action.to_string());
                    }
                }
                continue;
            }
            if is_allow {
                allow_set.insert(action.clone());
            } else if is_deny {
                deny_set.insert(action.clone());
            }
        }
    }

    // Apply Deny.
    for d in &deny_set {
        allow_set.remove(d);
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
    fn statement_can_be_object_not_array() {
        let doc = r#"{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}"#;
        let p = parse(doc);
        assert!(p.allowed.contains("s3:GetObject"));
    }

    #[test]
    fn handles_url_encoded_doc() {
        let doc = "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22*%22%7D%5D%7D";
        let p = parse(doc);
        assert!(p.allowed.contains("s3:GetObject"));
    }
}
