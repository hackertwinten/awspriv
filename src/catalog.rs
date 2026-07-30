//! Action catalog. Maps AWS action names to (service, risk-kind, weight).
//!
//! Two roles:
//!   * Scoring — actions confirmed via probe or policy parse get tagged here.
//!   * Wildcard expansion — when a policy contains `iam:*`, we expand it
//!     against this catalog to score it correctly.
//!
//! The Privesc set is the well-known Rhino Security Labs research (Spencer
//! Gietzen, 2018) plus a few widely accepted additions.
//!
//! Extending: append a row. Macros below keep it terse.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize)]
pub enum RiskKind {
    Privesc,
    DataRead,
    Write,
    #[allow(dead_code)]
    Destruct,
    Recon,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionMeta {
    pub action: &'static str,
    pub service: &'static str,
    pub kind: RiskKind,
    pub weight: u32,
}

#[rustfmt::skip]
pub const CATALOG: &[ActionMeta] = &[
    // --- Privesc — Rhino Security 2018 + commonly-cited additions ---
    p("iam:CreatePolicyVersion",            "iam",            25),
    p("iam:SetDefaultPolicyVersion",        "iam",            25),
    p("iam:CreateAccessKey",                "iam",            25),
    p("iam:CreateLoginProfile",             "iam",            25),
    p("iam:UpdateLoginProfile",             "iam",            25),
    p("iam:AttachUserPolicy",               "iam",            25),
    p("iam:AttachGroupPolicy",              "iam",            25),
    p("iam:AttachRolePolicy",               "iam",            25),
    p("iam:PutUserPolicy",                  "iam",            25),
    p("iam:PutGroupPolicy",                 "iam",            25),
    p("iam:PutRolePolicy",                  "iam",            25),
    p("iam:AddUserToGroup",                 "iam",            20),
    p("iam:UpdateAssumeRolePolicy",         "iam",            25),
    p("iam:PassRole",                       "iam",            20),
    p("sts:AssumeRole",                     "sts",            10),
    p("lambda:CreateFunction",              "lambda",         15),
    p("lambda:UpdateFunctionCode",          "lambda",         15),
    p("lambda:InvokeFunction",              "lambda",          8),
    p("ec2:RunInstances",                   "ec2",            15),
    p("glue:CreateDevEndpoint",             "glue",           15),
    p("cloudformation:CreateStack",         "cloudformation", 12),

    // --- Sensitive data reads ---
    d("s3:GetObject",                  "s3",              8),
    d("s3:ListBucket",                 "s3",              4),
    d("s3:GetBucketAcl",               "s3",              4),
    d("secretsmanager:GetSecretValue", "secretsmanager", 15),
    d("secretsmanager:ListSecrets",    "secretsmanager",  6),
    d("kms:Decrypt",                   "kms",            12),
    d("kms:ListKeys",                  "kms",             4),
    d("ssm:GetParameter",              "ssm",             8),
    d("ssm:GetParameters",             "ssm",             8),
    d("ssm:GetParametersByPath",       "ssm",            10),
    d("ssm:DescribeParameters",        "ssm",             5),
    d("dynamodb:Scan",                 "dynamodb",       10),
    d("dynamodb:GetItem",              "dynamodb",        6),
    d("rds:DescribeDBInstances",       "rds",             4),
    d("ecr:BatchGetImage",             "ecr",             6),
    d("ecr:GetDownloadUrlForLayer",    "ecr",             6),

    // --- Write / destructive ---
    w("ec2:TerminateInstances",             "ec2",        18),
    w("ec2:StopInstances",                  "ec2",        10),
    w("s3:DeleteBucket",                    "s3",         18),
    w("s3:DeleteObject",                    "s3",         10),
    w("s3:PutObject",                       "s3",          6),
    w("rds:DeleteDBInstance",               "rds",        20),
    w("dynamodb:DeleteTable",               "dynamodb",   15),
    w("kms:ScheduleKeyDeletion",            "kms",        18),
    w("eks:DeleteCluster",                  "eks",        18),
    w("cloudtrail:StopLogging",             "cloudtrail", 22),
    w("cloudtrail:DeleteTrail",             "cloudtrail", 22),
    w("config:DeleteConfigurationRecorder", "config",     18),

    // --- Recon (counted toward breadth, no weight) ---
    r("sts:GetCallerIdentity",        "sts"),
    r("iam:GetUser",                  "iam"),
    r("iam:GetAccountSummary",        "iam"),
    r("iam:ListAttachedUserPolicies", "iam"),
    r("iam:ListUserPolicies",         "iam"),
    r("iam:ListUsers",                "iam"),
    r("iam:ListRoles",                "iam"),
    r("iam:ListGroups",               "iam"),
    r("iam:ListPolicies",             "iam"),
    r("iam:GetPolicy",                "iam"),
    r("iam:GetPolicyVersion",         "iam"),
    r("iam:GetUserPolicy",            "iam"),
    r("iam:ListGroupsForUser",        "iam"),
    r("iam:ListAttachedGroupPolicies","iam"),
    r("iam:ListGroupPolicies",        "iam"),
    r("iam:GetGroupPolicy",           "iam"),
    r("iam:SimulatePrincipalPolicy",  "iam"),
    r("ec2:DescribeInstances",        "ec2"),
    r("ec2:DescribeSecurityGroups",   "ec2"),
    r("ec2:DescribeVpcs",             "ec2"),
    r("ec2:DescribeSnapshots",        "ec2"),
    r("lambda:ListFunctions",         "lambda"),
    r("eks:ListClusters",             "eks"),
    r("ecr:DescribeRepositories",     "ecr"),
    r("kms:ListAliases",              "kms"),
    r("dynamodb:ListTables",          "dynamodb"),
];

const fn p(action: &'static str, service: &'static str, weight: u32) -> ActionMeta {
    ActionMeta { action, service, kind: RiskKind::Privesc, weight }
}
const fn d(action: &'static str, service: &'static str, weight: u32) -> ActionMeta {
    ActionMeta { action, service, kind: RiskKind::DataRead, weight }
}
const fn w(action: &'static str, service: &'static str, weight: u32) -> ActionMeta {
    ActionMeta { action, service, kind: RiskKind::Write, weight }
}
const fn r(action: &'static str, service: &'static str) -> ActionMeta {
    ActionMeta { action, service, kind: RiskKind::Recon, weight: 0 }
}

pub fn lookup(action: &str) -> Option<&'static ActionMeta> {
    CATALOG.iter().find(|m| m.action.eq_ignore_ascii_case(action))
}

/// Expand a glob like `iam:*` or `s3:Get*` against the catalog.
/// Used by the policy parser to enumerate concrete actions from wildcards.
pub fn expand_glob(pattern: &str) -> Vec<&'static ActionMeta> {
    if pattern == "*" {
        return CATALOG.iter().collect();
    }
    let Some((svc, act)) = pattern.split_once(':') else {
        return Vec::new();
    };
    CATALOG
        .iter()
        .filter(|m| m.service.eq_ignore_ascii_case(svc))
        .filter(|m| {
            let action_part = m.action.split_once(':').map_or(m.action, |x| x.1);
            glob_match(act, action_part)
        })
        .collect()
}

fn glob_match(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return candidate
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase());
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return candidate
            .to_ascii_lowercase()
            .ends_with(&suffix.to_ascii_lowercase());
    }
    pattern.eq_ignore_ascii_case(candidate)
}

/// All catalog actions that touch privesc / data / write categories — the
/// "interesting" subset used to seed SimulatePrincipalPolicy when the IAM
/// read path is denied.
pub fn interesting_actions() -> Vec<&'static str> {
    CATALOG
        .iter()
        .filter(|m| !matches!(m.kind, RiskKind::Recon))
        .map(|m| m.action)
        .collect()
}
