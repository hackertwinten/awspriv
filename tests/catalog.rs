//! Integration tests for the catalog wildcard-expansion logic. The policy
//! parser's correctness depends on `expand_glob` returning the right set
//! of catalog actions for patterns like `iam:*` and `s3:Get*`.

use awspriv::catalog;

#[test]
fn star_expands_to_full_catalog() {
    let all = catalog::expand_glob("*");
    assert_eq!(all.len(), catalog::CATALOG.len());
}

#[test]
fn iam_star_expands_to_only_iam_actions() {
    let iam = catalog::expand_glob("iam:*");
    assert!(!iam.is_empty());
    assert!(iam.iter().all(|m| m.service == "iam"));
    // Must include known privesc-enabling actions.
    assert!(iam.iter().any(|m| m.action == "iam:CreateAccessKey"));
    assert!(iam.iter().any(|m| m.action == "iam:AttachUserPolicy"));
}

#[test]
fn prefix_glob_matches_correctly() {
    let s3_get = catalog::expand_glob("s3:Get*");
    assert!(s3_get.iter().any(|m| m.action == "s3:GetObject"));
    // Should not pull in s3:ListBucket via prefix match.
    assert!(!s3_get.iter().any(|m| m.action == "s3:ListBucket"));
    // Should not leak ec2 actions.
    assert!(s3_get.iter().all(|m| m.service == "s3"));
}

#[test]
fn unknown_service_returns_empty() {
    let empty = catalog::expand_glob("nosuchservice:*");
    assert!(empty.is_empty());
}

#[test]
fn pattern_without_colon_returns_empty() {
    let empty = catalog::expand_glob("iam");
    assert!(empty.is_empty());
}

#[test]
fn exact_match_is_case_insensitive() {
    let m = catalog::lookup("IAM:CreateAccessKey");
    assert!(m.is_some());
    assert_eq!(m.unwrap().action, "iam:CreateAccessKey");
}

#[test]
fn interesting_actions_excludes_recon() {
    let interesting = catalog::interesting_actions();
    // None of the listed actions should be Recon-kind.
    for a in &interesting {
        let m = catalog::lookup(a).expect("should be in catalog");
        assert!(
            !matches!(m.kind, catalog::RiskKind::Recon),
            "{} is Recon — should not appear in interesting_actions()",
            a
        );
    }
    // Should include canonical privesc + data actions.
    assert!(interesting.contains(&"iam:CreateAccessKey"));
    assert!(interesting.contains(&"secretsmanager:GetSecretValue"));
}
