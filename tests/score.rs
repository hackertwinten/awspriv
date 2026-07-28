//! Characterization tests for the scoring/ranking logic (`src/score.rs`).
//!
//! These pin the product's core judgment: the admin trump card, the composite
//! weighting, per-dimension caps, and the tier cutoffs. They exercise the
//! public `score::rank` entry point rather than the private `score_one`.

use std::collections::{BTreeMap, BTreeSet};

use awspriv::counter::CounterSnapshot;
use awspriv::enumerate::{Assessment, Source};
use awspriv::identity::{Identity, KeyKind};
use awspriv::score::{rank, Scored, Tier};

fn identity() -> Identity {
    Identity {
        account: Some("123456789012".into()),
        arn: Some("arn:aws:iam::123456789012:user/test".into()),
        user_id: Some("AIDATESTTESTTEST".into()),
        key_kind: KeyKind::LongTerm,
        principal_name: Some("test".into()),
        is_assumed_role: false,
        sts_error: None,
    }
}

/// Build an assessment from a set of confirmed actions (+ admin flag).
fn assess(label: &str, actions: &[&str], admin: bool) -> Assessment {
    Assessment {
        label: label.into(),
        mode: "Stealth".into(),
        identity: identity(),
        confirmed_actions: actions.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>(),
        allowed_wildcards: BTreeSet::new(),
        admin,
        wildcard_resource: false,
        source: Source::IamPolicy,
        raw_policy_documents: Vec::new(),
        policy_notes: Vec::new(),
        probe_errors: Vec::new(),
        api_calls: CounterSnapshot {
            total: 0,
            by_action: BTreeMap::new(),
        },
    }
}

fn score_one(actions: &[&str], admin: bool) -> Scored {
    rank(vec![assess("k", actions, admin)]).pop().unwrap()
}

#[test]
fn admin_trumps_everything() {
    // Admin flag with no confirmed actions still pins the top tier.
    let s = score_one(&[], true);
    assert_eq!(s.admin_score, 100);
    assert_eq!(s.score, 100);
    assert!(matches!(s.tier, Tier::Critical));
}

#[test]
fn empty_assessment_is_minimal() {
    let s = score_one(&[], false);
    assert_eq!(s.score, 0);
    assert!(matches!(s.tier, Tier::Minimal));
}

#[test]
fn privesc_weight_is_summed() {
    // iam:CreateAccessKey (25) + iam:AttachUserPolicy (25) = 50.
    let s = score_one(&["iam:CreateAccessKey", "iam:AttachUserPolicy"], false);
    assert_eq!(s.privesc_score, 50);
    assert_eq!(s.data_score, 0);
    assert_eq!(s.write_score, 0);
    assert_eq!(s.privesc_actions.len(), 2);
}

#[test]
fn dimensions_are_bucketed_by_kind() {
    let s = score_one(
        &[
            "iam:CreateAccessKey",           // privesc 25
            "secretsmanager:GetSecretValue", // data 15
            "ec2:TerminateInstances",        // write 18
        ],
        false,
    );
    assert_eq!(s.privesc_score, 25);
    assert_eq!(s.data_score, 15);
    assert_eq!(s.write_score, 18);
    assert_eq!(s.sensitive_actions, vec!["secretsmanager:GetSecretValue"]);
    assert_eq!(s.destructive_actions, vec!["ec2:TerminateInstances"]);
}

#[test]
fn per_dimension_scores_saturate_at_100() {
    // Many privesc actions summing well past 100 must clamp.
    let actions = [
        "iam:CreatePolicyVersion",     // 25
        "iam:SetDefaultPolicyVersion", // 25
        "iam:CreateAccessKey",         // 25
        "iam:CreateLoginProfile",      // 25
        "iam:AttachUserPolicy",        // 25
        "iam:PutUserPolicy",           // 25
    ]; // raw sum 150
    let s = score_one(&actions, false);
    assert_eq!(s.privesc_score, 100, "privesc dimension must cap at 100");
}

#[test]
fn breadth_counts_distinct_services_and_caps() {
    // Recon actions carry no risk weight but each distinct service adds breadth.
    let actions = [
        "ec2:DescribeInstances",
        "lambda:ListFunctions",
        "eks:ListClusters",
        "ecr:DescribeRepositories",
        "kms:ListAliases",
        "dynamodb:ListTables",
    ]; // 6 distinct services * 8 = 48
    let s = score_one(&actions, false);
    assert_eq!(s.breadth_score, 48);
    assert_eq!(s.privesc_score, 0);
    assert_eq!(s.services_touched.len(), 6);
}

#[test]
fn composite_blends_dimensions() {
    // privesc 25 (iam) + data 15 (secretsmanager) across 2 services (breadth 16).
    // composite = 25*0.40 + 15*0.25 + 0 + 16*0.15 = 10 + 3.75 + 2.4 = 16.15 -> 16
    let s = score_one(&["iam:CreateAccessKey", "secretsmanager:GetSecretValue"], false);
    assert_eq!(s.privesc_score, 25);
    assert_eq!(s.data_score, 15);
    assert_eq!(s.breadth_score, 16);
    assert_eq!(s.score, 16);
    assert!(matches!(s.tier, Tier::Low));
}

#[test]
fn tier_cutoffs() {
    // Exercise every boundary of Tier::from_score.
    assert!(matches!(Tier::from_score(80), Tier::Critical));
    assert!(matches!(Tier::from_score(79), Tier::High));
    assert!(matches!(Tier::from_score(60), Tier::High));
    assert!(matches!(Tier::from_score(59), Tier::Medium));
    assert!(matches!(Tier::from_score(35), Tier::Medium));
    assert!(matches!(Tier::from_score(34), Tier::Low));
    assert!(matches!(Tier::from_score(10), Tier::Low));
    assert!(matches!(Tier::from_score(9), Tier::Minimal));
    assert!(matches!(Tier::from_score(0), Tier::Minimal));
}

#[test]
fn rank_sorts_by_score_then_label() {
    let admin = assess("zebra", &[], true); // score 100
    let low = assess("alpha", &["iam:CreateAccessKey"], false); // low
    let low_tie = assess("beta", &["iam:AttachUserPolicy"], false); // same score as alpha
    let out = rank(vec![low_tie, admin, low]);

    // Highest score first; equal scores broken by label ascending.
    assert_eq!(out[0].label, "zebra");
    assert_eq!(out[0].score, 100);
    assert_eq!(out[1].label, "alpha");
    assert_eq!(out[2].label, "beta");
    assert_eq!(out[1].score, out[2].score);
}
