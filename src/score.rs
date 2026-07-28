//! Scoring + ranking.
//!
//! Each key earns points across five dimensions:
//!
//!   * Admin       — binary trump card (100 if `*:*` or AdministratorAccess)
//!   * Privesc     — sum of weights of confirmed privesc-enabling actions
//!   * Data        — sum of weights of confirmed sensitive-data reads
//!   * Write       — sum of weights of confirmed write/destructive actions
//!   * Breadth     — number of distinct services with at least one action
//!
//! Composite = max(Admin, 0.40·Privesc + 0.25·Data + 0.20·Write + 0.15·Breadth)
//!
//! Cap at 100. Map to a tier (CRITICAL ≥ 80, HIGH ≥ 60, MEDIUM ≥ 35,
//! LOW ≥ 10, MINIMAL otherwise). Sort descending.

use serde::Serialize;
use std::collections::BTreeSet;

use crate::catalog::{self, RiskKind};
use crate::counter::CounterSnapshot;
use crate::enumerate::{Assessment, Source};

#[derive(Debug, Serialize)]
pub struct Scored {
    pub label: String,
    pub mode: String,
    pub source: Source,
    pub account: Option<String>,
    pub arn: Option<String>,
    pub key_kind: String,

    pub tier: Tier,
    pub score: u32,

    pub admin_score: u32,
    pub privesc_score: u32,
    pub data_score: u32,
    pub write_score: u32,
    pub breadth_score: u32,

    pub services_touched: Vec<String>,
    pub privesc_actions: Vec<String>,
    pub sensitive_actions: Vec<String>,
    pub destructive_actions: Vec<String>,
    pub allowed_wildcards: Vec<String>,
    pub all_actions: Vec<String>,

    pub identity_reachable: bool,
    pub wildcard_resource: bool,
    pub policy_notes: Vec<String>,
    pub probe_errors: Vec<String>,
    pub api_calls: CounterSnapshot,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub enum Tier {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

impl Tier {
    pub fn from_score(s: u32) -> Self {
        match s {
            80..=u32::MAX => Tier::Critical,
            60..=79 => Tier::High,
            35..=59 => Tier::Medium,
            10..=34 => Tier::Low,
            _ => Tier::Minimal,
        }
    }
}

pub fn rank(assessments: Vec<Assessment>) -> Vec<Scored> {
    let mut out: Vec<Scored> = assessments.into_iter().map(score_one).collect();
    out.sort_by(|a, b| b.score.cmp(&a.score).then(a.label.cmp(&b.label)));
    out
}

fn score_one(a: Assessment) -> Scored {
    let mut services: BTreeSet<String> = BTreeSet::new();
    let mut privesc: Vec<String> = Vec::new();
    let mut sensitive: Vec<String> = Vec::new();
    let mut destructive: Vec<String> = Vec::new();
    let mut privesc_pts = 0u32;
    let mut data_pts = 0u32;
    let mut write_pts = 0u32;

    for action in &a.confirmed_actions {
        if let Some(svc) = action.split(':').next() {
            services.insert(svc.to_string());
        }
        if let Some(meta) = catalog::lookup(action) {
            match meta.kind {
                RiskKind::Privesc => {
                    privesc.push(action.clone());
                    privesc_pts = privesc_pts.saturating_add(meta.weight);
                }
                RiskKind::DataRead => {
                    sensitive.push(action.clone());
                    data_pts = data_pts.saturating_add(meta.weight);
                }
                RiskKind::Write | RiskKind::Destruct => {
                    destructive.push(action.clone());
                    write_pts = write_pts.saturating_add(meta.weight);
                }
                RiskKind::Recon => {}
            }
        }
    }

    let admin_score = if a.admin { 100 } else { 0 };
    let privesc_score = privesc_pts.min(100);
    let data_score = data_pts.min(100);
    let write_score = write_pts.min(100);
    let breadth_score = ((services.len() as u32) * 8).min(100);

    let composite = (privesc_score as f64) * 0.40
        + (data_score as f64) * 0.25
        + (write_score as f64) * 0.20
        + (breadth_score as f64) * 0.15;

    let score = admin_score.max(composite.round() as u32).min(100);
    let tier = Tier::from_score(score);

    Scored {
        label: a.label,
        mode: a.mode,
        source: a.source,
        account: a.identity.account.clone(),
        arn: a.identity.arn.clone(),
        key_kind: format!("{:?}", a.identity.key_kind),
        tier,
        score,
        admin_score,
        privesc_score,
        data_score,
        write_score,
        breadth_score,
        services_touched: services.into_iter().collect(),
        privesc_actions: privesc,
        sensitive_actions: sensitive,
        destructive_actions: destructive,
        allowed_wildcards: a.allowed_wildcards.into_iter().collect(),
        all_actions: a.confirmed_actions.into_iter().collect(),
        identity_reachable: a.identity.arn.is_some(),
        wildcard_resource: a.wildcard_resource,
        policy_notes: a.policy_notes,
        probe_errors: a.probe_errors,
        api_calls: a.api_calls,
    }
}
