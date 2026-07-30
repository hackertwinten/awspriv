//! Mode dispatcher. Sequences the assessment phases according to the
//! selected mode, prefering quieter techniques and short-circuiting as
//! soon as we have enough information.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::Serialize;

use crate::catalog;
use crate::cli::{Args, Mode};
use crate::counter::{Counter, CounterSnapshot};
use crate::iam_read;
use crate::identity::{self, Identity};
use crate::policy;
use crate::probe;
use crate::simulate;

#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub label: String,
    pub mode: String,
    pub identity: Identity,
    /// Set of confirmed actions (from policy parse, simulate, or probes).
    pub confirmed_actions: BTreeSet<String>,
    /// How each confirmed action was established. Different sources carry very
    /// different fidelity (a live call vs a parsed policy that an SCP or session
    /// policy might still cap), so the strongest evidence per action is kept.
    pub action_confidence: BTreeMap<String, Confidence>,
    /// Wildcard patterns from Allow statements (e.g. "iam:*").
    pub allowed_wildcards: BTreeSet<String>,
    /// Whether `*:*` or AdministratorAccess was observed.
    pub admin: bool,
    /// Resource-wildcard flag — most Allow statements use `Resource: "*"`.
    pub wildcard_resource: bool,
    /// How we discovered the permissions.
    pub source: Source,
    pub raw_policy_documents: Vec<String>,
    pub policy_notes: Vec<String>,
    pub probe_errors: Vec<String>,
    pub api_calls: CounterSnapshot,
}

/// Fidelity of a single confirmed action. `Ord` runs weakest → strongest, so
/// `max` keeps the best evidence when an action is seen from several sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Confidence {
    /// Inferred from parsing a policy document. Real access may be narrower —
    /// an SCP, permission boundary, or session policy can still cap it.
    PolicyInferred,
    /// Reported `allowed` by SimulatePrincipalPolicy (evaluated against
    /// `Resource: "*"`, so resource-scoped denies are not reflected).
    Simulated,
    /// We actually performed the call and it succeeded — highest fidelity.
    Observed,
}

/// Record an action's confidence, keeping the strongest seen so far.
fn record(map: &mut BTreeMap<String, Confidence>, action: &str, c: Confidence) {
    map.entry(action.to_string())
        .and_modify(|e| *e = (*e).max(c))
        .or_insert(c);
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum Source {
    /// Identity only (passive mode).
    Identity,
    /// IAM self-read + local policy parse.
    IamPolicy,
    /// `iam:SimulatePrincipalPolicy` fallback.
    Simulate,
    /// Live probe sweep.
    Probe,
    /// Mix of policy + probes.
    Combined,
    /// No permissions discovered.
    None,
}

pub async fn assess(
    label: String,
    creds: aws_credential_types::Credentials,
    args: &Args,
) -> Assessment {
    let counter = Arc::new(Counter::new());

    // -----------------------------------------------------------------------
    // Phase 0 — STS:GetCallerIdentity (always)
    // -----------------------------------------------------------------------
    // `whoami` builds the SdkConfig for this key; reuse it rather than building
    // a second identical one.
    let (id, cfg) = identity::whoami(&creds, args, &counter).await;

    let mut assessment = Assessment {
        label: label.clone(),
        mode: format!("{:?}", args.mode),
        identity: id.clone(),
        confirmed_actions: BTreeSet::new(),
        action_confidence: BTreeMap::new(),
        allowed_wildcards: BTreeSet::new(),
        admin: false,
        wildcard_resource: false,
        source: Source::None,
        raw_policy_documents: Vec::new(),
        policy_notes: Vec::new(),
        probe_errors: Vec::new(),
        api_calls: counter.snapshot(),
    };

    if id.arn.is_some() {
        assessment.confirmed_actions.insert("sts:GetCallerIdentity".into());
        record(
            &mut assessment.action_confidence,
            "sts:GetCallerIdentity",
            Confidence::Observed,
        );
    }

    if matches!(args.mode, Mode::Passive) {
        assessment.source = Source::Identity;
        assessment.api_calls = counter.snapshot();
        return assessment;
    }

    // -----------------------------------------------------------------------
    // Phase 1 — IAM self-read + local policy parse
    // -----------------------------------------------------------------------
    let iam = identity::iam_client(&cfg);
    let iam_read = iam_read::try_read(&iam, &id, &counter).await;
    let mut got_from_iam = false;
    if let Some(r) = iam_read {
        for a in &r.confirmed_actions {
            // These IAM reads were actually performed, so they are observed.
            assessment.confirmed_actions.insert((*a).to_string());
            record(&mut assessment.action_confidence, a, Confidence::Observed);
        }

        // Build the identity-based grant, folding in an AdministratorAccess
        // attachment (its admin `Action: "*"` may not have been parsed if the
        // document fetch was denied).
        let mut base = policy::merge(&r.policies);
        base.admin |= r.has_admin_attachment;

        // A permissions boundary caps effective permissions to the intersection
        // of the identity policies and the boundary — so a user with
        // AdministratorAccess but a read-only boundary is not admin (#7).
        let effective = match &r.boundary {
            Some(b) => policy::intersect(&base, b),
            None => base,
        };

        for a in &effective.allowed {
            // Parsed from a policy document — inferred, not observed.
            assessment.confirmed_actions.insert(a.clone());
            record(&mut assessment.action_confidence, a, Confidence::PolicyInferred);
        }
        for w in &effective.allowed_wildcards {
            assessment.allowed_wildcards.insert(w.clone());
        }
        assessment.admin |= effective.admin;
        assessment.wildcard_resource |= effective.has_wildcard_resource;
        assessment.policy_notes.extend(effective.notes.iter().cloned());
        assessment.policy_notes.extend(r.notes.iter().cloned());
        assessment.raw_policy_documents = r.raw_documents;
        got_from_iam = !r.policies.is_empty();
        if got_from_iam {
            assessment.source = Source::IamPolicy;
        }
    }

    // -----------------------------------------------------------------------
    // Phase 2 — SimulatePrincipalPolicy fallback (only if IAM read got nothing useful)
    // -----------------------------------------------------------------------
    if !got_from_iam {
        if let Some(arn) = id.arn.as_deref() {
            let actions = catalog::interesting_actions();
            if let Some(sim) = simulate::run(&iam, arn, &actions, &counter).await {
                for a in &sim.allowed {
                    assessment.confirmed_actions.insert(a.clone());
                    record(&mut assessment.action_confidence, a, Confidence::Simulated);
                }
                if !sim.allowed.is_empty() {
                    assessment.source = Source::Simulate;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Phase 3 — Probe sweep (opt-in only)
    // -----------------------------------------------------------------------
    let needs_probe = match args.mode {
        Mode::Passive | Mode::Stealth => false,
        Mode::Probe => !got_from_iam, // probe only as fallback
        Mode::Aggressive => true,     // always probe
    };
    if needs_probe {
        let set = match args.mode {
            Mode::Aggressive => probe::Set::Full,
            _ => probe::Set::Minimal,
        };
        let outcome = probe::run(
            &cfg,
            set,
            args.concurrency,
            args.jitter,
            args.fail_fast,
            Arc::clone(&counter),
        )
        .await;
        for a in outcome.confirmed {
            // A probe is a live call that succeeded — observed.
            assessment.confirmed_actions.insert(a.to_string());
            record(&mut assessment.action_confidence, a, Confidence::Observed);
        }
        assessment.probe_errors = outcome.unexpected_errors;
        assessment.source = match assessment.source {
            Source::None => Source::Probe,
            Source::IamPolicy | Source::Simulate => Source::Combined,
            other => other,
        };
    }

    assessment.api_calls = counter.snapshot();
    assessment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_keeps_the_strongest_confidence() {
        let mut m = BTreeMap::new();
        // Weaker after stronger does not downgrade.
        record(&mut m, "s3:GetObject", Confidence::Observed);
        record(&mut m, "s3:GetObject", Confidence::PolicyInferred);
        assert_eq!(m["s3:GetObject"], Confidence::Observed);

        // Stronger after weaker upgrades.
        record(&mut m, "kms:Decrypt", Confidence::PolicyInferred);
        record(&mut m, "kms:Decrypt", Confidence::Simulated);
        record(&mut m, "kms:Decrypt", Confidence::Observed);
        assert_eq!(m["kms:Decrypt"], Confidence::Observed);
    }

    #[test]
    fn confidence_orders_weakest_to_strongest() {
        assert!(Confidence::PolicyInferred < Confidence::Simulated);
        assert!(Confidence::Simulated < Confidence::Observed);
    }
}
