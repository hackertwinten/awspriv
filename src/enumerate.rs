//! Mode dispatcher. Sequences the assessment phases according to the
//! selected mode, prefering quieter techniques and short-circuiting as
//! soon as we have enough information.

use std::collections::BTreeSet;
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
            assessment.confirmed_actions.insert((*a).to_string());
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
            assessment.confirmed_actions.insert(a.clone());
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
            assessment.confirmed_actions.insert(a.to_string());
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
