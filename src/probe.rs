//! Opt-in probe sweep.
//!
//! Only reached when the user explicitly selects `--mode probe` or
//! `--mode aggressive`. Default `--mode stealth` never calls these.
//!
//! Two sets:
//!   * `minimal()` — one well-chosen List/Describe per service, ~10 calls.
//!   * `full()`    — broader read coverage, ~25–30 calls. Roughly comparable
//!     to `enumerate-iam`'s default surface, but still single-region.
//!
//! Per-service fail-fast: if the first call to a given service is denied,
//! subsequent calls to that service are skipped within the same run. This
//! collapses 5+ AccessDenied events down to 1.

use aws_config::SdkConfig;
use rand::Rng;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};

use crate::counter::Counter;
use crate::error::ErrorClass;

#[derive(Debug, Clone, Copy)]
pub enum Set {
    Minimal,
    Full,
}

#[derive(Debug, Default)]
pub struct ProbeOutcome {
    pub confirmed: Vec<&'static str>,
    pub unexpected_errors: Vec<String>,
}

pub async fn run(
    cfg: &SdkConfig,
    set: Set,
    concurrency: usize,
    jitter_ms: u64,
    fail_fast: bool,
    counter: Arc<Counter>,
) -> ProbeOutcome {
    let probes = match set {
        Set::Minimal => minimal(cfg.clone()),
        Set::Full => full(cfg.clone()),
    };

    let denied_services: Arc<Mutex<HashSet<&'static str>>> = Arc::new(Mutex::new(HashSet::new()));
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(probes.len());

    for p in probes {
        let sem = Arc::clone(&sem);
        let denied = Arc::clone(&denied_services);
        let counter = Arc::clone(&counter);

        handles.push(tokio::spawn(async move {
            // Acquire the permit BEFORE consulting the denied set. All probe
            // tasks are spawned up front, so checking here (rather than at spawn
            // time) is what lets a denial recorded by an earlier same-service
            // call actually short-circuit later ones. Note: with concurrency > 1,
            // up to `concurrency` same-service calls can still be in flight before
            // the first denial lands — full collapse requires concurrency == 1.
            let _permit = sem.acquire_owned().await.expect("semaphore closed");

            if fail_fast {
                let g = denied.lock().await;
                if g.contains(p.service) {
                    return Outcome::Skipped(());
                }
            }

            if jitter_ms > 0 {
                let delay = rand::thread_rng().gen_range(0..=jitter_ms);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            counter.inc(p.action);
            match (p.runner)().await {
                Ok(()) => Outcome::Ok(p.action),
                Err((class, msg)) => match class {
                    ErrorClass::AccessDenied => {
                        if fail_fast {
                            let mut g = denied.lock().await;
                            g.insert(p.service);
                        }
                        Outcome::Denied(())
                    }
                    // Throttling is not a denial: do NOT mark the service denied
                    // (that would skip valid probes). Surface it so the operator
                    // knows coverage was incomplete (#3).
                    ErrorClass::Throttling => {
                        Outcome::Error(p.action, format!("throttled: {}", msg))
                    }
                    ErrorClass::Other => Outcome::Error(p.action, msg),
                },
            }
        }));
    }

    let mut outcome = ProbeOutcome::default();
    for h in handles {
        match h.await {
            Ok(Outcome::Ok(a)) => outcome.confirmed.push(a),
            Ok(Outcome::Denied(_)) | Ok(Outcome::Skipped(_)) => {}
            Ok(Outcome::Error(a, m)) => outcome.unexpected_errors.push(format!("{}: {}", a, m)),
            Err(e) => outcome.unexpected_errors.push(format!("task panic: {}", e)),
        }
    }
    outcome
}

enum Outcome {
    Ok(&'static str),
    Denied(()),
    Skipped(()),
    Error(&'static str, String),
}

/// A failed probe carries its classification alongside the display string, so
/// the run loop branches on a typed `ErrorClass` rather than re-parsing text.
type ProbeErr = (ErrorClass, String);

// ---------------------------------------------------------------------------
// Probe definitions
// ---------------------------------------------------------------------------

type RunnerFut =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ProbeErr>> + Send + 'static>>;
type RunnerFn = Box<dyn FnOnce() -> RunnerFut + Send + 'static>;

struct Probe {
    action: &'static str,
    service: &'static str,
    runner: RunnerFn,
}

macro_rules! probe {
    // Zero-arg form: a bare `client.call().send()`. Delegates to the
    // customizer form with an identity closure.
    ($action:expr, $service:expr, $client:expr, $call:ident) => {
        probe!($action, $service, $client, $call, |b| b)
    };
    // Customizer form: `$customize` receives the fluent request builder and
    // returns it, so a probe that needs parameters (e.g. `.max_items(1)`) can
    // set them: `probe!("svc:Op", "svc", client, op, |b| b.max_items(1))`.
    ($action:expr, $service:expr, $client:expr, $call:ident, $customize:expr) => {{
        let c = $client.clone();
        Probe {
            action: $action,
            service: $service,
            runner: Box::new(move || {
                Box::pin(async move {
                    #[allow(clippy::redundant_closure_call)]
                    let req = ($customize)(c.$call());
                    req.send()
                        .await
                        .map(|_| ())
                        .map_err(|e| (crate::error::classify(&e), format!("{}", e)))
                })
            }),
        }
    }};
}

fn minimal(cfg: SdkConfig) -> Vec<Probe> {
    use aws_sdk_ec2::Client as Ec2;
    use aws_sdk_ecr::Client as Ecr;
    use aws_sdk_eks::Client as Eks;
    use aws_sdk_iam::Client as Iam;
    use aws_sdk_kms::Client as Kms;
    use aws_sdk_lambda::Client as Lambda;
    use aws_sdk_s3::Client as S3;
    use aws_sdk_secretsmanager::Client as Sm;
    use aws_sdk_ssm::Client as Ssm;

    let iam = Iam::new(&cfg);
    let s3 = S3::new(&cfg);
    let ec2 = Ec2::new(&cfg);
    let lambda = Lambda::new(&cfg);
    let sm = Sm::new(&cfg);
    let kms = Kms::new(&cfg);
    let ssm = Ssm::new(&cfg);
    let eks = Eks::new(&cfg);
    let ecr = Ecr::new(&cfg);

    vec![
        probe!("iam:GetAccountSummary",      "iam",            iam,    get_account_summary),
        probe!("s3:ListBuckets",             "s3",             s3,     list_buckets),
        probe!("ec2:DescribeInstances",      "ec2",            ec2,    describe_instances),
        probe!("lambda:ListFunctions",       "lambda",         lambda, list_functions),
        probe!("secretsmanager:ListSecrets", "secretsmanager", sm,     list_secrets),
        probe!("kms:ListKeys",               "kms",            kms,    list_keys),
        probe!("ssm:DescribeParameters",     "ssm",            ssm,    describe_parameters),
        probe!("eks:ListClusters",           "eks",            eks,    list_clusters),
        probe!("ecr:DescribeRepositories",   "ecr",            ecr,    describe_repositories),
    ]
}

fn full(cfg: SdkConfig) -> Vec<Probe> {
    use aws_sdk_ec2::Client as Ec2;
    use aws_sdk_ecr::Client as Ecr;
    use aws_sdk_eks::Client as Eks;
    use aws_sdk_iam::Client as Iam;
    use aws_sdk_kms::Client as Kms;
    use aws_sdk_lambda::Client as Lambda;
    use aws_sdk_s3::Client as S3;
    use aws_sdk_secretsmanager::Client as Sm;
    use aws_sdk_ssm::Client as Ssm;

    let iam = Iam::new(&cfg);
    let s3 = S3::new(&cfg);
    let ec2 = Ec2::new(&cfg);
    let lambda = Lambda::new(&cfg);
    let sm = Sm::new(&cfg);
    let kms = Kms::new(&cfg);
    let ssm = Ssm::new(&cfg);
    let eks = Eks::new(&cfg);
    let ecr = Ecr::new(&cfg);

    vec![
        probe!("iam:GetAccountSummary",      "iam",            iam,    get_account_summary),
        probe!("iam:ListUsers",              "iam",            iam,    list_users),
        probe!("iam:ListRoles",              "iam",            iam,    list_roles),
        probe!("iam:ListGroups",             "iam",            iam,    list_groups),
        probe!("iam:ListPolicies",           "iam",            iam,    list_policies),
        probe!("s3:ListBuckets",             "s3",             s3,     list_buckets),
        probe!("ec2:DescribeInstances",      "ec2",            ec2,    describe_instances),
        probe!("ec2:DescribeSecurityGroups", "ec2",            ec2,    describe_security_groups),
        probe!("ec2:DescribeVpcs",           "ec2",            ec2,    describe_vpcs),
        probe!("ec2:DescribeSnapshots",      "ec2",            ec2,    describe_snapshots),
        probe!("lambda:ListFunctions",       "lambda",         lambda, list_functions),
        probe!("secretsmanager:ListSecrets", "secretsmanager", sm,     list_secrets),
        probe!("kms:ListKeys",               "kms",            kms,    list_keys),
        probe!("kms:ListAliases",            "kms",            kms,    list_aliases),
        probe!("ssm:DescribeParameters",     "ssm",            ssm,    describe_parameters),
        probe!("eks:ListClusters",           "eks",            eks,    list_clusters),
        probe!("ecr:DescribeRepositories",   "ecr",            ecr,    describe_repositories),
    ]
}
