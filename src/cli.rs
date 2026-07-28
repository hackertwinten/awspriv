use clap::{Parser, ValueEnum};

/// Stealth-first AWS key permission assessment and ranking.
///
/// `awspriv` accepts one or more credential sets and determines what each
/// key can do, with a strong preference for low-noise techniques: parse
/// IAM policies locally rather than brute-forcing every API.
///
/// Default mode emits ~5–10 CloudTrail events per credential set, all of
/// which look identical to a normal `aws iam get-user`-style flow.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "awspriv",
    version,
    about = "Stealth-first AWS access key permission assessment",
    long_about = None,
)]
pub struct Args {
    /// Credential in `LABEL=AK:SK[:TOKEN]` form. Repeatable.
    #[arg(long = "key", value_name = "LABEL=AK:SK[:TOKEN]")]
    pub key: Vec<String>,

    /// File of credentials, one per line (`LABEL=AK:SK[:TOKEN]` or `AK:SK[:TOKEN]`).
    #[arg(long, value_name = "PATH")]
    pub keys_file: Option<String>,

    /// Also use credentials from the standard AWS env / default chain.
    /// Implicitly enabled when no `--key` / `--keys-file` is given.
    #[arg(long)]
    pub use_env: bool,

    /// Region for region-scoped probes. IAM/STS/S3-list-buckets are global.
    #[arg(long, default_value = "us-east-1")]
    pub region: String,

    /// Assessment mode (see README for trail-volume estimates).
    #[arg(long, value_enum, default_value_t = Mode::Stealth)]
    pub mode: Mode,

    /// Per-call operation timeout in seconds.
    #[arg(long, default_value_t = 8)]
    pub timeout: u64,

    /// Add 0–N ms of random jitter between calls to break burst patterns
    /// that rate-based anomaly detection looks for.
    #[arg(long, default_value_t = 0, value_name = "MS")]
    pub jitter: u64,

    /// In probe mode, fail-fast: after the first AccessDenied for a service,
    /// skip remaining calls to that service. On by default; pass `--no-fail-fast`
    /// to disable.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub fail_fast: bool,

    /// Concurrency cap for probe-mode calls (probe / aggressive only).
    #[arg(long, default_value_t = 4)]
    pub concurrency: usize,

    /// Emit JSON instead of the human-readable ranked table.
    #[arg(long)]
    pub json: bool,

    /// Verbose logging.
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum Mode {
    /// Identity only. 1 call: `sts:GetCallerIdentity`. No scoring beyond key kind.
    Passive,
    /// Default. IAM self-read + local policy parse. ~5–10 calls, all to IAM,
    /// all matching the call signature of routine SDK use.
    Stealth,
    /// Stealth + a minimal probe sweep (1 call per service) if IAM read yields
    /// nothing. Adds ~10 calls in the worst case.
    Probe,
    /// Stealth + a comprehensive probe sweep across all configured services.
    /// Loud (~30+ calls). Comparable to `enumerate-iam`. Use only when you've
    /// accepted the trail volume.
    Aggressive,
}
