//! awspriv — stealth-first AWS access key permission assessment.

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

mod catalog;
mod cli;
mod counter;
mod creds;
mod enumerate;
mod error;
mod iam_read;
mod identity;
mod policy;
mod probe;
mod report;
mod score;
mod simulate;

#[tokio::main]
async fn main() -> Result<()> {
    let args = cli::Args::parse();

    let filter = if args.verbose {
        EnvFilter::new("info,awspriv=debug")
    } else {
        EnvFilter::new("warn,awspriv=info")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let key_sets = creds::load_keys(&args)?;
    if key_sets.is_empty() {
        anyhow::bail!(
            "no credentials provided. Use --key, --keys-file, or set AWS_ACCESS_KEY_ID."
        );
    }

    tracing::info!(
        "assessing {} credential set(s) in {:?} mode",
        key_sets.len(),
        args.mode
    );

    let mut assessments = Vec::with_capacity(key_sets.len());
    for (label, creds) in key_sets {
        tracing::info!("=> {}", label);
        let a = enumerate::assess(label, creds, &args).await;
        assessments.push(a);
    }

    let scored = score::rank(assessments);

    if args.json {
        report::print_json(&scored)?;
    } else {
        report::print_table(&scored);
    }

    Ok(())
}
