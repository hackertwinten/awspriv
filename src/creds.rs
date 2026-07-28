//! Credential ingestion. Three sources, all combinable:
//!   1. `--key LABEL=AK:SK[:TOKEN]` (repeatable)
//!   2. `--keys-file PATH` (one credential per line; `#` comments allowed)
//!   3. Standard AWS env vars (when `--use-env` is set, or nothing else was)

use anyhow::{anyhow, Context, Result};
use aws_credential_types::Credentials;
use std::fs;
use std::path::Path;

use crate::cli::Args;

pub type KeySet = (String, Credentials);

pub fn load_keys(args: &Args) -> Result<Vec<KeySet>> {
    let mut out = Vec::new();

    for spec in &args.key {
        out.push(parse_spec(spec).with_context(|| format!("parsing --key '{}'", redact(spec)))?);
    }

    if let Some(path) = &args.keys_file {
        out.extend(parse_file(path)?);
    }

    let no_explicit = args.key.is_empty() && args.keys_file.is_none();
    if args.use_env || no_explicit {
        if let (Ok(ak), Ok(sk)) = (
            std::env::var("AWS_ACCESS_KEY_ID"),
            std::env::var("AWS_SECRET_ACCESS_KEY"),
        ) {
            let token = std::env::var("AWS_SESSION_TOKEN").ok();
            let label = format!("env:{}", redact(&ak));
            out.push((label, Credentials::new(ak, sk, token, None, "awspriv-env")));
        }
    }

    Ok(out)
}

fn parse_spec(spec: &str) -> Result<KeySet> {
    let (label, body) = match spec.split_once('=') {
        Some((l, b)) => (l.to_string(), b),
        None => {
            let head = spec.split(':').next().unwrap_or("?");
            (format!("key:{}", redact(head)), spec)
        }
    };
    let parts: Vec<&str> = body.splitn(3, ':').collect();
    if parts.len() < 2 {
        return Err(anyhow!("expected `AK:SK[:TOKEN]`"));
    }
    let creds = Credentials::new(
        parts[0].to_string(),
        parts[1].to_string(),
        parts.get(2).map(|s| s.to_string()),
        None,
        "awspriv-arg",
    );
    Ok((label, creds))
}

fn parse_file(path: &str) -> Result<Vec<KeySet>> {
    let p = Path::new(path);
    let content = fs::read_to_string(p).with_context(|| format!("reading {}", path))?;
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(parse_spec(line).with_context(|| format!("{}:{}", path, i + 1))?);
    }
    Ok(out)
}

fn redact(s: &str) -> String {
    let s = s.trim();
    if s.len() <= 8 {
        "***".to_string()
    } else {
        format!("{}…{}", &s[..4], &s[s.len() - 4..])
    }
}
