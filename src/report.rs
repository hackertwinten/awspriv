//! Output formatting. Two formats:
//!   * Pretty terminal table + per-key detail (default).
//!   * JSON (for piping into jq, reports, dashboards).
//!
//! Always includes the API call counter so the operator knows exactly how
//! many CloudTrail events the assessment generated.

use anyhow::Result;
use colored::Colorize;
use comfy_table::{presets::UTF8_BORDERS_ONLY, Cell, ContentArrangement, Table};

use crate::enumerate::Confidence;
use crate::score::{Scored, Tier};

pub fn print_table(rows: &[Scored]) {
    println!();
    let mut t = Table::new();
    t.load_preset(UTF8_BORDERS_ONLY)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "#", "Label", "Tier", "Score", "Account", "Identity", "Pe", "D", "W", "Svcs", "Calls",
        ]);
    for (i, r) in rows.iter().enumerate() {
        t.add_row(vec![
            Cell::new(i + 1),
            Cell::new(&r.label),
            Cell::new(tier_str(r.tier)),
            Cell::new(format!("{}", r.score)),
            Cell::new(r.account.as_deref().unwrap_or("?")),
            Cell::new(short_arn(r.arn.as_deref())),
            Cell::new(r.privesc_score),
            Cell::new(r.data_score),
            Cell::new(r.write_score),
            Cell::new(r.services_touched.len()),
            Cell::new(r.api_calls.total),
        ]);
    }
    println!("{}", t);
    println!(
        "  {} Pe=Privesc  D=Data-read  W=Write/Destruct  Calls=CloudTrail events generated",
        "legend:".dimmed()
    );

    // Per-key detail.
    for r in rows {
        println!();
        let header = format!(
            "{}  {}  {}  ({}/100)  via {:?}",
            "▶".cyan().bold(),
            r.label.bold(),
            tier_str(r.tier),
            r.score,
            r.source,
        );
        println!("{}", header);

        if let Some(arn) = &r.arn {
            println!("  identity: {}", arn.dimmed());
        } else {
            println!("  {}", "identity: unreachable (sts:GetCallerIdentity failed)".red());
        }

        if r.admin_score == 100 {
            println!(
                "  {}  {}",
                "ADMIN:".red().bold(),
                "wildcard `*` action or AdministratorAccess attached".red()
            );
        }
        if !r.allowed_wildcards.is_empty() {
            println!("  wildcards: {}", r.allowed_wildcards.join(", ").yellow());
        }
        if r.wildcard_resource {
            println!("  resource: {}", "Resource: \"*\" (unscoped)".yellow());
        }
        if !r.privesc_actions.is_empty() {
            println!(
                "  {} {}",
                "privesc:".red().bold(),
                r.privesc_actions.join(", ")
            );
        }
        if !r.sensitive_actions.is_empty() {
            println!(
                "  {}    {}",
                "data:".yellow().bold(),
                r.sensitive_actions.join(", ")
            );
        }
        if !r.destructive_actions.is_empty() {
            println!(
                "  {}   {}",
                "write:".magenta().bold(),
                r.destructive_actions.join(", ")
            );
        }
        if !r.services_touched.is_empty() {
            println!("  services: {}", r.services_touched.join(", ").dimmed());
        }
        if !r.action_confidence.is_empty() {
            let (mut observed, mut simulated, mut inferred) = (0, 0, 0);
            for c in r.action_confidence.values() {
                match c {
                    Confidence::Observed => observed += 1,
                    Confidence::Simulated => simulated += 1,
                    Confidence::PolicyInferred => inferred += 1,
                }
            }
            println!(
                "  {} {observed} observed, {simulated} simulated, {inferred} policy-inferred",
                "evidence:".dimmed(),
            );
        }
        if !r.policy_notes.is_empty() {
            for n in &r.policy_notes {
                println!("  {} {}", "note:".cyan(), n);
            }
        }
        println!(
            "  {}  {} ({} unique action types)",
            "trail:".dimmed(),
            format!("{} CloudTrail events", r.api_calls.total).dimmed(),
            r.api_calls.by_action.len()
        );
        if !r.probe_errors.is_empty() {
            println!(
                "  {} {}",
                "errors:".red(),
                r.probe_errors.len()
            );
        }
    }
    println!();
}

pub fn print_json(rows: &[Scored]) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(rows)?);
    Ok(())
}

fn tier_str(t: Tier) -> String {
    match t {
        Tier::Critical => "CRITICAL".red().bold().to_string(),
        Tier::High => "HIGH".bright_red().to_string(),
        Tier::Medium => "MEDIUM".yellow().to_string(),
        Tier::Low => "LOW".cyan().to_string(),
        Tier::Minimal => "MINIMAL".dimmed().to_string(),
    }
}

fn short_arn(a: Option<&str>) -> String {
    match a {
        Some(arn) => {
            // Drop everything before the resource part for terseness.
            let parts: Vec<&str> = arn.split(':').collect();
            if parts.len() >= 6 {
                parts[5].to_string()
            } else {
                arn.to_string()
            }
        }
        None => "(unreachable)".to_string(),
    }
}
