//! Identity discovery + shared `SdkConfig` construction.

use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::Credentials;
use aws_sdk_iam::Client as IamClient;
use aws_sdk_sts::Client as StsClient;
use serde::Serialize;
use std::time::Duration;

use crate::cli::Args;
use crate::counter::Counter;

#[derive(Debug, Clone, Serialize)]
pub struct Identity {
    pub account: Option<String>,
    pub arn: Option<String>,
    pub user_id: Option<String>,
    pub key_kind: KeyKind,
    /// Username extracted from a `user/` ARN, or role-name from `assumed-role/`.
    pub principal_name: Option<String>,
    pub is_assumed_role: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum KeyKind {
    /// AKIA — long-term IAM user access key.
    LongTerm,
    /// ASIA — temporary STS credential.
    ShortTerm,
    Unknown,
}

pub async fn whoami(creds: &Credentials, args: &Args, counter: &Counter) -> Identity {
    let kind = match creds.access_key_id().get(..4) {
        Some("AKIA") => KeyKind::LongTerm,
        Some("ASIA") => KeyKind::ShortTerm,
        _ => KeyKind::Unknown,
    };
    let cfg = build_config(creds.clone(), &args.region, args.timeout).await;
    let sts = StsClient::new(&cfg);

    counter.inc("sts:GetCallerIdentity");
    match sts.get_caller_identity().send().await {
        Ok(o) => {
            let (principal, is_role) = parse_principal(o.arn.as_deref());
            Identity {
                account: o.account,
                arn: o.arn,
                user_id: o.user_id,
                key_kind: kind,
                principal_name: principal,
                is_assumed_role: is_role,
            }
        }
        Err(e) => {
            tracing::warn!("sts:GetCallerIdentity failed: {}", crate::error::short(&e));
            Identity {
                account: None,
                arn: None,
                user_id: None,
                key_kind: kind,
                principal_name: None,
                is_assumed_role: false,
            }
        }
    }
}

/// `arn:aws:iam::123:user/alice` → ("alice", false)
/// `arn:aws:sts::123:assumed-role/role-name/session` → ("role-name", true)
fn parse_principal(arn: Option<&str>) -> (Option<String>, bool) {
    let Some(arn) = arn else { return (None, false) };
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() < 6 {
        return (None, false);
    }
    let resource = parts[5];
    if let Some(rest) = resource.strip_prefix("user/") {
        return (Some(rest.to_string()), false);
    }
    if let Some(rest) = resource.strip_prefix("assumed-role/") {
        let role = rest.split('/').next().unwrap_or("");
        return (Some(role.to_string()), true);
    }
    (None, false)
}

pub async fn build_config(
    creds: Credentials,
    region: &str,
    timeout_s: u64,
) -> aws_config::SdkConfig {
    use aws_config::timeout::TimeoutConfig;
    use aws_config::{BehaviorVersion, Region};

    let timeouts = TimeoutConfig::builder()
        .operation_timeout(Duration::from_secs(timeout_s))
        .operation_attempt_timeout(Duration::from_secs(timeout_s))
        .build();

    aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .credentials_provider(SharedCredentialsProvider::new(creds))
        .timeout_config(timeouts)
        .load()
        .await
}

pub fn iam_client(cfg: &aws_config::SdkConfig) -> IamClient {
    IamClient::new(cfg)
}
