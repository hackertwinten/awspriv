# awspriv

Stealth-first AWS access-key permission assessment and ranking.

`awspriv` takes one or more AWS credential sets, works out what each key can do, and ranks them by risk. It biases toward low-noise techniques: parse IAM policies locally rather than brute-forcing every API. Default mode emits ~5–10 CloudTrail events per key, all matching the signature of a routine `aws iam get-user` flow.

## Install

```bash
cargo build --release
# binary at target/release/awspriv
```

## Usage

```bash
# single key
awspriv --key prod=AKIA...:secret...

# temporary (STS) credential with session token
awspriv --key sess=ASIA...:secret...:token...

# many keys from a file (one LABEL=AK:SK[:TOKEN] per line, # comments allowed)
awspriv --keys-file keys.txt

# current environment / default credential chain
awspriv --use-env

# JSON output for jq / dashboards
awspriv --keys-file keys.txt --json
```

With no `--key` / `--keys-file`, the standard AWS environment chain is used automatically.

## Modes

Selected with `--mode` (default `stealth`). Louder modes only run when you accept the trail volume.

| Mode | Calls | Behavior |
|------|-------|----------|
| `passive` | 1 | `sts:GetCallerIdentity` only. Identity + key kind. |
| `stealth` | ~5–10 | Default. IAM self-read + local policy parse, then `SimulatePrincipalPolicy` fallback. All calls look like routine IAM read. |
| `probe` | +~10 worst case | Stealth, plus a minimal one-call-per-service sweep **only if** IAM read yielded nothing. |
| `aggressive` | ~30+ | Stealth, plus a full read sweep across all configured services. Loud — comparable to `enumerate-iam`. |

Every run reports exactly how many CloudTrail events it generated.

## How it works

Each credential set runs through ordered phases, short-circuiting as soon as the mode has enough information:

1. **Identity** — `sts:GetCallerIdentity`; derives key kind (AKIA long-term / ASIA short-term) and principal from the ARN.
2. **IAM self-read** — reads the caller's own attached and inline policies by name. Never calls `iam:ListUsers` (a classic enumeration signature). Fail-fast on the first `AccessDenied`.
3. **SimulatePrincipalPolicy** — fallback when the IAM read is denied; one call evaluates ~50 actions at once.
4. **Probe sweep** — opt-in only; actually calls List/Describe APIs, with per-service fail-fast so many denials collapse to one event.

Discovered permissions are parsed locally, scored across Admin / Privesc / Data / Write / Breadth, and sorted into tiers (CRITICAL / HIGH / MEDIUM / LOW / MINIMAL).

## Options

| Flag | Default | Purpose |
|------|---------|---------|
| `--region` | `us-east-1` | Region for region-scoped probes (IAM/STS global). |
| `--timeout` | `8` | Per-call operation timeout (seconds). |
| `--jitter` | `0` | 0–N ms random delay between calls to break burst patterns. |
| `--concurrency` | `4` | Probe-mode concurrency cap. |
| `--no-fail-fast` | (off) | Disable per-service fail-fast in probe mode. |
| `--json` | (off) | Emit JSON instead of the ranked table. |
| `-v`, `--verbose` | (off) | Verbose logging. |

## Limitations

Local policy parsing does not evaluate conditions (treated as advisory), approximates `NotAction`, and cannot see SCPs, permission boundaries, or session policies. `SimulatePrincipalPolicy` closes some of that gap when available. Treat the output as risk triage, not an authoritative access proof.

## Scope

For authorized security assessment only — pentest engagements, key-exposure triage, and your own accounts. You are responsible for having permission to assess the credentials you feed it.

## License

Copyright 2026 hackertwinten. Licensed under Apache-2.0. See [LICENSE](LICENSE).
