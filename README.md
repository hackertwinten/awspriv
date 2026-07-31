# awspriv

Stealth-first AWS access-key permission assessment and ranking.

`awspriv` takes one or more AWS credential sets, works out what each key can do, and ranks them by risk. It reads the calling principal's own IAM policies and parses them locally instead of probing service APIs. In stealth mode it emits one CloudTrail event per policy it reads (roughly 5 to 10 for a simple identity, more for a heavily privileged one), against the ~1,800 `get`/`list` calls a brute-force tool makes. Every run prints its exact event count, so the number is yours to verify rather than ours to assert.

## Why awspriv

Most permission-enumeration tools are loud. `enumerate-iam` brute-forces about 1,800 `get` and `list` calls across every service. Each one is a CloudTrail event, and the burst is easy for a defender to spot and shut down. `awspriv` reads only the policies attached to the calling principal and works out effective permissions locally, so it costs a handful of events rather than eighteen hundred.

Reading your own policies is not novel. Pacu's `iam__enum_permissions` does the same. `awspriv` differs on two points. It stays scoped: it never calls `iam:GetAccountAuthorizationDetails`, a single call that dumps the whole account's IAM configuration and trips a well-known detection, and in stealth mode it never enumerates the account with `ListUsers`, `ListRoles`, or `ListPolicies`. Beyond scope, it scores each key across privesc, data-read, and destructive axes, sorts keys into risk tiers, and ranks many at once.

One thing `awspriv` does not do is hide. Every call it makes is logged to CloudTrail. The goal is a small, routine-looking footprint, not evasion. Enumerating without logging at all is a separate technique and a separate tool.

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
| `stealth` | ~5–20 | Default. IAM self-read + local policy parse, then `SimulatePrincipalPolicy` fallback. Low volume, resembles routine IAM self-reads. |
| `probe` | +~10 worst case | Stealth, plus a minimal one-call-per-service sweep **only if** IAM read yielded nothing. |
| `aggressive` | ~30+ | Stealth, plus a full read sweep across all configured services. Loud, and no longer scoped to the caller. |

Every run reports exactly how many CloudTrail events it generated.

## How it works

Each credential set runs through ordered phases, short-circuiting as soon as the mode has enough information:

1. **Identity** — `sts:GetCallerIdentity`; derives key kind (AKIA long-term / ASIA short-term) and principal from the ARN.
2. **IAM self-read** — reads the caller's own attached and inline policies by name. Never calls `iam:ListUsers` (a classic enumeration signature). Fail-fast on the first `AccessDenied`.
3. **SimulatePrincipalPolicy** — fallback when the IAM read is denied; one call evaluates ~50 actions at once.
4. **Probe sweep** — opt-in only; actually calls List/Describe APIs, with per-service fail-fast so many denials collapse to one event.

Discovered permissions are parsed locally, scored across Admin / Privesc / Data / Write / Breadth, and sorted into tiers (CRITICAL / HIGH / MEDIUM / LOW / MINIMAL).

## Example output

Two keys from a `--keys-file` run, one heavily privileged and one read-only:

```text
$ awspriv --keys-file keys.txt

 ┌───┬─────────────┬──────────┬───────┬──────────────┬────────────┬────┬────┬────┬──────┬───────┐
 │ # │ Label       │ Tier     │ Score │ Account      │ Identity   │ Pe │ D  │ W  │ Svcs │ Calls │
 ├───┼─────────────┼──────────┼───────┼──────────────┼────────────┼────┼────┼────┼──────┼───────┤
 │ 1 │ prod-deploy │ CRITICAL │ 98    │ 123456789012 │ deploy-bot │ 90 │ 80 │ 85 │ 12   │ 14    │
 │ 2 │ readonly-ci │ LOW      │ 22    │ 123456789012 │ ci-reader  │ 0  │ 20 │ 0  │ 1    │ 7     │
 └───┴─────────────┴──────────┴───────┴──────────────┴────────────┴────┴────┴────┴──────┴───────┘
  legend: Pe=Privesc  D=Data-read  W=Write/Destruct  Calls=CloudTrail events generated

▶  prod-deploy  CRITICAL  (98/100)  via IamPolicy
  identity: arn:aws:iam::123456789012:user/deploy-bot
  ADMIN:  wildcard `*` action or AdministratorAccess attached
  wildcards: *
  resource: Resource: "*" (unscoped)
  privesc: iam:CreateAccessKey, iam:AttachUserPolicy
  data:    secretsmanager:GetSecretValue, s3:GetObject
  write:   ec2:TerminateInstances, s3:DeleteObject
  services: iam, s3, ec2, lambda, secretsmanager, sts, kms
  evidence: 0 observed, 0 simulated, 31 policy-inferred
  note: AdministratorAccess attached, effective permissions unbounded
  trail:  14 CloudTrail events (9 unique action types)

▶  readonly-ci  LOW  (22/100)  via IamPolicy
  identity: arn:aws:iam::123456789012:user/ci-reader
  data:    s3:GetObject
  services: s3
  evidence: 0 observed, 0 simulated, 3 policy-inferred
  trail:  7 CloudTrail events (7 unique action types)
```

The output above is illustrative, hand-built to match the tool's format. A real redacted capture is tracked in [#15](https://github.com/hackertwinten/awspriv/issues/15).

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

The `SimulatePrincipalPolicy` fallback, used when the IAM self-read is denied, only fires when the principal holds `iam:SimulatePrincipalPolicy` (uncommon), and it emits a distinct CloudTrail event rather than blending into the read pattern.

## Scope

For authorized security assessment only — pentest engagements, key-exposure triage, and your own accounts. You are responsible for having permission to assess the credentials you feed it.

## License

Copyright 2026 hackertwinten. Licensed under Apache-2.0. See [LICENSE](LICENSE).
