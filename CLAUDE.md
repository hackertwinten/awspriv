# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`awspriv` — stealth-first AWS access-key permission assessment and ranking CLI (Rust). Takes one or more AWS credential sets, determines what each key can do, and ranks them by risk. Design bias: prefer low-noise techniques (parse IAM policies locally) over brute-forcing every API. Default mode emits ~5–10 CloudTrail events per key, all looking like a routine `aws iam get-user` flow.

## Commands

```bash
cargo build                       # debug build
cargo build --release             # optimized (thin LTO, stripped)
cargo test                        # all tests (unit + tests/catalog.rs)
cargo test parses_simple_allow    # single test by name
cargo test --test catalog         # one integration test file
cargo clippy --all-targets        # lint
cargo run -- --key LABEL=AK:SK --mode stealth   # run
```

`.claude/settings.local.json` pre-allows `cargo build/test/clippy`.

## Assessment pipeline (the core architecture)

`main.rs` → `enumerate::assess()` runs each credential set through ordered phases, short-circuiting as soon as a mode has enough info. `enumerate.rs` is the dispatcher — read it first to understand control flow.

- **Phase 0 — identity** (`identity.rs`): always runs `sts:GetCallerIdentity`. Derives `KeyKind` from key prefix (AKIA=long-term, ASIA=short-term) and parses principal name / assumed-role flag from the ARN.
- **Phase 1 — IAM self-read** (`iam_read.rs`): the stealth primitive. Uses the principal name from Phase 0 to `GetUser` + fetch attached/inline policies. Never calls `iam:ListUsers` (classic enumeration signature). Fail-fast on first AccessDenied. Skipped for assumed-role sessions.
- **Phase 2 — SimulatePrincipalPolicy** (`simulate.rs`): fallback only when Phase 1 got nothing. One API call evaluates ~50 actions at once (batched at 50). Requires the principal to hold `iam:SimulatePrincipalPolicy`.
- **Phase 3 — probe sweep** (`probe.rs`): opt-in only (`--mode probe`/`aggressive`). Actually calls List/Describe APIs. Per-service fail-fast collapses many AccessDenied events into one. Concurrency-capped via semaphore, optional jitter.

Modes (`cli.rs`): `passive` (identity only) → `stealth` (default, Phases 0–2) → `probe` (adds minimal sweep as fallback) → `aggressive` (always full sweep, loud ~30+ calls).

Policy discovery feeds `policy.rs` (local IAM policy JSON parser: Allow/Deny, Action/NotAction, wildcard expansion, URL-decode, Deny subtracts from Allow — conditions are advisory, not evaluated). Results become an `Assessment`, then `score.rs::rank()` scores across Admin/Privesc/Data/Write/Breadth and sorts into tiers, then `report.rs` prints table or JSON (`--json`).

## Two things everything routes through

- **`catalog.rs`** — the single source of truth mapping AWS actions to `(service, RiskKind, weight)`. Used both for scoring confirmed actions and for expanding policy wildcards (`iam:*` → concrete actions). The Privesc set is Rhino Security Labs 2018 research. **To add a service/action: append one row here** (plus one `probe!` line in `probe.rs` if it should be probed). Keep the terse `p()`/`d()`/`w()`/`r()` macro style.
- **`counter.rs`** — a `Counter` is threaded (as `Arc`) through every phase so the report can show exactly how many CloudTrail events the run generated. Any new API call must `counter.inc("service:Action")`.

Stealth is the product. When touching probe/read/simulate code, preserve the low-noise invariants: fail-fast on AccessDenied, no broad enumeration calls, count every call.

## graphify knowledge graph

A knowledge graph lives at `graphify-out/` (git-ignored). `.claude/settings.json` installs hook-guards on search/read tools that steer toward it.

- For codebase questions, run `graphify query "<question>"` when `graphify-out/graph.json` exists; `graphify path "<A>" "<B>"` for relationships; `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than raw grep.
- Use `graphify-out/wiki/index.md` for broad navigation if present; read `graphify-out/GRAPH_REPORT.md` only for broad architecture review.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
