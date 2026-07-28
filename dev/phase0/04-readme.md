# 04 — write the README (the real work)

`Cargo.toml` points `readme = "README.md"` but no README exists. This is
write-from-scratch and it is most of the session. The plan is explicit: the
README explains the **why**, not just the how. That is what makes the repo
"count" to a reviewer.

Raw material already in the code — reuse it, do not reinvent:

- `Cargo.toml` description: "Stealth-first AWS access key permission assessment
  and ranking."
- `src/cli.rs` docstrings carry the whole trail-volume story. The four modes and
  their CloudTrail cost:
  - `passive` — 1 call (`sts:GetCallerIdentity`).
  - `stealth` (default) — ~5–10 calls, all IAM self-read + **local** policy
    parse, matching routine SDK call signatures.
  - `probe` — stealth + minimal 1-call-per-service sweep, ~10 more worst case.
  - `aggressive` — ~30+ calls, "comparable to `enumerate-iam`."
- Stealth levers worth naming: `--jitter` (breaks burst patterns rate-based
  anomaly detection looks for), `--fail-fast` (stop probing a service after
  first AccessDenied), default region-global IAM/STS path.

README must include (plan + audit requirements):

- [ ] The **why**: quiet IAM enumeration. What it avoids that the loud tools
      trip — parse policies locally instead of brute-forcing every API, so the
      default path looks like normal `aws iam get-user` flow rather than an
      enumeration sweep. Contrast explicitly with `enumerate-iam` (the code
      already names it as the aggressive-mode comparison).
- [ ] Sample output — run it against a throwaway key, paste the ranked table.
      **Scrub the account ID and key from the paste** (audit rule).
- [ ] An intended-use line (authorized assessment / pentest only) — legal
      hygiene, the plan requires it on every tool repo.
- [ ] Install + quick start (`--key LABEL=AK:SK`, `--keys-file`, `--mode`).
- [ ] Link to `hackertwinten.sh` once the site skeleton exists (issue tracked
      separately in Phase 0).

Keep it in agent-style prose (`.claude/rules` in the 2026-fix workspace): short
words, active voice, no "leverage"/"furthermore", no em-dash-as-comma.
