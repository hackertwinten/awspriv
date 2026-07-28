# 06 — read the whole source before push (owner pass)

You said you want to go over the entire thing yourself. This is that gate, and
it comes **before** the repo is created. Publish is one-way for a security tool.

~1,767 lines across 15 files. Read every one with two questions:

1. **Anything real leak in?** Audit was pattern-based (account IDs, ARNs, keys)
   and came back clean, but a comment, a test fixture, or a hardcoded default
   with a real hostname/bucket/role name would slip past a regex. Files most
   likely to carry a real value: `tests/catalog.rs`, `src/catalog.rs`,
   `examples/keys.txt`, any default in `src/cli.rs`.
2. **Does it do what the README will claim?** The stealth story is the selling
   point. Confirm the default path really is IAM-read + local parse and does not
   quietly make a probe call. Check `src/enumerate.rs`, `src/probe.rs`,
   `src/policy.rs`, `src/simulate.rs`.

Reading order by weight (largest / most sensitive first):
`policy.rs` (252) → `probe.rs` (217) → `enumerate.rs` (180) →
`catalog.rs` (178) → `score.rs` (154) → `report.rs` (149) →
`iam_read.rs` (148) → `identity.rs` (111) → then the small files.

- [ ] Every file read.
- [ ] Stealth claim verified against actual call sites.
- [ ] No real infra names, hosts, buckets, roles, or accounts anywhere.
