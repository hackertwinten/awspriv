# 03 — add LICENSE files (dual MIT / Apache-2.0)

`Cargo.toml` declares `license = "MIT OR Apache-2.0"` but there are **no LICENSE
files in the tree**. A dual-license declaration needs both texts present, by
convention:

- [ ] `LICENSE-MIT` — MIT text, copyright line for the year and the identity
      you are publishing under. Plan says the handle is public and the legal
      name is a private dial — decide which name goes in the copyright line now,
      because it is public the moment you push. A handle is a valid copyright
      holder.
- [ ] `LICENSE-APACHE` — Apache-2.0 text.
- [ ] Optional: a short `## License` section in the README pointing at both.

The plan's legal-hygiene rule for every tool repo (Phase 0): LICENSE with a
warranty disclaimer (both these licenses carry one), a README line stating
intended use (issue 04), and zero client names or real infra (audit already
confirmed clean).
