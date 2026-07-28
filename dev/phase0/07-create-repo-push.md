# 07 — create the GitHub repo and push

Last step. Do not run it until 01–06 are closed, especially 06.

- [ ] Create `hackertwinten/awspriv` on GitHub. Public.
- [ ] Description matches Cargo.toml: "Stealth-first AWS access key permission
      assessment and ranking."
- [ ] Topics: `aws`, `iam`, `security`, `pentest`, `rust` (mirror Cargo
      keywords).
- [ ] `git remote add origin` + `git push -u origin main`.
- [ ] Pin the repo on the `hackertwinten` profile (this closes the awspriv half
      of the plan's Phase 0 "profile tidy" item — repo pinning was blocked on
      the repo being public).
- [ ] After push: click your own repo as a reviewer would. README renders,
      LICENSE files show, no `settings.local.json`, no `target/`.

Not in this session, tracked in the plan: crates.io publish. Decide separately —
publishing the crate is a larger commitment (name squat, versioning, yanking
rules) than a public repo, and Phase 0 only needs the repo visible.
