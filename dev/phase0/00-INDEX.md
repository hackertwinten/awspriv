# awspriv — Phase 0 publish session

Goal: awspriv goes public under `hackertwinten`, clean, with a README that
explains the *why*. Plan reference: Phase 0, item 1 (the flagship — do not let
this slip).

Pre-work already done on 2026-07-27:
- Secret audit ran clean. No account IDs, no real ARNs, no live keys.
  `examples/keys.txt` is a commented format sample and is gitignored.
- Not a git repo yet, so there is **no history to scrub** — one clean initial
  commit, no rewrite.

## Issues, in dependency order

1. [01](01-gitignore-settings.md) — gitignore `.claude/settings.local.json` before init
2. [02](02-git-init.md) — `git init` + clean initial commit
3. [03](03-license-files.md) — add MIT + Apache-2.0 LICENSE files (dual)
4. [04](04-readme.md) — write the README (the real work of the session)
5. [05](05-build-clippy-green.md) — `cargo build` + `cargo clippy` green
6. [06](06-self-review.md) — read the whole source before push (owner pass)
7. [07](07-create-repo-push.md) — create the GitHub repo and push

Do 06 before 07. Publish is one-way for a security tool.
