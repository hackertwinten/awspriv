# 01 — gitignore local editor config before init

`.claude/settings.local.json` exists in the tree. It is local Claude Code
permission config (cargo build/test/clippy allowlist), not project code. It must
not land in a public repo.

Do this **before** `git init`, so it is never tracked in the first place.

- [ ] Add `.claude/settings.local.json` to `.gitignore`
      (or `.claude/` entirely — decide whether any `.claude` file is meant to
      ship).

Current `.gitignore` already covers: `/target`, `**/*.rs.bk`, `Cargo.lock`,
`.env`, `*.pem`, `keys.txt`.

Note: `Cargo.lock` is gitignored. That is correct for a library, debatable for a
binary crate — for a published CLI, committing the lock file gives reproducible
builds. Decide in this issue. If you keep it ignored, say why in the README or a
comment; a reviewer will notice a missing lock file on a security tool.
