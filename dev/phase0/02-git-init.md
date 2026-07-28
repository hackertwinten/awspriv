# 02 — git init + clean initial commit

No `.git` exists. This is the good case: no history means nothing to scrub.

- [ ] `git init`
- [ ] Confirm `git status` shows no ignored file staged — especially
      `settings.local.json` (issue 01), `target/`, `keys.txt`.
- [ ] One initial commit. Suggested message:
      `feat: initial public release of awspriv`
- [ ] Default branch `main`.

Do not init until issue 01 is closed. A file committed once and then gitignored
still lives in history.
