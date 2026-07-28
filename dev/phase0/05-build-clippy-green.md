# 05 — build and clippy green before push

A public Rust security tool that does not compile clean is an own-goal for a
reviewer. Confirm green on a cold checkout.

- [ ] `cargo build --release`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test` — there are tests (`tests/catalog.rs`, plus unit tests in
      `src/`). Confirm they pass and are not asserting against any real account.
- [ ] `cargo fmt --check`

`rust-version = "1.91"` in Cargo.toml — confirm your toolchain matches, or a
CI/reviewer on a pinned toolchain hits an MSRV error.
