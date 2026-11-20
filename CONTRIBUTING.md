# Contributing

Thank you for your interest in **Ciphered Private Bus** (**CPB**). For general help, see
[SUPPORT.md](SUPPORT.md). For branding and naming rules, see [BRAND.md](BRAND.md).

## Issues and discussions

- **Bugs:** open an issue using the **Bug report** form.
- **Ideas, protocol questions, and proposals:** open an issue using the **Feature request** form.
- **Security vulnerabilities:** do not open a public issue; follow [SECURITY.md](SECURITY.md).

## Pull requests (discuss first)

**Please open an issue and discuss your change before opening a pull request.**

Unsolicited pull requests that introduce unagreed protocol changes, new dependencies, or
architectural shifts may be closed without review. Discussing in an issue first ensures
the change aligns with the specification, threat model, and roadmap.

By submitting a pull request, you agree that:

- Your **code and test vector** contributions are licensed under [MPL-2.0](LICENSE).
- Your **specification and documentation** contributions in `docs/` are licensed under
  [CC BY 4.0](LICENSES/CC-BY-4.0.txt).

## Local setup

- Install the Rust toolchain with [rustup](https://rustup.rs). The pinned channel and
  components in `rust-toolchain.toml` are installed automatically on first use.
- Enable the repository's Git hooks once per clone:

  ```sh
  git config core.hooksPath .githooks
  ```

  The hooks run the same hygiene check as CI (`.github/scripts/check_hygiene.py`) before
  each commit, on each commit message, and on the branch name and commits of each push.
- Before pushing, run:

  ```sh
  cargo fmt --all --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  cargo deny check            # requires `cargo install cargo-deny`
  python3 -m unittest discover -s .github/scripts
  ```

## Conventions

- **English only** in code, comments, documentation, commit messages, and issues.
- **License headers.** Every Rust source file starts with:

  ```rust
  // SPDX-License-Identifier: MPL-2.0
  // Copyright (C) 2026 HunterEwok
  ```

  Other source files and scripts start with the same two lines in their own comment style.
  Files that cannot carry headers (e.g., JSON test vectors, images) are covered by
  [REUSE.toml](REUSE.toml); `reuse lint` checks that every file has a valid license.
- **Repository hygiene.** CI rejects non-English text, non-ASCII characters outside common
  typographic punctuation, traces of AI tooling (generation notices, trailers, chat links,
  model names, tool configuration files, bot identities, or tool-named branches), local
  filesystem paths, and secrets in files, commit messages, and pull request text. Keep editor- and tool-specific
  files out of the repository; use `.git/info/exclude` for local ignores.
- **Pull requests & branch protection.** Changes go into `main` through pull requests.
- **Commit messages.** Short summary line in the imperative mood (e.g., `"Add frame header
  parser"`), followed by a blank line and details if needed.
- **Changelog.** User-visible or protocol-visible changes go into
  [CHANGELOG.md](CHANGELOG.md) under *Unreleased*.
- **Rust code.** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo test` must pass. New protocol/crypto logic must include unit tests and, where
  applicable, deterministic test vectors in `testdata/`.
- **Specification sync.** Any change to framing, addressing, arbitration, replay
  protection, cryptography, or root recovery must update the formal specification in
  `docs/` in the same pull request.
