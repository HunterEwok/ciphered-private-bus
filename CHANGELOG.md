# Changelog

All notable changes to Ciphered Private Bus are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial repository setup, licensing (`MPL-2.0` for code, `CC-BY-4.0` for specification),
  branding policy, and contributor documentation.
- Rust Cargo workspace with a pinned toolchain, shared lints, and a placeholder `cpb`
  crate.
- CI for Rust (formatting, Clippy, tests on Linux, macOS, and Windows, MSRV check) and
  dependency policy checks with `cargo-deny`.
- OpenSSF Scorecard and GitHub Actions workflow auditing.

### Changed
- The repository hygiene check now also scans dot-files and directories (previously
  skipped), rejects more traces of AI tooling (notices, trailers, vendor and model names,
  tool configuration files, bot identities, and tool-named branches), and limits commit identities to the
  maintainer's only on the maintainer's own pull requests. It has unit tests.
