# Changelog

All notable changes to Ciphered Private Bus are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Protocol requirements specification (draft, baseline for gate G0) in `docs/spec/`: the
  requirements, Appendix B (wire format), Appendix C (CDDL schema and size analysis), and a
  glossary of terms and code identifiers.
- CDDL schema of the wire format (`docs/spec/cpb.cddl`) and scripts in `tools/cddl/` that
  build the largest instance of every object, validate it against the schema, and check
  negative examples.
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
  maintainer's only on the maintainer's own pull requests. A pre-push hook checks the
  branch name and the commits before they leave the machine. It has unit tests.
