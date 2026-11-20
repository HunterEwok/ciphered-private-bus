# Changelog

All notable changes to Ciphered Private Bus are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Protocol requirements specification (draft, baseline for gate G0) in `docs/spec/`: the
  requirements, Appendix B (wire format), Appendix C (CDDL schema and size analysis), and a
  glossary of terms and code identifiers.
- Quint model of the membership state machine (`models/membership/`) with its safety
  invariants, twelve probes, fixed scenarios, and non-vacuity witnesses, a check script,
  and a CI job that runs the simulator at the CI sizes.
- Version check for tools pinned outside Dependabot (`tools/versions/`): pull requests
  check that the pins agree with the files that use them; a weekly run fails when a newer
  stable release exists. Dependabot also watches the npm dependencies in `models/`.
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
- Specification: a halted node ranks its (generation, checkpoint) pair above every checkpoint of its
  generation and answers every sender of that generation with its halt proof (R-MEM-6, R-MEM-10,
  Appendix B, Section B.3, rule 3). Reason: the membership model showed that a proof of a generation
  a node had not reached yet was dropped, and on a direct link nothing sent it again, so the node
  could keep working under a Root that had signed conflicting records.
- Rust toolchain updated from 1.97.0 to 1.100.0.
- The repository hygiene check now also scans dot-files and directories (previously
  skipped), rejects more traces of AI tooling (notices, trailers, vendor and model names,
  tool configuration files, bot identities, and tool-named branches), and limits commit identities to the
  maintainer's only on the maintainer's own pull requests. A pre-push hook checks the
  branch name and the commits before they leave the machine. It has unit tests.
