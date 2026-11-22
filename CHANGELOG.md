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
  invariants, twelve safety probes and one liveness probe, fixed scenarios, and non-vacuity
  witnesses, a check script, and a CI job that runs the simulator at the CI sizes.
- Quint model of channel keys and retention (`models/channels/`): key rotation and grants,
  publication numbers reserved in blocks, the recipient's window and retention depth, the clearing
  publication, and reboots, with a relay that behaves arbitrarily; fourteen probes, witnesses, fixed
  scenarios, an inductive invariant that Apalache proves in CI for two devices, and CI jobs.
  `models/run-tlc.ps1` and `models/run-inductive.ps1` run TLC and the inductive proof for any model
  folder, and `models/run-all.ps1` runs both for several models one after another.
- Quint model of call nonce slots (`models/calls/`): nonce requests, calls, replies, the open
  refusals and the commander's automatic retries, "reset nonces" and reboot, key epoch rotation, and
  passport changes, with a network that replays and forges unsigned messages; twelve probes,
  witnesses, fixed scenarios, an inductive invariant, and CI jobs.
- Quint model of device enrollment (`models/enrollment/`): pairing by a code with attempts counted on
  both sides, the joiner's signed payload, join requests, a compromised acceptor and a network
  adversary that guesses codes and relays payloads between sessions, and admission after the owner
  compares fingerprints; six probes, witnesses, fixed scenarios, an inductive invariant, and CI jobs.
- Quint model of streams (`models/streams/`): a stream opened by the reply to a call in ordered or
  lossy mode, chunks with data, credit and "end" in both directions, the limit on open streams, and
  every event that closes a stream, with a network that replays and reorders chunks and a peer that
  may overrun its credit; thirteen probes, witnesses, fixed scenarios, and a CI job.
- Quint model of the relay (`models/relay/`): publications with retention depth, key grants, key
  requests and calls arriving with forged objects among them, quotas per source and per bus with the
  eviction rules of Appendix B, Section B.10 (fair share), revocation of a device, removal of the relay
  from the checkpoint, tickets across a root change, and the join request buffer; eighteen probes,
  witnesses, fixed scenarios, and a CI job.
- Inductive invariant of the membership model (`models/membership/inductive.qnt`): Apalache
  proves its safety for every reachable state, in CI for two devices and in long runs for
  larger sizes. Runners for shared Windows machines: `run-tlc.ps1` (exhaustive TLC, and a
  check of the TLA+ translation on every probe and witness) and `run-inductive.ps1`.
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
- Specification: when a device leaves the readers, the source marks its channels for key rotation
  in the same event and persists the mark (R-CH-5, R-CORE-5). Reason: the channels model showed that
  a source that rebooted with its key intact forgot whom it had granted the key and published under it
  to a removed reader.
- Specification: a clearing publication that arrives late, inside the window, clears the publications
  up to its number and moves the floor above it; a publication of depth 0 is accepted only as a new
  one; neither is ever retained (R-CH-9, R-CH-10). While the rotation mark is set, the source grants
  the marked key to no one (R-CH-5). A reader persists the depth of its latest accepted publication
  (R-CORE-5), which the refill after a reboot needs. Reason: a review of the channels model.
- Specification: a nonce mismatch for a commander without a slot, for example after "reset nonces",
  is answered like a nonce request, so the refusal carries a new nonce (R-CALL-6). Reason: the calls
  model; otherwise the commander needed a separate nonce request after every reset.
- Specification: when a device stops being a commander of the target, its nonce slot is erased in the
  same event (R-CALL-7). Reason: a review of the calls model found that the next call of a removed
  commander refilled its slot.
- Specification: the join request carries the transcript hash of the acceptor's own pairing session,
  and the acceptor checks the joiner's signature before sending it (R-JOIN-4). Reason: the
  enrollment model; it makes explicit what stops a man in the middle from relaying a payload.
- Specification: a permanently halted node (two root change records of one generation) answers
  every sender, of any generation, with its halt proof, and that proof takes effect at any
  generation because it is verified with K1 and K2 alone (R-MEM-6, R-MEM-13, Appendix B,
  Section B.3, rules 2 and 3).
- Rust toolchain updated from 1.97.0 to 1.100.0.
- The repository hygiene check now also scans dot-files and directories (previously
  skipped), rejects more traces of AI tooling (notices, trailers, vendor and model names,
  tool configuration files, bot identities, and tool-named branches), and limits commit identities to the
  maintainer's only on the maintainer's own pull requests. A pre-push hook checks the
  branch name and the commits before they leave the machine. It has unit tests.
