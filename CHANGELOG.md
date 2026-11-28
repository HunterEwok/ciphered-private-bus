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
- Quint model of the member relay (`models/relay/`): publications with retention depth, key grants,
  key requests and calls arriving with forged objects among them, quotas per source and per bus with
  the eviction rules of Appendix B, Section B.10 (fair share), revocation of a device, removal of the
  relay from the checkpoint's `relays` list, also across a root change, and the join request buffer;
  nineteen probes, witnesses, fixed scenarios, and a CI job.
- Quint model of external relays (`models/extrelay/`): relay epochs of the root device, relay access
  objects ordered by root device and epoch with a stolen key of a replaced root device signing any
  epoch, tickets, bridges under a closed alias with the records a member asleep through a root change
  needs, relay hello admission by the members tree, and Root-signed objects from the root device only;
  eleven probes, witnesses, fixed scenarios, an inductive invariant, and CI jobs.
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
- Local application interface crate `cpb-api` (R-API-2): the `LocalApi` trait, non-blocking and
  without callbacks, events through `poll_event`; blobs written in pieces and fetched by segment,
  streams opened by a call and its reply with data, credit, "end" and the reason a stream closed,
  the message of a reply, the key that signed an incoming call, root-signed application data,
  the application part of the node info, membership change events and the root device in the bus
  state, pairing by a code the joiner presents and the acceptor reads,
  the device key and bus fingerprints, and the owner's answer to a join request with the fingerprint
  the root device got from the joiner; the single list of rule codes `area/rule` (R-ERR-1); error reports with the debug and
  release modes (R-ERR-2, R-ERR-3).
- In-memory bus simulator `cpb-sim` for application authors: several nodes in one process behind
  `LocalApi`, an engine written from the enrollment, membership, channels, calls and streams models, a
  deterministic harness with loss, duplication, reordering, sleeping and rebooting nodes and a member
  relay that may refuse streams and holds join requests for the Root, owner operations, host requests for user confirmation, and the
  `CPB_ERRORS` override. Interface tests and a replay of 77 model traces (every scenario run of the
  five models and 50 random traces) with equal state after every step; `tools/sim/gen_traces.py` regenerates the traces, and a CI job checks that
  they match the current models.

### Changed
- Gate S in Section 14.3: the application simulator after G1, so profiles can start before the
  core; R-API-2 names the default readers of a channel, the delivery of retained publications on
  subscription, the owner's operations on the root device, a new channel key on the application's
  request (also in R-CH-5 and R-CH-6), blobs written in pieces and fetched by segment, the application node info, the root device in the bus state, and the membership change
  report (also in R-CORE-2); R-CALL-8 makes a commander forget its
  held nonces on its own "reset nonces"; Appendix B, Section B.9 keeps the rule code list in
  `cpb-api`.
- Specification: R-API-2 names the stream operations, the message of a reply, the key that signed
  an incoming call, and the report of why a stream closed; a relay that does not serve streams
  answers a chunk with `RelayRefusal` code 4, whose `ref` is the hash of the chunk header; the core
  passes this unsigned hint to the application and does not close the stream (R-STR-7, Appendix B,
  Section B.10); the channel number row
  of Section 13.1 says which numbers belong to the application. Reason: the interface was narrower
  than the rules it serves, and the refusal of a stream reached no one.
- Specification: R-API-2 names the state of a node without a bus, the pairing operations, the two
  fingerprints, and what the owner sees and answers for a join request; Appendix B, Section B.11
  says that a device has one pairing code at a time, that a member keeps an early `PairInit` until
  it gets a code, and where join requests wait and within which bound. Reason: the rules of
  Section 7 had no operations at the interface.
- Specification: the bus requires of an application only what its core checks. R-JOIN-7 no longer
  forbids a user interface to take a fingerprint from the network: the core admits only the key whose
  fingerprint it is given, and no other, without conditions: the fingerprint is how
  the owner names a device to the bus. Which physical device a key belongs to is outside the bus (new
  limitation L9). Section 15.7 describes the ways an application may let the owner learn a
  fingerprint, with an invitation issued by the root device among them. R-JOIN-1
  and R-JOIN-5 describe the core, not screens, and R-ARC-7 states what an observer of a link sees
  transport instead of recommending one.
- Specification: the right to accept join requests is removed. Any valid member pairs with a joiner
  and sends its join request; the passport rights are read, publish and relay (Sections 6.1 and 7,
  R-JOIN-4, R-API-2; Appendix B, Sections B.3 and B.11). Reason: admission depends only on the check
  the root device makes (R-JOIN-7), so the right guarded nothing. In the interface `Rights` loses
  `accept`, and the codes `join/no-right` and `join/not-acceptor` are gone; a join request from a
  device that is not a valid member is refused with `mem/not-member`.
- Specification: one way to pair, and the root device, not the owner, checks the joiner. The joiner
  generates a code, a 16-byte secret and the 32-byte fingerprint of its device key, and presents it
  as a QR code or a tag; the acceptor reads it through its own camera, reader or keyboard and refuses
  a peer with another device key (`PairAbort` code 5). The root device admits a joiner only with the
  fingerprint it read from the joiner itself, and its core refuses a request with another key. The
  short code, a code shown by the acceptor, the count of runs per code with its profile parameter,
  and the 20-digit form of the key fingerprint are removed (R-JOIN-1, R-JOIN-3, R-JOIN-5, R-JOIN-7,
  R-JOIN-9, R-API-2, Sections 13 and 15.7; Appendix B, Sections B.8 and B.11). Reason: people confirm
  mismatching strings, a code on a screen is known to everyone who sees the screen, and once the
  root device must read the fingerprint from the joiner, the same reading carries the secret.
- Specification: a root change names a root key never used on the bus before, and a node rejects a
  record that names the root key it holds now (R-MEM-11, Appendix B, Section B.3). Reason: the proofs
  assume a fresh root key per generation, and the text did not require it.
- Specification: the root key signs application data under its own label `cpb app v1`, bound to the
  bus, the root generation and an application tag, and every node verifies it without the
  application seeing the root key (new R-KEY-12, R-API-2, Appendix B, Section B.8, Section 13.1).
  Reason: a profile's owner-level settings deserve the same key as membership, so a stolen device key
  of the root device cannot change them.
- Specification: the blob key is 32 random bytes per blob carried in the publication content
  (field 5), and a blob segment authenticates only its last-segment flag (R-CH-3, R-CH-15, R-FMT-10,
  Appendix B, Sections B.1, B.5, B.7, B.8). A reader delivers verified segments in order, and a blob
  is published only at depth 1 or more. Reason: the blob key was derived from the header hash, and the
  header holds the hash of the encrypted blob, so neither could be computed first.
- Specification: `NodeInfo` has an optional application part `app` of up to 4024 bytes that the
  core does not parse; the extension range stays reserved for the bus (R-CH-16, Appendix B, Section
  B.5, Appendix C). Reason: a profile needs per-node state, and a channel of its own only for that
  costs every reader a key and a grant.
- Specification: an external relay sees a bus only under aliases that differ per relay and per relay
  epoch (new property S18, R-REL-13..R-REL-20, R-KEY-11, Section 15.9, decision D15, Appendix B,
  Section B.10, Appendix C). The Root starts a new relay epoch with every revocation and issues each
  member a sealed relay access object with the epoch secret and a link seed; tickets are signed by a
  period key whose hash is the bus alias and carry the root of a tree of (alias, link key) pairs;
  everything a member sends through an external relay is wrapped in `Relayed` with a single-use key;
  a closed alias keeps only the bridges to the next epoch. A member relay is unchanged. Reason: a
  third-party relay learned the bus identifier, every device identifier, and every passport for the
  life of the bus, and two relays of one bus could join their logs, although delivery and quotas need
  none of it.
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
- Specification: the window floor starts at 1 and rises only when publications leave the retained
  ones because the depth is exceeded, or above a clearing publication; losing the retained
  publications in a reboot does not move it (R-CH-9). Reason: with the floor defined as the lowest
  retained number, a floor kept below an evicted publication let it be accepted again after a reboot.
- Specification: a relay replaces a held grant also with one of the same generation, which may carry
  the nonce of a key request (R-REL-3). Reason: otherwise the answer to a key request of a reader whose
  source had not rotated could not pass the relay.
- Specification: the class of an action comes from the permits in the target's passport, never from
  the call; the root key has the right to every action, and the other keys of the root device only the
  rights the passport gives that device (R-CALL-4).
- Specification: the owner compares the device key fingerprint also when the Root pairs a joiner
  itself (R-JOIN-9, Appendix B, Section B.11, note 3). Reason: one pairing procedure, and the code is
  never the only barrier.
- Specification: a stream chunk sets exactly one of the flags data, credit and end; any other
  combination closes the stream (R-STR-2, Appendix B, Section B.7).
- Specification: S7 is stated for the records a node processed; a record dropped because it is not yet
  valid for the node reaches it again through the exchange of control-plane objects.
- Specification: the source persists the readers still to be granted a new channel key until each
  grant is sent (R-CH-5, R-CORE-5). Reason: the channels model showed that a source that rebooted
  between a new key and its grants published under the key without granting it.
- Rust toolchain updated from 1.97.0 to 1.100.0.
- The repository hygiene check now also scans dot-files and directories (previously
  skipped), rejects more traces of AI tooling (notices, trailers, vendor and model names,
  tool configuration files, bot identities, and tool-named branches), and limits commit identities to the
  maintainer's only on the maintainer's own pull requests. A pre-push hook checks the
  branch name and the commits before they leave the machine. It has unit tests.
