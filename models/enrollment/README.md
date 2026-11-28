<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Enrollment model

A Quint [model](enrollment.qnt) of device enrollment (verification level V2 of the
[specification](../../docs/spec/requirements.md), Section 14): pairing of a joiner with an acceptor or
with the Root by a code, with attempts counted on both sides; the joiner's signed payload; join
requests; a compromised acceptor and a network adversary that pairs by guessing the code and relays
payloads between sessions; and admission by the Root after the owner compares the key fingerprint.
CPace, signatures, and sealing are perfect here; Tamarin covers them. [Abstractions](#abstractions)
lists every abstraction.

## Instances

| Instance | Joiners | Honest acceptors | Attempts per code | Sessions | Purpose |
| --- | --- | --- | --- | --- | --- |
| `small` | `j1` (with user presence), `j2` | `h`, the Root | 2 | 6 | Simulator in CI |
| `tiny` | `j1` (with user presence) | `h` | 2 | 4 | Simulator in CI, TLC |
| `tiny_root` | `j1` (with user presence) | `h`, the Root | 2 | 4 | TLC witnesses (admission after pairing with the Root is reachable) |
| `probe_*` | as `small` | | | | One deliberate defect each; `safety` must fail (R-VER-2) |

Every instance also has the compromised acceptor `c` and the adversary's own device key.

### Why `small` is large enough

The safety proof runs at `small_ind`, the size of `small`. Every property relates at most the
following roles at the same time, and `small` holds a copy of each:

- two joiners, one with a user-presence key and one without, so that a payload of one joiner relayed
  into a session of the other is refused (`bound`, probe `no_transcript_binding`), and a request that
  swaps the presence key or the name meets a joiner that signed something else (`asSigned`, probe
  `sig_key_only`). The adversary's own device key is the third key that may be put in a request
  (`intended`, probe `no_fingerprint_compare`);
- two honest acceptors, an ordinary member and the Root pairing directly (R-JOIN-9), so that both
  paths to admission meet the same checks (`rootOnly`, `intended`);
- one compromised acceptor. It shares everything it knows with the network adversary, so a second
  compromised acceptor would know nothing more and could send nothing more; there is one Root, and it
  is honest;
- a limit of 2 attempts per code, the least in which a failed attempt is followed by one more allowed
  attempt and then a refusal. The counters are compared only with the limit, so a larger limit
  repeats the second attempt (`guessLimit`, probes `joiner_no_count`, `acceptor_no_count`);
- six sessions. Sessions are compared only for equality: a request is bound to the session it names.
  `indInit` draws the attempt counters, the used sessions and the payloads freely, so the states of
  `IndInv` hold every count of attempts up to the limit together with any five used sessions, and a
  new session needs only a name that differs from all of them.

A third joiner or a second ordinary acceptor repeats one of these roles, since every property is
about one joiner's key, the session it ran and the request made from it. The proof covers further
sessions and attempts from every state of `IndInv`, not only from reachable ones.

## Properties

| Invariant | Requirement | Property |
| --- | --- | --- |
| `intended` | R-JOIN-5, R-JOIN-7 | S4: a passport goes only to the key of the device the owner enrolls |
| `asSigned` | R-JOIN-4 | S4: a joiner's passport carries exactly the presence key and name it signed |
| `bound` | R-JOIN-4 | S4: a request through an honest acceptor admits a joiner only from a session the joiner ran with that acceptor |
| `guessLimit` | R-JOIN-3 | S4: no side runs more than the limit of attempts with one code |
| `rootOnly` | R-JOIN-6 | S4: every passport was confirmed by the owner on the Root |

Step properties are checked by a monitor when the step is taken, as in the membership model.

Probes, each expected to violate `safety`:

| Probe | Defect |
| --- | --- |
| `no_fingerprint_compare` | The owner confirms without comparing fingerprints |
| `sig_key_only` | The joiner's signature is checked for the key but not for the presence key and name |
| `no_transcript_binding` | The acceptor takes the transcript from the payload instead of its own session |
| `joiner_no_count` | The joiner does not count attempts against a fake acceptor |
| `acceptor_no_count` | The acceptor does not count attempts against a fake joiner |
| `acceptor_issues` | The compromised acceptor issues a passport itself |

The fixed scenarios in [`scenarios.qnt`](scenarios.qnt) show admission through an honest acceptor, a
compromised acceptor's tampered request being dropped, a relayed payload being refused, and the
attempt limit.

The model made one point of the specification explicit: the join request carries the transcript hash
of the acceptor's own session, and the acceptor checks the joiner's signature before sending it, so a
payload relayed from another session is refused (R-JOIN-4).

## Abstractions

What a green run of this model does and does not show:

- CPace, signatures, and sealing are perfect; Tamarin covers them. A pairing session is named by its
  transcript (`tid`), and only its two ends know what was sent in it. A run against a side that does
  not know the code is one password guess, and any guess may succeed: the model bounds the number of
  guesses, not their probability.
- The fingerprint is 64 bits of the key hash (R-JOIN-5); equal fingerprints are taken as equal keys.
- The owner enrolls the honest joiner in front of them and confirms only after comparing the
  fingerprint the Root shows with the one the joiner shows (R-JOIN-7). This holds for every
  admission, also when the Root pairs the joiner itself (R-JOIN-9): `rootAdmit` has the comparison as
  a guard on every path, and the probe `no_fingerprint_compare` removes it.
- When the Root pairs directly it is the acceptor `root`: the payload it receives in its own session
  becomes a request in its own inbox. R-JOIN-9 prepares no join request there; the model's request
  carries exactly what the Root holds at that point, so the checks are the same.
- The joiner's check of the bus fingerprint after admission is not modelled.
- The compromised acceptor `c` is a member. With the adversary it knows every payload sent to either of
  them and may put anything in a request. The Root itself is honest.
- The bus identity and the root key the joiner learns (R-JOIN-2) belong to Tamarin and the membership
  model. The sealing of a request to the root device and its open header (R-JOIN-4, last sentences)
  belong to Tamarin; the relay's buffer of requests (R-JOIN-8) to the relay model.

## Requirement coverage

Every normative sentence of the requirements in scope, and what in the model checks it: an invariant
(with the probe that breaks it), a guard, or a stated abstraction.

| Requirement | Sentence | Checked by |
| --- | --- | --- |
| R-JOIN-3 | a failed attempt lets the adversary test at most one password guess | abstraction: a run against a side without the code is one guess (above); CPace in Tamarin |
| R-JOIN-3 | the number of attempts per code is bounded | `guessLimit`; probes `joiner_no_count`, `acceptor_no_count`; scenario `limitTest` |
| R-JOIN-4 | the request holds the joiner's key, presence key, name, transcript hash, the joiner's signature over them, and the acceptor's signature | the record `Request`; `asSigned`; probe `sig_key_only`; scenario `tamperTest` |
| R-JOIN-4 | the transcript hash is the acceptor's own session's, and the acceptor checks the joiner's signature before sending | guard in `acceptorRequest`; `bound`; probe `no_transcript_binding`; scenario `relayTest` |
| R-JOIN-4 | the Root verifies the joiner's signature, so the acceptor substitutes neither the presence key nor the name | guards in `badRequest` and `rootAdmit`; `asSigned`; probe `sig_key_only`; witness `witnessTampered` |
| R-JOIN-4 | a request is a control-plane object with an open header and a body sealed to the root device | abstraction: sealing is perfect (above) |
| R-JOIN-5 | the Root shows the name, the acceptor, and the fingerprint of the joiner's key | the fields of `Request` that `rootAdmit` reads |
| R-JOIN-5 | the passport is issued only after the owner confirms on the root device | `rootOnly`; probe `acceptor_issues` |
| R-JOIN-6 | no sequence of messages without a Root signature makes a device a member; an acceptor cannot issue a passport | `rootOnly`; probe `acceptor_issues` |
| R-JOIN-7 | the joiner shows its fingerprint; the owner compares both before confirming | `intended`; probe `no_fingerprint_compare`; scenario `admitTest` |
| R-JOIN-7 | after admission the joiner shows the bus fingerprint | abstraction: not modelled (above) |
| R-JOIN-9 | the Root may pair a joiner itself, with the same exchange and no join request | the acceptor `root` (above); witness `witnessDirect` |
| R-JOIN-9 | the owner compares the fingerprint here too | `intended` (the comparison guards every admission); probe `no_fingerprint_compare` |

## Inductive invariant

[`inductive.qnt`](inductive.qnt) holds an inductive invariant `IndInv`; Apalache proves the same three
obligations as for the other models. Besides the bounds of every variable and `broken` staying empty,
`IndInv` states these lemmas: sessions are named uniquely by their transcript, and a joiner's latest
session is one it ran; every payload a joiner sent went to the other end of its own session; the Root
keeps only requests that the joiner's signature covers; a joiner's request carries its own presence
key and name; a request through an honest acceptor comes from a session of that joiner with that
acceptor; and every passport was confirmed.

The instances are `tiny_ind` (the size of `tiny`, checked in CI) and `small_ind` (the size of `small`)
for a long run.

## State view for TLC

Exhaustive TLC of `tiny` does not finish on its own: the adversary and the
compromised acceptor can file any subset of the requests signed by the
adversary's key. `view.qnt` defines a TLC `VIEW` that drops those requests
(the Root admits a request only for the joiner in front of it, so they never
enable or change a step) and the witness tags, and module `bisim` proves with
Apalache that states with equal views are interchangeable for `safety`, so TLC
with the view finds a violation exactly when TLC without it would. Run with
`run-tlc.ps1 -Model enrollment -View` and
`run-inductive.ps1 -Model enrollment -Section bisim`.

## Running

```sh
python3 models/enrollment/check.py                         # CI run
python3 models/enrollment/check.py --inductive tiny_ind    # IndInv in CI
```

```powershell
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model enrollment -Probes -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model enrollment -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model enrollment -Split -WorkDir <folder> -Java <path to java>
```

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |
| 2026-11-21 | `a8c801d73b0f` (commit 56d4c14) | TLC 1.7.4, `run-all.ps1 -Stages probes`, maintainer's server (49 workers) | 6 probes against `safety`, 5 witnesses on `tiny_root`, breadth-first until the first violation | 11 of 11 violated as expected, 1.0 to 17.4 min each (`probe_sig_key_only` the longest, 52 million distinct states at depth 8) |
| 2026-11-26 | `a8c801d73b0f`, invariant `9a33443ad926` (commit 78aea79) | Apalache 0.62.4, `run-inductive.ps1 -Split -Parallel 1`, maintainer's server (25 GB heap) | `small_ind`, all states satisfying `IndInv` | all three obligations hold: init in 1.0 min, the 7 step branches in 10.7 to 20.3 min, `IndInv` implies `safety` in 6.3 min; 106 min in total. Safety holds in every reachable state of `small` |
| 2026-11-23 | `a8c801d73b0f`, view `1b404602279a` (commit 279b046) | Apalache 0.62.4, `run-inductive.ps1 -Section bisim -Parallel 8`, maintainer's server (6 GB heap) | `tiny_bisim`, all pairs of states satisfying `Struct` | all 18 checks pass: init and the 7 step branches preserve `Struct` (0.6 to 1.1 min), equal views agree on `safety` (1.1 min), each of the 7 branches is answered with an equal view (3.6 to 4.1 min), both witnesses violated as expected; 5.4 min in total. TLC with the view is exact for `safety` |
| 2026-11-23 | `a8c801d73b0f`, view `1b404602279a` (commit 279b046) | TLC 1.7.4, `run-tlc.ps1 -View`, maintainer's server (54 workers) | `tiny`, exhaustive, `VIEW safetyView` | no error: 2,688 distinct states (3,265,222 generated), depth 10, 13 s; probability of a fingerprint collision 4.8E-10 (TLC's optimistic estimate), 2.5E-13 (from the actual fingerprints) |
