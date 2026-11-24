<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Enrollment model

A Quint [model](enrollment.qnt) of device enrollment (verification level V2 of the
[specification](../../docs/spec/requirements.md), Section 14): pairing of a joiner with an acceptor or
with the Root by a code, with attempts counted on both sides; the joiner's signed payload; join
requests; a compromised acceptor and a network adversary that pairs by guessing the code and relays
payloads between sessions; and admission by the Root after the owner compares the key fingerprint.
CPace, signatures, and sealing are perfect here; Tamarin covers them. The header of `enrollment.qnt`
lists every abstraction.

## Instances

| Instance | Joiners | Honest acceptors | Attempts per code | Sessions | Purpose |
| --- | --- | --- | --- | --- | --- |
| `small` | `j1` (with user presence), `j2` | `h`, the Root | 2 | 6 | Simulator in CI |
| `tiny` | `j1` (with user presence) | `h` | 2 | 4 | Simulator in CI, TLC |
| `tiny_root` | `j1` (with user presence) | `h`, the Root | 2 | 4 | TLC witnesses (admission after pairing with the Root is reachable) |
| `probe_*` | as `small` | | | | One deliberate defect each; `safety` must fail (R-VER-2) |

Every instance also has the compromised acceptor `c` and the adversary's own device key.

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
| 2026-11-23 | `a8c801d73b0f`, invariant `9a33443ad926` (commit 112a58e) | Apalache 0.62.4, `run-inductive.ps1 -Split -Parallel 1`, maintainer's server (12 GB heap; `stepBadRequest` with 25 GB, rerun alone with `-Only BadRequest` after it ran out of memory at 12 GB) | `small_ind`, all states satisfying `IndInv` | all three obligations hold: init in 1.0 min, the 7 step branches in 10.4 to 15.3 min, `IndInv` implies `safety` in 5.8 min; 90 min in total. Safety holds in every reachable state of `small` |
| 2026-11-23 | `a8c801d73b0f`, view `1b404602279a` (commit 279b046) | Apalache 0.62.4, `run-inductive.ps1 -Section bisim -Parallel 8`, maintainer's server (6 GB heap) | `tiny_bisim`, all pairs of states satisfying `Struct` | all 18 checks pass: init and the 7 step branches preserve `Struct` (0.6 to 1.1 min), equal views agree on `safety` (1.1 min), each of the 7 branches is answered with an equal view (3.6 to 4.1 min), both witnesses violated as expected; 5.4 min in total. TLC with the view is exact for `safety` |
| 2026-11-23 | `a8c801d73b0f`, view `1b404602279a` (commit 279b046) | TLC 1.7.4, `run-tlc.ps1 -View`, maintainer's server (54 workers) | `tiny`, exhaustive, `VIEW safetyView` | no error: 2,688 distinct states (3,265,222 generated), depth 10, 13 s; probability of a fingerprint collision 4.8E-10 (TLC's optimistic estimate), 2.5E-13 (from the actual fingerprints) |

After the proof, the only change to `inductive.qnt` was a three-line comment above `stepBadIssue`,
so the file now hashes to `9a33443ad926`; `IndInv` and every step branch of the proof are unchanged.
