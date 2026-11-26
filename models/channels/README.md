<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Channels model

A Quint [model](channels.qnt) of channel keys and retention (verification level V2 of the
[specification](../../docs/spec/requirements.md), Section 14): one source and one channel, key
rotation and grants, publication numbers reserved in blocks, the recipient's window and retention
depth, the clearing publication, and reboots of the source and the readers. The network and any relay
are a pool of every publication and grant, so the relay behaves arbitrarily except that it cannot
forge (R-REL-11). The header of `channels.qnt` lists every abstraction.

## Instances

| Instance | Devices | Key generations | Numbers | Depth | Block | Purpose |
| --- | --- | --- | --- | --- | --- | --- |
| `small` | 3 (one without the read right, one late) | 3 | 5 | 0..2 | 2 | Simulator in CI |
| `tiny` | 2 | 2 | 4 | 0..2 | 2 | Simulator in CI, TLC |
| `probe_*` | as `small` | | | | | One deliberate defect each; `safety` must fail (R-VER-2) |

## Properties

| Invariant | Requirement | Property |
| --- | --- | --- |
| `freshness` | R-CH-9, R-CORE-5 | S12: the highest accepted number and generation never decrease, also across reboots |
| `uniqueNumbers` | R-CH-8 | publication numbers increase strictly over the device key's life |
| `uniqueKeys` | R-CH-8 | a key generation is never used for two keys |
| `rotateOnRemove` | R-CH-5 | S5: no device outside the readers holds the key of a new publication |
| `grantsToReaders` | R-CH-13 | keys are granted only to valid readers with the read right |
| `acceptUnderHeldKey` | R-CH-9 | a publication is accepted only under a key the reader holds |
| `noMarkedGrant` | R-CH-5 | while the rotation mark is set, the marked key is granted to no one |
| `retention` | R-CH-10, R-CH-11, R-CH-12 | at most `depth` retained publications, all in the window, distinct numbers, none of them a clearing publication or one of depth 0 |
| `noReadNoKey` | R-CH-13 | a device without the read right never holds a key |

Step properties are checked by a monitor when the step is taken, as in the membership model.

Probes, each expected to violate `safety`:

| Probe | Defect |
| --- | --- |
| `no_rotate_on_remove` | A device leaves the readers and the source does not mark the key for rotation |
| `mark_not_persisted` | The rotation mark is lost in a reboot |
| `grant_removed` | The source grants the key to a device outside the readers |
| `grant_no_read` | The source grants the key to a device without the read right |
| `no_block_skip` | After a reboot the source reuses numbers of the reserved block |
| `gen_not_persisted` | A reboot loses the latest key generation |
| `accept_old_grant` | A reader accepts a grant of a lower generation |
| `accept_without_key` | A reader accepts a publication under a key it does not hold |
| `empty_no_clear` | The clearing publication does not clear the retained publications |
| `refill_moves_high` | A refill from the window moves the highest number back |
| `high_not_persisted` | A reader loses its highest number in a reboot |
| `no_trim` | A reader retains more publications than the depth |
| `late_clear_kept` | A late clearing publication, or one of depth 0, is retained by a refill |
| `grant_marked` | The source grants a key marked for rotation |

`empty_no_clear`, `refill_moves_high`, `no_trim`, and `late_clear_kept` need a long specific sequence
and are checked by fixed scenarios in [`scenarios.qnt`](scenarios.qnt), which also show that refill
after a reboot, shrinking the depth, clearing, a late clearing publication, and rotation after a
removal are reachable with `safety` intact.

A reader persists the depth of its latest accepted publication with its window (R-CORE-5): after a
reboot it is what lets the window refill. Losing it would only stop the refill, which is liveness, not
safety, so there is no probe for it; the scenario `refillAfterRebootTest` and the witness
`witnessRefillAfterReboot` show that the refill after a reboot happens.

The model found a gap in the specification: a source that rebooted with its key intact no longer
knew whom it had granted the key, and published under it to a device that had left the readers. The
source now persists a rotation mark set in the same event in which a device leaves (R-CH-5,
R-CORE-5); the probe `mark_not_persisted` removes it. A review of the model found a second gap: a
clearing publication or one of depth 0 that arrived late, inside the window, was retained by a refill.
A late clearing publication now clears the window up to its number and moves the floor above it, and a
publication of depth 0 is accepted only as a new one (R-CH-9, R-CH-10).

## Inductive invariant

[`inductive.qnt`](inductive.qnt) holds an inductive invariant `IndInv`. Apalache proves the same three
obligations as for the membership model: the initial state satisfies `IndInv`; one step from any state
of the bounded types that satisfies `IndInv` leads to such a state; and `IndInv` implies `safety`.

Besides the bounds of every variable and `broken` staying empty, `IndInv` states these lemmas: a key's
identity equals its generation, and the number of keys made equals the source's generation; a key is
held only from generation 1; every publication and grant in the pool is at or below the source's
generation, and every publication number is below the next number and within the reserved block; the
pool and every reader's retained set have distinct numbers, and what a reader retains is in the pool;
and while the key may be used (held and not marked), every grant of it went to a current reader. The
last lemma is what makes `rotateOnRemove` follow, and it needs the persisted rotation mark.

The instances are `tiny_ind` (the size of `tiny`, checked in CI) and `small_ind` (the size of `small`)
for a long run.

## State view for TLC

Exhaustive TLC of `tiny` runs with a TLC `VIEW` defined in `view.qnt`. The view drops what no longer
influences `safety`: the witness tags, the readers granted the current key (they feed only a witness
tag), the ghost key counter (equal to the source's generation), every grant its reader can no longer
accept unless it is of the current key, and every publication no reader can accept again, because no
reader holds its key or can still be granted it, or because its number is neither new nor able to
enter the window of any reader that may hold the key. These conditions are monotone: a reader's
highest generation, highest number and window floor never go back, and the source never returns to an
older key. Module `bisim` proves with Apalache that states with equal views are interchangeable for
`safety` (obligations O1 to O4 in `view.qnt`, with the inductive invariant as `Struct`), so TLC with the
view finds a violation exactly when TLC without it would. B answers each step of A with the same step
and the same choices; a step that reads a dropped grant or publication changes nothing in A, and B
answers it with no step. The proof runs on `tiny_bisim`, which has the constants of `tiny`; `tiny` has no
late devices, so `envJoin` has no transition. Two checks confirm it with Apalache: no state that
satisfies `Struct` and `safety`, and no pair with equal views, enables `EnvJoin` (Apalache reports a
deadlock, which is the expected result), so O2 and O4 hold for it with nothing to answer.

## Running

```sh
python3 models/channels/check.py                         # CI run
python3 models/channels/check.py --inductive tiny_ind    # IndInv in CI
```

```powershell
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model channels -View -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model channels -Section bisim -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model channels -Probes -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model channels -Split -WorkDir <folder> -Java <path to java>
```

`run-inductive.ps1` takes the instance (`-Main`, default `small_ind`) and the branches of the step from
[`checks.json`](checks.json).

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |
| 2026-11-21 | `d4085bb6dda6` | TLC 1.7.4, `run-tlc.ps1 -Probes`, maintainer's server (49 workers) | 14 probes against `safety`, 7 witnesses on `tiny`, breadth-first until the first violation | 21 of 21 violated as expected, depth 8 to 15, 9 s to 78 s each |
| 2026-11-24 | `d4085bb6dda6`, view `c83d88078c76` (commit f0ca664) | Apalache 0.62.4, `run-inductive.ps1 -Section bisim -Split -Parallel 4`, maintainer's server (6 GB heap) | `tiny_bisim`, all pairs of states satisfying `Struct` | all 24 checks pass: init and the 9 enabled step branches preserve `Struct` (0.9 to 4.5 min), `EnvJoin` has no transition from a state satisfying `Struct` and `safety` (1.7 min) nor from a pair with equal views (6.0 min), equal views agree on `safety` (2.1 min), each of the 9 enabled branches is answered with an equal view (9.0 to 131.5 min, `ReaderPub` the longest), both witnesses violated as expected; 2 h 32 min in total. TLC with the view is exact for `safety` |
| 2026-11-24 | `d4085bb6dda6`, view `c83d88078c76` (commit f0ca664) | TLC 1.7.4, `run-tlc.ps1 -View`, maintainer's server (54 workers, 64 GB heap) | `tiny`, exhaustive, `VIEW safetyView` | no error: 29,966,498 distinct states (586,616,335 generated), depth 28, 4 min 54 s; probability of a fingerprint collision 9.0E-4 (TLC's optimistic estimate), 2.8E-5 (from the actual fingerprints) |
| 2026-11-21 | `d4085bb6dda6`, invariant `5555ca83833d` | Apalache 0.62.4, `run-inductive.ps1 -Split`, maintainer's server (6 checks at a time, 8 GB heap each) | `small_ind`, all states satisfying `IndInv` | all three obligations hold: init in 0.9 min, the 10 step branches in 3.1 to 34.4 min (`ReaderPub` the longest), `IndInv` implies `safety` in 3.1 min; 38 min in total. Safety holds in every reachable state of `small` |
