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

### Why `small` is large enough

The safety proof runs at `small_ind`, the size of `small`. One source and one channel are enough
because the source keeps every number per channel (R-CH-8) and the recipient keeps its generation,
highest number, floor and retained publications per channel (R-CH-9): two channels share no key,
number or window, and a second source is a second channel. Within the channel, every property relates
at most the following roles at the same time, and `small` holds a copy of each:

- three devices: a reader that leaves the readers while it keeps running with what it holds
  (`rotateOnRemove`), a device that starts outside the readers and joins later, and a device without
  the read right (`noReadNoKey`, `grantsToReaders`, probe `grant_no_read`). The first two are two
  readers with the read right, which `grantBeforePublish` needs: granting one reader must not take
  the other off the list of readers still to be granted. No property relates more than two readers:
  each one is about what a single device holds or was granted, against the source's state;
- three key generations: a key, its rotation after a removal, and a second rotation after a reboot
  that lost the key, so that a grant of a lower generation can arrive after a higher one
  (`uniqueKeys`, probes `accept_old_grant`, `gen_not_persisted`, `mark_not_persisted`);
- five publication numbers with blocks of 2, so that a reboot inside the first block skips to the
  second and the source still has numbers after it (`uniqueNumbers`, probe `no_block_skip`), and the
  sequence 1, 3, 2 at depth 2 followed by a reboot fits with room for a later publication
  (`windowFloor`);
- depths 0 to 2: three publications at depth 2 make trim evict one, a newer publication of depth 1
  shrinks the retained ones, and depth 0 is never retained (`retention`, probes `no_trim`,
  `late_clear_kept`).

Further devices repeat one of these roles, further generations repeat a rotation, and further numbers
repeat a block or a trim. The proof covers these from every state of `IndInv`, not only from reachable
ones.

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
| `grantBeforePublish` | R-CH-5 | a publication is made only after its key was granted to every reader that was valid when the key was made and still is |
| `retention` | R-CH-10, R-CH-11, R-CH-12 | at most `depth` retained publications, all in the window, distinct numbers, none of them a clearing publication or one of depth 0 |
| `noReadNoKey` | R-CH-13 | a device without the read right never holds a key |
| `windowFloor` | R-CH-9, R-CH-10, R-CH-11 | S12: the floor of the window never falls, rises above every publication that trim evicts or a clear removes, and moves only then |

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
| `floor_stays` | The floor stays where it is when trim evicts publications |
| `publish_before_grant` | The source publishes under a new key before granting it to the readers |
| `grant_list_not_persisted` | A reboot loses the readers still to be granted the new key |

`empty_no_clear`, `refill_moves_high`, `no_trim`, `late_clear_kept`, and `floor_stays` need a long
specific sequence and are checked by fixed scenarios in [`scenarios.qnt`](scenarios.qnt), which also
show that refill after a reboot, shrinking the depth, clearing, a late clearing publication, eviction
by trim followed by a reboot, and rotation after a removal are reachable with `safety` intact.

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
publication of depth 0 is accepted only as a new one (R-CH-9, R-CH-10). A later review found a third:
the floor did not rise when trim evicted a publication, so after publications 1, 3 and 2 at depth 2
and a reboot, publication 1 was accepted again. The floor now moves to the lowest retained number when
trim evicts, and stays put when a reboot loses the retained publications (R-CH-9); the scenario
`floorAfterEvictionTest` replays that sequence. The same review found that nothing made the source
grant a new key before publishing under it; with that rule added, the model showed that a source
rebooting between the new key and its grants skipped them, so the source persists the readers still
to be granted the key (R-CH-5, R-CORE-5).

## Requirement coverage

Every normative sentence of the requirements in scope, and what in the model checks it: an invariant
(with the probe that breaks it), a guard, or a stated abstraction.

| Requirement | Sentence | Checked by |
| --- | --- | --- |
| R-CH-5 | a new key before the next publication when a reader is no longer valid or was removed | `rotateOnRemove`; probe `no_rotate_on_remove` |
| R-CH-5 | when the host signals "rotate key epoch" | guard: `sourceEpoch` sets the mark, and `sourcePublishWith` requires it cleared |
| R-CH-5 | when the key did not survive a reboot | guard: `sourcePublishWith` requires a held key |
| R-CH-5 | and grant it before the next publication | `grantBeforePublish`; probe `publish_before_grant`, scenario `grantBeforePublishTest` |
| R-CH-5 | a removed reader does not receive the new key | `grantsToReaders`; probe `grant_removed` |
| R-CH-5 | the mark is set in the same event as the leave and persisted | `rotateOnRemove`; probes `no_rotate_on_remove`, `mark_not_persisted` |
| R-CH-5 | while the mark is set, the marked key is granted to no one | `noMarkedGrant`; probe `grant_marked` |
| R-CH-5 | the readers still to be granted the new key are persisted | `grantBeforePublish`; probe `grant_list_not_persisted` |
| R-CH-6 | the source grants the current key to a new reader | guard: `sourceGrantTo` admits every valid reader with the read right, a joined one included |
| R-CH-6 | the source may rotate the key first | `sourceRotate` is allowed at any time |
| R-CH-7 | a reader erases the previous key once it accepts the next one | abstraction: processing is instantaneous, the reader holds one key (header) |
| R-CH-7 | a compromised reader discloses only publications under the keys it still holds | abstraction: no compromise in this model; the key a reader holds is `kid` (Tamarin) |
| R-CH-8 | the generation increases with every new key, strictly over the device key's life | `uniqueKeys`; probe `gen_not_persisted` |
| R-CH-8 | the publication number increases strictly and is not reset by a new key | `uniqueNumbers`; probe `no_block_skip` |
| R-CH-8 | the new value is persisted before sending; numbers may be reserved in blocks | guard in `sourcePublishWith` and `sourceReboot`; probe `no_block_skip` |
| R-CH-9 | stores the highest generation, highest number, and window floor | `Reader` fields `hiGen`, `hiNo`, `floor`, kept by `readerReboot`; probe `high_not_persisted` |
| R-CH-9 | a grant only with a generation not less than its own; at equal generation the commitment matches | guard in `readerGrant` (`kid` stands for the commitment); `freshness`; probe `accept_old_grant` |
| R-CH-9 | a publication only under a key it holds | `acceptUnderHeldKey`; probe `accept_without_key` |
| R-CH-9 | only new, or in the window if not held | `freshness`, `retention`; probe `refill_moves_high` |
| R-CH-9 | the floor starts at 1 and only rises, past what trim evicts or a clear removes | `windowFloor`; probe `floor_stays`, scenario `floorAfterEvictionTest` |
| R-CH-9 | a reboot does not move the floor | `windowFloor`; scenario `floorAfterEvictionTest` |
| R-CH-9 | at depth 0 no window; a publication of depth 0 only as a new one | `retention`; probe `late_clear_kept` |
| R-CH-9 | values change only after full verification and decryption | abstraction: signatures and the key commitment are perfect (header) |
| R-CH-9 | a publication under a key not held is dropped and changes no state | guard in `readerPub`; `acceptUnderHeldKey` |
| R-CH-9 | it triggers a key request; grants are followed by the retained publications | abstraction: every grant and publication is always in the pool (header) |
| R-CH-9 | a channel record is not evicted while the key is held | abstraction: one channel, never evicted |
| R-CH-10 | a clearing publication clears the channel | `retention`; probe `empty_no_clear`, scenario `clearTest` |
| R-CH-10 | a late clearing publication clears up to its number and moves the floor above it | `retention`, `windowFloor`; probe `late_clear_kept`, scenario `lateClearTest` |
| R-CH-10 | a clearing publication and one of depth 0 are never retained | `retention`; probe `late_clear_kept` |
| R-CH-10 | the latest depth governs; a lower depth deletes the excess at once | `retention`; probe `no_trim`, scenario `shrinkTest` |
| R-CH-11 | the recipient retains the N latest publications in number order | `retention`; probe `no_trim` |
| R-CH-11 | a holder sends the latest grant and the retained publications after hello | abstraction: the pool (header); the relay's side is the relay model's |
| R-CH-11 | the source starts with an empty window after its reboot | abstraction: the source's own retained publications are not modelled (header) |
| R-CH-12 | depth 0: delivered and not retained | `retention` |
| R-CH-13 | accept only from a valid member with the publish right | abstraction: one source, which is valid; nobody can forge (header) |
| R-CH-13 | grant only to a valid member with the read right | `grantsToReaders`; probes `grant_removed`, `grant_no_read` |
| R-CH-13 | a recipient without the read right rejects the grant | `noReadNoKey`; probe `grant_no_read` |
| R-CH-18 | the source answers a key request with a grant of the current key, if the requester is still a reader | the answer is the grant action `sourceGrantTo`, which carries only the current key and has the guards of every grant: `grantsToReaders`, `noMarkedGrant`; probes `grant_removed`, `grant_marked`; scenario `keyRequestTest`. The request itself and its 16 bytes are abstracted: in the pool every grant is always available (header) |
| R-CORE-5 | the key generation, publication number, rotation mark, and readers still to be granted survive a reboot | probes `gen_not_persisted`, `no_block_skip`, `mark_not_persisted`, `grant_list_not_persisted` |
| R-CORE-5 | the held key, highest generation and number, floor, and depth survive a reboot | probe `high_not_persisted`; `readerReboot`; scenario `refillAfterRebootTest` |
| R-REL-11 | every property holds when the relay behaves arbitrarily | abstraction: the pool delivers any grant or publication to anyone, any number of times, in any order (header) |

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
| 2026-11-27 | `740f470f28cf` (commit 19d8294) | TLC 1.7.4, `run-tlc.ps1 -Probes`, maintainer's server (16 workers, 19 GB heap) | 17 probes against `safety` at the size of `small`, 7 witnesses on `tiny`, breadth-first until the first violation | 24 of 24 violated as expected, depth 7 to 12, 0.7 to 1.9 min each (compilation included), 23 min in total |
| 2026-11-27 | `740f470f28cf`, view `a3807e504769` (commit 19d8294) | Apalache 0.62.4, `run-inductive.ps1 -Section bisim`, maintainer's server (3 GB heap, 4 checks at a time; `ReaderPub` alone with 15 GB) | `tiny_bisim`, all pairs of states satisfying `Struct` | all 24 checks pass: init and the 9 enabled step branches preserve `Struct` (1.0 to 5.2 min), `EnvJoin` has no transition from a state satisfying `Struct` and `safety` (1.7 min) nor from a pair with equal views (6.0 min), equal views agree on `safety` (2.1 min), each of the 9 enabled branches is answered with an equal view (9.2 to 186.9 min, `ReaderPub` the longest), both witnesses violated as expected. TLC with the view is exact for `safety` |
| 2026-11-27 | `740f470f28cf`, view `a3807e504769` (commit 19d8294) | TLC 1.7.4, `run-tlc.ps1 -View`, maintainer's server (16 workers, 19 GB heap) | `tiny`, exhaustive, `VIEW safetyView` | no error: 34,828,890 distinct states (699,615,605 generated), depth 28, 14.5 min; probability of a fingerprint collision 1.3E-3 (TLC's optimistic estimate), 1.1E-3 (from the actual fingerprints) |
| 2026-11-27 | `740f470f28cf`, invariant `5f2e60a36244` (commit 19d8294) | Apalache 0.62.4, `run-inductive.ps1 -Split -Parallel 1`, maintainer's server (15 GB heap) | `small_ind`, all states satisfying `IndInv` | all three obligations hold: init in 1.2 min, the 10 step branches in 3.6 to 42.2 min (`ReaderPub` the longest), `IndInv` implies `safety` in 4.8 min; 1 h 30 min in total. Safety holds in every reachable state of `small` |
