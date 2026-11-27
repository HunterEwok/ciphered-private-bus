<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Membership model

A Quint [model](membership.qnt) of the membership state machine (verification level V2 of
the [specification](../../docs/spec/requirements.md), Section 14): passports, checkpoints and
their window, revocation, change of rights, root change, halt and halt proofs, reboot, and the
acceptance of data and key grants against the read and publish rights. The header of
`membership.qnt` lists every abstraction.

## Instances

[`instances.qnt`](instances.qnt) fixes the sizes.

| Instance | Devices | Generations | Numbers per generation | Window | Purpose |
| --- | --- | --- | --- | --- | --- |
| `small` | 3 | 2 | 3 | 2 | Simulator runs in CI |
| `tiny` | 2 | 2 | 2 | 2 | Simulator in CI |
| `tiny_tlc` | 2 | 2 | 2 | 2 | TLC and Apalache: `tiny` without the processed-record sets, which only `convergence` reads |
| `conv_tlc` | 2 | 2 | 1 | 1 | TLC of `safety` including `convergence`, with the processed-record sets; two checkpoints out of order need two numbers and are covered by a scenario and the probe `need_next` |
| `live_tlc` | 2 | 2 | 1 | 1 | TLC of the liveness property `haltPropagates`; too large to finish, so liveness is proved from `IndInv` instead |
| `probe_*` | 3 | 2 | 3 | 2 | One deliberate defect each; `safety` must fail (R-VER-2). `rc_no_forever`, `accept_old_data_gen`, `halted_silent` and `need_next` have the size of `tiny_tlc`, so that breadth-first TLC reaches their deep traces before its queue spills to disk; `halted_silent_live` has the size of `live_tlc` |

With three numbers per generation a window of two binds: the Root has to reissue a passport
before it can issue a third. With two numbers it never binds, but the window start still moves
past revoked and replaced numbers.

### Why `large_ind` is large enough

The safety proof runs at `large_ind` (three devices, three generations, three numbers per generation,
a window of two), and so does the proof of `convergence` (`conv_large_ind`, `conv_large_pair`). Every
property relates at most the following roles at the same time, and `large_ind` holds a copy of each:

- three devices: a receiver and a sender, which every acceptance property relates
  (`revokedIsRejected`, `grantsNeedRead`, `dataNeedsPublish`), or two nodes, which `convergence` and
  the halt rules relate (a halted peer and a node that hears its proof); and a third device whose
  passport is revoked or reissued, so that the window start moves past its number while the other two
  keep valid passports (`windowKeepsValid`, `cacheConsistent`, probe `below_window_valid`). No
  property relates more than two devices besides the Root: each is about one node's state, or one
  node and one sender, or two nodes that processed the same records;
- three generations: generation 1 has no root change record, so a root change record of generation 2
  followed by one of generation 3, and a node that skips from generation 1 to 3, need three
  (`currentGeneration`, `installedKeyOnly`, `convergence`). Two root change records of one
  generation with different keys (L6) take the two keys of that generation (`haltIsSticky`, probe
  `rc_no_forever`);
- three numbers per generation with a window of two: the window binds, so the Root has to reissue a
  passport before it issues a third (`windowBounded`, probe `unbounded_window`); two checkpoints of
  one generation can arrive out of order (`convergence`, probe `need_next`); and the Root can
  equivocate at one number while a later number exists (`noRollback`, `proofIsObeyed`, probe
  `no_halt`). The rules compare numbers by order and equality and the window by the span from its
  start, so further numbers repeat these cases at a higher start;
- a window of two, the least that holds a cleared bit next to a set one, so that moving the start
  past leading cleared bits differs from moving it past a set bit (probe `window_past_set_bit`).

A fourth device repeats the third or one of the first two, further generations repeat a root change,
and further numbers repeat a window move. The proof covers these from every state of `IndInv`, not
only from reachable ones.

## Properties

`safety` is the conjunction of the invariants below. Properties of a single step (a node's
transition, an acceptance, a grant) are checked by a monitor when the step is taken: a violated
one adds its name to the variable `broken`, and the invariant states that its name is absent.
This is equivalent to comparing each state with the previous one, but keeps neither a copy of
the previous state nor a log of past acceptances, which would multiply the states TLC explores.

| Invariant | Requirement | Property |
| --- | --- | --- |
| `noRollback` | R-MEM-5 | S6 |
| `currentGeneration` | R-MEM-12 | S9 |
| `installedKeyOnly` | R-MEM-2; Appendix B, Section B.3, rule 1 | a node holds a checkpoint or passports of its generation only if the root key it installed for that generation signed them |
| `haltIsSticky` | R-MEM-9, R-MEM-13 | S8 |
| `haltedIsInert` | R-MEM-9 | S8 |
| `proofIsObeyed` | R-MEM-10 | S8 |
| `rootHonorsRevocation` | R-MEM-4 | S5 |
| `cacheConsistent` | R-MEM-7, R-MEM-8 | S8 |
| `revokedIsRejected` | R-MEM-2, R-MEM-12, R-VER-4 | S4, S5 |
| `grantsNeedRead` | R-CH-13 | S4, S16 |
| `dataNeedsPublish` | R-CH-13 | S4, S16: data off channel 0 is accepted only from a passport with the publish right |
| `windowBounded` | R-MEM-14 | every checkpoint the Root issues spans at most `WINDOW` numbers |
| `windowKeepsValid` | R-MEM-4, R-MEM-14 | the Root's latest checkpoint has the bit of every passport the Root holds valid: moving the window revokes nobody |
| `convergence` | R-ARC-6 | S7 |

The recovery key may sign two root change records of one generation (a stolen recovery key,
L6). The model's Root signs the records of a generation with the key of the first one (key 0);
the holder of the second key issues no passport or checkpoint, since a Root that the honest
history does not follow has no revocations for `revokedIsRejected` to check. A node that
installed the second key therefore verifies none of its generation's records, nor a proof built
from them, and stays at the genesis checkpoint until the other root change record or a root
change proof halts it for good. The scenario `otherKeyRecordsAreDroppedTest` drives a node
there, and the probe `ignore_signer` drops the key check.

`convergence` compares two nodes that processed the same records. A record of another
generation, or one that fails the key check, is dropped unprocessed: the core has no wait buffer
(R-MEM-6). That such a record comes back is part of the liveness property `haltPropagates` for
halt proofs.

Probes, each expected to violate `safety`:

| Probe | Defect |
| --- | --- |
| `ignore_bitmap` | A passport is accepted without checking its checkpoint bit |
| `keep_bit` | The Root issues a revoking checkpoint with the bit still set |
| `accept_old_gen` | A checkpoint of an older generation is accepted |
| `accept_lower` | A checkpoint with a lower number is accepted |
| `no_halt` | Conflicting records do not halt the node |
| `halted_accepts` | A halted node accepts checkpoints, data, and grants |
| `rc_no_forever` | Two root change records of one generation do not halt permanently |
| `proof_needs_cp` | A halt proof is ignored by a node that moved past its number |
| `reboot_rollback` | A reboot loses the persisted checkpoint |
| `grant_no_right` | A key is granted to a passport without the read right |
| `accept_old_data_gen` | Data of an older generation is accepted |
| `no_prune` | A new checkpoint does not remove revoked passports from the cache |
| `accept_no_publish` | Data off channel 0 is accepted from a passport without the publish right; violates `dataNeedsPublish` |
| `below_window_valid` | A passport number below the window start, which has no bit, is taken as valid, so a revoked passport comes back when the window moves past it; violates `revokedIsRejected` and `cacheConsistent` |
| `window_past_set_bit` | The Root moves the window start past a set bit; violates `windowKeepsValid` |
| `unbounded_window` | The Root issues a checkpoint whose window exceeds `WINDOW`; violates `windowBounded` |
| `ignore_signer` | A node that installed the second root key of its generation takes records signed with the first; violates `installedKeyOnly` |
| `need_next` | A node takes only the checkpoint right after its own, so its state depends on the order of arrival; violates `convergence` (S7) |
| `halted_silent` | A halted node does not answer a sender of its generation with the proof; violates `haltPropagates`, not `safety` |

Some defects need a long, specific sequence that random simulation rarely produces. Such a
probe also has a fixed scenario in [`scenarios.qnt`](scenarios.qnt) (`quint test`): the
correct model must refuse the step, and the broken one must violate `safety` after it.
`accept_old_data_gen` is checked this way, and so is the case that led to the halt rule of
R-MEM-6: a proof dropped as belonging to a future generation comes back from a halted peer once
the node has moved to that generation (`halted_silent` removes that answer). Further scenarios
show two nodes that receive two checkpoints in opposite orders ending at the same one (and
`need_next` leaving them apart), and a replaced passport leaving the cache when the window
start moves past it (and `below_window_valid` keeping it).

Liveness: `haltPropagates` states that while a halted peer of its generation exists, a node on
the key that signs its generation's records eventually halts too or leaves that generation, and
that once a peer is permanently halted, every node eventually is (S8, R-MEM-6, R-MEM-10,
R-MEM-13). It assumes weak fairness
of `nodeHearsHalted` only: a node that keeps talking to a halted peer is eventually answered with
the proof. It is proved from the inductive invariant, for every reachable state of `large_ind`
(see below): `IndInv` implies `HearingEnabled`, which says that while a node on that key has a
halted peer of its generation and is not halted, or a permanently halted peer and is not permanently halted,
`nodeHearsHalted` is enabled for it. Weak fairness needs more than a true guard: it needs a step
of the action that changes the state. While a node has a halted peer of its generation and is not
halted, every proof the action can choose halts it (a proof of its generation halts it, a root
change proof halts it permanently), so every step changes the state and reaches the goal. While a
node has a permanently halted peer and is not permanently halted, `IndInv` puts a root change proof
in the pool (a permanent halt has one behind it), the action can choose it, and it makes the halt
permanent. The other choices offer an already halted node another proof of its generation: a
stutter when the proof is known, a new element of its finite set of received proofs otherwise, so
they change the state only finitely often. A permanent halt is never undone, so this condition
holds until the goal is reached; the first one holds until the goal is reached or it ends (the
node leaves the generation or the peer is no longer halted there), which the property also
accepts. Either way the property holds. A node that installed the second root key of its
generation cannot verify a proof built from records signed with the first; the second part covers
it once a peer halts for good. The probe
`halted_silent` removes the answer: `safety` still holds, and `HearingEnabled` fails on
`probe_halted_silent_ind`. A direct TLC check of the temporal formula is out of reach: even
`live_tlc`, one number per generation and two devices, has more than 20 million states.

Witnesses (`witness*`) state that a behaviour never happens and are expected to be violated:
the violation shows that halts, permanent halts, accepted data, key grants, root changes, sends
under revoked passports, and a moving window are all reachable, so `safety` does not hold
vacuously.

## Requirement coverage

Every normative sentence of the requirements in scope, and what in the model checks it: an invariant
(with the probe that breaks it), a guard, or a stated abstraction. "Header" points to the abstractions
listed at the top of [`membership.qnt`](membership.qnt).

| Requirement | Sentence | Checked by |
| --- | --- | --- |
| R-MEM-1 | passports and checkpoints have separate number sequences, each strictly increasing within a generation | guards: `rootIssue` and `rootRevoke` raise `nextNo` and `cpNo`; a Root that breaks this is modelled by `rootEquivocateCp` and `rootEquivocatePp` (header) |
| R-MEM-2 | a passport is valid if signed by the Root of the current generation | `installedKeyOnly`, `currentGeneration`; probes `ignore_signer`, `accept_old_gen`; scenario `otherKeyRecordsAreDroppedTest` |
| R-MEM-2 | its number is below the next free number and its bit is 1 | `validIn`; `cacheConsistent`, `revokedIsRejected`; probes `ignore_bitmap`, `below_window_valid` |
| R-MEM-3 | a passport at or above the next free number is not accepted until a newer checkpoint | `validIn` (the bitmap covers only numbers below the next one); `cacheConsistent` |
| R-MEM-3 | when admitting a device the Root issues the passport and the checkpoint together | guard: `rootIssue` |
| R-MEM-4 | revocation is a new checkpoint with the bit cleared | `rootHonorsRevocation`; probe `keep_bit` |
| R-MEM-4 | a change of rights is a new passport with a new number, the old bit cleared | `rootChangeRights`; `rootHonorsRevocation`, `windowKeepsValid` |
| R-MEM-5 | a checkpoint is accepted only with a number greater than the node's own | `noRollback`; probe `accept_lower` |
| R-MEM-5 | its number and body are persisted before the node acts on it | `noRollback` across `nodeReboot`; probe `reboot_rollback` |
| R-MEM-6 | the hello, publications, grants and calls carry the sender's pair (generation, checkpoint number) | the fields `gen` and `cpNo` of `Data` |
| R-MEM-6 | a recipient with a smaller pair requests the checkpoint and drops the message | guard in `nodeAcceptData`; the request is the pool (header) |
| R-MEM-6 | a recipient with a larger pair sends its checkpoint; a new checkpoint is sent on all links | abstraction: the pool delivers every record to anyone (header) |
| R-MEM-6 | a halted node answers a sender of its generation with its halt proof, every time | `nodeHearsHalted`; `haltPropagates` (proved through `HearingEnabled`); probe `halted_silent`; scenario `droppedProofComesBackTest` |
| R-MEM-6 | a permanently halted node answers every sender, of any generation | `nodeHearsHalted` (`foreverPeer`); `haltPropagates` |
| R-MEM-7 | a node returns its own passport and checkpoint on request | abstraction: the pool (header) |
| R-MEM-7 | other passports are kept in a bounded cache | `pps`, at most one passport per number (`IndInv`) |
| R-MEM-7 | a new checkpoint removes passports whose bit is cleared | `cacheConsistent`; probe `no_prune`; scenario `windowMovesPastReplacedTest` |
| R-MEM-8 | two checkpoints or two passports with one number and different bodies halt the node | `cacheConsistent`, `convergence`; probe `no_halt`; witness `witnessHalt` |
| R-MEM-8 | records with the same body and different signatures are one record | abstraction: signatures are perfect and a record is its body (header) |
| R-MEM-9 | a halted node accepts no passport or checkpoint, no publication or grant, and grants no key | `haltedIsInert`; probe `halted_accepts` |
| R-MEM-9 | it does not publish | guard: `nodeSend` |
| R-MEM-9 | it executes no call and closes its streams | the calls and streams models (`haltClosesStreams`) |
| R-MEM-9 | values accepted before the halt stay readable | the channels model; nothing here removes them |
| R-MEM-9 | only a root change record leaves the halted state | `haltIsSticky`; probe `rc_no_forever` |
| R-MEM-10 | a node keeps the halt proof and sends it when it halts and to every sender behind it | the proof goes to the pool; `nodeHearsHalted`; `haltPropagates` |
| R-MEM-10 | on a valid proof a node halts whatever checkpoint it is at | `proofIsObeyed`; probe `proof_needs_cp` |
| R-MEM-10 | the proof does not depend on delivery order | `convergence`; probe `need_next` |
| R-MEM-11 | a root change record of a greater generation is accepted and the node moves to it directly | guard: `nodeRecvRc`; `currentGeneration`; witness `witnessRootChange` |
| R-MEM-11 | every participant stores the latest accepted record and returns it on request | the field `rc`; the pool (header) |
| R-MEM-12 | after a root change only records of the new Root are valid | `currentGeneration`, `installedKeyOnly`, `revokedIsRejected`; probes `accept_old_gen`, `accept_old_data_gen`, `ignore_signer`; scenario `oldGenerationDataIsDroppedTest` |
| R-MEM-12 | counters start over, and the new Root reissues passports | `recoveryChange` starts the Root over; `rootAdmit` reissues |
| R-MEM-13 | two root change records of one generation are a permanent halt | `haltIsSticky`; probe `rc_no_forever`; witness `witnessForever` |
| R-MEM-13 | their proof is accepted at any generation and reaches every node | `nodeRecvHp`; `haltPropagates` (`foreverReachesPeers`) |
| R-MEM-14 | the bitmap is no longer than the profile limit | `windowBounded`; probe `unbounded_window` |
| R-MEM-14 | the window start moves only past numbers below which all bits are cleared | `windowKeepsValid`; probes `window_past_set_bit`, `below_window_valid`; witness `witnessWindowMoves` |
| R-MEM-14 | the Root reissues the oldest valid passports to move the window | `rootChangeRights` with the same rights; scenario `windowMovesPastReplacedTest` |
| R-MEM-15 | the Root's counters are never below what it can receive, persisted before signing | abstraction: a Root that breaks this equivocates, which the model allows (header) |
| R-MEM-16 | a revoked device may still consider itself a member | `nodeSend` sends under any passport the device was issued; witness `witnessRevokedSends`; scenario `revokedSendNeedsLaterSendTest` |
| R-VER-4 | a revoked device that does not know it receives no new keys | `revokedIsRejected` on every grant; probe `keep_bit` |
| R-VER-4 | its publications are not accepted by a node that has seen the new checkpoint | `revokedIsRejected` on every acceptance; probes `ignore_bitmap`, `below_window_valid` |
| R-CH-13 | publications and grants only from a valid member with the publish right; not needed on channel 0 | `dataNeedsPublish`; probe `accept_no_publish` |
| R-CH-13 | the recipient computes the label of channel 0 itself | abstraction: channel 0 is the flag `ch0` |
| R-CH-13 | the source grants a key only to a valid member with the read right | `grantsNeedRead`; probe `grant_no_right` |
| R-CH-13 | a recipient without the read right rejects the grant | the channels model (`noReadNoKey`); not modelled here (header) |

## Inductive invariant

[`inductive.qnt`](inductive.qnt) holds an inductive invariant `IndInv` for the model without
the processed-record sets (`TRACK_RECV = false`, as in `tiny_tlc`). Apalache proves three
obligations, which together show that `safety` holds in every reachable state, at any depth:

1. the initial state satisfies `IndInv`;
2. from every state of the bounded types that satisfies `IndInv`, reachable or not, one step
   leads to a state that satisfies `IndInv`;
3. every state that satisfies `IndInv` satisfies `safety`.

Besides the state parts of `safety` and its monitor (`broken` stays empty), `IndInv` states
the bounds of every variable (every checkpoint keeps its valid numbers inside a window of at
most `WINDOW` numbers) and these lemmas: a permanent halt is a halt; a processed root
change proof made the halt permanent and every other processed proof is of the current or an
older generation; the Root's valid and revoked numbers are below its next number, its rights
map covers exactly those numbers, and its next checkpoint fits the window; the Root's latest
honest checkpoint carries exactly the Root's valid numbers; and the honest checkpoints of one generation never set a bit
again once it was cleared, which makes the honest-history part of `revokedIsRejected` follow
from validity under the receiver's own checkpoint; a node's passport cache holds at most one
passport per number, even after a halt; and the honest history holds at most one checkpoint
per generation and number. For liveness, it also states that behind every halt lies a proof
in the pool: a halt of a generation has a proof of that generation, and a permanent halt a root
change proof. From these a fourth obligation follows: `IndInv` implies `HearingEnabled`.

The cache and history lemmas keep the proof small. The arbitrary state of obligation 2 builds a cache
from one slot per number (3 instead of any subset of 108 passports) and the history from one
slot per generation and number (9 instead of any subset of 102 checkpoints), and membership in
the bounded types is checked field by field rather than by comparison with every element of
the type. The plain encoding of a step branch of `large_ind` does not fit in a 53 GB heap.

The instances are `tiny_ind` (the size of `tiny_tlc`, checked in CI), `small_ind` (three
devices, three numbers per generation), and `large_ind` (three devices, three generations,
three numbers) for a long run. In this proof the model runs without the processed-record sets,
so `convergence` holds trivially; it has a proof of its own.

### Convergence

`convergence` compares two nodes, and a lemma that relates the record sets of different nodes
makes the solver's work quadratic. [`conv_inductive.qnt`](conv_inductive.qnt) runs the model with
the processed-record sets and proves instead that every field `convergence` compares is a
function of the node's own sets (`nodeConv`):

- `gen` is the latest generation among the processed root change records, or 1 if there is
  none (root change records are of generation 2 or later), and `rc` is the key of that record;
- `forever` holds exactly when a root change proof was processed, or two root change records
  of one generation with different keys;
- unless halted, `cp` is the processed checkpoint of the current generation with the highest
  number, the only one with that number, or genesis if there is none;
- the sets never hold a checkpoint or proof of a later generation than the node's: records of
  another generation are dropped unprocessed.

The fourth fact covers the one exception in `convergence`: a node that processed a proof of its
own generation is halted (`proofIsObeyed`). Four obligations:

1. the initial state satisfies `IndInv` (`nodeConv` included);
2. every step from any state that satisfies `IndInv` leads to one that does;
3. every state that satisfies `IndInv` satisfies `safety` without `convergence`;
4. two nodes that satisfy the per-node part of `IndInv` and have the same processed records
   satisfy `convergence`. The two nodes are built from one drawing of the sets, so the check
   compares no sets.

Obligations 1 to 3 run on one device. `IndInv` speaks of one node at a time, a node's actions
read only that node and the pool, and the other actions change no node (`nodeHearsHalted` has
the effect of `nodeRecvHp` with a proof from the pool), so every step of a model with more
devices preserves the invariant of each node exactly when the one-device steps do. With one
device, `nodeAcceptData`, `nodeGrant` and `nodeHearsHalted` are never enabled, which the proof
checks for each of them; the first two change no node. Two devices in one state put the arbitrary state of
obligation 2 beyond the solver's memory even at the smallest size. Obligation 4 runs on two devices.

The instances are `conv_tiny_ind` and `conv_tiny_pair` (two generations, two numbers, checked in
CI) and `conv_large_ind` and `conv_large_pair` (three generations and three numbers, as in
`large_ind`) for a long run. Three generations are needed: generation 1 has no root change
record, so moving from generation 2 to 3, or skipping from 1 to 3, needs three. The probe
`conv_probe_need_next_ind` (a node takes only the checkpoint right after its own) must break
obligation 2. A TLC run of `conv_tlc` is no substitute: it allows one number per generation, so
two checkpoints of one generation never arrive out of order.

## State view for TLC

Exhaustive TLC of `tiny_tlc` does not finish on its own: the pools hold every
record ever issued, in any combination, and the run still grew by seven
million states a minute at depth 12. `view.qnt` defines a TLC `VIEW` that keeps
only what a guard or `safety` can still read: data messages are dropped
(sending and accepting them never change anything else), the history becomes
the two window facts, passports become counts per (generation, number) slot,
halt proofs become the generations that have one, halted nodes and nodes of
settled generations lose their checkpoint and cache, and old generations with
a conflict keep only the bits that can still conflict. Module `bisim` proves
with Apalache that states with equal views are interchangeable for `safety`,
so TLC with the view finds a violation exactly when TLC without it would. Its
structural invariant `Struct` bounds every record and node generation by the
Root's, and for O4 the six steps with several outcomes are split into cases
that together cover the whole step. Run with `run-tlc.ps1 -Model membership
-View` and `run-inductive.ps1 -Model membership -Section bisim`.

## Running

Requirements: Quint 0.33.1, pinned in [`models/package-lock.json`](../package-lock.json)
(`npm ci` in `models/`, then put `models/node_modules/.bin` on the `PATH`), and Java 17 or
later for Apalache and TLC; Quint downloads its evaluator and Apalache on first use.

```sh
python3 models/membership/check.py simulate            # CI run, about 10 minutes
python3 models/membership/check.py apalache --steps 5   # bounded smoke check, instance tiny_tlc
python3 models/membership/check.py tlc --main tiny_tlc  # exhaustive, long run
python3 models/membership/check.py apalache --main probe_no_halt --expect violated
python3 models/membership/check.py apalache --invariant witnessHalt --expect violated
python3 models/membership/check.py tlc --main conv_tlc  # safety with convergence, long run
python3 models/membership/check.py inductive                    # IndInv and HearingEnabled, instance tiny_ind
python3 models/membership/check.py inductive --main small_ind
python3 models/membership/check.py convergence                  # convergence proof, small instances (CI)
```

`--main` and `--invariant` select any instance and invariant, so probes and witnesses can be
checked with Apalache and TLC as well. Every run prints the model hash: the first 12 hex
digits of the SHA-256 of `membership.qnt` and `instances.qnt`. The results table records
this hash rather than a commit, because a squash merge replaces the commit hashes of a pull
request.

On a shared Windows or Linux machine, [`run-tlc.ps1`](../run-tlc.ps1) runs the exhaustive TLC
check end to end with progress output: it compiles the instance, starts TLC at below-normal
priority within 85% of the cores and memory, prints depth, distinct states, the queue and its
trend, and free disk space every minute, stops TLC when free disk space falls below 15%, and
writes `summary.txt` with the model hash and the result. It needs Java 17 or later, Node, and
git, and works in Windows PowerShell 5.1:

```powershell
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model membership -WorkDir <folder> -Java <path to java>
```

With `-Probes` the script checks the translation to TLA+ instead: it runs TLC on every probe
instance against `safety` and on every witness against `tiny_tlc` (both lists are in
[`checks.json`](checks.json)), each within
`-TimeoutMinutes` (30 by default), and writes a table of expected and actual outcomes. Every
row must be violated; a run that reaches its time limit has no verdict and fails. The liveness
probe `halted_silent` is not part of it.

[`run-inductive.ps1`](../run-inductive.ps1) checks the three obligations of the inductive
invariant the same way, without Python, at below-normal priority, with progress output and a
`summary.txt` that records the model hash and the hash of `inductive.qnt`:

```powershell
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model membership -WorkDir <folder> -Java <path to java> -Main large_ind
```

The convergence proof uses the section `convergence` of `checks.json` (file, instances, the
steps enabled with one device, and obligation 4 on `conv_large_pair`):

```powershell
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model membership -Section convergence -WorkDir <folder> -Java <path to java> -Split -Parallel 1
```

`-Only` runs selected checks, for example `-Split -Parallel 1 -Only RootChangeRights` with the
whole heap for one check; checks of the same model and invariant hashes together make one result.

Apalache hands each check to one solver, which runs on one core. With `-Split` the second
obligation is checked branch by branch of the step (`stepRootAdmit` to `stepGrant` in
`inductive.qnt`, which together are exactly `step`, listed in `checks.json`), up to `-Parallel` checks at a time, each with
its own Apalache server.

The simulator runs use a fixed seed, so a run is reproducible. Apalache and TLC runs beyond
the CI sizes are long runs (R-VER-3): their outcome is recorded below with the number of
states and the running time. An interrupted run is not a result (R-VER-5).

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |
| 2026-11-23 | `70c2b729bc7a` (commit 112a58e) | TLC 1.7.4, `run-tlc.ps1 -Probes -Share 0.3`, maintainer's server (19 workers, 22 GB heap) | every probe against `safety` and every witness on `tiny_tlc`, breadth-first until the first violation | 24 of 24 violated as expected (17 probes, 7 witnesses), depth 2 to 10, 26 min in total; the longest is `probe_accept_old_data_gen` (35,879,533 distinct states, depth 10, 4.0 min) |
| 2026-11-22 | `70c2b729bc7a`, invariant `6b74c23aed0f` (commit a1c4658) | Apalache 0.62.4, `run-inductive.ps1 -Split -Parallel 1`, maintainer's server (53 GB heap) | `large_ind`, all states satisfying `IndInv` | all four obligations hold: init in 1.9 min, the 17 step branches in 4.9 to 19.8 min (`HearsHalted` the longest), `IndInv` implies `safety` in 3.8 min and `HearingEnabled` in 4.0 min; 169 min in total. Safety holds in every reachable state of `large_ind`, and `haltPropagates` on every behaviour of it under the fairness it assumes (see the liveness argument above) |
| 2026-11-23 | `70c2b729bc7a`, convergence invariant `db8b9788f5fe` (commit 9d14dcd) | Apalache 0.62.4, `run-inductive.ps1 -Section convergence -Split -Parallel 1`, maintainer's server (53 GB heap) | `conv_large_ind` and `conv_large_pair`: init implies the per-node invariant, it and each of the 14 step branches imply it, it implies `modelSafetyRest`, and a pair of nodes with the same records is converged | 17 of 17 hold: init in 2.0 min, the 14 step branches in 50.5 to 69.0 min (`RecvRc` the longest), safety in 55.9 min, pair implies convergence in 42.7 min; 15.2 h in total. Convergence (S7) holds in every reachable state of `large_ind` |
| 2026-11-24 | `70c2b729bc7a`, view `6941373df49b` (commit c6c47d3) | Apalache 0.62.4, `run-inductive.ps1 -Section bisim -Parallel 6`, maintainer's server (8 GB heap) | `tiny_tlc_bisim`, all pairs of states satisfying `Struct` | all 49 checks pass: init and the 17 step branches preserve `Struct` (1.3 to 3.6 min), equal views agree on `safety` (2.6 min), each of the 28 step cases is answered with an equal view (4.3 to 10.7 min), both witnesses violated as expected; 42.6 min in total. TLC with the view is exact for `safety` |
| 2026-11-24 | `70c2b729bc7a`, view `6941373df49b` (commit c6c47d3) | TLC 1.7.4, `run-tlc.ps1 -View -Share 0.5`, maintainer's server (32 workers) | `tiny_tlc`, exhaustive, `VIEW safetyView` | no error: 1,746,254 distinct states (118,764,134 generated), depth 27, 6 min 40 s; probability of a fingerprint collision 1.1E-5 (TLC's optimistic estimate), 3.5E-7 (from the actual fingerprints) |
