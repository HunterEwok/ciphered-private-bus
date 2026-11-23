<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Relay model

A Quint [model](relay.qnt) of a relay (verification level V2 of the
[specification](../../docs/spec/requirements.md), Section 11 and Appendix B, Section B.10; R-REL-2..8,
R-JOIN-8, R-CH-12): one relay serving one bus, and what it accepts, stores, evicts, serves and
forgets. Publications with their retention depth, key grants, key requests, and calls arrive from a
network that also delivers forged objects; the relay keeps quotas per source and per bus with the
eviction rules of Section B.10, learns checkpoints that revoke a device or remove the relay itself,
holds tickets across a root change, and buffers join requests. The header of `relay.qnt` lists every
abstraction.

This model checks the honest relay. That a relay behaving arbitrarily cannot break S1..S14
(R-REL-11) is checked in the other models: their network is a pool that delivers any object any
number of times, in any order, or never, which is what a hostile relay can do.

## Instances

[`instances.qnt`](instances.qnt) fixes the sizes.

| Instance | Devices | Channels each | Numbers | Depth | Sizes | Source limit | Bus limit | Join buffer | Purpose |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `small` | 3 | 2 | 3 | 0..2 | 1, 2 | 3 | 5 | 2 | Simulator runs in CI |
| `tiny` | 2 | 1 | 2 | 0..1 | 1, 2 | 2 | 3 | 1 | Simulator in CI; TLC |
| `probe_*` | 2 | 1 | 2 | 0..1 | 1, 2 | 2 | 3 | 1 | One deliberate defect each; `safety` must fail (R-VER-2). `evict_other` and `unfair` have depth 2 and a source limit of 3, which their defects need |

A grant and a key request take one unit.

## Properties

`safety` is the conjunction of the invariants below. Properties of a single step, such as what a
send or an eviction may do, are checked by a monitor when the step is taken, as in the other models.

| Invariant | Requirement | Property |
| --- | --- | --- |
| `onlyVerified` | R-REL-2 | nothing without a valid signature is stored or forwarded |
| `nothingTransient` | R-REL-8, R-CH-12 | calls, replies, chunks and publications of depth 0 are never stored |
| `servedOnlyGranted` | R-REL-5, L5 | a publication goes only to a reader that holds a grant of its channel |
| `revokedPurged` | R-REL-6, S5 | nothing is stored from or for a revoked device, and nothing is sent to it |
| `quotasHold` | R-REL-4 | no source exceeds its limit and the bus does not exceed its own |
| `fairShare` | S14, B.10 | a source within its fair share never loses data because of another source |
| `evictsOnlyOwn` | R-REL-4, B.10 rule 1 | a source over its own limit evicts only its own publications |
| `grantsKept` | B.10 rule 2 | a grant is never evicted to make room |
| `latestGrant` | R-REL-3 | a grant replaces the held one only with a higher generation |
| `oneGrantOneRequest` | R-REL-3 | one grant per (source, channel, reader) and one key request per (reader, channel) |
| `retentionHolds` | R-REL-3, R-CH-10, R-CH-11 | a channel keeps at most as many publications as the depth of its newest |
| `joinsBounded` | R-JOIN-8 | the join buffer is bounded and keeps the newest request |
| `ticketOfCurrentRoot` | B.10 rules 2, 3 | a ticket is accepted only with a greater pair and of the latest root generation |
| `unlistedEmpty` | B.10 rule 4 | a relay no longer in the checkpoint stores nothing and buffers no join requests |
| `checkpointForward` | R-REL-7 | the relay's checkpoint never moves back |

Probes, each expected to violate `safety`:

| Probe | Defect |
| --- | --- |
| `no_verify` | Forged objects are accepted |
| `store_call` | A call is stored |
| `store_depth0` | A publication of depth 0 is stored |
| `serve_ungranted` | Publications go to every connected device |
| `keep_revoked` | What is stored for a revoked device stays |
| `accept_revoked` | Objects from and for a revoked device are accepted, and it is connected |
| `over_quota` | The per-source limit is not enforced |
| `evict_other` | A source over its limit evicts the oldest publication of any source |
| `evict_grant` | Grants are evicted like publications |
| `unfair` | On a full bus the victim is the source of the oldest publication, not the largest |
| `grant_downgrade` | A grant of a lower generation replaces the held one |
| `two_requests` | A new key request is kept beside the old one |
| `retain_all` | Retention depth is ignored |
| `join_unbounded` | The join buffer has no bound |
| `join_drop_new` | On overflow the new join request is dropped instead of the oldest |
| `old_ticket` | A ticket of the old root generation is accepted after a root change |
| `keep_unserved` | A relay removed from the checkpoint keeps its data |
| `cp_rollback` | An older checkpoint replaces a newer one |

Fixed scenarios in [`scenarios.qnt`](scenarios.qnt) (`quint test`): a source within its fair share keeps
its publication when another source fills the bus (and `unfair` evicts it); the join buffer evicts the
oldest request; and after the checkpoint that revokes a device nothing from or for it is stored and it
gets no hello.

Witnesses (`witness*`) state that a behaviour never happens and are expected to be violated: a
source evicts its own publication, a full bus evicts another source's publication, a full bus refuses
an object for lack of a victim, a grant is replaced, a publication is served, a publication of depth 0
is forwarded, a key request is answered, a revocation purges data, the relay is removed from the
checkpoint, the join buffer overflows, and a ticket of a new root generation is accepted.

## Inductive invariant

[`inductive.qnt`](inductive.qnt) holds an inductive invariant `IndInv`; Apalache proves the same three
obligations as for the other models: the initial state satisfies `IndInv`, every step keeps it, and
`IndInv` implies `safety`. Besides the bounds of every variable, the state parts of `safety` and
`broken` staying empty, `IndInv` states these lemmas:

- the Root's checkpoints only add revoked devices, and the relay's checkpoint is one of them, the
  latest it accepted, with its revoked set;
- a relay no longer listed holds the Root's last checkpoint, which unlisted it, and has no connected
  device and no join requests; no revoked device is connected;
- every stored object is signed, of a kind the relay stores, with its arrival number at most the
  relay's counter; publications are unique by source, channel and number, and none has a number
  above the highest seen for its channel.

Because of that uniqueness, `indInit` draws the store from one slot per key (publications by source,
channel and number; grants and key requests by source, channel and reader), and records are checked
field by field. The instances are `tiny_ind` (the size of `tiny`, checked in CI) and `small_ind` (the
size of `small`) for a long run. The step monitors (fair share, rule 1, grants kept, latest grant,
ticket, sends) are covered too: `IndInv` requires `broken` to be empty, so every step from any state
of `IndInv` must leave it empty.

Rules 1 and 4 evict in rounds, each removing the oldest candidates. The store is within both limits
before a new object arrives, every publication has a size of at least 1, and an object larger than
the per-source limit is refused, so `SOURCE_BYTES` rounds always suffice; a store still over a limit
after them has the object refused. Each round computes the usage of every source once. This keeps
the steps that store objects small enough for Apalache at the size of `small`.

The relay accounts by key slot: `bytes` holds, for each publication slot (source, channel, number)
and each grant and key request slot (source, channel, reader, never the source itself), the bytes
of the object in it, 0 for an empty slot. Storing an object writes its slot, deleting one clears it,
and every update is written slot by slot. The usage of a source is the plain sum of its slots, and
`quotasHold` states that the slots hold exactly the stored objects, the per-source limit, and the
bus limit on the sum of the usages (every object has exactly one payer, a device). A sum whose terms
depend on whether an object is present makes the solver enumerate the possible sets of objects:
over the 54 objects the store may hold at the size of `small` it does not finish, while the same
bound over slot bytes held in the state takes seconds. The quota rules compare usages without
multiplying two variables (a source above the average is a positive sum of differences), which
keeps the arithmetic linear. Mutant `evict_other` gets `MAX_ARR` rounds of rule 1, since removing
publications of other sources does not lower the usage of the payer.

## State view for TLC

Exhaustive TLC of `tiny` does not finish on its own: the relay records up to
fourteen witness tags in any combination, and the numbers of buffered join
requests multiply the states further. `view.qnt` defines a TLC `VIEW` that
drops the witness tags and keeps only the length of the join buffer (`safety`
reads only the length, and a new request is always the newest), and module
`bisim` proves with Apalache that states with equal views are
interchangeable for `safety`, so TLC with the view finds a violation exactly
when TLC without it would. Run with `run-tlc.ps1 -Model relay -View` and
`run-inductive.ps1 -Model relay -Section bisim`.

## Running

Requirements as for the other models: Quint 0.33.1 from [`models/package-lock.json`](../package-lock.json)
and Java 17 or later for TLC.

```sh
python3 models/relay/check.py                        # CI run: safety, probes, witnesses, scenarios
python3 models/relay/check.py --inductive tiny_ind   # IndInv in CI
```

On a shared machine, [`run-tlc.ps1`](../run-tlc.ps1) checks the TLA+ translation with `-Probes` (every
probe against `safety`, every witness on `tiny`; both lists are in [`checks.json`](checks.json)) and
runs the exhaustive check of `tiny`; [`run-inductive.ps1`](../run-inductive.ps1) proves `IndInv` on
`small_ind`:

```powershell
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model relay -WorkDir <folder> -Java <path to java> -Probes
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model relay -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model relay -Split -Parallel 1 -WorkDir <folder> -Java <path to java>
```

Every run prints the model hash: the first 12 hex digits of the SHA-256 of `relay.qnt` and
`instances.qnt`. The results table records this hash rather than a commit.

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |
| 2026-11-23 | `f8f283d5cf95` (commit de117de) | TLC 1.7.4, `run-tlc.ps1 -Probes`, maintainer's server (25 workers) | 18 probes against `safety`, 11 witnesses on `tiny`, breadth-first until the first violation | 29 of 29 violated as expected, depth 2 to 10, 1.2 to 1.6 min each (compilation included), 39 min in total |
| 2026-11-23 | `f8f283d5cf95`, inductive invariant `1e5cef2ee517` (commit de117de) | Apalache 0.62.4, `run-inductive.ps1 -Split`, maintainer's server, two runs combined (`-Only` for the second) | `small_ind`: init implies `IndInv`, `IndInv` and each of the 14 branches of the step imply `IndInv`, `IndInv` implies `safety` | 16 of 16 hold: `safety` holds in every reachable state of `small`; RecvGrant 198 min, RecvPub 176 min, RecvReq 60 min, LearnCp 10 min, every other check 2 to 4 min |
| 2026-11-23 | `f8f283d5cf95`, view `f9fe1c1f5c12` (commit 279b046) | Apalache 0.62.4, `run-inductive.ps1 -Section bisim -Parallel 8`, maintainer's server (6 GB heap) | `tiny_bisim`, all pairs of states satisfying `Struct` | all 32 checks pass: init and the 14 step branches preserve `Struct` (1.0 to 1.5 min), equal views agree on `safety` (1.3 min), each of the 14 branches is answered with an equal view (1.8 to 2.5 min), both witnesses violated as expected; 7.0 min in total. TLC with the view is exact for `safety` |
| 2026-11-24 | `f8f283d5cf95`, view `f9fe1c1f5c12` (commit 279b046) | TLC 1.7.4, `run-tlc.ps1 -View`, maintainer's server (54 workers) | `tiny`, exhaustive, `VIEW safetyView` | no error: 24,097,506 distinct states (263,984,749 generated), depth 17, 1 h 01 min |
