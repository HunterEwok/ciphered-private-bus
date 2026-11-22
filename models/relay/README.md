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
| `unlistedEmpty` | B.10 rule 4 | a relay no longer in the checkpoint stores nothing |
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

## Running

Requirements as for the other models: Quint 0.33.1 from [`models/package-lock.json`](../package-lock.json)
and Java 17 or later for TLC.

```sh
python3 models/relay/check.py        # CI run: safety, probes, witnesses, scenarios
```

On a shared machine, [`run-tlc.ps1`](../run-tlc.ps1) checks the TLA+ translation with `-Probes` (every
probe against `safety`, every witness on `tiny`; both lists are in [`checks.json`](checks.json)) and
runs the exhaustive check of `tiny`:

```powershell
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model relay -WorkDir <folder> -Java <path to java> -Probes
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model relay -WorkDir <folder> -Java <path to java>
```

Every run prints the model hash: the first 12 hex digits of the SHA-256 of `relay.qnt` and
`instances.qnt`. The results table records this hash rather than a commit.

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |
