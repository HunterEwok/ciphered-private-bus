<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Streams model

A Quint [model](streams.qnt) of streams (verification level V2 of the
[specification](../../docs/spec/requirements.md), Section 14; R-STR-3..6, R-CORE-6, R-MEM-9, and the
chunk-number half of R-KEY-9): one commander and one target, a stream opened by the reply to a call in
ordered or lossy mode, chunks in both directions with data, credit and "end", the limit on open
streams, and every event that closes a stream: link down, "reset nonces" after a period without
traffic, halt, revocation of the peer, and reboot. The network delivers any call, reply or chunk ever
sent, any number of times, in any order, or never, but cannot forge a chunk; a peer may be faulty and
send beyond its credit. The keys of a stream are the Tamarin model's ([proofs/calls](../../proofs/calls)):
here each call has its own key, named by the number of the call. The header of `streams.qnt` lists
every abstraction.

## Instances

[`instances.qnt`](instances.qnt) fixes the sizes.

| Instance | Open streams | Calls | Chunks per direction | Credit | Events | Purpose |
| --- | --- | --- | --- | --- | --- | --- |
| `small` | 2 | 3 | 3 | 2 | 3 | Simulator runs in CI |
| `tiny` | 1 | 2 | 2 | 1 | 2 | Simulator in CI; TLC |
| `probe_*` | 2 | 3 | 3 | 2 | 3 | One deliberate defect each; `safety` must fail (R-VER-2) |

Events are link down, "reset nonces", halt, revocation and reboot together. They are bounded so that
streams live long enough for the properties to matter: without a bound, random simulation halts a
node within a few steps.

## Properties

`safety` is the conjunction of the invariants below. Properties of a single step are checked by a
monitor when the step is taken, as in the other models.

| Invariant | Requirement | Property |
| --- | --- | --- |
| `chunkNumbersUnique` | R-KEY-9, R-STR-2 | a chunk number is never used twice under one key and direction, so the AEAD nonce never repeats |
| `orderedInOrder` | R-STR-3 | in ordered mode a chunk is taken only with the number after the last one |
| `lossyIncreasing` | R-STR-3 | in lossy mode a chunk is taken only with a number above the highest taken |
| `chunkBinding` | S11 | a chunk taken belongs to this stream instance and comes from the peer, in the direction the receiver expects |
| `unknownIsDropped` | R-STR-3 | a chunk of a stream the recipient does not have changes nothing and is not answered |
| `senderWithinCredit` | R-STR-4 | an honest sender in ordered mode stays within its credit |
| `creditRespected` | R-STR-4, S14 | a recipient in ordered mode never takes more data than it granted, even from a peer that overruns |
| `creditSound` | R-STR-4 | a sender never counts more credit than its peer gave for this stream: a replayed credit chunk is not counted twice |
| `openKeepsStreams` | R-STR-6 | opening beyond the limit is refused with a result code and closes no stream |
| `streamsBounded` | R-STR-6, S14 | no node has more open streams than the limit |
| `resetOnlyIdle` | R-STR-5 | "reset nonces" closes only streams without traffic since the previous reset |
| `haltClosesStreams` | R-STR-5, R-MEM-9, S8 | a halted node has no open stream |
| `revocationClosesStreams` | R-STR-5, S5 | a node that knows its peer was revoked has no open stream with it |

Probes, each expected to violate `safety`:

| Probe | Defect |
| --- | --- |
| `ordered_gap` | Ordered mode takes any higher number |
| `lossy_old` | Lossy mode takes an equal or lower number |
| `id_only` | The recipient matches a stream by its number alone, so a chunk of an earlier stream with that number is taken after a reboot |
| `no_dir` | The recipient does not check the direction, so its own chunks reflected back are taken |
| `unknown_opens` | A chunk of an unknown stream opens one |
| `reuse_no` | A chunk without data does not consume a number, so the next chunk reuses its nonce |
| `ignore_credit` | The sender sends data without credit |
| `no_credit_check` | The recipient takes data beyond the credit it granted |
| `credit_replay` | A credit chunk is taken whatever its number, so a replay adds credit twice |
| `evict` | At the limit the target closes a stream to open a new one |
| `reset_busy` | "Reset nonces" closes busy streams too |
| `halt_keeps` | A halted node keeps its streams |
| `revoke_keeps` | A node keeps its streams after learning that its peer was revoked |

Fixed scenarios in [`scenarios.qnt`](scenarios.qnt) (`quint test`): after the target reboots and opens
a new stream under the same number, a chunk of the old stream is dropped without any change (and
`id_only` takes it); and "reset nonces" keeps a stream that carried a chunk since the previous reset and
closes it after a quiet period.

Witnesses (`witness*`) state that a behaviour never happens and are expected to be violated: ordered
data taken, credit added, a gap skipped in lossy mode, an opening refused at the limit, a stale chunk
dropped, a stream closed by "reset nonces", by a chunk out of order, and by a chunk beyond the credit.

## Requirement coverage

Every normative sentence of the requirements in scope, and what in the model checks it: an invariant
(with the probe that breaks it), a guard, or a stated abstraction. "Header" points to the abstractions
listed at the top of [`streams.qnt`](streams.qnt).

| Requirement | Sentence | Checked by |
| --- | --- | --- |
| R-STR-1 | a stream is opened by the reply to a call | guards: `targetOpen` opens the target's side, `commanderReply` the commander's |
| R-STR-1 | the keys of the two directions come from the call's HPKE context with different labels | abstraction: the instance number `k` stands for the context, the direction for the label (header); the derivation is the Tamarin calls model's |
| R-STR-2 | a chunk carries the direction bit, stream number, chunk number, flags, and the added credit | the record `Chunk`; `chunkBinding`; probe `no_dir` |
| R-STR-2 | exactly one of the three flags is set; any other combination closes the stream | the field `kind` takes one of `data`, `credit`, `end`. A chunk with another combination can come only from a faulty peer and ends the stream like a chunk out of order (`witnessOrderClose`); it is not modelled separately |
| R-STR-2 | the cipher nonce equals the chunk number | `chunkNumbersUnique`; probe `reuse_no` |
| R-STR-2 | the chunk header is associated data | abstraction: a chunk cannot be forged or altered (header) |
| R-STR-3 | the mode is named in the call | the field `mode` of `Call`, copied to both sides |
| R-STR-3 | ordered: only the number one greater than the previous one; anything else closes the stream | `orderedInOrder`; probe `ordered_gap`; witness `witnessOrderClose` |
| R-STR-3 | lossy: a number above the highest is taken, gaps are not filled, a lower or equal one is dropped silently | `lossyIncreasing`; probe `lossy_old`; witness `witnessLossyGap` |
| R-STR-3 | credit does not apply in lossy mode; the recipient drops the excess | abstraction: in lossy mode no credit chunks are sent and the recipient takes what it can (header) |
| R-STR-3 | a chunk of a stream the recipient does not have is dropped, changes no state, and causes no answer | `unknownIsDropped`; probes `unknown_opens`, `id_only`; scenario `staleChunkIsDroppedTest`; witness `witnessStaleDropped` |
| R-STR-4 | a sender sends no more data than the credit granted to it | `senderWithinCredit`; probe `ignore_credit` |
| R-STR-4 | each direction has its own credit | the fields `sendCredit` and `recvCredit` of each side |
| R-STR-4 | the commander's initial credit travels in the call, the target's in the reply | `Call.credit`, `Reply.credit`; `creditSound` |
| R-STR-4 | after that each side adds credit with credit chunks | `creditSound`; probe `credit_replay`; witness `witnessCreditAdded` |
| R-STR-4 | a chunk with its header fits in one frame | abstraction: a data chunk carries one unit (header) |
| R-STR-4 | exceeding the credit closes the stream | `creditRespected`; probe `no_credit_check`; witness `witnessCreditClose` |
| R-STR-5 | an "end" chunk closes the stream | guards: `sendChunk` and `receive` remove the stream on `end` |
| R-STR-5 | "link down" closes the streams | guard: `linkDown` empties both sides |
| R-STR-5 | "reset nonces" closes the streams without traffic since the previous one | `resetOnlyIdle`; probe `reset_busy`; scenario `resetClosesOnlyIdleTest`; witness `witnessResetClosed` |
| R-STR-5 | a halt of the bus closes the streams | `haltClosesStreams`; probe `halt_keeps` |
| R-STR-5 | the revocation of either party closes the streams | `revocationClosesStreams`; probe `revoke_keeps` |
| R-STR-6 | the number of open streams is bounded by the profile | `streamsBounded` |
| R-STR-6 | opening beyond the limit is rejected with a result code, not by closing streams | `openKeepsStreams`; probe `evict`; witness `witnessTooMany` |
| R-CORE-6 | open streams do not survive a reboot | guard: `reboot` empties the node's streams; scenario `staleChunkIsDroppedTest` (and probe `id_only`) |
| R-KEY-9 | under one key the nonce equals the message number and never repeats | `chunkNumbersUnique`; probe `reuse_no` |
| R-MEM-9 | a halted node closes its streams | `haltClosesStreams`; probe `halt_keeps`; a halted node opens, sends and takes nothing (guards) |

R-STR-7 (a relay forwards chunks unchanged) is the relay's and is checked by a relay test.

## Inductive invariant

[`inductive.qnt`](inductive.qnt) holds an inductive invariant `IndInv`; Apalache proves the same three
obligations as for the other models: the initial state satisfies `IndInv`, every step keeps it, and
`IndInv` implies `safety`. Besides the bounds of every variable and `broken` staying empty, `IndInv`
states these lemmas:

- there is one call and at most one reply for each call number, and a reply is only for a call the
  target has taken;
- every open stream was opened by a successful reply with its number and a call in its mode, and the
  commander's side belongs to a call that is no longer pending;
- every chunk sent has a number below the sender's next number, chunks are unique by key, direction
  and number, and the highest number a recipient has taken is that of a chunk of its peer;
- in ordered mode the credit adds up: what a recipient still grants plus the data it took equals all
  it granted, which is the initial credit and its own credit chunks; what a sender may still send plus
  the data it sent equals all it got, which is the initial credit and the peer's credit chunks up to
  the highest number taken. In lossy mode every credit is 0;
- a halted node, and a node that knows its peer was revoked, has no open stream.

Together they make every invariant of `safety` follow. Because calls and replies are unique by call
number and chunks by direction, call and number, `indInit` draws each of them from one slot per key,
and record types are checked field by field: drawing from all subsets of every possible record, and
testing membership in that set, grows quadratically with its size. The instances are `tiny_ind` (the size of
`tiny`, checked in CI) and `small_ind` (the size of `small`) for a long run.

## Running

Requirements as for the other models: Quint 0.33.1 from [`models/package-lock.json`](../package-lock.json)
and Java 17 or later for TLC.

```sh
python3 models/streams/check.py                        # CI run: safety, probes, witnesses, scenarios
python3 models/streams/check.py --inductive tiny_ind   # IndInv in CI
```

On a shared machine, [`run-tlc.ps1`](../run-tlc.ps1) checks the TLA+ translation with `-Probes` (every
probe against `safety`, every witness on `tiny`; both lists are in [`checks.json`](checks.json)) and
runs the exhaustive check of `tiny`; [`run-inductive.ps1`](../run-inductive.ps1) proves `IndInv` on
`small_ind`, one step branch at a time with `-Split`:

```powershell
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model streams -WorkDir <folder> -Java <path to java> -Probes
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model streams -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model streams -Split -WorkDir <folder> -Java <path to java>
```

Every run prints the model hash: the first 12 hex digits of the SHA-256 of `streams.qnt` and
`instances.qnt`. The results table records this hash rather than a commit.

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |
| 2026-11-22 | `1c6175f78335` | TLC 1.7.4, `run-tlc.ps1 -Probes`, maintainer's server (54 workers) | 13 probes against `safety`, 8 witnesses on `tiny`, breadth-first until the first violation | 21 of 21 violated as expected, 1.0 to 1.5 min each (compilation included), 24 min in total |
| 2026-11-22 | `1c6175f78335`, invariant `dbb0286ea367` (commit 6b58fcd) | Apalache 0.62.4, `run-inductive.ps1 -Split -Parallel 1`, maintainer's server (53 GB heap) | `small_ind`, all states satisfying `IndInv` | all three obligations hold: init in 0.9 min, the 11 step branches in 1.1 to 5.3 min (`Receive` the longest), `IndInv` implies `safety` in 1.8 min; 29 min in total. Safety holds in every reachable state of `small_ind` |
| 2026-11-23 | `1c6175f78335` (commit 112a58e) | TLC 1.7.4, `run-tlc.ps1 -CheckpointMinutes 0`, maintainer's server (54 workers, 64 GB heap) | exhaustive check of `safety` on `tiny`, every reachable state | no error found: 47,088,551 distinct states (412,879,007 generated), depth 27, 7.5 min; probability of a fingerprint collision 9.3E-4 (TLC's optimistic estimate), 3.6E-5 (from the actual fingerprints) |
