<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Call, reply and stream model

A Tamarin [model](calls.spthy) of calls, replies and streams (verification level V1 of the
[specification](../../docs/spec/requirements.md), Section 14; R-CALL-1..5, R-CALL-9, R-CALL-10,
R-STR-1, R-STR-2; Appendix B, Sections B.6 and B.7): the target issues a nonce, the commander signs a
call over it and seals the command to the target's sealing key with HPKE, the target executes it once
and answers with a reply under a key exported from the HPKE context, and both sides exchange stream
chunks under per-direction keys from the same context. Actions of the class `auto` are signed with the
device key, actions of the class `confirm` with the user-presence key or with the root key from the root
device. The network is the Dolev-Yao adversary; it may in addition reveal device, user-presence and root
signing keys, sealing keys a target still holds, and the commander's HPKE context of a call. Rights,
revocation, mismatch answers, resets and stream credit are left to the state model in
[models/calls](../../models/calls). The header of `calls.spthy` lists every abstraction.

## Lemmas

| Lemma | Requirement | Property |
| --- | --- | --- |
| `executable_auto` | | sanity: an `auto` call is executed, answered, and a chunk goes each way, with nothing revealed |
| `executable_confirm` | | sanity: a `confirm` call signed with the user-presence key is answered |
| `executable_root` | | sanity: a `confirm` call signed with the root key is answered |
| `call_integrity_auto` | S10, R-CALL-2, R-CALL-4 | an `auto` action is executed only as a commander called it over this nonce, unless its device key is known |
| `call_integrity_confirm` | S10, R-CALL-4 | a `confirm` action is executed only as called, unless the commander's user-presence key or the root key is known; the device key alone is not enough |
| `at_most_once` | S10, R-CALL-5 | one nonce executes at most one action |
| `context_secrecy` | helper | the KEM secret of a call is learned only from the commander's context, with the target's sealing key, or by someone who can sign the target's sealing key claims; reused by the lemmas below |
| `command_secrecy` | S1, S13, R-CALL-3 | the arguments of a call are learned only from the commander's context, with the target's sealing key while the target still held it, or by someone who could sign its claims before the call |
| `reply_secrecy` | S1, S13, R-CALL-9, R-STR-1 | the reply (result and next nonce) and the target's stream data are learned only from the commander's context, with the target's sealing key while it held it, or by someone who could sign the call as the commander before it was executed |
| `stream_secrecy` | S1, S13, R-STR-1 | the commander's stream data are learned only in the ways of `command_secrecy` |
| `reply_binding` | S11, R-CALL-9 | a reply the commander accepts comes from the target of exactly that call |
| `stream_binding` | S11, R-STR-1, R-STR-2 | a chunk accepted on a stream comes from the other party of that call, in the direction the receiver expects |

Probes, each a deliberate defect selected with `-D`, each expected to falsify its lemma (R-VER-2):

| Probe | Defect | Lemma |
| --- | --- | --- |
| `PROBE_KEEP_NONCE` | the slot keeps its nonce after an execution | `at_most_once` |
| `PROBE_NONCE_UNSIGNED` | neither the signature nor the associated data covers the nonce | `call_integrity_auto` |
| `PROBE_CONFIRM_DEVICE_KEY` | a `confirm` action is also accepted with the device key | `call_integrity_confirm` |
| `PROBE_STATIC_REPLY_KEY` | the reply key comes from the target's sealing key, not from the call | `reply_binding` |
| `PROBE_NO_DIRECTION` | both directions share one stream key and one chunk header | `stream_binding` |

`PROBE_NONCE_UNSIGNED` removes the nonce from the associated data as well: the signature covers the
sealed command, whose associated data alone would still bind the nonce. For the same reason
`PROBE_NO_DIRECTION` removes the direction from both the key label and the chunk header: either alone
separates the directions.

A device key revealed after the call does not appear in the secrecy lemmas: it lets the adversary sign
claims and calls from then on, but does not open a recorded call. This is the case of a quantum adversary
that breaks ES256 later; the X-Wing KEM itself is perfect in this model.

[`checks.json`](checks.json) lists the probes and what CI runs: every lemma and every probe.

Tamarin warns that some variables of the call, execution and reply rules are not derivable from their
premises. This is intended: signature checks are written as pattern matches on `sign(message, key)` and
`pk(key)`.

## Running

```sh
proofs/run-tamarin.sh -m calls -w <folder> -c          # CI subset
proofs/run-tamarin.sh -m calls -w <folder> -p          # every lemma and every probe
```

## Results

| Date | Model | Run | Result |
| --- | --- | --- | --- |
| 2026-11-21 | `02b96d1b2583` | Tamarin 1.12.0, `run-tamarin.sh -c` (every lemma and every probe), 4 cores, one prover at a time | 12 of 12 lemmas verified, 5 of 5 probes falsified; 11.9 min in total |
