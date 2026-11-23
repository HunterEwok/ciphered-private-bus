<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Calls model

A Quint [model](calls.qnt) of call nonce slots (verification level V2 of the
[specification](../../docs/spec/requirements.md), Section 14): one target and its commanders, nonce
requests, calls, replies, the two open refusals ("nonce mismatch" and "stale key epoch") with the
commander's automatic retries, the host events "reset nonces" and reboot, rotation of the target's
sealing key epoch, and changes of the target's passport. The network is a pool of every call body and
reply; the adversary replays any of them, withholds replies, and forges the unsigned answers and
refusals with any nonce seen in the open. The header of `calls.qnt` lists every abstraction.

## Instances

| Instance | Commanders | Nonces | Key epochs | Calls per commander | Resets and reboots | Purpose |
| --- | --- | --- | --- | --- | --- | --- |
| `small` | `a` (automatic only), `b` (with user presence), root `r`, outsider `x` | 6 | 3 | 2 | 2 | Simulator in CI |
| `tiny` | `a` (with user presence), root `r` | 4 | 3 | 2 | 1 | Simulator in CI, TLC |
| `probe_*` | as `small` | | | | | One deliberate defect each; `safety` must fail (R-VER-2) |

## Properties

| Invariant | Requirement | Property |
| --- | --- | --- |
| `atMostOnce` | R-CALL-5, R-CALL-13 | S10: a call that is not idempotent is executed at most once, also across automatic retries |
| `freshNonce` | R-CALL-1, R-CALL-8, R-CORE-6 | S10: an action runs only over a nonce the target issued to this commander since the latest reset or reboot and did not consume |
| `permitted` | R-CALL-4 | S10: only with the right under the target's current passport and the key the action class requires |
| `slotsKnown` | R-CALL-7 | S14: slots only for named commanders and the root device, also after a commander stops being named |
| `mismatchKeepsSlot` | R-CALL-6 | S14: a mismatch does not change the slot |
| `noConfirmRetry` | R-CALL-13 | a confirmation-class call is never retried automatically |
| `epochGrows` | R-CALL-13 | a replayed old key claim never moves the commander's known epoch back |

Step properties are checked by a monitor when the step is taken, as in the membership model.

Probes, each expected to violate `safety`:

| Probe | Defect |
| --- | --- |
| `no_erase` | A matched nonce is not erased |
| `mismatch_changes` | A mismatch replaces the slot with a new nonce |
| `slot_for_anyone` | A slot is created for a device not named in the passport |
| `no_right_check` | An action runs without the right |
| `presence_not_required` | A confirmation-class action runs under the device key |
| `revoked_calls` | The target checks the passport it started with, not the current one |
| `retry_on_mismatch` | The commander retries a call that is not idempotent after a mismatch |
| `retry_confirmation` | The commander retries a confirmation-class call after a newer key claim |
| `accept_any_epoch` | The commander accepts a key claim that is not newer |
| `reset_keeps_slots` | "Reset nonces" does not erase the slots |
| `reboot_keeps_slots` | A reboot does not erase the slots |
| `keep_revoked_slot` | The slot of a commander that is no longer named survives, and its next call refills it |

`retry_on_mismatch` needs a specific sequence (an executed call whose reply is withheld is replayed)
and is checked by a fixed scenario in [`scenarios.qnt`](scenarios.qnt), which also shows that the
replay is reported as unknown, that a retry after a newer key claim is executed once, that a
confirmation-class call is not retried, and that a reset makes an earlier nonce stale.

The model led to two clarifications of the specification: a mismatch for a commander without a slot,
for example after a reset, is answered like a nonce request, so the refusal itself carries a new nonce
(R-CALL-6); and a review found that the slot of a commander that stops being named survived, so its
next call consumed the nonce and refilled the slot. The slot is now erased in the same event
(R-CALL-7).

## Inductive invariant

[`inductive.qnt`](inductive.qnt) holds an inductive invariant `IndInv`; Apalache proves the same three
obligations as for the other models. Besides the bounds of every variable and `broken` staying empty,
`IndInv` states these lemmas: every slot holds a nonce issued to its own device in the current era and
not consumed, and belongs to a named commander or the root device; every body of a call agrees with its first body (kept in the ghost variable `intents`)
in class, key, and idempotence, and all bodies of a call that is not idempotent carry one nonce; a
call that was executed and is not idempotent has consumed that nonce; a commander's pending call is in
the pool and is its latest call. Together they make `atMostOnce` and `freshNonce` follow.

The instances are `tiny_ind` (one commander and the root, 3 nonces, checked in CI), `small_ind` (the
size of `small`: both kinds of commander, an outsider and the root, 6 nonces, two resets) for a long
run, and `mid_ind` between the two. `indInit` draws each call's intent field by field and the bodies
of each call as a bitmap over (nonce, epoch), and `IndInv` checks records field by field: drawing the
pool of calls as a subset of every possible call (about 1,700 records at the size of `small`) made the
solver run out of a 53 GB heap.

## Running

```sh
python3 models/calls/check.py                         # CI run
python3 models/calls/check.py --inductive tiny_ind    # IndInv in CI
```

```powershell
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model calls -Probes -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model calls -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model calls -Split -WorkDir <folder> -Java <path to java>
```

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |
| 2026-11-21 | `dfa55320e4e3` | TLC 1.7.4, `run-tlc.ps1 -Probes`, maintainer's server (49 workers) | 12 probes against `safety`, 6 witnesses on `tiny`, breadth-first until the first violation | 18 of 18 violated as expected, 1.0 to 1.3 min each |
| 2026-11-23 | `dfa55320e4e3`, invariant `bfcba4e4a1d1` (commit 4ebbe06) | Apalache 0.62.4, `run-inductive.ps1 -Split -Parallel 1`, maintainer's server (12 GB heap) | `small_ind`, all states satisfying `IndInv` | all three obligations hold: init in 0.7 min, the 10 step branches in 1.4 to 2.3 min, `IndInv` implies `safety` in 1.8 min; 20.5 min in total. Safety holds in every reachable state of `small` |

