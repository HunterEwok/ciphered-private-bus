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

### Why `small` is large enough

The safety proof runs at `small_ind`, the size of `small`. One target is enough: each target keeps
its own slots and its own key epoch, and a body sealed for another target carries a nonce this target
never issued, which the adversary already supplies (any value seen on the wire, or junk). Every
property relates at most the following roles at the same time, and `small` holds a copy of each:

- two named commanders, one with only the automatic right and no user-presence key, one with both
  rights and a user-presence key: a nonce issued to one is "another device's nonce" for the other
  (`freshNonce`), and an action that needs a right or a key one of them lacks meets one that has it
  (`permitted`, probes `no_right_check`, `presence_not_required`). Either of them can stop being named
  (`slotsKnown`, probe `keep_revoked_slot`);
- the root device, whose root key has every right and whose other keys have only the rights of the
  passport (probes `root_device_all_rights`, `root_key_any_device`);
- an outsider, never named, that asks for a slot (`slotsKnown`, probe `slot_for_anyone`);
- two actions, automatic and confirmation-class, which are all the classes there are; passport
  changes only take rights away, so they end after at most two per commander;
- six nonces. Nonces are fresh values compared only for equality, and what a step does with one
  depends only on whether it is the slot of the sending device, no nonce, or another value; the state
  view of `view.qnt`, proven exact for `safety`, keeps exactly these classes. Six nonces give each of
  the three devices that can hold a slot a current nonce and a stale one, and `indInit` draws slots
  and call bodies freely over them;
- three key epochs: the epoch a commander knows, a newer claim it learns and retries under, and a
  replayed claim of the old epoch that must not move it back (`epochGrows`, `oneRetryPerKind`, probe
  `accept_any_epoch`);
- two calls per commander, so that the bodies of an earlier call are replayed while the pending call
  is a later one, and a call that is not idempotent meets one that is (`atMostOnce`);
- two resets or reboots: a reset and a reboot, which erase the slots in different events, or two
  resets so that a nonce issued between them goes stale (`freshNonce`, probes `reset_keeps_slots`,
  `reboot_keeps_slots`).

A third named commander repeats one of the first two, since every property is about one commander's
slot, calls and rights against the target's state. Further calls, epochs or resets repeat one of the
sequences above, and the proof covers them from every state of `IndInv`, not only from reachable ones.

## Properties

| Invariant | Requirement | Property |
| --- | --- | --- |
| `atMostOnce` | R-CALL-5, R-CALL-13 | S10: a call that is not idempotent is executed at most once, also across automatic retries |
| `freshNonce` | R-CALL-1, R-CALL-8, R-CORE-6 | S10: an action runs only over a nonce the target issued to this commander since the latest reset or reboot and did not consume |
| `permitted` | R-CALL-4 | S10: only with the right under the target's current passport and the key the action class requires; the root key has every right, the root device's other keys only those the passport gives it |
| `slotsKnown` | R-CALL-7 | S14: slots only for named commanders and the root device, also after a commander stops being named |
| `mismatchKeepsSlot` | R-CALL-6 | S14: a mismatch does not change the slot |
| `noConfirmRetry` | R-CALL-13 | a confirmation-class call is never retried automatically, after either open refusal |
| `oneRetryPerKind` | R-CALL-13 | per call, at most one automatic retry per kind of open refusal |
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
| `root_device_all_rights` | Every key of the root device has every right, not only the root key |
| `root_key_any_device` | A call signed with the root key is accepted from a device other than the root device |
| `retry_confirmation_mismatch` | The commander retries a confirmation-class call after a mismatch |
| `retry_twice` | The commander retries a call more than once after the same kind of open refusal |

`retry_on_mismatch` needs a specific sequence (an executed call whose reply is withheld is replayed)
and is checked by a fixed scenario in [`scenarios.qnt`](scenarios.qnt), which also shows that the
replay is reported as unknown, that a retry after a newer key claim is executed once, that a
confirmation-class call is not retried, that a reset makes an earlier nonce stale, and that the root
device's device key runs no action the passport does not give it while the root key runs it (the probe
`root_device_all_rights` breaks `safety` on the same steps).

The model led to two clarifications of the specification: a mismatch for a commander without a slot,
for example after a reset, is answered like a nonce request, so the refusal itself carries a new nonce
(R-CALL-6); and a review found that the slot of a commander that stops being named survived, so its
next call consumed the nonce and refilled the slot. The slot is now erased in the same event
(R-CALL-7).

## Requirement coverage

Every normative sentence of the requirements in scope, and what in the model checks it: an invariant
(with the probe that breaks it), a guard, or a stated abstraction.

| Requirement | Sentence | Checked by |
| --- | --- | --- |
| R-CALL-1 | A slot exists per pair (commander, target) | one target; `slots` per device |
| R-CALL-1 | kept in RAM only | `freshNonce`; probes `reset_keeps_slots`, `reboot_keeps_slots` |
| R-CALL-1 | holds 16 random bytes | abstraction: nonces are fresh counter values (header) |
| R-CALL-4 | executes only if the nonce matched the slot | `freshNonce`; probe `no_erase` |
| R-CALL-4 | and the signing key has the right under the target's passport | `permitted`; probes `no_right_check`, `revoked_calls` |
| R-CALL-4 | the class of an action is the target's, never from the call | the call names an action and no class; the target derives the class from the action. Abstraction: an action has one class for every commander, so the per-commander masks of a permit are not modelled |
| R-CALL-4 | an automatic action is signed by the device key | `permitted` (`keyOk`) |
| R-CALL-4 | a confirmation-class action by the user-presence key or the root key | `permitted`; probe `presence_not_required` |
| R-CALL-4 | the root key has the right to every action | `permitted`; scenario `rootDeviceKeyTest` (the root key runs an action the passport does not give the root device) |
| R-CALL-4 | the other keys of the root device have only the passport's rights | `permitted`; probe `root_device_all_rights`, scenario `rootDeviceKeyTest` |
| R-CALL-5 | a matched nonce is erased before the action is executed | abstraction: processing is instantaneous; the order is the storage test's (header) |
| R-CALL-5 | one nonce executes at most one action | `freshNonce`, `atMostOnce`; probe `no_erase` |
| R-CALL-6 | on a mismatch the slot does not change | `mismatchKeepsSlot`; probe `mismatch_changes` |
| R-CALL-6 | the answer needs neither decapsulation nor a signature | guard: the mismatch branch of `targetCall` reads only the slot |
| R-CALL-6 | without a slot the answer is that to a nonce request, under R-CALL-7 | guard in `targetCall`; `slotsKnown` |
| R-CALL-7 | slots only for named commanders and the root device | `slotsKnown`; probe `slot_for_anyone` |
| R-CALL-7 | a call signed by the root key comes from the root device | `permitted` (`keyOk`); probe `root_key_any_device` |
| R-CALL-7 | a nonce request from anyone else is not answered | guard in `targetAnswer`; `slotsKnown`; probe `slot_for_anyone` |
| R-CALL-7 | a device that stops being a commander loses its slot in the same event | `slotsKnown`; probe `keep_revoked_slot` |
| R-CALL-8 | "reset nonces" erases all slots | `freshNonce`; probe `reset_keeps_slots` |
| R-CALL-8 | raised from the host's uptime counter with the profile's period | abstraction: a nondeterministic event |
| R-CALL-8 | a reboot erases the slots | `freshNonce`; probe `reboot_keeps_slots` |
| R-CALL-13 | two open refusals, mismatch checked before stale epoch | guard: branch order in `targetCall`. Not a safety property here: with the order swapped, a retry after "stale key epoch" meets the mismatch and executes nothing |
| R-CALL-13 | a halted target answers with a halt proof | abstraction: the halt is the membership model's (header) |
| R-CALL-13 | refusals are unsigned and do not consume the nonce | the adversary forges refusals with any value seen in the open; the stale-epoch branch consumes nothing |
| R-CALL-13 | after "stale key epoch" an automatic retry with the same nonce and the new key | `cmdEpoch`; witness `witnessEpochRetryExecuted`, scenario `epochRetryTest` |
| R-CALL-13 | after "nonce mismatch" no automatic retry, except for an idempotent call | `atMostOnce`; probe `retry_on_mismatch`, scenario `replayNotRetriedTest` |
| R-CALL-13 | "no right" only after decapsulation, and the nonce is consumed | `freshNonce`; witness `witnessNoRight` |
| R-CALL-13 | at most one automatic retry per kind of open refusal | `oneRetryPerKind`; probe `retry_twice` |
| R-CALL-13 | a confirmation-class action is never retried automatically | `noConfirmRetry`; probes `retry_confirmation`, `retry_confirmation_mismatch` |
| R-CALL-13 | a stale-epoch claim is accepted only signed by the target and with a greater epoch | `epochGrows`; probe `accept_any_epoch`; signatures are perfect (header) |
| R-CORE-6 | nonce slots do not survive a reboot | `freshNonce`; probe `reboot_keeps_slots` |

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
run. `indInit` draws each call's intent field by field and the bodies
of each call as a bitmap over (nonce, epoch), and `IndInv` checks records field by field: a pool of
calls drawn as a subset of every possible call (about 1,700 records at the size of `small`) is beyond
the solver's memory.

## State view for TLC

Exhaustive TLC of `tiny` runs with a TLC `VIEW` defined in `view.qnt`. The view drops what can no
longer influence `safety`: the witness tags and the ghost intents, which only feed the tags; call
bodies whose nonce can never match a slot again or whose epoch is already stale; replies that cannot
end the pending call differently from a refusal; nonce values beyond "the slot of this device",
"none" and "another value"; epochs at or above the last one a commander can still learn; and every
device that can never hold a slot again. Module `bisim` proves with Apalache that states with equal
views are interchangeable for `safety` (obligations O1 to O4 in `view.qnt`), so TLC with the view
finds a violation exactly when TLC without it would.

The proof's draws `drawA` and `drawB` produce every state of `Struct` with no broken property
(`broken` empty). This covers every state the obligations need. A state that satisfies `safety` has
`broken` empty, because every tag the model adds to `broken` is one that `safety` forbids; so O2 and
O4, which start from a safe A, start from drawn states, and so does O1. For O3, the view keeps
`broken` as it is: two states with equal views and a non-empty `broken` both violate `safety` and
agree on it, and the pairs with `broken` empty are the drawn ones.

## Running

```sh
python3 models/calls/check.py                         # CI run
python3 models/calls/check.py --inductive tiny_ind    # IndInv in CI
```

```powershell
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model calls -Probes -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model calls -View -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model calls -Section bisim -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model calls -Split -WorkDir <folder> -Java <path to java>
```

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |
| 2026-11-21 | `dfa55320e4e3` | TLC 1.7.4, `run-tlc.ps1 -Probes`, maintainer's server (49 workers) | 12 probes against `safety`, 6 witnesses on `tiny`, breadth-first until the first violation | 18 of 18 violated as expected, 1.0 to 1.3 min each |
| 2026-11-26 | `dfa55320e4e3`, invariant `e7215840fea9` (commit 78aea79) | Apalache 0.62.4, `run-inductive.ps1 -Split -Parallel 1`, maintainer's server (12 GB heap) | `small_ind`, all states satisfying `IndInv` | all three obligations hold: init in 1.5 min, the 10 step branches in 2.1 to 2.8 min, `IndInv` implies `safety` in 2.1 min; 27.7 min in total. Safety holds in every reachable state of `small` |
| 2026-11-24 | `dfa55320e4e3`, view `bfc1f9b16f28` (commit c6c47d3) | Apalache 0.62.4, `run-inductive.ps1 -Section bisim`, maintainer's server (4 checks at a time with 13 GB heap each; the 6 longest checks of O4 6 at a time with 8 GB heap each) | `tiny_bisim`, all pairs of states satisfying `Struct` | all 24 checks pass: init and the 10 step branches preserve `Struct` (1.0 to 1.3 min), equal views agree on `safety` (1.4 min), each of the 10 branches is answered with an equal view (6.9 min for `Reset` to 2,894.9 min for `Epoch`), both witnesses violated as expected (1.7 and 4.6 min). TLC with the view is exact for `safety` |
| 2026-11-26 | `dfa55320e4e3`, view `bfc1f9b16f28` (commit c6c47d3) | TLC 1.7.4, `run-tlc.ps1 -View`, maintainer's server (54 workers, 64 GB heap) | `tiny`, exhaustive, `VIEW safetyView` | no error: 1,349,524 distinct states (28,847,963 generated), depth 24, 42 s; probability of a fingerprint collision 2.0E-6 (TLC's optimistic estimate), 1.7E-7 (from the actual fingerprints) |

