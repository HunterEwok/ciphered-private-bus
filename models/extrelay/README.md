<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# External relay model

A Quint [model](extrelay.qnt) of external relays (verification level V2 of the
[specification](../../docs/spec/requirements.md), Section 11.1 and Appendix B, Section B.10; R-REL-13,
R-REL-15, R-REL-18, R-REL-19, and the external relay halves of R-REL-3, R-REL-5 and R-REL-6): one
external relay of one bus, the relay epochs of the root device, relay access objects, tickets, bridges
under a closed alias, relay hello admission, Root-signed objects, and members that upload and fetch
under their aliases. The Root admits and revokes members, removes the relay from the `relays` list,
changes the root generation, and is replaced by a new root device after a loss, whose predecessor's
device key the adversary then holds and signs relay access objects with, of any epoch. The header of
`extrelay.qnt` lists every abstraction; the derivation of aliases and the secrecy of the relay epoch
secret are the Tamarin relay link model's.

## Instances

[`instances.qnt`](instances.qnt) fixes the sizes.

| Instance | Members (at start) | Relay epochs | Root devices | Root generations | Root events | Purpose |
| --- | --- | --- | --- | --- | --- | --- |
| `small` | 3 (2) | 3 | 2 | 2 | 4 | Simulator runs in CI; inductive proof as `small_ind` |
| `tiny` | 2 (1) | 2 | 2 | 2 | 3 | Simulator in CI; TLC; inductive proof as `tiny_ind` in CI |
| `probe_*` | 3 (2) | 3 | 2 | 2 | 4 | One deliberate defect each; `safety` must fail (R-VER-2) |

Root events are admissions, revocations, removal of the relay, root changes, and new root devices.

### Why `small` is large enough

Every property relates at most the following roles at the same time, and `small` holds a copy of each:

- three members: one that stays valid across an epoch change, one that is revoked by it, and one that
  is admitted during an epoch (R-REL-13, R-REL-19, `revokedNoCurrent`, `bridgesOnlyToMembers`). A
  member asleep through an epoch change is any of the members that stay; a member that claims another
  member's alias (probe `hello_no_tree`) needs two members of one tree;
- two root generations, so that a bridge crosses a root change and a member asleep through it must
  verify a relay access object of the new generation (R-REL-19, probe `bridge_without_records`);
- two root devices, the replaced one with a stolen key and its successor, so that a forged relay access
  object of any epoch meets the successor's epoch 1 (R-REL-13, `accessOfNamedRoot`, probes
  `epoch_only_order`, `no_rd_check`);
- three relay epochs, so that the stolen key can sign an epoch ahead of every honest one, and an
  epoch change follows another one under one root device;
- four root events, enough for an admission, a revocation, a root change and a new root device in one
  run, or two epoch changes followed by the removal of the relay.

A fourth member repeats one of these roles, and further epochs, generations or events repeat an
epoch change that the inductive invariant already covers from every state, not only from reachable
ones.

## Properties

`safety` is the conjunction of the invariants below. Properties of a single step are checked by a
monitor when the step is taken, as in the other models.

| Invariant | Requirement | Property |
| --- | --- | --- |
| `revokedNoCurrent` | S5, S18, R-REL-13, R-REL-19 | a device that is not a valid member does not know the relay epoch secret of the current epoch |
| `accessOfNamedRoot` | R-REL-13 | a member holds a relay access object only of the root device and generation of its checkpoint, so a replaced root device's key cannot keep it away from the new root device's relays |
| `bridgeForEveryMember` | R-REL-19 | under a closed bridged alias, every member of its tree that is a member of the next epoch knows that epoch or a later one, has moved to a later root device, or still has its bridge |
| `bridgesOnlyToMembers` | R-REL-19 | a bridge is addressed only to a member of the next epoch, and an alias closed because the relay left the list carries none |
| `closedHoldsOnlyBridges` | B.10 rule 3, R-REL-6 | a closed alias holds nothing but bridges |
| `rootObjectsFromRoot` | R-REL-18 | Root-signed objects are accepted only from the root device's alias |
| `uploaderIsLinkAlias` | R-REL-15, `Relayed` field `from` | a stored object names its true uploader |
| `ticketIsLatest` | B.10 rules 1, 3 | the relay holds the ticket with the greatest number the Root sent for each alias, so a closed alias stays closed |
| `newEpochOnClear` | R-REL-13 | a checkpoint that clears a passport bit starts a new epoch (monitor) |

Probes, each expected to violate `safety`:

| Probe | Defect |
| --- | --- |
| `no_new_epoch` | A revocation starts no new epoch |
| `epoch_only_order` | Relay access objects are ordered by epoch alone, and kept across a checkpoint naming another root device |
| `no_rd_check` | The root device that signed a relay access object is not checked |
| `no_bridges` | The root device uploads no bridges |
| `bridge_to_revoked` | A revoked member receives a bridge |
| `unlisted_bridges` | A relay removed from the list receives bridges |
| `keep_on_close` | A closing ticket keeps the members' objects |
| `member_root_obj` | A Root-signed object is accepted from a member's alias |
| `hello_no_tree` | The relay checks only that an alias is listed, not the link key's leaf in the tree, so a member can claim another member's alias |
| `ticket_rollback` | An earlier ticket of an alias replaces the one held |
| `bridge_without_records` | A bridge after a root change carries no root change record or checkpoint, so a member asleep through the root change cannot verify its relay access object, and the bridge is deleted |

Fixed scenarios in [`scenarios.qnt`](scenarios.qnt) (`quint test`): a member asleep through a root
change follows its bridge to the new generation (and is stranded under `bridge_without_records`); a
far-ahead relay access object signed by the stolen key is refused once the member takes the checkpoint
naming the new root device, which then admits it with epoch 1 (and locks it out under
`epoch_only_order`); a revoked member gets no bridge and no relay access object of the new epoch.

Witnesses (`witness*`) state that a behaviour never happens and are expected to be violated: a bridge
fetched, a revocation followed by a closing ticket, a member that took a forged object returning to the
new root device, the relay removed from the list and closed, a member bridged across a root change, and
an upload after an admission.

## Requirement coverage

Every normative sentence of the requirements in scope, and what in the model checks it: an invariant
(with the probe that breaks it), a guard, or a stated abstraction. "Header" points to the abstractions
listed at the top of [`extrelay.qnt`](extrelay.qnt).

| Requirement | Sentence | Checked by |
| --- | --- | --- |
| R-REL-13 | the root device keeps a relay epoch number, counted from 1 by each root device within a root generation | the fields `g`, `rd`, `e` of the Root and of an alias; guards: `rootChange` and `newRootDevice` start epoch 1 |
| R-REL-13 | a fresh relay epoch secret and period secret for each epoch, never disclosed | abstraction: a node knows an epoch's secret exactly when it accepted its relay access object (header); secrecy is the Tamarin relay link model's |
| R-REL-13 | a new epoch MUST start with every checkpoint that clears a passport bit or changes the `relays` list | `newEpochOnClear`, `revokedNoCurrent`; probe `no_new_epoch`; guard: `checkpoint` starts one when the list changes |
| R-REL-13 | MAY start one on the time event or at the owner's request | abstraction: the same epoch change without a checkpoint (header) |
| R-REL-13 | for each epoch the root device issues a relay access object to every valid member, and one to a member admitted during the epoch | guards: `checkpoint`, `rootChange`, `newRootDevice`, `rootAdmit`; `revokedNoCurrent` |
| R-REL-13 | it is issued again, sealed to the new key, on a newer sealing key claim | abstraction: sealing keys are not modelled; a relay access object opens only for its addressee (header) |
| R-REL-13 | a member accepts one only if signed by the root device named in its checkpoint, and orders them by (root device, epoch) | `acceptable`; `accessOfNamedRoot`; probes `no_rd_check`, `epoch_only_order`; scenario `farEpochIsRefusedTest` |
| R-REL-13 | on a checkpoint naming another root device it drops the one it holds and accepts the next of the new root device whatever its epoch | guard `nodeCheckpoint`; `accessOfNamedRoot`; probe `epoch_only_order`; witness `witnessReturned` |
| R-REL-13 | a member never sends the secret, its link seed, or anything derived from them in the open | abstraction: the Tamarin relay link model's |
| R-REL-15 | the relay keeps, per bus alias, the ticket with the greatest number | `ticketIsLatest`; probe `ticket_rollback` |
| R-REL-15 | it accepts a link only after a relay hello with a leaf of the ticket's tree and an authentication by that link key | `admits`; `uploaderIsLinkAlias`; probe `hello_no_tree` |
| R-REL-15 | it stores or forwards nothing but wrapped objects from admitted aliases | guard: `nodeUpload` requires `admits` |
| R-REL-18 | Root-signed objects are accepted only from the alias of the root device named in the ticket | `rootObjectsFromRoot`; probe `member_root_obj` |
| R-REL-18 | the relay keeps the latest of each kind | abstraction: one kind of object per alias and uploader (header); the order of a kind is the relay model's |
| R-REL-19 | at each relay that stays listed, the root device uploads a bridge for each member that stays valid | `bridgeForEveryMember`, `bridgesOnlyToMembers`; probes `no_bridges`, `bridge_to_revoked`; witness `witnessBridgeFetched` |
| R-REL-19 | after a root change it also uploads the root change record and the checkpoint of the new generation | `bridgeForEveryMember`; probe `bridge_without_records`; scenario `sleeperFollowsRootChangeTest`; witness `witnessRootChangeBridged` |
| R-REL-19 | it registers the ticket of the new alias and uploads the control-plane objects under it, and only then sends the closing ticket | guards: stages 1, 2, 3 of `rootBridges`, `rootRegister`, `rootClose` |
| R-REL-19 | sources upload their publications and grants again under the new aliases | abstraction: what members store is the relay model's (header) |
| R-REL-19 | on a closing ticket the relay deletes everything except the bridges and their records, and accepts only a relay hello that fetches a bridge | `closedHoldsOnlyBridges`; probe `keep_on_close`; guard: `nodeUpload` requires an open alias |
| R-REL-19 | it deletes each bridge once its addressee has fetched it | guard `nodeBridge` |
| R-REL-19 | a revoked device receives no bridge | `bridgesOnlyToMembers`, `revokedNoCurrent`; probe `bridge_to_revoked`; scenario `revokedIsNotBridgedTest` |
| R-REL-19 | a device that slept through several epochs follows the bridges from alias to alias | `bridgeForEveryMember`: a bridge stays until its addressee fetches it |
| R-REL-19 | at a relay removed from the checkpoint, the closing ticket carries no bridges | `bridgesOnlyToMembers`; probe `unlisted_bridges`; witness `witnessUnlisted` |
| R-REL-6 | an external relay deletes by the closing ticket | `closedHoldsOnlyBridges`; probe `keep_on_close` |
| R-REL-3, R-REL-5 | an external relay applies the retention and serving rules to aliases | abstraction: the relay model checks these rules (header) |
| B.10 rule 1 | the relay keeps the ticket with the greatest `no` and accepts none smaller or equal | `ticketIsLatest`; probe `ticket_rollback` |
| B.10 rule 2 | a new ticket with a greater number on an admission; a member leaves the tree only with a new epoch | guard `rootAdmit`; `revokedNoCurrent` |
| B.10 rule 3 | a closing ticket is final | `ticketIsLatest`; probe `ticket_rollback` |
| B.10 rule 3 | each bridge is served only to its addressee after a relay hello under the closed alias | `admits` in `nodeBridge`; probe `hello_no_tree` |
| B.10 rule 4 | bridges first, then the new ticket with the checkpoint, the latest root change record and the passports, then the closing ticket | guards: stages 1, 2, 3; `rootObjectsFromRoot` |
| B.10 rule 5 | a new root device starts epoch 1; with its predecessor's relay state it bridges and closes the old aliases, otherwise members reach it through member links | guards `rootChange` (keeps the relay state), `newRootDevice` (does not); witness `witnessReturned` |
| B.10 rule 5 | a relay access object of an older generation, or from a root device the checkpoint no longer names, is ignored | `acceptable`; `accessOfNamedRoot`; probes `no_rd_check`, `epoch_only_order` |
| B.10 relay hello | the relay accepts the link only if the leaf and path lead to the latest ticket's root; under a closed alias it serves only the bridge and its records | `admits`; guard `nodeBridge`; probe `hello_no_tree` |
| B.10 `Relayed` | `from` equals the alias of the link | `uploaderIsLinkAlias`; probe `hello_no_tree` |

R-REL-14 and R-REL-16 (derivations and wrapping) are the Tamarin relay link model's and the test
vectors'; R-REL-17 (upload counters) and R-REL-20 (retention of closed aliases) are checked by vectors
and a relay test.

## Inductive invariant

[`inductive.qnt`](inductive.qnt) holds an inductive invariant `IndInv`; Apalache proves the same three
obligations as for the other models: the initial state satisfies `IndInv`, every step keeps it, and
`IndInv` implies `safety`. Besides the bounds of every variable and `broken` staying empty, `IndInv`
states these lemmas:

- every Root event is one checkpoint; during an epoch change the old alias is open, the new alias is
  the current one and not yet registered at a listed relay, and the members at its start are the valid
  members;
- every alias the relay, a node or a relay access object knows is not later than the current one, and
  the relay knows the current alias exactly when it is listed and not between bridging and
  registration;
- a relay access object of the current epoch that the stolen key did not sign is addressed to a valid
  member, and a node that knows the current epoch is valid;
- an alias is bridged once, at the checkpoint of its new epoch, to a later alias; checkpoints, bridges and nodes agree on the order of (generation, root device) by checkpoint
  number;
- a node's relay access object is of the root device and generation of its checkpoint;
- `bridgeForEveryMember` holds from the moment the bridges are uploaded, not only after the closing
  ticket.

`indInit` draws maps total over the aliases or members and cuts them to a drawn domain, and draws
bridges and stored objects as the pairs that name them; the invariant fixes the other fields. The
branch `stepRelayTicket` is never enabled in a state of `IndInv` (an earlier ticket has a smaller
number), so Apalache reports its deadlock, which counts as its pass (`disabledSteps` in
[`checks.json`](checks.json)). The instances are `tiny_ind` (the size of `tiny`, checked in CI) and
`small_ind` (the size of `small`) for a long run.

## Running

Requirements as for the other models: Quint 0.33.1 from [`models/package-lock.json`](../package-lock.json)
and Java 17 or later for TLC.

```sh
python3 models/extrelay/check.py                        # CI run: safety, probes, witnesses, scenarios
python3 models/extrelay/check.py --inductive tiny_ind   # IndInv in CI
```

On a shared machine, [`run-tlc.ps1`](../run-tlc.ps1) checks the TLA+ translation with `-Probes` (every
probe against `safety`, every witness on `tiny`; both lists are in [`checks.json`](checks.json)) and
runs the exhaustive check of `tiny`; [`run-inductive.ps1`](../run-inductive.ps1) proves `IndInv` on
`small_ind`, one step branch at a time with `-Split`:

```powershell
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model extrelay -WorkDir <folder> -Java <path to java> -Probes
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model extrelay -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model extrelay -Split -WorkDir <folder> -Java <path to java>
```

Every run prints the model hash: the first 12 hex digits of the SHA-256 of `extrelay.qnt` and
`instances.qnt`. The results table records this hash rather than a commit.

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |
| 2026-11-28 | `4eb354135f7f` (commit 8dfd3dd) | TLC 1.7.4, `run-tlc.ps1 -Probes`, maintainer's server (6 workers, 7 GB heap) | 11 probes against `safety` at the size of `small`, 6 witnesses on `tiny`, breadth-first until the first violation | 17 of 17 violated as expected, depth 3 to 9, 1.0 to 2.0 min each (compilation included), 20 min in total |
| 2026-11-28 | `4eb354135f7f` (commit 8dfd3dd) | TLC 1.7.4, `run-tlc.ps1`, maintainer's server (6 workers, 7 GB heap) | exhaustive check of `safety` on `tiny`, every reachable state | no error found: 8,099,194 distinct states (69,298,607 generated), depth 31, 5 min; probability of a fingerprint collision 2.7E-5 (TLC's optimistic estimate), 2.4E-4 (from the actual fingerprints) |
| 2026-11-28 | `4eb354135f7f`, invariant `defe24f74725` (commit 8dfd3dd) | Apalache 0.62.4, `run-inductive.ps1 -Split -Parallel 2`, maintainer's server (7 GB heap each) | `small_ind`, all states satisfying `IndInv` | all three obligations hold: init in 1.9 min, the 13 enabled step branches in 13.7 to 149.6 min (`NodeBridge` the longest), `RelayTicket` has no transition from a state satisfying `IndInv` (12.4 min), `IndInv` implies `safety` in 3.2 min; 4 h 35 min in total. Safety holds in every reachable state of `small` |
