<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Membership model

A Quint [model](membership.qnt) of the membership state machine (verification level V2 of
the [specification](../../docs/spec/requirements.md), Section 14): passports, checkpoints,
revocation, change of rights, root change, halt and halt proofs, reboot, and the acceptance
of data and key grants. The header of `membership.qnt` lists every abstraction.

## Instances

[`instances.qnt`](instances.qnt) fixes the sizes.

| Instance | Devices | Generations | Numbers per generation | Purpose |
| --- | --- | --- | --- | --- |
| `small` | 3 | 2 | 3 | Simulator runs in CI |
| `tiny` | 2 | 2 | 2 | Simulator in CI; Apalache and TLC |
| `probe_*` | 3 | 2 | 3 | One deliberate defect each; `safety` must fail (R-VER-2) |

## Properties

`safety` is the conjunction of the invariants below.

| Invariant | Requirement | Property |
| --- | --- | --- |
| `noRollback` | R-MEM-5 | S6 |
| `currentGeneration` | R-MEM-12 | S9 |
| `haltIsSticky` | R-MEM-9, R-MEM-13 | S8 |
| `haltedIsInert` | R-MEM-9 | S8 |
| `proofIsObeyed` | R-MEM-10 | S8 |
| `rootHonorsRevocation` | R-MEM-4 | S5 |
| `cacheConsistent` | R-MEM-7, R-MEM-8 | S8 |
| `revokedIsRejected` | R-MEM-2, R-MEM-12, R-VER-4 | S4, S5 |
| `grantsNeedRead` | R-CH-13 | S4, S16 |
| `convergence` | R-ARC-6 | S7 |

`convergence` compares two nodes that processed the same records. A record of another
generation is dropped unprocessed: the core has no wait buffer (R-MEM-6). Getting such a
record again is a liveness property and is not checked yet.

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

Some defects need a long, specific sequence that random simulation rarely produces. Such a
probe also has a fixed scenario in [`scenarios.qnt`](scenarios.qnt) (`quint test`): the
correct model must refuse the step, and the broken one must violate `safety` after it.
`accept_old_data_gen` is checked this way.

Witnesses (`witness*`) state that a behaviour never happens and are expected to be violated:
the violation shows that halts, permanent halts, accepted data, key grants, root changes, and
sends under revoked passports are all reachable, so `safety` does not hold vacuously.

## Running

Requirements: Quint 0.33.1, pinned in [`models/package-lock.json`](../package-lock.json)
(`npm ci` in `models/`, then put `models/node_modules/.bin` on the `PATH`), and Java 17 or
later for Apalache and TLC; Quint downloads its evaluator and Apalache on first use.

```sh
python3 models/membership/check.py simulate            # CI run, about 10 minutes
python3 models/membership/check.py apalache --steps 5   # bounded, instance tiny
python3 models/membership/check.py tlc --main tiny      # exhaustive, long run
python3 models/membership/check.py apalache --main probe_no_halt --expect violated
python3 models/membership/check.py apalache --invariant witnessHalt --expect violated
```

`--main` and `--invariant` select any instance and invariant, so probes and witnesses can be
checked with Apalache and TLC as well. Every run prints the model hash: the first 12 hex
digits of the SHA-256 of `membership.qnt` and `instances.qnt`. The results table records
this hash rather than a commit, because a squash merge replaces the commit hashes of a pull
request.

The simulator runs use a fixed seed, so a run is reproducible. Apalache and TLC runs beyond
the CI sizes are long runs (R-VER-3): their outcome is recorded below with the number of
states and the running time. An interrupted run is not a result (R-VER-5).

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |

No run of the current model is recorded yet. Earlier runs of a previous revision are not
cited (R-VER-5); the CI run of this change and the long runs on the maintainer's machines
will be entered here with the model hash.
