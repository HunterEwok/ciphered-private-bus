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
| `tiny` | 2 | 2 | 2 | Simulator in CI |
| `tiny_tlc` | 2 | 2 | 2 | TLC and Apalache: `tiny` without the processed-record sets, which only `convergence` reads |
| `probe_*` | 3 | 2 | 3 | One deliberate defect each; `safety` must fail (R-VER-2). `accept_old_data_gen` and `halted_silent` have the size of `tiny_tlc`, which their defects need, so that TLC reaches them quickly |

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
| `halted_silent` | A halted node does not answer a sender of its generation with the proof; violates `haltPropagates`, not `safety` |

Some defects need a long, specific sequence that random simulation rarely produces. Such a
probe also has a fixed scenario in [`scenarios.qnt`](scenarios.qnt) (`quint test`): the
correct model must refuse the step, and the broken one must violate `safety` after it.
`accept_old_data_gen` is checked this way, and so is the case that led to the halt rule of
R-MEM-6: a proof dropped as belonging to a future generation comes back from a halted peer once
the node has moved to that generation (`halted_silent` removes that answer).

Liveness: `haltPropagates` states that while a halted peer of its generation exists, a node
eventually halts too or leaves that generation (S8, R-MEM-6, R-MEM-10). It assumes weak fairness
of `nodeHearsHalted` only: a node that keeps talking to a halted peer is eventually answered with
the proof. The probe `halted_silent` (the size of `tiny_tlc`) removes that answer, and the property must
then fail. Liveness is checked with TLC and is a long run.

Witnesses (`witness*`) state that a behaviour never happens and are expected to be violated:
the violation shows that halts, permanent halts, accepted data, key grants, root changes, and
sends under revoked passports are all reachable, so `safety` does not hold vacuously.

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
python3 models/membership/check.py tlc --main tiny_tlc --temporal haltPropagates
python3 models/membership/check.py tlc --main probe_halted_silent --temporal haltPropagates --expect violated
```

`--main` and `--invariant` select any instance and invariant, so probes and witnesses can be
checked with Apalache and TLC as well. Every run prints the model hash: the first 12 hex
digits of the SHA-256 of `membership.qnt` and `instances.qnt`. The results table records
this hash rather than a commit, because a squash merge replaces the commit hashes of a pull
request.

On a shared Windows or Linux machine, [`run-tlc.ps1`](run-tlc.ps1) runs the exhaustive TLC
check end to end with progress output: it compiles the instance, starts TLC at below-normal
priority within 85% of the cores and memory, prints depth, distinct states, the queue and its
trend, and free disk space every minute, stops TLC when free disk space falls below 15%, and
writes `summary.txt` with the model hash and the result. It needs Java 17 or later, Node, and
git, and works in Windows PowerShell 5.1:

```powershell
powershell -ExecutionPolicy Bypass -File models\membership\run-tlc.ps1 -WorkDir <folder> -Java <path to java>
```

With `-Probes` the script checks the translation to TLA+ instead: it runs TLC on every probe
instance against `safety` and on every witness against `tiny_tlc`, each within
`-TimeoutMinutes` (30 by default), and writes a table of expected and actual outcomes. Every
row must be violated; a run that reaches its time limit has no verdict and fails. The liveness
probe `halted_silent` is not part of it.

The simulator runs use a fixed seed, so a run is reproducible. Apalache and TLC runs beyond
the CI sizes are long runs (R-VER-3): their outcome is recorded below with the number of
states and the running time. An interrupted run is not a result (R-VER-5).

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |

No run of the current model is recorded yet. Earlier runs of a previous revision are not
cited (R-VER-5); the CI run of this change and the long runs on the maintainer's machines
will be entered here with the model hash.
