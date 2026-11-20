<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Channels model

A Quint [model](channels.qnt) of channel keys and retention (verification level V2 of the
[specification](../../docs/spec/requirements.md), Section 14): one source and one channel, key
rotation and grants, publication numbers reserved in blocks, the recipient's window and retention
depth, the clearing publication, and reboots of the source and the readers. The network and any relay
are a pool of every publication and grant, so the relay behaves arbitrarily except that it cannot
forge (R-REL-11). The header of `channels.qnt` lists every abstraction.

## Instances

| Instance | Devices | Key generations | Numbers | Depth | Block | Purpose |
| --- | --- | --- | --- | --- | --- | --- |
| `small` | 3 (one without the read right, one late) | 3 | 5 | 0..2 | 2 | Simulator in CI |
| `tiny` | 2 | 2 | 4 | 0..2 | 2 | Simulator in CI, TLC |
| `probe_*` | as `small` | | | | | One deliberate defect each; `safety` must fail (R-VER-2) |

## Properties

| Invariant | Requirement | Property |
| --- | --- | --- |
| `freshness` | R-CH-9, R-CORE-5 | S12: the highest accepted number and generation never decrease, also across reboots |
| `uniqueNumbers` | R-CH-8 | publication numbers increase strictly over the device key's life |
| `uniqueKeys` | R-CH-8 | a key generation is never used for two keys |
| `rotateOnRemove` | R-CH-5 | S5: no device outside the readers holds the key of a new publication |
| `grantsToReaders` | R-CH-13 | keys are granted only to valid readers with the read right |
| `acceptUnderHeldKey` | R-CH-9 | a publication is accepted only under a key the reader holds |
| `retention` | R-CH-10, R-CH-11 | at most `depth` retained publications, all in the window, distinct numbers |
| `noReadNoKey` | R-CH-13 | a device without the read right never holds a key |

Step properties are checked by a monitor when the step is taken, as in the membership model.

Probes, each expected to violate `safety`:

| Probe | Defect |
| --- | --- |
| `no_rotate_on_remove` | A device leaves the readers and the source does not mark the key for rotation |
| `mark_not_persisted` | The rotation mark is lost in a reboot |
| `grant_removed` | The source grants the key to a device outside the readers |
| `grant_no_read` | The source grants the key to a device without the read right |
| `no_block_skip` | After a reboot the source reuses numbers of the reserved block |
| `gen_not_persisted` | A reboot loses the latest key generation |
| `accept_old_grant` | A reader accepts a grant of a lower generation |
| `accept_without_key` | A reader accepts a publication under a key it does not hold |
| `empty_no_clear` | The clearing publication does not clear the retained publications |
| `refill_moves_high` | A refill from the window moves the highest number back |
| `high_not_persisted` | A reader loses its highest number in a reboot |
| `no_trim` | A reader retains more publications than the depth |

`empty_no_clear`, `refill_moves_high`, and `no_trim` need a long specific sequence and are checked by
fixed scenarios in [`scenarios.qnt`](scenarios.qnt), which also show that refill after a reboot,
shrinking the depth, clearing, and rotation after a removal are reachable with `safety` intact.

The model found a gap in the specification: a source that rebooted with its key intact no longer
knew whom it had granted the key, and published under it to a device that had left the readers. The
source now persists a rotation mark set in the same event in which a device leaves (R-CH-5,
R-CORE-5); the probe `mark_not_persisted` removes it.

## Running

```sh
python3 models/channels/check.py    # CI run
```

```powershell
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model channels -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model channels -Probes -WorkDir <folder> -Java <path to java>
```

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |

No run is recorded yet.
