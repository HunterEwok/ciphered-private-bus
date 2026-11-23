<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Link hello model

A Tamarin [model](hello.spthy) of the link hello (verification level V1 of the
[specification](../../docs/spec/requirements.md), Section 14; R-REL-1, R-FMT-15; Appendix B, Section
B.4; S14): both sides send a `Hello` with their supported versions, a fresh nonce, the bus, the root
generation, the checkpoint number and their device identifier, present their passport, and send `Auth`,
a device key signature over `cpb hello v1 || 0x00 || SHA-256(own hello) || SHA-256(peer's hello)`. The
network is the Dolev-Yao adversary; it may in addition reveal device keys and the root key of a bus. A
relay presents its ticket instead of a passport; the model has one root-signed credential for both.
Revocation, generations and the exchange of control-plane objects before the hello are left to the state
model in [models/membership](../../models/membership). The header of `hello.spthy` lists every
abstraction.

## Lemmas

A key counts against a property only if it was revealed before the event.

| Lemma | Requirement | Property |
| --- | --- | --- |
| `executable` | | sanity: two devices accept each other, with nothing revealed |
| `peer_authentic` | S14, R-REL-1, R-ARC-5 | a side accepts a peer only if that peer signed exactly these two hellos after it received this side's hello, so with this side's fresh nonce; an `Auth` reflected between two devices is rejected |
| `no_self_connection` | R-REL-1, B.4 | a side never accepts a link with itself, even when the adversary reflects its own hello and `Auth` back to it |
| `no_downgrade` | R-FMT-15 | a side that accepts a peer saw the version list the peer sent, and the peer saw the list this side sent, so both select the same version |
| `one_accept_per_hello` | R-REL-1 | each hello is accepted at most once: a recorded hello and `Auth` cannot be replayed |

Probes, each a deliberate defect selected with `-D`, each expected to falsify its lemma (R-VER-2):

| Probe | Defect | Lemma |
| --- | --- | --- |
| `PROBE_NO_PEER_HELLO` | `Auth` signs the own hello only, not the peer's, so not the peer's nonce | `peer_authentic` |
| `PROBE_NO_VERSIONS` | the hello hash leaves out the version list | `no_downgrade` |
| `PROBE_SELF_HELLO` | a hello that names the receiver's own device or repeats its nonce is not rejected | `no_self_connection` |

[`checks.json`](checks.json) lists the probes and what CI runs: every lemma and every probe.

Tamarin warns that some variables of the receiving rules are not derivable from their premises. This is
intended: signature checks are written as pattern matches on `sign(message, key)` and `pk(key)`.

## Running

```sh
proofs/run-tamarin.sh -m hello -w <folder> -c          # CI subset
proofs/run-tamarin.sh -m hello -w <folder> -p          # every lemma and every probe
```

## Results

| Date | Model | Run | Result |
| --- | --- | --- | --- |
| 2026-11-23 | `30a7b40c8eee` (commit 6c43fea) | Tamarin 1.12.0, `run-tamarin.sh -c` (every lemma and every probe), 4 cores, one prover at a time | 5 of 5 lemmas verified, 3 of 3 probes falsified; 0.3 min in total |
