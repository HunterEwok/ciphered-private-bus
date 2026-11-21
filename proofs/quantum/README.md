<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Quantum adversary model

A Tamarin [model](quantum.spthy) of sealing with X-Wing against a quantum adversary (verification level
V1 of the [specification](../../docs/spec/requirements.md), Section 14.1: "the quantum adversary is
described by separate lemmas"; S1, S13, R-KEY-2, R-KEY-6, L2). Every envelope of the bus that carries a
secret (key grant, call, join request) is HPKE with the X-Wing KEM to a sealing key whose claim the device
key signed. The other models treat that KEM as one perfect primitive; this model keeps the one step and
opens up the KEM: the ML-KEM-768 part is asymmetric encryption of a fresh secret, the X25519 part is
Diffie-Hellman, and the shared secret is the X-Wing combiner of both
(draft-connolly-cfrg-xwing-kem-11).

The quantum adversary may act at any point of the trace. It obtains every X25519 private key and every
ES256 signing key, including keys already erased, since it computes them from public keys; it never
obtains an ML-KEM key. A classical compromise reveals a whole sealing private key the node still holds,
or a device key. The header of `quantum.spthy` lists every abstraction.

## Lemmas

| Lemma | Requirement | Property |
| --- | --- | --- |
| `executable` | | sanity: a receiver opens a sealed envelope with nothing revealed |
| `harvest_now_decrypt_later` | S1, R-KEY-6 | a sealed secret is learned only with the receiver's whole sealing key, or by an adversary that could sign claims for the receiver before the secret was sealed; a quantum computer that comes after the envelope was recorded does not open it |
| `forward_secrecy` | S13 | the same once the receiver has erased the sealing key, even with a classical compromise of the node and a later quantum computer |
| `quantum_active_reads` | L2 | a quantum computer at work before the envelope is sealed forges the receiver's claim and reads what is sealed to its key: a stated limitation, so the trace must exist |

Probes, each a deliberate defect selected with `-D`, each expected to falsify its lemma (R-VER-2):

| Probe | Defect | Lemma |
| --- | --- | --- |
| `PROBE_X25519_ONLY` | the shared secret is X25519 alone, the classical-only sealing that R-KEY-6 forbids | `harvest_now_decrypt_later` |
| `PROBE_NO_ERASE` | an erased sealing key can still be revealed | `forward_secrecy` |

[`checks.json`](checks.json) lists the probes and what CI runs: every lemma and every probe.

Tamarin warns that a variable of `Seal` is not derivable from its premises. This is intended: the claim
signature check is a pattern match on `sign(message, key)` and `pk(key)`.

## Running

```sh
proofs/run-tamarin.sh -m quantum -w <folder> -c          # CI subset
proofs/run-tamarin.sh -m quantum -w <folder> -p          # every lemma and every probe
```

## Results

| Date | Model | Run | Result |
| --- | --- | --- | --- |
| 2026-11-21 | `a889f98c7d07` | Tamarin 1.12.0, `run-tamarin.sh -c` (every lemma and every probe), 4 cores, one prover at a time | 4 of 4 lemmas verified, 2 of 2 probes falsified; 0.4 min in total |
