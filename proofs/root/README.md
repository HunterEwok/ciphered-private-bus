<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Root change, recovery and halt proof model

A Tamarin [model](root.spthy) of the root change and recovery (verification level V1 of the
[specification](../../docs/spec/requirements.md), Section 14; R-MEM-8, R-MEM-10, R-MEM-11, R-MEM-13,
R-JOIN-2, R-FMT-9, R-KEY-12; Appendix B, Sections B.1, B.3 and B.8; S8, S9, L2): the bus identifier binds the first root
key and both halves of the recovery key, a root change record signed by K1 and K2 designates the root key
of a new generation, the root signs passports and checkpoints of its generation and, on request of the
application, application data with a tag, and a halt proof of two records with one head halts a node.
The application data and the tag are chosen by the adversary, so the root is a signing oracle for any
input. The network is the Dolev-Yao adversary; it may in addition reveal the
root key of any generation and either half of the recovery key. A quantum adversary is modelled as one
that obtains every classical signing key of the bus (the root keys and K1, ECDSA P-256) but not K2
(SLH-DSA). Which generation is current, counters, revocation and the effects of a halt are left to the
state model in [models/membership](../../models/membership). The header of `root.spthy` lists every
abstraction.

## Lemmas

In every property a key counts only if it was revealed before the event: a key broken later does not
undo what a node accepted.

| Lemma | Requirement | Property |
| --- | --- | --- |
| `executable` | | sanity: a node accepts a root change and then a checkpoint of the new root, with nothing revealed |
| `executable_halt` | | sanity: a root that signs two records with one head halts a node, with nothing revealed |
| `executable_permanent_halt` | | sanity: a recovery key that signs two root change records of one generation halts a node permanently |
| `join_authentic` | S4, S9, R-JOIN-2, R-FMT-9 | a joiner takes as the first root key and the recovery key exactly those of the bus it paired with |
| `root_change_authentic` | S9, R-MEM-11 | a node takes a root key for a generation only from the recovery key of its bus, unless both halves were known |
| `root_change_quantum` | S9, Section 14.1 | against a quantum adversary, with every classical key forgeable, a root change still needs K2 |
| `old_root_powerless` | S9, R-MEM-12 | a passport or checkpoint of a generation is accepted only as the root of that generation signed it; earlier root keys do not matter |
| `quantum_forges_records` | L2 | a quantum adversary forges records of the current root: a stated limitation, so the trace must exist |
| `halt_proof_authentic` | S8, R-MEM-8, Section 15.5 | a halt proof convicts the root of its generation: it signed two records of one kind with that head |
| `permanent_halt_authentic` | S8, R-MEM-13, L6 | a permanent halt proof convicts the recovery key: it signed two root change records of one generation |
| `app_signature_authentic` | R-KEY-12 | a node accepts application data of a generation only as the root of that generation signed it; a signature of the previous root does not verify after a root change |
| `app_signature_reachable` | | sanity: a node verifies signed application data, with nothing revealed |

Every lemma holds with the application signing oracle present: whatever the adversary has the root sign
as application data is never accepted as a passport, a checkpoint, a root change record or a halt proof
(R-KEY-8, R-KEY-12).

Probes, each a deliberate defect selected with `-D`, each expected to falsify its lemma (R-VER-2):

| Probe | Defect | Lemma |
| --- | --- | --- |
| `PROBE_K1_ONLY` | a root change record is accepted with K1 alone | `root_change_quantum` |
| `PROBE_K2_ONLY` | a root change record is accepted with K2 alone | `root_change_authentic` |
| `PROBE_ROOT_ANY_GEN` | a record is accepted from the root of any accepted generation | `old_root_powerless` |
| `PROBE_NO_BUS_CHECK` | the joiner does not check the bus identifier | `join_authentic` |
| `PROBE_HALT_SAME_REST` | a halt proof is accepted with two equal rests | `halt_proof_authentic` |
| `PROBE_NO_LABEL` | records are signed without the label of their kind, so a passport and a checkpoint with one number make a halt proof | `halt_proof_authentic` |
| `PROBE_APP_SAME_LABEL` | application data is signed with the passport label and in the passport's shape, so the adversary has the root sign a passport | `old_root_powerless` |

`PROBE_K1_ONLY` and `PROBE_K2_ONLY` together show that the root change is a hybrid: either half alone
opens the bus. `PROBE_ROOT_ANY_GEN` adds restrictions to one bus, one root change and one node, which is
all its attack needs; a restriction only removes traces, so the trace found is also a trace of the
unrestricted model.

The root generation inside the signed application data has no probe. Every generation has its own fresh
root key here, so a signature of the previous root already fails at the new generation because the key
differs: a probe that leaves the generation out still verifies `app_signature_authentic`. The generation
guards a node that verifies against an older root key by mistake, which is a defect of the node, not a
property of the protocol.

[`checks.json`](checks.json) lists the probes and what CI runs: every lemma and every probe.

Tamarin warns that some variables of the node rules are not derivable from their premises. This is
intended: signature checks are written as pattern matches on `sign(message, key)` and `pk(key)`.

## Running

```sh
proofs/run-tamarin.sh -m root -w <folder> -c          # CI subset
proofs/run-tamarin.sh -m root -w <folder> -p          # every lemma and every probe
```

## Results

| Date | Model | Run | Result |
| --- | --- | --- | --- |
| 2026-11-28 | `41264aab70c3` (commit 699df97) | Tamarin 1.12.0, `run-tamarin.sh -p` (every lemma and every probe), maintainer's server, 13 provers at a time, 2 cores and 8 GB each | 12 of 12 lemmas verified, 7 of 7 probes falsified; 0.1 to 1.0 min each, 1 min in total |
