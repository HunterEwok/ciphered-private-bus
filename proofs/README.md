<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Tamarin models

The cryptographic protocol models of verification level V1 (Section 14 of the
[specification](../docs/spec/requirements.md)). Each folder holds one model, its `checks.json` (probes
and the CI subset) and a `README.md` with its lemmas, probes and results. [`run-tamarin.sh`](run-tamarin.sh)
runs any of them; `.github/workflows/proofs.yml` runs every lemma and every probe of every model.

| Model | Protocol |
| --- | --- |
| [pairing](pairing) | pairing with CPace, the join request, the passport, direct pairing by the Root |
| [hello](hello) | the link hello and its authentication |
| [channels](channels) | sealing key claims, channel key grants and requests, publications |
| [calls](calls) | nonces, calls, replies and streams |
| [root](root) | root change, recovery and halt proofs |
| [quantum](quantum) | sealing with X-Wing against a quantum adversary |

## Coverage

Every requirement whose verification method names Tamarin, and where it is shown. In every model the
network is the Dolev-Yao adversary, which is the transport assumption of R-ARC-5.

| Requirement | Model | Lemmas |
| --- | --- | --- |
| R-ARC-5 | all | every lemma: the adversary controls the network |
| R-FMT-6 | root | `halt_proof_authentic` (with `PROBE_NO_LABEL`): labels and the head and rest hashes |
| R-FMT-9 | root | `join_authentic` |
| R-MEM-11 | root | `root_change_authentic`, `root_change_quantum` |
| R-JOIN-1 | pairing | `acceptor_key_secrecy`, `joiner_key_secrecy`, `joiner_agreement`, `acceptor_agreement` |
| R-JOIN-2 | pairing, root | `bus_authenticity`; `join_authentic` |
| R-JOIN-3 | pairing | see the note below |
| R-JOIN-6 | pairing, root | `admission_via_request`, `admission_direct`; `old_root_powerless` |
| R-JOIN-9 | pairing | `admission_direct` |
| R-KEY-2 | channels, calls, quantum | `channel_key_secrecy` (with `PROBE_UNSIGNED_CLAIM`), `command_secrecy`, `harvest_now_decrypt_later` |
| R-KEY-8 | all | every signature and derivation carries its own label; `PROBE_NO_LABEL` (root) shows a defect when one is missing; `key_separation` (channels) proves that no content key is a blob key |
| R-KEY-9 | channels, calls | see the note below |
| R-CH-1 | channels | `channel_key_secrecy` |
| R-CH-2 | channels | `channel_key_secrecy`, `grant_authenticity` |
| R-CH-3 | channels | `content_secrecy`, `blob_secrecy` (with `PROBE_BLOB_KEY_IN_CLEAR`), `content_key_unique` (with `PROBE_KEY_NO_HEADER`), `blob_key_unique` (with `PROBE_BLOB_KEY_FROM_K`), `key_separation` |
| R-CH-4 | channels | `grant_authenticity`, `source_authenticity` |
| R-CH-5 | channels | `channel_key_secrecy`: a reader the source no longer names does not learn the new key; when to rotate is the state model's |
| R-CH-18 | channels | `request_authenticity`, `answer_binding` |
| R-CALL-1 | calls | `at_most_once` |
| R-CALL-2 | calls | `call_integrity_auto` |
| R-CALL-3 | calls | `command_secrecy` |
| R-CALL-4 | calls | `call_integrity_auto`, `call_integrity_confirm` (with `PROBE_CONFIRM_DEVICE_KEY` and `PROBE_CLASS_FROM_CALL`) |
| R-CALL-9 | calls | `reply_secrecy`, `reply_binding` |
| R-STR-1 | calls | `reply_secrecy`, `stream_secrecy`, `stream_binding` |
| R-STR-2 | calls | `stream_binding` |
| R-REL-1 | hello | `peer_authentic`, `no_self_connection`, `no_downgrade`, `one_accept_per_hello` |
| R-API-3 | calls | `call_integrity_confirm` (with `PROBE_CONFIRM_DEVICE_KEY` and `PROBE_CLASS_FROM_CALL`) |

R-FMT-15 is verified by the release process; the property it states for the hello, that the version list
cannot be downgraded, is `no_downgrade` in the hello model.

**R-JOIN-3.** A symbolic model cannot express how many password guesses a run allows: the pairing code is
a value the adversary either has or does not. The pairing model shows that the pairing keys stay secret
and both sides agree on the run unless the code leaked; that a failed run allows at most one guess is the
security bound of CPace, and the number of attempts per code is checked by the enrollment model in
[models/enrollment](../models/enrollment).

**R-KEY-9.** A symbolic model has no AEAD nonces, so nonce reuse is not expressed directly. What the
models show is the first half of the requirement: every key used with nonce zero is derived from inputs
unique to one message. A publication key comes from the channel key and the publication header with its
number, and `content_key_unique` proves that no two publications share it (channels; the model draws the
number fresh, and that numbers do not repeat is the state model's; `PROBE_KEY_NO_HEADER` falsifies it).
A blob key is 32 random bytes drawn for one blob, and `blob_key_unique` proves that no two blobs share
it (channels; `PROBE_BLOB_KEY_FROM_K` derives the key from the channel key alone and falsifies it).
A call's reply and stream keys are exported from the HPKE context of that call, and `reply_key_unique`
proves that no two calls share a reply key (calls; `PROBE_SHARED_REPLY_KEY` derives the key from a secret
shared by every call to one sealing key and falsifies it). The second half, that the nonce of a stream
chunk equals its number and never repeats, is for the streams state model and code review.
