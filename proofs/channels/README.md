<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Channel key and publication model

A Tamarin [model](channels.spthy) of channel keys and publications (verification level V1 of the
[specification](../../docs/spec/requirements.md), Section 14; R-KEY-2, R-CH-1..4, R-CH-7; Appendix B,
Sections B.3, B.5 and B.8; R-CH-18): the sealing key claim, the key grant sealed to the reader, the key
request and the grant that answers it, and the publication, whose content and blob are encrypted under keys
derived from the channel key and the header with different labels. The network is the Dolev-Yao
adversary; it may in addition reveal device signing keys, sealing keys a node still holds, and
channel keys held by the source or a reader. Membership, rights and freshness are left to the state
models in [models/](../../models). That a key request names the reader's current sealing key and that
the source answers only a reader that still holds the right (R-CH-18) is checked by the channels state
model, [models/channels](../../models/channels) (scenario `keyRequestTest`). The header of `channels.spthy` lists every abstraction.

## Lemmas

| Lemma | Requirement | Property |
| --- | --- | --- |
| `executable` | | sanity: a reader accepts a publication with nothing revealed |
| `channel_key_secrecy` | S1, S13, R-CH-2, R-KEY-2 | the channel key is learned only through a reader the source named (its device key revealed before the grant, or a sealing key or channel key revealed before that reader erased it) or from the source itself; signing keys of others, and the reader's device key broken after the grant, do not matter |
| `content_secrecy` | S1, R-CH-3 | the content of a publication is learned only in the same ways |
| `blob_secrecy` | S1, R-CH-3 | the blob of a publication is learned only in the same ways |
| `content_key_unique` | R-CH-3, R-KEY-9 | every publication has its own content key |
| `key_separation` | R-CH-3, R-KEY-8 | no content key is ever a blob key |
| `grant_authenticity` | R-CH-2, R-CH-4 | a reader takes a channel key only from a grant its source made for it on this bus |
| `request_authenticity` | R-CH-18 | the source answers a key request only if the reader made it |
| `answer_binding` | R-CH-18 | a grant carrying the bytes of a reader's request was made by the source in answer to it |
| `source_authenticity` | S2, R-CH-4 | a reader accepts content only as the source published it, even though other readers hold the key |
| `content_agreement` | S3 | two readers of one publication read the same content, even with a compromised source |

Probes, each a deliberate defect selected with `-D`, each expected to falsify its lemma (R-VER-2):

| Probe | Defect | Lemma |
| --- | --- | --- |
| `PROBE_UNSIGNED_CLAIM` | the source seals to a sealing key claim without checking its signature | `channel_key_secrecy` |
| `PROBE_NO_ERASE` | an erased sealing key can still be revealed | `channel_key_secrecy` |
| `PROBE_NO_GRANT_SIG` | the reader does not check the grant signature | `grant_authenticity` |
| `PROBE_PUB_SIG_HEADER` | the publication signature covers the header only | `source_authenticity` |
| `PROBE_REQUEST_UNSIGNED` | the source answers a key request without checking its signature | `request_authenticity` |
| `PROBE_KEY_NO_HEADER` | the content key comes from the channel key alone, not from the header | `content_key_unique` |
| `PROBE_BLOB_SAME_LABEL` | the blob key uses the content key's label | `key_separation` |

`content_agreement` has no probe at this level. Symbolic encryption commits to its key, so the lemma
holds even without the key commitment of R-CH-1; the commitment matters because ChaCha20-Poly1305 does
not commit, which a symbolic model cannot express. That reliance needs a test vector (a ciphertext that
opens under two keys is rejected because the commitment does not match).

[`checks.json`](checks.json) lists the probes and what CI runs: every lemma and every probe.

Tamarin warns that some variables of `Grant`, `GrantOnRequest`, `ReaderGrant` and `ReaderAccept` are not derivable from
their premises. This is intended: signature checks are written as pattern matches on `sign(message,
key)` and `pk(key)`.

## Running

```sh
proofs/run-tamarin.sh -m channels -w <folder> -c          # CI subset
proofs/run-tamarin.sh -m channels -w <folder> -p          # every lemma and every probe
```

## Results

| Date | Model | Run | Result |
| --- | --- | --- | --- |
| 2026-11-21 | `2bb74e27518f` | Tamarin 1.12.0, `run-tamarin.sh -c` (every lemma and every probe), 4 cores, one prover at a time | 8 of 8 lemmas verified, 5 of 5 probes falsified; 2.2 min in total |
