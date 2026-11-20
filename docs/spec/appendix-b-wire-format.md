<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Ciphered Private Bus (CPB): Appendix B, Wire Format

- **Status:** Draft, baseline for gate G0. Companion to the
  [Protocol Requirements Specification](requirements.md).
- **Date:** 2026-11-20
- **Author:** Evgenii Russkikh

## Abstract

This appendix defines the message kinds, the fields of every object with their numbers and sizes, the
binary frames, the list of domain separation labels, and the size analysis of the CPB wire format. Field
and type names follow the [Glossary](glossary.md). The appendix introduces no new mechanisms. The places
where writing out the fields required a decision are collected in Section B.9.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown
here. The references cited in this appendix are listed in Section 16 of the requirements specification.

## B.1. Conventions

- Field types: `uint` unsigned integer, `bstr(n)` byte string of length n, `bstr(≤n)` byte string of at
  most n bytes, `tstr` UTF-8 text string, `array`, `map`.
- Every object is a map with integer keys. Field numbers are local to each object and start at 1. Key 0
  holds the message kind `t`.
- A field marked "optional" is absent when it has no value. An empty value is never written.
- A key is encoded as `Key = [alg, bytes]`.
- A signed object is an envelope `[body, sig]` or `[body, sig, sig2]`. The signature is computed over
  `label || 0x00 || encode(body)`.
- An object with a public and a sealed part (key grant, publication) is a triple `[header, sealed, sig]`.
  The signature is computed over `label || 0x00 || SHA-256(encode(header)) || SHA-256(sealed)`.
- A signed object inside a message is carried as a byte string: `{0: t, 1: bstr(object)}`. Nesting depth
  is therefore counted afresh for the object (R-FMT-4).
- Sizes are given in bytes of the encoded form, rounded up.

**Records with a head.** A passport, a checkpoint, and a root change record are not envelopes but
triples `[head, rest, sig]`: `head` carries the bus, the generation, and the number; `rest` carries
everything else. The signature is computed over
`label || 0x00 || SHA-256(encode(head)) || SHA-256(encode(rest))`, the same construction as for a
publication. The identifier of such a record is
`SHA-256(SHA-256(encode(head)) || SHA-256(encode(rest)))`. Rationale: two conflicting records with the
same number are then proven by one short `HaltProof` message (Section B.3), which needs neither full
body and does not depend on delivery order. Equivocation evidence in Certificate Transparency [RFC6962]
(the signed tree head) and in Tendermint works the same way.

Encoding rules common to all sections:

- An unsigned message (`Hello`, `Auth`, `Get`, `BlobGet`, `NonceRequest`, `Nonce`, `Reply`, `Refusal`,
  `RelayRefusal`, `HaltProof`, `Pair*`) places its fields directly in the top-level map next to `0: t`.
  A signed object is carried as a byte string in field 1.
- In every hash and fingerprint formula a key is taken in its encoded form,
  `encode(Key) = encode([alg, bytes])`. The algorithm is thereby part of the identifier, and keys of
  different algorithms with identical bytes never collide.
- "The map of fields i..j" is the object's map with only the fields of those numbers retained and
  without key 0. For map objects, the AEAD associated data is always `SHA-256(encode(that map))`.
- HKDF-SHA256 is always invoked with an empty salt (per [RFC5869], equivalent to 32 zero bytes). What
  the formulas call "key" is the input keying material.
- Integers assembled from hash bytes, and all integers in binary headers, are big-endian. The
  ChaCha20-Poly1305 nonce is 12 bytes: the number or counter is written into the trailing bytes,
  big-endian, and the remaining bytes are zero. In binary frames (Section B.7) the associated data is
  the header bytes as they are, without hashing.
- The signature length is determined by the key algorithm. `bstr(64)` in the tables refers to ES256.
- Unused bits in `Passport.rights` (4..7), `StreamChunk.flags` (4..7), and `BlobSegment.flags` (1..7)
  MUST be zero; otherwise the object is rejected.
- A default value (R-FMT-2) exists only for a field marked `.default` in the schema. In version 1 there
  is one such field: `flags` in the publication content. All other fields, when present, are written
  even when zero, for example `Reply.code = 0` and channel 0.
- The CDDL [RFC8610] schema of all objects, the exact maximum sizes, and the script that checks them are
  in [Appendix C](appendix-c-cddl.md). Where numbers disagree, the script's numbers are correct.

## B.2. Message Kinds

A message is a map in a frame whose length field has the high bit 0. Field 0 is the kind `t`.

| `t` | Name | Carries | Layer |
| --- | --- | --- | --- |
| 1 | `Hello` | Versions, random value, bus, generation, checkpoint number, device | Link |
| 2 | `Auth` | Signature over both hellos | Link |
| 3 | `Get` | Request for a control-plane object | Control |
| 4 | `Passport` | Passport | Control |
| 5 | `Checkpoint` | Checkpoint | Control |
| 6 | `RootChange` | Root change record | Control |
| 7 | `SealClaim` | Sealing key claim | Control |
| 8 | `JoinRequest` | Join request | Control |
| 9 | `KeyRequest` | Channel key request | Control |
| 10 | `RelayTicket` | Relay ticket, Section B.10 | Control |
| 11 | `RelayRefusal` | Relay refusal to accept an object, Section B.10 | Control |
| 12 | `HaltProof` | Halt proof: two root signatures over one head and different bodies, Section B.3 | Control |
| 16 | `KeyGrant` | Channel key grant | Data |
| 17 | `Publication` | Publication | Data |
| 18 | `BlobGet` | Request for a blob segment | Data |
| 24 | `NonceRequest` | Request for a call nonce | Data |
| 25 | `Nonce` | The target's current nonce | Data |
| 26 | `Call` | Call | Data |
| 27 | `Reply` | Reply | Data |
| 28 | `Refusal` | Public refusal | Data |
| 40..47 | reserved | Pairing messages, Section B.11. 40..45 are assigned; the rest are reserved | Link |

Kinds 13..15, 19..23, 29..39, and 48..255 are unassigned. An unknown kind is rejected with code
`fmt/kind`.

## B.3. Control-Plane Objects

### Passport (`Passport`)

A triple `[head, rest, sig]`, signed by the Root, label `cpb passport v1`. Fields 1–3 form `head`;
fields 4–7 form `rest`.

| No. | Field | Type | Size | Notes |
| --- | --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | 35 | |
| 2 | `gen` | uint | ≤ 6 | Root generation |
| 3 | `no` | uint | ≤ 6 | Passport number |
| 4 | `device_key` | Key | 70 | P-256, 65 bytes |
| 5 | `rights` | bstr(1) | 3 | Bit 0 read, 1 publish, 2 relay, 3 accept join requests |
| 6 | `presence_key` | Key | 70 | Optional |
| 7 | `permits` | array ≤ 128 | ≤ 4611 | Element `[commander bstr(16), auto bstr(8), confirm bstr(8)]`, 36 bytes |

Largest passport: 4877 bytes (4.8 KiB) with an ES256 signature.

### Checkpoint (`Checkpoint`)

A triple `[head, rest, sig]`, signed by the Root, label `cpb checkpoint v1`. Fields 1–3 form `head`;
fields 4–8 form `rest`.

| No. | Field | Type | Size | Notes |
| --- | --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | 35 | |
| 2 | `gen` | uint | ≤ 6 | |
| 3 | `no` | uint | ≤ 6 | Checkpoint number |
| 4 | `window_start` | uint | ≤ 6 | Passport number that bit 0 of the bitmap refers to |
| 5 | `valid_bits` | bstr(8..4096) | ≤ 4100 | Bit i refers to passport `window_start + i` |
| 6 | `next_passport_no` | uint | ≤ 6 | |
| 7 | `relays` | array ≤ 128 of bstr(16) | ≤ 2179 | Relay identifiers |
| 8 | `root_device` | bstr(16) | 18 | |

Largest checkpoint: 6432 bytes (6.3 KiB) with an ES256 signature.

### Root Change Record (`RootChange`)

A quadruple `[head, rest, sig, sig2]`: `sig` is by K1, `sig2` is by K2. Label `cpb root change v1`.
Fields 1–2 form `head`; field 3 forms `rest`.

| No. | Field | Type | Size | Notes |
| --- | --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | 35 | |
| 2 | `gen` | uint | ≤ 6 | New generation |
| 3 | `root_key` | Key | 70 | Key of the new Root |

Size: 8046 bytes (7.9 KiB), of which 7856 bytes are the K2 signature.

### Halt Proof (`HaltProof`)

An unsigned message, `t = 12`, with its fields next to `0: t`. It is verified by the signatures it
contains, so it depends neither on who sent it nor on delivery order.

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `kind` | uint | Kind of the records: 4 passport, 5 checkpoint, 6 root change record |
| 2 | `head` | bstr | The encoded head shared by both records: bus, generation, and number (for a root change record, bus and generation) |
| 3 | `rest_a` | bstr(32) | SHA-256 of `encode(rest)` of the first record |
| 4 | `sigs_a` | array of bstr | Signatures of the first record: one, or two (K1 and K2) for a root change record |
| 5 | `rest_b` | bstr(32) | The same for the second record. MUST differ from `rest_a` |
| 6 | `sigs_b` | array of bstr | Signatures of the second record |

Rules:

1. A proof is valid if `rest_a` and `rest_b` differ and all signatures are valid for the same `head`. A
   passport and a checkpoint are verified with the root key of the generation named in `head`; a root
   change record with K1 and K2.
2. A node that receives a valid proof for its bus MUST enter the halted state (R-MEM-8, R-MEM-13),
   whatever checkpoint it is at. It stores the proof and sends it on every link (R-MEM-10). A halted
   node answers a call, a nonce request, and every message that carries a pair of its generation with
   this same message (R-MEM-6).
3. A proof for a passport or checkpoint of a generation lower than the current one has no effect: that
   generation has already been replaced by a root change. A proof of a generation higher than the
   current one cannot be verified yet and is dropped; the node obtains the root change record as for
   any object of a new generation, and once it has moved to that generation, its next message to a
   halted peer brings the proof again (R-MEM-6). The core keeps no proof waiting.
4. A node constructs a proof itself when it receives a record with a valid signature and the same `head`
   as a record it stores, but with a different `rest`.
5. A relay verifies the proof, stores one per bus outside the data quota, and delivers it to every
   device of the bus together with the control-plane objects.

Size: about 260 bytes with ES256 signatures, and 15974 bytes (410 bytes of headroom) with post-quantum
signatures; it therefore always fits in a frame.

### Sealing Key Claim (`SealClaim`)

An envelope `[body, sig]`, signed by the device key, label `cpb seal claim v1`.

| No. | Field | Type | Size | Notes |
| --- | --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | 35 | |
| 2 | `device` | bstr(16) | 18 | |
| 3 | `epoch` | uint | ≤ 6 | |
| 4 | `seal_key` | Key | 1222 | X-Wing, 1216 bytes |

Size: 1356 bytes (1.3 KiB).

### Join Request (`JoinRequest`)

An envelope `[body, sig]`, signed by the acceptor, label `cpb join request v1`.

| No. | Field | Type | Size | Notes |
| --- | --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | 35 | |
| 2 | `acceptor` | bstr(16) | 18 | |
| 3 | `gen` | uint | ≤ 6 | |
| 4 | `cp_no` | uint | ≤ 6 | The acceptor's checkpoint |
| 5 | `epoch` | uint | ≤ 6 | Sealing key epoch of the root device |
| 6 | `enc` | bstr | ≤ 1450 | HPKE: the 1120-byte X-Wing ciphertext and the sealed body. Associated data: SHA-256 of the encoded map of fields 1..5 |

Sealed body:

| No. | Field | Type | Size | Notes |
| --- | --- | --- | --- | --- |
| 1 | `joiner_key` | Key | 70 | The joiner's device key |
| 2 | `name` | tstr, 1..64 bytes | ≤ 67 | |
| 3 | `pairing_hash` | bstr(32) | 35 | |
| 4 | `presence_key` | Key | 70 | Optional. Taken from `PairDevice`; the Root enters it into the passport |
| 5 | `joiner_sig` | bstr | 67 | The joiner's signature from `PairDevice`. It covers the device key, the user-presence key, and the name, so the acceptor cannot substitute any of them. The Root rebuilds the map of fields 1..3 of `PairDevice` from `joiner_key`, `presence_key`, and `name`, verifies the signature with `joiner_key` over `bus` and `pairing_hash`, and does not show the request to the owner without a valid signature |

Join request size: about 1.6 KiB.

### Channel Key Request (`KeyRequest`)

An envelope `[body, sig]`, signed by the reader, label `cpb key request v1`.

| No. | Field | Type | Size | Notes |
| --- | --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | 35 | |
| 2 | `source` | bstr(16) | 18 | |
| 3 | `reader` | bstr(16) | 18 | |
| 4 | `label` | bstr(16) | 18 | Channel label |
| 5 | `epoch` | uint | ≤ 6 | The reader's current sealing key epoch |
| 6 | `nonce` | bstr(16) | 18 | |

### Control-Plane Object Request (`Get`)

An unsigned message.

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | The bus whose object is requested. Needed because the request may precede the hello and an external relay serves many buses |
| 2 | `what` | uint | 1 passport, 2 checkpoint, 3 latest root change record, 4 sealing key claim, 5 relay ticket |
| 3 | `device` | bstr(16) | For a passport and a sealing key claim. For a ticket, the relay identifier |

**Who is answered.** The request is unsigned, so the right to an answer comes from the link, not from
the message. A `Get` is answered in three cases: the parties have completed the hello; the requester has
previously sent, on this link, a `Passport` message with a valid root signature of any generation of
this bus (this is how a node with an old passport catches up with a root change, R-REL-1); or pairing
has just completed successfully on this link and the joiner is the requester (this is how it obtains
the root change record and the checkpoint, Section B.11). In all other cases a `Get` is left
unanswered. A relay hands out its ticket (`what = 5`) to anyone who names the bus: the ticket is needed
before the hello and contains nothing but the server key and the limits.

## B.4. Link

### Hello (`Hello`)

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `versions` | array of uint, each version ≥ 1 | Supported versions. The list MUST be non-empty and strictly increasing; otherwise the hello is rejected |
| 2 | `nonce` | bstr(16) | |
| 3 | `bus` | bstr(32) | |
| 4 | `gen` | uint | |
| 5 | `cp_no` | uint | |
| 6 | `device` | bstr(16) | |

### Authentication (`Auth`)

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `sig` | bstr(64) | Device key signature over `cpb hello v1 \|\| 0x00 \|\| SHA-256(own hello) \|\| SHA-256(peer's hello)` |

The selected version is the highest version common to both lists. The lists are covered by the
signature through the hashes of the hellos.

## B.5. Channels

### Channel Key Grant (`KeyGrant`)

A triple `[header, wrap, sig]`, signed by the source, label `cpb key grant v1`.

| No. | Field | Type | Size | Notes |
| --- | --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | 35 | |
| 2 | `source` | bstr(16) | 18 | |
| 3 | `key_gen` | uint | ≤ 6 | Channel key generation |
| 4 | `gen` | uint | ≤ 6 | |
| 5 | `cp_no` | uint | ≤ 6 | |
| 6 | `label` | bstr(16) | 18 | |
| 7 | `reader` | bstr(16) | 18 | |
| 8 | `epoch` | uint | ≤ 6 | The reader's sealing key epoch |
| 9 | `commit` | bstr(32) | 35 | Channel key commitment |
| 10 | `req_nonce` | bstr(16) | 18 | Optional, taken from the key request |

`wrap` is a bstr(1168): the 1120-byte X-Wing ciphertext, the 32-byte channel key, and the 16-byte
authentication tag. HPKE info `cpb grant seal v1`; associated data `SHA-256(encode(header))`. Grant
size: about 1.4 KiB.

### Publication (`Publication`)

A triple `[header, content, sig]`, signed by the source, label `cpb publication v1`.

| No. | Field | Type | Size | Notes |
| --- | --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | 35 | |
| 2 | `source` | bstr(16) | 18 | |
| 3 | `key_gen` | uint | ≤ 6 | |
| 4 | `pub_no` | uint | ≤ 10 | Up to 2^53 - 1 |
| 5 | `gen` | uint | ≤ 6 | |
| 6 | `cp_no` | uint | ≤ 6 | |
| 7 | `label` | bstr(16) | 18 | |
| 8 | `commit` | bstr(32) | 35 | |
| 9 | `depth` | uint | ≤ 4 | 0..1024 |
| 10 | `blob` | `[size uint, hash bstr(32), seg uint]` | ≤ 48 | Optional; see below |

The `blob` field:

- `size` is the total ciphertext length of all segments, at least 17.
- `seg` is the ciphertext length of every segment except the last, from 1024 to 16346. The lower bound
  of 1024 keeps the authentication tag and the frame header (54 bytes) at about 5% of a segment; without
  it a source could cut a blob into one-byte segments and force readers and relays to serve millions of
  them. A blob shorter than `seg` consists of a single segment of any length.
- `hash` is SHA-256 over the ciphertexts of segments 0..N-1, concatenated without frame headers.
- Segment i starts at byte i × `seg`; the number of segments is N = ceil(`size` / `seg`).
- The publication is rejected if `size` mod `seg` is in 1..16 (the last segment would be shorter than
  the authentication tag) or if N exceeds 2^31 - 1 (the segment number is a 4-byte AEAD nonce, Section
  13.1 of the requirements specification).

`content` is the ChaCha20-Poly1305 ciphertext with an all-zero nonce and associated data
`SHA-256(encode(header))`. The plaintext:

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `channel` | uint | Channel number, 0..65535 |
| 2 | `flags` | uint | Always 0 in version 1; the field is omitted |
| 3 | `data` | bstr(≤ 4096) | Optional |
| 4 | `pad` | bstr | Optional: absent when its length would be zero. Zero bytes. The length of `data` plus `pad` equals a padding bucket and does not exceed 4096: the largest bucket equals the largest data. A publication with a greater length or with a non-zero padding byte is rejected |

Largest publication: about 4.3 KiB. The retention depth of a channel is set by the latest accepted
publication: when the depth decreases, surplus older publications are deleted immediately. A clearing
publication that arrives late, in the window, clears the publications up to its number; a publication of
depth 0 is accepted only as a new one, and neither is retained (R-CH-10). A publication
under a key the recipient does not hold is dropped without a state change and triggers one key request
per channel. Whoever sends or forwards a grant to a reader sends the retained publications of that
channel under that key immediately after it, so what was dropped arrives again.

### Blob Segment Request (`BlobGet`)

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | |
| 2 | `pub_id` | bstr(32) | `SHA-256(encode(header))` of the publication |
| 3 | `segment` | uint | Segment number from 0, at most 2^31 - 2 |

### Node Info (`NodeInfo`)

The content of the `data` field of a publication in channel 0 (R-CH-16). The core itself publishes it
after enrollment and after the "set node name" operation (R-API-2). The retention depth of channel 0 is
1: a new node info replaces the previous one.

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `name` | tstr, 1..64 bytes | Node name. The initial value comes from pairing (`PairDevice` field 3) |

Further fields go into the extension range 256..65535. The largest size without extensions is 68 bytes.

## B.6. Calls

### Nonce Request and Nonce (`NonceRequest`, `Nonce`)

Unsigned messages. `NonceRequest`: 1 `bus`, 2 `commander` bstr(16), 3 `target` bstr(16). `Nonce`: the
same three fields and 4 `nonce` bstr(16).

### Call (`Call`)

An envelope `[body, sig]`, signed by the device key, the user-presence key, or the root key. Label
`cpb call v1`.

| No. | Field | Type | Size | Notes |
| --- | --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | 35 | |
| 2 | `signer` | bstr(32) | 35 | SHA-256 of `encode(Key)` of the signing key |
| 3 | `commander` | bstr(16) | 18 | The commander's device |
| 4 | `target` | bstr(16) | 18 | |
| 5 | `nonce` | bstr(16) | 18 | |
| 6 | `gen` | uint | ≤ 6 | |
| 7 | `cp_no` | uint | ≤ 6 | |
| 8 | `epoch` | uint | ≤ 6 | The target's sealing key epoch |
| 9 | `enc` | bstr | ≤ 5252 | HPKE info `cpb call seal v1`. Associated data: SHA-256 of the encoded map of fields 1..8 |

The command (`Command`) is sealed in `enc`:

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `action` | uint | 1..64 |
| 2 | `args` | bstr(≤ 4096) | Optional |
| 3 | `stream_mode` | uint | Optional: a stream is requested. 1 ordered, 2 lossy |
| 4 | `credit` | uint | The commander's initial credit in bytes, 1..2^32 - 1 (the width of the `credit` field in the chunk header). Mode 1 only. A zero credit is not written; in mode 2 the field is absent, as in `Reply` |

Largest call: 5470 bytes (5.3 KiB) with an ES256 signature, and 13263 bytes if the call is signed by a
post-quantum root key. The call identifier `call_id` is `SHA-256(encode(body))`.

### Reply (`Reply`)

An unsigned message.

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | |
| 2 | `target` | bstr(16) | |
| 3 | `commander` | bstr(16) | |
| 4 | `call_id` | bstr(32) | |
| 5 | `ct` | bstr | ChaCha20-Poly1305 under the reply key, all-zero nonce, associated data: SHA-256 of the encoded map of fields 1..4. Length 37..4411 bytes: plaintext 21..4395 and a 16-byte tag |

Reply plaintext:

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `code` | uint | Required, 0..65535 (R-CALL-11); 0 is written explicitly because the field has no default. Result code, 0 means executed |
| 2 | `msg` | tstr ≤ 256 bytes | Optional |
| 3 | `data` | bstr(≤ 4096) | Optional |
| 4 | `stream_id` | uint | Optional: a stream is open |
| 5 | `credit` | uint | The target's initial credit in bytes, 1..2^32 - 1, together with field 4. A zero credit is not written; in lossy mode the field is absent |
| 6 | `next_nonce` | bstr(16) | |

Bus result codes: 0 executed, 1 not permitted, 2 declined by the user, 3 invalid arguments, 4 action
not supported, 5 too many streams.

### Public Refusal (`Refusal`)

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | |
| 2 | `target` | bstr(16) | |
| 3 | `commander` | bstr(16) | |
| 4 | `call_id` | bstr(32) | |
| 5 | `code` | uint | 1 stale key epoch, 2 nonce mismatch. The target checks the nonce first and the epoch second, so code 1 means the nonce matched and is still valid (R-CALL-13). A halted target answers with a `HaltProof` message instead of a refusal |
| 6 | `claim` | bstr | Code 1 only: the target's sealing key claim |
| 7 | `nonce` | bstr(16) | Code 2 only |

## B.7. Binary Frames

A frame whose length field has the high bit 1. The header is binary, of fixed length, with big-endian
integers. The entire header is the associated data.

### Stream Chunk (`StreamChunk`)

| Offset | Length | Field | Notes |
| --- | --- | --- | --- |
| 0 | 1 | `kind` | 1 |
| 1 | 1 | `flags` | Bit 0 direction (0 from the commander, 1 from the target), bit 1 data, bit 2 credit, bit 3 end |
| 2 | 16 | `target` | |
| 18 | 16 | `commander` | |
| 34 | 4 | `stream_id` | |
| 38 | 4 | `chunk_no` | AEAD nonce |
| 42 | 4 | `credit` | Added credit in bytes; 0 without the credit flag |
| 46 | ≤ 16338 | ciphertext | ChaCha20-Poly1305, ending with the 16-byte authentication tag |

Each direction has its own key and its own chunk counter; the first chunk is number 1 (Section 13.1 of
the requirements specification). A chunk without the data flag also consumes a number; its ciphertext
is just the 16-byte authentication tag.

### Blob Segment (`BlobSegment`)

| Offset | Length | Field | Notes |
| --- | --- | --- | --- |
| 0 | 1 | `kind` | 2 |
| 1 | 1 | `flags` | Bit 0 last segment |
| 2 | 32 | `pub_id` | |
| 34 | 4 | `segment` | AEAD nonce |
| 38 | ≤ 16346 | ciphertext | ChaCha20-Poly1305 under the blob key. The ciphertext of every segment except the last has length `seg` from the publication header; the last is not longer and carries at least one byte of data. The number of segments and the offset of each therefore follow from `size` and `seg` |

## B.8. Labels and Derivations

A label is an ASCII string. It is always followed by the byte 0x00, so no label is a prefix of another
labelled input.

| Label | Used for |
| --- | --- |
| `cpb bus v1` | Bus identifier (R-FMT-9) |
| `cpb passport v1` | Passport signature |
| `cpb checkpoint v1` | Checkpoint signature |
| `cpb root change v1` | K1 and K2 signatures |
| `cpb seal claim v1` | Sealing key claim signature |
| `cpb join request v1` | Join request signature |
| `cpb key request v1` | Key request signature |
| `cpb key grant v1` | Key grant signature |
| `cpb publication v1` | Publication signature |
| `cpb call v1` | Call signature |
| `cpb hello v1` | Hello signature |
| `cpb relay ticket v1` | Relay ticket signature |
| `cpb join seal v1` | HPKE info of the join request |
| `cpb grant seal v1` | HPKE info of the key grant |
| `cpb call seal v1` | HPKE info of the call |
| `cpb reply v1` | Reply key exported from the HPKE context |
| `cpb stream c2t v1` | Stream key, commander to target |
| `cpb stream t2c v1` | Stream key, target to commander |
| `cpb chan label v1` | Channel label |
| `cpb chan commit v1` | Channel key commitment |
| `cpb content v1` | Content key |
| `cpb blob v1` | Blob key |
| `cpb fingerprint v1` | Key fingerprint for comparison |
| `cpb pair v1` | CPace channel identifier |
| `cpb pair hash v1` | Pairing transcript hash |
| `cpb pair device v1` | The joiner's signature in `PairDevice` |
| `cpb pair confirm a v1` | Acceptor confirmation key |
| `cpb pair confirm n v1` | Joiner confirmation key |
| `cpb pair seal a v1` | Encryption key, acceptor to joiner |
| `cpb pair seal n v1` | Encryption key, joiner to acceptor |
| `cpb bus fingerprint v1` | Bus fingerprint shown to the user |

Formulas:

- `DeviceId = SHA-256(encode(device_key))[0..16]`
- `ChannelLabel = SHA-256("cpb chan label v1" || 0x00 || bus || source || channel as 2 bytes)[0..16]`
- `KeyCommit = HKDF-SHA256(key = K, info = "cpb chan commit v1" || 0x00, length 32)`
- `content_key = HKDF-SHA256(key = K, info = "cpb content v1" || 0x00 || pub_id, length 32)`
- `blob_key` is derived the same way, with the label `cpb blob v1`
- `reply_key` and the stream keys: `Context.Export(label || 0x00, 32)` per [RFC9180], Section 5.3
- `KeyFingerprint`: the first 8 bytes of `SHA-256("cpb fingerprint v1" || 0x00 || encode(Key))` as a
  big-endian integer, shown as 20 decimal digits with leading zeros

## B.9. Size Analysis and Decisions

| Object | Largest size now | With a post-quantum root signature (7856 bytes) | Frame of 16384 bytes |
| --- | --- | --- | --- |
| Passport | 4877 bytes, 4.8 KiB | 12670 bytes, 12.4 KiB | Fits |
| Checkpoint | 6432 bytes, 6.3 KiB | 14225 bytes, 13.9 KiB | Fits |
| Root change record | 8046 bytes, 7.9 KiB | 8046 bytes, 7.9 KiB | Fits |
| Call | 5470 bytes, 5.3 KiB | 13263 bytes, 13.0 KiB, if the call is signed by the root key | Fits |
| Publication | about 4.3 KiB | unchanged | Fits |
| Key grant, sealing key claim, join request | up to 1.6 KiB | unchanged | Fits |

The most deeply nested object is the passport: triple, `rest`, permit list, permit. That is depth 4.
The longest arrays are the 128 permits of a passport and the 128 relays of a checkpoint.

Decisions that writing out the fields required:

1. The halt proof is a separate message, `HaltProof` (Section B.3). It carries not two whole records
   but the shared head, two hashes of the rest, and the signatures. Two largest checkpoints would not
   fit in one frame together, so passports, checkpoints, and root change records are signed over the
   hashes of the head and the rest (Section B.1). Without this message, a halt would not reach a node
   that had already moved ahead by number.
2. A permit takes 36 bytes. An earlier estimate of 58 bytes counted an application identifier field
   that no longer exists (D11).
3. The relay list of a checkpoint has at most 128 entries. This is the general container limit; there
   is no separate constant.
4. The reply message `msg` is at most 256 bytes. It is text for a log, not data.
5. The nonce request and the nonce are unsigned: the nonce is not secret, and nonce slots are created
   only for commanders named in a passport (R-CALL-7).
6. There is no "bus halted" result code and no such public refusal: a target reports a halt with a
   `HaltProof`, which can be verified, rather than with a word that has to be trusted. Code 5 "too many
   streams" was added per R-STR-6.

The list of rule codes (`area/rule`) is published together with the test vectors at gate G2: every
code needs a vector, and writing the list without the vectors would mean writing it twice.

## B.10. Relay Ticket and Quota Accounting

This section specifies the relay ticket format and the quota accounting rules that gate G0 required. It
applies only to an external relay, that is, a server that is not a member of the bus. A node with the
relay right has no ticket: its rights are set by its passport, and its memory limits by the application
on that device. The accounting rules are the same for both.

### Relay Identifier and Key

An external relay has a P-256 signing key, one for all the buses it serves. The relay identifier is
computed in the same way as a device identifier: `RelayId = SHA-256(encode(relay_key))[0..16]`. The
Root enters this identifier into the `relays` list of the checkpoint. For a node with the relay right,
the list holds its device identifier.

### Ticket (`RelayTicket`)

An envelope `[body, sig]`, signed by the Root, label `cpb relay ticket v1`.

| No. | Field | Type | Size | Notes |
| --- | --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | 35 | |
| 2 | `gen` | uint | ≤ 6 | Generation of the Root that signed the ticket |
| 3 | `no` | uint | ≤ 6 | Ticket number within the generation. A ticket with a greater pair (gen, no) replaces the previous one |
| 4 | `relay_key` | Key | 70 | P-256 |
| 5 | `bus_bytes` | uint | ≤ 10 | Data storage limit for the whole bus, in bytes |
| 6 | `source_bytes` | uint | ≤ 10 | Data storage limit per source, at least 16384 and at most `bus_bytes` |

Ticket size: 211 bytes with an ES256 signature, 8005 bytes with a post-quantum root signature. A ticket
has no expiry time, like every other object of the bus.

Rules:

1. A ticket is valid while its signature belongs to the Root of the current generation and its
   `RelayId` is in the `relays` list of the latest checkpoint. A relay is revoked by a new checkpoint
   without its identifier. There is no separate revocation object.
2. Tickets are compared by the pair (gen, no): generation first, then number. A relay keeps the ticket
   with the greatest pair and MUST NOT accept a ticket with a smaller or equal pair. Ticket numbers
   restart for the Root of each generation (R-MEM-12), so a number alone cannot be compared without its
   generation.
3. After a root change, a relay continues to serve the bus under the previous limits until it receives
   a ticket of the new generation, or a checkpoint of the new generation without its identifier. After
   a root change it no longer accepts tickets of the old generation. Recovery of the bus therefore does
   not interrupt delivery, and the old root key cannot change the limits.
4. A relay that sees a valid checkpoint without its identifier deletes everything it stored for that
   bus.
5. The ticket contains no relay address. How a device finds a relay is decided by the transport and the
   application.
6. This specification defines no default values for `bus_bytes` and `source_bytes`. They are a matter
   of agreement between the owner of the bus and the server operator, not a property of the protocol.

### Relay in the Hello

A relay sends the same `Hello` as a device, with its `RelayId` in the `device` field. It signs `Auth`
with the relay key. Instead of a passport it presents its ticket: the device requests it with a `Get`
with `what = 5` before the hello, like any other control-plane object. The device verifies the root
signature on the ticket and the presence of the `RelayId` in its own checkpoint. A relay that fails
these checks receives nothing from the device except control-plane objects.

### Quota Accounting

The unit of accounting is a byte of the encoded object as it appears in the frame. Blob segments are
counted by the size in the publication header.

There is one principle: whoever signed a stored object pays for it.

| What is stored | Charged to | Limit |
| --- | --- | --- |
| Ticket, latest checkpoint, latest root change record, passports of valid devices | The bus, outside `bus_bytes` | Bounded by the bitmap size in the checkpoint |
| Latest sealing key claim of each device | The bus, outside `bus_bytes` | One per device |
| Publications and blobs | The source | `source_bytes` |
| Latest channel key grant per tuple (bus, source, label, reader) | The source | `source_bytes` |
| Channel key request | The reader that signed it | One per pair (reader, label), counted against the reader's `source_bytes` |
| Join requests | A separate buffer | The number of join requests in Section 13.2 of the requirements specification |
| Calls, replies, refusals, stream chunks | Not stored | |

Control-plane objects are not counted in `bus_bytes` because their number is bounded by the Root, not
by the sources: a relay sees the bitmap size and knows the maximum volume in advance. An operator who
does not accept that volume does not serve the bus (limitation L3).

Eviction rules:

1. A source has exceeded `source_bytes`. The relay deletes that source's publications, starting with
   the oldest in the same channel, then the oldest by arrival order in its other channels. A blob is
   deleted together with its publication.
2. Key grants are never evicted in favour of publications: without a grant, a reader cannot open any
   publication. If a source's grants alone do not fit in `source_bytes`, the new grant is rejected.
3. An object that by itself exceeds `source_bytes` is rejected.
4. The total over all sources has exceeded `bus_bytes`. The relay applies rule 1 to the source that
   occupies the most. On a tie, the source with the smaller identifier is chosen. If that source has
   only key grants left, the relay takes the next source by volume that has publications and occupies
   more than the average. If there is none, the relay rejects the new object instead of evicting other
   sources' data.
5. Arrival order is a local counter of the relay. No clock is needed for accounting.

Fair share invariant (R-REL-4, property S14): a source that occupies no more than `bus_bytes` divided by
the number of sources with stored data never loses data because of other sources' publications. It
follows from rule 4: when the total exceeds `bus_bytes`, the source with the largest volume occupies
more than the average. This is max-min fair allocation, as in fair queueing [DEMERS]. The invariant is
verified in the relay model.

### Relay Refusal (`RelayRefusal`)

An unsigned message, `t = 11`. It is the only message in which a relay speaks for itself. The sender
treats it as a hint and draws no conclusion from it about the fate of the object. There is no separate
notice that a call target is unreachable: that is code 5 of this message.

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | |
| 2 | `ref` | bstr(32) | Identifier of the rejected object: SHA-256(encode(body)) for an envelope, SHA-256(encode(header)) for a publication and a grant, `call_id` for a call |
| 3 | `code` | uint | 1 source quota exhausted, 2 object larger than the quota, 3 bus not served, 4 streams not served, 5 call target not connected (R-CALL-12) |

### Decisions in This Section

1. Quotas are signed by the Root, not assigned by the server. Every source therefore knows its limit in
   advance, and the fair share invariant has an exact bound. Devices still cannot verify that a relay
   is honest: that is a delivery property, not a security property (R-REL-11).
2. An external relay has one key for all buses. Only the relay itself can link buses through it, and it
   already sees all of them (L5).
3. A relay is revoked through the checkpoint; there is no separate mechanism.
4. Control-plane objects are stored outside the data quota.

## B.11. Pairing Step by Step

This section specifies the pairing messages that gate G0 required and refines requirements
R-JOIN-1..10. Participants: the joiner; the acceptor (a member of the bus with the right to accept join
requests, or the root device itself); the Root; and the owner.

### Code

The acceptor generates the code and shows it on its screen. There are two forms, and both yield the
CPace password:

- QR: 16 random bytes. The code is single-use; one attempt.
- Short code: 6 decimal digits. Three attempts per code (a profile parameter); then the code expires
  and the acceptor shows a new one.

Both parties count attempts, each for its own code. The acceptor counts every run in which it sent
`PairReply`. The joiner counts every run in which it received `PairReply`. How the run ended does not
matter. Otherwise an adversary could break the connection before the check and try codes without being
counted.

If only the joiner has a screen, the joiner shows the code and the owner enters it on the acceptor. The
messages do not change. When the attempts are exhausted, the party that showed the code discards it and
generates a new one, and the party where the code was entered asks for it again. Counting on both sides
is needed because an adversary can impersonate the acceptor to the joiner as well as the joiner to the
acceptor.

### Messages

The joiner always starts the exchange. The first four messages are in the clear; the rest are encrypted
with the pairing keys. There are four messages rather than three because the session identifier is
built from random bytes of both parties and must be known to both before CPace starts ([CPACE],
Sections 4.1 and 10.9).

| `t` | Name | From, to | Fields |
| --- | --- | --- | --- |
| 40 | `PairInit` | Joiner to acceptor | 1 `versions` array of uint, each version ≥ 1; 2 `nonce_n` bstr(16) |
| 41 | `PairReply` | Acceptor to joiner | 1 `version` uint ≥ 1; 2 `nonce_a` bstr(16); 3 `ya` bstr(32) |
| 42 | `PairConfirm` | Joiner to acceptor | 1 `yn` bstr(32); 2 `confirm` bstr(32) |
| 45 | `PairDone` | Acceptor to joiner | 1 `confirm` bstr(32) |
| 43 | `PairSealed` | Both directions | 1 `ct` bstr(157..291): the encrypted body of `PairBus` (215..219 bytes) or `PairDevice` (141..275) and a 16-byte tag |
| 44 | `PairAbort` | Both directions | 1 `code` uint: 1 wrong code, 2 attempts exhausted, 3 no common version, 4 declined by the owner on the acceptor |

The `PairBus` body, from the acceptor to the joiner:

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `bus` | bstr(32) | |
| 2 | `k1` | Key | Recovery key, P-256 |
| 3 | `k2` | Key | Recovery key, SLH-DSA |
| 4 | `first_root_key` | Key | Key of the first Root, generation 1 |
| 5 | `gen` | uint | Current root generation, from 1 |

The joiner checks that `bus` is computed from `first_root_key`, `k1`, and `k2` per R-FMT-9. Generations
are numbered from 1, as in Section 13.1 of the requirements specification. If `gen = 1`, the root key is
`first_root_key`. If `gen` is greater than 1, the joiner requests the latest root change record from the
acceptor with an ordinary `Get`, verifies the `k1` and `k2` signatures on it, checks that its generation
is not lower than `gen`, and takes the root key from it. No one needs the intermediate records: every
record is signed by K1 and K2, not by the previous Root, so each participant keeps only the latest one
(R-MEM-11). The current root key is not transferred in `PairBus`: only a record signed by K1 and K2
provides it; otherwise the acceptor could name any key. The joiner obtains the checkpoint the same way.

The `PairDevice` body, from the joiner to the acceptor:

| No. | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | `device_key` | Key | The joiner's device key |
| 2 | `presence_key` | Key | Optional |
| 3 | `name` | tstr, 1..64 bytes | Proposed name |
| 4 | `sig` | bstr(64) | Device key signature over `cpb pair device v1 \|\| 0x00 \|\| bus \|\| pairing_hash \|\| SHA-256(encode(map of fields 1..3))` |

The signature proves that the joiner holds the device key and binds the key to this run and to this
bus.

### Computations

- Exchange: CPace per draft-irtf-cfrg-cpace-21 [CPACE], suite `CPACE-X25519-SHA512`, initiator-responder
  mode. Party A in the draft's terms is the acceptor; party B is the joiner. Inputs: `PRS` is the code
  (16 raw bytes from the QR, or the 6 digits of the short code in ASCII); `CI = "cpb pair v1"`;
  `sid = nonce_n || nonce_a`; `ADa = SHA-256(encode(PairInit))`; `ADb` is empty. `Ya` is the field `ya`;
  `Yb` is the field `yn`. The output of the exchange is the shared key `ISK`. A party aborts if the
  X25519 result is 32 zero bytes ([CPACE], Section 7.2).
- `pairing_hash = SHA-256("cpb pair hash v1" || 0x00 || SHA-256(encode(PairInit)) ||
  SHA-256(encode(PairReply)) || yn)`. The `versions` list in `PairInit` MUST be non-empty and strictly
  increasing, as in `Hello`. It is part of `PairInit`, so a downgrade to an older version cannot be
  forced.
- Keys are derived with HKDF-SHA256 from `ISK`; info is the label, then the byte 0x00, then
  `pairing_hash`. Labels: `cpb pair confirm a v1` (acceptor confirmation), `cpb pair confirm n v1`
  (joiner confirmation), `cpb pair seal a v1` and `cpb pair seal n v1` (encryption per direction).
- `confirm` is HMAC-SHA256 under the confirmation key over `pairing_hash`.
- `PairSealed` is encrypted with ChaCha20-Poly1305 under the key of its direction; the AEAD nonce is the
  per-direction message counter starting from zero; the associated data is `pairing_hash`.

These computations were checked on 2026-11-20 against the text of draft-irtf-cfrg-cpace-21, an active
CFRG Internet-Draft not yet published as an RFC. Taken from the draft unchanged: the generator
computation from `PRS`, `CI`, and `sid` (Sections 8.1 and 8.2); the computation of `ISK` from `sid`,
the shared point, and the transcript `transcript_ir` (Section 7.2); the domain separation string
`CPace255`. Left by the draft to the application and specified here: the encoding of `PRS`, `CI`,
`sid`, and the associated data (Section 4.3); processing `ISK` with a key derivation function (which
Section 10.3 recommends); and key confirmation. The draft does not require key confirmation but
recommends it for explicit authentication: a MAC keyed from `ISK` (Section 10.4). Here it is
HMAC-SHA256 over the hash of the whole run, so the confirmation also covers the messages that precede
CPace, as Section 10.5 advises. Party identities are not part of the exchange: the joiner has no name
in the bus yet; its identity is established by the signature in `PairDevice` and by the owner comparing
the fingerprint. The draft revision is pinned together with its test vectors at gate G2.

### Steps and Screens

| Step | What happens | Acceptor screen | Joiner screen | Root screen |
| --- | --- | --- | --- | --- |
| 1 | The owner selects "Add device" on the acceptor | Code or QR, caption "Enter this code on the new device", remaining attempts counter | | |
| 2 | The owner enters the code or scans the QR on the joiner. The transport brings up a link | Code | Code entry field | |
| 3 | `PairInit`, `PairReply`, `PairConfirm`; the fourth message, `PairDone`, completes the exchange | "Connecting to the new device" | "Checking the code" | |
| 3a | Confirmation failed: `PairAbort` with code 1 or 2 | "Wrong code, attempts left: N", or a new code | "Wrong code, try again" | |
| 4 | `PairBus` and `PairDevice` in `PairSealed`. The joiner checks the bus identifier | | | |
| 5 | The acceptor prepares a `JoinRequest` and sends it to the Root directly or through a relay | "Request for 'name' sent to the owner" | "Waiting for the owner's approval" and the device key fingerprint, 20 digits in groups of five | |
| 6 | The Root opens the join request | | Fingerprint | The joiner's name, who accepted the request, the key fingerprint from the request, the prompt "Compare these digits with the new device's screen", buttons "Accept" and "Decline" |
| 7 | The owner has compared the digits and pressed "Accept". The Root issues a passport and a new checkpoint and delivers them to the relays and the acceptor | "'Name' accepted" | | "Device added" |
| 8 | The joiner receives the passport and the checkpoint, and verifies the root signature, its own key in the passport, and its own bit in the bitmap | | "Device is on the bus" and the bus fingerprint | |
| 9 | The joiner publishes its sealing key claim and its node info | | | |

### Rules

1. How the joiner obtains its passport (step 8). It opens an ordinary hello with its device identifier
   to the acceptor or to a relay. A relay answers only once it holds a valid passport with that
   identifier, and verifies the `Auth` signature with the key from the passport. Before the passport is
   issued, the relay tells the joiner nothing. This refines R-REL-1 and adds no new message.
2. The owner's refusal is not an object. The Root simply does not issue a passport and deletes the join
   request. How long to wait is decided by the joiner's application: the core has no clock.
3. If the root device itself is the acceptor (R-JOIN-9), steps 5 and 6 merge: there is no join request,
   and the Root shows the confirmation screen at once. The fingerprint is shown here too, but comparing
   it is optional, because there is no third device between the joiner and the Root.
4. The bus fingerprint is 20 digits by the same rule as `KeyFingerprint`, but with its own label and the
   raw 32 bytes of `bus` as input: the first 8 bytes of
   `SHA-256("cpb bus fingerprint v1" || 0x00 || bus)`.
5. The pairing keys and `ISK` are erased immediately after step 4. The code is erased after a
   successful run or when the attempts are exhausted.
6. The joiner's rights (read, publish, permits) are set by the owner on the Root's screen. How this
   choice is presented is decided by the application.

### Decisions in This Section

1. Both parties count attempts, and each counts every run it started.
2. The joiner confirms the key first, in `PairConfirm`; the acceptor answers in `PairDone`, not in
   `PairReply`. The exchange takes four messages, and the adversary still tests at most one code per
   run.
3. The joiner signs the transcript hash with its device key. Without this it could claim someone
   else's key as its own.
4. There is no separate "join declined" object.
5. The joiner fetches its passport with an ordinary hello; there is no dedicated message for it.
