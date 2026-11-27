<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Ciphered Private Bus (CPB): Glossary and Code Identifiers

- **Status:** Draft, baseline for gate G0. Companion to the
  [Protocol Requirements Specification](requirements.md),
  [Appendix B, Wire Format](appendix-b-wire-format.md), and
  [Appendix C, CDDL Schema and Size Analysis](appendix-c-cddl.md).
- **Date:** 2026-11-20
- **Author:** Evgenii Russkikh

This glossary lists every entity of the bus with the identifier used for it in code and the place where
it is defined. "Section N" refers to the requirements specification; "B.N" refers to Appendix B.

Naming rules: types are `UpperCamelCase`, fields and functions `snake_case`, constants
`UPPER_SNAKE_CASE`. Established cryptographic terms are kept as they are: `enc`, `aad`, `info`, `alg`,
`sig`, `nonce`. The core's input type is `In`, its output type `Out`, and the bus `Bus`. The field
names of wire objects are fixed by Appendix B; the remaining identifiers are recommendations for
implementations.

## 1. Authorities and Devices

| Term | Identifier | Definition | Defined in |
| --- | --- | --- | --- |
| Root | `Root` | The only authority that admits and revokes devices and grants rights | Sections 2, 6 |
| Node | `Node` | Any device of the bus that holds a passport | Section 2 |
| Recovery key | `Recovery` | The only authority that replaces the Root: the offline pair K1 and K2 | Section 2, R-MEM-11 |

## 2. Environment

These are not members of the bus: they hold no passport, and the bus either does not trust them or does
not know about them.

| Term | Identifier | Definition | Defined in |
| --- | --- | --- | --- |
| Owner | `Owner` (documentation only) | The person or organization with authority over the bus, exercised through the Root | Section 2 |
| Relay | `Relay` | Untrusted storage and forwarding | Section 11 |
| Member relay | `MemberRelay` | A node with the relay right acting as a relay | Section 11 |
| External relay | `ExternalRelay` | A relay server that is not a member and sees the bus only under aliases | Section 11.1 |
| Application | `App` | A program that uses the bus. One application is one bus | R-ARC-4 |
| Host | `Host` | The program in which the core is embedded: transport, storage, randomness, time events, keys | R-ARC-8..10 |
| Link | `Link` | One transport connection over which frames travel | R-ARC-6 |

## 3. Identifiers and Numbers

| Term | Identifier | Size or range | Defined in |
| --- | --- | --- | --- |
| Bus identifier | `BusId` | 32 bytes | R-FMT-9 |
| Device identifier | `DeviceId` | 16 bytes | R-FMT-9, B.8 |
| Relay identifier | `RelayId` | 16 bytes | B.10 |
| Relay epoch | `RelayEpoch` | 1..2^31 - 1, per root device within a root generation | R-REL-13 |
| Bus alias | `BusAlias` | 16 bytes, hash of the period key | R-REL-14, B.10 |
| Device alias | `DeviceAlias` | 16 bytes, per external relay and relay epoch | R-REL-14, B.10 |
| Label alias | `LabelAlias` | 16 bytes, per external relay and relay epoch | R-REL-14, B.10 |
| Upload counter | `seq` | 1..2^31 - 1, per uploader, relay, and relay epoch | R-REL-17, B.10 |
| Members tree depth | `depth` | 2..15 | B.10 |
| Signed object identifier | `ObjectId` | 32 bytes | R-FMT-7 |
| Channel number | `ChannelNo` | 0..65535 | Section 13.1 |
| Channel label | `ChannelLabel` | 16 bytes | Section 9.1, B.8 |
| Channel key commitment | `KeyCommit` | 32 bytes | R-CH-1, B.8 |
| Root generation | `RootGen` | 1..2^31 - 1 | R-MEM-11 |
| Passport number | `PassportNo` | 1..2^31 - 1 | R-MEM-1 |
| Checkpoint number | `CheckpointNo` | 1..2^31 - 1 | R-MEM-1 |
| Sealing key epoch | `SealEpoch` | 1..2^31 - 1 | R-KEY-2 |
| Channel key generation | `KeyGen` | 1..2^31 - 1 | R-CH-8 |
| Publication number | `PubNo` | 1..2^53 - 1 | R-CH-8 |
| Reader window floor | `pub_floor` | Publication number | R-CH-9 |
| Action number | `ActionNo` | 1..64 | R-CALL-3 |
| Call nonce | `CallNonce` | 16 bytes | R-CALL-1 |
| Stream identifier | `StreamId` | 1..2^31 - 1 | R-STR-2 |
| Chunk number | `ChunkNo` | 1..2^31 - 1 | R-STR-2 |
| Blob segment size | `seg` | 1024..16346 bytes | B.5 |
| Key fingerprint | `KeyFingerprint` | 64 bits, shown as 20 digits | R-JOIN-5, R-JOIN-7, B.8 |
| Bus fingerprint | `BusFingerprint` | 64 bits, shown as 20 digits | B.11 |

## 4. Keys and Algorithms

| Term | Identifier | Definition | Defined in |
| --- | --- | --- | --- |
| Root key | `RootKey` | Signs passports and checkpoints. Held by the host | R-KEY-1 |
| Device key | `DeviceKey` | Signs everything a node creates. Held by the host | R-KEY-1 |
| User-presence key | `PresenceKey` | Signs actions that require user confirmation | R-CALL-4 |
| K1 | `RecoveryKeyClassic` | Classical half of the recovery key (P-256) | Section 2 |
| K2 | `RecoveryKeyPq` | Post-quantum half of the recovery key (SLH-DSA) | Section 2 |
| First root key | `first_root_key` | Key of the Root of generation 1, part of the bus identifier | B.11 |
| Sealing key | `SealKey` | X-Wing key, rotated by epoch. Held by the core | R-KEY-2..4 |
| Channel key | `ChannelKey` | 32 bytes per pair (source, channel) | R-CH-1 |
| Content key | `content_key` | Derived from the channel key and the publication header | R-CH-3, B.8 |
| Blob key | `blob_key` | Derived the same way, with a different label | R-CH-3, B.8 |
| Reply key | `reply_key` | Exported from the HPKE context of the call | R-CALL-9, B.8 |
| Stream keys | `stream_key_out`, `stream_key_in` | One per direction, exported from the HPKE context of the call | R-STR-1, B.8 |
| Relay epoch secret | `relay_secret` | 32 bytes per relay epoch, known to members only | R-REL-13, B.10 |
| Link seed | `link_seed` | 32 bytes per member and relay epoch, issued by the Root | R-REL-13, B.10 |
| Link key | `LinkKey` | Authenticates a member to one external relay in one relay epoch. Held by the core | R-KEY-11, B.10 |
| Period secret and period key | `period_secret`, `PeriodKey` | The Root's secret per relay epoch and the key derived from it per external relay; the period key signs tickets | R-REL-13, B.10 |
| Wrapping key | `wrap_key` | Single-use key of one `Relayed` message | R-REL-16, B.10 |
| Relay key | `RelayKey` | An external relay's signing key, one for all buses | B.10 |
| Key encoding | `Key { alg, bytes }` | The pair (algorithm, bytes) | R-FMT-11 |
| ECDSA P-256 algorithm identifier | `ALG_ES256 = 1` | | R-FMT-11 |
| X-Wing algorithm identifier | `ALG_XWING = 2` | | R-FMT-11 |
| SLH-DSA-SHA2-128s algorithm identifier | `ALG_SLH_DSA_128S = 3` | | R-FMT-11 |
| Domain separation label | `Label` | One per use of a signature or key derivation | R-KEY-8, B.8 |

## 5. Control-Plane Objects

Public signed objects. Every member and member relay verifies and stores them; an external relay stores them only wrapped.

| Term | Identifier | Signed by | Defined in |
| --- | --- | --- | --- |
| Passport | `Passport` | Root | Section 6.1, B.3 |
| Checkpoint | `Checkpoint` | Root | Section 6.1, B.3 |
| Root change record | `RootChange` | K1 and K2 | R-MEM-11, B.3 |
| Head and rest of a record | `head`, `rest` | Parts of a passport, checkpoint, or root change record | B.1 |
| Sealing key claim | `SealClaim` | Device | R-KEY-2, B.3 |
| Join request | `JoinRequest` | Acceptor | R-JOIN-4, B.3 |
| Channel key request | `KeyRequest` | Reader | R-CH-18, B.3 |
| Halt proof | `HaltProof` | Contains two root-signed records | R-MEM-10, B.3 |
| Relay access | `RelayAccess` | Device key of the root device; sealed to one member | R-REL-13, B.10 |
| Relay ticket | `RelayTicket` | Period key | R-REL-15, B.10 |
| Closing ticket | field `closed` | The last ticket of a bus alias | R-REL-19, B.10 |
| Bridge | `Bridge` (documentation only) | A relay access object of the next epoch kept under a closed alias | R-REL-19, B.10 |
| Members tree | `members`, `depth` | Ticket fields: root and depth of the tree of (alias, link key) pairs | B.10 |
| Relay storage limits | `bus_bytes`, `source_bytes` | Fields of the relay ticket | B.10 |
| Control-plane object request | `Get` | Unsigned | B.3 |
| Read right | `RIGHT_READ` | | Section 6.1 |
| Publish right | `RIGHT_PUBLISH` | | Section 6.1 |
| Relay right | `RIGHT_RELAY` | | Section 6.1 |
| Accept join requests right | `RIGHT_ACCEPT` | | Section 6.1 |
| Permit | `Permit { commander, auto, confirm }` | Part of a passport | Section 6.1 |
| Action set | `ActionSet` | 8 bytes, one bit per action | R-FMT-5 |
| Valid passport bitmap | `valid_bits` | Checkpoint field | R-MEM-2 |
| Window start | `window_start` | Checkpoint field | R-MEM-14 |
| Next free passport number | `next_passport_no` | Checkpoint field | R-MEM-2 |
| Relay list | `relays` | Checkpoint field | Section 6.1 |
| Root device | `root_device` | Checkpoint field | R-CALL-7 |

## 6. Enrollment

| Term | Identifier | Definition | Defined in |
| --- | --- | --- | --- |
| Pairing | `Pairing` | CPace exchange between the joiner and the acceptor | R-JOIN-1, B.11 |
| Joiner | `joiner` | The device that is joining | Section 7 |
| Acceptor | `acceptor` | A node with the accept right, or the root device | Section 7 |
| Short code | `PairCode` | 6 digits | R-JOIN-1 |
| QR secret | `PairSecret` | 16 bytes | R-JOIN-1 |
| Pairing transcript hash | `pairing_hash` | Field of the join request | R-JOIN-4, B.11 |
| Joiner signature | `joiner_sig` | The joiner's `PairDevice` signature, carried in the join request | B.3 |
| Pairing messages | `PairInit`, `PairReply`, `PairConfirm`, `PairDone`, `PairSealed`, `PairAbort` | | B.11 |
| Bus information for the joiner | `PairBus` | | B.11 |
| Joiner information | `PairDevice` | | B.11 |

## 7. Channels and Publications

| Term | Identifier | Definition | Defined in |
| --- | --- | --- | --- |
| Channel | `Channel` | Addressed by source and number | Section 9 |
| Publication | `Publication` | Header, content, signature | Section 9.1, B.5 |
| Publication header | `PubHeader` | The public part | Section 9.1 |
| Publication content | `PubContent` | Channel number, flags, data, padding | Section 9.1 |
| Channel key grant | `KeyGrant` | The channel key sealed to a reader | R-CH-2, B.5 |
| Retention depth | `depth` | 0 no retention, 1 latest value, N history | R-CH-10..12 |
| Blob | `Blob` | Large data of a publication | R-CH-15 |
| Blob segment | `BlobSegment` | One binary frame | R-CH-15, B.7 |
| Blob segment request | `BlobGet` | | B.5 |
| Content padding | `pad` | Up to a padding bucket | R-CH-14 |
| Node info channel | `CHANNEL_NODE_INFO = 0` | Device name and description | R-CH-16 |
| Node info | `NodeInfo` | Content of channel 0 | R-CH-16, B.5 |

## 8. Calls and Streams

| Term | Identifier | Definition | Defined in |
| --- | --- | --- | --- |
| Call | `Call` | A signed request for an action | R-CALL-2, B.6 |
| Commander | `commander` | The device that calls | Section 10 |
| Target | `target` | The device that executes | Section 10 |
| Command | `Command` | The sealed part of a call: action and arguments | R-CALL-3, B.6 |
| Reply | `Reply` | The encrypted result | R-CALL-10, B.6 |
| Public refusal | `Refusal` | Refusal before decapsulation, a hint | R-CALL-13, B.6 |
| Nonce request and nonce | `NonceRequest`, `Nonce` | The first step of a call | Section 10.1, B.6 |
| Nonce slot | `NonceSlot` | One per pair (commander, target), in memory only | R-CALL-1 |
| Relay refusal | `RelayRefusal` | A relay's hint; code 5 reports an unreachable call target | R-CALL-12, B.10 |
| Stream | `Stream` | Bidirectional, opened by a call | Section 10.3 |
| Stream chunk | `StreamChunk` | One binary frame | R-STR-2, B.7 |
| Ordered mode | `StreamMode::Ordered` | `stream_mode = 1` | R-STR-3, B.6 |
| Lossy mode | `StreamMode::Lossy` | `stream_mode = 2` | R-STR-3, B.6 |
| Credit | `credit` | How many bytes the peer may send | R-STR-4 |
| Chunk direction | `dir` | From the commander or from the target | R-STR-2 |

## 9. Wire Format

| Term | Identifier | Definition | Defined in |
| --- | --- | --- | --- |
| Frame | `Frame` | 2-byte length and body | R-FMT-12 |
| Binary frame flag | `FRAME_BINARY_BIT` | High bit of the length | R-FMT-12 |
| Envelope | `Envelope { body, sig, sig2 }` | A signed object | R-FMT-6 |
| Message kind | field `t` | Kind number in the message map | R-FMT-12, B.2 |
| Hello | `Hello` | The first message on a link | R-REL-1, B.4 |
| Hello authentication | `Auth` | Signature over both hellos | B.4 |
| Relay hello | `RelayHello` | The first message on an external relay link | R-REL-15, B.10 |
| Wrapped object | `Relayed` | Everything a member sends through an external relay | R-REL-16, B.10 |
| Wrapped object class | `class` | 1 control, 2 key grant, 3 publication, 4 key request, 5 join request, 6 forwarded, 7 blob segment | B.10 |
| Request on an external relay link | `RelayGet` | Unsigned | B.10 |
| Critical field range | `0..=255` | An unknown field rejects the object | R-FMT-14 |
| Extension field range | `256..=65535` | An unknown field is preserved | R-FMT-14 |
| Protocol version | `version` | Announced in the hello and covered by the signature | R-FMT-15 |

## 10. Core State Machine

| Term | Identifier | Definition | Defined in |
| --- | --- | --- | --- |
| Core | `Core` | A pure state machine | R-ARC-1 |
| Input: start | `In::Start` | With restored state | R-CORE-1 |
| Input: link up | `In::LinkUp` | | R-CORE-1 |
| Input: frame received | `In::Frame` | | R-CORE-1 |
| Input: link down | `In::LinkDown` | | R-CORE-1 |
| Input: application operation | `In::App` | | R-CORE-1 |
| Input: reset nonces | `In::ResetNonces` | Time event | R-CORE-3 |
| Input: rotate key epoch | `In::RotateEpoch` | Time event | R-CORE-3 |
| Input: storage result | `In::StoreResult` | | R-CORE-7 |
| Output: send a frame | `Out::Send` | | R-CORE-2 |
| Output: store a record | `Out::Store` | | R-CORE-2 |
| Output: deliver to the application | `Out::Deliver` | Publication, call, stream data | R-CORE-2 |
| Output: request user presence | `Out::AskPresence` | | R-API-3 |
| Output: rejection with a rule code | `Out::Reject` | | R-CORE-2 |
| State: running | `State::Running` | | |
| State: halted | `State::Halted` | Observed two histories | R-MEM-8, R-MEM-9 |
| State: halted permanently | `State::HaltedForever` | Two root change records of one generation | R-MEM-13 |
| State: storage failed | `State::StoreFailed` | Until restart | R-CORE-7 |

## 11. Interfaces

| Term | Identifier | Definition | Defined in |
| --- | --- | --- | --- |
| Create an instance | `cpb_new` | In memory supplied by the caller | R-API-1 |
| Submit an event | `cpb_step` | One input, processed to completion | R-API-1, R-CORE-7 |
| Take effects | `cpb_next_out` | In emission order | R-API-1 |
| Host table | `HostKeys { random, generate, public_key, sign }` | Randomness and three key operations | R-ARC-9 |
| Publish | `publish` | | R-API-2 |
| Read a channel | `read` | | R-API-2 |
| Subscribe to a channel | `subscribe` | | R-API-2 |
| Set the readers of a channel | `set_readers` | A list of devices, or all valid members with the read right | R-API-2 |
| Call an action | `call` | | R-API-2 |
| Reply to a call | `reply` | | R-API-2 |
| Register an action handler | `on_action` | | R-API-2 |
| Write and read a stream | `stream_write`, `stream_read` | | R-API-2 |
| Set the node name | `set_node_name` | Publishes a new node info | R-API-2 |
| Read the bus state | `bus_state` | A snapshot without side effects and without secrets | R-API-2 |

## 12. Errors and Codes

| Term | Identifier | Definition | Defined in |
| --- | --- | --- | --- |
| Rule code | `RuleCode`, of the form `area/rule` | For example `sig/low-s`, `pub/commit`, `store/failed` | R-ERR-1 |
| Result: executed | `RESULT_OK = 0` | | R-CALL-11, B.6 |
| Result: not permitted | `RESULT_NO_RIGHT = 1` | | R-CALL-11, B.6 |
| Result: declined by the user | `RESULT_DENIED = 2` | | R-CALL-11, B.6 |
| Result: invalid arguments | `RESULT_BAD_ARGS = 3` | | R-CALL-11, B.6 |
| Result: action not supported | `RESULT_NO_ACTION = 4` | | R-CALL-11, B.6 |
| Result: too many streams | `RESULT_TOO_MANY_STREAMS = 5` | | R-STR-6, B.6 |
| Application result codes | `256..=65535` | | R-CALL-11 |
| Refusal: stale key epoch | `REFUSAL_STALE_EPOCH = 1` | Public, carries the sealing key claim | R-CALL-13, B.6 |
| Refusal: nonce mismatch | `REFUSAL_NONCE = 2` | Public, carries the current nonce | R-CALL-13, B.6 |
| Relay refusal codes | `RELAY_QUOTA_EXHAUSTED = 1`, `RELAY_TOO_LARGE = 2`, `RELAY_BUS_NOT_SERVED = 3`, `RELAY_STREAMS_NOT_SERVED = 4`, `RELAY_TARGET_UNREACHABLE = 5` | | B.10 |
| Error detail mode | `ErrorDetail::Debug`, `ErrorDetail::Release` | Full and short | R-ERR-2 |
| Error detail switch | `CPB_ERROR_DETAIL` | Environment variable or setting | R-ERR-3 |

A halted target does not answer with a refusal or a result code; it answers with a `HaltProof`
(B.3, B.9).

## 13. Format Constants

| Term | Identifier | Value |
| --- | --- | --- |
| Bus identifier length | `BUS_ID_LEN` | 32 |
| Device identifier length | `DEVICE_ID_LEN` | 16 |
| Channel label length | `CHANNEL_LABEL_LEN` | 16 |
| Call nonce length | `CALL_NONCE_LEN` | 16 |
| Channel key length | `CHANNEL_KEY_LEN` | 32 |
| Maximum frame body | `FRAME_BODY_MAX` | 16384 |
| Maximum nesting depth | `NESTING_MAX` | 4 |
| Maximum container items | `ITEMS_MAX` | 128 |
| Maximum integer | `INT_MAX` | 2^53 - 1 |
| Maximum number | `NUMBER_MAX` | 2^31 - 1 |
| Publication data and call arguments | `DATA_MAX` | 4096 |
| Actions per device | `ACTIONS_MAX` | 64 |
| Device name | `NAME_MAX` | 64 bytes |
| System channels | `SYSTEM_CHANNELS` | 16 |
| Short code digits | `PAIR_CODE_DIGITS` | 6 |
| QR secret length | `PAIR_SECRET_LEN` | 16 |
| Key fingerprint bits | `FINGERPRINT_BITS` | 64 |

## 14. Profile Parameters

| Term | Identifier | Range | Default |
| --- | --- | --- | --- |
| Checkpoint bitmap length | `bitmap_bits` | 64..32768 | 4096 |
| Permits per passport | `permits_max` | 0..128 | 32 |
| Channel retention depth | `depth_max` | 0..1024 | 16 |
| Retained sealing key epochs | `seal_epochs` | 2..16 | 4 |
| Open streams | `streams_max` | 0..256 | 8 |
| Stream chunk and blob segment | `chunk_len` | up to 16384 | 4096 |
| Initial stream credit | `initial_credit` | up to 1 MiB | 16 KiB |
| Content padding buckets | `pad_steps` | chosen by the source | 64, 256, 1024, 4096 |
| Pairing attempts per code | `pair_attempts` | 1..10 | 3 |
| Join requests held by a relay | `join_requests_max` | 1..256 | 16 |
| "Reset nonces" period | `nonce_reset_period` | set by the host | 30 s |
