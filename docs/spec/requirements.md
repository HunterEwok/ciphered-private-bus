<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Ciphered Private Bus (CPB): Protocol Requirements Specification

- **Status:** Draft, baseline for gate G0 (Section 14.3). Not frozen: the format may still change
  until the first release (R-FMT-15).
- **Date:** 2026-11-20
- **Author:** Evgenii Russkikh
- **Companion documents:** [Appendix B, Wire Format](appendix-b-wire-format.md);
  [Appendix C, CDDL Schema and Size Analysis](appendix-c-cddl.md); [Glossary](glossary.md).

## Abstract

Ciphered Private Bus (CPB) is an open, transport-independent message bus for the devices of a single
owner. It provides end-to-end encryption, untrusted relays, and operation on any operating system and
hardware class down to microcontrollers. This document states the numbered requirements of the
protocol. Each requirement names the security property it serves and the method by which it is
verified.

## Status of This Document

This is a working draft of the CPB requirements. Closing gate G0 records this text, Appendix B, and
Appendix C as the reference baseline. It does not freeze the wire format: the formal models (gate G1)
and the test vectors (gate G2) exist precisely to find errors in it. The format is frozen when version 1
is released (R-FMT-15).

## Table of Contents

1. [Introduction](#1-introduction)
2. [Participants and Terminology](#2-participants-and-terminology)
3. [Threat Model, Security Properties, and Limitations](#3-threat-model-security-properties-and-limitations)
4. [Architecture](#4-architecture)
5. [Wire Format](#5-wire-format)
6. [Membership](#6-membership)
7. [Device Enrollment](#7-device-enrollment)
8. [Keys and Cryptography](#8-keys-and-cryptography)
9. [Channels and Publications](#9-channels-and-publications)
10. [Calls and Streams](#10-calls-and-streams)
11. [Relays](#11-relays)
12. [Core State Machine, Interfaces, and Errors](#12-core-state-machine-interfaces-and-errors)
13. [Limits and Parameters](#13-limits-and-parameters)
14. [Verification, Acceptance, and Work Plan](#14-verification-acceptance-and-work-plan)
15. [Security Considerations](#15-security-considerations)
16. [References](#16-references)

Appendix A. [Design Decisions and Open Items](#appendix-a-design-decisions-and-open-items)

## 1. Introduction

CPB connects the devices of one owner so that an application can carry state, an event, a remote call,
or a stream from one device to another without trusting the network or any server in between.

Vendor ecosystems offer such connectivity, but only inside the ecosystem and only through the vendor's
servers. CPB provides the same across any operating system and any hardware. The bus knows nothing
about applications. No requirement in this document exists for the benefit of a particular
application.

### 1.1. Scope

This specification covers:

- the wire format and the rules for parsing it;
- membership: who belongs to a bus, how a device is enrolled and revoked, and how the root of trust is
  replaced;
- four communication patterns: a retained channel, an event without retention, a call with a reply,
  and a stream;
- the role of the relay: untrusted storage and forwarding;
- the core as a pure state machine, with two interfaces to it: the library interface and the local
  interface for applications;
- a conformance suite sufficient to build a second, independent implementation.

### 1.2. Non-Goals

| Non-goal | Rationale |
| --- | --- |
| Transport | The core consumes and produces frames. TCP, TLS, BLE, UART, wake-up, and nearby discovery are attached from outside as adapters. |
| Payload semantics | Clipboard, file transfer, home automation, or an AI bridge are profiles on top of the bus, specified in their own documents. |
| Federation between buses of different owners | Not in version 1. The bus identifier is part of every signed object, but permits and key grants name a device without a bus. Federation therefore requires new message kinds and extension fields (R-FMT-14); it does not arise by itself. |
| Metadata privacy against one's own relay | A relay sees who sends to whom and how much. Nobody sees content. |
| Anonymity of the owner against the network | The bus is not a replacement for Tor or a VPN. |
| Protection against a compromised root | Whoever holds the root key controls the bus until it is recovered with the recovery key. |

### 1.3. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown
here. A deviation from a SHOULD is documented by the implementation.

Every requirement has an identifier of the form `R-AREA-N`, the security property of Section 3 that it
serves, and the verification method of Section 14. Requirements are written as:

> **R-AREA-N.** Requirement text.
> *Serves:* property. *Verified by:* method.

Identifiers are stable: a removed requirement leaves a gap, and its number is not reused.

## 2. Participants and Terminology

A bus has exactly three kinds of authority keys and one kind of device.

| Term | Definition | Keys |
| --- | --- | --- |
| Owner | The person or organization acting as the single authority over a bus. | Holds no key itself; acts through the Root. |
| Bus | The set of devices admitted by one Root. Has a bus identifier. | The identifier is derived from the first root key and both halves of the recovery key. |
| Root | The only authority that admits and revokes devices and grants rights. | The root key. The bus does not know where it is kept: the core asks the host for a signature. Where the key lives is the application's decision. Recommended: hardware-backed storage gated by user presence. |
| Recovery key | The only authority that replaces the Root. Kept offline. | The pair K1 (classical signature) and K2 (post-quantum signature). This is a hybrid: both signatures are required, so a break of one scheme does not open the bus. The target state is a single post-quantum signature, introduced as a new algorithm identifier once a post-quantum scheme is considered mature. |
| Node | Any device of the bus: phone, computer, server, microcontroller. The root device is also a node that additionally holds the root key. | Device key, optional user-presence key, rotating sealing key. |
| Relay | A role of a node or of an external server: stores and forwards what it cannot read. | A member relay is a node that holds a passport with the relay right. An external relay is a server that is not a member: for each relay epoch it holds a ticket signed by a period key of the Root, and it sees the bus only under aliases (Section 11.1). |
| Application | A program that uses the bus. The bus knows nothing about the application; one application is one bus. | None. |
| Host | The program in which the core is embedded. Provides the transport, storage, randomness, and time events. | None. |

Further terms:

- **Passport.** A Root-signed record of an admitted device: its keys, rights, and the permits granted to
  it. (The equivalent of a membership certificate.)
- **Checkpoint.** A Root-signed record of which passports are currently valid.
- **Root change record.** A record signed by the recovery key that designates a new root key.
- **Channel.** A numbered place to which a node publishes data. A channel is addressed by its source
  device and channel number.
- **Publication.** One signed and encrypted message in a channel. It is readable by the devices to which
  the source has granted the channel key.
- **Call.** A request for another node to perform an action, with a reply.
- **Stream.** A bidirectional byte sequence between two nodes, opened by a call.
- **Halt.** A state in which a node stops executing calls and accepting membership changes because it
  has observed two conflicting histories (a fork).
- **Relay epoch.** A period, numbered per root device within a root generation, during which the members
  address each external relay under one set of aliases. Every revocation starts a new relay epoch.
- **Alias.** A 16-byte pseudonym of the bus, a device, or a channel label, valid for one external relay
  in one relay epoch. Aliases of different relays and different epochs are unrelated for anyone who is
  not a member.

The full list of terms and their code identifiers is in the [Glossary](glossary.md).

## 3. Threat Model, Security Properties, and Limitations

### 3.1. Adversary

The adversary controls the entire network and every relay: it can read, delay, reorder, replay, modify,
and drop any frame. It can compromise any number of nodes and obtain everything stored on them. It
records traffic today and may obtain a cryptographically relevant quantum computer later. It cannot
obtain the private root key and does not hold the recovery key. How the host protects the root key is
not defined by the bus; it is an assumption for which the application is responsible.

### 3.2. Security Properties

| ID | Property | Statement |
| --- | --- | --- |
| S1 | Confidentiality | The content of a publication, call, reply, or stream is learned only by the readers named by the sender. This holds also against an adversary that records traffic and later obtains a quantum computer (harvest now, decrypt later). |
| S2 | Source authenticity | A recipient knows which device created a message. A reader of a publication cannot present its own content to another reader as the source's content. |
| S3 | Content agreement | All readers of one publication decrypt the same content or all reject it. |
| S4 | Membership | A node accepts anything only from a device holding a passport of the current Root that is valid under that node's checkpoint. |
| S5 | Revocation | From the moment a node learns a checkpoint without device X, it accepts nothing from X and seals nothing to it. |
| S6 | No rollback | The checkpoint number on a node never decreases, including across reboots. A revoked device does not come back through an old record. |
| S7 | Convergence | Two nodes that processed the same set of records in any order are in the same membership state. A record a node drops because it is not yet valid for it, such as a checkpoint of a root generation the node has not reached, is not processed; it reaches the node again through the exchange of control-plane objects when the generations differ (R-MEM-6, R-REL-1). There is one exception: one node saw two conflicting records and halted, while the other received them already outdated, one per link, and did not notice the conflict. The halt then reaches the second node through the proof that the first node sends on every link (R-MEM-10). |
| S8 | Single history | Two different records of one author with the same number put the node into the halted state. Only a root change record leaves the halted state. |
| S9 | Root change | The root key changes only through a record signed by both halves of the recovery key. After the change the previous Root has no power. |
| S10 | Call integrity | An action is executed at most once, and only if the call is signed by a permitted key over a fresh nonce issued by the target. An action of the confirmation class requires the user-presence key or the root key. |
| S11 | Reply and stream binding | A reply and a stream belong to exactly the call that created them and originate from its target. |
| S12 | Channel freshness | A node never replaces a channel value with an older one, including across reboots. |
| S13 | Forward secrecy | After the sealing key is rotated and the old one erased, a compromise of the node does not disclose the envelopes sealed to the erased key: call commands and those channel keys the node has already erased. Channel publications are protected by channel key rotation: a compromised reader discloses publications only under the channel keys it still holds (R-CH-7). |
| S14 | Damage containment | A single compromised node cannot impersonate another device, cannot halt the bus, and cannot evict other devices' data from a relay beyond its own quota. |
| S15 | Untrusted relay | A relay cannot read, forge, or modify content. It learns only what L5 lists. |
| S16 | Instance isolation | Bus instances in one process share no state. An application cannot act on the bus's system channels and never receives private keys. |
| S17 | Parser robustness | On any input bytes the core does not crash and does not exceed its memory budget. An accepted message has exactly one byte representation. |
| S18 | Relay unlinkability | An external relay, and any set of colluding external relays that holds no key or secret of a member, learns no identifier, key, right, permit, or name of the bus or of its devices. Except through timing and network addresses, it cannot link what it sees in one relay epoch to what it sees in another, nor its view of a bus to another external relay's view of the same bus. |

### 3.3. Limitations

These limitations are accepted as part of this specification. An implementation MUST NOT promise more.

| ID | Limitation |
| --- | --- |
| L1 | A node that the adversary has cut off from everyone who knows a newer checkpoint operates under the old one. A revocation arrives with the first message from any honest device that knows of it. |
| L2 | Version 1 signatures are classical. An adversary with a working quantum computer can forge a root signature until the bus is moved to a post-quantum signature through the recovery key. |
| L3 | The network and relays can deny service. The bus guarantees safety, not delivery. |
| L4 | A compromised root key gives full control over the bus until the Root is changed. |
| L5 | A member relay sees: the bus identifier, the source device, the opaque channel label, the devices to which a channel key was granted, the retention depth, the padding bucket, the arrival time, and the control-plane objects: passports (keys, rights, permits), checkpoints, sealing key claims, and who submitted a join request. An external relay sees, separately in each relay epoch: one bus alias; the aliases of the devices that connect and of the channel labels; which alias granted a key for which label alias to which alias, which alias calls which, and which alias submitted a join request; the upload counters, the retention depth, the padding bucket, the arrival time, and the network address; and the number of valid members, because the root device uploads one passport and one bridge per member. It sees no control-plane object in the open. It can link two consecutive epochs of a bus by timing, because the root device and the sources upload under both aliases at the change, and it can link the old and the new alias of a device that fetches its bridge and then connects under the new alias, unless the device fetches the bridge through another external relay. The device name is not in the passport: it travels in the sealed join request and in the node info. A network observer behind an encrypting transport sees only volume and timing. |
| L6 | Two different root change records with the same generation halt the bus permanently. The owner creates a new bus. |
| L7 | A call is executed at most once, but a commander that received no reply does not know whether it was executed. |
| L8 | A reader that receives a channel for the first time or anew, and only through a relay, may receive a state of the channel that is not the newest. It converges with the first message from the source or an honest relay. The source's answer to a key request (R-CH-18) provides freshness immediately. |

## 4. Architecture

The CPB standard consists of three contracts and a conformance suite, not of one code base.

| Contract | What it fixes | Who needs it |
| --- | --- | --- |
| Wire format | The bytes on the wire and the rules for accepting them; test vectors. | Every implementation. |
| Core state machine | Input events, output effects, and the state between them. | Whoever embeds the core. |
| Local interface | The operations an application requests from the bus. | Application authors. |

> **R-ARC-1.** The core MUST be a pure state machine: `(state, event) -> (state, effects)`. It MUST NOT
> read the clock, open connections, access storage, or allocate memory on its own.
> *Serves:* S7, S17. *Verified by:* model, code review, bare-metal build.

> **R-ARC-2.** The core MUST NOT know any application. A payload is bytes whose format is unknown to the
> core.
> *Serves:* scope. *Verified by:* code review.

> **R-ARC-3.** The core MUST run as several independent instances in one process. There MUST be no
> global variables, fixed paths, or shared resources.
> *Serves:* S16. *Verified by:* test with 100 instances in one process.

> **R-ARC-4.** The core is a library that the application embeds. One application is one bus. A service
> that serves several programs is built as an ordinary application on top of the library and is outside
> this standard.
> *Serves:* scope. *Verified by:* code review.

> **R-ARC-5.** No property S1–S14 may depend on transport security. The transport is assumed to be fully
> controlled by the adversary.
> *Serves:* S1–S14. *Verified by:* Tamarin; model with an on-path adversary.

> **R-ARC-6.** The transport MUST deliver a frame whole or not at all. Ordering and reliability are not
> required by the core, with one exception: a stream in ordered mode (Section 10) requires ordered,
> reliable delivery from the link it uses.
> *Serves:* S17. *Verified by:* simulator with reordering and loss.

> **R-ARC-7.** An encrypting transport SHOULD be used on every link that leaves the device. Only
> limitation L5 for a network observer depends on it.
> *Serves:* L5. *Verified by:* deployment document.

> **R-ARC-8.** The host MUST provide storage with atomic replacement of a single record: after a power
> loss either the whole previous version or the whole new version remains, and a corrupted record is
> detected and never presented as valid. The storage MUST NOT return to the core a version older than
> the last acknowledged one. This is an assumption: without it S6 and S12 do not hold. What must survive
> a reboot is listed in R-CORE-5.
> *Serves:* S6, S12. *Verified by:* simulator with power loss.

> **R-ARC-9.** The host MUST provide a cryptographically secure random number generator and three
> operations on the device, presence, and root keys: generate, export the public key, sign. The core
> never sees the private parts of these keys. Sealing keys, channel keys, and all key derivations are
> computed and stored by the core itself.
> *Serves:* S1, S10. *Verified by:* code review.

> **R-ARC-10.** Time enters the core only as host events (R-CORE-3). No property relies on wall-clock
> time.
> *Serves:* S10. *Verified by:* time-free model.

> **R-ARC-11.** Wake-up of a sleeping device, nearby discovery, and pairing by an on-screen code are host
> adapters. The core knows of them only through the events "link up" and "link down".
> *Serves:* scope. *Verified by:* code review.

Layers from bottom to top: transport and adapters (outside the standard), wire format, membership,
communication (channels, calls, streams), local interface, application profiles (outside the standard).

Bus objects belong to two planes. The **control plane** consists of open signed objects: passport,
checkpoint, root change record, sealing key claim, join request, key request, relay access, and halt
proof. Any participant and any member relay verifies and stores them; a member relay distinguishes them
by object kind, and no "publish" right is needed for them. An external relay stores and forwards them
only wrapped, without reading them (Section 11.1). The **data plane** consists of encrypted channels, calls, and
streams. A control-plane object never travels as a channel publication.

### 4.1. Selection Principles and Comparison with Established Systems

A mechanism enters the bus core only if it passes the principles below. Every decision to remove or
keep a mechanism cites a principle, not an opinion.

| Principle | Source | What it decided in this specification |
| --- | --- | --- |
| End-to-end argument: a lower layer does only what cannot be done correctly at the endpoints | Saltzer, Reed, Clark, "End-to-End Arguments in System Design", 1984 [SALTZER-E2E] | The core does not know the data format; the format tag was removed. The "secret" class was removed: the source decides who reads a channel. Frame padding on the link is left to the transport. The "link silent" event was removed: link liveness is the transport's knowledge. |
| Economy of mechanism: one simple mechanism per job | Saltzer, Schroeder, "The Protection of Information in Computer Systems", 1975 [SALTZER-PROT] | A channel key instead of a wrap per reader. One frame limit for everyone. One tool for the cryptographic lemmas. Device wake-up is not part of the relay requirements. |
| Least common mechanism: as little shared between users as possible | Ibid. | No shared service for several applications and no application identifier. One application is one bus. |
| Least privilege and fail-safe defaults | Ibid. | Passport rights are kept, including the read right: a device without it receives no channel keys, whatever the source decides. A new device without permits cannot invoke any action. |
| Separation of privilege: a critical action requires two independent keys | Ibid. | The user-presence key and confirmation-class actions are kept. A root change requires both K1 and K2. |
| Complete mediation: every access is checked | Ibid. | Every message is checked against the recipient's current checkpoint; no decisions are cached. |
| Open design: security does not depend on secrecy of the design | Ibid. | Format, models, and conformance suite are public. |
| Narrow waist: the smaller the common layer, the more systems can build on it | Beck, "On the Hourglass Model", 2019 [BECK] | A small, stable core; applications are described by profiles outside it. |
| Application-level framing: each transmission unit is processed independently of its neighbours | Clark, Tennenhouse, "Architectural Considerations for a New Generation of Protocols", 1990 [CLARK] | A publication and a stream chunk are decrypted independently. The lossy stream mode rests on this. |

The set of transfer patterns was compared with established device buses and real-time middleware. A
pattern found in none of them does not enter the core. A pattern found in them and needed by devices
MUST be in the core.

| Transfer pattern | USB | IEEE 1394 | DDS | D-Bus | CPB |
| --- | --- | --- | --- | --- | --- |
| Command with response | control | asynchronous | request/reply | method call | call |
| Short event | interrupt | asynchronous | topic, no history | signal | channel, depth 0 |
| Current state | none | none | topic, keep last | property | channel, depth 1 |
| History of last N | none | none | topic history depth | none | channel, depth N |
| Bulk, reliable | bulk | asynchronous | none | file descriptor passing | blob, ordered stream |
| Live stream, loss tolerated | isochronous | isochronous | best-effort topic | none | lossy stream |
| Device description | descriptors | Configuration ROM | participant and topic discovery | introspection | system channel "node info" |

## 5. Wire Format

All bus structures are encoded with one strict CBOR profile in which every value has exactly one byte
representation.

> **R-FMT-1.** The CBOR profile [RFC8949] admits five types: unsigned integer up to 2^53 - 1, byte
> string, UTF-8 text string, array, and map with integer keys 0..65535 in strictly ascending order.
> Everything else MUST be rejected.
> *Serves:* S17. *Verified by:* vectors, fuzzing.

> **R-FMT-2.** Lengths and integers MUST use the shortest form. Indefinite lengths MUST NOT be used. A
> field holding its default value MUST be omitted, and an explicit encoding of it MUST be rejected. A
> default value exists only for a field for which the schema of Appendix C names one; in version 1 there
> is exactly one such field.
> *Serves:* S17. *Verified by:* vectors, one per violation.

> **R-FMT-3.** For every accepted byte string `b`, `encode(decode(b)) = b` MUST hold.
> *Serves:* S17. *Verified by:* Kani, fuzzing, a second decoder.

> **R-FMT-4.** Nesting depth MUST NOT exceed 4, and a container MUST NOT hold more than 128 items. A
> signed object inside another object is carried as a byte string and decoded on its own; its depth
> count starts afresh, and such embedding is allowed at most two levels deep. Decoding is non-recursive
> and does not allocate. Appendix B MUST show the deepest object and the longest list of the format.
> *Serves:* S17. *Verified by:* Kani, fuzzing.

> **R-FMT-5.** Bit sets (rights, actions) MUST be encoded as fixed-length byte strings, not as integers.
> *Serves:* S17. *Verified by:* vectors.

> **R-FMT-6.** A signed object is an envelope `[body, sig]` or `[body, sig, sig2]`. The signature is
> computed over `label || 0x00 || body`. The labels of different object kinds are distinct, and none is a
> prefix of another. Passport, checkpoint, and root change record split the body into a head (bus,
> generation, number) and the rest, and the signature is computed over the label, the hash of the head,
> and the hash of the rest, as for a publication. Two conflicting records with the same number are then
> proven by one short message (R-MEM-10); this is how equivocation evidence works in Certificate
> Transparency [RFC6962].
> *Serves:* S2, S4. *Verified by:* Tamarin, vectors.

> **R-FMT-7.** The identifier of a signed object is SHA-256 of `body`. The signature is not part of the
> identifier. For a record with a head, it is SHA-256 of the pair of hashes of the head and the rest.
> *Serves:* S8. *Verified by:* model, vectors.

> **R-FMT-8.** An ECDSA P-256 signature MUST be accepted only in the 64-byte form `r || s` with low `s`.
> *Serves:* S17. *Verified by:* vectors.

> **R-FMT-9.** The bus identifier is SHA-256 of `"cpb bus v1" || 0x00 || first root key || K1 || K2`,
> 32 bytes. The device identifier is the first 16 bytes of SHA-256 of the device key. Keys in both
> formulas are taken in encoded form, including the algorithm identifier (Appendix B, Section B.1). The
> generation of the first Root is 1.
> *Serves:* S4, S9. *Verified by:* vectors, Tamarin.

> **R-FMT-10.** Every signed and every sealed object MUST contain the bus identifier. An object of
> another bus MUST be rejected before signature verification. There is one exception: a stream chunk and
> a blob segment carry no bus identifier. Their key is derived from the call or publication in which the
> bus is named, so a chunk of another bus does not decrypt.
> *Serves:* S4. *Verified by:* model, test.

> **R-FMT-11.** Every key is encoded as a pair `[algorithm, bytes]`. Algorithm identifiers: 1 ECDSA
> P-256, 2 X-Wing, 3 SLH-DSA-SHA2-128s. Identifiers 4..15 are reserved for post-quantum and hybrid
> signatures. An unknown identifier MUST be rejected.
> *Serves:* L2. *Verified by:* vectors.

> **R-FMT-12.** A frame is a 2-byte big-endian length followed by a body of at most 16384 bytes. The
> body is either a message map with the kind field `t`, or a binary stream chunk or blob segment. The
> most significant bit of the length field distinguishes them: 0 for a map, 1 for a binary chunk. The
> length itself occupies the low 15 bits. The limit is the same for all participants.
> *Serves:* S17. *Verified by:* vectors, fuzzing.

> **R-FMT-13.** The bus does not define frame padding on the link; that is the transport's concern. The
> bus pads only the publication content (R-CH-14), so that a relay does not see the exact data size.
> *Serves:* L5. *Verified by:* vectors, relay test.

> **R-FMT-14.** Extension rule. Fields 0..255 are critical: an unknown field in this range MUST cause the
> object to be rejected. Fields 256..65535 are optional: an unknown field MUST be preserved when
> forwarding and MUST NOT affect any decision.
> *Serves:* versioning. *Verified by:* vectors, model.

> **R-FMT-15.** The version 1 format is frozen at release. A change to the critical range requires a new
> signature label and a new protocol version, announced in the hello message. The list of versions a
> party supports is covered by the hello signature, so the network and relays cannot force a downgrade.
> *Serves:* versioning. *Verified by:* release process.

The table of message kinds and the field tables of every object are specified in Appendix B. They are
derived from the requirements of Sections 6–11. The decisions that writing out the fields required are
listed in its Sections B.9, B.10, and B.11.

## 6. Membership

The membership state is defined by three kinds of records. Passports and checkpoints are signed only by
the Root; root change records only by the recovery key.

### 6.1. Records

| Record | Author | Contents |
| --- | --- | --- |
| Passport | Root | Bus, root generation, passport sequence number, device key, rights, optional user-presence key, list of permits. |
| Checkpoint | Root | Bus, root generation, checkpoint number, window start, bitmap of valid passports, next free passport number, list of relays, root device. |
| Root change record | K1 and K2 | Bus, generation number, new root key. |

Passport rights: read, publish, relay, and accept join requests. A permit is a triple: commander, set of
automatic actions, set of actions requiring confirmation. An action set is an 8-byte string; bit i - 1
corresponds to action i.

### 6.2. Requirements

> **R-MEM-1.** Passports and checkpoints have separate number sequences. Both MUST increase strictly
> within one root generation.
> *Serves:* S8. *Verified by:* model.

> **R-MEM-2.** A passport is valid for a verifier if it is signed by the Root of the current generation,
> its number is less than the "next free number" in the verifier's checkpoint, and its bit in the bitmap
> is 1.
> *Serves:* S4, S5. *Verified by:* model.

> **R-MEM-3.** A passport whose number is not less than the "next free number" MUST NOT be accepted until
> the verifier receives a newer checkpoint. When admitting a device, the Root issues the passport and the
> checkpoint together.
> *Serves:* S4. *Verified by:* model.

> **R-MEM-4.** Revocation is a new checkpoint with the bit cleared. A change of rights is a new passport
> with a new number and a checkpoint in which the old passport's bit is cleared.
> *Serves:* S5. *Verified by:* model.

> **R-MEM-5.** A node MUST accept a checkpoint only with a number greater than its own. The number and
> body of the checkpoint MUST be persisted before the node starts acting on it.
> *Serves:* S6. *Verified by:* model, power loss.

> **R-MEM-6.** The hello message, every publication, every key grant, and every call carry the sender's
> pair (generation, checkpoint number). A recipient with a smaller pair MUST request the checkpoint on
> that link and drop the message itself: the core has no wait buffer. A recipient with a larger pair MUST
> send its checkpoint. A node or relay that accepts a new checkpoint MUST immediately send it on all its
> links, so dropping happens only when frames are reordered, and the loss is recovered like any loss on
> the link. A halted node ranks its pair above every checkpoint of its generation: to a sender with a
> pair of the same generation it MUST answer with its halt proof (R-MEM-10) in place of a checkpoint, and
> it does so again on every such message, so a proof that was lost or dropped arrives with the next one.
> A permanently halted node (R-MEM-13) ranks above every pair of every generation: it answers every
> message that carries a pair, whatever its generation, with its halt proof of the two root change
> records.
> *Serves:* S5, L1. *Verified by:* model, simulator.

> **R-MEM-7.** A node MUST return its own passport and checkpoint when a link requests them. Who is
> answered on an unsigned request is defined by Appendix B (message `Get`). Other devices' passports are
> kept in a bounded cache; on receiving a new checkpoint, passports whose bit is cleared are removed from
> the cache.
> *Serves:* S5. *Verified by:* model.

> **R-MEM-8.** Two checkpoints with the same number and different bodies, or two passports with the same
> number and different bodies, from the Root of the current generation MUST put the node into the halted
> state. Records with the same body and different signatures are one record.
> *Serves:* S8. *Verified by:* model, test.

> **R-MEM-9.** In the halted state a node MUST NOT execute calls, MUST close streams, MUST NOT accept
> passports or checkpoints, MUST NOT publish, MUST NOT grant channel keys, and MUST NOT accept new
> publications or grants. Channel values accepted before the halt remain readable by the application.
> Only a root change record leaves the halted state.
> *Serves:* S8. *Verified by:* model.

> **R-MEM-10.** A node MUST keep the halt proof (the shared head of the two records, the two hashes of
> the rest, and the signatures), send it on every link as one `HaltProof` message (Appendix B,
> Section B.3) when it halts, and from then on send it to every sender that is behind it (R-MEM-6). The proof is self-contained and does not depend on delivery order (R-ARC-6). On
> receiving a valid proof for its bus, a node MUST halt whatever checkpoint it is at: a node that has
> moved ahead by number would otherwise drop the records themselves as old.
> *Serves:* S8. *Verified by:* model (the halt propagates).

> **R-MEM-11.** A root change record MUST be accepted if it is signed by both K1 and K2 from the bus
> identifier and its generation is greater than the current one. The node moves to that generation
> directly: intermediate records are not needed, because each record is signed by K1 and K2, not by the
> previous Root. Every participant, including the root device and the relay, stores the one most recent
> accepted record and returns it on request.
> *Serves:* S9. *Verified by:* Tamarin, model.

> **R-MEM-12.** After a root change only records of the Root of the new generation are valid. Passport
> and checkpoint counters start over. The new Root reissues the passports of the devices the owner keeps.
> *Serves:* S9. *Verified by:* model.

> **R-MEM-13.** Two root change records with the same generation and different bodies are a permanent
> halt (L6). Their halt proof is verified with K1 and K2 from the bus identifier alone, so a node
> accepts it whatever generation it is at, and the permanent halt reaches nodes of every generation
> (R-MEM-6).
> *Serves:* S8. *Verified by:* model.

> **R-MEM-14.** The checkpoint bitmap MUST NOT be longer than the profile limit. The window start moves
> only past numbers below which all bits are cleared. To move the window, the Root reissues the oldest
> valid passports with new numbers.
> *Serves:* limits. *Verified by:* model, Root test.

> **R-MEM-15.** Before every signature the Root MUST ensure that its counters are not less than the
> highest numbers it can receive from relays and nodes. The counters MUST be persisted before the
> signature is released.
> *Serves:* S8, G1. *Verified by:* test restoring the Root from an old backup.

> **R-MEM-16.** A device revoked by the group may continue to consider itself a member. The properties
> require only that members reject it.
> *Serves:* S5. *Verified by:* model (separate invariant).

> **R-MEM-17.** Loss or theft of the root key is remedied only by a root change. If the root key is
> intact and only the root device is replaced (for example, the key is on an external token), a new
> checkpoint naming the new root device and revoking the old one is sufficient.
> *Serves:* L4. *Verified by:* scenario test.

## 7. Device Enrollment

A device joins a bus in two steps: pairing with any member that has the right to accept join requests,
and a Root signature after the owner confirms.

> **R-JOIN-1.** Pairing is a password-authenticated key exchange using CPace [CPACE] between the joiner
> and the acceptor. The password is either a 16-byte secret from an on-screen QR code or a 6-digit short
> code that a person carries from one device to the other.
> *Serves:* S4. *Verified by:* Tamarin.

> **R-JOIN-2.** During pairing the joiner receives the bus identifier, the first root key, and the keys K1
> and K2, and checks that the bus identifier is derived from them. It takes the current root key only
> from the root change record of the current generation signed by K1 and K2; at generation 1 that is the
> first root key. Intermediate records are not needed (R-MEM-11). The acceptor receives the joiner's
> device key and proposed name.
> *Serves:* S4, S9. *Verified by:* Tamarin, vectors.

> **R-JOIN-3.** A failed pairing attempt MUST NOT let the adversary test more than one password guess.
> The number of attempts per code is bounded by a profile limit.
> *Serves:* S4. *Verified by:* Tamarin, test.

> **R-JOIN-4.** The acceptor prepares a join request: the joiner's key, an optional user-presence key,
> the name, the pairing transcript hash, the joiner's signature over all of these, and the acceptor's own
> signature. The transcript hash is that of the acceptor's own pairing session, and the acceptor checks
> the joiner's signature before sending the request, so a payload signed in another session and relayed
> by a man in the middle is refused. The Root verifies the joiner's signature, so the acceptor can
> substitute neither the presence key nor the name. A join request is a control-plane object, not a
> publication: an open header (bus, acceptor, its checkpoint number) and a body sealed to the sealing
> key of the root device. A relay sees who submitted the request but not the joiner's name or key.
> *Serves:* S4. *Verified by:* model.

> **R-JOIN-5.** The Root shows the owner the joiner's name, who accepted the request, and the fingerprint
> of the joiner's device key: 64 bits of the key hash, as 20 decimal digits. The passport is issued only
> after the owner confirms on the root device.
> *Serves:* S4. *Verified by:* scenario test, UI review.

> **R-JOIN-6.** No sequence of messages without a Root signature makes a device a member. An acceptor
> cannot issue a passport.
> *Serves:* S4. *Verified by:* model, Tamarin.

> **R-JOIN-7.** Before admission the joiner shows the fingerprint of its device key in the same form as
> the Root (R-JOIN-5). The Root's user interface MUST ask the owner to compare both fingerprints before
> confirming: otherwise a compromised acceptor substitutes its own key for the joiner's in the request.
> After admission the joiner shows the fingerprint of the bus it has joined.
> *Serves:* S4. *Verified by:* scenario test.

> **R-JOIN-8.** A relay holds join requests for the Root while it is offline. It recognizes them by
> object kind and keeps them in a separate buffer with its own quota. The number of requests is bounded;
> on overflow the oldest is evicted. The relay makes no decisions about requests.
> *Serves:* S14. *Verified by:* relay model.

> **R-JOIN-9.** The Root MAY pair a joiner itself, without an acceptor. It is the same exchange; no join
> request is prepared. The owner compares the device key fingerprint on both screens here too
> (R-JOIN-5, R-JOIN-7).
> *Serves:* S4. *Verified by:* Tamarin.

> **R-JOIN-10.** Bus creation: the root device asks the host to generate the root key, generates K1 and
> K2, computes the bus identifier, and issues its own passport and the first checkpoint. K1 and K2 are
> then exported to the owner for offline storage and erased from the device.
> *Serves:* S9. *Verified by:* scenario test.

## 8. Keys and Cryptography

Confidentiality is post-quantum from version 1; signatures are classical, with the migration designed
in.

| Purpose | Algorithm | Reference |
| --- | --- | --- |
| Root, device, user-presence, and K1 signatures | ECDSA P-256 with SHA-256 | [FIPS186-5] |
| K2 signature | SLH-DSA-SHA2-128s | [FIPS205] |
| Sealing a key to a reader | HPKE, base mode, KEM X-Wing (ML-KEM-768 and X25519), HKDF-SHA256, ChaCha20-Poly1305 | [RFC9180], [FIPS203], [XWING] |
| Content encryption | ChaCha20-Poly1305 | [RFC8439] |
| Key derivation | HKDF-SHA256 | [RFC5869] |
| Hash | SHA-256 | [FIPS180-4] |
| Pairing | CPace over X25519 with SHA-512 | [CPACE] |

> **R-KEY-1.** The core MUST NOT store or see the private root, presence, and device keys. It uses the
> host interface: generate a key, export the public key, sign. Decapsulation is done by the core itself:
> the private sealing keys and the channel keys are kept in the core's storage (R-CORE-5), because the
> core needs the HPKE context for the reply and stream keys. Where and how the host stores keys is not
> defined by the bus. Recommendation to hosts: non-exportable hardware-backed storage, and for the root
> key, user confirmation of every signature.
> *Serves:* S4, S10. *Verified by:* review of the host implementation.

> **R-KEY-2.** Every node has a sealing key with an epoch number. The node announces it with a sealing
> key claim signed by the device key: bus, device, epoch, key. The claim is a control-plane object: it is
> public, not encrypted, and requires no publish right.
> *Serves:* S1. *Verified by:* Tamarin.

> **R-KEY-3.** A sender MUST seal to a reader using the key from the claim with the highest epoch known to
> it. A claim whose epoch is not greater than the known one MUST be rejected.
> *Serves:* S13. *Verified by:* model.

> **R-KEY-4.** A node keeps the private keys of at most the N most recent epochs; N is set by the profile
> and is at least 2. An evicted key MUST be erased so that it cannot be recovered from storage.
> *Serves:* S13. *Verified by:* storage test, code review.

> **R-KEY-5.** An epoch change is triggered by a host event. The core never changes the epoch on its
> own.
> *Serves:* R-ARC-10. *Verified by:* code review.

> **R-KEY-6.** The only sealing algorithm in version 1 is X-Wing. Sealing with a classical algorithm alone
> MUST NOT be used.
> *Serves:* S1. *Verified by:* vectors.

> **R-KEY-7.** Secret values MUST be zeroized after use. Secrets MUST be compared in constant time.
> *Serves:* S1. *Verified by:* code review, tooling.

> **R-KEY-8.** Every key derivation and every signature uses its own label. The list of labels is part of
> Appendix B, and no label is used in two places.
> *Serves:* S2, S11. *Verified by:* Tamarin; CI check of the label list.

> **R-KEY-9.** A cipher key with nonce zero is used for exactly one message. For a sequence of messages
> under one key, the nonce equals the message number and never repeats.
> *Serves:* S1. *Verified by:* Tamarin, code review.

> **R-KEY-10.** Migration of the bus to a post-quantum signature is a root change: the root change record
> names a key of the new algorithm. Nodes that do not know the algorithm reject the record and stay on
> the previous Root, so the migration requires all nodes to be updated in advance.
> *Serves:* L2. *Verified by:* scenario test.

> **R-KEY-11.** A link key, which authenticates a member to one external relay in one relay epoch, is
> generated by the core from the link seed that the Root issued to the member (R-REL-13), with the
> signature algorithm of the device key, and is kept in the core's storage like a sealing key. It signs
> nothing but the hello on an external relay link. The relay epoch secret, the link seed, and the period
> secret of the Root are erased when the epoch they belong to has been closed at every external relay.
> *Serves:* S14, S18. *Verified by:* Tamarin, code review.

## 9. Channels and Publications

A node publishes data to a channel, and the channel itself determines how many publications are
retained: the latest one, the latest N, or none.

### 9.1. Structure of a Publication

The key belongs to the channel, not to the publication. The source grants the channel key to each
reader once; after that, publications are encrypted under this key and carry nothing per reader.

| Object | Part | Visible to | Contains |
| --- | --- | --- | --- |
| Key grant | Header | Everyone, including relays | Bus, source device, channel key generation, source checkpoint number, channel label, request nonce if the grant answers a key request, reader and the epoch of its sealing key, channel key commitment. |
| Key grant | Wrapped key | Everyone; only the reader can open it | The channel key, sealed to this reader. |
| Key grant | Signature | Everyone | Source signature over the header hash and the wrapped-key hash. |
| Publication | Header | Everyone, including relays | Bus, source device, channel key generation and publication number, source checkpoint number, channel label, channel key commitment, retention depth, size, and, if present, the hash and segment size of the encrypted blob. |
| Publication | Content | Channel key holders only | Channel number, flags, data, padding. |
| Publication | Signature | Everyone | Source signature over the header hash and the hash of the encrypted content. |

The channel label is 16 bytes of a hash over the bus, the source device, and the channel number. A relay
distinguishes channels by it but does not know which channel it is.

### 9.2. Requirements

> **R-CH-1.** The channel key K is 32 random bytes generated by the source for the pair (source,
> channel). The key commitment is `HKDF(K, "cpb chan commit v1")`, 32 bytes. The commitment serves as the
> name of the key in headers.
> *Serves:* S3. *Verified by:* Tamarin, vectors.

> **R-CH-2.** The source grants K to each reader in a separate signed message: HPKE sealing of K to the
> reader's sealing key, with the hash of the grant header as associated data. A reader that opened K MUST
> check the commitment. The format does not limit the number of readers of a channel.
> *Serves:* S1, S3. *Verified by:* Tamarin, vectors.

> **R-CH-3.** The content key and the blob key are derived from K and the publication header hash with
> different labels. The header contains the publication number, so every publication has its own key.
> Content is encrypted with nonce zero; a blob segment with a nonce equal to the segment number.
> *Serves:* S1. *Verified by:* Tamarin, vectors.

> **R-CH-4.** The source signature covers the header hash and the hash of the encrypted content; for a
> grant, the header hash and the wrapped-key hash. A message without a valid signature MUST be rejected
> before decryption. Publications and grants are not modified in transit.
> *Serves:* S2, S15. *Verified by:* Tamarin, relay test.

> **R-CH-5.** The source MUST generate a new channel key and grant it before the next publication if: a
> reader of the channel is no longer valid under the source's checkpoint; the application removed a
> reader; the host signalled "rotate key epoch"; or the key did not survive a reboot of the source. A
> removed reader does not receive the new key. When a device leaves the readers, the source marks every
> own channel that has a key for rotation in the same event and persists the mark (R-CORE-5, R-CORE-7):
> after a reboot it no longer knows whom it granted the key, so the condition cannot be recomputed.
> While the mark is set, the source grants the marked key to no one; a grant waits for the new key.
> The source persists the readers still to be granted the new key until each grant is sent, so a reboot
> between the new key and its grants does not skip them (R-CORE-5).
> *Serves:* S5. *Verified by:* model, Tamarin.

> **R-CH-6.** The source grants the current channel key to a new reader. With it the reader gains access
> to the retained publications under this key. If the application does not want that, the source rotates
> the key first.
> *Serves:* S1. *Verified by:* model.

> **R-CH-7.** A reader erases the previous channel key once it has accepted the next one and has no
> unprocessed publications under the previous one left. A compromised reader discloses only publications
> under the keys it still holds.
> *Serves:* S1. *Verified by:* storage test, model.

> **R-CH-8.** The source keeps two numbers per channel. The channel key generation increases with every
> new key. The publication number increases with every publication of the channel and is not reset when
> the key changes. Both MUST increase strictly over the whole lifetime of the device key, and the source
> MUST persist the new value before sending. Publication numbers MAY be reserved in blocks: the source
> persists the upper bound of the block, hands out numbers up to it without writing, and after a reboot
> continues from the next block. Numbers may therefore have gaps, and the recipient does not wait for
> them (as with a PostgreSQL sequence cache). This removes one flash write per publication. A grant
> carries the generation; a publication carries the generation and the number.
> *Serves:* S12. *Verified by:* model, power loss.

> **R-CH-9.** For every channel whose key it holds, the recipient stores the highest accepted generation,
> the highest accepted publication number, and the window floor. It MUST accept a grant only with a
> generation not less than its own; at equal generation the commitment MUST match. It MUST accept a
> publication only under a key it holds, and only with a number greater than its highest, or with a
> number in the window [floor, highest] if it does not currently hold that publication. The floor starts
> at 1 and only rises: when publications leave the retained ones because the depth is exceeded
> (R-CH-11), the floor moves to the lowest retained number, and a clearing publication moves it above
> its own number (R-CH-10). Losing the retained publications in a reboot does not move it, so a
> publication that once left the window is never accepted again. At depth 0 there is no window, and a
> publication of depth 0 is accepted only as a new one. A rebooted recipient thus refills its retained
> publications, and a repeat of an already accepted one changes nothing, as in the DDS/RTPS reader
> history cache [DDS-RTPS]. These values change
> only after full verification and decryption. A publication under a key the recipient does not hold is
> dropped, changes no state, and triggers one key request per channel (R-CH-18). Whoever sends or
> forwards a grant follows it immediately with the retained publications of the channel (R-CH-11), so
> what was dropped arrives again. The core has no choice between "hold or drop": the reaction is single.
> A channel record is not evicted while the recipient holds the channel key (R-CORE-4) and is erased
> together with the key.
> *Serves:* S12. *Verified by:* model, power loss.

> **R-CH-10.** Channel retention is set by a single number in the publication header, the depth: from 0
> to the profile limit. There are no separate modes: "no retention" is depth 0, "latest" is depth 1,
> "log of N" is depth N. At depth 1 or more, a publication without data and without a blob clears the
> channel at the recipient and at the relay. A clearing publication accepted in the window clears the
> publications up to its own number, and the floor moves above it. A clearing publication and a
> publication of depth 0 are never retained. The depth of the latest accepted publication of the channel
> governs: when it decreases, the excess old publications are deleted immediately; the depth of a
> publication accepted in the window does not change it.
> *Serves:* S12. *Verified by:* model.

> **R-CH-11.** At depth N ≥ 1 the source, the recipient, and the relay retain the N latest publications
> of the channel in number order. At depth 1 a new publication replaces the previous one. A holder, that
> is the source or a relay, after the hello of a channel reader sends it the latest key grant of the
> channel followed by the retained publications in number order (for a relay this is R-REL-3). State
> thus reaches a reader also on a direct link without a relay. The source keeps its own publications in
> memory and after its own reboot starts with an empty window.
> *Serves:* S12. *Verified by:* model.

> **R-CH-12.** Depth 0: a relay forwards the publication only to connected readers and does not retain
> it. The recipient delivers it to the application and does not retain it.
> *Serves:* S15. *Verified by:* relay model.

> **R-CH-13.** A recipient MUST accept publications and grants only from a valid member (R-MEM-2) with the
> publish right. For channel 0 this right is not required, and the recipient computes its label itself.
> The source grants a channel key only to a valid member with the read right, and a recipient without
> this right MUST reject the grant.
> *Serves:* S4, S16. *Verified by:* model.

> **R-CH-14.** Content is padded to a padding bucket. The source chooses the buckets; the defaults are in
> Section 13. The reader's core does not check the buckets. Data plus padding MUST NOT exceed 4096 bytes,
> and the padding MUST consist of zero bytes; otherwise the publication MUST be rejected.
> *Serves:* L5. *Verified by:* vectors.

> **R-CH-15.** A blob is transferred in segments separately from the publication, in the same binary
> frame as a stream chunk. Each segment is encrypted with the blob key; the associated data includes the
> publication header hash, the segment number, and a last-segment flag. A reader therefore verifies each
> segment at once and detects a truncated blob. The hash in the header is SHA-256 of the whole encrypted
> blob: a relay verifies the blob by it without the key and does not serve it to readers before
> verification. A reader requests segments by publication header hash and segment number, from any
> position. The blob is delivered to the application after all segments are verified.
> *Serves:* S2. *Verified by:* vectors, fuzzing.

> **R-CH-16.** Channel numbers 0..15 are reserved for the bus itself. Channel 0 is the node info: an
> ordinary encrypted channel to which any valid member may publish. Its readers are all valid members
> with the read right. The content of a channel 0 publication is `NodeInfo` (Appendix B, Section B.5).
> The core publishes it itself: the node name is taken from pairing and changed by the "set node name"
> operation (R-API-2). Numbers 1..15 are reserved. Sealing key claims and join requests are not channel
> traffic; they are control-plane objects (Section 4). The application cannot publish to these channels
> through the local interface.
> *Serves:* S16. *Verified by:* interface test.

> **R-CH-17.** Data is up to 4096 bytes inside the publication. Larger payloads are transferred as a
> blob. The core does not parse data and does not know its format.
> *Serves:* R-ARC-2. *Verified by:* code review.

> **R-CH-18.** A reader that has no valid channel key (the wrapped key is sealed to an erased epoch, the
> key is lost, or the subscription is new) sends the source a key request: bus, source device, reader,
> channel label, current sealing key epoch, 16 random bytes, device key signature. The source answers
> with a grant of the current key carrying these bytes in its header, if the reader is still a reader of
> the channel. The request is a control-plane object: a relay keeps one request per pair (reader,
> channel label) and delivers it to the source when it connects.
> *Serves:* S1, S12, S13. *Verified by:* model, Tamarin.

The cost of this design compared with a key per publication: a reader stores 32 bytes per channel, and
a compromised reader discloses the publications of the channel since the last key rotation. The gain: a
publication carries about 200 bytes of overhead instead of 1168 bytes per reader, the expensive X-Wing
operation is performed per grant rather than per publication, and there is no limit on the number of
readers.

## 10. Calls and Streams

A call is executed only if the commander signed it over a random nonce that the target issued to it and
has not yet consumed.

### 10.1. Call Flow

1. The commander requests a nonce from the target. The target answers with the current value of its
   nonce slot for this commander, creating the slot on the first request.
2. The commander signs the call with this nonce and seals the command to the target's sealing key.
3. The target verifies the signature, the permission, and the nonce. If the nonce matches, it erases it,
   executes the action, and replies. The reply carries the next nonce, so the next call takes a single
   round trip.
4. On a mismatch the target executes nothing, leaves the slot unchanged, and returns the current nonce.
   If the commander has no slot yet (for example after "reset nonces"), the refusal is the answer to a
   nonce request: the target creates the slot and returns its value.

### 10.2. Call Requirements

> **R-CALL-1.** A nonce slot exists per pair (commander, target), is kept in RAM only, and holds 16
> random bytes.
> *Serves:* S10. *Verified by:* Tamarin, model.

> **R-CALL-2.** The call body contains: the bus, the hash of the signing key, the commander device, the
> target, the nonce, the commander's root generation and checkpoint number, the epoch of the target's
> key, and the sealed command. The signature covers the whole body.
> *Serves:* S10. *Verified by:* Tamarin.

> **R-CALL-3.** The command contains the action number 1..64, the arguments, and, if the commander
> requests a stream, the stream mode and the commander's initial credit. It is sealed with HPKE to the
> target's key; the other body fields are associated data.
> *Serves:* S1, S10. *Verified by:* Tamarin.

> **R-CALL-4.** The target MUST execute the action only if the nonce matched the slot and the signing key
> has the right to this action under the target's passport. The class of an action is the target's:
> it comes from the permits in the target's passport, never from the call. An automatic action is signed
> by the commander's device key. A confirmation-class action is signed by the commander's user-presence
> key or by the root key. The root key has the right to every action; the device and user-presence keys
> of the root device have only the rights the target's passport gives that device.
> *Serves:* S10. *Verified by:* Tamarin, model.

> **R-CALL-5.** A matched nonce MUST be erased before the action is executed. One nonce executes at most
> one action.
> *Serves:* S10. *Verified by:* model.

> **R-CALL-6.** On a nonce mismatch the slot MUST NOT change. The answer to a mismatch requires neither
> decapsulation nor a signature from the target. If there is no slot for the commander, the answer is
> that to a nonce request: the slot is created under the conditions of R-CALL-7, so a call that a reset
> made stale costs one round trip, not two.
> *Serves:* S14. *Verified by:* model, load test.

> **R-CALL-7.** The target creates slots only for commander devices named in its passport and for the
> root device named in the checkpoint. A call signed by the root key comes from the root device. A nonce
> request from anyone else is not answered. When a device stops being a commander of the target (a new
> passport of the target, or the device's revocation), its slot is erased in the same event.
> *Serves:* S14. *Verified by:* model.

> **R-CALL-8.** The host event "reset nonces" erases all slots. The host raises it from its own uptime
> counter with the period set by the profile. A reboot erases the slots by itself. In the same event a
> node, as a commander, forgets the nonces it holds for targets with no call in flight, so its next call
> starts with a nonce request: a held nonce older than the period has most likely been erased at the
> target, and a call over it would end with the outcome unknown (R-CALL-13).
> *Serves:* S10. *Verified by:* model (nondeterministic event), simulator.

> **R-CALL-9.** The reply is encrypted with a key exported from the HPKE context of this call ([RFC9180],
> Section 5.3), with the hash of the call body as associated data. The reply carries no separate
> signature: only the target can open the context.
> *Serves:* S11. *Verified by:* Tamarin.

> **R-CALL-10.** The reply contains the result code, an optional message, data, and stream number, and
> the next nonce. A reply that opens a stream also carries the target's initial credit. The open header
> of the reply is: bus, target, commander device, and the hash of the call body without the signature
> (an ECDSA signature can be rewritten without losing validity, so a hash of the envelope would not be
> unique). The relay routes the reply by it, and the commander finds its call by it. The execution
> result is never sent outside the ciphertext.
> *Serves:* S1, S11. *Verified by:* vectors.

> **R-CALL-11.** Result codes 0..255 belong to the bus, 256..65535 to the application. Bus codes: done,
> no right, denied by the user, bad arguments, action not served, too many streams. A target reports a
> halted bus with a halt proof (R-MEM-10), not with a result code.
> *Serves:* interface. *Verified by:* vectors.

> **R-CALL-12.** A relay informs the commander that the target is unreachable with its unsigned refusal
> (Appendix B, `RelayRefusal`, code 5). The commander treats it as a hint and does not conclude from it
> that the call was not executed.
> *Serves:* L7. *Verified by:* interface test.

> **R-CALL-13.** There are two open refusals before decapsulation, and the target checks them in this
> order: first "nonce mismatch" (carrying the current nonce), then "stale key epoch" (carrying the
> target's current sealing key claim). A halted target answers not with a refusal but with a halt proof
> (R-MEM-10), which can be verified. The refusals are unsigned, do not consume the nonce, and require
> neither decapsulation nor a signature from the target. The commander treats them as hints. After
> "stale key epoch" it retries the call automatically, with the same nonce and the new key: this refusal
> means the nonce matched and was not consumed, so the action is executed at most once. After "nonce
> mismatch" it does not retry automatically: a network adversary obtains such a refusal by replaying an
> already executed call and withholding the reply, and an automatic retry would execute the action
> twice. The core reports to the application that the outcome of the call is unknown (L7), and retries
> only a call that the application marked as idempotent when sending it. Only the party that knows the
> meaning of an action knows whether to repeat it (Birrell and Nelson, "Implementing Remote Procedure
> Calls", 1984; the end-to-end argument of Section 4.1). A "no right" refusal can only be given after
> decapsulation; it travels in the encrypted reply, and the nonce is then consumed. Per call the
> commander makes at most one automatic retry per kind of open refusal. A confirmation-class action is
> never retried automatically: a new call requires a new user confirmation. A "stale key epoch" refusal
> is accepted only if the attached claim is signed by the target's key and its epoch is strictly greater
> than the one known to the commander.
> *Serves:* S8. *Verified by:* model.

### 10.3. Stream Requirements

> **R-STR-1.** A stream is opened by the reply to a call. The keys of the two directions are derived from
> the HPKE context of this call with different labels.
> *Serves:* S11. *Verified by:* Tamarin.

> **R-STR-2.** A stream chunk contains: target and commander, a direction bit (from the commander or from
> the target), the stream number, the chunk number, flags (data, credit, end), the amount of added credit
> in bytes if the credit flag is set, and the ciphertext. Exactly one of the three flags is set, so every
> chunk has one meaning; a chunk with any other combination closes the stream. The cipher nonce equals
> the chunk number; the chunk header is associated data.
> *Serves:* S1, S11. *Verified by:* vectors, Tamarin.

> **R-STR-3.** A stream is opened in one of two modes, named in the call. Ordered: the recipient MUST
> accept a chunk only with a number one greater than the previous one; anything else closes the stream.
> Lossy: the recipient accepts a chunk with a number greater than the highest accepted, neither waits for
> nor requests the missing ones, and silently drops a chunk with a lower or equal number. Credit does not
> apply in this mode: the recipient drops the excess. A chunk of a stream the recipient does not have
> (the stream is closed or the recipient rebooted) is dropped in both modes, changes no state, and
> causes no answer: there is no stream key to answer with, and an open refusal would let an outsider
> probe which streams are alive.
> *Serves:* S11. *Verified by:* model.

> **R-STR-4.** A sender MUST NOT send more data than the credit granted to it. Each direction has its own
> credit. The commander's initial credit travels in the command, the target's initial credit in the
> reply; after that each side adds credit with chunks carrying the credit flag. A chunk with its header
> fits in one frame. Exceeding the credit closes the stream.
> *Serves:* S14. *Verified by:* model.

> **R-STR-5.** A stream is closed by an "end" chunk, by the host event "link down", by the event "reset
> nonces" when there has been no traffic since the previous such event, by a halt of the bus, and by the
> revocation of either party.
> *Serves:* S5, S8. *Verified by:* model.

> **R-STR-6.** The number of open streams is bounded by the profile. Opening beyond the limit is
> rejected with a result code, not by tearing down existing streams.
> *Serves:* S14. *Verified by:* model.

> **R-STR-7.** A relay forwards stream chunks without modification and MAY refuse to serve streams at
> all.
> *Serves:* S15. *Verified by:* relay test.

## 11. Relays

A relay stores and forwards what it cannot read; its honesty is needed only for delivery, not for
security.

A relay is either a **member relay**, a node of the bus with the relay right, or an **external relay**,
a server that is not a member and serves many unrelated buses at once. A member relay sees the bus as a
member does (L5). An external relay sees it only under aliases that change with every relay epoch and
differ between relays (S18); the rules for it are in Section 11.1 and its formats in Appendix B,
Section B.10. R-REL-3, R-REL-4, R-REL-8, R-REL-11, and R-REL-12 apply to both kinds of relay; the other
requirements of this list apply to a member relay unless they name an external relay.

> **R-REL-1.** A member relay accepts a device connection after a hello in which the device presents its
> passport, its checkpoint, and a device key signature over the nonces of both sides and the list of
> versions. Before the hello, and when root generations differ, the sides exchange control-plane
> objects: the latest root change record, the checkpoint, and the device's passport. These objects are
> self-verifying, so a node with an old passport receives a new one and repeats the hello. The relay
> serves them to anyone who presents a passport of any generation of this bus.
> *Serves:* S14. *Verified by:* Tamarin, model.

> **R-REL-2.** A member relay MUST verify the Root signature on passports and checkpoints and the source
> signature on publications. It MUST NOT store or forward anything unverified. An external relay
> verifies what R-REL-15 lists instead.
> *Serves:* S14, S15. *Verified by:* relay model.

> **R-REL-3.** A relay retains publications keyed by (bus, source, channel label) according to the
> retention depth in the header and serves them to a reader on connection in publication number order.
> It keeps the latest key grant for each quadruple (bus, source, channel label, reader) against the
> source's quota, whether or not there are publications, and serves it before the publications. A grant
> with a generation not less than the held one replaces it: at equal generation it carries the same key
> and may carry the nonce of a key request (R-CH-18). A key request (R-CH-18) is deleted once the relay
> has forwarded to the reader a grant with the same nonce or has received a new request from the reader.
> An external relay applies the same rules to aliases, and compares by upload counter where this
> requirement compares generations and publication numbers (R-REL-17).
> *Serves:* delivery. *Verified by:* relay model, external relay model, simulator.

> **R-REL-4.** Relay memory is divided into quotas: per bus and per source within a bus. A source that
> exhausted its quota evicts only its own publications. For an external relay, the bus is a bus alias and
> the source is the alias that uploaded; the Root signs the limits in the ticket. The eviction order and
> the invariant are specified in Appendix B, Section B.10.
> *Serves:* S14. *Verified by:* model (fair-share invariant).

> **R-REL-5.** A relay serves a publication only to devices for which it has seen a key grant of this
> channel, and to the source itself. An external relay applies this rule to aliases.
> *Serves:* L5. *Verified by:* relay model.

> **R-REL-6.** A member relay deletes what it stores for a device that is revoked under its checkpoint,
> and accepts nothing more for or from it. A member relay that accepts a checkpoint whose `relays` list
> does not hold its device identifier deletes everything it stores for the bus, including buffered join
> requests, and serves the bus no more. An external relay deletes by the closing ticket instead
> (R-REL-19).
> *Serves:* S5. *Verified by:* relay model, external relay model.

> **R-REL-7.** A member relay stores and serves on request the latest checkpoint it knows, passports,
> sealing key claims, and the latest root change record. These are public bus data. An external relay
> stores them wrapped, as R-REL-18 states.
> *Serves:* S5, L1. *Verified by:* model.

> **R-REL-8.** A relay forwards calls, replies, and stream chunks to connected devices and does not store
> them.
> *Serves:* S15. *Verified by:* relay model.

> **R-REL-9.** A relay holds join requests for the Root (R-JOIN-8). An external relay holds them under the
> bus alias, wrapped (R-REL-18).
> *Serves:* L5. *Verified by:* adapter test.

> **R-REL-10.** An external relay does not distinguish buses by content and requires no owner account.
> Everything it needs to know about a bus alias is in the ticket of that alias, and it never learns which
> bus an alias belongs to.
> *Serves:* scope. *Verified by:* test: one relay, 1000 buses.

> **R-REL-11.** Every property S1–S14 holds when the relay behaves arbitrarily. The delivery properties
> (R-REL-3) require an honest relay and connectivity.
> *Serves:* S15. *Verified by:* model with a malicious relay.

> **R-REL-12.** A node MAY be connected to several relays at once. The same publication arriving over
> different paths is accepted once (R-CH-9). A node passes a newer checkpoint and a newer root change
> record from one member relay to another (R-MEM-6), so a lagging member relay catches up without the
> Root. An external relay takes Root-signed objects only from the root device (R-REL-18) and catches up
> when the root device next connects; through it, members still pass newer records to each other as
> forwarded objects.
> *Serves:* S12. *Verified by:* simulator.

### 11.1. External Relays

An external relay sees a bus only through pseudonyms. The Root starts a new relay epoch after every
revocation; in each epoch every member receives a secret that names everything on external relay links
and a seed from which it generates its link keys. The relay never learns the secret, so for it the
aliases of different relays and different epochs are unrelated random strings. This is the approach of
directory blinding in onion services [TOR-V3], applied to storage and quotas. The formats are in
Appendix B, Section B.10.

> **R-REL-13.** The root device keeps a relay epoch number, counted from 1 by each root device within a
> root generation, and for
> each epoch a fresh random 32-byte relay epoch secret and a fresh random period secret, which the root
> device never discloses. It MUST start a new epoch with every checkpoint that clears a passport bit or changes the
> `relays` list, and MAY start one on the "rotate key epoch" time event on the root device (R-CORE-3) or
> at the owner's request. For each epoch the root device issues to every valid member a relay access
> object, signed by its device key and sealed to the member's latest sealing key claim: the relay epoch secret, a
> fresh random link seed for that member, and the bus alias of each external relay of the checkpoint. It
> issues one to a member admitted during the epoch, and issues the current one again, sealed to the new
> key, when it receives a newer sealing key claim of a member. A member accepts a relay access object
> only if it is signed by the device key of the root device named in its checkpoint, and orders relay
> access objects by (root device, epoch): when it accepts a checkpoint that names another root device,
> it drops the relay access object it holds and accepts the next one of the new root device whatever its
> epoch. A relay access object signed by a root device that its checkpoint no longer names is rejected.
> A member never
> sends the relay epoch secret, its link seed, or anything derived from them in the open.
> *Serves:* S5, S18. *Verified by:* external relay model (a new epoch follows every cleared bit and every
> change of the `relays` list; probe: the key of a replaced root device issues a far-ahead epoch, and
> members must still return to the relays of the new root device), Tamarin.

> **R-REL-14.** For an external relay with identifier `RelayId`, the device aliases, the label aliases,
> and the wrapping keys are derived from the relay epoch secret and `RelayId`; a member's link key is
> generated from its link seed and `RelayId` (R-KEY-11); the bus alias is the hash of the period key,
> which the Root derives from its period secret and `RelayId`. Every member computes the alias of every
> other member and of every label it uses without asking anyone. The derivations are in Appendix B,
> Section B.10.
> *Serves:* S18. *Verified by:* vectors, Tamarin.

> **R-REL-15.** An external relay keeps, for each bus alias, the ticket with the greatest number whose
> period key hashes to that alias. It accepts a device link only after a relay hello that presents a
> device alias and a link key with a proof that the pair is a leaf of the ticket's members tree, and an
> authentication signed by that link key. It verifies no other signature and stores or forwards nothing
> but wrapped objects from admitted aliases.
> *Serves:* S14, S18. *Verified by:* Tamarin, external relay model.

> **R-REL-16.** A member sends everything through an external relay inside a wrapped object. The relay
> sees only its open fields: class, sender alias, target or reader alias, label alias, object kind,
> upload counter, retention depth, and size. The body is the frame the member would send on a member
> link, encrypted with ChaCha20-Poly1305 under a single-use key derived from the relay epoch secret,
> `RelayId`, and a random 32-byte salt. The recipient decrypts the body and applies to the inner object
> every check it applies on a member link; anything that fails is dropped.
> *Serves:* S15, S18. *Verified by:* Tamarin, vectors, fuzzing.

> **R-REL-17.** No open field of a wrapped object carries a number that is the same on two relays or in
> two epochs. The upload counter starts at 1 for each uploader in each relay epoch at each relay and
> grows by one with every stored object; it is the only order an external relay knows, so it survives a
> reboot (R-CORE-5). An uploader MUST NOT upload, under one alias, an object older than one it has
> already uploaded for the same channel, or for the same channel and reader: a grant of a lower key
> generation, or a publication of a lower number. Its recipients reject such an object anyway
> (R-CH-9); the rule keeps the relay from replacing the newer one. A blob size is rounded up to the
> sender's padding bucket (R-CH-14).
> *Serves:* S18. *Verified by:* Tamarin probe, vectors.

> **R-REL-18.** Checkpoints, passports, root change records, and relay access objects are signed by the
> Root and its root device. An external relay accepts them only from the alias of the root device named
> in the ticket, and keeps the latest of each kind, per subject alias for passports and relay access
> objects. The root device uploads every new checkpoint, passport, and root change record to every
> external relay of the checkpoint right after it is signed, and to a relay it cannot reach at the next
> connection: otherwise devices that meet only through that relay stay on the old checkpoint longer
> than L1 requires. A sealing key
> claim and a key request are kept in the slot of the alias that uploaded them, as Appendix B,
> Section B.10 counts them. A join request from any admitted alias goes to the join buffer of the bus
> alias and is delivered to the root device's alias. A halt proof, and any other control-plane object a
> member passes on, travels as a forwarded object and is not stored; a forwarded object without a target
> goes to every connected alias of the bus alias.
> *Serves:* S7, S14, S18. *Verified by:* external relay model.

> **R-REL-19.** When a new relay epoch begins, the root device, at each external relay that remains in
> the checkpoint: uploads under the old bus alias, for each member that stays valid, the member's new
> relay access object addressed to the member's old alias (a bridge), and after a root change also the
> root change record and the checkpoint of the new generation, so that a member that slept through the
> root change can verify its bridge; registers the ticket of the new alias and uploads the control-plane
> objects under it; and only then sends the closing ticket of the old alias. Sources upload their
> retained publications and latest grants again under the new aliases. On a closing ticket the relay
> deletes everything under the old alias except the bridges and the records uploaded with them, accepts
> nothing more there except a relay hello of a listed alias that fetches its bridge, serves the records
> with each bridge, deletes each bridge once its addressee has fetched it, and deletes the records with
> the last bridge. A revoked device receives no bridge. A device that slept through
> several epochs follows the bridges from alias to alias, and MAY fetch a bridge through another external
> relay than the one it then uses. At a relay removed from the checkpoint, the closing ticket carries no
> bridges.
> *Serves:* S5, S18, delivery. *Verified by:* external relay model, simulator.

> **R-REL-20.** Bridges under a closed alias count against that alias's `bus_bytes`. How long an operator
> keeps a closed alias whose bridges have not all been fetched is a matter of agreement between the
> owner and the operator, like the limits of the ticket (Appendix B, Section B.10). A member that finds
> no bridge, or that cannot open one because it has erased the sealing key the bridge was sealed to,
> rejoins through a member link or a member relay, where it receives its current relay access object as
> a newcomer does after admission. A sleeping device does not rotate its sealing key, so the second case
> arises only for a device that rotated keys while reachable through member links alone.
> *Serves:* delivery (L3). *Verified by:* relay test.

## 12. Core State Machine, Interfaces, and Errors

### 12.1. Core State Machine

> **R-CORE-1.** The input events of the core are: start with restored state, link up, frame received,
> link down, application action, time event, storage write result, and host key operation result
> (signature, public key, or failure). There are no other inputs.
> *Serves:* R-ARC-1. *Verified by:* code review, model.

> **R-CORE-2.** The output effects of the core are: send a frame on a link; persist a record; deliver a
> publication, a call, or stream data to the application; request a host operation with the device,
> presence, or root key (the host produces a presence or root key signature only after user
> confirmation; the result arrives as an event, and the core does not wait for it); report a rejection
> with a rule code. There are no other outputs.
> *Serves:* R-ARC-1. *Verified by:* code review, model.

> **R-CORE-3.** Time events are "reset nonces" and "rotate key epoch". The host raises them from its own
> uptime counter. The core makes no assumptions about the intervals between them.
> *Serves:* R-ARC-10. *Verified by:* model.

> **R-CORE-4.** The core operates in the memory that the host passed at start and allocates no other.
> The capacity of caches and the number of streams and nonce slots are determined by the size of this
> memory. When memory is short, the core refuses new work rather than destroying existing state.
> *Serves:* S14, S17. *Verified by:* Kani, low-memory test.

> **R-CORE-5.** The following MUST survive a reboot in the core's storage: the bus identifier with the
> root and recovery keys; the root generation and the checkpoint; the node's own passport; the latest
> accepted root change record; for its own channels, the key generation, the publication number, the
> rotation mark, and the readers still to be granted the new key (R-CH-5); the
> channel keys the node holds as source or reader, and for each of them the highest accepted generation
> and number, the window floor (R-CH-9), and the depth of the latest accepted publication (R-CH-10);
> the private sealing keys of the current epochs; the halt
> proof; the current relay access object and, per external relay, the upload counter of the current
> relay epoch; on the root device, the relay epoch secrets and period secrets of the epochs not yet
> closed at every external relay. The device, presence, and root keys are stored by the host (R-KEY-1).
> *Serves:* S6, S12. *Verified by:* simulator with power loss.

> **R-CORE-6.** Call nonce slots and open streams do not survive a reboot.
> *Serves:* S10. *Verified by:* model.

> **R-CORE-7.** For every persisted value an order is defined: the storage write is acknowledged before
> any effect that depends on it. A power loss between them leaves a state from which the core continues
> without violating any property. An event is processed to completion: the host executes the effects of
> one event strictly in the order produced and delivers the next event only after executing all of them,
> including the write. A frame that depends on a write waits for it in the host's buffer; the core needs
> no second buffer. The host reports a write failure with the "storage write result" event, and the core
> halts the instance with code `store/failed`; after a restart it continues from the persisted state.
> *Serves:* S6, S12. *Verified by:* simulator with a failure at every step.

> **R-CORE-8.** The core MUST work without the operating system's standard library and without unsafe
> code in its own modules.
> *Serves:* S17. *Verified by:* microcontroller build, CI check.

> **R-CORE-9.** The same input in the same state produces the same output. The only source of
> nondeterminism is the host's randomness, and it is substituted in tests.
> *Serves:* verifiability. *Verified by:* simulator, trace replay.

### 12.2. Library and Local Interfaces

> **R-API-1.** The library interface is callable from C: create an instance in caller-provided memory,
> submit an event, collect effects. No function blocks or calls back into the host, except through the
> cryptography and randomness table.
> *Serves:* R-ARC-1. *Verified by:* binding tests.

> **R-API-2.** The local interface gives the application these operations: publish; read a channel;
> subscribe to a channel; set the readers of its own channel (a list of devices, or all valid members
> with the read right; a key request from a device outside the list is not answered); invoke an action
> (with a flag stating whether it is idempotent, R-CALL-13); reply to a call; register an action handler;
> write and read a stream; set the node name (the core publishes it to channel 0, R-CH-16); read the bus
> state. The bus state is a snapshot without side effects: bus identifier, root generation, checkpoint
> number, halted flag, known valid members with their rights, connected links, core memory usage. The
> snapshot contains no secrets. Until the application sets them, the readers of a channel are all valid
> members with the read right. Subscribing delivers the channel's retained publications at once. On the
> root device the interface also gives the owner's operations, each confirmed through the root key
> (R-CORE-2): answer a join request (R-JOIN-5), change the rights and permits of a device (R-MEM-4), and
> revoke a device (R-MEM-4).
> *Serves:* scope. *Verified by:* interface test.

> **R-API-3.** A confirmation-class action always goes through the effect "sign with the presence key"
> (R-CORE-2) on the device that holds the presence key. A software confirmation flag does not exist.
> *Serves:* S10. *Verified by:* code review, Tamarin.

> **R-API-4.** The application sees the same behaviour regardless of the delivery path: direct link,
> local network, or relay.
> *Serves:* usability. *Verified by:* path compatibility test.

### 12.3. Errors

> **R-ERR-1.** Every rejection by the core has a stable rule code of the form `area/rule`, for example
> `sig/low-s` or `pub/commit`. The list of codes is part of the format and is covered by vectors.
> *Serves:* verifiability. *Verified by:* vectors, one per code.

> **R-ERR-2.** Error reporting has two modes. Debug: under the human-readable message, the rule code, the
> error kind, and the underlying message are shown, and every shown error is logged. Release: only the
> short message is shown; the details go to the log.
> *Serves:* usability. *Verified by:* interface test.

> **R-ERR-3.** The mode follows the build type (debug or release) and is switched by one obvious
> override: a setting, an environment variable, or a launch flag.
> *Serves:* usability. *Verified by:* interface test.

> **R-ERR-4.** An unexpected error MUST NOT be hidden behind a generic message without a way to see its
> cause.
> *Serves:* usability. *Verified by:* code review.

> **R-ERR-5.** Logs and error messages MUST NOT contain keys, publication content, or call arguments.
> *Serves:* S1. *Verified by:* code review, log test.

> **R-ERR-6.** A rejection of a message MUST NOT reveal to the peer which rule was violated if that would
> help an attacker. The peer receives a generic rejection; the rule code stays in the local log.
> *Serves:* S1. *Verified by:* code review.

## 13. Limits and Parameters

Limits are either format constants, identical for everyone, or profile parameters, chosen by a
deployment within the given bounds.

### 13.1. Format Constants

Every number is of one of three kinds, given in the last column. **Derived**: the number follows from a
standard or from other numbers; there is no choice. **Computed**: the number is obtained by a stated
rule. **Chosen**: the number is assigned; the rationale and the cost of getting it wrong are given.

| Constant | Value | Origin | Kind |
| --- | --- | --- | --- |
| Bus identifier, hash, record identifier | 32 bytes | Full SHA-256 output. The adversary chooses the content of records, so collision resistance is needed: 128 bits today, about 85 bits against quantum collision search. Truncation lowers this. | Derived |
| Device identifier | 16 bytes | First 16 bytes of SHA-256 of the key. A collision between two of its own keys gains the adversary nothing: the identifier is always checked together with the passport, which carries the full key. Only second-preimage resistance is needed, which is 128 bits. Saves 16 bytes in every header and every permit. The Root MUST reject a new passport if the identifier already belongs to another key. | Computed |
| Channel label | 16 bytes | A relay serves many buses and distinguishes channels only by label. A label collision mixes storage but enables no forgery: the real channel address is in the signed header. 16 bytes make an accidental collision unreachable for any number of buses. | Computed |
| Call nonce | 16 bytes | Random. It cannot be guessed (2^-128) and repeats by chance only after 2^64 issues. With 8 bytes a repeat would occur after 2^32 issues, which is reachable. | Computed |
| P-256 signature | 64 bytes | r and s of 32 bytes each, fixed by the curve. | Derived |
| P-256 public key | 65 bytes | SEC1 uncompressed form. Hardware keystores and platform APIs export keys in this form, and the verifier needs no modular square root. Cost: 32 bytes per key compared with the compressed form. | Chosen |
| X-Wing public key | 1216 bytes | 1184 (ML-KEM-768) + 32 (X25519). | Derived |
| Wrapped channel key | 1168 bytes | 1120 (X-Wing ciphertext) + 32 (channel key) + 16 (authentication tag). | Derived |
| K2 signature (SLH-DSA-SHA2-128s) | 7856 bytes | Fixed by FIPS 205. The "s" variant was chosen because its signature is half the size of the "f" variant, and slow signing during recovery does no harm. | Derived |
| Integer in the format | up to 2^53 - 1 | Exactly representable in all widespread languages, including JavaScript. No field needs more. | Computed |
| Numbers: passport, checkpoint, root generation, key epoch, channel key generation, relay ticket, relay epoch, upload counter, stream, chunk; number of blob segments | 1 .. 2^31 - 1 | Fits a signed 32-bit integer on any platform. Unreachable: one checkpoint per second exhausts the number in 68 years, a stream of 4 KiB chunks after 8 TiB, after which the stream is reopened. | Computed |
| Source publication counter | 1 .. 2^53 - 1 | Exhaustion costs a new passport, that is, owner confirmation. At 10 publications per second 2^31 runs out in 6.8 years, less than a device lifetime. 2^53 does not run out. | Computed |
| Alias | 16 bytes | As a channel label: a collision between two aliases at one relay mixes storage but enables no forgery, because every inner object is verified by its recipient and every link key by the members tree. 16 bytes make an accidental collision unreachable. | Computed |
| Relay epoch secret, link seed, period secret, wrapping salt | 32 bytes | The output size of SHA-256 and the key size of ChaCha20: 128 bits of security also against quantum search. A random salt repeats by chance only after 2^128 objects, so the single-use wrapping key never repeats (R-KEY-9). | Derived |
| Members tree depth | 2 .. 15 | 2^15 = 32768 leaves, the largest checkpoint bitmap (Section 13.2). Random leaves fill the tree to a power of two, so every proof has the same length for one depth; the minimum of 4 leaves keeps the proof non-trivial. Each level is one 32-byte hash in the relay hello: at most 480 bytes. | Computed |
| Nesting depth | 4 | The deepest object: envelope, body, list, list item. An embedded signed object travels as a byte string. Confirmed by Appendix B. | Computed |
| Items per container | 128 | Equal to the longest legitimate list of the format: the permits in a passport. | Computed |
| Map keys | 0 .. 65535, critical 0 .. 255 | Keys up to 255 encode in one or two bytes and are given to mandatory fields. Above that keys take three bytes; optional fields go there. | Computed |
| Publication data, call arguments, and call result | up to 4096 bytes | The smallest participant holds such a message in memory whole and decrypts it in place. State or a command fits with room to spare; anything larger goes as a segmented blob. Cost of error: smaller would push ordinary JSON data into blobs; larger would raise the smallest frame. | Chosen |
| Actions per device | 64 | An action set is exactly 8 bytes, so a permit has a constant size. An application with more commands uses arguments. The set is not encoded as an integer: 64 bits do not fit the integer limit. | Chosen |
| Device name | up to 64 bytes of UTF-8 | The owner sees the name when confirming; it must fit one line on screen. 64 bytes are 64 Latin letters, 32 Cyrillic letters, or 21 CJK characters. | Chosen |
| Bus system channels | 0 .. 15 | One is in use: channel 0 for node info. The other 15 are reserved for future needs of the bus; the number occupies one byte in any case. | Chosen |
| Application channel number | 0 .. 65535 | The number is not visible outside, only its hash in the label, so its size costs nothing. Every retained channel occupies recipient memory; an application needs no more than 65 thousand. | Chosen |
| Frame | body up to 16384 bytes, 2-byte big-endian length | Every participant must accept a root change record (8046 bytes, about 7.9 KiB, because of the K2 signature) and a checkpoint with the largest bitmap (6432 bytes, about 6.3 KiB, today, and 14225 bytes, about 13.9 KiB, with a post-quantum root signature; computed in Appendix B, Section B.9). The nearest power of two is 16384. No object needs more: a publication takes up to 4.3 KiB, a key grant 1.4 KiB, and streams and blobs are cut into chunks. The limit is therefore the same for everyone and not part of the passport. A TLS record has the same size. A length up to 16384 fits in 2 bytes. On an external relay link every frame travels inside a wrapped object, so the largest stream chunk or blob segment there is shorter by the wrapping overhead (Appendix B, Section B.10); every map object fits with room to spare. | Computed |
| Pairing short code | 6 decimal digits | CPace allows one guess per attempt. The probability of guessing is the number of attempts divided by 10^6: 3 in a million with three attempts. This matches Bluetooth numeric comparison. After the attempts are exhausted the code changes. | Computed |
| QR secret | 16 bytes | 128 bits; brute force is impossible, no attempt limit is needed. | Computed |
| Device key fingerprint for human comparison | 64 bits, 20 decimal digits | Before the owner confirms the request, a compromised acceptor would have to find its own key with the same fingerprint as the joiner's. P-256 key search is estimated at 10^7 keys per second per core. 40 bits (12 digits) fall to one core in a day. 64 bits need about 58 thousand core-years. The search rate is an estimate, to be refined by measurement. | Computed |

### 13.2. Profile Parameters

| Parameter | Bounds | Default | Origin | Kind |
| --- | --- | --- | --- | --- |
| Checkpoint bitmap length | 64 .. 32768 bits | 4096 bits | One bit per passport in the window. Upper bound: a 4 KiB bitmap leaves 12 KiB of the frame for the header and the root signature. That is enough for any ML-DSA signature (up to 4627 bytes, FIPS 204) and SLH-DSA-SHA2-128s (7856 bytes) together with a classical signature in a hybrid. The default of 512 bytes covers 4096 devices of one owner. | Computed; default chosen |
| Permits per passport | 0 .. 128 | 32 | A permit takes 36 bytes (Appendix B, Section B.9). 128 permits give a passport of 4877 bytes (4.8 KiB), and 12670 bytes (12.4 KiB) with a post-quantum root signature, which fits the frame. | Computed |
| Channel retention depth | 0 .. 1024 | 16 | Recipient and relay memory grows as depth times publication size. There is no basis for exactly 16; it is a starting value pending measurement. | Chosen |
| Retained sealing key epochs | 2 .. 16 | 4 | Minimum 2: while a new claim propagates, senders still seal to the previous epoch. Each extra epoch extends the window in which a device compromise discloses old messages, and takes 32 bytes of storage: an X-Wing private key is a 32-byte seed; the full key is expanded from it for the duration of an operation and takes about 2.4 KiB of working memory. Four epochs tolerate a sender three rotations behind. | Lower bound computed; rest chosen |
| Open streams per node | 0 .. 256 | 8 | A stream takes about 128 bytes of state. 0 is allowed for devices without streams. | Chosen |
| Stream chunk and blob segment, including header | up to 16384 bytes | 4096 bytes | A quarter of a frame: a short chunk does not occupy the link for long, and other messages pass between chunks. The source writes the blob segment size into the publication header (Appendix B, field `seg`), so readers and relays learn it without configuration, and the value can change after measurement without a format change. A segment other than the last is at least 1024 bytes of ciphertext (Appendix B, Section B.5). Starting value pending measurement. | Computed |
| Initial stream credit | up to 1 MiB | 16 KiB | The recipient grants credit and must have that much memory. 64 KiB consumed all the memory of the smallest participant. 16 KiB is four chunks, so the link does not idle during one round trip. | Computed; default chosen |
| Content padding buckets | chosen by the sender | 64, 256, 1024, 4096 | The source chooses the buckets; the recipient does not care. A factor of four leaves the relay four size classes and inflates content at most fourfold. A factor of two would give eight classes and twofold inflation. | Chosen |
| Pairing attempts per code | 1 .. 10 | 3 | The probability of guessing the code is the number of attempts per million. Three attempts forgive a typo; ten give 1 in 100 thousand, the accepted bound. | Computed |
| Join requests held by a relay | 1 .. 256 | 16 | As many as an owner can review at once. Only members with the accept right can create requests. | Chosen |
| "Reset nonces" period | set by the host | 30 s | The longest delay with which a network adversary can deliver an intercepted call. It cannot be made shorter without cost: a nonce issued just before a reset is lost, and the share of such refusals equals the round-trip time divided by the period; at 0.3 s that is 1%. | Chosen |

The memory of the smallest participant, "on the order of 64 KiB" in R-LIM-4, is an estimate, not a
computation: 16 KiB for the frame, the rest for X-Wing, signature verification, and state. A root change
record is verified in place in the frame buffer, without a copy. The figure is to be confirmed by
measurement on a microcontroller by gate G4. If it is not confirmed, this number changes; the format
does not.

The numbers in verification methods (100 instances per process, 1000 buses per relay) are not
constants: they are test sizes sufficient to expose a shared resource that grows with the number of
instances.

> **R-LIM-1.** A message that violates a format constant MUST be rejected by every participant.
> *Serves:* S17. *Verified by:* vectors.

> **R-LIM-2.** All profile parameters are local. None of them affects whether a participant accepts
> another participant's message built according to the format constants.
> *Serves:* S17. *Verified by:* model.

> **R-LIM-3.** Exhaustion of the publication counter leads to a refusal to publish. The device obtains a
> new device key and a new passport. The counter limit is chosen so that this never happens within a
> device's lifetime.
> *Serves:* S12. *Verified by:* test.

> **R-LIM-4.** The smallest full participant is a 32-bit microcontroller with memory for the bus on the
> order of 64 KiB. A weaker device connects through a gateway node and is not itself a node.
> *Serves:* scope. *Verified by:* build and run on a microcontroller.

> **R-LIM-5.** For every property of Section 3, the verification report states for which parameter
> values it was verified.
> *Serves:* verifiability. *Verified by:* report.

## 14. Verification, Acceptance, and Work Plan

Every requirement in this document has an identifier, the property it serves, and a verification
method. A requirement whose verification has not passed is considered unmet, however obvious it may
seem.

### 14.1. Verification Levels

| Level | What is verified | Tools | What is claimed, and no more |
| --- | --- | --- | --- |
| V1. Cryptographic protocol | Pairing, publication, call and reply, stream, root change, recovery: secrecy, authenticity, absence of replay, binding to the bus | Tamarin prover [TAMARIN] | A symbolic model: primitives are assumed perfect. The quantum adversary is described by separate lemmas (reading recorded traffic); limitations L1 and L2 remain limitations. |
| V2. State machine | Membership, checkpoints, revocation, root change, enrollment, nonce slots, channel retention depth, streams, relay storage and quotas | A new, small model in Quint [QUINT], its simulator, TLC [TLA], Apalache [APALACHE] | TLC: exhaustive state exploration for small N, with the sizes stated. Apalache: inductive invariants for fixed N, with the sizes stated. The claim "for all sizes" is not made. |
| V3. Code-to-model conformance | The core takes the same transitions as the model; the format parses unambiguously | Replay of model traces in the Informal Trace Format (ITF) [ITF] against the core, a second, independently written decoder, a test vector for every error code | Conformance is tested on a set of traces, not proven. |
| V4. Code | Absence of panics, overflows, and out-of-bounds reads; behaviour under faults | Kani model checker [KANI] on parsing and arithmetic, fuzzing, a deterministic fault simulator, mutation testing | Kani bounds and fuzzing time are recorded next to each result. |

### 14.2. Verification Requirements

> **R-VER-1.** For every requirement, the repository MUST hold a verification record: the method, the
> commit, the bounds, and the result.
> *Serves:* traceability. *Verified by:* the build fails if a requirement has no record.

> **R-VER-2.** Every property S1–S18 MUST have at least one lemma or invariant and at least one probe: a
> deliberately broken model on which the verification is required to fail.
> *Serves:* non-vacuous verification. *Verified by:* probes run in CI; a probe that does not fire is a
> defect.

> **R-VER-3.** The state machine model is written anew and kept small. Verification for small N MUST
> complete within one hour and runs in CI on every change. Long runs are executed separately, and their
> outcome is recorded with the number of states and the running time.
> *Serves:* reproducibility. *Verified by:* CI; log of long runs.

> **R-VER-4.** The model MUST contain an explicit invariant for a revoked device that does not know it
> has been revoked: it receives no new keys, and its publications are not accepted by any node that has
> seen the new checkpoint.
> *Serves:* S5, S6. *Verified by:* TLC, Apalache, simulator scenario.

> **R-VER-5.** An incomplete or interrupted run is not a result and MUST NOT be cited as evidence.
> *Serves:* honest reporting. *Verified by:* review of R-VER-1 records.

> **R-VER-6.** The format MUST be checked by two independently written decoders. A disagreement on any
> input is a format defect.
> *Serves:* unambiguous parsing. *Verified by:* differential fuzzing.

> **R-VER-7.** The simulator is deterministic: a run is fully determined by its seed. It models power
> loss between any two storage writes and in the middle of a write; reordering, duplication, and loss of
> messages; and a hostile relay.
> *Serves:* fault tolerance. *Verified by:* every failing seed becomes a permanent test.

> **R-VER-8.** The core is subjected to mutation testing. A surviving mutant in a signature check, a
> counter, a checkpoint number, or a bounds check blocks the release.
> *Serves:* tests that detect defects. *Verified by:* CI report.

> **R-VER-9.** A conformance suite is published separately from the implementation: vectors, traces, and
> scenarios with which a third-party implementation demonstrates interoperability.
> *Serves:* open standard. *Verified by:* a second decoder implementation passes the suite.

### 14.3. Phases and Gates

Work proceeds to the next phase only after the gate of the previous phase has passed.

| Gate | Deliverable | Exit criterion |
| --- | --- | --- |
| G0 | This specification and its threat model agreed; Appendix B written | No open questions that would change the format. |
| G1 | State machine model and cryptographic models | TLC and Apalache pass at the stated sizes, all Tamarin lemmas are proven, all probes fire. |
| S | Application simulator (`cpb-sim`) and the Rust shape of the local interface (`cpb-api`) | The simulator replays the traces of the channels, calls, membership, enrollment and streams models with equal state after every step, and the interface tests of R-API-2 pass against it. |
| G2 | Format: description, vectors, two decoders | R-VER-6 is met; every error code has a vector. |
| G3 | Core | Passes the model traces, the simulator, Kani, fuzzing, and mutation testing. |
| G4 | Application library and relay | End-to-end scenarios on two platforms, one of them of the ESP32 class. |
| G5 | First application profile outside this repository | The application is built on the public interfaces only; nothing was added to the bus for its sake. |

Gate S follows G1 and does not gate G2 to G4: it gives application authors a bus to build profiles on
before the core exists. Profile work toward G5 may start once S has passed; G5 itself still follows G4.
The simulator is the deterministic harness of R-VER-7 with an engine taken from the models; at G3 the
core is added as a second engine of the same harness, and the two run on the same seeds.

Closing G0 records this specification and Appendix B as the reference baseline but does not freeze the
format: the model (G1) and the vectors (G2) exist to find errors in it. After G0 the format changes only
through an entry in the change log that states the reason, and it is frozen at release (R-FMT-15). The
core is written after G1 and follows the model. Proven solutions from other projects are carried over
only as designs: each one passes the same verification again.

### 14.4. Acceptance

Version 1.0 is complete when gates G0–G4 have passed, all R-VER-1 records are green, limitations L1–L8
are stated in the user documentation in the same words as in this document, and the conformance suite
is published.

## 15. Security Considerations

This section collects, in one place, the assumptions on which the security properties of Section 3
rest and the residual risks that remain when every requirement is met. It adds no requirements; where
it refers to a requirement, the requirement governs.

### 15.1. Trust Assumptions

The properties of Section 3.2 hold only under the following assumptions. An implementation or a
deployment that violates one of them loses the properties that depend on it.

- **The root key is not compromised.** The bus does not define how the host protects the root key
  (R-KEY-1). A compromised root key gives full control over the bus until the Root is replaced with the
  recovery key (L4). Deployments are advised to keep the root key in non-exportable, hardware-backed
  storage and to require user presence for every root signature.
- **The recovery key is kept offline, and its two halves are not both compromised.** A root change
  requires both K1 and K2 (S9). Two conflicting root change records of the same generation halt the bus
  permanently (L6); the recovery key therefore must not be used from two places at once.
- **Host storage is atomic and does not roll back** (R-ARC-8). Without this, a power loss or a storage
  rollback can return a node to an earlier checkpoint or channel value, and S6 and S12 do not hold.
- **The host random number generator is cryptographically secure** (R-ARC-9). Channel keys, nonces,
  sealing keys, and pairing values are drawn from it. ECDSA additionally needs an unpredictable
  per-signature value; a repeated or biased value discloses the signing key. Hosts are advised to use
  deterministic [RFC6979] or hedged ECDSA signing for the device, user-presence, and root keys.
- **Implementations do not leak secrets through side channels.** Secrets are compared in constant time
  and zeroized after use (R-KEY-7). Timing, power, and electromagnetic side channels of a particular
  platform are outside the scope of the formal models (Section 14.1, level V1).

### 15.2. Network Adversary and Relays

The adversary controls the network and every relay (Section 3.1). Content confidentiality and
authenticity (S1, S2, S3) and the untrusted-relay property (S15) do not depend on transport security.
Transport encryption between a node and a relay is still recommended: without it a network observer
sees everything that L5 lists for a relay, not only volume and timing.

A relay learns the metadata listed in L5. A member relay learns who publishes, to whom channel keys
were granted, sizes by padding bucket, and timing. An external relay learns the same pattern only under
aliases that change with every relay epoch (S18, Section 15.9). Padding buckets (Section 13.2) reduce,
but do not remove, what sizes reveal. Applications for which the communication pattern within an epoch
is itself sensitive are advised to run their own relay or to add cover traffic in a profile.

The bus guarantees safety, not delivery (L3). A relay or the network can withhold messages
indefinitely. In particular, a node cut off from every device that knows a newer checkpoint continues to
operate under the old one (L1), and a reader that first receives a channel only through a relay may
receive an older state (L8). Applications that need bounded revocation latency must ensure that
revocation reaches devices over more than one path.

### 15.3. Replay and Call Execution

A call is executed at most once, and only over a fresh nonce issued by the target (S10). The window in
which an intercepted call can be delivered late is bounded by the "reset nonces" period, chosen by the
host (Section 13.2). A shorter period narrows the window at the cost of more refusals for calls in
flight. A commander that receives no reply cannot tell whether the action was executed (L7);
applications that need exactly-once effects build idempotence or confirmation into their own profile.

Refusals sent by a relay or by a target before the nonce check are unsigned hints (R-CALL-12). They can
be forged by the network adversary and never lead to repeated execution, because the nonce is consumed
only by an executed call.

### 15.4. Compromised Nodes

A compromised node discloses everything stored on it: its private sealing keys of retained epochs, the
channel keys it still holds, and the content it has received. Damage containment (S14) limits what it
can do to others: it cannot impersonate another device, halt the bus, or evict other devices' data from
a relay beyond its own quota.

Forward secrecy (S13) is bounded:

- envelopes sealed to an erased sealing key epoch stay protected; the number of retained epochs
  (Section 13.2) is the window of exposure;
- channel publications are protected by channel key rotation, not by a per-publication ratchet (D14 in
  Appendix A). A compromised reader discloses every publication under the channel keys it still holds
  (R-CH-7). The source shortens this window by rotating the channel key on a host event.

Revoking a compromised node takes effect at a given node only when that node learns the new checkpoint
(S5, L1). Until then, the revoked node can still exchange messages with nodes that have not learned it.

### 15.5. Forks and Halting

Two different records of one author with the same number put a node into the halted state (S8), and the
halt proof is forwarded on every link (R-MEM-10). This turns equivocation by the Root into a detectable,
bus-wide failure rather than a silent split. The cost is availability: a halted bus executes no calls
and accepts no membership changes until a root change record is accepted. An adversary that does not
hold the root key cannot produce a valid halt proof.

### 15.6. Post-Quantum Considerations

Confidentiality uses the X-Wing hybrid KEM (ML-KEM-768 with X25519) from version 1, so traffic recorded
today stays confidential against a future quantum adversary (S1). Version 1 signatures are classical
(ECDSA P-256), except K2, which is SLH-DSA. An adversary with a cryptographically relevant quantum
computer can forge root and device signatures (L2). The recovery key, which requires both a classical
and a post-quantum signature, is the designed migration path: it can install a new Root under a
post-quantum signature algorithm identifier without creating a new bus.

### 15.7. Pairing

Pairing uses CPace [CPACE], which lets an active adversary test exactly one password guess per pairing
attempt (R-JOIN-3). With a 6-digit short code the success probability of an online guessing attack is the
number of permitted attempts divided by 10^6 (Section 13.2); a 16-byte QR secret makes online guessing
infeasible. Pairing gives the joiner the bus identifier and the recovery key halves, from which it checks
the identifier (R-JOIN-2); it does not admit the joiner. Admission requires a Root signature after the
owner confirms the join request.

### 15.8. Parsing Untrusted Input

Every byte a node receives is untrusted. The strict canonical encoding (Section 5) gives every accepted
message exactly one byte representation, which prevents signature malleability and disagreement between
implementations (S17). Implementations are verified against this by bounded model checking, fuzzing,
and a second independent decoder (R-VER-6).

### 15.9. External Relays and Unlinkability

S18 rests on two assumptions: HKDF-SHA256 keyed with a secret is a pseudorandom function, and a relay
holds no member secret. A member, or a revoked device for the epochs it was valid in, knows the relay
epoch secret and can read the open fields and the wrapped bodies; collusion of a relay with such a
device removes S18 for those epochs and nothing else, because the inner objects are sealed and signed
as on a member link. Timing and network addresses are outside S18 (L5): a device with a fixed address
is linkable across epochs by that address, and the change of epoch is visible through the uploads of
the root device under both aliases.

The bus alias is the hash of a period key that only the Root can derive. A member that knows the relay
epoch secret therefore cannot register a bus alias before the Root and lock the bus out of the relay
(S14). For the same reason relay access objects are signed by the root device: a link seed from anyone
else would let one member cut another off. They are signed with the root device's device key, not the
root key, because a new epoch needs one signature per member, and the root key may require the owner's
confirmation of every signature (R-KEY-1). A thief with the root device's key and its relay secrets can
issue relay access objects with an epoch secret and link seeds of its own choosing, sign tickets for the
current aliases, and so deny relay service and, together with a relay, read the open fields and wrapped
headers of the bus (S18) for the epochs it issues. This lasts until the owner names a new root device in
a checkpoint (R-MEM-17): members then drop the relay epoch they hold, whatever its number, and follow the
new root device, which counts its epochs from 1 (R-REL-13). The thief gains no power over membership or
content: inner objects stay sealed and signed, and only the root key signs checkpoints and passports.

Every revocation costs a new epoch: one sealing and one signature per member on the root device, one
bridge per member at each external relay, and every source uploading its retained publications and
grants again to each external relay. Appendix B, Section B.9 gives the numbers for the largest bus.

Between a revocation and the closing ticket of the old alias, a revoked device can still fetch wrapped
objects under the old alias. It learns nothing new from them: channel keys and sealing keys rotate as
on member links, and the new epoch secret is never sealed to it.

## 16. References

### 16.1. Normative References

- **[CPACE]** Abdalla, M., Haase, B., and J. Hesse, "CPace, a balanced composable PAKE",
  draft-irtf-cfrg-cpace-21, Work in Progress, Internet-Draft, April 2026.
- **[FIPS180-4]** National Institute of Standards and Technology, "Secure Hash Standard (SHS)",
  FIPS PUB 180-4, August 2015.
- **[FIPS186-5]** National Institute of Standards and Technology, "Digital Signature Standard (DSS)",
  FIPS PUB 186-5, February 2023.
- **[FIPS203]** National Institute of Standards and Technology, "Module-Lattice-Based
  Key-Encapsulation Mechanism Standard", FIPS PUB 203, August 2024.
- **[FIPS205]** National Institute of Standards and Technology, "Stateless Hash-Based Digital
  Signature Standard", FIPS PUB 205, August 2024.
- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14,
  RFC 2119, March 1997.
- **[RFC5869]** Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function
  (HKDF)", RFC 5869, May 2010.
- **[RFC7748]** Langley, A., Hamburg, M., and S. Turner, "Elliptic Curves for Security", RFC 7748,
  January 2016.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14,
  RFC 8174, May 2017.
- **[RFC8439]** Nir, Y. and A. Langley, "ChaCha20 and Poly1305 for IETF Protocols", RFC 8439,
  June 2018.
- **[RFC8610]** Birkholz, H., Vigano, C., and C. Bormann, "Concise Data Definition Language (CDDL): A
  Notational Convention to Express Concise Binary Object Representation (CBOR) and JSON Data
  Structures", RFC 8610, June 2019.
- **[RFC8949]** Bormann, C. and P. Hoffman, "Concise Binary Object Representation (CBOR)", STD 94,
  RFC 8949, December 2020.
- **[RFC9180]** Barnes, R., Bhargavan, K., Lipp, B., and C. Wood, "Hybrid Public Key Encryption",
  RFC 9180, February 2022.
- **[XWING]** Connolly, D., Schwabe, P., and B. E. Westerbaan, "X-Wing: general-purpose hybrid
  post-quantum KEM", draft-connolly-cfrg-xwing-kem-11, Work in Progress, Internet-Draft,
  September 2026.

The CPace and X-Wing specifications are Internet-Drafts. This specification pins the cited revisions;
moving to a later revision or to the resulting RFC is a format change recorded in the change log.

### 16.2. Informative References

- **[APALACHE]** Konnov, I., Kukovec, J., and T.-H. Tran, "TLA+ Model Checking Made Symbolic",
  Proceedings of the ACM on Programming Languages, Vol. 3, OOPSLA, 2019.
- **[BECK]** Beck, M., "On the Hourglass Model", Communications of the ACM, Vol. 62, No. 7, 2019.
- **[CLARK]** Clark, D. and D. Tennenhouse, "Architectural Considerations for a New Generation of
  Protocols", ACM SIGCOMM, 1990.
- **[DEMERS]** Demers, A., Keshav, S., and S. Shenker, "Analysis and Simulation of a Fair Queueing
  Algorithm", ACM SIGCOMM, 1989.
- **[DDS-RTPS]** Object Management Group, "The Real-time Publish-Subscribe Protocol DDS
  Interoperability Wire Protocol (DDSI-RTPS)", Version 2.5, 2022.
- **[ITF]** Informal Systems, "The Informal Trace Format", Apalache documentation.
- **[KANI]** The Kani Rust Verifier, https://github.com/model-checking/kani.
- **[QUINT]** Informal Systems, "Quint: a specification language based on the temporal logic of
  actions", https://github.com/informalsystems/quint.
- **[RFC6962]** Laurie, B., Langley, A., and E. Kasper, "Certificate Transparency", RFC 6962,
  June 2013.
- **[RFC6979]** Pornin, T., "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic
  Curve Digital Signature Algorithm (ECDSA)", RFC 6979, August 2013.
- **[SALTZER-E2E]** Saltzer, J., Reed, D., and D. Clark, "End-to-End Arguments in System Design", ACM
  Transactions on Computer Systems, Vol. 2, No. 4, 1984.
- **[SALTZER-PROT]** Saltzer, J. and M. Schroeder, "The Protection of Information in Computer
  Systems", Proceedings of the IEEE, Vol. 63, No. 9, 1975.
- **[TAMARIN]** Meier, S., Schmidt, B., Cremers, C., and D. Basin, "The TAMARIN Prover for the Symbolic
  Analysis of Security Protocols", CAV 2013.
- **[TLA]** Lamport, L., "Specifying Systems: The TLA+ Language and Tools for Hardware and Software
  Engineers", Addison-Wesley, 2002.
- **[TOR-V3]** The Tor Project, "Tor Rendezvous Specification - Version 3", Section 2.2, "Key
  blinding", https://spec.torproject.org/rend-spec/.
- **[TUF]** Samuel, J., Mathewson, N., Cappos, J., and R. Dingledine, "Survivable Key Compromise in
  Software Update Systems", ACM CCS, 2010.

## Appendix A. Design Decisions and Open Items

### A.1. Replaceable Design Decisions

Each decision below lives in one place in this document; changing it does not break the rest. A
decision is challenged by citing its number.

| ID | Decision | Rationale | Consequence of reversing it |
| --- | --- | --- | --- |
| D1 | A relay sees an opaque 16-byte channel label. | Without the label a relay cannot keep the latest value and a bounded history without reading content. | The relay becomes a plain pipe, retention moves to the devices, and sleeping devices stop receiving what they missed. |
| D2 | After a root change, the new Root reissues all passports. | Old signatures cannot be treated as valid if the old key may have been stolen. | Carrying passports over without reissue is faster, but a stolen Root keeps the members it admitted. |
| D3 | Sealing uses X-Wing only; there is no X25519-only profile. | One profile instead of two, with protection against harvest-now-decrypt-later by default. | The wrapped key shrinks by about 1.1 KiB, and a second profile with its own verification appears. |
| D4 | A call reply carries no separate signature; it is protected by a key from the HPKE context. | Reply authenticity already follows from the key, and a signature is expensive on a microcontroller. | 64 more bytes and one more signature per reply. |
| D5 | Up to 64 actions per device; rights are granted to the commander. | The action set takes exactly 8 bytes, a permit has a constant size, and the range suffices for a typical application. | A different mask size, or a list of action numbers instead of a mask. |
| D6 | Device signatures use ES256; algorithm identifiers 4–15 are reserved for future algorithms. | Hardware support for P-256 is nearly universal, including secure elements. | The default algorithm changes before the format is released. |
| D7 | The default profile values of Section 13. | Tuned for an ESP32-class device. | The numbers change; the format does not. |
| D8 | The core has no timers or clocks; time arrives as host events. | The state machine is deterministic and verifiable, with no dependence on clock accuracy. | Expiry times appear in records, and every device needs a clock. |

The following decisions were taken when the design was checked against the selection principles of
Section 4.1:

| ID | Decision | Rationale | Consequence of reversing it |
| --- | --- | --- | --- |
| D9 | A stream has two modes: ordered and lossy. | Every reference system has streaming with tolerated loss: isochronous transfers in USB and IEEE 1394, best-effort topics in DDS. Without it, live video and audio accumulate latency. | One mode remains, and live data must be sent as publications without retention. |
| D10 | The core does not know the data format or a "secret" class. | End-to-end argument: only the endpoints know what the data means. The source decides who reads a channel through key grants. | The format tag, the "secret" flag, and the "receive secrets" right return, with their checks. |
| D11 | One application is one bus; there is no application identifier. | Least common mechanism: a shared service makes one process trusted by every program. | A shared service, client identification, and an application field in every address and permit return. |
| D12 | Frame padding on the link and link liveness checks are left to the transport. | End-to-end argument and the hourglass model: the core is narrow; the transport knows the properties of the link. | A padding field appears in the frame and a timer event appears in the core. |
| D13 | The protocol is proven with one tool, Tamarin. | Economy of mechanism: a second model of the same protocol doubles maintenance and adds no properties. | A ProVerif model appears, together with the obligation to keep two models consistent. |
| D14 | A channel key is constant within a generation; there is no per-publication ratchet. | Economy of mechanism. The transport may reorder frames, so a ratchet would require storing skipped keys and a window for depth-N history: state on every reader and separate lemmas. The disclosure window is bounded by channel key rotation on a host event. | The key of the next publication is derived from the previous one, and a reader compromise no longer discloses publications already read. The publication format does not change. |
| D15 | An external relay sees the bus only under aliases per relay and per relay epoch, and admits devices by a members tree signed with a period key. | A bus open to millions of projects runs mostly through third-party relays; a permanent identifier would let each operator profile a bus for its whole life, and two operators join their logs (S18). Delivery and quotas need only aliases and counters. | The relay hello, the wrapped object, relay access objects, and relay epochs disappear; an external relay sees what a member relay sees (L5). |

### A.2. Open Items

1. **Profile guide.** Separate from this specification, a guide to writing profiles is needed. It
   covers a deferred job queue built on channels in place of long-running calls, and deriving the
   recovery keys of several buses from a single owner secret.
2. **One-to-many streams.** A stream is currently a call with one recipient and its own key, so each
   viewer of a camera takes a separate copy of the source's data. Low-rate data is carried by a
   channel of depth 0. Delivering video as a single copy would require a shared stream key granted as
   a channel key is, and fan-out through a relay. Found during the application-author walkthrough; not
   resolved before version 1.

The items that gate G0 required (the message type table and all object fields in Appendix B, the relay
ticket format and quota accounting in Appendix B, Section B.10, and the step-by-step pairing messages in
Appendix B, Section B.11) are written.

### A.3. Provenance

This specification merges two earlier requirement documents. The line-by-line analysis of their
differences, with the evidence for each decision, is kept outside this repository. This text replaces
both of them.
