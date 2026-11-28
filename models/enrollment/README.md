<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Enrollment model

A Quint [model](enrollment.qnt) of device enrollment (verification level V2 of the
[specification](../../docs/spec/requirements.md), Section 14): pairing of a joiner with an acceptor or
with the Root by the code the joiner shows; the joiner's signed payload; join requests; a compromised
acceptor and a network adversary that knows the joiner's code and relays payloads between sessions;
and admission by the Root only for the key fingerprint the root device read from the joiner.
CPace, signatures, and sealing are perfect here; Tamarin covers them. [Abstractions](#abstractions)
lists every abstraction.

## Instances

| Instance | Joiners | Honest acceptors | Sessions | Purpose |
| --- | --- | --- | --- | --- |
| `small` | `j1` (with user presence), `j2` | `h`, the Root | 6 | Simulator in CI |
| `tiny` | `j1` (with user presence) | `h` | 4 | Simulator in CI, TLC |
| `tiny_root` | `j1` (with user presence) | `h`, the Root | 4 | TLC witnesses (admission after pairing with the Root is reachable) |
| `probe_*` | as `small` | | | One deliberate defect each; `safety` must fail (R-VER-2) |

Every instance also has the compromised acceptor `c` and the adversary's own device key.

### Why `small` is large enough

The safety proof runs at `small_ind`, the size of `small`. Every property relates at most the
following roles at the same time, and `small` holds a copy of each:

- two joiners, one with a user-presence key and one without, so that a payload of one joiner relayed
  into a session of the other is refused (`bound`, probe `no_transcript_binding`), and a request that
  swaps the presence key or the name meets a joiner that signed something else (`asSigned`, probe
  `sig_key_only`). The adversary's own device key is the third key that may be put in a request
  (`intended`, probe `no_fingerprint_compare`);
- two honest acceptors, an ordinary member and the Root pairing directly (R-JOIN-9), so that both
  paths to admission meet the same checks (`rootOnly`, `intended`);
- one compromised acceptor. It shares everything it knows with the network adversary, so a second
  compromised acceptor would know nothing more and could send nothing more; there is one Root, and it
  is honest;
- six sessions. Sessions are compared only for equality: a request is bound to the session it names.
  `indInit` draws the used sessions and the payloads freely, so the states of `IndInv` hold any five
  used sessions, and a new session needs only a name that differs from all of them. The adversary
  may pair at any time, with a joiner as an acceptor and with an acceptor or the Root as a joiner, so
  six sessions hold an honest session of each joiner beside the adversary's sessions.

A third joiner or a second ordinary acceptor repeats one of these roles, since every property is
about one joiner's key, the session it ran and the request made from it. The proof covers further
sessions from every state of `IndInv`, not only from reachable ones.

## Properties

| Invariant | Requirement | Property |
| --- | --- | --- |
| `intended` | R-JOIN-5, R-JOIN-7 | S4: a passport goes only to the key of the device the owner enrolls |
| `asSigned` | R-JOIN-4 | S4: a joiner's passport carries exactly the presence key and name it signed |
| `bound` | R-JOIN-4 | S4: a request through an honest acceptor admits a joiner only from a session the joiner ran with that acceptor |
| `rootOnly` | R-JOIN-6 | S4: every passport was confirmed by the owner on the Root |

Step properties are checked by a monitor when the step is taken, as in the membership model.

Probes, each expected to violate `safety`:

| Probe | Defect |
| --- | --- |
| `no_fingerprint_compare` | The root device admits without checking the key against the fingerprint it read from the joiner |
| `sig_key_only` | The joiner's signature is checked for the key but not for the presence key and name |
| `no_transcript_binding` | The acceptor takes the transcript from the payload instead of its own session |
| `acceptor_issues` | The compromised acceptor issues a passport itself |

The fixed scenarios in [`scenarios.qnt`](scenarios.qnt) show admission through an honest acceptor, a
compromised acceptor's tampered request being dropped, a relayed payload being refused, and a
compromised acceptor that read the joiner's code failing to have its own key admitted.

The model made one point of the specification explicit: the join request carries the transcript hash
of the acceptor's own session, and the acceptor checks the joiner's signature before sending it, so a
payload relayed from another session is refused (R-JOIN-4).

## Abstractions

What a green run of this model does and does not show:

- CPace, signatures, and sealing are perfect; Tamarin covers them. A pairing session is named by its
  transcript (`tid`), and only its two ends know what was sent in it.
- The code carries a 128-bit secret, so it cannot be guessed and runs are not counted (R-JOIN-3).
  The adversary is still given every code, as if it had seen the joiner's screen: it may pair with a
  joiner as an acceptor (`advPairJoiner`) and with an honest acceptor or the Root as a joiner
  (`advPairAcceptor`) at any time.
- The fingerprint is the SHA-256 of the joiner's device key (R-JOIN-7); equal fingerprints are taken
  as equal keys.
- The owner enrolls the honest joiner in front of them; the root device reads the fingerprint from
  that joiner and admits a request only for that key (R-JOIN-5, R-JOIN-7). A mismatch only refuses, so
  it is no step of the model. This holds for every admission, also when the Root pairs the joiner
  itself (R-JOIN-9): `rootAdmit` has the check as a guard on every path, and the probe
  `no_fingerprint_compare` removes it.
- The check by which an acceptor that read a joiner's code refuses a peer with another device key
  (R-JOIN-7) is not modelled: the honest acceptor turns any payload of its session into a request.
  The properties hold without it, since the root device checks the key itself.
- When the Root pairs directly it is the acceptor `root`: the payload it receives in its own session
  becomes a request in its own inbox. R-JOIN-9 prepares no join request there; the model's request
  carries exactly what the Root holds at that point, so the checks are the same.
- The joiner's check of the bus fingerprint after admission is not modelled.
- The compromised acceptor `c` is a member. With the adversary it knows every payload sent to either of
  them and may put anything in a request. The Root itself is honest.
- The bus identity and the root key the joiner learns (R-JOIN-2) belong to Tamarin and the membership
  model. The sealing of a request to the root device and its open header (R-JOIN-4, last sentences)
  belong to Tamarin; the relay's buffer of requests (R-JOIN-8) to the relay model.

## Requirement coverage

Every normative sentence of the requirements in scope, and what in the model checks it: an invariant
(with the probe that breaks it), a guard, or a stated abstraction.

| Requirement | Sentence | Checked by |
| --- | --- | --- |
| R-JOIN-3 | a failed attempt lets the adversary test at most one password guess | CPace in Tamarin; here the adversary is given every code (above), which is stronger |
| R-JOIN-3 | the secret has 128 bits, runs are not counted, and the joiner discards a secret after a completed pairing or a new one | abstraction: no counter and no guessing; the adversary knows every code (above) |
| R-JOIN-4 | the Root takes a request only from a valid member | every request comes from an acceptor, honest or compromised, and both are members; membership itself is the membership model's |
| R-JOIN-4 | the request holds the joiner's key, presence key, name, transcript hash, the joiner's signature over them, and the acceptor's signature | the record `Request`; `asSigned`; probe `sig_key_only`; scenario `tamperTest` |
| R-JOIN-4 | the transcript hash is the acceptor's own session's, and the acceptor checks the joiner's signature before sending | guard in `acceptorRequest`; `bound`; probe `no_transcript_binding`; scenario `relayTest` |
| R-JOIN-4 | the Root verifies the joiner's signature, so the acceptor substitutes neither the presence key nor the name | guards in `badRequest` and `rootAdmit`; `asSigned`; probe `sig_key_only`; witness `witnessTampered` |
| R-JOIN-4 | a request is a control-plane object with an open header and a body sealed to the root device | abstraction: sealing is perfect (above) |
| R-JOIN-5 | the Root shows the name and the acceptor | the fields of `Request` that `rootAdmit` reads |
| R-JOIN-5 | the passport is issued only after the root device checked the key against the fingerprint from the joiner and the owner confirmed | `intended`, `rootOnly`; probes `no_fingerprint_compare`, `acceptor_issues` |
| R-JOIN-6 | no sequence of messages without a Root signature makes a device a member; an acceptor cannot issue a passport | `rootOnly`; probe `acceptor_issues` |
| R-JOIN-7 | the root device compares the fingerprint it took from the joiner with the key in the request and refuses a mismatch | guard `r.key == j` in `rootAdmit`; `intended`; probe `no_fingerprint_compare`; scenarios `admitTest`, `substituteTest` |
| R-JOIN-7 | the fingerprint is not taken from the request, the network or a message | the Root's `j` is the joiner in front of it, never a field of a request (above) |
| R-JOIN-7 | the acceptor that read a joiner's code refuses a peer with another device key | abstraction: not modelled; the properties hold without it (above) |
| R-JOIN-7 | after admission the joiner shows the bus fingerprint | abstraction: not modelled (above) |
| R-JOIN-9 | the Root may pair a joiner itself, with the same exchange and no join request | the acceptor `root` (above); witness `witnessDirect` |
| R-JOIN-9 | the root device checks the presented fingerprint here too | `intended` (the check guards every admission); probe `no_fingerprint_compare` |

## Inductive invariant

[`inductive.qnt`](inductive.qnt) holds an inductive invariant `IndInv`; Apalache proves the same three
obligations as for the other models. Besides the bounds of every variable and `broken` staying empty,
`IndInv` states these lemmas: sessions are named uniquely by their transcript, and a joiner's latest
session is one it ran; every payload a joiner sent went to the other end of its own session; the Root
keeps only requests that the joiner's signature covers; a joiner's request carries its own presence
key and name; a request through an honest acceptor comes from a session of that joiner with that
acceptor; and every passport was confirmed.

The instances are `tiny_ind` (the size of `tiny`, checked in CI) and `small_ind` (the size of `small`)
for a long run.

## State view for TLC

Exhaustive TLC of `tiny` does not finish on its own: the adversary and the
compromised acceptor can file any subset of the requests signed by the
adversary's key. `view.qnt` defines a TLC `VIEW` that drops those requests
(the Root admits a request only for the joiner in front of it, so they never
enable or change a step) and the witness tags, and module `bisim` proves with
Apalache that states with equal views are interchangeable for `safety`, so TLC
with the view finds a violation exactly when TLC without it would. Run with
`run-tlc.ps1 -Model enrollment -View` and
`run-inductive.ps1 -Model enrollment -Section bisim`.

## Running

```sh
python3 models/enrollment/check.py                         # CI run
python3 models/enrollment/check.py --inductive tiny_ind    # IndInv in CI
```

```powershell
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model enrollment -Probes -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-tlc.ps1 -Model enrollment -WorkDir <folder> -Java <path to java>
powershell -ExecutionPolicy Bypass -File models\run-inductive.ps1 -Model enrollment -Split -WorkDir <folder> -Java <path to java>
```

## Results

| Date | Model | Run | Bounds | Result |
| --- | --- | --- | --- | --- |
