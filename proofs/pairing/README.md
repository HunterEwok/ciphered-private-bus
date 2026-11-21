<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# Pairing model

A Tamarin [model](pairing.spthy) of pairing and the join request (verification level V1 of the
[specification](../../docs/spec/requirements.md), Section 14, and Appendix B.11): the four CPace
messages between the joiner and an acceptor, the sealed bus parameters and device payload, the join
request from the acceptor to the root device, and the passport. The Root may also pair directly. The
network is the Dolev-Yao adversary; it may in addition leak a pairing code, compromise acceptors, and
reveal device keys. The header of `pairing.spthy` lists every abstraction.

## Lemmas

| Lemma | Requirement | Property |
| --- | --- | --- |
| `executable_via_request` | | sanity: an honest device is admitted through an honest acceptor |
| `executable_direct` | | sanity: an honest device is admitted by the Root directly |
| `acceptor_key_secrecy` | S4, R-JOIN-1 | the acceptor's pairing key is secret unless the code leaked |
| `joiner_key_secrecy` | S4, R-JOIN-1 | the joiner's pairing key is secret unless the code leaked |
| `joiner_agreement` | R-JOIN-1 | the joiner finishes only after an acceptor confirmed the same run and key |
| `acceptor_agreement` | R-JOIN-1 | the acceptor confirms only a run the joiner confirmed with the same key |
| `bus_authenticity` | R-JOIN-2 | the joiner takes bus parameters only from the acceptor that showed the code |
| `device_binding` | R-JOIN-4 | the acceptor takes an honest device's key only with a signature made in this run, even if the code leaked |
| `admission_via_request` | S4, R-JOIN-5..7 | a passport issued through a join request goes only to a device that paired for this bus, with the presence key and name it signed, even with a compromised acceptor and a leaked code |
| `admission_direct` | R-JOIN-9 | the same when the Root pairs directly, unless the code leaked |

Probes, each a deliberate defect selected with `-D`, each expected to falsify its lemma (R-VER-2):

| Probe | Defect | Lemma |
| --- | --- | --- |
| `PROBE_NO_FINGERPRINT` | the Root admits without the fingerprint comparison | `admission_via_request` |
| `PROBE_NO_TRANSCRIPT` | the joiner's signature omits `pairing_hash` | `device_binding` |
| `PROBE_SIG_KEY_ONLY` | the joiner's signature covers only the device key | `admission_via_request` |
| `PROBE_NO_CONFIRM` | the acceptor skips the joiner's confirmation | `acceptor_agreement` |

The attack that `PROBE_NO_TRANSCRIPT` must find relays a signature between two complete CPace runs with
the adversary in the middle. The probe adds restrictions to one bus, one code, one device, one joiner run
and one acceptor run, which is all the attack needs; a restriction only removes traces, so the trace found
is also a trace of the unrestricted model.

[`checks.json`](checks.json) lists the probes and what CI runs: three quick lemmas and every probe.

Tamarin warns that some variables of `Acceptor_Request`, `Root_Admit` and `Root_AdmitDirect` are not
derivable from their premises. This is intended: signature checks are written as pattern matches on
`sign(message, key)` and `pk(key)`, which accept exactly the messages the real check accepts.

## Running

```sh
proofs/run-tamarin.sh -m pairing -w <folder> -c          # CI subset
proofs/run-tamarin.sh -m pairing -w <folder> -p          # every lemma and every probe
```

The script downloads Tamarin and Maude into the work folder on first use, runs each lemma as its own
prover with 2 cores, uses at most 85% of the machine (`-s`), prints progress every minute, and writes
the logs, `results.txt` and `summary.txt` into a new run folder. `-t HOURS` limits each prover.

## Results

| Date | Model | Run | Result |
| --- | --- | --- | --- |
| 2026-11-21 | `52e6b4ae98d7` | Tamarin 1.12.0, `run-tamarin.sh -c`, 4 cores, one prover at a time | the 3 CI lemmas verified, 4 of 4 probes falsified (`PROBE_NO_TRANSCRIPT` in 2.4 min, 35 steps); 10.2 min in total |
| 2026-11-21 | `52e6b4ae98d7` | Tamarin 1.12.0, `run-tamarin.sh -p` (every lemma and every probe), maintainer's server (32 cores), 13 provers at a time, 4 GB each | 10 of 10 lemmas verified, 4 of 4 probes falsified (`PROBE_NO_TRANSCRIPT` in 1.3 min, `PROBE_SIG_KEY_ONLY` the longest at 4.4 min); 4.4 min in total |
