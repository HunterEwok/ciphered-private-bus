<!-- SPDX-License-Identifier: MPL-2.0 -->
<!-- Copyright (C) 2026 HunterEwok -->
# State machine models

This folder holds the Quint models of verification level V2 (requirements §14.1): one folder per
model, each with its own README that lists the properties, the probes, the instances and the
results. This page states once, for all of them, how a result is obtained, what it establishes,
and what it rests on.

| Model | Exhaustive TLC on `tiny` | Inductive proof (Apalache) | Probes and witnesses |
| --- | --- | --- | --- |
| [membership](membership/) | with a proven view, `tiny_tlc` | `large_ind`; convergence on `conv_large_ind` | TLC |
| [channels](channels/) | every state | `small_ind` | TLC |
| [calls](calls/) | with a proven view | `small_ind` | TLC |
| [enrollment](enrollment/) | with a proven view | `small_ind` | TLC |
| [streams](streams/) | every state | `small_ind` | TLC |
| [relay](relay/) | with a proven view | `small_ind` | TLC |

## How a result is obtained

**Exhaustive TLC.** TLC explores every reachable state of the instance and checks `safety` in each.
For channels and streams it stores every state. For the other four the state space of `tiny` is too
large to store, and TLC runs with a `VIEW`: two states with the same view are stored once, and only
the first one found is explored further. A view is not trusted on its own. Each `view.qnt` carries a
proof, checked by Apalache on two copies A and B of the model, that the view is exact for `safety`:

- O1. Every initial state satisfies `Struct`.
- O2. A state satisfying `Struct` and `safety` reaches only states satisfying `Struct`.
- O3. Two states satisfying `Struct` with equal views agree on `safety`.
- O4. For two states satisfying `Struct` with equal views, A safe, every step of A is answered by
  B with no step or one step, and the views are equal again.

From O1 to O4, TLC with the view reports a violation exactly when some reachable state of the full
model violates `safety`: take a shortest behaviour that ends in a violation; every earlier state is
safe and so satisfies `Struct`; by induction over the behaviour, O4 gives a state that TLC generates
with the view of each of its states; O3 transfers the violation to the last of them. The argument is
written out at the top of each `view.qnt`. Two witnesses per model are expected to fail and show that
the obligations are not vacuous: a pair with equal views exists, and B does answer a step. A TLC run
with a view counts as exhaustive only together with a complete run of all its obligations on the
same view hash.

**Inductive proof.** Apalache checks three obligations for an inductive invariant `IndInv`: the
initial states satisfy it, it and one step of the model imply it in the next state, and it implies
`safety`. Each step branch is checked separately (`-Split`). Together they prove that `safety` holds
in every reachable state of the instance, at every depth, not only within a bounded number of steps.

**Probes and witnesses.** Each probe is the model with one deliberate defect; `safety` must fail on it
(R-VER-2). Each witness is a property expected to fail on the correct model, showing that a behaviour
the safety checks speak about is reachable.

**Records.** A result is recorded in the model's README with the model hash and the hash of the
proof file (`run-tlc.ps1` and `run-inductive.ps1` compute both from the files and write them to the
run's `summary.txt`), the commit, the bounds and the time (R-VER-1). A run that was interrupted, or
that left no `summary.txt`, is not a result (R-VER-5); its checks are run again.

## What the results establish and what they rest on

**Fixed sizes.** Every result holds for the constants of its instance and for no other. The claim "for
all sizes" is not made (V2). The inductive proofs run at the size of each model's `small`, the
instance on which every probe fires; membership runs at `large` for a third generation.

**Steps argued by hand.** These parts of the argument are written in the READMEs and source comments
and checked by review, not by a tool:

1. Completeness of the drawn states. An induction step is proven only for the states that the
   proof's initial action draws: `indInit` for `IndInv`, `drawA` and `drawB` for `Struct`. Each draw
   is written to produce every state of the instance's types that satisfies the invariant, and is
   reviewed against it. A draw that missed states would leave those states unproven.
2. The view argument above, from O1 to O4 to exactness.
3. Membership liveness: `IndInv` implies `HearingEnabled` is checked by Apalache; the step from it to
   `haltPropagates` under weak fairness is argued in the [membership README](membership/README.md).
4. Membership convergence: the per-node invariant is checked on one device; why that covers every
   node of a larger model is argued in [`conv_inductive.qnt`](membership/conv_inductive.qnt).
5. Branches left out of a proof because they are disabled without a mutant (for example `badIssue`
   in enrollment) are named next to the proof.

**Tools.** The results trust the Quint translation to TLA+ and to Apalache's input, TLC, Apalache and
its SMT solver Z3, and the Java runtime. The versions are pinned in
[`tools/versions/versions.toml`](../tools/versions/versions.toml) and
[`package.json`](package.json) and recorded with each result.

**Fingerprints.** TLC stores a 64-bit fingerprint of each state, not the state. Two different states
with the same fingerprint make TLC treat the second as already explored, so an exhaustive run can in
principle miss states. TLC prints two estimates of the probability that this happened, an optimistic
one from the numbers of states and one from the fingerprints actually stored; both are recorded with
each exhaustive TLC result. The largest is that of channels (0.067 optimistic, 7.7E-4 from the
actual fingerprints, for 254 million distinct states). The Apalache proofs store no fingerprints and
carry no such probability.

**Model and code.** The models describe the protocol, not the core. Whether the core takes the same
transitions is level V3, tested by replaying model traces, not proven.

**Cryptography.** These models treat signatures, keys and encryption as ideal. The cryptographic
protocols are verified separately in Tamarin (level V1), which also assumes perfect cryptographic
primitives in the symbolic model.
