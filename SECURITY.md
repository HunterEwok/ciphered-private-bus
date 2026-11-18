# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately. Do not open a public issue, pull request,
or discussion.

Use GitHub private vulnerability reporting: open the
[Security tab](https://github.com/HunterEwok/ciphered-private-bus/security) of the
repository and choose **Report a vulnerability**. Only the maintainer can see the report.

Include, if you can:

- the affected component (specification, framing, addressing, access arbitration, replay
  protection, post-quantum E2EE, root recovery, or Rust crate/module) and the version or
  commit;
- steps to reproduce or a proof of concept;
- the security impact (what an attacker can read, forge, replay, or disrupt).

## What to expect

- An acknowledgement within 7 days.
- An assessment within 30 days: a plan for a fix, or the reason the report is not accepted.
- For an accepted report: a fix, a published GitHub security advisory, and credit if you
  want it.

Please keep the details private until the advisory is published.

## Scope

In scope:

- the formal protocol specification in `docs/`;
- the Rust reference implementation and test vectors in `testdata/`;
- cryptographic constructions, key schedule, framing parser, replay protection, and root
  recovery logic.

Out of scope:

- attacks that require root/physical compromise of an endpoint device with an unlocked
  private key store;
- vulnerabilities in underlying transport layers outside the bus's security guarantees
  (note that CPB assumes an untrusted transport).

## Good faith

Test only against your own instances and test environments. The maintainer will not take
legal action against security research conducted in good faith under this policy.
