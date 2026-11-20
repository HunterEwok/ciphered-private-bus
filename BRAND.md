<!-- SPDX-License-Identifier: MPL-2.0 -->
# Names, official builds, and brand policy

**Ciphered Private Bus** (**CPB**) is a cryptographic protocol specification and reference
implementation. Trust in a security protocol depends on knowing which specification,
test vectors, and builds are official. This page defines what belongs to the project and
how the name may be used.

## The name

- **Ciphered Private Bus** (short: **CPB**) is the official name of this project and
  protocol, maintained by **HunterEwok** at
  [github.com/HunterEwok/ciphered-private-bus](https://github.com/HunterEwok/ciphered-private-bus).
- Neither the [MPL-2.0](LICENSE) code license (see Section 2.3) nor the
  [CC BY 4.0](LICENSES/CC-BY-4.0.txt) specification license grants any trademark, service
  mark, or naming rights in "Ciphered Private Bus" or "CPB".

## Official releases and builds

An official release or specification version is one published directly from the
[Releases page](https://github.com/HunterEwok/ciphered-private-bus/releases) of this
repository and signed/attested by the maintainer.

## What belongs to the project

- The names **Ciphered Private Bus** and **CPB** in connection with the protocol,
  reference implementation, and official test vectors.
- The canonical repository `HunterEwok/ciphered-private-bus`.
- The project's release signing keys and build provenance attestations.

## What you may do without asking

- **Reference the project:** write articles, reviews, papers, or documentation citing
  "Ciphered Private Bus" or "CPB" with attribution to the official repository.
- **Implement the specification:** write an independent implementation under any license
  using the [CC BY 4.0](LICENSES/CC-BY-4.0.txt) specification, and state *"compatible
  with Ciphered Private Bus"* or *"implements the Ciphered Private Bus specification"*
  **only** if your implementation passes the official conformance test vectors without
  altering the wire format, cryptography, or security invariants.
- **Fork the code:** fork and modify the reference implementation under the terms of
  [MPL-2.0](LICENSE).

## Forks and modified versions

If you distribute a fork or modified version of the code or specification:

1. You **must** choose a distinct name that does not use "Ciphered Private Bus" or "CPB"
   as the product or crate name, and does not imply endorsement or official status.
2. You **must** clearly state that your version is a modified fork and link back to the
   upstream repository.
3. If your changes alter the wire format, cryptography, access arbitration, or security
   properties, you **must not** claim compatibility with Ciphered Private Bus.
