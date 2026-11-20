<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Ciphered Private Bus Documentation

This directory holds the formal specification and architectural documentation for
**Ciphered Private Bus** (**CPB**), licensed under
[CC BY 4.0](../LICENSES/CC-BY-4.0.txt).

## Specification

The specification is a draft and the baseline for gate G0. It is not frozen: the wire format
may change until the first release, and every change is recorded in the
[change log](../CHANGELOG.md) with its reason.

- [Protocol Requirements Specification](spec/requirements.md): scope, threat model and
  security properties, architecture, numbered requirements for the wire format,
  membership, enrollment, cryptography, channels, calls and streams, relays, and the core
  state machine; limits and parameters; verification plan and gates; security
  considerations; references; replaceable design decisions.
- [Appendix B, Wire Format](spec/appendix-b-wire-format.md): message kinds, every object's
  fields with numbers and sizes, binary frames, domain separation labels, relay tickets and
  quota accounting, and pairing step by step.
- [Appendix C, CDDL Schema and Size Analysis](spec/appendix-c-cddl.md): the CDDL schema
  ([`cpb.cddl`](spec/cpb.cddl)), the largest instance of every object, and how to reproduce
  the check with the scripts in [`tools/cddl/`](../tools/cddl/).
- [Glossary and Code Identifiers](spec/glossary.md): every entity of the bus with its
  identifier in code.
