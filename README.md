# Ciphered Private Bus

[![REUSE status](https://api.reuse.software/badge/github.com/HunterEwok/ciphered-private-bus)](https://api.reuse.software/info/github.com/HunterEwok/ciphered-private-bus)

**Formal specification and reference implementation of a cryptographically isolated logical communication bus.**

> **Status: early development.** The specification and Rust reference implementation are
> under active design.

Ciphered Private Bus (**CPB**) defines a transport-independent logical communication bus with:

- **Uniform framing** — canonical wire framing independent of the underlying carrier.
- **Endpoint addressing** — cryptographic endpoint identities and deterministic routing.
- **Decentralized access arbitration** — membership and authorization without a central broker.
- **Replay-protected command dispatch** — monotonic / causal replay protection for commands.
- **Post-quantum end-to-end encryption** — hybrid post-quantum confidentiality and authentication.
- **Root recovery without a central authority** — verifiable recovery of root authority without trusted third parties.

## Repository layout

| Path | Contents | License |
|---|---|---|
| `docs/` | Formal protocol specification, threat model, cryptography | [CC BY 4.0](LICENSES/CC-BY-4.0.txt) |
| `testdata/` | Interoperability and conformance test vectors | [MPL-2.0](LICENSE) |
| `crates/` | Rust reference implementation (Cargo workspace) | [MPL-2.0](LICENSE) |

## Contributing

Contributions are welcome, provided changes are discussed in an issue before opening a pull
request. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and code conventions.

## Security

Do not report security vulnerabilities in public issues. See [SECURITY.md](SECURITY.md) for
private reporting instructions.

## License and brand

- **Code, tooling, and test vectors:** [Mozilla Public License 2.0](LICENSE) (`MPL-2.0`).
- **Protocol specification and documentation (`docs/`):** [Creative Commons Attribution 4.0 International](LICENSES/CC-BY-4.0.txt) (`CC-BY-4.0`).
- **Name and official releases:** see [BRAND.md](BRAND.md) for trademark, naming, and
  compatibility rules.

Every file's license and copyright is machine-readable via [REUSE.toml](REUSE.toml).
