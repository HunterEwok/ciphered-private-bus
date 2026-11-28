# cpb-api

The local application interface of **Ciphered Private Bus** (CPB), requirement R-API-2 of the
[specification](../../docs/spec/requirements.md).

An application talks to its node only through the `LocalApi` trait. The simulator
([`cpb-sim`](../cpb-sim/)) and the application library of the core implement the same trait, so
an application written against the simulator moves to the core without changes to its own code.

- **Non-blocking, no callbacks.** Every operation returns at once. Publications, incoming calls,
  call outcomes and requests for a user-presence or root signature arrive from `poll_event`. No
  async runtime and no operating system are needed (`no_std` with `alloc`).
- **Rule codes.** `codes` is the single list of the stable `area/rule` codes (R-ERR-1), each
  with its kind, the requirement that defines it and a short message that is safe to show. The
  codes of the format layer are added together with their test vectors at gate G2.
- **Two reporting modes** (R-ERR-2, R-ERR-3). `Report::render` shows only the short message in
  release mode and adds the rule code, the requirement, the kind and the underlying message in
  debug mode. `ErrorMode::resolve` follows the build type unless an override (`debug` or
  `release`) is given. Reports carry identifiers and numbers only, never keys, publication
  content or call arguments (R-ERR-5).

The crate is at version 0.x: the shape may change until the format is frozen at release
(R-FMT-15). Streams are added to the trait in a later version.
