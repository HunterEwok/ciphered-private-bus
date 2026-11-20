<!-- SPDX-License-Identifier: MPL-2.0 -->
# CDDL schema checks

Scripts that check the CDDL schema of the wire format,
[`docs/spec/cpb.cddl`](../../docs/spec/cpb.cddl), as described in
[Appendix C](../../docs/spec/appendix-c-cddl.md), Section C.5.

- `maxsize.py` builds the largest instance of every object under the strict CBOR profile,
  validates it with the reference CDDL tool, and prints its size, nesting depth, longest
  container, and the headroom left in a 16384-byte frame. It exits with status 1 on any
  schema failure.
- `negative.py` checks instances the schema must reject. Every case except the extension
  field prints `rejected`. It needs the Python package `cbor2`.

Requirements: Python 3 and the reference CDDL tool, version 0.12.14
(`gem install cddl -v 0.12.14`).

```sh
python3 tools/cddl/maxsize.py  | diff - tools/cddl/maxsize-output.txt
python3 tools/cddl/negative.py | diff - tools/cddl/negative-output.txt
```

Both commands print nothing when the schema, the scripts, and the committed outputs agree.
