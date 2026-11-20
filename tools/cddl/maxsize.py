#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build the largest instance of every CPB v1 object, check it against the
CDDL schema, and report encoded size, nesting depth and container length.

Encoding follows the strict profile of R-FMT-1..4. Sizes include the
message wrapper {0: t, 1: bstr(object)} where the object travels in one.
"""
import hashlib, os, subprocess, sys, tempfile

SEQ = 2**31 - 1
U53 = 2**53 - 1
FRAME = 16384


def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | ai]) + n.to_bytes(width, "big")
    raise ValueError(n)


def enc(v):
    if isinstance(v, bool) or v is None:
        raise TypeError("not in profile")
    if isinstance(v, int):
        assert 0 <= v <= U53, v
        return head(0, v)
    if isinstance(v, (bytes, bytearray)):
        return head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        assert len(v) <= 128, len(v)
        return head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        assert len(v) <= 128, len(v)
        keys = sorted(v)
        assert all(isinstance(k, int) and 0 <= k <= 65535 for k in keys)
        return head(5, len(v)) + b"".join(enc(k) + enc(v[k]) for k in keys)
    raise TypeError(type(v))


def depth(v):
    if isinstance(v, list):
        return 1 + max((depth(x) for x in v), default=0)
    if isinstance(v, dict):
        return 1 + max((depth(x) for x in v.values()), default=0)
    return 0


def longest(v):
    if isinstance(v, (list, dict)):
        items = v if isinstance(v, list) else list(v.values())
        return max([len(v)] + [longest(x) for x in items])
    return 0


B = lambda n: b"\xff" * n
sha = lambda b: hashlib.sha256(b).digest()

P256 = [1, B(65)]
XWING = [2, B(1216)]
SLH = [3, B(32)]
SIG = B(64)
SIG_PQ = B(7856)
XWING_CT, TAG = 1120, 16


def hpke(plain):
    return B(XWING_CT + len(enc(plain)) + TAG)


def aead(plain):
    return B(len(enc(plain)) + TAG)


def msg(t, obj):
    return {0: t, 1: enc(obj)}


# ---------------- largest plaintexts ----------------
name64 = "x" * 64
join_sealed = {1: P256, 2: name64, 3: B(32), 4: P256, 5: SIG}
# data + pad <= 4096: the two-header split is the largest encoding
pub_content = max(
    ({1: 65535, 3: B(d), 4: B(4096 - d)} if d < 4096 else {1: 65535, 3: B(4096)}
     for d in range(1, 4097)),
    key=lambda m: len(enc(m)))
command = {1: 64, 2: B(4096), 3: 1, 4: 2**32 - 1}
reply_plain = {1: 65535, 2: "x" * 256, 3: B(4096), 4: SEQ, 5: 2**32 - 1, 6: B(16)}

# ---------------- objects ----------------
pp_head = {1: B(32), 2: SEQ, 3: SEQ}
pp_rest = {4: P256, 5: B(1), 6: P256, 7: [[B(16), B(8), B(8)]] * 128}
cp_head = {1: B(32), 2: SEQ, 3: SEQ}
cp_rest = {4: SEQ, 5: B(4096), 6: SEQ, 7: [B(16)] * 128, 8: B(16)}
rc_head = {1: B(32), 2: SEQ}
rc_rest = {3: P256}


def objects(root_sig):
    o = {}
    o["Passport"] = (4, [pp_head, pp_rest, root_sig])
    o["Checkpoint"] = (5, [cp_head, cp_rest, root_sig])
    o["RootChange"] = (6, [rc_head, rc_rest, SIG, SIG_PQ])
    o["RelayTicket"] = (10, [{1: B(32), 2: SEQ, 3: SEQ, 4: P256, 5: U53, 6: U53}, root_sig])
    # a call may be signed by the root key (R-CALL-4)
    call_body = {1: B(32), 2: B(32), 3: B(16), 4: B(16), 5: B(16), 6: SEQ, 7: SEQ,
                 8: SEQ, 9: hpke(command)}
    o["Call"] = (26, [call_body, root_sig])
    return o


common = {
    "SealClaim": (7, [{1: B(32), 2: B(16), 3: SEQ, 4: XWING}, SIG]),
    "JoinRequest": (8, [{1: B(32), 2: B(16), 3: SEQ, 4: SEQ, 5: SEQ,
                         6: hpke(join_sealed)}, SIG]),
    "KeyRequest": (9, [{1: B(32), 2: B(16), 3: B(16), 4: B(16), 5: SEQ, 6: B(16)}, SIG]),
    "KeyGrant": (16, [{1: B(32), 2: B(16), 3: SEQ, 4: SEQ, 5: SEQ, 6: B(16), 7: B(16),
                       8: SEQ, 9: B(32), 10: B(16)}, B(1168), SIG]),
    "Publication": (17, [{1: B(32), 2: B(16), 3: SEQ, 4: U53, 5: SEQ, 6: SEQ,
                          7: B(16), 8: B(32), 9: 1024,
                          10: [(2**31 - 1) * 16346, B(32), 16346]},
                         aead(pub_content), SIG]),
}


def halt(kind, h, sigs):
    return {0: 12, 1: kind, 2: enc(h), 3: B(32), 4: sigs, 5: B(32), 6: sigs}


plain_msgs = {
    "Hello": {0: 1, 1: list(range(1, 129)), 2: B(16), 3: B(32), 4: SEQ, 5: SEQ, 6: B(16)},
    "Auth": {0: 2, 1: SIG},
    "Get": {0: 3, 1: B(32), 2: 1, 3: B(16)},
    "RelayRefusal": {0: 11, 1: B(32), 2: B(32), 3: 5},
    "HaltProof(Passport, ES256)": halt(4, pp_head, [SIG]),
    "HaltProof(Checkpoint, PQ root)": halt(5, cp_head, [SIG_PQ]),
    "HaltProof(RootChange, K1+K2)": halt(6, rc_head, [SIG, SIG_PQ]),
    "BlobGet": {0: 18, 1: B(32), 2: B(32), 3: SEQ - 1},
    "NonceRequest": {0: 24, 1: B(32), 2: B(16), 3: B(16)},
    "Nonce": {0: 25, 1: B(32), 2: B(16), 3: B(16), 4: B(16)},
    "Reply": {0: 27, 1: B(32), 2: B(16), 3: B(16), 4: B(32), 5: aead(reply_plain)},
    "Refusal": {0: 28, 1: B(32), 2: B(16), 3: B(16), 4: B(32), 5: 1,
                6: enc(common["SealClaim"][1])},
    "PairInit": {0: 40, 1: list(range(1, 129)), 2: B(16)},
    "PairReply": {0: 41, 1: SEQ, 2: B(16), 3: B(32)},
    "PairConfirm": {0: 42, 1: B(32), 2: B(32)},
    "PairDone": {0: 45, 1: B(32)},
    "PairSealed": {0: 43, 1: aead({1: B(32), 2: P256, 3: SLH, 4: P256, 5: SEQ})},
    "PairAbort": {0: 44, 1: 4},
}

inner = {  # decoded on their own (R-FMT-4)
    "JoinSealed": join_sealed, "PubContent": pub_content, "Command": command,
    "ReplyPlain": reply_plain,
    "PairBus": {1: B(32), 2: P256, 3: SLH, 4: P256, 5: SEQ},
    "PairDevice": {1: P256, 2: P256, 3: name64, 4: SIG},
    "NodeInfo": {1: name64},
}

SCHEMA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs", "spec", "cpb.cddl"
)


def validate(rule, value):
    with tempfile.TemporaryDirectory() as d:
        schema = os.path.join(d, "s.cddl")
        with open(schema, "w") as f:
            f.write(f"start = {rule}\n" + open(SCHEMA).read())
        inst = os.path.join(d, "i.cbor")
        with open(inst, "wb") as f:
            f.write(enc(value))
        r = subprocess.run(["cddl", schema, "validate", inst], capture_output=True, text=True)
        bad = [l for l in (r.stdout + r.stderr).splitlines() if "Unused rule" not in l]
        return r.returncode == 0 and not bad, "\n".join(bad)


rows, failures = [], []


def report(name, rule, value, wrapped=None):
    ok, err = validate(rule, value)
    if not ok:
        failures.append((name, err))
    size = len(enc(wrapped if wrapped is not None else value))
    rows.append((name, size, depth(value), longest(value), FRAME - size, ok))


for name, (t, obj) in {**objects(SIG), **common}.items():
    report(name, name, obj, msg(t, obj))
for name, (t, obj) in objects(SIG_PQ).items():
    if name != "RootChange":
        report(name + " (PQ root sig)", name, obj, msg(t, obj))
for name, m in plain_msgs.items():
    report(name, name.split("(")[0], m)
for name, v in inner.items():
    report(name + " (plaintext)", name, v)

print(f"{'object':34} {'bytes':>6} {'depth':>5} {'items':>5} {'room':>6}  schema")
for name, size, dp, ln, room, ok in rows:
    print(f"{name:34} {size:6} {dp:5} {ln:5} {room:6}  {'ok' if ok else 'FAIL'}")
for name, err in failures:
    print("\nFAIL", name, "\n", err[:800])
assert all(r[2] <= 4 for r in rows), "depth"
assert all(r[4] >= 0 for r in rows), "frame"
sys.exit(1 if failures else 0)
