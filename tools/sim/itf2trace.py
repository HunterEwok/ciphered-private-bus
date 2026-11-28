#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok

"""Converts Quint ITF traces of the channels and calls models into replay traces.

A replay trace is plain text: a header with the instance constants, then for every step of
the model one line with the action and its arguments, followed by lines with the projected
state the model reached. The simulator's replay test (crates/cpb-sim/tests/replay.rs) feeds
the actions to the model engine and compares its state, projected the same way, after every
step.

Usage: itf2trace.py MODEL INSTANCE_CONSTANTS OUT_FILE ITF_FILE
"""

from __future__ import annotations

import json
import sys


def val(v):
    """Decodes an ITF value into Python."""
    if isinstance(v, dict):
        if "#bigint" in v:
            return int(v["#bigint"])
        if "#set" in v:
            return [val(x) for x in v["#set"]]
        if "#map" in v:
            return {val(k): val(x) for k, x in v["#map"]}
        if "#tup" in v:
            return tuple(val(x) for x in v["#tup"])
        return {k: val(x) for k, x in v.items()}
    return v


def names(s) -> str:
    return ",".join(sorted(s))


def b(x: bool) -> str:
    return "1" if x else "0"


# ------------------------------------------------------------------------- channels

def ch_state(st: dict, pre: str) -> list[str]:
    src = val(st[pre + "source"])
    out = [
        "= source gen={} kid={} keyok={} granted={} next={} reserved={} rotate={} togrant={}".format(
            src["gen"], src["kid"], b(src["keyOk"]), names(src["granted"]), src["nextNo"],
            src["reserved"], b(src["mustRotate"]), names(src["toGrant"]))
    ]
    readers = st[pre + "readers"]["#map"]
    for d, r in sorted(readers, key=lambda kv: kv[0]):
        r2 = val(r)
        nos = sorted(p["no"] for p in (val(x) for x in r["retained"]["#set"]))
        out.append("= reader {} gen={} kid={} higen={} hino={} floor={} depth={} retained={}".format(
            d, r2["gen"], r2["kid"], r2["hiGen"], r2["hiNo"], r2["floor"], r2["depth"],
            ",".join(str(n) for n in nos)))
    out.append("= members " + names(val(st[pre + "members"])))
    return out


def ch_step(st: dict, pre: str) -> str:
    a = st["mbt::actionTaken"]
    p = {k: v["value"] for k, v in st["mbt::nondetPicks"].items() if v["tag"] == "Some"}
    if a in ("envRemove", "envJoin", "sourceGrant", "readerReboot"):
        return f"{a} {p['d']}"
    if a == "sourceRotate":
        return f"{a} {val(st[pre + 'source'])['kid']}"
    if a == "sourcePublish":
        return f"{a} {val(p['depth'])} {b(p['empty'])}"
    if a == "sourceEpoch":
        return a
    if a == "sourceReboot":
        return f"{a} {b(p['keep'])}"
    if a == "readerGrant":
        x = val(p["x"])
        return f"{a} {p['d']} {x['gen']} {x['kid']} {x['reader']}"
    if a == "readerPub":
        x = val(p["p"])
        return f"{a} {p['d']} {x['gen']} {x['kid']} {x['no']} {x['depth']} {b(x['empty'])}"
    raise SystemExit(f"unknown channels action {a}")


# ---------------------------------------------------------------------------- calls

def call_text(c: dict) -> str:
    return "id:{},act:{},idem:{},key:{},nonce:{},epoch:{}".format(
        c["id"], c["act"], b(c["idem"]), c["key"], c["nonce"], c["epoch"])


def cl_state(st: dict, pre: str) -> list[str]:
    slots = val(st[pre + "slots"])
    named = val(st[pre + "named"])
    passport = val(st[pre + "passport"])
    out = [
        "= target tepoch={} slots={} named={}".format(
            val(st[pre + "tepoch"]),
            ",".join(f"{d}:{n}" for d, n in sorted(slots.items()) if n != 0),
            ",".join(f"{c}:{''.join(str(r) for r in sorted(passport[c]))}" for c in sorted(named)))
    ]
    for d, k in sorted(val(st[pre + "cmds"]).items()):
        pend = k["pending"]
        ptxt = "-" if not pend["active"] else "{},te:{},tm:{}".format(
            call_text(pend["call"]), b(pend["triedEpoch"]), b(pend["triedMismatch"]))
        out.append(f"= cmd {d} nonce={k['nonce']} epoch={k['epoch']} pending={ptxt}")
    return out


def cl_step(st: dict, pre: str) -> str:
    a = st["mbt::actionTaken"]
    p = {k: v["value"] for k, v in st["mbt::nondetPicks"].items() if v["tag"] == "Some"}
    if a == "targetAnswer":
        return f"{a} {p['c']}"
    if a in ("cmdLearn", "cmdMismatch"):
        return f"{a} {p['c']} {val(p['n'])}"
    if a == "cmdStart":
        nid = val(st[pre + "cmds"])[p["c"]]["nextId"] - 1
        return f"{a} {p['c']} {nid} {val(p['a'])} {b(p['idem'])} {p['key']}"
    if a == "cmdEpoch":
        return f"{a} {p['c']} {val(p['e'])}"
    if a == "cmdReply":
        r = val(p["r"])
        return f"{a} {p['c']} {r['id']} {r['nextNonce']}"
    if a == "envChange":
        rs = sorted(val(x) for x in p["rs"]["#set"])
        return f"{a} {p['c']} {''.join(str(r) for r in rs) or '-'}"
    if a == "targetCall":
        x = val(p["x"])
        return "{} {} {} {} {} {} {} {}".format(a, x["cmd"], x["id"], b(x["idem"]), x["act"], x["key"], x["nonce"], x["epoch"])
    if a == "targetReset":
        return f"{a} {p['kind']}"
    if a == "targetRotate":
        return a
    raise SystemExit(f"unknown calls action {a}")


def main() -> None:
    model, consts, out_file, itf_file = sys.argv[1:5]
    states = json.load(open(itf_file))["states"]
    pre = next(k for k in states[0] if not k.startswith(("#", "mbt::"))).rsplit("::", 1)[0] + "::"
    state, step = (ch_state, ch_step) if model == "channels" else (cl_state, cl_step)
    lines = [f"model {model}", f"const {consts}"]
    lines += state(states[0], pre)
    # The action that led to state i is recorded in state i.
    for cur in states[1:]:
        lines.append(step(cur, pre))
        lines += state(cur, pre)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
