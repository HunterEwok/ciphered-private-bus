#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok

"""Converts Quint ITF traces of the channels, calls, streams, enrollment and membership models into replay traces.

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


# -------------------------------------------------------------------------- streams

def st_chunk(c: dict) -> str:
    return "{} {} {} {} {} {}".format(c["dir"], c["sid"], c["k"], c["no"], c["kind"], c["credit"])


def st_state(st: dict, pre: str) -> list[str]:
    out = []
    for p, n in sorted(val(st[pre + "nodes"]).items()):
        sides = ";".join(
            "{}:k={},mode={},next={},high={},sc={},rc={},idle={},got={},granted={},sent={},recvd={}".format(
                sid, s["k"], s["mode"], s["next"], s["high"], s["sendCredit"], s["recvCredit"], b(s["idle"]),
                s["got"], s["granted"], s["sent"], s["recvd"])
            for sid, s in sorted(n["streams"].items()))
        out.append(f"= node {p} halted={b(n['halted'])} revoked={b(n['peerRevoked'])} streams={sides}")
    pending = val(st[pre + "pending"])
    out.append("= pending " + ",".join(f"{k}:{c['mode']}:{c['credit']}" for k, c in sorted(pending.items())))
    out.append("= done " + ",".join(str(k) for k in sorted(val(st[pre + "done"]))))
    return out


def st_open(k: int, mode: str, credit: int, cur: dict, pre: str) -> str:
    """The target's step: its own initial credit is read from the side it opened."""
    sides = [s for s in val(cur[pre + "nodes"])["T"]["streams"].values() if s["k"] == k]
    return f"targetOpen {k} {mode} {credit} {sides[0]['recvCredit'] if sides else 0}"


def st_step(st: dict, pre: str) -> str:
    a = st["mbt::actionTaken"]
    p = {k: v["value"] for k, v in st["mbt::nondetPicks"].items() if v["tag"] == "Some"}
    if a == "commanderCall":
        k = val(st[pre + "nextK"]) - 1
        c = val(st[pre + "pending"])[k]
        return f"{a} {k} {c['mode']} {c['credit']}"
    if a == "targetOpen":
        c = val(p["c"])
        return st_open(c["k"], c["mode"], c["credit"], st, pre)
    if a == "commanderReply":
        r = val(p["r"])
        return f"{a} {r['k']} {r['sid']} {r['credit']} {b(r['ok'])}"
    if a == "sendChunk":
        add = val(p["add"]) if p["kind"] == "credit" else 0
        return f"{a} {p['p']} {val(p['sid'])} {p['kind']} {add}"
    if a == "overrun":
        return f"{a} {p['p']} {val(p['sid'])}"
    if a == "receive":
        return f"{a} {p['p']} {st_chunk(val(p['ch']))}"
    if a in ("resetNonces", "halt", "learnRevoked", "reboot"):
        return f"{a} {p['p']}"
    if a == "linkDown":
        return a
    raise SystemExit(f"unknown streams action {a}")


# ----------------------------------------------------------------------- enrollment

def en_payload(p: dict) -> str:
    return f"{p['key']}:{p['presence']}:{p['name']}:{p['tid']}"


def en_request(r: dict) -> str:
    return f"{r['key']}:{r['presence']}:{r['name']}:{r['tid']}:{r['acceptor']}/{en_payload(r['signed'])}"


def en_state(st: dict, pre: str) -> list[str]:
    out = [f"= tid {val(st[pre + 'tid'])}"]
    current = val(st[pre + "current"])
    for j in sorted(current):
        out.append(f"= joiner {j} current={current[j]}")
    out.append("= sent " + ",".join(sorted(f"{en_payload(x['p'])}>{x['to']}" for x in val(st[pre + "sent"]))))
    out.append("= inbox " + ",".join(sorted(en_request(r) for r in val(st[pre + "inbox"]))))
    out.append("= passports " + ",".join(
        sorted(f"{x['key']}:{x['presence']}:{x['name']}" for x in val(st[pre + "passports"]))))
    return out


def en_step(st: dict, pre: str) -> str:
    a = st["mbt::actionTaken"]
    p = {k: val(v["value"]) for k, v in st["mbt::nondetPicks"].items() if v["tag"] == "Some"}
    if a == "pairHonest":
        return f"{a} {p['j']} {p['a']}"
    if a == "advPairJoiner":
        return f"{a} {p['j']}"
    if a == "advPairAcceptor":
        return f"{a} {p['a']}"
    if a == "joinerSend":
        return f"{a} {p['j']}"
    if a == "acceptorRequest":
        return f"{a} {p['s']['acceptor']} {p['s']['tid']} {en_payload(p['p'])}"
    if a == "badRequest":
        return f"{a} {p['key']} {p['presence']} {p['name']} {p['t']} {en_payload(p['p'])}"
    if a == "rootAdmit":
        return f"{a} {en_request(p['r'])} {p['j']}"
    raise SystemExit(f"unknown enrollment action {a}")


# ----------------------------------------------------------------------- membership

def nums(xs) -> str:
    return ".".join(str(x) for x in sorted(xs))


def me_cp(c: dict) -> str:
    return f"{c['gen']}:{c['no']}:{c['start']}:{nums(c['valid'])}:{c['nextNo']}"


def me_pp(p: dict) -> str:
    return f"{p['gen']}:{p['no']}:{p['dev']}:{p['rights']}"


def me_hp(h: dict) -> str:
    return f"{h['kind']}:{h['gen']}:{h['no']}"


def me_data(m: dict) -> str:
    return f"{m['src']}:{m['ppNo']}:{m['gen']}:{m['cpNo']}:{b(m['ch0'])}"


def me_state(st: dict, pre: str) -> list[str]:
    out = []
    for d, n in sorted(val(st[pre + "nodes"]).items()):
        out.append("= node {} gen={} rc={} halted={} forever={} cp={} pps={}".format(
            d, n["gen"], n["rc"], b(n["halted"]), b(n["forever"]), me_cp(n["cp"]),
            ",".join(sorted(me_pp(p) for p in n["pps"]))))
    r = val(st[pre + "root"])
    out.append(f"= root gen={r['gen']} cp={r['cpNo']} next={r['nextNo']} valid={nums(r['valid'])}")
    return out


def me_root_step(a: str, prev: dict, cur: dict, pre: str) -> str | None:
    """The Root's and the recovery key's steps, read from what they added to the pool."""
    if a in ("rootAdmit", "rootChangeRights", "rootIssue"):
        before, after = val(prev[pre + "root"]), val(cur[pre + "root"])
        new = [p for p in val(cur[pre + "pool"])["pp"] if p not in val(prev[pre + "pool"])["pp"]]
        replaces = sorted(set(before["valid"]) - set(after["valid"]))
        return f"rootIssue {new[0]['dev']} {new[0]['rights']} {nums(replaces) or '-'}"
    if a == "rootRevoke":
        before, after = val(prev[pre + "root"]), val(cur[pre + "root"])
        return f"rootRevoke {nums(set(before['valid']) - set(after['valid']))}"
    if a in ("adversaryProof", "setNodeless"):
        return "adversaryProof"
    if a in ("rootEquivocateCp", "rootEquivocatePp", "recoveryEquivocate", "recoveryChange"):
        return a
    return None


def me_step(st: dict, pre: str, prev: dict) -> str:
    a = st["mbt::actionTaken"]
    line = me_root_step(a, prev, st, pre)
    if line:
        return line
    p = {k: val(v["value"]) for k, v in st["mbt::nondetPicks"].items() if v["tag"] == "Some"}
    if a == "nodeRecvCp":
        return f"{a} {p['d']} {me_cp(p['c'])}"
    if a == "nodeRecvPp":
        return f"{a} {p['d']} {me_pp(p['p'])}"
    if a == "nodeRecvRc":
        return f"{a} {p['d']} {p['r']['gen']}:{p['r']['key']}"
    if a in ("nodeRecvHp", "nodeHearsHalted"):
        return f"nodeRecvHp {p['d']} {me_hp(p['h'])}"
    if a == "nodeAcceptData":
        return f"{a} {p['d']} {me_data(p['m'])}"
    if a == "nodeGrant":
        return f"{a} {p['d']} {me_pp(p['p'])}"
    if a in ("nodeReboot", "nodeSend"):
        return f"{a} {p['d']}"
    raise SystemExit(f"unknown membership action {a}")


STATE = {"channels": ch_state, "calls": cl_state, "streams": st_state, "enrollment": en_state,
         "membership": me_state}
STEP = {"channels": ch_step, "calls": cl_step, "streams": st_step, "enrollment": en_step}


def main() -> None:
    model, consts, out_file, itf_file = sys.argv[1:5]
    states = json.load(open(itf_file))["states"]
    pre = next(k for k in states[0] if not k.startswith(("#", "mbt::"))).rsplit("::", 1)[0] + "::"
    state, step = STATE[model], STEP.get(model)
    lines = [f"model {model}", f"const {consts}"]
    lines += state(states[0], pre)
    # The action that led to state i is recorded in state i.
    for prev, cur in zip(states, states[1:]):
        lines.append(me_step(cur, pre, prev) if model == "membership" else step(cur, pre))
        lines += state(cur, pre)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
