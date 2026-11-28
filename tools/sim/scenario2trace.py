#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok

"""Converts the scenario runs of the channels, calls, streams, enrollment and membership models into replay traces.

`quint test --out-itf` writes the states of a run but not the actions that led to them, so
the actions are read from the run's `.then(...)` steps in scenarios.qnt. The module named by
SCENARIO_MODULE is read, `scenarios` by default; the probe modules are deliberately broken
models.

Usage: [SCENARIO_MODULE=NAME] scenario2trace.py MODEL SCENARIOS_QNT INSTANCE_CONSTANTS OUT_DIR ITF_FILE...
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import itf2trace  # noqa: E402


class Parser:
    """A reader for the literals the scenarios use: strings, integers, booleans, names of
    values, records with spreads, and sets of integers."""

    def __init__(self, text: str, vals: dict):
        self.s = text
        self.i = 0
        self.vals = vals

    def ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i].isspace():
            self.i += 1

    def peek(self) -> str:
        self.ws()
        return self.s[self.i] if self.i < len(self.s) else ""

    def eat(self, c: str) -> None:
        self.ws()
        if not self.s.startswith(c, self.i):
            raise SystemExit(f"expected {c!r} at {self.s[self.i:self.i + 30]!r}")
        self.i += len(c)

    def name(self) -> str:
        self.ws()
        m = re.compile(r"[A-Za-z_][A-Za-z0-9_]*").match(self.s, self.i)
        if not m:
            raise SystemExit(f"expected a name at {self.s[self.i:self.i + 30]!r}")
        self.i = m.end()
        return m.group(0)

    def value(self):
        c = self.peek()
        if c == '"':
            j = self.s.index('"', self.i + 1)
            v = self.s[self.i + 1:j]
            self.i = j + 1
            return v
        if c.isdigit() or c == "-":
            m = re.compile(r"-?\d+").match(self.s, self.i)
            self.i = m.end()
            return int(m.group(0))
        if c == "{":
            self.eat("{")
            rec: dict = {}
            while self.peek() != "}":
                if self.s.startswith("...", self.i):
                    self.i += 3
                    rec.update(self.vals[self.name()])
                else:
                    k = self.name()
                    self.eat(":")
                    rec[k] = self.value()
                if self.peek() == ",":
                    self.eat(",")
            self.eat("}")
            return rec
        n = self.name()
        if n in ("true", "false"):
            return n == "true"
        if n == "Set":
            self.eat("(")
            items = []
            while self.peek() != ")":
                items.append(self.value())
                if self.peek() == ",":
                    self.eat(",")
            self.eat(")")
            return items
        return self.vals[n]

    def call(self) -> tuple[str, list]:
        n = self.name()
        args = []
        if self.peek() == "(":
            self.eat("(")
            while self.peek() != ")":
                args.append(self.value())
                if self.peek() == ",":
                    self.eat(",")
            self.eat(")")
        return n, args


def main_module(text: str) -> str:
    start = text.index("module " + os.environ.get("SCENARIO_MODULE", "scenarios") + " {")
    depth = 0
    for j in range(start, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start:j]
    raise SystemExit("unterminated module")


def runs(module: str) -> tuple[dict, dict]:
    vals: dict = {}
    for m in re.finditer(r"^\s*val (\w+) = (\{[^\n]*\})\s*$", module, re.M):
        try:
            vals[m.group(1)] = Parser(m.group(2), vals).value()
        except KeyError:
            # A value built from an action's parameter is not a constant of the scenario.
            continue
    out: dict = {}
    for m in re.finditer(r"run (\w+) =(.*?)(?=\n\s*(?://|run |val |$))", module, re.S):
        body = m.group(2)
        steps = []
        for t in re.finditer(r"\.then\(", body):
            depth, j = 1, t.end()
            while depth:
                depth += {"(": 1, ")": -1}.get(body[j], 0)
                j += 1
            steps.append(body[t.end():j - 1])
        out[m.group(1)] = steps
    return vals, out


def b(x: bool) -> str:
    return "1" if x else "0"


def stream_line(text: str, vals: dict, cur: dict, pre: str) -> str:
    """A step of the streams scenarios. Their arguments read the state (`nodes.get(...)`,
    `replyTo(k)`), so the values those stand for are taken from the state the step reached."""
    v = itf2trace.val
    n = re.match(r"\w+", text).group(0)
    if n == "startCall":
        k = int(re.search(r"\((\d+)\)", text).group(1))
        c = v(cur[pre + "pending"])[k]
        return f"commanderCall {k} {c['mode']} {c['credit']}"
    if n == "targetOpen":
        c = Parser(text, vals).call()[1][0]
        return itf2trace.st_open(c["k"], c["mode"], c["credit"], cur, pre)
    if n == "commanderReply":
        k = int(re.search(r"replyTo\((\d+)\)", text).group(1))
        r = [x for x in v(cur[pre + "replies"]) if x["k"] == k][0]
        return f"commanderReply {k} {r['sid']} {r['credit']} {b(r['ok'])}"
    if n == "sendChunk":
        m = re.match(r'sendChunk\("(\w)", (\d+), .*, "(\w+)", (\d+)\)$', text)
        return f"sendChunk {m.group(1)} {m.group(2)} {m.group(3)} {m.group(4)}"
    if n == "receive":
        a = Parser(text, vals).call()[1]
        return f"receive {a[0]} {itf2trace.st_chunk(a[1])}"
    if n in ("resetNonces", "halt", "learnRevoked", "reboot"):
        return f"{n} {Parser(text, vals).call()[1][0]}"
    if n == "linkDown":
        return n
    raise SystemExit(f"unsupported step {text}")


def line(model: str, text: str, vals: dict, prev: dict, cur: dict, pre: str) -> str:
    if model == "streams":
        return stream_line(text, vals, cur, pre)
    n, a = Parser(text, vals).call()
    v = itf2trace.val
    if model == "membership":
        root = itf2trace.me_root_step(n, prev, cur, pre)
        if root:
            return root
        if n == "nodeRecvCp":
            return f"{n} {a[0]} {itf2trace.me_cp(a[1])}"
        if n == "nodeRecvPp":
            return f"{n} {a[0]} {itf2trace.me_pp(a[1])}"
        if n == "nodeRecvRc":
            return f"{n} {a[0]} {a[1]['gen']}:{a[1]['key']}"
        if n == "nodeRecvHp":
            return f"{n} {a[0]} {itf2trace.me_hp(a[1])}"
        if n == "nodeHearsHalted":
            # The halted peer answers with a proof of the kind of its halt: of two root
            # change records if the node ends halted for good, else of its own generation.
            before, after = v(prev[pre + "nodes"])[a[0]], v(cur[pre + "nodes"])[a[0]]
            if after["forever"] and not before["forever"]:
                return f"nodeRecvHp {a[0]} rc:{after['gen']}:0"
            return f"nodeRecvHp {a[0]} pp:{after['gen']}:0"
        if n == "nodeAcceptData":
            return f"{n} {a[0]} {itf2trace.me_data(a[1])}"
        if n in ("nodeReboot", "nodeSend"):
            return f"{n} {a[0]}"
        raise SystemExit(f"unsupported step {n}{a}")
    if model == "enrollment":
        if n == "pairHonest":
            return f"{n} {a[0]} {a[1]}"
        if n == "advPairJoiner":
            return f"{n} {a[0]} {b(a[1])}"
        if n == "advPairAcceptor":
            return f"{n} {a[0]} {a[1]} {b(a[2])}"
        if n == "joinerSend":
            return f"{n} {a[0]}"
        if n == "acceptorRequest":
            return f"{n} {a[0]} {a[1]['tid']} {itf2trace.en_payload(a[2])}"
        if n == "badRequest":
            return f"{n} {a[0]} {a[1]} {a[2]} {a[3]} {itf2trace.en_payload(a[4])}"
        if n == "rootAdmit":
            return f"{n} {itf2trace.en_request(a[0])} {a[1]}"
        raise SystemExit(f"unsupported step {n}{a}")
    if model == "channels":
        if n == "sourceGrantTo":
            return f"sourceGrant {a[0]}"
        if n == "sourcePublishWith":
            return f"sourcePublish {a[0]} {b(a[1])}"
        if n == "envRemoveDevice":
            return f"envRemove {a[0]}"
        if n == "sourceRotate":
            return f"sourceRotate {v(cur[pre + 'source'])['kid']}"
        if n == "sourceReboot":
            before, after = v(prev[pre + "source"]), v(cur[pre + "source"])
            return f"sourceReboot {b(after['keyOk'] or not before['keyOk'])}"
        if n == "readerGrant":
            x = a[1]
            return f"readerGrant {a[0]} {x['gen']} {x['kid']} {x['reader']}"
        if n == "readerPub":
            x = a[1]
            return f"readerPub {a[0]} {x['gen']} {x['kid']} {x['no']} {x['depth']} {b(x['empty'])}"
        if n in ("readerReboot",):
            return f"{n} {a[0]}"
        if n == "sourceEpoch":
            return n
    else:
        if n == "targetAnswer":
            return f"{n} {a[0]}"
        if n in ("cmdLearn", "cmdMismatch", "cmdEpoch"):
            return f"{n} {a[0]} {a[1]}"
        if n == "cmdStart":
            nid = v(cur[pre + "cmds"])[a[0]]["nextId"] - 1
            return f"cmdStart {a[0]} {nid} {a[1]} {b(a[2])} {a[3]}"
        if n == "cmdReply":
            return f"cmdReply {a[0]} {a[1]['id']} {a[1]['nextNonce']}"
        if n == "targetCall":
            x = a[0]
            return f"targetCall {x['cmd']} {x['id']} {b(x['idem'])} {x['act']} {x['key']} {x['nonce']} {x['epoch']}"
        if n == "targetReset":
            return f"targetReset {a[0]}"
        if n == "targetRotate":
            return n
        if n == "envChange":
            return f"envChange {a[0]} {''.join(str(r) for r in sorted(a[1])) or '-'}"
    raise SystemExit(f"unsupported step {n}{a}")


def main() -> None:
    model, qnt, consts, out_dir = sys.argv[1:5]
    vals, scen = runs(main_module(Path(qnt).read_text()))
    state = itf2trace.STATE[model]
    for itf in sys.argv[5:]:
        test = re.match(rf"{model}_(?:\w+_)?([A-Za-z0-9]+)_\d+\.itf\.json", Path(itf).name).group(1)
        states = json.loads(Path(itf).read_text())["states"]
        steps = scen[test]
        # A run that ends with a disabled action (`.fail()`) ends in an empty state; the
        # replay covers the run up to it.
        if len(states[-1]) <= 1:
            states = states[:-1]
            steps = steps[:len(states) - 1]
        if len(steps) != len(states) - 1:
            raise SystemExit(f"{test}: {len(steps)} steps, {len(states) - 1} transitions")
        pre = next(k for k in states[0] if not k.startswith(("#", "mbt::"))).rsplit("::", 1)[0] + "::"
        lines = [f"model {model}", f"const {consts}"] + state(states[0], pre)
        for call, prev, cur in zip(steps, states, states[1:]):
            lines.append(line(model, call, vals, prev, cur, pre))
            lines += state(cur, pre)
        name = re.sub(r"(?<!^)(?=[A-Z])", "-", test).lower().removesuffix("-test")
        Path(out_dir, f"{model}-scenario-{name}.trace").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
