# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
"""Check that every value an inductive proof draws is bounded by its invariant.

An inductive proof starts from `indInit` (or `drawA`, `drawB`, `pairInit` of a
view), which draws every variable from a bounded range and keeps the states
that satisfy the invariant. The step obligation checks that the invariant
holds after one step; if the invariant does not bound a drawn value, a step
can leave the drawn range while the invariant still holds, and the proof no
longer covers the states it reaches. This script fails when a value drawn
from a range, a set of subsets, a map or a set of choices is stored in a
field (or passed as an argument to the invariant) that the invariant does not
bound:

- a number drawn from `a.to(b)`: the invariant compares the field from below
  and from above, tests it with `contains`, or equates it;
- a set drawn with `powerset()`: `subseteq` or an equation;
- a map drawn with `setOfMaps`: its keys are equated;
- a value drawn from another set: `contains` or an equation.

A boolean is never reported. The match is by field name in the file of the
draw, so it is a lint and not a proof: it finds a field that is never bounded
anywhere in that file.

Usage: python3 models/check_draws.py   Exit status 0 when every check passes.
"""

import re
import sys
from pathlib import Path

MODELS = Path(__file__).resolve().parent
DRAWS = ("indInit", "drawA", "drawB", "pairInit")
NONDET = re.compile(r"nondet\s+(\w+)\s*=\s*(.+?)\.oneOf\(\)")


def body(text, start):
    """The text of the braces opened at or after `start`."""
    i = text.index("{", start)
    depth, j = 1, i + 1
    while depth:
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        j += 1
    return text[i + 1:j - 1], j


def split_args(s):
    """The top-level comma-separated parts of s."""
    parts, depth, cur = [], 0, ""
    for ch in s:
        depth += {"(": 1, ")": -1}.get(ch, 0)
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    return parts + [cur]


def kind(expr):
    """The kind of one drawn value; a map drawn with setOfMaps gives its
    values to the fields, so it has the kind of its values."""
    expr = expr.strip()
    if re.fullmatch(r"Set\(\s*(false\s*,\s*true|true\s*,\s*false)\s*\)", expr):
        return "bool"
    if expr.startswith("setOfMaps(") and expr.endswith(")"):
        args = split_args(expr[len("setOfMaps("):-1])
        return kind(args[1]) if len(args) == 2 else "map"
    if "powerset()" in expr:
        return "set"
    if re.search(r"\.to\(", expr):
        return "int"
    return "enum"


def bounded(rest, name, k, dotted):
    # The field, possibly read through map lookups or tuple parts.
    f = ((r"[\w:.]*\." if dotted else r"(?<![\w.])") + re.escape(name) + r"\b"
         + r"(?:\.get\([^()]*(?:\([^()]*\))?[^()]*\)|\._\d)*")
    eq = re.search(f + r"\s*==|==\s*\(?" + f, rest)
    if k == "set":
        # subseteq, or a field predicate on every element
        return bool(eq or re.search(f + r"(?:\.keys\(\))?\.(subseteq|forall)\(", rest))
    if k == "map":
        return bool(re.search(f + r"\.keys\(\)\s*==", rest) or eq)
    if eq or re.search(r"contains\(\s*" + f + r"\s*\)", rest):
        return True
    upper = re.search(f + r"\s*<", rest) or re.search(r">=?\s*" + f, rest)
    lower = re.search(r"<=?\s*" + f, rest) or re.search(f + r"\s*>", rest)
    return bool(upper and lower)


def check_file(path):
    text = re.sub(r"//[^\n]*", "", path.read_text(encoding="utf-8"))
    spans, found = [], []
    for m in re.finditer(r"action\s+(%s)\s*=\s*\{" % "|".join(DRAWS), text):
        b, end = body(text, m.start())
        spans.append((m.start(), end))
        found.append((m.group(1), b))
    if not found:
        return []
    rest = "".join(text[s:e] for s, e in zip([0] + [e for _, e in spans], [s for s, _ in spans] + [len(text)]))
    errors = set()
    for action, b in found:
        draws = {n: kind(e) for n, e in NONDET.findall(b)}
        for n, k in draws.items():
            if k == "bool":
                continue
            # The field a drawn value is stored in directly (not inside a nested
            # record, and not through a helper that builds it).
            fields = {fld for fld, span in re.findall(r"(?<![\w:])(\w+)\s*:(?!:)\s*([^,{}\n]*?)\b%s\b" % re.escape(n), b)
                      if not re.search(r"(?<![\w.])[A-Za-z_]\w*\(", span)}
            fields -= {"kind"}
            for fld in fields:
                if not bounded(rest, fld, k, True):
                    errors.add(f"{path.relative_to(MODELS)} [{action}]: field `{fld}` drawn from `{n}` ({k}) is not bounded")
            # A drawn value passed straight to the invariant: bound its parameter.
            for call in re.finditer(r"(\w*InvOf|structOf|\w*[Cc]onvOf)\(([^()]*)\)", b):
                args = [a.strip() for a in call.group(2).split(",")]
                if n not in args:
                    continue
                sig = re.search(r"def\s+%s\(([^)]*)\)" % re.escape(call.group(1)), text)
                if not sig:
                    continue
                params = [p.split(":")[0].strip() for p in re.split(r",(?![^(]*\))", sig.group(1))]
                if len(params) == len(args):
                    p = params[args.index(n)]
                    if not bounded(rest, p, k, False):
                        errors.add(f"{path.relative_to(MODELS)} [{action}]: parameter `{p}` drawn from `{n}` ({k}) is not bounded")
    return sorted(errors)


def main():
    files = sorted(MODELS.glob("*/*.qnt"))
    errors = [e for f in files for e in check_file(f)]
    for e in errors:
        print(e)
    if not errors:
        print("every drawn value is bounded by its invariant")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
