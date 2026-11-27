# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
"""Check that the proof obligations of every model cover its whole step.

run-inductive.ps1 -Split checks the step branch by branch, one check for
each action listed under "steps" in checks.json, and a TLC view is proved
with one "preserves Struct" job and at least one "answered with an equal
view" job for each branch. The hashes recorded with a result cover the model
and the proof file, not checks.json, so a branch missing from the list would
leave a green run with one branch unproved. This script fails when:

- the step actions defined in a proof file (action stepX) differ from the
  list in checks.json (inductive and convergence sections), or from the
  "preserves Struct" jobs (bisim section);
- a branch of the bisim section has no "answered" job, or a match action
  defined in the view file has no job;
- an action called in the model's own step (action step = any { ... }) is
  used by none of the step actions of a proof file.

Usage: python3 models/check_steps.py [model ...]   (default: every model)
Exit status 0 when every check passes.
"""

import json
import re
import sys
from pathlib import Path

MODELS = Path(__file__).resolve().parent
ACTION = re.compile(r"^\s*action\s+(\w+)", re.M)


def actions(text):
    """Map each action defined in the text to its definition text."""
    found = list(ACTION.finditer(text))
    out = {}
    for i, m in enumerate(found):
        end = found[i + 1].start() if i + 1 < len(found) else len(text)
        out[m.group(1)] = text[m.start():end]
    return out


def body_of(text, name):
    """The text between the braces of `action name = any { ... }`."""
    m = re.search(r"^\s*action\s+%s\s*=\s*any\s*\{" % re.escape(name), text, re.M)
    if not m:
        return None
    depth, i = 1, m.end()
    while depth and i < len(text):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[m.end():i - 1]


def strip_comments(text):
    return re.sub(r"//[^\n]*", "", text)


def check_model(name):
    folder = MODELS / name
    checks = json.loads((folder / "checks.json").read_text(encoding="utf-8"))
    model_text = strip_comments((folder / f"{name}.qnt").read_text(encoding="utf-8"))
    model_actions = actions(model_text)
    step_body = body_of(model_text, "step")
    errors = []
    if step_body is None:
        return [f"{name}: no `action step = any {{ ... }}` in {name}.qnt"]
    called = {a for a in model_actions if a != "step" and re.search(r"\b%s\b" % re.escape(a), step_body)}

    for section, value in checks.items():
        if not isinstance(value, dict) or ("steps" not in value and "jobs" not in value):
            continue
        file = value.get("file", "inductive.qnt")
        proof = strip_comments((folder / file).read_text(encoding="utf-8"))
        defined = {a: t for a, t in actions(proof).items() if re.fullmatch(r"step[A-Z]\w*", a)}
        where = f"{name}/{file} [{section}]"
        if "steps" in value:
            listed = set(value["steps"])
        else:
            jobs = value["jobs"]
            listed = {j["step"] for j in jobs if j.get("invariant") == "structA" and j.get("init") == "initSafe"}
            answered = [j["step"] for j in jobs if j.get("invariant") == "matched"]
            all_actions = actions(proof)
            matches = {a: t for a, t in all_actions.items() if re.fullmatch(r"match[A-Z]\w*", a)}
            for a in sorted(set(matches) - set(answered)):
                errors.append(f"{where}: {a} is defined but has no job")
            # Sub-cases of a branch (stepRecvCpHalt, ...) are used by match actions only.
            in_matches = "".join(matches.values())
            listed |= {s for s in defined if re.search(r"\b%s\b" % re.escape(s), in_matches)}
            for s in sorted(listed & set(defined)):
                if s in {j["step"] for j in jobs if j.get("invariant") == "structA"} and \
                        not any(a.startswith("match" + s[len("step"):]) for a in answered):
                    errors.append(f"{where}: branch {s} has no 'answered with an equal view' job")
        disabled = set(value.get("disabledSteps", []))
        for s in sorted(set(defined) - listed - disabled):
            errors.append(f"{where}: {s} is defined but not checked")
        for s in sorted((listed | disabled) - set(defined)):
            errors.append(f"{where}: {s} is checked but not defined")
        if "steps" in value:
            # A view's steps restate the model's actions for copy A; that they
            # equal the model's step is argued in the view file.
            used = "".join(defined.values())
            for a in sorted(called):
                if not re.search(r"\b%s\b" % re.escape(a), used):
                    errors.append(f"{where}: the model's step calls {a}, which no step action uses")
    return errors


def main(argv):
    names = argv or sorted(p.parent.name for p in MODELS.glob("*/checks.json"))
    errors = [e for n in names for e in check_model(n)]
    for e in errors:
        print(e)
    if not errors:
        print(f"step coverage holds for {', '.join(names)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
