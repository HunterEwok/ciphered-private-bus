#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok

"""Regenerates the replay traces of the simulator from the Quint models.

For each model it takes two kinds of traces and writes them to crates/cpb-sim/tests/traces:

- every run of the model's fixed scenarios (scenarios.qnt), which reach each behaviour the
  witnesses name, converted with scenario2trace.py;
- random traces of the `small` instance with a fixed seed: of the sampled traces it keeps a
  small set that together reaches the most behaviours (the `seen` variable and the actions
  taken) and has the most of the rarer actions, converted with itf2trace.py.

Run it from the repository root after `npm ci` in models/; the TypeScript backend of the
pinned Quint needs no other download.

Usage: tools/sim/gen_traces.py [MODEL...]

Without arguments every model is regenerated; with model names, only those.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import itf2trace  # noqa: E402

OUT = ROOT / "crates/cpb-sim/tests/traces"
SEED = 11
SAMPLES = 300
STEPS = 60
KEEP = 10

MODELS = {
    "channels": {
        "consts": "devices=a,b,c no_read=c late=b block=2",
        "scenario_consts": "devices=a,b no_read= block=2",
        "rare": {"sourcePublish": 3, "readerPub": 2, "sourceGrant": 2, "readerGrant": 1, "envJoin": 1},
    },
    "calls": {
        "consts": "commanders=a,b root=r presence=b max_nonce=6 epochs=2",
        "scenario_consts": "commanders=a root=r presence=a max_nonce=4 epochs=2",
        "rare": {"cmdReply": 4, "cmdStart": 2, "cmdMismatch": 2, "cmdEpoch": 1, "envChange": 1},
    },
    "streams": {
        "consts": "max_streams=2",
        "scenario_consts": "max_streams=1",
        "scenario_modules": ["scenarios", "scenarios_reset"],
        "rare": {"commanderReply": 4, "sendChunk": 3, "overrun": 2, "resetNonces": 2},
    },
    "membership": {
        "consts": "devices=a,b,c window=2",
        "scenario_consts": "devices=a,b window=2",
        "scenario_modules": ["scenarios", "scenarios_convergence", "scenarios_window"],
        "rare": {"nodeRecvRc": 4, "nodeRecvHp": 4, "nodeHearsHalted": 4, "nodeAcceptData": 3, "nodeGrant": 2,
                 "rootRevoke": 2, "recoveryChange": 2},
        # Uniform choice among the model's actions rarely delivers the records a node needs
        # in order, so more and longer runs are sampled.
        "samples": 1000,
        "steps": 100,
        "transitions": "membership",
    },
    "enrollment": {
        "consts": "joiners=j1,j2 presence=j1 acceptors=h,root max_tid=6",
        "scenario_consts": "joiners=j1 presence=j1 acceptors=h max_tid=4",
        "rare": {"rootAdmit": 4, "acceptorRequest": 3, "joinerSend": 2, "badRequest": 1},
    },
}


def membership_transitions(prev: dict, cur: dict) -> set[str]:
    """What happened to a node in one step, as behaviours the replay should reach."""
    out = set()
    for d, a in prev.items():
        b = cur[d]
        if b["halted"] and not a["halted"]:
            out.add("halt at generation 1" if b["gen"] == 1 else "halt at a later generation")
        if a["halted"] and not b["halted"]:
            out.add("root change ends a halt")
        if b["forever"] and not a["forever"]:
            out.add("permanent halt")
        if b["gen"] > a["gen"]:
            out.add("root change accepted" if b["rc"] == 0 else "second root change record accepted")
        if b["gen"] == a["gen"] and b["cp"]["no"] > a["cp"]["no"]:
            out.add("checkpoint accepted")
            if len(b["pps"]) < len(a["pps"]):
                out.add("checkpoint prunes the cache")
            if b["cp"]["start"] > a["cp"]["start"]:
                out.add("window moves")
        if len(b["pps"]) > len(a["pps"]):
            out.add("passport accepted")
        if a["pps"] and not b["pps"] and b["gen"] == a["gen"] and b["cp"] == a["cp"]:
            out.add("reboot clears the cache")
    return out


TRANSITIONS = {"membership": membership_transitions}


def sample(model: str, spec: dict, tmp: Path) -> list[Path]:
    samples, steps = spec.get("samples", SAMPLES), spec.get("steps", STEPS)
    pattern = tmp / f"{model}_{{seq}}.itf.json"
    subprocess.run(
        ["npx", "quint", "run", f"{model}/instances.qnt", "--main=small", "--backend=typescript",
         "--mbt", f"--max-samples={samples}", f"--n-traces={samples}", f"--max-steps={steps}",
         f"--seed={SEED}", "--invariant=safety", f"--out-itf={pattern}"],
        cwd=ROOT / "models", check=True, stdout=subprocess.DEVNULL,
    )
    found = [p for p in tmp.glob(f"{model}_*.itf.json") if p.stem.split("_")[1].split(".")[0].isdigit()]
    return sorted(found, key=lambda p: int(p.stem.split("_")[1].split(".")[0]))


def scenarios(model: str, consts: str, modules: list[str], tmp: Path) -> None:
    count = 0
    for module in modules:
        pattern = tmp / f"{model}_{module}_{{test}}_{{seq}}.itf.json"
        subprocess.run(
            ["npx", "quint", "test", f"{model}/scenarios.qnt", f"--main={module}", "--backend=typescript",
             f"--seed={SEED}", f"--out-itf={pattern}"],
            cwd=ROOT / "models", check=True, stdout=subprocess.DEVNULL,
        )
        files = sorted(str(p) for p in tmp.glob(f"{model}_{module}_*Test_*.itf.json"))
        subprocess.run(
            [sys.executable, str(ROOT / "tools/sim/scenario2trace.py"), model,
             str(ROOT / "models" / model / "scenarios.qnt"), consts, str(OUT), *files],
            check=True, env={**os.environ, "SCENARIO_MODULE": module},
        )
        count += len(files)
    print(f"{model}: {count} scenario runs")


def profile(path: Path, spec: dict) -> tuple[set[str], int]:
    rare = spec["rare"]
    states = json.loads(path.read_text())["states"]
    last = states[-1]
    seen_key = next(k for k in last if k.endswith("::seen"))
    seen = set(last[seen_key]["#set"])
    counts = Counter(s["mbt::actionTaken"] for s in states)
    # The actions taken count as behaviours too, so every action of the model is replayed.
    seen |= {f"action {a}" for a in counts}
    if "transitions" in spec:
        nodes_key = next(k for k in last if k.endswith("::nodes"))
        for prev, cur in zip(states, states[1:]):
            seen |= TRANSITIONS[spec["transitions"]](itf2trace.val(prev[nodes_key]), itf2trace.val(cur[nodes_key]))
    return seen, sum(w * counts[a] for a, w in rare.items())


def select(paths: list[Path], spec: dict) -> list[Path]:
    info = {p: profile(p, spec) for p in paths}
    chosen: list[Path] = []
    covered: set[str] = set()
    while len(chosen) < KEEP:
        best = max(
            (p for p in paths if p not in chosen),
            key=lambda p: (len(info[p][0] - covered), info[p][1], -paths.index(p)),
        )
        chosen.append(best)
        covered |= info[best][0]
    return chosen


def main() -> None:
    chosen = sys.argv[1:] or list(MODELS)
    OUT.mkdir(parents=True, exist_ok=True)
    for model in chosen:
        for old in OUT.glob(f"{model}-*.trace"):
            old.unlink()
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        for model in chosen:
            spec = MODELS[model]
            scenarios(model, spec["scenario_consts"], spec.get("scenario_modules", ["scenarios"]), tmp)
            paths = sample(model, spec, tmp)
            for i, p in enumerate(select(paths, spec)):
                subprocess.run(
                    [sys.executable, str(ROOT / "tools/sim/itf2trace.py"), model, spec["consts"],
                     str(OUT / f"{model}-{i:02d}.trace"), str(p)],
                    check=True,
                )
            print(f"{model}: {KEEP} of {len(paths)} traces kept")


if __name__ == "__main__":
    main()
