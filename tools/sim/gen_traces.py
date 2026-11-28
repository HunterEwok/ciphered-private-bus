#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok

"""Regenerates the replay traces of the simulator from the Quint models.

For each model it takes two kinds of traces and writes them to crates/cpb-sim/tests/traces:

- every run of the model's fixed scenarios (scenarios.qnt), which reach each behaviour the
  witnesses name, converted with scenario2trace.py;
- random traces of the `small` instance with a fixed seed: of the sampled traces it keeps a
  small set that together reaches the most behaviours (the `seen` variable) and has the most
  of the rarer actions, converted with itf2trace.py.

Run it from the repository root after `npm ci` in models/; the TypeScript backend of the
pinned Quint needs no other download.

Usage: tools/sim/gen_traces.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
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
}


def sample(model: str, tmp: Path) -> list[Path]:
    pattern = tmp / f"{model}_{{seq}}.itf.json"
    subprocess.run(
        ["npx", "quint", "run", f"{model}/instances.qnt", "--main=small", "--backend=typescript",
         "--mbt", f"--max-samples={SAMPLES}", f"--n-traces={SAMPLES}", f"--max-steps={STEPS}",
         f"--seed={SEED}", "--invariant=safety", f"--out-itf={pattern}"],
        cwd=ROOT / "models", check=True, stdout=subprocess.DEVNULL,
    )
    found = [p for p in tmp.glob(f"{model}_*.itf.json") if p.stem.split("_")[1].split(".")[0].isdigit()]
    return sorted(found, key=lambda p: int(p.stem.split("_")[1].split(".")[0]))


def scenarios(model: str, consts: str, tmp: Path) -> None:
    pattern = tmp / f"{model}_{{test}}_{{seq}}.itf.json"
    subprocess.run(
        ["npx", "quint", "test", f"{model}/scenarios.qnt", "--main=scenarios", "--backend=typescript", f"--seed={SEED}",
         f"--out-itf={pattern}"],
        cwd=ROOT / "models", check=True, stdout=subprocess.DEVNULL,
    )
    files = sorted(str(p) for p in tmp.glob(f"{model}_*Test_*.itf.json"))
    subprocess.run(
        [sys.executable, str(ROOT / "tools/sim/scenario2trace.py"), model,
         str(ROOT / "models" / model / "scenarios.qnt"), consts, str(OUT), *files],
        check=True,
    )
    print(f"{model}: {len(files)} scenario runs")


def profile(path: Path, rare: dict[str, int]) -> tuple[set[str], int]:
    states = json.loads(path.read_text())["states"]
    last = states[-1]
    seen_key = next(k for k in last if k.endswith("::seen"))
    seen = set(last[seen_key]["#set"])
    counts = Counter(s["mbt::actionTaken"] for s in states)
    return seen, sum(w * counts[a] for a, w in rare.items())


def select(paths: list[Path], rare: dict[str, int]) -> list[Path]:
    info = {p: profile(p, rare) for p in paths}
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
    for old in OUT.glob("*.trace"):
        old.unlink()
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        for model, spec in MODELS.items():
            scenarios(model, spec["scenario_consts"], tmp)
            paths = sample(model, tmp)
            for i, p in enumerate(select(paths, spec["rare"])):
                subprocess.run(
                    [sys.executable, str(ROOT / "tools/sim/itf2trace.py"), model, spec["consts"],
                     str(OUT / f"{model}-{i:02d}.trace"), str(p)],
                    check=True,
                )
            print(f"{model}: {KEEP} of {len(paths)} traces kept")


if __name__ == "__main__":
    main()
