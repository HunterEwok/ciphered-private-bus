#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
"""Run the relay model checks in CI (R-VER-2, R-VER-3).

`safety` must hold on every checked instance, every probe must violate
`safety`, every witness the simulator reaches must be violated, and the fixed
scenarios in scenarios.qnt must pass. Seeds are fixed, so a run is
reproducible. With --inductive INSTANCE it proves `safety` for all reachable
states with Apalache instead, from the inductive invariant in inductive.qnt
(three obligations: init implies IndInv, IndInv and a step imply IndInv, IndInv
implies safety). Long runs use models/run-tlc.ps1 and models/run-inductive.ps1.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = "instances.qnt"
CHECKS = json.loads((HERE / "checks.json").read_text())
CHECKED = ["small", "tiny"]
# Random simulation reaches every witness.
SIM_WITNESSES = CHECKS["witnesses"]
# Probes whose defect needs a specific sequence are checked by a scenario only;
# unfair is reached by simulation and also has a scenario.
SCENARIO_PROBES = ["evict_other"]
SCENARIOS = ["scenarios", "scenarios_probe_unfair", "scenarios_own_limit", "scenarios_probe_evict_other"]
SEED = "0x5eed"
# The Apalache version is pinned with the other tools in tools/versions/versions.toml.
with open(HERE.parents[1] / "tools" / "versions" / "versions.toml", "rb") as _f:
    APALACHE = tomllib.load(_f)["apalache"]["version"]


def model_hash():
    h = hashlib.sha256()
    for name in ("relay.qnt", "instances.qnt"):
        h.update((HERE / name).read_bytes())
    return h.hexdigest()[:12]


def quint(args, timeout):
    start = time.monotonic()
    proc = subprocess.run([shutil.which("quint") or "quint", *args], cwd=HERE, capture_output=True,
                          text=True, timeout=timeout, check=False)
    return proc.returncode, proc.stdout + proc.stderr, time.monotonic() - start


def verdict(output):
    if re.search(r"^\[ok\]", output, re.M):
        return "holds"
    if re.search(r"^\[violation\]", output, re.M):
        return "violated"
    return "error"


def inductive(main, timeout):
    """The three obligations of the inductive invariant (R-VER-3)."""
    checks = [
        ("init implies IndInv", "modelInit", "IndInv", 0),
        ("IndInv and step imply IndInv", "indInit", "IndInv", 1),
        ("IndInv implies safety", "indInit", "modelSafety", 0),
    ]
    failures = 0
    for name, init, inv, steps in checks:
        _, out, secs = quint(["verify", f"--main={main}", f"--init={init}", "--step=modelStep", f"--invariant={inv}",
                              f"--max-steps={steps}", f"--apalache-version={APALACHE}", "inductive.qnt"], timeout)
        got = verdict(out)
        ok = got == "holds"
        failures += not ok
        print(f"{'pass' if ok else 'FAIL'}  {main:10} {name:30} {got:9} {secs:7.0f} s")
        if not ok:
            print(out, file=sys.stderr)
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--steps", type=int, default=40)
    ap.add_argument("--samples", type=int, default=20000)
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--inductive", metavar="INSTANCE", default=None,
                    help="prove safety from the inductive invariant instead, e.g. tiny_ind")
    a = ap.parse_args()
    print(f"model {model_hash()}")
    if a.inductive:
        # The invariant lives outside the model, so it gets a hash of its own.
        print(f"inductive invariant {hashlib.sha256((HERE / 'inductive.qnt').read_bytes()).hexdigest()[:12]}")
        sys.exit(1 if inductive(a.inductive, a.timeout) else 0)
    runs = [(m, "safety", "holds") for m in CHECKED]
    runs += [("probe_" + p, "safety", "violated") for p in CHECKS["probes"] if p not in SCENARIO_PROBES]
    runs += [("small", w, "violated") for w in SIM_WITNESSES]
    failures = 0
    for main_, inv, expected in runs:
        _, out, secs = quint(["run", f"--main={main_}", f"--invariant={inv}", f"--max-steps={a.steps}",
                              f"--max-samples={a.samples}", f"--seed={SEED}", "--backend=rust", SPEC], a.timeout)
        got = verdict(out)
        ok = got == expected
        failures += not ok
        print(f"{'pass' if ok else 'FAIL'}  {main_:28} {inv:26} {got:9} {secs:7.1f} s")
        if got == "error":
            print(out, file=sys.stderr)
    for main_ in SCENARIOS:
        status, out, secs = quint(["test", f"--main={main_}", f"--seed={SEED}", "scenarios.qnt"], a.timeout)
        ok = status == 0 and "failing" not in out
        failures += not ok
        print(f"{'pass' if ok else 'FAIL'}  {main_:55} {'tests pass' if ok else 'tests fail':9} {secs:7.1f} s")
        if not ok:
            print(out, file=sys.stderr)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
