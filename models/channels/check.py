#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# Copyright (C) 2026 HunterEwok
"""Run the channels model checks in CI (R-VER-2, R-VER-3).

`safety` must hold on every checked instance, every probe must violate
`safety`, every witness the simulator reaches must be violated, and the fixed
scenarios in scenarios.qnt must pass. Seeds are fixed, so a run is
reproducible. Long runs use models/run-tlc.ps1 and models/run-inductive.ps1.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = "instances.qnt"
CHECKS = json.loads((HERE / "checks.json").read_text())
CHECKED = ["small", "tiny"]
# Witnesses that random simulation reaches; the others (refill, shrink, refill
# after a reboot) are shown reachable by the fixed scenarios.
SIM_WITNESSES = ["witnessAccept", "witnessClear", "witnessRotateAfterRemove"]
# Probes whose defect needs a long specific sequence are checked by a scenario.
SCENARIO_PROBES = ["empty_no_clear", "refill_moves_high", "no_trim"]
SCENARIOS = ["scenarios"] + [f"scenarios_probe_{p}" for p in SCENARIO_PROBES]
SEED = "0x5eed"


def model_hash():
    h = hashlib.sha256()
    for name in ("channels.qnt", "instances.qnt"):
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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--steps", type=int, default=40)
    ap.add_argument("--samples", type=int, default=100000)
    ap.add_argument("--timeout", type=int, default=1800)
    a = ap.parse_args()
    print(f"model {model_hash()}")
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
